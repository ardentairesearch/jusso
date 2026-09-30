use super::{
    validate_external_id, ProviderWallet, WalletProvider, WalletProviderKind, WalletScope,
};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ethers::{
    types::{Address, Signature, H256, U256},
    utils::to_checksum,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde_json::Value;
use sqlx::PgPool;
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::time::sleep;
use turnkey_client::{
    generated::{
        immutable::common::v1::{
            AddressFormat, ApiKeyCurve, Curve, HashFunction, PathFormat, PayloadEncoding,
        },
        services::coordinator::public::v1::{
            GetSubOrgIdsRequest, GetWalletAccountsRequest, GetWalletsRequest, GetWhoamiRequest,
        },
        ApiKeyParamsV2, CreateSubOrganizationIntentV8, CreateWalletIntent, RootUserParamsV5,
        SignRawPayloadIntentV2, WalletAccountParams,
    },
    TurnkeyClient, TurnkeyP256ApiKey,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_BASE_URL: &str = "https://api.turnkey.com";
const ETHEREUM_BIP44_PATH: &str = "m/44'/60'/0'/0/0";
const PROVISIONING_STALE_SECONDS: i64 = 60;
const PROVISIONING_WAIT_ATTEMPTS: usize = 40;

#[derive(Clone)]
pub struct TurnkeyWalletProvider {
    parent_organization_id: String,
    parent_client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
    base_url: String,
    db_pool: PgPool,
    credential_encryption_key: Arc<Zeroizing<String>>,
}

impl std::fmt::Debug for TurnkeyWalletProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyWalletProvider")
            .field("parent_organization_id", &self.parent_organization_id)
            .field("base_url", &self.base_url)
            .field("credential_encryption_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
struct TurnkeyOrganizationContext {
    scope: WalletScope,
    organization_id: String,
    client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
}

#[derive(Clone, sqlx::FromRow)]
struct TurnkeyOrganizationBinding {
    organization_id: Uuid,
    provider_organization_id: Option<String>,
    sub_organization_name: String,
    api_public_key: String,
    api_private_key_encrypted: String,
    status: String,
    updated_at: DateTime<Utc>,
}

impl TurnkeyWalletProvider {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        api_public_key: &str,
        api_private_key: &str,
        base_url: Option<&str>,
        db_pool: PgPool,
        credential_encryption_key: String,
    ) -> Result<Self> {
        let organization_id = organization_id.into();
        Uuid::parse_str(&organization_id).context("TURNKEY_ORGANIZATION_ID must be a UUID")?;
        let base_url = validate_base_url(base_url.unwrap_or(DEFAULT_BASE_URL))?;
        let credential_encryption_key = Arc::new(Zeroizing::new(credential_encryption_key));
        let parent_client = build_client(
            api_public_key,
            api_private_key,
            &base_url,
            "parent Turnkey API key",
        )?;
        Ok(Self {
            parent_organization_id: organization_id,
            parent_client,
            base_url,
            db_pool,
            credential_encryption_key,
        })
    }

    async fn organization_context(&self, scope: WalletScope) -> Result<TurnkeyOrganizationContext> {
        match scope {
            WalletScope::Infrastructure => Ok(TurnkeyOrganizationContext {
                scope,
                organization_id: self.parent_organization_id.clone(),
                client: self.parent_client.clone(),
            }),
            WalletScope::Organization(organization_id) => {
                let binding = self.ensure_tenant_organization(organization_id).await?;
                self.context_from_binding(scope, &binding)
            }
        }
    }

    fn context_from_binding(
        &self,
        scope: WalletScope,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<TurnkeyOrganizationContext> {
        if scope != WalletScope::Organization(binding.organization_id) {
            bail!("Turnkey binding was requested for the wrong Jusso organization");
        }
        let provider_organization_id = binding
            .provider_organization_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("Turnkey organization binding is not active"))?;
        Uuid::parse_str(&provider_organization_id)
            .context("Turnkey binding contains an invalid organization ID")?;
        let mut private_key = crate::db::decrypt_secret(
            self.credential_encryption_key.as_str(),
            &binding.api_private_key_encrypted,
        )
        .context("failed to decrypt tenant Turnkey credential")?;
        let client = build_client(
            &binding.api_public_key,
            &private_key,
            &self.base_url,
            "tenant Turnkey API key",
        );
        private_key.zeroize();
        Ok(TurnkeyOrganizationContext {
            scope,
            organization_id: provider_organization_id,
            client: client?,
        })
    }

    async fn ensure_tenant_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<TurnkeyOrganizationBinding> {
        let mut created_here = false;
        let mut binding = match self.load_binding(organization_id).await? {
            Some(binding) => binding,
            None => {
                let inserted = self.create_provisioning_binding(organization_id).await?;
                created_here = inserted.is_some();
                match inserted {
                    Some(binding) => binding,
                    None => self
                        .load_binding(organization_id)
                        .await?
                        .ok_or_else(|| anyhow!("Turnkey binding disappeared during creation"))?,
                }
            }
        };

        if binding.status == "active" {
            return Ok(binding);
        }

        if binding.status == "provisioning" && !created_here {
            for _ in 0..PROVISIONING_WAIT_ATTEMPTS {
                if (Utc::now() - binding.updated_at).num_seconds() >= PROVISIONING_STALE_SECONDS {
                    break;
                }
                sleep(Duration::from_millis(250)).await;
                binding = self
                    .load_binding(organization_id)
                    .await?
                    .ok_or_else(|| anyhow!("Turnkey binding disappeared during provisioning"))?;
                if binding.status == "active" {
                    return Ok(binding);
                }
                if binding.status == "failed" {
                    break;
                }
            }
        }

        if !created_here {
            if let Some(provider_organization_id) = self
                .find_sub_organization_by_name(&binding.sub_organization_name)
                .await?
            {
                self.verify_tenant_credential(&binding, &provider_organization_id)
                    .await?;
                return self
                    .activate_binding(organization_id, &provider_organization_id)
                    .await;
            }
            let claimed = sqlx::query(
                r#"
                UPDATE turnkey_organization_bindings
                SET status = 'provisioning', last_error = NULL, updated_at = now()
                WHERE organization_id = $1
                  AND (
                    status = 'failed'
                    OR (status = 'provisioning' AND updated_at < now() - interval '60 seconds')
                  )
                "#,
            )
            .bind(organization_id)
            .execute(&self.db_pool)
            .await?
            .rows_affected();
            if claimed != 1 {
                bail!("Turnkey sub-organization provisioning is already in progress");
            }
        }

        match self.provision_sub_organization(&binding).await {
            Ok(provider_organization_id) => {
                self.activate_binding(organization_id, &provider_organization_id)
                    .await
            }
            Err(error) => {
                sqlx::query(
                    r#"
                    UPDATE turnkey_organization_bindings
                    SET status = 'failed',
                        last_error = 'Turnkey sub-organization provisioning failed',
                        updated_at = now()
                    WHERE organization_id = $1 AND status = 'provisioning'
                    "#,
                )
                .bind(organization_id)
                .execute(&self.db_pool)
                .await?;
                Err(error)
            }
        }
    }

    async fn load_binding(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<TurnkeyOrganizationBinding>> {
        Ok(sqlx::query_as::<_, TurnkeyOrganizationBinding>(
            r#"
            SELECT organization_id, provider_organization_id,
                   sub_organization_name, api_public_key,
                   api_private_key_encrypted, status, updated_at
            FROM turnkey_organization_bindings
            WHERE organization_id = $1
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&self.db_pool)
        .await?)
    }

    async fn create_provisioning_binding(
        &self,
        organization_id: Uuid,
    ) -> Result<Option<TurnkeyOrganizationBinding>> {
        let runtime_key = TurnkeyP256ApiKey::generate();
        let api_public_key = hex::encode(runtime_key.compressed_public_key());
        let mut private_bytes = runtime_key.private_key();
        let api_private_key = Zeroizing::new(hex::encode(&private_bytes));
        private_bytes.zeroize();
        let encrypted_private_key =
            crate::db::encrypt_secret(self.credential_encryption_key.as_str(), &api_private_key)?;
        let sub_organization_name = deterministic_sub_organization_name(organization_id);

        Ok(sqlx::query_as::<_, TurnkeyOrganizationBinding>(
            r#"
            INSERT INTO turnkey_organization_bindings (
                organization_id, sub_organization_name, api_public_key,
                api_private_key_encrypted, status
            )
            VALUES ($1, $2, $3, $4, 'provisioning')
            ON CONFLICT (organization_id) DO NOTHING
            RETURNING organization_id, provider_organization_id,
                      sub_organization_name, api_public_key,
                      api_private_key_encrypted, status, updated_at
            "#,
        )
        .bind(organization_id)
        .bind(sub_organization_name)
        .bind(api_public_key)
        .bind(encrypted_private_key)
        .fetch_optional(&self.db_pool)
        .await?)
    }

    async fn provision_sub_organization(
        &self,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<String> {
        if let Some(existing) = self
            .find_sub_organization_by_name(&binding.sub_organization_name)
            .await?
        {
            self.verify_tenant_credential(binding, &existing).await?;
            return Ok(existing);
        }

        let recovery_public_key = self
            .customer_recovery_public_key(binding.organization_id)
            .await?;
        let result = self
            .parent_client
            .create_sub_organization(
                self.parent_organization_id.clone(),
                self.parent_client.current_timestamp(),
                CreateSubOrganizationIntentV8 {
                    sub_organization_name: binding.sub_organization_name.clone(),
                    root_users: vec![
                        RootUserParamsV5 {
                            user_name: "Jusso Runtime".into(),
                            user_email: None,
                            user_phone_number: None,
                            api_keys: vec![ApiKeyParamsV2 {
                                api_key_name: "Jusso Tenant Runtime".into(),
                                public_key: binding.api_public_key.clone(),
                                curve_type: ApiKeyCurve::P256,
                                expiration_seconds: None,
                            }],
                            authenticators: vec![],
                            oauth_providers: vec![],
                        },
                        RootUserParamsV5 {
                            user_name: "Customer Recovery".into(),
                            user_email: None,
                            user_phone_number: None,
                            api_keys: vec![ApiKeyParamsV2 {
                                api_key_name: "Registration Recovery Key".into(),
                                public_key: recovery_public_key,
                                curve_type: ApiKeyCurve::P256,
                                expiration_seconds: None,
                            }],
                            authenticators: vec![],
                            oauth_providers: vec![],
                        },
                    ],
                    root_quorum_threshold: 1,
                    wallet: None,
                    disable_email_recovery: Some(true),
                    disable_email_auth: Some(true),
                    disable_sms_auth: Some(true),
                    disable_otp_email_auth: Some(true),
                    verification_token: None,
                    client_signature: None,
                },
            )
            .await
            .context("Turnkey sub-organization creation failed")?;
        let provider_organization_id = result.result.sub_organization_id;
        Uuid::parse_str(&provider_organization_id)
            .context("Turnkey returned an invalid sub-organization ID")?;
        self.verify_tenant_credential(binding, &provider_organization_id)
            .await?;
        Ok(provider_organization_id)
    }

    async fn find_sub_organization_by_name(&self, name: &str) -> Result<Option<String>> {
        let response = self
            .parent_client
            .get_sub_org_ids(GetSubOrgIdsRequest {
                organization_id: self.parent_organization_id.clone(),
                filter_type: "NAME".into(),
                filter_value: name.into(),
                pagination_options: None,
            })
            .await
            .context("Turnkey sub-organization reconciliation failed")?;
        match response.organization_ids.as_slice() {
            [] => Ok(None),
            [organization_id] => Ok(Some(organization_id.clone())),
            _ => bail!("multiple Turnkey sub-organizations use tenant name {name:?}"),
        }
    }

    async fn verify_tenant_credential(
        &self,
        binding: &TurnkeyOrganizationBinding,
        provider_organization_id: &str,
    ) -> Result<()> {
        let mut verified = binding.clone();
        verified.provider_organization_id = Some(provider_organization_id.to_string());
        let context = self.context_from_binding(
            WalletScope::Organization(binding.organization_id),
            &verified,
        )?;
        let whoami = context
            .client
            .get_whoami(GetWhoamiRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("tenant Turnkey credential verification failed")?;
        if whoami.organization_id != provider_organization_id {
            bail!("tenant Turnkey credential resolved to the wrong organization");
        }
        Ok(())
    }

    async fn activate_binding(
        &self,
        organization_id: Uuid,
        provider_organization_id: &str,
    ) -> Result<TurnkeyOrganizationBinding> {
        Ok(sqlx::query_as::<_, TurnkeyOrganizationBinding>(
            r#"
            UPDATE turnkey_organization_bindings
            SET provider_organization_id = $2, status = 'active',
                last_error = NULL, updated_at = now()
            WHERE organization_id = $1
            RETURNING organization_id, provider_organization_id,
                      sub_organization_name, api_public_key,
                      api_private_key_encrypted, status, updated_at
            "#,
        )
        .bind(organization_id)
        .bind(provider_organization_id)
        .fetch_one(&self.db_pool)
        .await?)
    }

    async fn customer_recovery_public_key(&self, organization_id: Uuid) -> Result<String> {
        let public_jwk: Value = sqlx::query_scalar(
            r#"
            SELECT cb.public_jwk
            FROM credential_bindings cb
            JOIN principals p ON p.id = cb.principal_id
            WHERE cb.organization_id = $1
              AND cb.credential_kind = 'local_jwk'
              AND cb.is_active = TRUE
              AND p.principal_type = 'owner'
              AND p.status = 'active'
            ORDER BY cb.created_at
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&self.db_pool)
        .await?
        .ok_or_else(|| anyhow!("organization has no active owner recovery credential"))?;
        compressed_p256_public_key(&public_jwk)
    }

    async fn resolve_wallet(
        &self,
        context: &TurnkeyOrganizationContext,
        wallet_id: String,
        external_id: &str,
    ) -> Result<ProviderWallet> {
        let response = context
            .client
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: context.organization_id.clone(),
                wallet_id: Some(wallet_id.clone()),
                include_wallet_details: Some(false),
                pagination_options: None,
            })
            .await
            .context("Turnkey wallet-account lookup failed")?;
        let mut ethereum_accounts = response.accounts.into_iter().filter(|account| {
            account.wallet_id == wallet_id
                && account.curve == Curve::Secp256k1
                && account.path_format == PathFormat::Bip32
                && account.address_format == AddressFormat::Ethereum
        });
        let account = ethereum_accounts
            .next()
            .ok_or_else(|| anyhow!("Turnkey wallet has no Ethereum account"))?;
        if ethereum_accounts.next().is_some() {
            bail!("Turnkey wallet has multiple Ethereum accounts");
        }
        if account.path != ETHEREUM_BIP44_PATH {
            bail!(
                "Turnkey wallet uses unexpected Ethereum derivation path {:?}",
                account.path
            );
        }
        Ok(ProviderWallet {
            provider: WalletProviderKind::Turnkey,
            scope: context.scope,
            provider_organization_id: context.organization_id.clone(),
            provider_wallet_id: wallet_id,
            provider_account_id: account.wallet_account_id,
            external_id: external_id.to_string(),
            address: account
                .address
                .parse()
                .context("Turnkey returned an invalid Ethereum address")?,
        })
    }
}

#[async_trait]
impl WalletProvider for TurnkeyWalletProvider {
    fn kind(&self) -> WalletProviderKind {
        WalletProviderKind::Turnkey
    }

    async fn find_wallet(
        &self,
        scope: WalletScope,
        external_id: &str,
    ) -> Result<Option<ProviderWallet>> {
        validate_external_id(external_id)?;
        let context = self.organization_context(scope).await?;
        let response = context
            .client
            .get_wallets(GetWalletsRequest {
                organization_id: context.organization_id.clone(),
            })
            .await
            .context("Turnkey wallet lookup failed")?;
        let mut matches = response
            .wallets
            .into_iter()
            .filter(|wallet| wallet.wallet_name == external_id);
        let Some(wallet) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() {
            bail!("multiple Turnkey wallets use external identifier {external_id:?}");
        }
        self.resolve_wallet(&context, wallet.wallet_id, external_id)
            .await
            .map(Some)
    }

    async fn create_wallet(&self, scope: WalletScope, external_id: &str) -> Result<ProviderWallet> {
        validate_external_id(external_id)?;
        let context = self.organization_context(scope).await?;
        let created = context
            .client
            .create_wallet(
                context.organization_id.clone(),
                context.client.current_timestamp(),
                CreateWalletIntent {
                    wallet_name: external_id.to_string(),
                    accounts: vec![WalletAccountParams {
                        curve: Curve::Secp256k1,
                        path_format: PathFormat::Bip32,
                        path: ETHEREUM_BIP44_PATH.to_string(),
                        address_format: AddressFormat::Ethereum,
                        name: None,
                    }],
                    mnemonic_length: None,
                },
            )
            .await
            .context("Turnkey wallet creation failed")?;
        if created.result.addresses.len() != 1 {
            bail!("Turnkey wallet creation returned an unexpected address count");
        }
        let wallet = self
            .resolve_wallet(&context, created.result.wallet_id, external_id)
            .await?;
        let created_address: Address = created.result.addresses[0]
            .parse()
            .context("Turnkey wallet creation returned an invalid Ethereum address")?;
        if wallet.address != created_address {
            bail!("Turnkey wallet creation and account lookup returned different addresses");
        }
        Ok(wallet)
    }

    async fn sign_hash(
        &self,
        wallet: &ProviderWallet,
        hash: H256,
        _idempotency_key: Uuid,
    ) -> Result<Signature> {
        if wallet.provider != WalletProviderKind::Turnkey {
            bail!("Turnkey cannot sign for a wallet owned by another provider");
        }
        let context = self.organization_context(wallet.scope).await?;
        if context.organization_id != wallet.provider_organization_id {
            bail!("managed wallet is bound to the wrong Turnkey organization");
        }
        let result = context
            .client
            .sign_raw_payload(
                context.organization_id,
                context.client.current_timestamp(),
                SignRawPayloadIntentV2 {
                    sign_with: turnkey_sign_with(wallet.address),
                    payload: hex::encode(hash.as_bytes()),
                    encoding: PayloadEncoding::Hexadecimal,
                    hash_function: HashFunction::NoOp,
                },
            )
            .await
            .context("Turnkey raw-payload signing failed")?
            .result;
        let signature = Signature {
            r: parse_signature_component(&result.r, "r")?,
            s: parse_signature_component(&result.s, "s")?,
            v: parse_recovery_id(&result.v)?,
        };
        let recovered = signature
            .recover(hash)
            .context("Turnkey signature recovery failed")?;
        if recovered != wallet.address {
            bail!(
                "Turnkey signature mismatch: expected {:?}, recovered {recovered:?}",
                wallet.address
            );
        }
        Ok(signature)
    }
}

fn validate_base_url(value: &str) -> Result<String> {
    let value = value.trim_end_matches('/');
    let parsed = reqwest::Url::parse(value).context("invalid TURNKEY_BASE_URL")?;
    if parsed.scheme() != "https"
        && parsed.host_str() != Some("localhost")
        && parsed.host_str() != Some("127.0.0.1")
    {
        bail!("TURNKEY_BASE_URL must use HTTPS outside local development");
    }
    Ok(value.to_string())
}

fn build_client(
    api_public_key: &str,
    api_private_key: &str,
    base_url: &str,
    label: &str,
) -> Result<Arc<TurnkeyClient<TurnkeyP256ApiKey>>> {
    let api_key = TurnkeyP256ApiKey::from_strings(api_private_key, Some(api_public_key))
        .with_context(|| format!("invalid {label}"))?;
    Ok(Arc::new(
        TurnkeyClient::builder()
            .api_key(api_key)
            .base_url(base_url)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build Turnkey client")?,
    ))
}

fn deterministic_sub_organization_name(organization_id: Uuid) -> String {
    format!("jusso-org-{}", organization_id.simple())
}

fn compressed_p256_public_key(jwk: &Value) -> Result<String> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        bail!("owner recovery credential is not a P-256 public JWK");
    }
    let x = URL_SAFE_NO_PAD
        .decode(
            jwk.get("x")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("owner recovery JWK is missing x"))?,
        )
        .context("owner recovery JWK has invalid x encoding")?;
    let y = URL_SAFE_NO_PAD
        .decode(
            jwk.get("y")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("owner recovery JWK is missing y"))?,
        )
        .context("owner recovery JWK has invalid y encoding")?;
    if x.len() != 32 || y.len() != 32 {
        bail!("owner recovery JWK has invalid P-256 coordinates");
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(4);
    uncompressed.extend_from_slice(&x);
    uncompressed.extend_from_slice(&y);
    let public_key = p256::PublicKey::from_sec1_bytes(&uncompressed)
        .context("owner recovery JWK is not a valid P-256 point")?;
    Ok(hex::encode(public_key.to_encoded_point(true).as_bytes()))
}

fn turnkey_sign_with(address: Address) -> String {
    to_checksum(&address, None)
}

fn parse_signature_component(value: &str, name: &str) -> Result<U256> {
    let value = value.trim_start_matches("0x");
    if value.is_empty() || value.len() > 64 {
        bail!("Turnkey returned an invalid signature {name} component");
    }
    U256::from_str_radix(value, 16)
        .with_context(|| format!("Turnkey returned a non-hex signature {name} component"))
}

fn parse_recovery_id(value: &str) -> Result<u64> {
    let value = value.trim();
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u64::from_str_radix(hex, 16)
    } else {
        u64::from_str(value).or_else(|_| u64::from_str_radix(value, 16))
    }
    .context("Turnkey returned an invalid signature recovery ID")?;
    match parsed {
        0 | 1 => Ok(parsed + 27),
        27 | 28 => Ok(parsed),
        _ => bail!("Turnkey returned unsupported signature recovery ID {parsed}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_turnkey_signature_formats() {
        assert_eq!(parse_recovery_id("0").unwrap(), 27);
        assert_eq!(parse_recovery_id("01").unwrap(), 28);
        assert_eq!(parse_recovery_id("0x1b").unwrap(), 27);
        assert!(parse_recovery_id("2").is_err());
        assert_eq!(parse_signature_component("0x01", "r").unwrap(), U256::one());
    }

    #[test]
    fn converts_registration_jwk_to_turnkey_public_key() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
        });
        assert_eq!(
            compressed_p256_public_key(&jwk).unwrap(),
            hex::encode(
                signing_key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
            )
        );
    }

    #[test]
    fn tenant_names_are_stable_and_non_identifying() {
        let organization_id = Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
        assert_eq!(
            deterministic_sub_organization_name(organization_id),
            "jusso-org-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }
}
