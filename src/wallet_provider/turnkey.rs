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
        external::data::v1::{Policy as TurnkeyPolicy, User as TurnkeyUser},
        immutable::common::v1::{
            AddressFormat, ApiKeyCurve, Curve, Effect, HashFunction, PathFormat, PayloadEncoding,
        },
        services::coordinator::public::v1::{
            GetOrganizationConfigsRequest, GetPoliciesRequest, GetSubOrgIdsRequest,
            GetUsersRequest, GetWalletAccountsRequest, GetWalletsRequest, GetWhoamiRequest,
        },
        ApiKeyParamsV2, AuthenticatorParamsV2, CreatePolicyIntentV3, CreateSubOrganizationIntentV8,
        CreateUsersIntentV4, CreateWalletIntent, RootUserParamsV5, SignRawPayloadIntentV2,
        UpdateRootQuorumIntent, UserParamsV4, WalletAccountParams,
    },
    TurnkeyClient, TurnkeyP256ApiKey,
};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const DEFAULT_BASE_URL: &str = "https://api.turnkey.com";
const ETHEREUM_BIP44_PATH: &str = "m/44'/60'/0'/0/0";
const PROVISIONING_STALE_SECONDS: i64 = 60;
const PROVISIONING_WAIT_ATTEMPTS: usize = 40;
const BOOTSTRAP_USER_NAME: &str = "Jusso Bootstrap";
const RECOVERY_USER_NAME: &str = "Customer Recovery";
const RUNTIME_USER_NAME: &str = "Jusso Runtime";
const WALLET_POLICY_NAME: &str = "Jusso Runtime Wallet Provisioning";
const SIGNING_POLICY_NAME: &str = "Jusso Runtime ERC-4337 Signing";
const CREDENTIAL_LOCKDOWN_POLICY_NAME: &str = "Jusso Runtime Credential Lockdown";

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
    bootstrap_api_public_key: Option<String>,
    bootstrap_api_private_key_encrypted: Option<String>,
    bootstrap_user_id: Option<String>,
    recovery_user_id: Option<String>,
    runtime_user_id: Option<String>,
    wallet_policy_id: Option<String>,
    signing_policy_id: Option<String>,
    credential_lockdown_policy_id: Option<String>,
    root_hardened_at: Option<DateTime<Utc>>,
    status: String,
    updated_at: DateTime<Utc>,
}

struct RestrictedTenant {
    provider_organization_id: String,
    bootstrap_user_id: String,
    recovery_user_id: String,
    runtime_user_id: String,
    wallet_policy_id: String,
    signing_policy_id: String,
    credential_lockdown_policy_id: String,
}

struct RuntimePolicySpec {
    name: &'static str,
    effect: Effect,
    consensus: Option<String>,
    condition: String,
}

enum CustomerRecoveryCredential {
    Passkey(AuthenticatorParamsV2),
    ApiKey(String),
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
        if binding.status != "active" || binding.root_hardened_at.is_none() {
            bail!("Turnkey organization binding is not security-hardened");
        }
        validate_active_binding_metadata(binding)?;
        let provider_organization_id = binding
            .provider_organization_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow!("Turnkey organization binding is not active"))?;
        Uuid::parse_str(&provider_organization_id)
            .context("Turnkey binding contains an invalid organization ID")?;
        let client = self.client_from_encrypted_key(
            &binding.api_public_key,
            &binding.api_private_key_encrypted,
            "tenant Turnkey API key",
        )?;
        Ok(TurnkeyOrganizationContext {
            scope,
            organization_id: provider_organization_id,
            client,
        })
    }

    fn client_from_encrypted_key(
        &self,
        public_key: &str,
        encrypted_private_key: &str,
        label: &str,
    ) -> Result<Arc<TurnkeyClient<TurnkeyP256ApiKey>>> {
        let mut private_key = crate::db::decrypt_secret(
            self.credential_encryption_key.as_str(),
            encrypted_private_key,
        )
        .with_context(|| format!("failed to decrypt {label}"))?;
        let client = build_client(public_key, &private_key, &self.base_url, label);
        private_key.zeroize();
        client
    }

    fn runtime_client(
        &self,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<Arc<TurnkeyClient<TurnkeyP256ApiKey>>> {
        self.client_from_encrypted_key(
            &binding.api_public_key,
            &binding.api_private_key_encrypted,
            "tenant runtime Turnkey API key",
        )
    }

    fn bootstrap_client(
        &self,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<Arc<TurnkeyClient<TurnkeyP256ApiKey>>> {
        self.client_from_encrypted_key(
            binding
                .bootstrap_api_public_key
                .as_deref()
                .ok_or_else(|| anyhow!("Turnkey bootstrap public key is unavailable"))?,
            binding
                .bootstrap_api_private_key_encrypted
                .as_deref()
                .ok_or_else(|| anyhow!("Turnkey bootstrap private key is unavailable"))?,
            "tenant bootstrap Turnkey API key",
        )
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
            Ok(tenant) => self.activate_binding(organization_id, &tenant).await,
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
                   api_private_key_encrypted, bootstrap_api_public_key,
                   bootstrap_api_private_key_encrypted, bootstrap_user_id,
                   recovery_user_id, runtime_user_id, wallet_policy_id,
                   signing_policy_id, credential_lockdown_policy_id,
                   root_hardened_at, status, updated_at
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
        let bootstrap_key = TurnkeyP256ApiKey::generate();
        let bootstrap_api_public_key = hex::encode(bootstrap_key.compressed_public_key());
        let mut bootstrap_private_bytes = bootstrap_key.private_key();
        let bootstrap_api_private_key = Zeroizing::new(hex::encode(&bootstrap_private_bytes));
        bootstrap_private_bytes.zeroize();
        let encrypted_bootstrap_private_key = crate::db::encrypt_secret(
            self.credential_encryption_key.as_str(),
            &bootstrap_api_private_key,
        )?;
        let sub_organization_name = deterministic_sub_organization_name(organization_id);

        Ok(sqlx::query_as::<_, TurnkeyOrganizationBinding>(
            r#"
            INSERT INTO turnkey_organization_bindings (
                organization_id, sub_organization_name, api_public_key,
                api_private_key_encrypted, bootstrap_api_public_key,
                bootstrap_api_private_key_encrypted, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'provisioning')
            ON CONFLICT (organization_id) DO NOTHING
            RETURNING organization_id, provider_organization_id,
                      sub_organization_name, api_public_key,
                      api_private_key_encrypted, bootstrap_api_public_key,
                      bootstrap_api_private_key_encrypted, bootstrap_user_id,
                      recovery_user_id, runtime_user_id, wallet_policy_id,
                      signing_policy_id, credential_lockdown_policy_id,
                      root_hardened_at, status, updated_at
            "#,
        )
        .bind(organization_id)
        .bind(sub_organization_name)
        .bind(api_public_key)
        .bind(encrypted_private_key)
        .bind(bootstrap_api_public_key)
        .bind(encrypted_bootstrap_private_key)
        .fetch_optional(&self.db_pool)
        .await?)
    }

    async fn provision_sub_organization(
        &self,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<RestrictedTenant> {
        let provider_organization_id = match self
            .find_sub_organization_by_name(&binding.sub_organization_name)
            .await?
        {
            Some(existing) => existing,
            None => self.create_bootstrap_sub_organization(binding).await?,
        };
        Uuid::parse_str(&provider_organization_id)
            .context("Turnkey returned an invalid sub-organization ID")?;

        if let Ok(tenant) = self
            .verify_restricted_tenant(binding, &provider_organization_id)
            .await
        {
            return Ok(tenant);
        }

        let bootstrap_client = self.bootstrap_client(binding)?;
        let bootstrap_identity = bootstrap_client
            .get_whoami(GetWhoamiRequest {
                organization_id: provider_organization_id.clone(),
            })
            .await
            .context("tenant bootstrap Turnkey credential verification failed")?;
        if bootstrap_identity.organization_id != provider_organization_id
            || bootstrap_identity.username != BOOTSTRAP_USER_NAME
        {
            bail!("tenant bootstrap credential resolved to an unexpected identity");
        }
        let users = bootstrap_client
            .get_users(GetUsersRequest {
                organization_id: provider_organization_id.clone(),
            })
            .await
            .context("Turnkey tenant user reconciliation failed")?
            .users;
        let bootstrap_public_key = binding
            .bootstrap_api_public_key
            .as_deref()
            .ok_or_else(|| anyhow!("Turnkey bootstrap public key is unavailable"))?;
        let bootstrap_user = find_exact_api_user(
            &users,
            BOOTSTRAP_USER_NAME,
            bootstrap_public_key,
            "bootstrap",
        )?;
        if bootstrap_user.user_id != bootstrap_identity.user_id {
            bail!("tenant bootstrap API key belongs to the wrong Turnkey user");
        }
        let recovery_user = find_unique_user(&users, RECOVERY_USER_NAME, "recovery")?;
        let runtime_user_id =
            match find_optional_api_user(&users, RUNTIME_USER_NAME, &binding.api_public_key)? {
                Some(user) => user.user_id.clone(),
                None => {
                    let created = bootstrap_client
                        .create_users(
                            provider_organization_id.clone(),
                            bootstrap_client.current_timestamp(),
                            CreateUsersIntentV4 {
                                users: vec![UserParamsV4 {
                                    user_name: RUNTIME_USER_NAME.into(),
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
                                    user_tags: vec![],
                                }],
                            },
                        )
                        .await
                        .context("Turnkey non-root runtime user creation failed")?;
                    match created.result.user_ids.as_slice() {
                        [user_id] => user_id.clone(),
                        _ => bail!("Turnkey returned an unexpected runtime user count"),
                    }
                }
            };

        self.ensure_runtime_policies(
            &bootstrap_client,
            &provider_organization_id,
            &runtime_user_id,
        )
        .await?;

        let config = bootstrap_client
            .get_organization_configs(GetOrganizationConfigsRequest {
                organization_id: provider_organization_id.clone(),
            })
            .await
            .context("Turnkey root-quorum lookup failed")?
            .configs
            .ok_or_else(|| anyhow!("Turnkey tenant organization config is missing"))?;
        let root_quorum = config
            .quorum
            .ok_or_else(|| anyhow!("Turnkey tenant root quorum is missing"))?;
        if root_quorum.threshold != 1 || root_quorum.user_ids != [recovery_user.user_id.clone()] {
            if root_quorum.threshold != 1
                || !root_quorum.user_ids.contains(&bootstrap_user.user_id)
                || !root_quorum.user_ids.contains(&recovery_user.user_id)
            {
                bail!("Turnkey tenant root quorum is not in a recoverable bootstrap state");
            }
            bootstrap_client
                .update_root_quorum(
                    provider_organization_id.clone(),
                    bootstrap_client.current_timestamp(),
                    UpdateRootQuorumIntent {
                        threshold: 1,
                        user_ids: vec![recovery_user.user_id.clone()],
                    },
                )
                .await
                .context("Turnkey customer-only root quorum update failed")?;
        }

        self.verify_restricted_tenant(binding, &provider_organization_id)
            .await
    }

    async fn create_bootstrap_sub_organization(
        &self,
        binding: &TurnkeyOrganizationBinding,
    ) -> Result<String> {
        let recovery_credential = self
            .customer_recovery_credential(binding.organization_id)
            .await?;
        let (recovery_api_keys, recovery_authenticators) = match recovery_credential {
            CustomerRecoveryCredential::Passkey(authenticator) => (vec![], vec![authenticator]),
            CustomerRecoveryCredential::ApiKey(public_key) => (
                vec![ApiKeyParamsV2 {
                    api_key_name: "Registration Recovery Key".into(),
                    public_key,
                    curve_type: ApiKeyCurve::P256,
                    expiration_seconds: None,
                }],
                vec![],
            ),
        };
        let bootstrap_public_key = binding
            .bootstrap_api_public_key
            .clone()
            .ok_or_else(|| anyhow!("Turnkey bootstrap public key is unavailable"))?;
        let result = self
            .parent_client
            .create_sub_organization(
                self.parent_organization_id.clone(),
                self.parent_client.current_timestamp(),
                CreateSubOrganizationIntentV8 {
                    sub_organization_name: binding.sub_organization_name.clone(),
                    root_users: vec![
                        RootUserParamsV5 {
                            user_name: BOOTSTRAP_USER_NAME.into(),
                            user_email: None,
                            user_phone_number: None,
                            api_keys: vec![ApiKeyParamsV2 {
                                api_key_name: "Jusso Tenant Bootstrap".into(),
                                public_key: bootstrap_public_key,
                                curve_type: ApiKeyCurve::P256,
                                expiration_seconds: None,
                            }],
                            authenticators: vec![],
                            oauth_providers: vec![],
                        },
                        RootUserParamsV5 {
                            user_name: RECOVERY_USER_NAME.into(),
                            user_email: None,
                            user_phone_number: None,
                            api_keys: recovery_api_keys,
                            authenticators: recovery_authenticators,
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
        if result.result.root_user_ids.len() != 2 {
            bail!("Turnkey returned an unexpected bootstrap root-user count");
        }
        Ok(result.result.sub_organization_id)
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

    async fn ensure_runtime_policies(
        &self,
        bootstrap_client: &TurnkeyClient<TurnkeyP256ApiKey>,
        provider_organization_id: &str,
        runtime_user_id: &str,
    ) -> Result<()> {
        let existing = bootstrap_client
            .get_policies(GetPoliciesRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("Turnkey runtime policy reconciliation failed")?
            .policies;
        for spec in runtime_policy_specs(runtime_user_id) {
            let matches = existing
                .iter()
                .filter(|policy| policy.policy_name == spec.name)
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [policy] => verify_policy(policy, &spec)?,
                [] => {
                    bootstrap_client
                        .create_policy(
                            provider_organization_id.to_string(),
                            bootstrap_client.current_timestamp(),
                            CreatePolicyIntentV3 {
                                policy_name: spec.name.into(),
                                effect: spec.effect,
                                condition: Some(spec.condition),
                                consensus: spec.consensus,
                                notes: "Jusso managed least-privilege runtime policy".into(),
                            },
                        )
                        .await
                        .with_context(|| {
                            format!("Turnkey runtime policy creation failed for {}", spec.name)
                        })?;
                }
                _ => bail!("multiple Turnkey policies use name {:?}", spec.name),
            }
        }
        Ok(())
    }

    async fn verify_restricted_tenant(
        &self,
        binding: &TurnkeyOrganizationBinding,
        provider_organization_id: &str,
    ) -> Result<RestrictedTenant> {
        let runtime_client = self.runtime_client(binding)?;
        let whoami = runtime_client
            .get_whoami(GetWhoamiRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("tenant runtime Turnkey credential verification failed")?;
        if whoami.organization_id != provider_organization_id
            || whoami.username != RUNTIME_USER_NAME
        {
            bail!("tenant runtime credential resolved to an unexpected identity");
        }
        let users = runtime_client
            .get_users(GetUsersRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("Turnkey restricted tenant user verification failed")?
            .users;
        let runtime_user = find_exact_api_user(
            &users,
            RUNTIME_USER_NAME,
            &binding.api_public_key,
            "runtime",
        )?;
        if runtime_user.user_id != whoami.user_id {
            bail!("tenant runtime API key belongs to the wrong Turnkey user");
        }
        let bootstrap_user = find_unique_user(&users, BOOTSTRAP_USER_NAME, "bootstrap")?;
        let recovery_user = find_unique_user(&users, RECOVERY_USER_NAME, "recovery")?;

        let policies = runtime_client
            .get_policies(GetPoliciesRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("Turnkey restricted tenant policy verification failed")?
            .policies;
        let specs = runtime_policy_specs(&runtime_user.user_id);
        let mut policy_ids = std::collections::BTreeMap::new();
        for spec in specs {
            let matches = policies
                .iter()
                .filter(|policy| policy.policy_name == spec.name)
                .collect::<Vec<_>>();
            let [policy] = matches.as_slice() else {
                bail!(
                    "Turnkey runtime policy {:?} is missing or duplicated",
                    spec.name
                );
            };
            verify_policy(policy, &spec)?;
            policy_ids.insert(spec.name, policy.policy_id.clone());
        }

        let config = runtime_client
            .get_organization_configs(GetOrganizationConfigsRequest {
                organization_id: provider_organization_id.to_string(),
            })
            .await
            .context("Turnkey restricted tenant root-quorum verification failed")?
            .configs
            .ok_or_else(|| anyhow!("Turnkey tenant organization config is missing"))?;
        let root_quorum = config
            .quorum
            .ok_or_else(|| anyhow!("Turnkey tenant root quorum is missing"))?;
        if root_quorum.threshold != 1
            || root_quorum.user_ids != [recovery_user.user_id.clone()]
            || root_quorum.user_ids.contains(&runtime_user.user_id)
            || root_quorum.user_ids.contains(&bootstrap_user.user_id)
        {
            bail!("Turnkey runtime or bootstrap user retains root authority");
        }

        Ok(RestrictedTenant {
            provider_organization_id: provider_organization_id.to_string(),
            bootstrap_user_id: bootstrap_user.user_id.clone(),
            recovery_user_id: recovery_user.user_id.clone(),
            runtime_user_id: runtime_user.user_id.clone(),
            wallet_policy_id: policy_ids
                .remove(WALLET_POLICY_NAME)
                .expect("wallet policy was verified"),
            signing_policy_id: policy_ids
                .remove(SIGNING_POLICY_NAME)
                .expect("signing policy was verified"),
            credential_lockdown_policy_id: policy_ids
                .remove(CREDENTIAL_LOCKDOWN_POLICY_NAME)
                .expect("credential policy was verified"),
        })
    }

    async fn activate_binding(
        &self,
        organization_id: Uuid,
        tenant: &RestrictedTenant,
    ) -> Result<TurnkeyOrganizationBinding> {
        Ok(sqlx::query_as::<_, TurnkeyOrganizationBinding>(
            r#"
            UPDATE turnkey_organization_bindings
            SET provider_organization_id = $2, bootstrap_user_id = $3,
                recovery_user_id = $4, runtime_user_id = $5,
                wallet_policy_id = $6, signing_policy_id = $7,
                credential_lockdown_policy_id = $8,
                root_hardened_at = now(), bootstrap_api_public_key = NULL,
                bootstrap_api_private_key_encrypted = NULL,
                status = 'active', last_error = NULL, updated_at = now()
            WHERE organization_id = $1
            RETURNING organization_id, provider_organization_id,
                      sub_organization_name, api_public_key,
                      api_private_key_encrypted, bootstrap_api_public_key,
                      bootstrap_api_private_key_encrypted, bootstrap_user_id,
                      recovery_user_id, runtime_user_id, wallet_policy_id,
                      signing_policy_id, credential_lockdown_policy_id,
                      root_hardened_at, status, updated_at
            "#,
        )
        .bind(organization_id)
        .bind(&tenant.provider_organization_id)
        .bind(&tenant.bootstrap_user_id)
        .bind(&tenant.recovery_user_id)
        .bind(&tenant.runtime_user_id)
        .bind(&tenant.wallet_policy_id)
        .bind(&tenant.signing_policy_id)
        .bind(&tenant.credential_lockdown_policy_id)
        .fetch_one(&self.db_pool)
        .await?)
    }

    async fn customer_recovery_credential(
        &self,
        organization_id: Uuid,
    ) -> Result<CustomerRecoveryCredential> {
        let passkey: Option<Value> = sqlx::query_scalar(
            r#"
            SELECT op.turnkey_recovery_credential
            FROM owner_passkeys op
            JOIN principals p ON p.id = op.principal_id
            WHERE op.organization_id = $1
              AND op.status = 'active'
              AND op.turnkey_recovery_credential IS NOT NULL
              AND p.principal_type = 'owner'
              AND p.status = 'active'
            ORDER BY CASE op.purpose
                         WHEN 'recovery' THEN 0
                         WHEN 'primary' THEN 1
                         ELSE 2
                     END,
                     op.created_at
            LIMIT 1
            "#,
        )
        .bind(organization_id)
        .fetch_optional(&self.db_pool)
        .await?;
        if let Some(passkey) = passkey {
            return Ok(CustomerRecoveryCredential::Passkey(
                serde_json::from_value(passkey)
                    .context("stored Turnkey recovery passkey is invalid")?,
            ));
        }

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
        Ok(CustomerRecoveryCredential::ApiKey(
            compressed_p256_public_key(&public_jwk)?,
        ))
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

fn runtime_policy_specs(runtime_user_id: &str) -> [RuntimePolicySpec; 3] {
    let consensus = format!("approvers.any(user, user.id == '{runtime_user_id}')");
    [
        RuntimePolicySpec {
            name: WALLET_POLICY_NAME,
            effect: Effect::Allow,
            consensus: Some(consensus.clone()),
            condition: "activity.type == 'ACTIVITY_TYPE_CREATE_WALLET'".into(),
        },
        RuntimePolicySpec {
            name: SIGNING_POLICY_NAME,
            effect: Effect::Allow,
            consensus: Some(consensus),
            condition: "activity.type == 'ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2' && activity.params.hash_function == 'HASH_FUNCTION_NO_OP' && activity.params.encoding == 'PAYLOAD_ENCODING_HEXADECIMAL'".into(),
        },
        RuntimePolicySpec {
            name: CREDENTIAL_LOCKDOWN_POLICY_NAME,
            effect: Effect::Deny,
            consensus: None,
            condition: "activity.resource in ['CREDENTIAL', 'AUTH', 'RECOVERY'] || (activity.resource == 'USER' && activity.action == 'UPDATE')".into(),
        },
    ]
}

fn validate_active_binding_metadata(binding: &TurnkeyOrganizationBinding) -> Result<()> {
    if binding.bootstrap_api_public_key.is_some()
        || binding.bootstrap_api_private_key_encrypted.is_some()
    {
        bail!("active Turnkey binding still contains bootstrap authority");
    }
    for (label, id) in [
        ("bootstrap user", binding.bootstrap_user_id.as_deref()),
        ("recovery user", binding.recovery_user_id.as_deref()),
        ("runtime user", binding.runtime_user_id.as_deref()),
        ("wallet policy", binding.wallet_policy_id.as_deref()),
        ("signing policy", binding.signing_policy_id.as_deref()),
        (
            "credential lockdown policy",
            binding.credential_lockdown_policy_id.as_deref(),
        ),
    ] {
        Uuid::parse_str(id.ok_or_else(|| anyhow!("active Turnkey binding is missing {label}"))?)
            .with_context(|| format!("active Turnkey binding contains an invalid {label} ID"))?;
    }
    Ok(())
}

fn verify_policy(policy: &TurnkeyPolicy, spec: &RuntimePolicySpec) -> Result<()> {
    Uuid::parse_str(&policy.policy_id).context("Turnkey returned an invalid policy ID")?;
    if policy.effect != spec.effect
        || policy.consensus != spec.consensus
        || policy.condition.as_deref() != Some(spec.condition.as_str())
    {
        bail!(
            "Turnkey policy {:?} differs from the required definition",
            spec.name
        );
    }
    Ok(())
}

fn find_unique_user<'a>(
    users: &'a [TurnkeyUser],
    name: &str,
    label: &str,
) -> Result<&'a TurnkeyUser> {
    let matches = users
        .iter()
        .filter(|user| user.user_name == name)
        .collect::<Vec<_>>();
    let [user] = matches.as_slice() else {
        bail!("Turnkey {label} user is missing or duplicated");
    };
    Uuid::parse_str(&user.user_id)
        .with_context(|| format!("Turnkey {label} user ID is invalid"))?;
    Ok(user)
}

fn find_exact_api_user<'a>(
    users: &'a [TurnkeyUser],
    name: &str,
    public_key: &str,
    label: &str,
) -> Result<&'a TurnkeyUser> {
    let user = find_unique_user(users, name, label)?;
    if user.api_keys.len() != 1
        || !user.api_keys[0]
            .credential
            .as_ref()
            .is_some_and(|credential| credential.public_key.eq_ignore_ascii_case(public_key))
    {
        bail!("Turnkey {label} user has unexpected API credentials");
    }
    Ok(user)
}

fn find_optional_api_user<'a>(
    users: &'a [TurnkeyUser],
    name: &str,
    public_key: &str,
) -> Result<Option<&'a TurnkeyUser>> {
    let named = users
        .iter()
        .filter(|user| user.user_name == name)
        .collect::<Vec<_>>();
    match named.as_slice() {
        [] => {
            if users.iter().any(|user| {
                user.api_keys.iter().any(|key| {
                    key.credential.as_ref().is_some_and(|credential| {
                        credential.public_key.eq_ignore_ascii_case(public_key)
                    })
                })
            }) {
                bail!("Turnkey runtime API key is attached to an unexpected user");
            }
            Ok(None)
        }
        [user] => {
            find_exact_api_user(users, name, public_key, "runtime")?;
            Ok(Some(user))
        }
        _ => bail!("Turnkey runtime user is duplicated"),
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

    #[test]
    fn runtime_policies_are_non_root_minimum_authority() {
        let runtime_user_id = "11111111-1111-1111-1111-111111111111";
        let policies = runtime_policy_specs(runtime_user_id);
        assert_eq!(policies.len(), 3);
        assert_eq!(policies[0].effect, Effect::Allow);
        assert_eq!(
            policies[0].condition,
            "activity.type == 'ACTIVITY_TYPE_CREATE_WALLET'"
        );
        assert_eq!(policies[1].effect, Effect::Allow);
        assert!(policies[1]
            .condition
            .contains("ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2"));
        assert!(policies[1].condition.contains("HASH_FUNCTION_NO_OP"));
        assert!(policies[1]
            .condition
            .contains("PAYLOAD_ENCODING_HEXADECIMAL"));
        assert!(policies[..2].iter().all(|policy| {
            policy
                .consensus
                .as_deref()
                .is_some_and(|consensus| consensus.contains(runtime_user_id))
        }));
        assert_eq!(policies[2].effect, Effect::Deny);
        assert!(policies[2].consensus.is_none());
        assert!(policies[2].condition.contains("'CREDENTIAL'"));
        assert!(!policies[2].condition.contains("ACTIVITY_TYPE_"));
        assert!(!policies
            .iter()
            .any(|policy| policy.condition.contains("EXPORT")));
    }

    #[test]
    fn active_bindings_cannot_retain_bootstrap_secrets() {
        let id = Uuid::new_v4().to_string();
        let mut binding = TurnkeyOrganizationBinding {
            organization_id: Uuid::new_v4(),
            provider_organization_id: Some(Uuid::new_v4().to_string()),
            sub_organization_name: "tenant".into(),
            api_public_key: format!("02{}", "a".repeat(64)),
            api_private_key_encrypted: "encrypted".into(),
            bootstrap_api_public_key: None,
            bootstrap_api_private_key_encrypted: None,
            bootstrap_user_id: Some(id.clone()),
            recovery_user_id: Some(Uuid::new_v4().to_string()),
            runtime_user_id: Some(Uuid::new_v4().to_string()),
            wallet_policy_id: Some(Uuid::new_v4().to_string()),
            signing_policy_id: Some(Uuid::new_v4().to_string()),
            credential_lockdown_policy_id: Some(Uuid::new_v4().to_string()),
            root_hardened_at: Some(Utc::now()),
            status: "active".into(),
            updated_at: Utc::now(),
        };
        assert!(validate_active_binding_metadata(&binding).is_ok());
        binding.bootstrap_api_public_key = Some(format!("03{}", "b".repeat(64)));
        binding.bootstrap_api_private_key_encrypted = Some("encrypted-bootstrap".into());
        assert!(validate_active_binding_metadata(&binding).is_err());
    }
}
