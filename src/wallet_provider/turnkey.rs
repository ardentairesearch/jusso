use super::{validate_external_id, ProviderWallet, WalletProvider, WalletProviderKind};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use ethers::{
    types::{Address, Signature, H256, U256},
    utils::to_checksum,
};
use std::{str::FromStr, sync::Arc, time::Duration};
use turnkey_client::{
    generated::{
        immutable::common::v1::{AddressFormat, Curve, HashFunction, PathFormat, PayloadEncoding},
        services::coordinator::public::v1::{GetWalletAccountsRequest, GetWalletsRequest},
        CreateWalletIntent, SignRawPayloadIntentV2, WalletAccountParams,
    },
    TurnkeyClient, TurnkeyP256ApiKey,
};
use uuid::Uuid;

const DEFAULT_BASE_URL: &str = "https://api.turnkey.com";
const ETHEREUM_BIP44_PATH: &str = "m/44'/60'/0'/0/0";

#[derive(Clone)]
pub struct TurnkeyWalletProvider {
    organization_id: String,
    client: Arc<TurnkeyClient<TurnkeyP256ApiKey>>,
}

impl std::fmt::Debug for TurnkeyWalletProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnkeyWalletProvider")
            .field("organization_id", &self.organization_id)
            .field("client", &self.client)
            .finish()
    }
}

impl TurnkeyWalletProvider {
    pub fn new(
        organization_id: impl Into<String>,
        api_public_key: &str,
        api_private_key: &str,
        base_url: Option<&str>,
    ) -> Result<Self> {
        let organization_id = organization_id.into();
        if organization_id.trim().is_empty() {
            bail!("TURNKEY_ORGANIZATION_ID cannot be empty");
        }
        let base_url = base_url.unwrap_or(DEFAULT_BASE_URL).trim_end_matches('/');
        let parsed = reqwest::Url::parse(base_url).context("invalid TURNKEY_BASE_URL")?;
        if parsed.scheme() != "https"
            && parsed.host_str() != Some("localhost")
            && parsed.host_str() != Some("127.0.0.1")
        {
            bail!("TURNKEY_BASE_URL must use HTTPS outside local development");
        }
        let api_key = TurnkeyP256ApiKey::from_strings(api_private_key, Some(api_public_key))
            .context("invalid Turnkey P-256 API key pair")?;
        let client = TurnkeyClient::builder()
            .api_key(api_key)
            .base_url(base_url)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build Turnkey client")?;
        Ok(Self {
            organization_id,
            client: Arc::new(client),
        })
    }

    async fn resolve_wallet(&self, wallet_id: String, external_id: &str) -> Result<ProviderWallet> {
        let response = self
            .client
            .get_wallet_accounts(GetWalletAccountsRequest {
                organization_id: self.organization_id.clone(),
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

    async fn find_wallet(&self, external_id: &str) -> Result<Option<ProviderWallet>> {
        validate_external_id(external_id)?;
        let response = self
            .client
            .get_wallets(GetWalletsRequest {
                organization_id: self.organization_id.clone(),
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
        self.resolve_wallet(wallet.wallet_id, external_id)
            .await
            .map(Some)
    }

    async fn create_wallet(&self, external_id: &str) -> Result<ProviderWallet> {
        validate_external_id(external_id)?;
        let created = self
            .client
            .create_wallet(
                self.organization_id.clone(),
                self.client.current_timestamp(),
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
            .resolve_wallet(created.result.wallet_id, external_id)
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
        let result = self
            .client
            .sign_raw_payload(
                self.organization_id.clone(),
                self.client.current_timestamp(),
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
        0 | 1 | 27 | 28 => Ok(parsed),
        _ => bail!("Turnkey returned unsupported signature recovery ID {parsed}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_turnkey_signature_formats() {
        assert_eq!(parse_recovery_id("0").unwrap(), 0);
        assert_eq!(parse_recovery_id("01").unwrap(), 1);
        assert_eq!(parse_recovery_id("0x1b").unwrap(), 27);
        assert!(parse_recovery_id("2").is_err());
        assert_eq!(parse_signature_component("0x01", "r").unwrap(), U256::one());
    }

    #[test]
    fn signer_address_uses_the_case_sensitive_checksum_form() {
        let address: Address = "0x4d5d4402fda9322b08311b72772a4459db65b674"
            .parse()
            .unwrap();

        assert_eq!(
            turnkey_sign_with(address),
            "0x4d5d4402FdA9322B08311B72772A4459dB65B674"
        );
    }
}
