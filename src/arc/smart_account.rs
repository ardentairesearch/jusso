//! Dedicated ERC-4337 accounts controlled by tenant-scoped Turnkey signers.
//!
//! A signer address is never used as the agent's Arc deposit or execution
//! address. This registry only provisions and persists account addresses; it
//! does not sign or submit UserOperations.

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use ethers::{
    abi::{decode, encode, ParamType, Token},
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, TransactionRequest, H256, U256},
    utils::keccak256,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::{fmt, sync::Arc, time::Duration};
use uuid::Uuid;

use super::{ArcNetwork, ARC_ENTRY_POINT_V07};
use crate::agent_wallet::AgentWallet;
use crate::wallet_provider::WalletScope;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmartAccount {
    pub address: Address,
    pub signer_address: Address,
    pub provider_account_id: String,
    pub network: ArcNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAccount {
    pub address: Address,
    pub provider_account_id: String,
}

const MAV2_FACTORY: &str = "0x00000000000017c61b5bEe81050EC8eFc9c6fecd";
const SMAV2_BYTECODE_IMPLEMENTATION: &str = "0x000000000000c5A9089039570Dd36455b5C07383";
const ERC1967_IMPLEMENTATION_SLOT: &str =
    "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const SMA_PROXY_RUNTIME_PREFIX: &str = "363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3";

fn validate_deployed_account(
    code: &[u8],
    implementation_slot: H256,
    signer: Address,
    expected_implementation: Address,
) -> Result<()> {
    let mut expected_runtime =
        hex::decode(SMA_PROXY_RUNTIME_PREFIX).expect("fixed proxy runtime prefix");
    expected_runtime.extend_from_slice(signer.as_bytes());
    if code != expected_runtime {
        bail!("deployed smart-account bytecode does not embed the expected owner");
    }
    if Address::from_slice(&implementation_slot.as_bytes()[12..]) != expected_implementation {
        bail!("deployed smart account uses an unexpected implementation");
    }
    Ok(())
}

#[async_trait]
pub trait SmartAccountVerifier: Send + Sync {
    async fn verify(&self, account: Address, signer: Address) -> Result<()>;
}

#[derive(Clone, Debug)]
pub struct AlchemyMav2Verifier {
    provider: Provider<Http>,
}

impl AlchemyMav2Verifier {
    pub fn new(rpc_url: &str) -> Result<Self> {
        if !rpc_url.starts_with("https://")
            && !rpc_url.starts_with("http://localhost")
            && !rpc_url.starts_with("http://127.0.0.1")
        {
            bail!("Arc RPC URL must use HTTPS outside local development");
        }
        Ok(Self {
            provider: Provider::<Http>::try_from(rpc_url).context("invalid Arc RPC URL")?,
        })
    }

    async fn call_address(
        &self,
        contract: Address,
        signature: &str,
        arguments: Vec<Token>,
    ) -> Result<Address> {
        let mut data = keccak256(signature.as_bytes())[..4].to_vec();
        data.extend(encode(&arguments));
        let raw = self
            .provider
            .call(
                &TransactionRequest::new()
                    .to(contract)
                    .data(Bytes::from(data))
                    .into(),
                None,
            )
            .await
            .with_context(|| format!("Arc contract call failed: {signature}"))?;
        let decoded = decode(&[ParamType::Address], &raw)
            .with_context(|| format!("Arc contract returned invalid data: {signature}"))?;
        decoded[0]
            .clone()
            .into_address()
            .context("Arc contract did not return an address")
    }
}

#[async_trait]
impl SmartAccountVerifier for AlchemyMav2Verifier {
    async fn verify(&self, account: Address, signer: Address) -> Result<()> {
        if account == Address::zero() || signer == Address::zero() || account == signer {
            bail!("invalid dedicated smart-account binding");
        }
        let factory: Address = MAV2_FACTORY.parse().expect("fixed MAv2 factory address");
        if self
            .provider
            .get_code(factory, None)
            .await
            .context("MAv2 factory code lookup failed")?
            .is_empty()
        {
            bail!("official MAv2 factory is not deployed on the Arc RPC chain");
        }
        let implementation: Address = SMAV2_BYTECODE_IMPLEMENTATION
            .parse()
            .expect("fixed SMA-B implementation address");
        if self
            .call_address(factory, "SEMI_MODULAR_ACCOUNT_IMPL()", Vec::new())
            .await?
            != implementation
        {
            bail!("MAv2 factory uses an unexpected SMA-B implementation");
        }
        let entry_point: Address = ARC_ENTRY_POINT_V07
            .parse()
            .expect("fixed ERC-4337 EntryPoint address");
        if self
            .call_address(factory, "ENTRY_POINT()", Vec::new())
            .await?
            != entry_point
        {
            bail!("MAv2 factory uses an unexpected EntryPoint");
        }
        let expected = self
            .call_address(
                factory,
                "getAddressSemiModular(address,uint256)",
                vec![Token::Address(signer), Token::Uint(U256::zero())],
            )
            .await?;
        if account != expected {
            bail!("smart-account address does not match the official factory derivation");
        }

        let code = self
            .provider
            .get_code(account, None)
            .await
            .context("smart-account code lookup failed")?;
        if code.is_empty() {
            return Ok(());
        }
        let implementation_slot: H256 = ERC1967_IMPLEMENTATION_SLOT
            .parse()
            .expect("fixed ERC-1967 implementation slot");
        let stored_implementation = self
            .provider
            .get_storage_at(account, implementation_slot, None)
            .await
            .context("smart-account implementation lookup failed")?;
        validate_deployed_account(&code, stored_implementation, signer, implementation)
    }
}

#[async_trait]
pub trait SmartAccountProvider: Send + Sync {
    fn name(&self) -> &'static str;

    async fn get_or_create_dedicated_account(&self, signer: Address) -> Result<ProviderAccount>;
}

#[derive(Clone)]
pub struct AlchemySmartAccountProvider {
    endpoint: reqwest::Url,
    http: reqwest::Client,
}

impl fmt::Debug for AlchemySmartAccountProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlchemySmartAccountProvider")
            .field("endpoint", &"[REDACTED]")
            .finish()
    }
}

impl AlchemySmartAccountProvider {
    pub fn new(api_key: &str) -> Result<Self> {
        if api_key.is_empty()
            || !api_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("ALCHEMY_API_KEY must contain only ASCII letters, digits, '-' or '_'");
        }
        let endpoint = reqwest::Url::parse(&format!("https://api.g.alchemy.com/v2/{api_key}"))
            .context("invalid Alchemy Wallet API endpoint")?;
        Self::with_endpoint(endpoint)
    }

    fn with_endpoint(endpoint: reqwest::Url) -> Result<Self> {
        if endpoint.scheme() != "https"
            && !(endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1")))
        {
            bail!("Alchemy Wallet API endpoint must use HTTPS outside local tests");
        }
        Ok(Self {
            endpoint,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .context("failed to build Alchemy Wallet API client")?,
        })
    }

    async fn request_account(&self, signer: Address) -> Result<ProviderAccount> {
        if signer == Address::zero() {
            bail!("Turnkey signer address cannot be zero");
        }
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "wallet_requestAccount",
            "params": [{
                "signerAddress": format!("{signer:?}"),
                "creationHint": {
                    "accountType": "sma-b",
                    "createAdditional": true
                }
            }]
        });
        let response = self
            .http
            .post(self.endpoint.clone())
            .json(&request)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    anyhow!("Alchemy Wallet API request timed out")
                } else {
                    anyhow!("Alchemy Wallet API transport failed")
                }
            })?;
        if !response.status().is_success() {
            bail!("Alchemy Wallet API returned HTTP {}", response.status());
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| anyhow!("Alchemy Wallet API returned invalid JSON"))?;
        parse_account_response(&body, signer)
    }
}

#[async_trait]
impl SmartAccountProvider for AlchemySmartAccountProvider {
    fn name(&self) -> &'static str {
        "alchemy"
    }

    async fn get_or_create_dedicated_account(&self, signer: Address) -> Result<ProviderAccount> {
        self.request_account(signer).await
    }
}

fn parse_account_response(body: &Value, signer: Address) -> Result<ProviderAccount> {
    if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || body.get("id").and_then(Value::as_u64) != Some(1)
        || body.get("error").is_some()
    {
        bail!("Alchemy Wallet API returned an invalid account response");
    }
    let result = body
        .get("result")
        .context("Alchemy Wallet API omitted the account result")?;
    let address: Address = result
        .get("accountAddress")
        .and_then(Value::as_str)
        .context("Alchemy Wallet API omitted the account address")?
        .parse()
        .context("Alchemy Wallet API returned an invalid account address")?;
    if address == Address::zero() || address == signer {
        bail!("Alchemy Wallet API did not return a dedicated smart-account address");
    }
    let provider_account_id = result
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty() && id.len() <= 128)
        .context("Alchemy Wallet API omitted a valid provider account ID")?
        .to_string();
    Ok(ProviderAccount {
        address,
        provider_account_id,
    })
}

#[derive(Clone)]
pub struct SmartAccountRegistry {
    db_pool: PgPool,
    provider: Arc<dyn SmartAccountProvider>,
    verifier: Arc<dyn SmartAccountVerifier>,
}

impl SmartAccountRegistry {
    pub fn new(
        db_pool: PgPool,
        provider: Arc<dyn SmartAccountProvider>,
        verifier: Arc<dyn SmartAccountVerifier>,
    ) -> Self {
        Self {
            db_pool,
            provider,
            verifier,
        }
    }

    pub async fn get_or_create(
        &self,
        agent_wallet: &AgentWallet,
        network: ArcNetwork,
    ) -> Result<SmartAccount> {
        self.validate_signer_binding(agent_wallet).await?;
        let signer = agent_wallet.managed_wallet.provider_wallet.address;
        if let Some(account) = self.load(agent_wallet.id, signer, network).await? {
            self.verifier.verify(account.address, signer).await?;
            return Ok(account);
        }

        let proposed = self
            .provider
            .get_or_create_dedicated_account(signer)
            .await
            .context("dedicated smart-account provisioning failed")?;
        if proposed.address == Address::zero() || proposed.address == signer {
            bail!("smart-account provider returned the signer instead of a dedicated account");
        }
        if proposed.provider_account_id.trim().is_empty()
            || proposed.provider_account_id.len() > 128
        {
            bail!("smart-account provider returned an invalid account ID");
        }
        self.verifier.verify(proposed.address, signer).await?;
        sqlx::query(
            r#"
            INSERT INTO agent_smart_accounts (
                agent_wallet_id, chain_id, account_address,
                account_provider, provider_account_id
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(agent_wallet.id)
        .bind(network.chain_id() as i64)
        .bind(format!("{:?}", proposed.address))
        .bind(self.provider.name())
        .bind(&proposed.provider_account_id)
        .execute(&self.db_pool)
        .await?;
        let stored = self
            .load(agent_wallet.id, signer, network)
            .await?
            .context("smart account disappeared after provisioning")?;
        if stored.address != proposed.address
            || stored.provider_account_id != proposed.provider_account_id
        {
            bail!("concurrent smart-account provisioning returned conflicting addresses");
        }
        Ok(stored)
    }

    async fn validate_signer_binding(&self, agent_wallet: &AgentWallet) -> Result<()> {
        let expected_scope = WalletScope::Organization(agent_wallet.organization_id);
        if agent_wallet.managed_wallet.provider_wallet.scope != expected_scope {
            bail!("agent signer is not organization-scoped");
        }
        let row: Option<(Uuid, String)> = sqlx::query_as(
            r#"
            SELECT aw.managed_wallet_id, mw.address
            FROM agent_wallets aw
            JOIN managed_wallets mw ON mw.id = aw.managed_wallet_id
            WHERE aw.id = $1 AND aw.organization_id = $2 AND aw.agent_uuid = $3
            "#,
        )
        .bind(agent_wallet.id)
        .bind(agent_wallet.organization_id)
        .bind(agent_wallet.agent_uuid)
        .fetch_optional(&self.db_pool)
        .await?;
        let Some((managed_wallet_id, signer_address)) = row else {
            bail!("agent signer binding is missing");
        };
        if managed_wallet_id != agent_wallet.managed_wallet.id
            || !signer_address.eq_ignore_ascii_case(&format!(
                "{:?}",
                agent_wallet.managed_wallet.provider_wallet.address
            ))
        {
            bail!("agent signer binding differs from the persisted Turnkey wallet");
        }
        Ok(())
    }

    async fn load(
        &self,
        agent_wallet_id: Uuid,
        signer: Address,
        network: ArcNetwork,
    ) -> Result<Option<SmartAccount>> {
        let row: Option<(String, String, String)> = sqlx::query_as(
            r#"
            SELECT account_address, account_provider, provider_account_id
            FROM agent_smart_accounts
            WHERE agent_wallet_id = $1 AND chain_id = $2
            "#,
        )
        .bind(agent_wallet_id)
        .bind(network.chain_id() as i64)
        .fetch_optional(&self.db_pool)
        .await?;
        row.map(|(raw_address, provider, provider_account_id)| {
            if provider != self.provider.name() {
                bail!("persisted smart-account provider differs from runtime provider");
            }
            let address: Address = raw_address
                .parse()
                .context("persisted smart-account address is invalid")?;
            if address == Address::zero() || address == signer {
                bail!("persisted Arc account is not distinct from its signer");
            }
            if provider_account_id.trim().is_empty() || provider_account_id.len() > 128 {
                bail!("persisted smart-account provider ID is invalid");
            }
            Ok(SmartAccount {
                address,
                signer_address: signer,
                provider_account_id,
                network,
            })
        })
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(account: Address, id: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"accountAddress": format!("{account:?}"), "id": id}
        })
    }

    #[test]
    fn rejects_eip7702_and_invalid_account_responses() {
        let signer = Address::from_low_u64_be(1);
        let account = Address::from_low_u64_be(2);
        assert!(parse_account_response(&response(account, "acct-1"), signer).is_ok());
        assert!(parse_account_response(&response(signer, "acct-1"), signer).is_err());
        assert!(parse_account_response(&response(Address::zero(), "acct-1"), signer).is_err());
        assert!(parse_account_response(&response(account, ""), signer).is_err());
        assert!(parse_account_response(
            &json!({"jsonrpc":"2.0","id":1,"error":{"code":-1}}),
            signer
        )
        .is_err());
    }

    #[tokio::test]
    async fn asks_for_a_dedicated_modular_account_not_7702() {
        use axum::{routing::post, Json, Router};
        let signer = Address::from_low_u64_be(1);
        let account = Address::from_low_u64_be(2);
        let app = Router::new().route(
            "/",
            post(move |Json(body): Json<Value>| async move {
                assert_eq!(body["method"], "wallet_requestAccount");
                assert_eq!(body["params"][0]["signerAddress"], format!("{signer:?}"));
                assert_eq!(body["params"][0]["creationHint"]["accountType"], "sma-b");
                assert_eq!(body["params"][0]["creationHint"]["createAdditional"], true);
                Json(response(account, "provider-account-1"))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url =
            reqwest::Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let provider = AlchemySmartAccountProvider::with_endpoint(url).unwrap();
        let actual = provider
            .get_or_create_dedicated_account(signer)
            .await
            .unwrap();
        assert_eq!(actual.address, account);
        assert_eq!(actual.provider_account_id, "provider-account-1");
        server.abort();
    }

    #[test]
    fn redacts_api_key_and_rejects_unsafe_keys() {
        let provider = AlchemySmartAccountProvider::new("test-key_123").unwrap();
        assert!(!format!("{provider:?}").contains("test-key_123"));
        assert!(AlchemySmartAccountProvider::new("bad/key").is_err());
        assert!(AlchemySmartAccountProvider::new("").is_err());
    }

    #[test]
    fn validates_deployed_proxy_owner_and_implementation() {
        let signer = Address::from_low_u64_be(1);
        let implementation: Address = SMAV2_BYTECODE_IMPLEMENTATION.parse().unwrap();
        let mut code = hex::decode(SMA_PROXY_RUNTIME_PREFIX).unwrap();
        code.extend_from_slice(signer.as_bytes());
        let mut slot = [0u8; 32];
        slot[12..].copy_from_slice(implementation.as_bytes());
        assert!(validate_deployed_account(&code, H256(slot), signer, implementation).is_ok());

        let other_signer = Address::from_low_u64_be(2);
        assert!(
            validate_deployed_account(&code, H256(slot), other_signer, implementation).is_err()
        );
        assert!(validate_deployed_account(&code, H256::zero(), signer, implementation).is_err());
    }
}
