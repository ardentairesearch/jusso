//! Minimal, hardened JSON-RPC client for Arc read operations.

use anyhow::{anyhow, bail, Context, Result};
use ethers_core::types::{Address, Bytes, H256, U256};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_RPC_RESPONSE_BYTES: usize = 1_048_576;

#[derive(Clone)]
pub struct ArcRpcClient {
    endpoint: reqwest::Url,
    http: reqwest::Client,
}

impl std::fmt::Debug for ArcRpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArcRpcClient")
            .field("endpoint", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct RpcEnvelope {
    jsonrpc: String,
    id: Value,
    result: Option<Value>,
    error: Option<RpcError>,
}

#[derive(Debug, Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl ArcRpcClient {
    pub fn new(endpoint: &str) -> Result<Self> {
        let endpoint = reqwest::Url::parse(endpoint).context("invalid Arc RPC URL")?;
        let local_http = endpoint.scheme() == "http"
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            );
        if (endpoint.scheme() != "https" && !local_http)
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!("Arc RPC URL must use HTTPS without credentials, query, or fragment outside local development");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(20))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .context("failed to build Arc RPC client")?;
        Ok(Self { endpoint, http })
    }

    pub async fn chain_id(&self) -> Result<U256> {
        self.quantity("eth_chainId", json!([])).await
    }

    pub async fn gas_price(&self) -> Result<U256> {
        self.quantity("eth_gasPrice", json!([])).await
    }

    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        self.quantity("eth_getBalance", json!([format!("{address:?}"), "latest"]))
            .await
    }

    pub async fn get_code(&self, address: Address) -> Result<Bytes> {
        self.bytes("eth_getCode", json!([format!("{address:?}"), "latest"]))
            .await
    }

    pub async fn get_storage_at(&self, address: Address, slot: H256) -> Result<H256> {
        let bytes = self
            .bytes(
                "eth_getStorageAt",
                json!([format!("{address:?}"), format!("{slot:?}"), "latest"]),
            )
            .await?;
        if bytes.len() != 32 {
            bail!("Arc RPC eth_getStorageAt returned {} bytes", bytes.len());
        }
        Ok(H256::from_slice(&bytes))
    }

    pub async fn call(&self, target: Address, data: &[u8]) -> Result<Bytes> {
        self.bytes(
            "eth_call",
            json!([{
                "to": format!("{target:?}"),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )
        .await
    }

    pub async fn transaction_receipt(&self, hash: H256) -> Result<Option<Value>> {
        let value = self
            .request("eth_getTransactionReceipt", json!([format!("{hash:?}")]))
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        if !value.is_object() {
            bail!("Arc RPC eth_getTransactionReceipt returned a non-object receipt");
        }
        Ok(Some(value))
    }

    pub async fn supported_entry_points(&self) -> Result<Vec<Address>> {
        let value = self.request("eth_supportedEntryPoints", json!([])).await?;
        let entries = value
            .as_array()
            .ok_or_else(|| anyhow!("Arc bundler returned a non-array EntryPoint list"))?;
        if entries.len() > 32 {
            bail!("Arc bundler returned too many EntryPoints");
        }
        entries
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .ok_or_else(|| anyhow!("Arc bundler returned a non-string EntryPoint"))?
                    .parse::<Address>()
                    .context("Arc bundler returned an invalid EntryPoint")
            })
            .collect()
    }

    async fn quantity(&self, method: &str, params: Value) -> Result<U256> {
        let value = self.request(method, params).await?;
        let encoded = value
            .as_str()
            .ok_or_else(|| anyhow!("Arc RPC {method} returned a non-string quantity"))?;
        parse_quantity(encoded).with_context(|| format!("Arc RPC {method} returned invalid data"))
    }

    async fn bytes(&self, method: &str, params: Value) -> Result<Bytes> {
        let value = self.request(method, params).await?;
        let encoded = value
            .as_str()
            .ok_or_else(|| anyhow!("Arc RPC {method} returned non-string bytes"))?;
        parse_bytes(encoded).with_context(|| format!("Arc RPC {method} returned invalid data"))
    }

    async fn request(&self, method: &str, params: Value) -> Result<Value> {
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .with_context(|| format!("Arc RPC {method} transport failed"))?
            .error_for_status()
            .with_context(|| format!("Arc RPC {method} returned an HTTP error"))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            bail!("Arc RPC {method} response is too large");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("Arc RPC {method} response body failed"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
                bail!("Arc RPC {method} response is too large");
            }
            body.extend_from_slice(&chunk);
        }
        let envelope: RpcEnvelope = serde_json::from_slice(&body)
            .with_context(|| format!("Arc RPC {method} returned invalid JSON"))?;
        if envelope.jsonrpc != "2.0" || envelope.id != json!(1) {
            bail!("Arc RPC {method} returned a mismatched response envelope");
        }
        if envelope.result.is_some() == envelope.error.is_some() {
            bail!("Arc RPC {method} returned an ambiguous response");
        }
        if let Some(error) = envelope.error {
            bail!(
                "Arc RPC {method} failed: code={}, message={}",
                error.code,
                error.message
            );
        }
        envelope
            .result
            .ok_or_else(|| anyhow!("Arc RPC {method} omitted its result"))
    }
}

fn parse_quantity(value: &str) -> Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("quantity must start with 0x"))?;
    if digits.is_empty() || (digits.len() > 1 && digits.starts_with('0')) {
        bail!("quantity is not minimally encoded");
    }
    U256::from_str_radix(digits, 16).context("quantity exceeds uint256")
}

fn parse_bytes(value: &str) -> Result<Bytes> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("bytes must start with 0x"))?;
    if digits.len() % 2 != 0 {
        bail!("hex byte string must have an even number of digits");
    }
    Ok(Bytes::from(hex::decode(digits)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities_and_bytes_are_canonical() {
        assert_eq!(parse_quantity("0x0").unwrap(), U256::zero());
        assert_eq!(parse_quantity("0x2a").unwrap(), U256::from(42));
        assert!(parse_quantity("0x00").is_err());
        assert!(parse_quantity("2a").is_err());
        assert_eq!(parse_bytes("0x1234").unwrap().as_ref(), &[0x12, 0x34]);
        assert!(parse_bytes("0x123").is_err());
    }

    #[test]
    fn endpoint_validation_rejects_localhost_lookalikes() {
        assert!(ArcRpcClient::new("https://rpc.example").is_ok());
        assert!(ArcRpcClient::new("http://localhost:8545").is_ok());
        assert!(ArcRpcClient::new("http://localhost.attacker.example").is_err());
        assert!(ArcRpcClient::new("https://rpc.example?secret=value").is_err());
    }
}
