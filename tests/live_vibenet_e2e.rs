use std::{env, time::Duration};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ethers::types::{Address, U256};
use jsonwebtoken::{encode, jwk::Jwk, Algorithm, EncodingKey, Header};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use rand::{rngs::OsRng, RngCore};
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, Instant};

const DEFAULT_API_BASE_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_RPC_URL: &str = "https://rpc.vibes.base.org";
const DEFAULT_FAUCET_API_URL: &str = "https://api.vibes.base.org/api/vibenet/faucet";
const DEFAULT_AGENT_ID: &str = "jusso-live-vibenet-e2e";
const MINIMUM_AGENT_TOKEN_BALANCE: u64 = 1_000_000;
const TERMINAL_TIMEOUT: Duration = Duration::from_secs(240);
const BALANCE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone)]
enum Credential {
    ApiKey(String),
    Dpop {
        access_token: String,
        issuer: String,
        signing_key: SigningKey,
    },
}

#[derive(Clone)]
struct Harness {
    http: Client,
    api_base_url: String,
    rpc_url: String,
    faucet_api_url: String,
    credential: Credential,
    admin_token: Option<String>,
    agent_id: String,
}

impl Harness {
    async fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to construct HTTP client")?;
        let api_base_url = env_or("VIBENET_E2E_API_BASE_URL", DEFAULT_API_BASE_URL)
            .trim_end_matches('/')
            .to_string();
        let rpc_url = env_or("VIBENET_E2E_RPC_URL", DEFAULT_RPC_URL);
        let faucet_api_url = env_or("VIBENET_E2E_FAUCET_API_URL", DEFAULT_FAUCET_API_URL)
            .trim_end_matches('/')
            .to_string();
        let admin_token = env::var("VIBENET_E2E_ADMIN_TOKEN")
            .ok()
            .or_else(|| env::var("BOOTSTRAP_ADMIN_TOKEN").ok())
            .filter(|value| !value.is_empty());
        let agent_id = env_or("VIBENET_E2E_AGENT_ID", DEFAULT_AGENT_ID);

        let health = http
            .get(format!("{api_base_url}/health"))
            .send()
            .await
            .context("Jusso API is not reachable")?;
        expect_status(health, StatusCode::OK, "health check").await?;

        let credential = match env::var("VIBENET_E2E_API_KEY")
            .ok()
            .filter(|value| !value.is_empty())
        {
            Some(key) => Credential::ApiKey(key),
            None => register_and_authenticate(&http, &api_base_url, &agent_id).await?,
        };

        Ok(Self {
            http,
            api_base_url,
            rpc_url,
            faucet_api_url,
            credential,
            admin_token,
            agent_id,
        })
    }

    async fn wallet(&self) -> Result<Value> {
        self.api_get(
            "/wallet",
            &[("agent_id", self.agent_id.as_str()), ("chain", "base")],
        )
        .await
    }

    async fn payer_status(&self) -> Result<Value> {
        let token = self.admin_token.as_deref().context(
            "VIBENET_E2E_ADMIN_TOKEN is required to discover and fund the configured payer",
        )?;
        let response = self
            .http
            .get(format!("{}/admin/payer/status", self.api_base_url))
            .bearer_auth(token)
            .send()
            .await?;
        json_response(response, StatusCode::OK, "payer status").await
    }

    async fn api_get(&self, path: &str, query: &[(&str, &str)]) -> Result<Value> {
        let request = self
            .http
            .get(format!("{}{}", self.api_base_url, path))
            .query(query);
        let response = self.authenticate(request, "GET", path)?.send().await?;
        json_response(response, StatusCode::OK, path).await
    }

    async fn simulate(&self, body: &Value) -> Result<Value> {
        let request = self
            .http
            .post(format!("{}/simulate", self.api_base_url))
            .json(body);
        let response = self
            .authenticate(request, "POST", "/simulate")?
            .send()
            .await?;
        json_response(response, StatusCode::OK, "simulation").await
    }

    async fn execute(&self, body: &Value, idempotency_key: &str) -> Result<(StatusCode, Value)> {
        let request = self
            .http
            .post(format!("{}/execute", self.api_base_url))
            .header("Idempotency-Key", idempotency_key)
            .json(body);
        let response = self
            .authenticate(request, "POST", "/execute")?
            .send()
            .await?;
        let status = response.status();
        let value = response
            .json::<Value>()
            .await
            .context("execution response was not JSON")?;
        Ok((status, value))
    }

    fn authenticate(
        &self,
        request: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> Result<reqwest::RequestBuilder> {
        match &self.credential {
            Credential::ApiKey(value) => Ok(request.header("X-API-Key", value)),
            Credential::Dpop {
                access_token,
                issuer,
                signing_key,
            } => Ok(request.bearer_auth(access_token).header(
                "DPoP",
                dpop_proof(
                    method,
                    &format!("{issuer}{path}"),
                    Some(access_token),
                    signing_key,
                )?,
            )),
        }
    }

    async fn wait_for_terminal_status(&self, request_id: &str) -> Result<Value> {
        let started = Instant::now();
        loop {
            let status = self.api_get(&format!("/status/{request_id}"), &[]).await?;
            match status.get("status").and_then(Value::as_str) {
                Some("confirmed" | "failed" | "reverted") => return Ok(status),
                Some(_) if started.elapsed() < TERMINAL_TIMEOUT => {
                    sleep(Duration::from_secs(2)).await
                }
                Some(value) => bail!(
                    "execution {request_id} did not finish within {TERMINAL_TIMEOUT:?}; last status: {value}"
                ),
                None => bail!("status response omitted status: {status}"),
            }
        }
    }

    async fn token_balance(&self, token: Address, owner: Address) -> Result<U256> {
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
        calldata.extend_from_slice(&[0u8; 12]);
        calldata.extend_from_slice(owner.as_bytes());

        let result: String = rpc(
            &self.http,
            &self.rpc_url,
            "eth_call",
            json!([{
                "to": format!("{token:?}"),
                "data": format!("0x{}", hex::encode(calldata))
            }, "latest"]),
        )
        .await?;
        parse_rpc_quantity(&result)
    }

    async fn native_balance(&self, owner: Address) -> Result<U256> {
        let result: String = rpc(
            &self.http,
            &self.rpc_url,
            "eth_getBalance",
            json!([format!("{owner:?}"), "latest"]),
        )
        .await?;
        parse_rpc_quantity(&result)
    }

    async fn faucet(&self, operation: &str, address: Address) -> Result<Value> {
        let response = self
            .http
            .post(format!("{}/{}", self.faucet_api_url, operation))
            .json(&json!({"address": format!("{address:?}")}))
            .send()
            .await?;
        json_response(response, StatusCode::OK, &format!("faucet {operation}")).await
    }

    async fn ensure_agent_usdv(&self, token: Address, agent: Address) -> Result<()> {
        let minimum = U256::from(MINIMUM_AGENT_TOKEN_BALANCE);
        if self.token_balance(token, agent).await? >= minimum {
            return Ok(());
        }
        self.faucet("drip-usdv", agent).await?;
        self.wait_for_balance(
            || self.token_balance(token, agent),
            |balance| balance >= minimum,
            "agent USDV funding",
        )
        .await
    }

    async fn ensure_payer_eth(&self, payer: Address, minimum: U256) -> Result<()> {
        if self.native_balance(payer).await? >= minimum {
            return Ok(());
        }
        self.faucet("drip", payer).await?;
        self.wait_for_balance(
            || self.native_balance(payer),
            |balance| balance >= minimum,
            "payer native funding",
        )
        .await
    }

    async fn wait_for_balance<F, Fut, P>(
        &self,
        mut read: F,
        predicate: P,
        operation: &str,
    ) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<U256>>,
        P: Fn(U256) -> bool,
    {
        let started = Instant::now();
        loop {
            if predicate(read().await?) {
                return Ok(());
            }
            if started.elapsed() >= BALANCE_TIMEOUT {
                bail!("{operation} did not become visible within {BALANCE_TIMEOUT:?}");
            }
            sleep(Duration::from_secs(2)).await;
        }
    }
}

/// Exercises the deployed API, worker, provider-managed native account, configured
/// payer, VibeNet RPC, and the atomic USDV fee path as one black-box flow.
///
/// This is ignored because it creates live provider wallets and VibeNet
/// transactions. Start the local API and worker first, then run:
///
/// `cargo test --test live_vibenet_e2e -- --ignored --nocapture`
#[tokio::test]
#[ignore = "requires a running API, Turnkey credentials, and live VibeNet"]
async fn atomic_usdv_execution_and_idempotency() -> Result<()> {
    let harness = Harness::from_env().await?;
    let wallet = harness.wallet().await?;
    let agent = address_field(&wallet, "smart_wallet_address")?;

    let payer_status = harness.payer_status().await?;
    let payer = address_field(&payer_status, "native_payer")?;
    let execution_token = address_field(&payer_status, "execution_token")?;
    let payer_minimum =
        decimal_u256_field(&payer_status, "native_payer_low_balance_threshold_wei")?;

    harness.ensure_agent_usdv(execution_token, agent).await?;
    harness.ensure_payer_eth(payer, payer_minimum).await?;

    let transfer_amount = U256::one();
    let body = json!({
        "agent_id": harness.agent_id,
        "chain": "base",
        "target_contract": format!("{execution_token:?}"),
        "calldata": erc20_transfer_calldata(payer, transfer_amount),
        "value": "0"
    });

    let simulation = harness.simulate(&body).await?;
    if simulation.get("status").and_then(Value::as_str) != Some("pending") {
        bail!("expected successful simulation, got: {simulation}");
    }
    let simulated_fee = decimal_u256_field(&simulation, "execution_fee_raw")?;
    if simulated_fee.is_zero() {
        bail!("simulation returned a zero execution fee");
    }

    let agent_before = harness.token_balance(execution_token, agent).await?;
    let payer_before = harness.token_balance(execution_token, payer).await?;
    let idempotency_key = format!("vibenet-e2e-{}", uuid::Uuid::new_v4());

    let (status, accepted) = harness.execute(&body, &idempotency_key).await?;
    if status != StatusCode::OK {
        bail!("execution was not accepted (HTTP {status}): {accepted}");
    }
    let request_id = string_field(&accepted, "request_id")?;
    let charged_fee = decimal_u256_field(&accepted, "execution_fee_raw")?;
    let terminal = harness.wait_for_terminal_status(request_id).await?;
    if terminal.get("status").and_then(Value::as_str) != Some("confirmed") {
        bail!("execution did not confirm: {terminal}");
    }
    if terminal.get("tx_hash").and_then(Value::as_str).is_none() {
        bail!("confirmed execution omitted its transaction hash: {terminal}");
    }

    let expected_agent = agent_before
        .checked_sub(charged_fee + transfer_amount)
        .context("agent balance was below the accepted execution charge")?;
    harness
        .wait_for_balance(
            || harness.token_balance(execution_token, agent),
            |balance| balance == expected_agent,
            "agent execution balance",
        )
        .await?;
    let payer_after = harness.token_balance(execution_token, payer).await?;
    if payer_after < payer_before + charged_fee + transfer_amount {
        bail!(
            "payer received less USDV than expected: before={payer_before}, \
             after={payer_after}, fee={charged_fee}, action={transfer_amount}"
        );
    }

    let (replay_status, replay) = harness.execute(&body, &idempotency_key).await?;
    if replay_status != StatusCode::OK || replay.get("request_id") != accepted.get("request_id") {
        bail!("idempotent replay did not return the original request: {replay}");
    }
    sleep(Duration::from_secs(3)).await;
    let agent_after_replay = harness.token_balance(execution_token, agent).await?;
    if agent_after_replay != expected_agent {
        bail!(
            "idempotent replay changed agent balance: expected={expected_agent}, \
             actual={agent_after_replay}"
        );
    }

    let conflicting_body = json!({
        "agent_id": harness.agent_id,
        "chain": "base",
        "target_contract": format!("{execution_token:?}"),
        "calldata": erc20_transfer_calldata(payer, U256::from(2u64)),
        "value": "0"
    });
    let (conflict_status, conflict) = harness.execute(&conflicting_body, &idempotency_key).await?;
    if conflict_status != StatusCode::CONFLICT {
        bail!(
            "changed payload reused an idempotency key without HTTP 409; \
             status={conflict_status}, body={conflict}"
        );
    }

    println!(
        "confirmed request={} tx={} fee_raw={} agent={} payer={}",
        request_id,
        string_field(&terminal, "tx_hash")?,
        charged_fee,
        agent,
        payer
    );
    Ok(())
}

#[derive(Serialize)]
struct ClientAssertion<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
}

async fn register_and_authenticate(
    http: &Client,
    api_base_url: &str,
    agent_id: &str,
) -> Result<Credential> {
    let signing_key = SigningKey::random(&mut OsRng);
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().context("P-256 key omitted x")?),
        "y": URL_SAFE_NO_PAD.encode(point.y().context("P-256 key omitted y")?),
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"]
    });
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let suffix = hex::encode(suffix);

    let response = http
        .post(format!("{api_base_url}/register"))
        .json(&json!({
            "organization_name": format!("Jusso VibeNet E2E {suffix}"),
            "display_name": "VibeNet E2E Agent",
            "agent_id": agent_id,
            "public_jwk": public_jwk,
            "terms_accepted": true
        }))
        .send()
        .await?;
    let registration =
        json_response(response, StatusCode::CREATED, "self-service registration").await?;
    let client_id = string_field(&registration, "client_id")?;

    let metadata_response = http
        .get(format!(
            "{api_base_url}/.well-known/oauth-authorization-server"
        ))
        .send()
        .await?;
    let metadata = json_response(metadata_response, StatusCode::OK, "OAuth metadata").await?;
    let issuer = string_field(&metadata, "issuer")?.to_string();
    let token_endpoint = string_field(&metadata, "token_endpoint")?;

    let now = chrono::Utc::now().timestamp();
    let assertion = ClientAssertion {
        iss: client_id,
        sub: client_id,
        aud: token_endpoint,
        iat: now,
        exp: now + 300,
        jti: uuid::Uuid::new_v4().to_string(),
    };
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode ephemeral OAuth signing key")?;
    let client_assertion = encode(
        &Header::new(Algorithm::ES256),
        &assertion,
        &EncodingKey::from_ec_pem(private_pem.as_bytes())
            .context("failed to load ephemeral OAuth signing key")?,
    )
    .context("failed to sign OAuth client assertion")?;

    let token_response = http
        .post(token_endpoint)
        .header(
            "DPoP",
            dpop_proof("POST", token_endpoint, None, &signing_key)?,
        )
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", client_assertion.as_str()),
        ])
        .send()
        .await?;
    let token = json_response(token_response, StatusCode::OK, "OAuth token exchange").await?;
    Ok(Credential::Dpop {
        access_token: string_field(&token, "access_token")?.to_string(),
        issuer,
        signing_key,
    })
}

#[derive(Serialize)]
struct DpopClaims<'a> {
    jti: String,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

fn dpop_proof(
    method: &str,
    htu: &str,
    access_token: Option<&str>,
    signing_key: &SigningKey,
) -> Result<String> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    let public_jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().context("P-256 key omitted x")?),
        "y": URL_SAFE_NO_PAD.encode(point.y().context("P-256 key omitted y")?),
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"]
    });
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(serde_json::from_value::<Jwk>(public_jwk)?);
    let private_pem = signing_key.to_pkcs8_pem(LineEnding::LF)?;
    Ok(encode(
        &header,
        &DpopClaims {
            jti: uuid::Uuid::new_v4().to_string(),
            htm: method,
            htu,
            iat: chrono::Utc::now().timestamp(),
            ath: access_token.map(|token| URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
        },
        &EncodingKey::from_ec_pem(private_pem.as_bytes())?,
    )?)
}

async fn rpc<T: DeserializeOwned>(
    http: &Client,
    rpc_url: &str,
    method: &str,
    params: Value,
) -> Result<T> {
    let response = http
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
        .send()
        .await
        .with_context(|| format!("RPC {method} request failed"))?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .with_context(|| format!("RPC {method} response was not JSON"))?;
    if !status.is_success() {
        bail!("RPC {method} returned HTTP {status}: {body}");
    }
    if let Some(error) = body.get("error") {
        bail!("RPC {method} failed: {error}");
    }
    serde_json::from_value(
        body.get("result")
            .cloned()
            .with_context(|| format!("RPC {method} omitted result: {body}"))?,
    )
    .with_context(|| format!("RPC {method} returned an unexpected result"))
}

async fn expect_status(response: Response, expected: StatusCode, operation: &str) -> Result<()> {
    let status = response.status();
    if status == expected {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    bail!("{operation} returned HTTP {status}, expected {expected}: {body}");
}

async fn json_response(response: Response, expected: StatusCode, operation: &str) -> Result<Value> {
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("{operation} response body could not be read"))?;
    if status != expected {
        bail!("{operation} returned HTTP {status}, expected {expected}: {body}");
    }
    serde_json::from_str(&body)
        .with_context(|| format!("{operation} response was not JSON: {body}"))
}

fn erc20_transfer_calldata(recipient: Address, amount: U256) -> String {
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(recipient.as_bytes());
    let mut amount_word = [0u8; 32];
    amount.to_big_endian(&mut amount_word);
    data.extend_from_slice(&amount_word);
    format!("0x{}", hex::encode(data))
}

fn address_field(body: &Value, field: &str) -> Result<Address> {
    string_field(body, field)?
        .parse()
        .with_context(|| format!("{field} was not an EVM address: {body}"))
}

fn decimal_u256_field(body: &Value, field: &str) -> Result<U256> {
    U256::from_dec_str(string_field(body, field)?)
        .with_context(|| format!("{field} was not a decimal uint256: {body}"))
}

fn string_field<'a>(body: &'a Value, field: &str) -> Result<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("response omitted string field {field}: {body}"))
}

fn parse_rpc_quantity(value: &str) -> Result<U256> {
    U256::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
        .with_context(|| format!("invalid RPC quantity: {value}"))
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_string())
}
