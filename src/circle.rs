//! Server-side Circle Onramp, Swap, and Earn integration for Arc.
//!
//! Circle supplies short-lived checkout sessions and service-signed adapter
//! instructions. Jusso validates those instructions, then executes them from
//! the agent's ERC-4337 smart account. The Turnkey signer address is never
//! exposed as a funding or execution wallet.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ethers_core::{
    abi::{Function, Param, ParamType, StateMutability, Token},
    types::{Address, U256},
};
use reqwest::{redirect::Policy, Method};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    arc::{
        ArcNetwork, ARC_MAINNET_CIRBTC_ADDRESS, ARC_MAINNET_EURC_ADDRESS,
        ARC_TESTNET_CIRBTC_ADDRESS, ARC_TESTNET_EURC_ADDRESS, ARC_USDC_ADDRESS,
    },
    config::CircleConfig,
    types::BatchCall,
};

pub const CIRCLE_ADAPTER_MAINNET: &str = "0x7FB8c7260b63934d8da38aF902f87ae6e284a845";
pub const CIRCLE_ADAPTER_TESTNET: &str = "0xBBD70b01a1CAbc96d5b7b129Ae1AAabdf50dd40b";
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_SIGNED_INSTRUCTIONS: usize = 16;
const MAX_SIGNED_TOKENS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CircleSwapAsset {
    pub symbol: &'static str,
    pub address: Address,
    pub decimals: u8,
    pub can_convert_to_usdc: bool,
}

#[derive(Clone)]
pub struct CircleClient {
    http: reqwest::Client,
    config: CircleConfig,
}

impl std::fmt::Debug for CircleClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CircleClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FundingSessionRequest {
    /// Optional three-letter fiat currency to preselect, such as USD, EUR, or NGN.
    pub fiat_currency: Option<String>,
    /// Optional fiat amount to prefill. The checkout still requires the user to confirm payment.
    pub fiat_amount: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundingSessionResponse {
    pub provider: &'static str,
    pub checkout_url: String,
    pub wallet_address: String,
    pub asset: &'static str,
    pub network: &'static str,
    pub session_id: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub notice: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwapQuote {
    pub input_token: String,
    pub input_amount_raw: String,
    pub estimated_usdc_raw: String,
    pub minimum_usdc_raw: String,
    pub route_provider: String,
}

#[derive(Debug, Clone)]
pub struct PreparedCircleExecution {
    pub provider_execution_id: String,
    pub calls: Vec<BatchCall>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedInstruction {
    target: String,
    data: String,
    value: Value,
    token_in: String,
    amount_to_approve: Value,
    token_out: String,
    min_token_out: Value,
}

#[derive(Debug, Deserialize)]
struct SignedToken {
    token: String,
    beneficiary: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedExecutionParams {
    instructions: Vec<SignedInstruction>,
    tokens: Vec<SignedToken>,
    exec_id: Value,
    deadline: Value,
    metadata: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignedTransaction {
    signature: String,
    execution_params: SignedExecutionParams,
}

impl CircleClient {
    pub fn new(config: &CircleConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("jusso/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build Circle HTTP client")?;
        Ok(Self {
            http,
            config: config.clone(),
        })
    }

    pub async fn create_onramp_session(
        &self,
        network: ArcNetwork,
        app_user_id: &str,
        wallet_address: &str,
        request: &FundingSessionRequest,
    ) -> Result<FundingSessionResponse> {
        if network != ArcNetwork::Mainnet {
            bail!(
                "Circle Onramp does not provide a public Arc testnet checkout; use the Arc testnet faucet while testing"
            );
        }
        let wallet = normalized_address(wallet_address, "funding wallet")?;
        let currency = request
            .fiat_currency
            .as_deref()
            .unwrap_or("USD")
            .trim()
            .to_ascii_uppercase();
        if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
            bail!("fiat_currency must be a three-letter currency code");
        }
        if let Some(amount) = request.fiat_amount.as_deref() {
            validate_decimal_amount(amount, 2, "fiat_amount")?;
        }
        let trace_id = Uuid::new_v4().to_string();
        let mut body = json!({
            "appUserId": app_user_id,
            "walletAddress": wallet,
            "destinationChain": "Arc",
            "traceId": trace_id,
            "metadata": {"product": "jusso", "network": "arc"}
        });
        let object = body.as_object_mut().expect("onramp body is an object");
        object.insert("currency".into(), Value::String(currency));
        if let Some(amount) = request.fiat_amount.as_deref() {
            object.insert("amount".into(), Value::String(amount.trim().into()));
        }
        let response = self
            .request_json_at(
                &self.config.api_base_url,
                Method::POST,
                "/v1/stablecoinKits/sessions",
                Some(&body),
                &[],
            )
            .await?;
        let data = unwrap_data(&response);
        let session_token = required_string(data, "sessionToken")?;
        let expires_at = DateTime::parse_from_rfc3339(required_string(data, "expiresAt")?)
            .context("Circle Onramp returned an invalid expiry")?
            .with_timezone(&Utc);
        if expires_at <= Utc::now() {
            bail!("Circle Onramp returned an expired session");
        }
        let mut checkout = reqwest::Url::parse(&self.config.onramp_widget_url)?;
        checkout
            .query_pairs_mut()
            .append_pair("sessionToken", session_token)
            .append_pair("tokens", "USDC")
            .append_pair("chains", "arc");
        Ok(FundingSessionResponse {
            provider: "circle_onramp",
            checkout_url: checkout.into(),
            wallet_address: wallet,
            asset: "USDC",
            network: network.name(),
            session_id: optional_string(data, "sessionId").map(str::to_owned),
            expires_at,
            notice: "Circle handles payment methods, quotes, fees, identity checks, limits, and settlement. Opening this checkout does not authorize a debit.",
        })
    }

    pub async fn quote_swap_to_usdc(
        &self,
        network: ArcNetwork,
        wallet: Address,
        token_in: Address,
        amount_raw: U256,
        slippage_bps: u16,
    ) -> Result<SwapQuote> {
        validate_slippage(slippage_bps)?;
        if token_in == ARC_USDC_ADDRESS {
            bail!("the selected asset is already USDC");
        }
        if amount_raw.is_zero() {
            bail!("swap amount must be greater than zero");
        }
        let chain = swap_chain(network);
        let wallet = format!("{wallet:?}");
        let token_in_string = format!("{token_in:?}");
        let usdc = format!("{ARC_USDC_ADDRESS:?}");
        let amount = amount_raw.to_string();
        let slippage = slippage_bps.to_string();
        let query = [
            ("tokenInAddress", token_in_string.as_str()),
            ("tokenInChain", chain),
            ("tokenOutAddress", usdc.as_str()),
            ("tokenOutChain", chain),
            ("fromAddress", wallet.as_str()),
            ("toAddress", wallet.as_str()),
            ("amount", amount.as_str()),
            ("slippageBps", slippage.as_str()),
        ];
        let response = self
            .request_json(Method::GET, "/v1/stablecoinKits/quote", None, &query)
            .await?;
        let quote = response
            .get("quote")
            .and_then(Value::as_object)
            .context("Circle Swap response is missing quote")?;
        let estimated = parse_u256_value(
            quote
                .get("estimatedAmount")
                .context("missing estimatedAmount")?,
            "estimatedAmount",
        )?;
        let minimum = parse_u256_value(
            quote.get("minAmount").context("missing minAmount")?,
            "minAmount",
        )?;
        if estimated.is_zero() || minimum.is_zero() || minimum > estimated {
            bail!("Circle Swap returned invalid output amounts");
        }
        let route_provider = quote
            .get("route")
            .and_then(|route| route.get("provider"))
            .and_then(Value::as_str)
            .filter(|provider| !provider.is_empty())
            .context("Circle Swap response is missing route provider")?
            .to_string();
        Ok(SwapQuote {
            input_token: token_in_string,
            input_amount_raw: amount,
            estimated_usdc_raw: estimated.to_string(),
            minimum_usdc_raw: minimum.to_string(),
            route_provider,
        })
    }

    pub async fn prepare_swap_to_usdc(
        &self,
        network: ArcNetwork,
        wallet: Address,
        token_in: Address,
        amount_raw: U256,
        slippage_bps: u16,
        quote: &SwapQuote,
    ) -> Result<PreparedCircleExecution> {
        validate_slippage(slippage_bps)?;
        let chain = swap_chain(network);
        let wallet_string = format!("{wallet:?}");
        let token_in_string = format!("{token_in:?}");
        let usdc = format!("{ARC_USDC_ADDRESS:?}");
        let body = json!({
            "tokenInAddress": token_in_string,
            "tokenInChain": chain,
            "tokenOutAddress": usdc,
            "tokenOutChain": chain,
            "fromAddress": wallet_string,
            "toAddress": wallet_string,
            "amount": amount_raw.to_string(),
            "stopLimit": quote.minimum_usdc_raw,
            "slippageBps": slippage_bps
        });
        let response = self
            .request_json(Method::POST, "/v1/stablecoinKits/swap", Some(&body), &[])
            .await?;
        assert_string_eq(&response, "tokenInAddress", &token_in_string)?;
        assert_string_eq(&response, "tokenInChain", chain)?;
        assert_string_eq(&response, "tokenOutAddress", &usdc)?;
        assert_string_eq(&response, "tokenOutChain", chain)?;
        assert_string_eq(&response, "fromAddress", &wallet_string)?;
        assert_string_eq(&response, "toAddress", &wallet_string)?;
        if parse_u256_value(
            response
                .get("amount")
                .context("Circle Swap response is missing amount")?,
            "amount",
        )? != amount_raw
        {
            bail!("Circle Swap response changed the input amount");
        }
        let minimum = parse_u256_value(
            response
                .get("stopLimit")
                .context("Circle Swap response is missing stopLimit")?,
            "stopLimit",
        )?;
        if minimum < U256::from_dec_str(&quote.minimum_usdc_raw)? {
            bail!("Circle Swap response weakened the quoted minimum output");
        }
        let transaction: SignedTransaction = serde_json::from_value(
            response
                .get("transaction")
                .cloned()
                .context("Circle Swap response is missing transaction")?,
        )
        .context("Circle Swap returned malformed signed instructions")?;
        let mut calls = vec![approval_call(
            token_in,
            circle_adapter(network),
            U256::zero(),
        )];
        calls.push(approval_call(token_in, circle_adapter(network), amount_raw));
        let (provider_execution_id, execute_call) = compile_signed_execute(
            network,
            wallet,
            transaction,
            &[(token_in, amount_raw)],
            Some(ARC_USDC_ADDRESS),
        )?;
        calls.push(execute_call);
        Ok(PreparedCircleExecution {
            provider_execution_id,
            calls,
        })
    }

    pub async fn explore_earn_vaults(&self, network: ArcNetwork) -> Result<Value> {
        let query = [
            ("chain", earn_chain(network)),
            ("asset", "USDC"),
            ("sortBy", "tvl"),
            ("page", "1"),
            ("pageSize", "100"),
        ];
        let response = self
            .request_json(Method::GET, "/v1/earnKit/vaults/explore", None, &query)
            .await?;
        Ok(unwrap_data(&response).clone())
    }

    pub async fn earn_position(
        &self,
        network: ArcNetwork,
        wallet: Address,
        vault: Address,
    ) -> Result<Value> {
        let path = format!("/v1/earnKit/position/{wallet:?}");
        let vault = format!("{vault:?}");
        let query = [
            ("chain", earn_chain(network)),
            ("vaultAddress", vault.as_str()),
        ];
        let response = self.request_json(Method::GET, &path, None, &query).await?;
        Ok(unwrap_data(&response).clone())
    }

    pub async fn earn_quote(
        &self,
        network: ArcNetwork,
        wallet: Address,
        vault: Address,
        amount: &str,
        withdrawal: bool,
    ) -> Result<Value> {
        validate_decimal_amount(amount, 6, "amount")?;
        let body = json!({
            "vaultAddress": format!("{vault:?}"),
            "amount": amount.trim(),
            "address": format!("{wallet:?}"),
            "chain": earn_chain(network)
        });
        let path = if withdrawal {
            "/v1/earnKit/withdrawal/quote"
        } else {
            "/v1/earnKit/deposit/quote"
        };
        let response = self
            .request_json(Method::POST, path, Some(&body), &[])
            .await?;
        Ok(unwrap_data(&response).clone())
    }

    pub async fn prepare_earn(
        &self,
        network: ArcNetwork,
        wallet: Address,
        vault: Address,
        amount: &str,
        withdrawal: bool,
    ) -> Result<PreparedCircleExecution> {
        validate_decimal_amount(amount, 6, "amount")?;
        let body = json!({
            "vaultAddress": format!("{vault:?}"),
            "amount": amount.trim(),
            "address": format!("{wallet:?}"),
            "chain": earn_chain(network)
        });
        let path = if withdrawal {
            "/v1/earnKit/withdraw"
        } else {
            "/v1/earnKit/deposit"
        };
        let response = self
            .request_json(Method::POST, path, Some(&body), &[])
            .await?;
        let data = unwrap_data(&response);
        let provider_execution_id = required_string(data, "execId")?.to_string();
        Uuid::parse_str(&provider_execution_id)
            .context("Circle Earn returned an invalid execution ID")?;
        let transaction = SignedTransaction {
            signature: required_string(data, "signature")?.to_string(),
            execution_params: serde_json::from_value(
                data.get("executionParams")
                    .cloned()
                    .context("Circle Earn response is missing executionParams")?,
            )
            .context("Circle Earn returned malformed signed instructions")?,
        };
        let expected_approval_token = if withdrawal { vault } else { ARC_USDC_ADDRESS };
        let expected_output_token = if withdrawal { ARC_USDC_ADDRESS } else { vault };
        let (execute_call, approval_amount) = compile_earn_execute(
            network,
            wallet,
            transaction,
            expected_approval_token,
            expected_output_token,
        )?;
        let mut calls = Vec::new();
        if !approval_amount.is_zero() {
            calls.push(approval_call(
                expected_approval_token,
                circle_adapter(network),
                U256::zero(),
            ));
            calls.push(approval_call(
                expected_approval_token,
                circle_adapter(network),
                approval_amount,
            ));
        }
        calls.push(execute_call);
        Ok(PreparedCircleExecution {
            provider_execution_id,
            calls,
        })
    }

    async fn request_json(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        query: &[(&str, &str)],
    ) -> Result<Value> {
        self.request_json_at(&self.config.api_base_url, method, path, body, query)
            .await
    }

    async fn request_json_at(
        &self,
        base_url: &str,
        method: Method,
        path: &str,
        body: Option<&Value>,
        query: &[(&str, &str)],
    ) -> Result<Value> {
        let mut url = reqwest::Url::parse(base_url)?;
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        for attempt in 0..3u64 {
            let mut request = self
                .http
                .request(method.clone(), url.clone())
                .bearer_auth(&self.config.api_key)
                .header(reqwest::header::ACCEPT, "application/json");
            if path == "/v1/stablecoinKits/sessions" {
                request = request.header(
                    "x-circle-sdk-user-agent",
                    concat!("jusso/", env!("CARGO_PKG_VERSION")),
                );
            } else if path.starts_with("/v1/earnKit/") {
                request = request.header(
                    "X-EarnKit-SDK-Version",
                    concat!("jusso/", env!("CARGO_PKG_VERSION")),
                );
            }
            if let Some(body) = body {
                request = request.json(body);
            }
            let mut response = match request.send().await {
                Ok(response) => response,
                Err(error) if attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt + 1))).await;
                    tracing::warn!(attempt = attempt + 1, %error, "retrying Circle API request");
                    continue;
                }
                Err(error) => return Err(error).context("Circle API request failed"),
            };
            let status = response.status();
            if response
                .content_length()
                .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
            {
                bail!("Circle API response exceeded the supported size");
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .context("Circle API response failed")?
            {
                if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    bail!("Circle API response exceeded the supported size");
                }
                bytes.extend_from_slice(&chunk);
            }
            let value: Value =
                serde_json::from_slice(&bytes).context("Circle API returned invalid JSON")?;
            if !status.is_success() {
                if attempt < 2
                    && (status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        || status.is_server_error())
                {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt + 1))).await;
                    continue;
                }
                bail!(
                    "Circle API returned {}: {}",
                    status.as_u16(),
                    circle_error_message(&value)
                );
            }
            return Ok(value);
        }
        unreachable!("Circle request attempts always return or continue")
    }
}

fn compile_earn_execute(
    network: ArcNetwork,
    wallet: Address,
    transaction: SignedTransaction,
    expected_approval_token: Address,
    expected_output_token: Address,
) -> Result<(BatchCall, U256)> {
    let mut total = U256::zero();
    let mut token_inputs = Vec::new();
    for instruction in &transaction.execution_params.instructions {
        let amount = parse_u256_value(&instruction.amount_to_approve, "amountToApprove")?;
        if amount.is_zero() {
            continue;
        }
        let token = parse_address(&instruction.token_in, "tokenIn")?;
        if token != expected_approval_token {
            bail!("Circle Earn requested approval for an unexpected token");
        }
        total = total
            .checked_add(amount)
            .context("Circle Earn approval amount overflow")?;
        token_inputs.push((token, amount));
    }
    let (_, call) = compile_signed_execute(
        network,
        wallet,
        transaction,
        &token_inputs,
        Some(expected_output_token),
    )?;
    Ok((call, total))
}

fn compile_signed_execute(
    network: ArcNetwork,
    wallet: Address,
    transaction: SignedTransaction,
    token_inputs: &[(Address, U256)],
    expected_output_token: Option<Address>,
) -> Result<(String, BatchCall)> {
    let params = transaction.execution_params;
    if params.instructions.is_empty() || params.instructions.len() > MAX_SIGNED_INSTRUCTIONS {
        bail!("Circle returned an unsupported instruction count");
    }
    if params.tokens.len() > MAX_SIGNED_TOKENS {
        bail!("Circle returned too many beneficiary tokens");
    }
    let exec_id = parse_u256_value(&params.exec_id, "execId")?;
    let deadline = parse_u256_value(&params.deadline, "deadline")?;
    let now = U256::from(Utc::now().timestamp().max(0) as u64);
    if deadline <= now || deadline > now + U256::from(3600u64) {
        bail!("Circle signed instruction deadline is expired or unreasonably distant");
    }
    let metadata = parse_hex(&params.metadata, "metadata", 16 * 1024)?;
    let signature = parse_hex(&transaction.signature, "signature", 1024)?;
    if signature.is_empty() {
        bail!("Circle signature cannot be empty");
    }
    let mut instruction_tokens = Vec::with_capacity(params.instructions.len());
    let mut signed_inputs = std::collections::BTreeMap::<Address, U256>::new();
    let mut instruction_returns_expected_output = expected_output_token.is_none();
    for instruction in params.instructions {
        let target = parse_nonzero_address(&instruction.target, "instruction target")?;
        let data = parse_hex(&instruction.data, "instruction data", 128 * 1024)?;
        let value = parse_u256_value(&instruction.value, "instruction value")?;
        if !value.is_zero() {
            bail!("Circle instructions requested unsupported native-value forwarding");
        }
        let token_in = parse_address(&instruction.token_in, "instruction tokenIn")?;
        let amount_to_approve = parse_u256_value(
            &instruction.amount_to_approve,
            "instruction amountToApprove",
        )?;
        let token_out = parse_address(&instruction.token_out, "instruction tokenOut")?;
        let min_token_out =
            parse_u256_value(&instruction.min_token_out, "instruction minTokenOut")?;
        if !amount_to_approve.is_zero() {
            let total = signed_inputs.entry(token_in).or_default();
            *total = total
                .checked_add(amount_to_approve)
                .context("Circle instruction approval amount overflow")?;
        }
        if expected_output_token.is_some_and(|expected| token_out == expected) {
            instruction_returns_expected_output = true;
        }
        instruction_tokens.push(Token::Tuple(vec![
            Token::Address(target),
            Token::Bytes(data),
            Token::Uint(value),
            Token::Address(token_in),
            Token::Uint(amount_to_approve),
            Token::Address(token_out),
            Token::Uint(min_token_out),
        ]));
    }
    let mut expected_inputs = std::collections::BTreeMap::<Address, U256>::new();
    for (token, amount) in token_inputs {
        if amount.is_zero() {
            bail!("Circle token input amount cannot be zero");
        }
        let total = expected_inputs.entry(*token).or_default();
        *total = total
            .checked_add(*amount)
            .context("Circle token input amount overflow")?;
    }
    if signed_inputs != expected_inputs {
        bail!("Circle instructions changed the authorized token input or amount");
    }
    let mut beneficiary_tokens = Vec::with_capacity(params.tokens.len());
    // Some Earn instructions send shares directly and therefore do not need
    // the adapter's final token sweep. When a sweep list is present, every
    // beneficiary must be the agent and it must include the expected asset.
    let mut found_expected_output = expected_output_token.is_none();
    for token in params.tokens {
        let output_token = parse_address(&token.token, "beneficiary token")?;
        let beneficiary = parse_address(&token.beneficiary, "token beneficiary")?;
        if beneficiary != wallet {
            bail!("Circle instructions attempted to send proceeds outside the agent wallet");
        }
        if expected_output_token.is_some_and(|expected| expected == output_token) {
            found_expected_output = true;
        }
        beneficiary_tokens.push(Token::Tuple(vec![
            Token::Address(output_token),
            Token::Address(beneficiary),
        ]));
    }
    if !found_expected_output && !instruction_returns_expected_output {
        bail!("Circle instructions do not return the expected asset to the agent wallet");
    }
    let token_inputs = token_inputs
        .iter()
        .map(|(token, amount)| {
            Token::Tuple(vec![
                Token::Uint(U256::zero()),
                Token::Address(*token),
                Token::Uint(*amount),
                Token::Bytes(Vec::new()),
            ])
        })
        .collect::<Vec<_>>();
    let function = circle_adapter_execute_function();
    let calldata = function.encode_input(&[
        Token::Tuple(vec![
            Token::Array(instruction_tokens),
            Token::Array(beneficiary_tokens),
            Token::Uint(exec_id),
            Token::Uint(deadline),
            Token::Bytes(metadata),
        ]),
        Token::Array(token_inputs),
        Token::Bytes(signature),
    ])?;
    Ok((
        exec_id.to_string(),
        BatchCall {
            target_contract: format!("{:?}", circle_adapter(network)),
            calldata: format!("0x{}", hex::encode(calldata)),
            value: "0".into(),
        },
    ))
}

#[allow(deprecated)]
fn circle_adapter_execute_function() -> Function {
    let instruction = ParamType::Tuple(vec![
        ParamType::Address,
        ParamType::Bytes,
        ParamType::Uint(256),
        ParamType::Address,
        ParamType::Uint(256),
        ParamType::Address,
        ParamType::Uint(256),
    ]);
    let beneficiary = ParamType::Tuple(vec![ParamType::Address, ParamType::Address]);
    let execution_params = ParamType::Tuple(vec![
        ParamType::Array(Box::new(instruction)),
        ParamType::Array(Box::new(beneficiary)),
        ParamType::Uint(256),
        ParamType::Uint(256),
        ParamType::Bytes,
    ]);
    let token_input = ParamType::Tuple(vec![
        ParamType::Uint(8),
        ParamType::Address,
        ParamType::Uint(256),
        ParamType::Bytes,
    ]);
    Function {
        name: "execute".into(),
        inputs: vec![
            Param {
                name: "executionParams".into(),
                kind: execution_params,
                internal_type: None,
            },
            Param {
                name: "tokenInputs".into(),
                kind: ParamType::Array(Box::new(token_input)),
                internal_type: None,
            },
            Param {
                name: "signature".into(),
                kind: ParamType::Bytes,
                internal_type: None,
            },
        ],
        outputs: Vec::new(),
        constant: None,
        state_mutability: StateMutability::Payable,
    }
}

fn approval_call(token: Address, spender: Address, amount: U256) -> BatchCall {
    let mut calldata = vec![0x09, 0x5e, 0xa7, 0xb3];
    calldata.extend(ethers_core::abi::encode(&[
        Token::Address(spender),
        Token::Uint(amount),
    ]));
    BatchCall {
        target_contract: format!("{token:?}"),
        calldata: format!("0x{}", hex::encode(calldata)),
        value: "0".into(),
    }
}

pub fn circle_adapter(network: ArcNetwork) -> Address {
    match network {
        ArcNetwork::Mainnet => CIRCLE_ADAPTER_MAINNET,
        ArcNetwork::Testnet => CIRCLE_ADAPTER_TESTNET,
    }
    .parse()
    .expect("fixed Circle adapter address")
}

pub fn resolve_swap_token(network: ArcNetwork, value: &str) -> Result<Address> {
    match value.trim().to_ascii_uppercase().as_str() {
        "USDC" => Ok(ARC_USDC_ADDRESS),
        "EURC" => match network {
            ArcNetwork::Mainnet => ARC_MAINNET_EURC_ADDRESS,
            ArcNetwork::Testnet => ARC_TESTNET_EURC_ADDRESS,
        }
        .parse()
        .context("fixed EURC address is invalid"),
        "CIRBTC" => match network {
            ArcNetwork::Mainnet => ARC_MAINNET_CIRBTC_ADDRESS,
            ArcNetwork::Testnet => ARC_TESTNET_CIRBTC_ADDRESS,
        }
        .parse()
        .context("fixed cirBTC address is invalid"),
        _ => parse_nonzero_address(value.trim(), "token"),
    }
}

pub fn arc_swap_assets(network: ArcNetwork) -> Result<[CircleSwapAsset; 3]> {
    let eurc = resolve_swap_token(network, "EURC")?;
    let cirbtc = resolve_swap_token(network, "cirBTC")?;
    Ok([
        CircleSwapAsset {
            symbol: "USDC",
            address: ARC_USDC_ADDRESS,
            decimals: 6,
            can_convert_to_usdc: false,
        },
        CircleSwapAsset {
            symbol: "EURC",
            address: eurc,
            decimals: 6,
            can_convert_to_usdc: true,
        },
        CircleSwapAsset {
            symbol: "cirBTC",
            address: cirbtc,
            decimals: 8,
            can_convert_to_usdc: true,
        },
    ])
}

pub fn parse_token_amount(value: &str, decimals: u8) -> Result<U256> {
    validate_decimal_amount(value, decimals, "amount")?;
    let value = value.trim();
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    let mut raw = whole.to_string();
    raw.push_str(fraction);
    raw.extend(std::iter::repeat_n('0', decimals as usize - fraction.len()));
    let parsed =
        U256::from_dec_str(raw.trim_start_matches('0')).or_else(|_| U256::from_dec_str("0"))?;
    if parsed.is_zero() {
        bail!("amount must be greater than zero");
    }
    Ok(parsed)
}

pub fn format_token_amount(raw: U256, decimals: u8) -> String {
    ethers_core::utils::format_units(raw, decimals as usize).unwrap_or_else(|_| raw.to_string())
}

fn swap_chain(network: ArcNetwork) -> &'static str {
    match network {
        ArcNetwork::Mainnet => "Arc",
        ArcNetwork::Testnet => "Arc_Testnet",
    }
}

fn earn_chain(network: ArcNetwork) -> &'static str {
    match network {
        ArcNetwork::Mainnet => "ARC",
        ArcNetwork::Testnet => "ARC-TESTNET",
    }
}

fn validate_slippage(value: u16) -> Result<()> {
    if !(10..=500).contains(&value) {
        bail!("swap price tolerance must be between 0.10% and 5.00%");
    }
    Ok(())
}

fn validate_decimal_amount(value: &str, max_decimals: u8, name: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() || value.len() > 80 || value.starts_with('-') || value.starts_with('+') {
        bail!("{name} must be a positive decimal amount");
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|part| {
            part.is_empty()
                || part.len() > max_decimals as usize
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
        || !value.bytes().any(|byte| matches!(byte, b'1'..=b'9'))
    {
        bail!("{name} must be greater than zero with at most {max_decimals} decimal places");
    }
    Ok(())
}

fn unwrap_data(value: &Value) -> &Value {
    value
        .get("data")
        .filter(|data| data.is_object())
        .unwrap_or(value)
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    optional_string(value, field)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("Circle response is missing {field}"))
}

fn optional_string<'a>(value: &'a Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(Value::as_str)
}

fn assert_string_eq(value: &Value, field: &str, expected: &str) -> Result<()> {
    let actual = required_string(value, field)?;
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("Circle response changed {field}");
    }
    Ok(())
}

fn parse_u256_value(value: &Value, field: &str) -> Result<U256> {
    match value {
        Value::String(value) => {
            U256::from_dec_str(value).with_context(|| format!("Circle returned invalid {field}"))
        }
        Value::Number(value) if value.is_u64() => {
            Ok(U256::from(value.as_u64().unwrap_or_default()))
        }
        _ => bail!("Circle returned invalid {field}"),
    }
}

fn normalized_address(value: &str, field: &str) -> Result<String> {
    Ok(format!("{:?}", parse_nonzero_address(value, field)?))
}

fn parse_address(value: &str, field: &str) -> Result<Address> {
    value
        .parse::<Address>()
        .with_context(|| format!("Circle returned invalid {field}"))
}

fn parse_nonzero_address(value: &str, field: &str) -> Result<Address> {
    let address = value
        .parse::<Address>()
        .with_context(|| format!("{field} must be an EVM address"))?;
    if address == Address::zero() {
        bail!("{field} cannot be the zero address");
    }
    Ok(address)
}

fn parse_hex(value: &str, field: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .with_context(|| format!("Circle returned non-hex {field}"))?;
    if value.len() % 2 != 0 || value.len() / 2 > max_bytes {
        bail!("Circle returned invalid or oversized {field}");
    }
    hex::decode(value).with_context(|| format!("Circle returned invalid {field}"))
}

fn circle_error_message(value: &Value) -> String {
    ["message", "error_description", "error"]
        .into_iter()
        .find_map(|field| value.get(field).and_then(Value::as_str))
        .map(|message| message.chars().take(300).collect())
        .unwrap_or_else(|| "request was rejected".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_amounts_are_strict_and_exact() {
        assert_eq!(
            parse_token_amount("12.34", 6).unwrap(),
            U256::from(12_340_000u64)
        );
        assert!(parse_token_amount("1e3", 6).is_err());
        assert!(parse_token_amount("0", 6).is_err());
        assert!(parse_token_amount("1.0000001", 6).is_err());
        assert_eq!(
            resolve_swap_token(ArcNetwork::Testnet, "EURC").unwrap(),
            ARC_TESTNET_EURC_ADDRESS.parse::<Address>().unwrap()
        );
        assert_eq!(
            resolve_swap_token(ArcNetwork::Mainnet, "EURC").unwrap(),
            ARC_MAINNET_EURC_ADDRESS.parse::<Address>().unwrap()
        );
        let testnet_assets = arc_swap_assets(ArcNetwork::Testnet).unwrap();
        assert_eq!(
            testnet_assets
                .iter()
                .map(|asset| asset.symbol)
                .collect::<Vec<_>>(),
            vec!["USDC", "EURC", "cirBTC"]
        );
        assert_eq!(testnet_assets[2].decimals, 8);
        assert_eq!(
            testnet_assets[2].address,
            ARC_TESTNET_CIRBTC_ADDRESS.parse::<Address>().unwrap()
        );
    }

    #[test]
    fn adapter_execute_encoding_accepts_service_shape() {
        let wallet: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token: Address = ARC_TESTNET_EURC_ADDRESS.parse().unwrap();
        let deadline = (Utc::now().timestamp() + 300).to_string();
        let transaction = SignedTransaction {
            signature: format!("0x{}", "11".repeat(65)),
            execution_params: SignedExecutionParams {
                instructions: vec![SignedInstruction {
                    target: "0x0000000000000000000000000000000000000002".into(),
                    data: "0x1234".into(),
                    value: json!("0"),
                    token_in: format!("{token:?}"),
                    amount_to_approve: json!("1000000"),
                    token_out: format!("{ARC_USDC_ADDRESS:?}"),
                    min_token_out: json!("900000"),
                }],
                tokens: vec![SignedToken {
                    token: format!("{ARC_USDC_ADDRESS:?}"),
                    beneficiary: format!("{wallet:?}"),
                }],
                exec_id: json!("42"),
                deadline: json!(deadline),
                metadata: "0x".into(),
            },
        };
        let (_, call) = compile_signed_execute(
            ArcNetwork::Testnet,
            wallet,
            transaction,
            &[(token, U256::from(1_000_000u64))],
            Some(ARC_USDC_ADDRESS),
        )
        .unwrap();
        assert!(call.calldata.starts_with("0x"));
        assert!(call.calldata.len() > 10);
        assert_eq!(
            call.target_contract,
            CIRCLE_ADAPTER_TESTNET.to_ascii_lowercase()
        );
    }

    #[test]
    fn execute_encoding_rejects_redirected_proceeds() {
        let wallet: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let transaction = SignedTransaction {
            signature: "0x11".into(),
            execution_params: SignedExecutionParams {
                instructions: vec![SignedInstruction {
                    target: "0x0000000000000000000000000000000000000002".into(),
                    data: "0x".into(),
                    value: json!("0"),
                    token_in: format!("{ARC_USDC_ADDRESS:?}"),
                    amount_to_approve: json!("0"),
                    token_out: format!("{ARC_USDC_ADDRESS:?}"),
                    min_token_out: json!("0"),
                }],
                tokens: vec![SignedToken {
                    token: format!("{ARC_USDC_ADDRESS:?}"),
                    beneficiary: "0x0000000000000000000000000000000000000003".into(),
                }],
                exec_id: json!("1"),
                deadline: json!((Utc::now().timestamp() + 300).to_string()),
                metadata: "0x".into(),
            },
        };
        assert!(compile_signed_execute(
            ArcNetwork::Testnet,
            wallet,
            transaction,
            &[],
            Some(ARC_USDC_ADDRESS)
        )
        .is_err());
    }

    #[test]
    fn execute_encoding_rejects_changed_token_input() {
        let wallet: Address = "0x0000000000000000000000000000000000000001"
            .parse()
            .unwrap();
        let token: Address = ARC_TESTNET_EURC_ADDRESS.parse().unwrap();
        let transaction = SignedTransaction {
            signature: "0x11".into(),
            execution_params: SignedExecutionParams {
                instructions: vec![SignedInstruction {
                    target: "0x0000000000000000000000000000000000000002".into(),
                    data: "0x".into(),
                    value: json!("0"),
                    token_in: format!("{token:?}"),
                    amount_to_approve: json!("1000001"),
                    token_out: format!("{ARC_USDC_ADDRESS:?}"),
                    min_token_out: json!("900000"),
                }],
                tokens: vec![SignedToken {
                    token: format!("{ARC_USDC_ADDRESS:?}"),
                    beneficiary: format!("{wallet:?}"),
                }],
                exec_id: json!("2"),
                deadline: json!((Utc::now().timestamp() + 300).to_string()),
                metadata: "0x".into(),
            },
        };
        assert!(compile_signed_execute(
            ArcNetwork::Testnet,
            wallet,
            transaction,
            &[(token, U256::from(1_000_000u64))],
            Some(ARC_USDC_ADDRESS)
        )
        .is_err());
    }

    #[tokio::test]
    async fn onramp_fails_closed_on_arc_testnet() {
        let client = CircleClient::new(&CircleConfig {
            api_key: "TEST_API_KEY:key:secret".into(),
            api_base_url: "https://api.circle.com".into(),
            onramp_widget_url: "https://onramp.arc.io".into(),
        })
        .unwrap();
        let error = client
            .create_onramp_session(
                ArcNetwork::Testnet,
                "test-user",
                "0x0000000000000000000000000000000000000001",
                &FundingSessionRequest {
                    fiat_currency: None,
                    fiat_amount: None,
                },
            )
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("does not provide a public Arc testnet checkout"));
    }
}
