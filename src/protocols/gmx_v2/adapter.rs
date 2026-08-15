//! GMX V2 typed action adapter.
//!
//! First supported market: Arbitrum Sepolia.  GMX V2 actions are created
//! through `ExchangeRouter.multicall(bytes[])` so ETH execution fees, token
//! transfers, and order creation land atomically in one account operation.

use anyhow::{anyhow, Result};
use ethers::abi::{self, Token};
use ethers::types::{Address, H256, U256};
use ethers::utils::id;
use serde::{Deserialize, Serialize};

use crate::types::ExecutionRequest;

const GMX_V2_ARBITRUM_SEPOLIA_EXCHANGE_ROUTER: &str = "0xEd50B2A1eF0C35DAaF08Da6486971180237909c3";
const GMX_V2_ARBITRUM_SEPOLIA_DATA_STORE: &str = "0xCF4c2C4c53157BcC01A596e3788fFF69cBBCD201";
const GMX_V2_ARBITRUM_SEPOLIA_READER: &str = "0x4750376b9378294138Cf7B7D69a2d243f4940f71";
const GMX_V2_ARBITRUM_SEPOLIA_ROUTER: &str = "0x72F13a44C8ba16a678CAD549F17bc9e06d2B8bD2";
const GMX_V2_ARBITRUM_SEPOLIA_ORDER_VAULT: &str = "0x1b8AC606de71686fd2a1AEDEcb6E0EFba28909a2";
const GMX_V2_ARBITRUM_SEPOLIA_DEPOSIT_VAULT: &str = "0x809Ea82C394beB993c2b6B0d73b8FD07ab92DE5A";
const GMX_V2_ARBITRUM_SEPOLIA_WITHDRAWAL_VAULT: &str = "0x7601c9dBbDCf1f5ED1E7Adba4EFd9f2cADa037A5";

const ORDER_TYPE_MARKET_SWAP: u8 = 0;
const ORDER_TYPE_LIMIT_SWAP: u8 = 1;
const ORDER_TYPE_MARKET_INCREASE: u8 = 2;
const ORDER_TYPE_LIMIT_INCREASE: u8 = 3;
const ORDER_TYPE_MARKET_DECREASE: u8 = 4;
const ORDER_TYPE_LIMIT_DECREASE: u8 = 5;
const ORDER_TYPE_STOP_LOSS_DECREASE: u8 = 6;
const ORDER_TYPE_STOP_INCREASE: u8 = 8;
const DECREASE_POSITION_SWAP_TYPE_NO_SWAP: u8 = 0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxCreateOrderRequest {
    pub agent_id: String,
    /// GMX V2 testnet support currently targets Arbitrum Sepolia.
    #[serde(default = "default_chain")]
    pub chain: String,
    /// `market_increase` or `market_swap`.
    pub order_type: String,
    /// GMX market token address.
    pub market: String,
    /// Collateral/input token sent into the GMX OrderVault.
    pub initial_collateral_token: String,
    /// Raw token amount in the collateral token's smallest unit.
    pub initial_collateral_delta_amount_raw: String,
    /// Raw USD size delta, 30-decimal GMX precision. Required for market increases.
    #[serde(default)]
    pub size_delta_usd_raw: Option<String>,
    /// Raw acceptable price, 30-decimal GMX precision. Required for market increases.
    #[serde(default)]
    pub acceptable_price_raw: Option<String>,
    /// Raw minimum output amount. Required for market swaps.
    #[serde(default)]
    pub min_output_amount_raw: Option<String>,
    /// Raw ETH execution fee paid to GMX keepers, in wei.
    pub execution_fee_raw: String,
    /// Long/short direction for market increases. Ignored for market swaps.
    #[serde(default)]
    pub is_long: Option<bool>,
    /// Optional receiver. Defaults to the agent smart wallet.
    #[serde(default)]
    pub receiver: Option<String>,
    /// Optional cancellation receiver. Defaults to the receiver.
    #[serde(default)]
    pub cancellation_receiver: Option<String>,
    /// Optional callback contract. Defaults to address(0).
    #[serde(default)]
    pub callback_contract: Option<String>,
    /// Optional UI fee receiver. Defaults to address(0).
    #[serde(default)]
    pub ui_fee_receiver: Option<String>,
    /// Optional GMX swap path market addresses.
    #[serde(default)]
    pub swap_path: Vec<String>,
    /// Raw trigger price, 30-decimal GMX precision. Defaults to 0 for market orders.
    #[serde(default)]
    pub trigger_price_raw: Option<String>,
    /// Raw callback gas limit. Defaults to 0.
    #[serde(default)]
    pub callback_gas_limit_raw: Option<String>,
    /// Raw timestamp from which the order is valid. Defaults to 0.
    #[serde(default)]
    pub valid_from_time_raw: Option<String>,
    /// Optional referral code. Accepts bytes32 hex or short ASCII.
    #[serde(default)]
    pub referral_code: Option<String>,
    #[serde(default)]
    pub should_unwrap_native_token: Option<bool>,
    #[serde(default)]
    pub auto_cancel: Option<bool>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxCancelOrderRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// GMX order key returned by GMX after order creation.
    pub order_key: String,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxUpdateOrderRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub order_key: String,
    pub size_delta_usd_raw: String,
    pub acceptable_price_raw: String,
    pub trigger_price_raw: String,
    pub min_output_amount_raw: String,
    pub valid_from_time_raw: String,
    #[serde(default)]
    pub auto_cancel: Option<bool>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxCreateDepositRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub market: String,
    pub initial_long_token: String,
    pub initial_short_token: String,
    #[serde(default)]
    pub initial_long_token_amount_raw: Option<String>,
    #[serde(default)]
    pub initial_short_token_amount_raw: Option<String>,
    pub min_market_tokens_raw: String,
    pub execution_fee_raw: String,
    #[serde(default)]
    pub receiver: Option<String>,
    #[serde(default)]
    pub callback_contract: Option<String>,
    #[serde(default)]
    pub ui_fee_receiver: Option<String>,
    #[serde(default)]
    pub long_token_swap_path: Vec<String>,
    #[serde(default)]
    pub short_token_swap_path: Vec<String>,
    #[serde(default)]
    pub callback_gas_limit_raw: Option<String>,
    #[serde(default)]
    pub should_unwrap_native_token: Option<bool>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxCreateWithdrawalRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub market: String,
    pub market_token_amount_raw: String,
    pub min_long_token_amount_raw: String,
    pub min_short_token_amount_raw: String,
    pub execution_fee_raw: String,
    #[serde(default)]
    pub receiver: Option<String>,
    #[serde(default)]
    pub callback_contract: Option<String>,
    #[serde(default)]
    pub ui_fee_receiver: Option<String>,
    #[serde(default)]
    pub long_token_swap_path: Vec<String>,
    #[serde(default)]
    pub short_token_swap_path: Vec<String>,
    #[serde(default)]
    pub callback_gas_limit_raw: Option<String>,
    #[serde(default)]
    pub should_unwrap_native_token: Option<bool>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxCancelRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// `order`, `deposit`, `withdrawal`, or `shift`.
    pub request_type: String,
    pub key: String,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmxClaimRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// `funding_fees`, `collateral`, `affiliate_rewards`, or `ui_fees`.
    pub claim_type: String,
    pub markets: Vec<String>,
    pub tokens: Vec<String>,
    #[serde(default)]
    pub time_keys_raw: Vec<String>,
    #[serde(default)]
    pub receiver: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GmxMarketsQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    #[serde(default)]
    pub start: Option<u64>,
    #[serde(default)]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GmxAccountQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    #[serde(default)]
    pub start: Option<u64>,
    #[serde(default)]
    pub end: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxMarketsResponse {
    pub chain: String,
    pub reader_address: String,
    pub data_store_address: String,
    pub start: u64,
    pub end: u64,
    pub markets: Vec<GmxMarket>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxMarket {
    pub market_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_token_symbol: Option<String>,
    pub index_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_token_symbol: Option<String>,
    pub long_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_token_symbol: Option<String>,
    pub short_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_token_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxPositionsResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub start: u64,
    pub end: u64,
    pub positions: Vec<GmxPosition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxPosition {
    pub account: String,
    pub market: String,
    pub collateral_token: String,
    pub size_in_usd: String,
    pub size_in_tokens: String,
    pub collateral_amount: String,
    pub borrowing_factor: String,
    pub funding_fee_amount_per_size: String,
    pub long_token_claimable_funding_amount_per_size: String,
    pub short_token_claimable_funding_amount_per_size: String,
    pub increased_at_time: String,
    pub decreased_at_time: String,
    pub pending_impact_amount: String,
    pub is_long: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxOrdersResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub start: u64,
    pub end: u64,
    pub orders: Vec<GmxOrder>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxOrder {
    pub order_key: String,
    pub account: String,
    pub receiver: String,
    pub cancellation_receiver: String,
    pub callback_contract: String,
    pub ui_fee_receiver: String,
    pub market: String,
    pub initial_collateral_token: String,
    pub swap_path: Vec<String>,
    pub order_type: String,
    pub decrease_position_swap_type: String,
    pub size_delta_usd: String,
    pub initial_collateral_delta_amount: String,
    pub trigger_price: String,
    pub acceptable_price: String,
    pub execution_fee: String,
    pub callback_gas_limit: String,
    pub min_output_amount: String,
    pub updated_at_block: String,
    pub updated_at_time: String,
    pub is_long: bool,
    pub should_unwrap_native_token: bool,
    pub is_frozen: bool,
    pub auto_cancel: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxBalancesResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    /// GM/market LP token balances held by the wallet.
    pub balances: Vec<GmxMarketBalance>,
    /// Underlying GMX market asset balances held by the wallet.
    pub token_balances: Vec<GmxTokenBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxMarketBalance {
    pub market_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub market_token_symbol: Option<String>,
    pub balance_raw: String,
    pub balance_formatted: String,
    pub decimals: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GmxTokenBalance {
    pub token_address: String,
    pub symbol: String,
    pub balance_raw: String,
    pub balance_formatted: String,
    pub decimals: u8,
    pub roles: Vec<String>,
    pub markets: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn default_chain() -> String {
    "base".to_string()
}

pub fn exchange_router_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_EXCHANGE_ROUTER
}

pub fn data_store_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_DATA_STORE
}

pub fn reader_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_READER
}

pub fn router_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_ROUTER
}

pub fn order_vault_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_ORDER_VAULT
}

pub fn deposit_vault_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_DEPOSIT_VAULT
}

pub fn withdrawal_vault_address() -> &'static str {
    GMX_V2_ARBITRUM_SEPOLIA_WITHDRAWAL_VAULT
}

pub fn compile_create_order(
    req: &GmxCreateOrderRequest,
    smart_wallet_address: Address,
) -> Result<ExecutionRequest> {
    validate_create_order_request(req)?;

    let exchange_router: Address = exchange_router_address().parse()?;
    let router: Address = router_address().parse()?;
    let order_vault: Address = order_vault_address().parse()?;
    let collateral_token: Address = req.initial_collateral_token.parse()?;
    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;
    let collateral_amount = parse_u256(
        &req.initial_collateral_delta_amount_raw,
        "initial_collateral_delta_amount_raw",
    )?;

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "gmx-v2-arbitrum-sepolia-{}",
                normalize_order_type(req)
            ))
        }),
        batch_calls: Some(vec![
            crate::types::BatchCall {
                target_contract: format!("{collateral_token:?}"),
                calldata: encode_erc20_approve(router, collateral_amount),
                value: "0".to_string(),
            },
            crate::types::BatchCall {
                target_contract: format!("{exchange_router:?}"),
                calldata: encode_exchange_router_multicall(vec![
                    encode_send_wnt(order_vault, execution_fee),
                    encode_send_tokens(collateral_token, order_vault, collateral_amount),
                    encode_create_order(req, smart_wallet_address)?,
                ]),
                value: execution_fee.to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_cancel_order(req: &GmxCancelOrderRequest) -> Result<ExecutionRequest> {
    validate_cancel_order_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{exchange_router:?}"),
        calldata: encode_cancel_order(parse_bytes32(&req.order_key, "order_key")?),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("gmx-v2-arbitrum-sepolia-cancel-order".to_string())),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_update_order(req: &GmxUpdateOrderRequest) -> Result<ExecutionRequest> {
    validate_update_order_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{exchange_router:?}"),
        calldata: encode_update_order(req)?,
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("gmx-v2-arbitrum-sepolia-update-order".to_string())),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_create_deposit(
    req: &GmxCreateDepositRequest,
    smart_wallet_address: Address,
) -> Result<ExecutionRequest> {
    validate_create_deposit_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;
    let router: Address = router_address().parse()?;
    let deposit_vault: Address = deposit_vault_address().parse()?;
    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;
    let long_amount = parse_optional_u256(
        req.initial_long_token_amount_raw.as_deref(),
        "initial_long_token_amount_raw",
    )?
    .unwrap_or_else(U256::zero);
    let short_amount = parse_optional_u256(
        req.initial_short_token_amount_raw.as_deref(),
        "initial_short_token_amount_raw",
    )?
    .unwrap_or_else(U256::zero);

    let mut batch_calls = Vec::new();
    let mut multicall = vec![encode_send_wnt(deposit_vault, execution_fee)];

    if !long_amount.is_zero() {
        let token = parse_address(&req.initial_long_token, "initial_long_token")?;
        batch_calls.push(crate::types::BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_erc20_approve(router, long_amount),
            value: "0".to_string(),
        });
        multicall.push(encode_send_tokens(token, deposit_vault, long_amount));
    }
    if !short_amount.is_zero() {
        let token = parse_address(&req.initial_short_token, "initial_short_token")?;
        batch_calls.push(crate::types::BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_erc20_approve(router, short_amount),
            value: "0".to_string(),
        });
        multicall.push(encode_send_tokens(token, deposit_vault, short_amount));
    }
    multicall.push(encode_create_deposit(req, smart_wallet_address)?);
    batch_calls.push(crate::types::BatchCall {
        target_contract: format!("{exchange_router:?}"),
        calldata: encode_exchange_router_multicall(multicall),
        value: execution_fee.to_string(),
    });

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("gmx-v2-arbitrum-sepolia-create-deposit".to_string())),
        batch_calls: Some(batch_calls),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_create_withdrawal(
    req: &GmxCreateWithdrawalRequest,
    smart_wallet_address: Address,
) -> Result<ExecutionRequest> {
    validate_create_withdrawal_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;
    let router: Address = router_address().parse()?;
    let withdrawal_vault: Address = withdrawal_vault_address().parse()?;
    let market: Address = parse_address(&req.market, "market")?;
    let market_token_amount = parse_u256(&req.market_token_amount_raw, "market_token_amount_raw")?;
    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("gmx-v2-arbitrum-sepolia-create-withdrawal".to_string())),
        batch_calls: Some(vec![
            crate::types::BatchCall {
                target_contract: format!("{market:?}"),
                calldata: encode_erc20_approve(router, market_token_amount),
                value: "0".to_string(),
            },
            crate::types::BatchCall {
                target_contract: format!("{exchange_router:?}"),
                calldata: encode_exchange_router_multicall(vec![
                    encode_send_wnt(withdrawal_vault, execution_fee),
                    encode_send_tokens(market, withdrawal_vault, market_token_amount),
                    encode_create_withdrawal(req, smart_wallet_address)?,
                ]),
                value: execution_fee.to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_cancel(req: &GmxCancelRequest) -> Result<ExecutionRequest> {
    validate_cancel_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;
    let key = parse_bytes32(&req.key, "key")?;
    let calldata = match normalize_request_type(&req.request_type).as_str() {
        "order" => encode_cancel_order(key),
        "deposit" => encode_call(
            "cancelDeposit(bytes32)",
            &[Token::FixedBytes(key.0.to_vec())],
        ),
        "withdrawal" => encode_call(
            "cancelWithdrawal(bytes32)",
            &[Token::FixedBytes(key.0.to_vec())],
        ),
        "shift" => encode_call("cancelShift(bytes32)", &[Token::FixedBytes(key.0.to_vec())]),
        _ => unreachable!("validate_cancel_request checked request_type"),
    };

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{exchange_router:?}"),
        calldata,
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "gmx-v2-arbitrum-sepolia-cancel-{}",
                normalize_request_type(&req.request_type)
            ))
        }),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_claim(
    req: &GmxClaimRequest,
    smart_wallet_address: Address,
) -> Result<ExecutionRequest> {
    validate_claim_request(req)?;
    let exchange_router: Address = exchange_router_address().parse()?;
    let receiver = parse_optional_address_or_default(
        req.receiver.as_deref(),
        smart_wallet_address,
        "receiver",
    )?;
    let markets = parse_address_array(&req.markets, "markets")?;
    let tokens = parse_address_array(&req.tokens, "tokens")?;
    let calldata = match normalize_claim_type(&req.claim_type).as_str() {
        "funding_fees" => encode_call(
            "claimFundingFees(address[],address[],address)",
            &[
                Token::Array(markets),
                Token::Array(tokens),
                Token::Address(receiver),
            ],
        ),
        "collateral" => {
            let time_keys = req
                .time_keys_raw
                .iter()
                .map(|raw| parse_u256(raw, "time_keys_raw item").map(Token::Uint))
                .collect::<Result<Vec<_>>>()?;
            encode_call(
                "claimCollateral(address[],address[],uint256[],address)",
                &[
                    Token::Array(markets),
                    Token::Array(tokens),
                    Token::Array(time_keys),
                    Token::Address(receiver),
                ],
            )
        }
        "affiliate_rewards" => encode_call(
            "claimAffiliateRewards(address[],address[],address)",
            &[
                Token::Array(markets),
                Token::Array(tokens),
                Token::Address(receiver),
            ],
        ),
        "ui_fees" => encode_call(
            "claimUiFees(address[],address[],address)",
            &[
                Token::Array(markets),
                Token::Array(tokens),
                Token::Address(receiver),
            ],
        ),
        _ => unreachable!("validate_claim_request checked claim_type"),
    };

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{exchange_router:?}"),
        calldata,
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "gmx-v2-arbitrum-sepolia-claim-{}",
                normalize_claim_type(&req.claim_type).replace('_', "-")
            ))
        }),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn validate_create_order_request(req: &GmxCreateOrderRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    let order_type = parse_order_type(&req.order_type)?;

    let market = parse_address(&req.market, "market")?;
    parse_address(&req.initial_collateral_token, "initial_collateral_token")?;
    parse_optional_address(req.receiver.as_deref(), "receiver")?;
    parse_optional_address(
        req.cancellation_receiver.as_deref(),
        "cancellation_receiver",
    )?;
    parse_optional_address(req.callback_contract.as_deref(), "callback_contract")?;
    parse_optional_address(req.ui_fee_receiver.as_deref(), "ui_fee_receiver")?;
    for raw in &req.swap_path {
        parse_address(raw, "swap_path item")?;
    }
    parse_optional_u256(req.trigger_price_raw.as_deref(), "trigger_price_raw")?;
    parse_optional_u256(
        req.callback_gas_limit_raw.as_deref(),
        "callback_gas_limit_raw",
    )?;
    parse_optional_u256(req.valid_from_time_raw.as_deref(), "valid_from_time_raw")?;

    let collateral_amount = parse_u256(
        &req.initial_collateral_delta_amount_raw,
        "initial_collateral_delta_amount_raw",
    )?;
    if collateral_amount.is_zero() {
        return Err(anyhow!(
            "initial_collateral_delta_amount_raw must be greater than zero"
        ));
    }

    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;
    if execution_fee.is_zero() {
        return Err(anyhow!("execution_fee_raw must be greater than zero"));
    }

    match order_type {
        ORDER_TYPE_MARKET_INCREASE | ORDER_TYPE_LIMIT_INCREASE | ORDER_TYPE_STOP_INCREASE => {
            let size =
                parse_optional_u256(req.size_delta_usd_raw.as_deref(), "size_delta_usd_raw")?
                    .ok_or_else(|| anyhow!("size_delta_usd_raw is required for market_increase"))?;
            if size.is_zero() {
                return Err(anyhow!("size_delta_usd_raw must be greater than zero"));
            }
            let acceptable_price = parse_optional_u256(
                req.acceptable_price_raw.as_deref(),
                "acceptable_price_raw",
            )?
            .ok_or_else(|| anyhow!("acceptable_price_raw is required for market_increase"))?;
            if acceptable_price.is_zero() {
                return Err(anyhow!("acceptable_price_raw must be greater than zero"));
            }
        }
        ORDER_TYPE_MARKET_DECREASE | ORDER_TYPE_LIMIT_DECREASE | ORDER_TYPE_STOP_LOSS_DECREASE => {
            let size =
                parse_optional_u256(req.size_delta_usd_raw.as_deref(), "size_delta_usd_raw")?
                    .ok_or_else(|| anyhow!("size_delta_usd_raw is required for decrease orders"))?;
            if size.is_zero() {
                return Err(anyhow!("size_delta_usd_raw must be greater than zero"));
            }
            let acceptable_price = parse_optional_u256(
                req.acceptable_price_raw.as_deref(),
                "acceptable_price_raw",
            )?
            .ok_or_else(|| anyhow!("acceptable_price_raw is required for decrease orders"))?;
            if acceptable_price.is_zero() {
                return Err(anyhow!("acceptable_price_raw must be greater than zero"));
            }
        }
        ORDER_TYPE_MARKET_SWAP | ORDER_TYPE_LIMIT_SWAP => {
            if market == Address::zero() && req.swap_path.is_empty() {
                return Err(anyhow!(
                    "market or swap_path is required for swap orders; provide a GMX swap-path market"
                ));
            }
            if market != Address::zero() && !req.swap_path.is_empty() {
                return Err(anyhow!(
                    "provide either market as a single swap-path market or swap_path for swap orders, not both"
                ));
            }
            let min_output = parse_optional_u256(
                req.min_output_amount_raw.as_deref(),
                "min_output_amount_raw",
            )?
            .ok_or_else(|| anyhow!("min_output_amount_raw is required for market_swap"))?;
            if min_output.is_zero() {
                return Err(anyhow!("min_output_amount_raw must be greater than zero"));
            }
        }
        _ => unreachable!("parse_order_type only returns supported order types"),
    }

    if let Some(raw) = &req.referral_code {
        parse_referral_code(raw)?;
    }

    Ok(())
}

pub fn validate_cancel_order_request(req: &GmxCancelOrderRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_bytes32(&req.order_key, "order_key")?;
    Ok(())
}

pub fn validate_update_order_request(req: &GmxUpdateOrderRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_bytes32(&req.order_key, "order_key")?;
    parse_u256(&req.size_delta_usd_raw, "size_delta_usd_raw")?;
    parse_u256(&req.acceptable_price_raw, "acceptable_price_raw")?;
    parse_u256(&req.trigger_price_raw, "trigger_price_raw")?;
    parse_u256(&req.min_output_amount_raw, "min_output_amount_raw")?;
    parse_u256(&req.valid_from_time_raw, "valid_from_time_raw")?;
    Ok(())
}

pub fn validate_create_deposit_request(req: &GmxCreateDepositRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_address(&req.market, "market")?;
    parse_address(&req.initial_long_token, "initial_long_token")?;
    parse_address(&req.initial_short_token, "initial_short_token")?;
    parse_optional_address(req.receiver.as_deref(), "receiver")?;
    parse_optional_address(req.callback_contract.as_deref(), "callback_contract")?;
    parse_optional_address(req.ui_fee_receiver.as_deref(), "ui_fee_receiver")?;
    parse_address_array(&req.long_token_swap_path, "long_token_swap_path")?;
    parse_address_array(&req.short_token_swap_path, "short_token_swap_path")?;
    let long_amount = parse_optional_u256(
        req.initial_long_token_amount_raw.as_deref(),
        "initial_long_token_amount_raw",
    )?
    .unwrap_or_else(U256::zero);
    let short_amount = parse_optional_u256(
        req.initial_short_token_amount_raw.as_deref(),
        "initial_short_token_amount_raw",
    )?
    .unwrap_or_else(U256::zero);
    if long_amount.is_zero() && short_amount.is_zero() {
        return Err(anyhow!(
            "at least one of initial_long_token_amount_raw or initial_short_token_amount_raw must be greater than zero"
        ));
    }
    parse_u256(&req.min_market_tokens_raw, "min_market_tokens_raw")?;
    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;
    if execution_fee.is_zero() {
        return Err(anyhow!("execution_fee_raw must be greater than zero"));
    }
    parse_optional_u256(
        req.callback_gas_limit_raw.as_deref(),
        "callback_gas_limit_raw",
    )?;
    Ok(())
}

pub fn validate_create_withdrawal_request(req: &GmxCreateWithdrawalRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_address(&req.market, "market")?;
    let market_token_amount = parse_u256(&req.market_token_amount_raw, "market_token_amount_raw")?;
    if market_token_amount.is_zero() {
        return Err(anyhow!("market_token_amount_raw must be greater than zero"));
    }
    parse_u256(&req.min_long_token_amount_raw, "min_long_token_amount_raw")?;
    parse_u256(
        &req.min_short_token_amount_raw,
        "min_short_token_amount_raw",
    )?;
    let execution_fee = parse_u256(&req.execution_fee_raw, "execution_fee_raw")?;
    if execution_fee.is_zero() {
        return Err(anyhow!("execution_fee_raw must be greater than zero"));
    }
    parse_optional_address(req.receiver.as_deref(), "receiver")?;
    parse_optional_address(req.callback_contract.as_deref(), "callback_contract")?;
    parse_optional_address(req.ui_fee_receiver.as_deref(), "ui_fee_receiver")?;
    parse_address_array(&req.long_token_swap_path, "long_token_swap_path")?;
    parse_address_array(&req.short_token_swap_path, "short_token_swap_path")?;
    parse_optional_u256(
        req.callback_gas_limit_raw.as_deref(),
        "callback_gas_limit_raw",
    )?;
    Ok(())
}

pub fn validate_cancel_request(req: &GmxCancelRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_bytes32(&req.key, "key")?;
    match normalize_request_type(&req.request_type).as_str() {
        "order" | "deposit" | "withdrawal" | "shift" => Ok(()),
        other => Err(anyhow!(
            "unsupported GMX request_type: {other}; supported: order, deposit, withdrawal, shift"
        )),
    }
}

pub fn validate_claim_request(req: &GmxClaimRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    require_non_empty(&req.agent_id, "agent_id")?;
    parse_address_array(&req.markets, "markets")?;
    parse_address_array(&req.tokens, "tokens")?;
    if req.markets.is_empty() || req.tokens.is_empty() {
        return Err(anyhow!("markets and tokens must not be empty"));
    }
    if req.markets.len() != req.tokens.len() {
        return Err(anyhow!("markets and tokens must have the same length"));
    }
    match normalize_claim_type(&req.claim_type).as_str() {
        "funding_fees" | "affiliate_rewards" | "ui_fees" => Ok(()),
        "collateral" => {
            if req.time_keys_raw.is_empty() {
                return Err(anyhow!("time_keys_raw is required for collateral claims"));
            }
            for raw in &req.time_keys_raw {
                parse_u256(raw, "time_keys_raw item")?;
            }
            Ok(())
        }
        other => Err(anyhow!(
            "unsupported GMX claim_type: {other}; supported: funding_fees, collateral, affiliate_rewards, ui_fees"
        )),
    }?;
    parse_optional_address(req.receiver.as_deref(), "receiver")?;
    Ok(())
}

fn validate_chain(chain: &str) -> Result<()> {
    match chain.trim().to_lowercase().as_str() {
        "arbitrum" | "arb" => Ok(()),
        "base" | "base-sepolia" | "base_sepolia" => Err(anyhow!(
            "GMX V2 has no official Base Sepolia deployment; keep this protocol disabled on Base"
        )),
        other => Err(anyhow!(
            "GMX V2 testnet integration supports chain arbitrum (Arbitrum Sepolia), got {other}"
        )),
    }
}

fn normalize_order_type(req: &GmxCreateOrderRequest) -> String {
    req.order_type.trim().to_lowercase().replace('_', "-")
}

fn parse_order_type(raw: &str) -> Result<u8> {
    match raw.trim().to_lowercase().as_str() {
        "market_swap" | "marketswap" | "swap" => Ok(ORDER_TYPE_MARKET_SWAP),
        "limit_swap" | "limitswap" => Ok(ORDER_TYPE_LIMIT_SWAP),
        "market_increase" | "marketincrease" | "increase" => Ok(ORDER_TYPE_MARKET_INCREASE),
        "limit_increase" | "limitincrease" => Ok(ORDER_TYPE_LIMIT_INCREASE),
        "market_decrease" | "marketdecrease" | "decrease" | "close" => {
            Ok(ORDER_TYPE_MARKET_DECREASE)
        }
        "limit_decrease" | "limitdecrease" => Ok(ORDER_TYPE_LIMIT_DECREASE),
        "stop_loss_decrease" | "stoplossdecrease" | "stop_loss" => {
            Ok(ORDER_TYPE_STOP_LOSS_DECREASE)
        }
        "stop_increase" | "stopincrease" => Ok(ORDER_TYPE_STOP_INCREASE),
        other => Err(anyhow!(
            "unsupported GMX order_type: {other}; supported: market_swap, limit_swap, market_increase, limit_increase, market_decrease, limit_decrease, stop_loss_decrease, stop_increase"
        )),
    }
}

fn normalize_request_type(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn normalize_claim_type(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn parse_decrease_position_swap_type() -> u8 {
    DECREASE_POSITION_SWAP_TYPE_NO_SWAP
}

fn parse_optional_u256(raw: Option<&str>, field: &str) -> Result<Option<U256>> {
    raw.map(|value| parse_u256(value, field)).transpose()
}

fn parse_u256(raw: &str, field: &str) -> Result<U256> {
    require_non_empty(raw, field)?;
    U256::from_dec_str(raw.trim())
        .map_err(|_| anyhow!("{field} must be a non-negative base-10 integer string"))
}

fn require_non_empty(raw: &str, field: &str) -> Result<()> {
    if raw.trim().is_empty() {
        return Err(anyhow!("{field} is required"));
    }
    Ok(())
}

fn parse_address(raw: &str, field: &str) -> Result<Address> {
    require_non_empty(raw, field)?;
    raw.parse::<Address>()
        .map_err(|_| anyhow!("{field} must be a valid EVM address"))
}

fn parse_optional_address(raw: Option<&str>, field: &str) -> Result<Option<Address>> {
    raw.map(|value| parse_address(value, field)).transpose()
}

fn parse_address_array(raw: &[String], field: &str) -> Result<Vec<Token>> {
    raw.iter()
        .map(|value| parse_address(value, field).map(Token::Address))
        .collect()
}

pub fn validate_markets_query(query: &GmxMarketsQuery) -> Result<(u64, u64)> {
    validate_chain(&query.chain)?;
    let start = query.start.unwrap_or(0);
    let end = query.end.unwrap_or(start.saturating_add(50));
    if end <= start {
        return Err(anyhow!("end must be greater than start"));
    }
    if end - start > 100 {
        return Err(anyhow!("GMX read range is limited to 100 items"));
    }
    Ok((start, end))
}

pub fn validate_account_query(query: &GmxAccountQuery) -> Result<(u64, u64)> {
    validate_chain(&query.chain)?;
    require_non_empty(&query.agent_id, "agent_id")?;
    let start = query.start.unwrap_or(0);
    let end = query.end.unwrap_or(start.saturating_add(50));
    if end <= start {
        return Err(anyhow!("end must be greater than start"));
    }
    if end - start > 100 {
        return Err(anyhow!("GMX read range is limited to 100 items"));
    }
    Ok((start, end))
}

pub fn encode_get_markets(data_store: Address, start: U256, end: U256) -> String {
    encode_call(
        "getMarkets(address,uint256,uint256)",
        &[
            Token::Address(data_store),
            Token::Uint(start),
            Token::Uint(end),
        ],
    )
}

pub fn encode_get_account_positions(
    data_store: Address,
    account: Address,
    start: U256,
    end: U256,
) -> String {
    encode_call(
        "getAccountPositions(address,address,uint256,uint256)",
        &[
            Token::Address(data_store),
            Token::Address(account),
            Token::Uint(start),
            Token::Uint(end),
        ],
    )
}

pub fn encode_get_account_orders(
    data_store: Address,
    account: Address,
    start: U256,
    end: U256,
) -> String {
    encode_call(
        "getAccountOrders(address,address,uint256,uint256)",
        &[
            Token::Address(data_store),
            Token::Address(account),
            Token::Uint(start),
            Token::Uint(end),
        ],
    )
}

pub fn encode_balance_of(account: Address) -> String {
    encode_call("balanceOf(address)", &[Token::Address(account)])
}

pub fn encode_decimals() -> String {
    encode_call("decimals()", &[])
}

pub fn encode_symbol() -> String {
    encode_call("symbol()", &[])
}

pub fn decode_markets(raw: &[u8]) -> Result<Vec<GmxMarket>> {
    let decoded = abi::decode(&[market_array_param()], raw)?;
    let markets = token_array(&decoded[0], "markets")?
        .iter()
        .map(decode_market)
        .collect::<Result<Vec<_>>>()?;
    Ok(markets)
}

pub fn decode_positions(raw: &[u8]) -> Result<Vec<GmxPosition>> {
    let decoded = abi::decode(&[position_array_param()], raw)?;
    token_array(&decoded[0], "positions")?
        .iter()
        .map(decode_position)
        .collect()
}

pub fn decode_orders(raw: &[u8]) -> Result<Vec<GmxOrder>> {
    let decoded = abi::decode(&[order_array_param()], raw)?;
    token_array(&decoded[0], "orders")?
        .iter()
        .map(decode_order)
        .collect()
}

fn market_array_param() -> abi::ParamType {
    abi::ParamType::Array(Box::new(abi::ParamType::Tuple(vec![
        abi::ParamType::Address,
        abi::ParamType::Address,
        abi::ParamType::Address,
        abi::ParamType::Address,
    ])))
}

fn position_array_param() -> abi::ParamType {
    abi::ParamType::Array(Box::new(abi::ParamType::Tuple(vec![
        abi::ParamType::Tuple(vec![
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
        ]),
        abi::ParamType::Tuple(vec![
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Int(256),
        ]),
        abi::ParamType::Tuple(vec![abi::ParamType::Bool]),
    ])))
}

fn order_array_param() -> abi::ParamType {
    abi::ParamType::Array(Box::new(abi::ParamType::Tuple(vec![
        abi::ParamType::FixedBytes(32),
        abi::ParamType::Tuple(vec![
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Array(Box::new(abi::ParamType::Address)),
        ]),
        abi::ParamType::Tuple(vec![
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
            abi::ParamType::Uint(256),
        ]),
        abi::ParamType::Tuple(vec![
            abi::ParamType::Bool,
            abi::ParamType::Bool,
            abi::ParamType::Bool,
            abi::ParamType::Bool,
        ]),
    ])))
}

fn token_array<'a>(token: &'a Token, field: &str) -> Result<&'a [Token]> {
    match token {
        Token::Array(values) => Ok(values.as_slice()),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_tuple<'a>(token: &'a Token, field: &str) -> Result<&'a [Token]> {
    match token {
        Token::Tuple(values) => Ok(values.as_slice()),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_address(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::Address(value) => Ok(format!("{value:?}")),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_u256(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::Uint(value) => Ok(value.to_string()),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_i256(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::Int(value) => Ok(value.to_string()),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_bool(token: &Token, field: &str) -> Result<bool> {
    match token {
        Token::Bool(value) => Ok(*value),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn token_bytes32_hex(token: &Token, field: &str) -> Result<String> {
    match token {
        Token::FixedBytes(value) if value.len() == 32 => Ok(format!("0x{}", hex::encode(value))),
        other => Err(anyhow!("{field} decoded to unexpected token: {other:?}")),
    }
}

fn decode_market(token: &Token) -> Result<GmxMarket> {
    let market = token_tuple(token, "market")?;
    Ok(GmxMarket {
        market_token: token_address(&market[0], "market.market_token")?,
        market_token_symbol: None,
        index_token: token_address(&market[1], "market.index_token")?,
        index_token_symbol: None,
        long_token: token_address(&market[2], "market.long_token")?,
        long_token_symbol: None,
        short_token: token_address(&market[3], "market.short_token")?,
        short_token_symbol: None,
    })
}

fn decode_position(token: &Token) -> Result<GmxPosition> {
    let position = token_tuple(token, "position")?;
    let addresses = token_tuple(&position[0], "position.addresses")?;
    let numbers = token_tuple(&position[1], "position.numbers")?;
    let flags = token_tuple(&position[2], "position.flags")?;
    Ok(GmxPosition {
        account: token_address(&addresses[0], "position.account")?,
        market: token_address(&addresses[1], "position.market")?,
        collateral_token: token_address(&addresses[2], "position.collateral_token")?,
        size_in_usd: token_u256(&numbers[0], "position.size_in_usd")?,
        size_in_tokens: token_u256(&numbers[1], "position.size_in_tokens")?,
        collateral_amount: token_u256(&numbers[2], "position.collateral_amount")?,
        borrowing_factor: token_u256(&numbers[3], "position.borrowing_factor")?,
        funding_fee_amount_per_size: token_u256(
            &numbers[4],
            "position.funding_fee_amount_per_size",
        )?,
        long_token_claimable_funding_amount_per_size: token_u256(
            &numbers[5],
            "position.long_token_claimable_funding_amount_per_size",
        )?,
        short_token_claimable_funding_amount_per_size: token_u256(
            &numbers[6],
            "position.short_token_claimable_funding_amount_per_size",
        )?,
        increased_at_time: token_u256(&numbers[7], "position.increased_at_time")?,
        decreased_at_time: token_u256(&numbers[8], "position.decreased_at_time")?,
        pending_impact_amount: token_i256(&numbers[9], "position.pending_impact_amount")?,
        is_long: token_bool(&flags[0], "position.is_long")?,
    })
}

fn decode_order(token: &Token) -> Result<GmxOrder> {
    let order = token_tuple(token, "order")?;
    let addresses = token_tuple(&order[1], "order.addresses")?;
    let numbers = token_tuple(&order[2], "order.numbers")?;
    let flags = token_tuple(&order[3], "order.flags")?;
    let swap_path = token_array(&addresses[7], "order.swap_path")?
        .iter()
        .map(|token| token_address(token, "order.swap_path item"))
        .collect::<Result<Vec<_>>>()?;
    Ok(GmxOrder {
        order_key: token_bytes32_hex(&order[0], "order.key")?,
        account: token_address(&addresses[0], "order.account")?,
        receiver: token_address(&addresses[1], "order.receiver")?,
        cancellation_receiver: token_address(&addresses[2], "order.cancellation_receiver")?,
        callback_contract: token_address(&addresses[3], "order.callback_contract")?,
        ui_fee_receiver: token_address(&addresses[4], "order.ui_fee_receiver")?,
        market: token_address(&addresses[5], "order.market")?,
        initial_collateral_token: token_address(&addresses[6], "order.initial_collateral_token")?,
        swap_path,
        order_type: order_type_label(token_u256(&numbers[0], "order.order_type")?.as_str())
            .to_string(),
        decrease_position_swap_type: token_u256(&numbers[1], "order.decrease_position_swap_type")?,
        size_delta_usd: token_u256(&numbers[2], "order.size_delta_usd")?,
        initial_collateral_delta_amount: token_u256(
            &numbers[3],
            "order.initial_collateral_delta_amount",
        )?,
        trigger_price: token_u256(&numbers[4], "order.trigger_price")?,
        acceptable_price: token_u256(&numbers[5], "order.acceptable_price")?,
        execution_fee: token_u256(&numbers[6], "order.execution_fee")?,
        callback_gas_limit: token_u256(&numbers[7], "order.callback_gas_limit")?,
        min_output_amount: token_u256(&numbers[8], "order.min_output_amount")?,
        updated_at_block: token_u256(&numbers[9], "order.updated_at_block")?,
        updated_at_time: token_u256(&numbers[10], "order.updated_at_time")?,
        is_long: token_bool(&flags[0], "order.is_long")?,
        should_unwrap_native_token: token_bool(&flags[1], "order.should_unwrap_native_token")?,
        is_frozen: token_bool(&flags[2], "order.is_frozen")?,
        auto_cancel: token_bool(&flags[3], "order.auto_cancel")?,
    })
}

fn order_type_label(raw: &str) -> &str {
    match raw {
        "0" => "market_swap",
        "1" => "limit_swap",
        "2" => "market_increase",
        "3" => "limit_increase",
        "4" => "market_decrease",
        "5" => "limit_decrease",
        "6" => "stop_loss_decrease",
        "8" => "stop_increase",
        other => other,
    }
}

fn parse_optional_address_or_default(
    raw: Option<&str>,
    default: Address,
    field: &str,
) -> Result<Address> {
    Ok(match raw {
        Some(value) => parse_address(value, field)?,
        None => default,
    })
}

fn parse_bytes32(raw: &str, field: &str) -> Result<H256> {
    require_non_empty(raw, field)?;
    raw.parse::<H256>()
        .map_err(|_| anyhow!("{field} must be a 0x-prefixed 32-byte hex value"))
}

fn parse_referral_code(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        let bytes = hex::decode(hex).map_err(|_| anyhow!("referral_code hex is invalid"))?;
        if bytes.len() != 32 {
            return Err(anyhow!("referral_code hex must be exactly 32 bytes"));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }

    let bytes = trimmed.as_bytes();
    if bytes.len() > 32 {
        return Err(anyhow!("referral_code ASCII must be at most 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(out)
}

fn is_swap_order_type(order_type: u8) -> bool {
    order_type == ORDER_TYPE_MARKET_SWAP || order_type == ORDER_TYPE_LIMIT_SWAP
}

fn normalized_order_market(req: &GmxCreateOrderRequest, order_type: u8) -> Result<Address> {
    if is_swap_order_type(order_type) {
        Ok(Address::zero())
    } else {
        parse_address(&req.market, "market")
    }
}

fn normalized_order_swap_path(req: &GmxCreateOrderRequest, order_type: u8) -> Result<Vec<Token>> {
    let route = if is_swap_order_type(order_type) && req.swap_path.is_empty() {
        vec![parse_address(&req.market, "market")?]
    } else {
        req.swap_path
            .iter()
            .map(|raw| parse_address(raw, "swap_path item"))
            .collect::<Result<Vec<_>>>()?
    };

    Ok(route.into_iter().map(Token::Address).collect())
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = id(signature);
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_call(signature: &str, args: &[Token]) -> String {
    let mut out = selector(signature).to_vec();
    out.extend(abi::encode(args));
    format!("0x{}", hex::encode(out))
}

fn encode_erc20_approve(spender: Address, amount: U256) -> String {
    encode_call(
        "approve(address,uint256)",
        &[Token::Address(spender), Token::Uint(amount)],
    )
}

fn encode_exchange_router_multicall(calls: Vec<String>) -> String {
    let call_tokens = calls
        .into_iter()
        .map(|call| {
            let bytes = hex::decode(call.trim_start_matches("0x"))
                .expect("adapter-generated calldata must be valid hex");
            Token::Bytes(bytes)
        })
        .collect::<Vec<_>>();
    encode_call("multicall(bytes[])", &[Token::Array(call_tokens)])
}

fn encode_send_wnt(receiver: Address, amount: U256) -> String {
    encode_call(
        "sendWnt(address,uint256)",
        &[Token::Address(receiver), Token::Uint(amount)],
    )
}

fn encode_send_tokens(token: Address, receiver: Address, amount: U256) -> String {
    encode_call(
        "sendTokens(address,address,uint256)",
        &[
            Token::Address(token),
            Token::Address(receiver),
            Token::Uint(amount),
        ],
    )
}

fn encode_cancel_order(order_key: H256) -> String {
    encode_call(
        "cancelOrder(bytes32)",
        &[Token::FixedBytes(order_key.0.to_vec())],
    )
}

fn encode_update_order(req: &GmxUpdateOrderRequest) -> Result<String> {
    Ok(encode_call(
        "updateOrder(bytes32,uint256,uint256,uint256,uint256,uint256,bool)",
        &[
            Token::FixedBytes(parse_bytes32(&req.order_key, "order_key")?.0.to_vec()),
            Token::Uint(parse_u256(&req.size_delta_usd_raw, "size_delta_usd_raw")?),
            Token::Uint(parse_u256(
                &req.acceptable_price_raw,
                "acceptable_price_raw",
            )?),
            Token::Uint(parse_u256(&req.trigger_price_raw, "trigger_price_raw")?),
            Token::Uint(parse_u256(
                &req.min_output_amount_raw,
                "min_output_amount_raw",
            )?),
            Token::Uint(parse_u256(&req.valid_from_time_raw, "valid_from_time_raw")?),
            Token::Bool(req.auto_cancel.unwrap_or(false)),
        ],
    ))
}

fn encode_create_deposit(
    req: &GmxCreateDepositRequest,
    smart_wallet_address: Address,
) -> Result<String> {
    let zero = Address::zero();
    let receiver = parse_optional_address_or_default(
        req.receiver.as_deref(),
        smart_wallet_address,
        "receiver",
    )?;
    let addresses = Token::Tuple(vec![
        Token::Address(receiver),
        Token::Address(parse_optional_address_or_default(
            req.callback_contract.as_deref(),
            zero,
            "callback_contract",
        )?),
        Token::Address(parse_optional_address_or_default(
            req.ui_fee_receiver.as_deref(),
            zero,
            "ui_fee_receiver",
        )?),
        Token::Address(parse_address(&req.market, "market")?),
        Token::Address(parse_address(
            &req.initial_long_token,
            "initial_long_token",
        )?),
        Token::Address(parse_address(
            &req.initial_short_token,
            "initial_short_token",
        )?),
        Token::Array(parse_address_array(
            &req.long_token_swap_path,
            "long_token_swap_path",
        )?),
        Token::Array(parse_address_array(
            &req.short_token_swap_path,
            "short_token_swap_path",
        )?),
    ]);
    Ok(encode_call(
        "createDeposit(((address,address,address,address,address,address,address[],address[]),uint256,bool,uint256,uint256,bytes32[]))",
        &[
            Token::Tuple(vec![
                addresses,
                Token::Uint(parse_u256(
                    &req.min_market_tokens_raw,
                    "min_market_tokens_raw",
                )?),
                Token::Bool(req.should_unwrap_native_token.unwrap_or(false)),
                Token::Uint(parse_u256(&req.execution_fee_raw, "execution_fee_raw")?),
                Token::Uint(
                    parse_optional_u256(
                        req.callback_gas_limit_raw.as_deref(),
                        "callback_gas_limit_raw",
                    )?
                    .unwrap_or_else(U256::zero),
                ),
                Token::Array(Vec::new()),
            ])
        ],
    ))
}

fn encode_create_withdrawal(
    req: &GmxCreateWithdrawalRequest,
    smart_wallet_address: Address,
) -> Result<String> {
    let zero = Address::zero();
    let receiver = parse_optional_address_or_default(
        req.receiver.as_deref(),
        smart_wallet_address,
        "receiver",
    )?;
    let addresses = Token::Tuple(vec![
        Token::Address(receiver),
        Token::Address(parse_optional_address_or_default(
            req.callback_contract.as_deref(),
            zero,
            "callback_contract",
        )?),
        Token::Address(parse_optional_address_or_default(
            req.ui_fee_receiver.as_deref(),
            zero,
            "ui_fee_receiver",
        )?),
        Token::Address(parse_address(&req.market, "market")?),
        Token::Array(parse_address_array(
            &req.long_token_swap_path,
            "long_token_swap_path",
        )?),
        Token::Array(parse_address_array(
            &req.short_token_swap_path,
            "short_token_swap_path",
        )?),
    ]);
    Ok(encode_call(
        "createWithdrawal(((address,address,address,address,address[],address[]),uint256,uint256,bool,uint256,uint256,bytes32[]))",
        &[
            Token::Tuple(vec![
                addresses,
                Token::Uint(parse_u256(
                    &req.min_long_token_amount_raw,
                    "min_long_token_amount_raw",
                )?),
                Token::Uint(parse_u256(
                    &req.min_short_token_amount_raw,
                    "min_short_token_amount_raw",
                )?),
                Token::Bool(req.should_unwrap_native_token.unwrap_or(false)),
                Token::Uint(parse_u256(&req.execution_fee_raw, "execution_fee_raw")?),
                Token::Uint(
                    parse_optional_u256(
                        req.callback_gas_limit_raw.as_deref(),
                        "callback_gas_limit_raw",
                    )?
                    .unwrap_or_else(U256::zero),
                ),
                Token::Array(Vec::new()),
            ])
        ],
    ))
}

fn encode_create_order(
    req: &GmxCreateOrderRequest,
    smart_wallet_address: Address,
) -> Result<String> {
    let order_type = parse_order_type(&req.order_type)?;
    let receiver = parse_optional_address_or_default(
        req.receiver.as_deref(),
        smart_wallet_address,
        "receiver",
    )?;
    let cancellation_receiver = parse_optional_address_or_default(
        req.cancellation_receiver.as_deref(),
        receiver,
        "cancellation_receiver",
    )?;
    let zero = Address::zero();
    let addresses = Token::Tuple(vec![
        Token::Address(receiver),
        Token::Address(cancellation_receiver),
        Token::Address(parse_optional_address_or_default(
            req.callback_contract.as_deref(),
            zero,
            "callback_contract",
        )?),
        Token::Address(parse_optional_address_or_default(
            req.ui_fee_receiver.as_deref(),
            zero,
            "ui_fee_receiver",
        )?),
        Token::Address(normalized_order_market(req, order_type)?),
        Token::Address(parse_address(
            &req.initial_collateral_token,
            "initial_collateral_token",
        )?),
        Token::Array(normalized_order_swap_path(req, order_type)?),
    ]);

    let numbers = Token::Tuple(vec![
        Token::Uint(
            parse_optional_u256(req.size_delta_usd_raw.as_deref(), "size_delta_usd_raw")?
                .unwrap_or_else(U256::zero),
        ),
        Token::Uint(parse_u256(
            &req.initial_collateral_delta_amount_raw,
            "initial_collateral_delta_amount_raw",
        )?),
        Token::Uint(
            parse_optional_u256(req.trigger_price_raw.as_deref(), "trigger_price_raw")?
                .unwrap_or_else(U256::zero),
        ),
        Token::Uint(
            parse_optional_u256(req.acceptable_price_raw.as_deref(), "acceptable_price_raw")?
                .unwrap_or_else(U256::zero),
        ),
        Token::Uint(parse_u256(&req.execution_fee_raw, "execution_fee_raw")?),
        Token::Uint(
            parse_optional_u256(
                req.callback_gas_limit_raw.as_deref(),
                "callback_gas_limit_raw",
            )?
            .unwrap_or_else(U256::zero),
        ),
        Token::Uint(
            parse_optional_u256(
                req.min_output_amount_raw.as_deref(),
                "min_output_amount_raw",
            )?
            .unwrap_or_else(U256::zero),
        ),
        Token::Uint(
            parse_optional_u256(req.valid_from_time_raw.as_deref(), "valid_from_time_raw")?
                .unwrap_or_else(U256::zero),
        ),
    ]);

    let referral_code = match req.referral_code.as_deref() {
        Some(raw) => parse_referral_code(raw)?,
        None => [0u8; 32],
    };

    let params = Token::Tuple(vec![
        addresses,
        numbers,
        Token::Uint(U256::from(order_type)),
        Token::Uint(U256::from(parse_decrease_position_swap_type())),
        Token::Bool(req.is_long.unwrap_or(true)),
        Token::Bool(req.should_unwrap_native_token.unwrap_or(false)),
        Token::Bool(req.auto_cancel.unwrap_or(false)),
        Token::FixedBytes(referral_code.to_vec()),
        Token::Array(Vec::new()),
    ]);

    Ok(encode_call(
        "createOrder(((address,address,address,address,address,address,address[]),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256),uint8,uint8,bool,bool,bool,bytes32,bytes32[]))",
        &[params],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::abi::ParamType;

    fn sample_req(order_type: &str) -> GmxCreateOrderRequest {
        GmxCreateOrderRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            order_type: order_type.to_string(),
            market: "0x1111111111111111111111111111111111111111".to_string(),
            initial_collateral_token: "0x2222222222222222222222222222222222222222".to_string(),
            initial_collateral_delta_amount_raw: "1000000".to_string(),
            size_delta_usd_raw: Some("50000000000000000000000000000000000".to_string()),
            acceptable_price_raw: Some("30000000000000000000000000000000000000000".to_string()),
            min_output_amount_raw: Some("1".to_string()),
            execution_fee_raw: "1000000000000000".to_string(),
            is_long: Some(true),
            receiver: None,
            cancellation_receiver: None,
            callback_contract: None,
            ui_fee_receiver: None,
            swap_path: Vec::new(),
            trigger_price_raw: None,
            callback_gas_limit_raw: None,
            valid_from_time_raw: None,
            referral_code: None,
            should_unwrap_native_token: None,
            auto_cancel: None,
            strategy_id: None,
            callback_url: None,
        }
    }

    fn sample_deposit_req() -> GmxCreateDepositRequest {
        GmxCreateDepositRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            market: "0x1111111111111111111111111111111111111111".to_string(),
            initial_long_token: "0x2222222222222222222222222222222222222222".to_string(),
            initial_short_token: "0x3333333333333333333333333333333333333333".to_string(),
            initial_long_token_amount_raw: Some("1000000".to_string()),
            initial_short_token_amount_raw: None,
            min_market_tokens_raw: "1".to_string(),
            execution_fee_raw: "1000000000000000".to_string(),
            receiver: None,
            callback_contract: None,
            ui_fee_receiver: None,
            long_token_swap_path: Vec::new(),
            short_token_swap_path: Vec::new(),
            callback_gas_limit_raw: None,
            should_unwrap_native_token: None,
            strategy_id: None,
            callback_url: None,
        }
    }

    #[test]
    fn rejects_base_until_an_official_deployment_exists() {
        let mut req = sample_req("market_increase");
        req.chain = "base".to_string();

        assert!(validate_create_order_request(&req)
            .unwrap_err()
            .to_string()
            .contains("no official Base Sepolia deployment"));
    }

    #[test]
    fn omitted_chain_fails_closed_on_base() {
        assert_eq!(default_chain(), "base");
        assert!(validate_chain(&default_chain())
            .unwrap_err()
            .to_string()
            .contains("no official Base Sepolia deployment"));
    }

    #[test]
    fn create_order_compiles_to_approve_and_exchange_router_multicall() {
        let wallet: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let req = sample_req("market_increase");
        let compiled = compile_create_order(&req, wallet).unwrap();
        let calls = compiled.batch_calls.unwrap();

        assert_eq!(compiled.chain, "arbitrum");
        assert_eq!(calls.len(), 2);
        assert_eq!(
            calls[0].target_contract,
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(
            calls[1].target_contract,
            "0xed50b2a1ef0c35daaf08da6486971180237909c3"
        );
        assert!(calls[0].calldata.starts_with("0x095ea7b3"));
        assert!(calls[1].calldata.starts_with("0xac9650d8"));
        assert_eq!(calls[1].value, "1000000000000000");

        let decoded_multicall = abi::decode(
            &[ParamType::Array(Box::new(ParamType::Bytes))],
            &hex::decode(calls[1].calldata.trim_start_matches("0x").get(8..).unwrap()).unwrap(),
        )
        .unwrap();
        let inner_calls = match &decoded_multicall[0] {
            Token::Array(items) => items,
            other => panic!("expected multicall bytes array, got {other:?}"),
        };
        assert_eq!(inner_calls.len(), 3);

        let create_order_bytes = match &inner_calls[2] {
            Token::Bytes(bytes) => bytes,
            other => panic!("expected createOrder bytes, got {other:?}"),
        };
        assert_eq!(&create_order_bytes[..4], &selector("createOrder(((address,address,address,address,address,address,address[]),(uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint256),uint8,uint8,bool,bool,bool,bytes32,bytes32[]))"));

        let create_params = abi::decode(
            &[ParamType::Tuple(vec![
                ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Array(Box::new(ParamType::Address)),
                ]),
                ParamType::Tuple(vec![
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                ]),
                ParamType::Uint(8),
                ParamType::Uint(8),
                ParamType::Bool,
                ParamType::Bool,
                ParamType::Bool,
                ParamType::FixedBytes(32),
                ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ])],
            &create_order_bytes[4..],
        )
        .unwrap();
        let params = match &create_params[0] {
            Token::Tuple(items) => items,
            other => panic!("expected createOrder tuple, got {other:?}"),
        };
        let numbers = match &params[1] {
            Token::Tuple(items) => items,
            other => panic!("expected numbers tuple, got {other:?}"),
        };
        assert_eq!(
            numbers[0],
            Token::Uint(U256::from_dec_str("50000000000000000000000000000000000").unwrap())
        );
        assert_eq!(numbers[1], Token::Uint(U256::from(1_000_000u64)));
        assert_eq!(numbers[7], Token::Uint(U256::zero()));
    }

    #[test]
    fn market_swap_requires_min_output_amount() {
        let mut req = sample_req("market_swap");
        req.min_output_amount_raw = None;
        let err = validate_create_order_request(&req).unwrap_err().to_string();
        assert!(err.contains("min_output_amount_raw is required"));
    }

    #[test]
    fn market_swap_uses_market_as_single_swap_path_and_zeroes_order_market() {
        let wallet: Address = "0x3333333333333333333333333333333333333333"
            .parse()
            .unwrap();
        let mut req = sample_req("market_swap");
        req.swap_path = Vec::new();

        let compiled = compile_create_order(&req, wallet).unwrap();
        let calls = compiled.batch_calls.unwrap();
        let decoded_multicall = abi::decode(
            &[ParamType::Array(Box::new(ParamType::Bytes))],
            &hex::decode(calls[1].calldata.trim_start_matches("0x").get(8..).unwrap()).unwrap(),
        )
        .unwrap();
        let inner_calls = match &decoded_multicall[0] {
            Token::Array(items) => items,
            other => panic!("expected multicall bytes array, got {other:?}"),
        };
        let create_order_bytes = match &inner_calls[2] {
            Token::Bytes(bytes) => bytes,
            other => panic!("expected createOrder bytes, got {other:?}"),
        };
        let create_params = abi::decode(
            &[ParamType::Tuple(vec![
                ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Array(Box::new(ParamType::Address)),
                ]),
                ParamType::Tuple(vec![
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                    ParamType::Uint(256),
                ]),
                ParamType::Uint(8),
                ParamType::Uint(8),
                ParamType::Bool,
                ParamType::Bool,
                ParamType::Bool,
                ParamType::FixedBytes(32),
                ParamType::Array(Box::new(ParamType::FixedBytes(32))),
            ])],
            &create_order_bytes[4..],
        )
        .unwrap();
        let params = match &create_params[0] {
            Token::Tuple(items) => items,
            other => panic!("expected createOrder tuple, got {other:?}"),
        };
        let addresses = match &params[0] {
            Token::Tuple(items) => items,
            other => panic!("expected addresses tuple, got {other:?}"),
        };
        assert_eq!(addresses[4], Token::Address(Address::zero()));
        assert_eq!(
            addresses[6],
            Token::Array(vec![Token::Address(
                "0x1111111111111111111111111111111111111111"
                    .parse()
                    .unwrap()
            )])
        );
    }

    #[test]
    fn cancel_order_encodes_bytes32_key() {
        let req = GmxCancelOrderRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            order_key: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            strategy_id: None,
            callback_url: None,
        };
        let compiled = compile_cancel_order(&req).unwrap();

        assert_eq!(
            compiled.target_contract,
            "0xed50b2a1ef0c35daaf08da6486971180237909c3"
        );
        assert!(compiled.calldata.starts_with("0x7489ec23"));
    }

    #[test]
    fn update_order_uses_gmx_update_selector() {
        let req = GmxUpdateOrderRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            order_key: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            size_delta_usd_raw: "1".to_string(),
            acceptable_price_raw: "2".to_string(),
            trigger_price_raw: "3".to_string(),
            min_output_amount_raw: "4".to_string(),
            valid_from_time_raw: "5".to_string(),
            auto_cancel: Some(true),
            strategy_id: None,
            callback_url: None,
        };
        let compiled = compile_update_order(&req).unwrap();

        assert!(compiled.calldata.starts_with("0xdd5baad2"));
    }

    #[test]
    fn create_deposit_and_withdrawal_build_multicalls() {
        let wallet: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let deposit = compile_create_deposit(&sample_deposit_req(), wallet).unwrap();
        let deposit_calls = deposit.batch_calls.unwrap();
        assert_eq!(deposit_calls.len(), 2);
        assert!(deposit_calls[1].calldata.starts_with("0xac9650d8"));
        assert_eq!(deposit_calls[1].value, "1000000000000000");

        let decoded_deposit_multicall = abi::decode(
            &[ParamType::Array(Box::new(ParamType::Bytes))],
            &hex::decode(
                deposit_calls[1]
                    .calldata
                    .trim_start_matches("0x")
                    .get(8..)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let deposit_inner_calls = match &decoded_deposit_multicall[0] {
            Token::Array(items) => items,
            other => panic!("expected deposit multicall bytes array, got {other:?}"),
        };
        let create_deposit_bytes = match &deposit_inner_calls[2] {
            Token::Bytes(bytes) => bytes,
            other => panic!("expected createDeposit bytes, got {other:?}"),
        };
        assert_eq!(
            &create_deposit_bytes[..4],
            &selector("createDeposit(((address,address,address,address,address,address,address[],address[]),uint256,bool,uint256,uint256,bytes32[]))")
        );

        let withdrawal_req = GmxCreateWithdrawalRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            market: "0x1111111111111111111111111111111111111111".to_string(),
            market_token_amount_raw: "1000000000000000000".to_string(),
            min_long_token_amount_raw: "1".to_string(),
            min_short_token_amount_raw: "1".to_string(),
            execution_fee_raw: "1000000000000000".to_string(),
            receiver: None,
            callback_contract: None,
            ui_fee_receiver: None,
            long_token_swap_path: Vec::new(),
            short_token_swap_path: Vec::new(),
            callback_gas_limit_raw: None,
            should_unwrap_native_token: None,
            strategy_id: None,
            callback_url: None,
        };
        let withdrawal = compile_create_withdrawal(&withdrawal_req, wallet).unwrap();
        let withdrawal_calls = withdrawal.batch_calls.unwrap();
        assert_eq!(withdrawal_calls.len(), 2);
        assert!(withdrawal_calls[1].calldata.starts_with("0xac9650d8"));

        let decoded_withdrawal_multicall = abi::decode(
            &[ParamType::Array(Box::new(ParamType::Bytes))],
            &hex::decode(
                withdrawal_calls[1]
                    .calldata
                    .trim_start_matches("0x")
                    .get(8..)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let withdrawal_inner_calls = match &decoded_withdrawal_multicall[0] {
            Token::Array(items) => items,
            other => panic!("expected withdrawal multicall bytes array, got {other:?}"),
        };
        let create_withdrawal_bytes = match &withdrawal_inner_calls[2] {
            Token::Bytes(bytes) => bytes,
            other => panic!("expected createWithdrawal bytes, got {other:?}"),
        };
        assert_eq!(
            &create_withdrawal_bytes[..4],
            &selector("createWithdrawal(((address,address,address,address,address[],address[]),uint256,uint256,bool,uint256,uint256,bytes32[]))")
        );
    }

    #[test]
    fn generic_cancel_and_claim_encode_expected_selectors() {
        let cancel = GmxCancelRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            request_type: "deposit".to_string(),
            key: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            strategy_id: None,
            callback_url: None,
        };
        let compiled_cancel = compile_cancel(&cancel).unwrap();
        assert!(compiled_cancel.calldata.starts_with("0x31404484"));

        let wallet: Address = "0x4444444444444444444444444444444444444444"
            .parse()
            .unwrap();
        let claim = GmxClaimRequest {
            agent_id: "agent-1".to_string(),
            chain: "arbitrum".to_string(),
            claim_type: "funding_fees".to_string(),
            markets: vec!["0x1111111111111111111111111111111111111111".to_string()],
            tokens: vec!["0x2222222222222222222222222222222222222222".to_string()],
            time_keys_raw: Vec::new(),
            receiver: None,
            strategy_id: None,
            callback_url: None,
        };
        let compiled_claim = compile_claim(&claim, wallet).unwrap();
        assert!(compiled_claim.calldata.starts_with("0xc41b1ab3"));
    }
}
