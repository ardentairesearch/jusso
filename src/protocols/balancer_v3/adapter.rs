//! Balancer V3 typed swap and liquidity adapter.

use anyhow::{anyhow, Result};
use ethers::abi::{self, ParamType, Token};
use ethers::types::{Address, U256};
use ethers::utils::id;
use serde::{Deserialize, Serialize};

use crate::types::{BatchCall, ExecutionRequest};

const BALANCER_V3_SEPOLIA_ROUTER: &str = "0x5e315f96389C1aaF9324D97d3512ae1e0Bf3C21a";
const BALANCER_V3_SEPOLIA_VAULT: &str = "0xbA1333333333a1BA1108E8412f11850A5C319bA9";
const BALANCER_V3_SEPOLIA_VAULT_EXPLORER: &str = "0xC82E329C832CAcc8DA65dbB57ac72B068e0CEb9B";
const BALANCER_V3_SEPOLIA_PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
pub const MAX_ADD_LIQUIDITY_INPUT_TOKENS: usize = 3;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BalancerSwapKind {
    ExactIn,
    ExactOut,
}

impl Default for BalancerSwapKind {
    fn default() -> Self {
        Self::ExactIn
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerSwapRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Optional Balancer V3 pool address. Omit for automatic pool discovery.
    #[serde(default)]
    pub pool: String,
    pub token_in: String,
    pub token_out: String,
    #[serde(default)]
    pub swap_kind: BalancerSwapKind,
    /// Exact input amount for `exact_in`, or exact output amount for `exact_out`.
    pub amount_raw: String,
    /// Minimum output for `exact_in`, or maximum input for `exact_out`.
    /// When omitted, the service derives it from the live quote and `slippage_bps`.
    #[serde(default)]
    pub limit_raw: Option<String>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u16,
    /// Unix timestamp used by the Router and the expiring Permit2 allowance.
    /// Defaults to twenty minutes after request handling.
    #[serde(default)]
    pub deadline: Option<u64>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerTokenAmount {
    pub token: String,
    pub amount_raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerAddLiquidityRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub pool: String,
    pub amounts_in: Vec<BalancerTokenAmount>,
    /// Minimum BPT to receive. Derived from the live quote when omitted.
    #[serde(default)]
    pub min_bpt_amount_out_raw: Option<String>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u16,
    /// Unix timestamp used only for the expiring Permit2 allowances.
    #[serde(default)]
    pub deadline: Option<u64>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerRemoveLiquidityRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub pool: String,
    pub bpt_amount_in_raw: String,
    /// Optional per-token minimums. Missing pool tokens default to zero.
    #[serde(default)]
    pub min_amounts_out: Option<Vec<BalancerTokenAmount>>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u16,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalancerPoolQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub pool: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalancerBalancesQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub pool: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BalancerPoolsQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub token_in: String,
    pub token_out: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BalancerPoolSelection {
    Automatic,
    Explicit,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerPoolResponse {
    pub chain: String,
    pub pool_address: String,
    pub pool_name: String,
    pub pool_symbol: String,
    pub pool_decimals: u8,
    pub total_supply_raw: String,
    pub total_supply_formatted: String,
    pub router_address: String,
    pub vault_address: String,
    pub vault_explorer_address: String,
    pub permit2_address: String,
    pub is_registered: bool,
    pub is_initialized: bool,
    pub is_paused: bool,
    pub is_in_recovery_mode: bool,
    pub static_swap_fee_percentage_raw: String,
    pub tokens: Vec<BalancerPoolToken>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerPoolToken {
    pub index: usize,
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub pool_balance_raw: String,
    pub pool_balance_formatted: String,
    pub live_balance_scaled_18_raw: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerBalancesResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub pool_address: String,
    pub bpt_balance_raw: String,
    pub bpt_balance_formatted: String,
    pub tokens: Vec<BalancerTokenBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerTokenBalance {
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub wallet_balance_raw: String,
    pub wallet_balance_formatted: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerQuoteResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub pool_address: String,
    pub pool_selection: BalancerPoolSelection,
    pub candidates_discovered: usize,
    pub candidates_quoted: usize,
    pub token_in: String,
    pub token_out: String,
    pub swap_kind: BalancerSwapKind,
    pub amount_raw: String,
    pub quoted_amount_raw: String,
    pub limit_raw: String,
    pub slippage_bps: u16,
    pub deadline: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerDiscoveredPool {
    pub pool_address: String,
    pub name: String,
    pub symbol: String,
    pub pool_type: String,
    pub total_liquidity_usd: Option<String>,
    pub swap_fee: Option<String>,
    pub tokens: Vec<BalancerDiscoveredPoolToken>,
    pub is_initialized: bool,
    pub is_paused: bool,
    pub is_in_recovery_mode: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerDiscoveredPoolToken {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerPoolsResponse {
    pub chain: String,
    pub token_in: String,
    pub token_out: String,
    pub pools: Vec<BalancerDiscoveredPool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerLiquidityAmount {
    pub token: String,
    pub amount_raw: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerAddLiquidityQuoteResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub pool_address: String,
    pub amounts_in: Vec<BalancerLiquidityAmount>,
    pub quoted_bpt_amount_out_raw: String,
    pub min_bpt_amount_out_raw: String,
    pub slippage_bps: u16,
    pub deadline: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BalancerRemoveLiquidityQuoteResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub pool_address: String,
    pub bpt_amount_in_raw: String,
    pub quoted_amounts_out: Vec<BalancerLiquidityAmount>,
    pub min_amounts_out: Vec<BalancerLiquidityAmount>,
    pub slippage_bps: u16,
}

pub fn router_address() -> Address {
    parse_hardcoded(BALANCER_V3_SEPOLIA_ROUTER, "Balancer V3 Sepolia Router")
}

pub fn vault_address() -> Address {
    parse_hardcoded(BALANCER_V3_SEPOLIA_VAULT, "Balancer V3 Sepolia Vault")
}

pub fn vault_explorer_address() -> Address {
    parse_hardcoded(
        BALANCER_V3_SEPOLIA_VAULT_EXPLORER,
        "Balancer V3 Sepolia Vault Explorer",
    )
}

pub fn permit2_address() -> Address {
    parse_hardcoded(BALANCER_V3_SEPOLIA_PERMIT2, "Balancer V3 Sepolia Permit2")
}

pub fn validate_swap_request(req: &BalancerSwapRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    if req.agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }

    let pool = if req.pool.trim().is_empty() {
        None
    } else {
        Some(parse_address(&req.pool, "pool")?)
    };
    let token_in = parse_address(&req.token_in, "token_in")?;
    let token_out = parse_address(&req.token_out, "token_out")?;
    if pool == Some(Address::zero()) {
        return Err(anyhow!("pool must not be the zero address"));
    }
    if token_in == Address::zero() || token_out == Address::zero() {
        return Err(anyhow!("token addresses must not be the zero address"));
    }
    if token_in == token_out {
        return Err(anyhow!("token_in and token_out must be different"));
    }

    let amount = parse_positive_u256(&req.amount_raw, "amount_raw")?;
    if req.swap_kind == BalancerSwapKind::ExactIn {
        validate_permit2_amount(amount, "amount_raw")?;
    }
    if let Some(limit) = req.limit_raw.as_deref() {
        let limit = parse_positive_u256(limit, "limit_raw")?;
        if req.swap_kind == BalancerSwapKind::ExactOut {
            validate_permit2_amount(limit, "limit_raw")?;
        }
    }
    if req.slippage_bps > 10_000 {
        return Err(anyhow!("slippage_bps must be between 0 and 10000"));
    }
    if let Some(deadline) = req.deadline {
        if deadline == 0 || deadline > ((1u64 << 48) - 1) {
            return Err(anyhow!("deadline must fit in uint48"));
        }
    }
    Ok(())
}

pub fn validate_pools_query(query: &BalancerPoolsQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    let token_in = parse_address(&query.token_in, "token_in")?;
    let token_out = parse_address(&query.token_out, "token_out")?;
    if token_in == Address::zero() || token_out == Address::zero() {
        return Err(anyhow!("token addresses must not be the zero address"));
    }
    if token_in == token_out {
        return Err(anyhow!("token_in and token_out must be different"));
    }
    Ok(())
}

pub fn validate_add_liquidity_request(req: &BalancerAddLiquidityRequest) -> Result<()> {
    validate_common_liquidity_request(&req.agent_id, &req.chain, &req.pool, req.slippage_bps)?;
    validate_token_amounts(&req.amounts_in, "amounts_in", false)?;
    if req.amounts_in.len() > MAX_ADD_LIQUIDITY_INPUT_TOKENS {
        return Err(anyhow!(
            "amounts_in supports at most {MAX_ADD_LIQUIDITY_INPUT_TOKENS} deposited tokens per operation"
        ));
    }
    for entry in &req.amounts_in {
        validate_permit2_amount(
            parse_positive_u256(&entry.amount_raw, "amounts_in.amount_raw")?,
            "amounts_in.amount_raw",
        )?;
    }
    if let Some(min_bpt) = req.min_bpt_amount_out_raw.as_deref() {
        parse_positive_u256(min_bpt, "min_bpt_amount_out_raw")?;
    }
    validate_deadline(req.deadline)?;
    Ok(())
}

pub fn validate_remove_liquidity_request(req: &BalancerRemoveLiquidityRequest) -> Result<()> {
    validate_common_liquidity_request(&req.agent_id, &req.chain, &req.pool, req.slippage_bps)?;
    parse_positive_u256(&req.bpt_amount_in_raw, "bpt_amount_in_raw")?;
    if let Some(min_amounts) = req.min_amounts_out.as_deref() {
        validate_token_amounts(min_amounts, "min_amounts_out", false)?;
    }
    Ok(())
}

pub fn validate_pool_query(query: &BalancerPoolQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    let pool = parse_address(&query.pool, "pool")?;
    if pool == Address::zero() {
        return Err(anyhow!("pool must not be the zero address"));
    }
    Ok(())
}

pub fn validate_balances_query(query: &BalancerBalancesQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    if query.agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    let pool = parse_address(&query.pool, "pool")?;
    if pool == Address::zero() {
        return Err(anyhow!("pool must not be the zero address"));
    }
    Ok(())
}

pub fn compile_swap(req: &BalancerSwapRequest) -> Result<ExecutionRequest> {
    validate_swap_request(req)?;
    if req.pool.trim().is_empty() {
        return Err(anyhow!(
            "pool must be resolved before compiling a Balancer swap"
        ));
    }
    let pool = parse_address(&req.pool, "pool")?;
    let token_in = parse_address(&req.token_in, "token_in")?;
    let token_out = parse_address(&req.token_out, "token_out")?;
    let amount = parse_positive_u256(&req.amount_raw, "amount_raw")?;
    let limit = parse_positive_u256(
        req.limit_raw.as_deref().ok_or_else(|| {
            anyhow!("limit_raw must be resolved before compiling a Balancer swap")
        })?,
        "limit_raw",
    )?;
    let deadline = req
        .deadline
        .ok_or_else(|| anyhow!("deadline must be resolved before compiling a Balancer swap"))?;

    let max_input = match req.swap_kind {
        BalancerSwapKind::ExactIn => amount,
        BalancerSwapKind::ExactOut => limit,
    };
    if max_input > uint160_max() {
        return Err(anyhow!(
            "Balancer Permit2 input amount exceeds the supported uint160 allowance range"
        ));
    }

    let router = router_address();
    let permit2 = permit2_address();
    let router_calldata = match req.swap_kind {
        BalancerSwapKind::ExactIn => {
            encode_swap_exact_in(pool, token_in, token_out, amount, limit, deadline)
        }
        BalancerSwapKind::ExactOut => {
            encode_swap_exact_out(pool, token_in, token_out, amount, limit, deadline)
        }
    };

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "balancer-v3-sepolia-swap-{}",
                match req.swap_kind {
                    BalancerSwapKind::ExactIn => "exact-in",
                    BalancerSwapKind::ExactOut => "exact-out",
                }
            ))
        }),
        batch_calls: Some(vec![
            BatchCall {
                target_contract: format!("{token_in:?}"),
                calldata: encode_erc20_approve(permit2, U256::zero()),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{token_in:?}"),
                calldata: encode_erc20_approve(permit2, max_input),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{permit2:?}"),
                calldata: encode_permit2_approve(token_in, router, max_input, deadline)?,
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{router:?}"),
                calldata: router_calldata,
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{permit2:?}"),
                calldata: encode_permit2_approve(token_in, router, U256::zero(), deadline)?,
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{token_in:?}"),
                calldata: encode_erc20_approve(permit2, U256::zero()),
                value: "0".to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_add_liquidity(
    req: &BalancerAddLiquidityRequest,
    tokens: &[Address],
    amounts_in: &[U256],
    min_bpt_amount_out: U256,
    deadline: u64,
) -> Result<ExecutionRequest> {
    validate_add_liquidity_request(req)?;
    if tokens.is_empty() || tokens.len() != amounts_in.len() {
        return Err(anyhow!(
            "Balancer add-liquidity token and amount arrays must have equal non-zero length"
        ));
    }
    validate_deadline(Some(deadline))?;

    let router = router_address();
    let permit2 = permit2_address();
    let mut batch_calls =
        Vec::with_capacity(amounts_in.iter().filter(|amount| !amount.is_zero()).count() * 5 + 1);

    for (token, amount) in tokens.iter().copied().zip(amounts_in.iter().copied()) {
        if amount.is_zero() {
            continue;
        }
        if amount > uint160_max() {
            return Err(anyhow!(
                "Balancer Permit2 liquidity amount exceeds the supported uint160 allowance range"
            ));
        }
        batch_calls.push(BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_erc20_approve(permit2, U256::zero()),
            value: "0".to_string(),
        });
        batch_calls.push(BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_erc20_approve(permit2, amount),
            value: "0".to_string(),
        });
        batch_calls.push(BatchCall {
            target_contract: format!("{permit2:?}"),
            calldata: encode_permit2_approve(token, router, amount, deadline)?,
            value: "0".to_string(),
        });
    }

    batch_calls.push(BatchCall {
        target_contract: format!("{router:?}"),
        calldata: encode_add_liquidity_unbalanced(
            parse_address(&req.pool, "pool")?,
            amounts_in,
            min_bpt_amount_out,
        ),
        value: "0".to_string(),
    });

    for (token, amount) in tokens.iter().copied().zip(amounts_in.iter()) {
        if amount.is_zero() {
            continue;
        }
        batch_calls.push(BatchCall {
            target_contract: format!("{permit2:?}"),
            calldata: encode_permit2_approve(token, router, U256::zero(), deadline)?,
            value: "0".to_string(),
        });
        batch_calls.push(BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_erc20_approve(permit2, U256::zero()),
            value: "0".to_string(),
        });
    }

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("balancer-v3-sepolia-add-liquidity".to_string())),
        batch_calls: Some(batch_calls),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_remove_liquidity(
    req: &BalancerRemoveLiquidityRequest,
    min_amounts_out: &[U256],
) -> Result<ExecutionRequest> {
    validate_remove_liquidity_request(req)?;
    if min_amounts_out.is_empty() {
        return Err(anyhow!(
            "Balancer remove-liquidity minimum output array must not be empty"
        ));
    }
    let pool = parse_address(&req.pool, "pool")?;
    let bpt_amount_in = parse_positive_u256(&req.bpt_amount_in_raw, "bpt_amount_in_raw")?;
    let router = router_address();

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some("balancer-v3-sepolia-remove-liquidity".to_string())),
        batch_calls: Some(vec![
            BatchCall {
                target_contract: format!("{pool:?}"),
                calldata: encode_erc20_approve(router, U256::zero()),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{pool:?}"),
                calldata: encode_erc20_approve(router, bpt_amount_in),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{router:?}"),
                calldata: encode_remove_liquidity_proportional(
                    pool,
                    bpt_amount_in,
                    min_amounts_out,
                ),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{pool:?}"),
                calldata: encode_erc20_approve(router, U256::zero()),
                value: "0".to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn swap_with_resolved_limit(
    req: &BalancerSwapRequest,
    pool: Address,
    limit: U256,
    deadline: u64,
) -> BalancerSwapRequest {
    let mut resolved = req.clone();
    resolved.pool = format!("{pool:?}");
    resolved.limit_raw = Some(limit.to_string());
    resolved.deadline = Some(deadline);
    resolved
}

pub fn parse_request_address(value: &str, field: &str) -> Result<Address> {
    parse_address(value, field)
}

pub fn amount(req: &BalancerSwapRequest) -> Result<U256> {
    parse_positive_u256(&req.amount_raw, "amount_raw")
}

pub fn explicit_limit(req: &BalancerSwapRequest) -> Result<Option<U256>> {
    req.limit_raw
        .as_deref()
        .map(|value| parse_positive_u256(value, "limit_raw"))
        .transpose()
}

pub fn validate_permit2_amount(amount: U256, field: &str) -> Result<()> {
    if amount > uint160_max() {
        return Err(anyhow!(
            "{field} exceeds the Permit2 uint160 allowance range"
        ));
    }
    Ok(())
}

pub fn encode_query_swap(req: &BalancerSwapRequest, sender: Address) -> Result<String> {
    let pool = parse_address(&req.pool, "pool")?;
    let token_in = parse_address(&req.token_in, "token_in")?;
    let token_out = parse_address(&req.token_out, "token_out")?;
    let amount = amount(req)?;
    let (signature, tokens) = match req.swap_kind {
        BalancerSwapKind::ExactIn => (
            "querySwapSingleTokenExactIn(address,address,address,uint256,address,bytes)",
            vec![
                Token::Address(pool),
                Token::Address(token_in),
                Token::Address(token_out),
                Token::Uint(amount),
                Token::Address(sender),
                Token::Bytes(Vec::new()),
            ],
        ),
        BalancerSwapKind::ExactOut => (
            "querySwapSingleTokenExactOut(address,address,address,uint256,address,bytes)",
            vec![
                Token::Address(pool),
                Token::Address(token_in),
                Token::Address(token_out),
                Token::Uint(amount),
                Token::Address(sender),
                Token::Bytes(Vec::new()),
            ],
        ),
    };
    Ok(encode_call(selector(signature), &tokens))
}

pub fn encode_query_add_liquidity_unbalanced(
    pool: Address,
    amounts_in: &[U256],
    sender: Address,
) -> String {
    encode_call(
        selector("queryAddLiquidityUnbalanced(address,uint256[],address,bytes)"),
        &[
            Token::Address(pool),
            Token::Array(amounts_in.iter().copied().map(Token::Uint).collect()),
            Token::Address(sender),
            Token::Bytes(Vec::new()),
        ],
    )
}

pub fn encode_query_remove_liquidity_proportional(
    pool: Address,
    bpt_amount_in: U256,
    sender: Address,
) -> String {
    encode_call(
        selector("queryRemoveLiquidityProportional(address,uint256,address,bytes)"),
        &[
            Token::Address(pool),
            Token::Uint(bpt_amount_in),
            Token::Address(sender),
            Token::Bytes(Vec::new()),
        ],
    )
}

pub fn decode_u256(raw: &[u8], context: &str) -> Result<U256> {
    let decoded = abi::decode(&[ParamType::Uint(256)], raw)
        .map_err(|e| anyhow!("failed to decode {context}: {e}"))?;
    decoded[0]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode {context} as uint256"))
}

pub fn decode_u256_array(raw: &[u8], context: &str) -> Result<Vec<U256>> {
    let decoded = abi::decode(&[ParamType::Array(Box::new(ParamType::Uint(256)))], raw)
        .map_err(|e| anyhow!("failed to decode {context}: {e}"))?;
    let values = decoded[0]
        .clone()
        .into_array()
        .ok_or_else(|| anyhow!("failed to decode {context} as uint256[]"))?;
    values
        .into_iter()
        .map(|token| {
            token
                .into_uint()
                .ok_or_else(|| anyhow!("failed to decode {context} amount"))
        })
        .collect()
}

pub fn decode_pool_token_info(raw: &[u8]) -> Result<(Vec<Address>, Vec<U256>)> {
    let token_info = ParamType::Tuple(vec![
        ParamType::Uint(8),
        ParamType::Address,
        ParamType::Bool,
    ]);
    let decoded = abi::decode(
        &[
            ParamType::Array(Box::new(ParamType::Address)),
            ParamType::Array(Box::new(token_info)),
            ParamType::Array(Box::new(ParamType::Uint(256))),
            ParamType::Array(Box::new(ParamType::Uint(256))),
        ],
        raw,
    )
    .map_err(|e| anyhow!("failed to decode Balancer pool token info: {e}"))?;

    let tokens = decoded[0]
        .clone()
        .into_array()
        .ok_or_else(|| anyhow!("failed to decode Balancer pool tokens"))?
        .into_iter()
        .map(|token| {
            token
                .into_address()
                .ok_or_else(|| anyhow!("failed to decode Balancer pool token address"))
        })
        .collect::<Result<Vec<_>>>()?;
    let balances = decoded[2]
        .clone()
        .into_array()
        .ok_or_else(|| anyhow!("failed to decode Balancer pool raw balances"))?
        .into_iter()
        .map(|token| {
            token
                .into_uint()
                .ok_or_else(|| anyhow!("failed to decode Balancer pool raw balance"))
        })
        .collect::<Result<Vec<_>>>()?;

    if tokens.len() != balances.len() {
        return Err(anyhow!(
            "Balancer pool token metadata returned mismatched token and balance lengths"
        ));
    }
    Ok((tokens, balances))
}

pub fn decode_bool(raw: &[u8], context: &str) -> Result<bool> {
    let decoded = abi::decode(&[ParamType::Bool], raw)
        .map_err(|e| anyhow!("failed to decode {context}: {e}"))?;
    decoded[0]
        .clone()
        .into_bool()
        .ok_or_else(|| anyhow!("failed to decode {context} as bool"))
}

pub fn encode_get_current_live_balances(pool: Address) -> String {
    encode_call(
        selector("getCurrentLiveBalances(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_get_pool_token_info(pool: Address) -> String {
    encode_call(
        selector("getPoolTokenInfo(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_is_pool_registered(pool: Address) -> String {
    encode_call(
        selector("isPoolRegistered(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_is_pool_initialized(pool: Address) -> String {
    encode_call(
        selector("isPoolInitialized(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_is_pool_paused(pool: Address) -> String {
    encode_call(selector("isPoolPaused(address)"), &[Token::Address(pool)])
}

pub fn encode_is_pool_in_recovery_mode(pool: Address) -> String {
    encode_call(
        selector("isPoolInRecoveryMode(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_get_static_swap_fee_percentage(pool: Address) -> String {
    encode_call(
        selector("getStaticSwapFeePercentage(address)"),
        &[Token::Address(pool)],
    )
}

pub fn encode_balance_of(account: Address) -> String {
    encode_call(selector("balanceOf(address)"), &[Token::Address(account)])
}

pub fn encode_total_supply() -> String {
    encode_call(selector("totalSupply()"), &[])
}

pub fn encode_decimals() -> String {
    encode_call(selector("decimals()"), &[])
}

pub fn encode_symbol() -> String {
    encode_call(selector("symbol()"), &[])
}

pub fn encode_name() -> String {
    encode_call(selector("name()"), &[])
}

fn encode_swap_exact_in(
    pool: Address,
    token_in: Address,
    token_out: Address,
    amount_in: U256,
    min_amount_out: U256,
    deadline: u64,
) -> String {
    encode_call(
        selector(
            "swapSingleTokenExactIn(address,address,address,uint256,uint256,uint256,bool,bytes)",
        ),
        &[
            Token::Address(pool),
            Token::Address(token_in),
            Token::Address(token_out),
            Token::Uint(amount_in),
            Token::Uint(min_amount_out),
            Token::Uint(U256::from(deadline)),
            Token::Bool(false),
            Token::Bytes(Vec::new()),
        ],
    )
}

fn encode_swap_exact_out(
    pool: Address,
    token_in: Address,
    token_out: Address,
    amount_out: U256,
    max_amount_in: U256,
    deadline: u64,
) -> String {
    encode_call(
        selector(
            "swapSingleTokenExactOut(address,address,address,uint256,uint256,uint256,bool,bytes)",
        ),
        &[
            Token::Address(pool),
            Token::Address(token_in),
            Token::Address(token_out),
            Token::Uint(amount_out),
            Token::Uint(max_amount_in),
            Token::Uint(U256::from(deadline)),
            Token::Bool(false),
            Token::Bytes(Vec::new()),
        ],
    )
}

fn encode_add_liquidity_unbalanced(
    pool: Address,
    amounts_in: &[U256],
    min_bpt_amount_out: U256,
) -> String {
    encode_call(
        selector("addLiquidityUnbalanced(address,uint256[],uint256,bool,bytes)"),
        &[
            Token::Address(pool),
            Token::Array(amounts_in.iter().copied().map(Token::Uint).collect()),
            Token::Uint(min_bpt_amount_out),
            Token::Bool(false),
            Token::Bytes(Vec::new()),
        ],
    )
}

fn encode_remove_liquidity_proportional(
    pool: Address,
    bpt_amount_in: U256,
    min_amounts_out: &[U256],
) -> String {
    encode_call(
        selector("removeLiquidityProportional(address,uint256,uint256[],bool,bytes)"),
        &[
            Token::Address(pool),
            Token::Uint(bpt_amount_in),
            Token::Array(min_amounts_out.iter().copied().map(Token::Uint).collect()),
            Token::Bool(false),
            Token::Bytes(Vec::new()),
        ],
    )
}

fn encode_erc20_approve(spender: Address, amount: U256) -> String {
    encode_call(
        selector("approve(address,uint256)"),
        &[Token::Address(spender), Token::Uint(amount)],
    )
}

fn encode_permit2_approve(
    token: Address,
    spender: Address,
    amount: U256,
    expiration: u64,
) -> Result<String> {
    if amount > uint160_max() {
        return Err(anyhow!("Permit2 approval amount exceeds uint160"));
    }
    if expiration > ((1u64 << 48) - 1) {
        return Err(anyhow!("Permit2 expiration exceeds uint48"));
    }
    Ok(encode_call(
        selector("approve(address,address,uint160,uint48)"),
        &[
            Token::Address(token),
            Token::Address(spender),
            Token::Uint(amount),
            Token::Uint(U256::from(expiration)),
        ],
    ))
}

fn validate_chain(chain: &str) -> Result<()> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "ethereum" | "eth" | "sepolia" => Ok(()),
        "base" | "base-sepolia" | "base_sepolia" => Err(anyhow!(
            "Balancer V3 has no official Base Sepolia deployment; keep this protocol disabled on Base"
        )),
        other => Err(anyhow!(
            "Balancer V3 typed adapter currently supports Ethereum Sepolia only; use chain \"ethereum\", got \"{other}\""
        )),
    }
}

fn validate_common_liquidity_request(
    agent_id: &str,
    chain: &str,
    pool: &str,
    slippage_bps: u16,
) -> Result<()> {
    validate_chain(chain)?;
    if agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    if parse_address(pool, "pool")? == Address::zero() {
        return Err(anyhow!("pool must not be the zero address"));
    }
    if slippage_bps > 10_000 {
        return Err(anyhow!("slippage_bps must be between 0 and 10000"));
    }
    Ok(())
}

fn validate_token_amounts(
    amounts: &[BalancerTokenAmount],
    field: &str,
    allow_empty: bool,
) -> Result<()> {
    if amounts.is_empty() && !allow_empty {
        return Err(anyhow!("{field} must contain at least one token amount"));
    }
    let mut seen = std::collections::HashSet::new();
    for entry in amounts {
        let token = parse_address(&entry.token, &format!("{field}.token"))?;
        if token == Address::zero() {
            return Err(anyhow!("{field} token must not be the zero address"));
        }
        if !seen.insert(token) {
            return Err(anyhow!("{field} contains a duplicate token address"));
        }
        parse_positive_u256(&entry.amount_raw, &format!("{field}.amount_raw"))?;
    }
    Ok(())
}

fn validate_deadline(deadline: Option<u64>) -> Result<()> {
    if let Some(deadline) = deadline {
        if deadline == 0 || deadline > ((1u64 << 48) - 1) {
            return Err(anyhow!("deadline must fit in uint48"));
        }
    }
    Ok(())
}

fn parse_address(value: &str, field: &str) -> Result<Address> {
    value
        .trim()
        .parse::<Address>()
        .map_err(|_| anyhow!("{field} must be a valid EVM address"))
}

fn parse_positive_u256(value: &str, field: &str) -> Result<U256> {
    let parsed = U256::from_dec_str(value.trim())
        .map_err(|_| anyhow!("{field} must be a raw unsigned integer string"))?;
    if parsed.is_zero() {
        return Err(anyhow!("{field} must be greater than zero"));
    }
    Ok(parsed)
}

fn parse_hardcoded(value: &str, label: &str) -> Address {
    value
        .parse()
        .unwrap_or_else(|_| panic!("hardcoded {label} address must be valid"))
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = id(signature);
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_call(selector: [u8; 4], tokens: &[Token]) -> String {
    let mut data = selector.to_vec();
    data.extend(abi::encode(tokens));
    format!("0x{}", hex::encode(data))
}

fn uint160_max() -> U256 {
    (U256::one() << 160) - U256::one()
}

fn default_chain() -> String {
    "base".to_string()
}

fn default_slippage_bps() -> u16 {
    100
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> BalancerSwapRequest {
        BalancerSwapRequest {
            agent_id: "agent-1".to_string(),
            chain: "ethereum".to_string(),
            pool: "0x48537ba872d86026deda098360c0b87d678a8d82".to_string(),
            token_in: "0x7b79995e5f793a07bc00c21412e50ecae098e7f9".to_string(),
            token_out: "0xaa8e23fb1079ea71e0a56f48a2aa51851d8433d0".to_string(),
            swap_kind: BalancerSwapKind::ExactIn,
            amount_raw: "1000000000000000".to_string(),
            limit_raw: Some("1".to_string()),
            slippage_bps: 100,
            deadline: Some(2_000_000_000),
            strategy_id: None,
            callback_url: None,
        }
    }

    fn add_liquidity_request() -> BalancerAddLiquidityRequest {
        BalancerAddLiquidityRequest {
            agent_id: "agent-1".to_string(),
            chain: "ethereum".to_string(),
            pool: "0x48537ba872d86026deda098360c0b87d678a8d82".to_string(),
            amounts_in: vec![
                BalancerTokenAmount {
                    token: "0x7b79995e5f793a07bc00c21412e50ecae098e7f9".to_string(),
                    amount_raw: "1000000".to_string(),
                },
                BalancerTokenAmount {
                    token: "0xaa8e23fb1079ea71e0a56f48a2aa51851d8433d0".to_string(),
                    amount_raw: "2000000".to_string(),
                },
            ],
            min_bpt_amount_out_raw: None,
            slippage_bps: 100,
            deadline: Some(2_000_000_000),
            strategy_id: None,
            callback_url: None,
        }
    }

    fn remove_liquidity_request() -> BalancerRemoveLiquidityRequest {
        BalancerRemoveLiquidityRequest {
            agent_id: "agent-1".to_string(),
            chain: "ethereum".to_string(),
            pool: "0x48537ba872d86026deda098360c0b87d678a8d82".to_string(),
            bpt_amount_in_raw: "1000000000000000000".to_string(),
            min_amounts_out: None,
            slippage_bps: 100,
            strategy_id: None,
            callback_url: None,
        }
    }

    #[test]
    fn compiles_exact_in_with_permit2_batch() {
        let compiled = compile_swap(&request()).unwrap();
        let calls = compiled.batch_calls.unwrap();

        assert_eq!(calls.len(), 6);
        assert_eq!(
            calls[0].target_contract.to_ascii_lowercase(),
            "0x7b79995e5f793a07bc00c21412e50ecae098e7f9"
        );
        assert_eq!(
            calls[2].target_contract.to_ascii_lowercase(),
            BALANCER_V3_SEPOLIA_PERMIT2.to_ascii_lowercase()
        );
        assert_eq!(
            calls[3].target_contract.to_ascii_lowercase(),
            BALANCER_V3_SEPOLIA_ROUTER.to_ascii_lowercase()
        );
        assert!(calls[0].calldata.starts_with("0x095ea7b3"));
        assert!(calls[1].calldata.starts_with("0x095ea7b3"));
        assert!(calls[2].calldata.starts_with("0x87517c45"));
        assert!(calls[3].calldata.starts_with("0x750283bc"));
        assert!(calls[4].calldata.starts_with("0x87517c45"));
        assert!(calls[5].calldata.starts_with("0x095ea7b3"));
        assert_eq!(calldata_word(&calls[0].calldata, 1), U256::zero());
        assert_eq!(
            calldata_word(&calls[1].calldata, 1),
            U256::from_dec_str("1000000000000000").unwrap()
        );
        assert_eq!(calldata_word(&calls[4].calldata, 2), U256::zero());
        assert_eq!(calldata_word(&calls[5].calldata, 1), U256::zero());
    }

    #[test]
    fn automatic_swap_request_omits_pool() {
        let req: BalancerSwapRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "agent-1",
            "chain": "ethereum",
            "token_in": "0x7b79995e5f793a07bc00c21412e50ecae098e7f9",
            "token_out": "0xaa8e23fb1079ea71e0a56f48a2aa51851d8433d0",
            "amount_raw": "1000000"
        }))
        .unwrap();
        assert!(req.pool.is_empty());
        validate_swap_request(&req).unwrap();
        assert!(compile_swap(&req)
            .unwrap_err()
            .to_string()
            .contains("must be resolved"));
    }

    #[test]
    fn compiles_exact_out_with_official_router_selector() {
        let mut req = request();
        req.swap_kind = BalancerSwapKind::ExactOut;
        req.amount_raw = "1000000".to_string();
        req.limit_raw = Some("2000000".to_string());

        let compiled = compile_swap(&req).unwrap();
        let calls = compiled.batch_calls.unwrap();
        assert!(calls[3].calldata.starts_with("0x94e86ef8"));
    }

    #[test]
    fn rejects_cross_chain_request() {
        let mut req = request();
        req.chain = "base".to_string();
        assert!(validate_swap_request(&req)
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
    fn rejects_same_input_and_output_token() {
        let mut req = request();
        req.token_out = req.token_in.clone();
        assert!(validate_swap_request(&req)
            .unwrap_err()
            .to_string()
            .contains("must be different"));
    }

    #[test]
    fn query_selector_matches_official_router_signature() {
        let encoded = encode_query_swap(&request(), Address::from_low_u64_be(1)).unwrap();
        let expected =
            selector("querySwapSingleTokenExactIn(address,address,address,uint256,address,bytes)");
        assert_eq!(&encoded[2..10], hex::encode(expected));
    }

    #[test]
    fn compiles_add_liquidity_with_bounded_permit2_approvals() {
        let req = add_liquidity_request();
        let tokens = vec![
            req.amounts_in[0].token.parse().unwrap(),
            req.amounts_in[1].token.parse().unwrap(),
        ];
        let amounts = vec![U256::from(1_000_000u64), U256::from(2_000_000u64)];
        let compiled = compile_add_liquidity(
            &req,
            &tokens,
            &amounts,
            U256::from(2_900_000u64),
            2_000_000_000,
        )
        .unwrap();
        let calls = compiled.batch_calls.unwrap();

        assert_eq!(calls.len(), 11);
        assert!(calls[0].calldata.starts_with("0x095ea7b3"));
        assert!(calls[2].calldata.starts_with("0x87517c45"));
        assert_eq!(
            &calls[6].calldata[2..10],
            hex::encode(selector(
                "addLiquidityUnbalanced(address,uint256[],uint256,bool,bytes)"
            ))
        );
        assert!(calls[7].calldata.starts_with("0x87517c45"));
        assert!(calls[10].calldata.starts_with("0x095ea7b3"));
    }

    #[test]
    fn three_token_add_fits_execution_batch_limit() {
        let mut req = add_liquidity_request();
        req.amounts_in.push(BalancerTokenAmount {
            token: "0x0000000000000000000000000000000000000003".to_string(),
            amount_raw: "3000000".to_string(),
        });
        let tokens = req
            .amounts_in
            .iter()
            .map(|entry| entry.token.parse().unwrap())
            .collect::<Vec<Address>>();
        let amounts = vec![
            U256::from(1_000_000u64),
            U256::from(2_000_000u64),
            U256::from(3_000_000u64),
        ];
        let calls = compile_add_liquidity(&req, &tokens, &amounts, U256::one(), 2_000_000_000)
            .unwrap()
            .batch_calls
            .unwrap();
        assert_eq!(calls.len(), 16);
    }

    #[test]
    fn compiles_remove_liquidity_with_bpt_router_approval() {
        let req = remove_liquidity_request();
        let compiled =
            compile_remove_liquidity(&req, &[U256::from(400_000u64), U256::from(500_000u64)])
                .unwrap();
        let calls = compiled.batch_calls.unwrap();
        assert_eq!(calls.len(), 4);
        assert_eq!(
            calls[0].target_contract.to_ascii_lowercase(),
            req.pool.to_ascii_lowercase()
        );
        assert_eq!(
            calls[1].target_contract.to_ascii_lowercase(),
            req.pool.to_ascii_lowercase()
        );
        assert_eq!(
            calls[2].target_contract.to_ascii_lowercase(),
            BALANCER_V3_SEPOLIA_ROUTER.to_ascii_lowercase()
        );
        assert_eq!(
            calls[3].target_contract.to_ascii_lowercase(),
            req.pool.to_ascii_lowercase()
        );
        assert_eq!(calldata_word(&calls[0].calldata, 1), U256::zero());
        assert_eq!(
            calldata_word(&calls[1].calldata, 1),
            U256::from_dec_str(&req.bpt_amount_in_raw).unwrap()
        );
        assert_eq!(
            &calls[2].calldata[2..10],
            hex::encode(selector(
                "removeLiquidityProportional(address,uint256,uint256[],bool,bytes)"
            ))
        );
        assert_eq!(calldata_word(&calls[3].calldata, 1), U256::zero());
    }

    #[test]
    fn rejects_duplicate_liquidity_tokens() {
        let mut req = add_liquidity_request();
        req.amounts_in[1].token = req.amounts_in[0].token.clone();
        assert!(validate_add_liquidity_request(&req)
            .unwrap_err()
            .to_string()
            .contains("duplicate token"));
    }

    #[test]
    fn rejects_empty_explicit_remove_minimums() {
        let mut req = remove_liquidity_request();
        req.min_amounts_out = Some(Vec::new());
        assert!(validate_remove_liquidity_request(&req)
            .unwrap_err()
            .to_string()
            .contains("must contain at least one"));
    }

    #[test]
    fn rejects_add_liquidity_beyond_atomic_batch_capacity() {
        let mut req = add_liquidity_request();
        req.amounts_in.push(BalancerTokenAmount {
            token: "0x0000000000000000000000000000000000000003".to_string(),
            amount_raw: "3".to_string(),
        });
        req.amounts_in.push(BalancerTokenAmount {
            token: "0x0000000000000000000000000000000000000004".to_string(),
            amount_raw: "4".to_string(),
        });
        assert!(validate_add_liquidity_request(&req)
            .unwrap_err()
            .to_string()
            .contains("at most 3"));
    }

    #[test]
    fn rejects_permit2_amount_over_uint160() {
        let mut req = add_liquidity_request();
        req.amounts_in[0].amount_raw = (U256::one() << 160).to_string();
        assert!(validate_add_liquidity_request(&req)
            .unwrap_err()
            .to_string()
            .contains("uint160"));
    }

    #[test]
    fn liquidity_query_selectors_match_official_router_interface() {
        let pool = Address::from_low_u64_be(1);
        let sender = Address::from_low_u64_be(2);
        let add =
            encode_query_add_liquidity_unbalanced(pool, &[U256::one(), U256::from(2u64)], sender);
        let remove = encode_query_remove_liquidity_proportional(pool, U256::one(), sender);
        assert_eq!(
            &add[2..10],
            hex::encode(selector(
                "queryAddLiquidityUnbalanced(address,uint256[],address,bytes)"
            ))
        );
        assert_eq!(
            &remove[2..10],
            hex::encode(selector(
                "queryRemoveLiquidityProportional(address,uint256,address,bytes)"
            ))
        );
    }

    #[test]
    fn decodes_live_sepolia_pool_token_info_shape() {
        let raw = hex::decode(
            "0000000000000000000000000000000000000000000000000000000000000080\
             00000000000000000000000000000000000000000000000000000000000000e0\
             00000000000000000000000000000000000000000000000000000000000001c0\
             0000000000000000000000000000000000000000000000000000000000000220\
             0000000000000000000000000000000000000000000000000000000000000002\
             0000000000000000000000007b79995e5f793a07bc00c21412e50ecae098e7f9\
             000000000000000000000000aa8e23fb1079ea71e0a56f48a2aa51851d8433d0\
             0000000000000000000000000000000000000000000000000000000000000002\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000000\
             0000000000000000000000000000000000000000000000000000000000000002\
             0000000000000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000000000000002540be400\
             0000000000000000000000000000000000000000000000000000000000000002\
             0000000000000000000000000000000000000000000000000000000000000000\
             00000000000000000000000000000000000000000000021e19e0c9bab2400000"
                .replace(char::is_whitespace, ""),
        )
        .unwrap();

        let (tokens, balances) = decode_pool_token_info(&raw).unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(balances, vec![U256::zero(), U256::from(10_000_000_000u64)]);
    }

    fn calldata_word(calldata: &str, index: usize) -> U256 {
        let raw = hex::decode(calldata.trim_start_matches("0x")).unwrap();
        let start = 4 + index * 32;
        U256::from_big_endian(&raw[start..start + 32])
    }
}
