//! Uniswap V4 typed single-pool swap adapter for Arc.

use anyhow::{anyhow, Result};
use ethers::abi::{self, ParamType, Token};
use ethers::types::{Address, H256, U256};
use ethers::utils::{id, keccak256};
use serde::{Deserialize, Serialize};

use crate::types::{BatchCall, ExecutionRequest};

const POOL_MANAGER: &str = "0x8366a39CC670B4001A1121B8F6A443A643e40951";
const UNIVERSAL_ROUTER: &str = "0x4fcA4a51Ab4F23A7447b3284fBd7D73289A89Fb1";
const STATE_VIEW: &str = "0xF3334192d15450cDD385C8b70e03f9A6bD9e673B";
const QUOTER: &str = "0x8Dc178eFB8111bb0973Dd9D722eBeFF267C98F94";
const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";
const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

const V4_SWAP_COMMAND: u8 = 0x10;
const SWAP_EXACT_IN_SINGLE: u8 = 0x06;
const SWAP_EXACT_OUT_SINGLE: u8 = 0x08;
const SETTLE_ALL: u8 = 0x0c;
const TAKE_ALL: u8 = 0x0f;
const DYNAMIC_FEE_FLAG: u32 = 0x800000;
const MAX_STATIC_FEE: u32 = 1_000_000;
const MAX_TICK_SPACING: i32 = 32_767;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UniswapSwapKind {
    ExactIn,
    ExactOut,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UniswapPoolSelection {
    Automatic,
    Explicit,
}

impl Default for UniswapSwapKind {
    fn default() -> Self {
        Self::ExactIn
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapSwapRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Input ERC-20 currency. Native Arc USDC input is deliberately disabled;
    /// use its ERC-20 interface at 0x3600000000000000000000000000000000000000.
    pub token_in: String,
    /// Output currency. The zero address represents native Arc USDC.
    pub token_out: String,
    /// Omit with `tick_spacing` and `hooks` to discover and select the best pool.
    #[serde(default)]
    pub fee: Option<u32>,
    /// Omit with `fee` and `hooks` to discover and select the best pool.
    #[serde(default)]
    pub tick_spacing: Option<i32>,
    /// Explicit pool hooks address. Omit in automatic mode.
    #[serde(default)]
    pub hooks: Option<String>,
    /// Automatic discovery excludes hook pools unless explicitly enabled.
    #[serde(default)]
    pub include_hooked_pools: bool,
    #[serde(default = "empty_bytes")]
    pub hook_data: String,
    #[serde(default)]
    pub swap_kind: UniswapSwapKind,
    /// Exact input for `exact_in`, or exact output for `exact_out`, in raw units.
    pub amount_raw: String,
    /// Minimum output for `exact_in`, or maximum input for `exact_out`.
    #[serde(default)]
    pub limit_raw: Option<String>,
    #[serde(default = "default_slippage_bps")]
    pub slippage_bps: u16,
    #[serde(default)]
    pub deadline: Option<u64>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UniswapPoolQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub token_a: String,
    pub token_b: String,
    pub fee: u32,
    pub tick_spacing: i32,
    #[serde(default = "zero_address")]
    pub hooks: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UniswapBalancesQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub token_a: String,
    pub token_b: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UniswapPoolsQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub token_a: String,
    pub token_b: String,
    #[serde(default)]
    pub include_hooked_pools: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapQuoteResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub pool_id: String,
    pub pool_selection: UniswapPoolSelection,
    pub token_in: String,
    pub token_out: String,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: String,
    pub swap_kind: UniswapSwapKind,
    pub amount_raw: String,
    pub quoted_amount_raw: String,
    pub limit_raw: String,
    pub slippage_bps: u16,
    pub quoter_gas_estimate: String,
    pub deadline: u64,
    pub candidates_discovered: usize,
    pub candidates_quoted: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapPoolResponse {
    pub chain: String,
    pub pool_id: String,
    pub currency0: String,
    pub currency1: String,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: String,
    pub initialized: bool,
    pub sqrt_price_x96: String,
    pub tick: i32,
    pub protocol_fee: u32,
    pub lp_fee: u32,
    pub liquidity: String,
    pub pool_manager_address: String,
    pub universal_router_address: String,
    pub state_view_address: String,
    pub quoter_address: String,
    pub permit2_address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapBalancesResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub tokens: Vec<UniswapTokenBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapPoolsResponse {
    pub chain: String,
    pub token_a: String,
    pub token_b: String,
    pub include_hooked_pools: bool,
    pub pools: Vec<UniswapDiscoveredPool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapDiscoveredPool {
    pub pool_id: String,
    pub currency0: String,
    pub currency1: String,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: String,
    pub initialized: bool,
    pub sqrt_price_x96: String,
    pub tick: i32,
    pub protocol_fee: u32,
    pub lp_fee: u32,
    pub liquidity: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniswapTokenBalance {
    pub address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub balance_raw: String,
    pub balance_formatted: String,
}

#[derive(Debug, Clone, Copy)]
pub struct PoolKey {
    pub currency0: Address,
    pub currency1: Address,
    pub fee: u32,
    pub tick_spacing: i32,
    pub hooks: Address,
}

pub fn pool_manager_address() -> Address {
    hardcoded(POOL_MANAGER)
}

pub fn universal_router_address() -> Address {
    hardcoded(UNIVERSAL_ROUTER)
}

pub fn state_view_address() -> Address {
    hardcoded(STATE_VIEW)
}

pub fn quoter_address() -> Address {
    hardcoded(QUOTER)
}

pub fn permit2_address() -> Address {
    hardcoded(PERMIT2)
}

pub fn validate_swap_request(req: &UniswapSwapRequest) -> Result<()> {
    validate_chain(&req.chain)?;
    if req.agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    validate_currency_pair(&req.token_in, &req.token_out)?;
    if parse_address(&req.token_in, "token_in")? == Address::zero() {
        return Err(anyhow!(
            "native Arc USDC input is not enabled; use the USDC ERC-20 interface at 0x3600000000000000000000000000000000000000"
        ));
    }
    explicit_pool_key(req)?;
    parse_positive_u256(&req.amount_raw, "amount_raw")?;
    if let Some(limit) = req.limit_raw.as_deref() {
        parse_positive_u256(limit, "limit_raw")?;
    }
    if req.slippage_bps > 10_000 {
        return Err(anyhow!("slippage_bps must be between 0 and 10000"));
    }
    parse_hex_bytes(&req.hook_data, "hook_data")?;
    if let Some(deadline) = req.deadline {
        validate_deadline(deadline)?;
    }
    Ok(())
}

pub fn validate_pool_query(query: &UniswapPoolQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    pool_key(
        &query.token_a,
        &query.token_b,
        query.fee,
        query.tick_spacing,
        &query.hooks,
    )?;
    Ok(())
}

pub fn validate_balances_query(query: &UniswapBalancesQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    if query.agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    validate_currency_pair(&query.token_a, &query.token_b)?;
    Ok(())
}

pub fn validate_pools_query(query: &UniswapPoolsQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    validate_currency_pair(&query.token_a, &query.token_b)?;
    Ok(())
}

pub fn compile_swap(req: &UniswapSwapRequest) -> Result<ExecutionRequest> {
    validate_swap_request(req)?;
    let token_in = parse_address(&req.token_in, "token_in")?;
    let amount = amount(req)?;
    let limit = explicit_limit(req)?
        .ok_or_else(|| anyhow!("limit_raw must be resolved before compiling a Uniswap V4 swap"))?;
    let deadline = req
        .deadline
        .ok_or_else(|| anyhow!("deadline must be resolved before compiling a Uniswap V4 swap"))?;
    let max_input = match req.swap_kind {
        UniswapSwapKind::ExactIn => amount,
        UniswapSwapKind::ExactOut => limit,
    };
    validate_permit2_amount(max_input, "Uniswap V4 maximum input")?;

    let router = universal_router_address();
    let router_calldata = encode_router_execute(req)?;
    let strategy_id = req.strategy_id.clone().or_else(|| {
        Some(format!(
            "uniswap-v4-arc-swap-{}",
            match req.swap_kind {
                UniswapSwapKind::ExactIn => "exact-in",
                UniswapSwapKind::ExactOut => "exact-out",
            }
        ))
    });

    let permit2 = permit2_address();
    let batch_calls = vec![
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
    ];

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id,
        batch_calls: Some(batch_calls),
        callback_url: req.callback_url.clone(),
    })
}

pub fn swap_with_resolved_limit(
    req: &UniswapSwapRequest,
    key: PoolKey,
    limit: U256,
    deadline: u64,
) -> UniswapSwapRequest {
    let mut resolved = swap_with_pool_key(req, key);
    resolved.limit_raw = Some(limit.to_string());
    resolved.deadline = Some(deadline);
    resolved
}

pub fn swap_with_pool_key(req: &UniswapSwapRequest, key: PoolKey) -> UniswapSwapRequest {
    let mut resolved = req.clone();
    resolved.fee = Some(key.fee);
    resolved.tick_spacing = Some(key.tick_spacing);
    resolved.hooks = Some(format!("{:?}", key.hooks));
    resolved
}

pub fn amount(req: &UniswapSwapRequest) -> Result<U256> {
    parse_positive_u256(&req.amount_raw, "amount_raw")
}

pub fn explicit_limit(req: &UniswapSwapRequest) -> Result<Option<U256>> {
    req.limit_raw
        .as_deref()
        .map(|value| parse_positive_u256(value, "limit_raw"))
        .transpose()
}

pub fn request_pool_key(req: &UniswapSwapRequest) -> Result<PoolKey> {
    explicit_pool_key(req)?.ok_or_else(|| {
        anyhow!("Uniswap pool key must be resolved before compiling or encoding a swap")
    })
}

pub fn explicit_pool_key(req: &UniswapSwapRequest) -> Result<Option<PoolKey>> {
    match (req.fee, req.tick_spacing) {
        (None, None) => {
            if req.hooks.is_some() {
                return Err(anyhow!(
                    "hooks requires fee and tick_spacing; omit all three for automatic pool selection"
                ));
            }
            Ok(None)
        }
        (Some(fee), Some(tick_spacing)) => Ok(Some(pool_key(
            &req.token_in,
            &req.token_out,
            fee,
            tick_spacing,
            req.hooks.as_deref().unwrap_or(ZERO_ADDRESS),
        )?)),
        _ => Err(anyhow!(
            "fee and tick_spacing must either both be supplied for an explicit pool or both be omitted for automatic pool selection"
        )),
    }
}

pub fn query_pool_key(query: &UniswapPoolQuery) -> Result<PoolKey> {
    pool_key(
        &query.token_a,
        &query.token_b,
        query.fee,
        query.tick_spacing,
        &query.hooks,
    )
}

pub fn pool_id(key: PoolKey) -> H256 {
    H256::from(keccak256(abi::encode(&pool_key_tokens(key))))
}

pub fn parse_request_address(value: &str, field: &str) -> Result<Address> {
    parse_address(value, field)
}

pub fn encode_quote(req: &UniswapSwapRequest) -> Result<String> {
    let key = request_pool_key(req)?;
    let token_in = parse_address(&req.token_in, "token_in")?;
    let zero_for_one = token_in == key.currency0;
    let signature = match req.swap_kind {
        UniswapSwapKind::ExactIn => {
            "quoteExactInputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))"
        }
        UniswapSwapKind::ExactOut => {
            "quoteExactOutputSingle(((address,address,uint24,int24,address),bool,uint128,bytes))"
        }
    };
    let amount = amount(req)?;
    validate_uint128(amount, "amount_raw")?;
    let params = Token::Tuple(vec![
        Token::Tuple(pool_key_tokens(key)),
        Token::Bool(zero_for_one),
        Token::Uint(amount),
        Token::Bytes(parse_hex_bytes(&req.hook_data, "hook_data")?),
    ]);
    Ok(encode_call(selector(signature), &[params]))
}

pub fn encode_get_slot0(id: H256) -> String {
    encode_call(
        selector("getSlot0(bytes32)"),
        &[Token::FixedBytes(id.as_bytes().to_vec())],
    )
}

pub fn encode_get_liquidity(id: H256) -> String {
    encode_call(
        selector("getLiquidity(bytes32)"),
        &[Token::FixedBytes(id.as_bytes().to_vec())],
    )
}

pub fn encode_balance_of(owner: Address) -> String {
    encode_call(selector("balanceOf(address)"), &[Token::Address(owner)])
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

pub fn decode_quote(raw: &[u8]) -> Result<(U256, U256)> {
    let decoded = abi::decode(&[ParamType::Uint(256), ParamType::Uint(256)], raw)
        .map_err(|e| anyhow!("failed to decode Uniswap V4 quote: {e}"))?;
    Ok((
        decoded[0]
            .clone()
            .into_uint()
            .ok_or_else(|| anyhow!("failed to decode Uniswap V4 quoted amount"))?,
        decoded[1]
            .clone()
            .into_uint()
            .ok_or_else(|| anyhow!("failed to decode Uniswap V4 quote gas estimate"))?,
    ))
}

pub fn decode_slot0(raw: &[u8]) -> Result<(U256, i32, u32, u32)> {
    let decoded = abi::decode(
        &[
            ParamType::Uint(160),
            ParamType::Int(24),
            ParamType::Uint(24),
            ParamType::Uint(24),
        ],
        raw,
    )
    .map_err(|e| anyhow!("failed to decode Uniswap V4 pool slot0: {e}"))?;
    let sqrt_price = decoded[0]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 sqrt price"))?;
    let tick_raw = decoded[1]
        .clone()
        .into_int()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 tick"))?;
    let protocol_fee = decoded[2]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 protocol fee"))?
        .as_u32();
    let lp_fee = decoded[3]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 LP fee"))?
        .as_u32();
    Ok((sqrt_price, decode_int24(tick_raw), protocol_fee, lp_fee))
}

pub fn decode_initialize_pool_key(
    raw: &[u8],
    currency0: Address,
    currency1: Address,
) -> Result<PoolKey> {
    let decoded = abi::decode(
        &[
            ParamType::Uint(24),
            ParamType::Int(24),
            ParamType::Address,
            ParamType::Uint(160),
            ParamType::Int(24),
        ],
        raw,
    )
    .map_err(|e| anyhow!("failed to decode Uniswap V4 Initialize event: {e}"))?;
    let fee = decoded[0]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 pool fee"))?
        .as_u32();
    let tick_spacing = decode_int24(
        decoded[1]
            .clone()
            .into_int()
            .ok_or_else(|| anyhow!("failed to decode Uniswap V4 pool tick spacing"))?,
    );
    let hooks = decoded[2]
        .clone()
        .into_address()
        .ok_or_else(|| anyhow!("failed to decode Uniswap V4 pool hooks"))?;
    discovered_pool_key(currency0, currency1, fee, tick_spacing, hooks)
}

pub fn decode_u256(raw: &[u8], context: &str) -> Result<U256> {
    let decoded = abi::decode(&[ParamType::Uint(256)], raw)
        .map_err(|e| anyhow!("failed to decode {context}: {e}"))?;
    decoded[0]
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("failed to decode {context} as uint256"))
}

pub fn validate_permit2_amount(amount: U256, field: &str) -> Result<()> {
    if amount > uint160_max() {
        return Err(anyhow!(
            "{field} exceeds the Permit2 uint160 allowance range"
        ));
    }
    Ok(())
}

pub fn validate_swap_amount(amount: U256, field: &str) -> Result<()> {
    validate_uint128(amount, field)
}

pub fn discovered_pool_key(
    currency0: Address,
    currency1: Address,
    fee: u32,
    tick_spacing: i32,
    hooks: Address,
) -> Result<PoolKey> {
    validate_pool_parameters(fee, tick_spacing)?;
    if currency0 >= currency1 {
        return Err(anyhow!(
            "discovered pool currencies are not in canonical order"
        ));
    }
    Ok(PoolKey {
        currency0,
        currency1,
        fee,
        tick_spacing,
        hooks,
    })
}

fn encode_router_execute(req: &UniswapSwapRequest) -> Result<String> {
    let key = request_pool_key(req)?;
    let token_in = parse_address(&req.token_in, "token_in")?;
    let token_out = parse_address(&req.token_out, "token_out")?;
    let amount = amount(req)?;
    let limit = explicit_limit(req)?.ok_or_else(|| anyhow!("limit_raw is required"))?;
    validate_uint128(amount, "amount_raw")?;
    validate_uint128(limit, "limit_raw")?;
    let deadline = req
        .deadline
        .ok_or_else(|| anyhow!("deadline is required"))?;
    let zero_for_one = token_in == key.currency0;
    let (action, amount_out_minimum, max_input) = match req.swap_kind {
        UniswapSwapKind::ExactIn => (SWAP_EXACT_IN_SINGLE, limit, amount),
        UniswapSwapKind::ExactOut => (SWAP_EXACT_OUT_SINGLE, amount, limit),
    };

    // Arc's deployed Universal Router includes the per-hop price field. The
    // quote-derived aggregate limit remains the authoritative slippage guard.
    let swap_params = abi::encode(&[
        Token::Address(key.currency0),
        Token::Address(key.currency1),
        Token::Uint(U256::from(key.fee)),
        Token::Int(U256::from(key.tick_spacing)),
        Token::Address(key.hooks),
        Token::Bool(zero_for_one),
        Token::Uint(amount),
        Token::Uint(match req.swap_kind {
            UniswapSwapKind::ExactIn => limit,
            UniswapSwapKind::ExactOut => max_input,
        }),
        Token::Uint(U256::zero()),
        Token::Bytes(parse_hex_bytes(&req.hook_data, "hook_data")?),
    ]);
    let settle_params = abi::encode(&[Token::Address(token_in), Token::Uint(max_input)]);
    let take_params = abi::encode(&[Token::Address(token_out), Token::Uint(amount_out_minimum)]);
    let v4_input = abi::encode(&[
        Token::Bytes(vec![action, SETTLE_ALL, TAKE_ALL]),
        Token::Array(vec![
            Token::Bytes(swap_params),
            Token::Bytes(settle_params),
            Token::Bytes(take_params),
        ]),
    ]);

    Ok(encode_call(
        selector("execute(bytes,bytes[],uint256)"),
        &[
            Token::Bytes(vec![V4_SWAP_COMMAND]),
            Token::Array(vec![Token::Bytes(v4_input)]),
            Token::Uint(U256::from(deadline)),
        ],
    ))
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
    validate_permit2_amount(amount, "Permit2 approval amount")?;
    validate_deadline(expiration)?;
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

fn pool_key(
    token_a: &str,
    token_b: &str,
    fee: u32,
    tick_spacing: i32,
    hooks: &str,
) -> Result<PoolKey> {
    let token_a = parse_address(token_a, "token_a/token_in")?;
    let token_b = parse_address(token_b, "token_b/token_out")?;
    if token_a == token_b {
        return Err(anyhow!("pool currencies must be different"));
    }
    validate_pool_parameters(fee, tick_spacing)?;
    let hooks = parse_address(hooks, "hooks")?;
    let (currency0, currency1) = if token_a < token_b {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    };
    discovered_pool_key(currency0, currency1, fee, tick_spacing, hooks)
}

fn validate_pool_parameters(fee: u32, tick_spacing: i32) -> Result<()> {
    if fee > MAX_STATIC_FEE && fee != DYNAMIC_FEE_FLAG {
        return Err(anyhow!(
            "fee must be at most 1000000, or 8388608 for a dynamic-fee pool"
        ));
    }
    if !(1..=MAX_TICK_SPACING).contains(&tick_spacing) {
        return Err(anyhow!("tick_spacing must be between 1 and 32767"));
    }
    Ok(())
}

fn validate_currency_pair(token_a: &str, token_b: &str) -> Result<(Address, Address)> {
    let token_a = parse_address(token_a, "token_a/token_in")?;
    let token_b = parse_address(token_b, "token_b/token_out")?;
    if token_a == token_b {
        return Err(anyhow!("pool currencies must be different"));
    }
    Ok(if token_a < token_b {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    })
}

fn pool_key_tokens(key: PoolKey) -> Vec<Token> {
    vec![
        Token::Address(key.currency0),
        Token::Address(key.currency1),
        Token::Uint(U256::from(key.fee)),
        Token::Int(U256::from(key.tick_spacing)),
        Token::Address(key.hooks),
    ]
}

fn validate_chain(chain: &str) -> Result<()> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "arc-testnet" => Ok(()),
        other => Err(anyhow!(
            "Uniswap V4 typed adapter is enabled on Arc testnet only; use chain \"arc-testnet\", got \"{other}\""
        )),
    }
}

fn validate_deadline(deadline: u64) -> Result<()> {
    if deadline == 0 || deadline > ((1u64 << 48) - 1) {
        return Err(anyhow!("deadline must fit in uint48"));
    }
    Ok(())
}

fn validate_uint128(value: U256, field: &str) -> Result<()> {
    if value > U256::from(u128::MAX) {
        return Err(anyhow!("{field} exceeds the Uniswap V4 uint128 range"));
    }
    Ok(())
}

fn parse_positive_u256(value: &str, field: &str) -> Result<U256> {
    let parsed = U256::from_dec_str(value)
        .map_err(|_| anyhow!("{field} must be a raw unsigned integer string"))?;
    if parsed.is_zero() {
        return Err(anyhow!("{field} must be greater than zero"));
    }
    validate_uint128(parsed, field)?;
    Ok(parsed)
}

fn parse_address(value: &str, field: &str) -> Result<Address> {
    value
        .parse()
        .map_err(|_| anyhow!("{field} must be a valid EVM address"))
}

fn parse_hex_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("{field} must start with 0x"))?;
    hex::decode(raw).map_err(|e| anyhow!("{field} must be valid even-length hex: {e}"))
}

fn decode_int24(value: U256) -> i32 {
    let raw = value.low_u32() & 0x00ff_ffff;
    if raw & 0x0080_0000 != 0 {
        (raw as i32) - (1 << 24)
    } else {
        raw as i32
    }
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = id(signature);
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_call(selector: [u8; 4], tokens: &[Token]) -> String {
    let mut bytes = selector.to_vec();
    bytes.extend(abi::encode(tokens));
    format!("0x{}", hex::encode(bytes))
}

fn hardcoded(value: &str) -> Address {
    value.parse().expect("hardcoded Uniswap address is valid")
}

fn uint160_max() -> U256 {
    (U256::one() << 160) - U256::one()
}

fn default_chain() -> String {
    "arc-testnet".to_string()
}

fn default_slippage_bps() -> u16 {
    100
}

fn zero_address() -> String {
    ZERO_ADDRESS.to_string()
}

fn empty_bytes() -> String {
    "0x".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    async fn arc_testnet_rpc(method: &str, params: Value) -> Value {
        let response = reqwest::Client::new()
            .post("https://rpc.testnet.arc.network")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .expect("Arc testnet RPC request");
        assert!(response.status().is_success());
        let body: Value = response.json().await.expect("Arc testnet RPC JSON");
        assert!(body.get("error").is_none(), "RPC error: {body}");
        body["result"].clone()
    }

    fn request() -> UniswapSwapRequest {
        UniswapSwapRequest {
            agent_id: "agent-1".to_string(),
            chain: "arc-testnet".to_string(),
            token_in: "0x3600000000000000000000000000000000000000".to_string(),
            token_out: "0x99f5ef58ecf20f4b8ec8c4af451a74045aa40573".to_string(),
            fee: Some(3_000),
            tick_spacing: Some(60),
            hooks: Some(zero_address()),
            include_hooked_pools: false,
            hook_data: "0x".to_string(),
            swap_kind: UniswapSwapKind::ExactIn,
            amount_raw: "1000000000000000".to_string(),
            limit_raw: Some("1".to_string()),
            slippage_bps: 100,
            deadline: Some(2_000_000_000),
            strategy_id: None,
            callback_url: None,
        }
    }

    #[test]
    fn derives_known_pool_id_vector() {
        let key = request_pool_key(&request()).unwrap();
        assert_eq!(
            format!("{:?}", pool_id(key)),
            "0x8cc7a0e4633bfbe1d12fe0bd8b52459c830b0a9c52fdbfb06b1f2da152fd12ae"
        );
    }

    #[test]
    fn arc_registry_matches_the_official_deployment() {
        assert_eq!(
            format!("{:?}", pool_manager_address()),
            "0x8366a39cc670b4001a1121b8f6a443a643e40951"
        );
        assert_eq!(
            format!("{:?}", universal_router_address()),
            "0x4fca4a51ab4f23a7447b3284fbd7d73289a89fb1"
        );
        assert_eq!(
            format!("{:?}", state_view_address()),
            "0xf3334192d15450cdd385c8b70e03f9a6bd9e673b"
        );
        assert_eq!(
            format!("{:?}", quoter_address()),
            "0x8dc178efb8111bb0973dd9d722ebeff267c98f94"
        );
        assert_eq!(
            format!("{:?}", permit2_address()),
            "0x000000000022d473030f116ddee9f6b43ac78ba3"
        );
    }

    #[tokio::test]
    #[ignore = "requires the public Arc testnet RPC"]
    async fn live_arc_testnet_registry_contains_contract_code() {
        for address in [
            pool_manager_address(),
            universal_router_address(),
            state_view_address(),
            quoter_address(),
            permit2_address(),
        ] {
            let code =
                arc_testnet_rpc("eth_getCode", json!([format!("{address:?}"), "latest"])).await;
            assert!(
                code.as_str().is_some_and(|value| value.len() > 2),
                "missing contract code at {address:?}"
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires the public Arc testnet RPC and an active pool"]
    async fn live_arc_testnet_quoter_accepts_the_encoded_tuple() {
        let mut req = request();
        req.amount_raw = "1000000".to_string();
        let calldata = encode_quote(&req).unwrap();
        let result = arc_testnet_rpc(
            "eth_call",
            json!([{
                "to": format!("{:?}", quoter_address()),
                "data": calldata,
            }, "latest"]),
        )
        .await;
        let raw = hex::decode(
            result
                .as_str()
                .expect("quoter result is hex")
                .trim_start_matches("0x"),
        )
        .unwrap();
        let (amount, gas) = decode_quote(&raw).unwrap();
        assert!(!amount.is_zero());
        assert!(!gas.is_zero());
    }

    #[test]
    fn compiles_erc20_input_with_arc_router_layout() {
        let compiled = compile_swap(&request()).unwrap();
        let calls = compiled.batch_calls.unwrap();
        assert_eq!(calls.len(), 6);
        assert_eq!(
            calls[3].target_contract,
            format!("{:?}", universal_router_address())
        );
        assert_eq!(calls[3].value, "0");
        assert!(calls[3].calldata.starts_with("0x3593564c"));

        let outer = abi::decode(
            &[
                ParamType::Bytes,
                ParamType::Array(Box::new(ParamType::Bytes)),
                ParamType::Uint(256),
            ],
            &hex::decode(&calls[3].calldata[10..]).unwrap(),
        )
        .unwrap();
        assert_eq!(
            outer[0].clone().into_bytes().unwrap(),
            vec![V4_SWAP_COMMAND]
        );
        let inputs = outer[1].clone().into_array().unwrap();
        let v4_input = inputs[0].clone().into_bytes().unwrap();
        let v4 = abi::decode(
            &[
                ParamType::Bytes,
                ParamType::Array(Box::new(ParamType::Bytes)),
            ],
            &v4_input,
        )
        .unwrap();
        assert_eq!(
            v4[0].clone().into_bytes().unwrap(),
            vec![SWAP_EXACT_IN_SINGLE, SETTLE_ALL, TAKE_ALL]
        );

        let action_params = v4[1].clone().into_array().unwrap();
        let swap_params = action_params[0].clone().into_bytes().unwrap();
        let decoded_swap = abi::decode(
            &[
                ParamType::Address,
                ParamType::Address,
                ParamType::Uint(24),
                ParamType::Int(24),
                ParamType::Address,
                ParamType::Bool,
                ParamType::Uint(128),
                ParamType::Uint(128),
                ParamType::Uint(256),
                ParamType::Bytes,
            ],
            &swap_params,
        )
        .unwrap();
        assert_eq!(
            decoded_swap[1].clone().into_address().unwrap(),
            "0x99f5ef58ecf20f4b8ec8c4af451a74045aa40573"
                .parse::<Address>()
                .unwrap()
        );
        assert_eq!(
            decoded_swap[6].clone().into_uint().unwrap(),
            U256::from_dec_str("1000000000000000").unwrap()
        );
    }

    #[test]
    fn rejects_native_input_until_native_value_policy_is_enabled() {
        let mut req = request();
        req.token_in = zero_address();
        assert!(validate_swap_request(&req)
            .unwrap_err()
            .to_string()
            .contains("native Arc USDC input is not enabled"));
    }

    #[test]
    fn compiles_erc20_input_with_temporary_permit2_approval() {
        let req = request();
        let compiled = compile_swap(&req).unwrap();
        assert_eq!(compiled.batch_calls.unwrap().len(), 6);
    }

    #[test]
    fn rejects_the_previous_ethereum_sepolia_chain() {
        let mut req = request();
        req.chain = "ethereum".to_string();
        assert!(validate_swap_request(&req)
            .unwrap_err()
            .to_string()
            .contains("Arc testnet only"));
    }

    #[test]
    fn rejects_invalid_pool_parameters() {
        let mut req = request();
        req.fee = Some(1_000_001);
        assert!(validate_swap_request(&req).is_err());
        req.fee = Some(500);
        req.tick_spacing = Some(0);
        assert!(validate_swap_request(&req).is_err());
    }

    #[test]
    fn accepts_automatic_pool_selection_without_pool_key_fields() {
        let mut req = request();
        req.fee = None;
        req.tick_spacing = None;
        req.hooks = None;
        assert!(validate_swap_request(&req).is_ok());
        assert!(explicit_pool_key(&req).unwrap().is_none());
    }

    #[test]
    fn deserializes_minimal_automatic_swap_request() {
        let req: UniswapSwapRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "agent-1",
            "token_in": "0x3600000000000000000000000000000000000000",
            "token_out": "0x99f5ef58ecf20f4b8ec8c4af451a74045aa40573",
            "amount_raw": "1000"
        }))
        .unwrap();
        assert_eq!(req.swap_kind, UniswapSwapKind::ExactIn);
        assert!(req.fee.is_none());
        assert!(req.tick_spacing.is_none());
        assert!(req.hooks.is_none());
        assert!(!req.include_hooked_pools);
        assert!(validate_swap_request(&req).is_ok());
    }

    #[test]
    fn rejects_partial_explicit_pool_key() {
        let mut req = request();
        req.tick_spacing = None;
        assert!(validate_swap_request(&req).is_err());
    }

    #[test]
    fn decodes_initialize_event_pool_key() {
        let currency0 = Address::zero();
        let currency1 = request_pool_key(&request()).unwrap().currency1;
        let data = abi::encode(&[
            Token::Uint(U256::from(10_000u64)),
            Token::Int(U256::from(200u64)),
            Token::Address(Address::zero()),
            Token::Uint(U256::from(1u64) << 96),
            Token::Int(U256::zero()),
        ]);
        let key = decode_initialize_pool_key(&data, currency0, currency1).unwrap();
        assert_eq!(key.fee, 10_000);
        assert_eq!(key.tick_spacing, 200);
        assert_eq!(key.hooks, Address::zero());
    }

    #[test]
    fn quote_calldata_matches_deployed_quoter_tuple_shape() {
        let calldata = encode_quote(&request()).unwrap();
        assert!(calldata.starts_with("0xaa9d21cb"));
        let decoded = abi::decode(
            &[ParamType::Tuple(vec![
                ParamType::Tuple(vec![
                    ParamType::Address,
                    ParamType::Address,
                    ParamType::Uint(24),
                    ParamType::Int(24),
                    ParamType::Address,
                ]),
                ParamType::Bool,
                ParamType::Uint(128),
                ParamType::Bytes,
            ])],
            &hex::decode(&calldata[10..]).unwrap(),
        )
        .unwrap();
        let params = decoded[0].clone().into_tuple().unwrap();
        assert!(params[1].clone().into_bool().unwrap());
        assert_eq!(
            params[2].clone().into_uint().unwrap(),
            U256::from_dec_str("1000000000000000").unwrap()
        );
    }

    #[test]
    fn decodes_negative_int24() {
        assert_eq!(decode_int24(U256::from(0x00ff_ff9cu32)), -100);
    }
}
