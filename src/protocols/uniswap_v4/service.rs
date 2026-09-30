use anyhow::{anyhow, Result};
use chrono::Utc;
use ethers::abi::{self, ParamType};
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, H256, U256};
use ethers::utils::format_units;
use redis::aio::ConnectionManager;
use serde::Deserialize;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::adapter as uniswap_v4;
use super::adapter::{
    PoolKey, UniswapBalancesQuery, UniswapBalancesResponse, UniswapDiscoveredPool,
    UniswapPoolQuery, UniswapPoolResponse, UniswapPoolSelection, UniswapPoolsQuery,
    UniswapPoolsResponse, UniswapQuoteResponse, UniswapSwapKind, UniswapSwapRequest,
    UniswapTokenBalance,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{
    handle_execute_idempotent, handle_simulate_authenticated, resolve_chain_smart_wallet_address,
};
use crate::execution_engine::ExecutionEngine;
use crate::types::{AuthContext, Chain, ExecutionResponse};

const DEFAULT_DEADLINE_SECS: u64 = 20 * 60;
const BPS_SCALE: u64 = 10_000;
const POOL_MANAGER_START_BLOCK: u64 = 62_417_020;
const BLOCKSCOUT_LOGS_URL: &str = "https://testnet.arcscan.app/api";
const INITIALIZE_EVENT_TOPIC: &str =
    "0xdd466e674ea557f56295e2d0218a125ea4b4f0f6f3307b95f85e6110838d6438";
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);
const MAX_DISCOVERED_POOLS: usize = 1_000;

#[derive(Clone)]
struct DiscoveryCacheEntry {
    fetched_at: Instant,
    pools: Vec<PoolKey>,
}

static DISCOVERY_CACHE: OnceLock<RwLock<HashMap<(Address, Address), DiscoveryCacheEntry>>> =
    OnceLock::new();

pub async fn handle_swap(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &UniswapSwapRequest,
    idempotency_key: &str,
) -> Result<ExecutionResponse> {
    let resolved = resolve_swap(engine, wallet_registry, auth_context.organization_id, req).await?;
    let execution_req = uniswap_v4::compile_swap(&resolved.request)?;
    handle_execute_idempotent(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        auth_context,
        &execution_req,
        idempotency_key,
    )
    .await
    .map_err(|e| anyhow!("Uniswap V4 swap on Arc testnet failed: {e}"))
}

pub async fn handle_swap_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &UniswapSwapRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_swap(engine, wallet_registry, auth_context.organization_id, req).await?;
    let execution_req = uniswap_v4::compile_swap(&resolved.request)?;
    handle_simulate_authenticated(engine, pool, wallet_registry, auth_context, &execution_req).await
}

pub async fn handle_quote(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &UniswapSwapRequest,
) -> Result<UniswapQuoteResponse> {
    let resolved = resolve_swap(engine, wallet_registry, organization_id, req).await?;
    let token_in = uniswap_v4::parse_request_address(&req.token_in, "token_in")?;
    let token_out = uniswap_v4::parse_request_address(&req.token_out, "token_out")?;
    Ok(UniswapQuoteResponse {
        agent_id: req.agent_id.clone(),
        chain: parse_chain(&req.chain)?.to_string(),
        smart_wallet_address: format!("{:?}", resolved.smart_wallet_address),
        pool_id: format!("{:?}", uniswap_v4::pool_id(resolved.pool_key)),
        pool_selection: resolved.pool_selection,
        token_in: format!("{token_in:?}"),
        token_out: format!("{token_out:?}"),
        fee: resolved.pool_key.fee,
        tick_spacing: resolved.pool_key.tick_spacing,
        hooks: format!("{:?}", resolved.pool_key.hooks),
        swap_kind: req.swap_kind,
        amount_raw: uniswap_v4::amount(req)?.to_string(),
        quoted_amount_raw: resolved.quoted_amount.to_string(),
        limit_raw: resolved.limit.to_string(),
        slippage_bps: req.slippage_bps,
        quoter_gas_estimate: resolved.quoter_gas_estimate.to_string(),
        deadline: resolved.deadline,
        candidates_discovered: resolved.candidates_discovered,
        candidates_quoted: resolved.candidates_quoted,
    })
}

pub async fn handle_pool(
    engine: &ExecutionEngine,
    query: &UniswapPoolQuery,
) -> Result<UniswapPoolResponse> {
    uniswap_v4::validate_pool_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let key = uniswap_v4::query_pool_key(query)?;
    let id = uniswap_v4::pool_id(key);
    let state = load_pool_state(engine, &chain, id).await?;

    Ok(UniswapPoolResponse {
        chain: chain.to_string(),
        pool_id: format!("{id:?}"),
        currency0: format!("{:?}", key.currency0),
        currency1: format!("{:?}", key.currency1),
        fee: key.fee,
        tick_spacing: key.tick_spacing,
        hooks: format!("{:?}", key.hooks),
        initialized: !state.sqrt_price_x96.is_zero(),
        sqrt_price_x96: state.sqrt_price_x96.to_string(),
        tick: state.tick,
        protocol_fee: state.protocol_fee,
        lp_fee: state.lp_fee,
        liquidity: state.liquidity.to_string(),
        pool_manager_address: format!("{:?}", uniswap_v4::pool_manager_address()),
        universal_router_address: format!("{:?}", uniswap_v4::universal_router_address()),
        state_view_address: format!("{:?}", uniswap_v4::state_view_address()),
        quoter_address: format!("{:?}", uniswap_v4::quoter_address()),
        permit2_address: format!("{:?}", uniswap_v4::permit2_address()),
    })
}

pub async fn handle_pools(
    engine: &ExecutionEngine,
    query: &UniswapPoolsQuery,
) -> Result<UniswapPoolsResponse> {
    uniswap_v4::validate_pools_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let token_a = uniswap_v4::parse_request_address(&query.token_a, "token_a")?;
    let token_b = uniswap_v4::parse_request_address(&query.token_b, "token_b")?;
    let keys = discover_pool_keys(token_a, token_b).await?;
    let mut pools = Vec::new();
    for key in keys {
        if !query.include_hooked_pools && key.hooks != Address::zero() {
            continue;
        }
        let id = uniswap_v4::pool_id(key);
        let state = match load_pool_state(engine, &chain, id).await {
            Ok(state) => state,
            Err(_) => continue,
        };
        pools.push(discovered_pool_response(key, state));
    }
    pools.sort_by(|left, right| {
        (left.fee, left.tick_spacing, &left.hooks).cmp(&(
            right.fee,
            right.tick_spacing,
            &right.hooks,
        ))
    });
    Ok(UniswapPoolsResponse {
        chain: chain.to_string(),
        token_a: format!("{token_a:?}"),
        token_b: format!("{token_b:?}"),
        include_hooked_pools: query.include_hooked_pools,
        pools,
    })
}

pub async fn handle_balances(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &UniswapBalancesQuery,
) -> Result<UniswapBalancesResponse> {
    uniswap_v4::validate_balances_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;
    let token_a = uniswap_v4::parse_request_address(&query.token_a, "token_a")?;
    let token_b = uniswap_v4::parse_request_address(&query.token_b, "token_b")?;

    let mut tokens = Vec::with_capacity(2);
    for token in [token_a, token_b] {
        tokens.push(load_token_balance(engine, &chain, smart_wallet_address, token).await?);
    }
    Ok(UniswapBalancesResponse {
        agent_id: query.agent_id.clone(),
        chain: chain.to_string(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        tokens,
    })
}

struct ResolvedSwap {
    request: UniswapSwapRequest,
    smart_wallet_address: Address,
    pool_key: PoolKey,
    pool_selection: UniswapPoolSelection,
    quoted_amount: U256,
    limit: U256,
    quoter_gas_estimate: U256,
    deadline: u64,
    candidates_discovered: usize,
    candidates_quoted: usize,
}

async fn resolve_swap(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &UniswapSwapRequest,
) -> Result<ResolvedSwap> {
    uniswap_v4::validate_swap_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;

    let explicit_key = uniswap_v4::explicit_pool_key(req)?;
    let (pool_key, quoted_amount, quoter_gas_estimate, pool_selection, discovered, quoted) =
        match explicit_key {
            Some(key) => {
                validate_pool_for_swap(engine, &chain, key).await?;
                let (amount, gas) = quote_swap(engine, &chain, req, smart_wallet_address).await?;
                (key, amount, gas, UniswapPoolSelection::Explicit, 1, 1)
            }
            None => {
                let token_in = uniswap_v4::parse_request_address(&req.token_in, "token_in")?;
                let token_out = uniswap_v4::parse_request_address(&req.token_out, "token_out")?;
                select_best_pool(
                    engine,
                    &chain,
                    req,
                    smart_wallet_address,
                    token_in,
                    token_out,
                )
                .await?
            }
        };
    if quoted_amount.is_zero() {
        return Err(anyhow!("Uniswap V4 quote returned zero"));
    }

    let limit = match uniswap_v4::explicit_limit(req)? {
        Some(limit) => {
            validate_explicit_limit(req.swap_kind, quoted_amount, limit)?;
            limit
        }
        None => limit_from_quote(req.swap_kind, quoted_amount, req.slippage_bps)?,
    };
    let max_input = match req.swap_kind {
        UniswapSwapKind::ExactIn => uniswap_v4::amount(req)?,
        UniswapSwapKind::ExactOut => limit,
    };
    uniswap_v4::validate_swap_amount(limit, "Uniswap V4 swap limit")?;
    uniswap_v4::validate_permit2_amount(max_input, "Uniswap V4 maximum input")?;
    let deadline = resolve_deadline(req.deadline)?;
    let request = uniswap_v4::swap_with_resolved_limit(req, pool_key, limit, deadline);

    Ok(ResolvedSwap {
        request,
        smart_wallet_address,
        pool_key,
        pool_selection,
        quoted_amount,
        limit,
        quoter_gas_estimate,
        deadline,
        candidates_discovered: discovered,
        candidates_quoted: quoted,
    })
}

async fn validate_pool_for_swap(
    engine: &ExecutionEngine,
    chain: &Chain,
    key: PoolKey,
) -> Result<()> {
    let state = load_pool_state(engine, chain, uniswap_v4::pool_id(key)).await?;
    if state.sqrt_price_x96.is_zero() {
        return Err(anyhow!(
            "Uniswap V4 swap rejected: the supplied pool key is not initialized on Arc testnet"
        ));
    }
    Ok(())
}

async fn select_best_pool(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &UniswapSwapRequest,
    smart_wallet_address: Address,
    token_in: Address,
    token_out: Address,
) -> Result<(PoolKey, U256, U256, UniswapPoolSelection, usize, usize)> {
    let discovered = discover_pool_keys(token_in, token_out).await?;
    let discovered_count = discovered.len();
    if discovered.is_empty() {
        return Err(anyhow!(
            "Uniswap V4 automatic selection found no initialized pools for the requested currencies"
        ));
    }

    let mut best: Option<(PoolKey, U256, U256)> = None;
    let mut quoted_count = 0usize;
    for key in discovered {
        if !req.include_hooked_pools && key.hooks != Address::zero() {
            continue;
        }
        if validate_pool_for_swap(engine, chain, key).await.is_err() {
            continue;
        }
        let candidate = uniswap_v4::swap_with_pool_key(req, key);
        let Ok((amount, gas)) = quote_swap(engine, chain, &candidate, smart_wallet_address).await
        else {
            continue;
        };
        if amount.is_zero() {
            continue;
        }
        quoted_count += 1;
        let better = quote_is_better(req.swap_kind, key, amount, gas, best);
        if better {
            best = Some((key, amount, gas));
        }
    }

    let (key, amount, gas) = best.ok_or_else(|| {
        let scope = if req.include_hooked_pools {
            "including hook pools"
        } else {
            "among no-hook pools"
        };
        anyhow!(
            "Uniswap V4 automatic selection found no liquid pool with a successful quote {scope}"
        )
    })?;
    Ok((
        key,
        amount,
        gas,
        UniswapPoolSelection::Automatic,
        discovered_count,
        quoted_count,
    ))
}

fn quote_is_better(
    kind: UniswapSwapKind,
    key: PoolKey,
    amount: U256,
    gas: U256,
    current: Option<(PoolKey, U256, U256)>,
) -> bool {
    let Some((current_key, current_amount, current_gas)) = current else {
        return true;
    };
    let price_is_better = match kind {
        UniswapSwapKind::ExactIn => amount > current_amount,
        UniswapSwapKind::ExactOut => amount < current_amount,
    };
    price_is_better
        || (amount == current_amount && gas < current_gas)
        || (amount == current_amount
            && gas == current_gas
            && uniswap_v4::pool_id(key) < uniswap_v4::pool_id(current_key))
}

async fn quote_swap(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &UniswapSwapRequest,
    sender: Address,
) -> Result<(U256, U256)> {
    let calldata = uniswap_v4::encode_quote(req)?;
    let raw = call_raw_from(
        engine,
        chain,
        uniswap_v4::quoter_address(),
        calldata,
        Some(sender),
    )
    .await
    .map_err(|e| anyhow!("Uniswap V4 quote rejected by the Arc testnet Quoter: {e}"))?;
    uniswap_v4::decode_quote(&raw)
}

struct PoolState {
    sqrt_price_x96: U256,
    tick: i32,
    protocol_fee: u32,
    lp_fee: u32,
    liquidity: U256,
}

fn discovered_pool_response(key: PoolKey, state: PoolState) -> UniswapDiscoveredPool {
    UniswapDiscoveredPool {
        pool_id: format!("{:?}", uniswap_v4::pool_id(key)),
        currency0: format!("{:?}", key.currency0),
        currency1: format!("{:?}", key.currency1),
        fee: key.fee,
        tick_spacing: key.tick_spacing,
        hooks: format!("{:?}", key.hooks),
        initialized: !state.sqrt_price_x96.is_zero(),
        sqrt_price_x96: state.sqrt_price_x96.to_string(),
        tick: state.tick,
        protocol_fee: state.protocol_fee,
        lp_fee: state.lp_fee,
        liquidity: state.liquidity.to_string(),
    }
}

#[derive(Debug, Deserialize)]
struct BlockscoutLogsResponse {
    status: String,
    message: String,
    result: Option<BlockscoutLogsResult>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BlockscoutLogsResult {
    Logs(Vec<BlockscoutLog>),
    Message(String),
}

#[derive(Debug, Deserialize)]
struct BlockscoutLog {
    data: String,
    topics: Vec<String>,
}

async fn discover_pool_keys(token_a: Address, token_b: Address) -> Result<Vec<PoolKey>> {
    let (currency0, currency1) = if token_a < token_b {
        (token_a, token_b)
    } else {
        (token_b, token_a)
    };
    let cache = DISCOVERY_CACHE.get_or_init(|| RwLock::new(HashMap::new()));
    let cached = cache.read().await.get(&(currency0, currency1)).cloned();
    if let Some(entry) = cached.as_ref() {
        if entry.fetched_at.elapsed() < DISCOVERY_CACHE_TTL {
            return Ok(entry.pools.clone());
        }
    }

    match fetch_pool_keys_from_blockscout(currency0, currency1).await {
        Ok(pools) => {
            cache.write().await.insert(
                (currency0, currency1),
                DiscoveryCacheEntry {
                    fetched_at: Instant::now(),
                    pools: pools.clone(),
                },
            );
            Ok(pools)
        }
        Err(error) => match cached {
            Some(entry) => Ok(entry.pools),
            None => Err(error),
        },
    }
}

async fn fetch_pool_keys_from_blockscout(
    currency0: Address,
    currency1: Address,
) -> Result<Vec<PoolKey>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;
    let response = client
        .get(BLOCKSCOUT_LOGS_URL)
        .query(&[
            ("module", "logs".to_string()),
            ("action", "getLogs".to_string()),
            ("fromBlock", POOL_MANAGER_START_BLOCK.to_string()),
            ("toBlock", "latest".to_string()),
            ("page", "1".to_string()),
            ("offset", MAX_DISCOVERED_POOLS.to_string()),
            (
                "address",
                format!("{:?}", uniswap_v4::pool_manager_address()),
            ),
            ("topic0", INITIALIZE_EVENT_TOPIC.to_string()),
            ("topic2", address_topic(currency0)),
            ("topic3", address_topic(currency1)),
            ("topic0_2_opr", "and".to_string()),
            ("topic0_3_opr", "and".to_string()),
            ("topic2_3_opr", "and".to_string()),
        ])
        .send()
        .await
        .map_err(|e| anyhow!("Uniswap V4 pool discovery request failed: {e}"))?
        .error_for_status()
        .map_err(|e| anyhow!("Uniswap V4 pool discovery returned an HTTP error: {e}"))?
        .json::<BlockscoutLogsResponse>()
        .await
        .map_err(|e| anyhow!("failed to decode Uniswap V4 pool discovery response: {e}"))?;

    let mut result_message = None;
    let logs = match response.result {
        Some(BlockscoutLogsResult::Logs(logs)) => logs,
        Some(BlockscoutLogsResult::Message(message)) => {
            result_message = Some(message);
            Vec::new()
        }
        None => Vec::new(),
    };
    let valid_empty_response = response.status == "0"
        && logs.is_empty()
        && (is_no_logs_message(&response.message)
            || result_message.as_deref().is_some_and(is_no_logs_message));
    if (response.status == "1" && result_message.is_some())
        || (response.status != "1" && !valid_empty_response)
    {
        return Err(anyhow!(
            "Uniswap V4 pool discovery failed: {}{}",
            response.message,
            result_message
                .as_deref()
                .map(|message| format!(" ({message})"))
                .unwrap_or_default()
        ));
    }
    if logs.len() >= MAX_DISCOVERED_POOLS {
        return Err(anyhow!(
            "Uniswap V4 pool discovery returned too many matching pools; use an explicit pool key"
        ));
    }

    let mut pools_by_id = HashMap::new();
    for log in logs {
        if log.topics.len() != 4 || !log.topics[0].eq_ignore_ascii_case(INITIALIZE_EVENT_TOPIC) {
            continue;
        }
        let Ok(event_currency0) = address_from_topic(&log.topics[2]) else {
            continue;
        };
        let Ok(event_currency1) = address_from_topic(&log.topics[3]) else {
            continue;
        };
        if event_currency0 != currency0 || event_currency1 != currency1 {
            continue;
        }
        let Ok(event_pool_id) = log.topics[1].parse::<H256>() else {
            continue;
        };
        let Ok(data) = parse_calldata(&log.data) else {
            continue;
        };
        let Ok(key) = uniswap_v4::decode_initialize_pool_key(&data, currency0, currency1) else {
            continue;
        };
        if uniswap_v4::pool_id(key) != event_pool_id {
            continue;
        }
        pools_by_id.insert(event_pool_id, key);
    }
    Ok(pools_by_id.into_values().collect())
}

fn is_no_logs_message(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    normalized.contains("no records") || normalized.contains("no logs")
}

fn address_topic(address: Address) -> String {
    format!("0x{:0>64}", hex::encode(address.as_bytes()))
}

fn address_from_topic(value: &str) -> Result<Address> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("event topic must start with 0x"))?;
    let bytes = hex::decode(value).map_err(|e| anyhow!("invalid event topic: {e}"))?;
    if bytes.len() != 32 || bytes[..12].iter().any(|byte| *byte != 0) {
        return Err(anyhow!("event topic is not an indexed address"));
    }
    Ok(Address::from_slice(&bytes[12..]))
}

async fn load_pool_state(
    engine: &ExecutionEngine,
    chain: &Chain,
    id: ethers::types::H256,
) -> Result<PoolState> {
    let view = uniswap_v4::state_view_address();
    let (slot0_raw, liquidity_raw) = tokio::try_join!(
        call_raw_from(engine, chain, view, uniswap_v4::encode_get_slot0(id), None),
        call_raw_from(
            engine,
            chain,
            view,
            uniswap_v4::encode_get_liquidity(id),
            None
        ),
    )?;
    let (sqrt_price_x96, tick, protocol_fee, lp_fee) = uniswap_v4::decode_slot0(&slot0_raw)?;
    let liquidity = uniswap_v4::decode_u256(&liquidity_raw, "Uniswap V4 liquidity")?;
    Ok(PoolState {
        sqrt_price_x96,
        tick,
        protocol_fee,
        lp_fee,
        liquidity,
    })
}

async fn load_token_balance(
    engine: &ExecutionEngine,
    chain: &Chain,
    owner: Address,
    token: Address,
) -> Result<UniswapTokenBalance> {
    if token == Address::zero() {
        let provider = engine.provider_for_chain(chain)?;
        let balance = provider.get_balance(owner, None).await?;
        return Ok(UniswapTokenBalance {
            address: format!("{token:?}"),
            symbol: "USDC".to_string(),
            name: "USD Coin (native)".to_string(),
            decimals: 18,
            balance_raw: balance.to_string(),
            balance_formatted: format_token_units(balance, 18)?,
        });
    }

    let (balance_raw, decimals_raw, symbol, name) = tokio::join!(
        call_raw_from(
            engine,
            chain,
            token,
            uniswap_v4::encode_balance_of(owner),
            None
        ),
        call_raw_from(engine, chain, token, uniswap_v4::encode_decimals(), None),
        token_string(engine, chain, token, uniswap_v4::encode_symbol(), "symbol"),
        token_string(engine, chain, token, uniswap_v4::encode_name(), "name"),
    );
    let balance = uniswap_v4::decode_u256(&balance_raw?, "Uniswap token balance")?;
    let decimals_value = uniswap_v4::decode_u256(&decimals_raw?, "Uniswap token decimals")?;
    if decimals_value > U256::from(u8::MAX) {
        return Err(anyhow!("ERC-20 decimals exceeds uint8"));
    }
    let decimals = decimals_value.as_u32() as u8;
    let symbol = symbol.unwrap_or_else(|_| compact_address_label(token));
    let name = name.unwrap_or_else(|_| symbol.clone());

    Ok(UniswapTokenBalance {
        address: format!("{token:?}"),
        symbol,
        name,
        decimals,
        balance_raw: balance.to_string(),
        balance_formatted: format_token_units(balance, decimals)?,
    })
}

fn validate_explicit_limit(kind: UniswapSwapKind, quote: U256, limit: U256) -> Result<()> {
    match kind {
        UniswapSwapKind::ExactIn if limit > quote => Err(anyhow!(
            "Uniswap exact-in limit_raw exceeds the current quoted output"
        )),
        UniswapSwapKind::ExactOut if limit < quote => Err(anyhow!(
            "Uniswap exact-out limit_raw is below the current quoted input"
        )),
        _ => Ok(()),
    }
}

fn limit_from_quote(kind: UniswapSwapKind, quote: U256, slippage_bps: u16) -> Result<U256> {
    let scale = U256::from(BPS_SCALE);
    let bps = U256::from(slippage_bps);
    let limit = match kind {
        UniswapSwapKind::ExactIn => {
            quote
                .checked_mul(scale - bps)
                .ok_or_else(|| anyhow!("Uniswap minimum output calculation overflowed"))?
                / scale
        }
        UniswapSwapKind::ExactOut => {
            let numerator = quote
                .checked_mul(scale + bps)
                .ok_or_else(|| anyhow!("Uniswap maximum input calculation overflowed"))?;
            numerator
                .checked_add(scale - U256::one())
                .ok_or_else(|| anyhow!("Uniswap maximum input calculation overflowed"))?
                / scale
        }
    };
    if limit.is_zero() {
        return Err(anyhow!(
            "Uniswap V4 slippage limit rounded to zero; provide limit_raw explicitly"
        ));
    }
    Ok(limit)
}

fn resolve_deadline(requested: Option<u64>) -> Result<u64> {
    let now = Utc::now().timestamp();
    if now < 0 {
        return Err(anyhow!("system clock is before the Unix epoch"));
    }
    let now = now as u64;
    let deadline = match requested {
        Some(deadline) if deadline <= now => {
            return Err(anyhow!("Uniswap swap deadline must be in the future"))
        }
        Some(deadline) => deadline,
        None => now
            .checked_add(DEFAULT_DEADLINE_SECS)
            .ok_or_else(|| anyhow!("Uniswap swap deadline overflowed"))?,
    };
    if deadline > ((1u64 << 48) - 1) {
        return Err(anyhow!("Uniswap swap deadline exceeds uint48"));
    }
    Ok(deadline)
}

async fn call_raw_from(
    engine: &ExecutionEngine,
    chain: &Chain,
    target: Address,
    calldata: String,
    from: Option<Address>,
) -> Result<Bytes> {
    let provider = engine.provider_for_chain(chain)?;
    let mut tx = TransactionRequest::new()
        .to(target)
        .data(parse_calldata(&calldata)?);
    if let Some(from) = from {
        tx = tx.from(from);
    }
    Ok(provider.call(&tx.into(), None).await?)
}

async fn token_string(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
    calldata: String,
    context: &str,
) -> Result<String> {
    let raw = call_raw_from(engine, chain, token, calldata, None).await?;
    if let Ok(decoded) = abi::decode(&[ParamType::String], &raw) {
        if let Some(value) = decoded[0].clone().into_string() {
            return Ok(value);
        }
    }
    if raw.len() == 32 {
        let value = raw
            .iter()
            .copied()
            .take_while(|byte| *byte != 0)
            .collect::<Vec<_>>();
        return String::from_utf8(value)
            .map_err(|e| anyhow!("failed to decode ERC-20 {context}: {e}"));
    }
    Err(anyhow!("failed to decode ERC-20 {context}"))
}

fn parse_calldata(value: &str) -> Result<Bytes> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| anyhow!("calldata must start with 0x"))?;
    Ok(Bytes::from(
        hex::decode(value).map_err(|e| anyhow!("invalid calldata hex: {e}"))?,
    ))
}

fn compact_address_label(address: Address) -> String {
    let raw = format!("{address:?}");
    format!("{}...{}", &raw[..8], &raw[raw.len() - 4..])
}

fn format_token_units(amount: U256, decimals: u8) -> Result<String> {
    format_units(amount, decimals as usize)
        .map_err(|e| anyhow!("failed to format token amount: {e}"))
}

fn parse_chain(chain: &str) -> Result<Chain> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "arc-testnet" => Ok(Chain::ArcTestnet),
        other => Err(anyhow!(
            "unsupported chain for Uniswap V4: {other}; use arc-testnet"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(fee: u32) -> PoolKey {
        uniswap_v4::discovered_pool_key(
            Address::zero(),
            Address::from_low_u64_be(2),
            fee,
            60,
            Address::zero(),
        )
        .unwrap()
    }

    #[test]
    fn exact_in_limit_applies_downward_slippage() {
        assert_eq!(
            limit_from_quote(UniswapSwapKind::ExactIn, U256::from(1_000u64), 100).unwrap(),
            U256::from(990u64)
        );
    }

    #[test]
    fn exact_out_limit_rounds_up() {
        assert_eq!(
            limit_from_quote(UniswapSwapKind::ExactOut, U256::from(1_001u64), 100).unwrap(),
            U256::from(1_012u64)
        );
    }

    #[test]
    fn automatic_selection_maximizes_exact_input_output() {
        let current = Some((key(500), U256::from(100u64), U256::from(50u64)));
        assert!(quote_is_better(
            UniswapSwapKind::ExactIn,
            key(3_000),
            U256::from(101u64),
            U256::from(100u64),
            current,
        ));
        assert!(!quote_is_better(
            UniswapSwapKind::ExactIn,
            key(3_000),
            U256::from(99u64),
            U256::from(1u64),
            current,
        ));
    }

    #[test]
    fn automatic_selection_minimizes_exact_output_input() {
        let current = Some((key(500), U256::from(100u64), U256::from(50u64)));
        assert!(quote_is_better(
            UniswapSwapKind::ExactOut,
            key(3_000),
            U256::from(99u64),
            U256::from(100u64),
            current,
        ));
    }

    #[test]
    fn automatic_selection_uses_gas_for_equal_quotes() {
        let current = Some((key(500), U256::from(100u64), U256::from(50u64)));
        assert!(quote_is_better(
            UniswapSwapKind::ExactIn,
            key(3_000),
            U256::from(100u64),
            U256::from(49u64),
            current,
        ));
    }

    #[test]
    fn indexed_address_topic_round_trips() {
        let address = Address::from_low_u64_be(42);
        assert_eq!(
            address_from_topic(&address_topic(address)).unwrap(),
            address
        );
    }

    #[tokio::test]
    #[ignore = "requires the public Arc testnet Blockscout API"]
    async fn live_discovers_official_arc_testnet_pools() {
        let usdc = "0x3600000000000000000000000000000000000000"
            .parse::<Address>()
            .unwrap();
        let paired_token = "0x99f5ef58ecf20f4b8ec8c4af451a74045aa40573"
            .parse::<Address>()
            .unwrap();
        let pools = fetch_pool_keys_from_blockscout(usdc, paired_token)
            .await
            .unwrap();
        assert!(!pools.is_empty());
        assert!(pools.iter().any(|pool| pool.hooks == Address::zero()));
    }
}
