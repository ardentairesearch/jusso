use anyhow::{anyhow, Result};
use chrono::Utc;
use ethers::abi::{self, ParamType};
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, U256};
use ethers::utils::format_units;
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::adapter as balancer_v3;
use super::adapter::{
    BalancerAddLiquidityQuoteResponse, BalancerAddLiquidityRequest, BalancerBalancesQuery,
    BalancerBalancesResponse, BalancerDiscoveredPool, BalancerDiscoveredPoolToken,
    BalancerLiquidityAmount, BalancerPoolQuery, BalancerPoolResponse, BalancerPoolSelection,
    BalancerPoolToken, BalancerPoolsQuery, BalancerPoolsResponse, BalancerQuoteResponse,
    BalancerRemoveLiquidityQuoteResponse, BalancerRemoveLiquidityRequest, BalancerSwapKind,
    BalancerSwapRequest, BalancerTokenAmount, BalancerTokenBalance,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{handle_execute, handle_simulate, resolve_chain_smart_wallet_address};
use crate::execution_engine::ExecutionEngine;
use crate::types::{Chain, ExecutionResponse};

const DEFAULT_DEADLINE_SECS: u64 = 20 * 60;
const BPS_SCALE: u64 = 10_000;
const BALANCER_API_URL: &str = "https://api-v3.balancer.fi/graphql";
const BLOCKSCOUT_LOGS_URL: &str = "https://eth-sepolia.blockscout.com/api";
const BALANCER_VAULT_ADDRESS: &str = "0xbA1333333333a1BA1108E8412f11850A5C319bA9";
const POOL_REGISTERED_TOPIC: &str =
    "0xbc1561eeab9f40962e2fb827a7ff9c7cdb47a9d7c84caeefa4ed90e043842dad";
const DISCOVERY_CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
struct DiscoveryCacheEntry {
    fetched_at: Instant,
    pools: Vec<ApiPool>,
}

static DISCOVERY_CACHE: OnceLock<RwLock<Option<DiscoveryCacheEntry>>> = OnceLock::new();
static REGISTERED_POOL_CACHE: OnceLock<RwLock<Option<DiscoveryCacheEntry>>> = OnceLock::new();

pub async fn handle_swap(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerSwapRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_swap(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_swap(&resolved.request)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow!("Balancer V3 swap on Ethereum Sepolia failed: {e}"))
}

pub async fn handle_swap_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerSwapRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_swap(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_swap(&resolved.request)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_add_liquidity(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerAddLiquidityRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_add_liquidity(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_add_liquidity(
        req,
        &resolved.tokens,
        &resolved.amounts_in,
        resolved.min_bpt_amount_out,
        resolved.deadline,
    )?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow!("Balancer V3 add liquidity on Ethereum Sepolia failed: {e}"))
}

pub async fn handle_add_liquidity_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerAddLiquidityRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_add_liquidity(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_add_liquidity(
        req,
        &resolved.tokens,
        &resolved.amounts_in,
        resolved.min_bpt_amount_out,
        resolved.deadline,
    )?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_remove_liquidity(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerRemoveLiquidityRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_remove_liquidity(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_remove_liquidity(req, &resolved.min_amounts_out)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow!("Balancer V3 remove liquidity on Ethereum Sepolia failed: {e}"))
}

pub async fn handle_remove_liquidity_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerRemoveLiquidityRequest,
) -> Result<ExecutionResponse> {
    let resolved = resolve_remove_liquidity(engine, wallet_registry, organization_id, req).await?;
    let execution_req = balancer_v3::compile_remove_liquidity(req, &resolved.min_amounts_out)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_quote(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerSwapRequest,
) -> Result<BalancerQuoteResponse> {
    let resolved = resolve_swap(engine, wallet_registry, organization_id, req).await?;

    Ok(BalancerQuoteResponse {
        agent_id: req.agent_id.clone(),
        chain: "ethereum".to_string(),
        smart_wallet_address: format!("{:?}", resolved.smart_wallet_address),
        pool_address: format!("{:?}", resolved.pool),
        pool_selection: resolved.pool_selection,
        candidates_discovered: resolved.candidates_discovered,
        candidates_quoted: resolved.candidates_quoted,
        token_in: format!(
            "{:?}",
            balancer_v3::parse_request_address(&req.token_in, "token_in")?
        ),
        token_out: format!(
            "{:?}",
            balancer_v3::parse_request_address(&req.token_out, "token_out")?
        ),
        swap_kind: req.swap_kind,
        amount_raw: balancer_v3::amount(req)?.to_string(),
        quoted_amount_raw: resolved.quoted_amount.to_string(),
        limit_raw: resolved.limit.to_string(),
        slippage_bps: req.slippage_bps,
        deadline: resolved.deadline,
    })
}

pub async fn handle_pools(
    engine: &ExecutionEngine,
    query: &BalancerPoolsQuery,
) -> Result<BalancerPoolsResponse> {
    balancer_v3::validate_pools_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let token_in = balancer_v3::parse_request_address(&query.token_in, "token_in")?;
    let token_out = balancer_v3::parse_request_address(&query.token_out, "token_out")?;
    let candidates = discover_pair_pools(token_in, token_out).await?;
    let mut pools = Vec::new();
    for candidate in candidates {
        let pool: Address = candidate
            .address
            .parse()
            .map_err(|_| anyhow!("Balancer API returned an invalid pool address"))?;
        let Ok(state) = load_pool_state(engine, &chain, pool).await else {
            continue;
        };
        pools.push(discovered_pool_response(engine, &chain, candidate, state).await?);
    }
    Ok(BalancerPoolsResponse {
        chain: "ethereum".to_string(),
        token_in: format!("{token_in:?}"),
        token_out: format!("{token_out:?}"),
        pools,
    })
}

pub async fn handle_add_liquidity_quote(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerAddLiquidityRequest,
) -> Result<BalancerAddLiquidityQuoteResponse> {
    let resolved = resolve_add_liquidity(engine, wallet_registry, organization_id, req).await?;
    Ok(BalancerAddLiquidityQuoteResponse {
        agent_id: req.agent_id.clone(),
        chain: "ethereum".to_string(),
        smart_wallet_address: format!("{:?}", resolved.smart_wallet_address),
        pool_address: format!(
            "{:?}",
            balancer_v3::parse_request_address(&req.pool, "pool")?
        ),
        amounts_in: liquidity_amounts(&resolved.tokens, &resolved.amounts_in),
        quoted_bpt_amount_out_raw: resolved.quoted_bpt_amount_out.to_string(),
        min_bpt_amount_out_raw: resolved.min_bpt_amount_out.to_string(),
        slippage_bps: req.slippage_bps,
        deadline: resolved.deadline,
    })
}

pub async fn handle_remove_liquidity_quote(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerRemoveLiquidityRequest,
) -> Result<BalancerRemoveLiquidityQuoteResponse> {
    let resolved = resolve_remove_liquidity(engine, wallet_registry, organization_id, req).await?;
    Ok(BalancerRemoveLiquidityQuoteResponse {
        agent_id: req.agent_id.clone(),
        chain: "ethereum".to_string(),
        smart_wallet_address: format!("{:?}", resolved.smart_wallet_address),
        pool_address: format!(
            "{:?}",
            balancer_v3::parse_request_address(&req.pool, "pool")?
        ),
        bpt_amount_in_raw: req.bpt_amount_in_raw.clone(),
        quoted_amounts_out: liquidity_amounts(&resolved.tokens, &resolved.quoted_amounts_out),
        min_amounts_out: liquidity_amounts(&resolved.tokens, &resolved.min_amounts_out),
        slippage_bps: req.slippage_bps,
    })
}

pub async fn handle_pool(
    engine: &ExecutionEngine,
    query: &BalancerPoolQuery,
) -> Result<BalancerPoolResponse> {
    balancer_v3::validate_pool_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let pool = balancer_v3::parse_request_address(&query.pool, "pool")?;
    let state = load_pool_state(engine, &chain, pool).await?;

    let (pool_name, pool_symbol, pool_decimals, total_supply) = tokio::try_join!(
        token_name(engine, &chain, pool),
        token_symbol(engine, &chain, pool),
        token_decimals(engine, &chain, pool),
        call_u256(
            engine,
            &chain,
            pool,
            balancer_v3::encode_total_supply(),
            "Balancer BPT total supply"
        ),
    )?;

    let mut tokens = Vec::with_capacity(state.tokens.len());
    for (index, token) in state.tokens.iter().copied().enumerate() {
        let decimals = token_decimals(engine, &chain, token).await?;
        let symbol = token_symbol_or_fallback(engine, &chain, token).await;
        let name = token_name_or_fallback(engine, &chain, token, &symbol).await;
        let raw_balance = state.raw_balances[index];
        tokens.push(BalancerPoolToken {
            index,
            address: format!("{token:?}"),
            symbol,
            name,
            decimals,
            pool_balance_raw: raw_balance.to_string(),
            pool_balance_formatted: format_token_units(raw_balance, decimals)?,
            live_balance_scaled_18_raw: state.live_balances[index].to_string(),
        });
    }

    Ok(BalancerPoolResponse {
        chain: "ethereum".to_string(),
        pool_address: format!("{pool:?}"),
        pool_name,
        pool_symbol,
        pool_decimals,
        total_supply_raw: total_supply.to_string(),
        total_supply_formatted: format_token_units(total_supply, pool_decimals)?,
        router_address: format!("{:?}", balancer_v3::router_address()),
        vault_address: format!("{:?}", balancer_v3::vault_address()),
        vault_explorer_address: format!("{:?}", balancer_v3::vault_explorer_address()),
        permit2_address: format!("{:?}", balancer_v3::permit2_address()),
        is_registered: true,
        is_initialized: state.is_initialized,
        is_paused: state.is_paused,
        is_in_recovery_mode: state.is_in_recovery_mode,
        static_swap_fee_percentage_raw: state.static_swap_fee_percentage.to_string(),
        tokens,
    })
}

pub async fn handle_balances(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &BalancerBalancesQuery,
) -> Result<BalancerBalancesResponse> {
    balancer_v3::validate_balances_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let pool = balancer_v3::parse_request_address(&query.pool, "pool")?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;
    let state = load_pool_state(engine, &chain, pool).await?;

    let (pool_decimals, bpt_balance) = tokio::try_join!(
        token_decimals(engine, &chain, pool),
        call_u256(
            engine,
            &chain,
            pool,
            balancer_v3::encode_balance_of(smart_wallet_address),
            "Balancer BPT balance"
        ),
    )?;

    let mut tokens = Vec::with_capacity(state.tokens.len());
    for token in state.tokens {
        let (decimals, wallet_balance) = tokio::try_join!(
            token_decimals(engine, &chain, token),
            call_u256(
                engine,
                &chain,
                token,
                balancer_v3::encode_balance_of(smart_wallet_address),
                "Balancer token wallet balance"
            ),
        )?;
        let symbol = token_symbol_or_fallback(engine, &chain, token).await;
        let name = token_name_or_fallback(engine, &chain, token, &symbol).await;
        tokens.push(BalancerTokenBalance {
            address: format!("{token:?}"),
            symbol,
            name,
            decimals,
            wallet_balance_raw: wallet_balance.to_string(),
            wallet_balance_formatted: format_token_units(wallet_balance, decimals)?,
        });
    }

    Ok(BalancerBalancesResponse {
        agent_id: query.agent_id.clone(),
        chain: "ethereum".to_string(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        pool_address: format!("{pool:?}"),
        bpt_balance_raw: bpt_balance.to_string(),
        bpt_balance_formatted: format_token_units(bpt_balance, pool_decimals)?,
        tokens,
    })
}

struct ResolvedSwap {
    request: BalancerSwapRequest,
    smart_wallet_address: Address,
    pool: Address,
    pool_selection: BalancerPoolSelection,
    quoted_amount: U256,
    limit: U256,
    deadline: u64,
    candidates_discovered: usize,
    candidates_quoted: usize,
}

async fn resolve_swap(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerSwapRequest,
) -> Result<ResolvedSwap> {
    balancer_v3::validate_swap_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;

    let (pool, quoted_amount, pool_selection, candidates_discovered, candidates_quoted) =
        if req.pool.trim().is_empty() {
            select_best_pool(engine, &chain, req, smart_wallet_address).await?
        } else {
            let pool = balancer_v3::parse_request_address(&req.pool, "pool")?;
            validate_pool_for_swap(engine, &chain, req).await?;
            let quote = quote_swap(engine, &chain, req, smart_wallet_address).await?;
            (pool, quote, BalancerPoolSelection::Explicit, 1usize, 1usize)
        };
    let limit = match balancer_v3::explicit_limit(req)? {
        Some(limit) => {
            validate_explicit_limit(req.swap_kind, quoted_amount, limit)?;
            limit
        }
        None => limit_from_quote(req.swap_kind, quoted_amount, req.slippage_bps)?,
    };
    let max_input = match req.swap_kind {
        BalancerSwapKind::ExactIn => balancer_v3::amount(req)?,
        BalancerSwapKind::ExactOut => limit,
    };
    balancer_v3::validate_permit2_amount(max_input, "Balancer swap maximum input")?;
    let deadline = resolve_deadline(req.deadline, "swap")?;
    let request = balancer_v3::swap_with_resolved_limit(req, pool, limit, deadline);
    Ok(ResolvedSwap {
        request,
        smart_wallet_address,
        pool,
        pool_selection,
        quoted_amount,
        limit,
        deadline,
        candidates_discovered,
        candidates_quoted,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiPool {
    address: String,
    name: String,
    symbol: String,
    #[serde(rename = "type")]
    pool_type: String,
    pool_tokens: Vec<ApiPoolToken>,
    dynamic_data: Option<ApiPoolDynamicData>,
}

#[derive(Debug, Clone, Deserialize)]
struct ApiPoolToken {
    address: String,
    symbol: String,
    decimals: u8,
    index: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApiPoolDynamicData {
    total_liquidity: Option<String>,
    swap_fee: Option<String>,
}

#[derive(Serialize)]
struct GraphQlRequest<'a> {
    query: &'a str,
    variables: serde_json::Value,
}

#[derive(Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
    #[serde(default)]
    errors: Vec<GraphQlError>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GraphQlData {
    pool_get_pools: Vec<ApiPool>,
}

#[derive(Deserialize)]
struct GraphQlError {
    message: String,
}

async fn discover_pair_pools(token_in: Address, token_out: Address) -> Result<Vec<ApiPool>> {
    let (api_result, registered_result) =
        tokio::join!(discover_pools(), discover_registered_pools());
    let (api_pools, registered) = match (api_result, registered_result) {
        (Ok(api), Ok(registered)) => (api, registered),
        (Ok(api), Err(_)) => (api, Vec::new()),
        (Err(_), Ok(registered)) => (Vec::new(), registered),
        (Err(api_error), Err(onchain_error)) => {
            return Err(anyhow!(
                "Balancer pool discovery failed through both API ({api_error}) and on-chain index ({onchain_error})"
            ));
        }
    };
    let mut pools = registered
        .into_iter()
        .map(|pool| {
            let address = pool.address.to_ascii_lowercase();
            (address, pool)
        })
        .collect::<HashMap<_, _>>();
    for pool in api_pools {
        pools.insert(pool.address.to_ascii_lowercase(), pool);
    }
    Ok(pools
        .into_values()
        .filter(|pool| {
            let has_in = pool.pool_tokens.iter().any(|token| {
                token
                    .address
                    .parse::<Address>()
                    .map(|address| address == token_in)
                    .unwrap_or(false)
            });
            let has_out = pool.pool_tokens.iter().any(|token| {
                token
                    .address
                    .parse::<Address>()
                    .map(|address| address == token_out)
                    .unwrap_or(false)
            });
            has_in && has_out
        })
        .collect())
}

async fn discover_registered_pools() -> Result<Vec<ApiPool>> {
    let cache = REGISTERED_POOL_CACHE.get_or_init(|| RwLock::new(None));
    if let Some(entry) = cache.read().await.as_ref() {
        if entry.fetched_at.elapsed() < DISCOVERY_CACHE_TTL {
            return Ok(entry.pools.clone());
        }
    }
    match fetch_registered_pools_from_blockscout().await {
        Ok(pools) => {
            *cache.write().await = Some(DiscoveryCacheEntry {
                fetched_at: Instant::now(),
                pools: pools.clone(),
            });
            Ok(pools)
        }
        Err(error) => {
            if let Some(entry) = cache.read().await.as_ref() {
                return Ok(entry.pools.clone());
            }
            Err(error)
        }
    }
}

async fn discover_pools() -> Result<Vec<ApiPool>> {
    let cache = DISCOVERY_CACHE.get_or_init(|| RwLock::new(None));
    if let Some(entry) = cache.read().await.as_ref() {
        if entry.fetched_at.elapsed() < DISCOVERY_CACHE_TTL {
            return Ok(entry.pools.clone());
        }
    }

    match fetch_pools_from_api().await {
        Ok(pools) => {
            *cache.write().await = Some(DiscoveryCacheEntry {
                fetched_at: Instant::now(),
                pools: pools.clone(),
            });
            Ok(pools)
        }
        Err(error) => {
            if let Some(entry) = cache.read().await.as_ref() {
                return Ok(entry.pools.clone());
            }
            Err(error)
        }
    }
}

async fn fetch_pools_from_api() -> Result<Vec<ApiPool>> {
    const QUERY: &str = r#"
        query Pools($where: GqlPoolFilter) {
          poolGetPools(first: 1000, where: $where) {
            address name symbol type
            poolTokens { address symbol decimals index }
            dynamicData { totalLiquidity swapFee }
          }
        }
    "#;
    let response = reqwest::Client::new()
        .post(BALANCER_API_URL)
        .json(&GraphQlRequest {
            query: QUERY,
            variables: serde_json::json!({
                "where": {
                    "chainIn": ["SEPOLIA"],
                    "protocolVersionIn": [3]
                }
            }),
        })
        .send()
        .await
        .map_err(|e| anyhow!("Balancer pool discovery API request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "Balancer pool discovery API returned HTTP {}",
            response.status()
        ));
    }
    let body: GraphQlResponse = response
        .json()
        .await
        .map_err(|e| anyhow!("Balancer pool discovery API response was invalid: {e}"))?;
    if !body.errors.is_empty() {
        return Err(anyhow!(
            "Balancer pool discovery API error: {}",
            body.errors
                .into_iter()
                .map(|error| error.message)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    body.data
        .map(|data| data.pool_get_pools)
        .ok_or_else(|| anyhow!("Balancer pool discovery API returned no data"))
}

#[derive(Deserialize)]
struct BlockscoutLogsResponse {
    status: String,
    message: String,
    result: Vec<BlockscoutLog>,
}

#[derive(Deserialize)]
struct BlockscoutLog {
    #[serde(rename = "blockNumber")]
    block_number: String,
    data: String,
    topics: Vec<Option<String>>,
}

async fn fetch_registered_pools_from_blockscout() -> Result<Vec<ApiPool>> {
    const PAGE_SIZE: usize = 1_000;
    const MAX_PAGES: usize = 100;
    let client = reqwest::Client::new();
    let mut pools = HashMap::new();
    let mut from_block = 0u64;
    for page in 1..=MAX_PAGES {
        let response = client
            .get(BLOCKSCOUT_LOGS_URL)
            .query(&[
                ("module", "logs".to_string()),
                ("action", "getLogs".to_string()),
                ("address", BALANCER_VAULT_ADDRESS.to_string()),
                ("topic0", POOL_REGISTERED_TOPIC.to_string()),
                ("fromBlock", from_block.to_string()),
                ("toBlock", "latest".to_string()),
            ])
            .send()
            .await
            .map_err(|e| anyhow!("Balancer on-chain pool discovery request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "Balancer on-chain pool discovery returned HTTP {}",
                response.status()
            ));
        }
        let body: BlockscoutLogsResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Balancer on-chain pool discovery response was invalid: {e}"))?;
        if body.status != "1" {
            if page > 1 && body.result.is_empty() {
                break;
            }
            return Err(anyhow!(
                "Balancer on-chain pool discovery failed: {}",
                body.message
            ));
        }
        let result_count = body.result.len();
        let mut highest_block = from_block;
        for log in body.result {
            highest_block = highest_block.max(
                u64::from_str_radix(log.block_number.trim_start_matches("0x"), 16)
                    .map_err(|_| anyhow!("Balancer discovery returned an invalid block number"))?,
            );
            let pool = decode_registered_pool(&log)?;
            pools.insert(pool.address.to_ascii_lowercase(), pool);
        }
        if result_count < PAGE_SIZE {
            break;
        }
        if highest_block <= from_block {
            return Err(anyhow!(
                "Balancer on-chain pool discovery block pagination made no progress"
            ));
        }
        // Repeat the boundary block so registrations sharing it cannot be skipped.
        from_block = highest_block;
        if page == MAX_PAGES {
            return Err(anyhow!(
                "Balancer on-chain pool discovery exceeded {MAX_PAGES} pages"
            ));
        }
    }
    Ok(pools.into_values().collect())
}

fn decode_registered_pool(log: &BlockscoutLog) -> Result<ApiPool> {
    let pool_topic = log
        .topics
        .get(1)
        .and_then(Option::as_deref)
        .ok_or_else(|| anyhow!("PoolRegistered log omitted indexed pool"))?;
    let topic = hex::decode(pool_topic.trim_start_matches("0x"))?;
    if topic.len() != 32 {
        return Err(anyhow!("PoolRegistered pool topic had invalid length"));
    }
    let pool = Address::from_slice(&topic[12..]);
    let data = hex::decode(log.data.trim_start_matches("0x"))?;
    if data.len() < 32 {
        return Err(anyhow!("PoolRegistered data was truncated"));
    }
    let offset = U256::from_big_endian(&data[..32]);
    if offset > U256::from(usize::MAX) {
        return Err(anyhow!("PoolRegistered token offset overflowed"));
    }
    let offset = offset.as_usize();
    let length_end = offset
        .checked_add(32)
        .ok_or_else(|| anyhow!("PoolRegistered token offset overflowed"))?;
    if length_end > data.len() {
        return Err(anyhow!("PoolRegistered token array was truncated"));
    }
    let count = U256::from_big_endian(&data[offset..length_end]);
    if count > U256::from(64u64) {
        return Err(anyhow!("PoolRegistered reported too many tokens"));
    }
    let mut pool_tokens = Vec::with_capacity(count.as_usize());
    for index in 0..count.as_usize() {
        let start = length_end
            .checked_add(
                index
                    .checked_mul(4 * 32)
                    .ok_or_else(|| anyhow!("PoolRegistered token index overflowed"))?,
            )
            .ok_or_else(|| anyhow!("PoolRegistered token index overflowed"))?;
        let end = start + 32;
        if end > data.len() {
            return Err(anyhow!("PoolRegistered token config was truncated"));
        }
        let token = Address::from_slice(&data[start + 12..end]);
        pool_tokens.push(ApiPoolToken {
            address: format!("{token:?}"),
            symbol: String::new(),
            decimals: 0,
            index,
        });
    }
    Ok(ApiPool {
        address: format!("{pool:?}"),
        name: String::new(),
        symbol: String::new(),
        pool_type: "unknown".to_string(),
        pool_tokens,
        dynamic_data: None,
    })
}

async fn select_best_pool(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &BalancerSwapRequest,
    sender: Address,
) -> Result<(Address, U256, BalancerPoolSelection, usize, usize)> {
    let token_in = balancer_v3::parse_request_address(&req.token_in, "token_in")?;
    let token_out = balancer_v3::parse_request_address(&req.token_out, "token_out")?;
    let candidates = discover_pair_pools(token_in, token_out).await?;
    let discovered = candidates.len();
    let mut quoted = 0usize;
    let mut best: Option<(Address, U256)> = None;

    for candidate in candidates {
        let Ok(pool) = candidate.address.parse::<Address>() else {
            continue;
        };
        let mut request = req.clone();
        request.pool = format!("{pool:?}");
        if validate_pool_for_swap(engine, chain, &request)
            .await
            .is_err()
        {
            continue;
        }
        let Ok(amount) = quote_swap(engine, chain, &request, sender).await else {
            continue;
        };
        if amount.is_zero() {
            continue;
        }
        quoted += 1;
        let replace = match best {
            None => true,
            Some((best_pool, best_amount)) => match req.swap_kind {
                BalancerSwapKind::ExactIn => {
                    amount > best_amount || (amount == best_amount && pool < best_pool)
                }
                BalancerSwapKind::ExactOut => {
                    amount < best_amount || (amount == best_amount && pool < best_pool)
                }
            },
        };
        if replace {
            best = Some((pool, amount));
        }
    }

    let (pool, quote) = best.ok_or_else(|| {
        anyhow!(
            "Balancer V3 automatic selection found {discovered} pair-compatible pools, but none produced a valid live quote"
        )
    })?;
    Ok((
        pool,
        quote,
        BalancerPoolSelection::Automatic,
        discovered,
        quoted,
    ))
}

async fn discovered_pool_response(
    engine: &ExecutionEngine,
    chain: &Chain,
    mut pool: ApiPool,
    state: PoolState,
) -> Result<BalancerDiscoveredPool> {
    let pool_address = pool.address.parse::<Address>()?;
    if pool.symbol.is_empty() {
        pool.symbol = token_symbol_or_fallback(engine, chain, pool_address).await;
    }
    if pool.name.is_empty() {
        pool.name = token_name_or_fallback(engine, chain, pool_address, &pool.symbol).await;
    }
    for token in &mut pool.pool_tokens {
        let address = token.address.parse::<Address>()?;
        if token.symbol.is_empty() {
            token.symbol = token_symbol_or_fallback(engine, chain, address).await;
        }
        if token.decimals == 0 {
            token.decimals = token_decimals(engine, chain, address).await?;
        }
    }
    Ok(BalancerDiscoveredPool {
        pool_address: pool.address,
        name: pool.name,
        symbol: pool.symbol,
        pool_type: pool.pool_type,
        total_liquidity_usd: pool
            .dynamic_data
            .as_ref()
            .and_then(|data| data.total_liquidity.clone()),
        swap_fee: pool
            .dynamic_data
            .as_ref()
            .and_then(|data| data.swap_fee.clone()),
        tokens: pool
            .pool_tokens
            .into_iter()
            .map(|token| BalancerDiscoveredPoolToken {
                address: token.address,
                symbol: token.symbol,
                decimals: token.decimals,
                index: token.index,
            })
            .collect(),
        is_initialized: state.is_initialized,
        is_paused: state.is_paused,
        is_in_recovery_mode: state.is_in_recovery_mode,
    })
}

struct ResolvedAddLiquidity {
    smart_wallet_address: Address,
    tokens: Vec<Address>,
    amounts_in: Vec<U256>,
    quoted_bpt_amount_out: U256,
    min_bpt_amount_out: U256,
    deadline: u64,
}

async fn resolve_add_liquidity(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerAddLiquidityRequest,
) -> Result<ResolvedAddLiquidity> {
    balancer_v3::validate_add_liquidity_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let pool = balancer_v3::parse_request_address(&req.pool, "pool")?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;
    let state = validate_pool_for_liquidity(engine, &chain, pool, "add").await?;
    let amounts_in = order_token_amounts(&state.tokens, &req.amounts_in, "amounts_in")?;
    let quoted_bpt_amount_out = call_u256(
        engine,
        &chain,
        balancer_v3::router_address(),
        balancer_v3::encode_query_add_liquidity_unbalanced(pool, &amounts_in, smart_wallet_address),
        "Balancer V3 add-liquidity quote",
    )
    .await
    .map_err(|e| {
        let raw = e.to_string();
        if raw.to_ascii_lowercase().contains("0xd4f5779c") {
            anyhow!(
                "Balancer V3 add liquidity rejected: the selected pool does not support unbalanced liquidity"
            )
        } else {
            anyhow!("Balancer V3 add liquidity rejected by Router quote: {raw}")
        }
    })?;
    if quoted_bpt_amount_out.is_zero() {
        return Err(anyhow!("Balancer V3 add-liquidity quote returned zero BPT"));
    }
    let min_bpt_amount_out = match req.min_bpt_amount_out_raw.as_deref() {
        Some(value) => {
            let explicit = U256::from_dec_str(value)
                .map_err(|_| anyhow!("min_bpt_amount_out_raw must be a raw unsigned integer"))?;
            if explicit > quoted_bpt_amount_out {
                return Err(anyhow!(
                    "Balancer min_bpt_amount_out_raw exceeds the current quoted BPT output"
                ));
            }
            explicit
        }
        None => downward_slippage(quoted_bpt_amount_out, req.slippage_bps)?,
    };

    Ok(ResolvedAddLiquidity {
        smart_wallet_address,
        tokens: state.tokens,
        amounts_in,
        quoted_bpt_amount_out,
        min_bpt_amount_out,
        deadline: resolve_deadline(req.deadline, "liquidity approval")?,
    })
}

struct ResolvedRemoveLiquidity {
    smart_wallet_address: Address,
    tokens: Vec<Address>,
    quoted_amounts_out: Vec<U256>,
    min_amounts_out: Vec<U256>,
}

async fn resolve_remove_liquidity(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &BalancerRemoveLiquidityRequest,
) -> Result<ResolvedRemoveLiquidity> {
    balancer_v3::validate_remove_liquidity_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let pool = balancer_v3::parse_request_address(&req.pool, "pool")?;
    let bpt_amount_in = U256::from_dec_str(&req.bpt_amount_in_raw)
        .map_err(|_| anyhow!("bpt_amount_in_raw must be a raw unsigned integer"))?;
    let wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;
    let state = validate_pool_for_liquidity(engine, &chain, pool, "remove").await?;
    let bpt_balance = call_u256(
        engine,
        &chain,
        pool,
        balancer_v3::encode_balance_of(smart_wallet_address),
        "Balancer BPT balance",
    )
    .await?;
    if bpt_amount_in > bpt_balance {
        return Err(anyhow!(
            "Balancer remove liquidity requested BPT amount {bpt_amount_in} exceeds the agent wallet balance {bpt_balance}"
        ));
    }
    let quoted_amounts_out = call_u256_array(
        engine,
        &chain,
        balancer_v3::router_address(),
        balancer_v3::encode_query_remove_liquidity_proportional(
            pool,
            bpt_amount_in,
            smart_wallet_address,
        ),
        "Balancer V3 remove-liquidity quote",
    )
    .await
    .map_err(|e| anyhow!("Balancer V3 remove liquidity rejected by Router quote: {e}"))?;
    if quoted_amounts_out.len() != state.tokens.len() {
        return Err(anyhow!(
            "Balancer remove-liquidity quote returned an unexpected token count"
        ));
    }

    let min_amounts_out = match req.min_amounts_out.as_deref() {
        Some(explicit) => {
            let ordered = order_token_amounts(&state.tokens, explicit, "min_amounts_out")?;
            for (minimum, quote) in ordered.iter().zip(&quoted_amounts_out) {
                if minimum > quote {
                    return Err(anyhow!(
                        "Balancer min_amounts_out contains an amount above the current quote"
                    ));
                }
            }
            ordered
        }
        None => quoted_amounts_out
            .iter()
            .copied()
            .map(|quote| downward_slippage_allow_zero(quote, req.slippage_bps))
            .collect::<Result<Vec<_>>>()?,
    };

    Ok(ResolvedRemoveLiquidity {
        smart_wallet_address,
        tokens: state.tokens,
        quoted_amounts_out,
        min_amounts_out,
    })
}

async fn validate_pool_for_swap(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &BalancerSwapRequest,
) -> Result<()> {
    let pool = balancer_v3::parse_request_address(&req.pool, "pool")?;
    let token_in = balancer_v3::parse_request_address(&req.token_in, "token_in")?;
    let token_out = balancer_v3::parse_request_address(&req.token_out, "token_out")?;
    let state = load_pool_state(engine, chain, pool).await?;

    if !state.is_initialized {
        return Err(anyhow!(
            "Balancer V3 swap rejected: pool is not initialized"
        ));
    }
    if state.is_paused {
        return Err(anyhow!("Balancer V3 swap rejected: pool is paused"));
    }
    if state.is_in_recovery_mode {
        return Err(anyhow!(
            "Balancer V3 swap rejected: pool is in recovery mode"
        ));
    }
    if !state.tokens.contains(&token_in) {
        return Err(anyhow!(
            "Balancer V3 swap rejected: token_in is not registered in the selected pool"
        ));
    }
    if !state.tokens.contains(&token_out) {
        return Err(anyhow!(
            "Balancer V3 swap rejected: token_out is not registered in the selected pool"
        ));
    }
    Ok(())
}

async fn quote_swap(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &BalancerSwapRequest,
    sender: Address,
) -> Result<U256> {
    let calldata = balancer_v3::encode_query_swap(req, sender)?;
    call_u256(
        engine,
        chain,
        balancer_v3::router_address(),
        calldata,
        "Balancer V3 swap quote",
    )
    .await
    .map_err(|e| {
        let raw = e.to_string();
        if raw.to_ascii_lowercase().contains("0xfdf79845") {
            anyhow!("Balancer V3 swap rejected: swaps are disabled for the selected pool")
        } else {
            anyhow!("Balancer V3 swap rejected by Router quote: {raw}")
        }
    })
}

fn validate_explicit_limit(kind: BalancerSwapKind, quote: U256, limit: U256) -> Result<()> {
    match kind {
        BalancerSwapKind::ExactIn if limit > quote => Err(anyhow!(
            "Balancer exact-in limit_raw exceeds the current quoted output"
        )),
        BalancerSwapKind::ExactOut if limit < quote => Err(anyhow!(
            "Balancer exact-out limit_raw is below the current quoted input"
        )),
        _ => Ok(()),
    }
}

fn limit_from_quote(kind: BalancerSwapKind, quote: U256, slippage_bps: u16) -> Result<U256> {
    if quote.is_zero() {
        return Err(anyhow!("Balancer V3 swap quote returned zero"));
    }
    let scale = U256::from(BPS_SCALE);
    let bps = U256::from(slippage_bps);
    let limit = match kind {
        BalancerSwapKind::ExactIn => {
            quote
                .checked_mul(scale - bps)
                .ok_or_else(|| anyhow!("Balancer swap minimum output calculation overflowed"))?
                / scale
        }
        BalancerSwapKind::ExactOut => {
            let numerator = quote
                .checked_mul(scale + bps)
                .ok_or_else(|| anyhow!("Balancer swap maximum input calculation overflowed"))?;
            numerator
                .checked_add(scale - U256::one())
                .ok_or_else(|| anyhow!("Balancer swap maximum input calculation overflowed"))?
                / scale
        }
    };
    if limit.is_zero() {
        return Err(anyhow!(
            "Balancer V3 swap slippage limit rounded to zero; provide limit_raw explicitly"
        ));
    }
    Ok(limit)
}

fn resolve_deadline(requested: Option<u64>, context: &str) -> Result<u64> {
    let now = Utc::now().timestamp();
    if now < 0 {
        return Err(anyhow!("system clock is before the Unix epoch"));
    }
    let now = now as u64;
    let deadline = match requested {
        Some(deadline) => {
            if deadline <= now {
                return Err(anyhow!("Balancer {context} deadline must be in the future"));
            }
            deadline
        }
        None => now
            .checked_add(DEFAULT_DEADLINE_SECS)
            .ok_or_else(|| anyhow!("Balancer {context} deadline overflowed"))?,
    };
    if deadline > ((1u64 << 48) - 1) {
        return Err(anyhow!("Balancer {context} deadline exceeds uint48"));
    }
    Ok(deadline)
}

async fn validate_pool_for_liquidity(
    engine: &ExecutionEngine,
    chain: &Chain,
    pool: Address,
    action: &str,
) -> Result<PoolState> {
    let state = load_pool_state(engine, chain, pool).await?;
    if !state.is_initialized {
        return Err(anyhow!(
            "Balancer V3 {action} liquidity rejected: pool is not initialized"
        ));
    }
    if state.is_paused {
        return Err(anyhow!(
            "Balancer V3 {action} liquidity rejected: pool is paused"
        ));
    }
    if state.is_in_recovery_mode {
        return Err(anyhow!(
            "Balancer V3 {action} liquidity rejected: pool is in recovery mode"
        ));
    }
    Ok(state)
}

fn order_token_amounts(
    pool_tokens: &[Address],
    requested: &[BalancerTokenAmount],
    field: &str,
) -> Result<Vec<U256>> {
    let mut ordered = vec![U256::zero(); pool_tokens.len()];
    for entry in requested {
        let token = balancer_v3::parse_request_address(&entry.token, &format!("{field}.token"))?;
        let index = pool_tokens
            .iter()
            .position(|candidate| *candidate == token)
            .ok_or_else(|| {
                anyhow!("Balancer {field} token {token:?} is not registered in the selected pool")
            })?;
        ordered[index] = U256::from_dec_str(&entry.amount_raw)
            .map_err(|_| anyhow!("{field}.amount_raw must be a raw unsigned integer"))?;
    }
    Ok(ordered)
}

fn liquidity_amounts(tokens: &[Address], amounts: &[U256]) -> Vec<BalancerLiquidityAmount> {
    tokens
        .iter()
        .zip(amounts)
        .map(|(token, amount)| BalancerLiquidityAmount {
            token: format!("{token:?}"),
            amount_raw: amount.to_string(),
        })
        .collect()
}

fn downward_slippage(value: U256, slippage_bps: u16) -> Result<U256> {
    let adjusted = downward_slippage_allow_zero(value, slippage_bps)?;
    if adjusted.is_zero() {
        return Err(anyhow!(
            "Balancer slippage limit rounded to zero; provide an explicit minimum"
        ));
    }
    Ok(adjusted)
}

fn downward_slippage_allow_zero(value: U256, slippage_bps: u16) -> Result<U256> {
    value
        .checked_mul(U256::from(BPS_SCALE - u64::from(slippage_bps)))
        .ok_or_else(|| anyhow!("Balancer liquidity slippage calculation overflowed"))
        .map(|numerator| numerator / U256::from(BPS_SCALE))
}

struct PoolState {
    tokens: Vec<Address>,
    raw_balances: Vec<U256>,
    live_balances: Vec<U256>,
    is_initialized: bool,
    is_paused: bool,
    is_in_recovery_mode: bool,
    static_swap_fee_percentage: U256,
}

async fn load_pool_state(
    engine: &ExecutionEngine,
    chain: &Chain,
    pool: Address,
) -> Result<PoolState> {
    let explorer = balancer_v3::vault_explorer_address();
    let is_registered = call_bool(
        engine,
        chain,
        explorer,
        balancer_v3::encode_is_pool_registered(pool),
        "Balancer pool registration",
    )
    .await?;
    if !is_registered {
        return Err(anyhow!(
            "Balancer V3 pool is not registered in the Sepolia Vault"
        ));
    }

    let (token_info_raw, live_balances, is_initialized, is_paused, recovery, fee) = tokio::try_join!(
        call_raw(
            engine,
            chain,
            explorer,
            balancer_v3::encode_get_pool_token_info(pool)
        ),
        call_u256_array(
            engine,
            chain,
            explorer,
            balancer_v3::encode_get_current_live_balances(pool),
            "Balancer live pool balances"
        ),
        call_bool(
            engine,
            chain,
            explorer,
            balancer_v3::encode_is_pool_initialized(pool),
            "Balancer pool initialization"
        ),
        call_bool(
            engine,
            chain,
            explorer,
            balancer_v3::encode_is_pool_paused(pool),
            "Balancer pool paused state"
        ),
        call_bool(
            engine,
            chain,
            explorer,
            balancer_v3::encode_is_pool_in_recovery_mode(pool),
            "Balancer pool recovery mode"
        ),
        call_u256(
            engine,
            chain,
            explorer,
            balancer_v3::encode_get_static_swap_fee_percentage(pool),
            "Balancer static swap fee"
        ),
    )?;
    let (tokens, raw_balances) = balancer_v3::decode_pool_token_info(&token_info_raw)?;
    if tokens.len() != live_balances.len() {
        return Err(anyhow!(
            "Balancer pool returned mismatched token and live-balance lengths"
        ));
    }

    Ok(PoolState {
        tokens,
        raw_balances,
        live_balances,
        is_initialized,
        is_paused,
        is_in_recovery_mode: recovery,
        static_swap_fee_percentage: fee,
    })
}

async fn call_raw(
    engine: &ExecutionEngine,
    chain: &Chain,
    target: Address,
    calldata: String,
) -> Result<Bytes> {
    let provider = engine.provider_for_chain(chain)?;
    let tx = TransactionRequest::new()
        .to(target)
        .data(parse_calldata(&calldata)?);
    Ok(provider.call(&tx.into(), None).await?)
}

async fn call_u256(
    engine: &ExecutionEngine,
    chain: &Chain,
    target: Address,
    calldata: String,
    context: &str,
) -> Result<U256> {
    let raw = call_raw(engine, chain, target, calldata).await?;
    balancer_v3::decode_u256(&raw, context)
}

async fn call_u256_array(
    engine: &ExecutionEngine,
    chain: &Chain,
    target: Address,
    calldata: String,
    context: &str,
) -> Result<Vec<U256>> {
    let raw = call_raw(engine, chain, target, calldata).await?;
    balancer_v3::decode_u256_array(&raw, context)
}

async fn call_bool(
    engine: &ExecutionEngine,
    chain: &Chain,
    target: Address,
    calldata: String,
    context: &str,
) -> Result<bool> {
    let raw = call_raw(engine, chain, target, calldata).await?;
    balancer_v3::decode_bool(&raw, context)
}

async fn token_decimals(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<u8> {
    let raw = call_raw(engine, chain, token, balancer_v3::encode_decimals()).await?;
    let value = balancer_v3::decode_u256(&raw, "ERC-20 decimals")?;
    if value > U256::from(u8::MAX) {
        return Err(anyhow!("ERC-20 decimals exceeds uint8"));
    }
    Ok(value.as_u32() as u8)
}

async fn token_symbol(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<String> {
    token_string(engine, chain, token, balancer_v3::encode_symbol(), "symbol").await
}

async fn token_name(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<String> {
    token_string(engine, chain, token, balancer_v3::encode_name(), "name").await
}

async fn token_symbol_or_fallback(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
) -> String {
    token_symbol(engine, chain, token)
        .await
        .unwrap_or_else(|_| compact_address_label(token))
}

async fn token_name_or_fallback(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
    symbol: &str,
) -> String {
    token_name(engine, chain, token)
        .await
        .unwrap_or_else(|_| symbol.to_string())
}

fn compact_address_label(address: Address) -> String {
    let raw = format!("{address:?}");
    format!("{}...{}", &raw[..8], &raw[raw.len() - 4..])
}

async fn token_string(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
    calldata: String,
    context: &str,
) -> Result<String> {
    let raw = call_raw(engine, chain, token, calldata).await?;
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

fn format_token_units(amount: U256, decimals: u8) -> Result<String> {
    format_units(amount, decimals as usize)
        .map_err(|e| anyhow!("failed to format token amount: {e}"))
}

fn parse_chain(chain: &str) -> Result<Chain> {
    match chain.trim().to_ascii_lowercase().as_str() {
        "ethereum" | "eth" | "sepolia" => Ok(Chain::Ethereum),
        other => Err(anyhow!(
            "unsupported chain for Balancer V3: {other}; use ethereum"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_in_limit_applies_downward_slippage() {
        assert_eq!(
            limit_from_quote(BalancerSwapKind::ExactIn, U256::from(1_000u64), 100).unwrap(),
            U256::from(990u64)
        );
    }

    #[test]
    fn exact_out_limit_rounds_up() {
        assert_eq!(
            limit_from_quote(BalancerSwapKind::ExactOut, U256::from(1_001u64), 100).unwrap(),
            U256::from(1_012u64)
        );
    }

    #[test]
    fn rejects_explicit_limit_that_conflicts_with_quote() {
        assert!(validate_explicit_limit(
            BalancerSwapKind::ExactIn,
            U256::from(100u64),
            U256::from(101u64)
        )
        .is_err());
        assert!(validate_explicit_limit(
            BalancerSwapKind::ExactOut,
            U256::from(100u64),
            U256::from(99u64)
        )
        .is_err());
    }

    #[test]
    fn orders_liquidity_amounts_by_vault_token_order() {
        let token_a = Address::from_low_u64_be(1);
        let token_b = Address::from_low_u64_be(2);
        let requested = vec![
            BalancerTokenAmount {
                token: format!("{token_b:?}"),
                amount_raw: "22".to_string(),
            },
            BalancerTokenAmount {
                token: format!("{token_a:?}"),
                amount_raw: "11".to_string(),
            },
        ];
        assert_eq!(
            order_token_amounts(&[token_a, token_b], &requested, "amounts_in").unwrap(),
            vec![U256::from(11u64), U256::from(22u64)]
        );
    }

    #[test]
    fn rejects_liquidity_token_not_registered_in_pool() {
        let requested = vec![BalancerTokenAmount {
            token: format!("{:?}", Address::from_low_u64_be(2)),
            amount_raw: "1".to_string(),
        }];
        assert!(
            order_token_amounts(&[Address::from_low_u64_be(1)], &requested, "amounts_in")
                .unwrap_err()
                .to_string()
                .contains("not registered")
        );
    }

    #[test]
    fn liquidity_slippage_rounds_down() {
        assert_eq!(
            downward_slippage(U256::from(1_001u64), 100).unwrap(),
            U256::from(990u64)
        );
        assert_eq!(
            downward_slippage_allow_zero(U256::zero(), 100).unwrap(),
            U256::zero()
        );
    }

    #[tokio::test]
    #[ignore = "requires the public Balancer GraphQL API"]
    async fn live_discovers_sepolia_v3_pools() {
        let pools = fetch_pools_from_api().await.unwrap();
        assert!(!pools.is_empty());
        assert!(pools.iter().all(|pool| !pool.pool_tokens.is_empty()));
    }
}
