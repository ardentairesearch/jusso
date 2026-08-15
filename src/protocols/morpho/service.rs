//! Morpho Blue orchestration and on-chain reads.

use anyhow::{anyhow, bail, Context, Result};
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, H256, U256, U512};
use ethers::utils::{format_units, parse_units};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

use super::adapter as morpho;
use super::adapter::{
    MorphoAction, MorphoActionRequest, MorphoMarketParams, MorphoMarketQuery, MorphoMarketState,
    MorphoMarketsQuery, MorphoPosition, MorphoPositionQuery, ResolvedAmount,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{handle_execute, handle_simulate, resolve_chain_smart_wallet_address};
use crate::execution_engine::ExecutionEngine;
use crate::types::{Chain, ExecutionResponse};

const WAD: u64 = 1_000_000_000_000_000_000;
const ORACLE_PRICE_SCALE_EXPONENT: usize = 36;
const VIRTUAL_SHARES: u64 = 1_000_000;
const VIRTUAL_ASSETS: u64 = 1;
const SECONDS_PER_YEAR: u64 = 31_536_000;
const MAX_SAFE_TOKEN_DECIMALS: u8 = 77;
const DEFAULT_MIN_HEALTH_FACTOR_WAD: u128 = 1_050_000_000_000_000_000;
const PYTH_STALE_PRICE_SELECTOR: &str = "0x19abf40e";
const BLOCKSCOUT_LOGS_URL: &str = "https://base-sepolia.blockscout.com/api";
const CREATE_MARKET_TOPIC: &str =
    "0xac4b2400f169220b0c0afdde7a0b32e775ba727ea1cb30b35f935cdaab8683ac";
const MARKET_CACHE_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
struct MarketDiscoveryCache {
    fetched_at: Instant,
    markets: Vec<(H256, MorphoMarketParams)>,
}

static MARKET_DISCOVERY_CACHE: OnceLock<RwLock<Option<MarketDiscoveryCache>>> = OnceLock::new();

#[derive(Debug, Clone, Serialize)]
pub struct MorphoToken {
    pub address: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MorphoOracleStatus {
    Available,
    Stale,
    Unavailable,
    ZeroPrice,
    NotConfigured,
    NotRead,
}

#[derive(Debug, Clone, Serialize)]
pub struct MorphoMarketResponse {
    pub chain: String,
    pub morpho_address: String,
    pub market_id: String,
    pub loan_token: MorphoToken,
    pub collateral_token: MorphoToken,
    pub oracle_address: String,
    pub irm_address: String,
    pub lltv_raw: String,
    pub lltv_percent: String,
    pub oracle_price_raw: Option<String>,
    pub oracle_status: MorphoOracleStatus,
    pub total_supply_assets_raw: String,
    pub total_supply_assets_formatted: String,
    pub total_borrow_assets_raw: String,
    pub total_borrow_assets_formatted: String,
    pub liquidity_assets_raw: String,
    pub liquidity_assets_formatted: String,
    pub utilization_percent: String,
    pub accrual_borrow_rate_per_second_raw: String,
    pub accrual_borrow_apr_percent: String,
    pub fee_raw: String,
    pub fee_percent: String,
    pub last_update: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MorphoMarketsResponse {
    pub chain: String,
    pub loan_token_filter: Option<String>,
    pub collateral_token_filter: Option<String>,
    pub require_available_oracle: bool,
    pub recommended_market_id: Option<String>,
    pub ranking: String,
    pub markets: Vec<MorphoMarketResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MorphoPositionResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub morpho_address: String,
    pub market_id: String,
    pub loan_token: MorphoToken,
    pub collateral_token: MorphoToken,
    pub wallet_loan_balance_raw: String,
    pub wallet_loan_balance_formatted: String,
    pub wallet_collateral_balance_raw: String,
    pub wallet_collateral_balance_formatted: String,
    pub supply_shares_raw: String,
    pub supplied_assets_raw: String,
    pub supplied_assets_formatted: String,
    pub borrow_shares_raw: String,
    pub borrowed_assets_raw: String,
    pub borrowed_assets_formatted: String,
    pub collateral_assets_raw: String,
    pub collateral_assets_formatted: String,
    pub collateral_value_in_loan_assets_raw: Option<String>,
    pub collateral_value_in_loan_assets_formatted: Option<String>,
    pub borrow_capacity_raw: Option<String>,
    pub borrow_capacity_formatted: Option<String>,
    pub available_borrow_raw: Option<String>,
    pub available_borrow_formatted: Option<String>,
    pub health_factor: Option<String>,
    pub ltv_percent: Option<String>,
    pub lltv_percent: String,
    pub is_healthy: Option<bool>,
    pub oracle_status: MorphoOracleStatus,
}

#[derive(Debug, Clone)]
struct MarketContext {
    market_id: H256,
    params: MorphoMarketParams,
    state: MorphoMarketState,
    loan_symbol: String,
    loan_decimals: u8,
    collateral_symbol: String,
    collateral_decimals: u8,
    oracle_price: Option<U256>,
    oracle_status: MorphoOracleStatus,
    borrow_rate: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataScope {
    Both,
    Loan,
    Collateral,
}

macro_rules! action_handlers {
    ($execute_fn:ident, $simulate_fn:ident, $action:expr) => {
        #[allow(clippy::too_many_arguments)]
        pub async fn $execute_fn(
            engine: &ExecutionEngine,
            pool: &PgPool,
            redis_conn: &mut ConnectionManager,
            wallet_registry: &AgentWalletRegistry,
            organization_id: Uuid,
            req: &MorphoActionRequest,
        ) -> Result<ExecutionResponse> {
            let (execution_req, _) =
                prepare_action(engine, wallet_registry, organization_id, req, $action).await?;
            handle_execute(
                engine,
                pool,
                redis_conn,
                wallet_registry,
                organization_id,
                &execution_req,
            )
            .await
            .map_err(|error| anyhow!("Morpho {} failed: {}", $action.slug(), error))
        }

        #[allow(clippy::too_many_arguments)]
        pub async fn $simulate_fn(
            engine: &ExecutionEngine,
            pool: &PgPool,
            wallet_registry: &AgentWalletRegistry,
            organization_id: Uuid,
            req: &MorphoActionRequest,
        ) -> Result<ExecutionResponse> {
            let (execution_req, _) =
                prepare_action(engine, wallet_registry, organization_id, req, $action).await?;
            handle_simulate(
                engine,
                pool,
                wallet_registry,
                organization_id,
                &execution_req,
            )
            .await
        }
    };
}

action_handlers!(handle_supply, handle_supply_simulate, MorphoAction::Supply);
action_handlers!(
    handle_withdraw,
    handle_withdraw_simulate,
    MorphoAction::Withdraw
);
action_handlers!(
    handle_supply_collateral,
    handle_supply_collateral_simulate,
    MorphoAction::SupplyCollateral
);
action_handlers!(
    handle_withdraw_collateral,
    handle_withdraw_collateral_simulate,
    MorphoAction::WithdrawCollateral
);
action_handlers!(handle_borrow, handle_borrow_simulate, MorphoAction::Borrow);
action_handlers!(handle_repay, handle_repay_simulate, MorphoAction::Repay);

pub async fn handle_market(
    engine: &ExecutionEngine,
    query: &MorphoMarketQuery,
) -> Result<MorphoMarketResponse> {
    morpho::validate_market_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let context = load_market_context(
        engine,
        &chain,
        &query.market_id,
        true,
        false,
        MetadataScope::Both,
    )
    .await?;
    build_market_response(&query.chain, context)
}

pub async fn handle_markets(
    engine: &ExecutionEngine,
    query: &MorphoMarketsQuery,
) -> Result<MorphoMarketsResponse> {
    morpho::validate_markets_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let loan_filter = query
        .loan_token
        .as_deref()
        .map(|value| value.trim().parse::<Address>())
        .transpose()?;
    let collateral_filter = query
        .collateral_token
        .as_deref()
        .map(|value| value.trim().parse::<Address>())
        .transpose()?;
    let max_lltv = query
        .max_lltv_raw
        .as_deref()
        .map(|value| U256::from_dec_str(value.trim()))
        .transpose()?;
    let min_liquidity = query
        .min_liquidity_raw
        .as_deref()
        .map(|value| U256::from_dec_str(value.trim()))
        .transpose()?
        .unwrap_or_default();

    let discovered = discover_markets().await?;
    let mut ranked = Vec::new();
    for (market_id, params) in discovered {
        if loan_filter.is_some_and(|token| token != params.loan_token)
            || collateral_filter.is_some_and(|token| token != params.collateral_token)
            || max_lltv.is_some_and(|limit| params.lltv > limit)
        {
            continue;
        }
        let Ok(context) = load_market_context(
            engine,
            &chain,
            &format!("{market_id:?}"),
            true,
            false,
            MetadataScope::Both,
        )
        .await
        else {
            continue;
        };
        let liquidity = context
            .state
            .total_supply_assets
            .saturating_sub(context.state.total_borrow_assets);
        if liquidity < min_liquidity
            || (query.require_available_oracle
                && context.oracle_status != MorphoOracleStatus::Available)
        {
            continue;
        }
        let borrow_rate = context.borrow_rate;
        let lltv = context.params.lltv;
        let response = build_market_response(&query.chain, context)?;
        ranked.push((response, liquidity, lltv, borrow_rate));
    }
    ranked.sort_by(
        |(left, left_liquidity, left_lltv, left_rate),
         (right, right_liquidity, right_lltv, right_rate)| {
            right_liquidity
                .cmp(left_liquidity)
                .then_with(|| left_lltv.cmp(right_lltv))
                .then_with(|| left_rate.cmp(right_rate))
                .then_with(|| left.market_id.cmp(&right.market_id))
        },
    );
    ranked.truncate(query.limit);
    let markets = ranked
        .into_iter()
        .map(|(market, _, _, _)| market)
        .collect::<Vec<_>>();
    Ok(MorphoMarketsResponse {
        chain: query.chain.clone(),
        loan_token_filter: query.loan_token.clone(),
        collateral_token_filter: query.collateral_token.clone(),
        require_available_oracle: query.require_available_oracle,
        recommended_market_id: markets.first().map(|market| market.market_id.clone()),
        ranking: "available liquidity descending, LLTV ascending, borrow APR ascending".to_string(),
        markets,
    })
}

fn build_market_response(chain: &str, context: MarketContext) -> Result<MorphoMarketResponse> {
    let liquidity = context
        .state
        .total_supply_assets
        .saturating_sub(context.state.total_borrow_assets);
    Ok(MorphoMarketResponse {
        chain: chain.to_string(),
        morpho_address: format!("{:?}", morpho::morpho_address()),
        market_id: format!("{:?}", context.market_id),
        loan_token: token_response(
            context.params.loan_token,
            &context.loan_symbol,
            context.loan_decimals,
        ),
        collateral_token: token_response(
            context.params.collateral_token,
            &context.collateral_symbol,
            context.collateral_decimals,
        ),
        oracle_address: format!("{:?}", context.params.oracle),
        irm_address: format!("{:?}", context.params.irm),
        lltv_raw: context.params.lltv.to_string(),
        lltv_percent: format_percent(context.params.lltv, U256::from(WAD), 2),
        oracle_price_raw: context.oracle_price.map(|price| price.to_string()),
        oracle_status: context.oracle_status,
        total_supply_assets_raw: context.state.total_supply_assets.to_string(),
        total_supply_assets_formatted: format_token_units(
            context.state.total_supply_assets,
            context.loan_decimals,
        )?,
        total_borrow_assets_raw: context.state.total_borrow_assets.to_string(),
        total_borrow_assets_formatted: format_token_units(
            context.state.total_borrow_assets,
            context.loan_decimals,
        )?,
        liquidity_assets_raw: liquidity.to_string(),
        liquidity_assets_formatted: format_token_units(liquidity, context.loan_decimals)?,
        utilization_percent: ratio_percent(
            context.state.total_borrow_assets,
            context.state.total_supply_assets,
            2,
        ),
        accrual_borrow_rate_per_second_raw: context.borrow_rate.to_string(),
        accrual_borrow_apr_percent: format_apr_percent(context.borrow_rate, 2),
        fee_raw: context.state.fee.to_string(),
        fee_percent: format_percent(context.state.fee, U256::from(WAD), 2),
        last_update: context.state.last_update.to_string(),
    })
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

async fn discover_markets() -> Result<Vec<(H256, MorphoMarketParams)>> {
    let cache = MARKET_DISCOVERY_CACHE.get_or_init(|| RwLock::new(None));
    if let Some(entry) = cache.read().await.as_ref() {
        if entry.fetched_at.elapsed() < MARKET_CACHE_TTL {
            return Ok(entry.markets.clone());
        }
    }

    match fetch_markets_from_blockscout().await {
        Ok(markets) => {
            *cache.write().await = Some(MarketDiscoveryCache {
                fetched_at: Instant::now(),
                markets: markets.clone(),
            });
            Ok(markets)
        }
        Err(error) => {
            if let Some(entry) = cache.read().await.as_ref() {
                return Ok(entry.markets.clone());
            }
            Err(error)
        }
    }
}

async fn fetch_markets_from_blockscout() -> Result<Vec<(H256, MorphoMarketParams)>> {
    const PAGE_SIZE: usize = 1_000;
    const MAX_PAGES: usize = 100;
    let client = reqwest::Client::new();
    let mut markets = HashMap::new();
    let mut from_block = 0u64;
    for page in 1..=MAX_PAGES {
        let response = client
            .get(BLOCKSCOUT_LOGS_URL)
            .query(&[
                ("module", "logs".to_string()),
                ("action", "getLogs".to_string()),
                ("address", morpho::MORPHO_ADDRESS.to_string()),
                ("topic0", CREATE_MARKET_TOPIC.to_string()),
                ("fromBlock", from_block.to_string()),
                ("toBlock", "latest".to_string()),
            ])
            .send()
            .await
            .context("Morpho market discovery request failed")?;
        if !response.status().is_success() {
            bail!(
                "Morpho market discovery returned HTTP {}",
                response.status()
            );
        }
        let body: BlockscoutLogsResponse = response
            .json()
            .await
            .context("Morpho market discovery response was invalid")?;
        if body.status != "1" {
            if page > 1 && body.result.is_empty() {
                break;
            }
            bail!("Morpho market discovery failed: {}", body.message);
        }
        let result_count = body.result.len();
        let mut highest_block = from_block;
        for log in body.result {
            highest_block = highest_block.max(
                u64::from_str_radix(log.block_number.trim_start_matches("0x"), 16)
                    .context("Morpho discovery returned an invalid block number")?,
            );
            let topic = log
                .topics
                .get(1)
                .and_then(Option::as_deref)
                .ok_or_else(|| anyhow!("Morpho CreateMarket log omitted market ID"))?;
            let market_id = topic.parse::<H256>()?;
            let data = hex::decode(log.data.trim_start_matches("0x"))?;
            let params = morpho::decode_market_params(&data)?;
            if morpho::derive_market_id(&params) != market_id {
                bail!("Morpho CreateMarket event market ID did not match its parameters");
            }
            markets.insert(market_id, params);
        }
        if result_count < PAGE_SIZE {
            break;
        }
        if highest_block <= from_block {
            bail!("Morpho market discovery block pagination made no progress");
        }
        from_block = highest_block;
        if page == MAX_PAGES {
            bail!("Morpho market discovery exceeded {MAX_PAGES} pages");
        }
    }
    let mut markets = markets.into_iter().collect::<Vec<_>>();
    markets.sort_by_key(|(id, _)| *id);
    Ok(markets)
}

pub async fn handle_position(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &MorphoPositionQuery,
) -> Result<MorphoPositionResponse> {
    morpho::validate_position_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let wallet = resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let context = load_market_context(
        engine,
        &chain,
        &query.market_id,
        true,
        false,
        MetadataScope::Both,
    )
    .await?;
    let (position, wallet_loan) = tokio::try_join!(
        load_position(engine, &chain, context.market_id, wallet),
        token_balance(engine, &chain, context.params.loan_token, wallet),
    )?;
    let wallet_collateral = if context.params.collateral_token == Address::zero() {
        U256::zero()
    } else {
        token_balance(engine, &chain, context.params.collateral_token, wallet).await?
    };

    build_position_response(
        query,
        wallet,
        context,
        position,
        wallet_loan,
        wallet_collateral,
    )
}

async fn prepare_action(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &MorphoActionRequest,
    action: MorphoAction,
) -> Result<(crate::types::ExecutionRequest, Address)> {
    morpho::validate_action_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let wallet = resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let metadata_scope = match action {
        MorphoAction::Supply
        | MorphoAction::Withdraw
        | MorphoAction::Borrow
        | MorphoAction::Repay => MetadataScope::Loan,
        MorphoAction::SupplyCollateral | MorphoAction::WithdrawCollateral => {
            MetadataScope::Collateral
        }
    };
    let mut context =
        load_market_context(engine, &chain, &req.market_id, false, false, metadata_scope).await?;
    if matches!(
        action,
        MorphoAction::SupplyCollateral
            | MorphoAction::WithdrawCollateral
            | MorphoAction::Borrow
            | MorphoAction::Repay
    ) && (context.params.collateral_token == Address::zero()
        || context.params.oracle == Address::zero()
        || context.params.lltv.is_zero())
    {
        bail!(
            "selected Morpho market has no collateral borrowing configuration; only supply and withdraw are available"
        );
    }
    let position = load_position(engine, &chain, context.market_id, wallet).await?;
    if action == MorphoAction::Borrow
        || (action == MorphoAction::WithdrawCollateral && !position.borrow_shares.is_zero())
    {
        context =
            load_market_context(engine, &chain, &req.market_id, true, true, metadata_scope).await?;
    }
    let amount =
        resolve_action_amount(engine, &chain, req, action, &context, &position, wallet).await?;
    enforce_health_guard(req, action, &context, &position, amount)?;
    let execution = morpho::compile_action(req, action, &context.params, wallet, amount)?;
    Ok((execution, wallet))
}

async fn resolve_action_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &MorphoActionRequest,
    action: MorphoAction,
    context: &MarketContext,
    position: &MorphoPosition,
    wallet: Address,
) -> Result<ResolvedAmount> {
    if !morpho::is_amount_max(req) {
        let decimals = match action {
            MorphoAction::SupplyCollateral | MorphoAction::WithdrawCollateral => {
                context.collateral_decimals
            }
            _ => context.loan_decimals,
        };
        return Ok(ResolvedAmount::Assets(morpho::parse_request_amount(
            req, decimals,
        )?));
    }

    let resolved = match action {
        MorphoAction::Supply => ResolvedAmount::Assets(
            token_balance(engine, chain, context.params.loan_token, wallet).await?,
        ),
        MorphoAction::SupplyCollateral => ResolvedAmount::Assets(
            token_balance(engine, chain, context.params.collateral_token, wallet).await?,
        ),
        MorphoAction::Withdraw => ResolvedAmount::Shares(position.supply_shares),
        MorphoAction::Repay => ResolvedAmount::Shares(position.borrow_shares),
        MorphoAction::WithdrawCollateral => {
            if !position.borrow_shares.is_zero() {
                bail!(
                    "amount=max for withdraw-collateral requires zero debt; repay first or provide an explicit safe amount"
                );
            }
            ResolvedAmount::Assets(position.collateral)
        }
        MorphoAction::Borrow => {
            bail!(
                "amount=max is not supported for borrow; use the position endpoint's available_borrow value with a safety margin"
            )
        }
    };

    match resolved {
        ResolvedAmount::Assets(value) | ResolvedAmount::Shares(value) if value.is_zero() => {
            bail!("amount=max resolved to zero")
        }
        _ => Ok(resolved),
    }
}

async fn load_market_context(
    engine: &ExecutionEngine,
    chain: &Chain,
    market_id_raw: &str,
    with_analytics: bool,
    require_oracle: bool,
    metadata_scope: MetadataScope,
) -> Result<MarketContext> {
    let market_id = morpho::parse_market_id(market_id_raw)?;
    let morpho_address = morpho::morpho_address();
    let (params_raw, state_raw) = tokio::try_join!(
        call_raw(
            engine,
            chain,
            morpho_address,
            morpho::encode_id_to_market_params(market_id)
        ),
        call_raw(
            engine,
            chain,
            morpho_address,
            morpho::encode_market(market_id)
        ),
    )?;
    let params = morpho::decode_market_params(&params_raw)?;
    let mut state = morpho::decode_market_state(&state_raw)?;

    let (loan_symbol, loan_decimals) = if metadata_scope == MetadataScope::Collateral {
        ("UNKNOWN".to_string(), 0)
    } else {
        tokio::try_join!(
            token_symbol(engine, chain, params.loan_token),
            token_decimals(engine, chain, params.loan_token),
        )?
    };
    let (collateral_symbol, collateral_decimals) = if metadata_scope == MetadataScope::Loan {
        ("UNKNOWN".to_string(), 0)
    } else if params.collateral_token == Address::zero() {
        ("NONE".to_string(), 0)
    } else {
        tokio::try_join!(
            token_symbol(engine, chain, params.collateral_token),
            token_decimals(engine, chain, params.collateral_token),
        )?
    };
    let (oracle_price, oracle_status) = if !with_analytics {
        (None, MorphoOracleStatus::NotRead)
    } else if params.oracle == Address::zero() {
        (None, MorphoOracleStatus::NotConfigured)
    } else {
        match call_u256(engine, chain, params.oracle, morpho::encode_oracle_price()).await {
            Ok(price) if !price.is_zero() => (Some(price), MorphoOracleStatus::Available),
            Ok(_) if require_oracle => bail!("Morpho market oracle returned a zero price"),
            Ok(_) => (None, MorphoOracleStatus::ZeroPrice),
            Err(error) if require_oracle => return Err(describe_oracle_error(error)),
            Err(error) => {
                let status = if is_stale_oracle_error(&error) {
                    MorphoOracleStatus::Stale
                } else {
                    MorphoOracleStatus::Unavailable
                };
                (None, status)
            }
        }
    };

    let borrow_rate = if !with_analytics || params.irm == Address::zero() {
        U256::zero()
    } else {
        call_u256(
            engine,
            chain,
            params.irm,
            morpho::encode_borrow_rate_view(&params, &state),
        )
        .await
        .context("failed to read Morpho market borrow rate")?
    };
    accrue_market_state(engine, chain, &mut state, borrow_rate).await?;

    Ok(MarketContext {
        market_id,
        params,
        state,
        loan_symbol,
        loan_decimals,
        collateral_symbol,
        collateral_decimals,
        oracle_price,
        oracle_status,
        borrow_rate,
    })
}

async fn accrue_market_state(
    engine: &ExecutionEngine,
    chain: &Chain,
    state: &mut MorphoMarketState,
    borrow_rate: U256,
) -> Result<()> {
    if borrow_rate.is_zero() {
        return Ok(());
    }
    let provider = engine.provider_for_chain(chain)?;
    let block = provider
        .get_block(ethers::types::BlockNumber::Latest)
        .await?
        .ok_or_else(|| anyhow!("latest block was unavailable"))?;
    accrue_market_state_at(state, borrow_rate, block.timestamp)
}

fn accrue_market_state_at(
    state: &mut MorphoMarketState,
    borrow_rate: U256,
    timestamp: U256,
) -> Result<()> {
    if timestamp <= state.last_update {
        return Ok(());
    }
    let elapsed = timestamp - state.last_update;
    let compounded = taylor_compounded(borrow_rate, elapsed)?;
    let interest = mul_div_down(state.total_borrow_assets, compounded, U256::from(WAD))?;
    state.total_borrow_assets = checked_add(state.total_borrow_assets, interest)?;
    state.total_supply_assets = checked_add(state.total_supply_assets, interest)?;

    if !state.fee.is_zero() && !interest.is_zero() {
        let fee_amount = mul_div_down(interest, state.fee, U256::from(WAD))?;
        let denominator_assets = state.total_supply_assets.saturating_sub(fee_amount);
        let fee_shares = to_shares_down(fee_amount, denominator_assets, state.total_supply_shares)?;
        state.total_supply_shares = checked_add(state.total_supply_shares, fee_shares)?;
    }
    Ok(())
}

fn build_position_response(
    query: &MorphoPositionQuery,
    wallet: Address,
    context: MarketContext,
    position: MorphoPosition,
    wallet_loan: U256,
    wallet_collateral: U256,
) -> Result<MorphoPositionResponse> {
    let supplied = to_assets_down(
        position.supply_shares,
        context.state.total_supply_assets,
        context.state.total_supply_shares,
    )?;
    let borrowed = to_assets_up(
        position.borrow_shares,
        context.state.total_borrow_assets,
        context.state.total_borrow_shares,
    )?;
    let market_liquidity = context
        .state
        .total_supply_assets
        .saturating_sub(context.state.total_borrow_assets);
    let risk = context
        .oracle_price
        .map(|oracle_price| {
            let collateral_value = mul_div_down(
                position.collateral,
                oracle_price,
                U256::exp10(ORACLE_PRICE_SCALE_EXPONENT),
            )?;
            let borrow_capacity =
                mul_div_down(collateral_value, context.params.lltv, U256::from(WAD))?;
            let available_capacity = borrow_capacity.saturating_sub(borrowed);
            let available_borrow = min_u256(available_capacity, market_liquidity);
            let health_factor = if borrowed.is_zero() {
                None
            } else {
                Some(format_ratio(borrow_capacity, borrowed, 4))
            };
            let ltv = if collateral_value.is_zero() {
                None
            } else {
                Some(ratio_percent(borrowed, collateral_value, 2))
            };
            Ok::<_, anyhow::Error>((
                collateral_value,
                borrow_capacity,
                available_borrow,
                health_factor,
                ltv,
                borrowed.is_zero() || borrowed <= borrow_capacity,
            ))
        })
        .transpose()?;
    let (collateral_value, borrow_capacity, available_borrow, health_factor, ltv, is_healthy) =
        match risk {
            Some((value, capacity, available, health, ltv, healthy)) => (
                Some(value),
                Some(capacity),
                Some(available),
                health,
                ltv,
                Some(healthy),
            ),
            None => (
                None,
                None,
                None,
                None,
                None,
                borrowed.is_zero().then_some(true),
            ),
        };

    Ok(MorphoPositionResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{wallet:?}"),
        morpho_address: format!("{:?}", morpho::morpho_address()),
        market_id: format!("{:?}", context.market_id),
        loan_token: token_response(
            context.params.loan_token,
            &context.loan_symbol,
            context.loan_decimals,
        ),
        collateral_token: token_response(
            context.params.collateral_token,
            &context.collateral_symbol,
            context.collateral_decimals,
        ),
        wallet_loan_balance_raw: wallet_loan.to_string(),
        wallet_loan_balance_formatted: format_token_units(wallet_loan, context.loan_decimals)?,
        wallet_collateral_balance_raw: wallet_collateral.to_string(),
        wallet_collateral_balance_formatted: format_token_units(
            wallet_collateral,
            context.collateral_decimals,
        )?,
        supply_shares_raw: position.supply_shares.to_string(),
        supplied_assets_raw: supplied.to_string(),
        supplied_assets_formatted: format_token_units(supplied, context.loan_decimals)?,
        borrow_shares_raw: position.borrow_shares.to_string(),
        borrowed_assets_raw: borrowed.to_string(),
        borrowed_assets_formatted: format_token_units(borrowed, context.loan_decimals)?,
        collateral_assets_raw: position.collateral.to_string(),
        collateral_assets_formatted: format_token_units(
            position.collateral,
            context.collateral_decimals,
        )?,
        collateral_value_in_loan_assets_raw: collateral_value.map(|value| value.to_string()),
        collateral_value_in_loan_assets_formatted: collateral_value
            .map(|value| format_token_units(value, context.loan_decimals))
            .transpose()?,
        borrow_capacity_raw: borrow_capacity.map(|value| value.to_string()),
        borrow_capacity_formatted: borrow_capacity
            .map(|value| format_token_units(value, context.loan_decimals))
            .transpose()?,
        available_borrow_raw: available_borrow.map(|value| value.to_string()),
        available_borrow_formatted: available_borrow
            .map(|value| format_token_units(value, context.loan_decimals))
            .transpose()?,
        health_factor,
        ltv_percent: ltv,
        lltv_percent: format_percent(context.params.lltv, U256::from(WAD), 2),
        is_healthy,
        oracle_status: context.oracle_status,
    })
}

async fn load_position(
    engine: &ExecutionEngine,
    chain: &Chain,
    market_id: H256,
    wallet: Address,
) -> Result<MorphoPosition> {
    let raw = call_raw(
        engine,
        chain,
        morpho::morpho_address(),
        morpho::encode_position(market_id, wallet),
    )
    .await?;
    morpho::decode_position(&raw)
}

async fn token_balance(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
    wallet: Address,
) -> Result<U256> {
    call_u256(engine, chain, token, morpho::encode_balance_of(wallet)).await
}

async fn token_decimals(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<u8> {
    let raw = call_raw(engine, chain, token, morpho::encode_decimals()).await?;
    let decimals = morpho::decode_u8(&raw)?;
    if decimals > MAX_SAFE_TOKEN_DECIMALS {
        bail!(
            "token {token:?} reports unsupported decimals {decimals}; maximum supported is {MAX_SAFE_TOKEN_DECIMALS}"
        );
    }
    Ok(decimals)
}

async fn token_symbol(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<String> {
    match call_raw(engine, chain, token, morpho::encode_symbol()).await {
        Ok(raw) => morpho::decode_string(&raw).or_else(|_| Ok("UNKNOWN".to_string())),
        Err(_) => Ok("UNKNOWN".to_string()),
    }
}

async fn call_u256(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> Result<U256> {
    let raw = call_raw(engine, chain, to, calldata).await?;
    morpho::decode_u256(&raw)
}

async fn call_raw(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> Result<Vec<u8>> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes = hex::decode(calldata.trim_start_matches("0x"))
        .context("generated calldata was invalid hex")?
        .into();
    let tx = TransactionRequest::new().to(to).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    Ok(raw.0.to_vec())
}

fn parse_chain(chain: &str) -> Result<Chain> {
    let parsed =
        Chain::from_str_loose(chain).ok_or_else(|| anyhow!("unsupported chain: {chain}"))?;
    if parsed != Chain::Base {
        bail!("Morpho Blue integration currently supports Base Sepolia only");
    }
    Ok(parsed)
}

fn token_response(address: Address, symbol: &str, decimals: u8) -> MorphoToken {
    MorphoToken {
        address: format!("{address:?}"),
        symbol: symbol.to_string(),
        decimals,
    }
}

fn to_assets_down(shares: U256, total_assets: U256, total_shares: U256) -> Result<U256> {
    mul_div_down(
        shares,
        checked_add(total_assets, U256::from(VIRTUAL_ASSETS))?,
        checked_add(total_shares, U256::from(VIRTUAL_SHARES))?,
    )
}

fn to_assets_up(shares: U256, total_assets: U256, total_shares: U256) -> Result<U256> {
    mul_div_up(
        shares,
        checked_add(total_assets, U256::from(VIRTUAL_ASSETS))?,
        checked_add(total_shares, U256::from(VIRTUAL_SHARES))?,
    )
}

fn to_shares_up(assets: U256, total_assets: U256, total_shares: U256) -> Result<U256> {
    mul_div_up(
        assets,
        checked_add(total_shares, U256::from(VIRTUAL_SHARES))?,
        checked_add(total_assets, U256::from(VIRTUAL_ASSETS))?,
    )
}

fn to_shares_down(assets: U256, total_assets: U256, total_shares: U256) -> Result<U256> {
    mul_div_down(
        assets,
        checked_add(total_shares, U256::from(VIRTUAL_SHARES))?,
        checked_add(total_assets, U256::from(VIRTUAL_ASSETS))?,
    )
}

fn taylor_compounded(rate: U256, elapsed: U256) -> Result<U256> {
    let first = checked_mul(rate, elapsed)?;
    let second = mul_div_down(first, first, U256::from(2u64) * U256::from(WAD))?;
    let third = mul_div_down(second, first, U256::from(3u64) * U256::from(WAD))?;
    checked_add(checked_add(first, second)?, third)
}

fn mul_div_down(x: U256, y: U256, denominator: U256) -> Result<U256> {
    if denominator.is_zero() {
        bail!("division by zero");
    }
    u512_to_u256(U512::from(x) * U512::from(y) / U512::from(denominator))
}

fn mul_div_up(x: U256, y: U256, denominator: U256) -> Result<U256> {
    if denominator.is_zero() {
        bail!("division by zero");
    }
    if x.is_zero() || y.is_zero() {
        return Ok(U256::zero());
    }
    let numerator = U512::from(x) * U512::from(y);
    u512_to_u256((numerator + U512::from(denominator) - U512::one()) / U512::from(denominator))
}

fn checked_add(a: U256, b: U256) -> Result<U256> {
    let (value, overflow) = a.overflowing_add(b);
    if overflow {
        bail!("uint256 addition overflow");
    }
    Ok(value)
}

fn checked_mul(a: U256, b: U256) -> Result<U256> {
    let value = U512::from(a) * U512::from(b);
    u512_to_u256(value)
}

fn u512_to_u256(value: U512) -> Result<U256> {
    if value > U512::from(U256::MAX) {
        bail!("calculation exceeds uint256");
    }
    let mut bytes = [0u8; 64];
    value.to_big_endian(&mut bytes);
    Ok(U256::from_big_endian(&bytes[32..]))
}

fn min_u256(a: U256, b: U256) -> U256 {
    if a < b {
        a
    } else {
        b
    }
}

fn is_stale_oracle_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .to_string()
            .to_ascii_lowercase()
            .contains(PYTH_STALE_PRICE_SELECTOR)
    })
}

fn describe_oracle_error(error: anyhow::Error) -> anyhow::Error {
    if is_stale_oracle_error(&error) {
        anyhow!("Morpho market oracle price is stale (StalePrice, {PYTH_STALE_PRICE_SELECTOR})")
    } else {
        anyhow!("failed to read Morpho market oracle price: {error}")
    }
}

fn enforce_health_guard(
    req: &MorphoActionRequest,
    action: MorphoAction,
    context: &MarketContext,
    position: &MorphoPosition,
    amount: ResolvedAmount,
) -> Result<()> {
    let guarded = matches!(
        action,
        MorphoAction::Borrow | MorphoAction::WithdrawCollateral
    );
    if !guarded {
        if req.min_health_factor.is_some() {
            bail!("min_health_factor is supported only for borrow and withdraw-collateral actions");
        }
        return Ok(());
    }

    let minimum = parse_min_health_factor(req.min_health_factor.as_deref())?;
    let assets = match amount {
        ResolvedAmount::Assets(value) => value,
        ResolvedAmount::Shares(_) => {
            bail!("health-guarded Morpho actions require an asset amount")
        }
    };

    let (projected_collateral, projected_debt) = match action {
        MorphoAction::Borrow => {
            let liquidity = context
                .state
                .total_supply_assets
                .saturating_sub(context.state.total_borrow_assets);
            if assets > liquidity {
                bail!(
                    "borrow amount exceeds current Morpho market liquidity: requested {assets}, available {liquidity}"
                );
            }
            let new_shares = to_shares_up(
                assets,
                context.state.total_borrow_assets,
                context.state.total_borrow_shares,
            )?;
            let projected_total_assets = checked_add(context.state.total_borrow_assets, assets)?;
            let projected_total_shares =
                checked_add(context.state.total_borrow_shares, new_shares)?;
            let projected_position_shares = checked_add(position.borrow_shares, new_shares)?;
            (
                position.collateral,
                to_assets_up(
                    projected_position_shares,
                    projected_total_assets,
                    projected_total_shares,
                )?,
            )
        }
        MorphoAction::WithdrawCollateral => {
            if assets > position.collateral {
                bail!(
                    "withdraw collateral amount exceeds supplied collateral: requested {}, supplied {}",
                    assets,
                    position.collateral
                );
            }
            (
                position.collateral - assets,
                to_assets_up(
                    position.borrow_shares,
                    context.state.total_borrow_assets,
                    context.state.total_borrow_shares,
                )?,
            )
        }
        _ => unreachable!("guarded action checked above"),
    };

    if projected_debt.is_zero() {
        return Ok(());
    }
    let oracle_price = context
        .oracle_price
        .ok_or_else(|| anyhow!("Morpho health-factor guard requires a responsive market oracle"))?;
    let collateral_value = mul_div_down(
        projected_collateral,
        oracle_price,
        U256::exp10(ORACLE_PRICE_SCALE_EXPONENT),
    )?;
    let projected_capacity = mul_div_down(collateral_value, context.params.lltv, U256::from(WAD))?;
    let left = U512::from(projected_capacity) * U512::from(WAD);
    let right = U512::from(projected_debt) * U512::from(minimum);
    if left < right {
        bail!(
            "projected Morpho health factor {} is below required minimum {}",
            format_ratio(projected_capacity, projected_debt, 4),
            format_scaled_decimal(minimum, U256::from(WAD), 4)
        );
    }
    Ok(())
}

fn parse_min_health_factor(raw: Option<&str>) -> Result<U256> {
    let value = match raw {
        Some(raw) => parse_units(raw.trim(), 18)
            .context("min_health_factor must be a non-negative decimal number")?
            .into(),
        None => U256::from(DEFAULT_MIN_HEALTH_FACTOR_WAD),
    };
    if value < U256::from(WAD) {
        bail!("min_health_factor must be at least 1.0");
    }
    Ok(value)
}

fn format_token_units(value: U256, decimals: u8) -> Result<String> {
    format_units(value, decimals as usize).map_err(Into::into)
}

fn format_apr_percent(rate_per_second: U256, decimals: usize) -> String {
    let annual = rate_per_second
        .saturating_mul(U256::from(SECONDS_PER_YEAR))
        .saturating_mul(U256::from(100u64));
    format_scaled_decimal(annual, U256::from(WAD), decimals)
}

fn format_percent(value: U256, scale: U256, decimals: usize) -> String {
    format_scaled_decimal(value.saturating_mul(U256::from(100u64)), scale, decimals)
}

fn ratio_percent(numerator: U256, denominator: U256, decimals: usize) -> String {
    if denominator.is_zero() {
        return "0".to_string();
    }
    let scale = U256::exp10(decimals + 2);
    let scaled = mul_div_down(numerator, scale, denominator).unwrap_or_default();
    format_scaled_integer(scaled, decimals)
}

fn format_ratio(numerator: U256, denominator: U256, decimals: usize) -> String {
    if denominator.is_zero() {
        return "0".to_string();
    }
    let scale = U256::exp10(decimals);
    let scaled = mul_div_down(numerator, scale, denominator).unwrap_or_default();
    format_scaled_integer(scaled, decimals)
}

fn format_scaled_decimal(value: U256, scale: U256, decimals: usize) -> String {
    if scale.is_zero() {
        return "0".to_string();
    }
    let display_scale = U256::exp10(decimals);
    let scaled = mul_div_down(value, display_scale, scale).unwrap_or_default();
    format_scaled_integer(scaled, decimals)
}

fn format_scaled_integer(value: U256, decimals: usize) -> String {
    if decimals == 0 {
        return value.to_string();
    }
    let scale = U256::exp10(decimals);
    let whole = value / scale;
    let fraction = value % scale;
    format!(
        "{whole}.{:0>width$}",
        fraction.to_string(),
        width = decimals
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn health_context() -> MarketContext {
        MarketContext {
            market_id: H256::zero(),
            params: MorphoMarketParams {
                loan_token: Address::from_low_u64_be(1),
                collateral_token: Address::from_low_u64_be(2),
                oracle: Address::from_low_u64_be(3),
                irm: Address::from_low_u64_be(4),
                lltv: U256::from_dec_str("860000000000000000").unwrap(),
            },
            state: MorphoMarketState {
                total_supply_assets: U256::from(2_000_000_000u64),
                total_supply_shares: U256::from(2_000_000_000u64),
                total_borrow_assets: U256::zero(),
                total_borrow_shares: U256::zero(),
                last_update: U256::one(),
                fee: U256::zero(),
            },
            loan_symbol: "USDC".to_string(),
            loan_decimals: 6,
            collateral_symbol: "WETH".to_string(),
            collateral_decimals: 18,
            oracle_price: Some(U256::from(2_000u64) * U256::exp10(24)),
            oracle_status: MorphoOracleStatus::Available,
            borrow_rate: U256::zero(),
        }
    }

    fn action_request(min_health_factor: Option<&str>) -> MorphoActionRequest {
        MorphoActionRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            market_id: morpho::DEFAULT_MARKET_ID.to_string(),
            amount: Some("1".to_string()),
            amount_raw: None,
            min_health_factor: min_health_factor.map(str::to_string),
            strategy_id: None,
            callback_url: None,
        }
    }

    #[test]
    fn morpho_share_conversions_follow_virtual_offsets() {
        let assets = to_assets_down(U256::from(1_000_000u64), U256::zero(), U256::zero()).unwrap();
        assert_eq!(assets, U256::one());
        let rounded_up =
            to_assets_up(U256::from(1_000_001u64), U256::zero(), U256::zero()).unwrap();
        assert_eq!(rounded_up, U256::from(2u64));
    }

    #[test]
    fn borrow_capacity_uses_morpho_oracle_scale() {
        let collateral = U256::exp10(18);
        let price = U256::from(2_000u64) * U256::exp10(24); // 2,000 USDC units per WETH.
        let quoted =
            mul_div_down(collateral, price, U256::exp10(ORACLE_PRICE_SCALE_EXPONENT)).unwrap();
        assert_eq!(quoted, U256::from(2_000_000_000u64));
        let capacity = mul_div_down(
            quoted,
            U256::from_dec_str("860000000000000000").unwrap(),
            U256::from(WAD),
        )
        .unwrap();
        assert_eq!(capacity, U256::from(1_720_000_000u64));
    }

    #[test]
    fn taylor_compounding_matches_first_term_for_zero_rate() {
        assert_eq!(
            taylor_compounded(U256::zero(), U256::from(3600u64)).unwrap(),
            U256::zero()
        );
    }

    #[test]
    fn offchain_accrual_preserves_contract_last_update() {
        let mut state = MorphoMarketState {
            total_supply_assets: U256::from(2_000_000_000u64),
            total_supply_shares: U256::from(2_000_000_000u64),
            total_borrow_assets: U256::from(1_000_000_000u64),
            total_borrow_shares: U256::from(1_000_000_000u64),
            last_update: U256::from(100u64),
            fee: U256::zero(),
        };
        accrue_market_state_at(&mut state, U256::from(1_000_000_000u64), U256::from(200u64))
            .unwrap();

        assert!(state.total_borrow_assets > U256::from(1_000_000_000u64));
        assert_eq!(state.last_update, U256::from(100u64));
    }

    #[test]
    fn borrow_guard_enforces_default_health_margin() {
        let context = health_context();
        let position = MorphoPosition {
            supply_shares: U256::zero(),
            borrow_shares: U256::zero(),
            collateral: U256::exp10(18),
        };
        let req = action_request(None);

        assert!(enforce_health_guard(
            &req,
            MorphoAction::Borrow,
            &context,
            &position,
            ResolvedAmount::Assets(U256::from(1_600_000_000u64)),
        )
        .is_ok());
        assert!(enforce_health_guard(
            &req,
            MorphoAction::Borrow,
            &context,
            &position,
            ResolvedAmount::Assets(U256::from(1_700_000_000u64)),
        )
        .is_err());
    }

    #[test]
    fn collateral_withdraw_guard_enforces_default_health_margin() {
        let mut context = health_context();
        context.state.total_borrow_assets = U256::from(1_000_000_000u64);
        context.state.total_borrow_shares = U256::from(1_000_000_000u64);
        let position = MorphoPosition {
            supply_shares: U256::zero(),
            borrow_shares: U256::from(1_000_000_000u64),
            collateral: U256::exp10(18),
        };
        let req = action_request(None);

        assert!(enforce_health_guard(
            &req,
            MorphoAction::WithdrawCollateral,
            &context,
            &position,
            ResolvedAmount::Assets(U256::from(3u64) * U256::exp10(17)),
        )
        .is_ok());
        assert!(enforce_health_guard(
            &req,
            MorphoAction::WithdrawCollateral,
            &context,
            &position,
            ResolvedAmount::Assets(U256::from(4u64) * U256::exp10(17)),
        )
        .is_err());
    }

    #[test]
    fn health_factor_cannot_be_lower_than_one() {
        assert!(parse_min_health_factor(Some("0.99")).is_err());
        assert_eq!(
            parse_min_health_factor(None).unwrap(),
            U256::from(DEFAULT_MIN_HEALTH_FACTOR_WAD)
        );
    }

    #[test]
    fn stale_oracle_selector_gets_a_clear_error() {
        let error = anyhow!("execution reverted, data: 0x19abf40e");
        assert!(is_stale_oracle_error(&error));
        assert_eq!(
            describe_oracle_error(error).to_string(),
            "Morpho market oracle price is stale (StalePrice, 0x19abf40e)"
        );
    }

    #[test]
    fn position_read_remains_available_without_oracle_analytics() {
        let mut context = health_context();
        context.oracle_price = None;
        context.oracle_status = MorphoOracleStatus::Stale;
        let response = build_position_response(
            &MorphoPositionQuery {
                agent_id: "agent".to_string(),
                chain: "base".to_string(),
                market_id: morpho::DEFAULT_MARKET_ID.to_string(),
            },
            Address::from_low_u64_be(7),
            context,
            MorphoPosition {
                supply_shares: U256::from(1_000_000u64),
                borrow_shares: U256::zero(),
                collateral: U256::exp10(18),
            },
            U256::from(10_000_000u64),
            U256::exp10(18),
        )
        .unwrap();

        assert_eq!(response.oracle_status, MorphoOracleStatus::Stale);
        assert!(response.collateral_value_in_loan_assets_raw.is_none());
        assert!(response.available_borrow_raw.is_none());
        assert_eq!(response.is_healthy, Some(true));

        let json = serde_json::to_value(response).unwrap();
        assert_eq!(json["oracle_status"], "stale");
        assert!(json["borrow_capacity_raw"].is_null());
        assert!(json["available_borrow_raw"].is_null());
        assert_eq!(json["is_healthy"], true);
    }

    #[test]
    fn rejects_health_guard_on_unrelated_action() {
        let context = health_context();
        let position = MorphoPosition {
            supply_shares: U256::zero(),
            borrow_shares: U256::zero(),
            collateral: U256::zero(),
        };
        assert!(enforce_health_guard(
            &action_request(Some("1.10")),
            MorphoAction::Supply,
            &context,
            &position,
            ResolvedAmount::Assets(U256::one()),
        )
        .is_err());
    }

    #[tokio::test]
    #[ignore = "requires the public Base Sepolia Blockscout API"]
    async fn live_discovers_and_verifies_default_market_event() {
        let markets = fetch_markets_from_blockscout().await.unwrap();
        let default_id = morpho::parse_market_id(morpho::DEFAULT_MARKET_ID).unwrap();
        assert!(markets
            .iter()
            .any(|(id, params)| { *id == default_id && morpho::derive_market_id(params) == *id }));
    }
}
