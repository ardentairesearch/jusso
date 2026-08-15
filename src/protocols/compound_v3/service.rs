use anyhow::Result;
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, U256, U512};
use ethers::utils::format_units;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use uuid::Uuid;

use super::adapter as compound_v3;
use super::adapter::{
    CompoundAssetBalance, CompoundBalancesQuery, CompoundBalancesResponse,
    CompoundBorrowCapacityCollateral, CompoundBorrowCapacityQuery, CompoundBorrowCapacityResponse,
    CompoundBorrowRequest, CompoundCollateralBalance, CompoundMarketCollateral,
    CompoundMarketSummary, CompoundMarketsQuery, CompoundMarketsResponse, CompoundPositionQuery,
    CompoundPositionResponse, CompoundRepayRequest, CompoundSupplyRequest, CompoundWithdrawRequest,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{handle_execute, handle_simulate, resolve_chain_smart_wallet_address};
use crate::execution_engine::ExecutionEngine;
use crate::types::{Chain, ExecutionResponse};

const FACTOR_SCALE: u64 = 1_000_000_000_000_000_000;
const SECONDS_PER_YEAR: u64 = 31_536_000;

pub async fn handle_markets(
    engine: &ExecutionEngine,
    query: &CompoundMarketsQuery,
) -> Result<CompoundMarketsResponse> {
    compound_v3::validate_markets_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let mut markets = Vec::new();
    for market in compound_v3::CompoundMarket::ALL {
        if query.base_asset.as_deref().is_some_and(|base| {
            !base.trim().eq_ignore_ascii_case(market.base_symbol())
                && !base
                    .trim()
                    .eq_ignore_ascii_case(&format!("{:?}", market.base_token()))
        }) {
            continue;
        }
        let comet = market.comet();
        let base = verify_market(engine, &chain, market).await?;
        let (symbol, decimals, utilization, collateral_assets) = tokio::try_join!(
            token_symbol(engine, &chain, base),
            token_decimals(engine, &chain, base),
            call_u256(engine, &chain, comet, compound_v3::encode_get_utilization()),
            market_collaterals(engine, &chain, comet),
        )?;
        let (supply_rate, borrow_rate) = tokio::try_join!(
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_get_supply_rate(utilization)
            ),
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_get_borrow_rate(utilization)
            ),
        )?;
        markets.push(CompoundMarketSummary {
            market: market.slug().to_string(),
            comet_address: format!("{comet:?}"),
            verified: true,
            base_token_address: format!("{base:?}"),
            base_token_symbol: symbol,
            base_token_decimals: decimals,
            utilization_raw: utilization.to_string(),
            utilization_percent: format_percent(utilization, U256::from(FACTOR_SCALE), 4),
            supply_apr_percent: format_apr_percent(supply_rate, 4),
            borrow_apr_percent: format_apr_percent(borrow_rate, 4),
            collateral_assets,
        });
    }
    Ok(CompoundMarketsResponse {
        chain: query.chain.clone(),
        markets,
    })
}

pub async fn handle_supply(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundSupplyRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_supply_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let _smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_supply_amount(engine, &chain, req, _smart_wallet_address).await?;
    let execution_req = compound_v3::compile_supply(&resolved_req)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Compound III supply on {chain} failed: {e}"))
}

pub async fn handle_supply_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundSupplyRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_supply_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_supply_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_supply(&resolved_req)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_withdraw(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundWithdrawRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_withdraw_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_withdraw_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_withdraw(&resolved_req)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Compound III withdraw on {chain} failed: {e}"))
}

pub async fn handle_withdraw_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundWithdrawRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_withdraw_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_withdraw_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_withdraw(&resolved_req)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_repay(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundRepayRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_repay_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_repay_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_repay(&resolved_req)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Compound III repay on {chain} failed: {e}"))
}

pub async fn handle_repay_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundRepayRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_repay_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_repay_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_repay(&resolved_req)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_borrow(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundBorrowRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_borrow_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_borrow_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_borrow(&resolved_req)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Compound III borrow on {chain} failed: {e}"))
}

pub async fn handle_borrow_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &CompoundBorrowRequest,
) -> Result<ExecutionResponse> {
    compound_v3::validate_borrow_request(req)?;
    let chain = parse_chain(&req.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_borrow_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = compound_v3::compile_borrow(&resolved_req)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_position(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &CompoundPositionQuery,
) -> Result<CompoundPositionResponse> {
    compound_v3::validate_position_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let market = compound_v3::market_from_query(query.market.as_deref())?;
    let comet = market.comet();
    let base = verify_market(engine, &chain, market).await?;
    let (base_symbol, base_decimals, base_supply_balance, base_borrow_balance, collateral_assets) =
        tokio::try_join!(
            token_symbol(engine, &chain, base),
            token_decimals(engine, &chain, base),
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_balance_of(smart_wallet_address)
            ),
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_borrow_balance_of(smart_wallet_address)
            ),
            collateral_balances(engine, &chain, comet, smart_wallet_address),
        )?;

    Ok(CompoundPositionResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        comet_address: format!("{comet:?}"),
        base_token_address: format!("{base:?}"),
        base_token_symbol: base_symbol,
        base_token_decimals: base_decimals,
        base_supply_balance_raw: base_supply_balance.to_string(),
        base_supply_balance_formatted: format_token_units(base_supply_balance, base_decimals)?,
        base_borrow_balance_raw: base_borrow_balance.to_string(),
        base_borrow_balance_formatted: format_token_units(base_borrow_balance, base_decimals)?,
        collateral_assets,
    })
}

pub async fn handle_balances(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &CompoundBalancesQuery,
) -> Result<CompoundBalancesResponse> {
    compound_v3::validate_balances_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let market = compound_v3::market_from_query(query.market.as_deref())?;
    let comet = market.comet();
    let base = verify_market(engine, &chain, market).await?;
    let base_symbol = token_symbol(engine, &chain, base).await?;
    let base_decimals = token_decimals(engine, &chain, base).await?;
    let (base_wallet_balance, base_supply_balance) = tokio::try_join!(
        call_u256(
            engine,
            &chain,
            base,
            compound_v3::encode_erc20_balance_of(smart_wallet_address)
        ),
        call_u256(
            engine,
            &chain,
            comet,
            compound_v3::encode_balance_of(smart_wallet_address)
        ),
    )?;

    let mut assets = vec![CompoundAssetBalance {
        symbol: base_symbol,
        token_address: format!("{base:?}"),
        decimals: base_decimals,
        wallet_balance_raw: base_wallet_balance.to_string(),
        wallet_balance_formatted: format_token_units(base_wallet_balance, base_decimals)?,
        compound_balance_raw: base_supply_balance.to_string(),
        compound_balance_formatted: format_token_units(base_supply_balance, base_decimals)?,
        is_base_asset: true,
    }];

    for collateral in collateral_balances(engine, &chain, comet, smart_wallet_address).await? {
        let token: Address = collateral.token_address.parse()?;
        let wallet_balance = call_u256(
            engine,
            &chain,
            token,
            compound_v3::encode_erc20_balance_of(smart_wallet_address),
        )
        .await?;
        assets.push(CompoundAssetBalance {
            symbol: collateral.symbol,
            token_address: collateral.token_address,
            decimals: collateral.decimals,
            wallet_balance_raw: wallet_balance.to_string(),
            wallet_balance_formatted: format_token_units(wallet_balance, collateral.decimals)?,
            compound_balance_raw: collateral.collateral_balance_raw,
            compound_balance_formatted: collateral.collateral_balance_formatted,
            is_base_asset: false,
        });
    }

    Ok(CompoundBalancesResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        comet_address: format!("{comet:?}"),
        assets,
    })
}

pub async fn handle_borrow_capacity(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &CompoundBorrowCapacityQuery,
) -> Result<CompoundBorrowCapacityResponse> {
    compound_v3::validate_borrow_capacity_query(query)?;
    let chain = parse_chain(&query.chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let market = compound_v3::market_from_query(query.market.as_deref())?;
    let comet = market.comet();
    let base = verify_market(engine, &chain, market).await?;
    let base_price_feed = call_address(
        engine,
        &chain,
        comet,
        compound_v3::encode_base_token_price_feed(),
    )
    .await?;

    let (base_symbol, base_decimals, base_price, utilization, current_borrow, collateralized) = tokio::try_join!(
        token_symbol(engine, &chain, base),
        token_decimals(engine, &chain, base),
        call_u256(
            engine,
            &chain,
            comet,
            compound_v3::encode_get_price(base_price_feed)
        ),
        call_u256(engine, &chain, comet, compound_v3::encode_get_utilization()),
        call_u256(
            engine,
            &chain,
            comet,
            compound_v3::encode_borrow_balance_of(smart_wallet_address)
        ),
        call_bool(
            engine,
            &chain,
            comet,
            compound_v3::encode_is_borrow_collateralized(smart_wallet_address)
        ),
    )?;
    if base_price.is_zero() {
        anyhow::bail!("Compound III borrow capacity unavailable: base price is zero");
    }

    let (supply_rate, borrow_rate) = tokio::try_join!(
        call_u256(
            engine,
            &chain,
            comet,
            compound_v3::encode_get_supply_rate(utilization)
        ),
        call_u256(
            engine,
            &chain,
            comet,
            compound_v3::encode_get_borrow_rate(utilization)
        ),
    )?;

    let mut total_capacity = U256::zero();
    let mut collateral_assets = Vec::new();
    let count = call_u256(engine, &chain, comet, compound_v3::encode_num_assets()).await?;
    if count > U256::from(u8::MAX) {
        anyhow::bail!("Compound III market reports too many collateral assets");
    }

    for index in 0..count.as_u32() {
        let info = call_asset_info(engine, &chain, comet, index as u8).await?;
        let (symbol, decimals, collateral_balance, price) = tokio::try_join!(
            token_symbol(engine, &chain, info.asset),
            token_decimals(engine, &chain, info.asset),
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_collateral_balance_of(smart_wallet_address, info.asset)
            ),
            call_u256(
                engine,
                &chain,
                comet,
                compound_v3::encode_get_price(info.price_feed)
            ),
        )?;

        let capacity = collateral_borrow_capacity(
            collateral_balance,
            price,
            info.borrow_collateral_factor,
            info.scale,
            U256::exp10(base_decimals as usize),
            base_price,
        )?;
        total_capacity = total_capacity.saturating_add(capacity);
        collateral_assets.push(CompoundBorrowCapacityCollateral {
            symbol,
            token_address: format!("{:?}", info.asset),
            decimals,
            price_feed_address: format!("{:?}", info.price_feed),
            price_raw: price.to_string(),
            borrow_collateral_factor_raw: info.borrow_collateral_factor.to_string(),
            borrow_collateral_factor_percent: format_percent(
                info.borrow_collateral_factor,
                U256::from(FACTOR_SCALE),
                4,
            ),
            collateral_balance_raw: collateral_balance.to_string(),
            collateral_balance_formatted: format_token_units(collateral_balance, decimals)?,
            borrow_capacity_raw: capacity.to_string(),
            borrow_capacity_formatted: format_token_units(capacity, base_decimals)?,
        });
    }

    let available_borrow = total_capacity.saturating_sub(current_borrow);

    Ok(CompoundBorrowCapacityResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        comet_address: format!("{comet:?}"),
        base_token_address: format!("{base:?}"),
        base_token_symbol: base_symbol,
        base_token_decimals: base_decimals,
        base_price_feed_address: format!("{base_price_feed:?}"),
        base_price_raw: base_price.to_string(),
        utilization_raw: utilization.to_string(),
        utilization_percent: format_percent(utilization, U256::from(FACTOR_SCALE), 4),
        supply_rate_per_second_raw: supply_rate.to_string(),
        supply_apr_percent: format_apr_percent(supply_rate, 4),
        borrow_rate_per_second_raw: borrow_rate.to_string(),
        borrow_apr_percent: format_apr_percent(borrow_rate, 4),
        current_borrow_raw: current_borrow.to_string(),
        current_borrow_formatted: format_token_units(current_borrow, base_decimals)?,
        total_borrow_capacity_raw: total_capacity.to_string(),
        total_borrow_capacity_formatted: format_token_units(total_capacity, base_decimals)?,
        available_borrow_raw: available_borrow.to_string(),
        available_borrow_formatted: format_token_units(available_borrow, base_decimals)?,
        is_borrow_collateralized: collateralized,
        collateral_assets,
    })
}

async fn resolve_supply_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &CompoundSupplyRequest,
    smart_wallet_address: Address,
) -> Result<CompoundSupplyRequest> {
    let market = compound_v3::market_from_action(&req.asset, req.market.as_deref())?;
    verify_market(engine, chain, market).await?;
    if !compound_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
        return Ok(req.clone());
    }
    let asset = action_asset_address(&req.asset, market)?;
    let balance = call_u256(
        engine,
        chain,
        asset,
        compound_v3::encode_erc20_balance_of(smart_wallet_address),
    )
    .await?;
    if balance.is_zero() {
        anyhow::bail!("Compound III supply rejected: wallet has zero selected asset balance");
    }
    Ok(compound_v3::supply_with_amount_raw(req, balance))
}

async fn resolve_withdraw_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &CompoundWithdrawRequest,
    smart_wallet_address: Address,
) -> Result<CompoundWithdrawRequest> {
    let market = compound_v3::market_from_action(&req.asset, req.market.as_deref())?;
    let base = verify_market(engine, chain, market).await?;
    if !compound_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
        return Ok(req.clone());
    }
    let comet = market.comet();
    let asset = action_asset_address(&req.asset, market)?;
    let balance = if asset == base {
        call_u256(
            engine,
            chain,
            comet,
            compound_v3::encode_balance_of(smart_wallet_address),
        )
        .await?
    } else {
        call_u256(
            engine,
            chain,
            comet,
            compound_v3::encode_collateral_balance_of(smart_wallet_address, asset),
        )
        .await?
    };
    if balance.is_zero() {
        anyhow::bail!("Compound III withdraw rejected: no supplied balance for selected asset");
    }
    Ok(compound_v3::withdraw_with_amount_raw(req, balance))
}

async fn resolve_repay_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &CompoundRepayRequest,
    smart_wallet_address: Address,
) -> Result<CompoundRepayRequest> {
    let market = compound_v3::market_from_action(&req.asset, req.market.as_deref())?;
    verify_market(engine, chain, market).await?;
    if !compound_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
        return Ok(req.clone());
    }
    let comet = market.comet();
    let base = market.base_token();
    let (debt, wallet_balance) = tokio::try_join!(
        call_u256(
            engine,
            chain,
            comet,
            compound_v3::encode_borrow_balance_of(smart_wallet_address)
        ),
        call_u256(
            engine,
            chain,
            base,
            compound_v3::encode_erc20_balance_of(smart_wallet_address)
        )
    )?;
    if debt.is_zero() {
        anyhow::bail!("Compound III repay rejected: no base debt");
    }
    if wallet_balance.is_zero() {
        anyhow::bail!("Compound III repay rejected: wallet has zero base asset balance");
    }
    Ok(compound_v3::repay_with_amount_raw(
        req,
        min_u256(debt, wallet_balance),
    ))
}

async fn resolve_borrow_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &CompoundBorrowRequest,
    _smart_wallet_address: Address,
) -> Result<CompoundBorrowRequest> {
    let market = compound_v3::market_from_action(&req.asset, req.market.as_deref())?;
    verify_market(engine, chain, market).await?;
    if compound_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
        anyhow::bail!(
            "Compound III borrow amount max is not supported yet; provide amount or amount_raw"
        );
    }
    Ok(req.clone())
}

async fn collateral_balances(
    engine: &ExecutionEngine,
    chain: &Chain,
    comet: Address,
    smart_wallet_address: Address,
) -> Result<Vec<CompoundCollateralBalance>> {
    let count = call_u256(engine, chain, comet, compound_v3::encode_num_assets()).await?;
    if count > U256::from(u8::MAX) {
        anyhow::bail!("Compound III market reports too many collateral assets");
    }

    let mut out = Vec::new();
    for index in 0..count.as_u32() {
        let info = call_asset_info(engine, chain, comet, index as u8).await?;
        let (symbol, decimals, balance) = tokio::try_join!(
            token_symbol(engine, chain, info.asset),
            token_decimals(engine, chain, info.asset),
            call_u256(
                engine,
                chain,
                comet,
                compound_v3::encode_collateral_balance_of(smart_wallet_address, info.asset)
            ),
        )?;
        out.push(CompoundCollateralBalance {
            symbol,
            token_address: format!("{:?}", info.asset),
            decimals,
            collateral_balance_raw: balance.to_string(),
            collateral_balance_formatted: format_token_units(balance, decimals)?,
        });
    }
    Ok(out)
}

async fn verify_market(
    engine: &ExecutionEngine,
    chain: &Chain,
    market: compound_v3::CompoundMarket,
) -> Result<Address> {
    let comet = market.comet();
    let reported = call_address(engine, chain, comet, compound_v3::encode_base_token())
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "Compound III {} registry verification failed for Comet {comet:?}: {error}",
                market.slug()
            )
        })?;
    if reported != market.base_token() {
        anyhow::bail!(
            "Compound III {} registry verification failed: Comet {comet:?} reports base token {reported:?}, expected {:?}",
            market.slug(),
            market.base_token()
        );
    }
    Ok(reported)
}

async fn market_collaterals(
    engine: &ExecutionEngine,
    chain: &Chain,
    comet: Address,
) -> Result<Vec<CompoundMarketCollateral>> {
    let count = call_u256(engine, chain, comet, compound_v3::encode_num_assets()).await?;
    if count > U256::from(u8::MAX) {
        anyhow::bail!("Compound III market reports too many collateral assets");
    }
    let mut assets = Vec::new();
    for index in 0..count.as_u32() {
        let info = call_asset_info(engine, chain, comet, index as u8).await?;
        let (symbol, decimals) = tokio::try_join!(
            token_symbol(engine, chain, info.asset),
            token_decimals(engine, chain, info.asset),
        )?;
        assets.push(CompoundMarketCollateral {
            symbol,
            token_address: format!("{:?}", info.asset),
            decimals,
            price_feed_address: format!("{:?}", info.price_feed),
            borrow_collateral_factor_percent: format_percent(
                info.borrow_collateral_factor,
                U256::from(FACTOR_SCALE),
                4,
            ),
            liquidation_collateral_factor_percent: format_percent(
                info.liquidate_collateral_factor,
                U256::from(FACTOR_SCALE),
                4,
            ),
            supply_cap_raw: info.supply_cap.to_string(),
        });
    }
    Ok(assets)
}

async fn call_u256(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> Result<U256> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes = hex::decode(calldata.trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(to).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_u256(&raw.0)
}

async fn call_address(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> Result<Address> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes = hex::decode(calldata.trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(to).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_address(&raw.0)
}

async fn call_bool(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> Result<bool> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes = hex::decode(calldata.trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(to).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_bool(&raw.0)
}

async fn call_asset_info(
    engine: &ExecutionEngine,
    chain: &Chain,
    comet: Address,
    index: u8,
) -> Result<compound_v3::CompoundAssetInfo> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes =
        hex::decode(compound_v3::encode_get_asset_info(index).trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(comet).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_asset_info(&raw.0)
}

async fn token_decimals(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<u8> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes =
        hex::decode(compound_v3::encode_erc20_decimals().trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(token).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_u8(&raw.0)
}

async fn token_symbol(engine: &ExecutionEngine, chain: &Chain, token: Address) -> Result<String> {
    let provider = engine.provider_for_chain(chain)?;
    let data: Bytes =
        hex::decode(compound_v3::encode_erc20_symbol().trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(token).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    compound_v3::decode_string(&raw.0).or_else(|_| Ok("UNKNOWN".to_string()))
}

fn action_asset_address(asset: &str, market: compound_v3::CompoundMarket) -> Result<Address> {
    match asset.trim().to_uppercase().as_str() {
        "BASE" => Ok(market.base_token()),
        "USDC" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
            .parse()
            .map_err(Into::into),
        "WETH" => "0x4200000000000000000000000000000000000006"
            .parse()
            .map_err(Into::into),
        _ => asset
            .parse()
            .map_err(|e| anyhow::anyhow!("asset must be a symbol or token address: {e}")),
    }
}

fn parse_chain(chain: &str) -> Result<Chain> {
    Chain::from_str_loose(chain).ok_or_else(|| anyhow::anyhow!("unsupported chain: {chain}"))
}

fn min_u256(a: U256, b: U256) -> U256 {
    if a < b {
        a
    } else {
        b
    }
}

fn format_token_units(value: U256, decimals: u8) -> Result<String> {
    format_units(value, decimals as usize).map_err(Into::into)
}

fn collateral_borrow_capacity(
    collateral_balance: U256,
    collateral_price: U256,
    borrow_collateral_factor: U256,
    collateral_scale: U256,
    base_scale: U256,
    base_price: U256,
) -> Result<U256> {
    if collateral_balance.is_zero()
        || collateral_price.is_zero()
        || borrow_collateral_factor.is_zero()
    {
        return Ok(U256::zero());
    }
    if collateral_scale.is_zero() || base_scale.is_zero() || base_price.is_zero() {
        anyhow::bail!("Compound III borrow capacity unavailable: invalid market scale or price");
    }

    let numerator = U512::from(collateral_balance)
        * U512::from(collateral_price)
        * U512::from(borrow_collateral_factor)
        * U512::from(base_scale);
    let denominator =
        U512::from(collateral_scale) * U512::from(FACTOR_SCALE) * U512::from(base_price);
    let value = numerator / denominator;
    if value > U512::from(U256::MAX) {
        anyhow::bail!("Compound III borrow capacity exceeds uint256");
    }
    let mut bytes = [0u8; 64];
    value.to_big_endian(&mut bytes);
    Ok(U256::from_big_endian(&bytes[32..]))
}

fn format_percent(value: U256, scale: U256, decimals: usize) -> String {
    format_scaled_decimal(value.saturating_mul(U256::from(100u64)), scale, decimals)
}

fn format_apr_percent(rate_per_second: U256, decimals: usize) -> String {
    let annual = rate_per_second
        .saturating_mul(U256::from(SECONDS_PER_YEAR))
        .saturating_mul(U256::from(100u64));
    format_scaled_decimal(annual, U256::from(FACTOR_SCALE), decimals)
}

fn format_scaled_decimal(value: U256, scale: U256, decimals: usize) -> String {
    if scale.is_zero() {
        return "0".to_string();
    }
    let whole = value / scale;
    if decimals == 0 {
        return whole.to_string();
    }
    let fractional_scale = U256::exp10(decimals);
    let fractional = (value % scale) * fractional_scale / scale;
    let fractional_str = format!("{:0>width$}", fractional.to_string(), width = decimals);
    format!("{whole}.{fractional_str}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collateral_borrow_capacity_converts_to_base_units() {
        let capacity = collateral_borrow_capacity(
            U256::exp10(18),
            U256::from(200_000_000_000u64),
            U256::from(800_000_000_000_000_000u64),
            U256::exp10(18),
            U256::exp10(6),
            U256::from(100_000_000u64),
        )
        .unwrap();

        assert_eq!(capacity, U256::from(1_600_000_000u64));
        assert_eq!(format_token_units(capacity, 6).unwrap(), "1600.000000");
    }

    #[test]
    fn percent_formatting_handles_utilization_and_apr() {
        assert_eq!(
            format_percent(
                U256::from(750_000_000_000_000_000u64),
                U256::from(FACTOR_SCALE),
                2
            ),
            "75.00"
        );
        assert_eq!(
            format_apr_percent(U256::from(1_000_000_000u64), 4),
            "3.1536"
        );
    }

    #[tokio::test]
    #[ignore = "requires configured Base Sepolia RPC"]
    async fn live_verifies_both_registered_comets() {
        dotenvy::dotenv().ok();
        let config = crate::config::AppConfig::from_env().unwrap();
        let engine = ExecutionEngine::new(config.runtime_config().unwrap()).unwrap();
        for market in compound_v3::CompoundMarket::ALL {
            assert_eq!(
                verify_market(&engine, &Chain::Base, market).await.unwrap(),
                market.base_token()
            );
        }
    }
}
