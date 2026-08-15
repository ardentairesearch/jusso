use anyhow::Result;
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, U256};
use ethers::utils::format_units;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use uuid::Uuid;

use super::adapter as aave_v3;
use super::adapter::{
    AaveAssetBalance, AaveBalancesQuery, AaveBalancesResponse, AaveBorrowRequest,
    AavePositionQuery, AavePositionResponse, AaveRepayRequest, AaveSupplyRequest,
    AaveWithdrawRequest,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{handle_execute, handle_simulate, resolve_chain_smart_wallet_address};
use crate::execution_engine::ExecutionEngine;
use crate::types::{Chain, ExecutionResponse};

pub async fn handle_supply(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveSupplyRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_supply_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = aave_v3::compile_supply(req, smart_wallet_address)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Aave V3 supply on {chain} failed: {e}"))
}

pub async fn handle_supply_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveSupplyRequest,
) -> Result<ExecutionResponse> {
    aave_v3::validate_supply_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = aave_v3::compile_supply(req, smart_wallet_address)?;

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
    req: &AaveWithdrawRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_withdraw_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = aave_v3::compile_withdraw(req, smart_wallet_address)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Aave V3 withdraw on {chain} failed: {e}"))
}

pub async fn handle_withdraw_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveWithdrawRequest,
) -> Result<ExecutionResponse> {
    aave_v3::validate_withdraw_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = aave_v3::compile_withdraw(req, smart_wallet_address)?;

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
    req: &AaveRepayRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_repay_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_repay_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = aave_v3::compile_repay(&resolved_req, smart_wallet_address)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Aave V3 repay on {chain} failed: {e}"))
}

pub async fn handle_repay_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveRepayRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_repay_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = resolve_repay_amount(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = aave_v3::compile_repay(&resolved_req, smart_wallet_address)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
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
    aave_v3::decode_u256(&raw.0)
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
    aave_v3::decode_address(&raw.0)
}

async fn fetch_reserve_debt_tokens(
    engine: &ExecutionEngine,
    chain: &Chain,
    asset: Address,
) -> Result<aave_v3::AaveReserveDebtTokens> {
    let provider = engine.provider_for_chain(chain)?;
    let pool_addr: Address = aave_v3::pool_address().parse()?;
    let data: Bytes =
        hex::decode(aave_v3::encode_get_reserve_data(asset).trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(pool_addr).data(data);
    let raw = provider.call(&tx.into(), None).await?;
    aave_v3::decode_reserve_debt_tokens(&raw.0)
}

async fn fetch_account_data(
    engine: &ExecutionEngine,
    chain: &Chain,
    smart_wallet_address: Address,
) -> Result<aave_v3::AaveAccountData> {
    let provider = engine.provider_for_chain(chain)?;
    let pool_addr: Address = aave_v3::pool_address().parse()?;
    let calldata: Bytes = hex::decode(
        aave_v3::encode_get_user_account_data(smart_wallet_address).trim_start_matches("0x"),
    )?
    .into();
    let tx = TransactionRequest::new().to(pool_addr).data(calldata);
    let raw = provider.call(&tx.into(), None).await?;
    aave_v3::decode_user_account_data_values(&raw.0)
}

async fn fetch_asset_price(
    engine: &ExecutionEngine,
    chain: &Chain,
    asset: Address,
) -> Result<U256> {
    let pool_addr: Address = aave_v3::pool_address().parse()?;
    let addresses_provider = call_address(
        engine,
        chain,
        pool_addr,
        aave_v3::encode_addresses_provider(),
    )
    .await?;
    let oracle = call_address(
        engine,
        chain,
        addresses_provider,
        aave_v3::encode_get_price_oracle(),
    )
    .await?;
    let asset_price = call_u256(
        engine,
        chain,
        oracle,
        aave_v3::encode_get_asset_price(asset),
    )
    .await?;
    if asset_price.is_zero() {
        anyhow::bail!("Aave action rejected: oracle returned zero asset price");
    }
    Ok(asset_price)
}

fn token_amount_to_base(amount: U256, asset_price: U256, decimals: u8) -> Result<U256> {
    amount
        .checked_mul(asset_price)
        .ok_or_else(|| anyhow::anyhow!("amount overflow"))?
        .checked_div(U256::exp10(decimals as usize))
        .ok_or_else(|| anyhow::anyhow!("invalid asset decimals"))
}

fn base_to_token_amount_floor(base_amount: U256, asset_price: U256, decimals: u8) -> Result<U256> {
    base_amount
        .checked_mul(U256::exp10(decimals as usize))
        .ok_or_else(|| anyhow::anyhow!("base amount overflow"))?
        .checked_div(asset_price)
        .ok_or_else(|| anyhow::anyhow!("invalid asset price"))
}

fn min_u256(a: U256, b: U256) -> U256 {
    if a < b {
        a
    } else {
        b
    }
}

fn max_borrow_base_for_health(
    account: &aave_v3::AaveAccountData,
    min_health_factor: U256,
) -> Result<U256> {
    let collateral_at_threshold = account
        .total_collateral_base
        .checked_mul(account.current_liquidation_threshold_bps)
        .ok_or_else(|| anyhow::anyhow!("health factor collateral overflow"))?
        / U256::from(10_000u64);
    let max_projected_debt = collateral_at_threshold
        .checked_mul(U256::exp10(18))
        .ok_or_else(|| anyhow::anyhow!("max projected debt overflow"))?
        / min_health_factor;

    if max_projected_debt <= account.total_debt_base {
        Ok(U256::zero())
    } else {
        Ok(max_projected_debt - account.total_debt_base)
    }
}

async fn resolve_borrow_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &AaveBorrowRequest,
    smart_wallet_address: Address,
) -> Result<(AaveBorrowRequest, aave_v3::AaveAccountData, U256, u8)> {
    let account = fetch_account_data(engine, chain, smart_wallet_address).await?;
    if account.total_collateral_base.is_zero() {
        anyhow::bail!("Aave borrow requires supplied collateral");
    }
    if account.available_borrows_base.is_zero() {
        anyhow::bail!("Aave borrow rejected: no available borrows");
    }

    let (asset, decimals) = aave_v3::asset_address_and_decimals(&req.asset)?;
    let asset_price = fetch_asset_price(engine, chain, asset).await?;
    let min_health_factor = aave_v3::min_health_factor_ray(req)?;

    let resolved_amount =
        if aave_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
            let health_limited_base = max_borrow_base_for_health(&account, min_health_factor)?;
            let max_base = min_u256(account.available_borrows_base, health_limited_base);
            let amount = base_to_token_amount_floor(max_base, asset_price, decimals)?;
            if amount.is_zero() {
                anyhow::bail!("Aave borrow rejected: max borrow amount is zero");
            }
            amount
        } else {
            aave_v3::borrow_amount(req)?
        };

    Ok((
        aave_v3::borrow_with_amount_raw(req, resolved_amount),
        account,
        asset_price,
        decimals,
    ))
}

async fn guard_borrow_health(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &AaveBorrowRequest,
    smart_wallet_address: Address,
) -> Result<AaveBorrowRequest> {
    let (resolved_req, account, asset_price, decimals) =
        resolve_borrow_amount(engine, chain, req, smart_wallet_address).await?;
    let amount = aave_v3::borrow_amount(&resolved_req)?;
    let requested_base = token_amount_to_base(amount, asset_price, decimals)?;
    if requested_base.is_zero() {
        anyhow::bail!("Aave borrow rejected: borrow amount is below oracle precision");
    }
    if requested_base > account.available_borrows_base {
        anyhow::bail!("Aave borrow rejected: requested amount exceeds available borrows");
    }

    let projected_debt = account
        .total_debt_base
        .checked_add(requested_base)
        .ok_or_else(|| anyhow::anyhow!("projected debt overflow"))?;
    if projected_debt.is_zero() {
        anyhow::bail!("Aave borrow rejected: projected debt is zero");
    }

    let collateral_at_threshold = account
        .total_collateral_base
        .checked_mul(account.current_liquidation_threshold_bps)
        .ok_or_else(|| anyhow::anyhow!("health factor collateral overflow"))?
        / U256::from(10_000u64);
    let projected_health_factor = collateral_at_threshold
        .checked_mul(U256::exp10(18))
        .ok_or_else(|| anyhow::anyhow!("projected health factor overflow"))?
        / projected_debt;
    let min_health_factor = aave_v3::min_health_factor_ray(req)?;

    if projected_health_factor < min_health_factor {
        anyhow::bail!(
            "Aave borrow rejected: projected health factor {projected_health_factor} is below minimum {min_health_factor}"
        );
    }

    Ok(resolved_req)
}

async fn resolve_repay_amount(
    engine: &ExecutionEngine,
    chain: &Chain,
    req: &AaveRepayRequest,
    smart_wallet_address: Address,
) -> Result<AaveRepayRequest> {
    if !aave_v3::is_amount_max(req.amount.as_deref(), req.amount_raw.as_deref()) {
        return Ok(req.clone());
    }

    let (asset, _decimals) = aave_v3::asset_address_and_decimals(&req.asset)?;
    let debt_tokens = fetch_reserve_debt_tokens(engine, chain, asset).await?;
    let debt_owner = match req.on_behalf_of.as_deref() {
        Some(raw) => raw.parse::<Address>()?,
        None => smart_wallet_address,
    };
    let debt_token = match req.interest_rate_mode.unwrap_or(2) {
        1 => debt_tokens.stable_debt_token,
        2 => debt_tokens.variable_debt_token,
        mode => anyhow::bail!("interest_rate_mode must be 1 (stable) or 2 (variable), got {mode}"),
    };

    let debt = call_u256(
        engine,
        chain,
        debt_token,
        aave_v3::encode_balance_of(debt_owner),
    )
    .await?;
    if debt.is_zero() {
        anyhow::bail!("Aave repay rejected: no debt for selected asset and rate mode");
    }

    let wallet_balance = call_u256(
        engine,
        chain,
        asset,
        aave_v3::encode_balance_of(smart_wallet_address),
    )
    .await?;
    if wallet_balance.is_zero() {
        anyhow::bail!("Aave repay rejected: wallet has zero balance for selected asset");
    }

    let amount = min_u256(debt, wallet_balance);
    if amount.is_zero() {
        anyhow::bail!("Aave repay rejected: max repay amount is zero");
    }

    Ok(aave_v3::repay_with_amount_raw(req, amount))
}

pub async fn handle_borrow(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveBorrowRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_borrow_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = guard_borrow_health(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = aave_v3::compile_borrow(&resolved_req, smart_wallet_address)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("Aave V3 borrow on {chain} failed: {e}"))
}

pub async fn handle_borrow_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &AaveBorrowRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    aave_v3::validate_borrow_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let resolved_req = guard_borrow_health(engine, &chain, req, smart_wallet_address).await?;
    let execution_req = aave_v3::compile_borrow(&resolved_req, smart_wallet_address)?;

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
    query: &AavePositionQuery,
) -> Result<AavePositionResponse> {
    aave_v3::validate_position_query(query)?;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let provider = engine.provider_for_chain(&chain)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let pool_addr: Address = aave_v3::pool_address().parse()?;
    let calldata: Bytes = hex::decode(
        aave_v3::encode_get_user_account_data(smart_wallet_address).trim_start_matches("0x"),
    )?
    .into();
    let tx = TransactionRequest::new().to(pool_addr).data(calldata);

    let raw = provider.call(&tx.into(), None).await?;
    aave_v3::decode_user_account_data(
        &raw.0,
        query.agent_id.clone(),
        query.chain.clone(),
        smart_wallet_address,
    )
}

pub async fn handle_balances(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &AaveBalancesQuery,
) -> Result<AaveBalancesResponse> {
    aave_v3::validate_balances_query(query)?;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;

    let mut assets = Vec::new();
    for (symbol, underlying, decimals) in aave_v3::supported_assets() {
        let reserve_tokens = fetch_reserve_debt_tokens(engine, &chain, underlying).await?;
        let balance_call = aave_v3::encode_balance_of(smart_wallet_address);
        let (wallet_balance, a_token_balance, stable_debt_balance, variable_debt_balance) = tokio::try_join!(
            call_u256(engine, &chain, underlying, balance_call.clone()),
            call_u256(engine, &chain, reserve_tokens.a_token, balance_call.clone()),
            call_u256(
                engine,
                &chain,
                reserve_tokens.stable_debt_token,
                balance_call.clone()
            ),
            call_u256(
                engine,
                &chain,
                reserve_tokens.variable_debt_token,
                balance_call
            ),
        )?;

        assets.push(AaveAssetBalance {
            symbol: symbol.to_string(),
            underlying_address: format!("{underlying:?}"),
            decimals,
            wallet_balance_raw: wallet_balance.to_string(),
            wallet_balance_formatted: format_token_units(wallet_balance, decimals)?,
            a_token_address: format!("{:?}", reserve_tokens.a_token),
            a_token_balance_raw: a_token_balance.to_string(),
            a_token_balance_formatted: format_token_units(a_token_balance, decimals)?,
            stable_debt_token_address: format!("{:?}", reserve_tokens.stable_debt_token),
            stable_debt_balance_raw: stable_debt_balance.to_string(),
            stable_debt_balance_formatted: format_token_units(stable_debt_balance, decimals)?,
            variable_debt_token_address: format!("{:?}", reserve_tokens.variable_debt_token),
            variable_debt_balance_raw: variable_debt_balance.to_string(),
            variable_debt_balance_formatted: format_token_units(variable_debt_balance, decimals)?,
        });
    }

    Ok(AaveBalancesResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        pool_address: aave_v3::pool_address().to_string(),
        assets,
    })
}

fn format_token_units(value: U256, decimals: u8) -> Result<String> {
    format_units(value, decimals as usize).map_err(Into::into)
}
