use anyhow::Result;
use ethers::prelude::Middleware;
use ethers::types::{Address, Bytes, TransactionRequest, U256};
use ethers::utils::format_units;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use super::adapter as gmx_v2;
use super::adapter::{
    GmxAccountQuery, GmxBalancesResponse, GmxCancelOrderRequest, GmxCancelRequest, GmxClaimRequest,
    GmxCreateDepositRequest, GmxCreateOrderRequest, GmxCreateWithdrawalRequest, GmxMarketBalance,
    GmxMarketsQuery, GmxMarketsResponse, GmxOrdersResponse, GmxPositionsResponse, GmxTokenBalance,
    GmxUpdateOrderRequest,
};
use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services::{handle_execute, handle_simulate, resolve_chain_smart_wallet_address};
use crate::execution_engine::ExecutionEngine;
use crate::types::{Chain, ExecutionResponse};

async fn call_reader(engine: &ExecutionEngine, chain: &Chain, calldata: String) -> Result<Bytes> {
    let provider = engine.provider_for_chain(chain)?;
    let reader: Address = gmx_v2::reader_address().parse()?;
    let data: Bytes = hex::decode(calldata.trim_start_matches("0x"))?.into();
    let tx = TransactionRequest::new().to(reader).data(data);
    Ok(provider.call(&tx.into(), None).await?)
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
    let decoded = ethers::abi::decode(&[ethers::abi::ParamType::Uint(256)], &raw.0)?;
    match &decoded[0] {
        ethers::abi::Token::Uint(value) => Ok(*value),
        other => anyhow::bail!("expected uint256 response, got {other:?}"),
    }
}

async fn try_call_u256(
    engine: &ExecutionEngine,
    chain: &Chain,
    to: Address,
    calldata: String,
) -> std::result::Result<U256, String> {
    call_u256(engine, chain, to, calldata)
        .await
        .map_err(|e| format!("{e:#}"))
}

async fn call_erc20_symbol(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
) -> Option<String> {
    let provider = engine.provider_for_chain(chain).ok()?;
    let data: Bytes = hex::decode(gmx_v2::encode_symbol().trim_start_matches("0x"))
        .ok()?
        .into();
    let tx = TransactionRequest::new().to(token).data(data);
    let raw = provider.call(&tx.into(), None).await.ok()?;
    decode_erc20_symbol(&raw.0)
}

async fn call_erc20_decimals(
    engine: &ExecutionEngine,
    chain: &Chain,
    token: Address,
) -> Option<u8> {
    let value = call_u256(engine, chain, token, gmx_v2::encode_decimals())
        .await
        .ok()?;
    Some(value.as_u32().min(u8::MAX as u32) as u8)
}

async fn ensure_token_balance(
    engine: &ExecutionEngine,
    chain: &Chain,
    smart_wallet: Address,
    token: Address,
    required: U256,
    field: &str,
) -> Result<()> {
    if required.is_zero() {
        return Ok(());
    }

    let balance = call_u256(
        engine,
        chain,
        token,
        gmx_v2::encode_balance_of(smart_wallet),
    )
    .await?;

    if balance < required {
        let symbol = call_erc20_symbol(engine, chain, token)
            .await
            .unwrap_or_else(|| format!("{token:?}"));
        anyhow::bail!(
            "GMX V2 request rejected before simulation: smart wallet {smart_wallet:?} has {balance} raw {symbol} ({token:?}) but {field} requires {required}. Fund the smart wallet with the required GMX asset or lower the requested amount."
        );
    }

    Ok(())
}

fn parse_preflight_u256(raw: &str, field: &str) -> Result<U256> {
    U256::from_dec_str(raw.trim()).map_err(|_| anyhow::anyhow!("invalid {field}: {raw}"))
}

fn parse_optional_preflight_u256(raw: Option<&str>, field: &str) -> Result<U256> {
    match raw {
        Some(value) if !value.trim().is_empty() => parse_preflight_u256(value, field),
        _ => Ok(U256::zero()),
    }
}

async fn guard_create_order_balances(
    engine: &ExecutionEngine,
    chain: &Chain,
    smart_wallet: Address,
    req: &GmxCreateOrderRequest,
) -> Result<()> {
    let token: Address = req.initial_collateral_token.parse()?;
    let amount = parse_preflight_u256(
        &req.initial_collateral_delta_amount_raw,
        "initial_collateral_delta_amount_raw",
    )?;
    ensure_token_balance(
        engine,
        chain,
        smart_wallet,
        token,
        amount,
        "initial_collateral_delta_amount_raw",
    )
    .await
}

async fn guard_create_deposit_balances(
    engine: &ExecutionEngine,
    chain: &Chain,
    smart_wallet: Address,
    req: &GmxCreateDepositRequest,
) -> Result<()> {
    let long_amount = parse_optional_preflight_u256(
        req.initial_long_token_amount_raw.as_deref(),
        "initial_long_token_amount_raw",
    )?;
    if !long_amount.is_zero() {
        let token: Address = req.initial_long_token.parse()?;
        ensure_token_balance(
            engine,
            chain,
            smart_wallet,
            token,
            long_amount,
            "initial_long_token_amount_raw",
        )
        .await?;
    }

    let short_amount = parse_optional_preflight_u256(
        req.initial_short_token_amount_raw.as_deref(),
        "initial_short_token_amount_raw",
    )?;
    if !short_amount.is_zero() {
        let token: Address = req.initial_short_token.parse()?;
        ensure_token_balance(
            engine,
            chain,
            smart_wallet,
            token,
            short_amount,
            "initial_short_token_amount_raw",
        )
        .await?;
    }

    Ok(())
}

async fn guard_create_withdrawal_balances(
    engine: &ExecutionEngine,
    chain: &Chain,
    smart_wallet: Address,
    req: &GmxCreateWithdrawalRequest,
) -> Result<()> {
    let market_token: Address = req.market.parse()?;
    let amount = parse_preflight_u256(&req.market_token_amount_raw, "market_token_amount_raw")?;
    ensure_token_balance(
        engine,
        chain,
        smart_wallet,
        market_token,
        amount,
        "market_token_amount_raw",
    )
    .await
}

fn decode_erc20_symbol(raw: &[u8]) -> Option<String> {
    if let Ok(decoded) = ethers::abi::decode(&[ethers::abi::ParamType::String], raw) {
        if let ethers::abi::Token::String(symbol) = &decoded[0] {
            let trimmed = symbol.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }

    if raw.len() >= 32 {
        let bytes = &raw[raw.len() - 32..];
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        let trimmed = &bytes[..end];
        if !trimmed.is_empty() {
            if let Ok(symbol) = std::str::from_utf8(trimmed) {
                let symbol = symbol.trim();
                if !symbol.is_empty() {
                    return Some(symbol.to_string());
                }
            }
        }
    }

    None
}

async fn enrich_market_symbols(
    engine: &ExecutionEngine,
    chain: &Chain,
    markets: &mut [gmx_v2::GmxMarket],
) {
    let mut cache: HashMap<String, Option<String>> = HashMap::new();

    for market in markets {
        market.index_token_symbol =
            cached_symbol(engine, chain, &mut cache, &market.index_token).await;
        market.long_token_symbol =
            cached_symbol(engine, chain, &mut cache, &market.long_token).await;
        market.short_token_symbol =
            cached_symbol(engine, chain, &mut cache, &market.short_token).await;
        market.market_token_symbol = cached_symbol(engine, chain, &mut cache, &market.market_token)
            .await
            .or_else(|| derived_market_symbol(market));
    }
}

async fn cached_symbol(
    engine: &ExecutionEngine,
    chain: &Chain,
    cache: &mut HashMap<String, Option<String>>,
    token: &str,
) -> Option<String> {
    let key = token.to_ascii_lowercase();
    if let Some(symbol) = cache.get(&key) {
        return symbol.clone();
    }

    let symbol = match token.parse::<Address>() {
        Ok(address) => call_erc20_symbol(engine, chain, address).await,
        Err(_) => None,
    };
    cache.insert(key, symbol.clone());
    symbol
}

fn derived_market_symbol(market: &gmx_v2::GmxMarket) -> Option<String> {
    let index = market
        .index_token_symbol
        .clone()
        .or_else(|| compact_address_label(&market.index_token));
    let long = market
        .long_token_symbol
        .clone()
        .or_else(|| compact_address_label(&market.long_token));
    let short = market
        .short_token_symbol
        .clone()
        .or_else(|| compact_address_label(&market.short_token));

    match (index, long, short) {
        (Some(index), Some(long), Some(short)) if long == short => {
            Some(format!("GM:{index}/{long}"))
        }
        (Some(index), Some(long), Some(short)) => Some(format!("GM:{index}/{long}-{short}")),
        _ => None,
    }
}

fn compact_address_label(raw: &str) -> Option<String> {
    let address = raw.strip_prefix("0x")?;
    if address.len() < 10 {
        return None;
    }
    Some(format!(
        "0x{}...{}",
        &address[..6],
        &address[address.len() - 4..]
    ))
}

pub async fn handle_markets(
    engine: &ExecutionEngine,
    query: &GmxMarketsQuery,
) -> Result<GmxMarketsResponse> {
    let (start, end) = gmx_v2::validate_markets_query(query)?;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let data_store: Address = gmx_v2::data_store_address().parse()?;
    let raw = call_reader(
        engine,
        &chain,
        gmx_v2::encode_get_markets(data_store, U256::from(start), U256::from(end)),
    )
    .await?;
    let mut markets = gmx_v2::decode_markets(&raw.0)?;
    enrich_market_symbols(engine, &chain, &mut markets).await;
    Ok(GmxMarketsResponse {
        chain: query.chain.clone(),
        reader_address: gmx_v2::reader_address().to_string(),
        data_store_address: gmx_v2::data_store_address().to_string(),
        start,
        end,
        markets,
    })
}

pub async fn handle_positions(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &GmxAccountQuery,
) -> Result<GmxPositionsResponse> {
    let (start, end) = gmx_v2::validate_account_query(query)?;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let data_store: Address = gmx_v2::data_store_address().parse()?;
    let raw = call_reader(
        engine,
        &chain,
        gmx_v2::encode_get_account_positions(
            data_store,
            smart_wallet_address,
            U256::from(start),
            U256::from(end),
        ),
    )
    .await?;
    let positions = gmx_v2::decode_positions(&raw.0)?;
    Ok(GmxPositionsResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        start,
        end,
        positions,
    })
}

pub async fn handle_orders(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &GmxAccountQuery,
) -> Result<GmxOrdersResponse> {
    let (start, end) = gmx_v2::validate_account_query(query)?;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let data_store: Address = gmx_v2::data_store_address().parse()?;
    let raw = call_reader(
        engine,
        &chain,
        gmx_v2::encode_get_account_orders(
            data_store,
            smart_wallet_address,
            U256::from(start),
            U256::from(end),
        ),
    )
    .await?;
    let orders = gmx_v2::decode_orders(&raw.0)?;
    Ok(GmxOrdersResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        start,
        end,
        orders,
    })
}

pub async fn handle_balances(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    query: &GmxAccountQuery,
) -> Result<GmxBalancesResponse> {
    let (start, end) = gmx_v2::validate_account_query(query)?;
    let markets = handle_markets(
        engine,
        &GmxMarketsQuery {
            chain: query.chain.clone(),
            start: Some(start),
            end: Some(end),
        },
    )
    .await?
    .markets;
    let chain = Chain::from_str_loose(&query.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", query.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &query.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let mut balances = Vec::new();
    let mut asset_roles: HashMap<Address, (HashSet<String>, HashSet<String>)> = HashMap::new();

    for market in &markets {
        collect_market_asset_role(
            &mut asset_roles,
            &market.index_token,
            "index",
            &market.market_token,
        )?;
        collect_market_asset_role(
            &mut asset_roles,
            &market.long_token,
            "long",
            &market.market_token,
        )?;
        collect_market_asset_role(
            &mut asset_roles,
            &market.short_token,
            "short",
            &market.market_token,
        )?;
    }

    for market in &markets {
        let token: Address = market.market_token.parse()?;
        let balance_result = try_call_u256(
            engine,
            &chain,
            token,
            gmx_v2::encode_balance_of(smart_wallet_address),
        )
        .await;
        let decimals = call_erc20_decimals(engine, &chain, token)
            .await
            .unwrap_or(18);
        let (balance, error) = match balance_result {
            Ok(balance) => (balance, None),
            Err(error) => (U256::zero(), Some(error)),
        };
        balances.push(GmxMarketBalance {
            market_token: market.market_token.clone(),
            market_token_symbol: market.market_token_symbol.clone(),
            balance_raw: balance.to_string(),
            balance_formatted: format_units(balance, decimals as usize)?,
            decimals,
            error,
        });
    }

    let mut token_balances = Vec::new();
    let mut assets = asset_roles.into_iter().collect::<Vec<_>>();
    assets.sort_by_key(|(address, _)| format!("{address:?}"));
    for (token, (roles, market_tokens)) in assets {
        let balance_result = try_call_u256(
            engine,
            &chain,
            token,
            gmx_v2::encode_balance_of(smart_wallet_address),
        )
        .await;
        let decimals = call_erc20_decimals(engine, &chain, token)
            .await
            .unwrap_or(18);
        let (balance, error) = match balance_result {
            Ok(balance) => (balance, None),
            Err(error) => (U256::zero(), Some(error)),
        };
        let mut roles = roles.into_iter().collect::<Vec<_>>();
        roles.sort();
        let mut markets = market_tokens.into_iter().collect::<Vec<_>>();
        markets.sort();
        let symbol = call_erc20_symbol(engine, &chain, token)
            .await
            .or_else(|| compact_address_label(&format!("{token:?}")))
            .unwrap_or_else(|| "UNKNOWN".to_string());
        token_balances.push(GmxTokenBalance {
            token_address: format!("{token:?}"),
            symbol,
            balance_raw: balance.to_string(),
            balance_formatted: format_units(balance, decimals as usize)?,
            decimals,
            roles,
            markets,
            error,
        });
    }

    Ok(GmxBalancesResponse {
        agent_id: query.agent_id.clone(),
        chain: query.chain.clone(),
        smart_wallet_address: format!("{smart_wallet_address:?}"),
        balances,
        token_balances,
    })
}

fn collect_market_asset_role(
    assets: &mut HashMap<Address, (HashSet<String>, HashSet<String>)>,
    token: &str,
    role: &str,
    market_token: &str,
) -> Result<()> {
    let address: Address = token.parse()?;
    if address == Address::zero() {
        return Ok(());
    }
    let entry = assets.entry(address).or_default();
    entry.0.insert(role.to_string());
    entry.1.insert(market_token.to_string());
    Ok(())
}

pub async fn handle_create_order(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateOrderRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_create_order_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_order_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_order(req, smart_wallet_address)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 create order on {chain} failed: {e}"))
}

pub async fn handle_create_order_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateOrderRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_create_order_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_order_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_order(req, smart_wallet_address)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_cancel_order(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCancelOrderRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_cancel_order_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_cancel_order(req)?;

    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 cancel order on {chain} failed: {e}"))
}

pub async fn handle_cancel_order_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCancelOrderRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_cancel_order_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_cancel_order(req)?;

    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_update_order(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxUpdateOrderRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_update_order_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_update_order(req)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 update order on {chain} failed: {e}"))
}

pub async fn handle_update_order_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxUpdateOrderRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_update_order_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_update_order(req)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_create_deposit(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateDepositRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_create_deposit_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_deposit_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_deposit(req, smart_wallet_address)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 create deposit on {chain} failed: {e}"))
}

pub async fn handle_create_deposit_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateDepositRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_create_deposit_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_deposit_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_deposit(req, smart_wallet_address)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_create_withdrawal(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateWithdrawalRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_create_withdrawal_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_withdrawal_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_withdrawal(req, smart_wallet_address)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 create withdrawal on {chain} failed: {e}"))
}

pub async fn handle_create_withdrawal_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCreateWithdrawalRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_create_withdrawal_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    guard_create_withdrawal_balances(engine, &chain, smart_wallet_address, req).await?;
    let execution_req = gmx_v2::compile_create_withdrawal(req, smart_wallet_address)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_cancel(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCancelRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_cancel_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_cancel(req)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 cancel request on {chain} failed: {e}"))
}

pub async fn handle_cancel_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxCancelRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_cancel_request(req)?;
    wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let execution_req = gmx_v2::compile_cancel(req)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}

pub async fn handle_claim(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxClaimRequest,
) -> Result<ExecutionResponse> {
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    gmx_v2::validate_claim_request(req)?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = gmx_v2::compile_claim(req, smart_wallet_address)?;
    handle_execute(
        engine,
        pool,
        redis_conn,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
    .map_err(|e| anyhow::anyhow!("GMX V2 claim on {chain} failed: {e}"))
}

pub async fn handle_claim_simulate(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    req: &GmxClaimRequest,
) -> Result<ExecutionResponse> {
    gmx_v2::validate_claim_request(req)?;
    let chain = Chain::from_str_loose(&req.chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {}", req.chain))?;
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let execution_req = gmx_v2::compile_claim(req, smart_wallet_address)?;
    handle_simulate(
        engine,
        pool,
        wallet_registry,
        organization_id,
        &execution_req,
    )
    .await
}
