//! Service layer — thin wrappers that coordinate between the execution engine,
//! agent wallet registry, database, queue, and payment verification for each
//! API endpoint.
//!
//! The Arc Beta flow is:
//!   validate → resolve smart wallet → simulate → price → check payment → enqueue

use anyhow::{Context, Result};
use chrono::Utc;
use ethers_core::abi::{decode, ParamType};
use ethers_core::types::{Address, U256};
use ethers_core::utils::format_units;
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::agent_wallet::AgentWalletRegistry;
use crate::arc::execution::{execution_calls, fee_transfer_call};
use crate::db;
use crate::execution_engine::{pricing::usd_to_token_raw_amount, ExecutionEngine};
use crate::queue;
use crate::types::*;

async fn simulate_arc_request(
    engine: &ExecutionEngine,
    req: &ExecutionRequest,
    chain: &Chain,
    sender: Address,
    fee: Option<&ExecutionFeeCharge>,
    _request_id: Uuid,
) -> Result<SimulationResult> {
    engine.config.chain_config(chain)?;
    let mut calls = execution_calls(
        &req.target_contract,
        &req.calldata,
        &req.value,
        req.batch_calls.as_deref(),
    )?;
    if let Some(fee) = fee {
        calls.insert(0, fee_transfer_call(fee)?);
    }
    match engine.arc_client.prepare(sender, &calls).await {
        Ok(prepared) => Ok(SimulationResult {
            success: true,
            gas_estimate: u64::try_from(prepared.gas_limit)
                .map_err(|_| anyhow::anyhow!("Arc gas estimate exceeds u64"))?,
            max_fee_per_gas_wei: Some(prepared.max_fee_per_gas.to_string()),
            return_data: Some(format!("user_operation_hash={:?}", prepared.hash)),
            error: None,
        }),
        Err(error) => Ok(SimulationResult {
            success: false,
            gas_estimate: 0,
            max_fee_per_gas_wei: None,
            return_data: None,
            error: Some(format!("Arc UserOperation preparation failed: {error:#}")),
        }),
    }
}

/// Arc uses a dedicated ERC-4337 account, never the Turnkey signer as a deposit address.
pub async fn resolve_chain_smart_wallet_address(
    engine: &ExecutionEngine,
    chain: &Chain,
    agent_wallet: &crate::agent_wallet::AgentWallet,
) -> Result<Address> {
    engine.config.chain_config(chain)?;
    Ok(engine
        .smart_accounts
        .get_or_create(agent_wallet, engine.config.arc_network)
        .await?
        .address)
}

/// Execute through the normal Jusso flow. The configured execution-token fee
/// is always embedded in the same native transaction as the requested calls.
pub async fn handle_execute_idempotent(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
    idempotency_key: &str,
) -> Result<ExecutionResponse> {
    let result = handle_execution(
        ExecutionContext {
            engine,
            pool,
            redis_conn,
            wallet_registry,
            auth_context,
            req,
            idempotency_key,
        },
        ExecutionPayment::AtomicExecutionToken,
    )
    .await;
    record_unfinished_failure(
        pool,
        auth_context,
        req,
        "execute:atomic-token",
        idempotency_key,
        &result,
    )
    .await;
    result
}

/// Create the locked quote used by the x402 challenge response.
pub async fn handle_x402_quote(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
    idempotency_key: &str,
) -> Result<ExecutionResponse> {
    let result = handle_execution(
        ExecutionContext {
            engine,
            pool,
            redis_conn,
            wallet_registry,
            auth_context,
            req,
            idempotency_key,
        },
        ExecutionPayment::X402Quote,
    )
    .await;
    record_unfinished_failure(
        pool,
        auth_context,
        req,
        "execute:x402",
        idempotency_key,
        &result,
    )
    .await;
    result
}

/// Re-simulate the requested calls immediately before x402 settlement without
/// adding the normal in-batch fee transfer.
pub async fn handle_x402_preflight(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
) -> Result<SimulationResult> {
    let chain = engine.validate(req)?;
    let wallet = wallet_registry
        .get_or_create(auth_context.organization_id, &req.agent_id)
        .await?;
    let smart_wallet = resolve_chain_smart_wallet_address(engine, &chain, &wallet).await?;
    simulate_arc_request(engine, req, &chain, smart_wallet, None, Uuid::new_v4()).await
}

/// Queue an execution after an x402 facilitator has settled its token payment.
pub async fn handle_x402_execute(
    engine: &ExecutionEngine,
    pool: &PgPool,
    redis_conn: &mut ConnectionManager,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
    settlement: X402Settlement<'_>,
) -> Result<ExecutionResponse> {
    let result = handle_execution(
        ExecutionContext {
            engine,
            pool,
            redis_conn,
            wallet_registry,
            auth_context,
            req,
            idempotency_key: settlement.idempotency_key,
        },
        ExecutionPayment::X402Settled(settlement.payment),
    )
    .await;
    record_unfinished_failure(
        pool,
        auth_context,
        req,
        "execute:x402",
        settlement.idempotency_key,
        &result,
    )
    .await;
    result
}

async fn record_unfinished_failure(
    pool: &PgPool,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
    operation: &str,
    idempotency_key: &str,
    result: &Result<ExecutionResponse>,
) {
    let Err(error) = result else {
        return;
    };
    let reason = format!("execution processing failed: {error:#}");
    if let Err(mark_error) = db::fail_unfinished_idempotent_execution(
        pool,
        auth_context,
        req,
        operation,
        idempotency_key,
        &reason,
    )
    .await
    {
        tracing::error!(
            %mark_error,
            organization_id = %auth_context.organization_id,
            idempotency_key,
            "failed to finalize interrupted idempotent request"
        );
    }
}

async fn record_policy_denial(
    pool: &PgPool,
    auth_context: &AuthContext,
    agent_id: Option<Uuid>,
    request_id: Option<Uuid>,
    phase: &str,
    error: &anyhow::Error,
) {
    let mut context = auth_context.clone();
    context.agent_id = agent_id.or(context.agent_id);
    db::insert_auth_audit_event(
        pool,
        &context,
        "policy:enforce",
        Some("execution"),
        "deny",
        serde_json::json!({
            "phase": phase,
            "request_id": request_id,
            "reason": error.to_string(),
        }),
    )
    .await
    .ok();
}

enum ExecutionPayment<'a> {
    AtomicExecutionToken,
    X402Quote,
    X402Settled(&'a SettledExecutionPayment),
}

pub struct X402Settlement<'a> {
    pub payment: &'a SettledExecutionPayment,
    pub idempotency_key: &'a str,
}

struct ExecutionContext<'a> {
    engine: &'a ExecutionEngine,
    pool: &'a PgPool,
    redis_conn: &'a mut ConnectionManager,
    wallet_registry: &'a AgentWalletRegistry,
    auth_context: &'a AuthContext,
    req: &'a ExecutionRequest,
    idempotency_key: &'a str,
}

async fn handle_execution(
    context: ExecutionContext<'_>,
    payment: ExecutionPayment<'_>,
) -> Result<ExecutionResponse> {
    let ExecutionContext {
        engine,
        pool,
        redis_conn,
        wallet_registry,
        auth_context,
        req,
        idempotency_key,
    } = context;
    // 1. Validate
    let chain = engine.validate(req)?;
    let (agent, policy) = db::authorize_execution_agent(pool, auth_context, &req.agent_id).await?;
    if let Err(error) = crate::auth::enforce_compiled_execution_limits(&policy, req) {
        record_policy_denial(
            pool,
            auth_context,
            Some(agent.id),
            None,
            "compiled_execution",
            &error,
        )
        .await;
        return Err(error);
    }
    let execution_token = engine.config.chain_config(&chain)?.execution_token.clone();

    // Validate callback_url if provided
    let callback_url = crate::webhook::validate_callback_url(req.callback_url.as_deref()).await?;

    // 2. Resolve agent's smart wallet (get or create)
    let agent_wallet = wallet_registry
        .get_or_create(auth_context.organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let smart_wallet_str = format!("{smart_wallet_address:?}");
    // Reserve the logical execution before any simulation, settlement, or
    // queue side effect. The database unique index is the concurrency lock.
    let operation = match payment {
        ExecutionPayment::AtomicExecutionToken => "execute:atomic-token",
        ExecutionPayment::X402Quote | ExecutionPayment::X402Settled(_) => "execute:x402",
    };
    let request_id = match payment {
        ExecutionPayment::X402Settled(settled) => {
            let quote_request_id = settled.quote_request_id.ok_or_else(|| {
                anyhow::anyhow!("x402 settlement is missing its quote_request_id")
            })?;
            let existing = db::get_idempotent_execution_request(
                pool,
                auth_context,
                req,
                operation,
                idempotency_key,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("x402 quote Idempotency-Key was not found"))?;
            if existing.id != quote_request_id {
                anyhow::bail!("x402 quote does not match Idempotency-Key");
            }
            quote_request_id
        }
        _ => {
            let (row, inserted) = db::reserve_execution_request(
                pool,
                auth_context,
                req,
                operation,
                idempotency_key,
                &smart_wallet_str,
                callback_url.as_deref(),
            )
            .await?;
            if !inserted {
                return existing_execution_response(row, &execution_token);
            }
            row.id
        }
    };
    if matches!(payment, ExecutionPayment::X402Settled(_)) {
        let existing = db::get_execution_request_for_organization(
            pool,
            request_id,
            auth_context.organization_id,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("x402 quote request no longer exists"))?;
        let existing_status = match existing.status.as_str() {
            "queued" => Some(ExecutionStatus::Queued),
            "broadcasting" => Some(ExecutionStatus::Broadcasting),
            "confirmed" => Some(ExecutionStatus::Confirmed),
            "reverted" => Some(ExecutionStatus::Reverted),
            _ => None,
        };
        if let Some(status) = existing_status {
            return Ok(ExecutionResponse {
                request_id,
                status,
                smart_wallet_address: existing.smart_wallet_address,
                estimated_gas: existing.gas_estimate.map(|value| value as u64),
                estimated_cost_usd: existing.cost_usd,
                execution_fee_token: Some(execution_token.symbol.clone()),
                execution_fee_raw: existing
                    .cost_usd
                    .map(|cost| usd_to_token_raw_amount(cost, execution_token.decimals))
                    .transpose()?
                    .map(|amount| amount.to_string()),
                tx_hash: existing.tx_hash,
                message: "x402 execution already accepted".into(),
            });
        }
    }
    let settled_x402_cost = if let ExecutionPayment::X402Settled(settled) = payment {
        let locked = db::get_locked_quote_cost(
            pool,
            auth_context.organization_id,
            request_id,
            req,
            &smart_wallet_str,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid, expired, or mismatched x402 quote"))?;
        validate_and_record_x402_payment(engine, pool, request_id, &chain, locked, settled).await?;
        db::update_execution_status(
            pool,
            request_id,
            &ExecutionStatus::PaymentVerified,
            None,
            Some(&format!("x402 {} payment settled", execution_token.symbol)),
            None,
            Some(locked),
        )
        .await?;
        Some(locked)
    } else {
        None
    };

    // 4. Simulate (using smart wallet as `from`)
    let sim =
        simulate_arc_request(engine, req, &chain, smart_wallet_address, None, request_id).await?;
    if !sim.success {
        db::update_execution_status(
            pool,
            request_id,
            &ExecutionStatus::Failed,
            None,
            sim.error.as_deref(),
            None,
            None,
        )
        .await?;

        return Ok(ExecutionResponse {
            request_id,
            status: ExecutionStatus::Failed,
            smart_wallet_address: Some(smart_wallet_str.clone()),
            estimated_gas: None,
            estimated_cost_usd: None,
            execution_fee_token: None,
            execution_fee_raw: None,
            tx_hash: None,
            message: format!("simulation failed: {}", sim.error.unwrap_or_default()),
        });
    }

    let quoted_cost = engine
        .estimate_arc_cost(&chain, sim.gas_estimate, simulation_fee_cap(&sim)?, true)
        .await?;
    let mut queued_req = req.clone();
    let mut final_sim = sim.clone();
    let mut atomic_execution_fee = None;
    let payable_cost = match payment {
        ExecutionPayment::X402Quote => {
            db::update_execution_status(
                pool,
                request_id,
                &ExecutionStatus::PaymentRequired,
                None,
                Some("x402 payment required"),
                Some(sim.gas_estimate as i64),
                Some(quoted_cost),
            )
            .await?;
            return Ok(ExecutionResponse {
                request_id,
                status: ExecutionStatus::PaymentRequired,
                smart_wallet_address: Some(smart_wallet_str),
                estimated_gas: Some(sim.gas_estimate),
                estimated_cost_usd: Some(quoted_cost),
                execution_fee_token: Some(execution_token.symbol.clone()),
                execution_fee_raw: Some(
                    usd_to_token_raw_amount(quoted_cost, execution_token.decimals)?.to_string(),
                ),
                tx_hash: None,
                message: "x402 payment required".into(),
            });
        }
        ExecutionPayment::X402Settled(settled) => {
            let _ = settled;
            settled_x402_cost.expect("x402 settlement was validated before simulation")
        }
        ExecutionPayment::AtomicExecutionToken => {
            let prepared = match prepare_atomic_fee_execution(
                engine,
                &chain,
                req,
                smart_wallet_address,
                request_id,
                quoted_cost,
            )
            .await
            {
                Ok(prepared) => prepared,
                Err(error) => {
                    let message = error.to_string();
                    db::update_execution_status(
                        pool,
                        request_id,
                        &ExecutionStatus::Failed,
                        None,
                        Some(&message),
                        Some(sim.gas_estimate as i64),
                        Some(quoted_cost),
                    )
                    .await?;
                    return Ok(ExecutionResponse {
                        request_id,
                        status: ExecutionStatus::Failed,
                        smart_wallet_address: Some(smart_wallet_str.clone()),
                        estimated_gas: Some(sim.gas_estimate),
                        estimated_cost_usd: Some(quoted_cost),
                        execution_fee_token: None,
                        execution_fee_raw: None,
                        tx_hash: None,
                        message,
                    });
                }
            };

            if !prepared.simulation.success {
                let reason = prepared
                    .simulation
                    .error
                    .clone()
                    .unwrap_or_else(|| "atomic execution-fee simulation failed".to_string());
                db::update_execution_status(
                    pool,
                    request_id,
                    &ExecutionStatus::Failed,
                    None,
                    Some(&reason),
                    None,
                    None,
                )
                .await?;
                return Ok(ExecutionResponse {
                    request_id,
                    status: ExecutionStatus::Failed,
                    smart_wallet_address: Some(smart_wallet_str.clone()),
                    estimated_gas: None,
                    estimated_cost_usd: Some(prepared.fee.amount_usd),
                    execution_fee_token: Some(prepared.fee.token_symbol),
                    execution_fee_raw: Some(prepared.fee.amount_raw),
                    tx_hash: None,
                    message: reason,
                });
            }

            final_sim = prepared.simulation;
            queued_req = prepared.request;
            let payable_cost = prepared.fee.amount_usd;
            atomic_execution_fee = Some(prepared.fee);
            db::update_execution_status(
                pool,
                request_id,
                &ExecutionStatus::PaymentVerified,
                None,
                Some(&format!(
                    "{} execution fee included in the sponsored atomic UserOperation",
                    execution_token.symbol
                )),
                Some(final_sim.gas_estimate as i64),
                Some(payable_cost),
            )
            .await?;
            payable_cost
        }
    };

    db::enforce_execution_fee_policy(pool, request_id, payable_cost).await?;
    if let Err(error) =
        db::reserve_policy_budget(pool, request_id, payable_cost, final_sim.gas_estimate).await
    {
        record_policy_denial(
            pool,
            auth_context,
            Some(agent.id),
            Some(request_id),
            "economic_budget",
            &error,
        )
        .await;
        return Err(error);
    }
    let permit_fee_raw = atomic_execution_fee
        .as_ref()
        .map(|fee| fee.amount_raw.as_str())
        .or(match payment {
            ExecutionPayment::X402Settled(settled) => settled.confirmed_amount_raw.as_deref(),
            _ => None,
        });
    let permit = db::issue_execution_permit(pool, request_id, permit_fee_raw, 300).await?;

    // Enqueue the immutable action and fee terms for ERC-4337 signing.
    let job = ExecutionJob {
        request_id,
        organization_id: auth_context.organization_id,
        execution_permit_id: permit.id,
        agent_id: req.agent_id.clone(),
        smart_wallet_address: smart_wallet_str.clone(),
        chain,
        target_contract: queued_req.target_contract.clone(),
        calldata: queued_req.calldata.clone(),
        value: queued_req.value.clone(),
        created_at: Utc::now(),
        attempt_count: 0,
        batch_calls: queued_req.batch_calls.clone(),
        callback_url,
        execution_fee: atomic_execution_fee.clone(),
    };
    queue::enqueue_job(redis_conn, &job).await?;

    db::update_execution_status(
        pool,
        request_id,
        &ExecutionStatus::Queued,
        None,
        None,
        None,
        None,
    )
    .await?;

    info!(
        request_id = %request_id,
        agent_id = %req.agent_id,
        has_callback = req.callback_url.is_some(),
        "execution request queued"
    );

    let message = if req.callback_url.is_some() {
        "execution queued — result will be POSTed to your callback URL".into()
    } else {
        "execution queued".into()
    };

    Ok(ExecutionResponse {
        request_id,
        status: ExecutionStatus::Queued,
        smart_wallet_address: Some(smart_wallet_str),
        estimated_gas: Some(final_sim.gas_estimate),
        estimated_cost_usd: Some(payable_cost),
        execution_fee_token: atomic_execution_fee
            .as_ref()
            .map(|fee| fee.token_symbol.clone()),
        execution_fee_raw: atomic_execution_fee
            .as_ref()
            .map(|fee| fee.amount_raw.clone()),
        tx_hash: None,
        message,
    })
}

fn existing_execution_response(
    row: db::models::ExecutionRequestRow,
    execution_token: &crate::config::ExecutionTokenConfig,
) -> Result<ExecutionResponse> {
    let status = parse_execution_status(&row.status)?;
    let execution_fee_raw = row
        .cost_usd
        .map(|cost| usd_to_token_raw_amount(cost, execution_token.decimals))
        .transpose()?
        .map(|amount| amount.to_string());
    Ok(ExecutionResponse {
        request_id: row.id,
        status,
        smart_wallet_address: row.smart_wallet_address,
        estimated_gas: row.gas_estimate.map(|value| value.max(0) as u64),
        estimated_cost_usd: row.cost_usd,
        execution_fee_token: execution_fee_raw
            .as_ref()
            .map(|_| execution_token.symbol.clone()),
        execution_fee_raw,
        tx_hash: row.tx_hash,
        message: "request already accepted for this Idempotency-Key".into(),
    })
}

fn parse_execution_status(status: &str) -> Result<ExecutionStatus> {
    Ok(match status {
        "pending" => ExecutionStatus::Pending,
        "payment_required" => ExecutionStatus::PaymentRequired,
        "payment_verified" => ExecutionStatus::PaymentVerified,
        "queued" => ExecutionStatus::Queued,
        "broadcasting" => ExecutionStatus::Broadcasting,
        "confirmed" => ExecutionStatus::Confirmed,
        "failed" => ExecutionStatus::Failed,
        "reverted" => ExecutionStatus::Reverted,
        other => anyhow::bail!("stored execution has unknown status {other}"),
    })
}

pub async fn handle_execution_status(
    pool: &PgPool,
    auth_context: &AuthContext,
    request_id: Uuid,
) -> Result<Option<StatusResponse>> {
    let Some(row) =
        db::get_execution_request_for_organization(pool, request_id, auth_context.organization_id)
            .await?
    else {
        return Ok(None);
    };
    let can_access = !auth_context.is_bound_to_other_agent(row.agent_uuid)
        && db::principal_can_access_agent(pool, auth_context.principal_id, row.agent_uuid).await?;
    if !can_access {
        db::insert_auth_audit_event(
            pool,
            auth_context,
            "execution:read",
            Some("/status/:id"),
            "deny",
            serde_json::json!({
                "reason": "agent_not_allowed",
                "request_id": row.id
            }),
        )
        .await?;
        return Ok(None);
    }

    Ok(Some(StatusResponse {
        request_id: row.id,
        status: parse_execution_status(&row.status)?,
        chain: row.chain,
        tx_hash: row.tx_hash,
        cost_usd: row.cost_usd,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }))
}

struct AtomicFeePreparation {
    request: ExecutionRequest,
    simulation: SimulationResult,
    fee: ExecutionFeeCharge,
}

async fn prepare_atomic_fee_execution(
    engine: &ExecutionEngine,
    chain: &Chain,
    request: &ExecutionRequest,
    smart_wallet: Address,
    request_id: Uuid,
    initial_cost_usd: f64,
) -> Result<AtomicFeePreparation> {
    let chain_cfg = engine.config.chain_config(chain)?.clone();
    let provider = engine.provider_for_chain(chain)?;
    let token = &chain_cfg.execution_token;

    let balance_raw = fetch_erc20_balance_of(provider.as_ref(), token.address, smart_wallet)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "{} execution-fee balance check failed: {error}",
                token.symbol
            )
        })?;

    let mut fee_usd = initial_cost_usd;
    let mut fee_raw = usd_to_token_raw_amount(fee_usd, token.decimals)?;
    let recipient = engine.config.execution_fee_recipient;
    let mut fee = ExecutionFeeCharge {
        token_symbol: token.symbol.clone(),
        token_contract: format!("{:?}", token.address),
        amount_raw: fee_raw.to_string(),
        amount_usd: fee_usd,
        recipient_address: format!("{recipient:?}"),
    };
    let mut simulation =
        simulate_arc_request(engine, request, chain, smart_wallet, Some(&fee), request_id).await?;

    // Phase 0 changes the gas estimate. Re-price until the token amount covers
    // the fee-inclusive sponsored UserOperation.
    for attempt in 0..3 {
        if !simulation.success {
            break;
        }

        let quoted_usd = engine
            .estimate_arc_cost(
                chain,
                simulation.gas_estimate,
                simulation_fee_cap(&simulation)?,
                true,
            )
            .await?;
        let quoted_raw = usd_to_token_raw_amount(quoted_usd, token.decimals)?;
        fee_usd = quoted_usd;
        if quoted_raw <= fee_raw {
            break;
        }
        if attempt == 2 {
            anyhow::bail!("atomic execution-fee quote did not converge after 3 simulations");
        }
        fee_raw = quoted_raw;
        fee.amount_raw = fee_raw.to_string();
        fee.amount_usd = fee_usd;
        simulation =
            simulate_arc_request(engine, request, chain, smart_wallet, Some(&fee), request_id)
                .await?;
    }

    if simulation.success && balance_raw < fee_raw {
        simulation = SimulationResult {
            success: false,
            gas_estimate: 0,
            max_fee_per_gas_wei: simulation.max_fee_per_gas_wei.clone(),
            return_data: None,
            error: Some(format!(
                "insufficient {} balance for atomic execution fee: balance={}, required={}",
                token.symbol, balance_raw, fee_raw
            )),
        };
    }
    fee_usd = fee_raw
        .to_string()
        .parse::<f64>()
        .context("execution-fee amount is too large to report")?
        / 10f64.powi(token.decimals as i32);
    fee.amount_raw = fee_raw.to_string();
    fee.amount_usd = fee_usd;

    Ok(AtomicFeePreparation {
        request: request.clone(),
        simulation,
        fee,
    })
}

pub(crate) async fn fetch_erc20_balance_of(
    provider: &crate::arc::rpc::ArcRpcClient,
    token_contract: Address,
    wallet: Address,
) -> Result<U256> {
    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
    let mut addr_slot = [0u8; 32];
    addr_slot[12..32].copy_from_slice(wallet.as_bytes());
    data.extend_from_slice(&addr_slot);

    let raw = provider.call(token_contract, &data).await?;
    if raw.0.len() < 32 {
        anyhow::bail!("short balanceOf return data length {}", raw.0.len());
    }

    let mut amount_slot = [0u8; 32];
    amount_slot.copy_from_slice(&raw.0[raw.0.len() - 32..]);
    Ok(U256::from_big_endian(&amount_slot))
}

pub async fn validate_execution_token(engine: &ExecutionEngine) -> Result<()> {
    let chain = if engine.config.arc_network == crate::arc::ArcNetwork::Testnet {
        Chain::ArcTestnet
    } else {
        Chain::Arc
    };
    let chain_config = engine.config.chain_config(&chain)?;
    let provider = engine.provider_for_chain(&chain)?;
    let configured = &chain_config.execution_token;
    let code = provider.get_code(configured.address).await?;
    if code.is_empty() {
        anyhow::bail!(
            "configured {} execution token has no bytecode at {:?}",
            configured.symbol,
            configured.address
        );
    }

    let symbol = read_erc20_symbol(provider.as_ref(), configured.address).await?;
    if symbol != configured.symbol {
        anyhow::bail!(
            "execution token symbol mismatch at {:?}: expected {}, got {}",
            configured.address,
            configured.symbol,
            symbol
        );
    }
    let decimals = read_erc20_decimals(provider.as_ref(), configured.address).await?;
    if decimals != configured.decimals {
        anyhow::bail!(
            "execution token decimals mismatch at {:?}: expected {}, got {}",
            configured.address,
            configured.decimals,
            decimals
        );
    }
    Ok(())
}

async fn read_erc20_symbol(
    provider: &crate::arc::rpc::ArcRpcClient,
    token: Address,
) -> Result<String> {
    let raw = provider
        .call(token, &[0x95, 0xd8, 0x9b, 0x41])
        .await
        .context("execution token symbol() call failed")?;
    decode(&[ParamType::String], &raw)
        .context("execution token symbol() returned malformed ABI")?
        .into_iter()
        .next()
        .and_then(|token| token.into_string())
        .filter(|symbol| !symbol.is_empty())
        .ok_or_else(|| anyhow::anyhow!("execution token symbol() returned an empty value"))
}

async fn read_erc20_decimals(
    provider: &crate::arc::rpc::ArcRpcClient,
    token: Address,
) -> Result<u8> {
    let raw = provider
        .call(token, &[0x31, 0x3c, 0xe5, 0x67])
        .await
        .context("execution token decimals() call failed")?;
    if raw.len() != 32 {
        anyhow::bail!(
            "execution token decimals() returned {} bytes instead of 32",
            raw.len()
        );
    }
    let value = U256::from_big_endian(&raw);
    if value > U256::from(u8::MAX) {
        anyhow::bail!("execution token decimals() exceeds uint8");
    }
    Ok(value.as_u32() as u8)
}

pub async fn arc_fee_recipient_status(engine: &ExecutionEngine) -> Result<serde_json::Value> {
    let chain = if engine.config.arc_network == crate::arc::ArcNetwork::Testnet {
        Chain::ArcTestnet
    } else {
        Chain::Arc
    };
    let chain_config = engine.config.chain_config(&chain)?;
    let provider = engine.provider_for_chain(&chain)?;
    let recipient = engine.config.execution_fee_recipient;
    let token = &chain_config.execution_token;
    let recipient_token_balance =
        fetch_erc20_balance_of(provider.as_ref(), token.address, recipient).await?;

    Ok(serde_json::json!({
        "network": engine.config.arc_network.name(),
        "chain_id": chain_config.chain_id,
        "gas_sponsor": "alchemy_gas_manager",
        "max_sponsored_gas_units": engine.config.arc_max_sponsored_gas_units,
        "max_sponsored_gas_cost_wei": engine.config.arc_max_sponsored_gas_cost_wei.to_string(),
        "execution_fee_recipient": format!("{recipient:?}"),
        "execution_token": format!("{:?}", token.address),
        "execution_token_balance_raw": recipient_token_balance.to_string(),
        "execution_token_symbol": token.symbol,
        "execution_token_decimals": token.decimals
    }))
}

async fn validate_and_record_x402_payment(
    engine: &ExecutionEngine,
    pool: &PgPool,
    request_id: Uuid,
    chain: &Chain,
    cost: f64,
    payment: &SettledExecutionPayment,
) -> Result<()> {
    let chain_cfg = engine.config.chain_config(chain)?;
    let token = &chain_cfg.execution_token;
    if payment.token != token.symbol {
        anyhow::bail!("x402 execution fees must be paid in {}", token.symbol);
    }
    if payment.chain != chain.to_string() {
        anyhow::bail!("x402 settlement chain does not match execution chain");
    }
    if payment
        .token_contract
        .as_deref()
        .and_then(|address| address.parse::<Address>().ok())
        != Some(token.address)
    {
        anyhow::bail!("x402 settlement asset does not match configured execution token");
    }
    let confirmed = payment
        .confirmed_amount_raw
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("x402 settlement omitted confirmed_amount_raw"))
        .and_then(|raw| {
            U256::from_dec_str(raw)
                .map_err(|error| anyhow::anyhow!("invalid x402 settlement amount: {error}"))
        })?;
    let required = usd_to_token_raw_amount(cost, token.decimals)?;
    if confirmed < required {
        anyhow::bail!(
            "x402 underpayment: paid {} raw {}, required {}",
            confirmed,
            token.symbol,
            required
        );
    }
    let inserted = db::insert_payment(pool, request_id, payment).await?;
    if inserted.is_none() {
        let existing = db::get_verified_payment_for_request(pool, request_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("x402 payment tx {} has already been used", payment.tx_hash)
            })?;
        if !existing
            .payment_tx_hash
            .eq_ignore_ascii_case(&payment.tx_hash)
            || !existing.payer.eq_ignore_ascii_case(&payment.payer)
            || existing.token != payment.token
            || payment
                .confirmed_amount_raw
                .as_deref()
                .is_none_or(|amount| amount != existing.amount_raw)
            || payment
                .token_contract
                .as_deref()
                .is_none_or(|token| !token.eq_ignore_ascii_case(&existing.token_contract))
            || existing.payment_chain != payment.chain
        {
            anyhow::bail!("x402 payment transaction is bound to another execution");
        }
    }
    Ok(())
}

/// Resolve the agent's smart wallet and return Arc USDC once.
pub async fn handle_get_wallet_balance(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    agent_id: &str,
    chain_str: &str,
) -> Result<WalletBalanceResponse> {
    let chain = Chain::from_str_loose(chain_str)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {chain_str}"))?;

    let chain_cfg = engine
        .config
        .chains
        .get(&chain)
        .ok_or_else(|| anyhow::anyhow!("chain {chain_str} is not configured"))?
        .clone();

    let provider = engine.provider_for_chain(&chain)?;

    // Resolve (or provision) the agent's smart wallet
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let smart_wallet_str = format!("{smart_wallet_address:?}");

    // Arc native and ERC-20 USDC are one balance. Use the six-decimal interface
    // for the one user-visible balance and execution-fee checks.
    let raw_balance = fetch_erc20_balance_of(
        provider.as_ref(),
        chain_cfg.execution_token.address,
        smart_wallet_address,
    )
    .await?;
    let formatted = format_units(raw_balance, chain_cfg.execution_token.decimals as usize)?;
    let tokens = vec![TokenBalance {
        symbol: chain_cfg.execution_token.symbol,
        contract_address: format!("{:?}", chain_cfg.execution_token.address),
        raw: raw_balance.to_string(),
        formatted,
        decimals: chain_cfg.execution_token.decimals,
    }];

    Ok(WalletBalanceResponse {
        agent_id: agent_id.to_string(),
        smart_wallet_address: smart_wallet_str,
        chain: chain.to_string(),
        tokens,
    })
}

/// Handle a simulation-only request (no payment, no queue).
pub async fn handle_simulate_authenticated(
    engine: &ExecutionEngine,
    pool: &PgPool,
    wallet_registry: &AgentWalletRegistry,
    auth_context: &AuthContext,
    req: &ExecutionRequest,
) -> Result<ExecutionResponse> {
    let chain = engine.validate(req)?;
    let (agent, policy) = db::authorize_execution_agent(pool, auth_context, &req.agent_id).await?;
    if let Err(error) = crate::auth::enforce_compiled_execution_limits(&policy, req) {
        record_policy_denial(
            pool,
            auth_context,
            Some(agent.id),
            None,
            "simulation",
            &error,
        )
        .await;
        return Err(error);
    }
    let agent_wallet = wallet_registry
        .get_or_create(auth_context.organization_id, &req.agent_id)
        .await?;
    let smart_wallet_address =
        resolve_chain_smart_wallet_address(engine, &chain, &agent_wallet).await?;
    let smart_wallet_str = format!("{smart_wallet_address:?}");
    let db_row = db::insert_execution_request(
        pool,
        auth_context,
        req,
        &ExecutionStatus::Pending,
        Some(&smart_wallet_str),
        None,
    )
    .await?;
    let request_id = db_row.id;
    let initial_sim =
        simulate_arc_request(engine, req, &chain, smart_wallet_address, None, request_id).await?;
    let (sim, cost, execution_fee) = if initial_sim.success {
        let initial_cost = engine
            .estimate_arc_cost(
                &chain,
                initial_sim.gas_estimate,
                simulation_fee_cap(&initial_sim)?,
                true,
            )
            .await?;
        let prepared = prepare_atomic_fee_execution(
            engine,
            &chain,
            req,
            smart_wallet_address,
            request_id,
            initial_cost,
        )
        .await?;
        let cost = prepared
            .simulation
            .success
            .then_some(prepared.fee.amount_usd);
        (prepared.simulation, cost, Some(prepared.fee))
    } else {
        (initial_sim, None, None)
    };

    db::update_execution_status(
        pool,
        request_id,
        if sim.success {
            &ExecutionStatus::Pending
        } else {
            &ExecutionStatus::Failed
        },
        None,
        sim.error.as_deref(),
        Some(sim.gas_estimate as i64),
        cost,
    )
    .await?;

    Ok(ExecutionResponse {
        request_id,
        status: if sim.success {
            ExecutionStatus::Pending
        } else {
            ExecutionStatus::Failed
        },
        smart_wallet_address: Some(smart_wallet_str),
        estimated_gas: Some(sim.gas_estimate),
        estimated_cost_usd: cost,
        execution_fee_token: execution_fee.as_ref().map(|fee| fee.token_symbol.clone()),
        execution_fee_raw: execution_fee.as_ref().map(|fee| fee.amount_raw.clone()),
        tx_hash: None,
        message: if sim.success {
            "simulation succeeded".into()
        } else {
            format!("simulation failed: {}", sim.error.unwrap_or_default())
        },
    })
}

fn simulation_fee_cap(simulation: &SimulationResult) -> Result<U256> {
    let raw = simulation
        .max_fee_per_gas_wei
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Arc simulation omitted max fee per gas"))?;
    U256::from_dec_str(raw).context("Arc simulation returned invalid max fee per gas")
}

/// Handle a wallet lookup — return the agent's smart wallet address.
///
/// This is a lightweight endpoint that lets agents discover their wallet
/// address so they can fund it with tokens before submitting execute requests.
pub async fn handle_get_wallet(
    engine: &ExecutionEngine,
    wallet_registry: &AgentWalletRegistry,
    organization_id: Uuid,
    agent_id: &str,
    chain: &str,
) -> Result<crate::types::WalletResponse> {
    use crate::types::WalletResponse;

    // Validate chain
    let resolved_chain = crate::types::Chain::from_str_loose(chain)
        .ok_or_else(|| anyhow::anyhow!("unsupported chain: {chain}"))?;

    // Validate agent_id
    if agent_id.trim().is_empty() {
        return Err(anyhow::anyhow!("agent_id is required"));
    }
    if agent_id.len() > 256 {
        return Err(anyhow::anyhow!("agent_id too long (max 256 characters)"));
    }

    // Resolve or create the smart wallet
    let agent_wallet = wallet_registry
        .get_or_create(organization_id, agent_id)
        .await?;
    let smart_wallet_addr =
        resolve_chain_smart_wallet_address(engine, &resolved_chain, &agent_wallet).await?;

    // A counterfactual ERC-4337 account is fundable before deployment.
    let provider = engine.provider_for_chain(&resolved_chain)?;
    let code = provider.get_code(smart_wallet_addr).await?;
    let deployed = !code.is_empty();

    let smart_wallet_str = format!("{smart_wallet_addr:?}");

    let message = if deployed {
        format!(
            "Arc smart account is deployed. Fund {smart_wallet_str} with USDC or assets required by your action.",
        )
    } else {
        format!(
            "This Arc smart account is ready to fund at {smart_wallet_str}. It deploys with its first sponsored UserOperation.",
        )
    };

    Ok(WalletResponse {
        agent_id: agent_id.to_string(),
        smart_wallet_address: smart_wallet_str,
        deployed,
        message,
    })
}

// ──────────────────────── Helpers ────────────────────────────────────
