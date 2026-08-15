//! Reliable Base native-AA execution worker.

use anyhow::{bail, Context, Result};
use ethers::{
    types::{H256, U256},
    utils::keccak256,
};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use std::str::FromStr;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    agent_wallet::AgentWalletRegistry,
    db,
    execution_engine::{pricing::usd_to_token_raw_amount, ExecutionEngine},
    native_aa::{execution_calls, NativeAaClient, NativeExecutionResult},
    queue::{self, MAX_JOB_ATTEMPTS},
    types::{ExecutionJob, ExecutionRequest, ExecutionStatus, SettledExecutionPayment},
    wallet_provider::ManagedWallet,
    webhook,
};

#[derive(Clone)]
pub struct WorkerContext {
    pub db_pool: PgPool,
    pub wallet_registry: AgentWalletRegistry,
    pub payer_wallet: ManagedWallet,
    pub engine: ExecutionEngine,
    pub native_client: NativeAaClient,
    pub webhook_client: reqwest::Client,
    pub webhook_encryption_key: String,
}

pub async fn run_worker(mut redis_conn: ConnectionManager, ctx: WorkerContext, worker_id: u32) {
    info!(worker_id, "native AA worker started");
    loop {
        let job = match queue::dequeue_job(&mut redis_conn, 5.0, worker_id).await {
            Ok(Some(job)) => job,
            Ok(None) => continue,
            Err(error) => {
                error!(worker_id, %error, "failed to dequeue job");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };

        if job.attempt_count >= MAX_JOB_ATTEMPTS {
            terminal_failure(
                &mut redis_conn,
                &ctx,
                &job,
                worker_id,
                &format!("exceeded {MAX_JOB_ATTEMPTS} execution attempts"),
            )
            .await;
            continue;
        }

        let _ = db::update_execution_status(
            &ctx.db_pool,
            job.request_id,
            &ExecutionStatus::Broadcasting,
            None,
            None,
            None,
            None,
        )
        .await;

        match execute_native(&ctx, &job).await {
            Ok(result) => {
                finalize_onchain_result(&mut redis_conn, &ctx, &job, worker_id, result).await;
            }
            Err(error) => {
                error!(
                    request_id = %job.request_id,
                    attempt = job.attempt_count + 1,
                    error = ?error,
                    "native AA execution attempt failed"
                );
                re_enqueue_with_bump(
                    &mut redis_conn,
                    &ctx,
                    &job,
                    worker_id,
                    &format!("{error:#}"),
                )
                .await;
            }
        }
    }
}

async fn execute_native(ctx: &WorkerContext, job: &ExecutionJob) -> Result<NativeExecutionResult> {
    if job.chain != crate::types::Chain::Base {
        bail!("Beta execution is Base-only");
    }
    let execution_record = db::get_execution_request_for_organization(
        &ctx.db_pool,
        job.request_id,
        job.organization_id,
    )
    .await?
    .ok_or_else(|| anyhow::anyhow!("queued execution does not belong to the organization"))?;
    let permit =
        db::claim_execution_permit(&ctx.db_pool, job.execution_permit_id, job.request_id).await?;
    if permit.organization_id != job.organization_id
        || !permit
            .wallet_address
            .eq_ignore_ascii_case(&job.smart_wallet_address)
        || permit.chain != job.chain.to_string()
    {
        bail!("queued execution does not match its authorization permit");
    }
    let queued_request = ExecutionRequest {
        agent_id: job.agent_id.clone(),
        chain: job.chain.to_string(),
        target_contract: job.target_contract.clone(),
        calldata: job.calldata.clone(),
        value: job.value.clone(),
        strategy_id: None,
        batch_calls: job.batch_calls.clone(),
        callback_url: job.callback_url.clone(),
    };
    if db::execution_payload_hash(&queued_request)? != execution_record.payload_hash
        || execution_record.agent_id != job.agent_id
        || execution_record
            .smart_wallet_address
            .as_deref()
            .is_none_or(|address| !address.eq_ignore_ascii_case(&job.smart_wallet_address))
        || execution_record.callback_url != job.callback_url
    {
        bail!("queued execution does not match its authenticated database record");
    }
    let execution_token = &ctx.engine.config.chain_config(&job.chain)?.execution_token;
    if let Some(fee) = &job.execution_fee {
        let authorized_fee_raw = usd_to_token_raw_amount(
            execution_record
                .cost_usd
                .ok_or_else(|| anyhow::anyhow!("execution record omitted its authorized fee"))?,
            execution_token.decimals,
        )?;
        let queued_fee_raw = U256::from_dec_str(&fee.amount_raw)
            .context("queued execution fee amount is invalid")?;
        if queued_fee_raw != authorized_fee_raw {
            bail!("queued execution fee differs from the authenticated quote");
        }
        if permit.execution_fee_raw.as_deref() != Some(fee.amount_raw.as_str()) {
            bail!("queued execution fee differs from its authorization permit");
        }
    } else {
        let settled_fee = db::get_verified_payment_for_request(&ctx.db_pool, job.request_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("verified x402 payment record disappeared"))?;
        if permit.execution_fee_raw.as_deref() != Some(settled_fee.amount_raw.as_str()) {
            bail!("settled x402 fee differs from its authorization permit");
        }
    }
    let wallet = ctx
        .wallet_registry
        .get_existing(job.organization_id, &job.agent_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent wallet no longer exists"))?;
    if job.execution_fee.is_none()
        && !db::has_verified_payment(&ctx.db_pool, job.request_id).await?
    {
        bail!("payer-funded execution has neither an in-transaction fee nor verified x402 payment");
    }
    let expected = format!("{:?}", wallet.address);
    if !expected.eq_ignore_ascii_case(&job.smart_wallet_address) {
        bail!("queued wallet address does not match the organization-owned managed account");
    }

    // EIP-8130 sequenced nonces are per sender. Serialize prepare-through-
    // receipt across every worker and application instance so two jobs cannot
    // sign different transactions with the same nonce.
    let mut nonce_lock = ctx.db_pool.begin().await?;
    let lock_digest = keccak256(wallet.address.as_bytes());
    let lock_key = i64::from_be_bytes(lock_digest[..8].try_into().expect("fixed digest length"));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *nonce_lock)
        .await
        .context("failed to acquire wallet nonce lock")?;

    let expected_phases = if job.execution_fee.is_some() { 2 } else { 1 };
    if let Some(stored) = db::get_signed_transaction(&ctx.db_pool, job.request_id).await? {
        if permit.consumed_at.is_none() {
            bail!("persisted native transaction has an unconsumed authorization permit");
        }
        if stored.transaction_phase_count != expected_phases {
            bail!("persisted native transaction has an invalid phase count");
        }
        let raw = hex::decode(stored.signed_transaction.trim_start_matches("0x"))
            .context("persisted signed transaction is invalid hex")?;
        let local_hash = H256::from(keccak256(&raw));
        let stored_hash = H256::from_str(&stored.signed_transaction_hash)
            .context("persisted transaction hash is invalid")?;
        if local_hash != stored_hash {
            bail!("persisted signed transaction hash mismatch");
        }
        let result = ctx
            .native_client
            .broadcast_raw_and_wait(&raw, expected_phases as usize)
            .await;
        nonce_lock.rollback().await?;
        return result;
    }

    if permit.consumed_at.is_some() {
        bail!("authorization permit was consumed without a persisted signed transaction");
    }

    let calls = execution_calls(
        &job.target_contract,
        &job.calldata,
        &job.value,
        job.batch_calls.as_deref(),
    )?;
    let prepared = ctx
        .native_client
        .prepare(
            wallet.address,
            job.execution_fee.as_ref(),
            &calls,
            job.request_id,
        )
        .await?;
    let required_fee_usd = ctx
        .engine
        .estimate_native_cost(
            &job.chain,
            prepared.transaction().gas_limit.as_u64(),
            prepared.transaction().max_fee_per_gas,
            true,
        )
        .await?;
    let paid_fee_raw = match &job.execution_fee {
        Some(fee) => {
            U256::from_dec_str(&fee.amount_raw).context("queued execution fee amount is invalid")?
        }
        None => db::get_verified_payment_for_request(&ctx.db_pool, job.request_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("verified x402 payment record disappeared"))?
            .amount_raw
            .parse::<U256>()
            .context("persisted x402 payment amount is invalid")?,
    };
    let required_fee_raw = usd_to_token_raw_amount(required_fee_usd, execution_token.decimals)?;
    if paid_fee_raw < required_fee_raw {
        bail!(
            "execution fee no longer covers current gas quote: paid {paid_fee_raw} raw {}, required {required_fee_raw}",
            execution_token.symbol
        );
    }
    let signed = ctx
        .native_client
        .sign(
            prepared,
            ctx.wallet_registry.wallet_manager(),
            &wallet.managed_wallet,
            &ctx.payer_wallet,
            job.request_id,
            job.execution_fee.as_ref(),
        )
        .await?;
    let raw = signed.serialize()?;
    let tx_hash = H256::from(keccak256(&raw));
    db::store_signed_transaction_and_consume_permit(
        &ctx.db_pool,
        job.request_id,
        permit.id,
        &format!("0x{}", hex::encode(&raw)),
        &format!("{tx_hash:?}"),
        signed.phases.len() as i16,
    )
    .await?;
    let result = ctx
        .native_client
        .broadcast_raw_and_wait(&raw, signed.phases.len())
        .await;
    nonce_lock.rollback().await?;
    result
}

async fn finalize_onchain_result(
    redis_conn: &mut ConnectionManager,
    ctx: &WorkerContext,
    job: &ExecutionJob,
    worker_id: u32,
    result: NativeExecutionResult,
) {
    let tx_hash = format!("{:?}", result.tx_hash);
    if job.execution_fee.is_some() && result.fee_phase_succeeded() {
        record_execution_fee(ctx, job, &tx_hash).await;
    }

    let (status, error_message) = if result.all_phases_succeeded() {
        (ExecutionStatus::Confirmed, None)
    } else {
        (
            ExecutionStatus::Reverted,
            Some("protocol action phase reverted"),
        )
    };
    if let Err(error) = db::update_execution_status(
        &ctx.db_pool,
        job.request_id,
        &status,
        Some(&tx_hash),
        error_message,
        result.gas_used.map(|value| value as i64),
        None,
    )
    .await
    {
        error!(request_id = %job.request_id, %error, "failed to persist terminal status");
    }
    if let Err(error) = db::insert_transaction(
        &ctx.db_pool,
        job.request_id,
        &job.chain.to_string(),
        &tx_hash,
        &job.smart_wallet_address,
        &job.target_contract,
        &status.to_string(),
    )
    .await
    {
        warn!(request_id = %job.request_id, %error, "failed to persist transaction record");
    }
    fire_webhook(
        ctx,
        job,
        &status,
        Some(&tx_hash),
        job.execution_fee.as_ref().map(|fee| fee.amount_usd),
        error_message,
    )
    .await;
    if let Err(error) = queue::ack_job(redis_conn, job, worker_id).await {
        error!(request_id = %job.request_id, %error, "failed to acknowledge terminal job");
    }
}

async fn record_execution_fee(ctx: &WorkerContext, job: &ExecutionJob, tx_hash: &str) {
    let Some(fee) = &job.execution_fee else {
        return;
    };
    let payment = SettledExecutionPayment {
        payment_id: Uuid::new_v4(),
        quote_request_id: Some(job.request_id),
        payer: job.smart_wallet_address.clone(),
        amount_usd: fee.amount_usd,
        token: fee.token_symbol.clone(),
        chain: job.chain.to_string(),
        tx_hash: tx_hash.to_string(),
        confirmed_amount_raw: Some(fee.amount_raw.clone()),
        token_contract: Some(fee.token_contract.clone()),
    };
    if let Err(error) = db::insert_payment(&ctx.db_pool, job.request_id, &payment).await {
        error!(
            request_id = %job.request_id,
            %error,
            "on-chain execution fee could not be recorded"
        );
    }
}

async fn terminal_failure(
    redis_conn: &mut ConnectionManager,
    ctx: &WorkerContext,
    job: &ExecutionJob,
    worker_id: u32,
    reason: &str,
) {
    let _ = db::update_execution_status(
        &ctx.db_pool,
        job.request_id,
        &ExecutionStatus::Failed,
        None,
        Some(reason),
        None,
        None,
    )
    .await;
    fire_webhook(ctx, job, &ExecutionStatus::Failed, None, None, Some(reason)).await;
    if let Err(error) = queue::move_to_dlq(redis_conn, job, worker_id).await {
        error!(request_id = %job.request_id, %error, "failed to move terminal job to DLQ");
    }
}

async fn re_enqueue_with_bump(
    redis_conn: &mut ConnectionManager,
    ctx: &WorkerContext,
    job: &ExecutionJob,
    worker_id: u32,
    last_error: &str,
) {
    if let Err(error) = queue::ack_job(redis_conn, job, worker_id).await {
        warn!(request_id = %job.request_id, %error, "failed to ack before retry");
    }
    let mut bumped = job.clone();
    bumped.attempt_count += 1;
    if bumped.attempt_count >= MAX_JOB_ATTEMPTS {
        terminal_failure(redis_conn, ctx, &bumped, worker_id, last_error).await;
        return;
    }
    if let Err(error) = queue::enqueue_job(redis_conn, &bumped).await {
        error!(request_id = %job.request_id, %error, "failed to re-enqueue job");
    }
}

async fn fire_webhook(
    ctx: &WorkerContext,
    job: &ExecutionJob,
    status: &ExecutionStatus,
    tx_hash: Option<&str>,
    cost_usd: Option<f64>,
    error_msg: Option<&str>,
) {
    let Some(callback_url) = job.callback_url.as_ref().filter(|url| !url.is_empty()) else {
        return;
    };
    let signing_secret = match db::get_webhook_secret_by_organization(
        &ctx.db_pool,
        job.organization_id,
        &ctx.webhook_encryption_key,
    )
    .await
    {
        Ok(Some(secret)) => secret,
        Ok(None) => return,
        Err(error) => {
            warn!(organization_id = %job.organization_id, %error, "webhook secret unavailable");
            return;
        }
    };
    let payload = webhook::WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: "execution.completed".into(),
        request_id: job.request_id,
        status: status.clone(),
        chain: job.chain.to_string(),
        tx_hash: tx_hash.map(str::to_string),
        cost_usd,
        error: error_msg.map(str::to_string),
        created_at: job.created_at,
        completed_at: chrono::Utc::now(),
    };
    let client = ctx.webhook_client.clone();
    let callback_url = callback_url.clone();
    tokio::spawn(async move {
        webhook::deliver(&client, &callback_url, &payload, &signing_secret).await;
    });
}
