//! Durable Arc ERC-4337 execution worker.

use anyhow::{bail, Context, Result};
use ethers_core::{
    types::{Address, U256},
    utils::keccak256,
};
use redis::aio::ConnectionManager;
use sqlx::PgPool;
use tracing::{error, info, warn};
use uuid::Uuid;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{
    agent_wallet::AgentWalletRegistry,
    arc::execution::{
        execution_calls, fee_transfer_call, ArcExecutionReceipt, ArcOperationRejected,
        SignedUserOperation,
    },
    db,
    execution_engine::ExecutionEngine,
    queue::{self, MAX_JOB_ATTEMPTS},
    types::{ExecutionJob, ExecutionRequest, ExecutionStatus, SettledExecutionPayment},
    webhook,
};

#[cfg(test)]
static INTERRUPT_AFTER_SUBMISSION: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
pub struct WorkerContext {
    pub db_pool: PgPool,
    pub wallet_registry: AgentWalletRegistry,
    pub engine: ExecutionEngine,
    pub webhook_encryption_key: String,
}

pub async fn run_worker(mut redis_conn: ConnectionManager, ctx: WorkerContext, worker_id: u32) {
    info!(worker_id, "Arc ERC-4337 worker started");
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
        match db::get_execution_request_for_organization(
            &ctx.db_pool,
            job.request_id,
            job.organization_id,
        )
        .await
        {
            Ok(Some(record)) if is_terminal_status(&record.status) => {
                if let Err(error) = queue::ack_job(&mut redis_conn, &job, worker_id).await {
                    error!(request_id = %job.request_id, %error, "failed to acknowledge completed job");
                }
                continue;
            }
            Ok(_) => {}
            Err(error) => {
                error!(request_id = %job.request_id, %error, "cannot inspect execution status");
                re_enqueue_with_bump(&mut redis_conn, &ctx, &job, worker_id, &error.to_string())
                    .await;
                continue;
            }
        }
        let already_signed = match db::get_signed_user_operation(&ctx.db_pool, job.request_id).await
        {
            Ok(value) => value.is_some(),
            Err(error) => {
                error!(request_id = %job.request_id, %error, "cannot inspect execution recovery state");
                re_enqueue_with_bump(&mut redis_conn, &ctx, &job, worker_id, &error.to_string())
                    .await;
                continue;
            }
        };
        if job.attempt_count >= MAX_JOB_ATTEMPTS && !already_signed {
            terminal_failure(
                &mut redis_conn,
                &ctx,
                &job,
                worker_id,
                "execution attempts exhausted before signing",
            )
            .await;
            continue;
        }
        match execute_arc(&ctx, &job).await {
            Ok(Some(receipt)) => {
                if let Err(error) =
                    finalize_onchain_result(&mut redis_conn, &ctx, &job, worker_id, receipt).await
                {
                    error!(request_id = %job.request_id, %error, "failed to finalize Arc execution");
                    re_enqueue_with_bump(
                        &mut redis_conn,
                        &ctx,
                        &job,
                        worker_id,
                        &error.to_string(),
                    )
                    .await;
                }
            }
            Ok(None) => {
                if let Err(error) = queue::ack_job(&mut redis_conn, &job, worker_id).await {
                    error!(request_id = %job.request_id, %error, "failed to acknowledge completed job");
                }
            }
            Err(error) => {
                error!(request_id = %job.request_id, attempt = job.attempt_count + 1,
                    error = ?error, "Arc execution attempt failed");
                if error.downcast_ref::<ArcOperationRejected>().is_some() {
                    terminal_failure(&mut redis_conn, &ctx, &job, worker_id, &error.to_string())
                        .await;
                } else {
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
}

fn is_terminal_status(status: &str) -> bool {
    matches!(status, "confirmed" | "reverted" | "failed")
}

async fn execute_arc(
    ctx: &WorkerContext,
    job: &ExecutionJob,
) -> Result<Option<ArcExecutionReceipt>> {
    ctx.engine.config.chain_config(&job.chain)?;
    if job.chain.chain_id() != ctx.engine.config.arc_network.chain_id() {
        bail!("queued execution targets a different Arc network");
    }
    let record = db::get_execution_request_for_organization(
        &ctx.db_pool,
        job.request_id,
        job.organization_id,
    )
    .await?
    .context("queued execution does not belong to the organization")?;
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
        policy_impact: serde_json::from_value(record.policy_impact.clone())
            .context("stored execution policy impact is invalid")?,
    };
    if db::execution_payload_hash(&queued_request)? != record.payload_hash
        || record.agent_id != job.agent_id
        || record
            .smart_wallet_address
            .as_deref()
            .is_none_or(|address| !address.eq_ignore_ascii_case(&job.smart_wallet_address))
        || record.callback_url != job.callback_url
    {
        bail!("queued execution differs from its authenticated record");
    }
    let token = &ctx.engine.config.chain_config(&job.chain)?.execution_token;
    if let Some(fee) = &job.execution_fee {
        if record.cost_usd.is_none()
            || U256::from_dec_str(&fee.amount_raw)
                .context("invalid queued fee")?
                .is_zero()
            || permit.execution_fee_raw.as_deref() != Some(fee.amount_raw.as_str())
            || fee.token_contract.parse::<Address>().ok() != Some(token.address)
            || fee.recipient_address.parse::<Address>().ok()
                != Some(ctx.engine.config.execution_fee_recipient)
        {
            bail!("queued fee differs from authorized Arc fee");
        }
    } else {
        let settled = db::get_verified_payment_for_request(&ctx.db_pool, job.request_id)
            .await?
            .context("verified x402 payment disappeared")?;
        if permit.execution_fee_raw.as_deref() != Some(settled.amount_raw.as_str()) {
            bail!("settled x402 fee differs from its authorization permit");
        }
    }
    let mut calls = execution_calls(
        &job.target_contract,
        &job.calldata,
        &job.value,
        job.batch_calls.as_deref(),
    )?;
    if let Some(fee) = &job.execution_fee {
        calls.insert(0, fee_transfer_call(fee)?);
    }

    // A transaction-scoped advisory lock covers preparation through receipt, so
    // two workers cannot prepare different nonces for the same smart account.
    let queued_account = job
        .smart_wallet_address
        .parse::<Address>()
        .context("queued smart-wallet address is invalid")?;
    if queued_account == Address::zero() {
        bail!("queued smart-wallet address cannot be zero");
    }
    let mut nonce_lock = ctx.db_pool.begin().await?;
    let digest = keccak256(queued_account.as_bytes());
    let lock_key = i64::from_be_bytes(digest[..8].try_into().expect("fixed digest length"));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *nonce_lock)
        .await
        .context("failed to acquire Arc account lock")?;
    // Resolve custody only after taking the account lock. This prevents an
    // execution from retaining the old signer while a concurrent rotation
    // changes ownership and reconciles the database binding.
    let wallet = ctx
        .wallet_registry
        .get_existing(job.organization_id, &job.agent_id)
        .await?
        .context("agent wallet no longer exists")?;
    let account = ctx
        .engine
        .smart_accounts
        .get_or_create(&wallet, ctx.engine.config.arc_network)
        .await?;
    if account.address != queued_account
        || account.signer_address != wallet.managed_wallet.provider_wallet.address
    {
        bail!("queued wallet does not match the tenant-owned Arc smart account");
    }
    let current = db::get_execution_request(&ctx.db_pool, job.request_id)
        .await?
        .context("queued execution disappeared")?;
    if is_terminal_status(&current.status) {
        nonce_lock.rollback().await?;
        return Ok(None);
    }

    let stored = db::get_signed_user_operation(&ctx.db_pool, job.request_id).await?;
    let (signed, call_id) = if let Some(stored) = stored {
        if permit.consumed_at.is_none() {
            bail!("signed UserOperation has an unconsumed permit");
        }
        let signed: SignedUserOperation = serde_json::from_value(stored.signed_user_operation)
            .context("persisted Arc UserOperation is invalid")?;
        ctx.engine.arc_client.verify_signed(&signed)?;
        if signed.sender != account.address
            || signed.calls != calls
            || format!("{:?}", signed.hash).to_lowercase()
                != stored.user_operation_hash.to_lowercase()
        {
            bail!("persisted UserOperation differs from queued authorization");
        }
        (signed, stored.provider_call_id)
    } else {
        if permit.consumed_at.is_some() {
            bail!("permit was consumed without a signed UserOperation");
        }
        let prepared = ctx
            .engine
            .arc_client
            .prepare(account.address, &calls)
            .await?;
        let required_raw = ctx
            .engine
            .quote_arc_fee_raw(
                &job.chain,
                prepared.gas_limit,
                prepared.max_fee_per_gas,
                true,
            )
            .await?;
        let paid_raw = match &job.execution_fee {
            Some(fee) => U256::from_dec_str(&fee.amount_raw)?,
            None => U256::from_dec_str(
                &db::get_verified_payment_for_request(&ctx.db_pool, job.request_id)
                    .await?
                    .context("verified x402 payment disappeared")?
                    .amount_raw,
            )?,
        };
        if paid_raw < required_raw {
            bail!("execution fee no longer covers current sponsored gas quote");
        }
        let signature = ctx
            .wallet_registry
            .wallet_manager()
            .sign_hash(
                &wallet.managed_wallet,
                prepared.signing_digest,
                job.request_id,
            )
            .await?;
        let signed = ctx
            .engine
            .arc_client
            .attach_signature(prepared, signature)?;
        ctx.engine.arc_client.verify_signed(&signed)?;
        db::store_signed_user_operation_and_consume_permit(
            &ctx.db_pool,
            job.request_id,
            permit.id,
            &serde_json::to_value(&signed)?,
            &format!("{:?}", signed.hash),
        )
        .await?;
        (signed, None)
    };

    let call_id = if let Some(call_id) = call_id {
        call_id
    } else {
        // A previous send can have succeeded before the call ID reached Postgres.
        let derived = ctx.engine.arc_client.expected_call_id(signed.hash);
        match ctx.engine.arc_client.status(&derived, signed.hash).await {
            Ok(Some(receipt)) => {
                nonce_lock.rollback().await?;
                return Ok(Some(receipt));
            }
            Ok(None) => {
                db::store_provider_call_id(
                    &ctx.db_pool,
                    job.request_id,
                    &format!("{:?}", signed.hash),
                    &derived,
                )
                .await?;
                derived
            }
            Err(error) if error.downcast_ref::<ArcOperationRejected>().is_some() => {
                return Err(error)
            }
            Err(_) => {
                let call_id = ctx.engine.arc_client.send(&signed).await?;
                #[cfg(test)]
                if INTERRUPT_AFTER_SUBMISSION.swap(false, Ordering::SeqCst) {
                    nonce_lock.rollback().await?;
                    bail!("injected process interruption after UserOperation submission");
                }
                db::store_provider_call_id(
                    &ctx.db_pool,
                    job.request_id,
                    &format!("{:?}", signed.hash),
                    &call_id,
                )
                .await?;
                call_id
            }
        }
    };
    db::update_execution_status(
        &ctx.db_pool,
        job.request_id,
        &ExecutionStatus::Broadcasting,
        None,
        None,
        None,
        None,
    )
    .await?;
    let result = ctx.engine.arc_client.wait(&call_id, signed.hash).await;
    nonce_lock.rollback().await?;
    result.map(Some)
}

async fn finalize_onchain_result(
    redis_conn: &mut ConnectionManager,
    ctx: &WorkerContext,
    job: &ExecutionJob,
    worker_id: u32,
    receipt: ArcExecutionReceipt,
) -> Result<()> {
    let tx_hash = format!("{:?}", receipt.tx_hash);
    let status = if receipt.succeeded {
        ExecutionStatus::Confirmed
    } else {
        ExecutionStatus::Reverted
    };
    let error_message = (!receipt.succeeded).then_some("Arc UserOperation reverted");
    let payment = if receipt.succeeded {
        job.execution_fee
            .as_ref()
            .map(|fee| SettledExecutionPayment {
                payment_id: Uuid::new_v4(),
                quote_request_id: Some(job.request_id),
                payer: job.smart_wallet_address.clone(),
                amount_usd: fee.amount_usd,
                token: fee.token_symbol.clone(),
                chain: job.chain.to_string(),
                tx_hash: tx_hash.clone(),
                confirmed_amount_raw: Some(fee.amount_raw.clone()),
                token_contract: Some(fee.token_contract.clone()),
            })
    } else {
        None
    };
    let newly_finalized = db::finalize_arc_execution(
        &ctx.db_pool,
        db::ArcExecutionFinalization {
            request_id: job.request_id,
            chain: &job.chain.to_string(),
            tx_hash: &tx_hash,
            from_address: &job.smart_wallet_address,
            to_address: &job.target_contract,
            status: &status,
            error_message,
            gas_used: receipt.gas_used.map(|value| value as i64),
            payment: payment.as_ref(),
        },
    )
    .await?;
    if newly_finalized {
        fire_webhook(
            ctx,
            job,
            &status,
            Some(&tx_hash),
            job.execution_fee.as_ref().map(|fee| fee.amount_usd),
            error_message,
        )
        .await;
    }
    queue::ack_job(redis_conn, job, worker_id).await?;
    Ok(())
}

async fn terminal_failure(
    redis_conn: &mut ConnectionManager,
    ctx: &WorkerContext,
    job: &ExecutionJob,
    worker_id: u32,
    reason: &str,
) {
    let newly_failed =
        match db::fail_arc_execution_status(&ctx.db_pool, job.request_id, reason).await {
            Ok(value) => value,
            Err(error) => {
                error!(request_id = %job.request_id, %error, "failed to persist terminal failure");
                return;
            }
        };
    if newly_failed {
        fire_webhook(ctx, job, &ExecutionStatus::Failed, None, None, Some(reason)).await;
    }
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
    let mut bumped = job.clone();
    bumped.attempt_count = bumped.attempt_count.saturating_add(1);
    if bumped.attempt_count >= MAX_JOB_ATTEMPTS {
        terminal_failure(redis_conn, ctx, job, worker_id, last_error).await;
        return;
    }
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    if let Err(error) = queue::retry_job(redis_conn, job, &bumped, worker_id).await {
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
    let callback_url = callback_url.clone();
    tokio::spawn(async move {
        webhook::deliver(&callback_url, &payload, &signing_secret).await;
    });
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, sync::Arc};

    use anyhow::{bail, Context};
    use ethers_core::types::U256;
    use sqlx::PgPool;

    use super::*;
    use crate::{
        api::services,
        arc::smart_account::{
            AlchemyMav2Verifier, AlchemySmartAccountProvider, SmartAccountRegistry,
        },
        config::AppConfig,
        types::{AuthContext, Chain, CredentialKind},
        wallet_provider::{TurnkeyWalletProvider, WalletManager},
    };

    fn erc20_transfer_calldata(recipient: Address, amount: U256) -> String {
        let mut data = Vec::with_capacity(68);
        data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data.extend_from_slice(&[0u8; 12]);
        data.extend_from_slice(recipient.as_bytes());
        let mut amount_word = [0u8; 32];
        amount.to_big_endian(&mut amount_word);
        data.extend_from_slice(&amount_word);
        format!("0x{}", hex::encode(data))
    }

    async fn recovery_test_identity(pool: &PgPool, external_id: &str) -> Result<AuthContext> {
        let row: Option<(Uuid, Uuid, Uuid, Uuid, Vec<String>)> = sqlx::query_as(
            r#"
            SELECT a.organization_id, p.id, cb.id, a.id, cb.scopes
            FROM agents a
            JOIN principal_agent_grants pag ON pag.agent_id = a.id
            JOIN principals p ON p.id = pag.principal_id
            JOIN credential_bindings cb ON cb.principal_id = p.id
            WHERE a.external_id = $1
              AND a.status = 'active'
              AND p.status = 'active'
              AND cb.is_active = TRUE
            ORDER BY cb.created_at
            LIMIT 1
            "#,
        )
        .bind(external_id)
        .fetch_optional(pool)
        .await?;
        let Some((organization_id, principal_id, credential_id, agent_id, scopes)) = row else {
            bail!("ARC_RECOVERY_TEST_AGENT_ID does not identify an active funded agent");
        };
        Ok(AuthContext {
            organization_id,
            principal_id,
            credential_id,
            credential_kind: CredentialKind::LocalJwk,
            scopes: scopes.into_iter().collect::<BTreeSet<_>>(),
            agent_id: Some(agent_id),
            agent_external_id: Some(external_id.to_string()),
            instance_id: None,
            dpop_jkt: None,
        })
    }

    fn build_worker_context(config: &AppConfig, pool: PgPool) -> Result<WorkerContext> {
        let turnkey = TurnkeyWalletProvider::new(
            config.turnkey_organization_id.clone(),
            &config.turnkey_api_public_key,
            &config.turnkey_api_private_key,
            config.turnkey_base_url.as_deref(),
            pool.clone(),
            config.turnkey_credential_encryption_key.clone(),
        )?;
        let wallet_manager = WalletManager::new(pool.clone(), Arc::new(turnkey));
        let wallet_registry = AgentWalletRegistry::new(pool.clone(), wallet_manager);
        let chain = match config.arc_network {
            crate::arc::ArcNetwork::Mainnet => Chain::Arc,
            crate::arc::ArcNetwork::Testnet => Chain::ArcTestnet,
        };
        let rpc_url = config.chain_config(&chain)?.rpc_url.clone();
        let smart_accounts = SmartAccountRegistry::new(
            pool.clone(),
            Arc::new(AlchemySmartAccountProvider::new(&config.alchemy_api_key)?),
            Arc::new(AlchemyMav2Verifier::new(&rpc_url)?),
        );
        Ok(WorkerContext {
            db_pool: pool,
            wallet_registry,
            engine: ExecutionEngine::new(config.runtime_config(), smart_accounts)?,
            webhook_encryption_key: config.auth_secret_encryption_key.clone(),
        })
    }

    /// Uses a pre-funded Arc testnet agent and submits one real sponsored
    /// UserOperation. Run this test alone with the API server stopped:
    ///
    /// `cargo test live_arc_submission_recovers_after_interruption -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "spends Arc testnet USDC and requires live Turnkey/Alchemy credentials"]
    async fn live_arc_submission_recovers_after_interruption() -> Result<()> {
        dotenvy::dotenv().ok();
        let config = AppConfig::from_env()?;
        if config.arc_network != crate::arc::ArcNetwork::Testnet {
            bail!("live recovery test is restricted to ARC_NETWORK=arc-testnet");
        }
        let pool = db::create_pool(&config.database_url).await?;
        let agent_id =
            std::env::var("ARC_RECOVERY_TEST_AGENT_ID").unwrap_or_else(|_| "arc-e2e-agent".into());
        let auth = recovery_test_identity(&pool, &agent_id).await?;
        let ctx = build_worker_context(&config, pool.clone())?;
        let mut redis = queue::create_redis_connection(&config.redis_url).await?;
        if queue::queue_length(&mut redis).await? != 0 {
            bail!("execution queue must be empty; stop every Jusso server before this test");
        }

        let chain = Chain::ArcTestnet;
        let execution_token = ctx
            .engine
            .config
            .chain_config(&chain)?
            .execution_token
            .address;
        let request = ExecutionRequest {
            agent_id: agent_id.clone(),
            chain: chain.to_string(),
            target_contract: format!("{execution_token:?}"),
            calldata: erc20_transfer_calldata(config.execution_fee_recipient, U256::one()),
            value: "0".into(),
            strategy_id: None,
            batch_calls: None,
            callback_url: None,
            policy_impact: crate::policy::ExecutionPolicyImpact::default(),
        };
        let response = services::handle_execute_idempotent(
            &ctx.engine,
            &pool,
            &mut redis,
            &ctx.wallet_registry,
            &auth,
            &request,
            &format!("arc-recovery-{}", Uuid::new_v4()),
        )
        .await?;
        if response.status != ExecutionStatus::Queued {
            bail!(
                "live recovery execution was not queued: {}",
                response.message
            );
        }

        let worker_id = u32::from_be_bytes(Uuid::new_v4().as_bytes()[..4].try_into()?);
        let job = queue::dequeue_job(&mut redis, 1.0, worker_id)
            .await?
            .context("queued recovery job disappeared")?;
        if job.request_id != response.request_id {
            bail!("dequeued an unrelated job; stop every Jusso server before this test");
        }

        INTERRUPT_AFTER_SUBMISSION.store(true, Ordering::SeqCst);
        let interruption = execute_arc(&ctx, &job).await;
        if interruption
            .as_ref()
            .err()
            .is_none_or(|error| !error.to_string().contains("injected process interruption"))
        {
            bail!("worker did not stop at the post-submission checkpoint");
        }
        let interrupted = db::get_signed_user_operation(&pool, job.request_id)
            .await?
            .context("interrupted execution did not persist its signed UserOperation")?;
        if interrupted.provider_call_id.is_some() {
            bail!("interruption occurred after provider call-ID persistence");
        }

        drop(ctx);
        if queue::recover_stale_jobs(&mut redis, worker_id).await? != 1 {
            bail!("restart did not recover exactly one in-flight job");
        }
        let recovered_job = queue::dequeue_job(&mut redis, 1.0, worker_id)
            .await?
            .context("recovered job was not available to the restarted worker")?;
        if recovered_job.request_id != job.request_id {
            bail!("restart recovered a different execution job");
        }
        let restarted = build_worker_context(&config, pool.clone())?;
        let receipt = execute_arc(&restarted, &recovered_job)
            .await?
            .context("recovered execution was already terminal unexpectedly")?;
        if !receipt.succeeded {
            bail!(
                "recovered Arc UserOperation reverted: {:?}",
                receipt.tx_hash
            );
        }
        let replay_receipt = ArcExecutionReceipt {
            tx_hash: receipt.tx_hash,
            gas_used: receipt.gas_used,
            succeeded: receipt.succeeded,
        };
        finalize_onchain_result(&mut redis, &restarted, &recovered_job, worker_id, receipt).await?;
        finalize_onchain_result(
            &mut redis,
            &restarted,
            &recovered_job,
            worker_id,
            replay_receipt,
        )
        .await?;

        let transaction_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM transactions WHERE request_id = $1")
                .bind(job.request_id)
                .fetch_one(&pool)
                .await?;
        let payment_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE request_id = $1")
                .bind(job.request_id)
                .fetch_one(&pool)
                .await?;
        let stored = db::get_execution_request(&pool, job.request_id)
            .await?
            .context("finalized execution disappeared")?;
        if transaction_count != 1 || payment_count != 1 || stored.status != "confirmed" {
            bail!(
                "recovery was not exactly once: transactions={transaction_count}, payments={payment_count}, status={}",
                stored.status
            );
        }
        let stored_operation = db::get_signed_user_operation(&pool, job.request_id)
            .await?
            .context("finalized execution lost its signed UserOperation")?;
        if stored_operation.user_operation_hash != interrupted.user_operation_hash {
            bail!("restart replaced the persisted UserOperation authorization");
        }

        println!(
            "recovered request={} user_operation={} tx={} transactions={} payments={}",
            job.request_id,
            stored_operation.user_operation_hash,
            stored.tx_hash.as_deref().unwrap_or("missing"),
            transaction_count,
            payment_count
        );
        Ok(())
    }
}
