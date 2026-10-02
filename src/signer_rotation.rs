//! Durable Turnkey signer rotation for deployed Arc smart accounts.

use anyhow::{bail, Context, Result};
use ethers::{
    abi::{encode, Token},
    types::{Address, U256},
    utils::keccak256,
};
use sqlx::PgPool;
use std::time::Duration;
use tracing::{error, info, warn};

use crate::{
    agent_wallet::AgentWalletRegistry,
    arc::execution::{ArcCall, ArcExecutionReceipt, ArcOperationRejected, SignedUserOperation},
    db::models::AgentSignerRotationRow,
    execution_engine::ExecutionEngine,
    wallet_provider::{replacement_wallet_name, WalletScope},
};

const MAX_AUTOMATIC_ATTEMPTS: i32 = 8;

#[derive(Clone)]
pub struct SignerRotationContext {
    pub db_pool: PgPool,
    pub wallet_registry: AgentWalletRegistry,
    pub engine: ExecutionEngine,
}

pub async fn run_signer_rotation_worker(ctx: SignerRotationContext) {
    info!("signer-rotation reconciler started");
    loop {
        match next_rotation(&ctx.db_pool).await {
            Ok(Some(rotation)) => {
                if let Err(error) = process_with_account_lock(&ctx, rotation).await {
                    error!(error = ?error, "signer-rotation reconciliation attempt failed");
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            Ok(None) => tokio::time::sleep(Duration::from_secs(2)).await,
            Err(error) => {
                error!(error = ?error, "failed to poll signer-rotation queue");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn next_rotation(pool: &PgPool) -> Result<Option<AgentSignerRotationRow>> {
    Ok(sqlx::query_as::<_, AgentSignerRotationRow>(
        r#"SELECT * FROM agent_signer_rotations
           WHERE status NOT IN ('reconciled', 'failed')
             AND updated_at < now() - CASE
                   WHEN status = 'recovery_required' THEN INTERVAL '30 seconds'
                   ELSE INTERVAL '2 seconds'
                 END
           ORDER BY updated_at ASC
           LIMIT 1"#,
    )
    .fetch_optional(pool)
    .await?)
}

async fn process_with_account_lock(
    ctx: &SignerRotationContext,
    candidate: AgentSignerRotationRow,
) -> Result<()> {
    let account = parse_address(&candidate.smart_account_address, "smart-account")?;
    let digest = keccak256(account.as_bytes());
    let lock_key = i64::from_be_bytes(digest[..8].try_into().expect("fixed digest length"));
    let mut lock_connection = ctx.db_pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_key)
        .execute(&mut *lock_connection)
        .await
        .context("failed to acquire signer-rotation account lock")?;

    let result = process_rotation(ctx, candidate.id).await;
    if let Err(unlock_error) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(lock_key)
        .execute(&mut *lock_connection)
        .await
    {
        warn!(rotation_id = %candidate.id, %unlock_error, "failed to explicitly release signer-rotation lock");
    }
    if let Err(error) = &result {
        record_attempt_error(&ctx.db_pool, candidate.id, &format!("{error:#}")).await?;
    }
    result
}

async fn process_rotation(ctx: &SignerRotationContext, rotation_id: uuid::Uuid) -> Result<()> {
    for _ in 0..6 {
        let rotation = load_rotation(&ctx.db_pool, rotation_id)
            .await?
            .context("signer rotation disappeared")?;
        if matches!(rotation.status.as_str(), "reconciled" | "failed") {
            return Ok(());
        }
        validate_rotation_network(ctx, &rotation)?;
        match rotation.status.as_str() {
            "pending" => provision_replacement(ctx, &rotation).await?,
            "provisioned" => prepare_or_reconcile(ctx, &rotation).await?,
            "prepared" => submit_or_recover(ctx, &rotation).await?,
            "submitted" => recover_submitted(ctx, &rotation).await?,
            "confirmed" => reconcile_database(ctx, &rotation).await?,
            "recovery_required" if rotation.provider_call_id.is_some() => {
                recover_submitted(ctx, &rotation).await?
            }
            "recovery_required" if rotation.signed_user_operation.is_some() => {
                submit_or_recover(ctx, &rotation).await?
            }
            "recovery_required" if rotation.replacement_managed_wallet_id.is_some() => {
                prepare_or_reconcile(ctx, &rotation).await?
            }
            "recovery_required" => provision_replacement(ctx, &rotation).await?,
            other => bail!("unsupported signer-rotation state {other:?}"),
        }
    }
    Ok(())
}

async fn load_rotation(pool: &PgPool, id: uuid::Uuid) -> Result<Option<AgentSignerRotationRow>> {
    Ok(sqlx::query_as::<_, AgentSignerRotationRow>(
        "SELECT * FROM agent_signer_rotations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?)
}

fn validate_rotation_network(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    if rotation.chain_id != ctx.engine.config.arc_network.chain_id() as i64 {
        bail!("signer rotation targets a different Arc network");
    }
    Ok(())
}

async fn provision_replacement(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    let name = replacement_wallet_name(rotation.agent_wallet_id, rotation.id);
    let replacement = ctx
        .wallet_registry
        .wallet_manager()
        .get_or_create(WalletScope::Organization(rotation.organization_id), &name)
        .await
        .context("replacement Turnkey signer provisioning failed")?;
    let old = parse_address(&rotation.old_signer_address, "old signer")?;
    let new = replacement.provider_wallet.address;
    if new == Address::zero() || new == old {
        bail!("replacement Turnkey signer is not distinct from the old signer");
    }
    let updated = sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET replacement_managed_wallet_id = $2, replacement_signer_address = $3,
               status = 'provisioned', error_message = NULL, updated_at = now()
           WHERE id = $1 AND status IN ('pending', 'recovery_required')
             AND replacement_managed_wallet_id IS NULL"#,
    )
    .bind(rotation.id)
    .bind(replacement.id)
    .bind(format!("{new:?}"))
    .execute(&ctx.db_pool)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("signer rotation changed during replacement provisioning");
    }
    Ok(())
}

async fn prepare_or_reconcile(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    let account = parse_address(&rotation.smart_account_address, "smart-account")?;
    let old = parse_address(&rotation.old_signer_address, "old signer")?;
    let new = replacement_signer(rotation)?;
    let current = ctx.engine.smart_accounts.effective_signer(account).await?;
    match current {
        Some(current) if current == new => {
            mark_confirmed(&ctx.db_pool, rotation.id, None).await?;
            return Ok(());
        }
        Some(current) if current == old => {}
        Some(current) => {
            mark_recovery_required(
                &ctx.db_pool,
                rotation.id,
                &format!("smart account is controlled by unexpected signer {current:?}"),
            )
            .await?;
            return Ok(());
        }
        None => {
            mark_failed(
                &ctx.db_pool,
                rotation.id,
                "smart account is not deployed; its counterfactual signer cannot be rotated in place",
            )
            .await?;
            return Ok(());
        }
    }

    let initial = initial_signer(&ctx.db_pool, rotation.agent_wallet_id, rotation.chain_id).await?;
    ctx.engine
        .smart_accounts
        .verify_existing(account, initial, old)
        .await?;
    let old_wallet = ctx
        .wallet_registry
        .wallet_manager()
        .get_by_id(
            WalletScope::Organization(rotation.organization_id),
            rotation.old_managed_wallet_id,
        )
        .await?;
    if old_wallet.provider_wallet.address != old {
        bail!("old Turnkey wallet does not match the approved signer");
    }
    let calls = vec![fallback_signer_update_call(account, new)];
    let prepared = ctx.engine.arc_client.prepare(account, &calls).await?;
    let signature = ctx
        .wallet_registry
        .wallet_manager()
        .sign_hash(&old_wallet, prepared.signing_digest, rotation.id)
        .await?;
    let signed = ctx
        .engine
        .arc_client
        .attach_signature(prepared, signature)?;
    ctx.engine.arc_client.verify_signed(&signed)?;
    let updated = sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET signed_user_operation = $2, user_operation_hash = $3,
               provider_call_id = NULL, status = 'prepared',
               error_message = NULL, updated_at = now()
           WHERE id = $1 AND status IN ('provisioned', 'recovery_required')"#,
    )
    .bind(rotation.id)
    .bind(serde_json::to_value(&signed)?)
    .bind(format!("{:?}", signed.hash))
    .execute(&ctx.db_pool)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("signer rotation changed while its UserOperation was prepared");
    }
    Ok(())
}

async fn submit_or_recover(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    let signed = stored_operation(ctx, rotation)?;
    let call_id = ctx.engine.arc_client.expected_call_id(signed.hash);
    match ctx.engine.arc_client.status(&call_id, signed.hash).await {
        Ok(Some(receipt)) => finalize_receipt(ctx, rotation, receipt).await,
        Ok(None) => {
            store_submitted(&ctx.db_pool, rotation.id, &call_id).await?;
            Ok(())
        }
        Err(error) if error.downcast_ref::<ArcOperationRejected>().is_some() => Err(error),
        Err(_) => {
            let returned = ctx.engine.arc_client.send(&signed).await?;
            if !returned.eq_ignore_ascii_case(&call_id) {
                bail!("Arc Wallet API returned an unexpected signer-rotation call ID");
            }
            store_submitted(&ctx.db_pool, rotation.id, &returned).await?;
            Ok(())
        }
    }
}

async fn recover_submitted(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    let signed = stored_operation(ctx, rotation)?;
    let call_id = rotation
        .provider_call_id
        .as_deref()
        .context("submitted signer rotation has no provider call ID")?;
    let receipt = ctx.engine.arc_client.wait(call_id, signed.hash).await?;
    finalize_receipt(ctx, rotation, receipt).await
}

fn stored_operation(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<SignedUserOperation> {
    let signed: SignedUserOperation = serde_json::from_value(
        rotation
            .signed_user_operation
            .clone()
            .context("prepared signer rotation has no signed UserOperation")?,
    )
    .context("persisted signer-rotation UserOperation is invalid")?;
    ctx.engine.arc_client.verify_signed(&signed)?;
    let account = parse_address(&rotation.smart_account_address, "smart-account")?;
    let new = replacement_signer(rotation)?;
    if signed.sender != account
        || signed.calls != vec![fallback_signer_update_call(account, new)]
        || rotation
            .user_operation_hash
            .as_deref()
            .is_none_or(|hash| !hash.eq_ignore_ascii_case(&format!("{:?}", signed.hash)))
    {
        bail!("persisted signer-rotation UserOperation differs from the approved action");
    }
    Ok(signed)
}

async fn finalize_receipt(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
    receipt: ArcExecutionReceipt,
) -> Result<()> {
    let account = parse_address(&rotation.smart_account_address, "smart-account")?;
    let new = replacement_signer(rotation)?;
    let effective = ctx.engine.smart_accounts.effective_signer(account).await?;
    if effective == Some(new) {
        mark_confirmed(
            &ctx.db_pool,
            rotation.id,
            Some(format!("{:?}", receipt.tx_hash)),
        )
        .await
    } else if effective == Some(parse_address(&rotation.old_signer_address, "old signer")?) {
        mark_failed(
            &ctx.db_pool,
            rotation.id,
            "signer-rotation UserOperation reverted without changing ownership",
        )
        .await
    } else {
        mark_recovery_required(
            &ctx.db_pool,
            rotation.id,
            "onchain receipt and effective signer could not be reconciled",
        )
        .await
    }
}

async fn reconcile_database(
    ctx: &SignerRotationContext,
    rotation: &AgentSignerRotationRow,
) -> Result<()> {
    let account = parse_address(&rotation.smart_account_address, "smart-account")?;
    let new = replacement_signer(rotation)?;
    let initial = initial_signer(&ctx.db_pool, rotation.agent_wallet_id, rotation.chain_id).await?;
    ctx.engine
        .smart_accounts
        .verify_existing(account, initial, new)
        .await?;
    let replacement_id = rotation
        .replacement_managed_wallet_id
        .context("confirmed signer rotation has no replacement wallet")?;
    let replacement_wallet = ctx
        .wallet_registry
        .wallet_manager()
        .get_by_id(
            WalletScope::Organization(rotation.organization_id),
            replacement_id,
        )
        .await?;
    if replacement_wallet.provider_wallet.address != new {
        bail!("replacement managed wallet does not match the confirmed onchain signer");
    }
    let mut transaction = ctx.db_pool.begin().await?;
    let current: (uuid::Uuid, String) = sqlx::query_as(
        r#"SELECT managed_wallet_id, address FROM agent_wallets
           WHERE id = $1 AND organization_id = $2 FOR UPDATE"#,
    )
    .bind(rotation.agent_wallet_id)
    .bind(rotation.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if current.0 == replacement_id && current.1.eq_ignore_ascii_case(&format!("{new:?}")) {
        // A crash may occur after the binding update but before the rotation row update.
    } else if current.0 == rotation.old_managed_wallet_id
        && current.1.eq_ignore_ascii_case(&rotation.old_signer_address)
    {
        sqlx::query("UPDATE agent_wallets SET managed_wallet_id = $2, address = $3 WHERE id = $1")
            .bind(rotation.agent_wallet_id)
            .bind(replacement_id)
            .bind(format!("{new:?}"))
            .execute(&mut *transaction)
            .await?;
    } else {
        bail!("agent wallet binding changed before signer reconciliation");
    }
    let updated = sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET status = 'reconciled', error_message = NULL,
               completed_at = now(), updated_at = now()
           WHERE id = $1 AND status = 'confirmed'"#,
    )
    .bind(rotation.id)
    .execute(&mut *transaction)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("signer rotation changed before reconciliation");
    }
    transaction.commit().await?;
    info!(rotation_id = %rotation.id, smart_account = %account, signer = %new, "agent signer rotation reconciled");
    Ok(())
}

async fn initial_signer(pool: &PgPool, wallet_id: uuid::Uuid, chain_id: i64) -> Result<Address> {
    let raw: String = sqlx::query_scalar(
        r#"SELECT initial_signer_address FROM agent_smart_accounts
           WHERE agent_wallet_id = $1 AND chain_id = $2"#,
    )
    .bind(wallet_id)
    .bind(chain_id)
    .fetch_one(pool)
    .await?;
    parse_address(&raw, "initial signer")
}

async fn store_submitted(pool: &PgPool, id: uuid::Uuid, call_id: &str) -> Result<()> {
    let updated = sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET provider_call_id = $2, status = 'submitted',
               error_message = NULL, updated_at = now()
           WHERE id = $1 AND status = 'prepared'"#,
    )
    .bind(id)
    .bind(call_id)
    .execute(pool)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("signer rotation changed during submission");
    }
    Ok(())
}

async fn mark_confirmed(pool: &PgPool, id: uuid::Uuid, tx_hash: Option<String>) -> Result<()> {
    sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET status = 'confirmed', tx_hash = COALESCE($2, tx_hash),
               error_message = NULL, updated_at = now()
           WHERE id = $1 AND status NOT IN ('reconciled', 'failed')"#,
    )
    .bind(id)
    .bind(tx_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_failed(pool: &PgPool, id: uuid::Uuid, message: &str) -> Result<()> {
    sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET status = 'failed', error_message = $2,
               completed_at = now(), updated_at = now()
           WHERE id = $1 AND status NOT IN ('reconciled', 'failed')"#,
    )
    .bind(id)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

async fn mark_recovery_required(pool: &PgPool, id: uuid::Uuid, message: &str) -> Result<()> {
    sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET status = 'recovery_required', error_message = $2, updated_at = now()
           WHERE id = $1 AND status NOT IN ('reconciled', 'failed')"#,
    )
    .bind(id)
    .bind(message)
    .execute(pool)
    .await?;
    Ok(())
}

async fn record_attempt_error(pool: &PgPool, id: uuid::Uuid, message: &str) -> Result<()> {
    let message = message.chars().take(2_000).collect::<String>();
    sqlx::query(
        r#"UPDATE agent_signer_rotations
           SET attempt_count = attempt_count + 1,
               status = CASE WHEN attempt_count + 1 >= $3
                             THEN 'recovery_required' ELSE status END,
               error_message = $2, updated_at = now()
           WHERE id = $1 AND status NOT IN ('reconciled', 'failed')"#,
    )
    .bind(id)
    .bind(&message)
    .bind(MAX_AUTOMATIC_ATTEMPTS)
    .execute(pool)
    .await?;
    Ok(())
}

fn replacement_signer(rotation: &AgentSignerRotationRow) -> Result<Address> {
    parse_address(
        rotation
            .replacement_signer_address
            .as_deref()
            .context("rotation has no replacement signer")?,
        "replacement signer",
    )
}

fn parse_address(raw: &str, label: &str) -> Result<Address> {
    let address = raw
        .parse::<Address>()
        .with_context(|| format!("invalid {label} address"))?;
    if address == Address::zero() {
        bail!("{label} address cannot be zero");
    }
    Ok(address)
}

fn fallback_signer_update_call(account: Address, replacement: Address) -> ArcCall {
    let mut calldata = keccak256(b"updateFallbackSignerData(address,bool)")[..4].to_vec();
    calldata.extend(encode(&[Token::Address(replacement), Token::Bool(false)]));
    ArcCall {
        to: account,
        data: format!("0x{}", hex::encode(calldata)),
        value: U256::zero(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_exact_fallback_signer_update_call() {
        let account = Address::from_low_u64_be(1);
        let replacement = Address::from_low_u64_be(2);
        let call = fallback_signer_update_call(account, replacement);
        assert_eq!(call.to, account);
        assert_eq!(call.value, U256::zero());
        assert!(call.data.starts_with(&format!(
            "0x{}",
            hex::encode(&keccak256(b"updateFallbackSignerData(address,bool)")[..4])
        )));
        assert_eq!(call.data.len(), 2 + (4 + 64) * 2);
    }

    #[test]
    fn replacement_names_are_stable_distinct_and_provider_safe() {
        let wallet = uuid::Uuid::from_u128(1);
        let first = replacement_wallet_name(wallet, uuid::Uuid::from_u128(2));
        let second = replacement_wallet_name(wallet, uuid::Uuid::from_u128(3));
        assert_eq!(
            first,
            replacement_wallet_name(wallet, uuid::Uuid::from_u128(2))
        );
        assert_ne!(first, second);
        crate::wallet_provider::validate_external_id(&first).unwrap();
    }
}
