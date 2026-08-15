//! Redis-backed job queue for execution requests.
//!
//! Uses a reliable queue pattern:
//!
//! * **Enqueue**: `LPUSH` onto the main queue list.
//! * **Dequeue**: `BLMOVE` (Redis ≥ 6.2) atomically pops from the main queue
//!   and pushes onto a per-worker "processing" list.  If the worker crashes
//!   before acknowledging, the job remains in the processing list and can be
//!   recovered.
//! * **Acknowledge**: `LREM` from the processing list after successful handling.
//! * **Recover**: Move stale jobs from processing lists back to the main queue.
//!
//! This gives **at-least-once delivery** — a job is never silently lost.

use anyhow::{anyhow, Result};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tracing::{info, warn};

use crate::types::ExecutionJob;

const QUEUE_KEY: &str = "execution_jobs";

/// Per-worker processing list key: `execution_jobs:processing:{worker_id}`
fn processing_key(worker_id: u32) -> String {
    format!("{QUEUE_KEY}:processing:{worker_id}")
}

/// Dead-letter queue for poison-pill jobs that fail repeatedly.
const DLQ_KEY: &str = "execution_jobs:dead_letter";

/// Maximum number of attempts before a job is moved to the dead-letter queue.
pub const MAX_JOB_ATTEMPTS: u32 = 3;

#[cfg(test)]
pub(crate) static TEST_QUEUE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Create a Redis connection manager (multiplexed, reconnect-aware).
pub async fn create_redis_connection(redis_url: &str) -> Result<ConnectionManager> {
    let client = redis::Client::open(redis_url)?;
    let mgr = ConnectionManager::new(client).await?;
    info!("redis connection manager created");
    Ok(mgr)
}

/// Push an execution job onto the queue.
pub async fn enqueue_job(conn: &mut ConnectionManager, job: &ExecutionJob) -> Result<()> {
    let payload = serde_json::to_string(job)?;
    let _: () = conn.lpush(QUEUE_KEY, &payload).await?;
    info!(request_id = %job.request_id, "job enqueued");
    Ok(())
}

/// Atomically dequeue a job from the main queue into this worker's processing
/// list.  The job stays in the processing list until explicitly acknowledged
/// via [`ack_job`], so it survives worker crashes.
///
/// Returns `None` if the timeout expires with no job available.
pub async fn dequeue_job(
    conn: &mut ConnectionManager,
    timeout_secs: f64,
    worker_id: u32,
) -> Result<Option<ExecutionJob>> {
    let proc_key = processing_key(worker_id);

    // BLMOVE: pop from queue tail (RIGHT), push to processing list head (LEFT).
    // This is the Redis 6.2+ replacement for the deprecated BRPOPLPUSH.
    let result: Option<String> = redis::cmd("BLMOVE")
        .arg(QUEUE_KEY)
        .arg(&proc_key)
        .arg("RIGHT")
        .arg("LEFT")
        .arg(timeout_secs)
        .query_async(conn)
        .await?;

    match result {
        Some(payload) => {
            match serde_json::from_str::<ExecutionJob>(&payload) {
                Ok(job) => {
                    info!(request_id = %job.request_id, worker_id, "job dequeued into processing list");
                    Ok(Some(job))
                }
                Err(e) => {
                    // Corrupt payload — remove it from the processing list so
                    // it doesn't block recovery, and push to DLQ for inspection.
                    warn!(error = %e, payload_len = payload.len(), "corrupt job payload, moving to DLQ");
                    let _: Result<i64, _> = conn.lrem(&proc_key, 1, &payload).await;
                    let _: Result<(), _> = conn.lpush(DLQ_KEY, &payload).await;
                    Err(anyhow!("corrupt job payload: {e}"))
                }
            }
        }
        None => Ok(None),
    }
}

/// Acknowledge a successfully processed job by removing it from this worker's
/// processing list.
pub async fn ack_job(
    conn: &mut ConnectionManager,
    job: &ExecutionJob,
    worker_id: u32,
) -> Result<()> {
    let proc_key = processing_key(worker_id);
    let payload = serde_json::to_string(job)?;
    // LREM: remove one occurrence of the payload from the processing list
    let removed: i64 = conn.lrem(&proc_key, 1, &payload).await?;
    if removed == 0 {
        warn!(
            request_id = %job.request_id,
            "job was not found in processing list during ack (already recovered?)"
        );
    }
    Ok(())
}

/// Move a job from this worker's processing list to the dead-letter queue.
///
/// Removes the job from the processing list and pushes it to the DLQ.
/// Use [`push_to_dlq`] instead if the job was already acknowledged/removed.
pub async fn move_to_dlq(
    conn: &mut ConnectionManager,
    job: &ExecutionJob,
    worker_id: u32,
) -> Result<()> {
    let proc_key = processing_key(worker_id);
    let payload = serde_json::to_string(job)?;

    // Remove from processing, push to DLQ
    let _: i64 = conn.lrem(&proc_key, 1, &payload).await?;
    let _: () = conn.lpush(DLQ_KEY, &payload).await?;

    warn!(
        request_id = %job.request_id,
        "job moved to dead-letter queue after {} failed attempts",
        MAX_JOB_ATTEMPTS
    );
    Ok(())
}

/// Push a job directly to the dead-letter queue without touching processing lists.
///
/// Use this when the job has already been removed from the processing list
/// (e.g. via [`ack_job`]) and you just need to record it in the DLQ.
pub async fn push_to_dlq(conn: &mut ConnectionManager, job: &ExecutionJob) -> Result<()> {
    let payload = serde_json::to_string(job)?;
    let _: () = conn.lpush(DLQ_KEY, &payload).await?;
    warn!(
        request_id = %job.request_id,
        "job pushed to dead-letter queue after {} failed attempts",
        MAX_JOB_ATTEMPTS
    );
    Ok(())
}

/// Recover stale jobs from a worker's processing list back to the main queue.
///
/// Call this at startup for each worker_id to reclaim jobs from a previous
/// instance that may have crashed.  Jobs are pushed back to the head of the
/// queue (LMOVE processing → queue).
pub async fn recover_stale_jobs(conn: &mut ConnectionManager, worker_id: u32) -> Result<u64> {
    let proc_key = processing_key(worker_id);
    let mut recovered = 0u64;

    loop {
        // LMOVE: pop from processing tail (RIGHT), push to queue head (LEFT).
        // This is the Redis 6.2+ replacement for the deprecated RPOPLPUSH.
        let result: Option<String> = redis::cmd("LMOVE")
            .arg(&proc_key)
            .arg(QUEUE_KEY)
            .arg("RIGHT")
            .arg("LEFT")
            .query_async(conn)
            .await?;

        match result {
            Some(_) => recovered += 1,
            None => break,
        }
    }

    if recovered > 0 {
        warn!(
            worker_id,
            recovered, "recovered stale jobs from previous worker instance"
        );
    }

    Ok(recovered)
}

/// Return the current length of the main queue (useful for metrics).
pub async fn queue_length(conn: &mut ConnectionManager) -> Result<u64> {
    let len: u64 = conn.llen(QUEUE_KEY).await?;
    Ok(len)
}

/// Return the current length of the dead-letter queue (useful for monitoring).
pub async fn dlq_length(conn: &mut ConnectionManager) -> Result<u64> {
    let len: u64 = conn.llen(DLQ_KEY).await?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Chain;
    use uuid::Uuid;

    async fn setup_redis() -> ConnectionManager {
        dotenvy::dotenv().ok();
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL env var");
        create_redis_connection(&redis_url)
            .await
            .expect("create redis connection")
    }

    async fn clear_keys(conn: &mut ConnectionManager, worker_id: u32) {
        let processing = format!("execution_jobs:processing:{worker_id}");
        let _: () = redis::cmd("DEL")
            .arg("execution_jobs")
            .arg(processing)
            .arg("execution_jobs:dead_letter")
            .query_async(conn)
            .await
            .expect("clear queue keys");
    }

    fn sample_job(attempt_count: u32) -> ExecutionJob {
        ExecutionJob {
            request_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            execution_permit_id: Uuid::new_v4(),
            agent_id: "queue-test".into(),
            smart_wallet_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            chain: Chain::Ethereum,
            target_contract: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".into(),
            calldata: "0xa9059cbb".into(),
            value: "0".into(),
            created_at: chrono::Utc::now(),
            attempt_count,
            batch_calls: None,
            callback_url: None,
            execution_fee: None,
        }
    }

    #[tokio::test]
    async fn test_queue_enqueue_and_dequeue() {
        let _guard = TEST_QUEUE_LOCK.lock().await;
        let mut conn = setup_redis().await;
        let worker_id = 199u32;
        clear_keys(&mut conn, worker_id).await;

        let job = sample_job(0);
        enqueue_job(&mut conn, &job).await.expect("enqueue job");
        assert!(queue_length(&mut conn).await.expect("queue length") >= 1);

        let dequeued = dequeue_job(&mut conn, 1.0, worker_id)
            .await
            .expect("dequeue job")
            .expect("job present");
        assert_eq!(dequeued.request_id, job.request_id);

        ack_job(&mut conn, &dequeued, worker_id)
            .await
            .expect("ack job");
        clear_keys(&mut conn, worker_id).await;
    }

    #[tokio::test]
    async fn test_queue_recover_stale_jobs() {
        let _guard = TEST_QUEUE_LOCK.lock().await;
        let mut conn = setup_redis().await;
        let worker_id = 197u32;
        clear_keys(&mut conn, worker_id).await;

        let proc_key = format!("execution_jobs:processing:{worker_id}");
        let payload = serde_json::to_string(&sample_job(1)).expect("serialize job");
        let _: () = redis::AsyncCommands::lpush(&mut conn, &proc_key, &payload)
            .await
            .expect("push processing payload");

        let recovered = recover_stale_jobs(&mut conn, worker_id)
            .await
            .expect("recover stale jobs");
        assert!(recovered >= 1);
        clear_keys(&mut conn, worker_id).await;
    }

    #[tokio::test]
    async fn test_queue_dead_letter() {
        let _guard = TEST_QUEUE_LOCK.lock().await;
        let mut conn = setup_redis().await;
        let worker_id = 198u32;
        clear_keys(&mut conn, worker_id).await;

        let job = sample_job(MAX_JOB_ATTEMPTS);
        push_to_dlq(&mut conn, &job).await.expect("push dlq");
        assert!(dlq_length(&mut conn).await.expect("dlq length") >= 1);
        clear_keys(&mut conn, worker_id).await;
    }
}
