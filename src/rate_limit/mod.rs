//! Distributed per-principal rate limiting backed by Redis.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    response::IntoResponse,
};
use redis::{aio::ConnectionManager, Script};

use crate::types::AuthContext;

/// Atomic Redis token bucket using Redis server time.
const TOKEN_BUCKET_SCRIPT: &str = r#"
local now_parts = redis.call('TIME')
local now = (tonumber(now_parts[1]) * 1000) + math.floor(tonumber(now_parts[2]) / 1000)
local interval = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local tat = tonumber(redis.call('GET', KEYS[1])) or now
local allow_at = tat - ((burst - 1) * interval)

if now < allow_at then
  return {0, allow_at - now}
end

local new_tat = math.max(now, tat) + interval
local ttl = math.ceil((new_tat - now) + ((burst - 1) * interval))
redis.call('SET', KEYS[1], new_tat, 'PX', math.max(ttl, 1000))
return {1, 0}
"#;

#[derive(Clone)]
pub struct RateLimiter {
    redis: ConnectionManager,
    interval_ms: f64,
    burst: u64,
}

impl RateLimiter {
    pub fn new(redis: ConnectionManager, rate: f64, burst: f64) -> Self {
        let rate = if rate.is_finite() && rate > 0.0 {
            rate
        } else {
            1.0
        };
        Self {
            redis,
            interval_ms: 1000.0 / rate,
            burst: burst.max(1.0).floor() as u64,
        }
    }

    pub async fn check(&self, principal_id: uuid::Uuid) -> anyhow::Result<Option<u64>> {
        self.check_key(&format!("auth:{principal_id}")).await
    }

    pub async fn check_key(&self, subject: &str) -> anyhow::Result<Option<u64>> {
        let key = format!("jusso:rate:{subject}");
        let mut connection = self.redis.clone();
        let (allowed, retry_ms): (i64, i64) = Script::new(TOKEN_BUCKET_SCRIPT)
            .key(key)
            .arg(self.interval_ms)
            .arg(self.burst)
            .invoke_async(&mut connection)
            .await?;
        Ok((allowed == 0).then_some(retry_ms.max(1) as u64))
    }
}

pub async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    req: Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let principal_id = req
        .extensions()
        .get::<AuthContext>()
        .map(|context| context.principal_id);
    let Some(principal_id) = principal_id else {
        return next.run(req).await.into_response();
    };

    match limiter.check(principal_id).await {
        Ok(None) => next.run(req).await.into_response(),
        Ok(Some(retry_ms)) => {
            let retry_secs = retry_ms.div_ceil(1000);
            tracing::warn!(
                %principal_id,
                retry_after_secs = retry_secs,
                "principal rate limited"
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_secs.to_string())],
                axum::Json(serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "message": "Too many requests; retry after the indicated delay.",
                    "retry_after_ms": retry_ms,
                })),
            )
                .into_response()
        }
        Err(error) => {
            tracing::error!(%principal_id, %error, "distributed rate limiter unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(serde_json::json!({
                    "error": "rate_limit_service_unavailable"
                })),
            )
                .into_response()
        }
    }
}
