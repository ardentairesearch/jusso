//! Webhook delivery — pushes execution results to agent-supplied callback URLs.
//!
//! When an agent includes a `callback_url` in their `/execute` request, the
//! platform POSTs the final status to that URL once the transaction reaches a
//! terminal state (Confirmed, Failed, Reverted).
//!
//! ## Security
//!
//! Every webhook request carries an `X-Webhook-Signature` header containing
//! an HMAC-SHA256 signature of the JSON body, keyed with an organization-owned
//! webhook secret that is independent from its OAuth credentials. This lets
//! agents verify that the webhook came from the platform without exposing
//! authentication key material.
//!
//! ## Reliability
//!
//! Delivery uses exponential backoff with up to [`MAX_RETRIES`] attempts.
//! If all retries fail the webhook is logged as undeliverable but does **not**
//! block the main execution flow — the agent can always fall back to polling
//! `/status/{id}`.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde::Serialize;
use sha2::Sha256;
use std::{net::IpAddr, time::Duration};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::types::ExecutionStatus;

// ──────────────────────── Constants ──────────────────────────────────

/// Maximum number of delivery attempts (initial + retries).
const MAX_RETRIES: u32 = 3;

/// Initial backoff before the first retry.
const INITIAL_BACKOFF: Duration = Duration::from_secs(2);

/// Maximum time to wait for a webhook endpoint to respond.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time to wait for connection establishment.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn validate_callback_url(url: Option<&str>) -> anyhow::Result<Option<String>> {
    let Some(raw) = url.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if raw.len() > 2048 {
        anyhow::bail!("callback_url too long (max 2048 characters)");
    }

    let parsed = reqwest::Url::parse(raw)?;
    if parsed.scheme() != "https" {
        anyhow::bail!("callback_url must use HTTPS");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        anyhow::bail!("callback_url cannot contain credentials or a fragment");
    }
    validate_public_destination(&parsed).await?;
    Ok(Some(parsed.to_string()))
}

async fn validate_public_destination(url: &reqwest::Url) -> anyhow::Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("callback_url is missing a host"))?;
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal")
    {
        anyhow::bail!("callback_url must target a public host");
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| anyhow::anyhow!("callback_url host resolution timed out"))?
        .map_err(|_| anyhow::anyhow!("callback_url host could not be resolved"))?
        .collect::<Vec<_>>();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        anyhow::bail!("callback_url must resolve only to public IP addresses");
    }
    Ok(())
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && octets[0] != 0
                && !(octets[0] == 100 && (64..=127).contains(&octets[1]))
                && !(octets[0] == 198 && (18..=19).contains(&octets[1]))
                && octets[0] < 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || (segments[0] == 0x2001 && segments[1] == 0x0db8))
                && ip
                    .to_ipv4_mapped()
                    .is_none_or(|mapped| is_public_ip(mapped.into()))
        }
    }
}

// ──────────────────────── Payload ────────────────────────────────────

/// The JSON body POSTed to the agent's callback URL.
///
/// Mirrors `StatusResponse` so agents use the same deserialization logic
/// whether they poll `/status/{id}` or receive a webhook push.
#[derive(Debug, Clone, Serialize)]
pub struct WebhookPayload {
    /// Unique event identifier for idempotency on the receiver side.
    pub event_id: Uuid,
    /// Always `"execution.completed"` for now — room for more event types later.
    pub event_type: String,
    /// The execution request ID.
    pub request_id: Uuid,
    /// Terminal status: confirmed, failed, or reverted.
    pub status: ExecutionStatus,
    /// The blockchain the transaction was executed on.
    pub chain: String,
    /// On-chain transaction hash (present for confirmed / reverted).
    pub tx_hash: Option<String>,
    /// Final gas cost in USD (if available).
    pub cost_usd: Option<f64>,
    /// Error message (if failed / reverted).
    pub error: Option<String>,
    /// When the execution request was originally created.
    pub created_at: DateTime<Utc>,
    /// When the terminal status was reached.
    pub completed_at: DateTime<Utc>,
}

// ──────────────────────── Delivery ───────────────────────────────────

/// Build a shared `reqwest::Client` suitable for webhook delivery.
///
/// Callers should keep one instance and pass it around (connection pooling).
pub fn build_http_client() -> Client {
    Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none()) // Don't follow redirects
        .user_agent("jusso/webhook")
        .build()
        .expect("failed to build webhook HTTP client")
}

/// Deliver a webhook payload to the callback URL with retries.
///
/// `signing_secret` is the organization's dedicated webhook secret.
///
/// Returns `true` if delivery succeeded (2xx), `false` if all attempts failed.
pub async fn deliver(
    client: &Client,
    callback_url: &str,
    payload: &WebhookPayload,
    signing_secret: &str,
) -> bool {
    if let Ok(url) = reqwest::Url::parse(callback_url) {
        if url.scheme() == "https" {
            if let Err(error) = validate_public_destination(&url).await {
                error!(
                    request_id = %payload.request_id,
                    %error,
                    "webhook destination failed outbound security validation"
                );
                return false;
            }
        }
    }

    let body = match serde_json::to_string(payload) {
        Ok(b) => b,
        Err(e) => {
            error!(
                request_id = %payload.request_id,
                error = %e,
                "failed to serialize webhook payload"
            );
            return false;
        }
    };

    // Compute HMAC-SHA256 signature
    let signature = compute_signature(&body, signing_secret);

    let mut backoff = INITIAL_BACKOFF;

    for attempt in 1..=MAX_RETRIES {
        match client
            .post(callback_url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", &signature)
            .header("X-Webhook-Event", &payload.event_type)
            .header("X-Webhook-Id", payload.event_id.to_string())
            .body(body.clone())
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    info!(
                        request_id = %payload.request_id,
                        attempt,
                        status = %status,
                        "webhook delivered successfully"
                    );
                    return true;
                }

                // Non-2xx — treat as failure and retry
                warn!(
                    request_id = %payload.request_id,
                    attempt,
                    status = %status,
                    "webhook endpoint returned non-success status"
                );
            }
            Err(error) => {
                warn!(
                    request_id = %payload.request_id,
                    attempt,
                    timeout = error.is_timeout(),
                    connect = error.is_connect(),
                    status = ?error.status(),
                    "webhook delivery failed"
                );
            }
        }

        if attempt < MAX_RETRIES {
            tokio::time::sleep(backoff).await;
            backoff *= 2; // exponential backoff: 2s → 4s → 8s
        }
    }

    error!(
        request_id = %payload.request_id,
        max_retries = MAX_RETRIES,
        "webhook delivery exhausted all retries"
    );
    false
}

// ──────────────────────── HMAC Signing ───────────────────────────────

/// Compute `HMAC-SHA256(body, secret)` and return as a hex string.
fn compute_signature(body: &str, secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
        Router,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn sample_payload() -> WebhookPayload {
        WebhookPayload {
            event_id: Uuid::new_v4(),
            event_type: "execution.completed".into(),
            request_id: Uuid::new_v4(),
            status: ExecutionStatus::Confirmed,
            chain: "base".into(),
            tx_hash: Some("0xabc".into()),
            cost_usd: Some(1.23),
            error: None,
            created_at: Utc::now(),
            completed_at: Utc::now(),
        }
    }

    #[test]
    fn test_signature_deterministic() {
        let sig1 = compute_signature(r#"{"hello":"world"}"#, "secret123");
        let sig2 = compute_signature(r#"{"hello":"world"}"#, "secret123");
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_changes_with_different_secret() {
        let sig1 = compute_signature(r#"{"hello":"world"}"#, "secret_a");
        let sig2 = compute_signature(r#"{"hello":"world"}"#, "secret_b");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_changes_with_different_body() {
        let sig1 = compute_signature(r#"{"a":1}"#, "secret");
        let sig2 = compute_signature(r#"{"a":2}"#, "secret");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn outbound_policy_rejects_non_public_ip_ranges() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
        ] {
            assert!(!is_public_ip(raw.parse().expect("test IP")), "{raw}");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[tokio::test]
    async fn callback_policy_rejects_credentials_before_resolution() {
        assert!(
            validate_callback_url(Some("https://user:pass@example.com/hook"))
                .await
                .is_err()
        );
        assert!(validate_callback_url(Some("http://example.com/hook"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_deliver_sends_post_with_hmac_header() {
        type TestState = (Arc<AtomicUsize>, Arc<Mutex<Option<String>>>);

        let hit_count = Arc::new(AtomicUsize::new(0));
        let captured_sig: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

        async fn handler(
            State((hits, sig_store)): State<TestState>,
            headers: HeaderMap,
        ) -> StatusCode {
            hits.fetch_add(1, Ordering::SeqCst);
            let sig = headers
                .get("x-webhook-signature")
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string);
            *sig_store.lock().await = sig;
            StatusCode::OK
        }

        let app = Router::new()
            .route("/", post(handler))
            .with_state((Arc::clone(&hit_count), Arc::clone(&captured_sig)));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = build_http_client();
        let payload = sample_payload();
        let secret = "test-secret";

        let delivered = deliver(&client, &format!("http://{addr}"), &payload, secret).await;

        assert!(delivered);
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);

        let body = serde_json::to_string(&payload).expect("payload json");
        let expected_sig = compute_signature(&body, secret);
        assert_eq!(
            captured_sig.lock().await.as_deref(),
            Some(expected_sig.as_str())
        );

        server.abort();
    }

    #[tokio::test]
    async fn test_deliver_retries_on_5xx_then_succeeds() {
        let hit_count = Arc::new(AtomicUsize::new(0));

        async fn handler(State(hits): State<Arc<AtomicUsize>>) -> StatusCode {
            let n = hits.fetch_add(1, Ordering::SeqCst) + 1;
            if n < 3 {
                StatusCode::INTERNAL_SERVER_ERROR
            } else {
                StatusCode::OK
            }
        }

        let app = Router::new()
            .route("/", post(handler))
            .with_state(Arc::clone(&hit_count));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let client = build_http_client();
        let payload = sample_payload();

        let delivered = deliver(&client, &format!("http://{addr}"), &payload, "retry-secret").await;

        assert!(delivered);
        assert_eq!(hit_count.load(Ordering::SeqCst), 3);

        server.abort();
    }
}
