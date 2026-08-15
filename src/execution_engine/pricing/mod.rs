//! Gas-cost → USD pricing module.
//!
//! Converts a native-AA gas estimate and Base gas price into a platform cost
//! denominated in USD. Uses a configured live price feed URL with
//! a configurable TTL cache.
//!
//! Design principles:
//! * **Base-native fees** — gas pricing comes from the configured Base RPC.
//! * **No silent fallbacks** — if we can't fetch the native token price, the
//!   pricing call fails and the request is rejected rather than under-quoting
//!   and operating at a loss.
//! * **Cached price feed** — avoids hammering the API on every request while
//!   staying reasonably fresh (default TTL: 60 s).
//! * **Chainlink-native mode** — when `*_PRICE_FEED_URL` is configured as
//!   `chainlink://0x...` (or just a `0x...` address), price is read directly
//!   from the on-chain AggregatorV3 proxy (`latestRoundData`, `decimals`).

use anyhow::{anyhow, Context, Result};
use ethers::{
    providers::{Http, Middleware, Provider},
    types::{Address, Bytes, TransactionRequest, U256},
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::info;

pub fn usd_to_token_raw_amount(usd: f64, decimals: u8) -> Result<U256> {
    if !usd.is_finite() || usd < 0.0 {
        anyhow::bail!("invalid USD amount: {usd}");
    }

    let scaled = usd * 10f64.powi(decimals as i32);
    if !scaled.is_finite() || scaled < 0.0 || scaled > u128::MAX as f64 {
        anyhow::bail!("token amount is outside the supported range");
    }

    Ok(U256::from(scaled.ceil() as u128))
}

// ──────────────────────── Price cache ────────────────────────────────

/// Cached native-token/USD price with expiry.
struct CachedPrice {
    price_usd: f64,
    fetched_at: Instant,
}

/// Thread-safe, TTL-based native-token/USD price cache.
///
/// The Base runtime owns one ETH/USD cache.
pub struct NativeTokenPriceCache {
    inner: RwLock<Option<CachedPrice>>,
    feed_url: String,
    ttl: Duration,
    provider: Arc<Provider<Http>>,
    http: reqwest::Client,
}

impl NativeTokenPriceCache {
    /// Create a new cache with the given feed URL and TTL.
    pub fn new(feed_url: String, ttl_secs: u64, provider: Arc<Provider<Http>>) -> Self {
        Self {
            inner: RwLock::new(None),
            feed_url,
            ttl: Duration::from_secs(ttl_secs),
            provider,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent(concat!("Jusso/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("failed to build reqwest client"),
        }
    }

    /// Get the cached native-token/USD price, refreshing if stale.
    pub async fn get_native_token_usd(&self) -> Result<f64> {
        // Fast path: read lock, check cache
        {
            let guard = self.inner.read().await;
            if let Some(ref cached) = *guard {
                if cached.fetched_at.elapsed() < self.ttl {
                    return Ok(cached.price_usd);
                }
            }
        }

        // Slow path: write lock, re-check (another task may have refreshed),
        // then fetch.
        let mut guard = self.inner.write().await;
        if let Some(ref cached) = *guard {
            if cached.fetched_at.elapsed() < self.ttl {
                return Ok(cached.price_usd);
            }
        }

        let price = self.fetch_price().await?;
        *guard = Some(CachedPrice {
            price_usd: price,
            fetched_at: Instant::now(),
        });
        Ok(price)
    }

    /// Fetch the native-token/USD price from the configured feed.
    ///
    /// Supported source formats:
    /// * Chainlink proxy address: `chainlink://0x...` (or raw `0x...`)
    /// * JSON endpoint: returns nested or flat `usd` field
    async fn fetch_price(&self) -> Result<f64> {
        if let Some(feed_address) = self.parse_chainlink_address()? {
            return self.fetch_price_from_chainlink(feed_address).await;
        }

        self.fetch_price_from_json().await
    }

    fn parse_chainlink_address(&self) -> Result<Option<Address>> {
        if let Some(raw) = self.feed_url.strip_prefix("chainlink://") {
            let addr = raw
                .parse::<Address>()
                .map_err(|e| anyhow!("invalid chainlink feed address '{raw}': {e}"))?;
            return Ok(Some(addr));
        }

        if self.feed_url.starts_with("0x") {
            let addr = self.feed_url.parse::<Address>().map_err(|e| {
                anyhow!("invalid chainlink feed address '{}': {}", self.feed_url, e)
            })?;
            return Ok(Some(addr));
        }

        Ok(None)
    }

    async fn fetch_price_from_json(&self) -> Result<f64> {
        let resp = self
            .http
            .get(&self.feed_url)
            .send()
            .await
            .map_err(|error| {
                let failure = if error.is_timeout() {
                    "request timed out"
                } else if error.is_connect() {
                    "connection failed"
                } else if error.is_redirect() {
                    "redirect failed"
                } else if error.is_request() {
                    "request could not be sent"
                } else {
                    "transport failed"
                };
                anyhow!("native token price feed request failed: {failure}")
            })?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "native token price feed returned HTTP {}",
                resp.status()
            ));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse native token price feed response")?;

        // Try nested shape: { "<asset>": { "usd": N } }
        // Works for any top-level key by scanning all values for a nested
        // "usd" field.
        let price = body
            .as_object()
            .and_then(|obj| {
                obj.values()
                    .filter_map(|v| v.get("usd").and_then(|u| u.as_f64()))
                    .next()
            })
            // Fallback: flat { "usd": N }
            .or_else(|| body.get("usd").and_then(|v| v.as_f64()))
            .ok_or_else(|| anyhow!("could not extract USD price from feed response: {body}"))?;

        if price <= 0.0 {
            return Err(anyhow!(
                "native token price feed returned non-positive price: {price}"
            ));
        }

        info!(native_token_usd = price, feed = %self.feed_url, "native token price refreshed");
        Ok(price)
    }

    async fn fetch_price_from_chainlink(&self, feed: Address) -> Result<f64> {
        const DECIMALS_SELECTOR: [u8; 4] = [0x31, 0x3c, 0xe5, 0x67];
        const LATEST_ROUND_DATA_SELECTOR: [u8; 4] = [0xfe, 0xaf, 0x96, 0x8c];

        let decimals_resp = self
            .provider
            .call(
                &TransactionRequest::new()
                    .to(feed)
                    .data(Bytes::from(DECIMALS_SELECTOR.to_vec()))
                    .into(),
                None,
            )
            .await
            .with_context(|| format!("failed to call Chainlink decimals() on {feed}"))?;

        if decimals_resp.len() < 32 {
            return Err(anyhow!(
                "Chainlink decimals() returned unexpected length: {}",
                decimals_resp.len()
            ));
        }
        let decimals = decimals_resp[31] as i32;

        let latest_resp = self
            .provider
            .call(
                &TransactionRequest::new()
                    .to(feed)
                    .data(Bytes::from(LATEST_ROUND_DATA_SELECTOR.to_vec()))
                    .into(),
                None,
            )
            .await
            .with_context(|| format!("failed to call Chainlink latestRoundData() on {feed}"))?;

        if latest_resp.len() < 64 {
            return Err(anyhow!(
                "Chainlink latestRoundData() returned unexpected length: {}",
                latest_resp.len()
            ));
        }

        let mut answer_bytes = [0u8; 32];
        answer_bytes.copy_from_slice(&latest_resp[32..64]);
        let answer = U256::from_big_endian(&answer_bytes);

        let raw_answer = answer
            .to_string()
            .parse::<f64>()
            .context("failed to convert Chainlink answer to f64")?;
        let scale = 10f64.powi(decimals);
        let price = raw_answer / scale;

        if !price.is_finite() || price <= 0.0 {
            return Err(anyhow!(
                "Chainlink price feed returned non-positive or invalid price: {price}"
            ));
        }

        info!(native_token_usd = price, feed = %feed, "native token price refreshed (chainlink)");
        Ok(price)
    }
}

// ──────────────────────── Public API ─────────────────────────────────

/// Calculate the execution cost in USD.
///
/// The caller supplies the Base gas price used for the quote.
///
/// Formula:
///   gas_cost_native = gas_estimate × gas_price  (in native token, e.g. ETH)
///   cost_usd        = gas_cost_native × live_native_token/USD + markup% + platform_fee
pub async fn calculate_cost(
    gas_price: U256,
    gas_estimate: u64,
    markup_pct: f64,
    platform_fee: f64,
    price_cache: &NativeTokenPriceCache,
) -> Result<f64> {
    if gas_price > U256::from(u128::MAX) {
        anyhow::bail!("gas price exceeds supported pricing range");
    }
    if !markup_pct.is_finite()
        || markup_pct < 0.0
        || !platform_fee.is_finite()
        || platform_fee < 0.0
    {
        anyhow::bail!("pricing configuration must be finite and non-negative");
    }

    // ── 1. Gas price provided by the Base execution engine ────────

    // ── 2. Live native-token/USD price ─────────────────────────────
    let native_usd = price_cache
        .get_native_token_usd()
        .await
        .context("failed to fetch native token/USD price for cost calculation")?;

    // ── 3. Calculate cost ──────────────────────────────────────────
    // Use u128 arithmetic to avoid U256 truncation risk:
    //   gas_cost_wei can be at most ~u64::MAX * ~100 gwei ≈ 1.8e27
    //   which fits comfortably in u128 (max ~3.4e38).
    let gas_cost_wei: u128 = (gas_estimate as u128)
        .checked_mul(gas_price.as_u128())
        .ok_or_else(|| anyhow!("gas cost overflow: estimate={gas_estimate}, price={gas_price}"))?;

    let gas_cost_native = gas_cost_wei as f64 / 1e18;
    let base_cost_usd = gas_cost_native * native_usd;
    let markup = base_cost_usd * (markup_pct / 100.0);
    let total = base_cost_usd + markup + platform_fee;
    if !total.is_finite() || total < 0.0 {
        anyhow::bail!("calculated execution cost is invalid");
    }

    info!(
        gas_estimate,
        gas_price_gwei = gas_price.as_u64() as f64 / 1e9,
        native_usd,
        base_cost_usd,
        markup,
        platform_fee,
        total,
        "cost calculation complete"
    );

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{extract::State, routing::get, Json, Router};
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn dummy_provider() -> Arc<Provider<Http>> {
        Arc::new(Provider::<Http>::try_from("http://127.0.0.1:8545").expect("provider"))
    }

    #[test]
    fn token_amount_rounds_up_without_undercharging() {
        assert_eq!(
            usd_to_token_raw_amount(0.000_001, 6).expect("one atomic unit"),
            U256::one()
        );
        assert_eq!(
            usd_to_token_raw_amount(1.000_000_1, 6).expect("round upward"),
            U256::from(1_000_001u64)
        );
        assert!(usd_to_token_raw_amount(f64::NAN, 6).is_err());
        assert!(usd_to_token_raw_amount(-0.01, 6).is_err());
    }

    #[tokio::test]
    async fn test_calculate_cost_gas_to_usd_conversion() {
        async fn price_handler() -> Json<serde_json::Value> {
            Json(json!({"ethereum": {"usd": 3000.0}}))
        }

        let app = Router::new().route("/", get(price_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let cache = NativeTokenPriceCache::new(format!("http://{addr}"), 60, dummy_provider());

        let total = calculate_cost(U256::from(20_000_000_000u64), 100_000, 10.0, 0.01, &cache)
            .await
            .expect("calculate cost");

        assert!((total - 6.61).abs() < 0.000_001);
        server.abort();
    }

    #[tokio::test]
    async fn test_native_price_cache_ttl_refreshes_after_expiry() {
        async fn price_handler(State(hits): State<Arc<AtomicUsize>>) -> Json<serde_json::Value> {
            hits.fetch_add(1, Ordering::SeqCst);
            Json(json!({"usd": 2500.0}))
        }

        let hit_count = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/", get(price_handler))
            .with_state(Arc::clone(&hit_count));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let cache = NativeTokenPriceCache::new(format!("http://{addr}"), 1, dummy_provider());

        let first = cache.get_native_token_usd().await.expect("first fetch");
        let second = cache.get_native_token_usd().await.expect("cache hit");
        assert_eq!(first, 2500.0);
        assert_eq!(second, 2500.0);
        assert_eq!(hit_count.load(Ordering::SeqCst), 1);

        tokio::time::sleep(Duration::from_millis(1100)).await;
        let third = cache.get_native_token_usd().await.expect("refresh fetch");
        assert_eq!(third, 2500.0);
        assert_eq!(hit_count.load(Ordering::SeqCst), 2);

        server.abort();
    }
}
