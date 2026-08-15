//! Jusso: service entry point.
//!
//! Boots:
//! 1. Configuration from env / .env
//! 2. PostgreSQL connection pool + migrations
//! 3. Redis connection
//! 4. Execution engine (providers)
//! 5. Provider-backed Base accounts
//! 6. Native EIP-8130 execution and payer service
//! 7. Background worker(s)
//! 8. Axum HTTP server with routing + middleware

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware,
    response::IntoResponse,
    routing::{any, get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroize;

use jusso::{
    agent_wallet::AgentWalletRegistry,
    api::routes::{self, AppState},
    auth::{self, AuthService},
    config::AppConfig,
    db,
    execution_engine::ExecutionEngine,
    native_aa::{NativeAaClient, NativeAaConfig},
    queue,
    rate_limit::{self, RateLimiter},
    wallet_provider::{TurnkeyWalletProvider, WalletManager},
    worker::{self, WorkerContext},
};

fn cors_allowed_origins(raw_origins: Option<&str>) -> Vec<HeaderValue> {
    let mut allowed_origins = Vec::new();

    if let Some(raw_origins) = raw_origins {
        for raw_origin in raw_origins
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let origin = raw_origin
                .parse::<HeaderValue>()
                .expect("invalid CORS_ORIGIN");
            if !allowed_origins.contains(&origin) {
                allowed_origins.push(origin);
            }
        }
    }

    allowed_origins
}

fn configured_cors_layer() -> CorsLayer {
    let raw_origins = std::env::var("CORS_ORIGIN").ok();
    let allowed_origins = cors_allowed_origins(raw_origins.as_deref());

    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(
            move |origin: &HeaderValue, _request_parts| allowed_origins.contains(origin),
        ))
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
        .expose_headers([
            HeaderName::from_static("payment-required"),
            HeaderName::from_static("payment-response"),
        ])
}

/// Supervisor that restarts a worker if it panics.  Each restart recovers
/// stale jobs from that worker's processing list first, so nothing is lost.
async fn worker_supervisor(
    redis_conn: redis::aio::ConnectionManager,
    ctx: WorkerContext,
    worker_id: u32,
) {
    loop {
        let rc = redis_conn.clone();
        let context = ctx.clone();

        let handle = tokio::spawn(async move {
            worker::run_worker(rc, context, worker_id).await;
        });

        match handle.await {
            Ok(()) => {
                // run_worker only returns if its loop breaks (shouldn't happen)
                tracing::warn!(worker_id, "worker exited cleanly — restarting");
            }
            Err(e) => {
                tracing::error!(worker_id, error = %e, "worker panicked — recovering and restarting");
                // Recover any in-flight jobs that were in this worker's processing list
                let mut rc = redis_conn.clone();
                if let Err(re) = queue::recover_stale_jobs(&mut rc, worker_id).await {
                    tracing::error!(worker_id, error = %re, "failed to recover stale jobs after panic");
                }
            }
        }

        // Brief cooldown before restart to avoid tight loops on persistent panics
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ─────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    info!("starting Jusso");

    // ── Configuration ───────────────────────────────────────────────
    let mut config = AppConfig::from_env()?;
    let admin_auth = routes::AdminAuthState::new(std::mem::take(&mut config.bootstrap_admin_token));
    info!(host = %config.host, port = config.port, "config loaded");

    // ── Database ────────────────────────────────────────────────────
    let db_pool = db::create_pool(&config.database_url).await?;
    db::run_migrations(&db_pool).await?;
    info!("database connected and migrations applied");
    let auth_service = AuthService::new(
        db_pool.clone(),
        config.oauth_issuer.clone(),
        config.oauth_audience.clone(),
        config.oauth_signing_secret.clone(),
        config.oauth_access_token_ttl_seconds,
    )?;

    // ── Redis ───────────────────────────────────────────────────────
    let redis_conn = queue::create_redis_connection(&config.redis_url).await?;
    info!("redis connected");

    // ── Wallet custody and native AA ────────────────────────────────
    let mut turnkey_api_private_key = std::mem::take(&mut config.turnkey_api_private_key);
    let turnkey = TurnkeyWalletProvider::new(
        config.turnkey_organization_id.clone(),
        &config.turnkey_api_public_key,
        &turnkey_api_private_key,
        config.turnkey_base_url.as_deref(),
    )?;
    turnkey_api_private_key.zeroize();
    let wallet_manager = WalletManager::new(db_pool.clone(), Arc::new(turnkey));
    let payer_wallet = wallet_manager
        .get_or_create(&config.turnkey_payer_wallet_name)
        .await?;
    let payer_address = payer_wallet.provider_wallet.address;
    if let Some(expected) = config.turnkey_payer_expected_address {
        if payer_address != expected {
            anyhow::bail!(
                "Turnkey payer address mismatch: expected {expected:?}, got {payer_address:?}"
            );
        }
    }
    config.native_payer_address = Some(payer_address);

    let engine = ExecutionEngine::new(config.runtime_config()?)?;
    routes::validate_beta_runtime_startup(&engine, &config, payer_address).await?;
    let wallet_registry = AgentWalletRegistry::new(db_pool.clone(), wallet_manager);
    let base = config.chain_config(&jusso::types::Chain::Base)?;
    let native_client = NativeAaClient::new(NativeAaConfig {
        rpc_url: base.rpc_url.clone(),
        chain_id: base.chain_id,
        default_account: config.native_default_account,
        payer: payer_address,
        execution_token: base.execution_token.address,
        execution_token_symbol: base.execution_token.symbol.clone(),
        receipt_timeout: std::time::Duration::from_secs(config.native_receipt_timeout_seconds),
        max_payer_gas_cost_wei: config.native_max_payer_gas_cost_wei,
    })?;
    info!(
        payer = %payer_address,
        execution_fee_recipient = %payer_address,
        profile = ?config.network_profile,
        "Turnkey custody and Base native AA initialized"
    );

    let worker_ctx = WorkerContext {
        db_pool: db_pool.clone(),
        wallet_registry: wallet_registry.clone(),
        payer_wallet,
        engine: engine.clone(),
        native_client: native_client.clone(),
        webhook_client: jusso::webhook::build_http_client(),
        webhook_encryption_key: config.auth_secret_encryption_key.clone(),
    };
    info!("worker context assembled");

    // ── Background Workers ──────────────────────────────────────────
    let num_workers: u32 = std::env::var("NUM_WORKERS")
        .unwrap_or_else(|_| "2".into())
        .parse()?;

    // Recover any stale jobs left in processing lists from a previous crash.
    // This must happen before workers start consuming, so recovered jobs are
    // available immediately.
    for wid in 0..num_workers {
        let mut rc = redis_conn.clone();
        let recovered = queue::recover_stale_jobs(&mut rc, wid).await?;
        if recovered > 0 {
            info!(
                worker_id = wid,
                recovered, "recovered stale jobs from previous run"
            );
        }
    }

    // Spawn workers with a supervisor that auto-restarts on panic.
    for wid in 0..num_workers {
        let redis_clone = redis_conn.clone();
        let ctx_clone = worker_ctx.clone();
        tokio::spawn(worker_supervisor(redis_clone, ctx_clone, wid));
    }
    info!(
        workers = num_workers,
        "background workers spawned with supervisors"
    );

    // ── App State ───────────────────────────────────────────────────
    let state = AppState {
        db_pool: db_pool.clone(),
        redis_conn: redis_conn.clone(),
        engine,
        config: config.clone(),
        wallet_registry,
    };

    // ── Per-principal Rate Limiter ──────────────────────────────────
    let rate_limiter = if config.per_principal_rate_limit_rps > 0.0 {
        let rl = RateLimiter::new(
            redis_conn.clone(),
            config.per_principal_rate_limit_rps,
            config.per_principal_rate_limit_burst,
        );
        info!(
            rps = config.per_principal_rate_limit_rps,
            burst = config.per_principal_rate_limit_burst,
            "per-principal rate limiter enabled"
        );
        Some(rl)
    } else {
        info!("per-principal rate limiting disabled (PER_PRINCIPAL_RATE_LIMIT_RPS = 0)");
        None
    };

    // ── Router ──────────────────────────────────────────────────────
    // Admin sub-router — separate auth (bearer token, not API key)
    let admin_router = Router::new()
        .route("/api-keys", post(routes::create_api_key_handler))
        .route("/api-keys", get(routes::list_api_keys_handler))
        .route(
            "/api-keys/:id",
            axum::routing::delete(routes::revoke_api_key_handler),
        )
        .route("/api-keys/:id/rotate", post(routes::rotate_api_key_handler))
        .route(
            "/organizations/:id/webhook-secret/rotate",
            post(routes::rotate_webhook_secret_handler),
        )
        .route("/payer/status", get(routes::payer_status_handler))
        .layer(middleware::from_fn_with_state(
            admin_auth,
            routes::admin_auth_middleware,
        ))
        .with_state(state.clone());

    let oauth_router = Router::new()
        .route("/oauth/token", post(routes::oauth_token_handler))
        .route(
            "/.well-known/oauth-authorization-server",
            get(routes::oauth_authorization_server_metadata_handler),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(routes::oauth_protected_resource_metadata_handler),
        )
        .with_state(auth_service.clone());

    let protected_api_router = Router::new()
        // Execution API — x402 middleware applied
        .route("/execute", post(routes::execute_handler))
        .route("/x402/execute", post(routes::x402_execute_handler))
        .route("/simulate", post(routes::simulate_handler))
        .route("/status/:id", get(routes::status_handler))
        .route("/wallet", get(routes::wallet_handler))
        .route("/wallet/balance", get(routes::wallet_balance_handler))
        .route("/agents", get(routes::list_agents_handler))
        .route("/agents", post(routes::create_agent_handler))
        .route(
            "/agents/:id/policy",
            post(routes::assign_agent_policy_handler),
        )
        .route(
            "/agents/:id/enrollment-grants",
            post(routes::create_enrollment_grant_handler),
        )
        .route(
            "/credential-bindings",
            get(routes::list_credential_bindings_handler),
        )
        .route(
            "/credential-bindings",
            post(routes::create_credential_binding_handler),
        )
        .route(
            "/credential-bindings/:id",
            axum::routing::delete(routes::revoke_credential_binding_handler),
        )
        .route(
            "/authorization-policies",
            post(routes::create_authorization_policy_handler),
        )
        .route(
            "/authorization-policies",
            get(routes::list_authorization_policies_handler),
        )
        .route(
            "/authorization-policies/:id",
            axum::routing::delete(routes::revoke_authorization_policy_handler),
        )
        .route(
            "/federation-trusts",
            get(routes::list_federation_trusts_handler),
        )
        .route(
            "/federation-trusts",
            post(routes::create_federation_trust_handler),
        )
        .route(
            "/federation-trusts/:id",
            axum::routing::delete(routes::revoke_federation_trust_handler),
        )
        // Preserve a stable API-level response while typed integrations are frozen.
        .route("/protocols", any(routes::protocol_routes_disabled_handler))
        .route(
            "/protocols/*path",
            any(routes::protocol_routes_disabled_handler),
        )
        // Distributed per-principal rate limiting (after authorization).
        .layer({
            let rl = rate_limiter.clone();
            middleware::from_fn(move |req: Request, next: axum::middleware::Next| {
                let limiter = rl.clone();
                async move {
                    match limiter {
                        Some(ref l) => {
                            rate_limit::rate_limit_middleware(State(l.clone()), req, next)
                                .await
                                .into_response()
                        }
                        None => next.run(req).await.into_response(),
                    }
                }
            })
        })
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth::authorization_middleware,
        ))
        // API key compatibility + OAuth bearer authentication
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth::authentication_middleware,
        ));

    let app = Router::new()
        // Health check (no auth, no payment middleware — for load balancers)
        .route("/health", get(routes::health_handler))
        // Public landing-page feed activity (sanitized recent events)
        .route("/feed/recent", get(routes::public_feed_handler))
        .route("/register", post(routes::self_service_registration_handler))
        .route("/agents/enroll", post(routes::agent_enrollment_handler))
        .merge(oauth_router)
        // Admin endpoints (bearer-token auth, no x402 or API key middleware)
        .nest("/admin", admin_router)
        // Protected API endpoints (API key or OAuth, policy, rate limit)
        .merge(protected_api_router)
        .layer(TraceLayer::new_for_http())
        // ── Request body size limit (1 MB — prevents OOM from giant payloads)
        .layer(RequestBodyLimitLayer::new(1024 * 1024))
        // ── Global concurrency limit (prevents resource exhaustion) ─────────
        // MAX_CONCURRENT_REQUESTS controls max concurrent in-flight requests.
        // Default 200.  Set high to effectively disable.
        .layer(tower::limit::ConcurrencyLimitLayer::new(
            config.max_concurrent_requests.max(1) as usize,
        ))
        .layer(configured_cors_layer())
        .with_state(state);

    // ── Serve with graceful shutdown ────────────────────────────────
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    info!(address = %addr, "HTTP server listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("server shut down gracefully");
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM to initiate graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received SIGINT, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

#[cfg(test)]
mod cors_tests {
    use super::cors_allowed_origins;
    use axum::http::HeaderValue;

    #[test]
    fn cors_denies_browser_origins_by_default() {
        assert!(cors_allowed_origins(None).is_empty());
    }

    #[test]
    fn cors_accepts_comma_separated_extra_origins_without_duplicates() {
        let origins = cors_allowed_origins(Some(
            "https://app.example.com, https://jusso.example.com, https://app.example.com",
        ));

        assert!(origins.contains(&HeaderValue::from_static("https://app.example.com")));
        assert_eq!(
            origins
                .iter()
                .filter(|origin| { *origin == HeaderValue::from_static("https://app.example.com") })
                .count(),
            1
        );
    }
}
