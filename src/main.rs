//! Jusso: service entry point.
//!
//! Boots:
//! 1. Configuration from env / .env
//! 2. PostgreSQL connection pool + migrations
//! 3. Redis connection
//! 4. Execution engine (providers)
//! 5. Tenant-scoped Turnkey signers and dedicated Arc smart accounts
//! 6. Sponsored ERC-4337 execution
//! 7. Background worker(s)
//! 8. Axum HTTP server with routing + middleware

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

use jusso::{
    agent_wallet::AgentWalletRegistry,
    api::routes::{self, AppState},
    arc::{
        probe_bundler, probe_rpc,
        smart_account::{AlchemyMav2Verifier, AlchemySmartAccountProvider, SmartAccountRegistry},
    },
    auth::{self, AuthService},
    config::AppConfig,
    connect::{self, ConnectService},
    db,
    execution_engine::ExecutionEngine,
    mcp, queue,
    rate_limit::{self, RateLimiter},
    signer_rotation::{self, SignerRotationContext},
    wallet_provider::{TurnkeyWalletProvider, WalletManager},
    worker::{self, WorkerContext},
    workflows,
};

async fn no_store_sensitive_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    response
}

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
    if let Some(onramp) = config.onramp.as_ref() {
        let fingerprint = jusso::funding::signing_key_fingerprint(onramp)?;
        info!(signing_key_fingerprint = %fingerprint, "fiat funding integration enabled");
    }

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

    // ── Turnkey custody and Arc ERC-4337 ────────────────────────────
    let turnkey_api_private_key =
        Zeroizing::new(std::mem::take(&mut config.turnkey_api_private_key));
    let turnkey_credential_encryption_key =
        std::mem::take(&mut config.turnkey_credential_encryption_key);
    let turnkey = TurnkeyWalletProvider::new(
        config.turnkey_organization_id.clone(),
        &config.turnkey_api_public_key,
        &turnkey_api_private_key,
        config.turnkey_base_url.as_deref(),
        db_pool.clone(),
        turnkey_credential_encryption_key,
    )?;
    let wallet_manager = WalletManager::new(db_pool.clone(), Arc::new(turnkey));
    let wallet_registry = AgentWalletRegistry::new(db_pool.clone(), wallet_manager);
    let chain = match config.arc_network {
        jusso::arc::ArcNetwork::Mainnet => jusso::types::Chain::Arc,
        jusso::arc::ArcNetwork::Testnet => jusso::types::Chain::ArcTestnet,
    };
    let arc = config.chain_config(&chain)?;
    let smart_provider = AlchemySmartAccountProvider::new(&config.alchemy_api_key)?;
    let smart_verifier = AlchemyMav2Verifier::new(&arc.rpc_url)?;
    let smart_accounts = SmartAccountRegistry::new(
        db_pool.clone(),
        Arc::new(smart_provider),
        Arc::new(smart_verifier),
    );
    let engine = ExecutionEngine::new(config.runtime_config(), smart_accounts)?;
    probe_rpc(config.arc_network, &arc.rpc_url, None).await?;
    let bundler_url = format!(
        "https://{}.g.alchemy.com/v2/{}",
        if config.arc_network == jusso::arc::ArcNetwork::Testnet {
            "arc-testnet"
        } else {
            "arc-mainnet"
        },
        config.alchemy_api_key,
    );
    probe_bundler(&bundler_url).await?;
    routes::validate_beta_runtime_startup(&engine).await?;
    info!(
        execution_fee_recipient = %config.execution_fee_recipient,
        network = ?config.arc_network,
        "Turnkey custody and Arc ERC-4337 initialized"
    );

    let worker_ctx = WorkerContext {
        db_pool: db_pool.clone(),
        wallet_registry: wallet_registry.clone(),
        engine: engine.clone(),
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

    // Blocking queue reads must use dedicated Redis connections. A cloned
    // ConnectionManager shares its multiplexed connection, so BLMOVE would
    // otherwise stall API-side Redis work such as registration rate limits.
    for wid in 0..num_workers {
        let worker_redis = queue::create_redis_connection(&config.redis_url).await?;
        let ctx_clone = worker_ctx.clone();
        tokio::spawn(worker_supervisor(worker_redis, ctx_clone, wid));
    }
    info!(
        workers = num_workers,
        "background workers spawned with supervisors"
    );
    tokio::spawn(signer_rotation::run_signer_rotation_worker(
        SignerRotationContext {
            db_pool: db_pool.clone(),
            wallet_registry: wallet_registry.clone(),
            engine: engine.clone(),
        },
    ));
    info!("signer-rotation reconciler spawned");

    // ── App State ───────────────────────────────────────────────────
    let state = AppState {
        db_pool: db_pool.clone(),
        redis_conn: redis_conn.clone(),
        engine,
        config: config.clone(),
        wallet_registry,
    };
    let connect_service = ConnectService::new(db_pool.clone(), redis_conn.clone(), config.clone())?;
    tokio::spawn(workflows::run_scheduler(state.clone()));
    info!("payment-plan scheduler spawned");

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
    // Admin sub-router — separate bootstrap-token authentication.
    let admin_router = Router::new()
        .route(
            "/organizations/:id/webhook-secret/rotate",
            post(routes::rotate_webhook_secret_handler),
        )
        .route(
            "/fee-recipient/status",
            get(routes::fee_recipient_status_handler),
        )
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

    let connect_router = Router::new()
        .route("/oauth/register", post(connect::register_client_handler))
        .route("/oauth/authorize", get(connect::authorize_handler))
        .route("/connect/:token", get(connect::connect_page_handler))
        .route(
            "/connect/:token/register/start",
            post(connect::registration_start_handler),
        )
        .route(
            "/connect/:token/register/finish",
            post(connect::registration_finish_handler),
        )
        .route(
            "/connect/:token/authenticate/start",
            post(connect::authentication_start_handler),
        )
        .route(
            "/connect/:token/authenticate/finish",
            post(connect::authentication_finish_handler),
        )
        .route(
            "/passkeys/enroll/:token",
            get(connect::owner_passkey_enrollment_page_handler),
        )
        .route(
            "/passkeys/enroll/:token/authenticate/start",
            post(connect::owner_passkey_enrollment_auth_start_handler),
        )
        .route(
            "/passkeys/enroll/:token/authenticate/finish",
            post(connect::owner_passkey_enrollment_auth_finish_handler),
        )
        .route(
            "/passkeys/enroll/:token/register/finish",
            post(connect::owner_passkey_enrollment_register_finish_handler),
        )
        .route("/approve/:token", get(connect::owner_approval_page_handler))
        .route(
            "/approve/:token/start",
            post(connect::owner_approval_start_handler),
        )
        .route(
            "/approve/:token/finish",
            post(connect::owner_approval_finish_handler),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp/agent",
            get(connect::agent_resource_metadata_handler),
        )
        .with_state(connect_service);

    let agent_mcp_router = Router::new()
        .nest_service(
            "/mcp/agent",
            mcp::agent_service(state.clone(), auth_service.clone())?,
        )
        .layer(middleware::from_fn_with_state(
            auth_service.clone(),
            auth::authentication_middleware,
        ))
        .layer(middleware::from_fn(no_store_sensitive_response));
    let protected_api_router = Router::new()
        .route("/status/:id", get(routes::status_handler))
        .route("/wallet", get(routes::wallet_handler))
        .route("/wallet/balance", get(routes::wallet_balance_handler))
        .route("/agents", get(routes::list_agents_handler))
        .route(
            "/credential-bindings",
            get(routes::list_credential_bindings_handler),
        )
        .route(
            "/authorization-policies",
            get(routes::list_authorization_policies_handler),
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
        // DPoP-bound OAuth bearer authentication.
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
        .merge(connect_router)
        .merge(agent_mcp_router)
        // Admin endpoints use only the bootstrap-token middleware.
        .nest("/admin", admin_router)
        // Protected API endpoints use OAuth, policy, and rate limiting.
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
