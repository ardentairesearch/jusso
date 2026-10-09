//! Axum route handlers for the Execution API.

use axum::{
    extract::{ConnectInfo, Extension, Form, Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use redis::aio::ConnectionManager;
use sha2::Sha256;
use sqlx::PgPool;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, info};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::agent_wallet::AgentWalletRegistry;
use crate::api::services;
use crate::auth::{AuthService, TokenRequest};
use crate::config::AppConfig;
use crate::db;
use crate::execution_engine::ExecutionEngine;
use crate::types::*;

#[derive(Debug, serde::Deserialize)]
pub struct FeedQuery {
    pub limit: Option<usize>,
}

#[derive(Debug, serde::Serialize)]
pub struct FeedResponse {
    pub items: Vec<FeedItem>,
}

#[derive(Debug, serde::Serialize)]
pub struct FeedItem {
    pub r#type: String,
    pub type_label: String,
    pub agent: String,
    pub detail: String,
    pub hash: String,
    pub status: String,
    pub confirm: String,
}

fn short_hash(value: &str) -> String {
    if value.len() <= 14 {
        return value.to_string();
    }
    let head = &value[..8];
    let tail = &value[value.len().saturating_sub(4)..];
    format!("{head}...{tail}")
}

fn chain_display(chain: &str) -> String {
    match chain.to_lowercase().as_str() {
        "arc" => "Arc".to_string(),
        "arc-testnet" => "Arc Testnet".to_string(),
        other => {
            let mut chars = other.chars();
            match chars.next() {
                Some(first) => format!("{}{}", first.to_uppercase(), chars.as_str()),
                None => "Unknown".to_string(),
            }
        }
    }
}

fn format_amount_usd(amount: f64) -> String {
    if amount >= 100.0 {
        format!("${amount:.0}")
    } else {
        format!("${amount:.2}")
    }
}

#[cfg(test)]
mod feed_tests {
    use super::{chain_display, registration_client_ip};
    use axum::http::{HeaderMap, HeaderValue};

    #[test]
    fn chain_display_names_arc_testnet() {
        assert_eq!(chain_display("arc-testnet"), "Arc Testnet");
    }

    #[test]
    fn registration_client_ip_uses_forwarding_only_when_explicitly_configured() {
        let peer = "127.0.0.1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.10, 10.0.0.1"),
        );

        assert_eq!(registration_client_ip(&headers, peer, None).unwrap(), peer);
        assert_eq!(
            registration_client_ip(&headers, peer, Some("x-forwarded-for")).unwrap(),
            "203.0.113.10".parse::<std::net::IpAddr>().unwrap()
        );
    }
}

/// Shared application state injected into every handler.
#[derive(Clone)]
pub struct AppState {
    pub db_pool: PgPool,
    pub redis_conn: ConnectionManager,
    pub engine: ExecutionEngine,
    pub config: AppConfig,
    pub wallet_registry: AgentWalletRegistry,
}

#[derive(Clone)]
pub struct AdminAuthState {
    token: Arc<Zeroizing<String>>,
}

pub async fn validate_beta_runtime_startup(engine: &ExecutionEngine) -> anyhow::Result<()> {
    services::validate_execution_token(engine).await?;
    services::arc_fee_recipient_status(engine).await?;
    Ok(())
}

impl AdminAuthState {
    pub fn new(token: String) -> Self {
        Self {
            token: Arc::new(Zeroizing::new(token)),
        }
    }
}

// ────────────────────── GET /status/:id ──────────────────────────────

pub async fn status_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    info!(request_id = %id, "GET /status");

    let uuid = match Uuid::parse_str(&id) {
        Ok(u) => u,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "invalid UUID" })),
            )
                .into_response();
        }
    };

    match services::handle_execution_status(&state.db_pool, &api_ctx, uuid).await {
        Ok(Some(response)) => (StatusCode::OK, Json(response)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "request not found" })),
        )
            .into_response(),
        Err(e) => {
            error!(error = %e, "status lookup failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "internal server error" })),
            )
                .into_response()
        }
    }
}

// ────────────────────── GET /health ──────────────────────────────────

pub async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Deep health check: verify DB and Redis are reachable.
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db_pool)
        .await
        .is_ok();

    let mut redis = state.redis_conn.clone();
    let redis_ok = redis::cmd("PING")
        .query_async::<_, String>(&mut redis)
        .await
        .is_ok();

    let all_ok = db_ok && redis_ok;
    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(serde_json::json!({
            "status": if all_ok { "ok" } else { "degraded" },
            "service": "jusso",
            "version": env!("CARGO_PKG_VERSION"),
            "checks": {
                "database": if db_ok { "ok" } else { "unreachable" },
                "redis": if redis_ok { "ok" } else { "unreachable" },
            }
        })),
    )
}

// ────────────────────── GET /feed/recent ────────────────────────────

pub async fn public_feed_handler(
    State(state): State<AppState>,
    Query(params): Query<FeedQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(12).clamp(1, 50) as i64;

    match db::get_recent_feed_rows(&state.db_pool, limit).await {
        Ok(rows) => {
            let items = rows
                .into_iter()
                .map(|row| {
                    let normalized_status = row.status.to_lowercase();
                    let (feed_type, type_label) = match normalized_status.as_str() {
                        "payment_verified" => ("pay", "PAY"),
                        "pending" => ("reg", "REG"),
                        "broadcasting" => ("relay", "RELAY"),
                        _ => ("exec", "EXEC"),
                    };

                    let status_ok =
                        matches!(normalized_status.as_str(), "confirmed" | "payment_verified");

                    let confirm = match normalized_status.as_str() {
                        "confirmed" | "payment_verified" => "Confirmed",
                        "failed" | "reverted" => "Failed",
                        _ => "Pending...",
                    };

                    let hash = row
                        .tx_hash
                        .as_deref()
                        .map(short_hash)
                        .unwrap_or_else(|| short_hash(&row.id.to_string()));

                    let agent = format!("agent-{}", &row.id.to_string()[..8]);

                    let display_chain =
                        chain_display(row.payment_chain.as_deref().unwrap_or(&row.chain));

                    let detail = match normalized_status.as_str() {
                        "payment_verified" => {
                            let amount = row
                                .payment_amount_usd
                                .map(format_amount_usd)
                                .unwrap_or_else(|| "$0.00".to_string());
                            let token = row
                                .payment_token
                                .clone()
                                .unwrap_or_else(|| "token".to_string());
                            format!("fee settled · {amount} {token} · {display_chain}")
                        }
                        "broadcasting" => {
                            format!("native relay · {display_chain}")
                        }
                        "pending" | "queued" => {
                            format!("request queued · {display_chain}")
                        }
                        "failed" | "reverted" => {
                            format!("execution failed · {display_chain}")
                        }
                        _ => {
                            format!("contract execution · {display_chain}")
                        }
                    };

                    FeedItem {
                        r#type: feed_type.to_string(),
                        type_label: type_label.to_string(),
                        agent,
                        detail,
                        hash,
                        status: if status_ok {
                            "ok".to_string()
                        } else {
                            "pending".to_string()
                        },
                        confirm: confirm.to_string(),
                    }
                })
                .collect::<Vec<_>>();

            (
                StatusCode::OK,
                Json(serde_json::to_value(FeedResponse { items }).unwrap()),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, "failed to load recent feed activity");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to load recent activity" })),
            )
                .into_response()
        }
    }
}

// ────────────────────── GET /wallet ──────────────────────────────────

/// Query parameters for `GET /wallet`.
#[derive(Debug, serde::Deserialize)]
pub struct WalletQuery {
    /// The agent identifier (same as used in /execute).
    pub agent_id: String,
    /// Defaults to the configured Arc network.
    pub chain: Option<String>,
}

fn wallet_error_response(error: &anyhow::Error) -> Response {
    let message = error.to_string();
    if message.contains("active agent is not registered") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent_not_found"})),
        )
            .into_response();
    }
    if message.starts_with("unsupported chain:")
        || (message.starts_with("chain ") && message.ends_with(" is not configured"))
        || message.starts_with("agent_id ")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": message})),
        )
            .into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "wallet_temporarily_unavailable"})),
    )
        .into_response()
}

/// Look up (or provision) the agent's smart wallet address.
///
/// This is a lightweight, free endpoint that returns the agent's provider-backed
/// Arc smart-account address. The agent should fund this address with whatever
/// tokens their strategy needs before calling `/execute`.
///
/// No payment or simulation is performed.
pub async fn wallet_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Query(params): Query<WalletQuery>,
) -> impl IntoResponse {
    let chain = params
        .chain
        .as_deref()
        .unwrap_or(state.config.arc_network.name());
    info!(agent_id = %params.agent_id, chain, "GET /wallet");

    match services::handle_get_wallet(
        &state.engine,
        &state.wallet_registry,
        api_ctx.organization_id,
        &params.agent_id,
        chain,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = ?e, "wallet lookup failed");
            wallet_error_response(&e)
        }
    }
}

// ────────────────────── GET /wallet/balance ─────────────────────────────

/// Query parameters for `GET /wallet/balance`.
#[derive(Debug, serde::Deserialize)]
pub struct WalletBalanceQuery {
    pub agent_id: String,
    pub chain: Option<String>,
}

/// Return the agent smart account's single Arc USDC balance.
pub async fn wallet_balance_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Query(params): Query<WalletBalanceQuery>,
) -> impl IntoResponse {
    let chain = params
        .chain
        .as_deref()
        .unwrap_or(state.config.arc_network.name());
    info!(agent_id = %params.agent_id, chain, "GET /wallet/balance");

    match services::handle_get_wallet_balance(
        &state.engine,
        &state.wallet_registry,
        api_ctx.organization_id,
        &params.agent_id,
        chain,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = ?e, "wallet balance lookup failed");
            wallet_error_response(&e)
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct SelfServiceRegistrationRequest {
    pub organization_name: String,
    pub display_name: String,
    pub agent_id: String,
    pub public_jwk: serde_json::Value,
    pub terms_accepted: bool,
    pub challenge_token: Option<String>,
}

pub async fn self_service_registration_handler(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<SelfServiceRegistrationRequest>,
) -> impl IntoResponse {
    if !state.config.public_registration_enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "registration_not_available"})),
        )
            .into_response();
    }
    let client_ip = match registration_client_ip(
        &headers,
        peer.ip(),
        state.config.registration_client_ip_header.as_deref(),
    ) {
        Ok(address) => address,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    let fingerprint =
        registration_client_fingerprint(&state.config.auth_secret_encryption_key, client_ip);
    let limiter = crate::rate_limit::RateLimiter::new(
        state.redis_conn.clone(),
        state.config.registration_hourly_limit as f64 / 3600.0,
        state.config.registration_hourly_limit as f64,
    );
    match limiter
        .check_key(&format!("registration:{fingerprint}"))
        .await
    {
        Ok(None) => {}
        Ok(Some(retry_ms)) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", retry_ms.div_ceil(1000).to_string())],
                Json(serde_json::json!({"error": "registration_rate_limit_exceeded"})),
            )
                .into_response()
        }
        Err(error) => {
            error!(%error, "registration rate limiter unavailable");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": "registration_temporarily_unavailable"})),
            )
                .into_response();
        }
    }

    if let Err(error) = crate::auth::verify_registration_challenge(
        state.config.registration_turnstile_secret.as_deref(),
        body.challenge_token.as_deref(),
        client_ip,
        &state.config.registration_allowed_hostnames,
    )
    .await
    {
        db::insert_registration_event(
            &state.db_pool,
            None,
            None,
            &fingerprint,
            "rejected",
            serde_json::json!({"reason": "challenge"}),
        )
        .await
        .ok();
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }

    let organization_name = body.organization_name.trim();
    let display_name = body.display_name.trim();
    let agent_id = body.agent_id.trim();
    let valid_agent_id = (2..=128).contains(&agent_id.len())
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !body.terms_accepted
        || !(2..=100).contains(&organization_name.len())
        || !(2..=100).contains(&display_name.len())
        || !valid_agent_id
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "terms_accepted must be true; names must be 2-100 characters; agent_id must be 2-128 characters using letters, numbers, dot, dash, or underscore"
            })),
        )
            .into_response();
    }
    let jwk_thumbprint = match crate::auth::validate_public_jwk(&body.public_jwk) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    let credential_scopes = crate::auth::DEFAULT_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    let policy_actions = crate::auth::DEFAULT_POLICY_ACTIONS
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    let policy_protocols = crate::auth::SUPPORTED_PROTOCOLS
        .iter()
        .map(|protocol| (*protocol).to_string())
        .collect::<Vec<_>>();
    match db::create_self_service_registration(
        &state.db_pool,
        &state.config.auth_secret_encryption_key,
        db::SelfServiceRegistrationOptions {
            chain: state.config.arc_network.name(),
            organization_name,
            display_name,
            agent_external_id: agent_id,
            public_jwk: &body.public_jwk,
            public_jwk_thumbprint: &jwk_thumbprint,
            credential_scopes: &credential_scopes,
            policy_actions: &policy_actions,
            policy_protocols: &policy_protocols,
            max_execution_fee_usd: crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD,
        },
    )
    .await
    {
        Ok(registration) => {
            let row = registration.credential;
            db::insert_registration_event(
                &state.db_pool,
                Some(row.organization_id),
                Some(row.principal_id),
                &fingerprint,
                "created",
                serde_json::json!({"credential_binding_id": row.id, "agent_id": registration.agent.id}),
            )
            .await
            .ok();
            (
                StatusCode::CREATED,
                [("cache-control", "no-store"), ("pragma", "no-cache")],
                Json(serde_json::json!({
                    "organization_id": row.organization_id,
                    "principal_id": row.principal_id,
                    "credential_binding_id": row.id,
                    "client_id": row.client_id,
                    "agent_id": registration.agent.external_id,
                    "agent_uuid": registration.agent.id,
                    "policy_id": registration.policy.id,
                    "scopes": row.scopes,
                    "token_auth_method": "private_key_jwt+dpop",
                    "webhook_signing_secret": registration.webhook_secret,
                    "message": "Registration complete. Jusso stored only the public JWK; keep the private key in your local credential store."
                })),
            )
                .into_response()
        }
        Err(error) => {
            let duplicate = error.to_string() == "public JWK is already registered";
            db::insert_registration_event(
                &state.db_pool,
                None,
                None,
                &fingerprint,
                "rejected",
                serde_json::json!({"reason": if duplicate { "duplicate_jwk" } else { "storage" }}),
            )
            .await
            .ok();
            error!(%error, "self-service registration failed");
            (
                if duplicate {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                },
                Json(serde_json::json!({
                    "error": if duplicate {
                        "public key is already registered"
                    } else {
                        "registration failed"
                    }
                })),
            )
                .into_response()
        }
    }
}

fn registration_client_ip(
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    trusted_header: Option<&str>,
) -> anyhow::Result<std::net::IpAddr> {
    let Some(header_name) = trusted_header else {
        return Ok(peer_ip);
    };
    let raw = headers
        .get(header_name)
        .ok_or_else(|| anyhow::anyhow!("configured registration client-IP header is missing"))?
        .to_str()
        .map_err(|_| anyhow::anyhow!("registration client-IP header is not valid ASCII"))?;
    raw.split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("registration client-IP header is empty"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("registration client-IP header is not an IP address"))
}

fn registration_client_fingerprint(secret: &str, ip: std::net::IpAddr) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(ip.to_string().as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Debug, serde::Deserialize)]
pub struct AgentEnrollmentRequest {
    pub enrollment_token: String,
    pub display_name: String,
    pub public_jwk: serde_json::Value,
}

pub async fn agent_enrollment_handler(
    State(state): State<AppState>,
    Json(body): Json<AgentEnrollmentRequest>,
) -> impl IntoResponse {
    let thumbprint = match crate::auth::validate_public_jwk(&body.public_jwk) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    if body.display_name.trim().is_empty() || body.enrollment_token.len() < 32 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "valid enrollment_token and display_name are required"}))).into_response();
    }
    match db::enroll_agent(
        &state.db_pool,
        db::EnrollAgentOptions {
            enrollment_token: &body.enrollment_token,
            display_name: body.display_name.trim(),
            public_jwk: &body.public_jwk,
            public_jwk_thumbprint: &thumbprint,
        },
    )
    .await
    {
        Ok((credential, agent)) => (
            StatusCode::CREATED,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(serde_json::json!({
                "organization_id": credential.organization_id,
                "principal_id": credential.principal_id,
                "agent_id": agent.external_id,
                "agent_uuid": agent.id,
                "credential_binding_id": credential.id,
                "client_id": credential.client_id,
                "scopes": credential.scopes,
                "token_auth_method": "private_key_jwt+dpop"
            })),
        )
            .into_response(),
        Err(error) => (
            if error.to_string().contains("already") {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            },
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn list_agents_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
) -> impl IntoResponse {
    match db::list_agents_for_principal(
        &state.db_pool,
        context.organization_id,
        context.principal_id,
    )
    .await
    {
        Ok(agents) => (StatusCode::OK, Json(serde_json::json!({"agents": agents}))).into_response(),
        Err(error) => {
            error!(%error, "failed to list agents");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn list_credential_bindings_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
) -> impl IntoResponse {
    match db::list_credential_bindings(&state.db_pool, context.organization_id).await {
        Ok(rows) => (
            StatusCode::OK,
            Json(serde_json::json!({"credential_bindings": rows})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to list credential bindings");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn rotate_webhook_secret_handler(
    State(state): State<AppState>,
    Path(organization_id): Path<Uuid>,
) -> impl IntoResponse {
    match db::rotate_webhook_secret(
        &state.db_pool,
        organization_id,
        &state.config.auth_secret_encryption_key,
    )
    .await
    {
        Ok(Some(secret)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "organization_id": organization_id,
                "webhook_signing_secret": secret,
                "message": "Update webhook verification before the next delivery. This secret is shown once."
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "organization not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to rotate webhook secret");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to rotate webhook secret"})),
            )
                .into_response()
        }
    }
}

pub async fn list_authorization_policies_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
) -> impl IntoResponse {
    match db::list_authorization_policies(&state.db_pool, context.organization_id).await {
        Ok(rows) => (StatusCode::OK, Json(serde_json::json!({"authorization_policies": rows.into_iter().map(|row| serde_json::json!({
            "id": row.id,
            "name": row.name,
            "version": row.version,
            "allowed_chains": row.allowed_chains,
            "allowed_protocols": row.allowed_protocols,
            "allowed_actions": row.allowed_actions,
            "allowed_targets": row.allowed_targets,
            "max_value_wei": row.max_value_wei,
            "max_execution_fee_usd": row.max_execution_fee_usd,
            "is_active": row.is_active,
            "created_at": row.created_at,
            "updated_at": row.updated_at
        })).collect::<Vec<_>>() }))).into_response(),
        Err(error) => { error!(%error, "failed to list authorization policies"); StatusCode::INTERNAL_SERVER_ERROR.into_response() }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateFederationTrustRequest {
    pub agent_id: Uuid,
    pub name: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub audience: String,
    pub subject_pattern: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

pub async fn create_federation_trust_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Json(body): Json<CreateFederationTrustRequest>,
) -> impl IntoResponse {
    let name = body.name.trim();
    let issuer = body.issuer.trim();
    let jwks_uri = body.jwks_uri.trim();
    let audience = body.audience.trim();
    let subject_pattern = body.subject_pattern.trim();
    let scopes = if body.scopes.is_empty() {
        crate::auth::RUNTIME_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect()
    } else {
        body.scopes.clone()
    };
    let validation = crate::auth::validate_runtime_scopes(&scopes)
        .and_then(|_| crate::auth::validate_federation_url(issuer))
        .and_then(|_| crate::auth::validate_federation_url(jwks_uri));
    if let Err(error) = validation {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }
    let wildcard_is_valid = subject_pattern != "*"
        && subject_pattern.matches('*').count() <= 1
        && (!subject_pattern.contains('*') || subject_pattern.ends_with('*'));
    if name.is_empty() || audience.is_empty() || subject_pattern.is_empty() || !wildcard_is_valid {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "name, audience, and an exact or trailing-wildcard subject_pattern are required"}))).into_response();
    }
    match db::create_federation_trust(
        &state.db_pool,
        db::CreateFederationTrustOptions {
            organization_id: context.organization_id,
            created_by_principal_id: context.principal_id,
            agent_id: body.agent_id,
            name,
            issuer,
            jwks_uri,
            audience,
            subject_pattern,
            scopes: &scopes,
        },
    )
    .await
    {
        Ok(row) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"federation_trust": row})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

pub async fn list_federation_trusts_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
) -> impl IntoResponse {
    match db::list_federation_trusts(&state.db_pool, context.organization_id).await {
        Ok(rows) => (
            StatusCode::OK,
            Json(serde_json::json!({"federation_trusts": rows})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to list federation trusts");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn revoke_federation_trust_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match db::revoke_federation_trust(&state.db_pool, context.organization_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "active federation trust not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to revoke federation trust");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn fee_recipient_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    match services::arc_fee_recipient_status(&state.engine).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(error) => {
            error!(%error, "failed to inspect Arc execution fee recipient");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    }
}

pub async fn oauth_token_handler(
    State(auth): State<AuthService>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> impl IntoResponse {
    let proof = headers.get("dpop").and_then(|value| value.to_str().ok());
    match auth.exchange_token(request, proof).await {
        Ok(response) => (
            StatusCode::OK,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(response),
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(%error, "OAuth client authentication failed");
            (
                StatusCode::UNAUTHORIZED,
                [("cache-control", "no-store"), ("pragma", "no-cache")],
                Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "authorization code, credential, workload identity, or proof verification failed"
                })),
            )
                .into_response()
        }
    }
}

pub async fn oauth_authorization_server_metadata_handler(
    State(auth): State<AuthService>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": auth.issuer(),
        "authorization_endpoint": format!("{}/oauth/authorize", auth.issuer()),
        "token_endpoint": auth.token_endpoint(),
        "registration_endpoint": format!("{}/oauth/register", auth.issuer()),
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "token_endpoint_auth_signing_alg_values_supported": [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"
        ],
        "scopes_supported": crate::auth::DEFAULT_SCOPES,
        "dpop_signing_alg_values_supported": [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384"
        ]
    }))
}

pub async fn oauth_protected_resource_metadata_handler(
    State(auth): State<AuthService>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "resource": auth.audience(),
        "authorization_servers": [auth.issuer()],
        "bearer_methods_supported": ["header"],
        "resource_signing_alg_values_supported": ["ES256", "ES384", "RS256", "PS256"],
        "scopes_supported": crate::auth::DEFAULT_SCOPES
    }))
}

/// Admin authentication middleware.
///
/// Checks the `Authorization: Bearer <token>` header against the
/// startup-validated bootstrap admin token.
pub async fn admin_auth_middleware(
    State(auth): State<AdminAuthState>,
    req: Request,
    next: axum::middleware::Next,
) -> impl IntoResponse {
    let provided = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");

    if !constant_time_equal(provided.as_bytes(), auth.token.as_bytes()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid admin token" })),
        )
            .into_response();
    }

    next.run(req).await.into_response()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        difference |= left.get(index).copied().unwrap_or(0) as usize
            ^ right.get(index).copied().unwrap_or(0) as usize;
    }
    difference == 0
}
