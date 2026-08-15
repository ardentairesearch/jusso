//! Axum route handlers for the Execution API.

use axum::{
    extract::{ConnectInfo, Extension, Form, Path, Query, Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use ethers::types::{Address, U256};
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
use crate::payments::x402::{
    self, FacilitatorClient, PaymentRequired, PaymentRequirements, ResourceInfo,
};
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
        "base" => "Base".to_string(),
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
    fn chain_display_names_base() {
        assert_eq!(chain_display("base"), "Base");
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

fn usd_to_raw_amount_ceil(usd: f64, decimals: u8) -> Option<String> {
    if !usd.is_finite() || usd < 0.0 {
        return None;
    }
    let scaled = usd * 10f64.powi(decimals as i32);
    if !scaled.is_finite() || scaled < 0.0 || scaled > u128::MAX as f64 {
        return None;
    }
    Some((scaled.ceil() as u128).to_string())
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

type RequestValidationError = (StatusCode, Json<serde_json::Value>);

fn required_idempotency_key(headers: &HeaderMap) -> Result<&str, RequestValidationError> {
    let value = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "missing_idempotency_key",
                    "message": "Idempotency-Key is required for execution requests"
                })),
            )
        })?;
    db::validate_idempotency_key(value).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
    })?;
    Ok(value)
}

pub async fn protocol_routes_disabled_handler() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": "protocol_integrations_temporarily_disabled",
            "message": "Typed protocol routes will reopen when native AA is available on a persistent Base test network."
        })),
    )
        .into_response()
}

#[derive(Clone)]
pub struct AdminAuthState {
    token: Arc<Zeroizing<String>>,
}

pub async fn validate_beta_runtime_startup(
    engine: &ExecutionEngine,
    config: &AppConfig,
    payer: Address,
) -> anyhow::Result<()> {
    services::validate_native_aa_deployment(engine).await?;
    services::validate_execution_token(engine).await?;
    services::native_payer_status(engine, payer, config.payer_low_balance_wei).await?;
    Ok(())
}

impl AdminAuthState {
    pub fn new(token: String) -> Self {
        Self {
            token: Arc::new(Zeroizing::new(token)),
        }
    }
}

// ────────────────────── POST /execute ────────────────────────────────

pub async fn execute_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(req): Json<ExecutionRequest>,
) -> impl IntoResponse {
    info!(agent_id = %req.agent_id, chain = %req.chain, "POST /execute");

    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let mut redis = state.redis_conn.clone();

    match services::handle_execute_idempotent(
        &state.engine,
        &state.db_pool,
        &mut redis,
        &state.wallet_registry,
        &api_ctx,
        &req,
        idempotency_key,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = %e, "execute failed");
            // Distinguish client errors from internal server errors.
            // Validation / parsing errors are client faults (400);
            // DB / RPC / queue errors are server faults (500).
            let err_str = e.to_string();
            let is_client_error = err_str.contains("unsupported chain")
                || err_str.contains("not configured")
                || err_str.contains("agent_id")
                || err_str.contains("invalid target contract")
                || err_str.contains("calldata")
                || err_str.contains("malformed");
            let status = if err_str.contains("idempotency key was already used") {
                StatusCode::CONFLICT
            } else if is_client_error || err_str.contains("Idempotency-Key") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": err_str }))).into_response()
        }
    }
}

// ─────────────────── POST /x402/execute ─────────────────────────────

pub async fn x402_execute_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    headers: HeaderMap,
    Json(req): Json<ExecutionRequest>,
) -> impl IntoResponse {
    let idempotency_key = match required_idempotency_key(&headers) {
        Ok(value) => value,
        Err(error) => return error.into_response(),
    };
    let signature = headers
        .get(x402::PAYMENT_SIGNATURE_HEADER)
        .and_then(|value| value.to_str().ok());
    let mut redis = state.redis_conn.clone();

    if signature.is_none() {
        let response = services::handle_x402_quote(
            &state.engine,
            &state.db_pool,
            &mut redis,
            &state.wallet_registry,
            &api_ctx,
            &req,
            idempotency_key,
        )
        .await;
        return match response {
            Ok(resp) if resp.status == ExecutionStatus::PaymentRequired => {
                match build_x402_payment_required(&state, &req, &resp).await {
                    Ok(required) => {
                        let encoded = match x402::encode_header(&required) {
                            Ok(value) => value,
                            Err(error) => return protocol_error_to_http(error),
                        };
                        let mut response = (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(serde_json::to_value(&required).unwrap()),
                        )
                            .into_response();
                        response.headers_mut().insert(
                            HeaderName::from_static(x402::PAYMENT_REQUIRED_HEADER),
                            HeaderValue::from_str(&encoded)
                                .expect("base64 is a valid header value"),
                        );
                        response
                    }
                    Err(error) => protocol_error_to_http(error),
                }
            }
            Ok(resp) => execution_response_to_http(&state, &req.chain, resp),
            Err(error) => protocol_error_to_http(error),
        };
    }

    let payload = match x402::decode_payment_signature(signature.unwrap()) {
        Ok(payload) => payload,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    let quote_id = match payload
        .extensions
        .get("executeRequestId")
        .and_then(|value| value.as_str())
        .and_then(|value| Uuid::parse_str(value).ok())
    {
        Some(id) => id,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "PAYMENT-SIGNATURE is missing extensions.executeRequestId"
                })),
            )
                .into_response()
        }
    };

    let result: anyhow::Result<_> = async {
        let chain = state.engine.validate(&req)?;
        let agent_wallet = state
            .wallet_registry
            .get_or_create(api_ctx.organization_id, &req.agent_id)
            .await?;
        let smart_wallet =
            services::resolve_chain_smart_wallet_address(&state.engine, &chain, &agent_wallet)
                .await?;
        let smart_wallet_str = format!("{smart_wallet:?}");
        let quoted_usd = db::get_locked_quote_cost(
            &state.db_pool,
            api_ctx.organization_id,
            quote_id,
            &req,
            &smart_wallet_str,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid, expired, or mismatched x402 quote"))?;
        let chain_cfg = state.config.chain_config(&chain)?;
        let execution_token = &chain_cfg.execution_token;
        let token_address = format!("{:?}", execution_token.address);
        if payload.accepted.asset.parse::<Address>().ok() != Some(execution_token.address) {
            anyhow::bail!(
                "x402 payment asset must be {} on {}",
                execution_token.symbol,
                chain
            );
        }
        let chain_id = chain_cfg.chain_id;
        let expected = x402_requirement(
            &state,
            chain_id,
            &token_address,
            &format!("{:?}", required_native_payer(&state.config)?),
            usd_to_raw_amount_ceil(quoted_usd, execution_token.decimals)
                .ok_or_else(|| anyhow::anyhow!("invalid locked x402 quote amount"))?,
        );
        x402::validate_accepted(&payload.accepted, &expected)?;

        let preflight =
            services::handle_x402_preflight(&state.engine, &state.wallet_registry, &api_ctx, &req)
                .await?;
        if !preflight.success {
            anyhow::bail!(
                "execution preflight failed before x402 settlement: {}",
                preflight
                    .error
                    .unwrap_or_else(|| "unknown simulation failure".into())
            );
        }
        let existing_payment =
            db::get_verified_payment_for_request(&state.db_pool, quote_id).await?;
        if existing_payment.is_none() {
            let preflight_fee_cap = preflight
                .max_fee_per_gas_wei
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("native preflight omitted max fee per gas"))
                .and_then(|raw| {
                    U256::from_dec_str(raw).map_err(|_| {
                        anyhow::anyhow!("native preflight returned an invalid fee cap")
                    })
                })?;
            let current_cost = state
                .engine
                .estimate_native_cost(&chain, preflight.gas_estimate, preflight_fee_cap, true)
                .await?;
            let current_amount = usd_to_raw_amount_ceil(current_cost, execution_token.decimals)
                .ok_or_else(|| anyhow::anyhow!("invalid native preflight cost"))?;
            if U256::from_dec_str(&current_amount)? > U256::from_dec_str(&expected.amount)? {
                anyhow::bail!(
                    "x402 quote no longer covers current execution cost; request a new quote"
                );
            }
        }

        if let Some(existing) = existing_payment {
            let payment = SettledExecutionPayment {
                payment_id: existing.id,
                quote_request_id: Some(quote_id),
                payer: existing.payer.clone(),
                amount_usd: quoted_usd,
                token: existing.token.clone(),
                chain: existing.payment_chain.clone(),
                tx_hash: existing.payment_tx_hash.clone(),
                confirmed_amount_raw: Some(existing.amount_raw.clone()),
                token_contract: Some(existing.token_contract.clone()),
            };
            let execution = services::handle_x402_execute(
                &state.engine,
                &state.db_pool,
                &mut redis,
                &state.wallet_registry,
                &api_ctx,
                &req,
                services::X402Settlement {
                    payment: &payment,
                    idempotency_key,
                },
            )
            .await?;
            let settled = x402::SettleResponse {
                success: true,
                transaction: Some(existing.payment_tx_hash),
                network: expected.network,
                payer: Some(existing.payer),
                amount: Some(existing.amount_raw),
                error_reason: None,
                extensions: None,
            };
            return Ok((execution, settled));
        }

        let facilitator_url = state
            .config
            .x402_facilitator_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("x402 execution is not configured"))?;
        let facilitator = FacilitatorClient::new(facilitator_url)?;
        let verified = facilitator.verify(&payload, &expected).await?;
        if !verified.is_valid {
            anyhow::bail!(
                "x402 payment verification failed: {}",
                verified
                    .invalid_reason
                    .unwrap_or_else(|| "facilitator rejected payment".into())
            );
        }
        let settled = facilitator.settle(&payload, &expected).await?;
        if !settled.success {
            anyhow::bail!(
                "x402 payment settlement failed: {}",
                settled
                    .error_reason
                    .clone()
                    .unwrap_or_else(|| "facilitator rejected settlement".into())
            );
        }
        if settled.network != expected.network {
            anyhow::bail!("x402 facilitator settled on an unexpected network");
        }
        let transaction = settled
            .transaction
            .clone()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("x402 settlement omitted its transaction hash"))?;
        if !transaction.starts_with("0x") || transaction.len() != 66 {
            anyhow::bail!("x402 facilitator returned an invalid EVM transaction hash");
        }
        if let Some(settled_amount) = settled.amount.as_deref() {
            let settled_amount = U256::from_dec_str(settled_amount)
                .map_err(|_| anyhow::anyhow!("x402 facilitator returned an invalid amount"))?;
            let required_amount = U256::from_dec_str(&expected.amount)?;
            if settled_amount < required_amount {
                anyhow::bail!("x402 facilitator reported an underpayment");
            }
        }
        let payer = settled
            .payer
            .clone()
            .or(verified.payer)
            .ok_or_else(|| anyhow::anyhow!("x402 facilitator omitted the payer address"))?;
        let _: Address = payer
            .parse()
            .map_err(|_| anyhow::anyhow!("x402 facilitator returned an invalid payer address"))?;

        let payment = SettledExecutionPayment {
            payment_id: Uuid::new_v4(),
            quote_request_id: Some(quote_id),
            payer,
            amount_usd: quoted_usd,
            token: execution_token.symbol.clone(),
            chain: chain.to_string(),
            tx_hash: transaction,
            confirmed_amount_raw: Some(expected.amount.clone()),
            token_contract: Some(token_address),
        };
        let execution = services::handle_x402_execute(
            &state.engine,
            &state.db_pool,
            &mut redis,
            &state.wallet_registry,
            &api_ctx,
            &req,
            services::X402Settlement {
                payment: &payment,
                idempotency_key,
            },
        )
        .await?;
        Ok((execution, settled))
    }
    .await;

    match result {
        Ok((execution, settled)) => {
            let encoded = match x402::encode_header(&settled) {
                Ok(value) => value,
                Err(error) => return protocol_error_to_http(error),
            };
            let mut response = execution_response_to_http(&state, &req.chain, execution);
            response.headers_mut().insert(
                HeaderName::from_static(x402::PAYMENT_RESPONSE_HEADER),
                HeaderValue::from_str(&encoded).expect("base64 is a valid header value"),
            );
            response
        }
        Err(error) => (
            StatusCode::PAYMENT_REQUIRED,
            Json(serde_json::json!({
                "error": "x402_payment_failed",
                "reason": error.to_string()
            })),
        )
            .into_response(),
    }
}

async fn build_x402_payment_required(
    state: &AppState,
    req: &ExecutionRequest,
    response: &ExecutionResponse,
) -> anyhow::Result<PaymentRequired> {
    let chain = state.engine.validate(req)?;
    let chain_id = state.config.chain_config(&chain)?.chain_id;
    let quoted_usd = response
        .estimated_cost_usd
        .ok_or_else(|| anyhow::anyhow!("x402 quote omitted its cost"))?;
    let chain_cfg = state.config.chain_config(&chain)?;
    let execution_token = &chain_cfg.execution_token;
    let amount = usd_to_raw_amount_ceil(quoted_usd, execution_token.decimals)
        .ok_or_else(|| anyhow::anyhow!("invalid x402 quote amount"))?;
    let token_address = format!("{:?}", execution_token.address);
    let accepts = vec![x402_requirement(
        state,
        chain_id,
        &token_address,
        &format!("{:?}", required_native_payer(&state.config)?),
        amount,
    )];
    let mut extensions = serde_json::Map::new();
    extensions.insert(
        "executeRequestId".into(),
        serde_json::Value::String(response.request_id.to_string()),
    );
    Ok(PaymentRequired {
        x402_version: x402::X402_VERSION,
        resource: x402_resource(state),
        accepts,
        extensions,
    })
}

fn x402_requirement(
    state: &AppState,
    chain_id: u64,
    asset: &str,
    pay_to: &str,
    amount: String,
) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".into(),
        network: format!("eip155:{chain_id}"),
        amount,
        asset: asset.to_string(),
        pay_to: pay_to.to_string(),
        max_timeout_seconds: state.config.x402_max_timeout_seconds,
        extra: None,
    }
}

fn required_native_payer(config: &AppConfig) -> anyhow::Result<Address> {
    config
        .native_payer_address
        .ok_or_else(|| anyhow::anyhow!("native payer is not initialized"))
}

fn x402_resource(state: &AppState) -> ResourceInfo {
    ResourceInfo {
        url: format!("{}/x402/execute", state.config.public_api_base_url),
        description: "Run one Jusso payer-funded Base native-AA transaction".into(),
        mime_type: "application/json".into(),
    }
}

// ──────────────────── POST /simulate ───────────────────────

pub async fn simulate_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Json(req): Json<ExecutionRequest>,
) -> impl IntoResponse {
    info!(agent_id = %req.agent_id, chain = %req.chain, "POST /simulate");

    match services::handle_simulate_authenticated(
        &state.engine,
        &state.db_pool,
        &state.wallet_registry,
        &api_ctx,
        &req,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = %format!("{e:#}"), "simulate failed");
            let err_str = e.to_string();
            let is_client_error = err_str.contains("unsupported chain")
                || err_str.contains("not configured")
                || err_str.contains("agent_id")
                || err_str.contains("invalid target contract")
                || err_str.contains("calldata")
                || err_str.contains("malformed");
            let status = if is_client_error {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": err_str }))).into_response()
        }
    }
}

fn execution_response_to_http(
    _state: &AppState,
    _chain: &str,
    response: ExecutionResponse,
) -> Response {
    let status = if response.status == ExecutionStatus::PaymentRequired {
        StatusCode::PAYMENT_REQUIRED
    } else {
        StatusCode::OK
    };
    (status, Json(serde_json::to_value(response).unwrap())).into_response()
}

fn protocol_error_to_http(error: anyhow::Error) -> Response {
    error!(%error, "execution request failed");
    let message = error.to_string();
    let status = if message.contains("idempotency key was already used") {
        StatusCode::CONFLICT
    } else if [
        "unsupported",
        "required",
        "invalid",
        "malformed",
        "not configured",
        "not found",
        "does not match",
        "rejected",
        "exceeds",
    ]
    .iter()
    .any(|candidate| message.contains(candidate))
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (status, Json(serde_json::json!({"error": message}))).into_response()
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

    match db::get_execution_request_for_organization(&state.db_pool, uuid, api_ctx.organization_id)
        .await
    {
        Ok(Some(row)) => {
            let can_access = !api_ctx.is_bound_to_other_agent(row.agent_uuid)
                && db::principal_can_access_agent(
                    &state.db_pool,
                    api_ctx.principal_id,
                    row.agent_uuid,
                )
                .await
                .unwrap_or(false);
            if !can_access {
                db::insert_auth_audit_event(
                    &state.db_pool,
                    &api_ctx,
                    "execution:read",
                    Some("/status/:id"),
                    "deny",
                    serde_json::json!({
                        "reason": "agent_not_allowed",
                        "request_id": row.id
                    }),
                )
                .await
                .ok();
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({ "error": "request not found" })),
                )
                    .into_response();
            }
            let resp = StatusResponse {
                request_id: row.id,
                status: serde_json::from_value(serde_json::Value::String(row.status.clone()))
                    .unwrap_or(ExecutionStatus::Pending),
                chain: row.chain,
                tx_hash: row.tx_hash,
                cost_usd: row.cost_usd,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response()
        }
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
                        "payment_required" | "payment_verified" => ("pay", "PAY"),
                        "pending" => ("reg", "REG"),
                        "broadcasting" => ("relay", "RELAY"),
                        _ => ("exec", "EXEC"),
                    };

                    let status_ok =
                        matches!(normalized_status.as_str(), "confirmed" | "payment_verified");

                    let confirm = match normalized_status.as_str() {
                        "confirmed" | "payment_verified" => "Confirmed",
                        "failed" | "reverted" => "Failed",
                        "payment_required" => "Payment Required",
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
                            format!("x402 verify · {amount} {token} · {display_chain}")
                        }
                        "payment_required" => {
                            format!("x402 quote required · {display_chain}")
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
    /// The blockchain to check native-account status on (default: "base").
    #[serde(default = "default_chain")]
    pub chain: String,
}

fn default_chain() -> String {
    "base".to_string()
}

/// Look up (or provision) the agent's smart wallet address.
///
/// This is a lightweight, free endpoint that returns the agent's provider-backed
/// Base account address. The agent should fund this address with whatever
/// tokens their strategy needs before calling `/execute`.
///
/// No payment or simulation is performed.
pub async fn wallet_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Query(params): Query<WalletQuery>,
) -> impl IntoResponse {
    info!(agent_id = %params.agent_id, chain = %params.chain, "GET /wallet");

    match services::handle_get_wallet(
        &state.engine,
        &state.wallet_registry,
        api_ctx.organization_id,
        &params.agent_id,
        &params.chain,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = ?e, "wallet lookup failed");
            let err_str = e.to_string();
            let is_client_error = err_str.contains("unsupported chain")
                || err_str.contains("not configured")
                || err_str.contains("agent_id");
            let status = if is_client_error {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": err_str }))).into_response()
        }
    }
}

// ────────────────────── GET /wallet/balance ─────────────────────────────

/// Query parameters for `GET /wallet/balance`.
#[derive(Debug, serde::Deserialize)]
pub struct WalletBalanceQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
}

/// Return native + ERC-20 token balances for the agent's smart wallet.
pub async fn wallet_balance_handler(
    State(state): State<AppState>,
    Extension(api_ctx): Extension<AuthContext>,
    Query(params): Query<WalletBalanceQuery>,
) -> impl IntoResponse {
    info!(agent_id = %params.agent_id, chain = %params.chain, "GET /wallet/balance");

    match services::handle_get_wallet_balance(
        &state.engine,
        &state.wallet_registry,
        api_ctx.organization_id,
        &params.agent_id,
        &params.chain,
    )
    .await
    {
        Ok(resp) => (StatusCode::OK, Json(serde_json::to_value(resp).unwrap())).into_response(),
        Err(e) => {
            error!(error = %e, "wallet balance lookup failed");
            let err_str = e.to_string();
            let is_client_error = err_str.contains("unsupported chain")
                || err_str.contains("not configured")
                || err_str.contains("agent_id");
            let status = if is_client_error {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": err_str }))).into_response()
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
    let policy_actions = crate::auth::RUNTIME_SCOPES
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>();
    match db::create_self_service_registration(
        &state.db_pool,
        &state.config.auth_secret_encryption_key,
        db::SelfServiceRegistrationOptions {
            organization_name,
            display_name,
            agent_external_id: agent_id,
            public_jwk: &body.public_jwk,
            public_jwk_thumbprint: &jwk_thumbprint,
            credential_scopes: &credential_scopes,
            policy_actions: &policy_actions,
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

// ────────────────────── POST /admin/api-keys ─────────────────────────

/// Request body for API key creation.
#[derive(Debug, serde::Deserialize)]
pub struct CreateApiKeyRequest {
    /// Optional human-readable label for the API key.
    pub label: Option<String>,
    /// Existing organization to attach the credential to. Omit to create one.
    pub organization_id: Option<Uuid>,
    /// Existing principal in the selected organization. Omit to create one.
    pub principal_id: Option<Uuid>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default = "default_api_key_environment")]
    pub environment: String,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

fn default_api_key_environment() -> String {
    "live".into()
}

/// Create a new API key (admin-only).
///
/// Protected by the `BOOTSTRAP_ADMIN_TOKEN` env var — callers must send
/// `Authorization: Bearer <token>`.  Returns the raw API key exactly once;
/// it is never stored in plaintext.
pub async fn create_api_key_handler(
    State(state): State<AppState>,
    Json(body): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    info!("POST /admin/api-keys");
    if let Err(error) = crate::auth::validate_scopes(&body.scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }
    if body
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "expires_at must be in the future"})),
        )
            .into_response();
    }

    match db::create_api_key(
        &state.db_pool,
        &state.config.auth_secret_encryption_key,
        db::CreateApiKeyOptions {
            label: body.label.as_deref(),
            organization_id: body.organization_id,
            principal_id: body.principal_id,
            scopes: &body.scopes,
            environment: &body.environment,
            expires_at: body.expires_at,
        },
    )
    .await
    {
        Ok((row, raw_key, webhook_secret)) => {
            info!(api_key_id = %row.id, "new API key created");
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "api_key_id": row.id,
                    "organization_id": row.organization_id,
                    "principal_id": row.principal_id,
                    "api_key": raw_key,
                    "key_prefix": row.key_prefix,
                    "label": row.label,
                    "scopes": row.scopes,
                    "environment": row.environment,
                    "expires_at": row.expires_at,
                    "webhook_signing_secret": webhook_secret,
                    "created_at": row.created_at,
                    "message": "Store this API key securely — it will not be shown again."
                })),
            )
                .into_response()
        }
        Err(e) => {
            error!(error = %e, "failed to create API key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "failed to create API key" })),
            )
                .into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct ListApiKeysQuery {
    pub organization_id: Uuid,
}

pub async fn list_api_keys_handler(
    State(state): State<AppState>,
    Query(query): Query<ListApiKeysQuery>,
) -> impl IntoResponse {
    match db::list_api_keys(&state.db_pool, query.organization_id).await {
        Ok(rows) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "api_keys": rows.into_iter().map(|row| serde_json::json!({
                    "id": row.id,
                    "organization_id": row.organization_id,
                    "principal_id": row.principal_id,
                    "key_prefix": row.key_prefix,
                    "label": row.label,
                    "scopes": row.scopes,
                    "environment": row.environment,
                    "is_active": row.is_active,
                    "expires_at": row.expires_at,
                    "revoked_at": row.revoked_at,
                    "last_used_at": row.last_used_at,
                    "created_at": row.created_at
                })).collect::<Vec<_>>()
            })),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to list API keys");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to list API keys"})),
            )
                .into_response()
        }
    }
}

pub async fn revoke_api_key_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match db::revoke_api_key(&state.db_pool, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "API key not found or already revoked"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to revoke API key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to revoke API key"})),
            )
                .into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct RotateApiKeyRequest {
    #[serde(default = "default_true")]
    pub revoke_old: bool,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

fn default_true() -> bool {
    true
}

pub async fn rotate_api_key_handler(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(body): Json<RotateApiKeyRequest>,
) -> impl IntoResponse {
    match db::rotate_api_key(
        &state.db_pool,
        id,
        body.revoke_old,
        body.expires_at,
    )
    .await
    {
        Ok(Some((new_key, raw_key))) => (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "api_key_id": new_key.id,
                    "organization_id": new_key.organization_id,
                    "principal_id": new_key.principal_id,
                    "api_key": raw_key,
                    "key_prefix": new_key.key_prefix,
                    "old_api_key_revoked": body.revoke_old,
                    "message": "The wallet namespace is unchanged. Store this key securely; it is shown once."
                })),
            )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "active API key not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to rotate API key");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to rotate API key"})),
            )
                .into_response()
        }
    }
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

#[derive(Debug, serde::Deserialize)]
pub struct CreateAgentRequest {
    pub agent_id: String,
    pub display_name: String,
    pub parent_agent_id: Option<Uuid>,
    pub policy_id: Uuid,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub enrollment_ttl_seconds: Option<i64>,
}

pub async fn create_agent_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Json(body): Json<CreateAgentRequest>,
) -> impl IntoResponse {
    let scopes = if body.scopes.is_empty() {
        crate::auth::RUNTIME_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect()
    } else {
        body.scopes.clone()
    };
    if let Err(error) = crate::auth::validate_runtime_scopes(&scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }
    let agent_id = body.agent_id.trim();
    let valid_agent_id = (2..=128).contains(&agent_id.len())
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid_agent_id || body.display_name.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "agent_id or display_name is invalid"})),
        )
            .into_response();
    }
    match db::create_agent_with_enrollment(
        &state.db_pool,
        db::CreateAgentOptions {
            organization_id: context.organization_id,
            created_by_principal_id: context.principal_id,
            external_id: agent_id,
            display_name: body.display_name.trim(),
            parent_agent_id: body.parent_agent_id,
            policy_id: body.policy_id,
            runtime_scopes: &scopes,
            enrollment_ttl_seconds: body.enrollment_ttl_seconds.unwrap_or(900),
        },
    )
    .await
    {
        Ok((agent, enrollment_token, expires_at)) => (
            StatusCode::CREATED,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(serde_json::json!({
                "agent": agent,
                "enrollment_token": enrollment_token,
                "enrollment_expires_at": expires_at,
                "message": "Pass this one-time token to the agent runtime; it is shown once."
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
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

#[derive(Debug, serde::Deserialize)]
pub struct AgentPolicyAssignmentRequest {
    pub policy_id: Uuid,
}

pub async fn assign_agent_policy_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Path(agent_id): Path<Uuid>,
    Json(body): Json<AgentPolicyAssignmentRequest>,
) -> impl IntoResponse {
    match db::assign_agent_policy(
        &state.db_pool,
        context.organization_id,
        context.principal_id,
        agent_id,
        body.policy_id,
    )
    .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "agent or active policy not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to assign agent policy");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateEnrollmentGrantRequest {
    #[serde(default)]
    pub scopes: Vec<String>,
    pub enrollment_ttl_seconds: Option<i64>,
}

pub async fn create_enrollment_grant_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Path(agent_id): Path<Uuid>,
    Json(body): Json<CreateEnrollmentGrantRequest>,
) -> impl IntoResponse {
    let scopes = if body.scopes.is_empty() {
        crate::auth::RUNTIME_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect()
    } else {
        body.scopes
    };
    if let Err(error) = crate::auth::validate_runtime_scopes(&scopes) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }
    match db::create_agent_enrollment_grant(
        &state.db_pool,
        context.organization_id,
        context.principal_id,
        agent_id,
        &scopes,
        body.enrollment_ttl_seconds.unwrap_or(900),
    )
    .await
    {
        Ok((token, expires_at)) => (
            StatusCode::CREATED,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(serde_json::json!({
                "enrollment_token": token,
                "enrollment_expires_at": expires_at,
                "scopes": scopes
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateCredentialBindingRequest {
    pub agent_id: Option<Uuid>,
    pub public_jwk: serde_json::Value,
    #[serde(default)]
    pub scopes: Vec<String>,
}

pub async fn create_credential_binding_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Json(body): Json<CreateCredentialBindingRequest>,
) -> impl IntoResponse {
    let scopes = if body.scopes.is_empty() {
        if body.agent_id.is_some() {
            crate::auth::RUNTIME_SCOPES
        } else {
            crate::auth::DEFAULT_SCOPES
        }
        .iter()
        .map(|scope| (*scope).to_string())
        .collect::<Vec<_>>()
    } else {
        body.scopes.clone()
    };
    let validation = if body.agent_id.is_some() {
        crate::auth::validate_runtime_scopes(&scopes)
    } else {
        crate::auth::validate_scopes(&scopes)
    };
    if let Err(error) = validation {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response();
    }
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
    match db::create_credential_binding(
        &state.db_pool,
        db::CreateCredentialBindingOptions {
            organization_id: context.organization_id,
            principal_id: context.principal_id,
            agent_id: body.agent_id,
            public_jwk: &body.public_jwk,
            public_jwk_thumbprint: &thumbprint,
            scopes: &scopes,
        },
    )
    .await
    {
        Ok(row) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "credential_binding_id": row.id,
                "client_id": row.client_id,
                "agent_id": row.agent_id,
                "scopes": row.scopes,
                "token_auth_method": "private_key_jwt+dpop"
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
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

pub async fn revoke_credential_binding_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match db::revoke_credential_binding(&state.db_pool, context.organization_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "active credential binding not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to revoke credential binding");
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

#[derive(Debug, serde::Deserialize)]
pub struct CreateAuthorizationPolicyRequest {
    pub name: String,
    pub allowed_chains: Option<Vec<String>>,
    pub allowed_protocols: Option<Vec<String>>,
    pub allowed_actions: Option<Vec<String>>,
    pub allowed_targets: Option<Vec<String>>,
    pub max_value_wei: Option<String>,
    pub max_execution_fee_usd: Option<f64>,
}

pub async fn create_authorization_policy_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Json(body): Json<CreateAuthorizationPolicyRequest>,
) -> impl IntoResponse {
    const CHAINS: &[&str] = &["base"];
    const PROTOCOLS: &[&str] = &[
        "aave-v3",
        "balancer-v3",
        "compound-v3",
        "gmx-v2",
        "morpho",
        "uniswap-v4",
    ];
    if body.allowed_chains.is_none()
        && body.allowed_protocols.is_none()
        && body.allowed_actions.is_none()
        && body.allowed_targets.is_none()
        && body.max_value_wei.is_none()
        && body.max_execution_fee_usd.is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "policy must restrict at least one of chains, protocols, or actions"
            })),
        )
            .into_response();
    }
    if body
        .allowed_chains
        .as_ref()
        .is_some_and(|values| values.iter().any(|value| !CHAINS.contains(&value.as_str())))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "allowed_chains contains an unsupported chain"})),
        )
            .into_response();
    }
    if body.allowed_protocols.as_ref().is_some_and(|values| {
        values
            .iter()
            .any(|value| !PROTOCOLS.contains(&value.as_str()))
    }) {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"error": "allowed_protocols contains an unsupported protocol"}),
            ),
        )
            .into_response();
    }
    if let Some(actions) = &body.allowed_actions {
        if let Err(error) = crate::auth::validate_policy_actions(actions) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response();
        }
    }
    if body.allowed_targets.as_ref().is_some_and(|targets| {
        targets
            .iter()
            .any(|target| target != "*" && target.parse::<Address>().is_err())
    }) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "allowed_targets must contain EVM addresses or *"})),
        )
            .into_response();
    }
    match db::create_authorization_policy(
        &state.db_pool,
        db::CreateAuthorizationPolicyOptions {
            organization_id: context.organization_id,
            name: body.name.trim(),
            allowed_chains: body.allowed_chains.as_deref(),
            allowed_protocols: body.allowed_protocols.as_deref(),
            allowed_actions: body.allowed_actions.as_deref(),
            allowed_targets: body.allowed_targets.as_deref(),
            max_value_wei: body.max_value_wei.as_deref(),
            max_execution_fee_usd: body.max_execution_fee_usd,
        },
    )
    .await
    {
        Ok(id) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "authorization_policy_id": id,
                "organization_id": context.organization_id,
                "name": body.name
            })),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to create authorization policy");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid authorization policy or organization"
                })),
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

pub async fn revoke_authorization_policy_handler(
    State(state): State<AppState>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match db::revoke_authorization_policy(&state.db_pool, context.organization_id, id).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "active authorization policy not found"})),
        )
            .into_response(),
        Err(error) => {
            error!(%error, "failed to revoke authorization policy");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
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

pub async fn payer_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let Some(payer) = state.config.native_payer_address else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "native payer is not initialized"})),
        )
            .into_response();
    };
    match services::native_payer_status(&state.engine, payer, state.config.payer_low_balance_wei)
        .await
    {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(error) => {
            error!(%error, "failed to inspect payer operations");
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
    let Some(proof) = proof else {
        return (
            StatusCode::BAD_REQUEST,
            [("cache-control", "no-store"), ("pragma", "no-cache")],
            Json(serde_json::json!({"error": "invalid_dpop_proof"})),
        )
            .into_response();
    };
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
                "error_description": "credential, workload identity, or DPoP verification failed"
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
        "token_endpoint": auth.token_endpoint(),
        "grant_types_supported": [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
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
