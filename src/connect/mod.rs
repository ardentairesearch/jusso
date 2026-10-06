//! Browser-mediated OAuth Connect flow for remote MCP clients.

use std::{net::SocketAddr, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Url, Webauthn, WebauthnBuilder,
};

use crate::{auth, config::AppConfig, db, rate_limit::RateLimiter};

const CONNECT_TTL_SECONDS: i64 = 600;
const CEREMONY_TTL_SECONDS: u64 = 300;
const CODE_TTL_SECONDS: i64 = 120;

#[derive(Clone)]
pub struct ConnectService {
    pool: PgPool,
    redis: redis::aio::ConnectionManager,
    config: AppConfig,
    webauthn: Arc<Webauthn>,
}

impl ConnectService {
    pub fn new(
        pool: PgPool,
        redis: redis::aio::ConnectionManager,
        config: AppConfig,
    ) -> Result<Self> {
        let origin = Url::parse(&config.webauthn_origin).context("invalid WebAuthn origin")?;
        let webauthn = WebauthnBuilder::new(&config.webauthn_rp_id, &origin)?
            .rp_name("Jusso")
            .build()?;
        Ok(Self {
            pool,
            redis,
            config,
            webauthn: Arc::new(webauthn),
        })
    }

    pub fn agent_resource(&self) -> String {
        format!(
            "{}/mcp/agent",
            self.config.oauth_issuer.trim_end_matches('/')
        )
    }

    pub fn control_resource(&self) -> String {
        format!(
            "{}/mcp/control",
            self.config.oauth_issuer.trim_end_matches('/')
        )
    }
}

#[derive(Debug, Deserialize)]
pub struct ClientRegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: Option<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
}

pub async fn register_client_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ClientRegistrationRequest>,
) -> Response {
    if let Err(error) = validate_client_registration(&body) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_client_metadata",
                "error_description": error.to_string()
            })),
        )
            .into_response();
    }
    let client_ip = match registration_client_ip(
        &headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    let limiter = RateLimiter::new(service.redis.clone(), 20.0 / 3600.0, 20.0);
    match limiter
        .check_key(&format!("oauth-client-registration:{client_ip}"))
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
            tracing::error!(%error, "OAuth client registration limiter unavailable");
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    let client_id = format!("jso_mcp_{}", Uuid::new_v4().simple());
    let client_name = body
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("MCP client");
    match sqlx::query(
        "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, $2, $3)",
    )
    .bind(&client_id)
    .bind(client_name)
    .bind(&body.redirect_uris)
    .execute(&service.pool)
    .await
    {
        Ok(_) => (
            StatusCode::CREATED,
            [("cache-control", "no-store")],
            Json(serde_json::json!({
                "client_id": client_id,
                "client_name": client_name,
                "redirect_uris": body.redirect_uris,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none"
            })),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(%error, "OAuth client registration failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn validate_client_registration(body: &ClientRegistrationRequest) -> Result<()> {
    if body.redirect_uris.is_empty() || body.redirect_uris.len() > 10 {
        anyhow::bail!("redirect_uris must contain between one and ten URLs");
    }
    if body
        .client_name
        .as_deref()
        .is_some_and(|name| name.len() > 100)
    {
        anyhow::bail!("client_name exceeds 100 characters");
    }
    if body
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method != "none")
    {
        anyhow::bail!("public MCP clients must use token_endpoint_auth_method none");
    }
    for (name, values) in [
        ("grant_types", body.grant_types.as_ref()),
        ("response_types", body.response_types.as_ref()),
    ] {
        if values.is_some_and(|values| {
            values.len() > 10
                || values
                    .iter()
                    .any(|value| value.is_empty() || value.len() > 128)
        }) {
            anyhow::bail!("{name} contains invalid client metadata");
        }
    }
    // Registration metadata describes client capabilities. Jusso deliberately
    // narrows them in its registration response to authorization_code,
    // refresh_token, code, PKCE, and public-client authentication.
    for redirect_uri in &body.redirect_uris {
        validate_redirect_uri(redirect_uri)?;
    }
    Ok(())
}

fn validate_redirect_uri(value: &str) -> Result<()> {
    if value.len() > 2048 {
        anyhow::bail!("redirect URI is too long");
    }
    let url = reqwest::Url::parse(value).context("redirect URI is invalid")?;
    let localhost = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    );
    if (url.scheme() != "https" && !(url.scheme() == "http" && localhost))
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("redirect URI must use HTTPS, except for loopback development URLs");
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct AuthorizationQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: String,
    code_challenge_method: String,
    resource: String,
}

#[derive(FromRow)]
struct OAuthClientRow {
    redirect_uris: Vec<String>,
}

pub async fn authorize_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    let client_ip = match registration_client_ip(
        &headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    ) {
        Ok(value) => value,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": error.to_string()})),
            )
                .into_response()
        }
    };
    match begin_authorization(&service, query, client_ip).await {
        Ok(location) => Redirect::to(&location).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": error.to_string()
            })),
        )
            .into_response(),
    }
}

pub async fn agent_resource_metadata_handler(
    State(service): State<ConnectService>,
) -> Json<serde_json::Value> {
    protected_resource_metadata(&service, service.agent_resource(), auth::RUNTIME_SCOPES)
}

pub async fn control_resource_metadata_handler(
    State(service): State<ConnectService>,
) -> Json<serde_json::Value> {
    protected_resource_metadata(
        &service,
        service.control_resource(),
        auth::MANAGEMENT_SCOPES,
    )
}

fn protected_resource_metadata(
    service: &ConnectService,
    resource: String,
    scopes: &[&str],
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "resource": resource,
        "authorization_servers": [service.config.oauth_issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": scopes
    }))
}

async fn begin_authorization(
    service: &ConnectService,
    query: AuthorizationQuery,
    client_ip: std::net::IpAddr,
) -> Result<String> {
    if query.response_type != "code" || query.code_challenge_method != "S256" {
        anyhow::bail!("response_type=code and code_challenge_method=S256 are required");
    }
    if query.code_challenge.len() != 43
        || !query
            .code_challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        anyhow::bail!("code_challenge must be an unpadded SHA-256 base64url value");
    }
    if query.client_id.len() > 2048
        || query.redirect_uri.len() > 2048
        || query
            .state
            .as_deref()
            .is_some_and(|value| value.len() > 1024)
        || query
            .scope
            .as_deref()
            .is_some_and(|value| value.len() > 1024)
    {
        anyhow::bail!("authorization request contains an oversized parameter");
    }
    let ip_limiter = RateLimiter::new(service.redis.clone(), 120.0 / 3600.0, 120.0);
    if ip_limiter
        .check_key(&format!("oauth-authorization-ip:{client_ip}"))
        .await?
        .is_some()
    {
        anyhow::bail!("authorization request rate limit exceeded");
    }
    let client = resolve_oauth_client(service, &query.client_id).await?;
    let limiter = RateLimiter::new(service.redis.clone(), 120.0 / 3600.0, 120.0);
    if limiter
        .check_key(&format!("oauth-authorization:{}", query.client_id))
        .await?
        .is_some()
    {
        anyhow::bail!("authorization request rate limit exceeded");
    }
    if !client
        .redirect_uris
        .iter()
        .any(|uri| uri == &query.redirect_uri)
    {
        anyhow::bail!("redirect_uri is not registered for this client");
    }
    let allowed = if query.resource == service.agent_resource() {
        auth::RUNTIME_SCOPES
    } else if query.resource == service.control_resource() {
        auth::MANAGEMENT_SCOPES
    } else {
        anyhow::bail!("resource must be the Jusso agent or control MCP endpoint");
    };
    let scopes = requested_scopes(query.scope.as_deref(), allowed)?;
    let raw_token = random_token();
    let token_hash = token_hash(&raw_token);
    sqlx::query(
        "DELETE FROM oauth_authorization_codes WHERE expires_at < now() - interval '1 day'",
    )
    .execute(&service.pool)
    .await
    .ok();
    sqlx::query("DELETE FROM connect_sessions WHERE expires_at < now() - interval '1 day'")
        .execute(&service.pool)
        .await
        .ok();
    sqlx::query(
        r#"INSERT INTO connect_sessions (
            id, token_hash, client_id, redirect_uri, client_state, code_challenge,
            resource, scopes, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(Uuid::new_v4())
    .bind(token_hash)
    .bind(query.client_id)
    .bind(query.redirect_uri)
    .bind(query.state)
    .bind(query.code_challenge)
    .bind(query.resource)
    .bind(scopes)
    .bind(Utc::now() + Duration::seconds(CONNECT_TTL_SECONDS))
    .execute(&service.pool)
    .await?;
    Ok(format!("/connect/{raw_token}"))
}

#[derive(Debug, Deserialize)]
struct ClientMetadataDocument {
    client_id: String,
    client_name: Option<String>,
    redirect_uris: Vec<String>,
    token_endpoint_auth_method: Option<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
}

async fn resolve_oauth_client(service: &ConnectService, client_id: &str) -> Result<OAuthClientRow> {
    if let Some(client) = sqlx::query_as::<_, OAuthClientRow>(
        "SELECT redirect_uris FROM oauth_clients WHERE client_id = $1",
    )
    .bind(client_id)
    .fetch_optional(&service.pool)
    .await?
    {
        return Ok(client);
    }

    auth::validate_federation_url(client_id)
        .context("unknown client_id must be an HTTPS Client ID Metadata Document URL")?;
    let response = auth::hardened_public_https_client(client_id)
        .await?
        .get(client_id)
        .send()
        .await
        .context("client metadata request failed")?;
    if !response.status().is_success() {
        anyhow::bail!("client metadata endpoint returned an error");
    }
    const MAX_CLIENT_METADATA_BYTES: u64 = 256 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CLIENT_METADATA_BYTES)
    {
        anyhow::bail!("client metadata document exceeds 256 KiB");
    }
    let bytes = response.bytes().await?;
    if bytes.len() as u64 > MAX_CLIENT_METADATA_BYTES {
        anyhow::bail!("client metadata document exceeds 256 KiB");
    }
    let metadata: ClientMetadataDocument =
        serde_json::from_slice(&bytes).context("client metadata document is invalid")?;
    if metadata.client_id != client_id {
        anyhow::bail!("client metadata client_id must exactly match its document URL");
    }
    let registration = ClientRegistrationRequest {
        client_name: metadata.client_name,
        redirect_uris: metadata.redirect_uris,
        token_endpoint_auth_method: metadata.token_endpoint_auth_method,
        grant_types: metadata.grant_types,
        response_types: metadata.response_types,
    };
    validate_client_registration(&registration)?;
    sqlx::query(
        r#"INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
           VALUES ($1, $2, $3) ON CONFLICT (client_id) DO NOTHING"#,
    )
    .bind(client_id)
    .bind(
        registration
            .client_name
            .as_deref()
            .unwrap_or("MCP metadata client"),
    )
    .bind(&registration.redirect_uris)
    .execute(&service.pool)
    .await?;
    Ok(OAuthClientRow {
        redirect_uris: registration.redirect_uris,
    })
}

fn requested_scopes(requested: Option<&str>, allowed: &[&str]) -> Result<Vec<String>> {
    let requested = requested
        .unwrap_or("")
        .split_whitespace()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let selected = if requested.is_empty() {
        allowed.to_vec()
    } else {
        requested
    };
    if selected.iter().any(|scope| !allowed.contains(scope)) {
        anyhow::bail!("requested scope is not available for this MCP endpoint");
    }
    Ok(selected.into_iter().map(str::to_string).collect())
}

#[derive(Debug, FromRow)]
struct ConnectSessionRow {
    id: Uuid,
    client_name: String,
    client_id: String,
    redirect_uri: String,
    client_state: Option<String>,
    code_challenge: String,
    resource: String,
    scopes: Vec<String>,
}

async fn pending_session(pool: &PgPool, raw_token: &str) -> Result<ConnectSessionRow> {
    sqlx::query_as::<_, ConnectSessionRow>(
        r#"SELECT cs.id, oc.client_name, cs.client_id, cs.redirect_uri,
                  cs.client_state, cs.code_challenge, cs.resource, cs.scopes
           FROM connect_sessions cs
           JOIN oauth_clients oc ON oc.client_id = cs.client_id
           WHERE cs.token_hash = $1 AND cs.status = 'pending' AND cs.expires_at > now()"#,
    )
    .bind(token_hash(raw_token))
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("Connect link is invalid, expired, or already used"))
}

pub async fn connect_page_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
) -> Response {
    let session = match pending_session(&service.pool, &token).await {
        Ok(session) => session,
        Err(_) => {
            return (
                StatusCode::GONE,
                Html("<h1>This Connect link is no longer available.</h1>"),
            )
                .into_response()
        }
    };
    let mut response = Html(connect_page_html(
        &token,
        service.config.registration_turnstile_site_key.as_deref(),
        session.resource == service.agent_resource(),
        service.config.public_registration_enabled,
        &session.client_name,
        &session.scopes,
    ))
    .into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().unwrap());
    response.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; script-src 'unsafe-inline' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        "permissions-policy",
        "publickey-credentials-create=(self), publickey-credentials-get=(self)"
            .parse()
            .unwrap(),
    );
    response
}

#[derive(Debug, Deserialize)]
pub struct RegistrationStartRequest {
    organization_name: String,
    display_name: String,
    owner_handle: String,
    agent_id: String,
    terms_accepted: bool,
    challenge_token: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredRegistration {
    session_id: Uuid,
    user_id: Uuid,
    organization_name: String,
    display_name: String,
    owner_handle: String,
    agent_id: String,
    state: PasskeyRegistration,
}

pub async fn registration_start_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<RegistrationStartRequest>,
) -> Response {
    match start_registration(&service, peer, &headers, &token, body).await {
        Ok((ceremony_id, challenge)) => Json(serde_json::json!({
            "ceremony_id": ceremony_id,
            "options": challenge
        }))
        .into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn start_registration(
    service: &ConnectService,
    peer: SocketAddr,
    headers: &HeaderMap,
    token: &str,
    body: RegistrationStartRequest,
) -> Result<(String, serde_json::Value)> {
    if !service.config.public_registration_enabled {
        anyhow::bail!("public registration is not available");
    }
    let session = pending_session(&service.pool, token).await?;
    validate_registration_fields(&body)?;
    let client_ip = registration_client_ip(
        headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    )?;
    let limiter = RateLimiter::new(
        service.redis.clone(),
        service.config.registration_hourly_limit as f64 / 3600.0,
        service.config.registration_hourly_limit as f64,
    );
    let client_fingerprint = keyed_fingerprint(
        &service.config.auth_secret_encryption_key,
        &client_ip.to_string(),
    );
    if limiter
        .check_key(&format!("connect-registration:{client_fingerprint}"))
        .await?
        .is_some()
    {
        anyhow::bail!("registration rate limit exceeded");
    }
    auth::verify_registration_challenge(
        service.config.registration_turnstile_secret.as_deref(),
        body.challenge_token.as_deref(),
        client_ip,
        &service.config.registration_allowed_hostnames,
    )
    .await?;
    let normalized_handle = normalize_owner_handle(&body.owner_handle)?;
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM owner_accounts WHERE owner_handle_normalized = $1)",
    )
    .bind(&normalized_handle)
    .fetch_one(&service.pool)
    .await?;
    if exists {
        anyhow::bail!("owner handle is already registered; use Sign in");
    }
    let user_id = Uuid::new_v4();
    let (challenge, state) = service.webauthn.start_passkey_registration(
        user_id,
        &normalized_handle,
        body.display_name.trim(),
        None,
    )?;
    let ceremony_id = random_token();
    store_ceremony(
        service,
        &ceremony_id,
        &StoredRegistration {
            session_id: session.id,
            user_id,
            organization_name: body.organization_name.trim().to_string(),
            display_name: body.display_name.trim().to_string(),
            owner_handle: normalized_handle,
            agent_id: body.agent_id.trim().to_string(),
            state,
        },
    )
    .await?;
    Ok((ceremony_id, serde_json::to_value(challenge)?))
}

fn validate_registration_fields(body: &RegistrationStartRequest) -> Result<()> {
    let organization = body.organization_name.trim();
    let display = body.display_name.trim();
    let agent = body.agent_id.trim();
    if !body.terms_accepted
        || !(2..=100).contains(&organization.len())
        || !(2..=100).contains(&display.len())
        || !(2..=128).contains(&agent.len())
        || !agent
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        anyhow::bail!("registration fields are invalid or terms were not accepted");
    }
    normalize_owner_handle(&body.owner_handle)?;
    Ok(())
}

fn normalize_owner_handle(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if !(3..=254).contains(&normalized.len())
        || !normalized.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'@' | b'.' | b'_' | b'+' | b'-')
        })
    {
        anyhow::bail!("owner handle must be 3-254 characters using letters, numbers, @, dot, dash, underscore, or plus");
    }
    Ok(normalized)
}

#[derive(Debug, Deserialize)]
pub struct RegistrationFinishRequest {
    ceremony_id: String,
    credential: RegisterPublicKeyCredential,
}

pub async fn registration_finish_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
    Json(body): Json<RegistrationFinishRequest>,
) -> Response {
    match finish_registration(&service, &token, body).await {
        Ok(redirect_uri) => Json(serde_json::json!({"redirect_uri": redirect_uri})).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn finish_registration(
    service: &ConnectService,
    token: &str,
    body: RegistrationFinishRequest,
) -> Result<String> {
    let session = pending_session(&service.pool, token).await?;
    let stored: StoredRegistration = take_ceremony(service, &body.ceremony_id).await?;
    if stored.session_id != session.id {
        anyhow::bail!("passkey ceremony does not belong to this Connect session");
    }
    let passkey = service
        .webauthn
        .finish_passkey_registration(&body.credential, &stored.state)
        .context("passkey registration verification failed")?;
    let passkey_id = Uuid::new_v4();
    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let turnkey_recovery_credential =
        turnkey_recovery_credential(&body.credential, &credential_id)?;
    let policy_actions = auth::DEFAULT_POLICY_ACTIONS
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let policy_protocols = auth::SUPPORTED_PROTOCOLS
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    let raw_code = random_token();
    let _registration = db::create_passkey_owner_registration(
        &service.pool,
        &service.config.auth_secret_encryption_key,
        db::PasskeyOwnerRegistrationOptions {
            chain: service.config.arc_network.name(),
            organization_name: &stored.organization_name,
            display_name: &stored.display_name,
            owner_handle: &stored.owner_handle,
            webauthn_user_id: stored.user_id,
            agent_external_id: &stored.agent_id,
            passkey_id,
            credential_id: &credential_id,
            passkey: &serde_json::to_value(passkey)?,
            turnkey_recovery_credential: &turnkey_recovery_credential,
            policy_actions: &policy_actions,
            policy_protocols: &policy_protocols,
            max_execution_fee_usd: auth::DEFAULT_MAX_EXECUTION_FEE_USD,
            connect_session_id: session.id,
            authorization_code_hash: &token_hash(&raw_code),
            oauth_client_id: &session.client_id,
            redirect_uri: &session.redirect_uri,
            code_challenge: &session.code_challenge,
            resource: &session.resource,
            oauth_scopes: &session.scopes,
            authorization_code_expires_at: Utc::now() + Duration::seconds(CODE_TTL_SECONDS),
            bind_agent_to_token: session.resource == service.agent_resource(),
        },
    )
    .await
    .context("owner account registration failed")?;
    authorization_redirect(&session, &raw_code, &service.config.oauth_issuer)
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationStartRequest {
    owner_handle: String,
    agent_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredAuthentication {
    session_id: Uuid,
    principal_id: Uuid,
    agent_id: Option<Uuid>,
    agent_external_id: Option<String>,
    state: PasskeyAuthentication,
}

#[derive(Debug, FromRow)]
struct OwnerPasskeyRow {
    id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    passkey: serde_json::Value,
}

pub async fn authentication_start_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
    Json(body): Json<AuthenticationStartRequest>,
) -> Response {
    match start_authentication(&service, peer, &headers, &token, body).await {
        Ok((ceremony_id, challenge)) => Json(serde_json::json!({
            "ceremony_id": ceremony_id,
            "options": challenge
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(%error, "Connect passkey sign-in could not be started");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "sign-in could not be started; check the owner handle and agent ID"
                })),
            )
                .into_response()
        }
    }
}

async fn start_authentication(
    service: &ConnectService,
    peer: SocketAddr,
    headers: &HeaderMap,
    token: &str,
    body: AuthenticationStartRequest,
) -> Result<(String, serde_json::Value)> {
    let session = pending_session(&service.pool, token).await?;
    let handle = normalize_owner_handle(&body.owner_handle)?;
    let client_ip = registration_client_ip(
        headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    )?;
    let limiter = RateLimiter::new(service.redis.clone(), 30.0 / 3600.0, 30.0);
    let ip_fingerprint = keyed_fingerprint(
        &service.config.auth_secret_encryption_key,
        &client_ip.to_string(),
    );
    let handle_fingerprint = keyed_fingerprint(&service.config.auth_secret_encryption_key, &handle);
    if limiter
        .check_key(&format!("connect-signin-ip:{ip_fingerprint}"))
        .await?
        .is_some()
        || limiter
            .check_key(&format!("connect-signin-owner:{handle_fingerprint}"))
            .await?
            .is_some()
    {
        anyhow::bail!("sign-in rate limit exceeded");
    }
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        r#"SELECT op.id, op.organization_id, op.principal_id, op.passkey
           FROM owner_passkeys op
           JOIN owner_accounts oa ON oa.principal_id = op.principal_id
           JOIN principals p ON p.id = op.principal_id AND p.status = 'active'
           JOIN organizations o ON o.id = op.organization_id AND o.status = 'active'
           WHERE oa.owner_handle_normalized = $1 AND op.status = 'active'"#,
    )
    .bind(handle)
    .fetch_all(&service.pool)
    .await?;
    let principal_id = rows
        .first()
        .map(|row| row.principal_id)
        .ok_or_else(|| anyhow!("owner account was not found"))?;
    let (agent_id, agent_external_id) = if session.resource == service.agent_resource() {
        let external_id = body
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("agent_id is required for an agent MCP connection"))?;
        let agent_id = sqlx::query_scalar::<_, Uuid>(
            r#"SELECT a.id FROM agents a
               JOIN principal_agent_grants pag ON pag.agent_id = a.id
               WHERE pag.principal_id = $1 AND a.external_id = $2 AND a.status = 'active'"#,
        )
        .bind(principal_id)
        .bind(external_id)
        .fetch_optional(&service.pool)
        .await?
        .ok_or_else(|| anyhow!("active agent is not available to this owner"))?;
        (Some(agent_id), Some(external_id.to_string()))
    } else {
        (None, None)
    };
    let passkeys = rows
        .iter()
        .map(|row| serde_json::from_value::<Passkey>(row.passkey.clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (challenge, state) = service.webauthn.start_passkey_authentication(&passkeys)?;
    let ceremony_id = random_token();
    store_ceremony(
        service,
        &ceremony_id,
        &StoredAuthentication {
            session_id: session.id,
            principal_id,
            agent_id,
            agent_external_id,
            state,
        },
    )
    .await?;
    Ok((ceremony_id, serde_json::to_value(challenge)?))
}

#[derive(Debug, Deserialize)]
pub struct AuthenticationFinishRequest {
    ceremony_id: String,
    credential: PublicKeyCredential,
}

pub async fn authentication_finish_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
    Json(body): Json<AuthenticationFinishRequest>,
) -> Response {
    match finish_authentication(&service, &token, body).await {
        Ok(redirect_uri) => Json(serde_json::json!({"redirect_uri": redirect_uri})).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": error.to_string()})),
        )
            .into_response(),
    }
}

async fn finish_authentication(
    service: &ConnectService,
    token: &str,
    body: AuthenticationFinishRequest,
) -> Result<String> {
    let session = pending_session(&service.pool, token).await?;
    let stored: StoredAuthentication = take_ceremony(service, &body.ceremony_id).await?;
    if stored.session_id != session.id {
        anyhow::bail!("passkey ceremony does not belong to this Connect session");
    }
    let result = service
        .webauthn
        .finish_passkey_authentication(&body.credential, &stored.state)
        .context("passkey authentication failed")?;
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        "SELECT id, organization_id, principal_id, passkey FROM owner_passkeys WHERE principal_id = $1 AND status = 'active'",
    )
    .bind(stored.principal_id)
    .fetch_all(&service.pool)
    .await?;
    let mut matched = None;
    for row in rows {
        let mut passkey: Passkey = serde_json::from_value(row.passkey.clone())?;
        if passkey.update_credential(&result).is_some() {
            let updated = sqlx::query(
                r#"UPDATE owner_passkeys
                   SET passkey = $2, last_used_at = now(), updated_at = now()
                   WHERE id = $1 AND status = 'active'"#,
            )
            .bind(row.id)
            .bind(serde_json::to_value(passkey)?)
            .execute(&service.pool)
            .await?;
            if updated.rows_affected() == 1 {
                matched = Some(row);
                break;
            }
        }
    }
    let passkey = matched.ok_or_else(|| anyhow!("authenticated passkey is not registered"))?;
    let owner = ConnectOwner {
        organization_id: passkey.organization_id,
        principal_id: passkey.principal_id,
        passkey_id: passkey.id,
    };
    complete_connect_session(
        &service.pool,
        &session,
        &service.config.oauth_issuer,
        &owner,
        stored.agent_id,
        stored.agent_external_id.as_deref(),
    )
    .await
}

struct ConnectOwner {
    organization_id: Uuid,
    principal_id: Uuid,
    passkey_id: Uuid,
}

async fn complete_connect_session(
    pool: &PgPool,
    session: &ConnectSessionRow,
    issuer: &str,
    owner: &ConnectOwner,
    agent_id: Option<Uuid>,
    agent_external_id: Option<&str>,
) -> Result<String> {
    let raw_code = random_token();
    let code_hash = token_hash(&raw_code);
    let mut transaction = pool.begin().await?;
    let updated = sqlx::query(
        r#"UPDATE connect_sessions
           SET status = 'completed', organization_id = $2, principal_id = $3,
               passkey_id = $4, selected_agent_id = $5,
               selected_agent_external_id = $6, completed_at = now()
           WHERE id = $1 AND status = 'pending' AND expires_at > now()
             AND EXISTS (
                 SELECT 1 FROM owner_passkeys op
                 WHERE op.id = $4 AND op.organization_id = $2
                   AND op.principal_id = $3 AND op.status = 'active'
             )"#,
    )
    .bind(session.id)
    .bind(owner.organization_id)
    .bind(owner.principal_id)
    .bind(owner.passkey_id)
    .bind(agent_id)
    .bind(agent_external_id)
    .execute(&mut *transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!("Connect session was already completed or expired");
    }
    sqlx::query(
        r#"INSERT INTO oauth_authorization_codes (
            code_hash, connect_session_id, organization_id, principal_id, passkey_id,
            agent_id, agent_external_id, client_id, redirect_uri, code_challenge,
            resource, scopes, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
    )
    .bind(code_hash)
    .bind(session.id)
    .bind(owner.organization_id)
    .bind(owner.principal_id)
    .bind(owner.passkey_id)
    .bind(agent_id)
    .bind(agent_external_id)
    .bind(&session.client_id)
    .bind(&session.redirect_uri)
    .bind(&session.code_challenge)
    .bind(&session.resource)
    .bind(&session.scopes)
    .bind(Utc::now() + Duration::seconds(CODE_TTL_SECONDS))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;

    authorization_redirect(session, &raw_code, issuer)
}

#[derive(Debug, FromRow)]
struct PendingPasskeyEnrollmentRow {
    id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    label: String,
    purpose: String,
    replaces_passkey_id: Option<Uuid>,
    owner_handle: String,
    display_name: String,
    webauthn_user_id: Uuid,
}

async fn pending_passkey_enrollment(
    pool: &PgPool,
    raw_token: &str,
) -> Result<PendingPasskeyEnrollmentRow> {
    let hash = token_hash(raw_token);
    sqlx::query(
        r#"UPDATE owner_passkey_enrollment_requests SET status = 'expired'
           WHERE token_hash = $1 AND status = 'pending' AND expires_at <= now()"#,
    )
    .bind(&hash)
    .execute(pool)
    .await?;
    sqlx::query_as::<_, PendingPasskeyEnrollmentRow>(
        r#"SELECT r.id, r.organization_id, r.principal_id, r.label, r.purpose,
                  r.replaces_passkey_id, oa.owner_handle_normalized AS owner_handle,
                  oa.display_name, oa.webauthn_user_id
           FROM owner_passkey_enrollment_requests r
           JOIN owner_accounts oa ON oa.principal_id = r.principal_id
             AND oa.organization_id = r.organization_id
           JOIN oauth_connections c ON c.id = r.oauth_connection_id
             AND c.organization_id = r.organization_id
             AND c.principal_id = r.principal_id
           JOIN principals p ON p.id = r.principal_id AND p.status = 'active'
           JOIN organizations o ON o.id = r.organization_id AND o.status = 'active'
           WHERE r.token_hash = $1 AND r.status = 'pending' AND r.expires_at > now()
             AND c.status = 'active' AND c.agent_id IS NULL
             AND oa.webauthn_user_id IS NOT NULL"#,
    )
    .bind(hash)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("passkey enrollment link is invalid, expired, or already used"))
}

pub async fn owner_passkey_enrollment_page_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
) -> Response {
    let enrollment = match pending_passkey_enrollment(&service.pool, &token).await {
        Ok(enrollment) => enrollment,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Html("This passkey enrollment link is invalid or expired.".to_string()),
            )
                .into_response()
        }
    };
    let mut response = Html(passkey_enrollment_page_html(
        &token,
        &enrollment.label,
        &enrollment.purpose,
        enrollment.replaces_passkey_id.is_some(),
    ))
    .into_response();
    response.headers_mut().insert(
        "cache-control",
        "no-store, max-age=0".parse().expect("static header"),
    );
    response.headers_mut().insert(
        "referrer-policy",
        "no-referrer".parse().expect("static header"),
    );
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().expect("static header"));
    response.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'"
            .parse()
            .expect("static header"),
    );
    response.headers_mut().insert(
        "permissions-policy",
        "publickey-credentials-get=(self), publickey-credentials-create=(self)"
            .parse()
            .expect("static header"),
    );
    response
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredPasskeyEnrollmentAuthentication {
    request_id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    state: PasskeyAuthentication,
}

pub async fn owner_passkey_enrollment_auth_start_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    match start_passkey_enrollment_authentication(&service, peer, &headers, &token).await {
        Ok((ceremony_id, options)) => Json(serde_json::json!({
            "ceremony_id": ceremony_id,
            "options": options
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(%error, "passkey enrollment authentication could not be started");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "passkey enrollment could not be started"})),
            )
                .into_response()
        }
    }
}

async fn start_passkey_enrollment_authentication(
    service: &ConnectService,
    peer: SocketAddr,
    headers: &HeaderMap,
    token: &str,
) -> Result<(String, serde_json::Value)> {
    let enrollment = pending_passkey_enrollment(&service.pool, token).await?;
    let client_ip = registration_client_ip(
        headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    )?;
    let limiter = RateLimiter::new(service.redis.clone(), 20.0 / 3600.0, 20.0);
    let fingerprint = keyed_fingerprint(
        &service.config.auth_secret_encryption_key,
        &client_ip.to_string(),
    );
    if limiter
        .check_key(&format!("passkey-enrollment:{fingerprint}"))
        .await?
        .is_some()
    {
        anyhow::bail!("passkey enrollment rate limit exceeded");
    }
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        r#"SELECT id, organization_id, principal_id, passkey
           FROM owner_passkeys
           WHERE organization_id = $1 AND principal_id = $2 AND status = 'active'"#,
    )
    .bind(enrollment.organization_id)
    .bind(enrollment.principal_id)
    .fetch_all(&service.pool)
    .await?;
    if rows.is_empty() {
        anyhow::bail!("owner has no active passkey");
    }
    let passkeys = rows
        .into_iter()
        .map(|row| serde_json::from_value::<Passkey>(row.passkey))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (challenge, state) = service.webauthn.start_passkey_authentication(&passkeys)?;
    let ceremony_id = random_token();
    store_ceremony(
        service,
        &ceremony_id,
        &StoredPasskeyEnrollmentAuthentication {
            request_id: enrollment.id,
            organization_id: enrollment.organization_id,
            principal_id: enrollment.principal_id,
            state,
        },
    )
    .await?;
    Ok((ceremony_id, serde_json::to_value(challenge)?))
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredAdditionalPasskeyRegistration {
    request_id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    authenticated_by_passkey_id: Uuid,
    state: PasskeyRegistration,
}

pub async fn owner_passkey_enrollment_auth_finish_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
    Json(body): Json<AuthenticationFinishRequest>,
) -> Response {
    match finish_passkey_enrollment_authentication(&service, &token, body).await {
        Ok((ceremony_id, options)) => Json(serde_json::json!({
            "ceremony_id": ceremony_id,
            "options": options
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(%error, "passkey enrollment authentication failed");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "owner passkey authentication failed"})),
            )
                .into_response()
        }
    }
}

async fn finish_passkey_enrollment_authentication(
    service: &ConnectService,
    token: &str,
    body: AuthenticationFinishRequest,
) -> Result<(String, serde_json::Value)> {
    let enrollment = pending_passkey_enrollment(&service.pool, token).await?;
    let stored: StoredPasskeyEnrollmentAuthentication =
        take_ceremony(service, &body.ceremony_id).await?;
    if stored.request_id != enrollment.id
        || stored.organization_id != enrollment.organization_id
        || stored.principal_id != enrollment.principal_id
    {
        anyhow::bail!("authentication ceremony does not belong to this enrollment");
    }
    let result = service
        .webauthn
        .finish_passkey_authentication(&body.credential, &stored.state)
        .context("passkey enrollment owner authentication failed")?;
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        r#"SELECT id, organization_id, principal_id, passkey
           FROM owner_passkeys
           WHERE organization_id = $1 AND principal_id = $2 AND status = 'active'"#,
    )
    .bind(enrollment.organization_id)
    .bind(enrollment.principal_id)
    .fetch_all(&service.pool)
    .await?;
    let mut matched = None;
    let mut active_passkeys = Vec::with_capacity(rows.len());
    for row in rows {
        let mut passkey: Passkey = serde_json::from_value(row.passkey)?;
        if passkey.update_credential(&result).is_some() {
            matched = Some((row.id, serde_json::to_value(&passkey)?));
        }
        active_passkeys.push(passkey);
    }
    let (authenticated_by, updated_passkey) =
        matched.ok_or_else(|| anyhow!("authenticated passkey is not registered"))?;
    db::authenticate_owner_passkey_enrollment(
        &service.pool,
        enrollment.id,
        authenticated_by,
        &updated_passkey,
    )
    .await?;
    let exclude = active_passkeys
        .iter()
        .map(|passkey| passkey.cred_id().clone())
        .collect::<Vec<_>>();
    let (challenge, state) = service.webauthn.start_passkey_registration(
        enrollment.webauthn_user_id,
        &enrollment.owner_handle,
        &enrollment.display_name,
        Some(exclude),
    )?;
    let ceremony_id = random_token();
    store_ceremony(
        service,
        &ceremony_id,
        &StoredAdditionalPasskeyRegistration {
            request_id: enrollment.id,
            organization_id: enrollment.organization_id,
            principal_id: enrollment.principal_id,
            authenticated_by_passkey_id: authenticated_by,
            state,
        },
    )
    .await?;
    Ok((ceremony_id, serde_json::to_value(challenge)?))
}

pub async fn owner_passkey_enrollment_register_finish_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
    Json(body): Json<RegistrationFinishRequest>,
) -> Response {
    match finish_additional_passkey_registration(&service, &token, body).await {
        Ok(result) => {
            Json(serde_json::json!({"completed": true, "result": result})).into_response()
        }
        Err(error) => {
            tracing::warn!(%error, "additional passkey registration failed");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "new passkey registration failed"})),
            )
                .into_response()
        }
    }
}

async fn finish_additional_passkey_registration(
    service: &ConnectService,
    token: &str,
    body: RegistrationFinishRequest,
) -> Result<serde_json::Value> {
    let enrollment = pending_passkey_enrollment(&service.pool, token).await?;
    let stored: StoredAdditionalPasskeyRegistration =
        take_ceremony(service, &body.ceremony_id).await?;
    if stored.request_id != enrollment.id
        || stored.organization_id != enrollment.organization_id
        || stored.principal_id != enrollment.principal_id
    {
        anyhow::bail!("registration ceremony does not belong to this enrollment");
    }
    let passkey = service
        .webauthn
        .finish_passkey_registration(&body.credential, &stored.state)
        .context("additional passkey registration verification failed")?;
    let credential_id = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());
    let turnkey_recovery_credential =
        turnkey_recovery_credential(&body.credential, &credential_id)?;
    db::complete_owner_passkey_enrollment(
        &service.pool,
        db::CompleteOwnerPasskeyEnrollmentOptions {
            request_id: enrollment.id,
            authenticated_by_passkey_id: stored.authenticated_by_passkey_id,
            new_passkey_id: Uuid::new_v4(),
            credential_id: &credential_id,
            passkey: &serde_json::to_value(passkey)?,
            turnkey_recovery_credential: &turnkey_recovery_credential,
        },
    )
    .await
}

#[derive(Deserialize)]
struct WebauthnClientData {
    challenge: String,
}

fn turnkey_recovery_credential(
    credential: &RegisterPublicKeyCredential,
    verified_credential_id: &str,
) -> Result<serde_json::Value> {
    if verified_credential_id.is_empty() || verified_credential_id.len() > 256 {
        anyhow::bail!("passkey credential ID cannot be used for Turnkey recovery");
    }
    let client_data = credential.response.client_data_json.as_ref();
    let challenge = serde_json::from_slice::<WebauthnClientData>(client_data)
        .context("passkey client data is invalid")?
        .challenge;
    if challenge.is_empty() || challenge.len() > 256 {
        anyhow::bail!("passkey challenge cannot be used for Turnkey recovery");
    }
    let transports = credential
        .response
        .transports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|transport| {
            let serialized = serde_json::to_value(transport).ok()?;
            match serialized.as_str()? {
                "ble" => Some("AUTHENTICATOR_TRANSPORT_BLE"),
                "internal" => Some("AUTHENTICATOR_TRANSPORT_INTERNAL"),
                "nfc" => Some("AUTHENTICATOR_TRANSPORT_NFC"),
                "usb" => Some("AUTHENTICATOR_TRANSPORT_USB"),
                "hybrid" => Some("AUTHENTICATOR_TRANSPORT_HYBRID"),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "authenticatorName": "Jusso Owner Passkey",
        "challenge": challenge,
        "attestation": {
            "credentialId": verified_credential_id,
            "clientDataJson": URL_SAFE_NO_PAD.encode(client_data),
            "attestationObject": URL_SAFE_NO_PAD.encode(
                credential.response.attestation_object.as_ref()
            ),
            "transports": transports,
        }
    }))
}

fn passkey_enrollment_page_html(
    token: &str,
    label: &str,
    purpose: &str,
    replacing: bool,
) -> String {
    let token = serde_json::to_string(token).expect("token is serializable");
    let label = html_escape(label);
    let purpose = html_escape(purpose);
    let verb = if replacing { "Replace" } else { "Add" };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{verb} owner passkey</title><style>
:root{{color-scheme:light dark;--ink:#111713;--paper:#f5f7f5;--line:#ccd5ce;--green:#008f50;--muted:#5f6d64}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--paper);color:var(--ink)}}
main{{width:min(560px,calc(100% - 32px));margin:8vh auto}}h1{{font-size:30px;margin:8px 0}}p{{color:var(--muted)}}
.mark{{font-weight:800;letter-spacing:.08em}}.panel{{border:1px solid var(--line);padding:24px}}dl{{display:grid;grid-template-columns:auto 1fr;gap:8px 18px;margin:0 0 22px}}dt{{color:var(--muted)}}dd{{margin:0;font-weight:650}}button{{width:100%;padding:12px;border:0;background:var(--green);color:white;font:inherit;font-weight:700;cursor:pointer}}button:disabled{{opacity:.55}}#message{{min-height:24px;margin-top:16px}}
</style></head><body><main><div class="mark">JUSSO</div><h1>{verb} owner passkey</h1><p>Confirm with an active owner passkey, then create the new credential.</p><section class="panel"><dl><dt>Label</dt><dd>{label}</dd><dt>Purpose</dt><dd>{purpose}</dd></dl><button id="continue">Continue with passkeys</button><div id="message" role="alert"></div></section></main>
<script>
const token={token};const message=document.querySelector('#message');const button=document.querySelector('#continue');
const b64u=b=>{{let s='';new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}};
const bytes=s=>{{s=s.replaceAll('-','+').replaceAll('_','/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}};
function creation(o){{o.challenge=bytes(o.challenge);o.user.id=bytes(o.user.id);(o.excludeCredentials||[]).forEach(c=>c.id=bytes(c.id));return o}}
function request(o){{o.challenge=bytes(o.challenge);(o.allowCredentials||[]).forEach(c=>c.id=bytes(c.id));return o}}
function regJSON(c){{return {{id:c.id,type:c.type,rawId:b64u(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{{attestationObject:b64u(c.response.attestationObject),clientDataJSON:b64u(c.response.clientDataJSON),transports:c.response.getTransports?c.response.getTransports():[]}},clientExtensionResults:c.getClientExtensionResults()}}}}
function authJSON(c){{return {{id:c.id,type:c.type,rawId:b64u(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{{authenticatorData:b64u(c.response.authenticatorData),clientDataJSON:b64u(c.response.clientDataJSON),signature:b64u(c.response.signature),userHandle:c.response.userHandle?b64u(c.response.userHandle):null}},clientExtensionResults:c.getClientExtensionResults()}}}}
async function post(path,body){{const r=await fetch(`/passkeys/enroll/${{token}}/${{path}}`,{{method:'POST',headers:{{'content-type':'application/json'}},body:body?JSON.stringify(body):null}});const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');return j}}
button.onclick=async()=>{{button.disabled=true;message.textContent='Confirming owner passkey...';try{{const auth=await post('authenticate/start');const existing=await navigator.credentials.get({{publicKey:request(auth.options.publicKey)}});const registration=await post('authenticate/finish',{{ceremony_id:auth.ceremony_id,credential:authJSON(existing)}});message.textContent='Create the new passkey...';const created=await navigator.credentials.create({{publicKey:creation(registration.options.publicKey)}});await post('register/finish',{{ceremony_id:registration.ceremony_id,credential:regJSON(created)}});message.textContent='Passkey updated. You may return to your assistant.'}}catch(err){{button.disabled=false;message.textContent=err.message}}}};
</script></body></html>"#
    )
}

#[derive(Debug, FromRow)]
struct PendingOwnerApprovalRow {
    id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    client_name: String,
    presentation: serde_json::Value,
    excluded_passkey_id: Option<Uuid>,
}

async fn pending_owner_approval(pool: &PgPool, raw_token: &str) -> Result<PendingOwnerApprovalRow> {
    sqlx::query(
        r#"UPDATE owner_approval_requests SET status = 'expired'
           WHERE token_hash = $1 AND status = 'pending' AND expires_at <= now()"#,
    )
    .bind(token_hash(raw_token))
    .execute(pool)
    .await?;
    sqlx::query_as::<_, PendingOwnerApprovalRow>(
        r#"SELECT ar.id, ar.organization_id, ar.principal_id,
                  oc.client_name, ar.presentation,
                  CASE WHEN ar.action = 'revoke_owner_passkey'
                       THEN (ar.payload->>'passkey_id')::uuid
                  END AS excluded_passkey_id
           FROM owner_approval_requests ar
           JOIN oauth_connections c ON c.id = ar.oauth_connection_id
           JOIN oauth_clients oc ON oc.client_id = c.client_id
           JOIN principals p ON p.id = ar.principal_id AND p.status = 'active'
           JOIN organizations o ON o.id = ar.organization_id AND o.status = 'active'
           WHERE ar.token_hash = $1 AND ar.status = 'pending'
             AND ar.expires_at > now() AND c.status = 'active'
             AND c.organization_id = ar.organization_id
             AND c.principal_id = ar.principal_id AND c.agent_id IS NULL"#,
    )
    .bind(token_hash(raw_token))
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow!("approval link is invalid, expired, or already used"))
}

pub async fn owner_approval_page_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
) -> Response {
    let approval = match pending_owner_approval(&service.pool, &token).await {
        Ok(approval) => approval,
        Err(_) => {
            return (
                StatusCode::GONE,
                Html("<h1>This approval link is no longer available.</h1>"),
            )
                .into_response()
        }
    };
    let mut response = Html(owner_approval_page_html(
        &token,
        &approval.client_name,
        &approval.presentation,
    ))
    .into_response();
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().unwrap());
    response.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'"
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        "permissions-policy",
        "publickey-credentials-get=(self)".parse().unwrap(),
    );
    response
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredOwnerApprovalAuthentication {
    approval_id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    state: PasskeyAuthentication,
}

pub async fn owner_approval_start_handler(
    State(service): State<ConnectService>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Response {
    match start_owner_approval(&service, peer, &headers, &token).await {
        Ok((ceremony_id, challenge)) => Json(serde_json::json!({
            "ceremony_id": ceremony_id,
            "options": challenge
        }))
        .into_response(),
        Err(error) => {
            tracing::warn!(%error, "owner approval ceremony could not be started");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "approval could not be started"})),
            )
                .into_response()
        }
    }
}

async fn start_owner_approval(
    service: &ConnectService,
    peer: SocketAddr,
    headers: &HeaderMap,
    token: &str,
) -> Result<(String, serde_json::Value)> {
    let approval = pending_owner_approval(&service.pool, token).await?;
    let client_ip = registration_client_ip(
        headers,
        peer.ip(),
        service.config.registration_client_ip_header.as_deref(),
    )?;
    let limiter = RateLimiter::new(service.redis.clone(), 30.0 / 3600.0, 30.0);
    let fingerprint = keyed_fingerprint(
        &service.config.auth_secret_encryption_key,
        &client_ip.to_string(),
    );
    if limiter
        .check_key(&format!("owner-approval:{fingerprint}"))
        .await?
        .is_some()
    {
        anyhow::bail!("approval rate limit exceeded");
    }
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        r#"SELECT op.id, op.organization_id, op.principal_id, op.passkey
           FROM owner_passkeys op
           WHERE op.organization_id = $1 AND op.principal_id = $2
             AND op.status = 'active' AND op.id IS DISTINCT FROM $3"#,
    )
    .bind(approval.organization_id)
    .bind(approval.principal_id)
    .bind(approval.excluded_passkey_id)
    .fetch_all(&service.pool)
    .await?;
    if rows.is_empty() {
        anyhow::bail!("owner has no registered passkey");
    }
    let passkeys = rows
        .into_iter()
        .map(|row| serde_json::from_value::<Passkey>(row.passkey))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let (challenge, state) = service.webauthn.start_passkey_authentication(&passkeys)?;
    let ceremony_id = random_token();
    store_ceremony(
        service,
        &ceremony_id,
        &StoredOwnerApprovalAuthentication {
            approval_id: approval.id,
            organization_id: approval.organization_id,
            principal_id: approval.principal_id,
            state,
        },
    )
    .await?;
    Ok((ceremony_id, serde_json::to_value(challenge)?))
}

pub async fn owner_approval_finish_handler(
    State(service): State<ConnectService>,
    Path(token): Path<String>,
    Json(body): Json<AuthenticationFinishRequest>,
) -> Response {
    match finish_owner_approval(&service, &token, body).await {
        Ok(result) => Json(serde_json::json!({"approved": true, "result": result})).into_response(),
        Err(error) => {
            tracing::warn!(%error, "owner approval failed");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "approval failed or is no longer available"})),
            )
                .into_response()
        }
    }
}

async fn finish_owner_approval(
    service: &ConnectService,
    token: &str,
    body: AuthenticationFinishRequest,
) -> Result<serde_json::Value> {
    let approval = pending_owner_approval(&service.pool, token).await?;
    let stored: StoredOwnerApprovalAuthentication =
        take_ceremony(service, &body.ceremony_id).await?;
    if stored.approval_id != approval.id
        || stored.organization_id != approval.organization_id
        || stored.principal_id != approval.principal_id
    {
        anyhow::bail!("passkey ceremony does not belong to this approval request");
    }
    let result = service
        .webauthn
        .finish_passkey_authentication(&body.credential, &stored.state)
        .context("owner approval passkey verification failed")?;
    let rows = sqlx::query_as::<_, OwnerPasskeyRow>(
        r#"SELECT id, organization_id, principal_id, passkey
           FROM owner_passkeys WHERE organization_id = $1 AND principal_id = $2
             AND status = 'active'"#,
    )
    .bind(approval.organization_id)
    .bind(approval.principal_id)
    .fetch_all(&service.pool)
    .await?;
    let mut matched = None;
    for row in rows {
        let mut passkey: Passkey = serde_json::from_value(row.passkey)?;
        if passkey.update_credential(&result).is_some() {
            matched = Some((row.id, serde_json::to_value(passkey)?));
            break;
        }
    }
    let (passkey_id, updated_passkey) =
        matched.ok_or_else(|| anyhow!("authenticated passkey is not registered"))?;
    db::complete_owner_approval(
        &service.pool,
        approval.id,
        approval.organization_id,
        approval.principal_id,
        passkey_id,
        &updated_passkey,
        service.config.arc_network.name(),
    )
    .await
}

fn owner_approval_page_html(
    token: &str,
    client_name: &str,
    presentation: &serde_json::Value,
) -> String {
    let token = serde_json::to_string(token).expect("token is serializable");
    let client_name = html_escape(client_name);
    let review = html_escape(
        &serde_json::to_string_pretty(presentation).expect("approval presentation is serializable"),
    );
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve Jusso change</title><style>
:root{{color-scheme:light dark;--ink:#111713;--paper:#f5f7f5;--line:#ccd5ce;--green:#008f50;--muted:#5f6d64}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--paper);color:var(--ink)}}
main{{width:min(720px,calc(100% - 32px));margin:7vh auto}}h1{{font-size:30px;margin:8px 0}}p{{color:var(--muted)}}
.mark{{font-weight:800;letter-spacing:.08em}}.panel{{border:1px solid var(--line);padding:24px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid var(--line);padding:16px;font-size:12px;line-height:1.6}}
button{{width:100%;padding:12px;border:0;background:var(--green);color:white;font:inherit;font-weight:700;cursor:pointer}}#message{{min-height:24px;margin-top:16px}}
</style></head><body><main><div class="mark">JUSSO</div><h1>Review authority change</h1><p>Requested by <strong>{client_name}</strong>. The change below is applied only after this passkey approval.</p><section class="panel"><pre>{review}</pre><button id="approve">Approve with passkey</button><div id="message" role="alert"></div></section></main>
<script>
const token={token};const message=document.querySelector('#message');
const b64u=b=>{{let s='';new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}};
const bytes=s=>{{s=s.replaceAll('-','+').replaceAll('_','/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}};
function request(o){{o.challenge=bytes(o.challenge);(o.allowCredentials||[]).forEach(c=>c.id=bytes(c.id));return o}}
function authJSON(c){{return {{id:c.id,type:c.type,rawId:b64u(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{{authenticatorData:b64u(c.response.authenticatorData),clientDataJSON:b64u(c.response.clientDataJSON),signature:b64u(c.response.signature),userHandle:c.response.userHandle?b64u(c.response.userHandle):null}},clientExtensionResults:c.getClientExtensionResults()}}}}
async function post(path,body){{const r=await fetch(`/approve/${{token}}/${{path}}`,{{method:'POST',headers:{{'content-type':'application/json'}},body:body?JSON.stringify(body):null}});const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');return j}}
document.querySelector('#approve').onclick=async()=>{{message.textContent='';try{{const start=await post('start');const c=await navigator.credentials.get({{publicKey:request(start.options.publicKey)}});await post('finish',{{ceremony_id:start.ceremony_id,credential:authJSON(c)}});document.querySelector('#approve').disabled=true;message.textContent='Approved. You may return to your assistant.'}}catch(err){{message.textContent=err.message}}}};
</script></body></html>"#
    )
}

fn authorization_redirect(
    session: &ConnectSessionRow,
    raw_code: &str,
    issuer: &str,
) -> Result<String> {
    let mut redirect = reqwest::Url::parse(&session.redirect_uri)?;
    redirect.query_pairs_mut().append_pair("code", raw_code);
    redirect.query_pairs_mut().append_pair("iss", issuer);
    if let Some(state) = &session.client_state {
        redirect.query_pairs_mut().append_pair("state", state);
    }
    Ok(redirect.to_string())
}

async fn store_ceremony<T: Serialize>(
    service: &ConnectService,
    ceremony_id: &str,
    value: &T,
) -> Result<()> {
    let mut redis = service.redis.clone();
    let serialized = serde_json::to_string(value)?;
    redis
        .set_ex::<_, _, ()>(
            format!("jusso:connect:ceremony:{}", token_hash(ceremony_id)),
            serialized,
            CEREMONY_TTL_SECONDS,
        )
        .await?;
    Ok(())
}

async fn take_ceremony<T: for<'de> Deserialize<'de>>(
    service: &ConnectService,
    ceremony_id: &str,
) -> Result<T> {
    let mut redis = service.redis.clone();
    let value: Option<String> = redis
        .get_del(format!(
            "jusso:connect:ceremony:{}",
            token_hash(ceremony_id)
        ))
        .await?;
    serde_json::from_str(
        value
            .as_deref()
            .ok_or_else(|| anyhow!("passkey ceremony is invalid, expired, or already used"))?,
    )
    .context("stored passkey ceremony is invalid")
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn keyed_fingerprint(secret: &str, value: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn registration_client_ip(
    headers: &HeaderMap,
    peer_ip: std::net::IpAddr,
    trusted_header: Option<&str>,
) -> Result<std::net::IpAddr> {
    let Some(header_name) = trusted_header else {
        return Ok(peer_ip);
    };
    headers
        .get(header_name)
        .ok_or_else(|| anyhow!("configured client-IP header is missing"))?
        .to_str()
        .context("client-IP header is invalid")?
        .split(',')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("client-IP header is empty"))?
        .parse()
        .context("client-IP header is not an IP address")
}

fn connect_page_html(
    token: &str,
    turnstile_site_key: Option<&str>,
    agent_connection: bool,
    registration_enabled: bool,
    client_name: &str,
    scopes: &[String],
) -> String {
    let token = serde_json::to_string(token).expect("token is serializable");
    let client_name = html_escape(client_name);
    let turnstile = turnstile_site_key.map_or_else(String::new, |key| {
        format!(
            r#"<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
            <div class="cf-turnstile" data-sitekey="{}" data-action="register"></div>"#,
            html_escape(key)
        )
    });
    let sign_in_agent = if agent_connection {
        r#"<label>Agent ID</label><input name="agent_id" required value="primary-agent">"#
    } else {
        ""
    };
    let connection_kind = if agent_connection {
        "Agent runtime"
    } else {
        "Organization control"
    };
    let scope_list = scopes
        .iter()
        .map(|scope| format!("<li><code>{}</code></li>", html_escape(scope)))
        .collect::<String>();
    let registration_tab = if registration_enabled {
        r#"<button class="tab active" data-mode="register">Create account</button>"#
    } else {
        ""
    };
    let sign_in_tab_class = if registration_enabled {
        "tab"
    } else {
        "tab active"
    };
    let sign_in_form_class = if registration_enabled { "hidden" } else { "" };
    let registration_form = if registration_enabled {
        format!(
            r#"<form id="register"><label>Organization</label><input name="organization_name" required minlength="2"><label>Your name</label><input name="display_name" required minlength="2"><label>Owner handle</label><input name="owner_handle" required autocomplete="username" placeholder="you@example.com"><label>First agent ID</label><input name="agent_id" required value="primary-agent"><label><input style="width:auto" type="checkbox" name="terms_accepted" required> I authorize this connection and accept the terms.</label>{turnstile}<button class="primary">Create passkey and connect</button></form>"#
        )
    } else {
        String::new()
    };
    let registration_script = if registration_enabled {
        r#"document.querySelector('#register').onsubmit=async e=>{e.preventDefault();message.textContent='';try{const f=new FormData(e.target);const start=await post('register/start',{organization_name:f.get('organization_name'),display_name:f.get('display_name'),owner_handle:f.get('owner_handle'),agent_id:f.get('agent_id'),terms_accepted:true,challenge_token:window.turnstile?turnstile.getResponse():null});const c=await navigator.credentials.create({publicKey:creation(start.options.publicKey)});const done=await post('register/finish',{ceremony_id:start.ceremony_id,credential:regJSON(c)});location.assign(done.redirect_uri)}catch(err){message.textContent=err.message}};"#
    } else {
        ""
    };
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connect to Jusso</title><style>
:root{{color-scheme:light dark;--ink:#111713;--paper:#f5f7f5;--line:#ccd5ce;--green:#00a85a;--muted:#5f6d64}}
*{{box-sizing:border-box}}body{{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--paper);color:var(--ink)}}
main{{width:min(560px,calc(100% - 32px));margin:8vh auto}}header{{margin-bottom:28px}}h1{{font-size:30px;margin:8px 0}}p{{color:var(--muted)}}
.mark{{font-weight:800;letter-spacing:.08em}}.panel{{border:1px solid var(--line);padding:24px;background:color-mix(in srgb,var(--paper) 92%,white)}}
.tabs{{display:flex;border-bottom:1px solid var(--line);margin-bottom:20px}}button{{font:inherit;cursor:pointer}}.tab{{border:0;background:none;padding:10px 14px;border-bottom:2px solid transparent}}.tab.active{{border-color:var(--green)}}
label{{display:block;margin:13px 0 5px;font-weight:600}}input{{width:100%;padding:11px;border:1px solid var(--line);background:transparent;color:inherit}}.primary{{width:100%;margin-top:20px;padding:12px;border:0;background:var(--green);color:white;font-weight:700}}.hidden{{display:none}}#message{{min-height:24px;margin-top:16px;color:#a32828}}.consent{{border:1px solid var(--line);padding:12px 14px;margin:18px 0}}.consent strong{{display:block}}.consent ul{{margin:8px 0 0;padding-left:20px}}code{{font-size:12px}}
</style></head><body><main><header><div class="mark">JUSSO</div><h1>Connect your agent</h1><p>One owner approval creates a protected organization and lets your assistant use only the permissions shown by Jusso.</p></header>
<section class="panel"><div class="consent"><strong>{client_name}</strong><span>{connection_kind}</span><ul>{scope_list}</ul></div><div class="tabs">{registration_tab}<button class="{sign_in_tab_class}" data-mode="signin">Sign in</button></div>
{registration_form}
<form id="signin" class="{sign_in_form_class}"><label>Owner handle</label><input name="owner_handle" required autocomplete="username">{sign_in_agent}<button class="primary">Approve with passkey</button></form><div id="message" role="alert"></div></section></main>
<script>
const token={token}; const message=document.querySelector('#message');
const b64u=b=>{{let s='';new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replaceAll('=','')}};
const bytes=s=>{{s=s.replaceAll('-','+').replaceAll('_','/');while(s.length%4)s+='=';return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}};
function creation(o){{o.challenge=bytes(o.challenge);o.user.id=bytes(o.user.id);(o.excludeCredentials||[]).forEach(c=>c.id=bytes(c.id));return o}}
function request(o){{o.challenge=bytes(o.challenge);(o.allowCredentials||[]).forEach(c=>c.id=bytes(c.id));return o}}
function regJSON(c){{return {{id:c.id,type:c.type,rawId:b64u(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{{attestationObject:b64u(c.response.attestationObject),clientDataJSON:b64u(c.response.clientDataJSON),transports:c.response.getTransports?c.response.getTransports():[]}},clientExtensionResults:c.getClientExtensionResults()}}}}
function authJSON(c){{return {{id:c.id,type:c.type,rawId:b64u(c.rawId),authenticatorAttachment:c.authenticatorAttachment,response:{{authenticatorData:b64u(c.response.authenticatorData),clientDataJSON:b64u(c.response.clientDataJSON),signature:b64u(c.response.signature),userHandle:c.response.userHandle?b64u(c.response.userHandle):null}},clientExtensionResults:c.getClientExtensionResults()}}}}
async function post(path,body){{const r=await fetch(`/connect/${{token}}/${{path}}`,{{method:'POST',headers:{{'content-type':'application/json'}},body:JSON.stringify(body)}});const j=await r.json();if(!r.ok)throw new Error(j.error||'Request failed');return j}}
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>{{document.querySelectorAll('.tab').forEach(x=>x.classList.toggle('active',x===b));document.querySelector('#register').classList.toggle('hidden',b.dataset.mode!=='register');document.querySelector('#signin').classList.toggle('hidden',b.dataset.mode!=='signin');message.textContent=''}});
{registration_script}
document.querySelector('#signin').onsubmit=async e=>{{e.preventDefault();message.textContent='';try{{const f=new FormData(e.target);const start=await post('authenticate/start',{{owner_handle:f.get('owner_handle'),agent_id:f.get('agent_id')}});const c=await navigator.credentials.get({{publicKey:request(start.options.publicKey)}});const done=await post('authenticate/finish',{{ceremony_id:start.ceremony_id,credential:authJSON(c)}});location.assign(done.redirect_uri)}}catch(err){{message.textContent=err.message}}}};
</script></body></html>"#
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redirect_uris_require_https_except_loopback() {
        assert!(validate_redirect_uri("https://assistant.example/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:8790/callback").is_ok());
        assert!(validate_redirect_uri("http://[::1]:8790/callback").is_ok());
        assert!(validate_redirect_uri("http://assistant.example/callback").is_err());
        assert!(validate_redirect_uri("https://assistant.example/callback#fragment").is_err());
    }

    #[test]
    fn public_client_capabilities_are_safely_narrowed_by_the_server() {
        let request = |grant_types: Option<Vec<&str>>| ClientRegistrationRequest {
            client_name: Some("Test client".to_string()),
            redirect_uris: vec!["https://assistant.example/callback".to_string()],
            token_endpoint_auth_method: Some("none".to_string()),
            grant_types: grant_types.map(|values| values.into_iter().map(str::to_string).collect()),
            response_types: Some(vec!["code".to_string()]),
        };

        assert!(validate_client_registration(&request(Some(vec![
            "authorization_code",
            "refresh_token",
        ])))
        .is_ok());
        assert!(validate_client_registration(&request(Some(vec!["refresh_token"]))).is_ok());
        assert!(validate_client_registration(&request(Some(vec![
            "authorization_code",
            "client_credentials",
        ])))
        .is_ok());
        assert!(validate_client_registration(&request(Some(vec![&"x".repeat(129)]))).is_err());
    }

    #[test]
    fn endpoint_scopes_are_selected_without_crossing_roles() {
        let scopes = requested_scopes(Some("wallet:read protocol:read"), auth::RUNTIME_SCOPES)
            .expect("runtime scopes");
        assert_eq!(scopes, ["wallet:read", "protocol:read"]);
        assert!(requested_scopes(Some("policy:manage"), auth::RUNTIME_SCOPES).is_err());
        assert!(requested_scopes(Some("transaction:execute"), auth::MANAGEMENT_SCOPES).is_err());
    }

    #[test]
    fn connect_tokens_are_full_entropy_and_stored_as_hashes() {
        let token = random_token();
        assert_eq!(token.len(), 43);
        assert_eq!(token_hash(&token).len(), 64);
        assert!(!token_hash(&token).contains(&token));
    }

    #[test]
    fn authorization_redirect_binds_code_to_issuer_and_preserves_state() {
        let session = ConnectSessionRow {
            id: Uuid::new_v4(),
            client_name: "Assistant".to_string(),
            client_id: "https://assistant.example/client-metadata.json".to_string(),
            redirect_uri: "https://assistant.example/callback?existing=value".to_string(),
            client_state: Some("client-state".to_string()),
            code_challenge: "challenge".to_string(),
            resource: "https://api.jusso.example/mcp/agent".to_string(),
            scopes: vec!["wallet:read".to_string()],
        };

        let redirect = authorization_redirect(&session, "raw-code", "https://api.jusso.example")
            .expect("authorization redirect");
        let redirect = reqwest::Url::parse(&redirect).expect("redirect URL");
        let query = redirect
            .query_pairs()
            .into_owned()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(query.get("existing").map(String::as_str), Some("value"));
        assert_eq!(query.get("code").map(String::as_str), Some("raw-code"));
        assert_eq!(
            query.get("iss").map(String::as_str),
            Some("https://api.jusso.example")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("client-state"));
    }

    #[test]
    fn connect_page_escapes_client_metadata_and_honors_registration_gate() {
        let html = connect_page_html(
            "safe-token",
            None,
            true,
            false,
            "<script>alert('xss')</script>",
            &["wallet:read".to_string()],
        );

        assert!(!html.contains("<script>alert('xss')</script>"));
        assert!(html.contains("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"));
        assert!(html.contains("wallet:read"));
        assert!(!html.contains("Create account"));
        assert!(!html.contains("id=\"register\""));
    }

    #[test]
    fn approval_page_escapes_client_and_review_content() {
        let html = owner_approval_page_html(
            "safe-token",
            "<img src=x onerror=alert(1)>",
            &serde_json::json!({"name": "</pre><script>alert(1)</script>"}),
        );

        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(!html.contains("</pre><script>alert(1)</script>"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&lt;/pre&gt;&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn passkey_enrollment_page_escapes_credential_metadata() {
        let html = passkey_enrollment_page_html(
            "safe-token",
            "<img src=x onerror=alert(1)>",
            "</dd><script>alert(2)</script>",
            true,
        );

        assert!(!html.contains("<img src=x onerror=alert(1)>"));
        assert!(!html.contains("</dd><script>alert(2)</script>"));
        assert!(html.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(html.contains("&lt;/dd&gt;&lt;script&gt;alert(2)&lt;/script&gt;"));
        assert!(html.contains("Replace owner passkey"));
    }

    #[test]
    fn verified_passkey_registration_builds_a_turnkey_authenticator() {
        let client_data = br#"{"type":"webauthn.create","challenge":"test-challenge","origin":"https://jusso.example"}"#;
        let credential: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": "verified-credential",
            "rawId": "dmVyaWZpZWQtY3JlZGVudGlhbA",
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(b"attestation"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(client_data),
                "transports": ["internal", "hybrid", "test"]
            },
            "clientExtensionResults": {}
        }))
        .expect("registration credential");

        let stored = turnkey_recovery_credential(&credential, "verified-credential")
            .expect("Turnkey recovery credential");
        let authenticator =
            serde_json::from_value::<turnkey_client::generated::AuthenticatorParamsV2>(stored)
                .expect("Turnkey SDK authenticator");

        assert_eq!(authenticator.challenge, "test-challenge");
        let attestation = authenticator.attestation.expect("attestation");
        assert_eq!(attestation.credential_id, "verified-credential");
        assert_eq!(attestation.transports.len(), 2);
    }

    #[test]
    fn invalid_turnkey_passkey_material_is_rejected() {
        let credential: RegisterPublicKeyCredential = serde_json::from_value(serde_json::json!({
            "id": "credential",
            "rawId": "Y3JlZGVudGlhbA",
            "type": "public-key",
            "response": {
                "attestationObject": URL_SAFE_NO_PAD.encode(b"attestation"),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(br#"{"type":"webauthn.create","challenge":"","origin":"https://jusso.example"}"#),
                "transports": []
            },
            "clientExtensionResults": {}
        }))
        .expect("registration credential");

        assert!(turnkey_recovery_credential(&credential, "credential").is_err());
        assert!(turnkey_recovery_credential(&credential, &"x".repeat(257)).is_err());
    }
}
