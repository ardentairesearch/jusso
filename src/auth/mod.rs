//! Proof-of-possession authentication and agent-scoped authorization.

use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};
use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use ethers_core::types::U256;
use jsonwebtoken::{
    decode, decode_header, encode,
    jwk::{Jwk, JwkSet},
    Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    db,
    types::{AuthContext, BatchCall, CredentialKind, ExecutionRequest},
};

pub const RUNTIME_SCOPES: &[&str] = &[
    "wallet:read",
    "workflow:read",
    "execution:read",
    "transaction:simulate",
    "transaction:execute",
];

pub const SUPPORTED_PROTOCOLS: &[&str] = &[];

pub const SUPPORTED_WORKFLOW_ACTIONS: &[&str] = &["payment_plan:execute"];

pub const DEFAULT_POLICY_ACTIONS: &[&str] = &[
    "wallet:read",
    "workflow:read",
    "execution:read",
    "transaction:simulate",
    "transaction:execute",
    "payment_plan:execute",
];

pub const DEFAULT_MAX_EXECUTION_FEE_USD: f64 = 1.0;
pub const DEFAULT_ROLLING_WINDOW_SECONDS: i64 = 86_400;
pub const DEFAULT_MAX_ROLLING_EXECUTION_FEE_USD: f64 = 10.0;
pub const DEFAULT_MAX_SPONSORED_GAS_UNITS: i64 = 2_000_000;
pub const DEFAULT_MAX_ROLLING_SPONSORED_GAS_UNITS: i64 = 10_000_000;
const OAUTH_REFRESH_TOKEN_TTL_DAYS: i64 = 30;

pub const MANAGEMENT_SCOPES: &[&str] = &[
    "agent:manage",
    "credential:manage",
    "trust:manage",
    "policy:manage",
    "workflow:manage",
];

pub const DEFAULT_SCOPES: &[&str] = &[
    "wallet:read",
    "workflow:read",
    "execution:read",
    "transaction:simulate",
    "transaction:execute",
    "agent:manage",
    "credential:manage",
    "trust:manage",
    "policy:manage",
    "workflow:manage",
];

pub fn validate_scopes(scopes: &[String]) -> Result<()> {
    if let Some(scope) = scopes
        .iter()
        .find(|scope| scope.as_str() != "*" && !DEFAULT_SCOPES.contains(&scope.as_str()))
    {
        anyhow::bail!("unknown scope: {scope}");
    }
    Ok(())
}

pub fn validate_runtime_scopes(scopes: &[String]) -> Result<()> {
    validate_scopes(scopes)?;
    if let Some(scope) = scopes
        .iter()
        .find(|scope| scope.as_str() == "*" || MANAGEMENT_SCOPES.contains(&scope.as_str()))
    {
        anyhow::bail!("agent runtime credentials cannot receive management scope {scope}");
    }
    Ok(())
}

fn bound_agent_external_id(context: &AuthContext) -> Result<&str> {
    if context.agent_id.is_none() {
        anyhow::bail!("agent MCP access token is not bound to an agent");
    }
    context
        .agent_external_id
        .as_deref()
        .filter(|agent_id| !agent_id.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("agent MCP access token is not bound to an agent"))
}

pub fn validate_policy_actions(actions: &[String]) -> Result<()> {
    if let Some(action) = actions.iter().find(|action| {
        action.as_str() != "*"
            && !RUNTIME_SCOPES.contains(&action.as_str())
            && !SUPPORTED_WORKFLOW_ACTIONS.contains(&action.as_str())
    }) {
        anyhow::bail!("unknown runtime policy action: {action}");
    }
    Ok(())
}

/// Enforce limits after a typed action has been compiled into exact onchain calls.
pub fn enforce_compiled_execution_limits(
    policy: &db::models::AuthorizationPolicyRow,
    request: &ExecutionRequest,
) -> Result<()> {
    enforce_policy_impact(policy, &request.policy_impact)?;

    let targets = request.batch_calls.as_ref().map_or_else(
        || vec![request.target_contract.as_str()],
        |calls| {
            calls
                .iter()
                .map(|call| call.target_contract.as_str())
                .collect()
        },
    );
    if let Some(allowed) = &policy.allowed_targets {
        for target in targets {
            if !allowed
                .iter()
                .any(|candidate| candidate == "*" || candidate.eq_ignore_ascii_case(target))
            {
                anyhow::bail!("target contract is denied by authorization policy");
            }
        }
    }

    if let Some(maximum) = policy.max_value_wei.as_deref() {
        let maximum = U256::from_dec_str(maximum)?;
        let total = request.batch_calls.as_ref().map_or_else(
            || parse_policy_value(&request.value),
            |calls| {
                calls.iter().try_fold(U256::zero(), |total, call| {
                    total
                        .checked_add(parse_policy_value(&call.value)?)
                        .ok_or_else(|| anyhow!("batch value overflow"))
                })
            },
        )?;
        if total > maximum {
            anyhow::bail!("transaction value exceeds authorization policy");
        }
    }
    Ok(())
}

pub fn enforce_policy_impact(
    policy: &db::models::AuthorizationPolicyRow,
    impact: &crate::policy::ExecutionPolicyImpact,
) -> Result<()> {
    impact.validate()?;
    for risk in &impact.risks {
        if !policy
            .risk_permissions
            .iter()
            .any(|allowed| allowed == risk)
        {
            anyhow::bail!("high-risk action requires explicit policy opt-in: {risk}");
        }
    }

    if impact.borrowed_value_usd > 0.0 {
        let maximum = policy
            .max_borrowed_value_usd
            .ok_or_else(|| anyhow!("borrowing requires an explicit per-execution limit"))?;
        if impact.borrowed_value_usd > maximum {
            anyhow::bail!("borrowed value exceeds authorization policy");
        }
    }

    let token_limits = crate::policy::validate_token_spend_limits(&policy.token_spend_limits)?;
    let mut token_totals = std::collections::BTreeMap::<String, U256>::new();
    for spend in &impact.token_spends {
        let token = spend.token.to_ascii_lowercase();
        let amount = U256::from_dec_str(&spend.amount_raw)?;
        let total = token_totals.entry(token).or_default();
        *total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow!("token spend impact overflow"))?;
    }
    for (token, total) in token_totals {
        let limit = token_limits
            .iter()
            .find(|limit| limit.token.eq_ignore_ascii_case(&token))
            .or_else(|| token_limits.iter().find(|limit| limit.token == "*"))
            .ok_or_else(|| anyhow!("token spending requires an explicit policy limit"))?;
        if total > U256::from_dec_str(&limit.max_per_execution_raw)? {
            anyhow::bail!("token spend exceeds per-execution authorization policy");
        }
    }

    Ok(())
}

fn parse_policy_value(value: &str) -> Result<U256> {
    if value.is_empty() {
        Ok(U256::zero())
    } else {
        U256::from_dec_str(value).map_err(Into::into)
    }
}

pub fn allowed_assertion_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384"
    )
}

fn allowed_algorithm(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
    )
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        _ => "unsupported",
    }
}

/// Validate a public signing JWK and return its RFC 7638 thumbprint.
pub fn validate_public_jwk(public_jwk: &serde_json::Value) -> Result<String> {
    const PRIVATE_JWK_FIELDS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
    if PRIVATE_JWK_FIELDS
        .iter()
        .any(|field| public_jwk.get(field).is_some())
    {
        anyhow::bail!("public_jwk must not contain private key material");
    }
    let algorithm = public_jwk
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("public_jwk.alg is required"))?;
    if !allowed_assertion_algorithm(algorithm) {
        anyhow::bail!("public_jwk.alg must be an allowed asymmetric signing algorithm");
    }
    if public_jwk
        .get("use")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|use_| use_ != "sig")
    {
        anyhow::bail!("public_jwk.use must be sig when provided");
    }
    if public_jwk
        .get("key_ops")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|operations| {
            operations.is_empty()
                || operations
                    .iter()
                    .any(|operation| operation.as_str() != Some("verify"))
        })
    {
        anyhow::bail!("public_jwk.key_ops may contain only verify");
    }

    let key_type = public_jwk.get("kty").and_then(serde_json::Value::as_str);
    let required: &[&str] = match key_type {
        Some("RSA") if algorithm.starts_with("RS") || algorithm.starts_with("PS") => {
            &["e", "kty", "n"]
        }
        Some("EC") if algorithm.starts_with("ES") => &["crv", "kty", "x", "y"],
        Some("RSA" | "EC") => {
            anyhow::bail!("public_jwk.alg is incompatible with public_jwk.kty")
        }
        _ => anyhow::bail!("public_jwk.kty must be RSA or EC"),
    };
    let mut canonical = serde_json::Map::new();
    for field in required {
        let value = public_jwk
            .get(*field)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("public_jwk.{field} is required"))?;
        canonical.insert(
            (*field).to_string(),
            serde_json::Value::String(value.into()),
        );
    }
    match key_type {
        Some("RSA") => {
            let modulus = decode_jwk_parameter(public_jwk, "n")?;
            let first_nonzero = modulus
                .iter()
                .position(|byte| *byte != 0)
                .ok_or_else(|| anyhow!("public_jwk.n must be non-zero"))?;
            let significant = &modulus[first_nonzero..];
            let modulus_bits =
                (significant.len() - 1) * 8 + (8 - significant[0].leading_zeros() as usize);
            if modulus_bits < 2048 {
                anyhow::bail!("public_jwk RSA modulus must be at least 2048 bits");
            }
            if decode_jwk_parameter(public_jwk, "e")?.is_empty() {
                anyhow::bail!("public_jwk.e must be non-empty");
            }
        }
        Some("EC") => {
            let (curve, coordinate_bytes) = match algorithm {
                "ES256" => ("P-256", 32),
                "ES384" => ("P-384", 48),
                _ => unreachable!("allowed EC algorithms are exhaustive"),
            };
            if public_jwk.get("crv").and_then(serde_json::Value::as_str) != Some(curve) {
                anyhow::bail!("public_jwk.crv does not match public_jwk.alg");
            }
            for coordinate in ["x", "y"] {
                if decode_jwk_parameter(public_jwk, coordinate)?.len() != coordinate_bytes {
                    anyhow::bail!("public_jwk.{coordinate} has an invalid length");
                }
            }
        }
        _ => unreachable!("key type was validated above"),
    }

    let parsed: Jwk = serde_json::from_value(public_jwk.clone()).context("invalid public_jwk")?;
    DecodingKey::from_jwk(&parsed).context("public_jwk is not a supported verification key")?;
    let canonical = serde_json::to_vec(&serde_json::Value::Object(canonical))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(canonical)))
}

fn decode_jwk_parameter(public_jwk: &serde_json::Value, field: &str) -> Result<Vec<u8>> {
    let value = public_jwk
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("public_jwk.{field} is required"))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("public_jwk.{field} must be unpadded base64url"))
}

#[derive(Debug, Deserialize)]
struct TurnstileResponse {
    success: bool,
    hostname: Option<String>,
    action: Option<String>,
}

pub async fn verify_registration_challenge(
    secret: Option<&str>,
    response_token: Option<&str>,
    remote_ip: std::net::IpAddr,
    allowed_hostnames: &[String],
) -> Result<()> {
    let Some(secret) = secret else {
        return Ok(());
    };
    let token = response_token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| anyhow!("registration challenge is required"))?;
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?
        .post("https://challenges.cloudflare.com/turnstile/v0/siteverify")
        .form(&[
            ("secret", secret),
            ("response", token),
            ("remoteip", &remote_ip.to_string()),
        ])
        .send()
        .await
        .context("registration challenge verification failed")?;
    if !response.status().is_success() {
        anyhow::bail!("registration challenge verifier is unavailable");
    }
    let result: TurnstileResponse = response
        .json()
        .await
        .context("invalid registration challenge response")?;
    if !result.success || result.action.as_deref() != Some("register") {
        anyhow::bail!("registration challenge was rejected");
    }
    if !allowed_hostnames.is_empty()
        && result.hostname.as_deref().is_none_or(|hostname| {
            !allowed_hostnames
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(hostname))
        })
    {
        anyhow::bail!("registration challenge hostname is not allowed");
    }
    Ok(())
}

#[derive(Clone)]
pub struct AuthService {
    pub(crate) pool: PgPool,
    issuer: String,
    audience: String,
    token_endpoint: String,
    signing_secret: String,
    token_ttl_seconds: i64,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("token_endpoint", &self.token_endpoint)
            .field("signing_secret", &"[REDACTED]")
            .field("token_ttl_seconds", &self.token_ttl_seconds)
            .finish()
    }
}

impl AuthService {
    pub fn new(
        pool: PgPool,
        issuer: String,
        audience: String,
        signing_secret: String,
        token_ttl_seconds: i64,
    ) -> Result<Self> {
        if signing_secret.len() < 32 {
            anyhow::bail!("OAUTH_SIGNING_SECRET must contain at least 32 bytes");
        }
        let issuer = issuer.trim_end_matches('/').to_string();
        Ok(Self {
            pool,
            token_endpoint: format!("{issuer}/oauth/token"),
            issuer,
            audience,
            signing_secret,
            token_ttl_seconds: token_ttl_seconds.clamp(60, 900),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn token_endpoint(&self) -> &str {
        &self.token_endpoint
    }

    pub fn protected_resource_metadata_url(&self, resource_path: &str) -> String {
        format!(
            "{}/.well-known/oauth-protected-resource{}",
            self.issuer, resource_path
        )
    }

    pub async fn authorize_mcp_action(
        &self,
        context: &AuthContext,
        chain: Option<&str>,
        required_scope: &'static str,
        resource: &'static str,
    ) -> Result<AuthContext> {
        if !context.allows_scope(required_scope) {
            anyhow::bail!("access token does not grant {required_scope}");
        }
        let agent_external_id = bound_agent_external_id(context)?;
        let (agent, policy) =
            db::authorize_execution_agent(&self.pool, context, agent_external_id).await?;
        let mut authorized = context.clone();
        authorized.agent_id = Some(agent.id);
        authorized.agent_external_id = Some(agent.external_id);
        let input = AuthorizationInput {
            agent_id: Some(agent_external_id.to_string()),
            chain: chain.map(str::to_string),
            ..AuthorizationInput::default()
        };
        self.enforce_policy(&authorized, &policy, required_scope, resource, &input)
            .await?;
        Ok(authorized)
    }

    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
    ) -> Result<AuthContext> {
        let authorization = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| anyhow!("missing access token"))?;
        let mut parts = authorization.split_ascii_whitespace();
        let scheme = parts
            .next()
            .filter(|value| {
                value.eq_ignore_ascii_case("Bearer") || value.eq_ignore_ascii_case("DPoP")
            })
            .ok_or_else(|| {
                anyhow!("access token must use the Bearer or DPoP authorization scheme")
            })?;
        let token = parts
            .next()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("missing access token"))?;
        if parts.next().is_some() {
            anyhow::bail!("authorization header is malformed");
        }
        let proof = dpop_header(headers).ok();
        self.authenticate_access_token(token, scheme, proof, method, uri)
            .await
    }

    async fn authenticate_access_token(
        &self,
        token: &str,
        scheme: &str,
        proof: Option<&str>,
        method: &Method,
        uri: &Uri,
    ) -> Result<AuthContext> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        let mcp_audience = format!("{}{}", self.issuer, uri.path());
        let expected_audience = if matches!(uri.path(), "/mcp/agent" | "/mcp/control") {
            mcp_audience.as_str()
        } else {
            self.audience.as_str()
        };
        validation.set_audience(&[expected_audience]);
        validation.leeway = 0;
        let claims = decode::<AccessTokenClaims>(
            token,
            &DecodingKey::from_secret(self.signing_secret.as_bytes()),
            &validation,
        )
        .context("invalid or expired access token")?
        .claims;
        let thumbprint = match claims.cnf.as_ref() {
            Some(confirmation) => {
                if !scheme.eq_ignore_ascii_case("DPoP") {
                    anyhow::bail!(
                        "DPoP-bound access tokens must use the DPoP authorization scheme"
                    );
                }
                let proof = proof.ok_or_else(|| anyhow!("DPoP header is required"))?;
                let htu = format!("{}{}", self.issuer, uri.path());
                let thumbprint = self
                    .verify_dpop(proof, method.as_str(), &htu, Some(token))
                    .await?;
                if confirmation.jkt != thumbprint {
                    anyhow::bail!("DPoP key does not match the access token binding");
                }
                Some(thumbprint)
            }
            None => {
                if !scheme.eq_ignore_ascii_case("Bearer") {
                    anyhow::bail!("unbound access tokens must use the Bearer authorization scheme");
                }
                if proof.is_some() {
                    anyhow::bail!("Bearer access tokens must not include a DPoP proof");
                }
                None
            }
        };
        let principal = db::get_active_principal(&self.pool, claims.sub).await?;
        if principal.organization_id != claims.organization_id
            || principal.auth_version != claims.auth_version
        {
            anyhow::bail!("access token has been revoked");
        }
        let credential_is_active: bool = match &claims.credential_kind {
            CredentialKind::LocalJwk => {
                sqlx::query_scalar(
                    r#"SELECT EXISTS(
                        SELECT 1 FROM credential_bindings
                        WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                          AND is_active = TRUE AND agent_id IS NOT DISTINCT FROM $4
                    )"#,
                )
                .bind(claims.credential_id)
                .bind(claims.organization_id)
                .bind(claims.sub)
                .bind(claims.agent_id)
                .fetch_one(&self.pool)
                .await?
            }
            CredentialKind::WorkloadIdentity => {
                sqlx::query_scalar(
                    r#"SELECT EXISTS(
                        SELECT 1 FROM federation_trusts ft
                        JOIN agent_instances ai ON ai.federation_trust_id = ft.id
                        WHERE ft.id = $1 AND ft.organization_id = $2
                          AND ft.principal_id = $3 AND ft.agent_id = $4
                          AND ft.is_active = TRUE AND ai.id = $5
                          AND ai.agent_id = ft.agent_id AND ai.status = 'active'
                          AND (ai.expires_at IS NULL OR ai.expires_at > now())
                    )"#,
                )
                .bind(claims.credential_id)
                .bind(claims.organization_id)
                .bind(claims.sub)
                .bind(claims.agent_id)
                .bind(claims.instance_id)
                .fetch_one(&self.pool)
                .await?
            }
            CredentialKind::OAuthSession => {
                sqlx::query_scalar(
                    r#"SELECT EXISTS(
                        SELECT 1 FROM oauth_connections
                        WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                          AND status = 'active' AND resource = $4
                          AND agent_id IS NOT DISTINCT FROM $5
                    )"#,
                )
                .bind(claims.credential_id)
                .bind(claims.organization_id)
                .bind(claims.sub)
                .bind(expected_audience)
                .bind(claims.agent_id)
                .fetch_one(&self.pool)
                .await?
            }
        };
        if !credential_is_active {
            anyhow::bail!("access token credential has been revoked");
        }
        if let Some(agent_id) = claims.agent_id {
            if !db::principal_can_access_agent(&self.pool, claims.sub, agent_id).await? {
                anyhow::bail!("agent access has been suspended or revoked");
            }
        }
        Ok(AuthContext {
            organization_id: claims.organization_id,
            principal_id: claims.sub,
            credential_id: claims.credential_id,
            credential_kind: claims.credential_kind,
            scopes: claims.scopes.into_iter().collect(),
            agent_id: claims.agent_id,
            agent_external_id: claims.agent_external_id,
            instance_id: claims.instance_id,
            dpop_jkt: thumbprint,
        })
    }

    pub async fn exchange_token(
        &self,
        request: TokenRequest,
        proof: Option<&str>,
    ) -> Result<TokenResponse> {
        match request.grant_type.as_str() {
            "authorization_code" => {
                self.authenticate_oauth_client(&request).await?;
                let dpop_jkt = match proof {
                    Some(proof) => Some(
                        self.verify_dpop(proof, "POST", &self.token_endpoint, None)
                            .await?,
                    ),
                    None => None,
                };
                self.exchange_authorization_code(request, dpop_jkt).await
            }
            "refresh_token" => {
                self.authenticate_oauth_client(&request).await?;
                let dpop_jkt = match proof {
                    Some(proof) => Some(
                        self.verify_dpop(proof, "POST", &self.token_endpoint, None)
                            .await?,
                    ),
                    None => None,
                };
                self.exchange_refresh_token(request, dpop_jkt).await
            }
            "client_credentials" => {
                let proof = proof.ok_or_else(|| anyhow!("DPoP header is required"))?;
                let dpop_jkt = self
                    .verify_dpop(proof, "POST", &self.token_endpoint, None)
                    .await?;
                self.exchange_local_credential(request, dpop_jkt).await
            }
            "urn:ietf:params:oauth:grant-type:token-exchange" => {
                let proof = proof.ok_or_else(|| anyhow!("DPoP header is required"))?;
                let dpop_jkt = self
                    .verify_dpop(proof, "POST", &self.token_endpoint, None)
                    .await?;
                self.exchange_workload_identity(request, dpop_jkt).await
            }
            _ => anyhow::bail!("unsupported grant_type"),
        }
    }

    async fn authenticate_oauth_client(&self, request: &TokenRequest) -> Result<()> {
        let client_id = request
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow!("client_id is required"))?;
        let client = sqlx::query_as::<_, OAuthClientAuthenticationRow>(
            r#"SELECT token_endpoint_auth_method, jwks_uri,
                      token_endpoint_auth_signing_alg
               FROM oauth_clients
               WHERE client_id = $1"#,
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| anyhow!("unknown OAuth client"))?;

        match client.token_endpoint_auth_method.as_str() {
            "none" => {
                if request.client_assertion_type.is_some() || request.client_assertion.is_some() {
                    anyhow::bail!("public OAuth clients must not send client credentials");
                }
                Ok(())
            }
            "private_key_jwt" => {
                if request.client_assertion_type.as_deref()
                    != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                {
                    anyhow::bail!("unsupported client_assertion_type");
                }
                let assertion = request
                    .client_assertion
                    .as_deref()
                    .ok_or_else(|| anyhow!("client_assertion is required"))?;
                let jwks_uri = client
                    .jwks_uri
                    .as_deref()
                    .ok_or_else(|| anyhow!("OAuth client JWKS is not configured"))?;
                let expected_algorithm = client
                    .token_endpoint_auth_signing_alg
                    .as_deref()
                    .ok_or_else(|| anyhow!("OAuth client signing algorithm is not configured"))?;
                let jwks = fetch_public_jwks(jwks_uri, "OAuth client").await?;
                let claims = verify_oauth_client_assertion(
                    assertion,
                    client_id,
                    &self.token_endpoint,
                    expected_algorithm,
                    &jwks,
                )?;
                db::consume_oauth_proof_jti(
                    &self.pool,
                    &format!("mcp-client-assertion:{client_id}"),
                    &claims.jti,
                    claims.exp,
                )
                .await?;
                Ok(())
            }
            _ => anyhow::bail!("OAuth client authentication method is unsupported"),
        }
    }

    async fn exchange_local_credential(
        &self,
        request: TokenRequest,
        dpop_jkt: String,
    ) -> Result<TokenResponse> {
        let client_id = request
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow!("client_id is required"))?;
        if request.client_assertion_type.as_deref()
            != Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        {
            anyhow::bail!("unsupported client_assertion_type");
        }
        let client_assertion = request
            .client_assertion
            .as_deref()
            .ok_or_else(|| anyhow!("client_assertion is required"))?;
        let account = db::get_credential_binding_by_client_id(&self.pool, client_id)
            .await?
            .ok_or_else(|| anyhow!("unknown or inactive OAuth client"))?;
        if account.public_jwk_thumbprint != dpop_jkt {
            anyhow::bail!("DPoP key must match the registered local credential");
        }
        let header = decode_header(client_assertion).context("invalid client assertion header")?;
        if !allowed_algorithm(header.alg) {
            anyhow::bail!("client assertion algorithm is not allowed");
        }
        let jwk: Jwk =
            serde_json::from_value(account.public_jwk.clone()).context("stored JWK is invalid")?;
        if account
            .public_jwk
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|algorithm| algorithm != algorithm_name(header.alg))
        {
            anyhow::bail!("client assertion algorithm does not match the registered JWK");
        }
        let key = DecodingKey::from_jwk(&jwk).context("stored JWK cannot verify assertions")?;
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[self.token_endpoint.as_str()]);
        validation.leeway = 0;
        let assertion = decode::<ClientAssertionClaims>(client_assertion, &key, &validation)
            .context("invalid client assertion")?
            .claims;
        if assertion.iss != client_id || assertion.sub != client_id {
            anyhow::bail!("client assertion iss and sub must equal client_id");
        }
        validate_proof_time(assertion.iat, assertion.exp, 300)?;
        if assertion.jti.trim().is_empty() {
            anyhow::bail!("client assertion jti is required");
        }
        db::consume_oauth_proof_jti(
            &self.pool,
            &format!("assertion:{client_id}"),
            &assertion.jti,
            assertion.exp,
        )
        .await?;
        let scopes = select_scopes(&account.scopes, request.scope.as_deref())?;
        let principal = db::get_active_principal(&self.pool, account.principal_id).await?;
        let agent_external_id = match account.agent_id {
            Some(agent_id) => {
                if !db::principal_can_access_agent(&self.pool, account.principal_id, agent_id)
                    .await?
                {
                    anyhow::bail!("agent access has been suspended or revoked");
                }
                Some(
                    sqlx::query_scalar::<_, String>(
                        "SELECT external_id FROM agents WHERE id = $1 AND status = 'active'",
                    )
                    .bind(agent_id)
                    .fetch_one(&self.pool)
                    .await?,
                )
            }
            None => None,
        };
        db::touch_credential_binding(&self.pool, account.id)
            .await
            .ok();
        self.issue_access_token(
            principal.auth_version,
            account.organization_id,
            account.principal_id,
            account.id,
            CredentialKind::LocalJwk,
            account.agent_id,
            agent_external_id,
            None,
            scopes,
            self.audience.clone(),
            Some(dpop_jkt),
        )
    }

    async fn exchange_workload_identity(
        &self,
        request: TokenRequest,
        dpop_jkt: String,
    ) -> Result<TokenResponse> {
        if request.subject_token_type.as_deref() != Some("urn:ietf:params:oauth:token-type:jwt") {
            anyhow::bail!("subject_token_type must identify a JWT");
        }
        let subject_token = request
            .subject_token
            .as_deref()
            .ok_or_else(|| anyhow!("subject_token is required"))?;
        let header = decode_header(subject_token).context("invalid workload token header")?;
        if !allowed_algorithm(header.alg) {
            anyhow::bail!("workload token algorithm is not allowed");
        }
        let unverified = decode_unverified_workload(subject_token, header.alg)?;
        let mut candidates = Vec::new();
        for audience in unverified.audience_values() {
            candidates
                .extend(db::find_federation_trusts(&self.pool, &unverified.iss, &audience).await?);
        }
        candidates.sort_by_key(|trust| trust.id);
        candidates.dedup_by_key(|trust| trust.id);
        let matching = candidates
            .into_iter()
            .filter(|trust| subject_matches(&trust.subject_pattern, &unverified.sub))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            anyhow::bail!("workload identity must match exactly one active federation trust");
        }
        let trust = matching.into_iter().next().expect("length checked");
        if !db::principal_can_access_agent(&self.pool, trust.principal_id, trust.agent_id).await? {
            anyhow::bail!("agent access has been suspended or revoked");
        }
        validate_federation_url(&trust.issuer)?;
        validate_federation_url(&trust.jwks_uri)?;
        let response = hardened_public_https_client(&trust.jwks_uri)
            .await?
            .get(&trust.jwks_uri)
            .send()
            .await
            .context("workload JWKS request failed")?;
        if !response.status().is_success() {
            anyhow::bail!("workload JWKS endpoint returned an error");
        }
        const MAX_JWKS_BYTES: u64 = 1024 * 1024;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES)
        {
            anyhow::bail!("workload JWKS response exceeds 1 MiB");
        }
        let body = response
            .bytes()
            .await
            .context("workload JWKS response could not be read")?;
        if body.len() as u64 > MAX_JWKS_BYTES {
            anyhow::bail!("workload JWKS response exceeds 1 MiB");
        }
        let jwks: JwkSet =
            serde_json::from_slice(&body).context("workload JWKS response is invalid")?;
        let jwk = match header.kid.as_deref() {
            Some(kid) => jwks
                .find(kid)
                .ok_or_else(|| anyhow!("workload signing key was not found"))?,
            None if jwks.keys.len() == 1 => &jwks.keys[0],
            None => {
                anyhow::bail!("workload token kid is required when JWKS contains multiple keys")
            }
        };
        let key = DecodingKey::from_jwk(jwk).context("workload signing key is unsupported")?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[trust.issuer.as_str()]);
        validation.set_audience(&[trust.audience.as_str()]);
        validation.leeway = 30;
        let verified = decode::<WorkloadClaims>(subject_token, &key, &validation)
            .context("workload identity token verification failed")?
            .claims;
        if !subject_matches(&trust.subject_pattern, &verified.sub) {
            anyhow::bail!("workload subject is not allowed by the federation trust");
        }
        let scopes = select_scopes(&trust.scopes, request.scope.as_deref())?;
        validate_runtime_scopes(&scopes.iter().cloned().collect::<Vec<_>>())?;
        let instance_exp = chrono::DateTime::from_timestamp(verified.exp, 0)
            .ok_or_else(|| anyhow!("workload token expiry is invalid"))?;
        let instance_id =
            db::upsert_agent_instance(&self.pool, &trust, &verified.sub, instance_exp).await?;
        let principal = db::get_active_principal(&self.pool, trust.principal_id).await?;
        let external_id = sqlx::query_scalar::<_, String>(
            "SELECT external_id FROM agents WHERE id = $1 AND status = 'active'",
        )
        .bind(trust.agent_id)
        .fetch_one(&self.pool)
        .await?;
        sqlx::query("UPDATE federation_trusts SET last_used_at = now() WHERE id = $1")
            .bind(trust.id)
            .execute(&self.pool)
            .await
            .ok();
        self.issue_access_token(
            principal.auth_version,
            trust.organization_id,
            trust.principal_id,
            trust.id,
            CredentialKind::WorkloadIdentity,
            Some(trust.agent_id),
            Some(external_id),
            Some(instance_id),
            scopes,
            self.audience.clone(),
            Some(dpop_jkt),
        )
    }

    async fn exchange_authorization_code(
        &self,
        request: TokenRequest,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse> {
        let code = request
            .code
            .as_deref()
            .ok_or_else(|| anyhow!("code is required"))?;
        let client_id = request
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow!("client_id is required"))?;
        let redirect_uri = request
            .redirect_uri
            .as_deref()
            .ok_or_else(|| anyhow!("redirect_uri is required"))?;
        let verifier = request
            .code_verifier
            .as_deref()
            .ok_or_else(|| anyhow!("code_verifier is required"))?;
        validate_pkce_verifier(verifier)?;
        let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut transaction = self.pool.begin().await?;
        let passkey_id = sqlx::query_scalar::<_, Uuid>(
            "SELECT passkey_id FROM oauth_authorization_codes WHERE code_hash = $1",
        )
        .bind(&code_hash)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow!("authorization code is invalid"))?;
        let active_passkey = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM owner_passkeys WHERE id = $1 AND status = 'active' FOR UPDATE",
        )
        .bind(passkey_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if active_passkey.is_none() {
            anyhow::bail!("authorization code is invalid");
        }
        let row = sqlx::query_as::<_, AuthorizationCodeRow>(
            r#"SELECT organization_id, principal_id, passkey_id, agent_id,
                      agent_external_id, client_id, redirect_uri, code_challenge,
                      resource, scopes, expires_at, used_at
               FROM oauth_authorization_codes
               WHERE code_hash = $1
               FOR UPDATE"#,
        )
        .bind(&code_hash)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow!("authorization code is invalid"))?;
        if row.used_at.is_some()
            || row.expires_at <= Utc::now()
            || row.client_id != client_id
            || row.redirect_uri != redirect_uri
            || row.code_challenge != challenge
        {
            anyhow::bail!("authorization code is invalid, expired, or does not match PKCE");
        }
        sqlx::query("UPDATE oauth_authorization_codes SET used_at = now() WHERE code_hash = $1")
            .bind(&code_hash)
            .execute(&mut *transaction)
            .await?;
        let connection_id = Uuid::new_v4();
        let refresh_token = random_oauth_token();
        let refresh_token_hash = hex::encode(Sha256::digest(refresh_token.as_bytes()));
        sqlx::query(
            r#"INSERT INTO oauth_connections (
                id, organization_id, principal_id, passkey_id, agent_id,
                agent_external_id, client_id, resource, scopes, dpop_jkt
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(connection_id)
        .bind(row.organization_id)
        .bind(row.principal_id)
        .bind(row.passkey_id)
        .bind(row.agent_id)
        .bind(&row.agent_external_id)
        .bind(&row.client_id)
        .bind(&row.resource)
        .bind(&row.scopes)
        .bind(&dpop_jkt)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            r#"INSERT INTO oauth_refresh_tokens (token_hash, connection_id, expires_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(refresh_token_hash)
        .bind(connection_id)
        .bind(Utc::now() + Duration::days(OAUTH_REFRESH_TOKEN_TTL_DAYS))
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let principal = db::get_active_principal(&self.pool, row.principal_id).await?;
        let mut response = self.issue_access_token(
            principal.auth_version,
            row.organization_id,
            row.principal_id,
            connection_id,
            CredentialKind::OAuthSession,
            row.agent_id,
            row.agent_external_id,
            None,
            row.scopes.into_iter().collect(),
            row.resource,
            dpop_jkt,
        )?;
        response.refresh_token = Some(refresh_token);
        Ok(response)
    }

    async fn exchange_refresh_token(
        &self,
        request: TokenRequest,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse> {
        let refresh_token = request
            .refresh_token
            .as_deref()
            .ok_or_else(|| anyhow!("refresh_token is required"))?;
        let client_id = request
            .client_id
            .as_deref()
            .ok_or_else(|| anyhow!("client_id is required"))?;
        let token_hash = hex::encode(Sha256::digest(refresh_token.as_bytes()));
        let mut transaction = self.pool.begin().await?;
        let row = sqlx::query_as::<_, RefreshTokenRow>(
            r#"SELECT rt.connection_id, rt.expires_at, rt.used_at,
                      c.organization_id, c.principal_id, c.agent_id,
                      c.agent_external_id, c.client_id, c.resource, c.scopes,
                      c.dpop_jkt, c.status
               FROM oauth_refresh_tokens rt
               JOIN oauth_connections c ON c.id = rt.connection_id
               WHERE rt.token_hash = $1
               FOR UPDATE OF rt, c"#,
        )
        .bind(&token_hash)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow!("refresh token is invalid"))?;
        if row.used_at.is_some() {
            sqlx::query(
                "UPDATE oauth_connections SET status = 'revoked', revoked_at = now(), updated_at = now() WHERE id = $1",
            )
            .bind(row.connection_id)
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            anyhow::bail!("refresh token reuse detected; OAuth connection was revoked");
        }
        if row.status != "active" || row.expires_at <= Utc::now() || row.client_id != client_id {
            anyhow::bail!("refresh token is expired, revoked, or belongs to another client");
        }
        validate_refresh_dpop_binding(row.dpop_jkt.as_deref(), dpop_jkt.as_deref())?;
        let scopes = select_scopes(&row.scopes, request.scope.as_deref())?;
        let replacement = random_oauth_token();
        let replacement_hash = hex::encode(Sha256::digest(replacement.as_bytes()));
        sqlx::query(
            r#"INSERT INTO oauth_refresh_tokens (token_hash, connection_id, expires_at)
               VALUES ($1, $2, $3)"#,
        )
        .bind(&replacement_hash)
        .bind(row.connection_id)
        .bind(Utc::now() + Duration::days(OAUTH_REFRESH_TOKEN_TTL_DAYS))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE oauth_refresh_tokens SET used_at = now(), replaced_by_hash = $2 WHERE token_hash = $1",
        )
        .bind(&token_hash)
        .bind(&replacement_hash)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "UPDATE oauth_connections SET last_used_at = now(), updated_at = now() WHERE id = $1",
        )
        .bind(row.connection_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        let principal = db::get_active_principal(&self.pool, row.principal_id).await?;
        let mut response = self.issue_access_token(
            principal.auth_version,
            row.organization_id,
            row.principal_id,
            row.connection_id,
            CredentialKind::OAuthSession,
            row.agent_id,
            row.agent_external_id,
            None,
            scopes,
            row.resource,
            dpop_jkt,
        )?;
        response.refresh_token = Some(replacement);
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_access_token(
        &self,
        auth_version: i64,
        organization_id: Uuid,
        principal_id: Uuid,
        credential_id: Uuid,
        credential_kind: CredentialKind,
        agent_id: Option<Uuid>,
        agent_external_id: Option<String>,
        instance_id: Option<Uuid>,
        scopes: BTreeSet<String>,
        audience: String,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse> {
        let issued_at = Utc::now();
        let expires_at = issued_at + Duration::seconds(self.token_ttl_seconds);
        let claims = AccessTokenClaims {
            iss: self.issuer.clone(),
            aud: audience,
            sub: principal_id,
            organization_id,
            credential_id,
            credential_kind,
            agent_id,
            agent_external_id,
            instance_id,
            scopes: scopes.iter().cloned().collect(),
            auth_version,
            cnf: dpop_jkt.map(|jkt| Confirmation { jkt }),
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
            jti: Uuid::new_v4(),
        };
        let access_token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(self.signing_secret.as_bytes()),
        )?;
        Ok(TokenResponse {
            access_token,
            token_type: if claims.cnf.is_some() {
                "DPoP"
            } else {
                "Bearer"
            },
            expires_in: self.token_ttl_seconds,
            scope: scopes.into_iter().collect::<Vec<_>>().join(" "),
            refresh_token: None,
        })
    }

    async fn verify_dpop(
        &self,
        proof: &str,
        method: &str,
        expected_htu: &str,
        access_token: Option<&str>,
    ) -> Result<String> {
        let header = decode_header(proof).context("invalid DPoP proof header")?;
        if header
            .typ
            .as_deref()
            .is_none_or(|typ| !typ.eq_ignore_ascii_case("dpop+jwt"))
        {
            anyhow::bail!("DPoP proof typ must be dpop+jwt");
        }
        if !allowed_algorithm(header.alg) {
            anyhow::bail!("DPoP proof algorithm is not allowed");
        }
        let jwk = header
            .jwk
            .ok_or_else(|| anyhow!("DPoP proof must embed a public JWK"))?;
        let mut jwk_value = serde_json::to_value(&jwk)?;
        if jwk_value.get("alg").is_none() {
            jwk_value["alg"] = serde_json::Value::String(algorithm_name(header.alg).into());
        }
        let thumbprint = validate_public_jwk(&jwk_value)?;
        let key = DecodingKey::from_jwk(&jwk).context("DPoP JWK is unsupported")?;
        let mut validation = Validation::new(header.alg);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        let claims = decode::<DpopClaims>(proof, &key, &validation)
            .context("invalid DPoP proof signature")?
            .claims;
        let now = Utc::now().timestamp();
        if claims.jti.trim().is_empty() || claims.iat < now - 300 || claims.iat > now + 30 {
            anyhow::bail!("DPoP proof is stale or malformed");
        }
        if !claims.htm.eq_ignore_ascii_case(method) || claims.htu != expected_htu {
            anyhow::bail!("DPoP proof does not match this HTTP request");
        }
        match access_token {
            Some(token) => {
                let expected = URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()));
                if claims.ath.as_deref() != Some(expected.as_str()) {
                    anyhow::bail!("DPoP proof access-token hash is missing or invalid");
                }
            }
            None if claims.ath.is_some() => {
                anyhow::bail!("token-endpoint DPoP proof must omit ath")
            }
            None => {}
        }
        db::consume_oauth_proof_jti(
            &self.pool,
            &format!("dpop:{thumbprint}"),
            &claims.jti,
            now + 300,
        )
        .await?;
        Ok(thumbprint)
    }

    async fn enforce_policy(
        &self,
        context: &AuthContext,
        policy: &db::models::AuthorizationPolicyRow,
        action: &str,
        resource: &str,
        input: &AuthorizationInput,
    ) -> Result<()> {
        if action.starts_with("transaction:") && !policy.allow_raw_execution {
            anyhow::bail!("raw transaction routes require an explicit policy opt-in");
        }
        if let Some(allowed) = &policy.allowed_chains {
            if let Some(chain) = input.chain.as_deref() {
                if !allowed
                    .iter()
                    .any(|candidate| candidate == "*" || candidate == chain)
                {
                    anyhow::bail!("chain is denied by authorization policy");
                }
            }
        }
        if let Some(allowed) = &policy.allowed_actions {
            if !allowed
                .iter()
                .any(|candidate| candidate == "*" || candidate == action)
            {
                anyhow::bail!("action is denied by authorization policy");
            }
        }
        if let Some(allowed) = &policy.allowed_targets {
            for target in input.targets() {
                if !allowed
                    .iter()
                    .any(|candidate| candidate == "*" || candidate.eq_ignore_ascii_case(target))
                {
                    anyhow::bail!("target contract is denied by authorization policy");
                }
            }
        }
        if let Some(maximum) = policy.max_value_wei.as_deref() {
            let maximum = U256::from_dec_str(maximum)?;
            if input.total_value()? > maximum {
                anyhow::bail!("transaction value exceeds authorization policy");
            }
        }
        db::insert_auth_audit_event(
            &self.pool,
            context,
            action,
            Some(resource),
            "allow",
            serde_json::json!({
                "chain": input.chain,
                "policy_id": policy.id,
                "policy_version": policy.version
            }),
        )
        .await
        .ok();
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    sub: Uuid,
    organization_id: Uuid,
    credential_id: Uuid,
    credential_kind: CredentialKind,
    agent_id: Option<Uuid>,
    agent_external_id: Option<String>,
    instance_id: Option<Uuid>,
    scopes: Vec<String>,
    auth_version: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    cnf: Option<Confirmation>,
    iat: i64,
    exp: i64,
    jti: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct Confirmation {
    jkt: String,
}

#[derive(Debug, Deserialize)]
struct ClientAssertionClaims {
    iss: String,
    sub: String,
    exp: i64,
    iat: i64,
    jti: String,
}

#[derive(Debug, Deserialize)]
struct DpopClaims {
    jti: String,
    htm: String,
    htu: String,
    iat: i64,
    ath: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkloadClaims {
    iss: String,
    sub: String,
    aud: Audience,
    exp: i64,
}

impl WorkloadClaims {
    fn audience_values(&self) -> Vec<String> {
        match &self.aud {
            Audience::One(value) => vec![value.clone()],
            Audience::Many(values) => values.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
    pub subject_token_type: Option<String>,
    pub subject_token: Option<String>,
    pub scope: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AuthorizationCodeRow {
    organization_id: Uuid,
    principal_id: Uuid,
    passkey_id: Uuid,
    agent_id: Option<Uuid>,
    agent_external_id: Option<String>,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    resource: String,
    scopes: Vec<String>,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct OAuthClientAuthenticationRow {
    token_endpoint_auth_method: String,
    jwks_uri: Option<String>,
    token_endpoint_auth_signing_alg: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    connection_id: Uuid,
    expires_at: chrono::DateTime<Utc>,
    used_at: Option<chrono::DateTime<Utc>>,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Option<Uuid>,
    agent_external_id: Option<String>,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    dpop_jkt: Option<String>,
    status: String,
}

fn random_oauth_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn validate_refresh_dpop_binding(expected: Option<&str>, supplied: Option<&str>) -> Result<()> {
    if expected != supplied {
        anyhow::bail!("refresh token proof does not match the OAuth connection");
    }
    Ok(())
}

fn validate_pkce_verifier(verifier: &str) -> Result<()> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        anyhow::bail!("code_verifier is not a valid RFC 7636 verifier");
    }
    Ok(())
}

fn dpop_header(headers: &HeaderMap) -> Result<&str> {
    headers
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("DPoP header is required"))
}

fn select_scopes(granted: &[String], requested: Option<&str>) -> Result<BTreeSet<String>> {
    let granted: BTreeSet<String> = granted.iter().cloned().collect();
    let requested: BTreeSet<String> = requested
        .unwrap_or("")
        .split_whitespace()
        .filter(|scope| !scope.is_empty())
        .map(String::from)
        .collect();
    validate_scopes(&requested.iter().cloned().collect::<Vec<_>>())?;
    if requested.is_empty() {
        return Ok(granted);
    }
    if !requested.is_subset(&granted) && !granted.contains("*") {
        anyhow::bail!("requested scope exceeds the credential grant");
    }
    Ok(requested)
}

fn validate_proof_time(iat: i64, exp: i64, maximum_lifetime: i64) -> Result<()> {
    let now = Utc::now().timestamp();
    if iat > now + 30 || exp <= now || exp <= iat || exp - iat > maximum_lifetime {
        anyhow::bail!("authentication proof must be current and short-lived");
    }
    Ok(())
}

async fn fetch_public_jwks(uri: &str, label: &str) -> Result<JwkSet> {
    let response = hardened_public_https_client(uri)
        .await?
        .get(uri)
        .send()
        .await
        .with_context(|| format!("{label} JWKS request failed"))?;
    if !response.status().is_success() {
        anyhow::bail!("{label} JWKS endpoint returned an error");
    }
    const MAX_JWKS_BYTES: u64 = 1024 * 1024;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_JWKS_BYTES)
    {
        anyhow::bail!("{label} JWKS response exceeds 1 MiB");
    }
    let body = response
        .bytes()
        .await
        .with_context(|| format!("{label} JWKS response could not be read"))?;
    if body.len() as u64 > MAX_JWKS_BYTES {
        anyhow::bail!("{label} JWKS response exceeds 1 MiB");
    }
    serde_json::from_slice(&body).with_context(|| format!("{label} JWKS response is invalid"))
}

fn verify_oauth_client_assertion(
    assertion: &str,
    client_id: &str,
    token_endpoint: &str,
    expected_algorithm: &str,
    jwks: &JwkSet,
) -> Result<ClientAssertionClaims> {
    let header = decode_header(assertion).context("invalid OAuth client assertion header")?;
    if !allowed_algorithm(header.alg) || algorithm_name(header.alg) != expected_algorithm {
        anyhow::bail!("OAuth client assertion algorithm is not allowed");
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks
            .find(kid)
            .ok_or_else(|| anyhow!("OAuth client signing key was not found"))?,
        None if jwks.keys.len() == 1 => &jwks.keys[0],
        None => {
            anyhow::bail!("OAuth client assertion kid is required when JWKS contains multiple keys")
        }
    };
    let jwk_value = serde_json::to_value(jwk)?;
    if jwk_value
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|algorithm| algorithm != expected_algorithm)
    {
        anyhow::bail!("OAuth client signing key algorithm does not match metadata");
    }
    let key = DecodingKey::from_jwk(jwk).context("OAuth client signing key is unsupported")?;
    let mut validation = Validation::new(header.alg);
    validation.set_audience(&[token_endpoint]);
    validation.leeway = 0;
    let claims = decode::<ClientAssertionClaims>(assertion, &key, &validation)
        .context("OAuth client assertion verification failed")?
        .claims;
    if claims.iss != client_id || claims.sub != client_id {
        anyhow::bail!("OAuth client assertion iss and sub must equal client_id");
    }
    validate_proof_time(claims.iat, claims.exp, 300)?;
    if claims.jti.trim().is_empty() {
        anyhow::bail!("OAuth client assertion jti is required");
    }
    Ok(claims)
}

fn decode_unverified_workload(token: &str, algorithm: Algorithm) -> Result<WorkloadClaims> {
    let mut validation = Validation::new(algorithm);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.aud = None;
    validation.required_spec_claims.clear();
    Ok(
        decode::<WorkloadClaims>(token, &DecodingKey::from_secret(&[]), &validation)
            .context("workload identity token claims are invalid")?
            .claims,
    )
}

fn subject_matches(pattern: &str, subject: &str) -> bool {
    pattern
        .strip_suffix('*')
        .map_or(pattern == subject, |prefix| subject.starts_with(prefix))
}

pub fn validate_federation_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value).context("federation URL is invalid")?;
    if url.scheme() != "https"
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("federation URLs must be public HTTPS URLs without credentials or fragments");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("federation URL hostname is required"))?;
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost"
        || normalized.ends_with(".localhost")
        || normalized.ends_with(".local")
        || normalized.ends_with(".internal")
        || normalized.parse::<std::net::IpAddr>().is_ok()
    {
        anyhow::bail!("federation URL must use a public DNS hostname");
    }
    Ok(())
}

pub(crate) async fn hardened_public_https_client(value: &str) -> Result<reqwest::Client> {
    validate_federation_url(value)?;
    let url = reqwest::Url::parse(value)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("federation URL hostname is required"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| anyhow!("federation host resolution timed out"))?
    .context("federation host could not be resolved")?
    .collect::<Vec<_>>();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !crate::webhook::is_public_ip(address.ip()))
    {
        anyhow::bail!("federation URL must resolve only to public IP addresses");
    }
    reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .resolve_to_addrs(host, &addresses)
        .build()
        .context("failed to build federation HTTP client")
}

pub async fn authentication_middleware(
    State(auth): State<AuthService>,
    mut request: Request,
    next: axum::middleware::Next,
) -> Response {
    match auth
        .authenticate(request.headers(), request.method(), request.uri())
        .await
    {
        Ok(context) => {
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(error) => {
            tracing::warn!(%error, "request authentication failed");
            let resource_path = match request.uri().path() {
                "/mcp/agent" => "/mcp/agent",
                "/mcp/control" => "/mcp/control",
                _ => "",
            };
            let metadata = auth.protected_resource_metadata_url(resource_path);
            let mut response = (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": "invalid_credentials",
                    "message": "credentials or proof-of-possession are missing, invalid, expired, or revoked"
                })),
            )
                .into_response();
            if let Ok(value) = format!("Bearer resource_metadata=\"{metadata}\"").parse() {
                response.headers_mut().insert("www-authenticate", value);
            }
            response
        }
    }
}

pub async fn authorization_middleware(
    State(auth): State<AuthService>,
    request: Request,
    next: axum::middleware::Next,
) -> Response {
    let mut context = match request.extensions().get::<AuthContext>().cloned() {
        Some(context) => context,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "authentication context missing"})),
            )
                .into_response()
        }
    };
    let required_scope = scope_for(request.uri().path());
    if !context.allows_scope(required_scope) {
        db::insert_auth_audit_event(
            &auth.pool,
            &context,
            required_scope,
            Some(request.uri().path()),
            "deny",
            serde_json::json!({"reason": "insufficient_scope"}),
        )
        .await
        .ok();
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "insufficient_scope",
                "required_scope": required_scope
            })),
        )
            .into_response();
    }

    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"error": "request body exceeds 1 MiB"})),
            )
                .into_response()
        }
    };
    let input_result: std::result::Result<AuthorizationInput, ()> = if parts.method == Method::GET {
        parts.uri.query().map_or_else(
            || Ok(AuthorizationInput::default()),
            |query| serde_urlencoded::from_str::<AuthorizationInput>(query).map_err(|_| ()),
        )
    } else if bytes.is_empty() {
        Ok(AuthorizationInput::default())
    } else {
        serde_json::from_slice::<AuthorizationInput>(&bytes).map_err(|_| ())
    };
    let input = match input_result {
        Ok(input) => input,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_authorization_input",
                    "message": "request contains malformed authorization fields"
                })),
            )
                .into_response()
        }
    };

    if !MANAGEMENT_SCOPES.contains(&required_scope) {
        if let Some(external_id) = input.agent_id.as_deref() {
            match db::authorize_execution_agent(&auth.pool, &context, external_id).await {
                Ok((agent, policy)) => {
                    context.agent_id = Some(agent.id);
                    context.agent_external_id = Some(agent.external_id);
                    if let Err(error) = auth
                        .enforce_policy(&context, &policy, required_scope, parts.uri.path(), &input)
                        .await
                    {
                        db::insert_auth_audit_event(
                        &auth.pool,
                        &context,
                        required_scope,
                        Some(parts.uri.path()),
                        "deny",
                        serde_json::json!({"reason": error.to_string(), "policy_id": policy.id}),
                    )
                    .await
                    .ok();
                        return (
                            StatusCode::FORBIDDEN,
                            Json(serde_json::json!({
                                "error": "policy_denied",
                                "message": error.to_string()
                            })),
                        )
                            .into_response();
                    }
                }
                Err(error) => {
                    db::insert_auth_audit_event(
                        &auth.pool,
                        &context,
                        required_scope,
                        Some(parts.uri.path()),
                        "deny",
                        serde_json::json!({"reason": error.to_string(), "agent_id": external_id}),
                    )
                    .await
                    .ok();
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({"error": "agent_not_allowed"})),
                    )
                        .into_response();
                }
            }
        }
    }
    parts.extensions.insert(context);
    next.run(Request::from_parts(parts, Body::from(bytes)))
        .await
}

#[derive(Default, Deserialize)]
struct AuthorizationInput {
    agent_id: Option<String>,
    chain: Option<String>,
    target_contract: Option<String>,
    #[serde(default)]
    value: String,
    batch_calls: Option<Vec<BatchCall>>,
}

impl AuthorizationInput {
    fn targets(&self) -> Vec<&str> {
        if let Some(calls) = &self.batch_calls {
            calls
                .iter()
                .map(|call| call.target_contract.as_str())
                .collect()
        } else {
            self.target_contract.as_deref().into_iter().collect()
        }
    }

    fn total_value(&self) -> Result<U256> {
        if let Some(calls) = &self.batch_calls {
            calls.iter().try_fold(U256::zero(), |total, call| {
                let value = if call.value.is_empty() {
                    U256::zero()
                } else {
                    U256::from_dec_str(&call.value)?
                };
                total
                    .checked_add(value)
                    .ok_or_else(|| anyhow!("batch value overflow"))
            })
        } else if self.value.is_empty() {
            Ok(U256::zero())
        } else {
            Ok(U256::from_dec_str(&self.value)?)
        }
    }
}

fn scope_for(path: &str) -> &'static str {
    if path.starts_with("/agents") {
        "agent:manage"
    } else if path.starts_with("/credential-bindings") {
        "credential:manage"
    } else if path.starts_with("/federation-trusts") {
        "trust:manage"
    } else if path.starts_with("/authorization-policies") {
        "policy:manage"
    } else if path.starts_with("/status/") {
        "execution:read"
    } else if path.starts_with("/wallet") {
        "wallet:read"
    } else if path.ends_with("/simulate") || path.ends_with("/quote") || path == "/simulate" {
        "transaction:simulate"
    } else {
        "transaction:execute"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::EncodingKey;
    use p256::pkcs8::{EncodePrivateKey, LineEnding};
    use rand::rngs::OsRng;

    #[derive(Serialize)]
    struct TestAssertion<'a> {
        iss: &'a str,
        sub: &'a str,
        aud: &'a str,
        iat: i64,
        exp: i64,
        jti: String,
    }

    #[derive(Serialize)]
    struct TestDpop<'a> {
        jti: String,
        htm: &'a str,
        htu: &'a str,
        iat: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        ath: Option<String>,
    }

    fn test_key_material() -> (p256::ecdsa::SigningKey, serde_json::Value) {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"]
        });
        (signing_key, jwk)
    }

    fn test_dpop(
        key: &p256::ecdsa::SigningKey,
        jwk: &serde_json::Value,
        method: &str,
        htu: &str,
        access_token: Option<&str>,
    ) -> String {
        let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.typ = Some("dpop+jwt".into());
        header.jwk = Some(serde_json::from_value(jwk.clone()).unwrap());
        encode(
            &header,
            &TestDpop {
                jti: Uuid::new_v4().to_string(),
                htm: method,
                htu,
                iat: Utc::now().timestamp(),
                ath: access_token
                    .map(|token| URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
            },
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn maps_route_scopes() {
        assert_eq!(scope_for("/wallet"), "wallet:read");
        assert_eq!(scope_for("/agents"), "agent:manage");
    }

    #[test]
    fn agent_mcp_context_requires_a_complete_agent_binding() {
        let mut context = AuthContext {
            organization_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            credential_kind: crate::types::CredentialKind::OAuthSession,
            scopes: BTreeSet::new(),
            agent_id: None,
            agent_external_id: None,
            instance_id: None,
            dpop_jkt: None,
        };
        assert!(bound_agent_external_id(&context).is_err());

        context.agent_id = Some(Uuid::new_v4());
        assert!(bound_agent_external_id(&context).is_err());

        context.agent_external_id = Some("primary-agent".into());
        assert_eq!(bound_agent_external_id(&context).unwrap(), "primary-agent");
    }

    #[test]
    fn compiled_workflow_calls_obey_target_and_native_value_limits() {
        let now = Utc::now();
        let policy = db::models::AuthorizationPolicyRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: "test".into(),
            version: 1,
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: None,
            allowed_actions: Some(vec!["payment_plan:execute".into()]),
            allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
            allow_raw_execution: false,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
            token_spend_limits: serde_json::json!([]),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: Some(10.0),
            max_sponsored_gas_units: Some(2_000_000),
            max_rolling_sponsored_gas_units: Some(10_000_000),
            max_borrowed_value_usd: Some(0.0),
            max_rolling_borrowed_value_usd: Some(0.0),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let allowed = ExecutionRequest {
            agent_id: "agent-1".into(),
            chain: "arc-testnet".into(),
            target_contract: "0x0000000000000000000000000000000000000001".into(),
            calldata: "0x".into(),
            value: "0".into(),
            strategy_id: None,
            batch_calls: None,
            callback_url: None,
            policy_impact: crate::policy::ExecutionPolicyImpact::default(),
        };
        assert!(enforce_compiled_execution_limits(&policy, &allowed).is_ok());

        let mut denied_target = allowed.clone();
        denied_target.target_contract = "0x0000000000000000000000000000000000000002".into();
        assert!(enforce_compiled_execution_limits(&policy, &denied_target).is_err());

        let mut denied_value = allowed;
        denied_value.value = "1".into();
        assert!(enforce_compiled_execution_limits(&policy, &denied_value).is_err());
    }

    #[test]
    fn policy_impacts_require_token_limits_and_explicit_risk_opt_ins() {
        let now = Utc::now();
        let mut policy = db::models::AuthorizationPolicyRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: "impact-test".into(),
            version: 1,
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: None,
            allowed_actions: Some(vec!["payment_plan:execute".into()]),
            allowed_targets: Some(vec!["*".into()]),
            allow_raw_execution: false,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
            token_spend_limits: serde_json::json!([{
                "token": crate::policy::ARC_USDC_ADDRESS,
                "max_per_execution_raw": "5000000",
                "max_rolling_raw": "10000000"
            }]),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: Some(10.0),
            max_sponsored_gas_units: Some(2_000_000),
            max_rolling_sponsored_gas_units: Some(10_000_000),
            max_borrowed_value_usd: Some(100.0),
            max_rolling_borrowed_value_usd: Some(100.0),
            is_active: true,
            created_at: now,
            updated_at: now,
        };
        let allowed = crate::policy::ExecutionPolicyImpact::token_spend(
            crate::policy::ARC_USDC_ADDRESS.parse().unwrap(),
            U256::from(5_000_000u64),
        );
        assert!(enforce_policy_impact(&policy, &allowed).is_ok());

        let oversized = crate::policy::ExecutionPolicyImpact::token_spend(
            crate::policy::ARC_USDC_ADDRESS.parse().unwrap(),
            U256::from(5_000_001u64),
        );
        assert!(enforce_policy_impact(&policy, &oversized).is_err());

        let borrowing = crate::policy::ExecutionPolicyImpact {
            borrowed_value_usd: 1.0,
            risks: vec![crate::policy::RISK_BORROWING.into()],
            ..Default::default()
        };
        assert!(enforce_policy_impact(&policy, &borrowing).is_err());
        policy
            .risk_permissions
            .push(crate::policy::RISK_BORROWING.into());
        assert!(enforce_policy_impact(&policy, &borrowing).is_ok());
    }

    #[test]
    fn authorization_input_rejects_malformed_values_and_sums_batches() {
        assert!(
            serde_json::from_value::<AuthorizationInput>(serde_json::json!({
                "agent_id": "agent-1",
                "value": 1
            }))
            .is_err()
        );
        let input: AuthorizationInput = serde_json::from_value(serde_json::json!({
            "agent_id": "agent-1",
            "batch_calls": [
                {"target_contract": "0x0000000000000000000000000000000000000001", "calldata": "0x", "value": "2"},
                {"target_contract": "0x0000000000000000000000000000000000000002", "calldata": "0x", "value": "3"}
            ]
        }))
        .unwrap();
        assert_eq!(input.total_value().unwrap(), U256::from(5));
        assert_eq!(input.targets().len(), 2);
    }

    #[test]
    fn pkce_verifiers_follow_rfc7636_character_and_length_rules() {
        assert!(validate_pkce_verifier(&"a".repeat(43)).is_ok());
        assert!(validate_pkce_verifier(&"A0-._~".repeat(10)).is_ok());
        assert!(validate_pkce_verifier(&"a".repeat(42)).is_err());
        assert!(validate_pkce_verifier(&"a".repeat(129)).is_err());
        assert!(validate_pkce_verifier(&format!("{}=", "a".repeat(42))).is_err());
    }

    #[test]
    fn refresh_tokens_preserve_their_original_dpop_binding() {
        let thumbprint = "a".repeat(43);
        assert!(validate_refresh_dpop_binding(Some(&thumbprint), Some(&thumbprint)).is_ok());
        assert!(validate_refresh_dpop_binding(None, None).is_ok());
        assert!(validate_refresh_dpop_binding(Some(&thumbprint), None).is_err());
        assert!(validate_refresh_dpop_binding(None, Some(&thumbprint)).is_err());
        assert!(validate_refresh_dpop_binding(Some(&thumbprint), Some(&"b".repeat(43))).is_err());
    }

    #[test]
    fn oauth_client_assertions_are_bound_to_client_audience_and_key() {
        let (signing_key, mut public_jwk) = test_key_material();
        public_jwk["kid"] = serde_json::Value::String("test-key".into());
        let jwks: JwkSet =
            serde_json::from_value(serde_json::json!({"keys": [public_jwk]})).unwrap();
        let pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let client_id = "https://client.example/oauth/client.json";
        let token_endpoint = "https://api.jusso.example/oauth/token";
        let now = Utc::now().timestamp();
        let sign = |audience: &str| {
            let mut header = Header::new(Algorithm::ES256);
            header.kid = Some("test-key".into());
            encode(
                &header,
                &TestAssertion {
                    iss: client_id,
                    sub: client_id,
                    aud: audience,
                    iat: now,
                    exp: now + 120,
                    jti: Uuid::new_v4().to_string(),
                },
                &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
            )
            .unwrap()
        };

        assert!(verify_oauth_client_assertion(
            &sign(token_endpoint),
            client_id,
            token_endpoint,
            "ES256",
            &jwks,
        )
        .is_ok());
        assert!(verify_oauth_client_assertion(
            &sign("https://other.example/oauth/token"),
            client_id,
            token_endpoint,
            "ES256",
            &jwks,
        )
        .is_err());
        assert!(verify_oauth_client_assertion(
            &sign(token_endpoint),
            "https://different.example/oauth/client.json",
            token_endpoint,
            "ES256",
            &jwks,
        )
        .is_err());
    }

    #[test]
    fn public_jwk_validation_uses_stable_rfc7638_thumbprints() {
        let signing_key = p256::ecdsa::SigningKey::random(&mut OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
            "alg": "ES256",
            "use": "sig",
            "key_ops": ["verify"]
        });
        let first = validate_public_jwk(&jwk).unwrap();
        assert_eq!(first, validate_public_jwk(&jwk).unwrap());
        assert_eq!(first.len(), 43);
        let mut private = jwk;
        private["d"] = serde_json::Value::String("not-allowed".into());
        assert!(validate_public_jwk(&private).is_err());
    }

    #[test]
    fn subject_patterns_are_exact_or_trailing_prefix_only() {
        assert!(subject_matches("repo:jusso/api", "repo:jusso/api"));
        assert!(subject_matches("repo:jusso/*", "repo:jusso/api"));
        assert!(!subject_matches("repo:*:api", "repo:jusso/api"));
    }

    #[test]
    fn federation_urls_reject_local_and_insecure_hosts() {
        assert!(validate_federation_url("https://token.actions.githubusercontent.com").is_ok());
        assert!(validate_federation_url("http://issuer.example").is_err());
        assert!(validate_federation_url("https://127.0.0.1/jwks").is_err());
        assert!(validate_federation_url("https://localhost/jwks").is_err());
        assert!(validate_federation_url("https://localhost./jwks").is_err());
        assert!(validate_federation_url("https://issuer.internal/jwks").is_err());
    }

    #[tokio::test]
    async fn local_oauth_tokens_are_dpop_bound_and_replay_protected() {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL env var");
        let pool = db::create_pool(&database_url).await.unwrap();
        db::run_migrations(&pool).await.unwrap();
        let (signing_key, public_jwk) = test_key_material();
        let thumbprint = validate_public_jwk(&public_jwk).unwrap();
        let scopes = DEFAULT_SCOPES
            .iter()
            .map(|scope| (*scope).to_string())
            .collect::<Vec<_>>();
        let actions = DEFAULT_POLICY_ACTIONS
            .iter()
            .map(|scope| (*scope).to_string())
            .collect::<Vec<_>>();
        let protocols = SUPPORTED_PROTOCOLS
            .iter()
            .map(|protocol| (*protocol).to_string())
            .collect::<Vec<_>>();
        let registration = db::create_self_service_registration(
            &pool,
            "1111111111111111111111111111111111111111111111111111111111111111",
            db::SelfServiceRegistrationOptions {
                chain: "arc-testnet",
                organization_name: "OAuth integration test",
                display_name: "OAuth owner",
                agent_external_id: &format!("oauth-agent-{}", Uuid::new_v4().simple()),
                public_jwk: &public_jwk,
                public_jwk_thumbprint: &thumbprint,
                credential_scopes: &scopes,
                policy_actions: &actions,
                policy_protocols: &protocols,
                max_execution_fee_usd: DEFAULT_MAX_EXECUTION_FEE_USD,
            },
        )
        .await
        .unwrap();
        let issuer = "https://api.jusso.test";
        let auth = AuthService::new(
            pool,
            issuer.into(),
            issuer.into(),
            "oauth-test-secret-with-more-than-32-bytes".into(),
            300,
        )
        .unwrap();
        let now = Utc::now().timestamp();
        let pem = signing_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        let assertion = encode(
            &Header::new(Algorithm::ES256),
            &TestAssertion {
                iss: &registration.credential.client_id,
                sub: &registration.credential.client_id,
                aud: auth.token_endpoint(),
                iat: now,
                exp: now + 120,
                jti: Uuid::new_v4().to_string(),
            },
            &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let token_dpop = test_dpop(
            &signing_key,
            &public_jwk,
            "POST",
            auth.token_endpoint(),
            None,
        );
        let request = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: Some(registration.credential.client_id.clone()),
            client_assertion_type: Some(
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
            ),
            client_assertion: Some(assertion),
            subject_token_type: None,
            subject_token: None,
            scope: Some("wallet:read".into()),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
        };
        let token = auth
            .exchange_token(request, Some(&token_dpop))
            .await
            .expect("exchange local credential");
        assert_eq!(token.token_type, "DPoP");

        let resource_dpop = test_dpop(
            &signing_key,
            &public_jwk,
            "GET",
            &format!("{issuer}/wallet"),
            Some(&token.access_token),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            format!("DPoP {}", token.access_token).parse().unwrap(),
        );
        headers.insert("dpop", resource_dpop.parse().unwrap());
        let mut wrong_scheme = headers.clone();
        wrong_scheme.insert(
            AUTHORIZATION,
            format!("Bearer {}", token.access_token).parse().unwrap(),
        );
        assert!(auth
            .authenticate(&wrong_scheme, &Method::GET, &"/wallet".parse().unwrap())
            .await
            .is_err());
        let context = auth
            .authenticate(&headers, &Method::GET, &"/wallet".parse().unwrap())
            .await
            .expect("authenticate DPoP-bound request");
        assert_eq!(
            context.organization_id,
            registration.credential.organization_id
        );
        assert!(context.allows_scope("wallet:read"));
        assert!(auth
            .authenticate(&headers, &Method::GET, &"/wallet".parse().unwrap())
            .await
            .is_err());
    }
}
