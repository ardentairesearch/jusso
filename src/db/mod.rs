//! Database access layer — connection pool + repository functions.

pub mod models;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::ExecutionStatus;
use models::*;

/// Create a connection pool with sensible defaults.
pub async fn create_pool(database_url: &str) -> Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await?;
    Ok(pool)
}

/// Run embedded migrations (from the `migrations/` folder).
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub async fn list_credential_bindings(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Vec<CredentialBindingRow>> {
    Ok(sqlx::query_as::<_, CredentialBindingRow>(
        "SELECT * FROM credential_bindings WHERE organization_id = $1 ORDER BY created_at DESC",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?)
}

pub async fn revoke_credential_binding(
    pool: &PgPool,
    organization_id: Uuid,
    id: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let principal_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE credential_bindings SET is_active = FALSE, updated_at = now() WHERE id = $1 AND organization_id = $2 AND is_active = TRUE RETURNING principal_id",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(principal_id) = principal_id {
        sqlx::query(
            "UPDATE principals SET auth_version = auth_version + 1, updated_at = now() WHERE id = $1",
        )
        .bind(principal_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(true)
    } else {
        transaction.rollback().await?;
        Ok(false)
    }
}

fn random_secret() -> String {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    URL_SAFE_NO_PAD.encode(secret)
}

fn encryption_key(encryption_key_hex: &str) -> Result<[u8; 32]> {
    let decoded =
        hex::decode(encryption_key_hex).map_err(|_| anyhow::anyhow!("invalid encryption key"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("encryption key must be exactly 32 bytes"))
}

pub(crate) fn encrypt_secret(encryption_key_hex: &str, plaintext: &str) -> Result<String> {
    let key = encryption_key(encryption_key_hex)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| anyhow::anyhow!("failed to initialize secret cipher: {error}"))?;
    let mut nonce_bytes = [0u8; 12];
    use aes_gcm::aead::rand_core::RngCore as _;
    AeadOsRng.fill_bytes(&mut nonce_bytes);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .map_err(|error| anyhow::anyhow!("secret encryption failed: {error}"))?;
    let mut encoded = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    encoded.extend_from_slice(&nonce_bytes);
    encoded.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

pub(crate) fn decrypt_secret(encryption_key_hex: &str, ciphertext: &str) -> Result<String> {
    let key = encryption_key(encryption_key_hex)?;
    let encoded = base64::engine::general_purpose::STANDARD
        .decode(ciphertext)
        .map_err(|_| anyhow::anyhow!("encrypted secret is not valid base64"))?;
    if encoded.len() < 13 {
        anyhow::bail!("encrypted secret is too short");
    }
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|error| anyhow::anyhow!("failed to initialize secret cipher: {error}"))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&encoded[..12]), &encoded[12..])
        .map_err(|_| anyhow::anyhow!("secret decryption failed"))?;
    String::from_utf8(plaintext).map_err(Into::into)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SignedUserOperationRow {
    pub signed_user_operation: serde_json::Value,
    pub user_operation_hash: String,
    pub provider_call_id: Option<String>,
}

pub async fn store_signed_user_operation_and_consume_permit(
    pool: &PgPool,
    request_id: Uuid,
    permit_id: Uuid,
    signed_user_operation: &serde_json::Value,
    user_operation_hash: &str,
) -> Result<()> {
    if user_operation_hash.len() != 66 || !user_operation_hash.starts_with("0x") {
        anyhow::bail!("invalid UserOperation hash");
    }
    let mut transaction = pool.begin().await?;
    let stored = sqlx::query(
        r#"
        UPDATE execution_requests
        SET signed_user_operation = $2,
            user_operation_hash = $3,
            updated_at = now()
        WHERE id = $1
          AND (signed_user_operation IS NULL OR signed_user_operation = $2)
          AND (user_operation_hash IS NULL OR user_operation_hash = $3)
        "#,
    )
    .bind(request_id)
    .bind(signed_user_operation)
    .bind(user_operation_hash)
    .execute(&mut *transaction)
    .await?;
    if stored.rows_affected() != 1 {
        anyhow::bail!("execution already contains a different signed UserOperation");
    }
    let consumed = sqlx::query(
        r#"
        UPDATE execution_permits ep
        SET consumed_at = now()
        FROM authorization_policies ap, agents a
        WHERE ep.id = $1 AND ep.request_id = $2
          AND ep.claimed_at IS NOT NULL AND ep.consumed_at IS NULL
          AND ep.expires_at > now()
          AND ap.id = ep.policy_id AND ap.organization_id = ep.organization_id
          AND ap.is_active = TRUE AND ap.version = ep.policy_version
          AND a.id = ep.agent_id AND a.organization_id = ep.organization_id
          AND a.status = 'active' AND a.policy_id = ep.policy_id
        "#,
    )
    .bind(permit_id)
    .bind(request_id)
    .execute(&mut *transaction)
    .await?;
    if consumed.rows_affected() != 1 {
        anyhow::bail!("execution permit expired or was revoked before signing completed");
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn get_signed_user_operation(
    pool: &PgPool,
    request_id: Uuid,
) -> Result<Option<SignedUserOperationRow>> {
    Ok(sqlx::query_as::<_, SignedUserOperationRow>(
        r#"
        SELECT signed_user_operation, user_operation_hash, provider_call_id
        FROM execution_requests
        WHERE id = $1 AND signed_user_operation IS NOT NULL
        "#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn store_provider_call_id(
    pool: &PgPool,
    request_id: Uuid,
    user_operation_hash: &str,
    provider_call_id: &str,
) -> Result<()> {
    let changed = sqlx::query(
        r#"
        UPDATE execution_requests
        SET provider_call_id = $3, updated_at = now()
        WHERE id = $1 AND user_operation_hash = $2
          AND (provider_call_id IS NULL OR provider_call_id = $3)
        "#,
    )
    .bind(request_id)
    .bind(user_operation_hash)
    .bind(provider_call_id)
    .execute(pool)
    .await?;
    if changed.rows_affected() != 1 {
        anyhow::bail!("execution contains a different provider call ID");
    }
    Ok(())
}

pub async fn get_active_principal(pool: &PgPool, id: Uuid) -> Result<PrincipalRow> {
    Ok(sqlx::query_as::<_, PrincipalRow>(
        r#"
        SELECT p.*
        FROM principals p
        JOIN organizations o ON o.id = p.organization_id
        WHERE p.id = $1 AND p.status = 'active' AND o.status = 'active'
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?)
}

pub struct SelfServiceRegistrationOptions<'a> {
    pub chain: &'a str,
    pub organization_name: &'a str,
    pub display_name: &'a str,
    pub agent_external_id: &'a str,
    pub public_jwk: &'a serde_json::Value,
    pub public_jwk_thumbprint: &'a str,
    pub credential_scopes: &'a [String],
    pub policy_actions: &'a [String],
    pub policy_protocols: &'a [String],
    pub max_execution_fee_usd: f64,
}

pub struct SelfServiceRegistrationResult {
    pub credential: CredentialBindingRow,
    pub agent: AgentRow,
    pub policy: AuthorizationPolicyRow,
    pub webhook_secret: String,
}

pub async fn create_self_service_registration(
    pool: &PgPool,
    encryption_key_hex: &str,
    options: SelfServiceRegistrationOptions<'_>,
) -> Result<SelfServiceRegistrationResult> {
    let mut transaction = pool.begin().await?;
    let organization_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let policy_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let webhook_secret = random_secret();
    let encrypted_webhook_secret = encrypt_secret(encryption_key_hex, &webhook_secret)?;

    sqlx::query(
        "INSERT INTO organizations (id, name, webhook_secret_encrypted) VALUES ($1, $2, $3)",
    )
    .bind(organization_id)
    .bind(options.organization_name)
    .bind(encrypted_webhook_secret)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO principals (id, organization_id, display_name, principal_type) VALUES ($1, $2, $3, 'owner')",
    )
    .bind(principal_id)
    .bind(organization_id)
    .bind(options.display_name)
    .execute(&mut *transaction)
    .await?;

    if !matches!(options.chain, "arc" | "arc-testnet") {
        anyhow::bail!("self-service registration requires an Arc network");
    }
    let allowed_chains = vec![options.chain.to_string()];
    let policy = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"
        INSERT INTO authorization_policies (
            id, organization_id, name, allowed_chains, allowed_protocols,
            allowed_actions, max_value_wei, max_execution_fee_usd
        )
        VALUES ($1, $2, 'default-autonomous', $3, $4, $5, '0', $6)
        RETURNING *
        "#,
    )
    .bind(policy_id)
    .bind(organization_id)
    .bind(&allowed_chains)
    .bind(options.policy_protocols)
    .bind(options.policy_actions)
    .bind(options.max_execution_fee_usd)
    .fetch_one(&mut *transaction)
    .await?;
    let agent = sqlx::query_as::<_, AgentRow>(
        r#"
        INSERT INTO agents (
            id, organization_id, external_id, display_name, policy_id
        )
        VALUES ($1, $2, $3, $4, $5)
        RETURNING *
        "#,
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(options.agent_external_id)
    .bind(options.display_name)
    .bind(policy_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO principal_agent_grants (principal_id, agent_id) VALUES ($1, $2)")
        .bind(principal_id)
        .bind(agent_id)
        .execute(&mut *transaction)
        .await?;

    let credential = sqlx::query_as::<_, CredentialBindingRow>(
        r#"
        INSERT INTO credential_bindings (
            id, organization_id, principal_id, agent_id, credential_kind,
            client_id, public_jwk, public_jwk_thumbprint, scopes
        )
        VALUES ($1, $2, $3, $4, 'local_jwk', $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(principal_id)
    .bind(Option::<Uuid>::None)
    .bind(format!("jso_client_{}", Uuid::new_v4().simple()))
    .bind(options.public_jwk)
    .bind(options.public_jwk_thumbprint)
    .bind(options.credential_scopes)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_duplicate_public_jwk)?;

    transaction.commit().await?;
    Ok(SelfServiceRegistrationResult {
        credential,
        agent,
        policy,
        webhook_secret,
    })
}

fn map_duplicate_public_jwk(error: sqlx::Error) -> anyhow::Error {
    if error.as_database_error().is_some_and(|database| {
        database.code().as_deref() == Some("23505")
            && database.constraint() == Some("credential_bindings_public_jwk_thumbprint_key")
    }) {
        anyhow::anyhow!("public JWK is already registered")
    } else {
        error.into()
    }
}

pub async fn get_agent_by_external_id(
    pool: &PgPool,
    organization_id: Uuid,
    external_id: &str,
) -> Result<Option<AgentRow>> {
    Ok(sqlx::query_as::<_, AgentRow>(
        r#"
        SELECT * FROM agents
        WHERE organization_id = $1 AND external_id = $2 AND status = 'active'
        "#,
    )
    .bind(organization_id)
    .bind(external_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn principal_can_access_agent(
    pool: &PgPool,
    principal_id: Uuid,
    agent_id: Uuid,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM principal_agent_grants pag
            JOIN principals p ON p.id = pag.principal_id
            JOIN agents a ON a.id = pag.agent_id
            JOIN organizations o ON o.id = a.organization_id
            WHERE pag.principal_id = $1 AND pag.agent_id = $2
              AND p.organization_id = a.organization_id
              AND p.status = 'active' AND a.status = 'active' AND o.status = 'active'
        )
        "#,
    )
    .bind(principal_id)
    .bind(agent_id)
    .fetch_one(pool)
    .await?)
}

pub async fn list_agents_for_principal(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
) -> Result<Vec<AgentRow>> {
    Ok(sqlx::query_as::<_, AgentRow>(
        r#"
        SELECT a.*
        FROM agents a
        JOIN principal_agent_grants pag ON pag.agent_id = a.id
        WHERE a.organization_id = $1 AND pag.principal_id = $2
        ORDER BY a.created_at
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_all(pool)
    .await?)
}

pub async fn assign_agent_policy(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    policy_id: Uuid,
) -> Result<bool> {
    let result = sqlx::query(
        r#"
        UPDATE agents a
        SET policy_id = $4, updated_at = now()
        WHERE a.id = $3 AND a.organization_id = $1 AND a.status = 'active'
          AND EXISTS (
              SELECT 1 FROM principal_agent_grants
              WHERE principal_id = $2 AND agent_id = a.id
          )
          AND EXISTS (
              SELECT 1 FROM authorization_policies
              WHERE id = $4 AND organization_id = $1 AND is_active = TRUE
          )
        "#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(agent_id)
    .bind(policy_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn create_agent_enrollment_grant(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    scopes: &[String],
    ttl_seconds: i64,
) -> Result<(String, chrono::DateTime<Utc>)> {
    let can_access = principal_can_access_agent(pool, principal_id, agent_id).await?;
    let belongs: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND organization_id = $2 AND status = 'active')",
    )
    .bind(agent_id)
    .bind(organization_id)
    .fetch_one(pool)
    .await?;
    if !can_access || !belongs {
        anyhow::bail!("agent is not granted to this principal");
    }
    let raw_token = format!("jso_enroll_{}", random_secret());
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds.clamp(60, 86_400));
    sqlx::query(
        r#"
        INSERT INTO agent_enrollment_grants (
            id, organization_id, agent_id, created_by_principal_id,
            token_hash, scopes, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(agent_id)
    .bind(principal_id)
    .bind(sha256_hex(&raw_token))
    .bind(scopes)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok((raw_token, expires_at))
}

pub struct CreateAgentOptions<'a> {
    pub organization_id: Uuid,
    pub created_by_principal_id: Uuid,
    pub external_id: &'a str,
    pub display_name: &'a str,
    pub parent_agent_id: Option<Uuid>,
    pub policy_id: Uuid,
    pub runtime_scopes: &'a [String],
    pub enrollment_ttl_seconds: i64,
}

pub async fn create_agent_with_enrollment(
    pool: &PgPool,
    options: CreateAgentOptions<'_>,
) -> Result<(AgentRow, String, chrono::DateTime<Utc>)> {
    let mut transaction = pool.begin().await?;
    if let Some(parent_agent_id) = options.parent_agent_id {
        let allowed: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM principal_agent_grants pag JOIN agents a ON a.id = pag.agent_id WHERE pag.principal_id = $1 AND pag.agent_id = $2 AND a.organization_id = $3 AND a.status = 'active')",
        )
        .bind(options.created_by_principal_id)
        .bind(parent_agent_id)
        .bind(options.organization_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !allowed {
            anyhow::bail!("parent agent is not granted to this principal");
        }
    }
    let policy_belongs: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM authorization_policies WHERE id = $1 AND organization_id = $2 AND is_active = TRUE)",
    )
    .bind(options.policy_id)
    .bind(options.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !policy_belongs {
        anyhow::bail!("active policy not found in organization");
    }
    let agent = sqlx::query_as::<_, AgentRow>(
        r#"
        INSERT INTO agents (
            id, organization_id, external_id, display_name, parent_agent_id, policy_id
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(options.organization_id)
    .bind(options.external_id)
    .bind(options.display_name)
    .bind(options.parent_agent_id)
    .bind(options.policy_id)
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO principal_agent_grants (principal_id, agent_id) VALUES ($1, $2)")
        .bind(options.created_by_principal_id)
        .bind(agent.id)
        .execute(&mut *transaction)
        .await?;

    let raw_token = format!("jso_enroll_{}", random_secret());
    let expires_at =
        Utc::now() + chrono::Duration::seconds(options.enrollment_ttl_seconds.clamp(60, 86_400));
    sqlx::query(
        r#"
        INSERT INTO agent_enrollment_grants (
            id, organization_id, agent_id, created_by_principal_id, token_hash, scopes, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(options.organization_id)
    .bind(agent.id)
    .bind(options.created_by_principal_id)
    .bind(sha256_hex(&raw_token))
    .bind(options.runtime_scopes)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((agent, raw_token, expires_at))
}

pub struct EnrollAgentOptions<'a> {
    pub enrollment_token: &'a str,
    pub display_name: &'a str,
    pub public_jwk: &'a serde_json::Value,
    pub public_jwk_thumbprint: &'a str,
}

pub async fn enroll_agent(
    pool: &PgPool,
    options: EnrollAgentOptions<'_>,
) -> Result<(CredentialBindingRow, AgentRow)> {
    let mut transaction = pool.begin().await?;
    let token_hash = sha256_hex(options.enrollment_token);
    let grant: (Uuid, Uuid, Vec<String>) = sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, scopes
        FROM agent_enrollment_grants
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        FOR UPDATE
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("invalid, expired, or already used enrollment grant"))?;
    let agent = sqlx::query_as::<_, AgentRow>(
        "SELECT * FROM agents WHERE id = $1 AND organization_id = $2 AND status = 'active'",
    )
    .bind(grant.1)
    .bind(grant.0)
    .fetch_one(&mut *transaction)
    .await?;
    let principal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO principals (id, organization_id, display_name, principal_type) VALUES ($1, $2, $3, 'agent')",
    )
    .bind(principal_id)
    .bind(grant.0)
    .bind(options.display_name)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO principal_agent_grants (principal_id, agent_id) VALUES ($1, $2)")
        .bind(principal_id)
        .bind(grant.1)
        .execute(&mut *transaction)
        .await?;
    let credential = sqlx::query_as::<_, CredentialBindingRow>(
        r#"
        INSERT INTO credential_bindings (
            id, organization_id, principal_id, agent_id, credential_kind,
            client_id, public_jwk, public_jwk_thumbprint, scopes
        )
        VALUES ($1, $2, $3, $4, 'local_jwk', $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(grant.0)
    .bind(principal_id)
    .bind(grant.1)
    .bind(format!("jso_client_{}", Uuid::new_v4().simple()))
    .bind(options.public_jwk)
    .bind(options.public_jwk_thumbprint)
    .bind(&grant.2)
    .fetch_one(&mut *transaction)
    .await
    .map_err(map_duplicate_public_jwk)?;
    sqlx::query("UPDATE agent_enrollment_grants SET used_at = now() WHERE token_hash = $1")
        .bind(token_hash)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok((credential, agent))
}

pub struct CreateFederationTrustOptions<'a> {
    pub organization_id: Uuid,
    pub created_by_principal_id: Uuid,
    pub agent_id: Uuid,
    pub name: &'a str,
    pub issuer: &'a str,
    pub jwks_uri: &'a str,
    pub audience: &'a str,
    pub subject_pattern: &'a str,
    pub scopes: &'a [String],
}

pub async fn create_federation_trust(
    pool: &PgPool,
    options: CreateFederationTrustOptions<'_>,
) -> Result<FederationTrustRow> {
    let mut transaction = pool.begin().await?;
    let can_manage: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM principal_agent_grants pag
            JOIN principals p ON p.id = pag.principal_id
            JOIN agents a ON a.id = pag.agent_id
            WHERE pag.principal_id = $1 AND pag.agent_id = $2
              AND p.organization_id = $3 AND a.organization_id = $3
              AND p.status = 'active' AND a.status = 'active'
        )
        "#,
    )
    .bind(options.created_by_principal_id)
    .bind(options.agent_id)
    .bind(options.organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !can_manage {
        anyhow::bail!("agent is not granted to this principal");
    }

    let principal_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO principals (id, organization_id, display_name, principal_type) VALUES ($1, $2, $3, 'agent')",
    )
    .bind(principal_id)
    .bind(options.organization_id)
    .bind(options.name)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("INSERT INTO principal_agent_grants (principal_id, agent_id) VALUES ($1, $2)")
        .bind(principal_id)
        .bind(options.agent_id)
        .execute(&mut *transaction)
        .await?;
    let row = sqlx::query_as::<_, FederationTrustRow>(
        r#"
        INSERT INTO federation_trusts (
            id, organization_id, principal_id, agent_id, name, issuer,
            jwks_uri, audience, subject_pattern, scopes
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(options.organization_id)
    .bind(principal_id)
    .bind(options.agent_id)
    .bind(options.name)
    .bind(options.issuer)
    .bind(options.jwks_uri)
    .bind(options.audience)
    .bind(options.subject_pattern)
    .bind(options.scopes)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(row)
}

pub async fn find_federation_trusts(
    pool: &PgPool,
    issuer: &str,
    audience: &str,
) -> Result<Vec<FederationTrustRow>> {
    Ok(sqlx::query_as::<_, FederationTrustRow>(
        r#"
        SELECT ft.* FROM federation_trusts ft
        JOIN organizations o ON o.id = ft.organization_id
        JOIN principals p ON p.id = ft.principal_id
        JOIN agents a ON a.id = ft.agent_id
        WHERE ft.issuer = $1 AND ft.audience = $2 AND ft.is_active = TRUE
          AND o.status = 'active' AND p.status = 'active' AND a.status = 'active'
        "#,
    )
    .bind(issuer)
    .bind(audience)
    .fetch_all(pool)
    .await?)
}

pub async fn list_federation_trusts(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Vec<FederationTrustRow>> {
    Ok(sqlx::query_as::<_, FederationTrustRow>(
        "SELECT * FROM federation_trusts WHERE organization_id = $1 ORDER BY created_at",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?)
}

pub async fn revoke_federation_trust(
    pool: &PgPool,
    organization_id: Uuid,
    id: Uuid,
) -> Result<bool> {
    let mut transaction = pool.begin().await?;
    let principal_id: Option<Uuid> = sqlx::query_scalar(
        "UPDATE federation_trusts SET is_active = FALSE, updated_at = now() WHERE id = $1 AND organization_id = $2 AND is_active = TRUE RETURNING principal_id",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    let Some(principal_id) = principal_id else {
        transaction.rollback().await?;
        return Ok(false);
    };
    sqlx::query(
        "UPDATE principals SET auth_version = auth_version + 1, updated_at = now() WHERE id = $1",
    )
    .bind(principal_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(true)
}

pub async fn upsert_agent_instance(
    pool: &PgPool,
    trust: &FederationTrustRow,
    instance_key: &str,
    expires_at: chrono::DateTime<Utc>,
) -> Result<Uuid> {
    Ok(sqlx::query_scalar(
        r#"
        INSERT INTO agent_instances (
            id, organization_id, agent_id, federation_trust_id,
            instance_key, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (agent_id, instance_key) DO UPDATE
        SET last_seen_at = now(), expires_at = EXCLUDED.expires_at
        WHERE agent_instances.status = 'active'
        RETURNING id
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(trust.organization_id)
    .bind(trust.agent_id)
    .bind(trust.id)
    .bind(instance_key)
    .bind(expires_at)
    .fetch_one(pool)
    .await?)
}

pub async fn get_credential_binding_by_client_id(
    pool: &PgPool,
    client_id: &str,
) -> Result<Option<CredentialBindingRow>> {
    Ok(sqlx::query_as::<_, CredentialBindingRow>(
        r#"
        SELECT sa.*
        FROM credential_bindings sa
        JOIN organizations o ON o.id = sa.organization_id
        JOIN principals p ON p.id = sa.principal_id
        WHERE sa.client_id = $1
          AND sa.is_active = TRUE
          AND o.status = 'active'
          AND p.status = 'active'
        "#,
    )
    .bind(client_id)
    .fetch_optional(pool)
    .await?)
}

pub struct CreateCredentialBindingOptions<'a> {
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub public_jwk: &'a serde_json::Value,
    pub public_jwk_thumbprint: &'a str,
    pub scopes: &'a [String],
}

pub async fn create_credential_binding(
    pool: &PgPool,
    options: CreateCredentialBindingOptions<'_>,
) -> Result<CredentialBindingRow> {
    let mut transaction = pool.begin().await?;
    let organization_id = options.organization_id;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1 AND status = 'active')",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !active {
        anyhow::bail!("active organization not found");
    }
    if let Some(agent_id) = options.agent_id {
        let belongs: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND organization_id = $2 AND status = 'active')",
        )
        .bind(agent_id)
        .bind(organization_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !belongs {
            anyhow::bail!("active agent not found in organization");
        }
    }
    let principal_id = options.principal_id;
    let belongs: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM principals WHERE id = $1 AND organization_id = $2 AND status = 'active')",
    )
    .bind(principal_id)
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !belongs {
        anyhow::bail!("active principal not found in organization");
    }
    if let Some(agent_id) = options.agent_id {
        let can_access: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM principal_agent_grants WHERE principal_id = $1 AND agent_id = $2)",
        )
        .bind(principal_id)
        .bind(agent_id)
        .fetch_one(&mut *transaction)
        .await?;
        if !can_access {
            anyhow::bail!("agent is not granted to this principal");
        }
    }

    let client_id = format!("jso_client_{}", Uuid::new_v4().simple());
    let scopes = if options.scopes.is_empty() {
        crate::auth::DEFAULT_SCOPES
            .iter()
            .map(|scope| scope.to_string())
            .collect::<Vec<_>>()
    } else {
        options.scopes.to_vec()
    };
    let row = sqlx::query_as::<_, CredentialBindingRow>(
        r#"
        INSERT INTO credential_bindings (
            id, organization_id, principal_id, agent_id, credential_kind,
            client_id, public_jwk, scopes, public_jwk_thumbprint
        )
        VALUES ($1, $2, $3, $4, 'local_jwk', $5, $6, $7, $8)
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(principal_id)
    .bind(options.agent_id)
    .bind(client_id)
    .bind(options.public_jwk)
    .bind(scopes)
    .bind(options.public_jwk_thumbprint)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|error| {
        if error.as_database_error().is_some_and(|database| {
            database.code().as_deref() == Some("23505")
                && database.constraint() == Some("credential_bindings_public_jwk_thumbprint_key")
        }) {
            anyhow::anyhow!("public JWK is already registered")
        } else {
            error.into()
        }
    })?;
    transaction.commit().await?;
    Ok(row)
}

pub async fn touch_credential_binding(pool: &PgPool, id: Uuid) -> Result<()> {
    sqlx::query("UPDATE credential_bindings SET last_used_at = now() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn consume_oauth_proof_jti(
    pool: &PgPool,
    proof_context: &str,
    jti: &str,
    expires_at: i64,
) -> Result<()> {
    let expires_at = chrono::DateTime::from_timestamp(expires_at, 0)
        .ok_or_else(|| anyhow::anyhow!("invalid assertion expiry"))?;
    let mut transaction = pool.begin().await?;
    sqlx::query("DELETE FROM oauth_proof_jtis WHERE expires_at <= now()")
        .execute(&mut *transaction)
        .await?;
    let inserted = sqlx::query(
        r#"
        INSERT INTO oauth_proof_jtis (proof_context, jti, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
    )
    .bind(proof_context)
    .bind(jti)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    if inserted.rows_affected() != 1 {
        anyhow::bail!("authentication proof has already been used");
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn get_authorization_policy(
    pool: &PgPool,
    organization_id: Uuid,
    policy_id: Uuid,
) -> Result<Option<AuthorizationPolicyRow>> {
    Ok(sqlx::query_as::<_, AuthorizationPolicyRow>(
        "SELECT * FROM authorization_policies WHERE id = $1 AND organization_id = $2 AND is_active = TRUE",
    )
    .bind(policy_id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn list_authorization_policies(
    pool: &PgPool,
    organization_id: Uuid,
) -> Result<Vec<AuthorizationPolicyRow>> {
    Ok(sqlx::query_as::<_, AuthorizationPolicyRow>(
        "SELECT * FROM authorization_policies WHERE organization_id = $1 ORDER BY created_at",
    )
    .bind(organization_id)
    .fetch_all(pool)
    .await?)
}

pub struct CreateAuthorizationPolicyOptions<'a> {
    pub organization_id: Uuid,
    pub name: &'a str,
    pub allowed_chains: Option<&'a [String]>,
    pub allowed_protocols: Option<&'a [String]>,
    pub allowed_actions: Option<&'a [String]>,
    pub allowed_targets: Option<&'a [String]>,
    pub allow_raw_execution: bool,
    pub max_value_wei: Option<&'a str>,
    pub max_execution_fee_usd: Option<f64>,
}

pub async fn create_authorization_policy(
    pool: &PgPool,
    options: CreateAuthorizationPolicyOptions<'_>,
) -> Result<Uuid> {
    let organization_active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM organizations WHERE id = $1 AND status = 'active')",
    )
    .bind(options.organization_id)
    .fetch_one(pool)
    .await?;
    if !organization_active {
        anyhow::bail!("active organization not found");
    }
    if options.name.trim().is_empty() || options.name.len() > 100 {
        anyhow::bail!("policy name must contain 1-100 characters");
    }
    if options
        .max_value_wei
        .is_some_and(|value| value.parse::<ethers::types::U256>().is_err())
    {
        anyhow::bail!("max_value_wei must be an unsigned decimal integer");
    }
    if options
        .max_execution_fee_usd
        .is_some_and(|value| !value.is_finite() || value < 0.0)
    {
        anyhow::bail!("max_execution_fee_usd must be a non-negative finite number");
    }
    let id = Uuid::new_v4();
    sqlx::query(
        r#"
        INSERT INTO authorization_policies (
            id, organization_id, name, allowed_chains,
            allowed_protocols, allowed_actions, allowed_targets,
            allow_raw_execution, max_value_wei, max_execution_fee_usd
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        "#,
    )
    .bind(id)
    .bind(options.organization_id)
    .bind(options.name.trim())
    .bind(options.allowed_chains)
    .bind(options.allowed_protocols)
    .bind(options.allowed_actions)
    .bind(options.allowed_targets)
    .bind(options.allow_raw_execution)
    .bind(options.max_value_wei)
    .bind(options.max_execution_fee_usd)
    .execute(pool)
    .await?;
    Ok(id)
}

pub async fn revoke_authorization_policy(
    pool: &PgPool,
    organization_id: Uuid,
    id: Uuid,
) -> Result<bool> {
    let result = sqlx::query(
        "UPDATE authorization_policies SET is_active = FALSE, updated_at = now() WHERE id = $1 AND organization_id = $2 AND is_active = TRUE AND NOT EXISTS (SELECT 1 FROM agents WHERE policy_id = $1 AND status = 'active')",
    )
    .bind(id)
    .bind(organization_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn insert_auth_audit_event(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    action: &str,
    resource: Option<&str>,
    decision: &str,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO auth_audit_events (
            id, organization_id, principal_id, agent_id, instance_id,
            credential_id, credential_kind, action, resource, decision, details
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(context.agent_id)
    .bind(context.instance_id)
    .bind(context.credential_id)
    .bind(
        serde_json::to_value(&context.credential_kind)?
            .as_str()
            .unwrap_or("unknown"),
    )
    .bind(action)
    .bind(resource)
    .bind(decision)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn execution_payload_hash(req: &crate::types::ExecutionRequest) -> Result<String> {
    let chain = crate::types::Chain::from_str_loose(&req.chain)
        .map(|chain| chain.to_string())
        .unwrap_or_else(|| req.chain.to_lowercase());
    let payload = serde_json::json!({
        "agent_id": req.agent_id,
        "chain": chain,
        "target_contract": req.target_contract,
        "calldata": req.calldata,
        "value": req.value,
        "batch_calls": req.batch_calls,
    });
    Ok(sha256_hex(&serde_json::to_string(&payload)?))
}

fn idempotency_fingerprint(
    req: &crate::types::ExecutionRequest,
    operation: &str,
) -> Result<String> {
    let chain = crate::types::Chain::from_str_loose(&req.chain)
        .map(|chain| chain.to_string())
        .unwrap_or_else(|| req.chain.to_lowercase());
    let payload = serde_json::json!({
        "operation": operation,
        "agent_id": req.agent_id,
        "chain": chain,
        "target_contract": req.target_contract,
        "calldata": req.calldata,
        "value": req.value,
        "strategy_id": req.strategy_id,
        "batch_calls": req.batch_calls,
        "callback_url": req.callback_url,
    });
    Ok(sha256_hex(&serde_json::to_string(&payload)?))
}

// ──────────────────────── Execution Requests ─────────────────────────

pub async fn authorize_execution_agent(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    external_id: &str,
) -> Result<(AgentRow, AuthorizationPolicyRow)> {
    let agent = get_agent_by_external_id(pool, context.organization_id, external_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("active agent is not registered in this organization"))?;
    if context.is_bound_to_other_agent(agent.id)
        || !principal_can_access_agent(pool, context.principal_id, agent.id).await?
    {
        anyhow::bail!("credential is not authorized for this agent");
    }
    let policy = get_authorization_policy(pool, context.organization_id, agent.policy_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("agent authorization policy is inactive"))?;
    Ok((agent, policy))
}

pub async fn insert_execution_request(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    req: &crate::types::ExecutionRequest,
    status: &ExecutionStatus,
    smart_wallet_address: Option<&str>,
    callback_url: Option<&str>,
) -> Result<ExecutionRequestRow> {
    let (agent, policy) = authorize_execution_agent(pool, context, &req.agent_id).await?;
    let now = Utc::now();
    let payload_hash = execution_payload_hash(req)?;
    let row = sqlx::query_as::<_, ExecutionRequestRow>(
        r#"
        INSERT INTO execution_requests
            (id, chain, target_contract, calldata, value, strategy_id,
             status, created_at, updated_at, agent_id, smart_wallet_address, callback_url,
             payload_hash, organization_id, principal_id, agent_uuid,
             instance_id, policy_id, policy_version)
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19
        )
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(&req.chain)
    .bind(&req.target_contract)
    .bind(&req.calldata)
    .bind(&req.value)
    .bind(&req.strategy_id)
    .bind(status.to_string())
    .bind(now)
    .bind(now)
    .bind(&req.agent_id)
    .bind(smart_wallet_address)
    .bind(callback_url)
    .bind(payload_hash)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(agent.id)
    .bind(context.instance_id)
    .bind(policy.id)
    .bind(policy.version)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Reserve an execution request exactly once for an organization-scoped key.
///
/// The unique index is the concurrency primitive: concurrent retries either
/// create the same logical request or load the winner. A reused key with a
/// different fingerprint is rejected.
pub async fn reserve_execution_request(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    req: &crate::types::ExecutionRequest,
    operation: &str,
    idempotency_key: &str,
    smart_wallet_address: &str,
    callback_url: Option<&str>,
) -> Result<(ExecutionRequestRow, bool)> {
    validate_idempotency_key(idempotency_key)?;
    let (agent, policy) = authorize_execution_agent(pool, context, &req.agent_id).await?;
    let now = Utc::now();
    let payload_hash = execution_payload_hash(req)?;
    let fingerprint = idempotency_fingerprint(req, operation)?;
    let candidate_id = Uuid::new_v4();
    let inserted = sqlx::query_as::<_, ExecutionRequestRow>(
        r#"
        INSERT INTO execution_requests
            (id, chain, target_contract, calldata, value, strategy_id,
             status, created_at, updated_at, agent_id, smart_wallet_address,
             callback_url, payload_hash, organization_id, principal_id, agent_uuid,
             instance_id, policy_id, policy_version, idempotency_key, idempotency_fingerprint)
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21
        )
        ON CONFLICT (organization_id, idempotency_key)
            WHERE idempotency_key IS NOT NULL
        DO NOTHING
        RETURNING *
        "#,
    )
    .bind(candidate_id)
    .bind(&req.chain)
    .bind(&req.target_contract)
    .bind(&req.calldata)
    .bind(&req.value)
    .bind(&req.strategy_id)
    .bind(ExecutionStatus::Pending.to_string())
    .bind(now)
    .bind(now)
    .bind(&req.agent_id)
    .bind(smart_wallet_address)
    .bind(callback_url)
    .bind(payload_hash)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(agent.id)
    .bind(context.instance_id)
    .bind(policy.id)
    .bind(policy.version)
    .bind(idempotency_key)
    .bind(&fingerprint)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = inserted {
        return Ok((row, true));
    }
    let existing = sqlx::query_as::<_, ExecutionRequestRow>(
        r#"
        SELECT * FROM execution_requests
        WHERE organization_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(context.organization_id)
    .bind(idempotency_key)
    .fetch_one(pool)
    .await?;
    if existing.idempotency_fingerprint.as_deref() != Some(fingerprint.as_str()) {
        anyhow::bail!("idempotency key was already used for a different request");
    }
    if existing.principal_id != context.principal_id
        || existing.agent_uuid != agent.id
        || existing.instance_id != context.instance_id
    {
        anyhow::bail!("idempotency key belongs to a different authenticated identity");
    }
    Ok((existing, false))
}

pub async fn get_idempotent_execution_request(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    req: &crate::types::ExecutionRequest,
    operation: &str,
    idempotency_key: &str,
) -> Result<Option<ExecutionRequestRow>> {
    validate_idempotency_key(idempotency_key)?;
    let fingerprint = idempotency_fingerprint(req, operation)?;
    let row = sqlx::query_as::<_, ExecutionRequestRow>(
        r#"
        SELECT * FROM execution_requests
        WHERE organization_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(context.organization_id)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    if row.as_ref().is_some_and(|existing| {
        existing.idempotency_fingerprint.as_deref() != Some(fingerprint.as_str())
    }) {
        anyhow::bail!("idempotency key was already used for a different request");
    }
    if row.as_ref().is_some_and(|existing| {
        existing.principal_id != context.principal_id
            || existing.instance_id != context.instance_id
            || context.is_bound_to_other_agent(existing.agent_uuid)
    }) {
        anyhow::bail!("idempotency key belongs to a different authenticated identity");
    }
    Ok(row)
}

/// Recover an already accepted typed execution before re-running mutable
/// protocol discovery or quote resolution. Ownership checks prevent a key
/// from revealing another agent's request.
pub async fn get_execution_request_by_idempotency_key_for_agent(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    agent_external_id: &str,
    idempotency_key: &str,
) -> Result<Option<ExecutionRequestRow>> {
    validate_idempotency_key(idempotency_key)?;
    let (agent, _) = authorize_execution_agent(pool, context, agent_external_id).await?;
    let row = sqlx::query_as::<_, ExecutionRequestRow>(
        r#"
        SELECT * FROM execution_requests
        WHERE organization_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind(context.organization_id)
    .bind(idempotency_key)
    .fetch_optional(pool)
    .await?;
    if row.as_ref().is_some_and(|existing| {
        existing.principal_id != context.principal_id
            || existing.agent_uuid != agent.id
            || existing.instance_id != context.instance_id
    }) {
        anyhow::bail!("idempotency key belongs to a different authenticated identity");
    }
    Ok(row)
}

pub async fn fail_unfinished_idempotent_execution(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    req: &crate::types::ExecutionRequest,
    operation: &str,
    idempotency_key: &str,
    reason: &str,
) -> Result<()> {
    let row = match get_idempotent_execution_request(pool, context, req, operation, idempotency_key)
        .await
    {
        Ok(row) => row,
        Err(error) if is_idempotency_ownership_error(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let Some(row) = row else {
        return Ok(());
    };
    sqlx::query(
        r#"
        UPDATE execution_requests
        SET status = 'failed', error_message = $2, updated_at = now()
        WHERE id = $1 AND status IN ('pending', 'payment_verified')
        "#,
    )
    .bind(row.id)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(())
}

fn is_idempotency_ownership_error(error: &anyhow::Error) -> bool {
    let message = error.to_string();
    message == "idempotency key was already used for a different request"
        || message == "idempotency key belongs to a different authenticated identity"
}

pub fn validate_idempotency_key(value: &str) -> Result<()> {
    let valid = (8..=128).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte));
    if !valid {
        anyhow::bail!(
            "Idempotency-Key must be 8-128 printable ASCII characters without whitespace"
        );
    }
    Ok(())
}

pub async fn insert_registration_event(
    pool: &PgPool,
    organization_id: Option<Uuid>,
    principal_id: Option<Uuid>,
    client_fingerprint: &str,
    outcome: &str,
    details: serde_json::Value,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO registration_events (
            id, organization_id, principal_id, client_fingerprint, outcome, details
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(organization_id)
    .bind(principal_id)
    .bind(client_fingerprint)
    .bind(outcome)
    .bind(details)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_execution_request(pool: &PgPool, id: Uuid) -> Result<Option<ExecutionRequestRow>> {
    let row =
        sqlx::query_as::<_, ExecutionRequestRow>("SELECT * FROM execution_requests WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
    Ok(row)
}

pub async fn get_execution_request_for_organization(
    pool: &PgPool,
    id: Uuid,
    organization_id: Uuid,
) -> Result<Option<ExecutionRequestRow>> {
    Ok(sqlx::query_as::<_, ExecutionRequestRow>(
        "SELECT * FROM execution_requests WHERE id = $1 AND organization_id = $2",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn issue_execution_permit(
    pool: &PgPool,
    request_id: Uuid,
    execution_fee_raw: Option<&str>,
    ttl_seconds: i64,
) -> Result<models::ExecutionPermitRow> {
    if execution_fee_raw.is_some_and(|amount| amount.parse::<ethers::types::U256>().is_err()) {
        anyhow::bail!("execution permit fee must be an unsigned decimal integer");
    }
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds.clamp(30, 600));
    Ok(sqlx::query_as::<_, models::ExecutionPermitRow>(
        r#"
        INSERT INTO execution_permits (
            id, request_id, organization_id, principal_id, agent_id, instance_id,
            policy_id, policy_version, payload_hash, wallet_address, chain,
            execution_fee_raw, expires_at
        )
        SELECT $2, er.id, er.organization_id, er.principal_id, er.agent_uuid,
               er.instance_id, er.policy_id, er.policy_version, er.payload_hash,
               er.smart_wallet_address, er.chain, $3, $4
        FROM execution_requests er
        JOIN authorization_policies ap
          ON ap.id = er.policy_id AND ap.organization_id = er.organization_id
        JOIN agents a ON a.id = er.agent_uuid
        WHERE er.id = $1 AND er.status = 'payment_verified'
          AND er.smart_wallet_address IS NOT NULL
          AND ap.is_active = TRUE AND ap.version = er.policy_version
          AND a.status = 'active' AND a.policy_id = er.policy_id
        ON CONFLICT (request_id) DO UPDATE
        SET expires_at = EXCLUDED.expires_at
        WHERE execution_permits.consumed_at IS NULL
          AND execution_permits.payload_hash = EXCLUDED.payload_hash
          AND execution_permits.execution_fee_raw IS NOT DISTINCT FROM EXCLUDED.execution_fee_raw
        RETURNING execution_permits.*
        "#,
    )
    .bind(request_id)
    .bind(Uuid::new_v4())
    .bind(execution_fee_raw)
    .bind(expires_at)
    .fetch_one(pool)
    .await?)
}

pub async fn enforce_execution_fee_policy(
    pool: &PgPool,
    request_id: Uuid,
    execution_fee_usd: f64,
) -> Result<()> {
    if !execution_fee_usd.is_finite() || execution_fee_usd < 0.0 {
        anyhow::bail!("execution fee is invalid");
    }
    let maximum: Option<f64> = sqlx::query_scalar(
        r#"
        SELECT ap.max_execution_fee_usd
        FROM execution_requests er
        JOIN authorization_policies ap ON ap.id = er.policy_id
        WHERE er.id = $1 AND ap.is_active = TRUE AND ap.version = er.policy_version
        "#,
    )
    .bind(request_id)
    .fetch_one(pool)
    .await?;
    if maximum.is_some_and(|maximum| execution_fee_usd > maximum) {
        anyhow::bail!("execution fee exceeds authorization policy");
    }
    Ok(())
}

pub async fn claim_execution_permit(
    pool: &PgPool,
    permit_id: Uuid,
    request_id: Uuid,
) -> Result<models::ExecutionPermitRow> {
    let row = sqlx::query_as::<_, models::ExecutionPermitRow>(
        r#"
        UPDATE execution_permits ep
        SET claimed_at = COALESCE(ep.claimed_at, now())
        FROM execution_requests er, authorization_policies ap, agents a
        WHERE ep.id = $1 AND ep.request_id = $2
          AND er.id = ep.request_id
          AND ap.id = ep.policy_id AND ap.organization_id = ep.organization_id
          AND a.id = ep.agent_id
          AND (
            (ep.expires_at > now() AND ap.is_active = TRUE
             AND ap.version = ep.policy_version
             AND a.status = 'active' AND a.policy_id = ep.policy_id)
            OR (ep.consumed_at IS NOT NULL AND er.signed_user_operation IS NOT NULL)
          )
          AND ep.organization_id = er.organization_id
          AND ep.principal_id = er.principal_id
          AND ep.agent_id = er.agent_uuid
          AND ep.instance_id IS NOT DISTINCT FROM er.instance_id
          AND ep.policy_id = er.policy_id AND ep.policy_version = er.policy_version
          AND ep.payload_hash = er.payload_hash
          AND ep.wallet_address = er.smart_wallet_address
          AND ep.chain = er.chain
        RETURNING ep.*
        "#,
    )
    .bind(permit_id)
    .bind(request_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("execution permit is invalid, expired, or revoked"))?;
    Ok(row)
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RecentFeedRow {
    pub id: Uuid,
    pub chain: String,
    pub status: String,
    pub tx_hash: Option<String>,
    pub payment_amount_usd: Option<f64>,
    pub payment_token: Option<String>,
    pub payment_chain: Option<String>,
}

pub async fn get_recent_feed_rows(pool: &PgPool, limit: i64) -> Result<Vec<RecentFeedRow>> {
    let bounded = limit.clamp(1, 50);
    let rows = sqlx::query_as::<_, RecentFeedRow>(
        r#"
        SELECT
            er.id,
            er.chain,
            er.status,
            er.tx_hash,
            p.amount_usd AS payment_amount_usd,
            p.token AS payment_token,
            p.payment_chain
        FROM execution_requests er
        LEFT JOIN LATERAL (
            SELECT amount_usd, token, payment_chain
            FROM payments p
            WHERE p.request_id = er.id
            ORDER BY p.created_at DESC
            LIMIT 1
        ) p ON TRUE
        ORDER BY er.updated_at DESC
        LIMIT $1
        "#,
    )
    .bind(bounded)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Resolve a locked quote cost from a prior request, scoped to the same
/// organization and execution payload.
pub async fn get_locked_quote_cost(
    pool: &PgPool,
    organization_id: Uuid,
    quote_request_id: Uuid,
    req: &crate::types::ExecutionRequest,
    smart_wallet_address: &str,
) -> Result<Option<f64>> {
    let payload_hash = execution_payload_hash(req)?;
    let row: Option<(f64,)> = sqlx::query_as(
        r#"
        SELECT er.cost_usd
        FROM execution_requests er
        WHERE er.id = $1
          AND er.organization_id = $9
          AND er.smart_wallet_address = $2
          AND er.chain = $3
          AND er.target_contract = $4
          AND er.calldata = $5
          AND er.value = $6
          AND er.agent_id = $7
          AND er.payload_hash = $8
          AND er.cost_usd IS NOT NULL
          AND (
              er.created_at >= now() - interval '5 minutes'
              OR EXISTS (
                  SELECT 1 FROM payments p
                  WHERE p.request_id = er.id AND p.verified = TRUE
              )
          )
        LIMIT 1
        "#,
    )
    .bind(quote_request_id)
    .bind(smart_wallet_address)
    .bind(&req.chain)
    .bind(&req.target_contract)
    .bind(&req.calldata)
    .bind(&req.value)
    .bind(&req.agent_id)
    .bind(payload_hash)
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| r.0))
}

pub async fn update_execution_status(
    pool: &PgPool,
    id: Uuid,
    status: &ExecutionStatus,
    tx_hash: Option<&str>,
    error_message: Option<&str>,
    gas_estimate: Option<i64>,
    cost_usd: Option<f64>,
) -> Result<()> {
    if matches!(
        status,
        ExecutionStatus::Confirmed | ExecutionStatus::Reverted
    ) {
        anyhow::bail!("on-chain terminal results must use atomic Arc finalization");
    }
    sqlx::query(
        r#"
        UPDATE execution_requests
        SET status = $2,
            tx_hash = COALESCE($3, tx_hash),
            error_message = COALESCE($4, error_message),
            gas_estimate = COALESCE($5, gas_estimate),
            cost_usd = COALESCE($6, cost_usd),
            updated_at = $7
        WHERE id = $1 AND status NOT IN ('confirmed', 'reverted', 'failed')
        "#,
    )
    .bind(id)
    .bind(status.to_string())
    .bind(tx_hash)
    .bind(error_message)
    .bind(gas_estimate)
    .bind(cost_usd)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

pub struct ArcExecutionFinalization<'a> {
    pub request_id: Uuid,
    pub chain: &'a str,
    pub tx_hash: &'a str,
    pub from_address: &'a str,
    pub to_address: &'a str,
    pub status: &'a ExecutionStatus,
    pub error_message: Option<&'a str>,
    pub gas_used: Option<i64>,
    pub payment: Option<&'a crate::types::SettledExecutionPayment>,
}

/// Atomically persist the on-chain transaction, optional managed execution
/// fee, and terminal request state. Replays with the same result are no-ops;
/// conflicting transaction or payment attribution fails closed.
pub async fn finalize_arc_execution(
    pool: &PgPool,
    finalization: ArcExecutionFinalization<'_>,
) -> Result<bool> {
    if !matches!(
        finalization.status,
        ExecutionStatus::Confirmed | ExecutionStatus::Reverted
    ) {
        anyhow::bail!("Arc execution finalization requires a confirmed or reverted status");
    }
    if let Some(payment) = finalization.payment {
        if payment.quote_request_id != Some(finalization.request_id) {
            anyhow::bail!("execution fee is not attributed to this request");
        }
        if payment.chain != finalization.chain {
            anyhow::bail!("execution fee chain differs from the execution chain");
        }
        if !payment.tx_hash.eq_ignore_ascii_case(finalization.tx_hash) {
            anyhow::bail!("execution fee transaction differs from the execution receipt");
        }
        if !payment.amount_usd.is_finite() || payment.amount_usd < 0.0 {
            anyhow::bail!("execution fee amount_usd must be finite and non-negative");
        }
    }

    let mut transaction = pool.begin().await?;
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT status, tx_hash FROM execution_requests WHERE id = $1 FOR UPDATE")
            .bind(finalization.request_id)
            .fetch_optional(&mut *transaction)
            .await?;
    let Some((current_status, current_tx_hash)) = current else {
        anyhow::bail!("execution request disappeared during finalization");
    };
    if matches!(current_status.as_str(), "confirmed" | "reverted" | "failed") {
        if current_status != finalization.status.to_string()
            || !current_tx_hash
                .as_deref()
                .is_some_and(|hash| hash.eq_ignore_ascii_case(finalization.tx_hash))
        {
            anyhow::bail!("execution already has a conflicting terminal result");
        }
        transaction.rollback().await?;
        return Ok(false);
    }

    let inserted_transaction = sqlx::query_as::<_, TransactionRow>(
        r#"
        INSERT INTO transactions (
            id, request_id, chain, tx_hash, from_address, to_address, gas_used,
            status, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
        ON CONFLICT (request_id) DO NOTHING
        RETURNING *
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(finalization.request_id)
    .bind(finalization.chain)
    .bind(finalization.tx_hash)
    .bind(finalization.from_address)
    .bind(finalization.to_address)
    .bind(finalization.gas_used)
    .bind(finalization.status.to_string())
    .fetch_optional(&mut *transaction)
    .await?;
    if inserted_transaction.is_none() {
        let existing =
            sqlx::query_as::<_, TransactionRow>("SELECT * FROM transactions WHERE request_id = $1")
                .bind(finalization.request_id)
                .fetch_one(&mut *transaction)
                .await?;
        if !existing.tx_hash.eq_ignore_ascii_case(finalization.tx_hash)
            || existing.chain != finalization.chain
            || !existing
                .from_address
                .eq_ignore_ascii_case(finalization.from_address)
            || !existing
                .to_address
                .eq_ignore_ascii_case(finalization.to_address)
        {
            anyhow::bail!("execution transaction attribution conflicts with the receipt");
        }
        sqlx::query(
            "UPDATE transactions SET status = $2, gas_used = COALESCE($3, gas_used) WHERE request_id = $1",
        )
            .bind(finalization.request_id)
            .bind(finalization.status.to_string())
            .bind(finalization.gas_used)
            .execute(&mut *transaction)
            .await?;
    }

    if let Some(payment) = finalization.payment {
        let amount_raw = payment
            .confirmed_amount_raw
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("verified payment is missing amount_raw"))?;
        let token_contract = payment
            .token_contract
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("verified payment is missing token_contract"))?;
        let inserted_payment = sqlx::query_as::<_, PaymentRow>(
            r#"
            INSERT INTO payments (
                id, request_id, payer, amount_usd, amount_raw, token, token_contract,
                payment_chain, payment_tx_hash, verified, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, now())
            ON CONFLICT DO NOTHING
            RETURNING *
            "#,
        )
        .bind(payment.payment_id)
        .bind(finalization.request_id)
        .bind(&payment.payer)
        .bind(payment.amount_usd)
        .bind(amount_raw)
        .bind(&payment.token)
        .bind(token_contract)
        .bind(&payment.chain)
        .bind(&payment.tx_hash)
        .fetch_optional(&mut *transaction)
        .await?;
        if inserted_payment.is_none() {
            let existing = sqlx::query_as::<_, PaymentRow>(
                "SELECT * FROM payments WHERE request_id = $1 OR payment_tx_hash = $2 LIMIT 1",
            )
            .bind(finalization.request_id)
            .bind(&payment.tx_hash)
            .fetch_one(&mut *transaction)
            .await?;
            if existing.request_id != finalization.request_id
                || !existing
                    .payment_tx_hash
                    .eq_ignore_ascii_case(&payment.tx_hash)
                || existing.amount_raw != amount_raw
                || !existing.payer.eq_ignore_ascii_case(&payment.payer)
                || existing.token != payment.token
                || !existing.token_contract.eq_ignore_ascii_case(token_contract)
                || existing.payment_chain != payment.chain
                || !existing.verified
            {
                anyhow::bail!("execution fee attribution conflicts with the receipt");
            }
        }
    }

    let updated = sqlx::query(
        r#"
        UPDATE execution_requests
        SET status = $2, tx_hash = $3, error_message = $4,
            gas_estimate = COALESCE($5, gas_estimate), updated_at = now()
        WHERE id = $1 AND status NOT IN ('confirmed', 'reverted', 'failed')
        "#,
    )
    .bind(finalization.request_id)
    .bind(finalization.status.to_string())
    .bind(finalization.tx_hash)
    .bind(finalization.error_message)
    .bind(finalization.gas_used)
    .execute(&mut *transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!("execution became terminal during finalization");
    }
    transaction.commit().await?;
    Ok(true)
}

pub async fn fail_arc_execution_status(pool: &PgPool, id: Uuid, reason: &str) -> Result<bool> {
    let updated = sqlx::query(
        r#"
        UPDATE execution_requests
        SET status = 'failed', error_message = $2, updated_at = now()
        WHERE id = $1 AND status NOT IN ('confirmed', 'reverted', 'failed')
        "#,
    )
    .bind(id)
    .bind(reason)
    .execute(pool)
    .await?;
    Ok(updated.rows_affected() == 1)
}

// ──────────────────────── Payments ───────────────────────────────────

/// Atomically insert a payment record.
///
/// Uses `ON CONFLICT (payment_tx_hash) DO NOTHING` so that if two concurrent
/// requests race with the same tx_hash, exactly one succeeds and the other
/// gets `None` back — eliminating the TOCTOU window.
pub async fn insert_payment(
    pool: &PgPool,
    request_id: Uuid,
    payment: &crate::types::SettledExecutionPayment,
) -> Result<Option<PaymentRow>> {
    let row = sqlx::query_as::<_, PaymentRow>(
        r#"
        INSERT INTO payments
            (id, request_id, payer, amount_usd, amount_raw, token, token_contract,
             payment_chain, payment_tx_hash, verified, created_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        ON CONFLICT (payment_tx_hash) DO NOTHING
        RETURNING *
        "#,
    )
    .bind(payment.payment_id)
    .bind(request_id)
    .bind(&payment.payer)
    .bind(payment.amount_usd)
    .bind(
        payment
            .confirmed_amount_raw
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("verified payment is missing amount_raw"))?,
    )
    .bind(&payment.token)
    .bind(
        payment
            .token_contract
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("verified payment is missing token_contract"))?,
    )
    .bind(&payment.chain)
    .bind(&payment.tx_hash)
    .bind(true)
    .bind(Utc::now())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn has_verified_payment(pool: &PgPool, request_id: Uuid) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM payments WHERE request_id = $1 AND verified = TRUE)",
    )
    .bind(request_id)
    .fetch_one(pool)
    .await?)
}

pub async fn get_verified_payment_for_request(
    pool: &PgPool,
    request_id: Uuid,
) -> Result<Option<PaymentRow>> {
    Ok(sqlx::query_as::<_, PaymentRow>(
        r#"
        SELECT * FROM payments
        WHERE request_id = $1 AND verified = TRUE
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(request_id)
    .fetch_optional(pool)
    .await?)
}

/// Resolve the organization-owned webhook signing secret.
pub async fn get_webhook_secret_by_organization(
    pool: &PgPool,
    organization_id: Uuid,
    encryption_key_hex: &str,
) -> Result<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        SELECT webhook_secret_encrypted
        FROM organizations
        WHERE id = $1
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(pool)
    .await?;
    row.map(|(encrypted,)| decrypt_secret(encryption_key_hex, &encrypted))
        .transpose()
}

pub async fn rotate_webhook_secret(
    pool: &PgPool,
    organization_id: Uuid,
    encryption_key_hex: &str,
) -> Result<Option<String>> {
    let secret = random_secret();
    let encrypted = encrypt_secret(encryption_key_hex, &secret)?;
    let result = sqlx::query(
        "UPDATE organizations SET webhook_secret_encrypted = $2, updated_at = now() WHERE id = $1",
    )
    .bind(organization_id)
    .bind(encrypted)
    .execute(pool)
    .await?;
    Ok((result.rows_affected() == 1).then_some(secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExecutionRequest, SettledExecutionPayment};

    async fn setup_pool() -> PgPool {
        dotenvy::dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL env var");
        let pool = create_pool(&database_url).await.expect("create pool");
        run_migrations(&pool).await.expect("run migrations");
        pool
    }

    fn sample_request(agent_id: &str) -> ExecutionRequest {
        ExecutionRequest {
            agent_id: agent_id.into(),
            chain: "arc-testnet".into(),
            target_contract: "0x1234567890abcdef1234567890abcdef12345678".into(),
            calldata: "0xdeadbeef".into(),
            value: "0".into(),
            strategy_id: None,
            batch_calls: None,
            callback_url: None,
        }
    }

    fn test_public_jwk() -> (serde_json::Value, String) {
        let seed = Uuid::new_v4().to_string();
        let thumbprint = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(seed.as_bytes()));
        (
            serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "x": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 32]),
                "y": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
                "alg": "ES256"
            }),
            thumbprint,
        )
    }

    async fn create_test_auth_context(
        pool: &PgPool,
        external_id: &str,
    ) -> crate::types::AuthContext {
        let (public_jwk, thumbprint) = test_public_jwk();
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
        let organization_name = format!("Test organization {}", Uuid::new_v4().simple());
        let registration = create_self_service_registration(
            pool,
            "1111111111111111111111111111111111111111111111111111111111111111",
            SelfServiceRegistrationOptions {
                chain: "arc-testnet",
                organization_name: &organization_name,
                display_name: "Test owner",
                agent_external_id: external_id,
                public_jwk: &public_jwk,
                public_jwk_thumbprint: &thumbprint,
                credential_scopes: &credential_scopes,
                policy_actions: &policy_actions,
                policy_protocols: &policy_protocols,
                max_execution_fee_usd: crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD,
            },
        )
        .await
        .expect("create test OAuth identity");
        crate::types::AuthContext {
            organization_id: registration.credential.organization_id,
            principal_id: registration.credential.principal_id,
            credential_id: registration.credential.id,
            credential_kind: crate::types::CredentialKind::LocalJwk,
            scopes: registration.credential.scopes.into_iter().collect(),
            agent_id: None,
            agent_external_id: None,
            instance_id: None,
            dpop_jkt: Some(thumbprint),
        }
    }

    #[test]
    fn test_execution_payload_hash_includes_batch_calls() {
        let mut first = sample_request("payload-hash");
        first.target_contract = String::new();
        first.calldata = String::new();
        first.batch_calls = Some(vec![crate::types::BatchCall {
            target_contract: "0x1111111111111111111111111111111111111111".into(),
            calldata: "0x095ea7b3".into(),
            value: "0".into(),
        }]);

        let mut second = first.clone();
        second.batch_calls = Some(vec![crate::types::BatchCall {
            target_contract: "0x2222222222222222222222222222222222222222".into(),
            calldata: "0x617ba037".into(),
            value: "0".into(),
        }]);

        assert_ne!(
            execution_payload_hash(&first).expect("first hash"),
            execution_payload_hash(&second).expect("second hash")
        );
    }

    #[test]
    fn test_execution_payload_hash_canonicalizes_chain_and_rejects_tampering() {
        let canonical = sample_request("payload-hash");
        let mut chain_alias = canonical.clone();
        chain_alias.chain = "ARC-TESTNET".into();
        assert_eq!(
            execution_payload_hash(&canonical).expect("canonical hash"),
            execution_payload_hash(&chain_alias).expect("alias hash")
        );

        let mut tampered = canonical.clone();
        tampered.calldata = "0xcafebabe".into();
        assert_ne!(
            execution_payload_hash(&canonical).expect("canonical hash"),
            execution_payload_hash(&tampered).expect("tampered hash")
        );
    }

    #[test]
    fn idempotency_keys_and_fingerprints_are_strict() {
        assert!(validate_idempotency_key("request-12345678").is_ok());
        assert!(validate_idempotency_key("short").is_err());
        assert!(validate_idempotency_key("contains whitespace").is_err());

        let request = sample_request("idempotent");
        let atomic = idempotency_fingerprint(&request, "execute:atomic-token").unwrap();
        let x402 = idempotency_fingerprint(&request, "execute:x402").unwrap();
        assert_ne!(atomic, x402);

        let mut callback_changed = request;
        callback_changed.callback_url = Some("https://example.com/callback".into());
        assert_ne!(
            atomic,
            idempotency_fingerprint(&callback_changed, "execute:atomic-token").unwrap()
        );

        assert!(is_idempotency_ownership_error(&anyhow::anyhow!(
            "idempotency key was already used for a different request"
        )));
        assert!(is_idempotency_ownership_error(&anyhow::anyhow!(
            "idempotency key belongs to a different authenticated identity"
        )));
        assert!(!is_idempotency_ownership_error(&anyhow::anyhow!(
            "database unavailable"
        )));
    }

    #[tokio::test]
    async fn test_db_execution_request_lifecycle() {
        let pool = setup_pool().await;
        let req = sample_request(&format!("lifecycle-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;

        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::Pending,
            Some("0xaaaa"),
            None,
        )
        .await
        .expect("insert request");
        assert_eq!(row.status, "pending");

        let fetched = get_execution_request(&pool, row.id)
            .await
            .expect("fetch request")
            .expect("request exists");
        assert_eq!(fetched.id, row.id);

        update_execution_status(
            &pool,
            row.id,
            &ExecutionStatus::Queued,
            None,
            None,
            Some(100_000),
            Some(0.05),
        )
        .await
        .expect("update request status");

        let updated = get_execution_request(&pool, row.id)
            .await
            .expect("fetch updated request")
            .expect("request exists");
        assert_eq!(updated.status, "queued");
        assert_eq!(updated.gas_estimate, Some(100_000));
    }

    #[tokio::test]
    async fn test_db_payment_replay_protection() {
        let pool = setup_pool().await;
        let req = sample_request(&format!("replay-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;
        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::PaymentRequired,
            None,
            None,
        )
        .await
        .expect("insert request");

        let tx_hash = format!(
            "0x{}",
            hex::encode(uuid::Uuid::new_v4().as_bytes().repeat(2))
        );
        let payment = SettledExecutionPayment {
            payment_id: uuid::Uuid::new_v4(),
            quote_request_id: None,
            payer: "0x0000000000000000000000000000000000000001".into(),
            amount_usd: 0.05,
            token: "USDC".into(),
            chain: "ethereum".into(),
            tx_hash: tx_hash.clone(),
            confirmed_amount_raw: Some("50000".into()),
            token_contract: Some("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238".into()),
        };

        assert!(insert_payment(&pool, row.id, &payment)
            .await
            .expect("insert payment")
            .is_some());
        assert!(insert_payment(&pool, row.id, &payment)
            .await
            .expect("insert replay")
            .is_none());
    }

    #[tokio::test]
    async fn self_service_registration_and_child_enrollment_are_relational_and_one_time() {
        let pool = setup_pool().await;
        let external_id = format!("owner-agent-{}", Uuid::new_v4().simple());
        let (owner_jwk, owner_thumbprint) = test_public_jwk();
        let owner_scopes = crate::auth::DEFAULT_SCOPES
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
        let registration = create_self_service_registration(
            &pool,
            "1111111111111111111111111111111111111111111111111111111111111111",
            SelfServiceRegistrationOptions {
                chain: "arc-testnet",
                organization_name: "Jusso test organization",
                display_name: "Test owner",
                agent_external_id: &external_id,
                public_jwk: &owner_jwk,
                public_jwk_thumbprint: &owner_thumbprint,
                credential_scopes: &owner_scopes,
                policy_actions: &policy_actions,
                policy_protocols: &policy_protocols,
                max_execution_fee_usd: crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD,
            },
        )
        .await
        .expect("register organization");
        assert_eq!(registration.credential.agent_id, None);
        assert_eq!(
            registration.policy.allowed_chains.as_deref(),
            Some(["arc-testnet".to_string()].as_slice())
        );
        assert_eq!(
            registration.policy.allowed_protocols,
            Some(policy_protocols)
        );
        assert!(!registration.policy.allow_raw_execution);
        assert_eq!(registration.policy.max_value_wei.as_deref(), Some("0"));
        assert_eq!(
            registration.policy.max_execution_fee_usd,
            Some(crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD)
        );
        assert!(principal_can_access_agent(
            &pool,
            registration.credential.principal_id,
            registration.agent.id
        )
        .await
        .unwrap());

        let child_external_id = format!("child-agent-{}", Uuid::new_v4().simple());
        let child_scopes = vec![
            "wallet:read".to_string(),
            "transaction:simulate".to_string(),
        ];
        let (child, enrollment_token, _) = create_agent_with_enrollment(
            &pool,
            CreateAgentOptions {
                organization_id: registration.credential.organization_id,
                created_by_principal_id: registration.credential.principal_id,
                external_id: &child_external_id,
                display_name: "Child agent",
                parent_agent_id: Some(registration.agent.id),
                policy_id: registration.policy.id,
                runtime_scopes: &child_scopes,
                enrollment_ttl_seconds: 900,
            },
        )
        .await
        .expect("create child agent");
        let (child_jwk, child_thumbprint) = test_public_jwk();
        let (credential, enrolled_agent) = enroll_agent(
            &pool,
            EnrollAgentOptions {
                enrollment_token: &enrollment_token,
                display_name: "Child runtime",
                public_jwk: &child_jwk,
                public_jwk_thumbprint: &child_thumbprint,
            },
        )
        .await
        .expect("enroll child agent");
        assert_eq!(enrolled_agent.id, child.id);
        assert_eq!(credential.agent_id, Some(child.id));
        assert_eq!(credential.scopes, child_scopes);
        assert!(enroll_agent(
            &pool,
            EnrollAgentOptions {
                enrollment_token: &enrollment_token,
                display_name: "Replay",
                public_jwk: &child_jwk,
                public_jwk_thumbprint: &child_thumbprint,
            },
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn signing_persistence_fails_atomically_when_policy_is_revoked() {
        let pool = setup_pool().await;
        let req = sample_request(&format!("permit-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;
        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::PaymentVerified,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .expect("insert payment-verified request");
        let permit = issue_execution_permit(&pool, row.id, Some("1000"), 300)
            .await
            .expect("issue permit");
        claim_execution_permit(&pool, permit.id, row.id)
            .await
            .expect("claim permit");
        sqlx::query("UPDATE authorization_policies SET is_active = FALSE WHERE id = $1")
            .bind(row.policy_id)
            .execute(&pool)
            .await
            .expect("revoke policy during signing");

        assert!(store_signed_user_operation_and_consume_permit(
            &pool,
            row.id,
            permit.id,
            &serde_json::json!({"type": "user-operation-v070"}),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .is_err());
        assert!(get_signed_user_operation(&pool, row.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn signed_arc_operation_remains_recoverable_after_policy_revocation() {
        let pool = setup_pool().await;
        let req = sample_request(&format!("recovery-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;
        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::PaymentVerified,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();
        let permit = issue_execution_permit(&pool, row.id, Some("1000"), 300)
            .await
            .unwrap();
        claim_execution_permit(&pool, permit.id, row.id)
            .await
            .unwrap();
        store_signed_user_operation_and_consume_permit(
            &pool,
            row.id,
            permit.id,
            &serde_json::json!({"type": "user-operation-v070"}),
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .await
        .unwrap();
        sqlx::query("UPDATE authorization_policies SET is_active = FALSE WHERE id = $1")
            .bind(row.policy_id)
            .execute(&pool)
            .await
            .unwrap();
        assert!(claim_execution_permit(&pool, permit.id, row.id)
            .await
            .unwrap()
            .consumed_at
            .is_some());
    }

    #[tokio::test]
    async fn arc_finalization_is_atomic_and_exactly_once() {
        let pool = setup_pool().await;
        let req = sample_request(&format!("finalize-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;
        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::Queued,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();
        let hash = format!("0x{}", hex::encode(Uuid::new_v4().as_bytes().repeat(2)));
        let payment = SettledExecutionPayment {
            payment_id: Uuid::new_v4(),
            quote_request_id: Some(row.id),
            payer: "0x1234567890abcdef1234567890abcdef12345678".into(),
            amount_usd: 0.01,
            token: "USDC".into(),
            chain: "arc-testnet".into(),
            tx_hash: hash.clone(),
            confirmed_amount_raw: Some("10000".into()),
            token_contract: Some("0x3600000000000000000000000000000000000000".into()),
        };

        assert!(update_execution_status(
            &pool,
            row.id,
            &ExecutionStatus::Confirmed,
            Some(&hash),
            None,
            Some(125_000),
            None,
        )
        .await
        .is_err());

        let finalization = || ArcExecutionFinalization {
            request_id: row.id,
            chain: "arc-testnet",
            tx_hash: &hash,
            from_address: "0x1234567890abcdef1234567890abcdef12345678",
            to_address: &req.target_contract,
            status: &ExecutionStatus::Confirmed,
            error_message: None,
            gas_used: Some(125_000),
            payment: Some(&payment),
        };
        assert!(finalize_arc_execution(&pool, finalization()).await.unwrap());
        assert!(!finalize_arc_execution(&pool, finalization()).await.unwrap());

        let transaction: TransactionRow =
            sqlx::query_as("SELECT * FROM transactions WHERE request_id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(transaction.tx_hash, hash);
        assert_eq!(transaction.gas_used, Some(125_000));
        let payment_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM payments WHERE request_id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(payment_count, 1);
        let stored = get_execution_request(&pool, row.id).await.unwrap().unwrap();
        assert_eq!(stored.status, "confirmed");
        assert_eq!(stored.tx_hash.as_deref(), Some(hash.as_str()));

        let conflicting_hash = format!("0x{}", hex::encode(Uuid::new_v4().as_bytes().repeat(2)));
        let conflicting = ArcExecutionFinalization {
            tx_hash: &conflicting_hash,
            ..finalization()
        };
        assert!(finalize_arc_execution(&pool, conflicting).await.is_err());
    }

    #[tokio::test]
    async fn arc_finalization_rolls_back_on_conflicting_payment() {
        let pool = setup_pool().await;
        let first_req = sample_request(&format!("paid-{}", Uuid::new_v4().simple()));
        let first_context = create_test_auth_context(&pool, &first_req.agent_id).await;
        let first_row = insert_execution_request(
            &pool,
            &first_context,
            &first_req,
            &ExecutionStatus::PaymentRequired,
            None,
            None,
        )
        .await
        .unwrap();
        let hash = format!("0x{}", hex::encode(Uuid::new_v4().as_bytes().repeat(2)));
        let existing_payment = SettledExecutionPayment {
            payment_id: Uuid::new_v4(),
            quote_request_id: Some(first_row.id),
            payer: "0x0000000000000000000000000000000000000001".into(),
            amount_usd: 0.01,
            token: "USDC".into(),
            chain: "arc-testnet".into(),
            tx_hash: hash.clone(),
            confirmed_amount_raw: Some("10000".into()),
            token_contract: Some("0x3600000000000000000000000000000000000000".into()),
        };
        insert_payment(&pool, first_row.id, &existing_payment)
            .await
            .unwrap()
            .expect("seed conflicting payment");

        let req = sample_request(&format!("rollback-{}", Uuid::new_v4().simple()));
        let context = create_test_auth_context(&pool, &req.agent_id).await;
        let row = insert_execution_request(
            &pool,
            &context,
            &req,
            &ExecutionStatus::Queued,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();
        let conflicting_payment = SettledExecutionPayment {
            payment_id: Uuid::new_v4(),
            quote_request_id: Some(row.id),
            ..existing_payment
        };
        let result = finalize_arc_execution(
            &pool,
            ArcExecutionFinalization {
                request_id: row.id,
                chain: "arc-testnet",
                tx_hash: &hash,
                from_address: "0x1234567890abcdef1234567890abcdef12345678",
                to_address: &req.target_contract,
                status: &ExecutionStatus::Confirmed,
                error_message: None,
                gas_used: Some(125_000),
                payment: Some(&conflicting_payment),
            },
        )
        .await;
        assert!(result.is_err());

        let transaction_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM transactions WHERE request_id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(transaction_count, 0);
        let stored = get_execution_request(&pool, row.id).await.unwrap().unwrap();
        assert_eq!(stored.status, "queued");
        assert!(stored.tx_hash.is_none());
    }
}
