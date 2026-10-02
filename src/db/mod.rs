//! Database access layer — connection pool + repository functions.

pub mod models;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::types::{AuthContext, CredentialKind, ExecutionStatus};
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

pub(crate) fn random_secret() -> String {
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

pub struct PasskeyOwnerRegistrationOptions<'a> {
    pub chain: &'a str,
    pub organization_name: &'a str,
    pub display_name: &'a str,
    pub owner_handle: &'a str,
    pub agent_external_id: &'a str,
    pub passkey_id: Uuid,
    pub credential_id: &'a str,
    pub passkey: &'a serde_json::Value,
    pub policy_actions: &'a [String],
    pub policy_protocols: &'a [String],
    pub max_execution_fee_usd: f64,
    pub connect_session_id: Uuid,
    pub authorization_code_hash: &'a str,
    pub oauth_client_id: &'a str,
    pub redirect_uri: &'a str,
    pub code_challenge: &'a str,
    pub resource: &'a str,
    pub oauth_scopes: &'a [String],
    pub authorization_code_expires_at: chrono::DateTime<Utc>,
    pub bind_agent_to_token: bool,
}

pub struct PasskeyOwnerRegistrationResult {
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub passkey_id: Uuid,
    pub agent: AgentRow,
    pub policy: AuthorizationPolicyRow,
    pub webhook_secret: String,
}

pub async fn create_passkey_owner_registration(
    pool: &PgPool,
    encryption_key_hex: &str,
    options: PasskeyOwnerRegistrationOptions<'_>,
) -> Result<PasskeyOwnerRegistrationResult> {
    if !matches!(options.chain, "arc" | "arc-testnet") {
        anyhow::bail!("passkey registration requires an Arc network");
    }
    let mut transaction = pool.begin().await?;
    let organization_id = Uuid::new_v4();
    let principal_id = Uuid::new_v4();
    let policy_id = Uuid::new_v4();
    let agent_id = Uuid::new_v4();
    let webhook_secret = random_secret();
    let encrypted_webhook_secret = encrypt_secret(encryption_key_hex, &webhook_secret)?;
    let normalized_handle = options.owner_handle.trim().to_ascii_lowercase();

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
    sqlx::query(
        r#"INSERT INTO owner_accounts (
            principal_id, organization_id, owner_handle, owner_handle_normalized, display_name
        ) VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .bind(options.owner_handle)
    .bind(normalized_handle)
    .bind(options.display_name)
    .execute(&mut *transaction)
    .await?;

    let allowed_chains = vec![options.chain.to_string()];
    let policy = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"
        INSERT INTO authorization_policies (
            id, organization_id, name, allowed_chains, allowed_protocols,
            allowed_actions, max_value_wei, max_execution_fee_usd
        ) VALUES ($1, $2, 'default-autonomous', $3, $4, $5, '0', $6)
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
        r#"INSERT INTO agents (id, organization_id, external_id, display_name, policy_id)
           VALUES ($1, $2, $3, $4, $5) RETURNING *"#,
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
    sqlx::query(
        r#"INSERT INTO owner_passkeys (
            id, organization_id, principal_id, credential_id, passkey
        ) VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(options.passkey_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(options.credential_id)
    .bind(options.passkey)
    .execute(&mut *transaction)
    .await?;

    let completed = sqlx::query(
        r#"UPDATE connect_sessions
           SET status = 'completed', organization_id = $2, principal_id = $3,
               passkey_id = $4, selected_agent_id = $5,
               selected_agent_external_id = $6, completed_at = now()
           WHERE id = $1 AND status = 'pending' AND expires_at > now()"#,
    )
    .bind(options.connect_session_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(options.passkey_id)
    .bind(options.bind_agent_to_token.then_some(agent_id))
    .bind(
        options
            .bind_agent_to_token
            .then_some(options.agent_external_id),
    )
    .execute(&mut *transaction)
    .await?;
    if completed.rows_affected() != 1 {
        anyhow::bail!("Connect session was already completed or expired");
    }
    sqlx::query(
        r#"INSERT INTO oauth_authorization_codes (
            code_hash, connect_session_id, organization_id, principal_id, passkey_id,
            agent_id, agent_external_id, client_id, redirect_uri, code_challenge,
            resource, scopes, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
    )
    .bind(options.authorization_code_hash)
    .bind(options.connect_session_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(options.passkey_id)
    .bind(options.bind_agent_to_token.then_some(agent_id))
    .bind(
        options
            .bind_agent_to_token
            .then_some(options.agent_external_id),
    )
    .bind(options.oauth_client_id)
    .bind(options.redirect_uri)
    .bind(options.code_challenge)
    .bind(options.resource)
    .bind(options.oauth_scopes)
    .bind(options.authorization_code_expires_at)
    .execute(&mut *transaction)
    .await?;

    transaction.commit().await?;
    Ok(PasskeyOwnerRegistrationResult {
        organization_id,
        principal_id,
        passkey_id: options.passkey_id,
        agent,
        policy,
        webhook_secret,
    })
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
        WITH RECURSIVE lineage AS (
            SELECT id, parent_agent_id, status
            FROM agents
            WHERE organization_id = $1 AND external_id = $2
            UNION
            SELECT parent.id, parent.parent_agent_id, parent.status
            FROM agents parent
            JOIN lineage child ON child.parent_agent_id = parent.id
            WHERE parent.organization_id = $1
        )
        SELECT agent.*
        FROM agents agent
        WHERE agent.organization_id = $1 AND agent.external_id = $2
          AND NOT EXISTS (SELECT 1 FROM lineage WHERE status <> 'active')
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
        WITH RECURSIVE lineage AS (
            SELECT id, parent_agent_id, status
            FROM agents
            WHERE id = $2
            UNION
            SELECT parent.id, parent.parent_agent_id, parent.status
            FROM agents parent
            JOIN lineage child ON child.parent_agent_id = parent.id
            WHERE parent.organization_id = (
                SELECT organization_id FROM agents WHERE id = $2
            )
        )
        SELECT EXISTS(
            SELECT 1
            FROM principal_agent_grants pag
            JOIN principals p ON p.id = pag.principal_id
            JOIN agents a ON a.id = pag.agent_id
            JOIN organizations o ON o.id = a.organization_id
            WHERE pag.principal_id = $1 AND pag.agent_id = $2
              AND p.organization_id = a.organization_id
              AND p.status = 'active' AND a.status = 'active' AND o.status = 'active'
              AND NOT EXISTS (SELECT 1 FROM lineage WHERE status <> 'active')
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

pub async fn get_agent_for_owner_by_external_id(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    external_id: &str,
) -> Result<Option<AgentRow>> {
    Ok(sqlx::query_as::<_, AgentRow>(
        r#"SELECT a.* FROM agents a
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE a.organization_id = $1 AND pag.principal_id = $2
             AND a.external_id = $3"#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(external_id)
    .fetch_optional(pool)
    .await?)
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AgentSignerBinding {
    pub agent_id: Uuid,
    pub agent_wallet_id: Uuid,
    pub managed_wallet_id: Uuid,
    pub signer_address: String,
    pub smart_account_address: String,
    pub initial_signer_address: String,
    pub chain_id: i64,
}

pub async fn get_agent_signer_binding_for_owner(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    chain_id: i64,
) -> Result<Option<AgentSignerBinding>> {
    Ok(sqlx::query_as::<_, AgentSignerBinding>(
        r#"
        SELECT a.id AS agent_id, aw.id AS agent_wallet_id,
               aw.managed_wallet_id, mw.address AS signer_address,
               asa.account_address AS smart_account_address,
               asa.initial_signer_address, asa.chain_id
        FROM agents a
        JOIN principal_agent_grants pag ON pag.agent_id = a.id
        JOIN agent_wallets aw ON aw.agent_uuid = a.id
        JOIN managed_wallets mw ON mw.id = aw.managed_wallet_id
        JOIN agent_smart_accounts asa ON asa.agent_wallet_id = aw.id
        WHERE a.id = $1 AND a.organization_id = $2 AND pag.principal_id = $3
          AND a.status = 'active' AND asa.chain_id = $4
        "#,
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(chain_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn get_agent_signer_rotation_for_owner(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    rotation_id: Uuid,
) -> Result<Option<AgentSignerRotationRow>> {
    Ok(sqlx::query_as::<_, AgentSignerRotationRow>(
        r#"SELECT r.*
           FROM agent_signer_rotations r
           JOIN principal_agent_grants pag ON pag.agent_id = r.agent_id
           WHERE r.id = $1 AND r.organization_id = $2 AND pag.principal_id = $3"#,
    )
    .bind(rotation_id)
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn agent_has_unresolved_signer_rotation(
    pool: &PgPool,
    organization_id: Uuid,
    agent_external_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1
               FROM agent_signer_rotations r
               JOIN agents a ON a.id = r.agent_id
               WHERE a.organization_id = $1 AND a.external_id = $2
                 AND r.status NOT IN ('reconciled', 'failed')
           )"#,
    )
    .bind(organization_id)
    .bind(agent_external_id)
    .fetch_one(pool)
    .await?)
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
        r#"
        WITH RECURSIVE lineage AS (
            SELECT id, parent_agent_id, status
            FROM agents
            WHERE id = $1 AND organization_id = $2
            UNION
            SELECT parent.id, parent.parent_agent_id, parent.status
            FROM agents parent
            JOIN lineage child ON child.parent_agent_id = parent.id
            WHERE parent.organization_id = $2
        )
        SELECT agent.*
        FROM agents agent
        WHERE agent.id = $1 AND agent.organization_id = $2
          AND NOT EXISTS (SELECT 1 FROM lineage WHERE status <> 'active')
        "#,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OwnerApprovalAction {
    CreatePolicy {
        name: String,
        allowed_chains: Option<Vec<String>>,
        allowed_protocols: Option<Vec<String>>,
        allowed_actions: Option<Vec<String>>,
        allowed_targets: Option<Vec<String>>,
        allow_raw_execution: bool,
        max_value_wei: Option<String>,
        max_execution_fee_usd: Option<f64>,
    },
    AssignPolicy {
        agent_id: Uuid,
        expected_current_policy_id: Uuid,
        policy_id: Uuid,
    },
    RevokePolicy {
        policy_id: Uuid,
    },
    CreateAgent {
        external_id: String,
        display_name: String,
        parent_agent_id: Option<Uuid>,
        policy_id: Uuid,
        runtime_scopes: Vec<String>,
        enrollment_token_hash: String,
        enrollment_ttl_seconds: i64,
    },
    SuspendAgent {
        agent_id: Uuid,
    },
    ReactivateAgent {
        agent_id: Uuid,
    },
    RotateAgentCredential {
        agent_id: Uuid,
        runtime_scopes: Vec<String>,
        enrollment_token_hash: String,
        enrollment_ttl_seconds: i64,
    },
    RotateAgentOnchainSigner {
        agent_id: Uuid,
        expected_agent_wallet_id: Uuid,
        expected_managed_wallet_id: Uuid,
        expected_smart_account_address: String,
        chain_id: i64,
    },
}

impl OwnerApprovalAction {
    fn kind(&self) -> &'static str {
        match self {
            Self::CreatePolicy { .. } => "create_policy",
            Self::AssignPolicy { .. } => "assign_policy",
            Self::RevokePolicy { .. } => "revoke_policy",
            Self::CreateAgent { .. } => "create_agent",
            Self::SuspendAgent { .. } => "suspend_agent",
            Self::ReactivateAgent { .. } => "reactivate_agent",
            Self::RotateAgentCredential { .. } => "rotate_agent_credential",
            Self::RotateAgentOnchainSigner { .. } => "rotate_agent_onchain_signer",
        }
    }

    pub fn validate(&self, expected_chain: &str) -> Result<()> {
        match self {
            Self::CreatePolicy {
                name,
                allowed_chains,
                allowed_protocols,
                allowed_actions,
                allowed_targets,
                max_value_wei,
                max_execution_fee_usd,
                ..
            } => {
                if name.trim().is_empty() || name.len() > 100 {
                    anyhow::bail!("policy name must contain 1-100 characters");
                }
                if allowed_chains.is_none()
                    && allowed_protocols.is_none()
                    && allowed_actions.is_none()
                    && allowed_targets.is_none()
                    && max_value_wei.is_none()
                    && max_execution_fee_usd.is_none()
                {
                    anyhow::bail!("policy must contain at least one explicit restriction");
                }
                validate_bounded_policy_values("allowed_chains", allowed_chains.as_deref())?;
                validate_bounded_policy_values("allowed_protocols", allowed_protocols.as_deref())?;
                validate_bounded_policy_values("allowed_actions", allowed_actions.as_deref())?;
                validate_bounded_policy_values("allowed_targets", allowed_targets.as_deref())?;
                if allowed_chains.as_ref().is_some_and(|values| {
                    values.is_empty() || values.iter().any(|value| value != expected_chain)
                }) {
                    anyhow::bail!("allowed_chains contains an unsupported chain");
                }
                if allowed_protocols.as_ref().is_some_and(|values| {
                    values
                        .iter()
                        .any(|value| !crate::auth::SUPPORTED_PROTOCOLS.contains(&value.as_str()))
                }) {
                    anyhow::bail!("allowed_protocols contains an unsupported protocol");
                }
                if let Some(actions) = allowed_actions {
                    crate::auth::validate_policy_actions(actions)?;
                }
                if allowed_targets.as_ref().is_some_and(|targets| {
                    targets.iter().any(|target| {
                        target != "*" && target.parse::<ethers::types::Address>().is_err()
                    })
                }) {
                    anyhow::bail!("allowed_targets must contain EVM addresses or *");
                }
                if max_value_wei
                    .as_deref()
                    .is_some_and(|value| value.parse::<ethers::types::U256>().is_err())
                {
                    anyhow::bail!("max_value_wei must be an unsigned decimal integer");
                }
                if max_execution_fee_usd.is_some_and(|value| !value.is_finite() || value < 0.0) {
                    anyhow::bail!("max_execution_fee_usd must be a non-negative finite number");
                }
            }
            Self::CreateAgent {
                external_id,
                display_name,
                runtime_scopes,
                enrollment_token_hash,
                enrollment_ttl_seconds,
                ..
            } => {
                validate_agent_identity(external_id, display_name)?;
                validate_enrollment_request(
                    runtime_scopes,
                    enrollment_token_hash,
                    *enrollment_ttl_seconds,
                )?;
            }
            Self::RotateAgentCredential {
                runtime_scopes,
                enrollment_token_hash,
                enrollment_ttl_seconds,
                ..
            } => validate_enrollment_request(
                runtime_scopes,
                enrollment_token_hash,
                *enrollment_ttl_seconds,
            )?,
            Self::AssignPolicy { .. }
            | Self::RevokePolicy { .. }
            | Self::SuspendAgent { .. }
            | Self::ReactivateAgent { .. } => {}
            Self::RotateAgentOnchainSigner {
                expected_smart_account_address,
                chain_id,
                ..
            } => {
                let account = expected_smart_account_address
                    .parse::<ethers::types::Address>()
                    .map_err(|_| anyhow::anyhow!("expected smart-account address is invalid"))?;
                if account == ethers::types::Address::zero() {
                    anyhow::bail!("expected smart-account address cannot be zero");
                }
                let expected_chain_id = match expected_chain {
                    "arc" => 5042,
                    "arc-testnet" => 5_042_002,
                    _ => anyhow::bail!("unsupported Arc network"),
                };
                if *chain_id != expected_chain_id {
                    anyhow::bail!("signer rotation targets the wrong Arc network");
                }
            }
        }
        Ok(())
    }
}

fn validate_agent_identity(external_id: &str, display_name: &str) -> Result<()> {
    if !(2..=128).contains(&external_id.len())
        || !external_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !(2..=100).contains(&display_name.trim().len())
    {
        anyhow::bail!("agent ID or display name is invalid");
    }
    Ok(())
}

fn validate_enrollment_request(
    runtime_scopes: &[String],
    token_hash: &str,
    ttl_seconds: i64,
) -> Result<()> {
    crate::auth::validate_runtime_scopes(runtime_scopes)?;
    if runtime_scopes.is_empty() {
        anyhow::bail!("runtime scopes cannot be empty");
    }
    if !(60..=86_400).contains(&ttl_seconds) {
        anyhow::bail!("enrollment TTL must be between 60 and 86400 seconds");
    }
    if token_hash.len() != 64
        || !token_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("enrollment token hash is invalid");
    }
    Ok(())
}

fn policy_values_are_subset(
    child: Option<&[String]>,
    parent: Option<&[String]>,
    case_insensitive: bool,
) -> bool {
    let Some(parent) = parent else {
        return true;
    };
    let Some(child) = child else {
        return parent.iter().any(|allowed| allowed == "*");
    };
    child.iter().all(|candidate| {
        parent.iter().any(|allowed| {
            allowed == "*"
                || if case_insensitive {
                    allowed.eq_ignore_ascii_case(candidate)
                } else {
                    allowed == candidate
                }
        })
    })
}

pub fn validate_delegated_policy(
    parent: &AuthorizationPolicyRow,
    child: &AuthorizationPolicyRow,
) -> Result<()> {
    if !policy_values_are_subset(
        child.allowed_chains.as_deref(),
        parent.allowed_chains.as_deref(),
        false,
    ) || !policy_values_are_subset(
        child.allowed_protocols.as_deref(),
        parent.allowed_protocols.as_deref(),
        false,
    ) || !policy_values_are_subset(
        child.allowed_actions.as_deref(),
        parent.allowed_actions.as_deref(),
        false,
    ) || !policy_values_are_subset(
        child.allowed_targets.as_deref(),
        parent.allowed_targets.as_deref(),
        true,
    ) {
        anyhow::bail!("child policy exceeds its parent agent policy");
    }
    if child.allow_raw_execution && !parent.allow_raw_execution {
        anyhow::bail!("child policy cannot enable raw execution denied by its parent");
    }
    match (&parent.max_value_wei, &child.max_value_wei) {
        (Some(_), None) => anyhow::bail!("child policy must retain the parent native-value limit"),
        (Some(parent), Some(child))
            if child.parse::<ethers::types::U256>()? > parent.parse::<ethers::types::U256>()? =>
        {
            anyhow::bail!("child policy exceeds the parent native-value limit")
        }
        _ => {}
    }
    match (parent.max_execution_fee_usd, child.max_execution_fee_usd) {
        (Some(_), None) => anyhow::bail!("child policy must retain the parent fee limit"),
        (Some(parent), Some(child)) if child > parent => {
            anyhow::bail!("child policy exceeds the parent execution-fee limit")
        }
        _ => {}
    }
    Ok(())
}

fn validate_bounded_policy_values(name: &str, values: Option<&[String]>) -> Result<()> {
    if values.is_some_and(|values| {
        values.len() > 100
            || values
                .iter()
                .any(|value| value.is_empty() || value.len() > 256)
    }) {
        anyhow::bail!("{name} contains too many or oversized values");
    }
    Ok(())
}

fn policy_risk_warnings(action: &OwnerApprovalAction) -> Vec<&'static str> {
    let OwnerApprovalAction::CreatePolicy {
        allowed_chains,
        allowed_protocols,
        allowed_actions,
        allowed_targets,
        allow_raw_execution,
        max_value_wei,
        max_execution_fee_usd,
        ..
    } = action
    else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    if *allow_raw_execution {
        warnings.push("Allows raw transaction execution");
    }
    if allowed_chains.is_none() {
        warnings.push("Does not restrict the allowed chain set");
    }
    if allowed_protocols.is_none() {
        warnings.push("Does not restrict the allowed protocol set");
    }
    if allowed_actions.is_none() {
        warnings.push("Does not restrict the allowed action set");
    }
    if allowed_targets.is_none() {
        warnings.push("Does not restrict target contracts");
    }
    if [
        allowed_chains,
        allowed_protocols,
        allowed_actions,
        allowed_targets,
    ]
    .iter()
    .any(|values| {
        values
            .as_ref()
            .is_some_and(|values| values.iter().any(|v| v == "*"))
    }) {
        warnings.push("Contains wildcard permissions");
    }
    if max_value_wei.is_none() {
        warnings.push("Does not set a native-value limit");
    }
    if max_execution_fee_usd.is_none() {
        warnings.push("Does not set an execution-fee limit");
    }
    warnings
}

async fn get_owner_agent_for_status(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    status: &str,
) -> Result<AgentRow> {
    sqlx::query_as::<_, AgentRow>(
        r#"WITH RECURSIVE lineage AS (
               SELECT id, parent_agent_id, status
               FROM agents
               WHERE id = $1 AND organization_id = $2
               UNION
               SELECT parent.id, parent.parent_agent_id, parent.status
               FROM agents parent
               JOIN lineage child ON child.parent_agent_id = parent.id
               WHERE parent.organization_id = $2
           )
           SELECT a.* FROM agents a
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE a.id = $1 AND a.organization_id = $2 AND pag.principal_id = $3
             AND a.status = $4
             AND ($4 <> 'active' OR NOT EXISTS (
                 SELECT 1 FROM lineage WHERE status <> 'active'
             ))"#,
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(status)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("agent with required status is not available to this owner"))
}

async fn validate_agent_policy_assignment(
    pool: &PgPool,
    organization_id: Uuid,
    agent: &AgentRow,
    proposed: &AuthorizationPolicyRow,
) -> Result<()> {
    if let Some(parent_id) = agent.parent_agent_id {
        let parent = sqlx::query_as::<_, AgentRow>(
            "SELECT * FROM agents WHERE id = $1 AND organization_id = $2 AND status = 'active'",
        )
        .bind(parent_id)
        .bind(organization_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("parent agent is not active"))?;
        let parent_policy = get_authorization_policy(pool, organization_id, parent.policy_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("parent agent policy is inactive"))?;
        validate_delegated_policy(&parent_policy, proposed)?;
    }
    let child_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents child
           JOIN authorization_policies ap ON ap.id = child.policy_id
           WHERE child.parent_agent_id = $1 AND child.organization_id = $2
             AND child.status = 'active' AND ap.is_active = TRUE"#,
    )
    .bind(agent.id)
    .bind(organization_id)
    .fetch_all(pool)
    .await?;
    for child_policy in child_policies {
        validate_delegated_policy(proposed, &child_policy)?;
    }
    Ok(())
}

async fn get_owner_agent_for_status_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    status: &str,
) -> Result<AgentRow> {
    sqlx::query_as::<_, AgentRow>(
        r#"WITH RECURSIVE lineage AS (
               SELECT id, parent_agent_id, status
               FROM agents
               WHERE id = $1 AND organization_id = $2
               UNION
               SELECT parent.id, parent.parent_agent_id, parent.status
               FROM agents parent
               JOIN lineage child ON child.parent_agent_id = parent.id
               WHERE parent.organization_id = $2
           )
           SELECT a.* FROM agents a
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE a.id = $1 AND a.organization_id = $2 AND pag.principal_id = $3
             AND a.status = $4
             AND ($4 <> 'active' OR NOT EXISTS (
                 SELECT 1 FROM lineage WHERE status <> 'active'
             ))
           FOR UPDATE OF a"#,
    )
    .bind(agent_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(status)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("agent with required status is not available to this owner"))
}

async fn get_active_policy_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    policy_id: Uuid,
) -> Result<AuthorizationPolicyRow> {
    sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT * FROM authorization_policies
           WHERE id = $1 AND organization_id = $2 AND is_active = TRUE
           FOR UPDATE"#,
    )
    .bind(policy_id)
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("active policy was not found in this organization"))
}

async fn validate_agent_policy_assignment_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    agent: &AgentRow,
    proposed: &AuthorizationPolicyRow,
) -> Result<()> {
    if let Some(parent_id) = agent.parent_agent_id {
        let parent = sqlx::query_as::<_, AgentRow>(
            r#"SELECT * FROM agents
               WHERE id = $1 AND organization_id = $2 AND status = 'active'
               FOR UPDATE"#,
        )
        .bind(parent_id)
        .bind(organization_id)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("parent agent is not active"))?;
        let parent_policy =
            get_active_policy_tx(transaction, organization_id, parent.policy_id).await?;
        validate_delegated_policy(&parent_policy, proposed)?;
    }
    let child_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents child
           JOIN authorization_policies ap ON ap.id = child.policy_id
           WHERE child.parent_agent_id = $1 AND child.organization_id = $2
             AND child.status = 'active' AND ap.is_active = TRUE
           FOR UPDATE OF child, ap"#,
    )
    .bind(agent.id)
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    for child_policy in child_policies {
        validate_delegated_policy(proposed, &child_policy)?;
    }
    Ok(())
}

pub async fn create_owner_approval_request(
    pool: &PgPool,
    context: &AuthContext,
    expected_chain: &str,
    token_hash: &str,
    action: &OwnerApprovalAction,
    expires_at: DateTime<Utc>,
) -> Result<OwnerApprovalRequestRow> {
    if context.credential_kind != CredentialKind::OAuthSession || context.agent_id.is_some() {
        anyhow::bail!("owner approvals require an organization control OAuth session");
    }
    if token_hash.len() != 64
        || !token_hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("approval token hash is invalid");
    }
    if expires_at <= Utc::now() {
        anyhow::bail!("approval expiry must be in the future");
    }
    action.validate(expected_chain)?;

    let active_owner_connection: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM oauth_connections c
            JOIN principals p ON p.id = c.principal_id
            JOIN organizations o ON o.id = c.organization_id
            JOIN owner_accounts oa ON oa.principal_id = c.principal_id
            WHERE c.id = $1 AND c.organization_id = $2 AND c.principal_id = $3
              AND c.status = 'active' AND c.agent_id IS NULL
              AND p.status = 'active' AND o.status = 'active'
        )"#,
    )
    .bind(context.credential_id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .fetch_one(pool)
    .await?;
    if !active_owner_connection {
        anyhow::bail!("active owner control connection was not found");
    }

    let presentation = match action {
        OwnerApprovalAction::CreatePolicy { .. } => serde_json::json!({
            "title": "Create authorization policy",
            "proposed_policy": action,
            "warnings": policy_risk_warnings(action)
        }),
        OwnerApprovalAction::AssignPolicy {
            agent_id,
            expected_current_policy_id,
            policy_id,
        } => {
            let agent = sqlx::query_as::<_, AgentRow>(
                r#"SELECT a.* FROM agents a
                   JOIN principal_agent_grants pag ON pag.agent_id = a.id
                   WHERE a.id = $1 AND a.organization_id = $2 AND pag.principal_id = $3
                     AND a.status = 'active'"#,
            )
            .bind(agent_id)
            .bind(context.organization_id)
            .bind(context.principal_id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active agent is not available to this owner"))?;
            if agent.policy_id != *expected_current_policy_id {
                anyhow::bail!("agent policy changed before the approval request was created");
            }
            let current = get_authorization_policy(pool, context.organization_id, agent.policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("agent's current policy is inactive"))?;
            let proposed = get_authorization_policy(pool, context.organization_id, *policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("proposed policy is inactive"))?;
            validate_agent_policy_assignment(pool, context.organization_id, &agent, &proposed)
                .await?;
            serde_json::json!({
                "title": "Assign authorization policy",
                "agent": agent,
                "current_policy": current,
                "proposed_policy": proposed
            })
        }
        OwnerApprovalAction::RevokePolicy { policy_id } => {
            let policy = get_authorization_policy(pool, context.organization_id, *policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("active policy was not found"))?;
            let assigned: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE policy_id = $1 AND status = 'active')",
            )
            .bind(policy_id)
            .fetch_one(pool)
            .await?;
            if assigned {
                anyhow::bail!("policy is assigned to an active agent and cannot be revoked");
            }
            serde_json::json!({
                "title": "Revoke authorization policy",
                "policy": policy,
                "warning": "This policy will no longer be available for assignment"
            })
        }
        OwnerApprovalAction::CreateAgent {
            external_id,
            display_name,
            parent_agent_id,
            policy_id,
            runtime_scopes,
            enrollment_ttl_seconds,
            ..
        } => {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM agents WHERE organization_id = $1 AND external_id = $2)",
            )
            .bind(context.organization_id)
            .bind(external_id)
            .fetch_one(pool)
            .await?;
            if exists {
                anyhow::bail!("agent ID is already registered in this organization");
            }
            let policy = get_authorization_policy(pool, context.organization_id, *policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("selected agent policy is inactive"))?;
            let parent = match parent_agent_id {
                Some(parent_id) => {
                    let parent = get_owner_agent_for_status(
                        pool,
                        context.organization_id,
                        context.principal_id,
                        *parent_id,
                        "active",
                    )
                    .await?;
                    let parent_policy =
                        get_authorization_policy(pool, context.organization_id, parent.policy_id)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("parent agent policy is inactive"))?;
                    validate_delegated_policy(&parent_policy, &policy)?;
                    Some(serde_json::json!({
                        "agent": parent,
                        "effective_policy": parent_policy
                    }))
                }
                None => None,
            };
            serde_json::json!({
                "title": "Create agent",
                "agent": {
                    "agent_id": external_id,
                    "display_name": display_name,
                    "runtime_scopes": runtime_scopes,
                    "enrollment_ttl_seconds": enrollment_ttl_seconds
                },
                "assigned_policy": policy,
                "parent_delegation": parent,
                "message": "The one-time enrollment credential becomes usable only after approval"
            })
        }
        OwnerApprovalAction::SuspendAgent { agent_id } => {
            let agent = get_owner_agent_for_status(
                pool,
                context.organization_id,
                context.principal_id,
                *agent_id,
                "active",
            )
            .await?;
            serde_json::json!({
                "title": "Suspend agent",
                "agent": agent,
                "effects": [
                    "Blocks the agent and its delegated descendants from new execution",
                    "Revokes local runtime credentials and agent-bound OAuth sessions",
                    "Revokes workload instances and consumes pending enrollment grants",
                    "Preserves the agent wallet, smart account, and assets"
                ]
            })
        }
        OwnerApprovalAction::ReactivateAgent { agent_id } => {
            let agent = get_owner_agent_for_status(
                pool,
                context.organization_id,
                context.principal_id,
                *agent_id,
                "suspended",
            )
            .await?;
            let policy = get_authorization_policy(pool, context.organization_id, agent.policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("agent policy is inactive"))?;
            validate_agent_policy_assignment(pool, context.organization_id, &agent, &policy)
                .await?;
            serde_json::json!({
                "title": "Reactivate agent",
                "agent": agent,
                "effective_policy": policy,
                "warning": "Previously revoked credentials remain revoked; issue a new credential separately"
            })
        }
        OwnerApprovalAction::RotateAgentCredential {
            agent_id,
            runtime_scopes,
            enrollment_ttl_seconds,
            ..
        } => {
            let agent = get_owner_agent_for_status(
                pool,
                context.organization_id,
                context.principal_id,
                *agent_id,
                "active",
            )
            .await?;
            serde_json::json!({
                "title": "Rotate agent runtime credential",
                "agent": agent,
                "new_runtime_scopes": runtime_scopes,
                "enrollment_ttl_seconds": enrollment_ttl_seconds,
                "effects": [
                    "Revokes existing local runtime credentials for this agent",
                    "Consumes older unused enrollment grants",
                    "Creates one new one-time enrollment grant",
                    "Does not rotate the Turnkey onchain wallet signer"
                ]
            })
        }
        OwnerApprovalAction::RotateAgentOnchainSigner {
            agent_id,
            expected_agent_wallet_id,
            expected_managed_wallet_id,
            expected_smart_account_address,
            chain_id,
        } => {
            let binding = get_agent_signer_binding_for_owner(
                pool,
                context.organization_id,
                context.principal_id,
                *agent_id,
                *chain_id,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("active agent signer binding was not found"))?;
            if binding.agent_wallet_id != *expected_agent_wallet_id
                || binding.managed_wallet_id != *expected_managed_wallet_id
                || !binding
                    .smart_account_address
                    .eq_ignore_ascii_case(expected_smart_account_address)
                || binding.chain_id != *chain_id
            {
                anyhow::bail!("agent signer binding changed before approval was created");
            }
            let active: bool = sqlx::query_scalar(
                r#"SELECT EXISTS(
                       SELECT 1 FROM agent_signer_rotations
                       WHERE agent_id = $1 AND status NOT IN ('reconciled', 'failed')
                   )"#,
            )
            .bind(agent_id)
            .fetch_one(pool)
            .await?;
            if active {
                anyhow::bail!("an unresolved signer rotation already exists for this agent");
            }
            serde_json::json!({
                "title": "Rotate agent onchain signer",
                "agent_id": agent_id,
                "chain_id": chain_id,
                "smart_account_address": binding.smart_account_address,
                "current_signer_address": binding.signer_address,
                "effects": [
                    "Creates a replacement signer inside the organization's Turnkey sub-organization",
                    "Pauses this agent's execution while rotation is unresolved",
                    "Updates the smart account owner without changing its address or moving assets",
                    "Keeps the previous managed-wallet record for audit and recovery"
                ]
            })
        }
    };
    let id = Uuid::new_v4();
    let payload = serde_json::to_value(action)?;
    Ok(sqlx::query_as::<_, OwnerApprovalRequestRow>(
        r#"INSERT INTO owner_approval_requests (
                id, organization_id, principal_id, oauth_connection_id,
                token_hash, action, payload, presentation, expires_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, organization_id, principal_id, oauth_connection_id,
                      action, presentation, status, result, expires_at,
                      created_at, approved_at"#,
    )
    .bind(id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(context.credential_id)
    .bind(token_hash)
    .bind(action.kind())
    .bind(payload)
    .bind(presentation)
    .bind(expires_at)
    .fetch_one(pool)
    .await?)
}

pub async fn get_owner_approval_request(
    pool: &PgPool,
    context: &AuthContext,
    id: Uuid,
) -> Result<Option<OwnerApprovalRequestRow>> {
    sqlx::query(
        r#"UPDATE owner_approval_requests SET status = 'expired'
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'pending' AND expires_at <= now()"#,
    )
    .bind(id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .execute(pool)
    .await?;
    Ok(sqlx::query_as::<_, OwnerApprovalRequestRow>(
        r#"SELECT id, organization_id, principal_id, oauth_connection_id,
                  action, presentation, status, result, expires_at,
                  created_at, approved_at
           FROM owner_approval_requests
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3"#,
    )
    .bind(id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .fetch_optional(pool)
    .await?)
}

#[derive(sqlx::FromRow)]
struct PendingOwnerApprovalExecution {
    organization_id: Uuid,
    principal_id: Uuid,
    oauth_connection_id: Uuid,
    action: String,
    payload: serde_json::Value,
    expires_at: DateTime<Utc>,
}

pub async fn complete_owner_approval(
    pool: &PgPool,
    approval_id: Uuid,
    organization_id: Uuid,
    principal_id: Uuid,
    passkey_id: Uuid,
    updated_passkey: &serde_json::Value,
    expected_chain: &str,
) -> Result<serde_json::Value> {
    let mut transaction = pool.begin().await?;
    let row = sqlx::query_as::<_, PendingOwnerApprovalExecution>(
        r#"SELECT organization_id, principal_id, oauth_connection_id,
                  action, payload, expires_at
           FROM owner_approval_requests
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'pending'
           FOR UPDATE"#,
    )
    .bind(approval_id)
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("approval request is unavailable or already completed"))?;
    if row.expires_at <= Utc::now() {
        sqlx::query("UPDATE owner_approval_requests SET status = 'expired' WHERE id = $1")
            .bind(approval_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        anyhow::bail!("approval request has expired");
    }
    let connection_active: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM oauth_connections
            WHERE id = $1 AND organization_id = $2 AND principal_id = $3
              AND status = 'active' AND agent_id IS NULL
        )"#,
    )
    .bind(row.oauth_connection_id)
    .bind(row.organization_id)
    .bind(row.principal_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !connection_active {
        anyhow::bail!("the OAuth connection that requested approval is no longer active");
    }
    let passkey_updated = sqlx::query(
        r#"UPDATE owner_passkeys op SET passkey = $4, last_used_at = now(), updated_at = now()
           FROM principals p, organizations o
           WHERE op.id = $1 AND op.organization_id = $2 AND op.principal_id = $3
             AND p.id = op.principal_id AND p.status = 'active'
             AND o.id = op.organization_id AND o.status = 'active'"#,
    )
    .bind(passkey_id)
    .bind(row.organization_id)
    .bind(row.principal_id)
    .bind(updated_passkey)
    .execute(&mut *transaction)
    .await?;
    if passkey_updated.rows_affected() != 1 {
        anyhow::bail!("approved passkey is not active for this owner");
    }

    let action: OwnerApprovalAction = serde_json::from_value(row.payload.clone())?;
    action.validate(expected_chain)?;
    if action.kind() != row.action {
        anyhow::bail!("approval action does not match its stored payload");
    }
    let result = match action {
        OwnerApprovalAction::CreatePolicy {
            name,
            allowed_chains,
            allowed_protocols,
            allowed_actions,
            allowed_targets,
            allow_raw_execution,
            max_value_wei,
            max_execution_fee_usd,
        } => {
            let policy_id = Uuid::new_v4();
            sqlx::query(
                r#"INSERT INTO authorization_policies (
                    id, organization_id, name, allowed_chains, allowed_protocols,
                    allowed_actions, allowed_targets, allow_raw_execution,
                    max_value_wei, max_execution_fee_usd
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
            )
            .bind(policy_id)
            .bind(row.organization_id)
            .bind(name.trim())
            .bind(allowed_chains)
            .bind(allowed_protocols)
            .bind(allowed_actions)
            .bind(allowed_targets)
            .bind(allow_raw_execution)
            .bind(max_value_wei)
            .bind(max_execution_fee_usd)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({"policy_id": policy_id, "created": true})
        }
        OwnerApprovalAction::AssignPolicy {
            agent_id,
            expected_current_policy_id,
            policy_id,
        } => {
            let agent = get_owner_agent_for_status_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                agent_id,
                "active",
            )
            .await?;
            if agent.policy_id != expected_current_policy_id {
                anyhow::bail!("agent policy changed while approval was pending");
            }
            let policy =
                get_active_policy_tx(&mut transaction, row.organization_id, policy_id).await?;
            validate_agent_policy_assignment_tx(
                &mut transaction,
                row.organization_id,
                &agent,
                &policy,
            )
            .await?;
            sqlx::query("UPDATE agents SET policy_id = $2, updated_at = now() WHERE id = $1")
                .bind(agent_id)
                .bind(policy_id)
                .execute(&mut *transaction)
                .await?;
            serde_json::json!({
                "agent_id": agent_id,
                "previous_policy_id": expected_current_policy_id,
                "policy_id": policy_id,
                "assigned": true
            })
        }
        OwnerApprovalAction::RevokePolicy { policy_id } => {
            let updated = sqlx::query(
                r#"UPDATE authorization_policies SET is_active = FALSE, updated_at = now()
                   WHERE id = $1 AND organization_id = $2 AND is_active = TRUE
                     AND NOT EXISTS (
                         SELECT 1 FROM agents WHERE policy_id = $1 AND status = 'active'
                     )"#,
            )
            .bind(policy_id)
            .bind(row.organization_id)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                anyhow::bail!("policy is inactive or assigned to an active agent");
            }
            serde_json::json!({"policy_id": policy_id, "revoked": true})
        }
        OwnerApprovalAction::CreateAgent {
            external_id,
            display_name,
            parent_agent_id,
            policy_id,
            runtime_scopes,
            enrollment_token_hash,
            enrollment_ttl_seconds,
        } => {
            let policy =
                get_active_policy_tx(&mut transaction, row.organization_id, policy_id).await?;
            if let Some(parent_id) = parent_agent_id {
                let parent = get_owner_agent_for_status_tx(
                    &mut transaction,
                    row.organization_id,
                    row.principal_id,
                    parent_id,
                    "active",
                )
                .await?;
                let parent_policy =
                    get_active_policy_tx(&mut transaction, row.organization_id, parent.policy_id)
                        .await?;
                validate_delegated_policy(&parent_policy, &policy)?;
            }
            let agent = sqlx::query_as::<_, AgentRow>(
                r#"INSERT INTO agents (
                       id, organization_id, external_id, display_name,
                       parent_agent_id, policy_id
                   ) VALUES ($1, $2, $3, $4, $5, $6)
                   ON CONFLICT (organization_id, external_id) DO NOTHING
                   RETURNING *"#,
            )
            .bind(Uuid::new_v4())
            .bind(row.organization_id)
            .bind(external_id)
            .bind(display_name.trim())
            .bind(parent_agent_id)
            .bind(policy_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("agent ID is already registered"))?;
            sqlx::query(
                "INSERT INTO principal_agent_grants (principal_id, agent_id) VALUES ($1, $2)",
            )
            .bind(row.principal_id)
            .bind(agent.id)
            .execute(&mut *transaction)
            .await?;
            let expires_at = Utc::now() + chrono::Duration::seconds(enrollment_ttl_seconds);
            sqlx::query(
                r#"INSERT INTO agent_enrollment_grants (
                       id, organization_id, agent_id, created_by_principal_id,
                       token_hash, scopes, expires_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(Uuid::new_v4())
            .bind(row.organization_id)
            .bind(agent.id)
            .bind(row.principal_id)
            .bind(enrollment_token_hash)
            .bind(&runtime_scopes)
            .bind(expires_at)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "agent": agent,
                "runtime_scopes": runtime_scopes,
                "enrollment_expires_at": expires_at,
                "created": true
            })
        }
        OwnerApprovalAction::SuspendAgent { agent_id } => {
            let agent = get_owner_agent_for_status_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                agent_id,
                "active",
            )
            .await?;
            sqlx::query("UPDATE agents SET status = 'suspended', updated_at = now() WHERE id = $1")
                .bind(agent.id)
                .execute(&mut *transaction)
                .await?;
            let invalidated_principals = sqlx::query(
                r#"WITH local_credentials AS (
                       UPDATE credential_bindings
                       SET is_active = FALSE, updated_at = now()
                       WHERE agent_id = $1 AND organization_id = $2 AND is_active = TRUE
                       RETURNING principal_id
                   ), workload_credentials AS (
                       UPDATE federation_trusts
                       SET is_active = FALSE, updated_at = now()
                       WHERE agent_id = $1 AND organization_id = $2 AND is_active = TRUE
                       RETURNING principal_id
                   ), affected AS (
                       SELECT principal_id FROM local_credentials
                       UNION
                       SELECT principal_id FROM workload_credentials
                   )
                   UPDATE principals p
                   SET auth_version = auth_version + 1, updated_at = now()
                   FROM affected
                   WHERE p.id = affected.principal_id AND p.principal_type = 'agent'"#,
            )
            .bind(agent.id)
            .bind(row.organization_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let revoked_instances = sqlx::query(
                "UPDATE agent_instances SET status = 'revoked' WHERE agent_id = $1 AND status = 'active'",
            )
            .bind(agent.id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let consumed_grants = sqlx::query(
                "UPDATE agent_enrollment_grants SET used_at = now() WHERE agent_id = $1 AND used_at IS NULL",
            )
            .bind(agent.id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let revoked_connections = sqlx::query(
                r#"UPDATE oauth_connections
                   SET status = 'revoked', revoked_at = now(), updated_at = now()
                   WHERE agent_id = $1 AND organization_id = $2 AND status = 'active'"#,
            )
            .bind(agent.id)
            .bind(row.organization_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            serde_json::json!({
                "agent_id": agent.id,
                "status": "suspended",
                "invalidated_principals": invalidated_principals,
                "revoked_instances": revoked_instances,
                "consumed_enrollment_grants": consumed_grants,
                "revoked_oauth_connections": revoked_connections,
                "wallet_preserved": true
            })
        }
        OwnerApprovalAction::ReactivateAgent { agent_id } => {
            let agent = get_owner_agent_for_status_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                agent_id,
                "suspended",
            )
            .await?;
            let policy =
                get_active_policy_tx(&mut transaction, row.organization_id, agent.policy_id)
                    .await?;
            validate_agent_policy_assignment_tx(
                &mut transaction,
                row.organization_id,
                &agent,
                &policy,
            )
            .await?;
            sqlx::query("UPDATE agents SET status = 'active', updated_at = now() WHERE id = $1")
                .bind(agent.id)
                .execute(&mut *transaction)
                .await?;
            serde_json::json!({
                "agent_id": agent.id,
                "status": "active",
                "credentials_restored": false
            })
        }
        OwnerApprovalAction::RotateAgentCredential {
            agent_id,
            runtime_scopes,
            enrollment_token_hash,
            enrollment_ttl_seconds,
        } => {
            let agent = get_owner_agent_for_status_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                agent_id,
                "active",
            )
            .await?;
            let invalidated_principals = sqlx::query(
                r#"WITH revoked AS (
                       UPDATE credential_bindings
                       SET is_active = FALSE, updated_at = now()
                       WHERE agent_id = $1 AND organization_id = $2 AND is_active = TRUE
                       RETURNING principal_id
                   )
                   UPDATE principals p
                   SET auth_version = auth_version + 1, updated_at = now()
                   FROM revoked
                   WHERE p.id = revoked.principal_id AND p.principal_type = 'agent'"#,
            )
            .bind(agent.id)
            .bind(row.organization_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let consumed_grants = sqlx::query(
                "UPDATE agent_enrollment_grants SET used_at = now() WHERE agent_id = $1 AND used_at IS NULL",
            )
            .bind(agent.id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let expires_at = Utc::now() + chrono::Duration::seconds(enrollment_ttl_seconds);
            sqlx::query(
                r#"INSERT INTO agent_enrollment_grants (
                       id, organization_id, agent_id, created_by_principal_id,
                       token_hash, scopes, expires_at
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7)"#,
            )
            .bind(Uuid::new_v4())
            .bind(row.organization_id)
            .bind(agent.id)
            .bind(row.principal_id)
            .bind(enrollment_token_hash)
            .bind(&runtime_scopes)
            .bind(expires_at)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "agent_id": agent.id,
                "runtime_scopes": runtime_scopes,
                "enrollment_expires_at": expires_at,
                "invalidated_principals": invalidated_principals,
                "consumed_enrollment_grants": consumed_grants,
                "turnkey_signer_rotated": false
            })
        }
        OwnerApprovalAction::RotateAgentOnchainSigner {
            agent_id,
            expected_agent_wallet_id,
            expected_managed_wallet_id,
            expected_smart_account_address,
            chain_id,
        } => {
            let binding: AgentSignerBinding = sqlx::query_as(
                r#"
                SELECT a.id AS agent_id, aw.id AS agent_wallet_id,
                       aw.managed_wallet_id, mw.address AS signer_address,
                       asa.account_address AS smart_account_address,
                       asa.initial_signer_address, asa.chain_id
                FROM agents a
                JOIN principal_agent_grants pag ON pag.agent_id = a.id
                JOIN agent_wallets aw ON aw.agent_uuid = a.id
                JOIN managed_wallets mw ON mw.id = aw.managed_wallet_id
                JOIN agent_smart_accounts asa ON asa.agent_wallet_id = aw.id
                WHERE a.id = $1 AND a.organization_id = $2 AND pag.principal_id = $3
                  AND a.status = 'active' AND asa.chain_id = $4
                FOR UPDATE OF a, aw, asa
                "#,
            )
            .bind(agent_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .bind(chain_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active agent signer binding was not found"))?;
            if binding.agent_wallet_id != expected_agent_wallet_id
                || binding.managed_wallet_id != expected_managed_wallet_id
                || !binding
                    .smart_account_address
                    .eq_ignore_ascii_case(&expected_smart_account_address)
                || binding.chain_id != chain_id
            {
                anyhow::bail!("agent signer binding changed while approval was pending");
            }
            let rotation_id = Uuid::new_v4();
            sqlx::query(
                r#"INSERT INTO agent_signer_rotations (
                       id, organization_id, agent_id, agent_wallet_id,
                       old_managed_wallet_id, old_signer_address,
                       smart_account_address, chain_id, requested_by_principal_id
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
            )
            .bind(rotation_id)
            .bind(row.organization_id)
            .bind(agent_id)
            .bind(binding.agent_wallet_id)
            .bind(binding.managed_wallet_id)
            .bind(&binding.signer_address)
            .bind(&binding.smart_account_address)
            .bind(binding.chain_id)
            .bind(row.principal_id)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "rotation_id": rotation_id,
                "agent_id": agent_id,
                "status": "pending",
                "smart_account_address": binding.smart_account_address,
                "message": "Signer rotation was approved and queued; execution remains paused until reconciliation completes."
            })
        }
    };
    sqlx::query(
        r#"UPDATE owner_approval_requests
           SET status = 'approved', result = $2, approved_by_passkey_id = $3,
               approved_at = now()
           WHERE id = $1"#,
    )
    .bind(approval_id)
    .bind(&result)
    .bind(passkey_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r#"INSERT INTO auth_audit_events (
            id, organization_id, principal_id, credential_id, credential_kind,
            action, resource, decision, details
        ) VALUES ($1, $2, $3, $4, 'oauth_session', $5, $6, 'allow', $7)"#,
    )
    .bind(Uuid::new_v4())
    .bind(row.organization_id)
    .bind(row.principal_id)
    .bind(row.oauth_connection_id)
    .bind(format!("owner_approval:{}", row.action))
    .bind("/owner-approvals")
    .bind(serde_json::json!({
        "approval_request_id": approval_id,
        "payload": row.payload,
        "result": result
    }))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(result)
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

    fn test_policy(
        allowed_actions: Option<Vec<String>>,
        allow_raw_execution: bool,
        max_value_wei: Option<&str>,
        max_execution_fee_usd: Option<f64>,
    ) -> AuthorizationPolicyRow {
        AuthorizationPolicyRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: format!("policy-{}", Uuid::new_v4().simple()),
            version: 1,
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: Some(vec!["uniswap-v4".into()]),
            allowed_actions,
            allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
            allow_raw_execution,
            max_value_wei: max_value_wei.map(str::to_string),
            max_execution_fee_usd,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn owner_approval_policy_drafts_are_restrictive_and_arc_scoped() {
        let valid = OwnerApprovalAction::CreatePolicy {
            name: "Arc swap policy".into(),
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: Some(vec!["uniswap-v4".into()]),
            allowed_actions: Some(vec!["protocol:uniswap-v4:swap".into()]),
            allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
            allow_raw_execution: false,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
        };
        assert!(valid.validate("arc-testnet").is_ok());

        let unrestricted = OwnerApprovalAction::CreatePolicy {
            name: "Unrestricted".into(),
            allowed_chains: None,
            allowed_protocols: None,
            allowed_actions: None,
            allowed_targets: None,
            allow_raw_execution: false,
            max_value_wei: None,
            max_execution_fee_usd: None,
        };
        assert!(unrestricted.validate("arc-testnet").is_err());

        let wrong_chain = OwnerApprovalAction::CreatePolicy {
            name: "Wrong chain".into(),
            allowed_chains: Some(vec!["base".into()]),
            allowed_protocols: None,
            allowed_actions: None,
            allowed_targets: None,
            allow_raw_execution: false,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: None,
        };
        assert!(wrong_chain.validate("arc-testnet").is_err());
    }

    #[test]
    fn delegated_policies_cannot_expand_parent_authority() {
        let parent = test_policy(
            Some(vec![
                "wallet:read".into(),
                "protocol:uniswap-v4:swap".into(),
            ]),
            false,
            Some("100"),
            Some(1.0),
        );
        let child = test_policy(
            Some(vec!["wallet:read".into()]),
            false,
            Some("50"),
            Some(0.5),
        );
        assert!(validate_delegated_policy(&parent, &child).is_ok());

        let mut wildcard = child.clone();
        wildcard.allowed_actions = Some(vec!["*".into()]);
        assert!(validate_delegated_policy(&parent, &wildcard).is_err());

        let mut raw = child.clone();
        raw.allow_raw_execution = true;
        assert!(validate_delegated_policy(&parent, &raw).is_err());

        let mut unlimited = child.clone();
        unlimited.max_value_wei = None;
        assert!(validate_delegated_policy(&parent, &unlimited).is_err());

        let mut costly = child;
        costly.max_execution_fee_usd = Some(2.0);
        assert!(validate_delegated_policy(&parent, &costly).is_err());

        let mut unrestricted_parent = parent;
        unrestricted_parent.allowed_actions = Some(vec!["*".into()]);
        let mut unrestricted_child = unrestricted_parent.clone();
        unrestricted_child.allowed_actions = None;
        assert!(validate_delegated_policy(&unrestricted_parent, &unrestricted_child).is_ok());
    }

    #[test]
    fn lifecycle_approval_payloads_require_valid_enrollment_material() {
        let valid_hash = "a".repeat(64);
        let action = OwnerApprovalAction::CreateAgent {
            external_id: "research-agent".into(),
            display_name: "Research agent".into(),
            parent_agent_id: None,
            policy_id: Uuid::new_v4(),
            runtime_scopes: vec!["wallet:read".into()],
            enrollment_token_hash: valid_hash,
            enrollment_ttl_seconds: 900,
        };
        assert!(action.validate("arc-testnet").is_ok());

        let invalid = OwnerApprovalAction::RotateAgentCredential {
            agent_id: Uuid::new_v4(),
            runtime_scopes: vec!["organization:manage".into()],
            enrollment_token_hash: "not-a-hash".into(),
            enrollment_ttl_seconds: 30,
        };
        assert!(invalid.validate("arc-testnet").is_err());

        let rotation = OwnerApprovalAction::RotateAgentOnchainSigner {
            agent_id: Uuid::new_v4(),
            expected_agent_wallet_id: Uuid::new_v4(),
            expected_managed_wallet_id: Uuid::new_v4(),
            expected_smart_account_address: "0x0000000000000000000000000000000000000001".into(),
            chain_id: 5_042_002,
        };
        assert!(rotation.validate("arc-testnet").is_ok());
        assert!(rotation.validate("arc").is_err());
    }

    #[tokio::test]
    async fn owner_approval_applies_once_and_records_an_audit_event() {
        let pool = setup_pool().await;
        let base = create_test_auth_context(
            &pool,
            &format!("approval-agent-{}", Uuid::new_v4().simple()),
        )
        .await;
        let passkey_id = Uuid::new_v4();
        let oauth_connection_id = Uuid::new_v4();
        let client_id = format!("approval-client-{}", Uuid::new_v4().simple());
        let owner_handle = format!("owner-{}@example.test", Uuid::new_v4().simple());
        sqlx::query(
            r#"INSERT INTO owner_accounts (
                principal_id, organization_id, owner_handle,
                owner_handle_normalized, display_name
            ) VALUES ($1, $2, $3, $3, 'Test owner')"#,
        )
        .bind(base.principal_id)
        .bind(base.organization_id)
        .bind(owner_handle)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO owner_passkeys (
                id, organization_id, principal_id, credential_id, passkey
            ) VALUES ($1, $2, $3, $4, '{}'::jsonb)"#,
        )
        .bind(passkey_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(format!("credential-{}", Uuid::new_v4().simple()))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, 'Test client', ARRAY['https://client.example/callback'])",
        )
        .bind(&client_id)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO oauth_connections (
                id, organization_id, principal_id, passkey_id,
                client_id, resource, scopes
            ) VALUES ($1, $2, $3, $4, $5, 'https://api.example/mcp/control', ARRAY['policy:manage'])"#,
        )
        .bind(oauth_connection_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(passkey_id)
        .bind(client_id)
        .execute(&pool)
        .await
        .unwrap();
        let context = AuthContext {
            credential_id: oauth_connection_id,
            credential_kind: CredentialKind::OAuthSession,
            agent_id: None,
            agent_external_id: None,
            instance_id: None,
            dpop_jkt: None,
            scopes: ["policy:manage".to_string()].into_iter().collect(),
            ..base
        };
        let policy_name = format!("approval-policy-{}", Uuid::new_v4().simple());
        let action = OwnerApprovalAction::CreatePolicy {
            name: policy_name.clone(),
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: Some(vec!["uniswap-v4".into()]),
            allowed_actions: Some(vec!["protocol:uniswap-v4:swap".into()]),
            allowed_targets: None,
            allow_raw_execution: false,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
        };
        let token_hash = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        let approval = create_owner_approval_request(
            &pool,
            &context,
            "arc-testnet",
            &token_hash,
            &action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
        let result = complete_owner_approval(
            &pool,
            approval.id,
            context.organization_id,
            context.principal_id,
            passkey_id,
            &serde_json::json!({"updated": true}),
            "arc-testnet",
        )
        .await
        .unwrap();
        assert_eq!(result["created"], true);
        let policy_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM authorization_policies WHERE organization_id = $1 AND name = $2",
        )
        .bind(context.organization_id)
        .bind(policy_name)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(policy_count, 1);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM auth_audit_events WHERE organization_id = $1 AND details->>'approval_request_id' = $2",
        )
        .bind(context.organization_id)
        .bind(approval.id.to_string())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 1);
        assert!(complete_owner_approval(
            &pool,
            approval.id,
            context.organization_id,
            context.principal_id,
            passkey_id,
            &serde_json::json!({"updated": true}),
            "arc-testnet",
        )
        .await
        .is_err());
    }

    struct OwnerControlFixture {
        context: AuthContext,
        passkey_id: Uuid,
        root_agent: AgentRow,
        root_policy: AuthorizationPolicyRow,
    }

    async fn create_owner_control_fixture(pool: &PgPool) -> OwnerControlFixture {
        let external_id = format!("control-agent-{}", Uuid::new_v4().simple());
        let base = create_test_auth_context(pool, &external_id).await;
        let root_agent = sqlx::query_as::<_, AgentRow>(
            "SELECT * FROM agents WHERE organization_id = $1 AND external_id = $2",
        )
        .bind(base.organization_id)
        .bind(&external_id)
        .fetch_one(pool)
        .await
        .unwrap();
        let root_policy =
            get_authorization_policy(pool, base.organization_id, root_agent.policy_id)
                .await
                .unwrap()
                .unwrap();
        let passkey_id = Uuid::new_v4();
        let oauth_connection_id = Uuid::new_v4();
        let owner_handle = format!("owner-{}@example.test", Uuid::new_v4().simple());
        sqlx::query(
            r#"INSERT INTO owner_accounts (
                principal_id, organization_id, owner_handle,
                owner_handle_normalized, display_name
            ) VALUES ($1, $2, $3, $3, 'Lifecycle owner')"#,
        )
        .bind(base.principal_id)
        .bind(base.organization_id)
        .bind(owner_handle)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO owner_passkeys (
                id, organization_id, principal_id, credential_id, passkey
            ) VALUES ($1, $2, $3, $4, '{}'::jsonb)"#,
        )
        .bind(passkey_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(format!("credential-{}", Uuid::new_v4().simple()))
        .execute(pool)
        .await
        .unwrap();
        let client_id = format!("control-client-{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, 'Control test client', ARRAY['https://client.example/callback'])",
        )
        .bind(&client_id)
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO oauth_connections (
                id, organization_id, principal_id, passkey_id,
                client_id, resource, scopes
            ) VALUES (
                $1, $2, $3, $4, $5, 'https://api.example/mcp/control',
                ARRAY['agent:manage', 'policy:manage', 'credential:manage']
            )"#,
        )
        .bind(oauth_connection_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(passkey_id)
        .bind(client_id)
        .execute(pool)
        .await
        .unwrap();
        OwnerControlFixture {
            context: AuthContext {
                credential_id: oauth_connection_id,
                credential_kind: CredentialKind::OAuthSession,
                agent_id: None,
                agent_external_id: None,
                instance_id: None,
                dpop_jkt: None,
                scopes: [
                    "agent:manage".to_string(),
                    "policy:manage".to_string(),
                    "credential:manage".to_string(),
                ]
                .into_iter()
                .collect(),
                ..base
            },
            passkey_id,
            root_agent,
            root_policy,
        }
    }

    async fn approve_test_action(
        pool: &PgPool,
        fixture: &OwnerControlFixture,
        action: &OwnerApprovalAction,
    ) -> Result<serde_json::Value> {
        let approval_hash = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        let approval = create_owner_approval_request(
            pool,
            &fixture.context,
            "arc-testnet",
            &approval_hash,
            action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await?;
        complete_owner_approval(
            pool,
            approval.id,
            fixture.context.organization_id,
            fixture.context.principal_id,
            fixture.passkey_id,
            &serde_json::json!({"counter": 1}),
            "arc-testnet",
        )
        .await
    }

    #[tokio::test]
    async fn approved_agent_lifecycle_is_one_time_contained_and_secret_safe() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let runtime_scopes = vec![
            "wallet:read".to_string(),
            "transaction:simulate".to_string(),
        ];
        let child_external_id = format!("child-{}", Uuid::new_v4().simple());
        let child_enrollment_token = format!("jso_enroll_{}", random_secret());
        let create_child = OwnerApprovalAction::CreateAgent {
            external_id: child_external_id.clone(),
            display_name: "Child agent".into(),
            parent_agent_id: Some(fixture.root_agent.id),
            policy_id: fixture.root_policy.id,
            runtime_scopes: runtime_scopes.clone(),
            enrollment_token_hash: sha256_hex(&child_enrollment_token),
            enrollment_ttl_seconds: 900,
        };
        let create_result = approve_test_action(&pool, &fixture, &create_child)
            .await
            .unwrap();
        assert!(!create_result.to_string().contains(&child_enrollment_token));
        let child = get_agent_for_owner_by_external_id(
            &pool,
            fixture.context.organization_id,
            fixture.context.principal_id,
            &child_external_id,
        )
        .await
        .unwrap()
        .unwrap();
        let (child_jwk, child_thumbprint) = test_public_jwk();
        let (old_credential, enrolled_child) = enroll_agent(
            &pool,
            EnrollAgentOptions {
                enrollment_token: &child_enrollment_token,
                display_name: "Child runtime",
                public_jwk: &child_jwk,
                public_jwk_thumbprint: &child_thumbprint,
            },
        )
        .await
        .unwrap();
        assert_eq!(enrolled_child.id, child.id);
        assert!(enroll_agent(
            &pool,
            EnrollAgentOptions {
                enrollment_token: &child_enrollment_token,
                display_name: "Replay",
                public_jwk: &child_jwk,
                public_jwk_thumbprint: &child_thumbprint,
            },
        )
        .await
        .is_err());

        let grandchild_external_id = format!("grandchild-{}", Uuid::new_v4().simple());
        approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::CreateAgent {
                external_id: grandchild_external_id.clone(),
                display_name: "Grandchild agent".into(),
                parent_agent_id: Some(child.id),
                policy_id: fixture.root_policy.id,
                runtime_scopes: runtime_scopes.clone(),
                enrollment_token_hash: sha256_hex(&format!("jso_enroll_{}", random_secret())),
                enrollment_ttl_seconds: 900,
            },
        )
        .await
        .unwrap();

        approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::SuspendAgent { agent_id: child.id },
        )
        .await
        .unwrap();
        assert!(get_agent_by_external_id(
            &pool,
            fixture.context.organization_id,
            &child_external_id
        )
        .await
        .unwrap()
        .is_none());
        assert!(get_agent_by_external_id(
            &pool,
            fixture.context.organization_id,
            &grandchild_external_id
        )
        .await
        .unwrap()
        .is_none());
        let old_active: bool =
            sqlx::query_scalar("SELECT is_active FROM credential_bindings WHERE id = $1")
                .bind(old_credential.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(!old_active);

        approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::ReactivateAgent { agent_id: child.id },
        )
        .await
        .unwrap();
        assert!(get_agent_by_external_id(
            &pool,
            fixture.context.organization_id,
            &grandchild_external_id
        )
        .await
        .unwrap()
        .is_some());

        let replacement_token = format!("jso_enroll_{}", random_secret());
        approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::RotateAgentCredential {
                agent_id: child.id,
                runtime_scopes: runtime_scopes.clone(),
                enrollment_token_hash: sha256_hex(&replacement_token),
                enrollment_ttl_seconds: 900,
            },
        )
        .await
        .unwrap();
        let (replacement_jwk, replacement_thumbprint) = test_public_jwk();
        let (replacement, _) = enroll_agent(
            &pool,
            EnrollAgentOptions {
                enrollment_token: &replacement_token,
                display_name: "Replacement child runtime",
                public_jwk: &replacement_jwk,
                public_jwk_thumbprint: &replacement_thumbprint,
            },
        )
        .await
        .unwrap();
        assert!(replacement.is_active);
        assert_ne!(replacement.id, old_credential.id);
    }

    #[tokio::test]
    async fn policy_reassignment_preserves_parent_child_authority() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let child_external_id = format!("policy-child-{}", Uuid::new_v4().simple());
        let child_result = approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::CreateAgent {
                external_id: child_external_id.clone(),
                display_name: "Policy child".into(),
                parent_agent_id: Some(fixture.root_agent.id),
                policy_id: fixture.root_policy.id,
                runtime_scopes: vec!["wallet:read".into()],
                enrollment_token_hash: sha256_hex(&format!("jso_enroll_{}", random_secret())),
                enrollment_ttl_seconds: 900,
            },
        )
        .await
        .unwrap();
        let child_id = Uuid::parse_str(child_result["agent"]["id"].as_str().unwrap()).unwrap();
        let narrow_result = approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::CreatePolicy {
                name: format!("narrow-{}", Uuid::new_v4().simple()),
                allowed_chains: Some(vec!["arc-testnet".into()]),
                allowed_protocols: Some(vec!["uniswap-v4".into()]),
                allowed_actions: Some(vec!["wallet:read".into()]),
                allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
                allow_raw_execution: false,
                max_value_wei: Some("0".into()),
                max_execution_fee_usd: Some(0.5),
            },
        )
        .await
        .unwrap();
        let narrow_policy_id =
            Uuid::parse_str(narrow_result["policy_id"].as_str().unwrap()).unwrap();

        let invalid_parent_assignment = OwnerApprovalAction::AssignPolicy {
            agent_id: fixture.root_agent.id,
            expected_current_policy_id: fixture.root_policy.id,
            policy_id: narrow_policy_id,
        };
        let approval_hash = hex::encode(Sha256::digest(Uuid::new_v4().as_bytes()));
        assert!(create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &approval_hash,
            &invalid_parent_assignment,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .is_err());

        approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::AssignPolicy {
                agent_id: child_id,
                expected_current_policy_id: fixture.root_policy.id,
                policy_id: narrow_policy_id,
            },
        )
        .await
        .unwrap();
        approve_test_action(&pool, &fixture, &invalid_parent_assignment)
            .await
            .unwrap();
        let root_policy_id: Uuid = sqlx::query_scalar("SELECT policy_id FROM agents WHERE id = $1")
            .bind(fixture.root_agent.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(root_policy_id, narrow_policy_id);
    }

    #[tokio::test]
    async fn approved_signer_rotation_is_pinned_unique_and_owner_visible() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let managed_wallet_id = Uuid::new_v4();
        let agent_wallet_id = Uuid::new_v4();
        let signer = format!(
            "0x{}",
            hex::encode(&Sha256::digest(Uuid::new_v4().as_bytes())[..20])
        );
        let account = format!(
            "0x{}",
            hex::encode(&Sha256::digest(Uuid::new_v4().as_bytes())[..20])
        );
        sqlx::query(
            r#"INSERT INTO managed_wallets (
                   id, wallet_provider, provider_organization_id,
                   provider_wallet_id, provider_account_id, provider_external_id,
                   scope_kind, scope_organization_id, address
               ) VALUES ($1, 'turnkey', $2, $3, $4, $5, 'organization', $6, $7)"#,
        )
        .bind(managed_wallet_id)
        .bind(Uuid::new_v4().to_string())
        .bind(format!("wallet-{managed_wallet_id}"))
        .bind(format!("account-{managed_wallet_id}"))
        .bind(format!("test-{}", managed_wallet_id.simple()))
        .bind(fixture.context.organization_id)
        .bind(&signer)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO agent_wallets (
                   id, organization_id, agent_uuid, managed_wallet_id, agent_id, address
               ) VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(agent_wallet_id)
        .bind(fixture.context.organization_id)
        .bind(fixture.root_agent.id)
        .bind(managed_wallet_id)
        .bind(&fixture.root_agent.external_id)
        .bind(&signer)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"INSERT INTO agent_smart_accounts (
                   agent_wallet_id, chain_id, account_address, initial_signer_address,
                   account_provider, provider_account_id
               ) VALUES ($1, 5042002, $2, $3, 'alchemy', $4)"#,
        )
        .bind(agent_wallet_id)
        .bind(&account)
        .bind(&signer)
        .bind(format!("smart-{agent_wallet_id}"))
        .execute(&pool)
        .await
        .unwrap();

        let action = OwnerApprovalAction::RotateAgentOnchainSigner {
            agent_id: fixture.root_agent.id,
            expected_agent_wallet_id: agent_wallet_id,
            expected_managed_wallet_id: managed_wallet_id,
            expected_smart_account_address: account.clone(),
            chain_id: 5_042_002,
        };
        let result = approve_test_action(&pool, &fixture, &action).await.unwrap();
        let rotation_id = Uuid::parse_str(result["rotation_id"].as_str().unwrap()).unwrap();
        let rotation = get_agent_signer_rotation_for_owner(
            &pool,
            fixture.context.organization_id,
            fixture.context.principal_id,
            rotation_id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rotation.status, "pending");
        assert_eq!(rotation.old_managed_wallet_id, managed_wallet_id);
        assert_eq!(rotation.agent_wallet_id, agent_wallet_id);
        assert!(rotation
            .smart_account_address
            .eq_ignore_ascii_case(&account));
        assert!(serde_json::to_value(&rotation)
            .unwrap()
            .get("signed_user_operation")
            .is_none());
        assert!(agent_has_unresolved_signer_rotation(
            &pool,
            fixture.context.organization_id,
            &fixture.root_agent.external_id,
        )
        .await
        .unwrap());
        assert!(approve_test_action(&pool, &fixture, &action).await.is_err());

        let stale = OwnerApprovalAction::RotateAgentOnchainSigner {
            agent_id: fixture.root_agent.id,
            expected_agent_wallet_id: agent_wallet_id,
            expected_managed_wallet_id: Uuid::new_v4(),
            expected_smart_account_address: account,
            chain_id: 5_042_002,
        };
        assert!(create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())),
            &stale,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .is_err());
    }

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
    async fn self_service_registration_is_relational_and_restrictive() {
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
