//! Database access layer — connection pool + repository functions.

pub mod models;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng as AeadOsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
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
    let committed = sqlx::query(
        r#"UPDATE policy_budget_reservations
           SET status = 'committed', committed_at = now()
           WHERE request_id = $1 AND status = 'reserved'"#,
    )
    .bind(request_id)
    .execute(&mut *transaction)
    .await?;
    if committed.rows_affected() != 1 {
        anyhow::bail!("execution policy budget reservation is missing or already consumed");
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
    pub webauthn_user_id: Uuid,
    pub agent_external_id: &'a str,
    pub passkey_id: Uuid,
    pub credential_id: &'a str,
    pub passkey: &'a serde_json::Value,
    pub turnkey_recovery_credential: &'a serde_json::Value,
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
            principal_id, organization_id, owner_handle, owner_handle_normalized,
            display_name, webauthn_user_id
        ) VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .bind(options.owner_handle)
    .bind(normalized_handle)
    .bind(options.display_name)
    .bind(options.webauthn_user_id)
    .execute(&mut *transaction)
    .await?;

    let allowed_chains = vec![options.chain.to_string()];
    let policy = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"
        INSERT INTO authorization_policies (
            id, organization_id, name, allowed_chains, allowed_protocols,
            allowed_actions, max_value_wei, max_execution_fee_usd,
            token_spend_limits, risk_permissions, rolling_window_seconds,
            max_rolling_execution_fee_usd, max_sponsored_gas_units,
            max_rolling_sponsored_gas_units, max_borrowed_value_usd,
            max_rolling_borrowed_value_usd
        ) VALUES (
            $1, $2, 'default-autonomous', $3, $4, $5, '0', $6,
            $7, $8, $9, $10, $11, $12, 0, 0
        )
        RETURNING *
        "#,
    )
    .bind(policy_id)
    .bind(organization_id)
    .bind(&allowed_chains)
    .bind(options.policy_protocols)
    .bind(options.policy_actions)
    .bind(options.max_execution_fee_usd)
    .bind(crate::policy::default_token_spend_limits())
    .bind(vec![crate::policy::RISK_EXTERNAL_WITHDRAWAL.to_string()])
    .bind(crate::auth::DEFAULT_ROLLING_WINDOW_SECONDS)
    .bind(crate::auth::DEFAULT_MAX_ROLLING_EXECUTION_FEE_USD)
    .bind(crate::auth::DEFAULT_MAX_SPONSORED_GAS_UNITS)
    .bind(crate::auth::DEFAULT_MAX_ROLLING_SPONSORED_GAS_UNITS)
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
            id, organization_id, principal_id, credential_id, passkey,
            turnkey_recovery_credential
        ) VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(options.passkey_id)
    .bind(organization_id)
    .bind(principal_id)
    .bind(options.credential_id)
    .bind(options.passkey)
    .bind(options.turnkey_recovery_credential)
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
            allowed_actions, max_value_wei, max_execution_fee_usd,
            token_spend_limits, risk_permissions, rolling_window_seconds,
            max_rolling_execution_fee_usd, max_sponsored_gas_units,
            max_rolling_sponsored_gas_units, max_borrowed_value_usd,
            max_rolling_borrowed_value_usd
        )
        VALUES (
            $1, $2, 'default-autonomous', $3, $4, $5, '0', $6,
            $7, $8, $9, $10, $11, $12, 0, 0
        )
        RETURNING *
        "#,
    )
    .bind(policy_id)
    .bind(organization_id)
    .bind(&allowed_chains)
    .bind(options.policy_protocols)
    .bind(options.policy_actions)
    .bind(options.max_execution_fee_usd)
    .bind(crate::policy::default_token_spend_limits())
    .bind(vec![crate::policy::RISK_EXTERNAL_WITHDRAWAL.to_string()])
    .bind(crate::auth::DEFAULT_ROLLING_WINDOW_SECONDS)
    .bind(crate::auth::DEFAULT_MAX_ROLLING_EXECUTION_FEE_USD)
    .bind(crate::auth::DEFAULT_MAX_SPONSORED_GAS_UNITS)
    .bind(crate::auth::DEFAULT_MAX_ROLLING_SPONSORED_GAS_UNITS)
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

pub struct CreateOwnerPasskeyEnrollmentOptions<'a> {
    pub token_hash: &'a str,
    pub label: &'a str,
    pub purpose: &'a str,
    pub replaces_passkey_id: Option<Uuid>,
    pub expires_at: DateTime<Utc>,
}

pub async fn create_owner_passkey_enrollment_request(
    pool: &PgPool,
    context: &AuthContext,
    options: CreateOwnerPasskeyEnrollmentOptions<'_>,
) -> Result<OwnerPasskeyEnrollmentRequestRow> {
    if context.credential_kind != CredentialKind::OAuthSession {
        anyhow::bail!("passkey enrollment requires an owner OAuth session");
    }
    validate_passkey_label_and_purpose(options.label, options.purpose)?;
    validate_secret_hash(options.token_hash, "passkey enrollment token")?;
    if options.expires_at <= Utc::now() {
        anyhow::bail!("passkey enrollment expiry must be in the future");
    }
    let mut transaction = pool.begin().await?;
    lock_owner_account_tx(
        &mut transaction,
        context.organization_id,
        context.principal_id,
    )
    .await?;
    let connection_active: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM oauth_connections c
               JOIN owner_accounts oa ON oa.principal_id = c.principal_id
               JOIN principals p ON p.id = c.principal_id AND p.status = 'active'
               JOIN organizations o ON o.id = c.organization_id AND o.status = 'active'
               WHERE c.id = $1 AND c.organization_id = $2 AND c.principal_id = $3
                 AND c.status = 'active'
           )"#,
    )
    .bind(context.credential_id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .fetch_one(&mut *transaction)
    .await?;
    if !connection_active {
        anyhow::bail!("active owner connection was not found");
    }
    sqlx::query(
        r#"UPDATE owner_passkey_enrollment_requests SET status = 'expired'
           WHERE organization_id = $1 AND principal_id = $2
             AND status = 'pending' AND expires_at <= now()"#,
    )
    .bind(context.organization_id)
    .bind(context.principal_id)
    .execute(&mut *transaction)
    .await?;
    let duplicate_label: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM owner_passkeys
               WHERE organization_id = $1 AND principal_id = $2
                 AND status = 'active' AND lower(label) = lower($3)
                 AND id IS DISTINCT FROM $4
           )"#,
    )
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(options.label.trim())
    .bind(options.replaces_passkey_id)
    .fetch_one(&mut *transaction)
    .await?;
    if duplicate_label {
        anyhow::bail!("an active passkey already uses this label");
    }
    if let Some(replaced_id) = options.replaces_passkey_id {
        let replaced: String = sqlx::query_scalar(
            r#"SELECT purpose FROM owner_passkeys
               WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                 AND status = 'active'"#,
        )
        .bind(replaced_id)
        .bind(context.organization_id)
        .bind(context.principal_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("replacement target is not an active owner passkey"))?;
        if replaced == "recovery" && options.purpose != "recovery" {
            let recovery_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM owner_passkeys
                   WHERE organization_id = $1 AND principal_id = $2
                     AND status = 'active' AND purpose = 'recovery'"#,
            )
            .bind(context.organization_id)
            .bind(context.principal_id)
            .fetch_one(&mut *transaction)
            .await?;
            if recovery_count <= 1 {
                anyhow::bail!(
                    "the final recovery passkey must be replaced by another recovery passkey"
                );
            }
        }
    }
    let request = sqlx::query_as::<_, OwnerPasskeyEnrollmentRequestRow>(
        r#"INSERT INTO owner_passkey_enrollment_requests (
               id, organization_id, principal_id, oauth_connection_id,
               token_hash, label, purpose, replaces_passkey_id, expires_at
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING *"#,
    )
    .bind(Uuid::new_v4())
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(context.credential_id)
    .bind(options.token_hash)
    .bind(options.label.trim())
    .bind(options.purpose)
    .bind(options.replaces_passkey_id)
    .bind(options.expires_at)
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(request)
}

pub async fn get_owner_passkey_enrollment_request(
    pool: &PgPool,
    context: &AuthContext,
    id: Uuid,
) -> Result<Option<OwnerPasskeyEnrollmentRequestRow>> {
    sqlx::query(
        r#"UPDATE owner_passkey_enrollment_requests SET status = 'expired'
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'pending' AND expires_at <= now()"#,
    )
    .bind(id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .execute(pool)
    .await?;
    Ok(sqlx::query_as::<_, OwnerPasskeyEnrollmentRequestRow>(
        r#"SELECT * FROM owner_passkey_enrollment_requests
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3"#,
    )
    .bind(id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .fetch_optional(pool)
    .await?)
}

pub fn validate_passkey_label_and_purpose(label: &str, purpose: &str) -> Result<()> {
    let label = label.trim();
    if !(1..=80).contains(&label.len()) || label.chars().any(char::is_control) {
        anyhow::bail!("passkey label must contain 1-80 characters without control characters");
    }
    if !matches!(purpose, "standard" | "recovery") {
        anyhow::bail!("passkey purpose must be standard or recovery");
    }
    Ok(())
}

pub async fn authenticate_owner_passkey_enrollment(
    pool: &PgPool,
    request_id: Uuid,
    passkey_id: Uuid,
    updated_passkey: &serde_json::Value,
) -> Result<OwnerPasskeyEnrollmentRequestRow> {
    let mut transaction = pool.begin().await?;
    let request = sqlx::query_as::<_, OwnerPasskeyEnrollmentRequestRow>(
        r#"SELECT * FROM owner_passkey_enrollment_requests
           WHERE id = $1 AND status = 'pending' AND expires_at > now()
           FOR UPDATE"#,
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("passkey enrollment is expired or no longer available"))?;
    let updated = sqlx::query(
        r#"UPDATE owner_passkeys SET passkey = $4, last_used_at = now(), updated_at = now()
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'active'"#,
    )
    .bind(passkey_id)
    .bind(request.organization_id)
    .bind(request.principal_id)
    .bind(updated_passkey)
    .execute(&mut *transaction)
    .await?;
    if updated.rows_affected() != 1 {
        anyhow::bail!("authenticated passkey is not active for this owner");
    }
    let request = sqlx::query_as::<_, OwnerPasskeyEnrollmentRequestRow>(
        r#"UPDATE owner_passkey_enrollment_requests
           SET authenticated_by_passkey_id = $2
           WHERE id = $1 AND status = 'pending'
             AND (
                 authenticated_by_passkey_id IS NULL
                 OR authenticated_by_passkey_id = $2
             )
           RETURNING *"#,
    )
    .bind(request_id)
    .bind(passkey_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| {
        anyhow::anyhow!("passkey enrollment is already authenticated by another owner passkey")
    })?;
    transaction.commit().await?;
    Ok(request)
}

pub struct CompleteOwnerPasskeyEnrollmentOptions<'a> {
    pub request_id: Uuid,
    pub authenticated_by_passkey_id: Uuid,
    pub new_passkey_id: Uuid,
    pub credential_id: &'a str,
    pub passkey: &'a serde_json::Value,
    pub turnkey_recovery_credential: &'a serde_json::Value,
}

pub async fn complete_owner_passkey_enrollment(
    pool: &PgPool,
    options: CompleteOwnerPasskeyEnrollmentOptions<'_>,
) -> Result<serde_json::Value> {
    if options.credential_id.trim().is_empty() || options.credential_id.len() > 1024 {
        anyhow::bail!("new passkey credential ID is invalid");
    }
    let mut transaction = pool.begin().await?;
    let owner: (Uuid, Uuid) = sqlx::query_as(
        r#"SELECT organization_id, principal_id
           FROM owner_passkey_enrollment_requests
           WHERE id = $1 AND status = 'pending' AND expires_at > now()"#,
    )
    .bind(options.request_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("passkey enrollment is expired or no longer available"))?;
    lock_owner_account_tx(&mut transaction, owner.0, owner.1).await?;
    let request = sqlx::query_as::<_, OwnerPasskeyEnrollmentRequestRow>(
        r#"SELECT * FROM owner_passkey_enrollment_requests
           WHERE id = $1 AND status = 'pending' AND expires_at > now()
           FOR UPDATE"#,
    )
    .bind(options.request_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("passkey enrollment is expired or no longer available"))?;
    if request.authenticated_by_passkey_id != Some(options.authenticated_by_passkey_id) {
        anyhow::bail!("passkey enrollment was not authenticated by the expected owner passkey");
    }
    let approving_active = sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM owner_passkeys
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'active'
           FOR UPDATE"#,
    )
    .bind(options.authenticated_by_passkey_id)
    .bind(request.organization_id)
    .bind(request.principal_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if approving_active.is_none() {
        anyhow::bail!("authenticating owner passkey is no longer active");
    }
    let mut revoked_connections = 0;
    if let Some(replaced_id) = request.replaces_passkey_id {
        let replaced_purpose: String = sqlx::query_scalar(
            r#"SELECT purpose FROM owner_passkeys
               WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                 AND status = 'active' FOR UPDATE"#,
        )
        .bind(replaced_id)
        .bind(request.organization_id)
        .bind(request.principal_id)
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or_else(|| anyhow::anyhow!("replacement target is no longer active"))?;
        if replaced_purpose == "recovery" && request.purpose != "recovery" {
            let recovery_count: i64 = sqlx::query_scalar(
                r#"SELECT COUNT(*) FROM owner_passkeys
                   WHERE organization_id = $1 AND principal_id = $2
                     AND status = 'active' AND purpose = 'recovery'"#,
            )
            .bind(request.organization_id)
            .bind(request.principal_id)
            .fetch_one(&mut *transaction)
            .await?;
            if recovery_count <= 1 {
                anyhow::bail!("replacement would remove the final recovery passkey");
            }
        }
        sqlx::query(
            r#"UPDATE owner_passkeys
               SET status = 'revoked', revoked_by_passkey_id = $2,
                   revoked_at = now(), updated_at = now()
               WHERE id = $1 AND status = 'active'"#,
        )
        .bind(replaced_id)
        .bind(options.authenticated_by_passkey_id)
        .execute(&mut *transaction)
        .await?;
        revoked_connections = revoke_owner_sessions_tx(
            &mut transaction,
            request.organization_id,
            request.principal_id,
            replaced_id,
        )
        .await?;
        sqlx::query(
            r#"UPDATE owner_approval_requests SET status = 'expired'
               WHERE organization_id = $1 AND principal_id = $2 AND status = 'pending'"#,
        )
        .bind(request.organization_id)
        .bind(request.principal_id)
        .execute(&mut *transaction)
        .await?;
    }
    sqlx::query(
        r#"INSERT INTO owner_passkeys (
               id, organization_id, principal_id, credential_id, passkey,
               turnkey_recovery_credential, label, purpose, created_by_passkey_id
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(options.new_passkey_id)
    .bind(request.organization_id)
    .bind(request.principal_id)
    .bind(options.credential_id)
    .bind(options.passkey)
    .bind(options.turnkey_recovery_credential)
    .bind(&request.label)
    .bind(&request.purpose)
    .bind(options.authenticated_by_passkey_id)
    .execute(&mut *transaction)
    .await?;
    let completed = sqlx::query(
        r#"UPDATE owner_passkey_enrollment_requests
           SET status = 'completed', created_passkey_id = $2,
               completed_at = now()
           WHERE id = $1 AND status = 'pending'"#,
    )
    .bind(request.id)
    .bind(options.new_passkey_id)
    .execute(&mut *transaction)
    .await?;
    if completed.rows_affected() != 1 {
        anyhow::bail!("passkey enrollment changed before completion");
    }
    let action = if request.replaces_passkey_id.is_some() {
        "owner_passkey:replaced"
    } else {
        "owner_passkey:added"
    };
    sqlx::query(
        r#"INSERT INTO auth_audit_events (
               id, organization_id, principal_id, credential_id, credential_kind,
               action, resource, decision, details
           ) VALUES ($1, $2, $3, $4, 'oauth_session', $5, $6, 'allow', $7)"#,
    )
    .bind(Uuid::new_v4())
    .bind(request.organization_id)
    .bind(request.principal_id)
    .bind(request.oauth_connection_id)
    .bind(action)
    .bind("/passkeys/enroll")
    .bind(serde_json::json!({
        "enrollment_request_id": request.id,
        "new_passkey_id": options.new_passkey_id,
        "purpose": request.purpose,
        "replaced_passkey_id": request.replaces_passkey_id,
        "authenticated_by_passkey_id": options.authenticated_by_passkey_id,
        "revoked_connections": revoked_connections
    }))
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(serde_json::json!({
        "passkey_id": options.new_passkey_id,
        "label": request.label,
        "purpose": request.purpose,
        "replaced_passkey_id": request.replaces_passkey_id,
        "revoked_connections": revoked_connections
    }))
}

async fn validate_owner_passkey_removal(
    pool: &PgPool,
    organization_id: Uuid,
    principal_id: Uuid,
    passkey_id: Uuid,
) -> Result<()> {
    let purpose: String = sqlx::query_scalar(
        r#"SELECT purpose FROM owner_passkeys
           WHERE id = $1 AND organization_id = $2 AND principal_id = $3
             AND status = 'active'"#,
    )
    .bind(passkey_id)
    .bind(organization_id)
    .bind(principal_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("active owner passkey was not found"))?;
    let active_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM owner_passkeys
           WHERE organization_id = $1 AND principal_id = $2 AND status = 'active'"#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_one(pool)
    .await?;
    if active_count <= 1 {
        anyhow::bail!("the final active owner passkey cannot be revoked");
    }
    if purpose == "recovery" {
        let recovery_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM owner_passkeys
               WHERE organization_id = $1 AND principal_id = $2
                 AND status = 'active' AND purpose = 'recovery'"#,
        )
        .bind(organization_id)
        .bind(principal_id)
        .fetch_one(pool)
        .await?;
        if recovery_count <= 1 {
            anyhow::bail!("the final recovery passkey cannot be revoked");
        }
    }
    Ok(())
}

async fn lock_owner_account_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    principal_id: Uuid,
) -> Result<()> {
    sqlx::query_scalar::<_, Uuid>(
        r#"SELECT oa.principal_id FROM owner_accounts oa
           JOIN principals p ON p.id = oa.principal_id AND p.status = 'active'
           JOIN organizations o ON o.id = oa.organization_id AND o.status = 'active'
           WHERE oa.principal_id = $1 AND oa.organization_id = $2
           FOR UPDATE OF oa"#,
    )
    .bind(principal_id)
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("active owner account was not found"))?;
    Ok(())
}

async fn validate_owner_passkey_removal_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    principal_id: Uuid,
    passkey_id: Uuid,
    purpose: &str,
) -> Result<()> {
    let active_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM owner_passkeys
           WHERE organization_id = $1 AND principal_id = $2 AND status = 'active'"#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .fetch_one(&mut **transaction)
    .await?;
    if active_count <= 1 {
        anyhow::bail!("the final active owner passkey cannot be revoked");
    }
    if purpose == "recovery" {
        let recovery_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM owner_passkeys
               WHERE organization_id = $1 AND principal_id = $2
                 AND status = 'active' AND purpose = 'recovery'"#,
        )
        .bind(organization_id)
        .bind(principal_id)
        .fetch_one(&mut **transaction)
        .await?;
        if recovery_count <= 1 {
            anyhow::bail!("the final recovery passkey cannot be revoked");
        }
    }
    let target_active: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM owner_passkeys
               WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                 AND status = 'active'
           )"#,
    )
    .bind(passkey_id)
    .bind(organization_id)
    .bind(principal_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !target_active {
        anyhow::bail!("owner passkey is no longer active");
    }
    Ok(())
}

async fn revoke_owner_sessions_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    principal_id: Uuid,
    revoked_passkey_id: Uuid,
) -> Result<u64> {
    let revoked = sqlx::query(
        r#"UPDATE oauth_connections
           SET status = 'revoked', revoked_at = now(), updated_at = now()
           WHERE organization_id = $1 AND principal_id = $2 AND status = 'active'
             AND passkey_id = $3"#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(revoked_passkey_id)
    .execute(&mut **transaction)
    .await?
    .rows_affected();
    sqlx::query(
        r#"UPDATE oauth_authorization_codes SET used_at = now()
           WHERE organization_id = $1 AND principal_id = $2 AND passkey_id = $3
             AND used_at IS NULL"#,
    )
    .bind(organization_id)
    .bind(principal_id)
    .bind(revoked_passkey_id)
    .execute(&mut **transaction)
    .await?;
    Ok(revoked)
}

fn validate_secret_hash(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        anyhow::bail!("{label} hash is invalid");
    }
    Ok(())
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
        max_value_wei: Option<String>,
        max_execution_fee_usd: Option<f64>,
        token_spend_limits: serde_json::Value,
        risk_permissions: Vec<String>,
        rolling_window_seconds: i64,
        max_rolling_execution_fee_usd: Option<f64>,
        max_sponsored_gas_units: Option<i64>,
        max_rolling_sponsored_gas_units: Option<i64>,
        max_borrowed_value_usd: Option<f64>,
        max_rolling_borrowed_value_usd: Option<f64>,
    },
    UpdatePolicy {
        policy_id: Uuid,
        expected_version: i64,
        name: String,
        allowed_chains: Option<Vec<String>>,
        allowed_protocols: Option<Vec<String>>,
        allowed_actions: Option<Vec<String>>,
        allowed_targets: Option<Vec<String>>,
        max_value_wei: Option<String>,
        max_execution_fee_usd: Option<f64>,
        token_spend_limits: serde_json::Value,
        risk_permissions: Vec<String>,
        rolling_window_seconds: i64,
        max_rolling_execution_fee_usd: Option<f64>,
        max_sponsored_gas_units: Option<i64>,
        max_rolling_sponsored_gas_units: Option<i64>,
        max_borrowed_value_usd: Option<f64>,
        max_rolling_borrowed_value_usd: Option<f64>,
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
    RevokeOwnerPasskey {
        passkey_id: Uuid,
        expected_credential_id: String,
    },
    ConnectCircleAgentWallet {
        challenge_id: Uuid,
        agent_id: Uuid,
        chain: String,
        wallet_address: String,
        ownership_signature: String,
    },
    RevokeExternalWallet {
        connection_id: Uuid,
    },
    CreatePaymentPlan {
        plan: crate::workflows::NormalizedPaymentPlan,
    },
    UpdatePaymentPlan {
        plan_id: Uuid,
        expected_version: i64,
        plan: crate::workflows::NormalizedPaymentPlan,
    },
    ChangePaymentPlanStatus {
        plan_id: Uuid,
        expected_version: i64,
        change: crate::workflows::PaymentPlanStatusChange,
    },
}

impl OwnerApprovalAction {
    fn kind(&self) -> &'static str {
        match self {
            Self::CreatePolicy { .. } => "create_policy",
            Self::UpdatePolicy { .. } => "update_policy",
            Self::AssignPolicy { .. } => "assign_policy",
            Self::RevokePolicy { .. } => "revoke_policy",
            Self::CreateAgent { .. } => "create_agent",
            Self::SuspendAgent { .. } => "suspend_agent",
            Self::ReactivateAgent { .. } => "reactivate_agent",
            Self::RotateAgentCredential { .. } => "rotate_agent_credential",
            Self::RotateAgentOnchainSigner { .. } => "rotate_agent_onchain_signer",
            Self::RevokeOwnerPasskey { .. } => "revoke_owner_passkey",
            Self::ConnectCircleAgentWallet { .. } => "connect_circle_agent_wallet",
            Self::RevokeExternalWallet { .. } => "revoke_external_wallet",
            Self::CreatePaymentPlan { .. } => "create_payment_plan",
            Self::UpdatePaymentPlan { .. } => "update_payment_plan",
            Self::ChangePaymentPlanStatus { .. } => "change_payment_plan_status",
        }
    }

    pub fn validate(&self, expected_chain: &str) -> Result<()> {
        if let Self::UpdatePolicy {
            expected_version, ..
        } = self
        {
            if *expected_version <= 0 {
                anyhow::bail!("expected policy version must be positive");
            }
        }
        if let Self::UpdatePaymentPlan {
            expected_version, ..
        }
        | Self::ChangePaymentPlanStatus {
            expected_version, ..
        } = self
        {
            if *expected_version <= 0 {
                anyhow::bail!("expected payment-plan version must be positive");
            }
        }
        match self {
            Self::CreatePolicy {
                name,
                allowed_chains,
                allowed_protocols,
                allowed_actions,
                allowed_targets,
                max_value_wei,
                max_execution_fee_usd,
                token_spend_limits,
                risk_permissions,
                rolling_window_seconds,
                max_rolling_execution_fee_usd,
                max_sponsored_gas_units,
                max_rolling_sponsored_gas_units,
                max_borrowed_value_usd,
                max_rolling_borrowed_value_usd,
                ..
            }
            | Self::UpdatePolicy {
                name,
                allowed_chains,
                allowed_protocols,
                allowed_actions,
                allowed_targets,
                max_value_wei,
                max_execution_fee_usd,
                token_spend_limits,
                risk_permissions,
                rolling_window_seconds,
                max_rolling_execution_fee_usd,
                max_sponsored_gas_units,
                max_rolling_sponsored_gas_units,
                max_borrowed_value_usd,
                max_rolling_borrowed_value_usd,
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
                    && token_spend_limits == &serde_json::json!([])
                    && risk_permissions.is_empty()
                    && max_rolling_execution_fee_usd.is_none()
                    && max_sponsored_gas_units.is_none()
                    && max_rolling_sponsored_gas_units.is_none()
                    && max_borrowed_value_usd.is_none()
                    && max_rolling_borrowed_value_usd.is_none()
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
                        target != "*" && target.parse::<ethers_core::types::Address>().is_err()
                    })
                }) {
                    anyhow::bail!("allowed_targets must contain EVM addresses or *");
                }
                if max_value_wei
                    .as_deref()
                    .is_some_and(|value| value.parse::<ethers_core::types::U256>().is_err())
                {
                    anyhow::bail!("max_value_wei must be an unsigned decimal integer");
                }
                if max_execution_fee_usd.is_some_and(|value| !value.is_finite() || value < 0.0) {
                    anyhow::bail!("max_execution_fee_usd must be a non-negative finite number");
                }
                crate::policy::validate_token_spend_limits(token_spend_limits)?;
                crate::policy::validate_risk_permissions(risk_permissions)?;
                if !(60..=2_678_400).contains(rolling_window_seconds) {
                    anyhow::bail!("rolling_window_seconds must be between 60 and 2678400");
                }
                validate_policy_usd_limit(
                    "max_rolling_execution_fee_usd",
                    *max_rolling_execution_fee_usd,
                )?;
                validate_policy_usd_limit("max_borrowed_value_usd", *max_borrowed_value_usd)?;
                validate_policy_usd_limit(
                    "max_rolling_borrowed_value_usd",
                    *max_rolling_borrowed_value_usd,
                )?;
                if max_sponsored_gas_units.is_some_and(|value| value <= 0)
                    || max_rolling_sponsored_gas_units.is_some_and(|value| value <= 0)
                {
                    anyhow::bail!("sponsored gas limits must be positive");
                }
                if let (Some(per_execution), Some(rolling)) =
                    (max_execution_fee_usd, max_rolling_execution_fee_usd)
                {
                    if rolling < per_execution {
                        anyhow::bail!(
                            "rolling execution-fee limit is below the per-execution limit"
                        );
                    }
                }
                if let (Some(per_execution), Some(rolling)) =
                    (max_sponsored_gas_units, max_rolling_sponsored_gas_units)
                {
                    if rolling < per_execution {
                        anyhow::bail!(
                            "rolling sponsored-gas limit is below the per-execution limit"
                        );
                    }
                }
                if let (Some(per_execution), Some(rolling)) =
                    (max_borrowed_value_usd, max_rolling_borrowed_value_usd)
                {
                    if rolling < per_execution {
                        anyhow::bail!(
                            "rolling borrowed-value limit is below the per-execution limit"
                        );
                    }
                }
                let executes = allowed_actions.as_ref().is_some_and(|actions| {
                    actions
                        .iter()
                        .any(|action| action == "*" || action == "payment_plan:execute")
                });
                if executes
                    && (max_execution_fee_usd.is_none()
                        || max_rolling_execution_fee_usd.is_none()
                        || max_sponsored_gas_units.is_none()
                        || max_rolling_sponsored_gas_units.is_none())
                {
                    anyhow::bail!(
                        "execution policies require per-execution and rolling fee/gas limits"
                    );
                }
                if allowed_actions.as_ref().is_some_and(|actions| {
                    actions
                        .iter()
                        .any(|action| action == "*" || action == "payment_plan:execute")
                }) && crate::policy::validate_token_spend_limits(token_spend_limits)?.is_empty()
                {
                    anyhow::bail!("payment-plan execution requires at least one token spend limit");
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
                    .parse::<ethers_core::types::Address>()
                    .map_err(|_| anyhow::anyhow!("expected smart-account address is invalid"))?;
                if account == ethers_core::types::Address::zero() {
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
            Self::RevokeOwnerPasskey {
                expected_credential_id,
                ..
            } => {
                if expected_credential_id.trim().is_empty() || expected_credential_id.len() > 1024 {
                    anyhow::bail!("expected passkey credential ID is invalid");
                }
            }
            Self::ConnectCircleAgentWallet {
                chain,
                wallet_address,
                ownership_signature,
                ..
            } => {
                if chain != expected_chain {
                    anyhow::bail!("Circle wallet connection targets the wrong Arc network");
                }
                let address = wallet_address
                    .parse::<ethers_core::types::Address>()
                    .map_err(|_| anyhow::anyhow!("Circle wallet address is invalid"))?;
                if address == ethers_core::types::Address::zero()
                    || !ownership_signature.starts_with("0x")
                    || ownership_signature.len() < 4
                    || ownership_signature.len() > 8194
                    || ownership_signature.len() % 2 != 0
                    || !ownership_signature[2..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
                {
                    anyhow::bail!("Circle wallet connection proof is invalid");
                }
            }
            Self::RevokeExternalWallet { .. } => {}
            Self::CreatePaymentPlan { plan } | Self::UpdatePaymentPlan { plan, .. } => {
                plan.validate()?;
                if plan.recipients.iter().any(|recipient| {
                    recipient
                        .verification
                        .as_ref()
                        .is_none_or(|verification| verification.chain != expected_chain)
                }) || plan
                    .surplus_verification
                    .as_ref()
                    .is_some_and(|verification| verification.chain != expected_chain)
                {
                    anyhow::bail!("payment recipient verification targets the wrong Arc network");
                }
            }
            Self::ChangePaymentPlanStatus { .. } => {}
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

fn validate_policy_usd_limit(name: &str, value: Option<f64>) -> Result<()> {
    if value.is_some_and(|value| !value.is_finite() || !(0.0..=1_000_000_000.0).contains(&value)) {
        anyhow::bail!("{name} must be a finite value between 0 and 1000000000");
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
    match (&parent.max_value_wei, &child.max_value_wei) {
        (Some(_), None) => anyhow::bail!("child policy must retain the parent native-value limit"),
        (Some(parent), Some(child))
            if child.parse::<ethers_core::types::U256>()?
                > parent.parse::<ethers_core::types::U256>()? =>
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
    if !policy_values_are_subset(
        Some(&child.risk_permissions),
        Some(&parent.risk_permissions),
        false,
    ) {
        anyhow::bail!("child policy enables a risk denied by its parent");
    }
    if child.rolling_window_seconds < parent.rolling_window_seconds {
        anyhow::bail!("child policy cannot shorten the parent rolling window");
    }
    validate_delegated_optional_limit(
        "rolling execution-fee",
        parent.max_rolling_execution_fee_usd,
        child.max_rolling_execution_fee_usd,
    )?;
    validate_delegated_optional_limit(
        "borrowed-value",
        parent.max_borrowed_value_usd,
        child.max_borrowed_value_usd,
    )?;
    validate_delegated_optional_limit(
        "rolling borrowed-value",
        parent.max_rolling_borrowed_value_usd,
        child.max_rolling_borrowed_value_usd,
    )?;
    validate_delegated_optional_limit(
        "sponsored-gas",
        parent.max_sponsored_gas_units,
        child.max_sponsored_gas_units,
    )?;
    validate_delegated_optional_limit(
        "rolling sponsored-gas",
        parent.max_rolling_sponsored_gas_units,
        child.max_rolling_sponsored_gas_units,
    )?;

    let parent_tokens = crate::policy::validate_token_spend_limits(&parent.token_spend_limits)?;
    let child_tokens = crate::policy::validate_token_spend_limits(&child.token_spend_limits)?;
    for child_limit in child_tokens {
        let parent_limit = parent_tokens
            .iter()
            .find(|limit| limit.token.eq_ignore_ascii_case(&child_limit.token))
            .or_else(|| parent_tokens.iter().find(|limit| limit.token == "*"))
            .ok_or_else(|| anyhow::anyhow!("child policy adds token-spend authority"))?;
        if child_limit
            .max_per_execution_raw
            .parse::<ethers_core::types::U256>()?
            > parent_limit
                .max_per_execution_raw
                .parse::<ethers_core::types::U256>()?
            || child_limit
                .max_rolling_raw
                .parse::<ethers_core::types::U256>()?
                > parent_limit
                    .max_rolling_raw
                    .parse::<ethers_core::types::U256>()?
        {
            anyhow::bail!("child policy exceeds a parent token-spend limit");
        }
    }
    Ok(())
}

fn validate_delegated_optional_limit<T>(
    name: &str,
    parent: Option<T>,
    child: Option<T>,
) -> Result<()>
where
    T: PartialOrd + Copy,
{
    match (parent, child) {
        (Some(_), None) => anyhow::bail!("child policy must retain the parent {name} limit"),
        (Some(parent), Some(child)) if child > parent => {
            anyhow::bail!("child policy exceeds the parent {name} limit")
        }
        _ => Ok(()),
    }
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
    let (OwnerApprovalAction::CreatePolicy {
        allowed_chains,
        allowed_protocols,
        allowed_actions,
        allowed_targets,
        max_value_wei,
        max_execution_fee_usd,
        ..
    }
    | OwnerApprovalAction::UpdatePolicy {
        allowed_chains,
        allowed_protocols,
        allowed_actions,
        allowed_targets,
        max_value_wei,
        max_execution_fee_usd,
        ..
    }) = action
    else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
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
    if let OwnerApprovalAction::CreatePolicy {
        token_spend_limits,
        risk_permissions,
        max_rolling_execution_fee_usd,
        max_sponsored_gas_units,
        max_rolling_sponsored_gas_units,
        ..
    }
    | OwnerApprovalAction::UpdatePolicy {
        token_spend_limits,
        risk_permissions,
        max_rolling_execution_fee_usd,
        max_sponsored_gas_units,
        max_rolling_sponsored_gas_units,
        ..
    } = action
    {
        if token_spend_limits == &serde_json::json!([]) {
            warnings.push("Denies all token spending");
        }
        if !risk_permissions.is_empty() {
            warnings.push("Enables explicitly listed high-risk actions");
        }
        if max_rolling_execution_fee_usd.is_none() {
            warnings.push("Does not set a rolling execution-fee limit");
        }
        if max_sponsored_gas_units.is_none() || max_rolling_sponsored_gas_units.is_none() {
            warnings.push("Does not fully limit sponsored gas");
        }
    }
    warnings
}

fn approval_agent_summary(agent: &AgentRow) -> serde_json::Value {
    serde_json::json!({
        "name": agent.display_name,
        "agent": agent.external_id,
        "status": agent.status
    })
}

fn approval_policy_summary(policy: &AuthorizationPolicyRow) -> serde_json::Value {
    policy_summary(
        &policy.name,
        policy.allowed_chains.as_deref(),
        policy.allowed_actions.as_deref(),
        &policy.token_spend_limits,
        &policy.risk_permissions,
        policy.rolling_window_seconds,
        policy.max_execution_fee_usd,
    )
}

fn approval_policy_action_summary(action: &OwnerApprovalAction) -> serde_json::Value {
    let (OwnerApprovalAction::CreatePolicy {
        name,
        allowed_chains,
        allowed_actions,
        token_spend_limits,
        risk_permissions,
        rolling_window_seconds,
        max_execution_fee_usd,
        ..
    }
    | OwnerApprovalAction::UpdatePolicy {
        name,
        allowed_chains,
        allowed_actions,
        token_spend_limits,
        risk_permissions,
        rolling_window_seconds,
        max_execution_fee_usd,
        ..
    }) = action
    else {
        return serde_json::Value::Null;
    };
    policy_summary(
        name,
        allowed_chains.as_deref(),
        allowed_actions.as_deref(),
        token_spend_limits,
        risk_permissions,
        *rolling_window_seconds,
        *max_execution_fee_usd,
    )
}

fn policy_summary(
    name: &str,
    chains: Option<&[String]>,
    actions: Option<&[String]>,
    token_limits: &serde_json::Value,
    risks: &[String],
    rolling_window_seconds: i64,
    max_execution_fee_usd: Option<f64>,
) -> serde_json::Value {
    let limits = crate::policy::validate_token_spend_limits(token_limits).unwrap_or_default();
    let usdc = limits.iter().find(|limit| {
        limit.token == "*"
            || limit
                .token
                .eq_ignore_ascii_case(crate::policy::ARC_USDC_ADDRESS)
    });
    serde_json::json!({
        "policy": name,
        "network": chains.map(|values| values.iter().map(|value| match value.as_str() {
            "arc-testnet" => "Arc Testnet".to_string(),
            "arc" => "Arc".to_string(),
            other => other.to_string()
        }).collect::<Vec<_>>().join(", ")).unwrap_or_else(|| "Any network".into()),
        "abilities": actions.map(|values| values.iter().map(|value| human_policy_action(value)).collect::<Vec<_>>()).unwrap_or_else(|| vec!["Any action".into()]),
        "per_payment_limit": usdc.map(|limit| format!("{} USDC", format_usdc_raw(&limit.max_per_execution_raw))),
        "rolling_limit": usdc.map(|limit| format!("{} USDC every {}", format_usdc_raw(&limit.max_rolling_raw), human_duration(rolling_window_seconds))),
        "maximum_execution_fee": max_execution_fee_usd.map(|value| format!("${value:.2}")),
        "sensitive_permissions": if risks.is_empty() { serde_json::Value::String("None".into()) } else { serde_json::json!(risks.iter().map(|value| human_policy_action(value)).collect::<Vec<_>>()) }
    })
}

fn human_policy_action(value: &str) -> String {
    match value {
        "*" => "All actions".into(),
        "payment_plan:execute" => "Run scheduled payments".into(),
        "wallet:read" => "View wallet and balances".into(),
        "workflow:read" => "View payment plans and runs".into(),
        "workflow:manage" => "Manage payment plans".into(),
        "external_withdrawal" => "Pay external recipients".into(),
        other => other.replace(['_', ':'], " "),
    }
}

fn approval_payment_plan_summary(
    plan: &crate::workflows::NormalizedPaymentPlan,
) -> serde_json::Value {
    let recipients = plan
        .recipients
        .iter()
        .map(|recipient| {
            let verification = recipient.verification.as_ref();
            serde_json::json!({
                "name": recipient.name.as_deref().unwrap_or("Unnamed recipient"),
                "address": recipient.address,
                "amount": format!("{} USDC", format_usdc_raw(&recipient.amount_raw)),
                "verified": verification.map(|value| format!("Verified {} on {}", value.address_kind, value.chain))
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "plan": plan.name,
        "agent": plan.agent_id,
        "schedule": human_schedule(&plan.schedule),
        "recipients": recipients,
        "wallet_reserve": format!("{} USDC", format_usdc_raw(&plan.reserve_raw)),
        "address_check": "Observed on Arc. Recipient names are owner-provided and do not prove identity.",
        "surplus_rule": plan.surplus.as_ref().map(|surplus| format!(
            "Send available balance above the reserve to {} when at least {} USDC is available",
            surplus.destination,
            format_usdc_raw(&surplus.minimum_transfer_raw)
        ))
    })
}

fn human_schedule(schedule: &crate::workflows::PaymentSchedule) -> String {
    match schedule.cadence {
        crate::workflows::ScheduleCadence::Daily => {
            format!(
                "Every day at {} ({})",
                schedule.local_time, schedule.timezone
            )
        }
        crate::workflows::ScheduleCadence::Weekly => format!(
            "Every {} at {} ({})",
            schedule.weekday.as_deref().unwrap_or("week"),
            schedule.local_time,
            schedule.timezone
        ),
        crate::workflows::ScheduleCadence::Monthly => format!(
            "Day {} of every month at {} ({})",
            schedule.day_of_month.unwrap_or_default(),
            schedule.local_time,
            schedule.timezone
        ),
    }
}

fn human_duration(seconds: i64) -> String {
    if seconds % 86_400 == 0 {
        let value = seconds / 86_400;
        format!("{value} day{}", if value == 1 { "" } else { "s" })
    } else if seconds % 3_600 == 0 {
        let value = seconds / 3_600;
        format!("{value} hour{}", if value == 1 { "" } else { "s" })
    } else if seconds % 60 == 0 {
        let value = seconds / 60;
        format!("{value} minute{}", if value == 1 { "" } else { "s" })
    } else {
        format!("{seconds} seconds")
    }
}

fn format_usdc_raw(raw: &str) -> String {
    ethers_core::utils::format_units(
        ethers_core::types::U256::from_dec_str(raw).unwrap_or_default(),
        crate::workflows::USDC_DECIMALS as usize,
    )
    .unwrap_or_else(|_| raw.to_string())
}

fn proposed_policy_update(
    current: &AuthorizationPolicyRow,
    action: &OwnerApprovalAction,
) -> Result<AuthorizationPolicyRow> {
    let OwnerApprovalAction::UpdatePolicy {
        policy_id,
        expected_version,
        name,
        allowed_chains,
        allowed_protocols,
        allowed_actions,
        allowed_targets,
        max_value_wei,
        max_execution_fee_usd,
        token_spend_limits,
        risk_permissions,
        rolling_window_seconds,
        max_rolling_execution_fee_usd,
        max_sponsored_gas_units,
        max_rolling_sponsored_gas_units,
        max_borrowed_value_usd,
        max_rolling_borrowed_value_usd,
    } = action
    else {
        anyhow::bail!("owner approval is not a policy update");
    };
    if current.id != *policy_id || current.version != *expected_version {
        anyhow::bail!("policy changed before the update could be applied");
    }
    let mut proposed = current.clone();
    proposed.name = name.trim().to_owned();
    proposed.version = current
        .version
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("policy version overflow"))?;
    proposed.allowed_chains = allowed_chains.clone();
    proposed.allowed_protocols = allowed_protocols.clone();
    proposed.allowed_actions = allowed_actions.clone();
    proposed.allowed_targets = allowed_targets.clone();
    proposed.max_value_wei = max_value_wei.clone();
    proposed.max_execution_fee_usd = *max_execution_fee_usd;
    proposed.token_spend_limits = token_spend_limits.clone();
    proposed.risk_permissions = risk_permissions.clone();
    proposed.rolling_window_seconds = *rolling_window_seconds;
    proposed.max_rolling_execution_fee_usd = *max_rolling_execution_fee_usd;
    proposed.max_sponsored_gas_units = *max_sponsored_gas_units;
    proposed.max_rolling_sponsored_gas_units = *max_rolling_sponsored_gas_units;
    proposed.max_borrowed_value_usd = *max_borrowed_value_usd;
    proposed.max_rolling_borrowed_value_usd = *max_rolling_borrowed_value_usd;
    proposed.updated_at = Utc::now();
    Ok(proposed)
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

async fn validate_policy_update_assignments(
    pool: &PgPool,
    organization_id: Uuid,
    proposed: &AuthorizationPolicyRow,
) -> Result<()> {
    let parent_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents assigned
           JOIN agents parent ON parent.id = assigned.parent_agent_id
           JOIN authorization_policies ap ON ap.id = parent.policy_id
           WHERE assigned.organization_id = $1 AND assigned.policy_id = $2
             AND assigned.status = 'active' AND parent.status = 'active'
             AND parent.policy_id <> $2 AND ap.is_active = TRUE"#,
    )
    .bind(organization_id)
    .bind(proposed.id)
    .fetch_all(pool)
    .await?;
    for parent_policy in parent_policies {
        validate_delegated_policy(&parent_policy, proposed)?;
    }

    let child_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents assigned
           JOIN agents child ON child.parent_agent_id = assigned.id
           JOIN authorization_policies ap ON ap.id = child.policy_id
           WHERE assigned.organization_id = $1 AND assigned.policy_id = $2
             AND assigned.status = 'active' AND child.status = 'active'
             AND child.policy_id <> $2 AND ap.is_active = TRUE"#,
    )
    .bind(organization_id)
    .bind(proposed.id)
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

async fn validate_policy_update_assignments_tx(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    proposed: &AuthorizationPolicyRow,
) -> Result<()> {
    let parent_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents assigned
           JOIN agents parent ON parent.id = assigned.parent_agent_id
           JOIN authorization_policies ap ON ap.id = parent.policy_id
           WHERE assigned.organization_id = $1 AND assigned.policy_id = $2
             AND assigned.status = 'active' AND parent.status = 'active'
             AND parent.policy_id <> $2 AND ap.is_active = TRUE
           FOR UPDATE OF ap"#,
    )
    .bind(organization_id)
    .bind(proposed.id)
    .fetch_all(&mut **transaction)
    .await?;
    for parent_policy in parent_policies {
        validate_delegated_policy(&parent_policy, proposed)?;
    }

    let child_policies = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT ap.* FROM agents assigned
           JOIN agents child ON child.parent_agent_id = assigned.id
           JOIN authorization_policies ap ON ap.id = child.policy_id
           WHERE assigned.organization_id = $1 AND assigned.policy_id = $2
             AND assigned.status = 'active' AND child.status = 'active'
             AND child.policy_id <> $2 AND ap.is_active = TRUE
           FOR UPDATE OF ap"#,
    )
    .bind(organization_id)
    .bind(proposed.id)
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
    if context.credential_kind != CredentialKind::OAuthSession {
        anyhow::bail!("owner approvals require an owner OAuth session");
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
              AND c.status = 'active'
              AND p.status = 'active' AND o.status = 'active'
        )"#,
    )
    .bind(context.credential_id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .fetch_one(pool)
    .await?;
    if !active_owner_connection {
        anyhow::bail!("active owner connection was not found");
    }

    let presentation = match action {
        OwnerApprovalAction::CreatePolicy { .. } => serde_json::json!({
            "title": "Create authorization policy",
            "summary": "Choose what an agent may do and how much it may spend.",
            "policy": approval_policy_action_summary(action),
            "warnings": policy_risk_warnings(action)
        }),
        OwnerApprovalAction::UpdatePolicy {
            policy_id,
            expected_version,
            ..
        } => {
            let current = get_authorization_policy(pool, context.organization_id, *policy_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("active policy was not found"))?;
            if current.version != *expected_version {
                anyhow::bail!("policy changed before the approval request was created");
            }
            let proposed = proposed_policy_update(&current, action)?;
            validate_policy_update_assignments(pool, context.organization_id, &proposed).await?;
            serde_json::json!({
                "title": "Update authorization policy",
                "summary": "Review the agent's new permissions and spending limits.",
                "current": approval_policy_summary(&current),
                "new_policy": approval_policy_summary(&proposed),
                "warnings": policy_risk_warnings(action),
                "note": "Any unsigned work using the previous policy is cancelled."
            })
        }
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
                "summary": "Change what this agent is allowed to do.",
                "agent": approval_agent_summary(&agent),
                "current": approval_policy_summary(&current),
                "new_policy": approval_policy_summary(&proposed)
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
                "summary": "Remove this policy from future use.",
                "policy": approval_policy_summary(&policy),
                "warning": "This policy will no longer be available for assignment"
            })
        }
        OwnerApprovalAction::CreateAgent {
            external_id,
            display_name,
            parent_agent_id,
            policy_id,
            runtime_scopes: _,
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
                "summary": "Add a new autonomous agent to this organization.",
                "agent": {
                    "agent_id": external_id,
                    "display_name": display_name
                },
                "assigned_policy": approval_policy_summary(&policy),
                "delegated_from": parent.as_ref().and_then(|value| value.get("agent")).and_then(|agent| agent.get("display_name")).cloned(),
                "note": format!("A one-time enrollment link will remain valid for {}.", human_duration(*enrollment_ttl_seconds))
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
                "summary": "Immediately stop this agent from starting new work.",
                "agent": approval_agent_summary(&agent),
                "effects": [
                    "New work and active sessions are blocked",
                    "Delegated child agents are also suspended",
                    "Wallets and funds remain untouched"
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
                "summary": "Allow this agent to work again under its existing policy.",
                "agent": approval_agent_summary(&agent),
                "policy": approval_policy_summary(&policy),
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
                "summary": "Replace this agent's runtime access credential.",
                "agent": approval_agent_summary(&agent),
                "new_access": runtime_scopes,
                "enrollment_link_valid_for": human_duration(*enrollment_ttl_seconds),
                "effects": [
                    "Existing runtime credentials stop working",
                    "A new one-time enrollment link is created",
                    "The wallet signer does not change"
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
                "summary": "Replace the signer controlling this agent's smart account.",
                "wallet": binding.smart_account_address,
                "network": "Arc",
                "effects": [
                    "The wallet address and funds do not change",
                    "The agent pauses until rotation is complete",
                    "The previous signer loses control after confirmation"
                ]
            })
        }
        OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id,
            expected_credential_id,
        } => {
            let passkey: (String, String, String, DateTime<Utc>, Option<DateTime<Utc>>) =
                sqlx::query_as(
                    r#"SELECT label, purpose, credential_id, created_at, last_used_at
                       FROM owner_passkeys
                       WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                         AND status = 'active'"#,
                )
                .bind(passkey_id)
                .bind(context.organization_id)
                .bind(context.principal_id)
                .fetch_optional(pool)
                .await?
                .ok_or_else(|| anyhow::anyhow!("active owner passkey was not found"))?;
            if passkey.2 != *expected_credential_id {
                anyhow::bail!("passkey changed before approval was created");
            }
            validate_owner_passkey_removal(
                pool,
                context.organization_id,
                context.principal_id,
                *passkey_id,
            )
            .await?;
            serde_json::json!({
                "title": "Revoke owner passkey",
                "summary": "Remove this passkey from your Jusso account.",
                "passkey": {
                    "label": passkey.0,
                    "purpose": passkey.1,
                    "last_used_at": passkey.4
                },
                "effects": [
                    "Sessions created with this passkey are signed out",
                    "Pending sensitive changes are cancelled",
                    "Your remaining recovery passkey stays active"
                ]
            })
        }
        OwnerApprovalAction::ConnectCircleAgentWallet {
            challenge_id,
            agent_id,
            chain,
            wallet_address,
            ..
        } => {
            let _connection: (String, DateTime<Utc>) = sqlx::query_as(
                r#"SELECT c.challenge, c.expires_at
                   FROM external_wallet_connection_challenges c
                   JOIN principal_agent_grants pag ON pag.agent_id=c.agent_id
                   JOIN agents a ON a.id=c.agent_id AND a.organization_id=c.organization_id
                   WHERE c.id=$1 AND c.organization_id=$2 AND c.agent_id=$3
                     AND c.created_by_principal_id=$4 AND pag.principal_id=$4
                     AND c.chain=$5 AND c.wallet_address=$6
                     AND c.consumed_at IS NULL AND c.expires_at > now()
                     AND a.status='active'"#,
            )
            .bind(challenge_id)
            .bind(context.organization_id)
            .bind(agent_id)
            .bind(context.principal_id)
            .bind(chain)
            .bind(wallet_address)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Circle wallet proof is invalid or expired"))?;
            let incompatible_plan: bool = sqlx::query_scalar(
                r#"SELECT EXISTS(
                       SELECT 1 FROM payment_plans p
                       WHERE p.organization_id=$1 AND p.agent_id=$2
                         AND p.status <> 'cancelled'
                         AND (p.surplus_destination IS NOT NULL OR
                              (SELECT COUNT(*) FROM payment_plan_recipients r
                               WHERE r.plan_id=p.id) <> 1)
                   )"#,
            )
            .bind(context.organization_id)
            .bind(agent_id)
            .fetch_one(pool)
            .await?;
            if incompatible_plan {
                anyhow::bail!(
                    "Circle Agent Wallet currently requires one-recipient plans without surplus sweeps"
                );
            }
            serde_json::json!({
                "title": "Connect Circle Agent Wallet",
                "summary": "Use this Circle wallet for this agent's scheduled USDC payments.",
                "wallet": {
                    "provider": "Circle Agent Wallet",
                    "address": wallet_address,
                    "network": chain,
                    "ownership": "Verified"
                },
                "effects": [
                    "Circle continues to control signing and key security",
                    "Jusso prepares payments and verifies every receipt",
                    "Both Jusso and Circle spending policies remain active"
                ],
                "note": "Circle payment plans currently support one recipient and no surplus sweep."
            })
        }
        OwnerApprovalAction::RevokeExternalWallet { connection_id } => {
            let connection: (String, String, String) = sqlx::query_as(
                r#"SELECT a.external_id, c.wallet_address, c.chain
                   FROM external_wallet_connections c
                   JOIN agents a ON a.id=c.agent_id AND a.organization_id=c.organization_id
                   JOIN principal_agent_grants pag ON pag.agent_id=a.id
                   WHERE c.id=$1 AND c.organization_id=$2 AND pag.principal_id=$3
                     AND c.status='active'"#,
            )
            .bind(connection_id)
            .bind(context.organization_id)
            .bind(context.principal_id)
            .fetch_optional(pool)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active external wallet connection was not found"))?;
            serde_json::json!({
                "title": "Disconnect Circle Agent Wallet",
                "summary": "Stop creating new payment instructions for this Circle wallet.",
                "agent": connection.0,
                "wallet_address": connection.1,
                "network": connection.2,
                "effects": [
                    "Pending payment instructions expire without moving funds",
                    "The Circle wallet and its funds remain untouched",
                    "Future plans use the agent's Jusso-managed wallet"
                ]
            })
        }
        OwnerApprovalAction::CreatePaymentPlan { plan } => {
            validate_payment_plan_for_owner(pool, context, plan).await?;
            serde_json::json!({
                "title": "Create recurring USDC payment plan",
                "summary": "Confirm who gets paid, how much, and when.",
                "payment": approval_payment_plan_summary(plan),
                "note": "Jusso skips a payment when the wallet cannot pay everyone and preserve its reserve."
            })
        }
        OwnerApprovalAction::UpdatePaymentPlan {
            plan_id,
            expected_version,
            plan,
        } => {
            let (current, _recipients) = crate::workflows::get_plan(pool, context, *plan_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("payment plan was not found"))?;
            if current.version != *expected_version || current.status == "cancelled" {
                anyhow::bail!("payment plan changed or was cancelled before approval was created");
            }
            validate_payment_plan_for_owner(pool, context, plan).await?;
            serde_json::json!({
                "title": "Update recurring USDC payment plan",
                "summary": "Confirm the replacement payment schedule and recipients.",
                "new_payment": approval_payment_plan_summary(plan),
                "note": "This replaces the current plan. A payment already submitted onchain cannot be changed."
            })
        }
        OwnerApprovalAction::ChangePaymentPlanStatus {
            plan_id,
            expected_version,
            change,
        } => {
            let (current, recipients) = crate::workflows::get_plan(pool, context, *plan_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("payment plan was not found"))?;
            if current.version != *expected_version {
                anyhow::bail!("payment plan changed before approval was created");
            }
            match change {
                crate::workflows::PaymentPlanStatusChange::Pause if current.status != "active" => {
                    anyhow::bail!("only an active payment plan can be paused")
                }
                crate::workflows::PaymentPlanStatusChange::Resume if current.status != "paused" => {
                    anyhow::bail!("only a paused payment plan can be resumed")
                }
                crate::workflows::PaymentPlanStatusChange::Cancel
                    if current.status == "cancelled" =>
                {
                    anyhow::bail!("payment plan is already cancelled")
                }
                _ => {}
            }
            serde_json::json!({
                "title": format!("{:?} recurring USDC payment plan", change),
                "summary": match change {
                    crate::workflows::PaymentPlanStatusChange::Pause => "Temporarily stop future scheduled payments.",
                    crate::workflows::PaymentPlanStatusChange::Resume => "Restart future scheduled payments.",
                    crate::workflows::PaymentPlanStatusChange::Cancel => "Permanently stop this payment plan."
                },
                "plan": {
                    "name": current.name,
                    "status": current.status,
                    "recipient_count": recipients.len()
                },
                "warning": if matches!(change, crate::workflows::PaymentPlanStatusChange::Cancel) {
                    Some("Cancellation is permanent and does not cancel an already queued transaction")
                } else { None }
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

async fn validate_payment_plan_for_owner(
    pool: &PgPool,
    context: &AuthContext,
    plan: &crate::workflows::NormalizedPaymentPlan,
) -> Result<()> {
    plan.validate()?;
    if let Some(callback_url) = plan.callback_url.as_deref() {
        crate::webhook::validate_callback_url(Some(callback_url)).await?;
    }
    let (agent, policy) = authorize_execution_agent(pool, context, &plan.agent_id).await?;
    if context.is_bound_to_other_agent(agent.id) {
        anyhow::bail!("owner session is bound to another agent");
    }
    if crate::byow::active_connection_for_agent(pool, context.organization_id, agent.id)
        .await?
        .is_some()
        && (plan.recipients.len() != 1 || plan.surplus.is_some())
    {
        anyhow::bail!(
            "Circle Agent Wallet plans currently support one recipient and no surplus sweep"
        );
    }
    validate_payment_plan_against_policy(&policy, plan)
}

fn validate_payment_plan_against_policy(
    policy: &AuthorizationPolicyRow,
    plan: &crate::workflows::NormalizedPaymentPlan,
) -> Result<()> {
    if !policy.allowed_actions.as_ref().is_some_and(|actions| {
        actions
            .iter()
            .any(|action| action == "*" || action == "payment_plan:execute")
    }) {
        anyhow::bail!("agent policy does not allow recurring payment-plan execution");
    }
    let mut total = ethers_core::types::U256::zero();
    let mut recipients = Vec::with_capacity(plan.recipients.len() + 1);
    for recipient in &plan.recipients {
        total = total
            .checked_add(ethers_core::types::U256::from_dec_str(
                &recipient.amount_raw,
            )?)
            .ok_or_else(|| anyhow::anyhow!("payment-plan total overflow"))?;
        recipients.push(recipient.address.clone());
    }
    if let Some(surplus) = &plan.surplus {
        if let Some(maximum) = surplus.maximum_transfer_raw.as_deref() {
            total = total
                .checked_add(ethers_core::types::U256::from_dec_str(maximum)?)
                .ok_or_else(|| anyhow::anyhow!("payment-plan total overflow"))?;
        }
        recipients.push(surplus.destination.clone());
    }
    let impact = crate::policy::ExecutionPolicyImpact {
        token_spends: vec![crate::policy::TokenSpend {
            token: crate::policy::ARC_USDC_ADDRESS.into(),
            amount_raw: total.to_string(),
        }],
        borrowed_value_usd: 0.0,
        risks: vec![crate::policy::RISK_EXTERNAL_WITHDRAWAL.into()],
        recipients,
    };
    crate::auth::enforce_policy_impact(policy, &impact)?;
    if policy.allowed_targets.as_ref().is_some_and(|targets| {
        !targets.iter().any(|target| {
            target == "*" || target.eq_ignore_ascii_case(crate::policy::ARC_USDC_ADDRESS)
        })
    }) {
        anyhow::bail!("agent policy does not allow the Arc USDC contract target");
    }
    Ok(())
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
    lock_owner_account_tx(&mut transaction, organization_id, principal_id).await?;
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
              AND status = 'active'
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
             AND op.status = 'active'
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
            max_value_wei,
            max_execution_fee_usd,
            token_spend_limits,
            risk_permissions,
            rolling_window_seconds,
            max_rolling_execution_fee_usd,
            max_sponsored_gas_units,
            max_rolling_sponsored_gas_units,
            max_borrowed_value_usd,
            max_rolling_borrowed_value_usd,
        } => {
            let policy_id = Uuid::new_v4();
            sqlx::query(
                r#"INSERT INTO authorization_policies (
                    id, organization_id, name, allowed_chains, allowed_protocols,
                    allowed_actions, allowed_targets, max_value_wei,
                    max_execution_fee_usd, token_spend_limits,
                    risk_permissions, rolling_window_seconds,
                    max_rolling_execution_fee_usd, max_sponsored_gas_units,
                    max_rolling_sponsored_gas_units, max_borrowed_value_usd,
                    max_rolling_borrowed_value_usd
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                    $11, $12, $13, $14, $15, $16, $17
                )"#,
            )
            .bind(policy_id)
            .bind(row.organization_id)
            .bind(name.trim())
            .bind(allowed_chains)
            .bind(allowed_protocols)
            .bind(allowed_actions)
            .bind(allowed_targets)
            .bind(max_value_wei)
            .bind(max_execution_fee_usd)
            .bind(token_spend_limits)
            .bind(risk_permissions)
            .bind(rolling_window_seconds)
            .bind(max_rolling_execution_fee_usd)
            .bind(max_sponsored_gas_units)
            .bind(max_rolling_sponsored_gas_units)
            .bind(max_borrowed_value_usd)
            .bind(max_rolling_borrowed_value_usd)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({"policy_id": policy_id, "created": true})
        }
        update @ OwnerApprovalAction::UpdatePolicy { policy_id, .. } => {
            let current =
                get_active_policy_tx(&mut transaction, row.organization_id, policy_id).await?;
            let proposed = proposed_policy_update(&current, &update)?;
            validate_policy_update_assignments_tx(&mut transaction, row.organization_id, &proposed)
                .await?;

            let released_reservations = sqlx::query(
                r#"UPDATE policy_budget_reservations pbr
                   SET status = 'released', released_at = now()
                   FROM execution_requests er
                   WHERE pbr.request_id = er.id
                     AND pbr.organization_id = $1 AND pbr.policy_id = $2
                     AND pbr.policy_version = $3 AND pbr.status = 'reserved'
                     AND er.signed_user_operation IS NULL"#,
            )
            .bind(row.organization_id)
            .bind(current.id)
            .bind(current.version)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let revoked_permits = sqlx::query(
                r#"DELETE FROM execution_permits
                   WHERE organization_id = $1 AND policy_id = $2
                     AND policy_version = $3 AND consumed_at IS NULL"#,
            )
            .bind(row.organization_id)
            .bind(current.id)
            .bind(current.version)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let failed_requests = sqlx::query(
                r#"UPDATE execution_requests
                   SET status = 'failed',
                       error_message = 'authorization policy was updated before signing',
                       updated_at = now()
                   WHERE organization_id = $1 AND policy_id = $2 AND policy_version = $3
                     AND signed_user_operation IS NULL
                     AND status IN ('pending', 'payment_verified')"#,
            )
            .bind(row.organization_id)
            .bind(current.id)
            .bind(current.version)
            .execute(&mut *transaction)
            .await?
            .rows_affected();

            let updated = sqlx::query(
                r#"UPDATE authorization_policies SET
                       name = $4, version = $5, allowed_chains = $6,
                       allowed_protocols = $7, allowed_actions = $8,
                       allowed_targets = $9, max_value_wei = $10,
                       max_execution_fee_usd = $11,
                       token_spend_limits = $12, risk_permissions = $13,
                       rolling_window_seconds = $14,
                       max_rolling_execution_fee_usd = $15,
                       max_sponsored_gas_units = $16,
                       max_rolling_sponsored_gas_units = $17,
                       max_borrowed_value_usd = $18,
                       max_rolling_borrowed_value_usd = $19,
                       updated_at = now()
                   WHERE id = $1 AND organization_id = $2 AND version = $3
                     AND is_active = TRUE"#,
            )
            .bind(current.id)
            .bind(row.organization_id)
            .bind(current.version)
            .bind(&proposed.name)
            .bind(proposed.version)
            .bind(&proposed.allowed_chains)
            .bind(&proposed.allowed_protocols)
            .bind(&proposed.allowed_actions)
            .bind(&proposed.allowed_targets)
            .bind(&proposed.max_value_wei)
            .bind(proposed.max_execution_fee_usd)
            .bind(&proposed.token_spend_limits)
            .bind(&proposed.risk_permissions)
            .bind(proposed.rolling_window_seconds)
            .bind(proposed.max_rolling_execution_fee_usd)
            .bind(proposed.max_sponsored_gas_units)
            .bind(proposed.max_rolling_sponsored_gas_units)
            .bind(proposed.max_borrowed_value_usd)
            .bind(proposed.max_rolling_borrowed_value_usd)
            .execute(&mut *transaction)
            .await?;
            if updated.rows_affected() != 1 {
                anyhow::bail!("policy changed while approval was pending");
            }
            serde_json::json!({
                "policy_id": current.id,
                "previous_version": current.version,
                "version": proposed.version,
                "updated": true,
                "revoked_unsigned_permits": revoked_permits,
                "released_uncommitted_reservations": released_reservations,
                "failed_unfinished_requests": failed_requests
            })
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
        OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: target_passkey_id,
            expected_credential_id,
        } => {
            if passkey_id == target_passkey_id {
                anyhow::bail!("a passkey cannot approve its own revocation");
            }
            let target: (String, String) = sqlx::query_as(
                r#"SELECT credential_id, purpose FROM owner_passkeys
                   WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                     AND status = 'active' FOR UPDATE"#,
            )
            .bind(target_passkey_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active owner passkey was not found"))?;
            if target.0 != expected_credential_id {
                anyhow::bail!("passkey changed while approval was pending");
            }
            validate_owner_passkey_removal_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                target_passkey_id,
                &target.1,
            )
            .await?;
            sqlx::query(
                r#"UPDATE owner_passkeys
                   SET status = 'revoked', revoked_by_passkey_id = $2,
                       revoked_at = now(), updated_at = now()
                   WHERE id = $1 AND status = 'active'"#,
            )
            .bind(target_passkey_id)
            .bind(passkey_id)
            .execute(&mut *transaction)
            .await?;
            let revoked_connections = revoke_owner_sessions_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                target_passkey_id,
            )
            .await?;
            let expired_approvals = sqlx::query(
                r#"UPDATE owner_approval_requests SET status = 'expired'
                   WHERE organization_id = $1 AND principal_id = $2
                     AND id <> $3 AND status = 'pending'"#,
            )
            .bind(row.organization_id)
            .bind(row.principal_id)
            .bind(approval_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            let expired_enrollments = sqlx::query(
                r#"UPDATE owner_passkey_enrollment_requests SET status = 'expired'
                   WHERE organization_id = $1 AND principal_id = $2
                     AND status = 'pending'"#,
            )
            .bind(row.organization_id)
            .bind(row.principal_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            serde_json::json!({
                "passkey_id": target_passkey_id,
                "revoked": true,
                "revoked_connections": revoked_connections,
                "expired_approvals": expired_approvals,
                "expired_passkey_enrollments": expired_enrollments
            })
        }
        OwnerApprovalAction::ConnectCircleAgentWallet {
            challenge_id,
            agent_id,
            chain,
            wallet_address,
            ownership_signature,
        } => {
            let consumed = sqlx::query(
                r#"UPDATE external_wallet_connection_challenges
                   SET consumed_at=now()
                   WHERE id=$1 AND organization_id=$2 AND agent_id=$3
                     AND created_by_principal_id=$4 AND chain=$5 AND wallet_address=$6
                     AND consumed_at IS NULL AND expires_at > now()"#,
            )
            .bind(challenge_id)
            .bind(row.organization_id)
            .bind(agent_id)
            .bind(row.principal_id)
            .bind(&chain)
            .bind(&wallet_address)
            .execute(&mut *transaction)
            .await?;
            if consumed.rows_affected() != 1 {
                anyhow::bail!("Circle wallet proof expired or was already consumed");
            }
            let agent: (String,) = sqlx::query_as(
                r#"SELECT a.external_id FROM agents a
                   JOIN principal_agent_grants pag ON pag.agent_id=a.id
                   WHERE a.id=$1 AND a.organization_id=$2 AND pag.principal_id=$3
                     AND a.status='active' FOR UPDATE OF a"#,
            )
            .bind(agent_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active agent is no longer available"))?;
            let incompatible_plan: bool = sqlx::query_scalar(
                r#"SELECT EXISTS(
                       SELECT 1 FROM payment_plans p
                       WHERE p.organization_id=$1 AND p.agent_id=$2
                         AND p.status <> 'cancelled'
                         AND (p.surplus_destination IS NOT NULL OR
                              (SELECT COUNT(*) FROM payment_plan_recipients r
                               WHERE r.plan_id=p.id) <> 1)
                   )"#,
            )
            .bind(row.organization_id)
            .bind(agent_id)
            .fetch_one(&mut *transaction)
            .await?;
            if incompatible_plan {
                anyhow::bail!(
                    "Circle Agent Wallet currently requires one-recipient plans without surplus sweeps"
                );
            }
            sqlx::query(
                r#"UPDATE external_wallet_connections
                   SET status='revoked', revoked_at=now(), updated_at=now()
                   WHERE organization_id=$1 AND agent_id=$2 AND status='active'"#,
            )
            .bind(row.organization_id)
            .bind(agent_id)
            .execute(&mut *transaction)
            .await?;
            let connection_id = Uuid::new_v4();
            let challenge: String = sqlx::query_scalar(
                "SELECT challenge FROM external_wallet_connection_challenges WHERE id=$1",
            )
            .bind(challenge_id)
            .fetch_one(&mut *transaction)
            .await?;
            sqlx::query(
                r#"INSERT INTO external_wallet_connections (
                       id, organization_id, agent_id, provider, chain, wallet_address,
                       ownership_challenge, ownership_signature,
                       connected_by_principal_id, verified_at
                   ) VALUES ($1,$2,$3,'circle_agent_wallet',$4,$5,$6,$7,$8,now())"#,
            )
            .bind(connection_id)
            .bind(row.organization_id)
            .bind(agent_id)
            .bind(&chain)
            .bind(&wallet_address)
            .bind(challenge)
            .bind(&ownership_signature)
            .bind(row.principal_id)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "connection_id": connection_id,
                "provider": "circle_agent_wallet",
                "agent_id": agent.0,
                "chain": chain,
                "wallet_address": wallet_address,
                "status": "active"
            })
        }
        OwnerApprovalAction::RevokeExternalWallet { connection_id } => {
            let revoked = sqlx::query(
                r#"UPDATE external_wallet_connections c
                   SET status='revoked', revoked_at=now(), updated_at=now()
                   FROM principal_agent_grants pag
                   WHERE c.id=$1 AND c.organization_id=$2 AND c.status='active'
                     AND pag.agent_id=c.agent_id AND pag.principal_id=$3"#,
            )
            .bind(connection_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .execute(&mut *transaction)
            .await?;
            if revoked.rows_affected() != 1 {
                anyhow::bail!("external wallet connection changed while approval was pending");
            }
            // Let the scheduler expire these intents so their associated runs
            // follow the normal terminal-state and callback path.
            sqlx::query(
                r#"UPDATE external_wallet_payment_intents
                   SET expires_at=LEAST(expires_at, now())
                   WHERE connection_id=$1 AND status='pending'"#,
            )
            .bind(connection_id)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "connection_id": connection_id,
                "status": "revoked",
                "wallet_funds_moved": false
            })
        }
        OwnerApprovalAction::CreatePaymentPlan { mut plan } => {
            let agent: AgentRow = sqlx::query_as(
                r#"SELECT a.* FROM agents a
                   JOIN principal_agent_grants pag ON pag.agent_id = a.id
                   WHERE a.organization_id = $1 AND a.external_id = $2
                     AND pag.principal_id = $3 AND a.status = 'active'
                   FOR UPDATE OF a"#,
            )
            .bind(row.organization_id)
            .bind(&plan.agent_id)
            .bind(row.principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active payment-plan agent was not found"))?;
            let policy =
                get_active_policy_tx(&mut transaction, row.organization_id, agent.policy_id)
                    .await?;
            validate_payment_plan_against_policy(&policy, &plan)?;
            plan.first_run_at = plan.schedule.next_after(Utc::now())?;
            let plan_id = crate::workflows::insert_plan_tx(
                &mut transaction,
                row.organization_id,
                row.principal_id,
                agent.id,
                &plan,
            )
            .await?;
            serde_json::json!({
                "payment_plan_id": plan_id,
                "version": 1,
                "status": "active",
                "next_run_at": plan.first_run_at
            })
        }
        OwnerApprovalAction::UpdatePaymentPlan {
            plan_id,
            expected_version,
            mut plan,
        } => {
            let current: (Uuid, i64, String) = sqlx::query_as(
                r#"SELECT p.agent_id, p.version, p.status FROM payment_plans p
                   JOIN principal_agent_grants pag ON pag.agent_id = p.agent_id
                   WHERE p.id = $1 AND p.organization_id = $2 AND pag.principal_id = $3
                   FOR UPDATE OF p"#,
            )
            .bind(plan_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("payment plan was not found"))?;
            if current.1 != expected_version || current.2 == "cancelled" {
                anyhow::bail!("payment plan changed or was cancelled while approval was pending");
            }
            let agent: AgentRow = sqlx::query_as(
                r#"SELECT a.* FROM agents a
                   JOIN principal_agent_grants pag ON pag.agent_id = a.id
                   WHERE a.organization_id = $1 AND a.external_id = $2
                     AND pag.principal_id = $3 AND a.status = 'active'
                   FOR UPDATE OF a"#,
            )
            .bind(row.organization_id)
            .bind(&plan.agent_id)
            .bind(row.principal_id)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("active payment-plan agent was not found"))?;
            let policy =
                get_active_policy_tx(&mut transaction, row.organization_id, agent.policy_id)
                    .await?;
            validate_payment_plan_against_policy(&policy, &plan)?;
            plan.first_run_at = plan.schedule.next_after(Utc::now())?;
            let cadence = serde_json::to_value(&plan.schedule.cadence)?
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("invalid cadence"))?
                .to_owned();
            sqlx::query(
                r#"UPDATE payment_plans SET agent_id=$4, name=$5, version=version+1,
                       cadence=$6, timezone=$7, local_time=$8, weekday=$9,
                       day_of_month=$10, reserve_raw=$11::NUMERIC,
                       surplus_destination=$12, surplus_minimum_raw=$13::NUMERIC,
                       surplus_maximum_raw=$14::NUMERIC, callback_url=$15,
                       next_run_at=$16, updated_at=now()
                   WHERE id=$1 AND organization_id=$2 AND version=$3"#,
            )
            .bind(plan_id)
            .bind(row.organization_id)
            .bind(expected_version)
            .bind(agent.id)
            .bind(&plan.name)
            .bind(cadence)
            .bind(&plan.schedule.timezone)
            .bind(&plan.schedule.local_time)
            .bind(
                plan.schedule
                    .weekday
                    .as_ref()
                    .map(|value| value.to_ascii_lowercase()),
            )
            .bind(plan.schedule.day_of_month.map(i16::from))
            .bind(&plan.reserve_raw)
            .bind(plan.surplus.as_ref().map(|value| &value.destination))
            .bind(
                plan.surplus
                    .as_ref()
                    .map(|value| &value.minimum_transfer_raw),
            )
            .bind(
                plan.surplus
                    .as_ref()
                    .and_then(|value| value.maximum_transfer_raw.as_ref()),
            )
            .bind(&plan.callback_url)
            .bind(plan.first_run_at)
            .execute(&mut *transaction)
            .await?;
            sqlx::query("DELETE FROM payment_plan_recipients WHERE plan_id = $1")
                .bind(plan_id)
                .execute(&mut *transaction)
                .await?;
            for (position, recipient) in plan.recipients.iter().enumerate() {
                sqlx::query(
                    r#"INSERT INTO payment_plan_recipients
                       (id, plan_id, position, recipient_address, amount_raw,
                        recipient_name, address_kind, verified_at)
                       VALUES ($1,$2,$3,$4,$5::NUMERIC,$6,$7,$8)"#,
                )
                .bind(Uuid::new_v4())
                .bind(plan_id)
                .bind(position as i16)
                .bind(&recipient.address)
                .bind(&recipient.amount_raw)
                .bind(&recipient.name)
                .bind(
                    recipient
                        .verification
                        .as_ref()
                        .map(|verification| &verification.address_kind),
                )
                .bind(
                    recipient
                        .verification
                        .as_ref()
                        .map(|verification| verification.verified_at),
                )
                .execute(&mut *transaction)
                .await?;
                crate::workflows::remember_recipient_contact_tx(
                    &mut transaction,
                    row.organization_id,
                    row.principal_id,
                    recipient,
                )
                .await?;
            }
            serde_json::json!({
                "payment_plan_id": plan_id,
                "previous_version": expected_version,
                "version": expected_version + 1,
                "status": current.2,
                "next_run_at": plan.first_run_at
            })
        }
        OwnerApprovalAction::ChangePaymentPlanStatus {
            plan_id,
            expected_version,
            change,
        } => {
            let current: (String, String, String, Option<i16>) = sqlx::query_as(
                r#"SELECT p.status, p.cadence, p.timezone, p.day_of_month
                   FROM payment_plans p
                   JOIN principal_agent_grants pag ON pag.agent_id = p.agent_id
                   WHERE p.id=$1 AND p.organization_id=$2 AND pag.principal_id=$3
                     AND p.version=$4 FOR UPDATE OF p"#,
            )
            .bind(plan_id)
            .bind(row.organization_id)
            .bind(row.principal_id)
            .bind(expected_version)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or_else(|| anyhow::anyhow!("payment plan changed while approval was pending"))?;
            let (new_status, next_run_at, cancelled_at) = match change {
                crate::workflows::PaymentPlanStatusChange::Pause if current.0 == "active" => {
                    ("paused", None, None)
                }
                crate::workflows::PaymentPlanStatusChange::Resume if current.0 == "paused" => {
                    let schedule_row: (String, Option<String>) =
                        sqlx::query_as("SELECT local_time, weekday FROM payment_plans WHERE id=$1")
                            .bind(plan_id)
                            .fetch_one(&mut *transaction)
                            .await?;
                    let cadence = serde_json::from_value(serde_json::Value::String(current.1))?;
                    let schedule = crate::workflows::PaymentSchedule {
                        cadence,
                        timezone: current.2,
                        local_time: schedule_row.0,
                        weekday: schedule_row.1,
                        day_of_month: current.3.map(|value| value as u8),
                    };
                    ("active", Some(schedule.next_after(Utc::now())?), None)
                }
                crate::workflows::PaymentPlanStatusChange::Cancel if current.0 != "cancelled" => {
                    ("cancelled", None, Some(Utc::now()))
                }
                _ => anyhow::bail!("payment-plan status transition is no longer valid"),
            };
            sqlx::query(
                r#"UPDATE payment_plans SET status=$5, version=version+1,
                       next_run_at=$6, cancelled_at=$7, updated_at=now()
                   WHERE id=$1 AND organization_id=$2 AND version=$3 AND status=$4"#,
            )
            .bind(plan_id)
            .bind(row.organization_id)
            .bind(expected_version)
            .bind(&current.0)
            .bind(new_status)
            .bind(next_run_at)
            .bind(cancelled_at)
            .execute(&mut *transaction)
            .await?;
            serde_json::json!({
                "payment_plan_id": plan_id,
                "previous_version": expected_version,
                "version": expected_version + 1,
                "status": new_status,
                "next_run_at": next_run_at
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
        "policy_impact": req.policy_impact,
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
             instance_id, policy_id, policy_version, policy_impact)
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20
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
    .bind(serde_json::to_value(&req.policy_impact)?)
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
             instance_id, policy_id, policy_version, policy_impact,
             idempotency_key, idempotency_fingerprint)
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
            $14, $15, $16, $17, $18, $19, $20, $21, $22
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
    .bind(serde_json::to_value(&req.policy_impact)?)
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
    release_policy_budget_reservation(pool, row.id).await?;
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
    if execution_fee_raw.is_some_and(|amount| amount.parse::<ethers_core::types::U256>().is_err()) {
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
        JOIN policy_budget_reservations pbr ON pbr.request_id = er.id
        WHERE er.id = $1 AND er.status = 'payment_verified'
          AND er.smart_wallet_address IS NOT NULL
          AND ap.is_active = TRUE AND ap.version = er.policy_version
          AND a.status = 'active' AND a.policy_id = er.policy_id
          AND pbr.organization_id = er.organization_id
          AND pbr.agent_id = er.agent_uuid
          AND pbr.policy_id = er.policy_id
          AND pbr.policy_version = er.policy_version
          AND pbr.status = 'reserved'
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

fn usd_to_microusd(value: f64, round_up: bool) -> Result<i64> {
    if !value.is_finite() || !(0.0..=1_000_000_000.0).contains(&value) {
        anyhow::bail!("USD policy value is outside the supported range");
    }
    let scaled = value * 1_000_000.0;
    let rounded = if round_up {
        scaled.ceil()
    } else {
        scaled.floor()
    };
    if rounded > i64::MAX as f64 {
        anyhow::bail!("USD policy value is too large");
    }
    Ok(rounded as i64)
}

/// Atomically reserve the economic authority consumed by an execution.
///
/// Locking the agent row serializes reservations even while policies are
/// migrated. Active reservations from prior policy versions remain part of
/// the rolling total, preventing a policy replacement from resetting spend.
pub async fn reserve_policy_budget(
    pool: &PgPool,
    request_id: Uuid,
    execution_fee_usd: f64,
    sponsored_gas_units: u64,
) -> Result<()> {
    let execution_fee_microusd = usd_to_microusd(execution_fee_usd, true)?;
    let sponsored_gas_units = i64::try_from(sponsored_gas_units)
        .map_err(|_| anyhow::anyhow!("sponsored gas units exceed the supported range"))?;
    let mut transaction = pool.begin().await?;
    let execution = sqlx::query_as::<_, (Uuid, Uuid, Uuid, i64, serde_json::Value, String)>(
        r#"SELECT er.organization_id, er.agent_uuid, er.policy_id,
                  er.policy_version, er.policy_impact, er.status
           FROM execution_requests er
           JOIN agents a ON a.id = er.agent_uuid AND a.organization_id = er.organization_id
           WHERE er.id = $1
           FOR UPDATE OF a"#,
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("execution request was not found"))?;
    if execution.5 != "payment_verified" {
        anyhow::bail!("policy budget can only be reserved for a payment-verified execution");
    }
    let policy = sqlx::query_as::<_, AuthorizationPolicyRow>(
        r#"SELECT * FROM authorization_policies
           WHERE id = $1 AND organization_id = $2 AND is_active = TRUE
             AND version = $3
           FOR UPDATE"#,
    )
    .bind(execution.2)
    .bind(execution.0)
    .bind(execution.3)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or_else(|| anyhow::anyhow!("execution policy changed or was revoked"))?;
    let impact: crate::policy::ExecutionPolicyImpact =
        serde_json::from_value(execution.4).context("stored policy impact is invalid")?;
    crate::auth::enforce_policy_impact(&policy, &impact)?;

    if let Some(limit) = policy.max_execution_fee_usd {
        if execution_fee_microusd > usd_to_microusd(limit, false)? {
            anyhow::bail!("execution fee exceeds per-execution authorization policy");
        }
    }
    if policy
        .max_sponsored_gas_units
        .is_some_and(|limit| sponsored_gas_units > limit)
    {
        anyhow::bail!("sponsored gas exceeds per-execution authorization policy");
    }
    let borrowed_value_microusd = usd_to_microusd(impact.borrowed_value_usd, true)?;
    if let Some(limit) = policy.max_borrowed_value_usd {
        if borrowed_value_microusd > usd_to_microusd(limit, false)? {
            anyhow::bail!("borrowed value exceeds per-execution authorization policy");
        }
    }

    let existing = sqlx::query_as::<_, (i64, i64, i64, String)>(
        r#"SELECT execution_fee_microusd, borrowed_value_microusd,
                  sponsored_gas_units, status
           FROM policy_budget_reservations WHERE request_id = $1"#,
    )
    .bind(request_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some(existing) = existing {
        if existing.0 != execution_fee_microusd
            || existing.1 != borrowed_value_microusd
            || existing.2 != sponsored_gas_units
            || existing.3 == "released"
        {
            anyhow::bail!("execution already has a different policy budget reservation");
        }
        transaction.commit().await?;
        return Ok(());
    }

    let rolling: (i64, i64, i64) = sqlx::query_as(
        r#"SELECT
             COALESCE(SUM(execution_fee_microusd), 0)::BIGINT,
             COALESCE(SUM(borrowed_value_microusd), 0)::BIGINT,
             COALESCE(SUM(sponsored_gas_units), 0)::BIGINT
           FROM policy_budget_reservations
           WHERE organization_id = $1 AND agent_id = $2
             AND status IN ('reserved', 'committed')
             AND reserved_at >= now() - ($3 * interval '1 second')"#,
    )
    .bind(execution.0)
    .bind(execution.1)
    .bind(policy.rolling_window_seconds)
    .fetch_one(&mut *transaction)
    .await?;
    if let Some(limit) = policy.max_rolling_execution_fee_usd {
        let next = rolling
            .0
            .checked_add(execution_fee_microusd)
            .ok_or_else(|| anyhow::anyhow!("rolling execution-fee budget overflow"))?;
        if next > usd_to_microusd(limit, false)? {
            anyhow::bail!("execution fee exceeds rolling authorization policy");
        }
    }
    if let Some(limit) = policy.max_rolling_borrowed_value_usd {
        let next = rolling
            .1
            .checked_add(borrowed_value_microusd)
            .ok_or_else(|| anyhow::anyhow!("rolling borrowed-value budget overflow"))?;
        if next > usd_to_microusd(limit, false)? {
            anyhow::bail!("borrowed value exceeds rolling authorization policy");
        }
    }
    if let Some(limit) = policy.max_rolling_sponsored_gas_units {
        let next = rolling
            .2
            .checked_add(sponsored_gas_units)
            .ok_or_else(|| anyhow::anyhow!("rolling sponsored-gas budget overflow"))?;
        if next > limit {
            anyhow::bail!("sponsored gas exceeds rolling authorization policy");
        }
    }

    sqlx::query(
        r#"INSERT INTO policy_budget_reservations (
               request_id, organization_id, agent_id, policy_id, policy_version,
               execution_fee_microusd, borrowed_value_microusd, sponsored_gas_units
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
    )
    .bind(request_id)
    .bind(execution.0)
    .bind(execution.1)
    .bind(execution.2)
    .bind(execution.3)
    .bind(execution_fee_microusd)
    .bind(borrowed_value_microusd)
    .bind(sponsored_gas_units)
    .execute(&mut *transaction)
    .await?;

    let token_limits = crate::policy::validate_token_spend_limits(&policy.token_spend_limits)?;
    let mut spends = std::collections::BTreeMap::<String, ethers_core::types::U256>::new();
    for spend in impact.token_spends {
        let token = spend.token.to_ascii_lowercase();
        let amount = ethers_core::types::U256::from_dec_str(&spend.amount_raw)?;
        let total = spends.entry(token).or_default();
        *total = total
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("token spend reservation overflow"))?;
    }
    for (token, amount) in spends {
        let limit = token_limits
            .iter()
            .find(|limit| limit.token.eq_ignore_ascii_case(&token))
            .or_else(|| token_limits.iter().find(|limit| limit.token == "*"))
            .ok_or_else(|| anyhow::anyhow!("token spending requires an explicit policy limit"))?;
        let current: String = sqlx::query_scalar(
            r#"SELECT COALESCE(SUM(ts.amount_raw), 0)::TEXT
               FROM policy_token_spend_reservations ts
               JOIN policy_budget_reservations br ON br.request_id = ts.request_id
               WHERE br.organization_id = $1 AND br.agent_id = $2
                 AND br.status IN ('reserved', 'committed')
                 AND br.reserved_at >= now() - ($3 * interval '1 second')
                 AND ts.token_address = $4"#,
        )
        .bind(execution.0)
        .bind(execution.1)
        .bind(policy.rolling_window_seconds)
        .bind(&token)
        .fetch_one(&mut *transaction)
        .await?;
        let next = ethers_core::types::U256::from_dec_str(&current)?
            .checked_add(amount)
            .ok_or_else(|| anyhow::anyhow!("rolling token spend overflow"))?;
        if next > ethers_core::types::U256::from_dec_str(&limit.max_rolling_raw)? {
            anyhow::bail!("token spend exceeds rolling authorization policy");
        }
        sqlx::query(
            r#"INSERT INTO policy_token_spend_reservations (
                   request_id, token_address, amount_raw
               ) VALUES ($1, $2, $3::NUMERIC)"#,
        )
        .bind(request_id)
        .bind(token)
        .bind(amount.to_string())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

pub async fn release_policy_budget_reservation(pool: &PgPool, request_id: Uuid) -> Result<bool> {
    let released = sqlx::query(
        r#"UPDATE policy_budget_reservations br
           SET status = 'released', released_at = now()
           WHERE br.request_id = $1 AND br.status = 'reserved'
             AND NOT EXISTS (
                 SELECT 1 FROM execution_requests er
                 WHERE er.id = br.request_id AND er.signed_user_operation IS NOT NULL
             )"#,
    )
    .bind(request_id)
    .execute(pool)
    .await?;
    Ok(released.rows_affected() == 1)
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
    pub payment: Option<&'a crate::types::SettledExecutionFee>,
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
        if payment.request_id != finalization.request_id {
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
        let amount_raw = &payment.amount_raw;
        let token_contract = &payment.token_contract;
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
        .bind(payment.fee_id)
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
                || existing.amount_raw != *amount_raw
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
    use crate::types::{ExecutionRequest, SettledExecutionFee};

    fn test_policy(
        allowed_actions: Option<Vec<String>>,
        max_value_wei: Option<&str>,
        max_execution_fee_usd: Option<f64>,
    ) -> AuthorizationPolicyRow {
        AuthorizationPolicyRow {
            id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            name: format!("policy-{}", Uuid::new_v4().simple()),
            version: 1,
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: None,
            allowed_actions,
            allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
            max_value_wei: max_value_wei.map(str::to_string),
            max_execution_fee_usd,
            token_spend_limits: crate::policy::default_token_spend_limits(),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: max_execution_fee_usd.map(|value| value * 10.0),
            max_sponsored_gas_units: Some(2_000_000),
            max_rolling_sponsored_gas_units: Some(10_000_000),
            max_borrowed_value_usd: Some(0.0),
            max_rolling_borrowed_value_usd: Some(0.0),
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn update_policy_action(policy: &AuthorizationPolicyRow) -> OwnerApprovalAction {
        OwnerApprovalAction::UpdatePolicy {
            policy_id: policy.id,
            expected_version: policy.version,
            name: policy.name.clone(),
            allowed_chains: policy.allowed_chains.clone(),
            allowed_protocols: policy.allowed_protocols.clone(),
            allowed_actions: policy.allowed_actions.clone(),
            allowed_targets: policy.allowed_targets.clone(),
            max_value_wei: policy.max_value_wei.clone(),
            max_execution_fee_usd: policy.max_execution_fee_usd,
            token_spend_limits: policy.token_spend_limits.clone(),
            risk_permissions: policy.risk_permissions.clone(),
            rolling_window_seconds: policy.rolling_window_seconds,
            max_rolling_execution_fee_usd: policy.max_rolling_execution_fee_usd,
            max_sponsored_gas_units: policy.max_sponsored_gas_units,
            max_rolling_sponsored_gas_units: policy.max_rolling_sponsored_gas_units,
            max_borrowed_value_usd: policy.max_borrowed_value_usd,
            max_rolling_borrowed_value_usd: policy.max_rolling_borrowed_value_usd,
        }
    }

    #[test]
    fn owner_approval_policy_drafts_are_restrictive_and_arc_scoped() {
        let valid = OwnerApprovalAction::CreatePolicy {
            name: "Arc payment policy".into(),
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: None,
            allowed_actions: Some(vec!["payment_plan:execute".into()]),
            allowed_targets: Some(vec![crate::policy::ARC_USDC_ADDRESS.into()]),
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
            token_spend_limits: crate::policy::default_token_spend_limits(),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: Some(10.0),
            max_sponsored_gas_units: Some(2_000_000),
            max_rolling_sponsored_gas_units: Some(10_000_000),
            max_borrowed_value_usd: Some(0.0),
            max_rolling_borrowed_value_usd: Some(0.0),
        };
        assert!(valid.validate("arc-testnet").is_ok());

        let unrestricted = OwnerApprovalAction::CreatePolicy {
            name: "Unrestricted".into(),
            allowed_chains: None,
            allowed_protocols: None,
            allowed_actions: None,
            allowed_targets: None,
            max_value_wei: None,
            max_execution_fee_usd: None,
            token_spend_limits: serde_json::json!([]),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: None,
            max_sponsored_gas_units: None,
            max_rolling_sponsored_gas_units: None,
            max_borrowed_value_usd: None,
            max_rolling_borrowed_value_usd: None,
        };
        assert!(unrestricted.validate("arc-testnet").is_err());

        let wrong_chain = OwnerApprovalAction::CreatePolicy {
            name: "Wrong chain".into(),
            allowed_chains: Some(vec!["base".into()]),
            allowed_protocols: None,
            allowed_actions: None,
            allowed_targets: None,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: None,
            token_spend_limits: serde_json::json!([]),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: None,
            max_sponsored_gas_units: None,
            max_rolling_sponsored_gas_units: None,
            max_borrowed_value_usd: None,
            max_rolling_borrowed_value_usd: None,
        };
        assert!(wrong_chain.validate("arc-testnet").is_err());
    }

    #[test]
    fn delegated_policies_cannot_expand_parent_authority() {
        let parent = test_policy(
            Some(vec!["wallet:read".into(), "payment_plan:execute".into()]),
            Some("100"),
            Some(1.0),
        );
        let child = test_policy(Some(vec!["wallet:read".into()]), Some("50"), Some(0.5));
        assert!(validate_delegated_policy(&parent, &child).is_ok());

        let mut wildcard = child.clone();
        wildcard.allowed_actions = Some(vec!["*".into()]);
        assert!(validate_delegated_policy(&parent, &wildcard).is_err());

        let mut unlimited = child.clone();
        unlimited.max_value_wei = None;
        assert!(validate_delegated_policy(&parent, &unlimited).is_err());

        let mut costly = child.clone();
        costly.max_execution_fee_usd = Some(2.0);
        assert!(validate_delegated_policy(&parent, &costly).is_err());

        let mut risky = child.clone();
        risky.risk_permissions = vec![crate::policy::RISK_BORROWING.into()];
        assert!(validate_delegated_policy(&parent, &risky).is_err());

        let mut shorter_window = child.clone();
        shorter_window.rolling_window_seconds = 60;
        assert!(validate_delegated_policy(&parent, &shorter_window).is_err());

        let mut larger_token_budget = child.clone();
        larger_token_budget.token_spend_limits = serde_json::json!([{
            "token": crate::policy::ARC_USDC_ADDRESS,
            "max_per_execution_raw": "500000001",
            "max_rolling_raw": "2500000001"
        }]);
        assert!(validate_delegated_policy(&parent, &larger_token_budget).is_err());

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
        let agent = sqlx::query_as::<_, AgentRow>(
            "SELECT * FROM agents WHERE organization_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(base.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
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
                agent_id, agent_external_id, client_id, resource, scopes
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7,
                'https://api.example/mcp/agent', ARRAY['policy:manage']
            )"#,
        )
        .bind(oauth_connection_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(passkey_id)
        .bind(agent.id)
        .bind(&agent.external_id)
        .bind(client_id)
        .execute(&pool)
        .await
        .unwrap();
        let context = AuthContext {
            credential_id: oauth_connection_id,
            credential_kind: CredentialKind::OAuthSession,
            agent_id: Some(agent.id),
            agent_external_id: Some(agent.external_id),
            instance_id: None,
            dpop_jkt: None,
            scopes: ["policy:manage".to_string()].into_iter().collect(),
            ..base
        };
        let policy_name = format!("approval-policy-{}", Uuid::new_v4().simple());
        let action = OwnerApprovalAction::CreatePolicy {
            name: policy_name.clone(),
            allowed_chains: Some(vec!["arc-testnet".into()]),
            allowed_protocols: None,
            allowed_actions: Some(vec!["payment_plan:execute".into()]),
            allowed_targets: None,
            max_value_wei: Some("0".into()),
            max_execution_fee_usd: Some(1.0),
            token_spend_limits: crate::policy::default_token_spend_limits(),
            risk_permissions: vec![],
            rolling_window_seconds: 86_400,
            max_rolling_execution_fee_usd: Some(10.0),
            max_sponsored_gas_units: Some(2_000_000),
            max_rolling_sponsored_gas_units: Some(10_000_000),
            max_borrowed_value_usd: Some(0.0),
            max_rolling_borrowed_value_usd: Some(0.0),
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
                owner_handle_normalized, display_name, webauthn_user_id
            ) VALUES ($1, $2, $3, $3, 'Lifecycle owner', $4)"#,
        )
        .bind(base.principal_id)
        .bind(base.organization_id)
        .bind(owner_handle)
        .bind(Uuid::new_v4())
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
                agent_id, agent_external_id, client_id, resource, scopes
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, 'https://api.example/mcp/agent',
                ARRAY['agent:manage', 'policy:manage', 'credential:manage']
            )"#,
        )
        .bind(oauth_connection_id)
        .bind(base.organization_id)
        .bind(base.principal_id)
        .bind(passkey_id)
        .bind(root_agent.id)
        .bind(&root_agent.external_id)
        .bind(client_id)
        .execute(pool)
        .await
        .unwrap();
        OwnerControlFixture {
            context: AuthContext {
                credential_id: oauth_connection_id,
                credential_kind: CredentialKind::OAuthSession,
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

    async fn insert_owner_passkey(
        pool: &PgPool,
        fixture: &OwnerControlFixture,
        label: &str,
        purpose: &str,
    ) -> (Uuid, String) {
        let id = Uuid::new_v4();
        let credential_id = format!("credential-{}", Uuid::new_v4().simple());
        sqlx::query(
            r#"INSERT INTO owner_passkeys (
                   id, organization_id, principal_id, credential_id, passkey,
                   label, purpose, created_by_passkey_id
               ) VALUES ($1, $2, $3, $4, '{}'::jsonb, $5, $6, $7)"#,
        )
        .bind(id)
        .bind(fixture.context.organization_id)
        .bind(fixture.context.principal_id)
        .bind(&credential_id)
        .bind(label)
        .bind(purpose)
        .bind(fixture.passkey_id)
        .execute(pool)
        .await
        .unwrap();
        (id, credential_id)
    }

    #[test]
    fn passkey_enrollment_fields_and_revocation_payload_are_validated() {
        assert!(validate_passkey_label_and_purpose("Travel key", "standard").is_ok());
        assert!(validate_passkey_label_and_purpose("Safe recovery", "recovery").is_ok());
        assert!(validate_passkey_label_and_purpose("", "standard").is_err());
        assert!(validate_passkey_label_and_purpose("Bad\nlabel", "standard").is_err());
        assert!(validate_passkey_label_and_purpose("Key", "primary").is_err());

        let valid = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: Uuid::new_v4(),
            expected_credential_id: "credential-id".into(),
        };
        assert!(valid.validate("arc-testnet").is_ok());
        let invalid = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: Uuid::new_v4(),
            expected_credential_id: String::new(),
        };
        assert!(invalid.validate("arc-testnet").is_err());
    }

    #[tokio::test]
    async fn passkey_enrollment_adds_and_atomically_replaces_recovery_credentials() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let first_request = create_owner_passkey_enrollment_request(
            &pool,
            &fixture.context,
            CreateOwnerPasskeyEnrollmentOptions {
                token_hash: &sha256_hex(&random_secret()),
                label: "Offline recovery",
                purpose: "recovery",
                replaces_passkey_id: None,
                expires_at: Utc::now() + chrono::Duration::minutes(10),
            },
        )
        .await
        .unwrap();
        let (other_passkey_id, _) =
            insert_owner_passkey(&pool, &fixture, "Secondary device", "standard").await;
        authenticate_owner_passkey_enrollment(
            &pool,
            first_request.id,
            fixture.passkey_id,
            &serde_json::json!({"counter": 1}),
        )
        .await
        .unwrap();
        assert!(authenticate_owner_passkey_enrollment(
            &pool,
            first_request.id,
            other_passkey_id,
            &serde_json::json!({"counter": 1}),
        )
        .await
        .is_err());
        let first_recovery_id = Uuid::new_v4();
        let added = complete_owner_passkey_enrollment(
            &pool,
            CompleteOwnerPasskeyEnrollmentOptions {
                request_id: first_request.id,
                authenticated_by_passkey_id: fixture.passkey_id,
                new_passkey_id: first_recovery_id,
                credential_id: &format!("credential-{}", Uuid::new_v4().simple()),
                passkey: &serde_json::json!({"counter": 0}),
                turnkey_recovery_credential: &serde_json::json!({"challenge": "first"}),
            },
        )
        .await
        .unwrap();
        assert_eq!(added["purpose"], "recovery");

        let unsafe_downgrade = create_owner_passkey_enrollment_request(
            &pool,
            &fixture.context,
            CreateOwnerPasskeyEnrollmentOptions {
                token_hash: &sha256_hex(&random_secret()),
                label: "No longer recovery",
                purpose: "standard",
                replaces_passkey_id: Some(first_recovery_id),
                expires_at: Utc::now() + chrono::Duration::minutes(10),
            },
        )
        .await;
        assert!(unsafe_downgrade.is_err());

        let replacement_request = create_owner_passkey_enrollment_request(
            &pool,
            &fixture.context,
            CreateOwnerPasskeyEnrollmentOptions {
                token_hash: &sha256_hex(&random_secret()),
                label: "Offline recovery",
                purpose: "recovery",
                replaces_passkey_id: Some(first_recovery_id),
                expires_at: Utc::now() + chrono::Duration::minutes(10),
            },
        )
        .await
        .unwrap();
        authenticate_owner_passkey_enrollment(
            &pool,
            replacement_request.id,
            fixture.passkey_id,
            &serde_json::json!({"counter": 2}),
        )
        .await
        .unwrap();
        let replacement_id = Uuid::new_v4();
        let replaced = complete_owner_passkey_enrollment(
            &pool,
            CompleteOwnerPasskeyEnrollmentOptions {
                request_id: replacement_request.id,
                authenticated_by_passkey_id: fixture.passkey_id,
                new_passkey_id: replacement_id,
                credential_id: &format!("credential-{}", Uuid::new_v4().simple()),
                passkey: &serde_json::json!({"counter": 0}),
                turnkey_recovery_credential: &serde_json::json!({"challenge": "replacement"}),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            replaced["replaced_passkey_id"],
            first_recovery_id.to_string()
        );

        let states = sqlx::query_as::<_, (Uuid, String, Option<Uuid>)>(
            r#"SELECT id, status, revoked_by_passkey_id FROM owner_passkeys
               WHERE id IN ($1, $2) ORDER BY id"#,
        )
        .bind(first_recovery_id)
        .bind(replacement_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let first = states
            .iter()
            .find(|row| row.0 == first_recovery_id)
            .unwrap();
        let replacement = states.iter().find(|row| row.0 == replacement_id).unwrap();
        assert_eq!(first.1, "revoked");
        assert_eq!(first.2, Some(fixture.passkey_id));
        assert_eq!(replacement.1, "active");
        let request_status: String = sqlx::query_scalar(
            "SELECT status FROM owner_passkey_enrollment_requests WHERE id = $1",
        )
        .bind(replacement_request.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(request_status, "completed");
        let connection_status: String =
            sqlx::query_scalar("SELECT status FROM oauth_connections WHERE id = $1")
                .bind(fixture.context.credential_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(connection_status, "active");
        let audit_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM auth_audit_events
               WHERE organization_id = $1
                 AND action IN ('owner_passkey:added', 'owner_passkey:replaced')"#,
        )
        .bind(fixture.context.organization_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit_count, 2);
    }

    #[tokio::test]
    async fn passkey_revocation_requires_another_passkey_and_contains_sessions() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let (first_recovery_id, first_credential_id) =
            insert_owner_passkey(&pool, &fixture, "Recovery one", "recovery").await;
        let final_recovery_action = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: first_recovery_id,
            expected_credential_id: first_credential_id.clone(),
        };
        assert!(create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &sha256_hex(&random_secret()),
            &final_recovery_action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .is_err());

        let (_second_recovery_id, _) =
            insert_owner_passkey(&pool, &fixture, "Recovery two", "recovery").await;
        let primary_credential_id: String =
            sqlx::query_scalar("SELECT credential_id FROM owner_passkeys WHERE id = $1")
                .bind(fixture.passkey_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let self_revoke_action = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: fixture.passkey_id,
            expected_credential_id: primary_credential_id,
        };
        let self_revoke = create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &sha256_hex(&random_secret()),
            &self_revoke_action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
        assert!(complete_owner_approval(
            &pool,
            self_revoke.id,
            fixture.context.organization_id,
            fixture.context.principal_id,
            fixture.passkey_id,
            &serde_json::json!({"counter": 1}),
            "arc-testnet",
        )
        .await
        .is_err());

        let client_id: String =
            sqlx::query_scalar("SELECT client_id FROM oauth_connections WHERE id = $1")
                .bind(fixture.context.credential_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        let target_owner_connection = Uuid::new_v4();
        let target_agent_connection = Uuid::new_v4();
        let survivor_agent_connection = Uuid::new_v4();
        for (id, passkey_id, agent_bound) in [
            (target_owner_connection, first_recovery_id, true),
            (target_agent_connection, first_recovery_id, true),
            (survivor_agent_connection, fixture.passkey_id, true),
        ] {
            sqlx::query(
                r#"INSERT INTO oauth_connections (
                       id, organization_id, principal_id, passkey_id, agent_id,
                       agent_external_id, client_id, resource, scopes
                   ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ARRAY['wallet:read'])"#,
            )
            .bind(id)
            .bind(fixture.context.organization_id)
            .bind(fixture.context.principal_id)
            .bind(passkey_id)
            .bind(agent_bound.then_some(fixture.root_agent.id))
            .bind(agent_bound.then_some(fixture.root_agent.external_id.as_str()))
            .bind(&client_id)
            .bind("https://api.example/mcp/agent")
            .execute(&pool)
            .await
            .unwrap();
        }

        let revocation = create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &sha256_hex(&random_secret()),
            &final_recovery_action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
        let result = complete_owner_approval(
            &pool,
            revocation.id,
            fixture.context.organization_id,
            fixture.context.principal_id,
            fixture.passkey_id,
            &serde_json::json!({"counter": 2}),
            "arc-testnet",
        )
        .await
        .unwrap();
        assert_eq!(result["revoked"], true);
        assert_eq!(result["revoked_connections"], 2);

        let target_status: (String, Option<Uuid>) = sqlx::query_as(
            "SELECT status, revoked_by_passkey_id FROM owner_passkeys WHERE id = $1",
        )
        .bind(first_recovery_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(target_status.0, "revoked");
        assert_eq!(target_status.1, Some(fixture.passkey_id));
        let connection_states = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, status FROM oauth_connections WHERE id = ANY($1)",
        )
        .bind(vec![
            fixture.context.credential_id,
            target_owner_connection,
            target_agent_connection,
            survivor_agent_connection,
        ])
        .fetch_all(&pool)
        .await
        .unwrap();
        for (id, status) in connection_states {
            let expected = if id == survivor_agent_connection || id == fixture.context.credential_id
            {
                "active"
            } else {
                "revoked"
            };
            assert_eq!(status, expected);
        }
        let stale_approval_status: String =
            sqlx::query_scalar("SELECT status FROM owner_approval_requests WHERE id = $1")
                .bind(self_revoke.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(stale_approval_status, "expired");
    }

    #[tokio::test]
    async fn concurrent_recovery_revocations_preserve_a_recovery_passkey() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let (first_id, first_credential) =
            insert_owner_passkey(&pool, &fixture, "Recovery alpha", "recovery").await;
        let (second_id, second_credential) =
            insert_owner_passkey(&pool, &fixture, "Recovery beta", "recovery").await;
        let first_action = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: first_id,
            expected_credential_id: first_credential,
        };
        let second_action = OwnerApprovalAction::RevokeOwnerPasskey {
            passkey_id: second_id,
            expected_credential_id: second_credential,
        };
        let first_approval = create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &sha256_hex(&random_secret()),
            &first_action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();
        let second_approval = create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &sha256_hex(&random_secret()),
            &second_action,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .unwrap();

        let first_updated_passkey = serde_json::json!({"counter": 1});
        let second_updated_passkey = serde_json::json!({"counter": 2});
        let first = complete_owner_approval(
            &pool,
            first_approval.id,
            fixture.context.organization_id,
            fixture.context.principal_id,
            fixture.passkey_id,
            &first_updated_passkey,
            "arc-testnet",
        );
        let second = complete_owner_approval(
            &pool,
            second_approval.id,
            fixture.context.organization_id,
            fixture.context.principal_id,
            fixture.passkey_id,
            &second_updated_passkey,
            "arc-testnet",
        );
        let (first_result, second_result) = tokio::join!(first, second);
        assert_ne!(first_result.is_ok(), second_result.is_ok());

        let active_recovery_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM owner_passkeys
               WHERE organization_id = $1 AND principal_id = $2
                 AND status = 'active' AND purpose = 'recovery'"#,
        )
        .bind(fixture.context.organization_id)
        .bind(fixture.context.principal_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(active_recovery_count, 1);
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
        let runtime_scopes = vec!["wallet:read".to_string(), "workflow:read".to_string()];
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
                allowed_protocols: Some(vec![]),
                allowed_actions: Some(vec!["wallet:read".into()]),
                allowed_targets: Some(vec!["0x0000000000000000000000000000000000000001".into()]),
                max_value_wei: Some("0".into()),
                max_execution_fee_usd: Some(0.5),
                token_spend_limits: serde_json::json!([]),
                risk_permissions: vec![],
                rolling_window_seconds: 86_400,
                max_rolling_execution_fee_usd: Some(5.0),
                max_sponsored_gas_units: Some(1_000_000),
                max_rolling_sponsored_gas_units: Some(5_000_000),
                max_borrowed_value_usd: Some(0.0),
                max_rolling_borrowed_value_usd: Some(0.0),
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
    async fn approved_payment_plan_is_persisted_with_exact_recipients() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let mut plan = crate::workflows::PaymentPlanInput {
            name: "Weekly contractors".into(),
            agent_id: fixture.root_agent.external_id.clone(),
            schedule: crate::workflows::PaymentSchedule {
                cadence: crate::workflows::ScheduleCadence::Weekly,
                timezone: "Africa/Lagos".into(),
                local_time: "09:00".into(),
                weekday: Some("friday".into()),
                day_of_month: None,
            },
            recipients: vec![crate::workflows::PaymentRecipientInput {
                address: "0x0000000000000000000000000000000000000001".into(),
                amount_usdc: "5.25".into(),
                name: Some("Contractor".into()),
            }],
            reserve_usdc: "10".into(),
            surplus: None,
            callback_url: None,
        }
        .normalize(Utc::now())
        .unwrap();
        plan.recipients[0].verification = Some(crate::workflows::RecipientAddressVerification {
            chain: "arc-testnet".into(),
            address_kind: "wallet".into(),
            evidence: vec!["transaction_history".into()],
            verified_at: Utc::now(),
        });
        let result = approve_test_action(
            &pool,
            &fixture,
            &OwnerApprovalAction::CreatePaymentPlan { plan },
        )
        .await
        .unwrap();
        let plan_id = Uuid::parse_str(result["payment_plan_id"].as_str().unwrap()).unwrap();
        let (stored, recipients) = crate::workflows::get_plan(&pool, &fixture.context, plan_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, "active");
        assert_eq!(stored.reserve_raw, "10000000");
        assert_eq!(recipients.len(), 1);
        assert_eq!(recipients[0].amount_raw, "5250000");
        assert_eq!(recipients[0].name.as_deref(), Some("Contractor"));
        assert_eq!(recipients[0].address_kind.as_deref(), Some("wallet"));
        let saved_name: String = sqlx::query_scalar(
            r#"SELECT recipient_name FROM payment_recipient_contacts
               WHERE organization_id=$1 AND chain='arc-testnet'
                 AND recipient_address=$2"#,
        )
        .bind(fixture.context.organization_id)
        .bind(&recipients[0].recipient_address)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(saved_name, "Contractor");
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
            policy_impact: crate::policy::ExecutionPolicyImpact::default(),
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
        let different_operation = idempotency_fingerprint(&request, "execute:other").unwrap();
        assert_ne!(atomic, different_operation);

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
        reserve_policy_budget(&pool, row.id, 0.001, 1_000)
            .await
            .expect("reserve policy budget");
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
    async fn rolling_token_budget_is_atomic_idempotent_and_releasable() {
        let pool = setup_pool().await;
        let external_id = format!("budget-{}", Uuid::new_v4().simple());
        let context = create_test_auth_context(&pool, &external_id).await;
        let policy_id: Uuid = sqlx::query_scalar(
            "SELECT policy_id FROM agents WHERE organization_id = $1 AND external_id = $2",
        )
        .bind(context.organization_id)
        .bind(&external_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query(
            r#"UPDATE authorization_policies
               SET token_spend_limits = $2
               WHERE id = $1"#,
        )
        .bind(policy_id)
        .bind(serde_json::json!([{
            "token": crate::policy::ARC_USDC_ADDRESS,
            "max_per_execution_raw": "20000000",
            "max_rolling_raw": "20000000"
        }]))
        .execute(&pool)
        .await
        .unwrap();

        let mut first = sample_request(&external_id);
        first.policy_impact = crate::policy::ExecutionPolicyImpact::token_spend(
            crate::policy::ARC_USDC_ADDRESS.parse().unwrap(),
            ethers_core::types::U256::from(20_000_000u64),
        );
        let second = first.clone();
        let first_row = insert_execution_request(
            &pool,
            &context,
            &first,
            &ExecutionStatus::PaymentVerified,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();
        let second_row = insert_execution_request(
            &pool,
            &context,
            &second,
            &ExecutionStatus::PaymentVerified,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();

        let first_reservation = reserve_policy_budget(&pool, first_row.id, 0.0, 1);
        let second_reservation = reserve_policy_budget(&pool, second_row.id, 0.0, 1);
        let (first_result, second_result) = tokio::join!(first_reservation, second_reservation);
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let (reserved_id, denied_id) = if first_result.is_ok() {
            (first_row.id, second_row.id)
        } else {
            (second_row.id, first_row.id)
        };

        reserve_policy_budget(&pool, reserved_id, 0.0, 1)
            .await
            .expect("repeating an identical reservation is idempotent");
        let reservation_count: i64 = sqlx::query_scalar(
            r#"SELECT COUNT(*) FROM policy_budget_reservations
               WHERE organization_id = $1 AND agent_id = $2 AND status = 'reserved'"#,
        )
        .bind(first_row.organization_id)
        .bind(first_row.agent_uuid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reservation_count, 1);

        assert!(release_policy_budget_reservation(&pool, reserved_id)
            .await
            .unwrap());
        reserve_policy_budget(&pool, denied_id, 0.0, 1)
            .await
            .expect("released reservations no longer consume the rolling budget");
    }

    #[tokio::test]
    async fn approved_policy_update_revokes_unsigned_old_version_work() {
        let pool = setup_pool().await;
        let fixture = create_owner_control_fixture(&pool).await;
        let request = sample_request(&fixture.root_agent.external_id);
        let row = insert_execution_request(
            &pool,
            &fixture.context,
            &request,
            &ExecutionStatus::PaymentVerified,
            Some("0x1234567890abcdef1234567890abcdef12345678"),
            None,
        )
        .await
        .unwrap();
        reserve_policy_budget(&pool, row.id, 0.001, 1_000)
            .await
            .unwrap();
        let permit = issue_execution_permit(&pool, row.id, Some("1000"), 300)
            .await
            .unwrap();

        let mut update = update_policy_action(&fixture.root_policy);
        if let OwnerApprovalAction::UpdatePolicy {
            max_rolling_execution_fee_usd,
            ..
        } = &mut update
        {
            *max_rolling_execution_fee_usd = Some(9.0);
        }
        let result = approve_test_action(&pool, &fixture, &update).await.unwrap();
        assert_eq!(result["previous_version"], 1);
        assert_eq!(result["version"], 2);

        let updated = get_authorization_policy(
            &pool,
            fixture.context.organization_id,
            fixture.root_policy.id,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(updated.version, 2);
        assert_eq!(updated.max_rolling_execution_fee_usd, Some(9.0));
        assert!(claim_execution_permit(&pool, permit.id, row.id)
            .await
            .is_err());
        let request_status: String =
            sqlx::query_scalar("SELECT status FROM execution_requests WHERE id = $1")
                .bind(row.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(request_status, "failed");
        let reservation_status: String = sqlx::query_scalar(
            "SELECT status FROM policy_budget_reservations WHERE request_id = $1",
        )
        .bind(row.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(reservation_status, "released");

        assert!(create_owner_approval_request(
            &pool,
            &fixture.context,
            "arc-testnet",
            &hex::encode(Sha256::digest(Uuid::new_v4().as_bytes())),
            &update,
            Utc::now() + chrono::Duration::minutes(10),
        )
        .await
        .is_err());
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
        reserve_policy_budget(&pool, row.id, 0.001, 1_000)
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
        let payment = SettledExecutionFee {
            fee_id: Uuid::new_v4(),
            request_id: row.id,
            payer: "0x1234567890abcdef1234567890abcdef12345678".into(),
            amount_usd: 0.01,
            token: "USDC".into(),
            chain: "arc-testnet".into(),
            tx_hash: hash.clone(),
            amount_raw: "10000".into(),
            token_contract: "0x3600000000000000000000000000000000000000".into(),
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
            &ExecutionStatus::Pending,
            None,
            None,
        )
        .await
        .unwrap();
        let hash = format!("0x{}", hex::encode(Uuid::new_v4().as_bytes().repeat(2)));
        let existing_payment = SettledExecutionFee {
            fee_id: Uuid::new_v4(),
            request_id: first_row.id,
            payer: "0x0000000000000000000000000000000000000001".into(),
            amount_usd: 0.01,
            token: "USDC".into(),
            chain: "arc-testnet".into(),
            tx_hash: hash.clone(),
            amount_raw: "10000".into(),
            token_contract: "0x3600000000000000000000000000000000000000".into(),
        };
        finalize_arc_execution(
            &pool,
            ArcExecutionFinalization {
                request_id: first_row.id,
                chain: "arc-testnet",
                tx_hash: &hash,
                from_address: "0x0000000000000000000000000000000000000001",
                to_address: &first_req.target_contract,
                status: &ExecutionStatus::Confirmed,
                error_message: None,
                gas_used: Some(125_000),
                payment: Some(&existing_payment),
            },
        )
        .await
        .unwrap()
        .then_some(())
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
        let conflicting_payment = SettledExecutionFee {
            fee_id: Uuid::new_v4(),
            request_id: row.id,
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
