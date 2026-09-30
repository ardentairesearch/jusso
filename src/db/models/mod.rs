//! SQLx models that map directly to PostgreSQL tables.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PrincipalRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub display_name: Option<String>,
    pub principal_type: String,
    pub status: String,
    pub auth_version: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CredentialBindingRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub agent_id: Option<Uuid>,
    pub credential_kind: String,
    pub client_id: String,
    pub public_jwk: serde_json::Value,
    pub public_jwk_thumbprint: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuthorizationPolicyRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub version: i64,
    pub allowed_chains: Option<Vec<String>>,
    pub allowed_protocols: Option<Vec<String>>,
    pub allowed_actions: Option<Vec<String>>,
    pub allowed_targets: Option<Vec<String>>,
    pub allow_raw_execution: bool,
    pub max_value_wei: Option<String>,
    pub max_execution_fee_usd: Option<f64>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AgentRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub external_id: String,
    pub display_name: String,
    pub parent_agent_id: Option<Uuid>,
    pub policy_id: Uuid,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FederationTrustRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub agent_id: Uuid,
    pub name: String,
    pub issuer: String,
    pub jwks_uri: String,
    pub audience: String,
    pub subject_pattern: String,
    pub scopes: Vec<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

// ──────────────────────────── execution_requests ─────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ExecutionRequestRow {
    pub id: Uuid,
    pub chain: String,
    pub target_contract: String,
    pub calldata: String,
    pub value: String,
    pub strategy_id: Option<String>,
    pub gas_estimate: Option<i64>,
    pub cost_usd: Option<f64>,
    pub status: String,
    pub tx_hash: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub agent_id: String,
    pub smart_wallet_address: Option<String>,
    pub callback_url: Option<String>,
    pub payload_hash: String,
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub agent_uuid: Uuid,
    pub instance_id: Option<Uuid>,
    pub policy_id: Uuid,
    pub policy_version: i64,
    pub idempotency_key: Option<String>,
    pub idempotency_fingerprint: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ExecutionPermitRow {
    pub id: Uuid,
    pub request_id: Uuid,
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub agent_id: Uuid,
    pub instance_id: Option<Uuid>,
    pub policy_id: Uuid,
    pub policy_version: i64,
    pub payload_hash: String,
    pub wallet_address: String,
    pub chain: String,
    pub execution_fee_raw: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────── transactions ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TransactionRow {
    pub id: Uuid,
    pub request_id: Uuid,
    pub chain: String,
    pub tx_hash: String,
    pub from_address: String,
    pub to_address: String,
    pub gas_used: Option<i64>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

// ──────────────────────────── payments ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentRow {
    pub id: Uuid,
    pub request_id: Uuid,
    pub payer: String,
    pub amount_usd: f64,
    pub amount_raw: String,
    pub token: String,
    pub token_contract: String,
    pub payment_chain: String,
    pub payment_tx_hash: String,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
}
