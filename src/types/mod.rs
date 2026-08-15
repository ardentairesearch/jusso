//! Core domain types shared across the entire platform.
//!
//! Every module imports from here so changes propagate cleanly.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use uuid::Uuid;

// ──────────────────────────── Enumerations ────────────────────────────

/// Blockchain networks we support.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Ethereum,
    Base,
    Arbitrum,
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Ethereum => write!(f, "ethereum"),
            Chain::Base => write!(f, "base"),
            Chain::Arbitrum => write!(f, "arbitrum"),
        }
    }
}

impl Chain {
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ethereum" | "eth" | "mainnet" => Some(Chain::Ethereum),
            "base" => Some(Chain::Base),
            "arbitrum" | "arb" => Some(Chain::Arbitrum),
            _ => None,
        }
    }

    /// Return the EVM chain ID.
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::Ethereum => 1,
            Chain::Base => 8453,
            Chain::Arbitrum => 42161,
        }
    }
}

/// Lifecycle of an execution request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Pending,
    PaymentRequired,
    PaymentVerified,
    Queued,
    Broadcasting,
    Confirmed,
    Failed,
    Reverted,
}

impl std::fmt::Display for ExecutionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| format!("{self:?}"));
        write!(f, "{s}")
    }
}

// ──────────────────────────── API DTOs ────────────────────────────────

/// A single call within a batch transaction.
///
/// When sent inside `ExecutionRequest.batch_calls`, each entry becomes one
/// leg of the protocol phase in a native Base transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCall {
    pub target_contract: String,
    pub calldata: String,
    #[serde(default)]
    pub value: String,
}

/// Inbound request body for `POST /execute` and `POST /simulate`.
///
/// Supports two modes:
///   1. **Single call** — populate `target_contract` / `calldata` / `value`
///      directly. Maps to `BaseAccount.execute()`.
///   2. **Batch call** — populate `batch_calls` (2+). Maps to
///      `BaseAccount.executeBatch(Call[])` (v0.9). When `batch_calls` is
///      present, `target_contract` / `calldata` / `value` are ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    /// Agent-supplied identifier scoped to the authenticated organization.
    pub agent_id: String,
    pub chain: String,
    /// Target contract for single-call mode. Ignored when `batch_calls` is set.
    #[serde(default)]
    pub target_contract: String,
    /// Calldata for single-call mode. Ignored when `batch_calls` is set.
    #[serde(default)]
    pub calldata: String,
    #[serde(default)]
    pub value: String,
    pub strategy_id: Option<String>,
    /// Optional batch of calls to execute atomically in one protocol phase.
    /// When present (and non-empty), takes priority over the single-call fields.
    #[serde(default)]
    pub batch_calls: Option<Vec<BatchCall>>,
    /// Optional webhook callback URL.  When provided, the platform will POST
    /// the final execution result to this URL when the transaction reaches a
    /// terminal state (confirmed, failed, reverted).  The agent does not need
    /// to poll `/status/{id}` — the result will be pushed automatically.
    #[serde(default)]
    pub callback_url: Option<String>,
}

/// Response after an execution or simulation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResponse {
    pub request_id: Uuid,
    pub status: ExecutionStatus,
    /// The agent's Base account address.
    /// Always included so the agent knows where to send tokens before executing.
    pub smart_wallet_address: Option<String>,
    pub estimated_gas: Option<u64>,
    pub estimated_cost_usd: Option<f64>,
    /// Stablecoin symbol charged for execution when the fee is collected
    /// atomically in phase zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_fee_token: Option<String>,
    /// Exact execution fee in the token's smallest unit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_fee_raw: Option<String>,
    pub tx_hash: Option<String>,
    pub message: String,
}

/// Response for `GET /wallet` — returns the agent's smart wallet address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletResponse {
    /// The agent-supplied identifier.
    pub agent_id: String,
    /// The provider-backed Base account address.
    pub smart_wallet_address: String,
    /// Whether the canonical native-account delegation is installed.
    /// The EOA can receive assets regardless of this value.
    pub deployed: bool,
    /// Human-readable note explaining wallet funding.
    pub message: String,
}

/// Response for `GET /status/{id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub request_id: Uuid,
    pub status: ExecutionStatus,
    pub chain: String,
    pub tx_hash: Option<String>,
    pub cost_usd: Option<f64>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A single token balance entry in a wallet balance response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    /// Token symbol, e.g. `"USDV"` or `"USDC"`.
    pub symbol: String,
    /// Token contract address on the queried chain.
    pub contract_address: String,
    /// Raw on-chain balance in the token's smallest unit.
    pub raw: String,
    /// Human-readable balance scaled by token decimals.
    pub formatted: String,
    /// Number of decimals used for formatting.
    pub decimals: u8,
}

/// Response for `GET /wallet/balance`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceResponse {
    pub agent_id: String,
    pub smart_wallet_address: String,
    pub chain: String,
    /// Native token balance (ETH / ARB etc.) in wei as a decimal string.
    pub native_balance_wei: String,
    /// Native balance formatted in the chain's base unit (e.g. ETH).
    pub native_balance_formatted: String,
    /// Balances for each accepted payment token configured on this chain.
    pub tokens: Vec<TokenBalance>,
}

// ──────────────────────────── Internal Models ─────────────────────────

/// A fully validated execution job ready for the queue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionJob {
    pub request_id: Uuid,
    /// Stable organization that owns the agent and execution.
    #[serde(default)]
    pub organization_id: Uuid,
    /// Exact authorization record issued after policy evaluation and simulation.
    pub execution_permit_id: Uuid,
    /// The agent-supplied ID (not namespaced; organization ownership is resolved before queuing).
    pub agent_id: String,
    /// The agent's Base account address.
    pub smart_wallet_address: String,
    pub chain: Chain,
    pub target_contract: String,
    pub calldata: String,
    pub value: String,
    pub created_at: DateTime<Utc>,
    /// Number of times this job has been attempted (for poison-pill protection).
    /// Defaults to 0 for newly enqueued jobs.
    #[serde(default)]
    pub attempt_count: u32,
    /// When present, the worker uses `executeBatch` instead of `execute`.
    /// Each entry maps to one leg of the batch.
    #[serde(default)]
    pub batch_calls: Option<Vec<BatchCall>>,
    /// Agent-supplied webhook URL.  The worker POSTs the result here on completion.
    #[serde(default)]
    pub callback_url: Option<String>,
    /// Stablecoin fee transfer included in phase zero of the same transaction.
    #[serde(default)]
    pub execution_fee: Option<ExecutionFeeCharge>,
}

/// Stablecoin execution fee collected atomically with a protocol action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionFeeCharge {
    pub token_symbol: String,
    pub token_contract: String,
    pub amount_raw: String,
    pub amount_usd: f64,
    pub recipient_address: String,
}

/// Simulation output from the execution engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub gas_estimate: u64,
    pub max_fee_per_gas_wei: Option<String>,
    pub return_data: Option<String>,
    pub error: Option<String>,
}

/// A payment settled by an x402 facilitator before execution is queued.
#[derive(Debug, Clone)]
pub struct SettledExecutionPayment {
    pub payment_id: Uuid,
    /// Optional original quote request ID from a prior 402 response.
    /// When present, server can lock required payment to that quote.
    pub quote_request_id: Option<Uuid>,
    pub payer: String,
    pub amount_usd: f64,
    pub token: String,
    pub chain: String,
    pub tx_hash: String,
    /// The on-chain amount transferred in token-native units.
    pub confirmed_amount_raw: Option<String>,
    /// The token contract address settled by the facilitator.
    pub token_contract: Option<String>,
}

// ─────────────────────── Authentication Context ───────────────────────

/// Authentication mechanism used for the current request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ApiKey,
    LocalJwk,
    WorkloadIdentity,
}

/// Authenticated identity attached to every protected request.
///
/// Wallet and resource ownership always use `organization_id`, never the
/// credential ID, so credential rotation cannot alter a wallet address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub organization_id: Uuid,
    pub principal_id: Uuid,
    pub credential_id: Uuid,
    pub credential_kind: CredentialKind,
    pub scopes: BTreeSet<String>,
    /// Stable logical agent bound to this token, when the credential is agent-specific.
    pub agent_id: Option<Uuid>,
    pub agent_external_id: Option<String>,
    /// Ephemeral runtime identity for workload-federated tokens.
    pub instance_id: Option<Uuid>,
    /// RFC 9449 JWK thumbprint to which the access token is sender-constrained.
    pub dpop_jkt: Option<String>,
}

impl AuthContext {
    pub fn allows_scope(&self, required: &str) -> bool {
        self.scopes.contains("*") || self.scopes.contains(required)
    }

    pub fn is_bound_to_other_agent(&self, agent_id: Uuid) -> bool {
        self.agent_id.is_some_and(|bound| bound != agent_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_from_str_loose() {
        assert_eq!(Chain::from_str_loose("ethereum"), Some(Chain::Ethereum));
        assert_eq!(Chain::from_str_loose("eth"), Some(Chain::Ethereum));
        assert_eq!(Chain::from_str_loose("mainnet"), Some(Chain::Ethereum));
        assert_eq!(Chain::from_str_loose("ETHEREUM"), Some(Chain::Ethereum));
        assert_eq!(Chain::from_str_loose("base"), Some(Chain::Base));
        assert_eq!(Chain::from_str_loose("arbitrum"), Some(Chain::Arbitrum));
        assert_eq!(Chain::from_str_loose("arb"), Some(Chain::Arbitrum));
        assert_eq!(Chain::from_str_loose("solana"), None);
        assert_eq!(Chain::from_str_loose("polygon"), None);
        assert_eq!(Chain::from_str_loose(""), None);
    }

    #[test]
    fn test_chain_display() {
        assert_eq!(Chain::Ethereum.to_string(), "ethereum");
        assert_eq!(Chain::Base.to_string(), "base");
        assert_eq!(Chain::Arbitrum.to_string(), "arbitrum");
    }

    #[test]
    fn test_chain_ids() {
        assert_eq!(Chain::Ethereum.chain_id(), 1);
        assert_eq!(Chain::Base.chain_id(), 8453);
        assert_eq!(Chain::Arbitrum.chain_id(), 42161);
    }

    #[test]
    fn test_execution_status_display() {
        assert_eq!(ExecutionStatus::Pending.to_string(), "pending");
        assert_eq!(
            ExecutionStatus::PaymentRequired.to_string(),
            "payment_required"
        );
        assert_eq!(
            ExecutionStatus::PaymentVerified.to_string(),
            "payment_verified"
        );
        assert_eq!(ExecutionStatus::Queued.to_string(), "queued");
        assert_eq!(ExecutionStatus::Broadcasting.to_string(), "broadcasting");
        assert_eq!(ExecutionStatus::Confirmed.to_string(), "confirmed");
        assert_eq!(ExecutionStatus::Failed.to_string(), "failed");
        assert_eq!(ExecutionStatus::Reverted.to_string(), "reverted");
    }

    #[test]
    fn auth_context_enforces_agent_allow_list() {
        let bound_agent = Uuid::new_v4();
        let context = AuthContext {
            organization_id: Uuid::new_v4(),
            principal_id: Uuid::new_v4(),
            credential_id: Uuid::new_v4(),
            credential_kind: CredentialKind::ApiKey,
            scopes: BTreeSet::new(),
            agent_id: Some(bound_agent),
            agent_external_id: Some("agent-a".into()),
            instance_id: None,
            dpop_jkt: Some("test-thumbprint".into()),
        };
        assert!(!context.is_bound_to_other_agent(bound_agent));
        assert!(context.is_bound_to_other_agent(Uuid::new_v4()));
    }

    #[test]
    fn test_execution_job_serde_round_trip() {
        let job = ExecutionJob {
            request_id: Uuid::new_v4(),
            organization_id: Uuid::new_v4(),
            execution_permit_id: Uuid::new_v4(),
            agent_id: "serde".into(),
            smart_wallet_address: "0xaaaa".into(),
            chain: Chain::Ethereum,
            target_contract: "0xcccc".into(),
            calldata: "0xdddd".into(),
            value: "123".into(),
            created_at: Utc::now(),
            attempt_count: 2,
            batch_calls: Some(vec![BatchCall {
                target_contract: "0xeeee".into(),
                calldata: "0xffff".into(),
                value: "456".into(),
            }]),
            callback_url: Some("https://example.com/cb".into()),
            execution_fee: None,
        };

        let json = serde_json::to_string(&job).expect("serialize execution job");
        let round_trip: ExecutionJob =
            serde_json::from_str(&json).expect("deserialize execution job");
        assert_eq!(round_trip.request_id, job.request_id);
        assert_eq!(round_trip.attempt_count, 2);
        assert_eq!(round_trip.batch_calls.expect("batch calls").len(), 1);
    }
}
