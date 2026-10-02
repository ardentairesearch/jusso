//! Hosted MCP servers with separate runtime and control-plane capabilities.

use chrono::{Duration, Utc};
use rmcp::{
    handler::server::{
        router::tool::ToolRouter,
        wrapper::{Json as McpJson, Parameters},
    },
    model::{Implementation, ServerCapabilities, ServerConfig},
    service::RequestContext,
    tool, tool_handler, tool_router,
    transport::streamable_http_server::{
        session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
    },
    ErrorData, RoleServer, ServerHandler,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    api::{routes::AppState, services},
    auth::AuthService,
    db,
    protocols::uniswap_v4::{
        adapter::UniswapSwapKind, service as uniswap_service, UniswapPoolsQuery, UniswapSwapRequest,
    },
    types::AuthContext,
};

pub type AgentMcpService = StreamableHttpService<AgentMcp, LocalSessionManager>;
pub type ControlMcpService = StreamableHttpService<ControlMcp, LocalSessionManager>;

pub fn agent_service(state: AppState, auth: AuthService) -> AgentMcpService {
    let config = StreamableHttpServerConfig::default().with_json_response(true);
    StreamableHttpService::new(
        move || Ok(AgentMcp::new(state.clone(), auth.clone())),
        Default::default(),
        config,
    )
}

pub fn control_service(state: AppState) -> ControlMcpService {
    let config = StreamableHttpServerConfig::default().with_json_response(true);
    StreamableHttpService::new(
        move || Ok(ControlMcp::new(state.clone())),
        Default::default(),
        config,
    )
}

fn request_auth(context: &RequestContext<RoleServer>) -> Result<AuthContext, ErrorData> {
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<AuthContext>())
        .cloned()
        .ok_or_else(|| ErrorData::invalid_request("authenticated Jusso context is missing", None))
}

fn require_scope(context: &AuthContext, scope: &'static str) -> Result<(), ErrorData> {
    if context.allows_scope(scope) {
        Ok(())
    } else {
        Err(ErrorData::invalid_request(
            format!("access token does not grant {scope}"),
            None,
        ))
    }
}

fn tool_error(error: impl std::fmt::Display) -> ErrorData {
    ErrorData::invalid_request(error.to_string(), None)
}

fn json_output(value: impl Serialize) -> Result<McpJson<serde_json::Value>, ErrorData> {
    serde_json::to_value(value)
        .map(McpJson)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct WalletParams {
    /// Logical Jusso agent ID.
    agent_id: String,
    /// Arc network name. Defaults to the server's configured Arc network.
    chain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct PoolsParams {
    /// First token contract address.
    token_a: String,
    /// Second token contract address.
    token_b: String,
    /// Include pools with hooks. Defaults to false.
    include_hooked_pools: Option<bool>,
    /// Arc network name. Defaults to the server's configured Arc network.
    chain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SwapParams {
    /// Logical Jusso agent ID.
    agent_id: String,
    /// Input ERC-20 token address.
    token_in: String,
    /// Output token address. The zero address means native Arc USDC.
    token_out: String,
    /// Raw token amount in base units.
    amount_raw: String,
    /// exact_in or exact_out. Defaults to exact_in.
    swap_kind: Option<String>,
    /// Explicit pool fee. Omit with tick_spacing and hooks for discovery.
    fee: Option<u32>,
    /// Explicit pool tick spacing. Omit with fee and hooks for discovery.
    tick_spacing: Option<i32>,
    /// Explicit hooks contract. Omit for automatic discovery.
    hooks: Option<String>,
    /// Permit automatic selection of hooked pools.
    include_hooked_pools: Option<bool>,
    /// Hook calldata as a 0x-prefixed byte string.
    hook_data: Option<String>,
    /// Minimum output for exact_in or maximum input for exact_out.
    limit_raw: Option<String>,
    /// Maximum slippage in basis points. Defaults to 50.
    slippage_bps: Option<u16>,
    /// Unix deadline. Defaults to the protocol adapter's safe window.
    deadline: Option<u64>,
    /// Arc network name. Defaults to the configured Arc network.
    chain: Option<String>,
    /// Optional strategy correlation identifier.
    strategy_id: Option<String>,
    /// Optional HTTPS completion webhook.
    callback_url: Option<String>,
    /// Stable retry key. Omit to derive it from the MCP request ID and arguments.
    idempotency_key: Option<String>,
}

impl SwapParams {
    fn to_request(&self, default_chain: &str) -> Result<UniswapSwapRequest, ErrorData> {
        let swap_kind = match self.swap_kind.as_deref().unwrap_or("exact_in") {
            "exact_in" => UniswapSwapKind::ExactIn,
            "exact_out" => UniswapSwapKind::ExactOut,
            _ => return Err(tool_error("swap_kind must be exact_in or exact_out")),
        };
        Ok(UniswapSwapRequest {
            agent_id: self.agent_id.clone(),
            chain: self
                .chain
                .clone()
                .unwrap_or_else(|| default_chain.to_string()),
            token_in: self.token_in.clone(),
            token_out: self.token_out.clone(),
            fee: self.fee,
            tick_spacing: self.tick_spacing,
            hooks: self.hooks.clone(),
            include_hooked_pools: self.include_hooked_pools.unwrap_or(false),
            hook_data: self.hook_data.clone().unwrap_or_else(|| "0x".into()),
            swap_kind,
            amount_raw: self.amount_raw.clone(),
            limit_raw: self.limit_raw.clone(),
            slippage_bps: self.slippage_bps.unwrap_or(50),
            deadline: self.deadline,
            strategy_id: self.strategy_id.clone(),
            callback_url: self.callback_url.clone(),
        })
    }
}

#[derive(Clone)]
pub struct AgentMcp {
    state: AppState,
    auth: AuthService,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

impl AgentMcp {
    fn new(state: AppState, auth: AuthService) -> Self {
        Self {
            state,
            auth,
            tool_router: Self::tool_router(),
        }
    }

    async fn authorize(
        &self,
        context: &RequestContext<RoleServer>,
        agent_id: &str,
        chain: Option<&str>,
        scope: &'static str,
        resource: &'static str,
        protocol: Option<&'static str>,
    ) -> Result<AuthContext, ErrorData> {
        let auth = request_auth(context)?;
        self.auth
            .authorize_mcp_action(&auth, agent_id, chain, scope, resource, protocol)
            .await
            .map_err(tool_error)
    }
}

#[tool_router]
impl AgentMcp {
    #[tool(description = "Get or provision an agent's dedicated Arc smart-account address.")]
    async fn get_wallet(
        &self,
        Parameters(params): Parameters<WalletParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let auth = self
            .authorize(
                &context,
                &params.agent_id,
                Some(chain),
                "wallet:read",
                "/wallet",
                None,
            )
            .await?;
        let response = services::handle_get_wallet(
            &self.state.engine,
            &self.state.wallet_registry,
            auth.organization_id,
            &params.agent_id,
            chain,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }

    #[tool(description = "Read the Arc USDC balance held by an agent's smart account.")]
    async fn get_wallet_balance(
        &self,
        Parameters(params): Parameters<WalletParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let auth = self
            .authorize(
                &context,
                &params.agent_id,
                Some(chain),
                "wallet:read",
                "/wallet/balance",
                None,
            )
            .await?;
        let response = services::handle_get_wallet_balance(
            &self.state.engine,
            &self.state.wallet_registry,
            auth.organization_id,
            &params.agent_id,
            chain,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }

    #[tool(description = "Discover initialized Uniswap V4 pools for a token pair on Arc.")]
    async fn discover_uniswap_v4_pools(
        &self,
        Parameters(params): Parameters<PoolsParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "protocol:read")?;
        let query = UniswapPoolsQuery {
            chain: params
                .chain
                .unwrap_or_else(|| self.state.config.arc_network.name().to_string()),
            token_a: params.token_a,
            token_b: params.token_b,
            include_hooked_pools: params.include_hooked_pools.unwrap_or(false),
        };
        json_output(
            uniswap_service::handle_pools(&self.state.engine, &query)
                .await
                .map_err(tool_error)?,
        )
    }

    #[tool(description = "Quote a Uniswap V4 swap without submitting an on-chain operation.")]
    async fn quote_uniswap_v4_swap(
        &self,
        Parameters(params): Parameters<SwapParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let request = params.to_request(self.state.config.arc_network.name())?;
        let auth = self
            .authorize(
                &context,
                &request.agent_id,
                Some(&request.chain),
                "transaction:simulate",
                "/protocols/uniswap-v4/swap/quote",
                Some("uniswap-v4"),
            )
            .await?;
        json_output(
            uniswap_service::handle_quote(
                &self.state.engine,
                &self.state.wallet_registry,
                auth.organization_id,
                &request,
            )
            .await
            .map_err(tool_error)?,
        )
    }

    #[tool(description = "Fully simulate a Uniswap V4 swap as an Arc UserOperation.")]
    async fn simulate_uniswap_v4_swap(
        &self,
        Parameters(params): Parameters<SwapParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let request = params.to_request(self.state.config.arc_network.name())?;
        let auth = self
            .authorize(
                &context,
                &request.agent_id,
                Some(&request.chain),
                "transaction:simulate",
                "/protocols/uniswap-v4/swap/simulate",
                Some("uniswap-v4"),
            )
            .await?;
        json_output(
            uniswap_service::handle_swap_simulate(
                &self.state.engine,
                &self.state.db_pool,
                &self.state.wallet_registry,
                &auth,
                &request,
            )
            .await
            .map_err(tool_error)?,
        )
    }

    #[tool(
        description = "Execute a policy-authorized Uniswap V4 swap through sponsored Arc ERC-4337."
    )]
    async fn execute_uniswap_v4_swap(
        &self,
        Parameters(params): Parameters<SwapParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let request = params.to_request(self.state.config.arc_network.name())?;
        let auth = self
            .authorize(
                &context,
                &request.agent_id,
                Some(&request.chain),
                "transaction:execute",
                "/protocols/uniswap-v4/swap",
                Some("uniswap-v4"),
            )
            .await?;
        let idempotency_key = params.idempotency_key.clone().unwrap_or_else(|| {
            let material = format!("{}:{:?}:{:?}", auth.credential_id, context.id, params);
            format!("mcp-{}", hex::encode(Sha256::digest(material.as_bytes())))
        });
        db::validate_idempotency_key(&idempotency_key).map_err(tool_error)?;
        if let Some(existing) = services::handle_existing_protocol_execution(
            &self.state.engine,
            &self.state.db_pool,
            &auth,
            &request.agent_id,
            &idempotency_key,
        )
        .await
        .map_err(tool_error)?
        {
            return json_output(existing);
        }
        let mut redis = self.state.redis_conn.clone();
        let response = uniswap_service::handle_swap(
            &self.state.engine,
            &self.state.db_pool,
            &mut redis,
            &self.state.wallet_registry,
            &auth,
            &request,
            &idempotency_key,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }
}

#[tool_handler]
impl ServerHandler for AgentMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("jusso-agent", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Jusso runtime tools. Execute only for the authenticated organization and within the agent's assigned policy.",
            )
    }
}

#[derive(Clone)]
pub struct ControlMcp {
    state: AppState,
    #[allow(dead_code)]
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RevokeConnectionParams {
    /// OAuth connection UUID returned by list_oauth_connections.
    connection_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CreatePolicyApprovalParams {
    /// Human-readable policy name.
    name: String,
    /// Allowed Arc network names. Use the configured Arc network only.
    allowed_chains: Option<Vec<String>>,
    /// Allowed protocol identifiers, currently uniswap-v4.
    allowed_protocols: Option<Vec<String>>,
    /// Allowed runtime and typed protocol actions.
    allowed_actions: Option<Vec<String>>,
    /// Allowed EVM target addresses. A wildcard is an explicit dangerous opt-in.
    allowed_targets: Option<Vec<String>>,
    /// Explicitly permit raw transaction routes.
    #[serde(default)]
    allow_raw_execution: bool,
    /// Maximum native value in wei.
    max_value_wei: Option<String>,
    /// Maximum execution fee in USDC-denominated dollars.
    max_execution_fee_usd: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AssignPolicyApprovalParams {
    /// Logical Jusso agent ID.
    agent_id: String,
    /// Existing active authorization policy UUID.
    policy_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RevokePolicyApprovalParams {
    /// Unassigned active authorization policy UUID.
    policy_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ApprovalStatusParams {
    /// Approval request UUID returned by a request_*_approval tool.
    approval_request_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct CreateAgentApprovalParams {
    /// Stable logical ID for the new agent.
    agent_id: String,
    /// Human-readable name shown during owner review.
    display_name: String,
    /// Optional logical parent agent ID for constrained delegation.
    parent_agent_id: Option<String>,
    /// Existing active authorization policy UUID.
    policy_id: String,
    /// Runtime scopes. Defaults to the supported runtime scope set.
    #[serde(default)]
    scopes: Vec<String>,
    /// Lifetime of the one-time enrollment token. Defaults to 15 minutes.
    enrollment_ttl_seconds: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct AgentLifecycleApprovalParams {
    /// Logical Jusso agent ID.
    agent_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct SignerRotationStatusParams {
    /// Signer-rotation UUID returned after the owner approves the request.
    rotation_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RotateAgentCredentialApprovalParams {
    /// Logical Jusso agent ID.
    agent_id: String,
    /// Scopes for the replacement runtime credential.
    #[serde(default)]
    scopes: Vec<String>,
    /// Lifetime of the one-time enrollment token. Defaults to 15 minutes.
    enrollment_ttl_seconds: Option<i64>,
}

impl ControlMcp {
    fn new(state: AppState) -> Self {
        Self {
            state,
            tool_router: Self::tool_router(),
        }
    }

    async fn request_owner_approval(
        &self,
        auth: &AuthContext,
        action: db::OwnerApprovalAction,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        self.request_owner_approval_with_output(auth, action, serde_json::Map::new())
            .await
    }

    async fn request_owner_approval_with_output(
        &self,
        auth: &AuthContext,
        action: db::OwnerApprovalAction,
        one_time_output: serde_json::Map<String, serde_json::Value>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let raw_token = db::random_secret();
        let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
        let approval = db::create_owner_approval_request(
            &self.state.db_pool,
            auth,
            self.state.config.arc_network.name(),
            &token_hash,
            &action,
            Utc::now() + Duration::minutes(10),
        )
        .await
        .map_err(tool_error)?;
        let mut output = serde_json::json!({
            "approval_request_id": approval.id,
            "status": approval.status,
            "expires_at": approval.expires_at,
            "approval_url": format!(
                "{}/approve/{}",
                self.state.config.public_api_base_url.trim_end_matches('/'),
                raw_token
            ),
            "review": approval.presentation,
            "message": "Owner passkey approval is required before this change is applied."
        });
        output
            .as_object_mut()
            .expect("approval output is an object")
            .extend(one_time_output);
        json_output(output)
    }
}

#[tool_router]
impl ControlMcp {
    #[tool(description = "List agents visible to the authenticated organization owner.")]
    async fn list_agents(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        json_output(
            db::list_agents_for_principal(
                &self.state.db_pool,
                auth.organization_id,
                auth.principal_id,
            )
            .await
            .map_err(tool_error)?,
        )
    }

    #[tool(description = "List the organization's structured authorization policies.")]
    async fn list_authorization_policies(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "policy:manage")?;
        let rows = db::list_authorization_policies(&self.state.db_pool, auth.organization_id)
            .await
            .map_err(tool_error)?;
        let values = rows
            .into_iter()
            .map(|row| {
                serde_json::json!({
                    "id": row.id,
                    "name": row.name,
                    "version": row.version,
                    "allowed_chains": row.allowed_chains,
                    "allowed_protocols": row.allowed_protocols,
                    "allowed_actions": row.allowed_actions,
                    "allowed_targets": row.allowed_targets,
                    "allow_raw_execution": row.allow_raw_execution,
                    "max_value_wei": row.max_value_wei,
                    "max_execution_fee_usd": row.max_execution_fee_usd,
                    "is_active": row.is_active
                })
            })
            .collect::<Vec<_>>();
        json_output(values)
    }

    #[tool(
        description = "Draft an authorization policy and create a short-lived owner passkey approval. This does not create the policy until the owner approves the exact structured permissions."
    )]
    async fn request_create_policy_approval(
        &self,
        Parameters(params): Parameters<CreatePolicyApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "policy:manage")?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::CreatePolicy {
                name: params.name,
                allowed_chains: params.allowed_chains,
                allowed_protocols: params.allowed_protocols,
                allowed_actions: params.allowed_actions,
                allowed_targets: params.allowed_targets,
                allow_raw_execution: params.allow_raw_execution,
                max_value_wei: params.max_value_wei,
                max_execution_fee_usd: params.max_execution_fee_usd,
            },
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to assign an existing policy to an agent. The review shows the current and proposed effective permissions."
    )]
    async fn request_assign_policy_approval(
        &self,
        Parameters(params): Parameters<AssignPolicyApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        require_scope(&auth, "policy:manage")?;
        let policy_id = Uuid::parse_str(&params.policy_id).map_err(tool_error)?;
        let (agent, current_policy) =
            db::authorize_execution_agent(&self.state.db_pool, &auth, params.agent_id.trim())
                .await
                .map_err(tool_error)?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::AssignPolicy {
                agent_id: agent.id,
                expected_current_policy_id: current_policy.id,
                policy_id,
            },
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to revoke an unassigned authorization policy."
    )]
    async fn request_revoke_policy_approval(
        &self,
        Parameters(params): Parameters<RevokePolicyApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "policy:manage")?;
        let policy_id = Uuid::parse_str(&params.policy_id).map_err(tool_error)?;
        self.request_owner_approval(&auth, db::OwnerApprovalAction::RevokePolicy { policy_id })
            .await
    }

    #[tool(
        description = "Create a passkey approval for a new agent, its policy, and a one-time runtime enrollment. The returned enrollment token is shown once and works only after approval."
    )]
    async fn request_create_agent_approval(
        &self,
        Parameters(params): Parameters<CreateAgentApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        require_scope(&auth, "policy:manage")?;
        let parent_agent_id = match params.parent_agent_id.as_deref() {
            Some(external_id) => Some(
                db::get_agent_for_owner_by_external_id(
                    &self.state.db_pool,
                    auth.organization_id,
                    auth.principal_id,
                    external_id.trim(),
                )
                .await
                .map_err(tool_error)?
                .ok_or_else(|| tool_error("parent agent was not found"))?
                .id,
            ),
            None => None,
        };
        let scopes = if params.scopes.is_empty() {
            crate::auth::RUNTIME_SCOPES
                .iter()
                .map(|scope| (*scope).to_string())
                .collect()
        } else {
            params.scopes
        };
        let enrollment_token = format!("jso_enroll_{}", db::random_secret());
        let enrollment_token_hash = hex::encode(Sha256::digest(enrollment_token.as_bytes()));
        let mut one_time_output = serde_json::Map::new();
        one_time_output.insert(
            "enrollment_token".into(),
            serde_json::Value::String(enrollment_token),
        );
        one_time_output.insert(
            "enrollment_message".into(),
            serde_json::Value::String(
                "Store this token securely. It is shown once and becomes usable only after owner approval."
                    .into(),
            ),
        );
        self.request_owner_approval_with_output(
            &auth,
            db::OwnerApprovalAction::CreateAgent {
                external_id: params.agent_id.trim().to_string(),
                display_name: params.display_name.trim().to_string(),
                parent_agent_id,
                policy_id: Uuid::parse_str(&params.policy_id).map_err(tool_error)?,
                runtime_scopes: scopes,
                enrollment_token_hash,
                enrollment_ttl_seconds: params.enrollment_ttl_seconds.unwrap_or(900),
            },
            one_time_output,
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to suspend an agent. This blocks its descendants and revokes its runtime access while preserving wallets and assets."
    )]
    async fn request_suspend_agent_approval(
        &self,
        Parameters(params): Parameters<AgentLifecycleApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        let agent = db::get_agent_for_owner_by_external_id(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            params.agent_id.trim(),
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("agent was not found"))?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::SuspendAgent { agent_id: agent.id },
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to reactivate a suspended agent. Previously revoked credentials remain revoked."
    )]
    async fn request_reactivate_agent_approval(
        &self,
        Parameters(params): Parameters<AgentLifecycleApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        let agent = db::get_agent_for_owner_by_external_id(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            params.agent_id.trim(),
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("agent was not found"))?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::ReactivateAgent { agent_id: agent.id },
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to revoke an agent's local runtime credentials and issue one replacement enrollment token. This does not rotate its Turnkey onchain signer."
    )]
    async fn request_rotate_agent_runtime_credential_approval(
        &self,
        Parameters(params): Parameters<RotateAgentCredentialApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        require_scope(&auth, "credential:manage")?;
        let agent = db::get_agent_for_owner_by_external_id(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            params.agent_id.trim(),
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("agent was not found"))?;
        let scopes = if params.scopes.is_empty() {
            crate::auth::RUNTIME_SCOPES
                .iter()
                .map(|scope| (*scope).to_string())
                .collect()
        } else {
            params.scopes
        };
        let enrollment_token = format!("jso_enroll_{}", db::random_secret());
        let enrollment_token_hash = hex::encode(Sha256::digest(enrollment_token.as_bytes()));
        let mut one_time_output = serde_json::Map::new();
        one_time_output.insert(
            "enrollment_token".into(),
            serde_json::Value::String(enrollment_token),
        );
        one_time_output.insert(
            "enrollment_message".into(),
            serde_json::Value::String(
                "Store this token securely. It is shown once and becomes usable only after owner approval."
                    .into(),
            ),
        );
        self.request_owner_approval_with_output(
            &auth,
            db::OwnerApprovalAction::RotateAgentCredential {
                agent_id: agent.id,
                runtime_scopes: scopes,
                enrollment_token_hash,
                enrollment_ttl_seconds: params.enrollment_ttl_seconds.unwrap_or(900),
            },
            one_time_output,
        )
        .await
    }

    #[tool(
        description = "Request owner passkey approval to replace an agent's Turnkey onchain signer while preserving its Arc smart-account address and assets. Agent execution pauses until reconciliation completes."
    )]
    async fn request_rotate_agent_onchain_signer_approval(
        &self,
        Parameters(params): Parameters<AgentLifecycleApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        require_scope(&auth, "credential:manage")?;
        let agent = db::get_agent_for_owner_by_external_id(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            params.agent_id.trim(),
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("agent was not found"))?;
        let binding = db::get_agent_signer_binding_for_owner(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            agent.id,
            self.state.config.arc_network.chain_id() as i64,
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| {
            tool_error("agent must have a provisioned Arc smart account before signer rotation")
        })?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::RotateAgentOnchainSigner {
                agent_id: agent.id,
                expected_agent_wallet_id: binding.agent_wallet_id,
                expected_managed_wallet_id: binding.managed_wallet_id,
                expected_smart_account_address: binding.smart_account_address,
                chain_id: binding.chain_id,
            },
        )
        .await
    }

    #[tool(
        description = "Get the operational status of an approved onchain signer rotation, including any recovery-required state."
    )]
    async fn get_agent_onchain_signer_rotation_status(
        &self,
        Parameters(params): Parameters<SignerRotationStatusParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "agent:manage")?;
        let rotation_id = Uuid::parse_str(&params.rotation_id).map_err(tool_error)?;
        let rotation = db::get_agent_signer_rotation_for_owner(
            &self.state.db_pool,
            auth.organization_id,
            auth.principal_id,
            rotation_id,
        )
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("signer rotation was not found"))?;
        json_output(rotation)
    }

    #[tool(
        description = "Check whether an owner policy or agent-lifecycle approval is pending, approved, or expired."
    )]
    async fn get_owner_approval_status(
        &self,
        Parameters(params): Parameters<ApprovalStatusParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        if !auth.allows_scope("policy:manage") && !auth.allows_scope("agent:manage") {
            return Err(tool_error(
                "access token must grant policy:manage or agent:manage",
            ));
        }
        let id = Uuid::parse_str(&params.approval_request_id).map_err(tool_error)?;
        let approval = db::get_owner_approval_request(&self.state.db_pool, &auth, id)
            .await
            .map_err(tool_error)?
            .ok_or_else(|| tool_error("owner approval request was not found"))?;
        json_output(approval)
    }

    #[tool(description = "List active and revoked remote MCP connections for this owner.")]
    async fn list_oauth_connections(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let rows = sqlx::query_as::<_, OAuthConnectionView>(
            r#"SELECT id, agent_external_id, client_id, resource, scopes, status,
                      created_at, last_used_at, revoked_at
               FROM oauth_connections
               WHERE organization_id = $1 AND principal_id = $2
               ORDER BY created_at DESC"#,
        )
        .bind(auth.organization_id)
        .bind(auth.principal_id)
        .fetch_all(&self.state.db_pool)
        .await
        .map_err(tool_error)?;
        json_output(rows)
    }

    #[tool(
        description = "Revoke a remote MCP connection and all access and refresh tokens derived from it."
    )]
    async fn revoke_oauth_connection(
        &self,
        Parameters(params): Parameters<RevokeConnectionParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let connection_id = Uuid::parse_str(&params.connection_id).map_err(tool_error)?;
        let result = sqlx::query(
            r#"UPDATE oauth_connections
               SET status = 'revoked', revoked_at = now(), updated_at = now()
               WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                 AND status = 'active'"#,
        )
        .bind(connection_id)
        .bind(auth.organization_id)
        .bind(auth.principal_id)
        .execute(&self.state.db_pool)
        .await
        .map_err(tool_error)?;
        if result.rows_affected() != 1 {
            return Err(tool_error("active OAuth connection was not found"));
        }
        json_output(serde_json::json!({
            "connection_id": connection_id,
            "revoked": true
        }))
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
struct OAuthConnectionView {
    id: Uuid,
    agent_external_id: Option<String>,
    client_id: String,
    resource: String,
    scopes: Vec<String>,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[tool_handler]
impl ServerHandler for ControlMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("jusso-control", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Jusso control-plane tools. Policy changes alter agent authority and should be owner-approved.",
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_and_control_tool_catalogs_are_separate() {
        let runtime = [
            AgentMcp::get_wallet_tool_attr().name.to_string(),
            AgentMcp::get_wallet_balance_tool_attr().name.to_string(),
            AgentMcp::discover_uniswap_v4_pools_tool_attr()
                .name
                .to_string(),
            AgentMcp::quote_uniswap_v4_swap_tool_attr().name.to_string(),
            AgentMcp::simulate_uniswap_v4_swap_tool_attr()
                .name
                .to_string(),
            AgentMcp::execute_uniswap_v4_swap_tool_attr()
                .name
                .to_string(),
        ];
        let control = [
            ControlMcp::list_agents_tool_attr().name.to_string(),
            ControlMcp::list_authorization_policies_tool_attr()
                .name
                .to_string(),
            ControlMcp::list_oauth_connections_tool_attr()
                .name
                .to_string(),
            ControlMcp::revoke_oauth_connection_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_create_policy_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_assign_policy_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_revoke_policy_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_create_agent_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_suspend_agent_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_reactivate_agent_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_rotate_agent_runtime_credential_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_rotate_agent_onchain_signer_approval_tool_attr()
                .name
                .to_string(),
            ControlMcp::get_agent_onchain_signer_rotation_status_tool_attr()
                .name
                .to_string(),
            ControlMcp::get_owner_approval_status_tool_attr()
                .name
                .to_string(),
        ];
        assert!(runtime.iter().any(|name| name == "execute_uniswap_v4_swap"));
        assert!(control.iter().all(|name| !name.contains("execute")));
        assert!(control
            .iter()
            .filter(|name| {
                name.contains("policy") && name.as_str() != "list_authorization_policies"
            })
            .all(|name| name.contains("approval")));
        assert!(control
            .iter()
            .any(|name| name == "get_agent_onchain_signer_rotation_status"));
        assert!(runtime.iter().all(|name| !control.contains(name)));
    }
}
