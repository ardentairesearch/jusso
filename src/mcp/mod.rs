//! Hosted MCP servers with separate runtime and control-plane capabilities.

use anyhow::Context;
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
    types::{AuthContext, BatchCall, ExecutionRequest},
};

pub type AgentMcpService = StreamableHttpService<AgentMcp, LocalSessionManager>;
pub type ControlMcpService = StreamableHttpService<ControlMcp, LocalSessionManager>;

pub fn agent_service(state: AppState, auth: AuthService) -> anyhow::Result<AgentMcpService> {
    let config = streamable_http_config(&state.config.public_api_base_url)?;
    Ok(StreamableHttpService::new(
        move || Ok(AgentMcp::new(state.clone(), auth.clone())),
        Default::default(),
        config,
    ))
}

pub fn control_service(state: AppState) -> anyhow::Result<ControlMcpService> {
    let config = streamable_http_config(&state.config.public_api_base_url)?;
    Ok(StreamableHttpService::new(
        move || Ok(ControlMcp::new(state.clone())),
        Default::default(),
        config,
    ))
}

fn streamable_http_config(public_api_base_url: &str) -> anyhow::Result<StreamableHttpServerConfig> {
    let url = reqwest::Url::parse(public_api_base_url)
        .context("PUBLIC_API_BASE_URL must be an absolute URL")?;
    let host = url
        .host_str()
        .context("PUBLIC_API_BASE_URL must include a hostname")?;
    let mut config = StreamableHttpServerConfig::default().with_json_response(true);
    if !config
        .allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        config.allowed_hosts.push(host.to_ascii_lowercase());
    }
    Ok(config)
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

fn mcp_idempotency_key(
    explicit: Option<&str>,
    auth: &AuthContext,
    context: &RequestContext<RoleServer>,
    params: &impl std::fmt::Debug,
) -> Result<String, ErrorData> {
    let key = explicit.map(str::to_owned).unwrap_or_else(|| {
        let material = format!("{}:{:?}:{params:?}", auth.credential_id, context.id);
        format!("mcp-{}", hex::encode(Sha256::digest(material.as_bytes())))
    });
    db::validate_idempotency_key(&key).map_err(tool_error)?;
    Ok(key)
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct WalletParams {
    /// Arc network name. Defaults to the server's configured Arc network.
    chain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct ExecutionStatusParams {
    /// Execution request UUID returned by an execute tool.
    request_id: String,
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
    fn to_request(
        &self,
        default_chain: &str,
        agent_id: String,
    ) -> Result<UniswapSwapRequest, ErrorData> {
        let swap_kind = match self.swap_kind.as_deref().unwrap_or("exact_in") {
            "exact_in" => UniswapSwapKind::ExactIn,
            "exact_out" => UniswapSwapKind::ExactOut,
            _ => return Err(tool_error("swap_kind must be exact_in or exact_out")),
        };
        Ok(UniswapSwapRequest {
            agent_id,
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RawCallParams {
    /// Destination contract address.
    target_contract: String,
    /// 0x-prefixed contract calldata.
    calldata: String,
    /// Native Arc value in wei as a decimal string. Defaults to zero.
    value: Option<String>,
}

impl From<RawCallParams> for BatchCall {
    fn from(call: RawCallParams) -> Self {
        Self {
            target_contract: call.target_contract,
            calldata: call.calldata,
            value: call.value.unwrap_or_else(|| "0".into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RawTransactionParams {
    /// Destination contract for a single call. Omit when batch_calls is used.
    target_contract: Option<String>,
    /// 0x-prefixed calldata for a single call. Omit when batch_calls is used.
    calldata: Option<String>,
    /// Native Arc value in wei as a decimal string. Defaults to zero.
    value: Option<String>,
    /// Calls to execute atomically in one UserOperation. Maximum 16.
    batch_calls: Option<Vec<RawCallParams>>,
    /// Arc network name. Defaults to the configured Arc network.
    chain: Option<String>,
    /// Optional strategy correlation identifier.
    strategy_id: Option<String>,
    /// Optional HTTPS completion webhook.
    callback_url: Option<String>,
}

impl RawTransactionParams {
    fn to_request(&self, default_chain: &str, agent_id: String) -> ExecutionRequest {
        ExecutionRequest {
            agent_id,
            chain: self
                .chain
                .clone()
                .unwrap_or_else(|| default_chain.to_string()),
            target_contract: self.target_contract.clone().unwrap_or_default(),
            calldata: self.calldata.clone().unwrap_or_default(),
            value: self.value.clone().unwrap_or_else(|| "0".into()),
            strategy_id: self.strategy_id.clone(),
            batch_calls: self
                .batch_calls
                .clone()
                .map(|calls| calls.into_iter().map(Into::into).collect()),
            callback_url: self.callback_url.clone(),
            policy_impact: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RawExecutionParams {
    #[serde(flatten)]
    transaction: RawTransactionParams,
    /// Stable retry key. Omit to derive it from the MCP request ID and arguments.
    idempotency_key: Option<String>,
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
        chain: Option<&str>,
        scope: &'static str,
        resource: &'static str,
        protocol: Option<&'static str>,
    ) -> Result<(AuthContext, String), ErrorData> {
        let auth = request_auth(context)?;
        let authorized = self
            .auth
            .authorize_mcp_action(&auth, chain, scope, resource, protocol)
            .await
            .map_err(tool_error)?;
        let agent_id = authorized
            .agent_external_id
            .clone()
            .ok_or_else(|| tool_error("agent MCP access token is not bound to an agent"))?;
        Ok((authorized, agent_id))
    }
}

#[tool_router]
impl AgentMcp {
    #[tool(
        description = "Get or provision the connected agent's dedicated Arc smart-account address."
    )]
    async fn get_wallet(
        &self,
        Parameters(params): Parameters<WalletParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(&context, Some(chain), "wallet:read", "/wallet", None)
            .await?;
        let response = services::handle_get_wallet(
            &self.state.engine,
            &self.state.wallet_registry,
            auth.organization_id,
            &agent_id,
            chain,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }

    #[tool(description = "Read the Arc USDC balance held by the connected agent's smart account.")]
    async fn get_wallet_balance(
        &self,
        Parameters(params): Parameters<WalletParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
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
            &agent_id,
            chain,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }

    #[tool(description = "Read the current status and transaction hash of an execution request.")]
    async fn get_execution_status(
        &self,
        Parameters(params): Parameters<ExecutionStatusParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "execution:read")?;
        let request_id = Uuid::parse_str(params.request_id.trim())
            .map_err(|_| tool_error("request_id must be a UUID"))?;
        let response = services::handle_execution_status(&self.state.db_pool, &auth, request_id)
            .await
            .map_err(tool_error)?
            .ok_or_else(|| tool_error("execution request was not found"))?;
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
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
                Some(chain),
                "transaction:simulate",
                "/protocols/uniswap-v4/swap/quote",
                Some("uniswap-v4"),
            )
            .await?;
        let request = params.to_request(self.state.config.arc_network.name(), agent_id)?;
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
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
                Some(chain),
                "transaction:simulate",
                "/protocols/uniswap-v4/swap/simulate",
                Some("uniswap-v4"),
            )
            .await?;
        let request = params.to_request(self.state.config.arc_network.name(), agent_id)?;
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
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
                Some(chain),
                "transaction:execute",
                "/protocols/uniswap-v4/swap",
                Some("uniswap-v4"),
            )
            .await?;
        let request = params.to_request(self.state.config.arc_network.name(), agent_id)?;
        let idempotency_key =
            mcp_idempotency_key(params.idempotency_key.as_deref(), &auth, &context, &params)?;
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

    #[tool(
        description = "Simulate a raw single-call or atomic-batch Arc UserOperation for the connected agent. Requires the agent policy to explicitly allow raw execution."
    )]
    async fn simulate_raw_transaction(
        &self,
        Parameters(params): Parameters<RawTransactionParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
                Some(chain),
                "transaction:simulate",
                "/simulate",
                None,
            )
            .await?;
        let request = params.to_request(self.state.config.arc_network.name(), agent_id);
        let response = services::handle_simulate_authenticated(
            &self.state.engine,
            &self.state.db_pool,
            &self.state.wallet_registry,
            &auth,
            &request,
        )
        .await
        .map_err(tool_error)?;
        json_output(response)
    }

    #[tool(
        description = "Execute a raw single-call or atomic-batch transaction through sponsored Arc ERC-4337 for the connected agent. Requires explicit raw-execution policy permission and is always simulated before queueing."
    )]
    async fn execute_raw_transaction(
        &self,
        Parameters(params): Parameters<RawExecutionParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let chain = params
            .transaction
            .chain
            .as_deref()
            .unwrap_or(self.state.config.arc_network.name());
        let (auth, agent_id) = self
            .authorize(
                &context,
                Some(chain),
                "transaction:execute",
                "/execute",
                None,
            )
            .await?;
        let request = params
            .transaction
            .to_request(self.state.config.arc_network.name(), agent_id);
        let idempotency_key =
            mcp_idempotency_key(params.idempotency_key.as_deref(), &auth, &context, &params)?;
        let mut redis = self.state.redis_conn.clone();
        let response = services::handle_execute_idempotent(
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
    /// Token-specific raw-unit spending limits. Empty means token spending is denied.
    #[serde(default)]
    token_spend_limits: Vec<crate::policy::TokenSpendLimit>,
    /// Explicit high-risk permissions such as borrowing or leverage.
    #[serde(default)]
    risk_permissions: Vec<String>,
    /// Rolling budget window in seconds. Defaults to 24 hours.
    rolling_window_seconds: Option<i64>,
    /// Maximum cumulative execution fees in the rolling window.
    max_rolling_execution_fee_usd: Option<f64>,
    /// Maximum sponsored gas units in one execution.
    max_sponsored_gas_units: Option<i64>,
    /// Maximum sponsored gas units in the rolling window.
    max_rolling_sponsored_gas_units: Option<i64>,
    /// Maximum borrowed USD value in one execution.
    max_borrowed_value_usd: Option<f64>,
    /// Maximum borrowed USD value in the rolling window.
    max_rolling_borrowed_value_usd: Option<f64>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct UpdatePolicyApprovalParams {
    /// Authorization policy UUID returned by list_authorization_policies.
    policy_id: String,
    /// Current policy version returned by list_authorization_policies.
    expected_version: i64,
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
    /// Token-specific raw-unit spending limits. Empty means token spending is denied.
    #[serde(default)]
    token_spend_limits: Vec<crate::policy::TokenSpendLimit>,
    /// Explicit high-risk permissions such as borrowing or leverage.
    #[serde(default)]
    risk_permissions: Vec<String>,
    /// Rolling budget window in seconds.
    rolling_window_seconds: i64,
    /// Maximum cumulative execution fees in the rolling window.
    max_rolling_execution_fee_usd: Option<f64>,
    /// Maximum sponsored gas units in one execution.
    max_sponsored_gas_units: Option<i64>,
    /// Maximum sponsored gas units in the rolling window.
    max_rolling_sponsored_gas_units: Option<i64>,
    /// Maximum borrowed USD value in one execution.
    max_borrowed_value_usd: Option<f64>,
    /// Maximum borrowed USD value in the rolling window.
    max_rolling_borrowed_value_usd: Option<f64>,
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

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct OwnerPasskeyEnrollmentParams {
    /// Human-readable name for the new passkey, such as "Office laptop".
    label: String,
    /// Credential role: standard or recovery.
    purpose: String,
    /// Active passkey UUID to replace atomically after the new passkey is created.
    replaces_passkey_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct OwnerPasskeyEnrollmentStatusParams {
    /// Enrollment request UUID returned by request_add_or_replace_owner_passkey.
    enrollment_request_id: String,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
struct RevokeOwnerPasskeyApprovalParams {
    /// Active owner passkey UUID returned by list_owner_passkeys.
    passkey_id: String,
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
                    "token_spend_limits": row.token_spend_limits,
                    "risk_permissions": row.risk_permissions,
                    "rolling_window_seconds": row.rolling_window_seconds,
                    "max_rolling_execution_fee_usd": row.max_rolling_execution_fee_usd,
                    "max_sponsored_gas_units": row.max_sponsored_gas_units,
                    "max_rolling_sponsored_gas_units": row.max_rolling_sponsored_gas_units,
                    "max_borrowed_value_usd": row.max_borrowed_value_usd,
                    "max_rolling_borrowed_value_usd": row.max_rolling_borrowed_value_usd,
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
                max_execution_fee_usd: params
                    .max_execution_fee_usd
                    .or(Some(crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD)),
                token_spend_limits: serde_json::to_value(params.token_spend_limits)
                    .map_err(tool_error)?,
                risk_permissions: params.risk_permissions,
                rolling_window_seconds: params
                    .rolling_window_seconds
                    .unwrap_or(crate::auth::DEFAULT_ROLLING_WINDOW_SECONDS),
                max_rolling_execution_fee_usd: params
                    .max_rolling_execution_fee_usd
                    .or(Some(crate::auth::DEFAULT_MAX_ROLLING_EXECUTION_FEE_USD)),
                max_sponsored_gas_units: params
                    .max_sponsored_gas_units
                    .or(Some(crate::auth::DEFAULT_MAX_SPONSORED_GAS_UNITS)),
                max_rolling_sponsored_gas_units: params
                    .max_rolling_sponsored_gas_units
                    .or(Some(crate::auth::DEFAULT_MAX_ROLLING_SPONSORED_GAS_UNITS)),
                max_borrowed_value_usd: params.max_borrowed_value_usd.or(Some(0.0)),
                max_rolling_borrowed_value_usd: params.max_rolling_borrowed_value_usd.or(Some(0.0)),
            },
        )
        .await
    }

    #[tool(
        description = "Create an owner passkey approval for a full policy replacement. The expected version prevents overwriting a concurrent change, and approval revokes unsigned work pinned to the old version."
    )]
    async fn request_update_policy_approval(
        &self,
        Parameters(params): Parameters<UpdatePolicyApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "policy:manage")?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::UpdatePolicy {
                policy_id: Uuid::parse_str(&params.policy_id).map_err(tool_error)?,
                expected_version: params.expected_version,
                name: params.name,
                allowed_chains: params.allowed_chains,
                allowed_protocols: params.allowed_protocols,
                allowed_actions: params.allowed_actions,
                allowed_targets: params.allowed_targets,
                allow_raw_execution: params.allow_raw_execution,
                max_value_wei: params.max_value_wei,
                max_execution_fee_usd: params.max_execution_fee_usd,
                token_spend_limits: serde_json::to_value(params.token_spend_limits)
                    .map_err(tool_error)?,
                risk_permissions: params.risk_permissions,
                rolling_window_seconds: params.rolling_window_seconds,
                max_rolling_execution_fee_usd: params.max_rolling_execution_fee_usd,
                max_sponsored_gas_units: params.max_sponsored_gas_units,
                max_rolling_sponsored_gas_units: params.max_rolling_sponsored_gas_units,
                max_borrowed_value_usd: params.max_borrowed_value_usd,
                max_rolling_borrowed_value_usd: params.max_rolling_borrowed_value_usd,
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
        if !auth.allows_scope("policy:manage")
            && !auth.allows_scope("agent:manage")
            && !auth.allows_scope("credential:manage")
        {
            return Err(tool_error(
                "access token must grant policy:manage, agent:manage, or credential:manage",
            ));
        }
        let id = Uuid::parse_str(&params.approval_request_id).map_err(tool_error)?;
        let approval = db::get_owner_approval_request(&self.state.db_pool, &auth, id)
            .await
            .map_err(tool_error)?
            .ok_or_else(|| tool_error("owner approval request was not found"))?;
        json_output(approval)
    }

    #[tool(
        description = "List the owner's passkeys and recovery readiness. Credential material is never returned."
    )]
    async fn list_owner_passkeys(
        &self,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let rows = sqlx::query_as::<_, OwnerPasskeyView>(
            r#"SELECT op.id, op.label, op.purpose, op.status, op.created_at,
                      op.last_used_at, op.revoked_at,
                      op.id = c.passkey_id AS is_current_connection
               FROM owner_passkeys op
               JOIN oauth_connections c ON c.id = $3
                 AND c.organization_id = op.organization_id
                 AND c.principal_id = op.principal_id
               WHERE op.organization_id = $1 AND op.principal_id = $2
               ORDER BY
                 CASE op.status WHEN 'active' THEN 0 ELSE 1 END,
                 op.created_at"#,
        )
        .bind(auth.organization_id)
        .bind(auth.principal_id)
        .bind(auth.credential_id)
        .fetch_all(&self.state.db_pool)
        .await
        .map_err(tool_error)?;
        let active_count = rows.iter().filter(|row| row.status == "active").count();
        let recovery_count = rows
            .iter()
            .filter(|row| row.status == "active" && row.purpose == "recovery")
            .count();
        json_output(serde_json::json!({
            "passkeys": rows,
            "active_count": active_count,
            "active_recovery_count": recovery_count,
            "recovery_ready": recovery_count > 0
        }))
    }

    #[tool(
        description = "Create a 10-minute browser ceremony to add an owner passkey or atomically replace an existing one. The owner confirms with an active passkey before creating the new credential."
    )]
    async fn request_add_or_replace_owner_passkey(
        &self,
        Parameters(params): Parameters<OwnerPasskeyEnrollmentParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let replaces_passkey_id = params
            .replaces_passkey_id
            .as_deref()
            .map(Uuid::parse_str)
            .transpose()
            .map_err(tool_error)?;
        let raw_token = db::random_secret();
        let token_hash = hex::encode(Sha256::digest(raw_token.as_bytes()));
        let request = db::create_owner_passkey_enrollment_request(
            &self.state.db_pool,
            &auth,
            db::CreateOwnerPasskeyEnrollmentOptions {
                token_hash: &token_hash,
                label: &params.label,
                purpose: &params.purpose,
                replaces_passkey_id,
                expires_at: Utc::now() + Duration::minutes(10),
            },
        )
        .await
        .map_err(tool_error)?;
        json_output(serde_json::json!({
            "enrollment_request_id": request.id,
            "status": request.status,
            "label": request.label,
            "purpose": request.purpose,
            "replaces_passkey_id": request.replaces_passkey_id,
            "expires_at": request.expires_at,
            "enrollment_url": format!(
                "{}/passkeys/enroll/{}",
                self.state.config.public_api_base_url.trim_end_matches('/'),
                raw_token
            ),
            "message": "Open the enrollment URL, confirm with an active owner passkey, then create the new passkey."
        }))
    }

    #[tool(
        description = "Check whether an owner passkey enrollment is pending, completed, or expired."
    )]
    async fn get_owner_passkey_enrollment_status(
        &self,
        Parameters(params): Parameters<OwnerPasskeyEnrollmentStatusParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let id = Uuid::parse_str(&params.enrollment_request_id).map_err(tool_error)?;
        let request = db::get_owner_passkey_enrollment_request(&self.state.db_pool, &auth, id)
            .await
            .map_err(tool_error)?
            .ok_or_else(|| tool_error("passkey enrollment request was not found"))?;
        json_output(serde_json::json!({
            "enrollment_request_id": request.id,
            "status": request.status,
            "label": request.label,
            "purpose": request.purpose,
            "replaces_passkey_id": request.replaces_passkey_id,
            "created_passkey_id": request.created_passkey_id,
            "expires_at": request.expires_at,
            "created_at": request.created_at,
            "completed_at": request.completed_at
        }))
    }

    #[tool(
        description = "Request revocation of an owner passkey. A different active owner passkey must approve it, and the final active or final recovery passkey cannot be removed."
    )]
    async fn request_revoke_owner_passkey_approval(
        &self,
        Parameters(params): Parameters<RevokeOwnerPasskeyApprovalParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<McpJson<serde_json::Value>, ErrorData> {
        let auth = request_auth(&context)?;
        require_scope(&auth, "credential:manage")?;
        let passkey_id = Uuid::parse_str(&params.passkey_id).map_err(tool_error)?;
        let credential_id = sqlx::query_scalar::<_, String>(
            r#"SELECT credential_id FROM owner_passkeys
               WHERE id = $1 AND organization_id = $2 AND principal_id = $3
                 AND status = 'active'"#,
        )
        .bind(passkey_id)
        .bind(auth.organization_id)
        .bind(auth.principal_id)
        .fetch_optional(&self.state.db_pool)
        .await
        .map_err(tool_error)?
        .ok_or_else(|| tool_error("active owner passkey was not found"))?;
        self.request_owner_approval(
            &auth,
            db::OwnerApprovalAction::RevokeOwnerPasskey {
                passkey_id,
                expected_credential_id: credential_id,
            },
        )
        .await
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

#[derive(Debug, Serialize, sqlx::FromRow)]
struct OwnerPasskeyView {
    id: Uuid,
    label: String,
    purpose: String,
    status: String,
    created_at: chrono::DateTime<chrono::Utc>,
    last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    is_current_connection: bool,
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
            AgentMcp::get_execution_status_tool_attr().name.to_string(),
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
            AgentMcp::simulate_raw_transaction_tool_attr()
                .name
                .to_string(),
            AgentMcp::execute_raw_transaction_tool_attr()
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
            ControlMcp::request_update_policy_approval_tool_attr()
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
            ControlMcp::list_owner_passkeys_tool_attr().name.to_string(),
            ControlMcp::request_add_or_replace_owner_passkey_tool_attr()
                .name
                .to_string(),
            ControlMcp::get_owner_passkey_enrollment_status_tool_attr()
                .name
                .to_string(),
            ControlMcp::request_revoke_owner_passkey_approval_tool_attr()
                .name
                .to_string(),
        ];
        assert!(runtime.iter().any(|name| name == "execute_uniswap_v4_swap"));
        assert!(runtime
            .iter()
            .any(|name| name == "simulate_raw_transaction"));
        assert!(runtime.iter().any(|name| name == "execute_raw_transaction"));
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
        assert!(control
            .iter()
            .any(|name| name == "request_revoke_owner_passkey_approval"));
        assert!(runtime.iter().all(|name| !control.contains(name)));
    }

    #[test]
    fn agent_runtime_tool_inputs_use_the_oauth_bound_agent() {
        let wallet_schema = serde_json::to_value(schemars::schema_for!(WalletParams)).unwrap();
        let swap_schema = serde_json::to_value(schemars::schema_for!(SwapParams)).unwrap();
        let raw_schema = serde_json::to_value(schemars::schema_for!(RawExecutionParams)).unwrap();

        for schema in [&wallet_schema, &swap_schema, &raw_schema] {
            let properties = schema
                .pointer("/properties")
                .and_then(serde_json::Value::as_object)
                .expect("tool schema properties");
            assert!(!properties.contains_key("agent_id"));
        }
        let raw_properties = raw_schema["properties"].as_object().unwrap();
        assert!(raw_properties.contains_key("target_contract"));
        assert!(raw_properties.contains_key("batch_calls"));
        assert!(raw_properties.contains_key("idempotency_key"));
        assert!(!raw_properties.contains_key("transaction"));
    }

    #[test]
    fn raw_tool_request_uses_bound_agent_and_preserves_atomic_batch() {
        let params = RawTransactionParams {
            target_contract: None,
            calldata: None,
            value: None,
            batch_calls: Some(vec![RawCallParams {
                target_contract: "0x0000000000000000000000000000000000000001".into(),
                calldata: "0x12345678".into(),
                value: None,
            }]),
            chain: None,
            strategy_id: Some("strategy-1".into()),
            callback_url: None,
        };
        let request = params.to_request("arc-testnet", "primary-agent".into());
        assert_eq!(request.agent_id, "primary-agent");
        assert_eq!(request.chain, "arc-testnet");
        assert!(request.target_contract.is_empty());
        let calls = request.batch_calls.expect("batch calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].value, "0");
    }

    #[test]
    fn public_mcp_host_is_allowed_without_disabling_host_validation() {
        let config = streamable_http_config("https://api.jusso.tech").expect("MCP config");
        assert!(config
            .allowed_hosts
            .iter()
            .any(|host| host == "api.jusso.tech"));
        assert!(config.allowed_hosts.iter().any(|host| host == "localhost"));
        assert!(!config.allowed_hosts.is_empty());
    }
}
