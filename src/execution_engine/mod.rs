//! Execution request validation and Arc RPC access.

pub mod pricing;

use anyhow::{anyhow, Result};
use ethers::prelude::*;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

use crate::arc::{execution::ArcExecutionClient, smart_account::SmartAccountRegistry};
use crate::arc::{quote_execution_fee_usdc_raw, ARC_MIN_GAS_PRICE_WEI};
use crate::config::RuntimeConfig;
use crate::types::{Chain, ExecutionRequest};

fn validate_sponsorship_budget(
    gas_limit: U256,
    fee_per_gas: U256,
    max_gas_units: u64,
    max_gas_cost_wei: U256,
) -> Result<()> {
    if gas_limit > U256::from(max_gas_units) {
        return Err(anyhow!(
            "Arc operation exceeds the sponsored gas-unit limit"
        ));
    }
    let sponsored_cost = gas_limit
        .checked_mul(fee_per_gas)
        .ok_or_else(|| anyhow!("Arc sponsored gas cost overflow"))?;
    if sponsored_cost > max_gas_cost_wei {
        return Err(anyhow!(
            "Arc operation exceeds the sponsored gas-cost limit"
        ));
    }
    Ok(())
}

/// Shared state for Arc execution.
#[derive(Clone)]
pub struct ExecutionEngine {
    pub config: RuntimeConfig,
    pub smart_accounts: SmartAccountRegistry,
    pub arc_client: ArcExecutionClient,
    /// Per-chain JSON-RPC providers.
    providers: HashMap<Chain, Arc<Provider<Http>>>,
}

impl ExecutionEngine {
    /// Boot the execution engine for all configured chains.
    pub fn new(config: RuntimeConfig, smart_accounts: SmartAccountRegistry) -> Result<Self> {
        let mut providers = HashMap::new();

        for (chain, chain_cfg) in &config.chains {
            let provider = Provider::<Http>::try_from(&chain_cfg.rpc_url)
                .map_err(|e| anyhow!("failed to create provider for {chain}: {e}"))?;
            let provider = Arc::new(provider);
            providers.insert(chain.clone(), provider.clone());

            info!(chain = %chain, "provider initialized");
        }

        let arc_client = ArcExecutionClient::new(
            &config.alchemy_api_key,
            config.arc_network,
            &config.alchemy_gas_policy_id,
            std::time::Duration::from_secs(config.receipt_timeout_seconds),
            config.arc_max_sponsored_gas_units,
        )?;
        Ok(Self {
            config,
            smart_accounts,
            arc_client,
            providers,
        })
    }

    /// Resolve the provider for a given chain.
    pub fn provider_for_chain(&self, chain: &Chain) -> Result<Arc<Provider<Http>>> {
        self.providers
            .get(chain)
            .cloned()
            .ok_or_else(|| anyhow!("chain {chain} is not configured"))
    }

    // ────────────────────── Validation ────────────────────────────────

    /// Validate an inbound execution request.
    ///
    /// `agent_id` replaces a caller-supplied wallet address.
    /// The agent does NOT need to supply a wallet — the platform resolves
    /// the smart wallet from the namespaced agent_id.
    ///
    /// Supports two modes:
    ///   * **Single call** — `target_contract` + `calldata` are validated
    ///     directly.
    ///   * **Batch call** — `batch_calls` is present and each entry is
    ///     validated independently.
    pub fn validate(&self, req: &ExecutionRequest) -> Result<Chain> {
        // Chain resolution
        let chain = Chain::from_str_loose(&req.chain)
            .ok_or_else(|| anyhow!("unsupported chain: {}", req.chain))?;

        // Verify the chain is actually configured (has an RPC URL)
        if !self.providers.contains_key(&chain) {
            return Err(anyhow!(
                "chain '{chain}' is recognized but not configured for this Arc runtime"
            ));
        }

        // Agent ID must be non-empty
        if req.agent_id.trim().is_empty() {
            return Err(anyhow!("agent_id is required"));
        }
        // Agent ID length check (reasonable limit to prevent abuse)
        if req.agent_id.len() > 256 {
            return Err(anyhow!("agent_id too long (max 256 characters)"));
        }

        // Decide between batch and single-call validation
        if let Some(ref batch_calls) = req.batch_calls {
            if batch_calls.is_empty() {
                return Err(anyhow!(
                    "batch_calls is present but empty — provide at least one call"
                ));
            }
            if batch_calls.len() > 16 {
                return Err(anyhow!(
                    "batch_calls has {} entries — max 16 protocol calls per UserOperation",
                    batch_calls.len()
                ));
            }
            for (i, call) in batch_calls.iter().enumerate() {
                Self::validate_call_fields(&call.target_contract, &call.calldata)
                    .map_err(|e| anyhow!("batch_calls[{i}]: {e}"))?;
            }
        } else {
            // Single-call mode — original validation
            Self::validate_call_fields(&req.target_contract, &req.calldata)?;
        }

        info!(chain = %chain, agent_id = %req.agent_id, "request validated");
        Ok(chain)
    }

    /// Validate target contract address and calldata (shared between single
    /// and batch call modes).
    fn validate_call_fields(target_contract: &str, calldata: &str) -> Result<()> {
        if !target_contract.starts_with("0x") || target_contract.len() != 42 {
            return Err(anyhow!("invalid target contract address"));
        }
        if !calldata.starts_with("0x") {
            return Err(anyhow!("calldata must be hex-encoded with 0x prefix"));
        }
        let calldata_hex = calldata.trim_start_matches("0x");
        if calldata_hex.is_empty() {
            return Err(anyhow!(
                "calldata is empty — must contain at least a 4-byte function selector"
            ));
        }
        if calldata_hex.len() % 2 != 0 {
            return Err(anyhow!(
                "calldata has odd-length hex — must be even number of hex characters"
            ));
        }
        if hex::decode(calldata_hex).is_err() {
            return Err(anyhow!("calldata contains invalid hex characters"));
        }
        if calldata_hex.len() < 8 {
            return Err(anyhow!("calldata too short — must contain at least a 4-byte function selector (8 hex chars)"));
        }
        Ok(())
    }

    // ────────────────────── Pricing ──────────────────────────────────

    /// Quote the sponsored Arc gas cap and platform fee in USD-denominated USDC.
    pub async fn estimate_arc_cost(
        &self,
        chain: &Chain,
        gas_estimate: u64,
        max_fee_per_gas: U256,
        include_platform_fee: bool,
    ) -> Result<f64> {
        let raw = self
            .quote_arc_fee_raw(
                chain,
                U256::from(gas_estimate),
                max_fee_per_gas,
                include_platform_fee,
            )
            .await?;
        Ok(raw.as_u128() as f64 / 1_000_000.0)
    }

    pub async fn quote_arc_fee_raw(
        &self,
        chain: &Chain,
        gas_limit: U256,
        max_fee_per_gas: U256,
        include_platform_fee: bool,
    ) -> Result<U256> {
        self.config.chain_config(chain)?;
        // Alchemy's provider-sponsored Arc operations currently carry a zero
        // signed fee cap. Price those operations from Arc's live gas market;
        // the account still signs and submits the exact zero-fee operation.
        let pricing_fee_per_gas = if max_fee_per_gas.is_zero() {
            self.provider_for_chain(chain)?
                .get_gas_price()
                .await
                .map_err(|error| anyhow!("failed to fetch Arc gas price: {error}"))?
                .max(U256::from(ARC_MIN_GAS_PRICE_WEI))
        } else {
            max_fee_per_gas
        };
        validate_sponsorship_budget(
            gas_limit,
            pricing_fee_per_gas,
            self.config.arc_max_sponsored_gas_units,
            self.config.arc_max_sponsored_gas_cost_wei,
        )?;
        let raw = quote_execution_fee_usdc_raw(
            gas_limit,
            pricing_fee_per_gas,
            self.config.gas_markup_basis_points,
            if include_platform_fee {
                self.config.platform_fee_usdc_raw
            } else {
                U256::zero()
            },
        )?;
        if raw > U256::from(1_000_000_000_000u64) {
            return Err(anyhow!("Arc fee exceeds supported reporting range"));
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sponsorship_budget_enforces_units_cost_and_overflow() {
        let max_cost = U256::from(100_000u64);
        assert!(validate_sponsorship_budget(
            U256::from(100u64),
            U256::from(1_000u64),
            100,
            max_cost
        )
        .is_ok());
        assert!(
            validate_sponsorship_budget(U256::from(101u64), U256::one(), 100, max_cost).is_err()
        );
        assert!(validate_sponsorship_budget(
            U256::from(100u64),
            U256::from(1_001u64),
            100,
            max_cost
        )
        .is_err());
        assert!(validate_sponsorship_budget(U256::MAX, U256::MAX, u64::MAX, U256::MAX).is_err());
    }
}
