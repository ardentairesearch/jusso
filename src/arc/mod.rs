//! Arc network constants, RPC checks, and exact USDC gas accounting.
//!
//! Arc transaction submission uses dedicated ERC-4337 smart accounts.

pub mod execution;
pub mod rpc;
pub mod smart_account;

use anyhow::{bail, Context, Result};
use ethers_core::types::{Address, H160, U256};

pub const ARC_MAINNET_CHAIN_ID: u64 = 5042;
pub const ARC_TESTNET_CHAIN_ID: u64 = 5_042_002;
pub const ARC_MAINNET_RPC_URL: &str = "https://rpc.mainnet.arc.io";
pub const ARC_TESTNET_RPC_URL: &str = "https://rpc.testnet.arc.io";
pub const ARC_USDC_ADDRESS: Address = H160([
    0x36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);
pub const ARC_MAINNET_EURC_ADDRESS: &str = "0xbEf5f6d51CB62b58e6A8f77868681825C6fe21c1";
pub const ARC_TESTNET_EURC_ADDRESS: &str = "0x89B50855Aa3bE2F677cD6303Cec089B5F319D72a";
pub const ARC_NATIVE_USDC_DECIMALS: u8 = 18;
pub const ARC_ERC20_USDC_DECIMALS: u8 = 6;
pub const ARC_MIN_GAS_PRICE_WEI: u64 = 20_000_000_000;
pub const ARC_ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
const NATIVE_TO_ERC20_SCALE: u64 = 1_000_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArcNetwork {
    Mainnet,
    Testnet,
}

impl ArcNetwork {
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Mainnet => ARC_MAINNET_CHAIN_ID,
            Self::Testnet => ARC_TESTNET_CHAIN_ID,
        }
    }

    pub const fn default_rpc_url(self) -> &'static str {
        match self {
            Self::Mainnet => ARC_MAINNET_RPC_URL,
            Self::Testnet => ARC_TESTNET_RPC_URL,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "arc",
            Self::Testnet => "arc-testnet",
        }
    }
}

impl std::str::FromStr for ArcNetwork {
    type Err = anyhow::Error;

    fn from_str(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "arc" | "arc-mainnet" => Ok(Self::Mainnet),
            "arc-testnet" => Ok(Self::Testnet),
            _ => bail!("Arc network must be arc or arc-testnet"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcRpcStatus {
    pub network: ArcNetwork,
    pub gas_price_wei: U256,
    pub native_usdc_balance_wei: Option<U256>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcBundlerStatus {
    pub entry_point: Address,
}

/// Check the chain before trusting a configured RPC endpoint or payer balance.
pub async fn probe_rpc(
    network: ArcNetwork,
    rpc_url: &str,
    balance_address: Option<Address>,
) -> Result<ArcRpcStatus> {
    let provider = rpc::ArcRpcClient::new(rpc_url)?;
    let actual_chain_id = provider
        .chain_id()
        .await
        .context("Arc RPC chain ID failed")?;
    if actual_chain_id != U256::from(network.chain_id()) {
        bail!(
            "Arc RPC chain ID mismatch: expected {}, got {actual_chain_id}",
            network.chain_id()
        );
    }

    let decimals = provider
        .call(ARC_USDC_ADDRESS, &[0x31, 0x3c, 0xe5, 0x67])
        .await
        .context("Arc USDC decimals() call failed")?;
    if decimals.len() != 32
        || U256::from_big_endian(&decimals) != U256::from(ARC_ERC20_USDC_DECIMALS)
    {
        bail!("Arc USDC ERC-20 interface did not report 6 decimals");
    }

    let entry_point: Address = ARC_ENTRY_POINT_V07
        .parse()
        .expect("fixed ERC-4337 EntryPoint address");
    if provider
        .get_code(entry_point)
        .await
        .context("Arc ERC-4337 EntryPoint code lookup failed")?
        .is_empty()
    {
        bail!("ERC-4337 EntryPoint v0.7 is not deployed on the Arc RPC chain");
    }

    let gas_price_wei = provider
        .gas_price()
        .await
        .context("Arc gas price lookup failed")?;
    if gas_price_wei < U256::from(ARC_MIN_GAS_PRICE_WEI) {
        bail!("Arc RPC returned a gas price below its documented 20 Gwei minimum");
    }
    let native_usdc_balance_wei = match balance_address {
        Some(address) => Some(
            provider
                .get_balance(address)
                .await
                .context("Arc native USDC balance lookup failed")?,
        ),
        None => None,
    };
    Ok(ArcRpcStatus {
        network,
        gas_price_wei,
        native_usdc_balance_wei,
    })
}

/// Check that a configured bundler actually supports the EntryPoint deployed
/// on Arc. This is a discovery check only and does not submit a UserOperation.
pub async fn probe_bundler(bundler_url: &str) -> Result<ArcBundlerStatus> {
    let supported = rpc::ArcRpcClient::new(bundler_url)?
        .supported_entry_points()
        .await?;
    let entry_point: Address = ARC_ENTRY_POINT_V07
        .parse()
        .expect("fixed ERC-4337 EntryPoint address");
    let found = supported.contains(&entry_point);
    if !found {
        bail!("Arc bundler does not support ERC-4337 EntryPoint v0.7");
    }
    Ok(ArcBundlerStatus { entry_point })
}

fn ceil_div(value: U256, divisor: U256) -> Result<U256> {
    if value.is_zero() {
        return Ok(U256::zero());
    }
    Ok(value
        .checked_sub(U256::one())
        .context("USDC fee calculation underflow")?
        / divisor
        + U256::one())
}

/// Price an Arc gas cap in ERC-20 USDC base units, rounding up at each boundary.
/// The maximum fee, not an optimistic effective fee, is used so sponsorship is
/// covered even when the base fee rises between quote and inclusion.
pub fn quote_execution_fee_usdc_raw(
    gas_limit: U256,
    max_fee_per_gas_wei: U256,
    markup_basis_points: u32,
    platform_fee_usdc_raw: U256,
) -> Result<U256> {
    if gas_limit.is_zero() || max_fee_per_gas_wei < U256::from(ARC_MIN_GAS_PRICE_WEI) {
        bail!("Arc gas limit must be positive and fee cap at least 20 Gwei");
    }
    if markup_basis_points > 100_000 {
        bail!("Arc gas markup exceeds the supported limit");
    }
    let native_gas_cost = gas_limit
        .checked_mul(max_fee_per_gas_wei)
        .context("Arc native gas cost overflow")?;
    let multiplier = U256::from(10_000u64 + u64::from(markup_basis_points));
    let marked_native_cost = native_gas_cost
        .checked_mul(multiplier)
        .context("Arc marked-up gas cost overflow")?;
    let marked_native_cost = ceil_div(marked_native_cost, U256::from(10_000u64))?;
    let gas_usdc_raw = ceil_div(marked_native_cost, U256::from(NATIVE_TO_ERC20_SCALE))?;
    gas_usdc_raw
        .checked_add(platform_fee_usdc_raw)
        .context("Arc execution fee overflow")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_constants_are_distinct() {
        assert_eq!(
            "arc-testnet".parse::<ArcNetwork>().unwrap().chain_id(),
            5_042_002
        );
        assert_eq!("arc".parse::<ArcNetwork>().unwrap().chain_id(), 5042);
        assert_ne!(
            ArcNetwork::Testnet.default_rpc_url(),
            ArcNetwork::Mainnet.default_rpc_url()
        );
    }

    #[test]
    fn arc_usdc_fee_uses_native_eighteen_decimals_and_erc20_six() {
        let fee = quote_execution_fee_usdc_raw(
            U256::from(100_000u64),
            U256::from(20_000_000_000u64),
            1_000,
            U256::from(10_000u64),
        )
        .unwrap();
        assert_eq!(fee, U256::from(12_200u64));
    }

    #[test]
    fn fee_rounds_up_and_checks_caps() {
        assert_eq!(
            quote_execution_fee_usdc_raw(
                U256::one(),
                U256::from(ARC_MIN_GAS_PRICE_WEI),
                0,
                U256::zero(),
            )
            .unwrap(),
            U256::one(),
        );
        assert!(quote_execution_fee_usdc_raw(
            U256::zero(),
            U256::from(ARC_MIN_GAS_PRICE_WEI),
            0,
            U256::zero()
        )
        .is_err());
        assert!(quote_execution_fee_usdc_raw(U256::MAX, U256::MAX, 0, U256::zero()).is_err());
        assert!(quote_execution_fee_usdc_raw(U256::one(), U256::one(), 0, U256::zero()).is_err());
    }
}
