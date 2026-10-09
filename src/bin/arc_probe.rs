//! Read-only Arc network check. No wallet key or transaction is required.

use anyhow::{Context, Result};
use ethers_core::types::Address;
use jusso::arc::{probe_bundler, probe_rpc, ArcNetwork};

#[tokio::main]
async fn main() -> Result<()> {
    let network: ArcNetwork = std::env::var("ARC_NETWORK")
        .unwrap_or_else(|_| "arc-testnet".into())
        .parse()?;
    let rpc_url =
        std::env::var("ARC_RPC_URL").unwrap_or_else(|_| network.default_rpc_url().to_string());
    let address = std::env::var("ARC_BALANCE_ADDRESS")
        .ok()
        .map(|value| {
            value
                .parse::<Address>()
                .context("ARC_BALANCE_ADDRESS must be an EVM address")
        })
        .transpose()?;
    let status = probe_rpc(network, &rpc_url, address).await?;
    println!(
        "network={} chain_id={}",
        status.network.name(),
        status.network.chain_id()
    );
    println!("gas_price_native_wei={}", status.gas_price_wei);
    if let Some(balance) = status.native_usdc_balance_wei {
        println!("native_usdc_balance_wei={balance}");
    }
    println!("entry_point_v07=deployed");
    if let Ok(bundler_url) = std::env::var("ARC_BUNDLER_RPC_URL") {
        let bundler = probe_bundler(&bundler_url).await?;
        println!("bundler_entry_point={:?}", bundler.entry_point);
    }
    Ok(())
}
