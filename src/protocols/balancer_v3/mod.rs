//! Balancer V3 typed action adapter and orchestration.
//!
//! Supports single-pool swaps and liquidity management on Ethereum Sepolia.
//!
//! Balancer has no official Base Sepolia V3 deployment. Keep this preserved
//! adapter disabled in the Base Beta until official Base Sepolia contracts exist.

pub mod adapter;
pub mod service;

pub use adapter::{
    BalancerAddLiquidityQuoteResponse, BalancerAddLiquidityRequest, BalancerBalancesQuery,
    BalancerPoolQuery, BalancerPoolsQuery, BalancerQuoteResponse,
    BalancerRemoveLiquidityQuoteResponse, BalancerRemoveLiquidityRequest, BalancerSwapKind,
    BalancerSwapRequest,
};
