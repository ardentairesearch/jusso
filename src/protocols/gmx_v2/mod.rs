//! GMX V2 actions and reads for Arbitrum Sepolia.
//!
//! GMX has no official Base Sepolia deployment. Keep this preserved adapter
//! disabled in the Base Beta until GMX publishes Base Sepolia contracts.

pub mod adapter;
pub mod service;

pub use adapter::{
    GmxAccountQuery, GmxCancelOrderRequest, GmxCancelRequest, GmxClaimRequest,
    GmxCreateDepositRequest, GmxCreateOrderRequest, GmxCreateWithdrawalRequest, GmxMarketsQuery,
    GmxUpdateOrderRequest,
};
