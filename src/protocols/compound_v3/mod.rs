//! Compound III typed action adapter and orchestration.
//!
//! First supported target: Base Sepolia USDC and WETH Comet markets.

pub mod adapter;
pub mod service;

pub use adapter::{
    CompoundBalancesQuery, CompoundBorrowCapacityQuery, CompoundBorrowRequest,
    CompoundMarketsQuery, CompoundPositionQuery, CompoundRepayRequest, CompoundSupplyRequest,
    CompoundWithdrawRequest,
};
