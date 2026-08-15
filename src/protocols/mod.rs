//! Protocol-specific typed action adapters.
//!
//! These modules translate higher-level DeFi actions into the raw
//! `ExecutionRequest`/`BatchCall` shape consumed by the native Base
//! executor.

pub mod aave_v3;
pub mod balancer_v3;
pub mod compound_v3;
pub mod gmx_v2;
pub mod morpho;
pub(crate) mod serde_utils;
pub mod uniswap_v4;
