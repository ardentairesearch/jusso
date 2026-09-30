//! Protocol-specific typed action adapters.
//!
//! These modules translate higher-level DeFi actions into the raw
//! `ExecutionRequest`/`BatchCall` shape consumed by the Arc ERC-4337 executor.
//!
//! Only adapters revalidated for Arc are compiled into the Beta runtime.
//! Other preserved protocol sources remain dormant until their Arc deployment
//! and market assumptions can be verified.

pub mod uniswap_v4;
