//! Typed policy-impact metadata and Policy Enforcement V2 primitives.

use anyhow::{anyhow, Context, Result};
use ethers_core::types::{Address, U256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const RISK_BORROWING: &str = "borrowing";
pub const RISK_LEVERAGE: &str = "leverage";
pub const RISK_EXTERNAL_WITHDRAWAL: &str = "external_withdrawal";
pub const RISK_UNLIMITED_APPROVAL: &str = "unlimited_approval";
pub const SUPPORTED_RISK_PERMISSIONS: &[&str] = &[
    RISK_BORROWING,
    RISK_LEVERAGE,
    RISK_EXTERNAL_WITHDRAWAL,
    RISK_UNLIMITED_APPROVAL,
];

pub const ARC_USDC_ADDRESS: &str = "0x3600000000000000000000000000000000000000";
pub const DEFAULT_USDC_PER_PAYMENT_RAW: &str = "500000000";
pub const DEFAULT_USDC_ROLLING_RAW: &str = "2500000000";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct TokenSpendLimit {
    /// ERC-20 contract address. Use `*` only as an explicit universal opt-in.
    pub token: String,
    /// Maximum raw token units in one execution.
    pub max_per_execution_raw: String,
    /// Maximum raw token units reserved in the rolling policy window.
    pub max_rolling_raw: String,
}

impl TokenSpendLimit {
    pub fn validate(&self) -> Result<()> {
        if self.token != "*" && self.token.parse::<Address>().is_err() {
            anyhow::bail!("token spend limit contains an invalid token address");
        }
        let per_execution =
            parse_positive_u256(&self.max_per_execution_raw, "max_per_execution_raw")?;
        let rolling = parse_positive_u256(&self.max_rolling_raw, "max_rolling_raw")?;
        if per_execution > rolling {
            anyhow::bail!("token per-execution limit exceeds its rolling limit");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenSpend {
    pub token: String,
    pub amount_raw: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExecutionPolicyImpact {
    #[serde(default)]
    pub token_spends: Vec<TokenSpend>,
    #[serde(default)]
    pub borrowed_value_usd: f64,
    #[serde(default)]
    pub risks: Vec<String>,
    #[serde(default)]
    pub recipients: Vec<String>,
}

impl ExecutionPolicyImpact {
    pub fn validate(&self) -> Result<()> {
        if !self.borrowed_value_usd.is_finite() || self.borrowed_value_usd < 0.0 {
            anyhow::bail!("borrowed value impact is invalid");
        }
        if self.token_spends.len() > 32
            || self.risks.len() > SUPPORTED_RISK_PERMISSIONS.len()
            || self.recipients.len() > 32
        {
            anyhow::bail!("execution policy impact is oversized");
        }
        for spend in &self.token_spends {
            spend
                .token
                .parse::<Address>()
                .map_err(|_| anyhow!("execution policy impact contains an invalid token"))?;
            parse_positive_u256(&spend.amount_raw, "token spend amount")?;
        }
        for risk in &self.risks {
            if !SUPPORTED_RISK_PERMISSIONS.contains(&risk.as_str()) {
                anyhow::bail!("execution policy impact contains an unknown risk");
            }
        }
        for recipient in &self.recipients {
            recipient
                .parse::<Address>()
                .map_err(|_| anyhow!("execution policy impact contains an invalid recipient"))?;
        }
        if self.borrowed_value_usd > 0.0 && !self.risks.iter().any(|risk| risk == RISK_BORROWING) {
            anyhow::bail!("borrowed value must be marked as borrowing risk");
        }
        if !self.recipients.is_empty()
            && !self
                .risks
                .iter()
                .any(|risk| risk == RISK_EXTERNAL_WITHDRAWAL)
        {
            anyhow::bail!("external recipients must be marked as withdrawal risk");
        }
        Ok(())
    }

    pub fn token_spend(token: Address, amount: U256) -> Self {
        Self {
            token_spends: vec![TokenSpend {
                token: format!("{token:?}").to_ascii_lowercase(),
                amount_raw: amount.to_string(),
            }],
            ..Self::default()
        }
    }
}

pub fn validate_token_spend_limits(value: &serde_json::Value) -> Result<Vec<TokenSpendLimit>> {
    let limits: Vec<TokenSpendLimit> = serde_json::from_value(value.clone())
        .context("token_spend_limits must be an array of structured limits")?;
    if limits.len() > 100 {
        anyhow::bail!("token_spend_limits contains too many entries");
    }
    let mut seen = std::collections::BTreeSet::new();
    for limit in &limits {
        limit.validate()?;
        let normalized = limit.token.to_ascii_lowercase();
        if !seen.insert(normalized) {
            anyhow::bail!("token_spend_limits contains a duplicate token");
        }
    }
    Ok(limits)
}

pub fn default_token_spend_limits() -> serde_json::Value {
    serde_json::to_value([
        TokenSpendLimit {
            token: ARC_USDC_ADDRESS.into(),
            // Useful for real payment operations while still bounding a newly
            // onboarded agent to $500 per run and $2,500 per rolling day.
            max_per_execution_raw: DEFAULT_USDC_PER_PAYMENT_RAW.into(),
            max_rolling_raw: DEFAULT_USDC_ROLLING_RAW.into(),
        },
        TokenSpendLimit {
            token: crate::arc::ARC_TESTNET_EURC_ADDRESS.into(),
            max_per_execution_raw: DEFAULT_USDC_PER_PAYMENT_RAW.into(),
            max_rolling_raw: DEFAULT_USDC_ROLLING_RAW.into(),
        },
        TokenSpendLimit {
            token: crate::arc::ARC_MAINNET_EURC_ADDRESS.into(),
            max_per_execution_raw: DEFAULT_USDC_PER_PAYMENT_RAW.into(),
            max_rolling_raw: DEFAULT_USDC_ROLLING_RAW.into(),
        },
    ])
    .expect("default token spend policy is serializable")
}

pub fn validate_risk_permissions(values: &[String]) -> Result<()> {
    if values.len() > SUPPORTED_RISK_PERMISSIONS.len()
        || values
            .iter()
            .any(|value| !SUPPORTED_RISK_PERMISSIONS.contains(&value.as_str()))
    {
        anyhow::bail!("risk_permissions contains an unsupported permission");
    }
    let unique = values.iter().collect::<std::collections::BTreeSet<_>>();
    if unique.len() != values.len() {
        anyhow::bail!("risk_permissions contains duplicates");
    }
    Ok(())
}

fn parse_positive_u256(value: &str, name: &str) -> Result<U256> {
    let parsed =
        U256::from_dec_str(value).map_err(|_| anyhow!("{name} must be raw token units"))?;
    if parsed.is_zero() {
        anyhow::bail!("{name} must be greater than zero");
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_limits_are_structured_unique_and_bounded() {
        let defaults = default_token_spend_limits();
        let parsed = validate_token_spend_limits(&defaults).unwrap();
        assert_eq!(parsed.len(), 3);
        assert_eq!(
            parsed[0].max_per_execution_raw,
            DEFAULT_USDC_PER_PAYMENT_RAW
        );
        assert_eq!(parsed[0].max_rolling_raw, DEFAULT_USDC_ROLLING_RAW);
        let duplicate = serde_json::json!([
            {"token": ARC_USDC_ADDRESS, "max_per_execution_raw": "1", "max_rolling_raw": "2"},
            {"token": ARC_USDC_ADDRESS.to_ascii_uppercase(), "max_per_execution_raw": "1", "max_rolling_raw": "2"}
        ]);
        assert!(validate_token_spend_limits(&duplicate).is_err());
    }

    #[test]
    fn execution_impacts_reject_unknown_risks_and_zero_spends() {
        let mut impact = ExecutionPolicyImpact::default();
        impact.risks.push("arbitrary".into());
        assert!(impact.validate().is_err());
        impact.risks.clear();
        impact.token_spends.push(TokenSpend {
            token: ARC_USDC_ADDRESS.into(),
            amount_raw: "0".into(),
        });
        assert!(impact.validate().is_err());
    }
}
