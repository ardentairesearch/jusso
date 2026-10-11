//! Owner-approved autonomous treasury controls and operation idempotency.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use ethers_core::types::{Address, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApprovedEarnVault {
    pub address: String,
    pub name: String,
    pub protocol: String,
    pub current_apy: f64,
    pub circle_guarded: bool,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TreasurySettingsInput {
    pub agent_id: Uuid,
    pub expected_version: Option<i64>,
    pub swaps_enabled: bool,
    pub earn_enabled: bool,
    pub max_swap_usdc_raw: String,
    pub max_slippage_bps: i32,
    pub minimum_liquid_usdc_raw: String,
    pub max_earn_allocation_usdc_raw: String,
    #[serde(default)]
    pub earn_vaults: Vec<ApprovedEarnVault>,
}

impl TreasurySettingsInput {
    pub fn validate(&self) -> Result<()> {
        if self.expected_version.is_some_and(|version| version <= 0) {
            bail!("expected treasury-settings version must be positive");
        }
        let max_swap = parse_raw(&self.max_swap_usdc_raw, "maximum swap value")?;
        let reserve = parse_raw(&self.minimum_liquid_usdc_raw, "minimum liquid reserve")?;
        let max_earn = parse_raw(
            &self.max_earn_allocation_usdc_raw,
            "maximum earn allocation",
        )?;
        if self.swaps_enabled && max_swap.is_zero() {
            bail!("enabled swaps require a positive maximum swap value");
        }
        if !(10..=500).contains(&self.max_slippage_bps) {
            bail!("swap price tolerance must be between 0.10% and 5.00%");
        }
        if self.earn_enabled && (max_earn.is_zero() || self.earn_vaults.is_empty()) {
            bail!("enabled earnings require a positive allocation cap and at least one approved vault");
        }
        if reserve > U256::from_dec_str("1000000000000000000000000000000")?
            || max_swap > U256::from_dec_str("1000000000000000000000000000000")?
            || max_earn > U256::from_dec_str("1000000000000000000000000000000")?
        {
            bail!("treasury amount is outside the supported range");
        }
        if self.earn_vaults.len() > 20 {
            bail!("at most 20 earn vaults can be approved");
        }
        let mut seen = std::collections::BTreeSet::new();
        for vault in &self.earn_vaults {
            let address: Address = vault
                .address
                .parse()
                .context("approved vault contains an invalid address")?;
            if address == Address::zero() || !seen.insert(format!("{address:?}")) {
                bail!("approved vault addresses must be nonzero and unique");
            }
            if vault.name.trim().is_empty()
                || vault.name.len() > 120
                || vault.protocol.trim().is_empty()
                || vault.protocol.len() > 80
                || !vault.current_apy.is_finite()
                || vault.current_apy < 0.0
                || vault.warnings.len() > 20
                || vault.warnings.iter().any(|warning| warning.len() > 300)
            {
                bail!("approved vault metadata is invalid");
            }
        }
        Ok(())
    }

    pub fn approved_vault_addresses(&self) -> Vec<String> {
        self.earn_vaults
            .iter()
            .map(|vault| vault.address.to_ascii_lowercase())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TreasurySettingsRow {
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub version: i64,
    pub swaps_enabled: bool,
    pub earn_enabled: bool,
    pub max_swap_usdc_raw: String,
    pub max_slippage_bps: i32,
    pub minimum_liquid_usdc_raw: String,
    pub max_earn_allocation_usdc_raw: String,
    pub allowed_earn_vaults: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl TreasurySettingsRow {
    pub fn max_swap_raw(&self) -> Result<U256> {
        parse_raw(&self.max_swap_usdc_raw, "stored maximum swap value")
    }

    pub fn minimum_reserve_raw(&self) -> Result<U256> {
        parse_raw(
            &self.minimum_liquid_usdc_raw,
            "stored minimum liquid reserve",
        )
    }

    pub fn max_earn_raw(&self) -> Result<U256> {
        parse_raw(
            &self.max_earn_allocation_usdc_raw,
            "stored maximum earn allocation",
        )
    }

    pub fn allows_vault(&self, vault: Address) -> bool {
        let vault = format!("{vault:?}");
        self.allowed_earn_vaults
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&vault))
    }
}

pub async fn get_settings(
    pool: &PgPool,
    organization_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<TreasurySettingsRow>> {
    sqlx::query_as(
        r#"SELECT organization_id, agent_id, version, swaps_enabled, earn_enabled,
                  max_swap_usdc_raw::TEXT AS max_swap_usdc_raw, max_slippage_bps,
                  minimum_liquid_usdc_raw::TEXT AS minimum_liquid_usdc_raw,
                  max_earn_allocation_usdc_raw::TEXT AS max_earn_allocation_usdc_raw,
                  allowed_earn_vaults, created_at, updated_at
           FROM agent_treasury_settings
           WHERE organization_id=$1 AND agent_id=$2"#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .fetch_optional(pool)
    .await
    .context("failed to load agent treasury settings")
}

#[derive(Debug, Clone, FromRow)]
pub struct TreasuryOperationRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub operation_kind: String,
    pub client_request_id: String,
    pub request_fingerprint: String,
    pub status: String,
    pub provider_execution_id: Option<String>,
    pub execution_request_id: Option<Uuid>,
    pub result: Option<serde_json::Value>,
    pub error_message: Option<String>,
    pub lease_expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct ReservedTreasuryOperation {
    pub row: TreasuryOperationRow,
    pub acquired: bool,
}

pub async fn reserve_operation(
    pool: &PgPool,
    organization_id: Uuid,
    agent_id: Uuid,
    kind: &str,
    client_request_id: &str,
    input: &impl Serialize,
) -> Result<ReservedTreasuryOperation> {
    validate_client_request_id(client_request_id)?;
    if !matches!(kind, "swap_to_usdc" | "earn_deposit" | "earn_withdraw") {
        bail!("unsupported treasury operation kind");
    }
    let fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(input)?));
    let id = Uuid::new_v4();
    let inserted = sqlx::query(
        r#"INSERT INTO treasury_operations (
               id, organization_id, agent_id, operation_kind, client_request_id,
               request_fingerprint, status, lease_expires_at
           ) VALUES ($1,$2,$3,$4,$5,$6,'preparing',now() + interval '2 minutes')
           ON CONFLICT (organization_id, agent_id, client_request_id) DO NOTHING"#,
    )
    .bind(id)
    .bind(organization_id)
    .bind(agent_id)
    .bind(kind)
    .bind(client_request_id)
    .bind(&fingerprint)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    let mut row = get_operation(pool, organization_id, agent_id, client_request_id)
        .await?
        .context("treasury operation reservation disappeared")?;
    if row.request_fingerprint != fingerprint || row.operation_kind != kind {
        bail!("request_id was already used for a different treasury operation");
    }
    if inserted {
        return Ok(ReservedTreasuryOperation {
            row,
            acquired: true,
        });
    }
    if row.execution_request_id.is_some()
        || matches!(row.status.as_str(), "queued" | "confirmed" | "reverted")
    {
        return Ok(ReservedTreasuryOperation {
            row,
            acquired: false,
        });
    }
    if row.status == "preparing" && row.lease_expires_at > Utc::now() {
        return Ok(ReservedTreasuryOperation {
            row,
            acquired: false,
        });
    }
    let reacquired = sqlx::query(
        r#"UPDATE treasury_operations
           SET status='preparing', error_message=NULL,
               lease_expires_at=now() + interval '2 minutes', updated_at=now()
           WHERE id=$1 AND request_fingerprint=$2
             AND (status='failed' OR lease_expires_at <= now())"#,
    )
    .bind(row.id)
    .bind(&fingerprint)
    .execute(pool)
    .await?
    .rows_affected()
        == 1;
    if reacquired {
        row = get_operation(pool, organization_id, agent_id, client_request_id)
            .await?
            .context("reacquired treasury operation disappeared")?;
    }
    Ok(ReservedTreasuryOperation {
        row,
        acquired: reacquired,
    })
}

pub async fn complete_operation(
    pool: &PgPool,
    operation_id: Uuid,
    provider_execution_id: &str,
    execution_request_id: Uuid,
    status: &str,
    result: &impl Serialize,
) -> Result<()> {
    if !matches!(status, "queued" | "confirmed" | "failed" | "reverted") {
        bail!("invalid treasury operation completion status");
    }
    let updated = sqlx::query(
        r#"UPDATE treasury_operations
           SET status=$4, provider_execution_id=$2, execution_request_id=$3,
               result=$5, error_message=NULL, updated_at=now()
           WHERE id=$1 AND status='preparing'"#,
    )
    .bind(operation_id)
    .bind(provider_execution_id)
    .bind(execution_request_id)
    .bind(status)
    .bind(serde_json::to_value(result)?)
    .execute(pool)
    .await?;
    if updated.rows_affected() != 1 {
        bail!("treasury operation lease was lost before execution was recorded");
    }
    Ok(())
}

pub async fn fail_operation(pool: &PgPool, operation_id: Uuid, error: &anyhow::Error) {
    let message = format!("{error:#}").chars().take(1000).collect::<String>();
    if let Err(update_error) = sqlx::query(
        r#"UPDATE treasury_operations
           SET status='failed', error_message=$2, updated_at=now()
           WHERE id=$1 AND status='preparing'"#,
    )
    .bind(operation_id)
    .bind(message)
    .execute(pool)
    .await
    {
        tracing::error!(%operation_id, %update_error, "failed to record treasury operation failure");
    }
}

pub async fn get_operation(
    pool: &PgPool,
    organization_id: Uuid,
    agent_id: Uuid,
    client_request_id: &str,
) -> Result<Option<TreasuryOperationRow>> {
    sqlx::query_as(
        r#"SELECT o.id, o.organization_id, o.agent_id, o.operation_kind,
                  o.client_request_id, o.request_fingerprint,
                  COALESCE(e.status, o.status) AS status, o.provider_execution_id,
                  o.execution_request_id, o.result, o.error_message,
                  o.lease_expires_at, o.created_at, o.updated_at
           FROM treasury_operations o
           LEFT JOIN execution_requests e ON e.id=o.execution_request_id
           WHERE o.organization_id=$1 AND o.agent_id=$2 AND o.client_request_id=$3"#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .bind(client_request_id)
    .fetch_optional(pool)
    .await
    .context("failed to load treasury operation")
}

pub fn parse_raw(value: &str, name: &str) -> Result<U256> {
    U256::from_dec_str(value).with_context(|| format!("{name} must be raw USDC units"))
}

fn validate_client_request_id(value: &str) -> Result<()> {
    if !(8..=128).contains(&value.len())
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || byte.is_ascii_whitespace())
    {
        bail!("request_id must contain 8-128 printable characters without spaces");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn treasury_settings_require_bounded_explicit_controls() {
        let settings = TreasurySettingsInput {
            agent_id: Uuid::new_v4(),
            expected_version: None,
            swaps_enabled: true,
            earn_enabled: false,
            max_swap_usdc_raw: "500000000".into(),
            max_slippage_bps: 100,
            minimum_liquid_usdc_raw: "50000000".into(),
            max_earn_allocation_usdc_raw: "0".into(),
            earn_vaults: Vec::new(),
        };
        assert!(settings.validate().is_ok());
        let mut unsafe_settings = settings;
        unsafe_settings.max_slippage_bps = 501;
        assert!(unsafe_settings.validate().is_err());
    }
}
