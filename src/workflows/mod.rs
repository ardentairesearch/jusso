//! Durable, owner-approved USDC payment plans.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Datelike, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use ethers_core::{
    abi::{encode, Token},
    types::{Address, U256},
    utils::{format_units, id},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    api::{routes::AppState, services},
    policy::{ExecutionPolicyImpact, TokenSpend, ARC_USDC_ADDRESS, RISK_EXTERNAL_WITHDRAWAL},
    types::{AuthContext, BatchCall, CredentialKind, ExecutionRequest, ExecutionStatus},
};

pub const USDC_DECIMALS: u32 = 6;
pub const MAX_BATCH_CALLS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleCadence {
    Daily,
    Weekly,
    Monthly,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PaymentSchedule {
    pub cadence: ScheduleCadence,
    /// IANA time-zone name, for example `Africa/Lagos`.
    pub timezone: String,
    /// Local wall-clock time in `HH:MM` 24-hour form.
    pub local_time: String,
    /// Monday through Sunday. Required only for weekly schedules.
    pub weekday: Option<String>,
    /// Day 1-28. Required only for monthly schedules.
    pub day_of_month: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PaymentRecipientInput {
    pub address: String,
    pub amount_usdc: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct SurplusRuleInput {
    pub destination: String,
    /// Surplus transfers smaller than this amount are skipped.
    pub minimum_transfer_usdc: String,
    /// Optional cap on a single surplus transfer.
    pub maximum_transfer_usdc: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct PaymentPlanInput {
    pub name: String,
    pub agent_id: String,
    pub schedule: PaymentSchedule,
    pub recipients: Vec<PaymentRecipientInput>,
    /// Balance that must remain after payouts and the conservatively reserved execution fee.
    pub reserve_usdc: String,
    pub surplus: Option<SurplusRuleInput>,
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedRecipient {
    pub address: String,
    pub amount_raw: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedSurplusRule {
    pub destination: String,
    pub minimum_transfer_raw: String,
    pub maximum_transfer_raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedPaymentPlan {
    pub name: String,
    pub agent_id: String,
    pub schedule: PaymentSchedule,
    pub recipients: Vec<NormalizedRecipient>,
    pub reserve_raw: String,
    pub surplus: Option<NormalizedSurplusRule>,
    pub callback_url: Option<String>,
    pub first_run_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PaymentPlanStatusChange {
    Pause,
    Resume,
    Cancel,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentPlanRow {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub agent_external_id: String,
    pub created_by_principal_id: Uuid,
    pub name: String,
    pub version: i64,
    pub status: String,
    pub cadence: String,
    pub timezone: String,
    pub local_time: String,
    pub weekday: Option<String>,
    pub day_of_month: Option<i16>,
    pub reserve_raw: String,
    pub surplus_destination: Option<String>,
    pub surplus_minimum_raw: Option<String>,
    pub surplus_maximum_raw: Option<String>,
    pub callback_url: Option<String>,
    pub next_run_at: Option<DateTime<Utc>>,
    pub last_run_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub cancelled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentPlanRecipientRow {
    pub id: Uuid,
    pub plan_id: Uuid,
    pub position: i16,
    pub recipient_address: String,
    pub amount_raw: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct PaymentPlanRunRow {
    pub id: Uuid,
    pub plan_id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub plan_version: i64,
    pub scheduled_for: DateTime<Utc>,
    pub status: String,
    #[serde(skip_serializing)]
    pub plan_snapshot: serde_json::Value,
    pub execution_request_id: Option<Uuid>,
    pub payout_total_raw: String,
    pub surplus_raw: String,
    pub balance_observed_raw: Option<String>,
    pub reason: Option<String>,
    pub attempt_count: i32,
    #[serde(skip_serializing)]
    pub lease_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PaymentPlanRunSnapshot {
    organization_id: Uuid,
    agent_id: Uuid,
    agent_external_id: String,
    principal_id: Uuid,
    plan_version: i64,
    reserve_raw: String,
    surplus_destination: Option<String>,
    surplus_minimum_raw: Option<String>,
    surplus_maximum_raw: Option<String>,
    callback_url: Option<String>,
    recipients: Vec<NormalizedRecipient>,
}

impl PaymentPlanInput {
    pub fn normalize(&self, now: DateTime<Utc>) -> Result<NormalizedPaymentPlan> {
        let name = self.name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            bail!("payment plan name must contain 1-100 characters");
        }
        let agent_id = self.agent_id.trim();
        if agent_id.is_empty() || agent_id.chars().count() > 100 {
            bail!("agent_id must contain 1-100 characters");
        }
        if self.recipients.is_empty() || self.recipients.len() > MAX_BATCH_CALLS {
            bail!("payment plan must contain 1-{MAX_BATCH_CALLS} recipients");
        }
        self.schedule.validate()?;
        let mut seen = std::collections::BTreeSet::new();
        let recipients = self
            .recipients
            .iter()
            .map(|recipient| {
                let address = normalize_address(&recipient.address)?;
                if !seen.insert(address.clone()) {
                    bail!("payment plan contains a duplicate recipient");
                }
                let label = normalize_label(recipient.label.as_deref())?;
                Ok(NormalizedRecipient {
                    address,
                    amount_raw: parse_usdc_amount(&recipient.amount_usdc, false)?.to_string(),
                    label,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let reserve_raw = parse_usdc_amount(&self.reserve_usdc, true)?.to_string();
        let surplus = self
            .surplus
            .as_ref()
            .map(|rule| {
                let destination = normalize_address(&rule.destination)?;
                let minimum = parse_usdc_amount(&rule.minimum_transfer_usdc, false)?;
                let maximum = rule
                    .maximum_transfer_usdc
                    .as_deref()
                    .map(|value| parse_usdc_amount(value, false))
                    .transpose()?;
                if maximum.is_some_and(|value| value < minimum) {
                    bail!("surplus maximum must be at least its minimum transfer");
                }
                Ok(NormalizedSurplusRule {
                    destination,
                    minimum_transfer_raw: minimum.to_string(),
                    maximum_transfer_raw: maximum.map(|value| value.to_string()),
                })
            })
            .transpose()?;
        if self.recipients.len() + usize::from(surplus.is_some()) > MAX_BATCH_CALLS {
            bail!("recipients plus an optional surplus transfer cannot exceed {MAX_BATCH_CALLS} calls");
        }
        let callback_url = self
            .callback_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        Ok(NormalizedPaymentPlan {
            name: name.into(),
            agent_id: agent_id.into(),
            schedule: self.schedule.clone(),
            recipients,
            reserve_raw,
            surplus,
            callback_url,
            first_run_at: self.schedule.next_after(now)?,
        })
    }
}

impl NormalizedPaymentPlan {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.chars().count() > 100 {
            bail!("payment plan name must contain 1-100 characters");
        }
        if self.agent_id.trim().is_empty() || self.agent_id.chars().count() > 100 {
            bail!("agent_id must contain 1-100 characters");
        }
        self.schedule.validate()?;
        if self.recipients.is_empty() || self.recipients.len() > MAX_BATCH_CALLS {
            bail!("payment plan must contain 1-{MAX_BATCH_CALLS} recipients");
        }
        let mut seen = std::collections::BTreeSet::new();
        for recipient in &self.recipients {
            let address = normalize_address(&recipient.address)?;
            if address != recipient.address || !seen.insert(address) {
                bail!("payment plan recipients must be normalized and unique");
            }
            parse_raw_amount(&recipient.amount_raw, false)?;
            normalize_label(recipient.label.as_deref())?;
        }
        parse_raw_amount(&self.reserve_raw, true)?;
        if let Some(surplus) = &self.surplus {
            if normalize_address(&surplus.destination)? != surplus.destination {
                bail!("surplus destination must be normalized");
            }
            let minimum = parse_raw_amount(&surplus.minimum_transfer_raw, false)?;
            if let Some(maximum) = surplus.maximum_transfer_raw.as_deref() {
                if parse_raw_amount(maximum, false)? < minimum {
                    bail!("surplus maximum must be at least its minimum transfer");
                }
            }
        }
        if self.recipients.len() + usize::from(self.surplus.is_some()) > MAX_BATCH_CALLS {
            bail!("recipients plus an optional surplus transfer cannot exceed {MAX_BATCH_CALLS} calls");
        }
        Ok(())
    }
}

impl PaymentSchedule {
    pub fn validate(&self) -> Result<()> {
        self.timezone
            .parse::<Tz>()
            .map_err(|_| anyhow!("timezone must be a valid IANA time-zone name"))?;
        parse_local_time(&self.local_time)?;
        match self.cadence {
            ScheduleCadence::Daily => {
                if self.weekday.is_some() || self.day_of_month.is_some() {
                    bail!("daily schedules cannot include weekday or day_of_month");
                }
            }
            ScheduleCadence::Weekly => {
                parse_weekday(
                    self.weekday
                        .as_deref()
                        .context("weekly schedule needs weekday")?,
                )?;
                if self.day_of_month.is_some() {
                    bail!("weekly schedules cannot include day_of_month");
                }
            }
            ScheduleCadence::Monthly => {
                if self.weekday.is_some() {
                    bail!("monthly schedules cannot include weekday");
                }
                if !matches!(self.day_of_month, Some(1..=28)) {
                    bail!("monthly schedule day_of_month must be between 1 and 28");
                }
            }
        }
        Ok(())
    }

    pub fn next_after(&self, after: DateTime<Utc>) -> Result<DateTime<Utc>> {
        self.validate()?;
        let tz = self.timezone.parse::<Tz>()?;
        let time = parse_local_time(&self.local_time)?;
        let local_after = after.with_timezone(&tz);
        let mut date = local_after.date_naive();
        for _ in 0..370 {
            let matches = match self.cadence {
                ScheduleCadence::Daily => true,
                ScheduleCadence::Weekly => {
                    date.weekday()
                        == parse_weekday(self.weekday.as_deref().expect("validated weekday"))?
                }
                ScheduleCadence::Monthly => {
                    date.day() == u32::from(self.day_of_month.expect("validated day"))
                }
            };
            if matches {
                let local = date.and_time(time);
                let candidate = match tz.from_local_datetime(&local) {
                    chrono::LocalResult::Single(value) => value,
                    chrono::LocalResult::Ambiguous(first, _) => first,
                    chrono::LocalResult::None => {
                        date = date.succ_opt().context("schedule date overflow")?;
                        continue;
                    }
                };
                let utc = candidate.with_timezone(&Utc);
                if utc > after {
                    return Ok(utc);
                }
            }
            date = date.succ_opt().context("schedule date overflow")?;
        }
        bail!("could not calculate the next payment-plan run")
    }
}

fn parse_local_time(value: &str) -> Result<NaiveTime> {
    NaiveTime::parse_from_str(value, "%H:%M")
        .map_err(|_| anyhow!("local_time must use 24-hour HH:MM format"))
}

fn parse_weekday(value: &str) -> Result<Weekday> {
    match value.trim().to_ascii_lowercase().as_str() {
        "monday" => Ok(Weekday::Mon),
        "tuesday" => Ok(Weekday::Tue),
        "wednesday" => Ok(Weekday::Wed),
        "thursday" => Ok(Weekday::Thu),
        "friday" => Ok(Weekday::Fri),
        "saturday" => Ok(Weekday::Sat),
        "sunday" => Ok(Weekday::Sun),
        _ => bail!("weekday must be Monday through Sunday"),
    }
}

fn normalize_address(value: &str) -> Result<String> {
    let address = value
        .trim()
        .parse::<Address>()
        .map_err(|_| anyhow!("invalid EVM address"))?;
    Ok(format!("{address:?}").to_ascii_lowercase())
}

fn normalize_label(value: Option<&str>) -> Result<Option<String>> {
    let value = value.map(str::trim).filter(|value| !value.is_empty());
    if value.is_some_and(|value| value.chars().count() > 80) {
        bail!("recipient label cannot exceed 80 characters");
    }
    Ok(value.map(str::to_owned))
}

pub fn parse_usdc_amount(value: &str, allow_zero: bool) -> Result<U256> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        bail!("USDC amount must be a non-negative decimal string");
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("USDC amount must be a decimal string");
    }
    let fraction = fraction.unwrap_or("");
    if fraction.len() > USDC_DECIMALS as usize
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("USDC amount supports at most six decimal places");
    }
    let whole = U256::from_dec_str(whole)?;
    let padded = format!("{fraction:0<6}");
    let fraction = if padded.is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(&padded)?
    };
    let raw = whole
        .checked_mul(U256::from(10u64.pow(USDC_DECIMALS)))
        .and_then(|amount| amount.checked_add(fraction))
        .context("USDC amount is too large")?;
    if raw.is_zero() && !allow_zero {
        bail!("USDC amount must be greater than zero");
    }
    Ok(raw)
}

pub fn format_usdc_amount(raw: U256) -> String {
    let scale = U256::from(10u64.pow(USDC_DECIMALS));
    let whole = raw / scale;
    let fraction = (raw % scale).as_u64();
    if fraction == 0 {
        return whole.to_string();
    }
    format!("{whole}.{fraction:06}")
        .trim_end_matches('0')
        .to_string()
}

fn parse_raw_amount(value: &str, allow_zero: bool) -> Result<U256> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("raw USDC amount must contain digits only");
    }
    let amount = U256::from_dec_str(value)?;
    if amount.is_zero() && !allow_zero {
        bail!("raw USDC amount must be greater than zero");
    }
    Ok(amount)
}

const PLAN_SELECT: &str = r#"
    SELECT p.id, p.organization_id, p.agent_id, a.external_id AS agent_external_id,
           p.created_by_principal_id, p.name, p.version, p.status, p.cadence,
           p.timezone, p.local_time, p.weekday, p.day_of_month,
           p.reserve_raw::TEXT AS reserve_raw, p.surplus_destination,
           p.surplus_minimum_raw::TEXT AS surplus_minimum_raw,
           p.surplus_maximum_raw::TEXT AS surplus_maximum_raw, p.callback_url,
           p.next_run_at, p.last_run_at, p.created_at, p.updated_at, p.cancelled_at
    FROM payment_plans p JOIN agents a ON a.id = p.agent_id
"#;

pub async fn list_plans(
    pool: &PgPool,
    context: &crate::types::AuthContext,
) -> Result<Vec<PaymentPlanRow>> {
    let sql = format!(
        "{PLAN_SELECT} JOIN principal_agent_grants pag ON pag.agent_id = p.agent_id\n\
         WHERE p.organization_id = $1 AND pag.principal_id = $2\n\
           AND ($3::UUID IS NULL OR p.agent_id = $3) ORDER BY p.created_at DESC"
    );
    Ok(sqlx::query_as::<_, PaymentPlanRow>(&sql)
        .bind(context.organization_id)
        .bind(context.principal_id)
        .bind(context.agent_id)
        .fetch_all(pool)
        .await?)
}

pub async fn get_plan(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    plan_id: Uuid,
) -> Result<Option<(PaymentPlanRow, Vec<PaymentPlanRecipientRow>)>> {
    let sql = format!(
        "{PLAN_SELECT} JOIN principal_agent_grants pag ON pag.agent_id = p.agent_id\n\
         WHERE p.id = $1 AND p.organization_id = $2 AND pag.principal_id = $3\n\
           AND ($4::UUID IS NULL OR p.agent_id = $4)"
    );
    let Some(plan) = sqlx::query_as::<_, PaymentPlanRow>(&sql)
        .bind(plan_id)
        .bind(context.organization_id)
        .bind(context.principal_id)
        .bind(context.agent_id)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let recipients = list_recipients(pool, plan.id).await?;
    Ok(Some((plan, recipients)))
}

pub async fn list_recipients(pool: &PgPool, plan_id: Uuid) -> Result<Vec<PaymentPlanRecipientRow>> {
    Ok(sqlx::query_as::<_, PaymentPlanRecipientRow>(
        r#"SELECT id, plan_id, position, recipient_address, amount_raw::TEXT AS amount_raw,
                  label, created_at FROM payment_plan_recipients
           WHERE plan_id = $1 ORDER BY position"#,
    )
    .bind(plan_id)
    .fetch_all(pool)
    .await?)
}

pub async fn list_runs(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    plan_id: Uuid,
    limit: i64,
) -> Result<Vec<PaymentPlanRunRow>> {
    let limit = limit.clamp(1, 100);
    Ok(sqlx::query_as::<_, PaymentPlanRunRow>(
        r#"SELECT r.id, r.plan_id, r.organization_id, r.agent_id, r.plan_version,
                  r.scheduled_for, r.status, r.plan_snapshot, r.execution_request_id,
                  r.payout_total_raw::TEXT AS payout_total_raw,
                  r.surplus_raw::TEXT AS surplus_raw,
                  r.balance_observed_raw::TEXT AS balance_observed_raw,
                  r.reason, r.attempt_count, r.lease_until,
                  r.created_at, r.updated_at, r.completed_at
           FROM payment_plan_runs r
           JOIN payment_plans p ON p.id = r.plan_id
           JOIN principal_agent_grants pag ON pag.agent_id = p.agent_id
           WHERE r.plan_id = $1 AND r.organization_id = $2 AND pag.principal_id = $3
             AND ($4::UUID IS NULL OR r.agent_id = $4)
           ORDER BY r.scheduled_for DESC LIMIT $5"#,
    )
    .bind(plan_id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(context.agent_id)
    .bind(limit)
    .fetch_all(pool)
    .await?)
}

pub async fn insert_plan_tx(
    tx: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    principal_id: Uuid,
    agent_id: Uuid,
    plan: &NormalizedPaymentPlan,
) -> Result<Uuid> {
    plan.validate()?;
    let plan_id = Uuid::new_v4();
    let cadence = serde_json::to_value(&plan.schedule.cadence)?
        .as_str()
        .context("cadence serialization failed")?
        .to_owned();
    sqlx::query(
        r#"INSERT INTO payment_plans (
               id, organization_id, agent_id, created_by_principal_id, name,
               cadence, timezone, local_time, weekday, day_of_month, reserve_raw,
               surplus_destination, surplus_minimum_raw, surplus_maximum_raw,
               callback_url, next_run_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::NUMERIC,$12,$13::NUMERIC,$14::NUMERIC,$15,$16)"#,
    )
    .bind(plan_id).bind(organization_id).bind(agent_id).bind(principal_id)
    .bind(&plan.name).bind(cadence).bind(&plan.schedule.timezone)
    .bind(&plan.schedule.local_time)
    .bind(plan.schedule.weekday.as_ref().map(|v| v.to_ascii_lowercase()))
    .bind(plan.schedule.day_of_month.map(i16::from)).bind(&plan.reserve_raw)
    .bind(plan.surplus.as_ref().map(|v| &v.destination))
    .bind(plan.surplus.as_ref().map(|v| &v.minimum_transfer_raw))
    .bind(plan.surplus.as_ref().and_then(|v| v.maximum_transfer_raw.as_ref()))
    .bind(&plan.callback_url).bind(plan.first_run_at)
    .execute(&mut **tx).await?;
    for (position, recipient) in plan.recipients.iter().enumerate() {
        sqlx::query(
            r#"INSERT INTO payment_plan_recipients
               (id, plan_id, position, recipient_address, amount_raw, label)
               VALUES ($1,$2,$3,$4,$5::NUMERIC,$6)"#,
        )
        .bind(Uuid::new_v4())
        .bind(plan_id)
        .bind(position as i16)
        .bind(&recipient.address)
        .bind(&recipient.amount_raw)
        .bind(&recipient.label)
        .execute(&mut **tx)
        .await?;
    }
    Ok(plan_id)
}

pub async fn pause_plan_immediately(
    pool: &PgPool,
    context: &crate::types::AuthContext,
    plan_id: Uuid,
) -> Result<bool> {
    let changed = sqlx::query(
        r#"UPDATE payment_plans p SET status = 'paused', version = version + 1, updated_at = now()
           FROM principal_agent_grants pag
           WHERE p.id = $1 AND p.organization_id = $2 AND p.agent_id = pag.agent_id
             AND pag.principal_id = $3 AND p.status = 'active'
             AND ($4::UUID IS NULL OR p.agent_id = $4)"#,
    )
    .bind(plan_id)
    .bind(context.organization_id)
    .bind(context.principal_id)
    .bind(context.agent_id)
    .execute(pool)
    .await?;
    Ok(changed.rows_affected() == 1)
}

async fn claim_due_plan(pool: &PgPool) -> Result<bool> {
    let mut tx = pool.begin().await?;
    let sql = format!(
        "{PLAN_SELECT} WHERE p.status = 'active' AND p.next_run_at <= now()\n\
         ORDER BY p.next_run_at FOR UPDATE OF p SKIP LOCKED LIMIT 1"
    );
    let Some(plan) = sqlx::query_as::<_, PaymentPlanRow>(&sql)
        .fetch_optional(&mut *tx)
        .await?
    else {
        tx.rollback().await?;
        return Ok(false);
    };
    let recipients = sqlx::query_as::<_, PaymentPlanRecipientRow>(
        r#"SELECT id, plan_id, position, recipient_address, amount_raw::TEXT AS amount_raw,
                  label, created_at FROM payment_plan_recipients
           WHERE plan_id = $1 ORDER BY position"#,
    )
    .bind(plan.id)
    .fetch_all(&mut *tx)
    .await?;
    if recipients.is_empty() {
        bail!("active payment plan {} has no recipients", plan.id);
    }
    let scheduled_for = plan
        .next_run_at
        .context("active payment plan has no next run")?;
    let schedule = schedule_from_row(&plan)?;
    // Advance from now, not from a deeply stale due date, to avoid a catch-up burst after downtime.
    let next_run_at = schedule.next_after(Utc::now())?;
    let snapshot = PaymentPlanRunSnapshot {
        organization_id: plan.organization_id,
        agent_id: plan.agent_id,
        agent_external_id: plan.agent_external_id.clone(),
        principal_id: plan.created_by_principal_id,
        plan_version: plan.version,
        reserve_raw: plan.reserve_raw.clone(),
        surplus_destination: plan.surplus_destination.clone(),
        surplus_minimum_raw: plan.surplus_minimum_raw.clone(),
        surplus_maximum_raw: plan.surplus_maximum_raw.clone(),
        callback_url: plan.callback_url.clone(),
        recipients: recipients
            .into_iter()
            .map(|recipient| NormalizedRecipient {
                address: recipient.recipient_address,
                amount_raw: recipient.amount_raw,
                label: recipient.label,
            })
            .collect(),
    };
    sqlx::query(
        r#"INSERT INTO payment_plan_runs (
               id, plan_id, organization_id, agent_id, plan_version,
               scheduled_for, plan_snapshot
           ) VALUES ($1,$2,$3,$4,$5,$6,$7)
           ON CONFLICT (plan_id, scheduled_for) DO NOTHING"#,
    )
    .bind(Uuid::new_v4())
    .bind(plan.id)
    .bind(plan.organization_id)
    .bind(plan.agent_id)
    .bind(plan.version)
    .bind(scheduled_for)
    .bind(serde_json::to_value(snapshot)?)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE payment_plans SET next_run_at=$2, last_run_at=$3, updated_at=now() WHERE id=$1",
    )
    .bind(plan.id)
    .bind(next_run_at)
    .bind(scheduled_for)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(true)
}

async fn claim_run(pool: &PgPool) -> Result<Option<PaymentPlanRunRow>> {
    Ok(sqlx::query_as::<_, PaymentPlanRunRow>(
        r#"WITH selected AS (
               SELECT id FROM payment_plan_runs
               WHERE (status = 'claimed' OR (status = 'processing' AND lease_until <= now()))
                 AND attempt_count < 5
               ORDER BY scheduled_for FOR UPDATE SKIP LOCKED LIMIT 1
           )
           UPDATE payment_plan_runs r
           SET status='processing', attempt_count=attempt_count+1,
               lease_until=now()+interval '2 minutes', updated_at=now()
           FROM selected WHERE r.id=selected.id
           RETURNING r.id, r.plan_id, r.organization_id, r.agent_id, r.plan_version,
                     r.scheduled_for, r.status, r.plan_snapshot, r.execution_request_id,
                     r.payout_total_raw::TEXT AS payout_total_raw,
                     r.surplus_raw::TEXT AS surplus_raw,
                     r.balance_observed_raw::TEXT AS balance_observed_raw,
                     r.reason, r.attempt_count, r.lease_until,
                     r.created_at, r.updated_at, r.completed_at"#,
    )
    .fetch_optional(pool)
    .await?)
}

fn schedule_from_row(plan: &PaymentPlanRow) -> Result<PaymentSchedule> {
    Ok(PaymentSchedule {
        cadence: serde_json::from_value(serde_json::Value::String(plan.cadence.clone()))?,
        timezone: plan.timezone.clone(),
        local_time: plan.local_time.clone(),
        weekday: plan.weekday.clone(),
        day_of_month: plan.day_of_month.map(|value| value as u8),
    })
}

fn erc20_transfer_call(recipient: &str, amount: U256) -> Result<BatchCall> {
    let recipient = recipient.parse::<Address>()?;
    let mut calldata = id("transfer(address,uint256)")[..4].to_vec();
    calldata.extend(encode(&[Token::Address(recipient), Token::Uint(amount)]));
    Ok(BatchCall {
        target_contract: ARC_USDC_ADDRESS.into(),
        calldata: format!("0x{}", hex::encode(calldata)),
        value: "0".into(),
    })
}

fn terminal_run_status(execution_status: &ExecutionStatus) -> Option<&'static str> {
    match execution_status {
        ExecutionStatus::Confirmed => Some("confirmed"),
        ExecutionStatus::Reverted => Some("reverted"),
        ExecutionStatus::Failed => Some("failed"),
        _ => None,
    }
}

async fn finish_run(
    pool: &PgPool,
    run_id: Uuid,
    status: &str,
    reason: Option<&str>,
    amounts: RunAmounts,
    execution_request_id: Option<Uuid>,
) -> Result<()> {
    sqlx::query(
        r#"UPDATE payment_plan_runs SET status=$2, reason=$3,
               balance_observed_raw=$4::NUMERIC, payout_total_raw=$5::NUMERIC,
               surplus_raw=$6::NUMERIC, execution_request_id=$7, lease_until=NULL,
               completed_at=CASE WHEN $2 IN ('confirmed','skipped','failed','reverted')
                                 THEN now() ELSE NULL END,
               updated_at=now() WHERE id=$1"#,
    )
    .bind(run_id)
    .bind(status)
    .bind(reason)
    .bind(amounts.balance.map(|value| value.to_string()))
    .bind(amounts.payout_total.to_string())
    .bind(amounts.surplus.to_string())
    .bind(execution_request_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
struct RunAmounts {
    balance: Option<U256>,
    payout_total: U256,
    surplus: U256,
}

async fn process_run(state: &AppState, run: PaymentPlanRunRow) -> Result<()> {
    let snapshot: PaymentPlanRunSnapshot = serde_json::from_value(run.plan_snapshot.clone())?;
    let current: Option<(String, i64)> = sqlx::query_as(
        "SELECT status, version FROM payment_plans WHERE id=$1 AND organization_id=$2",
    )
    .bind(run.plan_id)
    .bind(run.organization_id)
    .fetch_optional(&state.db_pool)
    .await?;
    if current
        .as_ref()
        .is_none_or(|(status, version)| status != "active" || *version != run.plan_version)
    {
        return finish_run(
            &state.db_pool,
            run.id,
            "skipped",
            Some("plan was paused, cancelled, or changed before execution"),
            RunAmounts::default(),
            None,
        )
        .await;
    }
    let mut scopes = std::collections::BTreeSet::new();
    scopes.insert("*".into());
    let auth = AuthContext {
        organization_id: snapshot.organization_id,
        principal_id: snapshot.principal_id,
        credential_id: Uuid::nil(),
        credential_kind: CredentialKind::OAuthSession,
        scopes,
        agent_id: Some(snapshot.agent_id),
        agent_external_id: Some(snapshot.agent_external_id.clone()),
        instance_id: None,
        dpop_jkt: None,
    };
    let (_, policy) =
        crate::db::authorize_execution_agent(&state.db_pool, &auth, &snapshot.agent_external_id)
            .await?;
    if !policy.allowed_actions.as_ref().is_some_and(|actions| {
        actions
            .iter()
            .any(|action| action == "*" || action == "payment_plan:execute")
    }) {
        return finish_run(
            &state.db_pool,
            run.id,
            "failed",
            Some("agent policy no longer allows payment-plan execution"),
            RunAmounts::default(),
            None,
        )
        .await;
    }
    let external_wallet = crate::byow::active_connection_for_agent(
        &state.db_pool,
        snapshot.organization_id,
        snapshot.agent_id,
    )
    .await?;
    let balance = if let Some(connection) = external_wallet.as_ref() {
        if connection.chain != state.config.arc_network.name() {
            bail!("active Circle wallet connection targets a different Arc network");
        }
        let chain = crate::types::Chain::from_str_loose(&connection.chain)
            .context("Circle wallet connection has an invalid Arc network")?;
        let provider = state.engine.provider_for_chain(&chain)?;
        services::fetch_erc20_balance_of(
            provider.as_ref(),
            ARC_USDC_ADDRESS.parse::<Address>()?,
            connection.wallet_address.parse::<Address>()?,
        )
        .await?
    } else {
        let balance_response = services::handle_get_wallet_balance(
            &state.engine,
            &state.db_pool,
            &state.wallet_registry,
            snapshot.organization_id,
            &snapshot.agent_external_id,
            state.config.arc_network.name(),
        )
        .await?;
        U256::from_dec_str(
            &balance_response
                .tokens
                .first()
                .context("Arc USDC balance was unavailable")?
                .raw,
        )?
    };
    let payout_total = snapshot
        .recipients
        .iter()
        .try_fold(U256::zero(), |total, recipient| {
            total
                .checked_add(U256::from_dec_str(&recipient.amount_raw)?)
                .context("payout total overflow")
        })?;
    let reserve = U256::from_dec_str(&snapshot.reserve_raw)?;
    let fee_buffer = if external_wallet.is_some() {
        U256::zero()
    } else {
        crate::execution_engine::pricing::usd_to_token_raw_amount(
            policy
                .max_execution_fee_usd
                .unwrap_or(crate::auth::DEFAULT_MAX_EXECUTION_FEE_USD),
            USDC_DECIMALS as u8,
        )?
    };
    let required = payout_total
        .checked_add(reserve)
        .and_then(|v| v.checked_add(fee_buffer))
        .context("required balance overflow")?;
    if balance < required {
        let reason = if external_wallet.is_some() {
            "insufficient USDC to pay every recipient while preserving the reserve"
        } else {
            "insufficient USDC to pay every recipient while preserving the reserve and execution fee buffer"
        };
        return finish_run(
            &state.db_pool,
            run.id,
            "skipped",
            Some(reason),
            RunAmounts {
                balance: Some(balance),
                payout_total,
                surplus: U256::zero(),
            },
            None,
        )
        .await;
    }
    let token_limits = crate::policy::validate_token_spend_limits(&policy.token_spend_limits)?;
    let spend_limit = token_limits
        .iter()
        .find(|limit| limit.token.eq_ignore_ascii_case(ARC_USDC_ADDRESS))
        .or_else(|| token_limits.iter().find(|limit| limit.token == "*"))
        .context("agent policy has no Arc USDC spend limit")?;
    let spend_limit = U256::from_dec_str(&spend_limit.max_per_execution_raw)?;
    if payout_total > spend_limit {
        return finish_run(
            &state.db_pool,
            run.id,
            "failed",
            Some("fixed payouts exceed the current per-execution policy limit"),
            RunAmounts {
                balance: Some(balance),
                payout_total,
                surplus: U256::zero(),
            },
            None,
        )
        .await;
    }
    let mut surplus = U256::zero();
    if let (Some(destination), Some(minimum)) = (
        snapshot.surplus_destination.as_deref(),
        snapshot.surplus_minimum_raw.as_deref(),
    ) {
        let available = balance - required;
        let policy_room = spend_limit - payout_total;
        surplus = available.min(policy_room);
        if let Some(maximum) = snapshot.surplus_maximum_raw.as_deref() {
            surplus = surplus.min(U256::from_dec_str(maximum)?);
        }
        if surplus < U256::from_dec_str(minimum)? {
            surplus = U256::zero();
        }
        if !surplus.is_zero() && destination.parse::<Address>().is_err() {
            bail!("stored surplus destination is invalid");
        }
    }
    let total_spend = payout_total
        .checked_add(surplus)
        .context("payment total overflow")?;
    if let Some(connection) = external_wallet.as_ref() {
        if snapshot.recipients.len() != 1 || snapshot.surplus_destination.is_some() {
            return finish_run(
                &state.db_pool,
                run.id,
                "failed",
                Some(
                    "Circle Agent Wallet currently supports one recipient per plan and no surplus sweep",
                ),
                RunAmounts {
                    balance: Some(balance),
                    payout_total,
                    surplus,
                },
                None,
            )
            .await;
        }
        let rolling_limit = token_limits
            .iter()
            .find(|limit| limit.token.eq_ignore_ascii_case(ARC_USDC_ADDRESS))
            .or_else(|| token_limits.iter().find(|limit| limit.token == "*"))
            .context("agent policy has no Arc USDC rolling limit")?;
        let mut transfers = snapshot
            .recipients
            .iter()
            .map(|recipient| {
                let amount = U256::from_dec_str(&recipient.amount_raw)?;
                Ok(crate::byow::ExternalPaymentTransfer {
                    recipient: recipient.address.clone(),
                    amount_raw: recipient.amount_raw.clone(),
                    amount_usdc: format_units(amount, USDC_DECIMALS as usize)?,
                    label: recipient.label.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if !surplus.is_zero() {
            transfers.push(crate::byow::ExternalPaymentTransfer {
                recipient: snapshot
                    .surplus_destination
                    .clone()
                    .expect("surplus destination"),
                amount_raw: surplus.to_string(),
                amount_usdc: format_units(surplus, USDC_DECIMALS as usize)?,
                label: Some("Surplus sweep".into()),
            });
        }
        let intent = crate::byow::create_payment_intent(
            &state.db_pool,
            run.id,
            connection,
            &transfers,
            total_spend,
            U256::from_dec_str(&rolling_limit.max_rolling_raw)?,
            policy.rolling_window_seconds,
        )
        .await?;
        return finish_run(
            &state.db_pool,
            run.id,
            "awaiting_wallet",
            Some(&format!(
                "Circle Agent Wallet payment intent {} is ready for the connected agent",
                intent.id
            )),
            RunAmounts {
                balance: Some(balance),
                payout_total,
                surplus,
            },
            None,
        )
        .await;
    }
    let mut calls = snapshot
        .recipients
        .iter()
        .map(|recipient| {
            erc20_transfer_call(
                &recipient.address,
                U256::from_dec_str(&recipient.amount_raw)?,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let mut recipients = snapshot
        .recipients
        .iter()
        .map(|recipient| recipient.address.clone())
        .collect::<Vec<_>>();
    if !surplus.is_zero() {
        let destination = snapshot
            .surplus_destination
            .as_deref()
            .expect("surplus destination");
        calls.push(erc20_transfer_call(destination, surplus)?);
        recipients.push(destination.into());
    }
    let request = ExecutionRequest {
        agent_id: snapshot.agent_external_id.clone(),
        chain: state.config.arc_network.name().into(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".into(),
        strategy_id: Some(format!("payment-plan:{}", run.plan_id)),
        batch_calls: Some(calls),
        callback_url: snapshot.callback_url.clone(),
        policy_impact: ExecutionPolicyImpact {
            token_spends: vec![TokenSpend {
                token: ARC_USDC_ADDRESS.into(),
                amount_raw: total_spend.to_string(),
            }],
            borrowed_value_usd: 0.0,
            risks: vec![RISK_EXTERNAL_WITHDRAWAL.into()],
            recipients,
        },
    };
    let mut redis = state.redis_conn.clone();
    let response = services::handle_execute_idempotent(
        &state.engine,
        &state.db_pool,
        &mut redis,
        &state.wallet_registry,
        &auth,
        &request,
        &format!("payment-plan-run-{}", run.id),
    )
    .await?;
    if let Some(status) = terminal_run_status(&response.status) {
        finish_run(
            &state.db_pool,
            run.id,
            status,
            Some(&response.message),
            RunAmounts {
                balance: Some(balance),
                payout_total,
                surplus,
            },
            Some(response.request_id),
        )
        .await
    } else {
        finish_run(
            &state.db_pool,
            run.id,
            "queued",
            None,
            RunAmounts {
                balance: Some(balance),
                payout_total,
                surplus,
            },
            Some(response.request_id),
        )
        .await
    }
}

async fn reconcile_queued_runs(pool: &PgPool) -> Result<u64> {
    Ok(sqlx::query(
        r#"UPDATE payment_plan_runs r
           SET status = CASE er.status
                 WHEN 'confirmed' THEN 'confirmed'
                 WHEN 'reverted' THEN 'reverted'
                 WHEN 'failed' THEN 'failed'
                 ELSE r.status END,
               reason = CASE WHEN er.status IN ('reverted','failed') THEN er.error_message ELSE r.reason END,
               completed_at = CASE WHEN er.status IN ('confirmed','reverted','failed') THEN now() ELSE r.completed_at END,
               updated_at = now()
           FROM execution_requests er
           WHERE r.execution_request_id = er.id AND r.status = 'queued'
             AND er.status IN ('confirmed','reverted','failed')"#,
    ).execute(pool).await?.rows_affected())
}

async fn expire_exhausted_runs(pool: &PgPool) -> Result<u64> {
    Ok(sqlx::query(
        r#"UPDATE payment_plan_runs SET status='failed', lease_until=NULL,
               reason=COALESCE(reason, 'payment-plan scheduler exhausted its retry limit'),
               completed_at=now(), updated_at=now()
           WHERE status IN ('claimed','processing') AND attempt_count >= 5
             AND (lease_until IS NULL OR lease_until <= now())"#,
    )
    .execute(pool)
    .await?
    .rows_affected())
}

pub async fn run_scheduler(state: AppState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    loop {
        interval.tick().await;
        if let Err(error) = reconcile_queued_runs(&state.db_pool).await {
            tracing::error!(%error, "payment-plan reconciliation failed");
        }
        match crate::byow::expire_pending_payment_intents(&state.db_pool).await {
            Ok(run_ids) => {
                for run_id in run_ids {
                    fire_payment_plan_webhook(
                        &state,
                        run_id,
                        ExecutionStatus::Failed,
                        None,
                        Some("Circle wallet payment window expired".into()),
                    )
                    .await;
                }
            }
            Err(error) => {
                tracing::error!(%error, "external-wallet payment expiry failed");
            }
        }
        if let Err(error) = expire_exhausted_runs(&state.db_pool).await {
            tracing::error!(%error, "payment-plan retry cleanup failed");
        }
        for _ in 0..25 {
            match claim_due_plan(&state.db_pool).await {
                Ok(true) => {}
                Ok(false) => break,
                Err(error) => {
                    tracing::error!(%error, "failed to claim a due payment plan");
                    break;
                }
            }
        }
        for _ in 0..25 {
            let run = match claim_run(&state.db_pool).await {
                Ok(Some(run)) => run,
                Ok(None) => break,
                Err(error) => {
                    tracing::error!(%error, "failed to claim a payment-plan run");
                    break;
                }
            };
            if let Err(error) = process_run(&state, run.clone()).await {
                tracing::error!(run_id=%run.id, %error, "payment-plan run attempt failed");
                let retryable = run.attempt_count < 5;
                let status = if retryable { "processing" } else { "failed" };
                let completed = if retryable { None } else { Some(Utc::now()) };
                let retry_delay_seconds = 15_i32.saturating_mul(1_i32 << (run.attempt_count - 1));
                if let Err(update_error) = sqlx::query(
                    r#"UPDATE payment_plan_runs SET status=$2, reason=$3,
                           lease_until=CASE WHEN $2='processing'
                             THEN now() + make_interval(secs => $5) ELSE NULL END,
                           completed_at=$4, updated_at=now()
                       WHERE id=$1 AND status='processing'"#,
                )
                .bind(run.id)
                .bind(status)
                .bind(error.to_string())
                .bind(completed)
                .bind(retry_delay_seconds)
                .execute(&state.db_pool)
                .await
                {
                    tracing::error!(run_id=%run.id, %update_error, "failed to release payment-plan run lease");
                }
            }
        }
    }
}

pub async fn fire_payment_plan_webhook(
    state: &AppState,
    run_id: Uuid,
    status: ExecutionStatus,
    tx_hash: Option<String>,
    error: Option<String>,
) {
    let context = match sqlx::query_as::<_, (Uuid, Option<String>, DateTime<Utc>)>(
        r#"SELECT organization_id, plan_snapshot->>'callback_url', created_at
           FROM payment_plan_runs WHERE id=$1"#,
    )
    .bind(run_id)
    .fetch_optional(&state.db_pool)
    .await
    {
        Ok(Some(context)) => context,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%run_id, %error, "payment-plan callback context unavailable");
            return;
        }
    };
    let (organization_id, callback_url, created_at) = context;
    let Some(callback_url) = callback_url.filter(|url| !url.is_empty()) else {
        return;
    };
    let signing_secret = match crate::db::get_webhook_secret_by_organization(
        &state.db_pool,
        organization_id,
        &state.config.auth_secret_encryption_key,
    )
    .await
    {
        Ok(Some(secret)) => secret,
        Ok(None) => return,
        Err(error) => {
            tracing::warn!(%organization_id, %error, "payment-plan webhook secret unavailable");
            return;
        }
    };
    let payload = crate::webhook::WebhookPayload {
        event_id: Uuid::new_v4(),
        event_type: "payment_plan.completed".into(),
        request_id: run_id,
        status,
        chain: state.config.arc_network.name().to_string(),
        tx_hash,
        cost_usd: None,
        error,
        created_at,
        completed_at: Utc::now(),
    };
    tokio::spawn(async move {
        crate::webhook::deliver(&callback_url, &payload, &signing_secret).await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usdc_amounts_are_exact() {
        assert_eq!(
            parse_usdc_amount("12.340001", false).unwrap(),
            U256::from(12_340_001u64)
        );
        assert_eq!(format_usdc_amount(U256::from(12_340_000u64)), "12.34");
        assert!(parse_usdc_amount("1.0000001", false).is_err());
        assert!(parse_usdc_amount("0", false).is_err());
    }

    #[test]
    fn weekly_schedule_uses_iana_timezone() {
        let schedule = PaymentSchedule {
            cadence: ScheduleCadence::Weekly,
            timezone: "Africa/Lagos".into(),
            local_time: "09:30".into(),
            weekday: Some("Friday".into()),
            day_of_month: None,
        };
        let after = DateTime::parse_from_rfc3339("2026-10-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            schedule.next_after(after).unwrap(),
            DateTime::parse_from_rfc3339("2026-10-09T08:30:00Z")
                .unwrap()
                .with_timezone(&Utc)
        );
    }

    #[test]
    fn plan_normalization_rejects_duplicate_recipients() {
        let input = PaymentPlanInput {
            name: "Payroll".into(),
            agent_id: "primary".into(),
            schedule: PaymentSchedule {
                cadence: ScheduleCadence::Daily,
                timezone: "UTC".into(),
                local_time: "12:00".into(),
                weekday: None,
                day_of_month: None,
            },
            recipients: vec![
                PaymentRecipientInput {
                    address: "0x0000000000000000000000000000000000000001".into(),
                    amount_usdc: "1".into(),
                    label: None,
                },
                PaymentRecipientInput {
                    address: "0x0000000000000000000000000000000000000001".into(),
                    amount_usdc: "2".into(),
                    label: None,
                },
            ],
            reserve_usdc: "5".into(),
            surplus: None,
            callback_url: None,
        };
        assert!(input.normalize(Utc::now()).is_err());
    }
}
