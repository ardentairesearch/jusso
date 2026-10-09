//! Bring-your-own-wallet adapters.
//!
//! Circle Agent Wallet is intentionally integrated as an external wallet. The
//! owner keeps Circle's MPC session on their own machine; Jusso stores only a
//! verified public address and independently verifies completed transfers.

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use ethers_core::{
    abi::{encode, Token},
    types::{Address, H256, U256},
    utils::{hash_message, id},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{arc::rpc::ArcRpcClient, policy::ARC_USDC_ADDRESS, types::AuthContext};

pub const CIRCLE_PROVIDER: &str = "circle_agent_wallet";
const EIP1271_MAGIC_VALUE: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];
const CONNECTION_CHALLENGE_TTL_MINUTES: i64 = 10;
const PAYMENT_INTENT_TTL_HOURS: i64 = 24;

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ExternalWalletConnection {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub agent_external_id: String,
    pub provider: String,
    pub chain: String,
    pub wallet_address: String,
    pub status: String,
    pub verified_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct WalletConnectionChallenge {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub agent_external_id: String,
    pub chain: String,
    pub wallet_address: String,
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ExternalPaymentTransfer {
    pub recipient: String,
    pub amount_raw: String,
    pub amount_usdc: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ExternalPaymentIntentRow {
    pub id: Uuid,
    pub payment_plan_run_id: Uuid,
    pub organization_id: Uuid,
    pub agent_id: Uuid,
    pub agent_external_id: String,
    pub connection_id: Uuid,
    pub chain: String,
    pub wallet_address: String,
    pub token_address: String,
    #[serde(skip_serializing)]
    pub transfers: Value,
    pub total_amount_raw: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalPaymentIntent {
    pub id: Uuid,
    pub payment_plan_run_id: Uuid,
    pub agent_id: String,
    pub provider: &'static str,
    pub chain: String,
    pub wallet_address: String,
    pub token_address: String,
    pub transfers: Vec<ExternalPaymentTransfer>,
    pub total_amount_raw: String,
    pub status: String,
    pub expires_at: DateTime<Utc>,
    pub circle_commands: Vec<String>,
}

pub struct ExternalPaymentConfirmation {
    pub intent: ExternalPaymentIntent,
    pub newly_confirmed: bool,
}

impl TryFrom<ExternalPaymentIntentRow> for ExternalPaymentIntent {
    type Error = anyhow::Error;

    fn try_from(row: ExternalPaymentIntentRow) -> Result<Self> {
        let transfers: Vec<ExternalPaymentTransfer> = serde_json::from_value(row.transfers)
            .context("stored external transfers are invalid")?;
        if transfers.is_empty() || transfers.len() > 16 {
            bail!("stored external payment intent has an invalid transfer count");
        }
        let chain = circle_chain_name(&row.chain)?;
        let commands = transfers
            .iter()
            .map(|transfer| {
                format!(
                    "circle wallet transfer {} --amount {} --token {} --address {} --chain {} --output json",
                    transfer.recipient,
                    transfer.amount_usdc,
                    row.token_address,
                    row.wallet_address,
                    chain
                )
            })
            .collect();
        Ok(Self {
            id: row.id,
            payment_plan_run_id: row.payment_plan_run_id,
            agent_id: row.agent_external_id,
            provider: CIRCLE_PROVIDER,
            chain: row.chain,
            wallet_address: row.wallet_address,
            token_address: row.token_address,
            transfers,
            total_amount_raw: row.total_amount_raw,
            status: row.status,
            expires_at: row.expires_at,
            circle_commands: commands,
        })
    }
}

pub async fn create_connection_challenge(
    pool: &PgPool,
    auth: &AuthContext,
    agent_external_id: &str,
    chain: &str,
    wallet_address: &str,
) -> Result<WalletConnectionChallenge> {
    validate_chain(chain)?;
    let address = parse_nonzero_address(wallet_address)?;
    let agent: (Uuid, String) = sqlx::query_as(
        r#"SELECT a.id, a.external_id FROM agents a
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE a.organization_id = $1 AND a.external_id = $2
             AND pag.principal_id = $3 AND a.status = 'active'"#,
    )
    .bind(auth.organization_id)
    .bind(agent_external_id)
    .bind(auth.principal_id)
    .fetch_optional(pool)
    .await?
    .context("active agent is not available to this owner")?;
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::minutes(CONNECTION_CHALLENGE_TTL_MINUTES);
    let normalized = format!("{address:?}").to_ascii_lowercase();
    let challenge = format!(
        "jusso-circle-v1:{id}:{}:{}:{normalized}:{}",
        auth.organization_id,
        agent.0,
        expires_at.timestamp()
    );
    sqlx::query(
        r#"INSERT INTO external_wallet_connection_challenges (
               id, organization_id, agent_id, provider, chain, wallet_address,
               challenge, created_by_principal_id, expires_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"#,
    )
    .bind(id)
    .bind(auth.organization_id)
    .bind(agent.0)
    .bind(CIRCLE_PROVIDER)
    .bind(chain)
    .bind(&normalized)
    .bind(&challenge)
    .bind(auth.principal_id)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(WalletConnectionChallenge {
        id,
        organization_id: auth.organization_id,
        agent_id: agent.0,
        agent_external_id: agent.1,
        chain: chain.into(),
        wallet_address: normalized.clone(),
        challenge: challenge.clone(),
        expires_at,
    })
}

pub async fn get_connection_challenge(
    pool: &PgPool,
    auth: &AuthContext,
    challenge_id: Uuid,
) -> Result<WalletConnectionChallenge> {
    sqlx::query_as::<_, WalletConnectionChallenge>(
        r#"SELECT c.id, c.organization_id, c.agent_id, a.external_id AS agent_external_id,
                  c.chain, c.wallet_address, c.challenge, c.expires_at
           FROM external_wallet_connection_challenges c
           JOIN agents a ON a.id = c.agent_id AND a.organization_id = c.organization_id
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE c.id = $1 AND c.organization_id = $2
             AND c.created_by_principal_id = $3 AND pag.principal_id = $3
             AND c.consumed_at IS NULL AND c.expires_at > now()
             AND a.status = 'active'"#,
    )
    .bind(challenge_id)
    .bind(auth.organization_id)
    .bind(auth.principal_id)
    .fetch_optional(pool)
    .await?
    .context("Circle wallet connection challenge is invalid, expired, or already used")
}

pub async fn verify_circle_ownership(
    rpc: &ArcRpcClient,
    wallet_address: &str,
    challenge: &str,
    signature: &str,
) -> Result<String> {
    let address = parse_nonzero_address(wallet_address)?;
    let code = rpc.get_code(address).await?;
    if code.is_empty() {
        bail!("Circle Agent Wallet must be deployed before it can be connected");
    }
    let signature = signature.trim().to_ascii_lowercase();
    let signature_bytes = parse_signature(&signature)?;
    let digest = hash_message(challenge.as_bytes());
    let mut calldata = id("isValidSignature(bytes32,bytes)")[..4].to_vec();
    calldata.extend(encode(&[
        Token::FixedBytes(digest.as_bytes().to_vec()),
        Token::Bytes(signature_bytes),
    ]));
    let result = rpc
        .call(address, &calldata)
        .await
        .context("Circle Agent Wallet rejected the ownership proof")?;
    if result.len() < 4 || result[..4] != EIP1271_MAGIC_VALUE {
        bail!("Circle Agent Wallet ownership signature is invalid");
    }
    Ok(signature)
}

pub async fn list_connections(
    pool: &PgPool,
    auth: &AuthContext,
) -> Result<Vec<ExternalWalletConnection>> {
    Ok(sqlx::query_as::<_, ExternalWalletConnection>(
        r#"SELECT c.id, c.organization_id, c.agent_id,
                  a.external_id AS agent_external_id, c.provider, c.chain,
                  c.wallet_address, c.status, c.verified_at, c.created_at, c.revoked_at
           FROM external_wallet_connections c
           JOIN agents a ON a.id = c.agent_id AND a.organization_id = c.organization_id
           JOIN principal_agent_grants pag ON pag.agent_id = a.id
           WHERE c.organization_id = $1 AND pag.principal_id = $2
           ORDER BY c.created_at DESC"#,
    )
    .bind(auth.organization_id)
    .bind(auth.principal_id)
    .fetch_all(pool)
    .await?)
}

pub async fn active_connection_for_agent(
    pool: &PgPool,
    organization_id: Uuid,
    agent_id: Uuid,
) -> Result<Option<ExternalWalletConnection>> {
    Ok(sqlx::query_as::<_, ExternalWalletConnection>(
        r#"SELECT c.id, c.organization_id, c.agent_id,
                  a.external_id AS agent_external_id, c.provider, c.chain,
                  c.wallet_address, c.status, c.verified_at, c.created_at, c.revoked_at
           FROM external_wallet_connections c
           JOIN agents a ON a.id = c.agent_id AND a.organization_id = c.organization_id
           WHERE c.organization_id = $1 AND c.agent_id = $2
             AND c.status = 'active' AND a.status = 'active'"#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn active_connection_for_external_id(
    pool: &PgPool,
    organization_id: Uuid,
    agent_external_id: &str,
) -> Result<Option<ExternalWalletConnection>> {
    Ok(sqlx::query_as::<_, ExternalWalletConnection>(
        r#"SELECT c.id, c.organization_id, c.agent_id,
                  a.external_id AS agent_external_id, c.provider, c.chain,
                  c.wallet_address, c.status, c.verified_at, c.created_at, c.revoked_at
           FROM external_wallet_connections c
           JOIN agents a ON a.id=c.agent_id AND a.organization_id=c.organization_id
           WHERE c.organization_id=$1 AND a.external_id=$2
             AND c.status='active' AND a.status='active'"#,
    )
    .bind(organization_id)
    .bind(agent_external_id)
    .fetch_optional(pool)
    .await?)
}

pub async fn create_payment_intent(
    pool: &PgPool,
    run_id: Uuid,
    connection: &ExternalWalletConnection,
    transfers: &[ExternalPaymentTransfer],
    total_amount: U256,
    max_rolling_raw: U256,
    rolling_window_seconds: i64,
) -> Result<ExternalPaymentIntent> {
    if transfers.is_empty() || transfers.len() > 16 || total_amount.is_zero() {
        bail!("external payment intent is empty or oversized");
    }
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("circle-payment:{}", connection.agent_id))
        .execute(&mut *transaction)
        .await?;
    let connection_active: Option<bool> = sqlx::query_scalar(
        r#"SELECT TRUE FROM external_wallet_connections
           WHERE id=$1 AND organization_id=$2 AND agent_id=$3
             AND provider='circle_agent_wallet' AND status='active'
             AND chain=$4 AND wallet_address=$5
           FOR UPDATE"#,
    )
    .bind(connection.id)
    .bind(connection.organization_id)
    .bind(connection.agent_id)
    .bind(&connection.chain)
    .bind(&connection.wallet_address)
    .fetch_optional(&mut *transaction)
    .await?;
    if connection_active.is_none() {
        bail!("Circle Agent Wallet connection is no longer active");
    }
    let reserved: String = sqlx::query_scalar(
        r#"SELECT COALESCE(SUM(total_amount_raw), 0)::TEXT
           FROM external_wallet_payment_intents
           WHERE organization_id=$1 AND agent_id=$2
             AND (status='confirmed' OR (status='pending' AND expires_at > now()))
             AND created_at >= now() - make_interval(secs => $3)"#,
    )
    .bind(connection.organization_id)
    .bind(connection.agent_id)
    .bind(rolling_window_seconds as f64)
    .fetch_one(&mut *transaction)
    .await?;
    let reserved = U256::from_dec_str(&reserved)?;
    if reserved
        .checked_add(total_amount)
        .context("external payment rolling amount overflow")?
        > max_rolling_raw
    {
        bail!("payment exceeds the agent's rolling USDC policy limit");
    }
    let id = Uuid::new_v4();
    let expires_at = Utc::now() + Duration::hours(PAYMENT_INTENT_TTL_HOURS);
    sqlx::query(
        r#"INSERT INTO external_wallet_payment_intents (
               id, payment_plan_run_id, organization_id, agent_id, connection_id,
               chain, wallet_address, token_address, transfers, total_amount_raw,
               expires_at
           ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::NUMERIC,$11)
           ON CONFLICT (payment_plan_run_id) DO NOTHING"#,
    )
    .bind(id)
    .bind(run_id)
    .bind(connection.organization_id)
    .bind(connection.agent_id)
    .bind(connection.id)
    .bind(&connection.chain)
    .bind(&connection.wallet_address)
    .bind(ARC_USDC_ADDRESS)
    .bind(serde_json::to_value(transfers)?)
    .bind(total_amount.to_string())
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    let row = load_intent_tx(&mut transaction, run_id).await?;
    transaction.commit().await?;
    ExternalPaymentIntent::try_from(row)
}

pub async fn list_pending_payment_intents(
    pool: &PgPool,
    auth: &AuthContext,
) -> Result<Vec<ExternalPaymentIntent>> {
    let agent_id = auth.agent_id.context("MCP session is not agent-bound")?;
    let rows = sqlx::query_as::<_, ExternalPaymentIntentRow>(
        r#"SELECT i.id, i.payment_plan_run_id, i.organization_id, i.agent_id,
                  a.external_id AS agent_external_id, i.connection_id, i.chain,
                  i.wallet_address, i.token_address, i.transfers,
                  i.total_amount_raw::TEXT AS total_amount_raw, i.status,
                  i.expires_at, i.created_at, i.confirmed_at
           FROM external_wallet_payment_intents i
           JOIN agents a ON a.id=i.agent_id AND a.organization_id=i.organization_id
           WHERE i.organization_id=$1 AND i.agent_id=$2 AND i.status='pending'
             AND i.expires_at > now()
           ORDER BY i.created_at"#,
    )
    .bind(auth.organization_id)
    .bind(agent_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(ExternalPaymentIntent::try_from)
        .collect()
}

pub async fn expire_pending_payment_intents(pool: &PgPool) -> Result<Vec<Uuid>> {
    let rows = sqlx::query_as::<_, (Uuid,)>(
        r#"WITH expired AS (
               UPDATE external_wallet_payment_intents
               SET status='expired'
               WHERE status='pending' AND expires_at <= now()
               RETURNING payment_plan_run_id
           )
           UPDATE payment_plan_runs r
           SET status='failed', reason='Circle wallet payment window expired',
               completed_at=now(), updated_at=now()
           FROM expired
           WHERE r.id=expired.payment_plan_run_id AND r.status='awaiting_wallet'
           RETURNING r.id"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id,)| id).collect())
}

pub async fn confirm_payment_intent(
    pool: &PgPool,
    rpc: &ArcRpcClient,
    auth: &AuthContext,
    intent_id: Uuid,
    tx_hashes: &[String],
) -> Result<ExternalPaymentConfirmation> {
    let agent_id = auth.agent_id.context("MCP session is not agent-bound")?;
    let mut transaction = pool.begin().await?;
    let row = sqlx::query_as::<_, ExternalPaymentIntentRow>(
        r#"SELECT i.id, i.payment_plan_run_id, i.organization_id, i.agent_id,
                  a.external_id AS agent_external_id, i.connection_id, i.chain,
                  i.wallet_address, i.token_address, i.transfers,
                  i.total_amount_raw::TEXT AS total_amount_raw, i.status,
                  i.expires_at, i.created_at, i.confirmed_at
           FROM external_wallet_payment_intents i
           JOIN agents a ON a.id=i.agent_id AND a.organization_id=i.organization_id
           WHERE i.id=$1 AND i.organization_id=$2 AND i.agent_id=$3
           FOR UPDATE OF i"#,
    )
    .bind(intent_id)
    .bind(auth.organization_id)
    .bind(agent_id)
    .fetch_optional(&mut *transaction)
    .await?
    .context("external payment intent was not found")?;
    if row.status == "confirmed" {
        transaction.rollback().await?;
        return Ok(ExternalPaymentConfirmation {
            intent: ExternalPaymentIntent::try_from(row)?,
            newly_confirmed: false,
        });
    }
    if row.status != "pending" || row.expires_at <= Utc::now() {
        bail!("external payment intent is no longer payable");
    }
    let transfers: Vec<ExternalPaymentTransfer> = serde_json::from_value(row.transfers.clone())?;
    if tx_hashes.len() != transfers.len() {
        bail!("one transaction hash is required for each payment transfer");
    }
    let wallet = row.wallet_address.parse::<Address>()?;
    let token = row.token_address.parse::<Address>()?;
    for (position, (transfer, raw_hash)) in transfers.iter().zip(tx_hashes).enumerate() {
        let normalized = raw_hash.trim().to_ascii_lowercase();
        let hash = normalized
            .parse::<H256>()
            .context("payment transaction hash is invalid")?;
        verify_transfer_receipt(rpc, hash, token, wallet, transfer).await?;
        let inserted = sqlx::query(
            r#"INSERT INTO external_wallet_intent_transactions (intent_id, position, tx_hash)
               VALUES ($1,$2,$3)
               ON CONFLICT (intent_id, position) DO UPDATE SET tx_hash=EXCLUDED.tx_hash
               WHERE external_wallet_intent_transactions.tx_hash=EXCLUDED.tx_hash"#,
        )
        .bind(intent_id)
        .bind(position as i16)
        .bind(normalized)
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            bail!("payment transaction conflicts with a previously recorded receipt");
        }
    }
    sqlx::query(
        "UPDATE external_wallet_payment_intents SET status='confirmed', confirmed_at=now() WHERE id=$1",
    )
    .bind(intent_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        r#"UPDATE payment_plan_runs SET status='confirmed', reason=NULL,
                  completed_at=now(), updated_at=now()
           WHERE id=$1 AND status='awaiting_wallet'"#,
    )
    .bind(row.payment_plan_run_id)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    let mut confirmed = row;
    confirmed.status = "confirmed".into();
    confirmed.confirmed_at = Some(Utc::now());
    Ok(ExternalPaymentConfirmation {
        intent: ExternalPaymentIntent::try_from(confirmed)?,
        newly_confirmed: true,
    })
}

async fn verify_transfer_receipt(
    rpc: &ArcRpcClient,
    hash: H256,
    token: Address,
    wallet: Address,
    transfer: &ExternalPaymentTransfer,
) -> Result<()> {
    let receipt = rpc
        .transaction_receipt(hash)
        .await?
        .context("payment transaction is not confirmed yet")?;
    if receipt.get("status").and_then(Value::as_str) != Some("0x1") {
        bail!("payment transaction reverted");
    }
    let recipient = transfer.recipient.parse::<Address>()?;
    let amount = U256::from_dec_str(&transfer.amount_raw)?;
    let event = H256::from_slice(&ethers_core::utils::keccak256(
        "Transfer(address,address,uint256)".as_bytes(),
    ));
    let matched = receipt
        .get("logs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|log| transfer_log_matches(log, token, wallet, recipient, amount, event));
    if !matched {
        bail!("payment receipt does not contain the authorized USDC transfer");
    }
    Ok(())
}

fn transfer_log_matches(
    log: &Value,
    token: Address,
    sender: Address,
    recipient: Address,
    amount: U256,
    event: H256,
) -> bool {
    let Some(address) = log.get("address").and_then(Value::as_str) else {
        return false;
    };
    if !address.eq_ignore_ascii_case(&format!("{token:?}")) {
        return false;
    }
    let Some(topics) = log.get("topics").and_then(Value::as_array) else {
        return false;
    };
    if topics.len() != 3
        || topics[0]
            .as_str()
            .and_then(|value| value.parse::<H256>().ok())
            != Some(event)
        || topic_address(topics[1].as_str()) != Some(sender)
        || topic_address(topics[2].as_str()) != Some(recipient)
    {
        return false;
    }
    log.get("data")
        .and_then(Value::as_str)
        .and_then(|value| U256::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        == Some(amount)
}

fn topic_address(value: Option<&str>) -> Option<Address> {
    let bytes = hex::decode(value?.strip_prefix("0x")?).ok()?;
    (bytes.len() == 32).then(|| Address::from_slice(&bytes[12..]))
}

async fn load_intent_tx(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    run_id: Uuid,
) -> Result<ExternalPaymentIntentRow> {
    Ok(sqlx::query_as::<_, ExternalPaymentIntentRow>(
        r#"SELECT i.id, i.payment_plan_run_id, i.organization_id, i.agent_id,
                  a.external_id AS agent_external_id, i.connection_id, i.chain,
                  i.wallet_address, i.token_address, i.transfers,
                  i.total_amount_raw::TEXT AS total_amount_raw, i.status,
                  i.expires_at, i.created_at, i.confirmed_at
           FROM external_wallet_payment_intents i
           JOIN agents a ON a.id=i.agent_id AND a.organization_id=i.organization_id
           WHERE i.payment_plan_run_id=$1"#,
    )
    .bind(run_id)
    .fetch_one(&mut **transaction)
    .await?)
}

pub fn circle_sign_command(challenge: &WalletConnectionChallenge) -> Result<String> {
    Ok(format!(
        "circle wallet sign message '{}' --address {} --chain {} --output json",
        challenge.challenge,
        challenge.wallet_address,
        circle_chain_name(&challenge.chain)?
    ))
}

fn circle_chain_name(chain: &str) -> Result<&'static str> {
    match chain {
        "arc" => Ok("ARC"),
        "arc-testnet" => Ok("ARC-TESTNET"),
        _ => bail!("Circle Agent Wallet connection targets an unsupported chain"),
    }
}

fn validate_chain(chain: &str) -> Result<()> {
    circle_chain_name(chain).map(|_| ())
}

fn parse_nonzero_address(value: &str) -> Result<Address> {
    let address = value
        .trim()
        .parse::<Address>()
        .context("Circle Agent Wallet address is invalid")?;
    if address == Address::zero() {
        bail!("Circle Agent Wallet address cannot be zero");
    }
    Ok(address)
}

fn parse_signature(value: &str) -> Result<Vec<u8>> {
    let encoded = value
        .strip_prefix("0x")
        .context("Circle wallet signature must be 0x-prefixed")?;
    if encoded.is_empty() || encoded.len() > 8192 || encoded.len() % 2 != 0 {
        bail!("Circle wallet signature has an invalid length");
    }
    hex::decode(encoded).context("Circle wallet signature is not valid hex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_log_matching_is_exact() {
        let token = ARC_USDC_ADDRESS.parse::<Address>().unwrap();
        let sender = "0x1111111111111111111111111111111111111111"
            .parse::<Address>()
            .unwrap();
        let recipient = "0x2222222222222222222222222222222222222222"
            .parse::<Address>()
            .unwrap();
        let event = H256::from_slice(&ethers_core::utils::keccak256(
            "Transfer(address,address,uint256)".as_bytes(),
        ));
        let topic = |address: Address| format!("0x{:0>64}", hex::encode(address));
        let log = serde_json::json!({
            "address": format!("{token:?}"),
            "topics": [format!("{event:?}"), topic(sender), topic(recipient)],
            "data": format!("0x{:064x}", U256::from(25_000_000u64))
        });
        assert!(transfer_log_matches(
            &log,
            token,
            sender,
            recipient,
            U256::from(25_000_000u64),
            event
        ));
        assert!(!transfer_log_matches(
            &log,
            token,
            sender,
            recipient,
            U256::from(25_000_001u64),
            event
        ));
    }

    #[test]
    fn circle_commands_are_chain_specific() {
        let challenge = WalletConnectionChallenge {
            id: Uuid::nil(),
            organization_id: Uuid::nil(),
            agent_id: Uuid::nil(),
            agent_external_id: "primary-agent".into(),
            chain: "arc-testnet".into(),
            wallet_address: "0x1111111111111111111111111111111111111111".into(),
            challenge: "jusso-circle-v1:test".into(),
            expires_at: Utc::now(),
        };
        assert!(circle_sign_command(&challenge)
            .unwrap()
            .contains("--chain ARC-TESTNET"));
    }
}
