//! Base native account-abstraction transaction support (EIP-8130/EIP-8168).
//!
//! The sender is a provider-managed EOA. Its first transaction atomically
//! delegates to Base's canonical DefaultAccount, so the address never changes.

use anyhow::{anyhow, bail, Context, Result};
use ethers::{
    abi::{encode, Function, Param, ParamType, StateMutability, Token},
    types::{Address, Bytes, Signature, H256, U256},
    utils::keccak256,
};
use reqwest::Client;
use rlp::RlpStream;
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{str::FromStr, time::Duration};
use tokio::time::{sleep, Instant};
use uuid::Uuid;

use crate::{
    types::{BatchCall, ExecutionFeeCharge},
    wallet_provider::{ManagedWallet, WalletManager},
};

pub const AA_TRANSACTION_TYPE: u8 = 0x79;
pub const AA_PAYER_TYPE: u8 = 0x7a;
const ESTIMATION_GAS_CAP: u64 = 30_000_000;
const AUTH_SIGNATURE_LENGTH: usize = 65;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeCall {
    pub to: Address,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountChange {
    Delegation(Address),
}

#[derive(Debug, Clone)]
pub struct NativeTransaction {
    pub chain_id: u64,
    /// Omitted for the implicit EOA path. The node recovers it from sender_auth.
    pub from: Option<Address>,
    pub nonce_key: U256,
    pub nonce_sequence: U256,
    pub expiry: U256,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: U256,
    pub account_changes: Vec<AccountChange>,
    pub phases: Vec<Vec<NativeCall>>,
    pub metadata: Bytes,
    pub payer: Option<Address>,
    pub sender_auth: Bytes,
    pub payer_auth: Bytes,
}

impl NativeTransaction {
    pub fn sender_signature_hash(&self) -> H256 {
        self.signature_hash(AA_TRANSACTION_TYPE, self.from)
    }

    /// Payer signatures bind the recovered EOA even though `from` is omitted
    /// from the serialized implicit-EOA transaction.
    pub fn payer_signature_hash(&self, resolved_sender: Address) -> Result<H256> {
        if self.payer.is_none() {
            bail!("cannot compute a payer hash without a payer");
        }
        Ok(self.signature_hash(AA_PAYER_TYPE, Some(resolved_sender)))
    }

    pub fn set_sender_signature(&mut self, signature: Signature) -> Result<()> {
        self.sender_auth = Bytes::from(normalized_signature_bytes(signature)?);
        Ok(())
    }

    pub fn set_payer_signature(&mut self, signature: Signature) -> Result<()> {
        if self.payer.is_none() {
            bail!("cannot set payer authorization without a payer");
        }
        let signature = normalized_signature_bytes(signature)?;
        let mut auth = Vec::with_capacity(20 + signature.len());
        auth.extend_from_slice(ecrecover_authenticator().as_bytes());
        auth.extend_from_slice(&signature);
        self.payer_auth = Bytes::from(auth);
        Ok(())
    }

    pub fn serialize(&self) -> Result<Bytes> {
        if self.chain_id == 0 {
            bail!("EIP-8130 chain ID cannot be zero");
        }
        if self.sender_auth.len() != AUTH_SIGNATURE_LENGTH {
            bail!("implicit EOA sender authorization must be exactly 65 bytes");
        }
        match self.payer {
            Some(_) if self.payer_auth.len() != 20 + AUTH_SIGNATURE_LENGTH => {
                bail!("payer authorization must be authenticator plus 65-byte signature")
            }
            Some(_) if self.payer_auth[..20] != ecrecover_authenticator().as_bytes()[..] => {
                bail!("payer authorization uses an unsupported authenticator")
            }
            None if !self.payer_auth.is_empty() => {
                bail!("payer authorization was provided without a payer")
            }
            _ => {}
        }

        let mut stream = RlpStream::new_list(14);
        self.append_body(&mut stream, self.from);
        append_address(&mut stream, self.payer);
        stream.append(&self.sender_auth.as_ref());
        stream.append(&self.payer_auth.as_ref());
        let payload = stream.out();
        let mut encoded = Vec::with_capacity(1 + payload.len());
        encoded.push(AA_TRANSACTION_TYPE);
        encoded.extend_from_slice(&payload);
        Ok(Bytes::from(encoded))
    }

    pub fn transaction_hash(&self) -> Result<H256> {
        Ok(H256::from(keccak256(self.serialize()?)))
    }

    fn signature_hash(&self, domain: u8, from: Option<Address>) -> H256 {
        let mut stream = RlpStream::new_list(12);
        self.append_body(&mut stream, from);
        append_address(&mut stream, self.payer);
        let payload = stream.out();
        let mut encoded = Vec::with_capacity(1 + payload.len());
        encoded.push(domain);
        encoded.extend_from_slice(&payload);
        H256::from(keccak256(encoded))
    }

    fn append_body(&self, stream: &mut RlpStream, from: Option<Address>) {
        append_u256(stream, U256::from(self.chain_id));
        append_address(stream, from);
        append_u256(stream, self.nonce_key);
        append_u256(stream, self.nonce_sequence);
        append_u256(stream, self.expiry);
        append_u256(stream, self.max_priority_fee_per_gas);
        append_u256(stream, self.max_fee_per_gas);
        append_u256(stream, self.gas_limit);

        stream.begin_list(self.account_changes.len());
        for change in &self.account_changes {
            match change {
                AccountChange::Delegation(target) => {
                    stream.begin_list(2);
                    append_u256(stream, U256::from(2));
                    stream.append(&target.as_bytes());
                }
            }
        }

        stream.begin_list(self.phases.len());
        for phase in &self.phases {
            stream.begin_list(phase.len());
            for call in phase {
                stream.begin_list(2);
                stream.append(&call.to.as_bytes());
                stream.append(&call.data.as_ref());
            }
        }
        stream.append(&self.metadata.as_ref());
    }
}

#[derive(Clone)]
pub struct NativeAaClient {
    http: Client,
    rpc_url: String,
    pub chain_id: u64,
    pub default_account: Address,
    pub payer: Address,
    pub execution_token: Address,
    pub execution_token_symbol: String,
    max_payer_gas_cost_wei: U256,
    receipt_timeout: Duration,
    receipt_poll_interval: Duration,
}

impl std::fmt::Debug for NativeAaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeAaClient")
            .field("rpc_url", &"[REDACTED]")
            .field("chain_id", &self.chain_id)
            .field("default_account", &self.default_account)
            .field("payer", &self.payer)
            .field("execution_token", &self.execution_token)
            .field("execution_token_symbol", &self.execution_token_symbol)
            .field("max_payer_gas_cost_wei", &self.max_payer_gas_cost_wei)
            .field("receipt_timeout", &self.receipt_timeout)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct NativeAaConfig {
    pub rpc_url: String,
    pub chain_id: u64,
    pub default_account: Address,
    pub payer: Address,
    pub execution_token: Address,
    pub execution_token_symbol: String,
    pub receipt_timeout: Duration,
    pub max_payer_gas_cost_wei: U256,
}

#[derive(Debug, Clone)]
pub struct PreparedNativeTransaction {
    transaction: NativeTransaction,
    sender: Address,
}

impl PreparedNativeTransaction {
    pub fn transaction(&self) -> &NativeTransaction {
        &self.transaction
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeReceipt {
    pub transaction_hash: String,
    pub status: Option<String>,
    pub block_number: Option<String>,
    pub gas_used: Option<String>,
    pub payer: Option<String>,
    pub phase_statuses: Option<Vec<String>>,
    pub metadata: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NativeExecutionResult {
    pub tx_hash: H256,
    pub block_number: Option<u64>,
    pub gas_used: Option<u64>,
    pub phase_statuses: Vec<bool>,
}

impl NativeExecutionResult {
    pub fn fee_phase_succeeded(&self) -> bool {
        self.phase_statuses.first().copied().unwrap_or(false)
    }

    pub fn all_phases_succeeded(&self) -> bool {
        !self.phase_statuses.is_empty() && self.phase_statuses.iter().all(|status| *status)
    }
}

impl NativeAaClient {
    pub fn new(config: NativeAaConfig) -> Result<Self> {
        let NativeAaConfig {
            rpc_url,
            chain_id,
            default_account,
            payer,
            execution_token,
            execution_token_symbol,
            receipt_timeout,
            max_payer_gas_cost_wei,
        } = config;
        if chain_id == 0 {
            bail!("native AA chain ID cannot be zero");
        }
        if [default_account, payer, execution_token]
            .iter()
            .any(|address| *address == Address::zero())
        {
            bail!("native AA addresses cannot be zero");
        }
        if execution_token_symbol.is_empty() {
            bail!("native AA execution token symbol cannot be empty");
        }
        if max_payer_gas_cost_wei.is_zero() {
            bail!("native AA sponsorship limit cannot be zero");
        }
        let parsed = reqwest::Url::parse(&rpc_url).context("invalid Base RPC URL")?;
        if parsed.scheme() != "https"
            && parsed.host_str() != Some("localhost")
            && parsed.host_str() != Some("127.0.0.1")
        {
            bail!("Base RPC URL must use HTTPS outside local development");
        }
        Ok(Self {
            http: Client::builder().timeout(Duration::from_secs(30)).build()?,
            rpc_url,
            chain_id,
            default_account,
            payer,
            execution_token,
            execution_token_symbol,
            max_payer_gas_cost_wei,
            receipt_timeout,
            receipt_poll_interval: Duration::from_secs(2),
        })
    }

    pub async fn prepare(
        &self,
        sender: Address,
        fee: Option<&ExecutionFeeCharge>,
        protocol_calls: &[BatchCall],
        request_id: Uuid,
    ) -> Result<PreparedNativeTransaction> {
        if protocol_calls.is_empty() {
            bail!("at least one protocol call is required");
        }
        self.validate_fee(fee)?;
        if let Some(fee) = fee {
            self.preflight_fee_transfer(sender, fee).await?;
        }
        let action_phase = encode_wire_phase(sender, protocol_calls)?;
        let mut phases = Vec::with_capacity(if fee.is_some() { 2 } else { 1 });
        if let Some(fee) = fee {
            phases.push(vec![fee_transfer_call(fee)?]);
        }
        phases.push(action_phase);
        let account_changes = match delegation_target(&self.get_code(sender).await?)? {
            None => vec![AccountChange::Delegation(self.default_account)],
            Some(target) if target == self.default_account => Vec::new(),
            Some(target) => {
                bail!("sender is delegated to unauthorized account implementation {target:?}")
            }
        };
        let nonce_sequence = self.get_transaction_count(sender).await?;
        let (max_priority_fee_per_gas, max_fee_per_gas) = self.fee_caps().await?;
        let mut transaction = NativeTransaction {
            chain_id: self.chain_id,
            from: None,
            nonce_key: U256::zero(),
            nonce_sequence,
            expiry: U256::zero(),
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit: U256::from(ESTIMATION_GAS_CAP),
            account_changes,
            phases,
            metadata: Bytes::from(request_id.as_bytes().to_vec()),
            payer: Some(self.payer),
            sender_auth: Bytes::new(),
            payer_auth: Bytes::new(),
        };
        let estimate = self.estimate_gas(sender, &transaction).await?;
        let buffered = estimate
            .checked_mul(U256::from(120))
            .and_then(|value| value.checked_div(U256::from(100)))
            .ok_or_else(|| anyhow!("gas estimate overflow"))?;
        if buffered > U256::from(ESTIMATION_GAS_CAP) {
            bail!("native AA gas estimate exceeds configured safety cap");
        }
        transaction.gas_limit = buffered.max(U256::from(21_000u64));
        self.validate_sponsorship_cost(&transaction)?;
        Ok(PreparedNativeTransaction {
            transaction,
            sender,
        })
    }

    pub async fn sign(
        &self,
        mut prepared: PreparedNativeTransaction,
        wallet_manager: &WalletManager,
        sender_wallet: &ManagedWallet,
        payer_wallet: &ManagedWallet,
        request_id: Uuid,
        expected_fee: Option<&ExecutionFeeCharge>,
    ) -> Result<NativeTransaction> {
        self.validate_signing_policy(&prepared, request_id, expected_fee)?;
        if sender_wallet.provider_wallet.address != prepared.sender {
            bail!("prepared sender does not match the managed sender wallet");
        }
        if payer_wallet.provider_wallet.address != self.payer {
            bail!("configured payer does not match the managed payer wallet");
        }
        let sender_hash = prepared.transaction.sender_signature_hash();
        let sender_signature = wallet_manager
            .sign_hash(
                sender_wallet,
                sender_hash,
                derived_idempotency_key(request_id, b"sender", sender_hash),
            )
            .await?;
        prepared
            .transaction
            .set_sender_signature(sender_signature)?;

        let payer_hash = prepared.transaction.payer_signature_hash(prepared.sender)?;
        let payer_signature = wallet_manager
            .sign_hash(
                payer_wallet,
                payer_hash,
                derived_idempotency_key(request_id, b"payer", payer_hash),
            )
            .await?;
        prepared.transaction.set_payer_signature(payer_signature)?;
        Ok(prepared.transaction)
    }

    fn validate_fee(&self, fee: Option<&ExecutionFeeCharge>) -> Result<()> {
        let Some(fee) = fee else {
            return Ok(());
        };
        if fee.token_symbol != self.execution_token_symbol {
            bail!(
                "native execution fees must be denominated in {}",
                self.execution_token_symbol
            );
        }
        let token: Address = fee
            .token_contract
            .parse()
            .context("invalid execution-fee token")?;
        let recipient: Address = fee
            .recipient_address
            .parse()
            .context("invalid execution-fee recipient")?;
        if token != self.execution_token || recipient != self.payer {
            bail!("execution fee terms do not match configured payer policy");
        }
        if U256::from_dec_str(&fee.amount_raw)
            .context("invalid execution-fee amount")?
            .is_zero()
        {
            bail!("execution fee must be positive");
        }
        Ok(())
    }

    async fn preflight_fee_transfer(
        &self,
        sender: Address,
        fee: &ExecutionFeeCharge,
    ) -> Result<()> {
        let call = fee_transfer_call(fee)?;
        let raw: String = self
            .rpc(
                "eth_call",
                json!([
                    {
                        "from": format!("{sender:?}"),
                        "to": format!("{:?}", call.to),
                        "data": format!("0x{}", hex::encode(call.data)),
                    },
                    "pending"
                ]),
            )
            .await
            .context("execution-fee transfer preflight failed")?;
        let bytes = hex::decode(raw.trim_start_matches("0x"))
            .context("execution-fee transfer preflight returned invalid hex")?;
        if bytes.len() != 32 || U256::from_big_endian(&bytes).is_zero() {
            bail!("execution-fee token transfer preflight did not return true");
        }
        Ok(())
    }

    fn validate_signing_policy(
        &self,
        prepared: &PreparedNativeTransaction,
        request_id: Uuid,
        expected_fee: Option<&ExecutionFeeCharge>,
    ) -> Result<()> {
        self.validate_fee(expected_fee)?;
        let transaction = &prepared.transaction;
        if transaction.chain_id != self.chain_id
            || prepared.sender == Address::zero()
            || prepared.sender == self.payer
            || transaction.from.is_some()
            || transaction.payer != Some(self.payer)
            || transaction.metadata.as_ref() != request_id.as_bytes()
            || transaction.nonce_key != U256::zero()
            || transaction.expiry != U256::zero()
            || transaction.gas_limit > U256::from(ESTIMATION_GAS_CAP)
            || transaction.gas_limit.is_zero()
            || transaction.max_fee_per_gas.is_zero()
            || transaction.max_fee_per_gas < transaction.max_priority_fee_per_gas
            || !transaction.sender_auth.is_empty()
            || !transaction.payer_auth.is_empty()
        {
            bail!("native transaction violates payer signing policy");
        }
        self.validate_sponsorship_cost(transaction)?;
        if transaction.account_changes.len() > 1 {
            bail!("native transaction contains too many account changes");
        }
        if transaction.account_changes.iter().any(|change| {
            !matches!(change, AccountChange::Delegation(target) if *target == self.default_account)
        }) {
            bail!("native transaction contains an unauthorized account change");
        }
        let expected_phase_count = if expected_fee.is_some() { 2 } else { 1 };
        if transaction.phases.len() != expected_phase_count
            || transaction.phases.iter().any(Vec::is_empty)
        {
            bail!("native transaction phase layout violates payer signing policy");
        }
        if let Some(fee) = expected_fee {
            let expected = fee_transfer_call(fee)?;
            if transaction.phases[0].as_slice() != [expected] {
                bail!("native transaction fee phase does not match the authorized quote");
            }
        }
        Ok(())
    }

    fn validate_sponsorship_cost(&self, transaction: &NativeTransaction) -> Result<()> {
        let maximum_cost = transaction
            .gas_limit
            .checked_mul(transaction.max_fee_per_gas)
            .ok_or_else(|| anyhow!("native sponsorship cost overflow"))?;
        if maximum_cost > self.max_payer_gas_cost_wei {
            bail!(
                "native transaction sponsorship exceeds configured maximum: {} > {} wei",
                maximum_cost,
                self.max_payer_gas_cost_wei
            );
        }
        Ok(())
    }

    pub async fn broadcast_and_wait(
        &self,
        transaction: &NativeTransaction,
    ) -> Result<NativeExecutionResult> {
        let raw = transaction.serialize()?;
        self.broadcast_raw_and_wait(&raw, transaction.phases.len())
            .await
    }

    /// Broadcasts an already-signed transaction. Persisting this payload before
    /// the call gives queue retries exactly-once signing and safe rebroadcast.
    pub async fn broadcast_raw_and_wait(
        &self,
        raw: &[u8],
        expected_phases: usize,
    ) -> Result<NativeExecutionResult> {
        let local_hash = H256::from(keccak256(raw));
        let send_result: Result<String> = self
            .rpc(
                "eth_sendRawTransaction",
                json!([format!("0x{}", hex::encode(raw))]),
            )
            .await;
        match send_result {
            Ok(remote_hash) => {
                let remote_hash =
                    H256::from_str(&remote_hash).context("RPC returned invalid tx hash")?;
                if remote_hash != local_hash {
                    bail!(
                        "RPC transaction hash mismatch: local {local_hash:?}, remote {remote_hash:?}"
                    );
                }
            }
            Err(error) => {
                let message = format!("{error:#}").to_lowercase();
                if !message.contains("already known")
                    && !message.contains("known transaction")
                    && !message.contains("nonce too low")
                {
                    return Err(error).context("native AA broadcast failed");
                }
            }
        }
        self.wait_for_receipt(local_hash, expected_phases).await
    }

    pub async fn wait_for_receipt(
        &self,
        tx_hash: H256,
        expected_phases: usize,
    ) -> Result<NativeExecutionResult> {
        let deadline = Instant::now() + self.receipt_timeout;
        loop {
            let receipt: Option<NativeReceipt> = self
                .rpc("eth_getTransactionReceipt", json!([format!("{tx_hash:?}")]))
                .await?;
            if let Some(receipt) = receipt {
                return validate_receipt(receipt, tx_hash, self.payer, expected_phases);
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for native AA receipt {tx_hash:?}");
            }
            sleep(self.receipt_poll_interval).await;
        }
    }

    async fn estimate_gas(&self, sender: Address, transaction: &NativeTransaction) -> Result<U256> {
        let account_changes = transaction
            .account_changes
            .iter()
            .map(|change| match change {
                AccountChange::Delegation(target) => {
                    json!({"type":"delegation","target":format!("{target:?}")})
                }
            })
            .collect::<Vec<_>>();
        let phases = transaction
            .phases
            .iter()
            .map(|phase| {
                phase
                    .iter()
                    .map(|call| {
                        json!({
                            "to": format!("{:?}", call.to),
                            "value": "0x0",
                            "data": format!("0x{}", hex::encode(&call.data)),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let request = json!({
            "type": "0x79",
            "sender": format!("{sender:?}"),
            "nonceKey": transaction.nonce_key.as_u64(),
            "nonceSequence": transaction.nonce_sequence.as_u64(),
            "expiry": transaction.expiry.as_u64(),
            "maxFeePerGas": u256_hex(transaction.max_fee_per_gas),
            "maxPriorityFeePerGas": u256_hex(transaction.max_priority_fee_per_gas),
            "gasLimit": ESTIMATION_GAS_CAP,
            "accountChanges": account_changes,
            "calls": phases,
            "metadata": format!("0x{}", hex::encode(&transaction.metadata)),
            "payer": transaction.payer.map(|address| format!("{address:?}")),
            // Nonzero fillers price high-entropy signatures accurately under
            // calldata byte-cost rules. The estimator validates shape, not sigs.
            "senderAuth": format!("0x{}", "ff".repeat(AUTH_SIGNATURE_LENGTH)),
            "payerAuth": format!(
                "0x{}{}",
                hex::encode(ecrecover_authenticator()),
                "ff".repeat(AUTH_SIGNATURE_LENGTH)
            ),
        });
        let raw: String = self.rpc("eth_estimateGas", json!([request])).await?;
        parse_u256_hex(&raw)
    }

    async fn get_code(&self, address: Address) -> Result<Bytes> {
        let raw: String = self
            .rpc("eth_getCode", json!([format!("{address:?}"), "latest"]))
            .await?;
        Ok(Bytes::from(
            hex::decode(raw.trim_start_matches("0x")).context("invalid eth_getCode")?,
        ))
    }

    async fn get_transaction_count(&self, address: Address) -> Result<U256> {
        let raw: String = self
            .rpc(
                "eth_getTransactionCount",
                json!([format!("{address:?}"), "pending"]),
            )
            .await?;
        parse_u256_hex(&raw)
    }

    async fn fee_caps(&self) -> Result<(U256, U256)> {
        let priority_raw: String = self.rpc("eth_maxPriorityFeePerGas", json!([])).await?;
        let priority = parse_u256_hex(&priority_raw)?;
        let block: LatestBlock = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let base_fee = block
            .base_fee_per_gas
            .as_deref()
            .map(parse_u256_hex)
            .transpose()?
            .ok_or_else(|| anyhow!("Base RPC latest block has no baseFeePerGas"))?;
        let max_fee = base_fee
            .checked_mul(U256::from(2))
            .and_then(|value| value.checked_add(priority))
            .ok_or_else(|| anyhow!("fee cap overflow"))?;
        Ok((priority, max_fee))
    }

    async fn rpc<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let response = self
            .http
            .post(&self.rpc_url)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .map_err(|_| anyhow!("{method} RPC request failed"))?;
        if !response.status().is_success() {
            bail!("{method} RPC returned HTTP {}", response.status());
        }
        let envelope: RpcResponse<T> = response.json().await?;
        if let Some(error) = envelope.error {
            bail!(
                "{method} RPC error {}: {}{}",
                error.code,
                error.message,
                error
                    .data
                    .map(|data| format!(", data={data}"))
                    .unwrap_or_default()
            );
        }
        envelope
            .result
            .ok_or_else(|| anyhow!("{method} RPC response omitted result"))
    }
}

#[derive(Deserialize)]
struct RpcResponse<T> {
    result: Option<T>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct LatestBlock {
    base_fee_per_gas: Option<String>,
}

pub fn execution_calls(
    target_contract: &str,
    calldata: &str,
    value: &str,
    batch_calls: Option<&[BatchCall]>,
) -> Result<Vec<BatchCall>> {
    if let Some(calls) = batch_calls {
        if calls.is_empty() {
            bail!("batch_calls cannot be empty");
        }
        return Ok(calls.to_vec());
    }
    Ok(vec![BatchCall {
        target_contract: target_contract.to_string(),
        calldata: calldata.to_string(),
        value: value.to_string(),
    }])
}

fn fee_transfer_call(fee: &ExecutionFeeCharge) -> Result<NativeCall> {
    let token: Address = fee
        .token_contract
        .parse()
        .context("invalid execution-fee token address")?;
    let recipient: Address = fee
        .recipient_address
        .parse()
        .context("invalid execution-fee recipient address")?;
    let amount = U256::from_dec_str(&fee.amount_raw).context("invalid execution-fee amount")?;
    if amount.is_zero() {
        bail!("execution fee cannot be zero");
    }
    let mut calldata = Vec::with_capacity(68);
    calldata.extend_from_slice(&keccak256("transfer(address,uint256)")[..4]);
    calldata.extend_from_slice(&encode(&[Token::Address(recipient), Token::Uint(amount)]));
    Ok(NativeCall {
        to: token,
        data: Bytes::from(calldata),
    })
}

fn encode_wire_phase(account: Address, calls: &[BatchCall]) -> Result<Vec<NativeCall>> {
    let parsed = calls
        .iter()
        .map(parse_batch_call)
        .collect::<Result<Vec<_>>>()?;
    if parsed.iter().all(|(_, value, _)| value.is_zero()) {
        return Ok(parsed
            .into_iter()
            .map(|(to, _, data)| NativeCall { to, data })
            .collect());
    }

    #[allow(deprecated)]
    let execute_batch = Function {
        name: "executeBatch".into(),
        inputs: vec![Param {
            name: "calls".into(),
            kind: ParamType::Array(Box::new(ParamType::Tuple(vec![
                ParamType::Address,
                ParamType::Uint(256),
                ParamType::Bytes,
            ]))),
            internal_type: None,
        }],
        outputs: vec![],
        constant: None,
        state_mutability: StateMutability::NonPayable,
    };
    let call_tokens = parsed
        .into_iter()
        .map(|(to, value, data)| {
            Token::Tuple(vec![
                Token::Address(to),
                Token::Uint(value),
                Token::Bytes(data.to_vec()),
            ])
        })
        .collect();
    let data = execute_batch
        .encode_input(&[Token::Array(call_tokens)])
        .context("failed to encode DefaultAccount.executeBatch")?;
    Ok(vec![NativeCall {
        to: account,
        data: Bytes::from(data),
    }])
}

fn parse_batch_call(call: &BatchCall) -> Result<(Address, U256, Bytes)> {
    let to = call
        .target_contract
        .parse()
        .context("invalid protocol target address")?;
    let value = if call.value.trim().is_empty() {
        U256::zero()
    } else {
        U256::from_dec_str(call.value.trim()).context("invalid protocol call value")?
    };
    let data =
        hex::decode(call.calldata.trim_start_matches("0x")).context("invalid protocol calldata")?;
    Ok((to, value, Bytes::from(data)))
}

fn validate_receipt(
    receipt: NativeReceipt,
    expected_hash: H256,
    expected_payer: Address,
    expected_phases: usize,
) -> Result<NativeExecutionResult> {
    let receipt_hash = H256::from_str(&receipt.transaction_hash)
        .context("receipt has invalid transaction hash")?;
    if receipt_hash != expected_hash {
        bail!("receipt transaction hash does not match submitted transaction");
    }
    if !is_success_status(receipt.status.as_deref()) {
        bail!("native AA transaction reverted");
    }
    let payer = receipt
        .payer
        .as_deref()
        .ok_or_else(|| anyhow!("native AA receipt omitted payer"))?
        .parse::<Address>()
        .context("native AA receipt contains invalid payer")?;
    if payer != expected_payer {
        bail!("native AA receipt payer does not match configured payer");
    }
    let statuses = receipt
        .phase_statuses
        .ok_or_else(|| anyhow!("native AA receipt omitted phaseStatuses"))?;
    if statuses.len() != expected_phases {
        bail!(
            "native AA receipt reported {} phases, expected {}",
            statuses.len(),
            expected_phases
        );
    }
    let phase_statuses = statuses
        .iter()
        .map(|status| match status.as_str() {
            "0x1" | "0x01" => Ok(true),
            "0x0" | "0x00" => Ok(false),
            _ => bail!("native AA receipt contains an invalid phase status"),
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(NativeExecutionResult {
        tx_hash: expected_hash,
        block_number: receipt
            .block_number
            .as_deref()
            .map(parse_u64_hex)
            .transpose()?,
        gas_used: receipt.gas_used.as_deref().map(parse_u64_hex).transpose()?,
        phase_statuses,
    })
}

fn normalized_signature_bytes(signature: Signature) -> Result<Vec<u8>> {
    let mut raw = signature.to_vec();
    if raw.len() != AUTH_SIGNATURE_LENGTH {
        bail!("ECDSA signature must be 65 bytes");
    }
    raw[64] = match raw[64] {
        0 | 1 => raw[64] + 27,
        27 | 28 => raw[64],
        other => bail!("invalid ECDSA recovery ID {other}"),
    };
    Ok(raw)
}

fn derived_idempotency_key(request_id: Uuid, role: &[u8], hash: H256) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(request_id.as_bytes());
    hasher.update(role);
    hasher.update(hash.as_bytes());
    let digest = hasher.finalize();
    let mut bytes: [u8; 16] = digest[..16].try_into().expect("fixed digest length");
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn append_u256(stream: &mut RlpStream, value: U256) {
    if value.is_zero() {
        stream.append_empty_data();
        return;
    }
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    let first = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
    let encoded = &bytes[first..];
    stream.append(&encoded);
}

fn ecrecover_authenticator() -> Address {
    Address::from_low_u64_be(1)
}

pub fn delegation_target(code: &[u8]) -> Result<Option<Address>> {
    if code.is_empty() {
        return Ok(None);
    }
    if code.len() != 23 || code[..3] != [0xef, 0x01, 0x00] {
        bail!("sender has unexpected contract code");
    }
    Ok(Some(Address::from_slice(&code[3..])))
}

fn append_address(stream: &mut RlpStream, address: Option<Address>) {
    match address {
        Some(address) => {
            stream.append(&address.as_bytes());
        }
        None => {
            stream.append_empty_data();
        }
    };
}

fn parse_u256_hex(raw: &str) -> Result<U256> {
    U256::from_str_radix(raw.trim_start_matches("0x"), 16)
        .with_context(|| format!("invalid hex quantity {raw}"))
}

fn parse_u64_hex(raw: &str) -> Result<u64> {
    let value = parse_u256_hex(raw)?;
    if value > U256::from(u64::MAX) {
        bail!("hex quantity exceeds u64");
    }
    Ok(value.as_u64())
}

fn u256_hex(value: U256) -> String {
    format!("{value:#x}")
}

fn is_success_status(status: Option<&str>) -> bool {
    matches!(status, Some("0x1" | "0x01"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};

    fn address(raw: &str) -> Address {
        raw.parse().unwrap()
    }

    fn sample_transaction() -> NativeTransaction {
        NativeTransaction {
            chain_id: 8453,
            from: None,
            nonce_key: U256::zero(),
            nonce_sequence: U256::from(3),
            expiry: U256::zero(),
            max_priority_fee_per_gas: U256::from(1_000_000_000u64),
            max_fee_per_gas: U256::from(2_000_000_000u64),
            gas_limit: U256::from(100_000),
            account_changes: vec![AccountChange::Delegation(address(
                crate::config::VIBENET_DEFAULT_ACCOUNT,
            ))],
            phases: vec![vec![NativeCall {
                to: address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            }]],
            metadata: Bytes::from_static(b"jusso"),
            payer: Some(address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")),
            sender_auth: Bytes::from(vec![0x11; 65]),
            payer_auth: {
                let mut auth = ecrecover_authenticator().as_bytes().to_vec();
                auth.extend_from_slice(&[0x22; 65]);
                Bytes::from(auth)
            },
        }
    }

    fn sample_client(maximum_cost: u64) -> NativeAaClient {
        NativeAaClient::new(NativeAaConfig {
            rpc_url: "http://localhost:8545".into(),
            chain_id: 8453,
            default_account: address(crate::config::VIBENET_DEFAULT_ACCOUNT),
            payer: address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            execution_token: address("0x81a6C7626Ce9EbC3f4Bf898CBaa5599e993652a0"),
            execution_token_symbol: "USDV".into(),
            receipt_timeout: Duration::from_secs(1),
            max_payer_gas_cost_wei: U256::from(maximum_cost),
        })
        .unwrap()
    }

    fn sample_fee() -> ExecutionFeeCharge {
        ExecutionFeeCharge {
            token_symbol: "USDV".into(),
            token_contract: "0x81a6C7626Ce9EbC3f4Bf898CBaa5599e993652a0".into(),
            amount_raw: "12500".into(),
            amount_usd: 0.0125,
            recipient_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".into(),
        }
    }

    fn policy_transaction(request_id: Uuid, fee: &ExecutionFeeCharge) -> PreparedNativeTransaction {
        let sender = address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        PreparedNativeTransaction {
            sender,
            transaction: NativeTransaction {
                chain_id: 8453,
                from: None,
                nonce_key: U256::zero(),
                nonce_sequence: U256::from(3),
                expiry: U256::zero(),
                max_priority_fee_per_gas: U256::from(10),
                max_fee_per_gas: U256::from(20),
                gas_limit: U256::from(100_000),
                account_changes: vec![AccountChange::Delegation(address(
                    crate::config::VIBENET_DEFAULT_ACCOUNT,
                ))],
                phases: vec![
                    vec![fee_transfer_call(fee).unwrap()],
                    vec![NativeCall {
                        to: address("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
                        data: Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
                    }],
                ],
                metadata: Bytes::from(request_id.as_bytes().to_vec()),
                payer: Some(address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")),
                sender_auth: Bytes::new(),
                payer_auth: Bytes::new(),
            },
        }
    }

    #[test]
    fn serialization_uses_typed_envelope_and_binds_every_body_field() {
        let transaction = sample_transaction();
        let raw = transaction.serialize().unwrap();
        assert_eq!(raw[0], AA_TRANSACTION_TYPE);
        assert_ne!(
            transaction.sender_signature_hash(),
            transaction
                .payer_signature_hash(address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"))
                .unwrap()
        );
        let mut changed = transaction.clone();
        changed.metadata = Bytes::from_static(b"other");
        assert_ne!(
            transaction.sender_signature_hash(),
            changed.sender_signature_hash()
        );
    }

    #[test]
    fn value_bearing_phase_routes_through_default_account() {
        let account = address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
        let calls = vec![BatchCall {
            target_contract: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
            calldata: "0xdeadbeef".into(),
            value: "1".into(),
        }];
        let wire = encode_wire_phase(account, &calls).unwrap();
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].to, account);
        assert_eq!(
            &wire[0].data[..4],
            &keccak256("executeBatch((address,uint256,bytes)[])")[..4]
        );
    }

    #[test]
    fn receipt_requires_exact_payer_and_phase_count() {
        let hash = H256::from_low_u64_be(7);
        let payer = address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let valid = NativeReceipt {
            transaction_hash: format!("{hash:?}"),
            status: Some("0x1".into()),
            block_number: Some("0xa".into()),
            gas_used: Some("0x5208".into()),
            payer: Some(format!("{payer:?}")),
            phase_statuses: Some(vec!["0x1".into(), "0x0".into()]),
            metadata: None,
        };
        let result = validate_receipt(valid.clone(), hash, payer, 2).unwrap();
        assert!(result.fee_phase_succeeded());
        assert!(!result.all_phases_succeeded());
        assert!(validate_receipt(valid, hash, payer, 1).is_err());
    }

    #[test]
    fn execution_fee_call_is_canonical_erc20_transfer() {
        let fee = sample_fee();
        let call = fee_transfer_call(&fee).unwrap();
        assert_eq!(
            &call.data[..4],
            &keccak256("transfer(address,uint256)")[..4]
        );
        assert_eq!(call.data.len(), 68);
    }

    #[test]
    fn payer_policy_binds_quote_and_rejects_mutated_fee_phase() {
        let client = sample_client(10_000_000);
        let request_id = Uuid::new_v4();
        let fee = sample_fee();
        let prepared = policy_transaction(request_id, &fee);
        client
            .validate_signing_policy(&prepared, request_id, Some(&fee))
            .unwrap();

        let mut changed = prepared;
        let mut changed_data = changed.transaction.phases[0][0].data.to_vec();
        changed_data[67] ^= 1;
        changed.transaction.phases[0][0].data = Bytes::from(changed_data);
        assert!(client
            .validate_signing_policy(&changed, request_id, Some(&fee))
            .is_err());
    }

    #[test]
    fn execution_fee_recipient_must_be_the_native_payer() {
        let client = sample_client(10_000_000);
        let request_id = Uuid::new_v4();
        let mut fee = sample_fee();
        let prepared = policy_transaction(request_id, &fee);

        fee.recipient_address = "0x90F79bf6EB2c4f870365E785982E1f101E93b906".into();
        assert!(client
            .validate_signing_policy(&prepared, request_id, Some(&fee))
            .is_err());
    }

    #[test]
    fn execution_fee_token_must_match_the_network_profile() {
        let client = sample_client(10_000_000);
        let mut fee = sample_fee();
        assert!(client.validate_fee(Some(&fee)).is_ok());

        fee.token_symbol = "USDC".into();
        assert!(client.validate_fee(Some(&fee)).is_err());

        fee = sample_fee();
        fee.token_contract = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into();
        assert!(client.validate_fee(Some(&fee)).is_err());
    }

    #[test]
    fn payer_policy_caps_native_spend_and_rejects_prefilled_auth() {
        let request_id = Uuid::new_v4();
        let fee = sample_fee();
        let mut prepared = policy_transaction(request_id, &fee);
        assert!(sample_client(1_999_999)
            .validate_signing_policy(&prepared, request_id, Some(&fee))
            .is_err());

        prepared.transaction.sender_auth = Bytes::from(vec![0; 65]);
        assert!(sample_client(10_000_000)
            .validate_signing_policy(&prepared, request_id, Some(&fee))
            .is_err());
    }

    #[test]
    fn serialization_rejects_noncanonical_payer_authenticator() {
        let mut transaction = sample_transaction();
        transaction.payer_auth = Bytes::from(vec![0x22; 85]);
        assert!(transaction.serialize().is_err());
    }

    #[test]
    fn receipt_rejects_unknown_phase_status_encoding() {
        let hash = H256::from_low_u64_be(7);
        let payer = address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
        let receipt = NativeReceipt {
            transaction_hash: format!("{hash:?}"),
            status: Some("0x1".into()),
            block_number: None,
            gas_used: None,
            payer: Some(format!("{payer:?}")),
            phase_statuses: Some(vec!["success".into()]),
            metadata: None,
        };
        assert!(validate_receipt(receipt, hash, payer, 1).is_err());
    }

    #[test]
    fn sender_code_must_be_a_canonical_delegation_designation() {
        let target = address(crate::config::VIBENET_DEFAULT_ACCOUNT);
        let mut code = vec![0xef, 0x01, 0x00];
        code.extend_from_slice(target.as_bytes());
        assert_eq!(delegation_target(&code).unwrap(), Some(target));
        assert_eq!(delegation_target(&[]).unwrap(), None);
        assert!(delegation_target(&[0x60, 0x00]).is_err());
    }

    #[test]
    fn debug_output_redacts_rpc_credentials() {
        let client = sample_client(10_000_000);
        let debug = format!("{client:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("localhost:8545"));
    }

    #[tokio::test]
    async fn mock_rpc_prepares_a_vibenet_fee_and_action_transaction() {
        async fn rpc(Json(request): Json<Value>) -> Json<Value> {
            let method = request["method"].as_str().unwrap_or_default();
            let result = match method {
                "eth_call" => Value::String(format!("0x{:064x}", 1)),
                "eth_getCode" => Value::String("0x".into()),
                "eth_getTransactionCount" => Value::String("0x0".into()),
                "eth_maxPriorityFeePerGas" => Value::String("0xf4240".into()),
                "eth_getBlockByNumber" => json!({"baseFeePerGas": "0x3b9aca00"}),
                "eth_estimateGas" => Value::String("0x186a0".into()),
                _ => panic!("unexpected RPC method {method}"),
            };
            Json(json!({"jsonrpc": "2.0", "id": request["id"], "result": result}))
        }

        let app = Router::new().route("/", post(rpc));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = NativeAaClient::new(NativeAaConfig {
            rpc_url: format!("http://{server_address}"),
            chain_id: crate::config::VIBENET_CHAIN_ID,
            default_account: address(crate::config::VIBENET_DEFAULT_ACCOUNT),
            payer: address("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
            execution_token: address("0x81a6C7626Ce9EbC3f4Bf898CBaa5599e993652a0"),
            execution_token_symbol: "USDV".into(),
            receipt_timeout: Duration::from_secs(1),
            max_payer_gas_cost_wei: U256::from_dec_str("100000000000000000").unwrap(),
        })
        .unwrap();
        let request_id = Uuid::new_v4();
        let prepared = client
            .prepare(
                address("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"),
                Some(&sample_fee()),
                &[BatchCall {
                    target_contract: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266".into(),
                    calldata: "0xd09de08a".into(),
                    value: "0".into(),
                }],
                request_id,
            )
            .await
            .unwrap();

        assert_eq!(
            prepared.transaction().chain_id,
            crate::config::VIBENET_CHAIN_ID
        );
        assert_eq!(prepared.transaction().account_changes.len(), 1);
        assert_eq!(prepared.transaction().phases.len(), 2);
        assert_eq!(
            prepared.transaction().metadata.as_ref(),
            request_id.as_bytes()
        );
        assert_eq!(prepared.transaction().gas_limit, U256::from(120_000u64));
        server.abort();
    }
}
