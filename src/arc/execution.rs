//! Sponsored ERC-4337 execution through Alchemy Wallet APIs on Arc.

use anyhow::{bail, Context, Result};
use ethers_core::{
    abi::{decode, encode, ParamType, Token},
    types::{Address, Signature, H256, U256},
    utils::{hash_message, keccak256},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{str::FromStr, time::Duration};

use super::ArcNetwork;
use crate::types::{BatchCall, ExecutionFeeCharge};

const USER_OPERATION_EVENT: &str =
    "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f";
const ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArcCall {
    pub to: Address,
    pub data: String,
    pub value: U256,
}

impl ArcCall {
    fn as_rpc_value(&self) -> Value {
        json!({
            "to": format!("{:?}", self.to),
            "data": self.data,
            "value": format!("{:#x}", self.value)
        })
    }
}

pub fn execution_calls(
    target: &str,
    calldata: &str,
    value: &str,
    batch: Option<&[BatchCall]>,
) -> Result<Vec<ArcCall>> {
    let calls = match batch {
        Some(calls) if !calls.is_empty() => calls.to_vec(),
        Some(_) => bail!("batch_calls cannot be empty"),
        None => vec![BatchCall {
            target_contract: target.to_owned(),
            calldata: calldata.to_owned(),
            value: value.to_owned(),
        }],
    };
    calls
        .into_iter()
        .map(|call| {
            let to = call
                .target_contract
                .parse::<Address>()
                .context("invalid call target")?;
            if to == Address::zero() {
                bail!("call target cannot be zero");
            }
            let bytes = hex_bytes(&call.calldata).context("invalid call calldata")?;
            let value = if call.value.is_empty() {
                U256::zero()
            } else {
                U256::from_dec_str(&call.value).context("invalid call value")?
            };
            Ok(ArcCall {
                to,
                data: format!("0x{}", hex::encode(bytes)),
                value,
            })
        })
        .collect()
}

pub fn fee_transfer_call(fee: &ExecutionFeeCharge) -> Result<ArcCall> {
    let to = fee
        .token_contract
        .parse::<Address>()
        .context("invalid fee token")?;
    let recipient = fee
        .recipient_address
        .parse::<Address>()
        .context("invalid fee recipient")?;
    let amount = U256::from_dec_str(&fee.amount_raw).context("invalid fee amount")?;
    if amount.is_zero() || recipient == Address::zero() {
        bail!("invalid execution fee transfer");
    }
    let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
    data.extend(encode(&[Token::Address(recipient), Token::Uint(amount)]));
    Ok(ArcCall {
        to,
        data: format!("0x{}", hex::encode(data)),
        value: U256::zero(),
    })
}

#[derive(Debug, Clone)]
pub struct PreparedUserOperation {
    pub data: Value,
    pub chain_id: u64,
    pub hash: H256,
    pub signing_digest: H256,
    pub gas_limit: U256,
    pub max_fee_per_gas: U256,
    pub sender: Address,
    pub calls: Vec<ArcCall>,
    pub sponsored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedUserOperation {
    pub payload: Value,
    pub hash: H256,
    pub sender: Address,
    pub calls: Vec<ArcCall>,
    pub chain_id: u64,
    pub sponsored: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcExecutionReceipt {
    pub tx_hash: H256,
    pub gas_used: Option<u64>,
    pub succeeded: bool,
}

#[derive(Debug)]
pub struct ArcOperationRejected(pub u64);

impl std::fmt::Display for ArcOperationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Arc Wallet API rejected the UserOperation with status {}",
            self.0
        )
    }
}

impl std::error::Error for ArcOperationRejected {}

#[derive(Clone)]
pub struct ArcExecutionClient {
    endpoint: reqwest::Url,
    http: reqwest::Client,
    pub network: ArcNetwork,
    policy_id: String,
    receipt_timeout: Duration,
    max_sponsored_gas_units: U256,
}

impl std::fmt::Debug for ArcExecutionClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArcExecutionClient")
            .field("endpoint", &"[REDACTED]")
            .field("network", &self.network)
            .field("policy_id", &"[REDACTED]")
            .finish()
    }
}

impl ArcExecutionClient {
    pub fn new(
        api_key: &str,
        network: ArcNetwork,
        policy_id: &str,
        receipt_timeout: Duration,
        max_sponsored_gas_units: u64,
    ) -> Result<Self> {
        if api_key.is_empty()
            || !api_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("ALCHEMY_API_KEY has invalid characters");
        }
        let endpoint = reqwest::Url::parse(&format!("https://api.g.alchemy.com/v2/{api_key}"))?;
        Self::with_endpoint(
            endpoint,
            network,
            policy_id,
            receipt_timeout,
            max_sponsored_gas_units,
        )
    }

    fn with_endpoint(
        endpoint: reqwest::Url,
        network: ArcNetwork,
        policy_id: &str,
        receipt_timeout: Duration,
        max_sponsored_gas_units: u64,
    ) -> Result<Self> {
        if endpoint.scheme() != "https"
            && !(endpoint.scheme() == "http"
                && matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1")))
        {
            bail!("Arc Wallet API must use HTTPS outside local tests");
        }
        if policy_id.trim().is_empty() || policy_id.len() > 128 {
            bail!("ALCHEMY_GAS_POLICY_ID is required");
        }
        if max_sponsored_gas_units == 0 {
            bail!("maximum sponsored gas units must be greater than zero");
        }
        Ok(Self {
            endpoint,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            network,
            policy_id: policy_id.to_owned(),
            receipt_timeout,
            max_sponsored_gas_units: U256::from(max_sponsored_gas_units),
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let response = self
            .http
            .post(self.endpoint.clone())
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Arc Wallet API transport failed"))?;
        if !response.status().is_success() {
            bail!("Arc Wallet API returned HTTP {}", response.status());
        }
        let body: Value = response
            .json()
            .await
            .context("Arc Wallet API returned invalid JSON")?;
        if body.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || body.get("id").and_then(Value::as_u64) != Some(1)
        {
            bail!("Arc Wallet API returned an invalid RPC envelope");
        }
        if let Some(error) = body.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            bail!("Arc Wallet API {method} failed ({code}): {message}");
        }
        body.get("result")
            .cloned()
            .context("Arc Wallet API omitted result")
    }

    pub async fn prepare(
        &self,
        sender: Address,
        calls: &[ArcCall],
    ) -> Result<PreparedUserOperation> {
        if sender == Address::zero() || calls.is_empty() || calls.len() > 17 {
            bail!("Arc UserOperation requires a nonzero sender and 1-17 calls");
        }
        let result = self
            .rpc(
                "wallet_prepareCalls",
                json!([{
                    "from": format!("{sender:?}"),
                    "chainId": format!("{:#x}", self.network.chain_id()),
                    "atomic": true,
                    "calls": calls.iter().map(ArcCall::as_rpc_value).collect::<Vec<_>>(),
                    "capabilities": {"paymasterService": {"policyId": self.policy_id}}
                }]),
            )
            .await?;
        parse_prepared(
            &result,
            self.network,
            sender,
            calls,
            self.max_sponsored_gas_units,
        )
    }

    pub fn attach_signature(
        &self,
        prepared: PreparedUserOperation,
        signature: Signature,
    ) -> Result<SignedUserOperation> {
        let signature = signature.to_vec();
        if signature.len() != 65 {
            bail!("Turnkey returned an invalid secp256k1 signature");
        }
        let payload = json!({
            "type": "user-operation-v070",
            "data": prepared.data,
            "chainId": format!("{:#x}", prepared.chain_id),
            "signature": {"type": "secp256k1", "data": format!("0x{}", hex::encode(signature))},
            "capabilities": {"paymasterService": {"policyId": self.policy_id}}
        });
        Ok(SignedUserOperation {
            payload,
            hash: prepared.hash,
            sender: prepared.sender,
            calls: prepared.calls,
            chain_id: prepared.chain_id,
            sponsored: prepared.sponsored,
        })
    }

    pub async fn send(&self, signed: &SignedUserOperation) -> Result<String> {
        self.verify_signed(signed)?;
        let result = self
            .rpc("wallet_sendPreparedCalls", json!([signed.payload]))
            .await?;
        let id = result
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| is_hex_bytes(id, 64))
            .context("Arc Wallet API omitted a valid call ID")?;
        if !id.eq_ignore_ascii_case(&self.expected_call_id(signed.hash)) {
            bail!("Arc Wallet API returned an unexpected call ID");
        }
        let actual_hash = result
            .pointer("/details/data/hash")
            .and_then(Value::as_str)
            .and_then(|hash| H256::from_str(hash).ok())
            .context("Arc Wallet API omitted the submitted UserOperation hash")?;
        if actual_hash != signed.hash {
            bail!("Arc Wallet API submitted a different UserOperation");
        }
        Ok(id.to_owned())
    }

    /// Wallet API call IDs encode the chain ID followed by the UserOperation hash.
    /// This lets a crash between send and DB persistence recover the same operation.
    pub fn expected_call_id(&self, hash: H256) -> String {
        format!("0x{:064x}{}", self.network.chain_id(), hex::encode(hash))
    }

    pub async fn status(
        &self,
        call_id: &str,
        expected_hash: H256,
    ) -> Result<Option<ArcExecutionReceipt>> {
        if !is_hex_bytes(call_id, 64) {
            bail!("invalid Arc Wallet API call ID");
        }
        let result = self.rpc("wallet_getCallsStatus", json!([call_id])).await?;
        if !result
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.eq_ignore_ascii_case(call_id))
            || result
                .get("chainId")
                .and_then(Value::as_str)
                .and_then(|id| parse_hex_u256(id).ok())
                != Some(U256::from(self.network.chain_id()))
        {
            bail!("Arc Wallet API returned status for a different operation");
        }
        let reported_hash = result
            .pointer("/details/data/hash")
            .and_then(Value::as_str)
            .map(H256::from_str)
            .transpose()
            .context("Arc Wallet API returned an invalid operation hash")?;
        if reported_hash.is_some_and(|hash| hash != expected_hash) {
            bail!("Arc Wallet API returned status for a different operation");
        }
        let status = result
            .get("status")
            .and_then(Value::as_u64)
            .context("Arc Wallet API status is missing")?;
        if (100..200).contains(&status) {
            if reported_hash.is_none()
                && !call_id.eq_ignore_ascii_case(&self.expected_call_id(expected_hash))
            {
                bail!("pending Arc operation has no verifiable hash");
            }
            return Ok(None);
        }
        if reported_hash != Some(expected_hash) {
            bail!("final Arc operation omitted the expected hash");
        }
        if status != 200 && status != 500 {
            return Err(ArcOperationRejected(status).into());
        }
        if status == 500 && result.get("receipts").is_none() {
            return Err(ArcOperationRejected(status).into());
        }
        if result.get("atomic").and_then(Value::as_bool) != Some(true) {
            bail!("Arc Wallet API did not confirm atomic execution");
        }
        let receipts = result
            .get("receipts")
            .and_then(Value::as_array)
            .filter(|receipts| receipts.len() == 1)
            .context("Arc Wallet API did not return one atomic receipt")?;
        let receipt = &receipts[0];
        let tx_hash = receipt
            .get("transactionHash")
            .and_then(Value::as_str)
            .context("Arc receipt has no transaction hash")?
            .parse::<H256>()?;
        let tx_succeeded = receipt
            .get("status")
            .and_then(Value::as_str)
            .and_then(|value| parse_hex_u256(value).ok())
            == Some(U256::one());
        let gas_used = receipt
            .get("gasUsed")
            .and_then(Value::as_str)
            .and_then(|value| parse_hex_u256(value).ok())
            .and_then(|value| (value <= U256::from(u64::MAX)).then(|| value.as_u64()));
        let event_success = user_operation_success(receipt, expected_hash)?;
        Ok(Some(ArcExecutionReceipt {
            tx_hash,
            gas_used,
            succeeded: status == 200 && tx_succeeded && event_success,
        }))
    }

    pub async fn wait(&self, call_id: &str, expected_hash: H256) -> Result<ArcExecutionReceipt> {
        let deadline = tokio::time::Instant::now() + self.receipt_timeout;
        loop {
            if let Some(receipt) = self.status(call_id, expected_hash).await? {
                return Ok(receipt);
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("Arc UserOperation receipt timed out; status remains recoverable by call ID");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    pub fn verify_signed(&self, signed: &SignedUserOperation) -> Result<()> {
        if !signed.sponsored
            || signed.chain_id != self.network.chain_id()
            || signed.payload.get("type").and_then(Value::as_str) != Some("user-operation-v070")
            || signed
                .payload
                .get("chainId")
                .and_then(Value::as_str)
                .and_then(|id| parse_hex_u256(id).ok())
                != Some(U256::from(signed.chain_id))
            || signed
                .payload
                .pointer("/capabilities/paymasterService/policyId")
                .and_then(Value::as_str)
                != Some(self.policy_id.as_str())
        {
            bail!("persisted Arc UserOperation has an invalid envelope");
        }
        let data = signed
            .payload
            .get("data")
            .context("persisted Arc UserOperation lacks data")?;
        if data
            .get("sender")
            .and_then(Value::as_str)
            .and_then(|raw| raw.parse::<Address>().ok())
            != Some(signed.sender)
            || decode_account_calls(
                data.get("callData")
                    .and_then(Value::as_str)
                    .context("missing callData")?,
            )? != signed.calls
            || user_operation_hash(data, signed.chain_id)? != signed.hash
            || !has_valid_optional_paymaster(data)
        {
            bail!("persisted Arc UserOperation does not match its authorized calls");
        }
        if user_operation_gas_limit(data)? > self.max_sponsored_gas_units {
            bail!("persisted Arc UserOperation exceeds the sponsored gas-unit limit");
        }
        if signed
            .payload
            .pointer("/signature/type")
            .and_then(Value::as_str)
            != Some("secp256k1")
            || !signed
                .payload
                .pointer("/signature/data")
                .and_then(Value::as_str)
                .is_some_and(|raw| is_hex_bytes(raw, 65))
        {
            bail!("persisted Arc UserOperation has an invalid signature");
        }
        Ok(())
    }
}

fn parse_prepared(
    result: &Value,
    network: ArcNetwork,
    sender: Address,
    expected: &[ArcCall],
    max_sponsored_gas_units: U256,
) -> Result<PreparedUserOperation> {
    if result.get("type").and_then(Value::as_str) != Some("user-operation-v070") {
        bail!("Alchemy did not return a dedicated ERC-4337 UserOperation");
    }
    let chain_id = result
        .get("chainId")
        .and_then(Value::as_str)
        .and_then(|raw| parse_hex_u256(raw).ok())
        .context("prepared UserOperation omitted chain ID")?;
    if chain_id != U256::from(network.chain_id()) {
        bail!("prepared UserOperation is on the wrong Arc chain");
    }
    let sponsored = result
        .pointer("/feePayment/sponsored")
        .and_then(Value::as_bool)
        == Some(true);
    let max_payment = result
        .pointer("/feePayment/maxAmount")
        .and_then(Value::as_str)
        .map(parse_hex_u256)
        .transpose()?
        .context("sponsored UserOperation omitted maximum payment")?;
    if !sponsored || !max_payment.is_zero() {
        bail!("Alchemy gas policy did not sponsor the UserOperation");
    }
    let data = result
        .get("data")
        .context("prepared UserOperation omitted data")?;
    if data
        .get("sender")
        .and_then(Value::as_str)
        .and_then(|raw| raw.parse::<Address>().ok())
        != Some(sender)
        || !has_valid_optional_paymaster(data)
    {
        bail!("prepared UserOperation has an unexpected sender or invalid paymaster");
    }
    let actual_calls = decode_account_calls(
        data.get("callData")
            .and_then(Value::as_str)
            .context("prepared UserOperation omitted callData")?,
    )?;
    if actual_calls != expected {
        bail!("prepared UserOperation callData differs from requested calls");
    }
    let detail_calls = result
        .pointer("/details/data/calls")
        .and_then(Value::as_array)
        .context("prepared UserOperation omitted call details")?;
    if detail_calls.len() != expected.len() {
        bail!("prepared UserOperation call details length differs");
    }
    for (detail, call) in detail_calls.iter().zip(expected) {
        if detail
            .get("to")
            .and_then(Value::as_str)
            .and_then(|raw| raw.parse::<Address>().ok())
            != Some(call.to)
            || !detail
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or("0x")
                .eq_ignore_ascii_case(&call.data)
            || detail
                .get("value")
                .and_then(Value::as_str)
                .and_then(|raw| parse_hex_u256(raw).ok())
                .unwrap_or_default()
                != call.value
        {
            bail!("prepared UserOperation call details differ from requested calls");
        }
    }
    let hash = user_operation_hash(data, network.chain_id())?;
    if result
        .pointer("/details/data/hash")
        .and_then(Value::as_str)
        .and_then(|raw| H256::from_str(raw).ok())
        != Some(hash)
        || result
            .pointer("/signatureRequest/type")
            .and_then(Value::as_str)
            != Some("personal_sign")
        || result
            .pointer("/signatureRequest/data/raw")
            .and_then(Value::as_str)
            .and_then(|raw| H256::from_str(raw).ok())
            != Some(hash)
    {
        bail!("prepared UserOperation signing hash does not match its fields");
    }
    // We independently derive the EIP-191 digest from the verified UserOp hash.
    // The provider's optional rawPayload is never sent to Turnkey for signing.
    let digest = hash_message(hash.as_bytes());
    let gas_limit = user_operation_gas_limit(data)?;
    let max_fee_per_gas = required_hex(data, "maxFeePerGas")?;
    if gas_limit.is_zero() {
        bail!("prepared UserOperation has no gas estimate");
    }
    if gas_limit > max_sponsored_gas_units {
        bail!("prepared UserOperation exceeds the sponsored gas-unit limit");
    }
    Ok(PreparedUserOperation {
        data: data.clone(),
        chain_id: network.chain_id(),
        hash,
        signing_digest: digest,
        gas_limit,
        max_fee_per_gas,
        sender,
        calls: expected.to_vec(),
        sponsored,
    })
}

fn user_operation_gas_limit(data: &Value) -> Result<U256> {
    [
        "callGasLimit",
        "verificationGasLimit",
        "preVerificationGas",
        "paymasterVerificationGasLimit",
        "paymasterPostOpGasLimit",
    ]
    .iter()
    .try_fold(U256::zero(), |total, key| -> Result<U256> {
        let amount = data
            .get(*key)
            .and_then(Value::as_str)
            .map(parse_hex_u256)
            .transpose()?
            .unwrap_or_default();
        total
            .checked_add(amount)
            .context("Arc gas estimate overflow")
    })
}

fn has_valid_optional_paymaster(data: &Value) -> bool {
    match data.get("paymaster") {
        None | Some(Value::Null) => true,
        Some(Value::String(raw)) => raw
            .parse::<Address>()
            .is_ok_and(|address| address != Address::zero()),
        Some(_) => false,
    }
}

fn user_operation_success(receipt: &Value, hash: H256) -> Result<bool> {
    let entry_point = ENTRY_POINT_V07.parse::<Address>()?;
    let logs = receipt
        .get("logs")
        .and_then(Value::as_array)
        .context("Arc receipt omitted logs")?;
    for log in logs {
        let topics = match log.get("topics").and_then(Value::as_array) {
            Some(topics) if topics.len() >= 2 => topics,
            _ => continue,
        };
        if log
            .get("address")
            .and_then(Value::as_str)
            .and_then(|address| address.parse::<Address>().ok())
            != Some(entry_point)
        {
            continue;
        }
        if topics[0]
            .as_str()
            .is_some_and(|topic| topic.eq_ignore_ascii_case(USER_OPERATION_EVENT))
            && topics[1]
                .as_str()
                .and_then(|topic| H256::from_str(topic).ok())
                == Some(hash)
        {
            let data = log
                .get("data")
                .and_then(Value::as_str)
                .context("UserOperationEvent omitted data")?;
            let bytes = hex::decode(
                data.strip_prefix("0x")
                    .context("invalid UserOperationEvent data")?,
            )?;
            if bytes.len() < 64 {
                bail!("UserOperationEvent data is too short");
            }
            return Ok(U256::from_big_endian(&bytes[32..64]) == U256::one());
        }
    }
    bail!("Arc receipt omitted the expected UserOperationEvent")
}

fn decode_account_calls(raw: &str) -> Result<Vec<ArcCall>> {
    let bytes = hex::decode(raw.strip_prefix("0x").context("callData is not hex")?)?;
    if bytes.len() < 4 {
        bail!("account callData is too short");
    }
    let payload = if bytes[..4] == [0x8d, 0xd7, 0x71, 0x2f] {
        bytes.get(4..).context("account callData is too short")?
    } else {
        &bytes[..]
    };
    if payload.len() < 4 {
        bail!("account callData has no execution selector");
    }
    let decoded = match &payload[..4] {
        [0xb6, 0x1d, 0x27, 0xf6] => {
            vec![decode(
                &[ParamType::Address, ParamType::Uint(256), ParamType::Bytes],
                &payload[4..],
            )?]
        }
        [0x34, 0xfc, 0xd5, 0xbe] => {
            let ty = ParamType::Array(Box::new(ParamType::Tuple(vec![
                ParamType::Address,
                ParamType::Uint(256),
                ParamType::Bytes,
            ])));
            decode(&[ty], &payload[4..])?
                .into_iter()
                .next()
                .context("empty batch payload")?
                .into_array()
                .context("invalid batch payload")?
                .into_iter()
                .map(|token| token.into_tuple().context("invalid batch call"))
                .collect::<Result<Vec<_>>>()?
        }
        _ => bail!("prepared smart account used an unexpected execution selector"),
    };
    let mut calls = Vec::with_capacity(decoded.len());
    for tokens in decoded {
        if tokens.len() != 3 {
            bail!("invalid account call tuple");
        }
        calls.push(ArcCall {
            to: tokens[0]
                .clone()
                .into_address()
                .context("invalid call target")?,
            value: tokens[1]
                .clone()
                .into_uint()
                .context("invalid call value")?,
            data: format!(
                "0x{}",
                hex::encode(
                    tokens[2]
                        .clone()
                        .into_bytes()
                        .context("invalid call data")?
                )
            ),
        });
    }
    Ok(calls)
}

fn user_operation_hash(data: &Value, chain_id: u64) -> Result<H256> {
    let sender = data
        .get("sender")
        .and_then(Value::as_str)
        .context("missing sender")?
        .parse::<Address>()?;
    let factory = data
        .get("factory")
        .and_then(Value::as_str)
        .map(str::parse::<Address>)
        .transpose()?;
    let mut init_code = Vec::new();
    if let Some(factory) = factory {
        init_code.extend_from_slice(factory.as_bytes());
        init_code.extend(hex_bytes(
            data.get("factoryData")
                .and_then(Value::as_str)
                .unwrap_or("0x"),
        )?);
    }
    let mut paymaster_data = Vec::new();
    if let Some(paymaster) = data.get("paymaster").and_then(Value::as_str) {
        paymaster_data.extend_from_slice(paymaster.parse::<Address>()?.as_bytes());
        paymaster_data.extend_from_slice(&u128_bytes(required_hex(
            data,
            "paymasterVerificationGasLimit",
        )?)?);
        paymaster_data
            .extend_from_slice(&u128_bytes(required_hex(data, "paymasterPostOpGasLimit")?)?);
        paymaster_data.extend(hex_bytes(
            data.get("paymasterData")
                .and_then(Value::as_str)
                .unwrap_or("0x"),
        )?);
    }
    let mut account_gas = u128_bytes(required_hex(data, "verificationGasLimit")?)?.to_vec();
    account_gas.extend_from_slice(&u128_bytes(required_hex(data, "callGasLimit")?)?);
    let mut gas_fees = u128_bytes(required_hex(data, "maxPriorityFeePerGas")?)?.to_vec();
    gas_fees.extend_from_slice(&u128_bytes(required_hex(data, "maxFeePerGas")?)?);
    let packed = encode(&[
        Token::Address(sender),
        Token::Uint(required_hex(data, "nonce")?),
        Token::FixedBytes(keccak256(init_code).to_vec()),
        Token::FixedBytes(
            keccak256(hex_bytes(
                data.get("callData")
                    .and_then(Value::as_str)
                    .context("missing callData")?,
            )?)
            .to_vec(),
        ),
        Token::FixedBytes(account_gas),
        Token::Uint(required_hex(data, "preVerificationGas")?),
        Token::FixedBytes(gas_fees),
        Token::FixedBytes(keccak256(paymaster_data).to_vec()),
    ]);
    let entry_point = ENTRY_POINT_V07.parse::<Address>()?;
    Ok(H256::from(keccak256(encode(&[
        Token::FixedBytes(keccak256(packed).to_vec()),
        Token::Address(entry_point),
        Token::Uint(U256::from(chain_id)),
    ]))))
}

fn required_hex(data: &Value, key: &str) -> Result<U256> {
    parse_hex_u256(
        data.get(key)
            .and_then(Value::as_str)
            .with_context(|| format!("UserOperation omitted {key}"))?,
    )
}

fn parse_hex_u256(raw: &str) -> Result<U256> {
    U256::from_str_radix(
        raw.strip_prefix("0x")
            .context("expected 0x-prefixed integer")?,
        16,
    )
    .context("invalid hexadecimal integer")
}

fn hex_bytes(raw: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(
        raw.strip_prefix("0x")
            .context("expected 0x-prefixed bytes")?,
    )?)
}

fn u128_bytes(value: U256) -> Result<[u8; 16]> {
    if value > U256::from(u128::MAX) {
        bail!("UserOperation gas field exceeds uint128");
    }
    let mut full = [0u8; 32];
    value.to_big_endian(&mut full);
    Ok(full[16..].try_into().expect("fixed byte width"))
}

fn is_hex_bytes(raw: &str, bytes: usize) -> bool {
    raw.len() == 2 + bytes * 2
        && raw.starts_with("0x")
        && raw.as_bytes()[2..].iter().all(u8::is_ascii_hexdigit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoded_batch_calls_are_exact() {
        let target = Address::from_low_u64_be(42);
        let payload = encode(&[Token::Array(vec![Token::Tuple(vec![
            Token::Address(target),
            Token::Uint(U256::from(7)),
            Token::Bytes(vec![1, 2, 3]),
        ])])]);
        let raw = format!("0x34fcd5be{}", hex::encode(payload));
        assert_eq!(
            decode_account_calls(&raw).unwrap(),
            vec![ArcCall {
                to: target,
                value: U256::from(7),
                data: "0x010203".into(),
            }]
        );
        assert!(decode_account_calls("0xdeadbeef").is_err());
    }

    #[test]
    fn status_requires_matching_user_operation_event() {
        let hash = H256::from_low_u64_be(1);
        let receipt = json!({"logs": []});
        assert!(user_operation_success(&receipt, hash).is_err());
        let data = format!(
            "0x{}",
            hex::encode(encode(&[
                Token::Uint(U256::zero()),
                Token::Bool(true),
                Token::Uint(U256::from(100)),
                Token::Uint(U256::from(200)),
            ]))
        );
        let receipt = json!({"logs": [{"address": ENTRY_POINT_V07, "topics": [USER_OPERATION_EVENT, format!("{hash:?}")], "data": data}]});
        assert!(user_operation_success(&receipt, hash).unwrap());
        let spoofed = json!({"logs": [{"address": format!("{:?}", Address::from_low_u64_be(9)), "topics": [USER_OPERATION_EVENT, format!("{hash:?}")], "data": receipt["logs"][0]["data"]}]});
        assert!(user_operation_success(&spoofed, hash).is_err());
        let failed_data = format!(
            "0x{}",
            hex::encode(encode(&[
                Token::Uint(U256::zero()),
                Token::Bool(false),
                Token::Uint(U256::from(100)),
                Token::Uint(U256::from(200)),
            ]))
        );
        let failed = json!({"logs": [{"address": ENTRY_POINT_V07, "topics": [USER_OPERATION_EVENT, format!("{hash:?}")], "data": failed_data}]});
        assert!(!user_operation_success(&failed, hash).unwrap());
    }

    #[test]
    fn recovery_call_id_contains_chain_and_operation_hash() {
        let client = ArcExecutionClient::new(
            "test-key",
            ArcNetwork::Testnet,
            "policy-id",
            Duration::from_secs(1),
            2_000_000,
        )
        .unwrap();
        let hash = H256::from_low_u64_be(42);
        let id = client.expected_call_id(hash);
        assert_eq!(id.len(), 130);
        assert!(
            id.starts_with("0x00000000000000000000000000000000000000000000000000000000004cef52")
        );
        assert!(id.ends_with(&hex::encode(hash)));
    }

    #[test]
    fn personal_sign_digest_uses_raw_hash_bytes() {
        let operation_hash = "0xc69e468aa6fafb5c7298c02841e76f976b433018266af39a5807bc29ea9ad392"
            .parse::<H256>()
            .unwrap();
        assert_ne!(
            hash_message(operation_hash.as_bytes()),
            hash_message(format!("{operation_hash:?}").as_bytes())
        );
    }

    #[test]
    fn prepared_operation_rejects_changed_calls_and_unsigned_sponsorship() {
        let sender = Address::from_low_u64_be(11);
        let call = ArcCall {
            to: Address::from_low_u64_be(12),
            value: U256::zero(),
            data: "0x12345678".into(),
        };
        let call_data = format!(
            "0x34fcd5be{}",
            hex::encode(encode(&[Token::Array(vec![Token::Tuple(vec![
                Token::Address(call.to),
                Token::Uint(call.value),
                Token::Bytes(hex_bytes(&call.data).unwrap()),
            ])])]))
        );
        let data = json!({
            "sender": format!("{sender:?}"), "nonce": "0x0", "callData": call_data,
            "callGasLimit": "0x10000", "verificationGasLimit": "0x10000",
            "preVerificationGas": "0x10000", "maxFeePerGas": "0x4a817c800",
            "maxPriorityFeePerGas": "0x4a817c800",
            "paymaster": format!("{:?}", Address::from_low_u64_be(13)),
            "paymasterData": "0x", "paymasterVerificationGasLimit": "0x10000",
            "paymasterPostOpGasLimit": "0x0"
        });
        let hash = user_operation_hash(&data, ArcNetwork::Testnet.chain_id()).unwrap();
        let mut result = json!({
            "type": "user-operation-v070", "chainId": format!("{:#x}", ArcNetwork::Testnet.chain_id()),
            "data": data, "feePayment": {"sponsored": true, "maxAmount": "0x0"},
            "details": {"data": {"hash": format!("{hash:?}"), "calls": [call.as_rpc_value()]}},
            "signatureRequest": {"type": "personal_sign", "data": {"raw": format!("{hash:?}")},
                "rawPayload": format!("{:?}", hash_message(hash.as_bytes()))}
        });
        let gas_cap = U256::from(2_000_000u64);
        assert!(parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            gas_cap
        )
        .is_ok());
        assert!(parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            U256::one()
        )
        .is_err());
        let client = ArcExecutionClient::with_endpoint(
            "http://127.0.0.1:1".parse().unwrap(),
            ArcNetwork::Testnet,
            "policy-1",
            Duration::from_secs(1),
            2_000_000,
        )
        .unwrap();
        let prepared = parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            gas_cap,
        )
        .unwrap();
        let mut signed = client
            .attach_signature(
                prepared,
                Signature {
                    r: U256::one(),
                    s: U256::from(2u64),
                    v: 27,
                },
            )
            .unwrap();
        assert!(client.verify_signed(&signed).is_ok());
        signed.payload["capabilities"]["paymasterService"]["policyId"] = json!("different-policy");
        assert!(client.verify_signed(&signed).is_err());
        result["feePayment"]["sponsored"] = json!(false);
        assert!(parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            gas_cap
        )
        .is_err());
        result["feePayment"]["sponsored"] = json!(true);
        result["feePayment"]["maxAmount"] = json!("0x1");
        assert!(parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            gas_cap
        )
        .is_err());
        result["feePayment"]["maxAmount"] = json!("0x0");
        result["data"].as_object_mut().unwrap().remove("paymaster");
        result["data"]
            .as_object_mut()
            .unwrap()
            .remove("paymasterData");
        result["data"]
            .as_object_mut()
            .unwrap()
            .remove("paymasterVerificationGasLimit");
        result["data"]
            .as_object_mut()
            .unwrap()
            .remove("paymasterPostOpGasLimit");
        let hash = user_operation_hash(&result["data"], ArcNetwork::Testnet.chain_id()).unwrap();
        result["details"]["data"]["hash"] = json!(format!("{hash:?}"));
        result["signatureRequest"]["data"]["raw"] = json!(format!("{hash:?}"));
        assert!(parse_prepared(
            &result,
            ArcNetwork::Testnet,
            sender,
            &[call.clone()],
            gas_cap
        )
        .is_ok());
        result["data"]["callData"] = json!("0x34fcd5be");
        assert!(parse_prepared(&result, ArcNetwork::Testnet, sender, &[call], gas_cap).is_err());
    }

    #[tokio::test]
    async fn gas_manager_policy_rejection_fails_closed() {
        use axum::{routing::post, Json, Router};

        let app = Router::new().route(
            "/",
            post(|| async {
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "error": {"code": -32001, "message": "policy rejected sponsorship"}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = ArcExecutionClient::with_endpoint(
            endpoint,
            ArcNetwork::Testnet,
            "policy-1",
            Duration::from_secs(1),
            2_000_000,
        )
        .unwrap();
        let error = client
            .prepare(
                Address::from_low_u64_be(1),
                &[ArcCall {
                    to: Address::from_low_u64_be(2),
                    data: "0x12345678".into(),
                    value: U256::zero(),
                }],
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("policy rejected sponsorship"));
        server.abort();
    }
}
