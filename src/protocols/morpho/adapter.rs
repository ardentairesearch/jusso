//! Morpho Blue calldata adapter.

use anyhow::{anyhow, Context, Result};
use ethers::abi::{self, ParamType, Token};
use ethers::types::{Address, H256, U256};
use ethers::utils::{id, parse_units};
use serde::{Deserialize, Serialize};

use super::super::serde_utils::deserialize_optional_decimal;
use crate::types::{BatchCall, ExecutionRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MorphoActionRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Market ID on the operator-pinned Arc Morpho deployment.
    pub market_id: String,
    /// Human-readable token amount. `max` is supported where documented.
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub amount: Option<String>,
    /// Integer amount in the token's native units. `max` is supported where documented.
    #[serde(default)]
    pub amount_raw: Option<String>,
    /// Minimum projected health factor for borrow and collateral withdrawal. Defaults to 1.05.
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub min_health_factor: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MorphoMarketQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    pub market_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MorphoPositionQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub market_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MorphoMarketsQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    #[serde(default)]
    pub loan_token: Option<String>,
    #[serde(default)]
    pub collateral_token: Option<String>,
    #[serde(default)]
    pub max_lltv_raw: Option<String>,
    #[serde(default)]
    pub min_liquidity_raw: Option<String>,
    #[serde(default = "default_require_available_oracle")]
    pub require_available_oracle: bool,
    #[serde(default = "default_markets_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MorphoAction {
    Supply,
    Withdraw,
    SupplyCollateral,
    WithdrawCollateral,
    Borrow,
    Repay,
}

impl MorphoAction {
    pub fn slug(self) -> &'static str {
        match self {
            Self::Supply => "supply",
            Self::Withdraw => "withdraw",
            Self::SupplyCollateral => "supply-collateral",
            Self::WithdrawCollateral => "withdraw-collateral",
            Self::Borrow => "borrow",
            Self::Repay => "repay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MorphoMarketParams {
    pub loan_token: Address,
    pub collateral_token: Address,
    pub oracle: Address,
    pub irm: Address,
    pub lltv: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MorphoMarketState {
    pub total_supply_assets: U256,
    pub total_supply_shares: U256,
    pub total_borrow_assets: U256,
    pub total_borrow_shares: U256,
    pub last_update: U256,
    pub fee: U256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MorphoPosition {
    pub supply_shares: U256,
    pub borrow_shares: U256,
    pub collateral: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedAmount {
    Assets(U256),
    Shares(U256),
}

fn default_chain() -> String {
    "arc-testnet".to_string()
}

fn default_require_available_oracle() -> bool {
    true
}

fn default_markets_limit() -> usize {
    20
}

pub fn validate_action_request(req: &MorphoActionRequest) -> Result<()> {
    validate_agent_and_chain(&req.agent_id, &req.chain)?;
    parse_market_id(&req.market_id)?;
    validate_amount_fields(req.amount.as_deref(), req.amount_raw.as_deref())?;
    Ok(())
}

pub fn validate_market_query(query: &MorphoMarketQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    parse_market_id(&query.market_id)?;
    Ok(())
}

pub fn validate_position_query(query: &MorphoPositionQuery) -> Result<()> {
    validate_agent_and_chain(&query.agent_id, &query.chain)?;
    parse_market_id(&query.market_id)?;
    Ok(())
}

pub fn validate_markets_query(query: &MorphoMarketsQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    if query.loan_token.is_none() && query.collateral_token.is_none() {
        return Err(anyhow!(
            "loan_token or collateral_token is required for Morpho market discovery"
        ));
    }
    for (field, value) in [
        ("loan_token", query.loan_token.as_deref()),
        ("collateral_token", query.collateral_token.as_deref()),
    ] {
        if let Some(value) = value {
            let address = value
                .trim()
                .parse::<Address>()
                .with_context(|| format!("{field} must be a valid address"))?;
            if address == Address::zero() {
                return Err(anyhow!("{field} must not be the zero address"));
            }
        }
    }
    for (field, value) in [
        ("max_lltv_raw", query.max_lltv_raw.as_deref()),
        ("min_liquidity_raw", query.min_liquidity_raw.as_deref()),
    ] {
        if let Some(value) = value {
            U256::from_dec_str(value.trim())
                .with_context(|| format!("{field} must be an unsigned base-10 integer"))?;
        }
    }
    if query.limit == 0 || query.limit > 50 {
        return Err(anyhow!("limit must be between 1 and 50"));
    }
    Ok(())
}

pub fn parse_market_id(raw: &str) -> Result<H256> {
    let raw = raw.trim();
    if !raw.starts_with("0x") || raw.len() != 66 {
        return Err(anyhow!("market_id must be a 32-byte 0x-prefixed hex value"));
    }
    raw.parse::<H256>()
        .with_context(|| "market_id must be a 32-byte 0x-prefixed hex value")
}

pub fn derive_market_id(params: &MorphoMarketParams) -> H256 {
    H256::from(ethers::utils::keccak256(abi::encode(&market_param_tokens(
        params,
    ))))
}

pub fn is_amount_max(req: &MorphoActionRequest) -> bool {
    req.amount
        .as_deref()
        .map(|value| value.trim().eq_ignore_ascii_case("max"))
        .unwrap_or(false)
        || req
            .amount_raw
            .as_deref()
            .map(|value| value.trim().eq_ignore_ascii_case("max"))
            .unwrap_or(false)
}

pub fn parse_request_amount(req: &MorphoActionRequest, decimals: u8) -> Result<U256> {
    validate_amount_fields(req.amount.as_deref(), req.amount_raw.as_deref())?;

    if is_amount_max(req) {
        return Err(anyhow!(
            "amount=max must be resolved against the wallet position before compiling"
        ));
    }

    let amount = if let Some(raw) = req.amount_raw.as_deref() {
        U256::from_dec_str(raw.trim()).context("amount_raw must be an unsigned base-10 integer")?
    } else {
        let raw = req
            .amount
            .as_deref()
            .ok_or_else(|| anyhow!("amount or amount_raw is required"))?;
        parse_units(raw.trim(), decimals as usize)
            .context("amount must be a non-negative decimal number")?
            .into()
    };

    if amount.is_zero() {
        return Err(anyhow!("amount must be greater than zero"));
    }
    Ok(amount)
}

pub fn compile_action(
    req: &MorphoActionRequest,
    action: MorphoAction,
    morpho: Address,
    params: &MorphoMarketParams,
    wallet: Address,
    amount: ResolvedAmount,
) -> Result<ExecutionRequest> {
    validate_action_request(req)?;
    let market_tokens = market_param_tokens(params);

    let (target_contract, calldata, batch_calls) = match action {
        MorphoAction::Supply => {
            let assets = require_assets(amount, action)?;
            (
                String::new(),
                String::new(),
                Some(approval_batch(
                    params.loan_token,
                    morpho,
                    assets,
                    encode_morpho_call(
                        "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                        vec![
                            Token::Tuple(market_tokens),
                            Token::Uint(assets),
                            Token::Uint(U256::zero()),
                            Token::Address(wallet),
                            Token::Bytes(Vec::new()),
                        ],
                    ),
                )),
            )
        }
        MorphoAction::Withdraw => {
            let (assets, shares) = split_amount(amount);
            (
                format!("{morpho:?}"),
                encode_morpho_call(
                    "withdraw((address,address,address,address,uint256),uint256,uint256,address,address)",
                    vec![
                        Token::Tuple(market_tokens),
                        Token::Uint(assets),
                        Token::Uint(shares),
                        Token::Address(wallet),
                        Token::Address(wallet),
                    ],
                ),
                None,
            )
        }
        MorphoAction::SupplyCollateral => {
            let assets = require_assets(amount, action)?;
            (
                String::new(),
                String::new(),
                Some(approval_batch(
                    params.collateral_token,
                    morpho,
                    assets,
                    encode_morpho_call(
                        "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
                        vec![
                            Token::Tuple(market_tokens),
                            Token::Uint(assets),
                            Token::Address(wallet),
                            Token::Bytes(Vec::new()),
                        ],
                    ),
                )),
            )
        }
        MorphoAction::WithdrawCollateral => {
            let assets = require_assets(amount, action)?;
            (
                format!("{morpho:?}"),
                encode_morpho_call(
                    "withdrawCollateral((address,address,address,address,uint256),uint256,address,address)",
                    vec![
                        Token::Tuple(market_tokens),
                        Token::Uint(assets),
                        Token::Address(wallet),
                        Token::Address(wallet),
                    ],
                ),
                None,
            )
        }
        MorphoAction::Borrow => {
            let assets = require_assets(amount, action)?;
            (
                format!("{morpho:?}"),
                encode_morpho_call(
                    "borrow((address,address,address,address,uint256),uint256,uint256,address,address)",
                    vec![
                        Token::Tuple(market_tokens),
                        Token::Uint(assets),
                        Token::Uint(U256::zero()),
                        Token::Address(wallet),
                        Token::Address(wallet),
                    ],
                ),
                None,
            )
        }
        MorphoAction::Repay => {
            let (assets, shares) = split_amount(amount);
            let approval = if shares.is_zero() { assets } else { U256::MAX };
            (
                String::new(),
                String::new(),
                Some(approval_batch(
                    params.loan_token,
                    morpho,
                    approval,
                    encode_morpho_call(
                        "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                        vec![
                            Token::Tuple(market_tokens),
                            Token::Uint(assets),
                            Token::Uint(shares),
                            Token::Address(wallet),
                            Token::Bytes(Vec::new()),
                        ],
                    ),
                )),
            )
        }
    };

    let market_suffix = req
        .market_id
        .trim_start_matches("0x")
        .get(..8)
        .unwrap_or("market");

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract,
        calldata,
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "morpho-blue-arc-{}-{}",
                action.slug(),
                market_suffix
            ))
        }),
        batch_calls,
        callback_url: req.callback_url.clone(),
    })
}

pub fn encode_id_to_market_params(market_id: H256) -> String {
    encode_call(
        "idToMarketParams(bytes32)",
        vec![Token::FixedBytes(market_id.as_bytes().to_vec())],
    )
}

pub fn encode_market(market_id: H256) -> String {
    encode_call(
        "market(bytes32)",
        vec![Token::FixedBytes(market_id.as_bytes().to_vec())],
    )
}

pub fn encode_position(market_id: H256, wallet: Address) -> String {
    encode_call(
        "position(bytes32,address)",
        vec![
            Token::FixedBytes(market_id.as_bytes().to_vec()),
            Token::Address(wallet),
        ],
    )
}

pub fn encode_balance_of(wallet: Address) -> String {
    encode_call("balanceOf(address)", vec![Token::Address(wallet)])
}

pub fn encode_decimals() -> String {
    encode_call("decimals()", Vec::new())
}

pub fn encode_symbol() -> String {
    encode_call("symbol()", Vec::new())
}

pub fn encode_oracle_price() -> String {
    encode_call("price()", Vec::new())
}

pub fn encode_borrow_rate_view(params: &MorphoMarketParams, state: &MorphoMarketState) -> String {
    encode_call(
        "borrowRateView((address,address,address,address,uint256),(uint128,uint128,uint128,uint128,uint128,uint128))",
        vec![
            Token::Tuple(market_param_tokens(params)),
            Token::Tuple(vec![
                Token::Uint(state.total_supply_assets),
                Token::Uint(state.total_supply_shares),
                Token::Uint(state.total_borrow_assets),
                Token::Uint(state.total_borrow_shares),
                Token::Uint(state.last_update),
                Token::Uint(state.fee),
            ]),
        ],
    )
}

pub fn decode_market_params(raw: &[u8]) -> Result<MorphoMarketParams> {
    let tokens = abi::decode(
        &[
            ParamType::Address,
            ParamType::Address,
            ParamType::Address,
            ParamType::Address,
            ParamType::Uint(256),
        ],
        raw,
    )
    .context("failed to decode Morpho market parameters")?;

    let params = MorphoMarketParams {
        loan_token: token_address(&tokens[0])?,
        collateral_token: token_address(&tokens[1])?,
        oracle: token_address(&tokens[2])?,
        irm: token_address(&tokens[3])?,
        lltv: token_uint(&tokens[4])?,
    };
    if params.loan_token == Address::zero() {
        return Err(anyhow!(
            "Morpho market does not exist or has invalid parameters"
        ));
    }
    Ok(params)
}

pub fn decode_market_state(raw: &[u8]) -> Result<MorphoMarketState> {
    let tokens = abi::decode(&vec![ParamType::Uint(256); 6], raw)
        .context("failed to decode Morpho market state")?;
    let state = MorphoMarketState {
        total_supply_assets: token_uint(&tokens[0])?,
        total_supply_shares: token_uint(&tokens[1])?,
        total_borrow_assets: token_uint(&tokens[2])?,
        total_borrow_shares: token_uint(&tokens[3])?,
        last_update: token_uint(&tokens[4])?,
        fee: token_uint(&tokens[5])?,
    };
    if state.last_update.is_zero() {
        return Err(anyhow!("Morpho market has not been created"));
    }
    Ok(state)
}

pub fn decode_position(raw: &[u8]) -> Result<MorphoPosition> {
    let tokens = abi::decode(&vec![ParamType::Uint(256); 3], raw)
        .context("failed to decode Morpho position")?;
    Ok(MorphoPosition {
        supply_shares: token_uint(&tokens[0])?,
        borrow_shares: token_uint(&tokens[1])?,
        collateral: token_uint(&tokens[2])?,
    })
}

pub fn decode_u256(raw: &[u8]) -> Result<U256> {
    let tokens = abi::decode(&[ParamType::Uint(256)], raw).context("failed to decode uint256")?;
    token_uint(&tokens[0])
}

pub fn decode_u8(raw: &[u8]) -> Result<u8> {
    let value = decode_u256(raw)?;
    if value > U256::from(u8::MAX) {
        return Err(anyhow!("decoded token decimals exceed u8"));
    }
    Ok(value.as_u32() as u8)
}

pub fn decode_string(raw: &[u8]) -> Result<String> {
    if let Ok(tokens) = abi::decode(&[ParamType::String], raw) {
        return tokens[0]
            .clone()
            .into_string()
            .ok_or_else(|| anyhow!("failed to decode token symbol"));
    }
    if raw.len() == 32 {
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        return String::from_utf8(raw[..end].to_vec()).context("token symbol is not UTF-8");
    }
    Err(anyhow!("failed to decode token symbol"))
}

fn validate_agent_and_chain(agent_id: &str, chain: &str) -> Result<()> {
    if agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    if agent_id.len() > 256 {
        return Err(anyhow!("agent_id too long (max 256 characters)"));
    }
    validate_chain(chain)
}

fn validate_chain(chain: &str) -> Result<()> {
    if !chain.trim().eq_ignore_ascii_case("arc-testnet") {
        return Err(anyhow!(
            "Morpho Blue integration is enabled on Arc testnet only; use chain=arc-testnet"
        ));
    }
    Ok(())
}

fn validate_amount_fields(amount: Option<&str>, amount_raw: Option<&str>) -> Result<()> {
    match (amount, amount_raw) {
        (Some(_), Some(_)) => Err(anyhow!("provide exactly one of amount or amount_raw")),
        (None, None) => Err(anyhow!("amount or amount_raw is required")),
        (Some(value), None) | (None, Some(value)) if value.trim().is_empty() => {
            Err(anyhow!("amount must not be empty"))
        }
        _ => Ok(()),
    }
}

fn require_assets(amount: ResolvedAmount, action: MorphoAction) -> Result<U256> {
    match amount {
        ResolvedAmount::Assets(value) if !value.is_zero() => Ok(value),
        ResolvedAmount::Assets(_) => Err(anyhow!("amount must be greater than zero")),
        ResolvedAmount::Shares(_) => Err(anyhow!(
            "{} does not support a share-denominated amount",
            action.slug()
        )),
    }
}

fn split_amount(amount: ResolvedAmount) -> (U256, U256) {
    match amount {
        ResolvedAmount::Assets(value) => (value, U256::zero()),
        ResolvedAmount::Shares(value) => (U256::zero(), value),
    }
}

fn approval_batch(
    token: Address,
    spender: Address,
    allowance: U256,
    protocol_calldata: String,
) -> Vec<BatchCall> {
    vec![
        BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_call(
                "approve(address,uint256)",
                vec![Token::Address(spender), Token::Uint(U256::zero())],
            ),
            value: "0".to_string(),
        },
        BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_call(
                "approve(address,uint256)",
                vec![Token::Address(spender), Token::Uint(allowance)],
            ),
            value: "0".to_string(),
        },
        BatchCall {
            target_contract: format!("{spender:?}"),
            calldata: protocol_calldata,
            value: "0".to_string(),
        },
        BatchCall {
            target_contract: format!("{token:?}"),
            calldata: encode_call(
                "approve(address,uint256)",
                vec![Token::Address(spender), Token::Uint(U256::zero())],
            ),
            value: "0".to_string(),
        },
    ]
}

fn market_param_tokens(params: &MorphoMarketParams) -> Vec<Token> {
    vec![
        Token::Address(params.loan_token),
        Token::Address(params.collateral_token),
        Token::Address(params.oracle),
        Token::Address(params.irm),
        Token::Uint(params.lltv),
    ]
}

fn encode_morpho_call(signature: &str, tokens: Vec<Token>) -> String {
    encode_call(signature, tokens)
}

fn encode_call(signature: &str, tokens: Vec<Token>) -> String {
    let selector = id(signature);
    let mut out = selector[..4].to_vec();
    out.extend(abi::encode(&tokens));
    format!("0x{}", hex::encode(out))
}

fn token_address(token: &Token) -> Result<Address> {
    token
        .clone()
        .into_address()
        .ok_or_else(|| anyhow!("expected address token"))
}

fn token_uint(token: &Token) -> Result<U256> {
    token
        .clone()
        .into_uint()
        .ok_or_else(|| anyhow!("expected uint token"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_morpho() -> Address {
        Address::from_low_u64_be(99)
    }

    fn market_id() -> String {
        format!("{:?}", derive_market_id(&market_params()))
    }

    fn request(amount: &str) -> MorphoActionRequest {
        MorphoActionRequest {
            agent_id: "agent".to_string(),
            chain: "arc-testnet".to_string(),
            market_id: market_id(),
            amount: Some(amount.to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
            min_health_factor: None,
        }
    }

    fn market_params() -> MorphoMarketParams {
        MorphoMarketParams {
            loan_token: "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
                .parse()
                .unwrap(),
            collateral_token: "0x4200000000000000000000000000000000000006"
                .parse()
                .unwrap(),
            oracle: "0x1631366c38d49ba58793a5f219050923fbf24c81"
                .parse()
                .unwrap(),
            irm: "0x46415998764c29ab2a25cbea6254146d50d22687"
                .parse()
                .unwrap(),
            lltv: U256::from_dec_str("860000000000000000").unwrap(),
        }
    }

    #[test]
    fn market_id_is_derived_from_immutable_parameters() {
        let derived_id = H256::from(ethers::utils::keccak256(abi::encode(&market_param_tokens(
            &market_params(),
        ))));
        assert_eq!(parse_market_id(&market_id()).unwrap(), derived_id);
    }

    #[test]
    fn market_discovery_requires_a_token_filter() {
        let query = MorphoMarketsQuery {
            chain: "arc-testnet".to_string(),
            loan_token: None,
            collateral_token: None,
            max_lltv_raw: None,
            min_liquidity_raw: None,
            require_available_oracle: true,
            limit: 20,
        };
        assert!(validate_markets_query(&query)
            .unwrap_err()
            .to_string()
            .contains("loan_token or collateral_token"));
    }

    #[test]
    fn create_market_event_data_decodes_to_the_indexed_id() {
        let params = market_params();
        let encoded = abi::encode(&market_param_tokens(&params));
        let decoded = decode_market_params(&encoded).unwrap();
        assert_eq!(decoded, params);
        assert_eq!(
            derive_market_id(&decoded),
            parse_market_id(&market_id()).unwrap()
        );
    }

    #[test]
    fn supply_collateral_compiles_approve_action_cleanup() {
        let req = request("1");
        let execution = compile_action(
            &req,
            MorphoAction::SupplyCollateral,
            test_morpho(),
            &market_params(),
            Address::from_low_u64_be(7),
            ResolvedAmount::Assets(U256::exp10(18)),
        )
        .unwrap();
        let calls = execution.batch_calls.unwrap();
        assert_eq!(calls.len(), 4);
        assert!(calls[0].calldata.starts_with("0x095ea7b3"));
        assert!(calls[0].calldata.ends_with(&"0".repeat(64)));
        assert!(calls[1].calldata.starts_with("0x095ea7b3"));
        assert!(calls[2].calldata.starts_with("0x238d6579"));
        assert!(calls[3].calldata.ends_with(&"0".repeat(64)));
    }

    #[test]
    fn max_repay_uses_shares_and_temporary_max_approval() {
        let req = request("max");
        let execution = compile_action(
            &req,
            MorphoAction::Repay,
            test_morpho(),
            &market_params(),
            Address::from_low_u64_be(7),
            ResolvedAmount::Shares(U256::from(123u64)),
        )
        .unwrap();
        let calls = execution.batch_calls.unwrap();
        assert!(calls[0].calldata.ends_with(&"0".repeat(64)));
        assert!(calls[1].calldata.ends_with(&"f".repeat(64)));
        assert!(calls[2].calldata.starts_with("0x20b76e81"));
    }

    #[test]
    fn action_selectors_match_morpho_blue_interface() {
        let params = Token::Tuple(market_param_tokens(&market_params()));
        let wallet = Token::Address(Address::from_low_u64_be(7));
        let amount = Token::Uint(U256::one());
        let zero = Token::Uint(U256::zero());

        let cases = [
            (
                "supply((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                vec![
                    params.clone(),
                    amount.clone(),
                    zero.clone(),
                    wallet.clone(),
                    Token::Bytes(Vec::new()),
                ],
                "0xa99aad89",
            ),
            (
                "withdraw((address,address,address,address,uint256),uint256,uint256,address,address)",
                vec![
                    params.clone(),
                    amount.clone(),
                    zero.clone(),
                    wallet.clone(),
                    wallet.clone(),
                ],
                "0x5c2bea49",
            ),
            (
                "supplyCollateral((address,address,address,address,uint256),uint256,address,bytes)",
                vec![
                    params.clone(),
                    amount.clone(),
                    wallet.clone(),
                    Token::Bytes(Vec::new()),
                ],
                "0x238d6579",
            ),
            (
                "withdrawCollateral((address,address,address,address,uint256),uint256,address,address)",
                vec![
                    params.clone(),
                    amount.clone(),
                    wallet.clone(),
                    wallet.clone(),
                ],
                "0x8720316d",
            ),
            (
                "borrow((address,address,address,address,uint256),uint256,uint256,address,address)",
                vec![
                    params.clone(),
                    amount.clone(),
                    zero.clone(),
                    wallet.clone(),
                    wallet.clone(),
                ],
                "0x50d8cd4b",
            ),
            (
                "repay((address,address,address,address,uint256),uint256,uint256,address,bytes)",
                vec![
                    params,
                    amount,
                    zero,
                    wallet,
                    Token::Bytes(Vec::new()),
                ],
                "0x20b76e81",
            ),
        ];

        for (signature, tokens, expected) in cases {
            assert!(encode_morpho_call(signature, tokens).starts_with(expected));
        }
    }

    #[test]
    fn rejects_non_arc_testnet_chain() {
        let mut req = request("1");
        req.chain = "ethereum".to_string();
        assert!(validate_action_request(&req).is_err());
    }

    #[test]
    fn requires_exactly_one_amount_representation() {
        let mut req = request("1");
        req.amount_raw = Some("1".to_string());
        assert!(validate_action_request(&req).is_err());
    }

    #[test]
    fn action_request_accepts_numeric_human_amounts() {
        let integer: MorphoActionRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "agent",
            "market_id": market_id(),
            "amount": 5
        }))
        .unwrap();
        assert_eq!(integer.amount.as_deref(), Some("5"));

        let decimal: MorphoActionRequest = serde_json::from_value(serde_json::json!({
            "agent_id": "agent",
            "market_id": market_id(),
            "amount": 0.125,
            "min_health_factor": 1.1
        }))
        .unwrap();
        assert_eq!(decimal.amount.as_deref(), Some("0.125"));
        assert_eq!(decimal.min_health_factor.as_deref(), Some("1.1"));
    }

    #[test]
    fn raw_amount_remains_string_only_to_preserve_precision() {
        let result = serde_json::from_value::<MorphoActionRequest>(serde_json::json!({
            "agent_id": "agent",
            "market_id": market_id(),
            "amount_raw": 1000000
        }));
        assert!(result.is_err());
    }

    #[test]
    fn market_id_requires_prefix_and_exact_length() {
        let market_id = market_id();
        assert!(parse_market_id(&market_id).is_ok());
        assert!(parse_market_id(market_id.trim_start_matches("0x")).is_err());
        assert!(parse_market_id("0x01").is_err());
    }
}
