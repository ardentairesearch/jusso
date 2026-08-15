//! Compound III typed action adapter.

use anyhow::{anyhow, Result};
use ethers::abi::{self, Token};
use ethers::types::{Address, U256};
use ethers::utils::id;
use serde::{Deserialize, Serialize};

use super::super::serde_utils::deserialize_optional_decimal;
use crate::types::{BatchCall, ExecutionRequest};

const BASE_SEPOLIA_COMET_USDC: &str = "0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017";
const BASE_SEPOLIA_COMET_WETH: &str = "0x61490650AbaA31393464C3f34E8B29cd1C44118E";
const BASE_SEPOLIA_USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const BASE_SEPOLIA_WETH: &str = "0x4200000000000000000000000000000000000006";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundSupplyRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// `USDC`, `base`, `WETH`, or a token address supported by the selected Comet market.
    pub asset: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`. Defaults from `asset`.
    #[serde(default)]
    pub market: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub amount: Option<String>,
    #[serde(default)]
    pub amount_raw: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundWithdrawRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    pub asset: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`. Defaults from `asset`.
    #[serde(default)]
    pub market: Option<String>,
    /// Human-readable token amount, or `max`. For raw token addresses, use `amount_raw`.
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub amount: Option<String>,
    #[serde(default)]
    pub amount_raw: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundRepayRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Base asset amount. Defaults to the selected Comet market base asset.
    #[serde(default = "default_base_asset")]
    pub asset: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`. Defaults from `asset`.
    #[serde(default)]
    pub market: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub amount: Option<String>,
    #[serde(default)]
    pub amount_raw: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompoundBorrowRequest {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Base asset amount. Compound III borrows are base-asset withdrawals.
    #[serde(default = "default_base_asset")]
    pub asset: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`. Defaults from `asset`.
    #[serde(default)]
    pub market: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_decimal")]
    pub amount: Option<String>,
    #[serde(default)]
    pub amount_raw: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
    #[serde(default)]
    pub callback_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompoundPositionQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`.
    #[serde(default)]
    pub market: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompoundBalancesQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`.
    #[serde(default)]
    pub market: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompoundBorrowCapacityQuery {
    pub agent_id: String,
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Compound III Base Sepolia market: `usdc` or `weth`.
    #[serde(default)]
    pub market: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CompoundMarketsQuery {
    #[serde(default = "default_chain")]
    pub chain: String,
    /// Optional base asset symbol or address.
    #[serde(default)]
    pub base_asset: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundMarketsResponse {
    pub chain: String,
    pub markets: Vec<CompoundMarketSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundMarketSummary {
    pub market: String,
    pub comet_address: String,
    pub verified: bool,
    pub base_token_address: String,
    pub base_token_symbol: String,
    pub base_token_decimals: u8,
    pub utilization_raw: String,
    pub utilization_percent: String,
    pub supply_apr_percent: String,
    pub borrow_apr_percent: String,
    pub collateral_assets: Vec<CompoundMarketCollateral>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundMarketCollateral {
    pub symbol: String,
    pub token_address: String,
    pub decimals: u8,
    pub price_feed_address: String,
    pub borrow_collateral_factor_percent: String,
    pub liquidation_collateral_factor_percent: String,
    pub supply_cap_raw: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundPositionResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub comet_address: String,
    pub base_token_address: String,
    pub base_token_symbol: String,
    pub base_token_decimals: u8,
    pub base_supply_balance_raw: String,
    pub base_supply_balance_formatted: String,
    pub base_borrow_balance_raw: String,
    pub base_borrow_balance_formatted: String,
    pub collateral_assets: Vec<CompoundCollateralBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundBalancesResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub comet_address: String,
    pub assets: Vec<CompoundAssetBalance>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundAssetBalance {
    pub symbol: String,
    pub token_address: String,
    pub decimals: u8,
    pub wallet_balance_raw: String,
    pub wallet_balance_formatted: String,
    pub compound_balance_raw: String,
    pub compound_balance_formatted: String,
    pub is_base_asset: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundCollateralBalance {
    pub symbol: String,
    pub token_address: String,
    pub decimals: u8,
    pub collateral_balance_raw: String,
    pub collateral_balance_formatted: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundBorrowCapacityCollateral {
    pub symbol: String,
    pub token_address: String,
    pub decimals: u8,
    pub price_feed_address: String,
    pub price_raw: String,
    pub borrow_collateral_factor_raw: String,
    pub borrow_collateral_factor_percent: String,
    pub collateral_balance_raw: String,
    pub collateral_balance_formatted: String,
    pub borrow_capacity_raw: String,
    pub borrow_capacity_formatted: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CompoundBorrowCapacityResponse {
    pub agent_id: String,
    pub chain: String,
    pub smart_wallet_address: String,
    pub comet_address: String,
    pub base_token_address: String,
    pub base_token_symbol: String,
    pub base_token_decimals: u8,
    pub base_price_feed_address: String,
    pub base_price_raw: String,
    pub utilization_raw: String,
    pub utilization_percent: String,
    pub supply_rate_per_second_raw: String,
    pub supply_apr_percent: String,
    pub borrow_rate_per_second_raw: String,
    pub borrow_apr_percent: String,
    pub current_borrow_raw: String,
    pub current_borrow_formatted: String,
    pub total_borrow_capacity_raw: String,
    pub total_borrow_capacity_formatted: String,
    pub available_borrow_raw: String,
    pub available_borrow_formatted: String,
    pub is_borrow_collateralized: bool,
    pub collateral_assets: Vec<CompoundBorrowCapacityCollateral>,
}

#[derive(Debug, Clone)]
pub struct CompoundAssetInfo {
    pub asset: Address,
    pub price_feed: Address,
    pub scale: U256,
    pub borrow_collateral_factor: U256,
    pub liquidate_collateral_factor: U256,
    pub liquidation_factor: U256,
    pub supply_cap: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompoundMarket {
    Usdc,
    Weth,
}

impl CompoundMarket {
    pub const ALL: [CompoundMarket; 2] = [CompoundMarket::Usdc, CompoundMarket::Weth];

    pub fn slug(self) -> &'static str {
        match self {
            CompoundMarket::Usdc => "usdc",
            CompoundMarket::Weth => "weth",
        }
    }

    pub fn comet(self) -> Address {
        match self {
            CompoundMarket::Usdc => BASE_SEPOLIA_COMET_USDC
                .parse()
                .expect("hardcoded Base Sepolia cUSDCv3 address must be valid"),
            CompoundMarket::Weth => BASE_SEPOLIA_COMET_WETH
                .parse()
                .expect("hardcoded Base Sepolia cWETHv3 address must be valid"),
        }
    }

    pub fn base_token(self) -> Address {
        match self {
            CompoundMarket::Usdc => BASE_SEPOLIA_USDC
                .parse()
                .expect("hardcoded Base Sepolia USDC address must be valid"),
            CompoundMarket::Weth => BASE_SEPOLIA_WETH
                .parse()
                .expect("hardcoded Base Sepolia WETH address must be valid"),
        }
    }

    pub fn base_symbol(self) -> &'static str {
        match self {
            CompoundMarket::Usdc => "USDC",
            CompoundMarket::Weth => "WETH",
        }
    }

    pub fn base_decimals(self) -> u8 {
        match self {
            CompoundMarket::Usdc => 6,
            CompoundMarket::Weth => 18,
        }
    }
}

fn default_chain() -> String {
    "base".to_string()
}

fn default_base_asset() -> String {
    "base".to_string()
}

fn selector(signature: &str) -> [u8; 4] {
    let hash = id(signature);
    [hash[0], hash[1], hash[2], hash[3]]
}

fn encode_call(selector: [u8; 4], tokens: &[Token]) -> String {
    let mut out = selector.to_vec();
    out.extend(abi::encode(tokens));
    format!("0x{}", hex::encode(out))
}

pub fn market_from_action(asset: &str, market: Option<&str>) -> Result<CompoundMarket> {
    parse_market(market, infer_market_from_asset(asset))
}

pub fn market_from_query(market: Option<&str>) -> Result<CompoundMarket> {
    parse_market(market, CompoundMarket::Usdc)
}

pub fn validate_supply_request(req: &CompoundSupplyRequest) -> Result<()> {
    validate_chain_and_agent(&req.agent_id, &req.chain)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let asset = resolve_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        asset.decimals,
        true,
    )?;
    if amount.is_zero() {
        return Err(anyhow!("amount must be greater than zero"));
    }
    Ok(())
}

pub fn validate_withdraw_request(req: &CompoundWithdrawRequest) -> Result<()> {
    validate_chain_and_agent(&req.agent_id, &req.chain)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let asset = resolve_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        asset.decimals,
        true,
    )?;
    if amount.is_zero() {
        return Err(anyhow!("amount must be greater than zero"));
    }
    Ok(())
}

pub fn validate_repay_request(req: &CompoundRepayRequest) -> Result<()> {
    validate_chain_and_agent(&req.agent_id, &req.chain)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    ensure_base_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        Some(market.base_decimals()),
        true,
    )?;
    if amount.is_zero() {
        return Err(anyhow!("amount must be greater than zero"));
    }
    Ok(())
}

pub fn validate_borrow_request(req: &CompoundBorrowRequest) -> Result<()> {
    validate_chain_and_agent(&req.agent_id, &req.chain)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    ensure_base_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        Some(market.base_decimals()),
        true,
    )?;
    if amount.is_zero() {
        return Err(anyhow!("amount must be greater than zero"));
    }
    Ok(())
}

pub fn validate_position_query(query: &CompoundPositionQuery) -> Result<()> {
    validate_chain_and_agent(&query.agent_id, &query.chain)?;
    market_from_query(query.market.as_deref())?;
    Ok(())
}

pub fn validate_balances_query(query: &CompoundBalancesQuery) -> Result<()> {
    validate_chain_and_agent(&query.agent_id, &query.chain)?;
    market_from_query(query.market.as_deref())?;
    Ok(())
}

pub fn validate_borrow_capacity_query(query: &CompoundBorrowCapacityQuery) -> Result<()> {
    validate_chain_and_agent(&query.agent_id, &query.chain)?;
    market_from_query(query.market.as_deref())?;
    Ok(())
}

pub fn validate_markets_query(query: &CompoundMarketsQuery) -> Result<()> {
    validate_chain(&query.chain)?;
    if let Some(base_asset) = query.base_asset.as_deref() {
        let normalized = base_asset.trim();
        if normalized.is_empty() {
            return Err(anyhow!("base_asset must not be empty"));
        }
        let matches = CompoundMarket::ALL.iter().any(|market| {
            normalized.eq_ignore_ascii_case(market.base_symbol())
                || normalized.eq_ignore_ascii_case(&format!("{:?}", market.base_token()))
        });
        if !matches {
            return Err(anyhow!(
                "unsupported Compound III Base Sepolia base_asset; supported: USDC, WETH"
            ));
        }
    }
    Ok(())
}

fn validate_chain(chain: &str) -> Result<()> {
    let chain = crate::types::Chain::from_str_loose(chain)
        .ok_or_else(|| anyhow!("unsupported chain for Compound III: {chain}"))?;
    if chain != crate::types::Chain::Base {
        return Err(anyhow!(
            "Compound III typed adapter currently supports Base Sepolia only; use chain \"base\""
        ));
    }
    Ok(())
}

pub fn compile_supply(req: &CompoundSupplyRequest) -> Result<ExecutionRequest> {
    validate_supply_request(req)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let asset = resolve_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        asset.decimals,
        false,
    )?;
    let comet = market.comet();

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "compound-iii-base-sepolia-supply-{}",
                strategy_suffix(market, &asset.strategy_symbol)
            ))
        }),
        batch_calls: Some(vec![
            BatchCall {
                target_contract: format!("{:?}", asset.address),
                calldata: encode_erc20_approve(comet, amount),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{comet:?}"),
                calldata: encode_comet_supply(asset.address, amount),
                value: "0".to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_withdraw(req: &CompoundWithdrawRequest) -> Result<ExecutionRequest> {
    validate_withdraw_request(req)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let asset = resolve_asset(&req.asset, market)?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        asset.decimals,
        false,
    )?;
    let comet = market.comet();

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{comet:?}"),
        calldata: encode_comet_withdraw(asset.address, amount),
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "compound-iii-base-sepolia-withdraw-{}",
                strategy_suffix(market, &asset.strategy_symbol)
            ))
        }),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_repay(req: &CompoundRepayRequest) -> Result<ExecutionRequest> {
    validate_repay_request(req)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        Some(market.base_decimals()),
        false,
    )?;
    let comet = market.comet();
    let base = market.base_token();

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: String::new(),
        calldata: String::new(),
        value: "0".to_string(),
        strategy_id: req
            .strategy_id
            .clone()
            .or_else(|| Some(format!("compound-iii-base-sepolia-repay-{}", market.slug()))),
        batch_calls: Some(vec![
            BatchCall {
                target_contract: format!("{base:?}"),
                calldata: encode_erc20_approve(comet, amount),
                value: "0".to_string(),
            },
            BatchCall {
                target_contract: format!("{comet:?}"),
                calldata: encode_comet_supply(base, amount),
                value: "0".to_string(),
            },
        ]),
        callback_url: req.callback_url.clone(),
    })
}

pub fn compile_borrow(req: &CompoundBorrowRequest) -> Result<ExecutionRequest> {
    validate_borrow_request(req)?;
    let market = market_from_action(&req.asset, req.market.as_deref())?;
    let amount = resolve_amount(
        req.amount.as_deref(),
        req.amount_raw.as_deref(),
        Some(market.base_decimals()),
        false,
    )?;
    let comet = market.comet();
    let base = market.base_token();

    Ok(ExecutionRequest {
        agent_id: req.agent_id.clone(),
        chain: req.chain.clone(),
        target_contract: format!("{comet:?}"),
        calldata: encode_comet_withdraw(base, amount),
        value: "0".to_string(),
        strategy_id: req.strategy_id.clone().or_else(|| {
            Some(format!(
                "compound-iii-base-sepolia-borrow-{}",
                market.slug()
            ))
        }),
        batch_calls: None,
        callback_url: req.callback_url.clone(),
    })
}

pub fn is_amount_max(amount: Option<&str>, amount_raw: Option<&str>) -> bool {
    amount
        .map(|v| v.trim().eq_ignore_ascii_case("max"))
        .unwrap_or(false)
        || amount_raw
            .map(|v| v.trim().eq_ignore_ascii_case("max"))
            .unwrap_or(false)
}

pub fn supply_with_amount_raw(req: &CompoundSupplyRequest, amount: U256) -> CompoundSupplyRequest {
    let mut resolved = req.clone();
    resolved.amount = None;
    resolved.amount_raw = Some(amount.to_string());
    resolved
}

pub fn withdraw_with_amount_raw(
    req: &CompoundWithdrawRequest,
    amount: U256,
) -> CompoundWithdrawRequest {
    let mut resolved = req.clone();
    resolved.amount = None;
    resolved.amount_raw = Some(amount.to_string());
    resolved
}

pub fn repay_with_amount_raw(req: &CompoundRepayRequest, amount: U256) -> CompoundRepayRequest {
    let mut resolved = req.clone();
    resolved.amount = None;
    resolved.amount_raw = Some(amount.to_string());
    resolved
}

pub fn borrow_with_amount_raw(req: &CompoundBorrowRequest, amount: U256) -> CompoundBorrowRequest {
    let mut resolved = req.clone();
    resolved.amount = None;
    resolved.amount_raw = Some(amount.to_string());
    resolved
}

pub fn encode_balance_of(user: Address) -> String {
    encode_call(selector("balanceOf(address)"), &[Token::Address(user)])
}

pub fn encode_borrow_balance_of(user: Address) -> String {
    encode_call(
        selector("borrowBalanceOf(address)"),
        &[Token::Address(user)],
    )
}

pub fn encode_collateral_balance_of(account: Address, asset: Address) -> String {
    encode_call(
        selector("collateralBalanceOf(address,address)"),
        &[Token::Address(account), Token::Address(asset)],
    )
}

pub fn encode_base_token() -> String {
    encode_call(selector("baseToken()"), &[])
}

pub fn encode_num_assets() -> String {
    encode_call(selector("numAssets()"), &[])
}

pub fn encode_get_asset_info(index: u8) -> String {
    encode_call(
        selector("getAssetInfo(uint8)"),
        &[Token::Uint(U256::from(index))],
    )
}

pub fn encode_is_borrow_collateralized(account: Address) -> String {
    encode_call(
        selector("isBorrowCollateralized(address)"),
        &[Token::Address(account)],
    )
}

pub fn encode_base_token_price_feed() -> String {
    encode_call(selector("baseTokenPriceFeed()"), &[])
}

pub fn encode_get_price(price_feed: Address) -> String {
    encode_call(selector("getPrice(address)"), &[Token::Address(price_feed)])
}

pub fn encode_get_utilization() -> String {
    encode_call(selector("getUtilization()"), &[])
}

pub fn encode_get_supply_rate(utilization: U256) -> String {
    encode_call(
        selector("getSupplyRate(uint256)"),
        &[Token::Uint(utilization)],
    )
}

pub fn encode_get_borrow_rate(utilization: U256) -> String {
    encode_call(
        selector("getBorrowRate(uint256)"),
        &[Token::Uint(utilization)],
    )
}

pub fn encode_erc20_balance_of(user: Address) -> String {
    encode_call(selector("balanceOf(address)"), &[Token::Address(user)])
}

pub fn encode_erc20_decimals() -> String {
    encode_call(selector("decimals()"), &[])
}

pub fn encode_erc20_symbol() -> String {
    encode_call(selector("symbol()"), &[])
}

pub fn decode_address(raw: &[u8]) -> Result<Address> {
    let decoded = abi::decode(&[abi::ParamType::Address], raw)?;
    match decoded.first() {
        Some(Token::Address(value)) => Ok(*value),
        _ => Err(anyhow!("unexpected address return token")),
    }
}

pub fn decode_u256(raw: &[u8]) -> Result<U256> {
    let decoded = abi::decode(&[abi::ParamType::Uint(256)], raw)?;
    match decoded.first() {
        Some(Token::Uint(value)) => Ok(*value),
        _ => Err(anyhow!("unexpected uint256 return token")),
    }
}

pub fn decode_u8(raw: &[u8]) -> Result<u8> {
    let value = decode_u256(raw)?;
    if value > U256::from(u8::MAX) {
        anyhow::bail!("uint256 value does not fit into u8");
    }
    Ok(value.as_u32() as u8)
}

pub fn decode_bool(raw: &[u8]) -> Result<bool> {
    let decoded = abi::decode(&[abi::ParamType::Bool], raw)?;
    match decoded.first() {
        Some(Token::Bool(value)) => Ok(*value),
        _ => Err(anyhow!("unexpected bool return token")),
    }
}

pub fn decode_string(raw: &[u8]) -> Result<String> {
    if let Ok(decoded) = abi::decode(&[abi::ParamType::String], raw) {
        if let Some(Token::String(value)) = decoded.first() {
            return Ok(value.clone());
        }
    }
    if let Ok(decoded) = abi::decode(&[abi::ParamType::FixedBytes(32)], raw) {
        if let Some(Token::FixedBytes(value)) = decoded.first() {
            let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
            return Ok(String::from_utf8_lossy(&value[..end]).to_string());
        }
    }
    Err(anyhow!("unexpected string return token"))
}

pub fn decode_asset_info(raw: &[u8]) -> Result<CompoundAssetInfo> {
    let decoded = abi::decode(
        &[abi::ParamType::Tuple(vec![
            abi::ParamType::Uint(8),
            abi::ParamType::Address,
            abi::ParamType::Address,
            abi::ParamType::Uint(64),
            abi::ParamType::Uint(64),
            abi::ParamType::Uint(64),
            abi::ParamType::Uint(64),
            abi::ParamType::Uint(128),
        ])],
        raw,
    )?;

    let tokens = match decoded.first() {
        Some(Token::Tuple(tokens)) => tokens,
        _ => return Err(anyhow!("unexpected getAssetInfo return token")),
    };

    match (
        tokens.get(1),
        tokens.get(2),
        tokens.get(3),
        tokens.get(4),
        tokens.get(5),
        tokens.get(6),
        tokens.get(7),
    ) {
        (
            Some(Token::Address(asset)),
            Some(Token::Address(price_feed)),
            Some(Token::Uint(scale)),
            Some(Token::Uint(borrow_collateral_factor)),
            Some(Token::Uint(liquidate_collateral_factor)),
            Some(Token::Uint(liquidation_factor)),
            Some(Token::Uint(supply_cap)),
        ) => Ok(CompoundAssetInfo {
            asset: *asset,
            price_feed: *price_feed,
            scale: *scale,
            borrow_collateral_factor: *borrow_collateral_factor,
            liquidate_collateral_factor: *liquidate_collateral_factor,
            liquidation_factor: *liquidation_factor,
            supply_cap: *supply_cap,
        }),
        _ => Err(anyhow!("unexpected getAssetInfo fields")),
    }
}

fn validate_chain_and_agent(agent_id: &str, chain: &str) -> Result<()> {
    validate_chain(chain)?;
    if agent_id.trim().is_empty() {
        return Err(anyhow!("agent_id is required"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ResolvedAsset {
    address: Address,
    decimals: Option<u8>,
    strategy_symbol: String,
}

fn resolve_asset(asset: &str, market: CompoundMarket) -> Result<ResolvedAsset> {
    let trimmed = asset.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("asset is required"));
    }

    let upper = trimmed.to_uppercase();
    match upper.as_str() {
        "BASE" => Ok(ResolvedAsset {
            address: market.base_token(),
            decimals: Some(market.base_decimals()),
            strategy_symbol: market.base_symbol().to_string(),
        }),
        "USDC" => Ok(ResolvedAsset {
            address: BASE_SEPOLIA_USDC.parse()?,
            decimals: Some(6),
            strategy_symbol: "USDC".to_string(),
        }),
        "WETH" => Ok(ResolvedAsset {
            address: BASE_SEPOLIA_WETH.parse()?,
            decimals: Some(18),
            strategy_symbol: "WETH".to_string(),
        }),
        _ => {
            let address: Address = trimmed.parse().map_err(|e| {
                anyhow!("asset must be USDC, base, WETH, or a valid token address: {e}")
            })?;
            Ok(ResolvedAsset {
                address,
                decimals: None,
                strategy_symbol: format!("{address:?}"),
            })
        }
    }
}

fn ensure_base_asset(asset: &str, market: CompoundMarket) -> Result<()> {
    let normalized = asset.trim().to_uppercase();
    if normalized == "BASE" || normalized == market.base_symbol() {
        return Ok(());
    }

    if asset
        .trim()
        .parse::<Address>()
        .map(|address| address == market.base_token())
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(anyhow!(
            "Compound III borrow/repay supports the selected market base asset only; use base or {}",
            market.base_symbol()
        ))
    }
}

fn infer_market_from_asset(asset: &str) -> CompoundMarket {
    let normalized = asset.trim().to_uppercase();
    if normalized == "WETH" || normalized == BASE_SEPOLIA_WETH.to_uppercase() {
        CompoundMarket::Weth
    } else {
        CompoundMarket::Usdc
    }
}

fn parse_market(raw: Option<&str>, default: CompoundMarket) -> Result<CompoundMarket> {
    let Some(raw) = raw else {
        return Ok(default);
    };
    let normalized = raw.trim().to_lowercase();
    match normalized.as_str() {
        "" => Ok(default),
        "usdc" | "cusdc" | "cusdcv3" | "base-usdc" => Ok(CompoundMarket::Usdc),
        "weth" | "cweth" | "cwethv3" | "base-weth" => Ok(CompoundMarket::Weth),
        _ if raw.eq_ignore_ascii_case(BASE_SEPOLIA_COMET_USDC) => Ok(CompoundMarket::Usdc),
        _ if raw.eq_ignore_ascii_case(BASE_SEPOLIA_COMET_WETH) => Ok(CompoundMarket::Weth),
        _ => Err(anyhow!(
            "unsupported Compound III Base Sepolia market '{raw}'; supported: usdc, weth"
        )),
    }
}

fn strategy_suffix(market: CompoundMarket, asset_symbol: &str) -> String {
    format!("{}-{}", market.slug(), asset_symbol)
}

fn resolve_amount(
    amount: Option<&str>,
    amount_raw: Option<&str>,
    decimals: Option<u8>,
    allow_max: bool,
) -> Result<U256> {
    match (amount, amount_raw) {
        (Some(_), Some(_)) => Err(anyhow!("provide either amount or amount_raw, not both")),
        (Some(raw), None) if allow_max && raw.trim().eq_ignore_ascii_case("max") => Ok(U256::MAX),
        (Some(amount), None) => {
            let decimals = decimals.ok_or_else(|| {
                anyhow!("amount requires a known asset symbol; use amount_raw for token addresses")
            })?;
            parse_decimal_amount(amount, decimals)
        }
        (None, Some(raw)) if allow_max && raw.trim().eq_ignore_ascii_case("max") => Ok(U256::MAX),
        (None, Some(raw)) => U256::from_dec_str(raw.trim())
            .map_err(|e| anyhow!("amount_raw must be a base-10 integer: {e}")),
        (None, None) => Err(anyhow!("amount or amount_raw is required")),
    }
}

fn parse_decimal_amount(raw: &str, decimals: u8) -> Result<U256> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("amount is required"));
    }
    if trimmed.starts_with('-') {
        return Err(anyhow!("amount cannot be negative"));
    }

    let parts = trimmed.split('.').collect::<Vec<_>>();
    if parts.len() > 2 {
        return Err(anyhow!("amount has too many decimal points"));
    }

    let whole = parts[0];
    let fractional = parts.get(1).copied().unwrap_or("");
    if whole.is_empty() && fractional.is_empty() {
        return Err(anyhow!("amount is required"));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !fractional.chars().all(|c| c.is_ascii_digit())
    {
        return Err(anyhow!("amount must be a positive decimal number"));
    }
    if fractional.len() > decimals as usize {
        return Err(anyhow!(
            "amount has too many decimal places for asset decimals {decimals}"
        ));
    }

    let mut normalized = String::new();
    normalized.push_str(if whole.is_empty() { "0" } else { whole });
    normalized.push_str(fractional);
    normalized.push_str(&"0".repeat(decimals as usize - fractional.len()));
    let trimmed_zeroes = normalized.trim_start_matches('0');
    if trimmed_zeroes.is_empty() {
        Ok(U256::zero())
    } else {
        U256::from_dec_str(trimmed_zeroes).map_err(|e| anyhow!("invalid amount: {e}"))
    }
}

fn encode_erc20_approve(spender: Address, amount: U256) -> String {
    encode_call(
        selector("approve(address,uint256)"),
        &[Token::Address(spender), Token::Uint(amount)],
    )
}

fn encode_comet_supply(asset: Address, amount: U256) -> String {
    encode_call(
        selector("supply(address,uint256)"),
        &[Token::Address(asset), Token::Uint(amount)],
    )
}

fn encode_comet_withdraw(asset: Address, amount: U256) -> String {
    encode_call(
        selector("withdraw(address,uint256)"),
        &[Token::Address(asset), Token::Uint(amount)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_requests_accept_numeric_human_amounts() {
        let base = serde_json::json!({
            "agent_id": "agent-compound",
            "asset": "USDC",
            "amount": 1.25
        });
        let supply: CompoundSupplyRequest = serde_json::from_value(base.clone()).unwrap();
        let withdraw: CompoundWithdrawRequest = serde_json::from_value(base.clone()).unwrap();
        let repay: CompoundRepayRequest = serde_json::from_value(base.clone()).unwrap();
        let borrow: CompoundBorrowRequest = serde_json::from_value(base).unwrap();

        assert_eq!(supply.amount.as_deref(), Some("1.25"));
        assert_eq!(withdraw.amount.as_deref(), Some("1.25"));
        assert_eq!(repay.amount.as_deref(), Some("1.25"));
        assert_eq!(borrow.amount.as_deref(), Some("1.25"));
    }

    #[test]
    fn encodes_compound_supply_selector() {
        let usdc = BASE_SEPOLIA_USDC.parse::<Address>().unwrap();
        let calldata = encode_comet_supply(usdc, U256::from(1_000_000u64));
        assert!(calldata.starts_with("0xf2b9fdb8"));
    }

    #[test]
    fn parses_base_asset_amount() {
        let req = CompoundSupplyRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "USDC".to_string(),
            market: None,
            amount: Some("1.25".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };
        validate_supply_request(&req).unwrap();
    }

    #[test]
    fn hardcodes_base_sepolia_comet_markets() {
        assert_eq!(
            CompoundMarket::Usdc.comet(),
            BASE_SEPOLIA_COMET_USDC.parse::<Address>().unwrap()
        );
        assert_eq!(
            CompoundMarket::Weth.comet(),
            BASE_SEPOLIA_COMET_WETH.parse::<Address>().unwrap()
        );
    }

    #[test]
    fn verified_registry_filters_supported_base_assets() {
        let query = CompoundMarketsQuery {
            chain: "base".to_string(),
            base_asset: Some("WETH".to_string()),
        };
        validate_markets_query(&query).unwrap();

        let invalid = CompoundMarketsQuery {
            chain: "base".to_string(),
            base_asset: Some("DAI".to_string()),
        };
        assert!(validate_markets_query(&invalid).is_err());
    }

    #[test]
    fn base_asset_uses_selected_market() {
        let req = CompoundBorrowRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "base".to_string(),
            market: Some("weth".to_string()),
            amount: Some("0.01".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };

        let execution = compile_borrow(&req).unwrap();
        assert_eq!(
            execution.target_contract,
            format!("{:?}", CompoundMarket::Weth.comet())
        );
        assert!(execution
            .calldata
            .contains("4200000000000000000000000000000000000006"));
    }

    #[test]
    fn weth_asset_infers_weth_market() {
        let req = CompoundSupplyRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "WETH".to_string(),
            market: None,
            amount: Some("0.01".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };

        let execution = compile_supply(&req).unwrap();
        let calls = execution.batch_calls.unwrap();
        assert_eq!(
            calls[1].target_contract,
            format!("{:?}", CompoundMarket::Weth.comet())
        );
    }

    #[test]
    fn rejects_unknown_market() {
        let req = CompoundSupplyRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "USDC".to_string(),
            market: Some("unknown".to_string()),
            amount: Some("1".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };

        assert!(validate_supply_request(&req).is_err());
    }

    #[test]
    fn compile_rejects_unresolved_max_amount() {
        let req = CompoundWithdrawRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "USDC".to_string(),
            market: None,
            amount: Some("max".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };

        assert!(validate_withdraw_request(&req).is_ok());
        assert!(compile_withdraw(&req).is_err());
    }

    #[test]
    fn raw_address_asset_requires_raw_amount() {
        let req = CompoundSupplyRequest {
            agent_id: "agent".to_string(),
            chain: "base".to_string(),
            asset: "0x0000000000000000000000000000000000000001".to_string(),
            market: None,
            amount: Some("1".to_string()),
            amount_raw: None,
            strategy_id: None,
            callback_url: None,
        };
        assert!(validate_supply_request(&req).is_err());
    }
}
