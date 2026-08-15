//! Base Beta configuration.

use anyhow::{bail, Context, Result};
use ethers::types::{Address, U256};
use std::{collections::HashMap, fmt, str::FromStr};

use crate::types::Chain;

pub const VIBENET_CHAIN_ID: u64 = 84_538_453;
pub const VIBENET_RPC_URL: &str = "https://rpc.vibes.base.org";
pub const VIBENET_DEFAULT_ACCOUNT: &str = "0x58da469ef71dd4b092b010cda37de124c926eebd";
pub const VIBENET_EXECUTION_TOKEN_ADDRESS: &str = "0x81a6C7626Ce9EbC3f4Bf898CBaa5599e993652a0";

#[derive(Clone, Debug)]
pub struct ExecutionTokenConfig {
    pub address: Address,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkProfile {
    Vibenet,
    LocalNativeAa,
}

impl FromStr for NetworkProfile {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "vibenet" => Ok(Self::Vibenet),
            "local-native-aa" | "local" => Ok(Self::LocalNativeAa),
            _ => bail!(
                "NETWORK_PROFILE must be vibenet or local-native-aa; native AA is not active on Base Sepolia/mainnet yet"
            ),
        }
    }
}

#[derive(Clone)]
pub struct ChainConfig {
    pub chain: Chain,
    pub chain_id: u64,
    pub rpc_url: String,
    pub price_feed_url: String,
    pub execution_token: ExecutionTokenConfig,
}

impl fmt::Debug for ChainConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainConfig")
            .field("chain", &self.chain)
            .field("chain_id", &self.chain_id)
            .field("rpc_url", &"[REDACTED]")
            .field("price_feed_url", &"[REDACTED]")
            .field("execution_token", &self.execution_token)
            .finish()
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub network_profile: NetworkProfile,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub max_concurrent_requests: u64,

    pub gas_price_markup_pct: f64,
    pub platform_fee_usd: f64,
    pub price_cache_ttl_secs: u64,

    pub x402_facilitator_url: Option<String>,
    pub public_api_base_url: String,
    pub x402_max_timeout_seconds: u64,

    /// Exactly one runtime network is enabled: Base.
    pub chains: HashMap<Chain, ChainConfig>,
    pub native_default_account: Address,
    /// Resolved from the configured wallet provider during startup.
    pub native_payer_address: Option<Address>,
    pub native_receipt_timeout_seconds: u64,
    pub native_max_payer_gas_cost_wei: U256,
    pub payer_low_balance_wei: U256,

    pub turnkey_organization_id: String,
    pub turnkey_api_public_key: String,
    pub turnkey_api_private_key: String,
    pub turnkey_base_url: Option<String>,
    pub turnkey_payer_wallet_name: String,
    pub turnkey_payer_expected_address: Option<Address>,

    pub auth_secret_encryption_key: String,
    pub bootstrap_admin_token: String,
    pub oauth_issuer: String,
    pub oauth_audience: String,
    pub oauth_signing_secret: String,
    pub oauth_access_token_ttl_seconds: i64,
    pub per_principal_rate_limit_rps: f64,
    pub per_principal_rate_limit_burst: f64,
    pub public_registration_enabled: bool,
    pub registration_turnstile_secret: Option<String>,
    pub registration_allowed_hostnames: Vec<String>,
    pub registration_client_ip_header: Option<String>,
    pub registration_hourly_limit: u64,
}

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub network_profile: NetworkProfile,
    pub chains: HashMap<Chain, ChainConfig>,
    pub gas_price_markup_pct: f64,
    pub platform_fee_usd: f64,
    pub price_cache_ttl_secs: u64,
    pub native_default_account: Address,
    pub native_payer_address: Address,
    pub native_receipt_timeout_seconds: u64,
    pub native_max_payer_gas_cost_wei: U256,
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("network_profile", &self.network_profile)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database_url", &"[REDACTED]")
            .field("redis_url", &"[REDACTED]")
            .field("max_concurrent_requests", &self.max_concurrent_requests)
            .field("gas_price_markup_pct", &self.gas_price_markup_pct)
            .field("platform_fee_usd", &self.platform_fee_usd)
            .field("price_cache_ttl_secs", &self.price_cache_ttl_secs)
            .field("x402_facilitator_url", &self.x402_facilitator_url)
            .field("public_api_base_url", &self.public_api_base_url)
            .field("chains", &self.chains)
            .field("native_default_account", &self.native_default_account)
            .field("native_payer_address", &self.native_payer_address)
            .field(
                "native_max_payer_gas_cost_wei",
                &self.native_max_payer_gas_cost_wei,
            )
            .field("turnkey_organization_id", &self.turnkey_organization_id)
            .field("turnkey_api_public_key", &self.turnkey_api_public_key)
            .field("turnkey_api_private_key", &"[REDACTED]")
            .field("turnkey_base_url", &self.turnkey_base_url)
            .field("turnkey_payer_wallet_name", &self.turnkey_payer_wallet_name)
            .field(
                "turnkey_payer_expected_address",
                &self.turnkey_payer_expected_address,
            )
            .field("auth_secret_encryption_key", &"[REDACTED]")
            .field("bootstrap_admin_token", &"[REDACTED]")
            .field("oauth_issuer", &self.oauth_issuer)
            .field("oauth_audience", &self.oauth_audience)
            .field("oauth_signing_secret", &"[REDACTED]")
            .field(
                "public_registration_enabled",
                &self.public_registration_enabled,
            )
            .field("registration_turnstile_secret", &"[REDACTED]")
            .finish()
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();

        let public_api_base_url = env_or("PUBLIC_API_BASE_URL", "http://localhost:8080")
            .trim_end_matches('/')
            .to_string();
        let x402_facilitator_url = optional_env("X402_FACILITATOR_URL");
        if x402_facilitator_url.is_some() && !is_https_or_localhost(&public_api_base_url) {
            bail!("PUBLIC_API_BASE_URL must use HTTPS when x402 is enabled");
        }

        let network_profile: NetworkProfile = env_or("NETWORK_PROFILE", "vibenet").parse()?;
        let (chain_id, rpc_url, native_default_account, execution_token) = match network_profile {
            NetworkProfile::Vibenet => {
                let address = env_or(
                    "VIBENET_EXECUTION_TOKEN_ADDRESS",
                    VIBENET_EXECUTION_TOKEN_ADDRESS,
                )
                .parse::<Address>()
                .context("VIBENET_EXECUTION_TOKEN_ADDRESS must be an EVM address")?;
                (
                    VIBENET_CHAIN_ID,
                    env_or("BASE_RPC_URL", VIBENET_RPC_URL),
                    env_or("VIBENET_DEFAULT_ACCOUNT_ADDRESS", VIBENET_DEFAULT_ACCOUNT)
                        .parse::<Address>()
                        .context("VIBENET_DEFAULT_ACCOUNT_ADDRESS must be an EVM address")?,
                    ExecutionTokenConfig {
                        address,
                        symbol: "USDV".into(),
                        decimals: 6,
                    },
                )
            }
            NetworkProfile::LocalNativeAa => {
                let symbol = env_or("LOCAL_EXECUTION_TOKEN_SYMBOL", "USDV");
                validate_token_symbol(&symbol)?;
                (
                    parse_positive_u64_env("LOCAL_NATIVE_AA_CHAIN_ID", "31337")?,
                    required_env("BASE_RPC_URL")?,
                    required_address("LOCAL_DEFAULT_ACCOUNT_ADDRESS")?,
                    ExecutionTokenConfig {
                        address: required_address("LOCAL_EXECUTION_TOKEN_ADDRESS")?,
                        symbol,
                        decimals: parse_token_decimals_env("LOCAL_EXECUTION_TOKEN_DECIMALS", "6")?,
                    },
                )
            }
        };
        if execution_token.address == Address::zero() || native_default_account == Address::zero() {
            bail!("native AA profile addresses cannot be zero");
        }
        if !is_https_or_localhost(&rpc_url) {
            bail!("BASE_RPC_URL must use HTTPS outside local development");
        }
        let base = ChainConfig {
            chain: Chain::Base,
            chain_id,
            rpc_url,
            price_feed_url: required_env("BASE_PRICE_FEED_URL")?,
            execution_token,
        };
        let mut chains = HashMap::new();
        chains.insert(Chain::Base, base);

        let auth_secret_encryption_key = required_env("AUTH_SECRET_ENCRYPTION_KEY")?;
        validate_hex_key(
            "AUTH_SECRET_ENCRYPTION_KEY",
            &auth_secret_encryption_key,
            32,
        )?;
        let oauth_signing_secret = required_env("OAUTH_SIGNING_SECRET")?;
        if oauth_signing_secret.len() < 32 {
            bail!("OAUTH_SIGNING_SECRET must contain at least 32 bytes");
        }
        let bootstrap_admin_token = required_env("BOOTSTRAP_ADMIN_TOKEN")?;
        if bootstrap_admin_token.len() < 32 {
            bail!("BOOTSTRAP_ADMIN_TOKEN must contain at least 32 bytes");
        }
        let oauth_issuer = optional_env("OAUTH_ISSUER")
            .unwrap_or_else(|| public_api_base_url.clone())
            .trim_end_matches('/')
            .to_string();
        if !is_https_or_localhost(&oauth_issuer) {
            bail!("OAUTH_ISSUER must use HTTPS outside local development");
        }

        let turnkey_payer_wallet_name = env_or("TURNKEY_PAYER_WALLET_NAME", "jusso-beta-payer");
        validate_wallet_name("TURNKEY_PAYER_WALLET_NAME", &turnkey_payer_wallet_name)?;
        let gas_price_markup_pct = parse_nonnegative_f64_env("GAS_PRICE_MARKUP_PCT", "10.0")?;
        let platform_fee_usd = parse_nonnegative_f64_env("PLATFORM_FEE_USD", "0.01")?;
        let per_principal_rate_limit_rps =
            parse_nonnegative_f64_env("PER_PRINCIPAL_RATE_LIMIT_RPS", "5.0")?;
        let per_principal_rate_limit_burst =
            parse_nonnegative_f64_env("PER_PRINCIPAL_RATE_LIMIT_BURST", "10.0")?;
        if per_principal_rate_limit_rps > 0.0 && per_principal_rate_limit_burst < 1.0 {
            bail!(
                "PER_PRINCIPAL_RATE_LIMIT_BURST must be at least 1 when rate limiting is enabled"
            );
        }

        let public_registration_enabled = parse_bool_env("PUBLIC_REGISTRATION_ENABLED", true)?;
        let registration_turnstile_secret = optional_env("REGISTRATION_TURNSTILE_SECRET");
        if public_registration_enabled
            && registration_turnstile_secret.is_none()
            && !is_local_url(&public_api_base_url)
        {
            bail!(
                "REGISTRATION_TURNSTILE_SECRET is required when public registration is enabled outside local development"
            );
        }
        let registration_allowed_hostnames = optional_env("REGISTRATION_ALLOWED_HOSTNAMES")
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if public_registration_enabled
            && registration_turnstile_secret.is_some()
            && registration_allowed_hostnames.is_empty()
        {
            bail!(
                "REGISTRATION_ALLOWED_HOSTNAMES is required when Turnstile-protected registration is enabled"
            );
        }
        let registration_client_ip_header = optional_env("REGISTRATION_CLIENT_IP_HEADER")
            .map(|value| {
                value
                    .parse::<axum::http::HeaderName>()
                    .map(|header| header.as_str().to_string())
                    .with_context(|| "REGISTRATION_CLIENT_IP_HEADER must be an HTTP header name")
            })
            .transpose()?;

        Ok(Self {
            network_profile,
            host: env_or("HOST", "0.0.0.0"),
            port: env_or("PORT", "8080").parse()?,
            database_url: env_or(
                "DATABASE_URL",
                "postgres://postgres:postgres@localhost:5432/jusso",
            ),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            max_concurrent_requests: parse_positive_u64_env("MAX_CONCURRENT_REQUESTS", "200")?,
            gas_price_markup_pct,
            platform_fee_usd,
            price_cache_ttl_secs: env_or("PRICE_CACHE_TTL_SECS", "60").parse()?,
            x402_facilitator_url,
            public_api_base_url: public_api_base_url.clone(),
            x402_max_timeout_seconds: parse_positive_u64_env("X402_MAX_TIMEOUT_SECONDS", "60")?,
            chains,
            native_default_account,
            native_payer_address: None,
            native_receipt_timeout_seconds: parse_positive_u64_env(
                "NATIVE_AA_RECEIPT_TIMEOUT_SECONDS",
                "180",
            )?,
            native_max_payer_gas_cost_wei: parse_positive_u256_env(
                "NATIVE_AA_MAX_PAYER_GAS_COST_WEI",
                "50000000000000000",
            )?,
            payer_low_balance_wei: parse_positive_u256_env(
                "PAYER_LOW_BALANCE_WEI",
                "100000000000000000",
            )?,
            turnkey_organization_id: required_env("TURNKEY_ORGANIZATION_ID")?,
            turnkey_api_public_key: required_env("TURNKEY_API_PUBLIC_KEY")?,
            turnkey_api_private_key: required_env("TURNKEY_API_PRIVATE_KEY")?,
            turnkey_base_url: optional_env("TURNKEY_BASE_URL"),
            turnkey_payer_wallet_name,
            turnkey_payer_expected_address: optional_address("TURNKEY_PAYER_EXPECTED_ADDRESS")?,
            auth_secret_encryption_key,
            bootstrap_admin_token,
            oauth_issuer,
            oauth_audience: optional_env("OAUTH_AUDIENCE")
                .unwrap_or_else(|| public_api_base_url.clone()),
            oauth_signing_secret,
            oauth_access_token_ttl_seconds: env_or("OAUTH_ACCESS_TOKEN_TTL_SECONDS", "900")
                .parse()?,
            per_principal_rate_limit_rps,
            per_principal_rate_limit_burst,
            public_registration_enabled,
            registration_turnstile_secret,
            registration_allowed_hostnames,
            registration_client_ip_header,
            registration_hourly_limit: parse_positive_u64_env("REGISTRATION_HOURLY_LIMIT", "5")?,
        })
    }

    pub fn chain_config(&self, chain: &Chain) -> Result<&ChainConfig> {
        if chain != &Chain::Base {
            bail!("Beta supports Base only");
        }
        self.chains
            .get(chain)
            .ok_or_else(|| anyhow::anyhow!("Base is not configured"))
    }

    pub fn runtime_config(&self) -> Result<RuntimeConfig> {
        Ok(RuntimeConfig {
            network_profile: self.network_profile,
            chains: self.chains.clone(),
            gas_price_markup_pct: self.gas_price_markup_pct,
            platform_fee_usd: self.platform_fee_usd,
            price_cache_ttl_secs: self.price_cache_ttl_secs,
            native_default_account: self.native_default_account,
            native_payer_address: self
                .native_payer_address
                .ok_or_else(|| anyhow::anyhow!("native payer has not been initialized"))?,
            native_receipt_timeout_seconds: self.native_receipt_timeout_seconds,
            native_max_payer_gas_cost_wei: self.native_max_payer_gas_cost_wei,
        })
    }
}

fn parse_positive_u256_env(name: &str, default: &str) -> Result<U256> {
    let raw = env_or(name, default);
    let value = U256::from_dec_str(&raw)
        .with_context(|| format!("{name} must be an unsigned decimal integer"))?;
    if value.is_zero() {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_positive_u64_env(name: &str, default: &str) -> Result<u64> {
    let value: u64 = env_or(name, default)
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_token_decimals_env(name: &str, default: &str) -> Result<u8> {
    let value: u8 = env_or(name, default)
        .parse()
        .with_context(|| format!("{name} must be an integer from 1 to 18"))?;
    if !(1..=18).contains(&value) {
        bail!("{name} must be an integer from 1 to 18");
    }
    Ok(value)
}

fn validate_token_symbol(symbol: &str) -> Result<()> {
    let valid = (2..=16).contains(&symbol.len())
        && symbol
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
    if !valid {
        bail!("execution token symbol must be 2-16 uppercase ASCII letters or digits");
    }
    Ok(())
}

fn parse_nonnegative_f64_env(name: &str, default: &str) -> Result<f64> {
    let value: f64 = env_or(name, default)
        .parse()
        .with_context(|| format!("{name} must be a number"))?;
    if !value.is_finite() || value < 0.0 {
        bail!("{name} must be finite and non-negative");
    }
    Ok(value)
}

fn parse_bool_env(name: &str, default: bool) -> Result<bool> {
    match optional_env(name)
        .unwrap_or_else(|| default.to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        _ => bail!("{name} must be true or false"),
    }
}

impl RuntimeConfig {
    pub fn chain_config(&self, chain: &Chain) -> Result<&ChainConfig> {
        if chain != &Chain::Base {
            bail!("Beta supports Base only");
        }
        self.chains
            .get(chain)
            .ok_or_else(|| anyhow::anyhow!("Base is not configured"))
    }
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name)
        .with_context(|| format!("{name} is required"))
        .and_then(|value| {
            if value.trim().is_empty() {
                bail!("{name} cannot be empty");
            }
            Ok(value)
        })
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_address(name: &str) -> Result<Address> {
    let address: Address = required_env(name)?
        .parse()
        .with_context(|| format!("{name} must be an EVM address"))?;
    if address == Address::zero() {
        bail!("{name} cannot be zero");
    }
    Ok(address)
}

fn optional_address(name: &str) -> Result<Option<Address>> {
    optional_env(name)
        .map(|raw| {
            let address: Address = raw
                .parse()
                .with_context(|| format!("{name} must be an EVM address"))?;
            if address == Address::zero() {
                bail!("{name} cannot be zero");
            }
            Ok(address)
        })
        .transpose()
}

fn validate_hex_key(name: &str, value: &str, bytes: usize) -> Result<()> {
    if value.len() != bytes * 2 || hex::decode(value).is_err() {
        bail!(
            "{name} must be exactly {} hexadecimal characters",
            bytes * 2
        );
    }
    Ok(())
}

fn validate_wallet_name(variable: &str, name: &str) -> Result<()> {
    let valid = (2..=36).contains(&name.len())
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (byte == b'-' && index > 0 && index + 1 < name.len())
        });
    if !valid {
        bail!("{variable} is invalid");
    }
    Ok(())
}

fn is_https_or_localhost(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://localhost")
        || value.starts_with("http://127.0.0.1")
}

fn is_local_url(value: &str) -> bool {
    value.starts_with("http://localhost") || value.starts_with("http://127.0.0.1")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payer_wallet_names_are_provider_safe() {
        assert!(validate_wallet_name("TEST", "jusso-beta-payer").is_ok());
        assert!(validate_wallet_name("TEST", "-bad").is_err());
        assert!(validate_wallet_name("TEST", "bad_name").is_err());
    }

    #[test]
    fn transport_security_allows_https_and_local_development_only() {
        assert!(is_https_or_localhost("https://mainnet.base.org"));
        assert!(is_https_or_localhost("http://localhost:8545"));
        assert!(!is_https_or_localhost("http://rpc.example.com"));
    }

    #[test]
    fn network_profiles_reject_persistent_base_networks_until_activation() {
        assert_eq!(
            "vibenet".parse::<NetworkProfile>().unwrap(),
            NetworkProfile::Vibenet
        );
        assert_eq!(
            "local".parse::<NetworkProfile>().unwrap(),
            NetworkProfile::LocalNativeAa
        );
        assert!("base-sepolia".parse::<NetworkProfile>().is_err());
        assert!("base-mainnet".parse::<NetworkProfile>().is_err());
    }

    #[test]
    fn execution_token_configuration_is_strict() {
        assert!(validate_token_symbol("USDV").is_ok());
        assert!(validate_token_symbol("USDC").is_ok());
        assert!(validate_token_symbol("usd").is_err());
        assert!(validate_token_symbol("USD-V").is_err());
    }
}
