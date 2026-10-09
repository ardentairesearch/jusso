//! Arc runtime and security configuration.

use anyhow::{bail, Context, Result};
use ethers_core::types::{Address, U256};
use std::{collections::HashMap, fmt};

use crate::{
    arc::{ArcNetwork, ARC_USDC_ADDRESS},
    types::Chain,
};

#[derive(Clone, Debug)]
pub struct ExecutionTokenConfig {
    pub address: Address,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Clone)]
pub struct ChainConfig {
    pub chain: Chain,
    pub chain_id: u64,
    pub rpc_url: String,
    pub execution_token: ExecutionTokenConfig,
}

impl fmt::Debug for ChainConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChainConfig")
            .field("chain", &self.chain)
            .field("chain_id", &self.chain_id)
            .field("rpc_url", &"[REDACTED]")
            .field("execution_token", &self.execution_token)
            .finish()
    }
}

#[derive(Clone)]
pub struct AppConfig {
    pub arc_network: ArcNetwork,
    pub host: String,
    pub port: u16,
    pub database_url: String,
    pub redis_url: String,
    pub max_concurrent_requests: u64,
    pub chains: HashMap<Chain, ChainConfig>,
    pub alchemy_api_key: String,
    pub alchemy_gas_policy_id: String,
    pub arc_max_sponsored_gas_units: u64,
    pub arc_max_sponsored_gas_cost_wei: U256,
    pub execution_fee_recipient: Address,
    pub gas_markup_basis_points: u32,
    pub platform_fee_usdc_raw: U256,
    pub receipt_timeout_seconds: u64,
    pub x402_facilitator_url: Option<String>,
    pub public_api_base_url: String,
    pub x402_max_timeout_seconds: u64,
    pub turnkey_organization_id: String,
    pub turnkey_api_public_key: String,
    pub turnkey_api_private_key: String,
    pub turnkey_base_url: Option<String>,
    pub turnkey_credential_encryption_key: String,
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
    pub registration_turnstile_site_key: Option<String>,
    pub registration_allowed_hostnames: Vec<String>,
    pub registration_client_ip_header: Option<String>,
    pub registration_hourly_limit: u64,
    pub webauthn_rp_id: String,
    pub webauthn_origin: String,
    pub onramp: Option<OnrampConfig>,
}

#[derive(Clone)]
pub struct OnrampConfig {
    pub widget_url: String,
    pub api_key: String,
    pub signing_private_key_pkcs8_base64: String,
    pub usdc_asset_id: String,
    pub arc_network_id: String,
}

impl fmt::Debug for OnrampConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OnrampConfig")
            .field("widget_url", &self.widget_url)
            .field("api_key", &"[REDACTED]")
            .field("signing_private_key_pkcs8_base64", &"[REDACTED]")
            .field("usdc_asset_id", &self.usdc_asset_id)
            .field("arc_network_id", &self.arc_network_id)
            .finish()
    }
}

#[derive(Clone)]
pub struct RuntimeConfig {
    pub arc_network: ArcNetwork,
    pub chains: HashMap<Chain, ChainConfig>,
    pub gas_markup_basis_points: u32,
    pub platform_fee_usdc_raw: U256,
    pub execution_fee_recipient: Address,
    pub alchemy_api_key: String,
    pub alchemy_gas_policy_id: String,
    pub arc_max_sponsored_gas_units: u64,
    pub arc_max_sponsored_gas_cost_wei: U256,
    pub receipt_timeout_seconds: u64,
}

impl fmt::Debug for RuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeConfig")
            .field("arc_network", &self.arc_network)
            .field("chains", &self.chains)
            .field("gas_markup_basis_points", &self.gas_markup_basis_points)
            .field("platform_fee_usdc_raw", &self.platform_fee_usdc_raw)
            .field("execution_fee_recipient", &self.execution_fee_recipient)
            .field("alchemy_api_key", &"[REDACTED]")
            .field("alchemy_gas_policy_id", &"[REDACTED]")
            .field(
                "arc_max_sponsored_gas_units",
                &self.arc_max_sponsored_gas_units,
            )
            .field(
                "arc_max_sponsored_gas_cost_wei",
                &self.arc_max_sponsored_gas_cost_wei,
            )
            .finish()
    }
}

impl fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppConfig")
            .field("arc_network", &self.arc_network)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database_url", &"[REDACTED]")
            .field("redis_url", &"[REDACTED]")
            .field("chains", &self.chains)
            .field("alchemy_api_key", &"[REDACTED]")
            .field("alchemy_gas_policy_id", &"[REDACTED]")
            .field(
                "arc_max_sponsored_gas_units",
                &self.arc_max_sponsored_gas_units,
            )
            .field(
                "arc_max_sponsored_gas_cost_wei",
                &self.arc_max_sponsored_gas_cost_wei,
            )
            .field("execution_fee_recipient", &self.execution_fee_recipient)
            .field("turnkey_organization_id", &self.turnkey_organization_id)
            .field("turnkey_api_public_key", &self.turnkey_api_public_key)
            .field("turnkey_api_private_key", &"[REDACTED]")
            .field("turnkey_base_url", &self.turnkey_base_url)
            .field("turnkey_credential_encryption_key", &"[REDACTED]")
            .field("auth_secret_encryption_key", &"[REDACTED]")
            .field("bootstrap_admin_token", &"[REDACTED]")
            .field("oauth_signing_secret", &"[REDACTED]")
            .field("registration_turnstile_secret", &"[REDACTED]")
            .field("webauthn_rp_id", &self.webauthn_rp_id)
            .field("webauthn_origin", &self.webauthn_origin)
            .field("onramp", &self.onramp)
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
        let arc_network: ArcNetwork = env_or("ARC_NETWORK", "arc-testnet").parse()?;
        if arc_network == ArcNetwork::Mainnet && !parse_bool_env("ARC_ENABLE_MAINNET", false)? {
            bail!("Arc mainnet requires explicit ARC_ENABLE_MAINNET=true after testnet validation");
        }
        let rpc_url = env_or("ARC_RPC_URL", arc_network.default_rpc_url());
        if !is_https_or_localhost(&rpc_url) {
            bail!("ARC_RPC_URL must use HTTPS outside local development");
        }
        let chain = match arc_network {
            ArcNetwork::Mainnet => Chain::Arc,
            ArcNetwork::Testnet => Chain::ArcTestnet,
        };
        let mut chains = HashMap::new();
        chains.insert(
            chain.clone(),
            ChainConfig {
                chain,
                chain_id: arc_network.chain_id(),
                rpc_url,
                execution_token: ExecutionTokenConfig {
                    address: ARC_USDC_ADDRESS,
                    symbol: "USDC".into(),
                    decimals: 6,
                },
            },
        );
        let alchemy_api_key = required_env("ALCHEMY_API_KEY")?;
        if !alchemy_api_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        {
            bail!("ALCHEMY_API_KEY has invalid characters");
        }
        let alchemy_gas_policy_id = required_env("ALCHEMY_GAS_POLICY_ID")?;
        let arc_max_sponsored_gas_units =
            parse_positive_u64_env("ARC_MAX_SPONSORED_GAS_UNITS", "2000000")?;
        let arc_max_sponsored_gas_cost_wei =
            parse_u256_env("ARC_MAX_SPONSORED_GAS_COST_WEI", "100000000000000000")?;
        if arc_max_sponsored_gas_cost_wei.is_zero() {
            bail!("ARC_MAX_SPONSORED_GAS_COST_WEI must be greater than zero");
        }
        let execution_fee_recipient = required_address("EXECUTION_FEE_RECIPIENT")?;
        let gas_markup_basis_points = parse_u32_env("GAS_MARKUP_BPS", "1000")?;
        if gas_markup_basis_points > 100_000 {
            bail!("GAS_MARKUP_BPS exceeds the supported limit");
        }
        let platform_fee_usdc_raw = parse_u256_env("PLATFORM_FEE_USDC_RAW", "10000")?;
        let auth_secret_encryption_key = required_env("AUTH_SECRET_ENCRYPTION_KEY")?;
        validate_hex_key(
            "AUTH_SECRET_ENCRYPTION_KEY",
            &auth_secret_encryption_key,
            32,
        )?;
        let turnkey_credential_encryption_key = required_env("TURNKEY_CREDENTIAL_ENCRYPTION_KEY")?;
        validate_hex_key(
            "TURNKEY_CREDENTIAL_ENCRYPTION_KEY",
            &turnkey_credential_encryption_key,
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
        let registration_turnstile_site_key = optional_env("REGISTRATION_TURNSTILE_SITE_KEY");
        if public_registration_enabled
            && registration_turnstile_secret.is_none()
            && !is_local_url(&public_api_base_url)
        {
            bail!("REGISTRATION_TURNSTILE_SECRET is required when public registration is enabled outside local development");
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
            bail!("REGISTRATION_ALLOWED_HOSTNAMES is required when Turnstile-protected registration is enabled");
        }
        if registration_turnstile_secret.is_some() != registration_turnstile_site_key.is_some() {
            bail!("REGISTRATION_TURNSTILE_SECRET and REGISTRATION_TURNSTILE_SITE_KEY must be configured together");
        }
        let webauthn_origin = optional_env("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|| public_api_base_url.clone())
            .trim_end_matches('/')
            .to_string();
        if !is_https_or_localhost(&webauthn_origin) {
            bail!("WEBAUTHN_ORIGIN must use HTTPS outside local development");
        }
        let parsed_webauthn_origin = reqwest::Url::parse(&webauthn_origin)
            .context("WEBAUTHN_ORIGIN must be an absolute URL")?;
        if parsed_webauthn_origin.path() != "/"
            || parsed_webauthn_origin.query().is_some()
            || parsed_webauthn_origin.fragment().is_some()
        {
            bail!("WEBAUTHN_ORIGIN must contain only scheme and authority");
        }
        let webauthn_rp_id = optional_env("WEBAUTHN_RP_ID").unwrap_or_else(|| {
            parsed_webauthn_origin
                .host_str()
                .unwrap_or("localhost")
                .to_string()
        });
        let registration_client_ip_header = optional_env("REGISTRATION_CLIENT_IP_HEADER")
            .map(|value| {
                value
                    .parse::<axum::http::HeaderName>()
                    .map(|header| header.as_str().to_string())
                    .with_context(|| "REGISTRATION_CLIENT_IP_HEADER must be an HTTP header name")
            })
            .transpose()?;
        let onramp_values = [
            optional_env("ONRAMPER_API_KEY"),
            optional_env("ONRAMPER_SIGNING_PRIVATE_KEY_PKCS8_BASE64"),
            optional_env("ONRAMPER_USDC_ASSET_ID"),
            optional_env("ONRAMPER_ARC_NETWORK_ID"),
        ];
        let onramp = if onramp_values.iter().all(Option::is_none) {
            None
        } else {
            if onramp_values.iter().any(Option::is_none) {
                bail!("Onramper requires ONRAMPER_API_KEY, ONRAMPER_SIGNING_PRIVATE_KEY_PKCS8_BASE64, ONRAMPER_USDC_ASSET_ID, and ONRAMPER_ARC_NETWORK_ID together");
            }
            if arc_network != ArcNetwork::Mainnet {
                bail!("fiat on-ramping is disabled outside Arc mainnet");
            }
            let widget_url = env_or("ONRAMPER_WIDGET_URL", "https://buy.onramper.com");
            let parsed = reqwest::Url::parse(&widget_url)
                .context("ONRAMPER_WIDGET_URL must be an absolute URL")?;
            if parsed.scheme() != "https"
                || parsed.host_str() != Some("buy.onramper.com")
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.path() != "/"
                || parsed.query().is_some()
                || parsed.fragment().is_some()
            {
                bail!("ONRAMPER_WIDGET_URL must be exactly https://buy.onramper.com");
            }
            Some(OnrampConfig {
                widget_url,
                api_key: onramp_values[0].clone().unwrap(),
                signing_private_key_pkcs8_base64: onramp_values[1].clone().unwrap(),
                usdc_asset_id: validate_onramper_id(
                    "ONRAMPER_USDC_ASSET_ID",
                    onramp_values[2].clone().unwrap(),
                )?,
                arc_network_id: validate_onramper_id(
                    "ONRAMPER_ARC_NETWORK_ID",
                    onramp_values[3].clone().unwrap(),
                )?,
            })
        };
        Ok(Self {
            arc_network,
            host: env_or("HOST", "0.0.0.0"),
            port: env_or("PORT", "8080").parse()?,
            database_url: env_or(
                "DATABASE_URL",
                "postgres://postgres:postgres@localhost:5432/jusso",
            ),
            redis_url: env_or("REDIS_URL", "redis://127.0.0.1:6379"),
            max_concurrent_requests: parse_positive_u64_env("MAX_CONCURRENT_REQUESTS", "200")?,
            chains,
            alchemy_api_key,
            alchemy_gas_policy_id,
            arc_max_sponsored_gas_units,
            arc_max_sponsored_gas_cost_wei,
            execution_fee_recipient,
            gas_markup_basis_points,
            platform_fee_usdc_raw,
            receipt_timeout_seconds: parse_positive_u64_env("ARC_RECEIPT_TIMEOUT_SECONDS", "180")?,
            x402_facilitator_url,
            public_api_base_url: public_api_base_url.clone(),
            x402_max_timeout_seconds: parse_positive_u64_env("X402_MAX_TIMEOUT_SECONDS", "60")?,
            turnkey_organization_id: required_env("TURNKEY_ORGANIZATION_ID")?,
            turnkey_api_public_key: required_env("TURNKEY_API_PUBLIC_KEY")?,
            turnkey_api_private_key: required_env("TURNKEY_API_PRIVATE_KEY")?,
            turnkey_base_url: optional_env("TURNKEY_BASE_URL"),
            turnkey_credential_encryption_key,
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
            registration_turnstile_site_key,
            registration_allowed_hostnames,
            registration_client_ip_header,
            registration_hourly_limit: parse_positive_u64_env("REGISTRATION_HOURLY_LIMIT", "5")?,
            webauthn_rp_id,
            webauthn_origin,
            onramp,
        })
    }

    pub fn chain_config(&self, chain: &Chain) -> Result<&ChainConfig> {
        self.chains
            .get(chain)
            .ok_or_else(|| anyhow::anyhow!("chain {chain} is not configured"))
    }

    pub fn runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            arc_network: self.arc_network,
            chains: self.chains.clone(),
            gas_markup_basis_points: self.gas_markup_basis_points,
            platform_fee_usdc_raw: self.platform_fee_usdc_raw,
            execution_fee_recipient: self.execution_fee_recipient,
            alchemy_api_key: self.alchemy_api_key.clone(),
            alchemy_gas_policy_id: self.alchemy_gas_policy_id.clone(),
            arc_max_sponsored_gas_units: self.arc_max_sponsored_gas_units,
            arc_max_sponsored_gas_cost_wei: self.arc_max_sponsored_gas_cost_wei,
            receipt_timeout_seconds: self.receipt_timeout_seconds,
        }
    }
}

impl RuntimeConfig {
    pub fn chain_config(&self, chain: &Chain) -> Result<&ChainConfig> {
        self.chains
            .get(chain)
            .ok_or_else(|| anyhow::anyhow!("chain {chain} is not configured"))
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
fn validate_onramper_id(name: &str, value: String) -> Result<String> {
    if value.len() > 80
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
    {
        bail!("{name} must be a lowercase Onramper identifier");
    }
    Ok(value)
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
fn parse_positive_u64_env(name: &str, default: &str) -> Result<u64> {
    let value: u64 = env_or(name, default)
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))?;
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}
fn parse_u32_env(name: &str, default: &str) -> Result<u32> {
    env_or(name, default)
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))
}
fn parse_u256_env(name: &str, default: &str) -> Result<U256> {
    U256::from_dec_str(&env_or(name, default))
        .with_context(|| format!("{name} must be an unsigned decimal integer"))
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
fn validate_hex_key(name: &str, value: &str, bytes: usize) -> Result<()> {
    if value.len() != bytes * 2 || hex::decode(value).is_err() {
        bail!(
            "{name} must be exactly {} hexadecimal characters",
            bytes * 2
        );
    }
    Ok(())
}
fn is_https_or_localhost(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(
                url.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            ))
}
fn is_local_url(value: &str) -> bool {
    reqwest::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "http"
            && matches!(
                url.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
            )
            && url.username().is_empty()
            && url.password().is_none()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_security_allows_https_and_local_development_only() {
        assert!(is_https_or_localhost("https://rpc.testnet.arc.io"));
        assert!(is_https_or_localhost("http://localhost:8545"));
        assert!(!is_https_or_localhost("http://rpc.example.com"));
        assert!(!is_https_or_localhost("http://localhost.attacker.example"));
        assert!(!is_https_or_localhost("https://user:pass@rpc.example.com"));
    }
}
