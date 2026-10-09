//! Short-lived, server-signed funding links.
//!
//! The ramp provider remains merchant of record and handles quotes, KYC/AML,
//! payment credentials, limits, and fiat settlement. Jusso only binds a fresh
//! checkout link to the agent's smart-account address.

use anyhow::{bail, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use chrono::{SecondsFormat, Utc};
use ed25519_dalek::{pkcs8::DecodePrivateKey, Signer, SigningKey};
use ethers_core::types::Address;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::config::OnrampConfig;

const EMPTY_BODY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct FundingSessionRequest {
    /// ISO-4217 fiat code, for example USD, EUR, or NGN. Availability is provider- and country-specific.
    pub fiat_currency: Option<String>,
    /// Optional fiat amount to prefill. This is not an authorization to debit the user.
    pub fiat_amount: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FundingSessionResponse {
    pub provider: &'static str,
    pub checkout_url: String,
    pub wallet_address: String,
    pub asset: String,
    pub network: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub notice: &'static str,
}

pub fn create_onramper_session(
    config: &OnrampConfig,
    wallet_address: &str,
    request: &FundingSessionRequest,
) -> Result<FundingSessionResponse> {
    let wallet = wallet_address
        .parse::<Address>()
        .context("invalid smart-account address")?;
    let wallet = format!("{wallet:?}").to_ascii_lowercase();
    let fiat = request
        .fiat_currency
        .as_deref()
        .unwrap_or("USD")
        .trim()
        .to_ascii_uppercase();
    if fiat.len() != 3 || !fiat.bytes().all(|byte| byte.is_ascii_uppercase()) {
        bail!("fiat_currency must be a three-letter ISO currency code");
    }
    if let Some(amount) = request.fiat_amount.as_deref() {
        validate_fiat_amount(amount)?;
    }
    let now = Utc::now();
    let expires_at = now + chrono::Duration::minutes(15);
    let timestamp = now.to_rfc3339_opts(SecondsFormat::Millis, true);
    let expiry = expires_at.to_rfc3339_opts(SecondsFormat::Millis, true);
    let nonce = Uuid::new_v4().to_string();
    let partner_context = Uuid::new_v4().to_string();
    let mut fields = vec![
        ("apiKey".to_string(), config.api_key.clone()),
        ("defaultCrypto".to_string(), config.usdc_asset_id.clone()),
        ("defaultFiat".to_string(), fiat),
        ("isAddressEditable".to_string(), "false".into()),
        ("mode".to_string(), "buy".into()),
        (
            "onlyCryptoNetworks".to_string(),
            config.arc_network_id.clone(),
        ),
        ("onlyCryptos".to_string(), config.usdc_asset_id.clone()),
        ("partnerContext".to_string(), partner_context),
        ("redirectAtCheckout".to_string(), "false".into()),
        (
            "wallets".to_string(),
            format!("{}:{wallet}", config.usdc_asset_id),
        ),
    ];
    if let Some(amount) = request.fiat_amount.as_deref() {
        fields.push(("defaultAmount".into(), amount.trim().into()));
    }
    fields.sort_by(|left, right| left.0.cmp(&right.0));
    let canonical_query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(
            fields
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
        .finish();
    let content = [
        "ONRAMPER-SIG-V2",
        &timestamp,
        &nonce,
        "GET",
        "/",
        &canonical_query,
        "",
        EMPTY_BODY_SHA256,
    ]
    .join("\n");
    let key_der = STANDARD
        .decode(config.signing_private_key_pkcs8_base64.as_bytes())
        .context("ONRAMPER_SIGNING_PRIVATE_KEY_PKCS8_BASE64 is not valid base64")?;
    let signing_key = SigningKey::from_pkcs8_der(&key_der)
        .context("Onramper signing key is not Ed25519 PKCS#8 DER")?;
    let signature = signing_key.sign(content.as_bytes());
    let mut url = reqwest::Url::parse(&config.widget_url)?;
    {
        let mut query = url.query_pairs_mut();
        for (key, value) in &fields {
            query.append_pair(key, value);
        }
        query.append_pair(
            "sigV2",
            &format!("v2:{}", STANDARD.encode(signature.to_bytes())),
        );
        query.append_pair("sigV2Timestamp", &timestamp);
        query.append_pair("sigV2Nonce", &nonce);
        query.append_pair("sigV2Expiry", &expiry);
        query.append_pair(
            "sigV2Fields",
            &fields
                .iter()
                .map(|(key, _)| key.as_str())
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    Ok(FundingSessionResponse {
        provider: "onramper",
        checkout_url: url.into(),
        wallet_address: wallet,
        asset: config.usdc_asset_id.clone(),
        network: config.arc_network_id.clone(),
        expires_at,
        notice: "Payment methods, quotes, fees, KYC, limits, and availability are determined by the ramp provider. This link does not authorize recurring fiat debits.",
    })
}

fn validate_fiat_amount(value: &str) -> Result<()> {
    let value = value.trim();
    if value.len() > 16 {
        bail!("fiat_amount is too large");
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|fraction| {
            fraction.is_empty()
                || fraction.len() > 2
                || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        })
        || !value
            .bytes()
            .any(|byte| byte.is_ascii_digit() && byte != b'0')
    {
        bail!("fiat_amount must be a positive decimal with at most two decimal places");
    }
    Ok(())
}

pub fn signing_key_fingerprint(config: &OnrampConfig) -> Result<String> {
    let key_der = STANDARD.decode(config.signing_private_key_pkcs8_base64.as_bytes())?;
    let key = SigningKey::from_pkcs8_der(&key_der)?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(key.verifying_key().as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    use ed25519_dalek::{Signature, Verifier};
    use rand::rngs::OsRng;

    #[test]
    fn funding_urls_are_signed_and_wallet_bound() {
        let key = SigningKey::generate(&mut OsRng);
        let config = OnrampConfig {
            widget_url: "https://buy.onramper.com".into(),
            api_key: "pk_test_example".into(),
            signing_private_key_pkcs8_base64: STANDARD
                .encode(key.to_pkcs8_der().unwrap().as_bytes()),
            usdc_asset_id: "usdc_arc".into(),
            arc_network_id: "arc".into(),
        };
        let response = create_onramper_session(
            &config,
            "0x0000000000000000000000000000000000000001",
            &FundingSessionRequest {
                fiat_currency: Some("NGN".into()),
                fiat_amount: Some("1000".into()),
            },
        )
        .unwrap();
        assert!(response.checkout_url.contains("sigV2="));
        assert!(response
            .checkout_url
            .contains("wallets=usdc_arc%3A0x0000000000000000000000000000000000000001"));
        assert!(response.checkout_url.contains("defaultFiat=NGN"));
        let url = reqwest::Url::parse(&response.checkout_url).unwrap();
        let parameters = url
            .query_pairs()
            .into_owned()
            .collect::<std::collections::BTreeMap<_, _>>();
        let signed_fields = parameters["sigV2Fields"]
            .split(',')
            .map(|field| (field, parameters[field].as_str()))
            .collect::<Vec<_>>();
        let canonical_query = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(signed_fields)
            .finish();
        let canonical = [
            "ONRAMPER-SIG-V2",
            parameters["sigV2Timestamp"].as_str(),
            parameters["sigV2Nonce"].as_str(),
            "GET",
            "/",
            &canonical_query,
            "",
            EMPTY_BODY_SHA256,
        ]
        .join("\n");
        let signature = STANDARD
            .decode(parameters["sigV2"].trim_start_matches("v2:"))
            .unwrap();
        key.verifying_key()
            .verify(
                canonical.as_bytes(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        assert!(validate_fiat_amount("0.00").is_err());
        assert!(validate_fiat_amount("10.001").is_err());
    }
}
