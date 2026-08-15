use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const PAYMENT_REQUIRED_HEADER: &str = "payment-required";
pub const PAYMENT_SIGNATURE_HEADER: &str = "payment-signature";
pub const PAYMENT_RESPONSE_HEADER: &str = "payment-response";
pub const X402_VERSION: u8 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    pub url: String,
    pub description: String,
    pub mime_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    pub amount: String,
    pub asset: String,
    pub pay_to: String,
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    pub x402_version: u8,
    pub resource: ResourceInfo,
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extensions: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    pub accepted: PaymentRequirements,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extensions: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FacilitatorRequest<'a> {
    x402_version: u8,
    payment_payload: &'a PaymentPayload,
    payment_requirements: &'a PaymentRequirements,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub is_valid: bool,
    #[serde(default)]
    pub invalid_reason: Option<String>,
    #[serde(default)]
    pub payer: Option<String>,
    #[serde(default)]
    pub extra: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    pub success: bool,
    #[serde(default)]
    pub transaction: Option<String>,
    pub network: String,
    #[serde(default)]
    pub payer: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
    #[serde(default)]
    pub error_reason: Option<String>,
    #[serde(default)]
    pub extensions: Option<Value>,
}

#[derive(Clone)]
pub struct FacilitatorClient {
    client: reqwest::Client,
    base_url: String,
}

impl FacilitatorClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = base_url.trim_end_matches('/');
        if !base_url.starts_with("https://") && !base_url.starts_with("http://localhost") {
            anyhow::bail!("X402_FACILITATOR_URL must use HTTPS (localhost is allowed for testing)");
        }
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            base_url: base_url.to_string(),
        })
    }

    pub async fn verify(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<VerifyResponse> {
        let response = self
            .client
            .post(format!("{}/verify", self.base_url))
            .json(&FacilitatorRequest {
                x402_version: X402_VERSION,
                payment_payload: payload,
                payment_requirements: requirements,
            })
            .send()
            .await
            .context("x402 facilitator verify request failed")?
            .error_for_status()
            .context("x402 facilitator verify returned an error")?;
        Ok(response.json().await?)
    }

    pub async fn settle(
        &self,
        payload: &PaymentPayload,
        requirements: &PaymentRequirements,
    ) -> Result<SettleResponse> {
        let response = self
            .client
            .post(format!("{}/settle", self.base_url))
            .json(&FacilitatorRequest {
                x402_version: X402_VERSION,
                payment_payload: payload,
                payment_requirements: requirements,
            })
            .send()
            .await
            .context("x402 facilitator settle request failed")?
            .error_for_status()
            .context("x402 facilitator settle returned an error")?;
        Ok(response.json().await?)
    }
}

pub fn encode_header<T: Serialize>(value: &T) -> Result<String> {
    Ok(STANDARD.encode(serde_json::to_vec(value)?))
}

pub fn decode_payment_signature(value: &str) -> Result<PaymentPayload> {
    let decoded = STANDARD
        .decode(value.trim())
        .context("PAYMENT-SIGNATURE is not valid base64")?;
    let payload: PaymentPayload =
        serde_json::from_slice(&decoded).context("PAYMENT-SIGNATURE is not valid x402 JSON")?;
    if payload.x402_version != X402_VERSION {
        anyhow::bail!("unsupported x402 version {}", payload.x402_version);
    }
    Ok(payload)
}

pub fn validate_accepted(
    accepted: &PaymentRequirements,
    expected: &PaymentRequirements,
) -> Result<()> {
    if accepted != expected {
        anyhow::bail!("PAYMENT-SIGNATURE accepted requirements do not match the locked quote");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_header_round_trip() {
        let payload = PaymentPayload {
            x402_version: 2,
            resource: None,
            accepted: PaymentRequirements {
                scheme: "exact".into(),
                network: "eip155:11155111".into(),
                amount: "12000".into(),
                asset: "0x1111111111111111111111111111111111111111".into(),
                pay_to: "0x2222222222222222222222222222222222222222".into(),
                max_timeout_seconds: 60,
                extra: None,
            },
            payload: serde_json::json!({"signature": "0x01"}),
            extensions: Map::new(),
        };
        let encoded = encode_header(&payload).unwrap();
        let decoded = decode_payment_signature(&encoded).unwrap();
        assert_eq!(decoded.accepted, payload.accepted);
    }

    #[test]
    fn accepted_requirement_comparison_is_exact() {
        let expected = PaymentRequirements {
            scheme: "exact".into(),
            network: "eip155:84532".into(),
            amount: "10000".into(),
            asset: "0x1111111111111111111111111111111111111111".into(),
            pay_to: "0x2222222222222222222222222222222222222222".into(),
            max_timeout_seconds: 60,
            extra: None,
        };
        let mut changed = expected.clone();
        changed.amount = "9999".into();
        assert!(validate_accepted(&expected, &expected).is_ok());
        assert!(validate_accepted(&changed, &expected).is_err());
    }
}
