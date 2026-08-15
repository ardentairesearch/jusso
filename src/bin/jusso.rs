//! Minimal, dependency-free-to-install onboarding CLI for the Jusso Beta.

use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use jsonwebtoken::{encode, jwk::Jwk, Algorithm, EncodingKey, Header};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("onboard") => onboard(parse_options(args.collect())?).await,
        Some("enroll") => enroll(parse_enroll_options(args.collect())?).await,
        Some("agent") if args.next().as_deref() == Some("create") => {
            create_agent(parse_create_agent_options(args.collect())?).await
        }
        _ => {
            eprintln!(
                "Usage:\n  jusso onboard --organization NAME --agent-id ID --accept-terms [--display-name NAME] [--api-url URL] [--challenge-token TOKEN]\n  jusso agent create --profile FILE --agent-id ID --display-name NAME [--policy-id UUID] [--parent-agent-id UUID] [--enrollment-ttl-seconds N]\n  jusso enroll --enrollment-token TOKEN --display-name NAME [--api-url URL]"
            );
            std::process::exit(2);
        }
    }
}

#[derive(Debug)]
struct OnboardOptions {
    organization: String,
    agent_id: String,
    display_name: String,
    api_url: String,
    challenge_token: Option<String>,
    accept_terms: bool,
}

fn parse_options(arguments: Vec<String>) -> Result<OnboardOptions> {
    let (mut values, accept_terms) = parse_arguments(arguments, Some("--accept-terms"))?;
    let organization = values
        .remove("--organization")
        .ok_or_else(|| anyhow!("--organization is required"))?;
    let agent_id = values
        .remove("--agent-id")
        .ok_or_else(|| anyhow!("--agent-id is required"))?;
    let display_name = values
        .remove("--display-name")
        .unwrap_or_else(|| agent_id.clone());
    let api_url = values
        .remove("--api-url")
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
        .trim_end_matches('/')
        .to_string();
    let challenge_token = values.remove("--challenge-token");
    reject_unknown_options(&values)?;
    if !accept_terms {
        anyhow::bail!("--accept-terms is required to create an organization");
    }
    Ok(OnboardOptions {
        organization,
        agent_id,
        display_name,
        api_url,
        challenge_token,
        accept_terms,
    })
}

#[derive(Debug)]
struct EnrollOptions {
    enrollment_token: String,
    display_name: String,
    api_url: String,
}

#[derive(Debug)]
struct CreateAgentOptions {
    profile: PathBuf,
    agent_id: String,
    display_name: String,
    policy_id: Option<String>,
    parent_agent_id: Option<String>,
    enrollment_ttl_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct LocalProfile {
    version: u8,
    api_url: String,
    client_id: String,
    private_key_file: PathBuf,
    policy_id: Option<String>,
}

fn parse_enroll_options(arguments: Vec<String>) -> Result<EnrollOptions> {
    let (mut values, _) = parse_arguments(arguments, None)?;
    let enrollment_token = values
        .remove("--enrollment-token")
        .ok_or_else(|| anyhow!("--enrollment-token is required"))?;
    let display_name = values
        .remove("--display-name")
        .ok_or_else(|| anyhow!("--display-name is required"))?;
    let api_url = values
        .remove("--api-url")
        .unwrap_or_else(|| "http://127.0.0.1:8080".to_string())
        .trim_end_matches('/')
        .to_string();
    reject_unknown_options(&values)?;
    Ok(EnrollOptions {
        enrollment_token,
        display_name,
        api_url,
    })
}

fn parse_create_agent_options(arguments: Vec<String>) -> Result<CreateAgentOptions> {
    let (mut values, _) = parse_arguments(arguments, None)?;
    let profile = values
        .remove("--profile")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("--profile is required"))?;
    let agent_id = values
        .remove("--agent-id")
        .ok_or_else(|| anyhow!("--agent-id is required"))?;
    let display_name = values
        .remove("--display-name")
        .ok_or_else(|| anyhow!("--display-name is required"))?;
    let policy_id = values.remove("--policy-id");
    let parent_agent_id = values.remove("--parent-agent-id");
    let enrollment_ttl_seconds = values
        .remove("--enrollment-ttl-seconds")
        .unwrap_or_else(|| "900".into())
        .parse::<i64>()
        .context("--enrollment-ttl-seconds must be an integer")?;
    if !(60..=86_400).contains(&enrollment_ttl_seconds) {
        anyhow::bail!("--enrollment-ttl-seconds must be between 60 and 86400");
    }
    reject_unknown_options(&values)?;
    Ok(CreateAgentOptions {
        profile,
        agent_id,
        display_name,
        policy_id,
        parent_agent_id,
        enrollment_ttl_seconds,
    })
}

fn parse_arguments(
    arguments: Vec<String>,
    boolean_flag: Option<&str>,
) -> Result<(BTreeMap<String, String>, bool)> {
    let mut values = BTreeMap::new();
    let mut boolean_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        let flag = &arguments[index];
        if boolean_flag == Some(flag.as_str()) {
            if boolean_seen {
                anyhow::bail!("duplicate option {flag}");
            }
            boolean_seen = true;
            index += 1;
            continue;
        }
        if !flag.starts_with("--") || index + 1 >= arguments.len() {
            anyhow::bail!("invalid or incomplete option {flag}");
        }
        if values
            .insert(flag.clone(), arguments[index + 1].clone())
            .is_some()
        {
            anyhow::bail!("duplicate option {flag}");
        }
        index += 2;
    }
    Ok((values, boolean_seen))
}

fn reject_unknown_options(values: &BTreeMap<String, String>) -> Result<()> {
    if !values.is_empty() {
        anyhow::bail!(
            "unknown options: {}",
            values.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

async fn onboard(options: OnboardOptions) -> Result<()> {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_jwk = public_jwk(&signing_key)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let response = http
        .post(format!("{}/register", options.api_url))
        .json(&json!({
            "organization_name": options.organization,
            "display_name": options.display_name,
            "agent_id": options.agent_id,
            "public_jwk": public_jwk,
            "terms_accepted": options.accept_terms,
            "challenge_token": options.challenge_token,
        }))
        .send()
        .await
        .context("Jusso registration request failed")?;
    let registration = json_response(response, "registration").await?;
    finish_onboarding(
        &http,
        &options.api_url,
        signing_key,
        public_jwk,
        registration,
    )
    .await
}

async fn enroll(options: EnrollOptions) -> Result<()> {
    let signing_key = SigningKey::random(&mut OsRng);
    let public_jwk = public_jwk(&signing_key)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let response = http
        .post(format!("{}/agents/enroll", options.api_url))
        .json(&json!({
            "enrollment_token": options.enrollment_token,
            "display_name": options.display_name,
            "public_jwk": public_jwk,
        }))
        .send()
        .await
        .context("Jusso agent enrollment request failed")?;
    let registration = json_response(response, "agent enrollment").await?;
    finish_onboarding(
        &http,
        &options.api_url,
        signing_key,
        public_jwk,
        registration,
    )
    .await
}

async fn create_agent(options: CreateAgentOptions) -> Result<()> {
    let profile: LocalProfile = serde_json::from_slice(
        &fs::read(&options.profile)
            .with_context(|| format!("failed to read profile {}", options.profile.display()))?,
    )
    .context("profile is not valid Jusso JSON")?;
    if profile.version != 1 {
        anyhow::bail!("unsupported Jusso profile version {}", profile.version);
    }
    let policy_id = options
        .policy_id
        .as_deref()
        .or(profile.policy_id.as_deref())
        .ok_or_else(|| anyhow!("--policy-id is required because this profile has no default"))?;
    Uuid::parse_str(policy_id).context("policy_id must be a UUID")?;
    if let Some(parent) = options.parent_agent_id.as_deref() {
        Uuid::parse_str(parent).context("parent_agent_id must be a UUID")?;
    }

    let private_pem = Zeroizing::new(fs::read(&profile.private_key_file).with_context(|| {
        format!(
            "failed to read private key {}",
            profile.private_key_file.display()
        )
    })?);
    let signing_key = SigningKey::from_pkcs8_pem(
        std::str::from_utf8(&private_pem).context("private key is not UTF-8 PEM")?,
    )
    .context("profile private key is not a P-256 PKCS#8 key")?;
    let public_jwk = public_jwk(&signing_key)?;
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;
    let (issuer, access_token) = obtain_access_token(
        &http,
        &profile.api_url,
        &profile.client_id,
        &public_jwk,
        &private_pem,
    )
    .await?;
    let path = "/agents";
    let proof = dpop_proof(
        "POST",
        &format!("{issuer}{path}"),
        Some(&access_token),
        &public_jwk,
        &private_pem,
    )?;
    let response = json_response(
        http.post(format!("{}{path}", profile.api_url.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {access_token}"))
            .header("DPoP", proof)
            .json(&json!({
                "agent_id": options.agent_id,
                "display_name": options.display_name,
                "parent_agent_id": options.parent_agent_id,
                "policy_id": policy_id,
                "scopes": [],
                "enrollment_ttl_seconds": options.enrollment_ttl_seconds,
            }))
            .send()
            .await?,
        "agent creation",
    )
    .await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn finish_onboarding(
    http: &reqwest::Client,
    api_url: &str,
    signing_key: SigningKey,
    public_jwk: Value,
    registration: Value,
) -> Result<()> {
    let client_id = string_field(&registration, "client_id")?.to_string();
    let organization_id = string_field(&registration, "organization_id")?.to_string();
    let principal_id = string_field(&registration, "principal_id")?.to_string();
    let agent_id = string_field(&registration, "agent_id")?.to_string();
    let policy_id = registration
        .get("policy_id")
        .and_then(Value::as_str)
        .map(String::from);
    let webhook_signing_secret = registration
        .get("webhook_signing_secret")
        .and_then(Value::as_str);

    let config_dir = config_directory()?;
    create_private_directory(&config_dir)?;
    let credential_dir = config_dir.join("credentials");
    create_private_directory(&credential_dir)?;
    let key_path = credential_dir.join(format!("{client_id}.pem"));
    let pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .context("failed to encode the local P-256 key")?;
    write_private_file(&key_path, pem.as_bytes())?;
    let profile_dir = config_dir.join("profiles");
    create_private_directory(&profile_dir)?;
    let config_path = profile_dir.join(format!("{client_id}.json"));
    write_private_file(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "version": 1,
            "api_url": api_url,
            "organization_id": organization_id,
            "principal_id": principal_id,
            "agent_id": agent_id,
            "client_id": client_id,
            "private_key_file": key_path,
            "policy_id": policy_id,
            "webhook_signing_secret": webhook_signing_secret,
        }))?
        .as_slice(),
    )?;

    let private_pem = pem.as_bytes();
    let (issuer, access_token) =
        obtain_access_token(http, api_url, &client_id, &public_jwk, private_pem).await?;
    let wallet_path = "/wallet";
    let wallet_dpop = dpop_proof(
        "GET",
        &format!("{issuer}{wallet_path}"),
        Some(&access_token),
        &public_jwk,
        private_pem,
    )?;
    let wallet = json_response(
        http.get(format!("{api_url}{wallet_path}"))
            .query(&[("agent_id", agent_id.as_str()), ("chain", "base")])
            .header("Authorization", format!("Bearer {access_token}"))
            .header("DPoP", wallet_dpop)
            .send()
            .await?,
        "authentication verification",
    )
    .await?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "status": "ready",
            "organization_id": organization_id,
            "agent_id": agent_id,
            "client_id": client_id,
            "wallet_address": wallet.get("smart_wallet_address"),
            "config_file": config_path,
            "private_key_file": key_path,
        }))?
    );
    Ok(())
}

async fn obtain_access_token(
    http: &reqwest::Client,
    api_url: &str,
    client_id: &str,
    public_jwk: &Value,
    private_pem: &[u8],
) -> Result<(String, String)> {
    let metadata = json_response(
        http.get(format!("{api_url}/.well-known/oauth-authorization-server"))
            .send()
            .await?,
        "OAuth metadata",
    )
    .await?;
    let issuer = string_field(&metadata, "issuer")?;
    let token_endpoint = string_field(&metadata, "token_endpoint")?;
    let assertion = signed_client_assertion(client_id, token_endpoint, private_pem)?;
    let token_dpop = dpop_proof("POST", token_endpoint, None, public_jwk, private_pem)?;
    let token = json_response(
        http.post(token_endpoint)
            .header("DPoP", token_dpop)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", assertion.as_str()),
            ])
            .send()
            .await?,
        "token exchange",
    )
    .await?;
    Ok((
        issuer.to_string(),
        string_field(&token, "access_token")?.to_string(),
    ))
}

fn public_jwk(signing_key: &SigningKey) -> Result<Value> {
    let point = signing_key.verifying_key().to_encoded_point(false);
    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(point.x().ok_or_else(|| anyhow!("P-256 key omitted x"))?),
        "y": URL_SAFE_NO_PAD.encode(point.y().ok_or_else(|| anyhow!("P-256 key omitted y"))?),
        "alg": "ES256",
        "use": "sig",
        "key_ops": ["verify"]
    }))
}

#[derive(Serialize)]
struct ClientAssertion<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    iat: i64,
    exp: i64,
    jti: String,
}

fn signed_client_assertion(client_id: &str, audience: &str, pem: &[u8]) -> Result<String> {
    let now = Utc::now().timestamp();
    Ok(encode(
        &Header::new(Algorithm::ES256),
        &ClientAssertion {
            iss: client_id,
            sub: client_id,
            aud: audience,
            iat: now,
            exp: now + 300,
            jti: Uuid::new_v4().to_string(),
        },
        &EncodingKey::from_ec_pem(pem)?,
    )?)
}

#[derive(Serialize)]
struct DpopClaims<'a> {
    jti: String,
    htm: &'a str,
    htu: &'a str,
    iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ath: Option<String>,
}

fn dpop_proof(
    method: &str,
    htu: &str,
    access_token: Option<&str>,
    public_jwk: &Value,
    pem: &[u8],
) -> Result<String> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("dpop+jwt".into());
    header.jwk = Some(serde_json::from_value::<Jwk>(public_jwk.clone())?);
    Ok(encode(
        &header,
        &DpopClaims {
            jti: Uuid::new_v4().to_string(),
            htm: method,
            htu,
            iat: Utc::now().timestamp(),
            ath: access_token.map(|token| URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))),
        },
        &EncodingKey::from_ec_pem(pem)?,
    )?)
}

async fn json_response(response: reqwest::Response, operation: &str) -> Result<Value> {
    let status = response.status();
    let body = response.text().await?;
    let json: Value = serde_json::from_str(&body)
        .with_context(|| format!("{operation} returned non-JSON: {body}"))?;
    if !status.is_success() {
        anyhow::bail!("{operation} failed ({status}): {json}");
    }
    Ok(json)
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("response omitted {field}"))
}

fn config_directory() -> Result<PathBuf> {
    let home = env::var_os("HOME").ok_or_else(|| anyhow!("HOME is not set"))?;
    Ok(PathBuf::from(home).join(".config/jusso"))
}

fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onboard_requires_explicit_terms_and_rejects_duplicates() {
        let base = vec![
            "--organization".into(),
            "Acme".into(),
            "--agent-id".into(),
            "treasury".into(),
        ];
        assert!(parse_options(base.clone()).is_err());
        let mut duplicate = base;
        duplicate.extend(["--agent-id".into(), "other".into(), "--accept-terms".into()]);
        assert!(parse_options(duplicate).is_err());
    }

    #[test]
    fn parses_child_agent_enrollment() {
        let options = parse_enroll_options(vec![
            "--enrollment-token".into(),
            "jso_enroll_secret".into(),
            "--display-name".into(),
            "Treasury worker".into(),
        ])
        .unwrap();
        assert_eq!(options.display_name, "Treasury worker");
        assert_eq!(options.api_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn parses_owner_driven_agent_creation() {
        let options = parse_create_agent_options(vec![
            "--profile".into(),
            "/tmp/owner.json".into(),
            "--agent-id".into(),
            "researcher".into(),
            "--display-name".into(),
            "Research agent".into(),
        ])
        .unwrap();
        assert_eq!(options.agent_id, "researcher");
        assert_eq!(options.enrollment_ttl_seconds, 900);
    }
}
