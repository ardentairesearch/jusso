use jusso::config::{
    VIBENET_CHAIN_ID, VIBENET_DEFAULT_ACCOUNT, VIBENET_EXECUTION_TOKEN_ADDRESS, VIBENET_RPC_URL,
};
use serde_json::{json, Value};

async fn rpc(method: &str, params: Value) -> Value {
    let response = reqwest::Client::new()
        .post(VIBENET_RPC_URL)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        }))
        .send()
        .await
        .expect("VibeNet RPC request");
    assert!(response.status().is_success());
    let body: Value = response.json().await.expect("VibeNet RPC JSON");
    assert!(body.get("error").is_none(), "RPC error: {body}");
    body["result"].clone()
}

/// VibeNet is ephemeral and public-RPC availability is external, so this lane
/// is explicit rather than part of the hermetic default test suite.
#[tokio::test]
#[ignore = "requires the public ephemeral VibeNet RPC"]
async fn vibenet_profile_matches_the_live_chain() {
    let deployments: Value = reqwest::Client::new()
        .get("https://api.vibes.base.org/api/vibenet/contracts")
        .send()
        .await
        .expect("VibeNet contracts request")
        .error_for_status()
        .expect("VibeNet contracts response")
        .json()
        .await
        .expect("VibeNet contracts JSON");
    assert!(
        deployments["eip8130"]["DefaultAccount"]
            .as_str()
            .is_some_and(|address| address.eq_ignore_ascii_case(VIBENET_DEFAULT_ACCOUNT)),
        "configured DefaultAccount does not match the official live deployment"
    );
    assert!(
        deployments["usdv"]
            .as_str()
            .is_some_and(|address| address.eq_ignore_ascii_case(VIBENET_EXECUTION_TOKEN_ADDRESS)),
        "configured USDV does not match the official live deployment"
    );

    let chain_id = rpc("eth_chainId", json!([])).await;
    let expected_chain_id = format!("0x{VIBENET_CHAIN_ID:x}");
    assert_eq!(chain_id.as_str(), Some(expected_chain_id.as_str()));

    let code = rpc("eth_getCode", json!([VIBENET_DEFAULT_ACCOUNT, "latest"])).await;
    assert!(
        code.as_str().is_some_and(|code| code.len() > 2),
        "canonical DefaultAccount is not deployed"
    );

    let token_code = rpc(
        "eth_getCode",
        json!([VIBENET_EXECUTION_TOKEN_ADDRESS, "latest"]),
    )
    .await;
    assert!(
        token_code.as_str().is_some_and(|code| code.len() > 2),
        "Vibe USD is not deployed"
    );

    let symbol = rpc(
        "eth_call",
        json!([
            {
                "to": VIBENET_EXECUTION_TOKEN_ADDRESS,
                "data": "0x95d89b41"
            },
            "latest"
        ]),
    )
    .await;
    assert_eq!(decode_abi_string(symbol.as_str().unwrap()), "USDV");

    let decimals = rpc(
        "eth_call",
        json!([
            {
                "to": VIBENET_EXECUTION_TOKEN_ADDRESS,
                "data": "0x313ce567"
            },
            "latest"
        ]),
    )
    .await;
    assert_eq!(
        u8::from_str_radix(decimals.as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        6
    );
}

fn decode_abi_string(raw: &str) -> String {
    let bytes = hex::decode(raw.trim_start_matches("0x")).expect("ABI string hex");
    let offset = usize::try_from(ethers::types::U256::from_big_endian(&bytes[..32]))
        .expect("ABI string offset");
    let length = usize::try_from(ethers::types::U256::from_big_endian(
        &bytes[offset..offset + 32],
    ))
    .expect("ABI string length");
    String::from_utf8(bytes[offset + 32..offset + 32 + length].to_vec()).expect("ABI string UTF-8")
}
