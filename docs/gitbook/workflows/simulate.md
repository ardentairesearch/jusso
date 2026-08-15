# Simulate Transaction

Use simulation to validate execution and estimate payable cost before submitting live execution.

## Endpoint

`POST /simulate`

## Authentication

`X-API-Key` required.

## Command

```bash
curl -X POST "$BASE_URL/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "target_contract": "0xTargetContract",
    "calldata": "0xCalldata",
    "value": "0"
  }'
```

## Success response

Status code: `200 OK`

Example:

```json
{
  "request_id": "your_request_id",
  "status": "pending",
  "smart_wallet_address": "0xAgentSmartWallet",
  "estimated_gas": 52000,
  "estimated_cost_usd": 0.23,
  "tx_hash": null,
  "message": "simulation succeeded"
}
```

## CLI equivalent

```bash
ardent simulate \
  --agent-id my-agent-001 \
  --chain ethereum \
  --target-contract 0xTargetContract \
  --calldata 0xCalldata \
  --value 0
```

See [Agent Integration](../agent-integration.md) for the one-line installer.

## Cost semantics

The estimate includes gas, markup, platform fee, and the simulated USDC
transfer to the chain's VerifyingPaymaster.

## Typical use

1. Call simulate first.
2. Validate gas and cost constraints.
3. Continue to execute only when output is acceptable.

## Batch simulation semantics

Simulation builds the same smart-wallet operation shape used by execution and
checks it before broadcast. Batch requests are simulated as a full ERC-4337
`executeBatch` UserOperation through the configured bundler, including
`eth_estimateUserOperationGas` where supported.

This means dependent call sequences such as `approve -> supply` are checked as
one atomic wallet operation instead of as independent calls.
