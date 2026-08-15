# Get Wallet

Use this endpoint to resolve or provision the smart wallet address for a specific agent.

## Endpoint

`GET /wallet`

## Authentication

`X-API-Key` required.

## Query parameters

1. `agent_id` required string. A stable identifier you choose for this agent. Any alphanumeric string, slug, or UUID works — for example `trading-bot-01`, `my-agent-001`, or a UUID. The platform provisions a dedicated smart wallet the first time it sees a new `agent_id` in your organization. Use the same value consistently so the wallet mapping stays stable across credential rotation.
2. `chain` optional string. Default is `ethereum`.

## Command

```bash
curl -G "$BASE_URL/wallet" \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode "agent_id=my-agent-001" \
  --data-urlencode "chain=ethereum"
```

## Success response

Status code: `200 OK`

Example:

```json
{
  "agent_id": "my-agent-001",
  "smart_wallet_address": "0x1234567890abcdef1234567890abcdef12345678",
  "deployed": false,
  "message": "Wallet is not yet deployed (counterfactual). You can still safely send ERC-20 tokens and native currency to 0x1234567890abcdef1234567890abcdef12345678."
}
```

## CLI equivalent

```bash
ardent wallet --agent-id my-agent-001 --chain ethereum
```

See [Agent Integration](../agent-integration.md) for the one-line installer.

## Practical usage

1. Call this once per new `(api_key, agent_id)` pair.
2. Fund the returned wallet if strategy needs token transfers.
3. Use same `agent_id` consistently so the wallet mapping remains stable.

With the hosted deterministic deployment, the same `(api_key, agent_id)` can resolve to the same counterfactual smart wallet address across Ethereum Sepolia, Base Sepolia, and Arbitrum Sepolia. Always pass the intended `chain` anyway, because balances, deployment state, gas, and protocol liquidity are chain-specific.
