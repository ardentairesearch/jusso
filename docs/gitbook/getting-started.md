# Getting Started

This section helps you complete a first successful integration quickly.

## 1. Prepare required values

Set these shell variables in your terminal.

```bash
BASE_URL="https://api.ardentresearch.xyz"
API_KEY="ard_live_your_api_key"
```

If you do not have an API key yet, request access first using the onboarding channel.

See [Request API Key](workflows/request-api-key.md).

## 2. Understand endpoint groups

The hosted API has two endpoint groups for users.

1. Public endpoints.
   1. `GET /health`
   2. `GET /feed/recent`
2. Credential-protected endpoints (API key or OAuth bearer token).
   1. `GET /wallet`
   2. `GET /wallet/balance`
   3. `POST /simulate`
   4. `POST /execute`
   5. `GET /status/:id`

## 3. Understand execution fees

Normal executions atomically transfer a USDC fee from the agent smart wallet
to the chain's VerifyingPaymaster. Ardent sponsors the native gas.

Independent wallets can pay through x402 V2 at `POST /x402/execute`.

Detailed behavior is in [Execution Fees](execution-fees.md).

## 4. First end to end path

Use this sequence for first validation.

1. Request API key access.
1. Choose an `agent_id` — any stable string you pick, such as `my-agent-001` or `trading-bot`. No registration needed; the platform provisions a smart wallet automatically on first use.
1. Get wallet address for your agent ID.
1. Fund wallet if your strategy needs tokens.
1. Simulate execution.
1. Execute transaction.
1. Poll status until terminal state.

You can run every step with raw curl or with the `ardent` CLI. See [Agent Integration](agent-integration.md) for the one-line installer and CLI reference.

## 5. Terminal states

A request eventually reaches one of these terminal states.

1. `confirmed`
2. `reverted`
3. `failed`

## 6. Supported chain names in request payloads

Use one of:

1. `ethereum`
2. `base`
3. `arbitrum`

Aliases like `eth` and `arb` are accepted by server side chain parsing, but using canonical names is recommended for clean client code.

## 7. Testnet token details for Sepolia users

| Payload chain | Test network | USDC |
| --- | --- | --- |
| `ethereum` | Ethereum Sepolia | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` |
| `base` | Base Sepolia | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| `arbitrum` | Arbitrum Sepolia | `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d` |

Circle faucet USDC is available at `https://faucet.circle.com`; select the
matching Sepolia network before funding.

For complete testnet instructions, see [Testnet Guide](testnet-guide.md).
