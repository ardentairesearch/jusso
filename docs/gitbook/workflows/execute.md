# Execute Transaction

This endpoint submits a transaction request for execution.

## Endpoint

`POST /execute`

## Authentication

1. `X-API-Key` required.
2. No payment header is required. The execution fee is included atomically.

## Request shapes

Two request shapes are supported.

### Single call shape

```json
{
  "agent_id": "my-agent-001",
  "chain": "ethereum",
  "target_contract": "0xTargetContract",
  "calldata": "0xCalldata",
  "value": "0",
  "strategy_id": "optional-strategy-id",
  "callback_url": "https://your-system.example.com/webhook/execution"
}
```

### Batch call shape

```json
{
  "agent_id": "my-agent-001",
  "chain": "ethereum",
  "batch_calls": [
    {
      "target_contract": "0xToken",
      "value": "0",
      "calldata": "0xApproveCalldata"
    },
    {
      "target_contract": "0xDex",
      "value": "0",
      "calldata": "0xSwapCalldata"
    }
  ],
  "strategy_id": "approve-and-swap",
  "callback_url": "https://your-system.example.com/webhook/execution"
}
```

Use one shape at a time for clean client behavior.

## Execution-fee tokens

USDC is the only accepted execution-fee token.

| Payload chain | USDC |
| --- | --- |
| `ethereum` | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` |
| `base` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| `arbitrum` | `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d` |

Circle faucet USDC is available at `https://faucet.circle.com`.

## First execute command

```bash
curl -X POST "$BASE_URL/execute" \
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

This constructs and simulates one atomic batch containing the USDC transfer to
the VerifyingPaymaster followed by the requested protocol calls.

## Success response

Status code: `200 OK`

Example:

```json
{
  "request_id": "your_request_id",
  "status": "queued",
  "smart_wallet_address": "0xAgentSmartWallet",
  "estimated_gas": 52000,
  "estimated_cost_usd": 0.25,
  "tx_hash": null,
  "message": "execution queued"
}
```

## CLI equivalent

```bash
ardent execute \
  --agent-id my-agent-001 \
  --chain ethereum \
  --target-contract 0xTargetContract \
  --calldata 0xCalldata \
  --value 0
```

For manual payment re-submit after `402`:

```bash
ardent execute \
  --agent-id my-agent-001 \
  --chain ethereum \
  --target-contract 0xTargetContract \
  --calldata 0xCalldata \
  --value 0 \
  --proof-request-id your_request_id \
  --proof-payer 0xYourPayer \
  --proof-token USDC \
  --proof-chain ethereum \
  --proof-tx-hash 0xYourPaymentTxHash
```

See [Agent Integration](../agent-integration.md) for the one-line installer.

## Aave V3 Sepolia supply

For testnet Aave V3 supply actions, prefer the typed protocol endpoint instead
of manually encoding calldata.

For the full Aave command/reference page, including reserve balances and test asset funding, see [Aave V3 Sepolia](../aave-v3.md).

Simulate:

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/supply/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "asset": "USDC",
    "amount": "1.25"
  }'
```

Execute:

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/supply" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "asset": "USDC",
    "amount": "1.25"
  }'
```

CLI equivalent:

```bash
ardent aave-supply-simulate \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount 1.25

ardent aave-supply \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount 1.25
```

For manual payment re-submit after `402`:

```bash
ardent aave-supply \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount 1.25 \
  --proof-request-id your_request_id \
  --proof-payer 0xYourPayer \
  --proof-token USDC \
  --proof-chain ethereum \
  --proof-tx-hash 0xYourPaymentTxHash
```

The adapter compiles the request into an atomic `approve -> Pool.supply` batch
for the agent's ERC-4337 smart wallet and uses full UserOperation simulation.
Human-readable `amount` values may be JSON strings or numbers; prefer strings
when exact decimal precision matters. Use an `amount_raw` string when the
caller already has exact token base units.

Withdraw:

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/withdraw" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "asset": "USDC",
    "amount": "max"
  }'
```

CLI equivalent:

```bash
ardent aave-withdraw-simulate \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max

ardent aave-withdraw \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max
```

Repay:

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/repay" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "asset": "USDC",
    "amount": "max",
    "interest_rate_mode": 2
  }'
```

CLI equivalent:

```bash
ardent aave-repay-simulate \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max

ardent aave-repay \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max
```

Repay `max` resolves to the smaller of selected-rate debt and the wallet's
underlying token balance before the normal approve/repay batch is simulated.

Borrow:

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/borrow" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "asset": "USDC",
    "amount": "max",
    "interest_rate_mode": 2,
    "min_health_factor": "1.10"
  }'
```

CLI equivalent:

```bash
ardent aave-borrow-simulate \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max \
  --min-health-factor 1.10

ardent aave-borrow \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max \
  --min-health-factor 1.10
```

Borrow checks projected health factor using Aave account data and oracle price
before the normal execution simulation. The default minimum projected health
factor is `1.05`, and custom values must be at least `1.0`. Borrow `max`
resolves to the largest amount allowed by available borrows and that projected
health-factor floor.

Read position:

```bash
curl -X GET "$BASE_URL/protocols/aave-v3/position?agent_id=my-agent-001&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

CLI equivalent:

```bash
ardent aave-balances --agent-id my-agent-001
ardent aave-position --agent-id my-agent-001
```

## Morpho Blue Base Sepolia

Morpho actions are keyed by a market ID. The examples below use Ardent's
default Base Sepolia USDC/WETH 86% LLTV market.

```bash
curl -X GET "$BASE_URL/protocols/morpho/position?agent_id=my-agent-001&chain=base" \
  -H "X-API-Key: $ARDENT_API_KEY"

curl -X POST "$BASE_URL/protocols/morpho/supply-collateral/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ARDENT_API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "base",
    "amount": "0.01"
  }'

curl -X POST "$BASE_URL/protocols/morpho/borrow/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $ARDENT_API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "base",
    "amount": "5"
  }'
```

CLI equivalents:

```bash
ardent morpho-markets \
  --loan-token 0xYourLoanToken \
  --collateral-token 0xYourCollateralToken
ardent morpho-market
ardent morpho-position --agent-id my-agent-001
ardent morpho-supply-collateral-simulate --agent-id my-agent-001 --amount 0.01
ardent morpho-borrow-simulate --agent-id my-agent-001 --amount 5 --min-health-factor 1.10
ardent morpho-repay-simulate --agent-id my-agent-001 --amount max
ardent morpho-withdraw-collateral-simulate --agent-id my-agent-001 --amount 0.001
```

Read [Morpho Blue Base Sepolia](../morpho.md) for market selection, all
commands, amount behavior, and safety considerations.

## Balancer V3 Ethereum Sepolia

Balancer V3 swaps and liquidity actions should use the typed endpoints instead
of manually encoding Permit2 and Router calls. See
[Balancer V3 Ethereum Sepolia](../balancer-v3.md) for the full reference.

Discover pools or request an automatically routed quote:

```bash
curl -X GET "$BASE_URL/protocols/balancer-v3/pools?chain=ethereum&token_in=0xFirstPoolToken&token_out=0xSecondPoolToken" \
  -H "X-API-Key: $API_KEY"

curl -X POST "$BASE_URL/protocols/balancer-v3/swap/quote" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "token_in": "0xFirstPoolToken",
    "token_out": "0xSecondPoolToken",
    "swap_kind": "exact_in",
    "amount_raw": "1000000",
    "slippage_bps": 100
  }'
```

CLI equivalents:

```bash
ardent balancer-pool --pool 0xYourBalancerV3Pool
ardent balancer-pools --token-in 0xFirstPoolToken --token-out 0xSecondPoolToken

ardent balancer-quote \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-swap \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-add-liquidity-simulate \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --amount-in 0xFirstPoolToken=1000000 \
  --amount-in 0xSecondPoolToken=1000000

ardent balancer-add-liquidity \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --amount-in 0xFirstPoolToken=1000000 \
  --amount-in 0xSecondPoolToken=1000000

ardent balancer-remove-liquidity-simulate \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000

ardent balancer-remove-liquidity \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000
```

The adapter resets existing approval, grants bounded ERC-20 and Permit2
allowances, executes the Router swap, then clears both allowance layers in one
atomic batch. The server derives the limit from a live Router quote when
`limit_raw` is omitted, then runs the normal full UserOperation simulation.
Liquidity additions use the same bounded approval and cleanup pattern.
They support up to three deposited token addresses per operation. Proportional
removals use an exact temporary BPT allowance for the Router and clear it after
the removal inside the same atomic batch.

## Uniswap V4 Ethereum Sepolia

Uniswap V4 pools are identified by a complete pool key, not a pool contract
address. Ardent discovers matching keys and selects the best successful quote
when pool-key fields are omitted. See
[Uniswap V4 Ethereum Sepolia](../uniswap-v4.md) for the complete reference.

```bash
curl -X POST "$BASE_URL/protocols/uniswap-v4/swap/quote" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "token_in": "0xInputCurrency",
    "token_out": "0xOutputCurrency",
    "swap_kind": "exact_in",
    "amount_raw": "1000000",
    "slippage_bps": 100
  }'
```

CLI equivalents:

```bash
ardent uniswap-v4-pool \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency \
  --fee 3000 \
  --tick-spacing 60 \
  --hooks 0xPoolHooksOrZeroAddress

ardent uniswap-v4-pools \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency

ardent uniswap-v4-quote \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --amount-raw 1000000

ardent uniswap-v4-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --amount-raw 1000000

ardent uniswap-v4-swap \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --amount-raw 1000000
```

Use the zero address for native ETH. ERC-20 input uses bounded temporary
Permit2 approvals that are cleared in the same atomic batch.

## GMX V2 Arbitrum Sepolia

For GMX V2, prefer the typed protocol endpoints instead of manually encoding
the `ExchangeRouter` calldata. For the full GMX command/reference page, see
[GMX V2 Arbitrum Sepolia](../gmx-v2.md).

Create-order simulation:

```bash
curl -X POST "$BASE_URL/protocols/gmx-v2/orders/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "arbitrum",
    "order_type": "market_increase",
    "market": "0xYourGmxMarketToken",
    "initial_collateral_token": "0xYourCollateralToken",
    "initial_collateral_delta_amount_raw": "1000000",
    "size_delta_usd_raw": "50000000000000000000000000000000000",
    "acceptable_price_raw": "30000000000000000000000000000000000000000",
    "execution_fee_raw": "1000000000000000",
    "is_long": true
  }'
```

CLI equivalent:

```bash
ardent gmx-create-order-simulate \
  --agent-id my-agent-001 \
  --order-type market_increase \
  --market 0xYourGmxMarketToken \
  --initial-collateral-token 0xYourCollateralToken \
  --initial-collateral-delta-amount-raw 1000000 \
  --size-delta-usd-raw 50000000000000000000000000000000000 \
  --acceptable-price-raw 30000000000000000000000000000000000000000 \
  --execution-fee-raw 1000000000000000 \
  --long

ardent gmx-create-order --agent-id my-agent-001 --body-file ./gmx-order.json
```

Cancel-order CLI equivalent:

```bash
ardent gmx-cancel-order-simulate \
  --agent-id my-agent-001 \
  --order-key 0xYourBytes32OrderKey

ardent gmx-cancel-order \
  --agent-id my-agent-001 \
  --order-key 0xYourBytes32OrderKey
```

The adapter compiles create-order requests into an atomic
`approve -> ExchangeRouter.multicall(sendWnt, sendTokens, createOrder)` bundle
for the agent's ERC-4337 smart wallet. `execution_fee_raw` is paid as ETH value
to the GMX router call, so the smart wallet must hold enough Arbitrum Sepolia
ETH for the GMX keeper fee.

## Testnet execution tips

1. Use `chain: "ethereum"` for Sepolia testnet execution flow.
2. Keep enough USDC in the smart wallet for the simulated execution fee.
3. Keep payment and execute requests tied to the same `agent_id` context.
