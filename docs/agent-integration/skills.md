# AI Agent Blockchain Execution Skills

This file covers everything needed to get started with AI Agent Blockchain Execution API — from initial install through to running autonomous agents. It serves as both a human setup guide and a runtime playbook for LLM agents (ChatGPT, Grok, Claude, etc.).

---

## Part 1 — Human Setup

### 1) Install CLI

```bash
curl -fsSL https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration/install.sh | bash
```

This installs an `ardent` command in `~/.local/bin` and downloads runtime files (MCP server, OpenAPI spec) into `~/.ardent/`.

### 2) Set credentials

```bash
export ARDENT_API_KEY="your_api_key"
```

### 3) Quick commands

```bash
ardent --version
ardent health
ardent feed                             # public activity feed
ardent wallet         --agent-id my-agent-001 --chain ethereum
ardent wallet-balance --agent-id my-agent-001 --chain ethereum
ardent aave-balances --agent-id my-agent-001
ardent compound-borrow-capacity --agent-id my-agent-001
ardent morpho-position --agent-id my-agent-001
ardent gmx-create-order-simulate --agent-id my-agent-001 --body-file ./gmx-order.json
ardent simulate --agent-id my-agent-001 --chain ethereum --target-contract 0xTargetContract --calldata 0xCalldata --value 0
ardent execute --agent-id my-agent-001 --chain ethereum --target-contract 0xTargetContract --calldata 0xCalldata --value 0
ardent status --request-id your_request_id
```

### 4) Update later

```bash
ardent self-update              # updates CLI plus ~/.ardent runtime files
ardent self-update --cli-only   # updates only the CLI
```

### Optional: MCP server for AI tool runtimes

The installer registers Ardent in Codex by default and automatically patches Claude Desktop, ChatGPT Desktop, Cursor, and Windsurf when detected. Just restart the app after install.

> **After install, open the patched config file and replace the `ARDENT_API_KEY` placeholder with your real key before restarting the app.**
> The installer prints the exact path of every file it patches.

To register manually (or for any other MCP-compatible AI), point it at:

```bash
python3 ~/.ardent/mcp_server.py
```

---

## Part 2 — Agent Playbook

_This section is written for LLM agents that have direct HTTP/tool access to Ardent API._

### Environment

- API base URL: `https://api.ardentresearch.xyz`
- Required auth header: `X-API-Key`

### Variables

```bash
BASE_URL="https://api.ardentresearch.xyz"
API_KEY="your_api_key"
AGENT_ID="my-agent-001"
REQUEST_ID="your_request_id"
```

### Core Execution Flow

1. Resolve wallet with `GET /wallet`.
2. Confirm funding with `GET /wallet/balance` — verify the wallet holds enough tokens before executing.
3. Simulate with `POST /simulate`.
4. Execute with `POST /execute`.
5. Track completion with `GET /status/:id` (or callback webhook if configured).

### Typed Aave V3 Sepolia Flow

Use typed protocol tools for Aave V3 Sepolia actions instead of manually
encoding calldata. Before changing state, read balances and position:

```bash
curl -X GET "$BASE_URL/protocols/aave-v3/balances?agent_id=$AGENT_ID&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

```bash
curl -X GET "$BASE_URL/protocols/aave-v3/position?agent_id=$AGENT_ID&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

For supply, the API compiles the request into an atomic `approve -> Pool.supply`
ERC-4337 batch and runs full UserOperation simulation.

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

Use the same typed flow for withdrawing and repaying:

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

Read Aave account data before borrowing or making risk-sensitive decisions:

```bash
curl -X GET "$BASE_URL/protocols/aave-v3/position?agent_id=$AGENT_ID&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

Borrow uses a projected health-factor guard before simulation/execution. The
default minimum projected health factor is `1.05`; callers can set a stricter
floor with `min_health_factor`, which must be at least `1.0`.

```bash
curl -X POST "$BASE_URL/protocols/aave-v3/borrow/simulate" \
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

Supported assets: `AAVE`, `DAI`, `EURS`, `GHO`, `LINK`, `USDC`, `USDT`,
`WBTC`, `WETH`. Human-readable `amount` values may be JSON strings or numbers;
prefer strings when exact decimal precision matters. Use `amount_raw` strings
for exact base units.
Withdraw, repay, and borrow support `amount: "max"`. Repay max resolves to the
smaller of selected-rate debt and wallet token balance. Borrow max resolves to
the largest amount allowed by available borrows and the projected health-factor
floor.

### Typed Compound III Base Sepolia Flow

Use typed Compound III tools for Base Sepolia Comet actions instead of manually
encoding Comet calldata. Base Sepolia supports the `usdc` market at
`0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017` and the `weth` market at
`0x61490650AbaA31393464C3f34E8B29cd1C44118E`.

Read balances and position before planning an action:

```bash
curl -X GET "$BASE_URL/protocols/compound-v3/balances?agent_id=$AGENT_ID&chain=base" \
  -H "X-API-Key: $API_KEY"
```

```bash
curl -X GET "$BASE_URL/protocols/compound-v3/position?agent_id=$AGENT_ID&chain=base" \
  -H "X-API-Key: $API_KEY"
```

Supply compiles to an atomic `approve -> Comet.supply` ERC-4337 batch and runs
full UserOperation simulation.

```bash
curl -X POST "$BASE_URL/protocols/compound-v3/supply/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "base",
    "asset": "USDC",
    "amount": "1.25"
  }'
```

Withdraw and borrow compile to `Comet.withdraw(asset, amount)`. Repay compiles
to `approve -> Comet.supply(base, amount)`.

```bash
curl -X POST "$BASE_URL/protocols/compound-v3/repay/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "base",
    "asset": "USDC",
    "amount": "max"
  }'
```

Use `USDC`, `base`, `WETH`, or a Comet-supported token address as `asset`.
Human-readable `amount` values may be JSON strings or numbers. For raw token
addresses and exact base units, use an `amount_raw` string. Supply, withdraw,
and repay support `amount: "max"`; borrow requires an explicit `amount` or
`amount_raw`. Include
`market: "usdc"` or `market: "weth"` when the asset alone does not identify the
intended market.

### Typed Morpho Blue Base Sepolia Flow

Morpho actions are isolated by market ID. Inspect the market and position before
planning a write:

```bash
ardent morpho-markets --loan-token 0xYourLoanToken --collateral-token 0xYourCollateralToken
ardent morpho-market
ardent morpho-position --agent-id my-agent-001
```

Use the action-specific simulation tool before execution:

```bash
ardent morpho-supply-collateral-simulate --agent-id my-agent-001 --amount 0.01
ardent morpho-borrow-simulate --agent-id my-agent-001 --amount 5 --min-health-factor 1.10
ardent morpho-repay-simulate --agent-id my-agent-001 --amount max
```

The default market is Base Sepolia USDC/WETH at 86% LLTV. For another market,
pass its bytes32 ID as `market_id` or `--market-id`; Ardent resolves and verifies
the complete parameter tuple on-chain. Never infer that a permissionlessly
created market is trustworthy merely because it exists.

### Typed Balancer V3 Ethereum Sepolia Flow

Balancer V3 swaps can discover and quote pair-compatible pools automatically.
Liquidity actions remain pool-address driven:

```bash
curl -X GET "$BASE_URL/protocols/balancer-v3/pools?chain=ethereum&token_in=0xFirstPoolToken&token_out=0xSecondPoolToken" \
  -H "X-API-Key: $API_KEY"
```

Request a live quote before simulation:

```bash
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

Then simulate the same body at `/protocols/balancer-v3/swap/simulate`. The
service verifies the pool and tokens, quotes the Router, derives `limit_raw`
when omitted, and compiles allowance reset, ERC-20 Permit2 approval, Permit2
Router approval, Router swap, and allowance cleanup as one atomic UserOperation
batch.

Use raw integer amounts only. For `exact_in`, `amount_raw` is input and
`limit_raw` is minimum output. For `exact_out`, `amount_raw` is output and
`limit_raw` is maximum input. A registered pool may still reject quotes because
of hook rules, such as an inactive LBP sale window.

For liquidity, use `ardent_balancer_add_liquidity_quote`, simulate, then execute
with `ardent_balancer_add_liquidity_execute`. Supply `amounts_in` as token
address and raw amount objects; the API reorders them using the Vault token
order. Up to three deposited token addresses are supported per operation. Use
`ardent_balancer_remove_liquidity_quote`, simulate, then execute with
`ardent_balancer_remove_liquidity_execute` to burn an exact BPT amount and
receive every pool token proportionally.

### Typed Uniswap V4 Ethereum Sepolia Flow

Use automatic selection by default: provide the pair and amount while omitting
fee, tick spacing, and hooks. The API discovers matching pool keys, validates
initialization, and selects the best successful quote.

```bash
curl -X POST "$BASE_URL/protocols/uniswap-v4/swap/quote" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "ethereum",
    "token_in": "0xInputCurrency",
    "token_out": "0xOutputCurrency",
    "hook_data": "0x",
    "swap_kind": "exact_in",
    "amount_raw": "1000000",
    "slippage_bps": 100
  }'
```

Then call `ardent_uniswap_v4_swap_simulate` with the same body. Execute through
`ardent_uniswap_v4_swap_execute` only after successful simulation and explicit
user approval. Use the zero address for native ETH. Automatic mode excludes
hook pools by default. Supply `fee`, `tick_spacing`, and optional `hooks` only
when intentionally forcing an explicit pool key.

### Typed GMX V2 Arbitrum Sepolia Flow

Use typed protocol tools for GMX V2 Arbitrum Sepolia orders instead of manually
encoding `ExchangeRouter` calldata. For create-order actions, the API compiles
`approve -> ExchangeRouter.multicall(sendWnt, sendTokens, createOrder)` and
runs full UserOperation simulation.

Create a market increase simulation:

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

Create a market swap simulation:

For `market_swap`, `market` is treated as the single GMX swap-path market. The
platform encodes the on-chain GMX order `market` field as `address(0)`, which is
required for GMX swap orders.

```bash
curl -X POST "$BASE_URL/protocols/gmx-v2/orders/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "arbitrum",
    "order_type": "market_swap",
    "market": "0xYourGmxMarketToken",
    "initial_collateral_token": "0xYourInputToken",
    "initial_collateral_delta_amount_raw": "1000000",
    "min_output_amount_raw": "1",
    "execution_fee_raw": "1000000000000000"
  }'
```

Cancel an order:

```bash
curl -X POST "$BASE_URL/protocols/gmx-v2/orders/cancel/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $API_KEY" \
  -d '{
    "agent_id": "my-agent-001",
    "chain": "arbitrum",
    "order_key": "0xYourBytes32OrderKey"
  }'
```

Agents should treat GMX values as raw integers: token amounts use token base
units, while size and price values use GMX 30-decimal precision. The agent smart
wallet must hold the collateral/input token and enough Arbitrum Sepolia ETH for
the GMX execution fee.

### Canonical curl Commands

#### Health

```bash
curl -X GET "$BASE_URL/health"
```

#### Get Wallet

```bash
curl -X GET "$BASE_URL/wallet?agent_id=$AGENT_ID&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

#### Get Wallet Balance

```bash
curl -X GET "$BASE_URL/wallet/balance?agent_id=$AGENT_ID&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

#### Simulate

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

#### Execute

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

#### Status

```bash
curl -X GET "$BASE_URL/status/$REQUEST_ID" \
  -H "X-API-Key: $API_KEY"
```

### Guardrails For Agents

1. Always use placeholders like `your_request_id` in generated examples.
2. Prefer `simulate` before `execute` and inspect `execution_fee_raw`.
3. Use `GET /wallet/balance` to verify enough chain USDC and protocol assets.
4. Treat `GET /status/:id` as source of truth for terminal result (`confirmed`, `failed`, `reverted`).
