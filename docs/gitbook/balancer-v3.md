# Balancer V3 Ethereum Sepolia

Ardent exposes typed Balancer V3 swaps and liquidity actions on Ethereum
Sepolia using the `chain: "ethereum"` label.

## Supported actions

- Exact-input swap
- Exact-output swap
- Live swap quote with automatic slippage limit
- Automatic pair-compatible pool discovery and best-quote selection
- Unbalanced add liquidity, including balanced and single-token additions
- Proportional remove liquidity by exact BPT input
- Liquidity quotes with automatic slippage limits
- Pool state and registered-token read
- Agent BPT and pool-token balance read

Balancer pool addresses and token sets are not hardcoded. For swaps, the API
discovers pair-compatible pools, verifies each candidate against the Balancer
V3 Vault, and selects the best live quote. An explicit pool address pins the
route. Liquidity actions remain pool-address driven.

## Contracts

| Contract | Ethereum Sepolia address |
|---|---|
| Router V2 | `0x5e315f96389C1aaF9324D97d3512ae1e0Bf3C21a` |
| Vault | `0xbA1333333333a1BA1108E8412f11850A5C319bA9` |
| Vault Explorer V2 | `0xC82E329C832CAcc8DA65dbB57ac72B068e0CEb9B` |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` |

These addresses come from Balancer's official deployment repository.

## Discover or inspect pools

Discover pair-compatible pools:

```bash
ardent balancer-pools \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken
```

`balancer-pools` merges Balancer's official API metadata with paginated
`PoolRegistered` events from the Vault, so pools missing from the API are still
discoverable. Every pair-compatible result is verified against live Vault
state. `balancer-pool` inspects one explicit pool address:

```bash
ardent balancer-pool \
  --pool 0xYourBalancerV3Pool
```

The response includes:

- Pool registration, initialization, pause, and recovery-mode state
- BPT name, symbol, decimals, and total supply
- Registered token addresses in Vault order
- Token metadata and pool balances
- Static swap fee

A registered pool can still reject a swap because of pool-specific hooks or
rules. For example, an LBP may disable swaps outside its active sale window.
Always request a quote and simulate the action.

## External pool discovery

The simplest option is Balancer's testnet application:

`https://test.balancer.fi/`

For programmatic discovery, query Balancer's official GraphQL API and filter for
Sepolia V3 pools:

```bash
curl -X POST "https://api-v3.balancer.fi/graphql" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query Pools($where: GqlPoolFilter) { poolGetPools(first: 50, where: $where) { address name symbol type protocolVersion chain poolTokens { address symbol decimals index } dynamicData { totalLiquidity swapFee } } }",
    "variables": {
      "where": {
        "chainIn": ["SEPOLIA"],
        "protocolVersionIn": [3]
      }
    }
  }'
```

The deployment-address repository lists shared Balancer contracts and pool
factories, but it is not a complete list of pools created by those factories.

## Read wallet balances

```bash
ardent balancer-balances \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool
```

This returns the wallet's BPT balance and wallet balances for every registered
token in the selected pool.

## Add liquidity

Provide one `--amount-in TOKEN_ADDRESS=RAW_AMOUNT` value for each token you
want to deposit. The server reads the pool's canonical token order, quotes the
expected BPT output, derives a minimum, and fully simulates the approval and
Router batch.

Two-token example:

```bash
ardent balancer-add-liquidity-quote \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --amount-in 0xFirstPoolToken=1000000 \
  --amount-in 0xSecondPoolToken=1000000

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
```

You may supply only one registered token, but an unbalanced addition generally
has more price impact than depositing at the pool's current ratio. One
add-liquidity operation supports up to three deposited token addresses so its
approval, Router, and cleanup calls remain within the atomic batch limit.

## Remove liquidity

Proportional removal burns an exact BPT amount and returns every registered pool
token. Read `balancer-balances` first to obtain the wallet's raw BPT balance.

```bash
ardent balancer-remove-liquidity-quote \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000

ardent balancer-remove-liquidity-simulate \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000

ardent balancer-remove-liquidity \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000
```

The quote derives a minimum for every output token. Advanced callers may supply
repeatable `--min-amount-out TOKEN_ADDRESS=RAW_AMOUNT` values instead.
Execution atomically resets the BPT allowance, approves the Router for the exact
BPT input, removes liquidity, and clears the remaining allowance.

## Quote an exact-input swap

All amounts are raw token base units.

```bash
ardent balancer-quote \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000 \
  --slippage-bps 100
```

The response returns the selected `pool_address`, `pool_selection`, candidate
counts, `quoted_amount_raw`, `limit_raw`, and `deadline`. Pass the returned pool
with `--pool` on later calls when you need to pin that exact route.
For `exact_in`, `limit_raw` is the minimum output amount.

## Quote an exact-output swap

```bash
ardent balancer-quote \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_out \
  --amount-raw 1000000 \
  --slippage-bps 100
```

For `exact_out`, `amount_raw` is the exact desired output and `limit_raw` is
the maximum input amount.

## Simulate and execute

```bash
ardent balancer-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000 \
  --slippage-bps 100

ardent balancer-swap \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000 \
  --slippage-bps 100
```

You may provide `--limit-raw` to bypass automatic slippage calculation. You may
also provide a future `--deadline` Unix timestamp; otherwise the server uses a
deadline twenty minutes from request handling.

## How token approval works

Balancer V3's retail Router pulls swap input through Permit2. Ardent compiles
one atomic smart-wallet batch:

1. Reset the ERC-20 Permit2 allowance to zero
2. `ERC20.approve(Permit2, maxInput)`
3. `Permit2.approve(tokenIn, Router, maxInput, deadline)`
4. `Router.swapSingleTokenExactIn(...)` or `swapSingleTokenExactOut(...)`
5. Clear the Router allowance in Permit2
6. Clear the ERC-20 Permit2 allowance

The complete batch is simulated as a UserOperation before execution. The
approval cleanup occurs atomically after a successful swap.

## Current scope

The Balancer V3 integration covers single-pool swaps, unbalanced liquidity
addition, and proportional liquidity removal. Multi-hop Batch Router swaps,
single-token removal, boosted pools, buffers, and gauge actions are not exposed
yet.
