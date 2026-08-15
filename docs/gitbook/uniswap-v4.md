# Uniswap V4 Ethereum Sepolia

Ardent exposes typed, single-pool Uniswap V4 swaps on Ethereum Sepolia using
the `chain: "ethereum"` label.

## Supported actions

- Exact-input and exact-output swaps
- Automatic pool discovery and best-quote selection
- Live quotes with automatic slippage limits
- Full UserOperation simulation before execution
- Pool state reads from the official V4 StateView
- Agent balance reads for both pool currencies
- Native ETH and ERC-20 currencies
- Hook-enabled pools when the caller supplies the required hook address and data

## Contracts

| Contract | Ethereum Sepolia address |
|---|---|
| PoolManager | `0xE03A1074c86CFeDd5C142C4F04F1a1536e203543` |
| Universal Router | `0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b` |
| StateView | `0xe1dd9c3fa50edb962e442f60dfbc432e24537e4c` |
| Quoter | `0x61b3f2011a92d183c7dbadbda940a7555ccf9227` |
| Permit2 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` |

These are the official Uniswap V4 Sepolia deployments.

## Automatic pool selection

For the normal workflow, provide only the two currencies, amount, and swap
kind. Do not provide `fee`, `tick_spacing`, or `hooks`.

Ardent reads matching `Initialize` events, verifies each candidate through the
official StateView, requests a live quote from each initialized no-hook pool,
and selects:

- The highest output for an exact-input swap
- The lowest input for an exact-output swap

Hook pools are excluded by default because they can implement custom behavior
and may require pool-specific hook data. Advanced callers can enable them with
`--include-hooked-pools`.

```bash
ardent uniswap-v4-quote \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --swap-kind exact_in \
  --amount-raw 1000000
```

The quote response reports `pool_selection`, the selected `pool_id`, `fee`,
`tick_spacing`, `hooks`, and candidate counts.

Automatic simulation and execution discover and quote pools again so they use
the best route available at that moment. To pin a quoted route, pass the
returned `fee`, `tick_spacing`, and `hooks` as the explicit pool key in the
later request.

## Pool keys, not pool addresses

A V4 pool does not have its own contract address. Every pool lives inside the
singleton `PoolManager` and is identified by its complete pool key:

1. Two currency addresses
2. Fee
3. Tick spacing
4. Hooks contract

Changing any one field identifies a different pool. Automatic mode discovers
these fields. Explicit mode remains available when an advanced caller wants to
force one known key.

Use the zero address for native ETH:

`0x0000000000000000000000000000000000000000`

## Discover pools

```bash
ardent uniswap-v4-pools \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency
```

This lists matching no-hook pool keys and their current on-chain state. Add
`--include-hooked-pools` to include hook-enabled pools.

## Inspect one explicit pool

```bash
ardent uniswap-v4-pool \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency \
  --fee 3000 \
  --tick-spacing 60 \
  --hooks 0xPoolHooksOrZeroAddress
```

The response includes the derived pool ID, canonical currency order, current
sqrt price, tick, protocol fee, LP fee, and liquidity active at the current
tick. A zero current-tick liquidity value does not by itself prove a swap is
impossible; the live Quoter determines swap viability.

This endpoint inspects one supplied pool key. Use `uniswap-v4-pools` or
automatic quote mode when the key is not already known.

## Read currency balances

```bash
ardent uniswap-v4-balances \
  --agent-id my-agent-001 \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency
```

Native ETH metadata and balance handling are built in. ERC-20 metadata is read
from each token contract, with an address label used when optional token
metadata is unavailable.

## Quote a swap

All amounts are raw base-unit integer strings.

```bash
ardent uniswap-v4-quote \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --swap-kind exact_in \
  --amount-raw 1000000 \
  --slippage-bps 100
```

For `exact_in`, `amount_raw` is the exact input and `limit_raw` is the minimum
output. For `exact_out`, `amount_raw` is the exact output and `limit_raw` is the
maximum input. The server derives `limit_raw` from the live Quoter result when
it is omitted.

To force a specific pool, add `--fee`, `--tick-spacing`, and optionally
`--hooks`. Hook-enabled pools may require non-empty `--hook-data`.

## Simulate and execute

```bash
ardent uniswap-v4-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent uniswap-v4-swap \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --swap-kind exact_in \
  --amount-raw 1000000
```

Execution always resolves a fresh quote and runs the same full-bundle
simulation path before submitting the UserOperation.

## Approval and native ETH behavior

For ERC-20 input, Ardent atomically resets and grants bounded ERC-20 and
Permit2 allowances, calls the Universal Router, and clears both allowance
layers after a successful swap.

Native ETH input requires no token approval. Exact-output swaps send the
maximum input to the Router and include an explicit sweep command that returns
unused ETH to the smart wallet.

## Current scope

The integration discovers and compares direct single-pool routes for the
requested pair. It does not yet perform multi-hop routing, split routing,
liquidity position management, or pool initialization.
