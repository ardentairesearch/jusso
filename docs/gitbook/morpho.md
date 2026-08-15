# Morpho Blue Base Sepolia

Ardent exposes typed Morpho Blue lending and borrowing actions on Base Sepolia using `chain: "base"`.

Morpho markets are permissionless and isolated. A market is identified by the hash of its loan token, collateral token, oracle, interest-rate model, and LLTV. Always inspect a market before using it.

## Contracts and default market

| Item | Address or ID |
| --- | --- |
| Morpho Blue | `0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb` |
| Default USDC/WETH 86% LLTV market | `0x6143c1e52ed45fb9a0551b349abb4a1b8c5962dd39545ac235a9c98610bf97da` |
| Loan token | Base Sepolia USDC, `0x036CbD53842c5426634e7929541eC2318f3dCF7e` |
| Collateral token | Base Sepolia WETH, `0x4200000000000000000000000000000000000006` |

The default market is provided for convenience and had a correctly scaled,
responsive ETH/USD feed when checked on July 4, 2026; it is not an official
Morpho endorsement or allowlist. Pass
`--market-id` to use any other created Base Sepolia market. Ardent resolves its
immutable parameters directly from `Morpho.idToMarketParams`; callers do not
supply token, oracle, IRM, or LLTV addresses separately.

Testnet liquidity is not guaranteed. The default market had no supplied
liquidity when selected, so a tester must supply USDC before borrowing. Always
check `ardent morpho-market` first.

Base Sepolia USDC is available from Circle's faucet. WETH is obtained by wrapping Base Sepolia ETH through the canonical WETH contract shown above.

## Commands

```bash
ardent morpho-markets \
  --loan-token 0x036CbD53842c5426634e7929541eC2318f3dCF7e \
  --collateral-token 0x4200000000000000000000000000000000000006 \
  --max-lltv-raw 860000000000000000 \
  --min-liquidity-raw 1000000
ardent morpho-market
ardent morpho-position --agent-id my-agent-001

ardent morpho-supply-simulate --agent-id my-agent-001 --amount 10
ardent morpho-supply --agent-id my-agent-001 --amount 10
ardent morpho-withdraw-simulate --agent-id my-agent-001 --amount max

ardent morpho-supply-collateral-simulate --agent-id my-agent-001 --amount 0.01
ardent morpho-supply-collateral --agent-id my-agent-001 --amount 0.01
ardent morpho-borrow-simulate --agent-id my-agent-001 --amount 5 --min-health-factor 1.10
ardent morpho-borrow --agent-id my-agent-001 --amount 5 --min-health-factor 1.10
ardent morpho-repay-simulate --agent-id my-agent-001 --amount max
ardent morpho-repay --agent-id my-agent-001 --amount max
ardent morpho-withdraw-collateral-simulate --agent-id my-agent-001 --amount 0.001
```

Every execute command has a matching `-simulate` command and follows the normal UserOperation simulation path.

## Discover markets safely

`morpho-markets` reads Morpho `CreateMarket` events, recomputes every market ID,
and verifies the selected candidates against `idToMarketParams` and live market
state. At least one of `--loan-token` or `--collateral-token` is required.
Oracle availability is required by default.

Results are ranked by available liquidity descending, LLTV ascending, then
borrow APR ascending. The response includes `recommended_market_id`, but Ardent
does not silently route actions to it. Pass that ID explicitly with
`--market-id` after reviewing its tokens, oracle, IRM, LLTV, liquidity, and
rate. This prevents an index change from redirecting an existing position.

## Read market and position

`morpho-market` returns token metadata, immutable market parameters, oracle price, accrued supply and borrow totals, available liquidity, utilization, fee, and the annualized average rate that would be used for pending interest accrual at the read block.

`morpho-position` returns:

- wallet USDC and WETH balances
- supplied loan assets and supply shares
- borrowed assets and borrow shares
- supplied collateral
- collateral value in loan-asset units
- borrow capacity and available borrow
- current LTV, LLTV, health factor, and health status

Interest accrued since the market's last on-chain update is included using Morpho's IRM and canonical Taylor-compounding formula.

Both reads include `oracle_status`. If a permissionless market's oracle is
stale or unavailable, the endpoints still return market state, token balances,
supply, debt, and collateral. Oracle-dependent values such as collateral value,
borrow capacity, LTV, and health are `null`. Borrow and collateral withdrawal
continue to fail closed until the oracle is responsive.

## Amount behavior

API requests accept `amount` and `min_health_factor` as either JSON strings or
JSON numbers. Decimal strings are recommended when exact precision matters.
Keep `amount_raw` as a string because large base-unit integers can exceed JSON's
safe numeric range.

| Action | Action token | `amount=max` |
| --- | --- | --- |
| Supply | Loan token | Entire wallet balance |
| Withdraw | Loan token | All supply shares |
| Supply collateral | Collateral token | Entire wallet balance |
| Withdraw collateral | Collateral token | Only when borrow shares are zero |
| Borrow | Loan token | Not supported; use an explicit amount below available capacity |
| Repay | Loan token | All borrow shares |

Full withdrawals and repayments use Morpho shares rather than an estimated asset amount. This avoids residual supply or debt caused by interest and conversion rounding.

A full share repayment can revert if another transaction repays part of the same
position before this transaction is included. Refresh the position and retry
`amount=max` if that race occurs.

## Safety

- Read `morpho-position` immediately before borrowing or withdrawing collateral.
- Borrow and collateral withdrawal enforce a projected minimum health factor of `1.05` by default. `--min-health-factor` may raise it, but cannot lower it below `1.0`.
- Do not borrow the displayed maximum. Leave a meaningful safety margin below the market LLTV.
- A market being permissionlessly created does not make its tokens, oracle, or IRM trustworthy.
- Execution simulation remains the final pre-flight check, and Morpho enforces position health and market liquidity on-chain.
- ERC-20 allowances are reset to zero before use, set only for the action, and cleared to zero afterward in the same atomic UserOperation.
