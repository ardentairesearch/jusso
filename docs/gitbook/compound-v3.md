# Compound III Base Sepolia

Ardent exposes typed Compound III actions for Base Sepolia using the `chain: "base"` label.

Compound III deployments are Comet markets. Base Sepolia currently supports two markets in Ardent:

| Market | Base asset | Comet proxy |
| --- | --- | --- |
| `usdc` | USDC | `0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017` |
| `weth` | WETH | `0x61490650AbaA31393464C3f34E8B29cd1C44118E` |

## Supported Actions

| Action | API | CLI |
| --- | --- | --- |
| Discover verified markets | `GET /protocols/compound-v3/markets` | `ardent compound-markets` |
| Read position | `GET /protocols/compound-v3/position` | `ardent compound-position` |
| Read balances | `GET /protocols/compound-v3/balances` | `ardent compound-balances` |
| Read borrow capacity and rates | `GET /protocols/compound-v3/borrow-capacity` | `ardent compound-borrow-capacity` |
| Supply base or collateral | `POST /protocols/compound-v3/supply` | `ardent compound-supply` |
| Withdraw base or collateral | `POST /protocols/compound-v3/withdraw` | `ardent compound-withdraw` |
| Repay base debt | `POST /protocols/compound-v3/repay` | `ardent compound-repay` |
| Borrow base asset | `POST /protocols/compound-v3/borrow` | `ardent compound-borrow` |

Each state-changing action also has a simulation endpoint and CLI command:

```bash
ardent compound-markets
ardent compound-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent compound-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent compound-repay-simulate --agent-id my-agent-001 --amount max
ardent compound-borrow-simulate --agent-id my-agent-001 --amount 1
ardent compound-position --agent-id my-agent-001 --market weth
ardent compound-borrow-capacity --agent-id my-agent-001
```

API requests accept `amount` as either a JSON string or JSON number. Decimal
strings are recommended when exact precision matters. Keep `amount_raw` as a
string because large base-unit integers can exceed JSON's safe numeric range.

## Read State

```bash
ardent compound-markets
ardent compound-position --agent-id my-agent-001
ardent compound-balances --agent-id my-agent-001
ardent compound-borrow-capacity --agent-id my-agent-001
```

`compound-markets` verifies each maintained Comet proxy by reading its base
token on-chain, then returns its current utilization, rates, collateral assets,
factors, price feeds, and supply caps. Actions infer the USDC or WETH market
from `asset` unless `--market` explicitly selects one, and the same Comet
identity check runs before every read, simulation, and execution.

`compound-position` returns base supplied balance, base borrow balance, and all collateral balances discovered from `Comet.numAssets()` and `Comet.getAssetInfo(index)` for the selected market.

`compound-balances` returns wallet balances and Compound balances for the base asset plus Comet collateral assets in the selected market.

`compound-borrow-capacity` returns current base debt, total collateral-backed borrow capacity, currently available borrow amount, market utilization, supply APR, borrow APR, and each collateral asset's contribution to borrow capacity.

## Supply

```bash
ardent compound-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent compound-supply --agent-id my-agent-001 --asset USDC --amount 1.25
```

Supply compiles to an atomic `approve -> Comet.supply` batch. `asset` can be `USDC`, `base`, `WETH`, or a token address supported by the selected Comet market. For raw token addresses, use `amount_raw`. Use `--market usdc` or `--market weth` when the asset alone does not identify the intended market.

`amount max` supplies the wallet's full selected asset balance.

## Withdraw

```bash
ardent compound-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent compound-withdraw --agent-id my-agent-001 --asset USDC --amount max
```

Withdraw compiles to `Comet.withdraw(asset, amount)`. For the base asset, this withdraws supplied base and can create debt if the amount exceeds supplied base and the account has enough collateral. For collateral assets, it withdraws collateral.

## Repay

```bash
ardent compound-repay-simulate --agent-id my-agent-001 --amount max
ardent compound-repay --agent-id my-agent-001 --amount max
```

Repay is base-asset only and compiles to `approve -> Comet.supply(base, amount)`. `amount max` resolves to the smaller of current base debt and wallet base balance.

## Borrow

```bash
ardent compound-borrow-simulate --agent-id my-agent-001 --amount 1
ardent compound-borrow --agent-id my-agent-001 --amount 1
```

Borrow is base-asset only and compiles to `Comet.withdraw(base, amount)`. The platform still runs the normal ERC-4337 simulation path before execution, so undercollateralized borrows should fail before submission.

Check `ardent compound-borrow-capacity --agent-id my-agent-001` before borrowing to see the wallet's collateral-backed available borrow amount and the market borrow APR.

`amount max` is intentionally not enabled for borrow. Use an explicit `amount` or `amount_raw`.

## Base Sepolia Assets

The default base asset symbol maps to Circle faucet Base Sepolia USDC:

```bash
USDC=0x036CbD53842c5426634e7929541eC2318f3dCF7e
```

WETH maps to the standard Base wrapped native token address:

```bash
WETH=0x4200000000000000000000000000000000000006
```
