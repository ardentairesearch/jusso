# Aave V3 Sepolia

Ardent provides typed Aave V3 actions for Ethereum Sepolia. Use `chain: "ethereum"` for these endpoints because the hosted testnet environment maps that label to Ethereum Sepolia infrastructure.

The typed Aave layer handles calldata encoding for common actions and runs the normal pre-flight simulation path before execution.

## Supported Actions

| Action | API | CLI |
| --- | --- | --- |
| Read reserve balances | `GET /protocols/aave-v3/balances` | `ardent aave-balances` |
| Read account position | `GET /protocols/aave-v3/position` | `ardent aave-position` |
| Supply | `POST /protocols/aave-v3/supply` | `ardent aave-supply` |
| Withdraw | `POST /protocols/aave-v3/withdraw` | `ardent aave-withdraw` |
| Repay | `POST /protocols/aave-v3/repay` | `ardent aave-repay` |
| Borrow | `POST /protocols/aave-v3/borrow` | `ardent aave-borrow` |

Each state-changing action also has a simulation endpoint and CLI command:

```bash
ardent aave-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent aave-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-repay-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-borrow-simulate --agent-id my-agent-001 --asset USDC --amount max --min-health-factor 1.10
```

API requests accept `amount` and `min_health_factor` as either JSON strings or
JSON numbers. Decimal strings are recommended when exact precision matters.
Keep `amount_raw` as a string because large base-unit integers can exceed JSON's
safe numeric range.

## Read Balances

Use balances before action planning to see what the agent wallet currently holds across Aave-supported reserve assets.

```bash
ardent aave-balances --agent-id my-agent-001
```

The response includes one entry per supported reserve:

1. `wallet_balance_*`: underlying token held directly by the smart wallet.
2. `a_token_balance_*`: supplied position token balance.
3. `stable_debt_balance_*`: stable-rate debt token balance.
4. `variable_debt_balance_*`: variable-rate debt token balance.

## Read Position

Use position for account-level risk and borrowing data.

```bash
ardent aave-position --agent-id my-agent-001
```

The response includes collateral, debt, available borrows, LTV, liquidation threshold, and health factor in Aave's base units.

## Supply

```bash
ardent aave-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent aave-supply --agent-id my-agent-001 --asset USDC --amount 1.25
```

Supply compiles to an atomic `approve -> Pool.supply` batch for the agent smart wallet.

## Withdraw

```bash
ardent aave-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-withdraw --agent-id my-agent-001 --asset USDC --amount max
```

`amount max` withdraws the maximum available aToken balance for the selected reserve.

## Repay

```bash
ardent aave-repay-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-repay --agent-id my-agent-001 --asset USDC --amount max
```

`amount max` resolves to the smaller of selected-rate debt and wallet underlying balance, then compiles the normal `approve -> Pool.repay` batch.

## Borrow

```bash
ardent aave-borrow-simulate \
  --agent-id my-agent-001 \
  --asset USDC \
  --amount max \
  --min-health-factor 1.10
```

Borrow checks projected health factor using Aave account data and oracle price before simulation or execution. The default minimum projected health factor is `1.05`; custom values must be at least `1.0`.

## Supported Reserve Assets

Current Ethereum Sepolia Aave V3 reserves:

| Symbol | Address |
| --- | --- |
| AAVE | `0x88541670E55cC00bEEFD87eB59EDd1b7C511AC9a` |
| DAI | `0xFF34B3d4Aee8ddCd6F9AFFFB6Fe49bD371b8a357` |
| EURS | `0x6d906e526a4e2Ca02097BA9d0caA3c382F52278E` |
| GHO | `0xc4bF5CbDaBE595361438F8c6a187bDc330539c60` |
| LINK | `0xf8Fb3713D459D7C1018BD0A49D19b4C44290EBE5` |
| USDC | `0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8` |
| USDT | `0xaA8E23Fb1079EA71e0a56F48a2aA51851D8433D0` |
| WBTC | `0x29f2D40B0605204364af54EC677bD022dA425d03` |
| WETH | `0xC558DBdd856501FCd9aaF1E62eae57A9F0629a3c` |

These are Aave Sepolia reserve assets. They are not always the same as official issuer faucet tokens. For example, Aave Sepolia `USDC` is different from Circle faucet USDC, and Aave Sepolia `LINK` is different from Chainlink faucet LINK.

## Getting Aave Test Assets

Use Aave's testnet UI/faucet when available. If you are minting directly for development, the Aave Sepolia token faucet-style contract is:

```bash
AAVE_TOKEN_FAUCET=0xC959483DBa39aa9E78757139af0e9a2EDEb3f42D
```

Example mint for Aave Sepolia USDC:

```bash
cast send $AAVE_TOKEN_FAUCET \
  "mint(address,address,uint256)" \
  0x94a9D9AC8a22534E3FaCa9F4e7F2E2cf85d5E4C8 \
  0xYourAgentSmartWallet \
  100000000 \
  --rpc-url $ETHEREUM_RPC_URL \
  --private-key $PRIVATE_KEY
```

This mints `100` Aave Sepolia USDC to the agent wallet.
