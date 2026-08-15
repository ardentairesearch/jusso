# GMX V2 Arbitrum Sepolia

GMX V2 actions are exposed as typed protocol endpoints for Arbitrum Sepolia.
The platform compiles each supported write into ERC-4337 calls and runs the
same UserOperation simulation path before execution.

## Supported actions

| Action | Endpoint | CLI |
| --- | --- | --- |
| Read markets | `GET /protocols/gmx-v2/markets` | `ardent gmx-markets` |
| Read positions | `GET /protocols/gmx-v2/positions` | `ardent gmx-positions` |
| Read orders | `GET /protocols/gmx-v2/orders` | `ardent gmx-orders` |
| Read GM + token balances | `GET /protocols/gmx-v2/balances` | `ardent gmx-balances` |
| Simulate create order | `POST /protocols/gmx-v2/orders/simulate` | `ardent gmx-create-order-simulate` |
| Execute create order | `POST /protocols/gmx-v2/orders` | `ardent gmx-create-order` |
| Simulate cancel order | `POST /protocols/gmx-v2/orders/cancel/simulate` | `ardent gmx-cancel-order-simulate` |
| Execute cancel order | `POST /protocols/gmx-v2/orders/cancel` | `ardent gmx-cancel-order` |
| Simulate update order | `POST /protocols/gmx-v2/orders/update/simulate` | `ardent gmx-update-order-simulate` |
| Execute update order | `POST /protocols/gmx-v2/orders/update` | `ardent gmx-update-order` |
| Simulate create deposit | `POST /protocols/gmx-v2/deposits/simulate` | `ardent gmx-create-deposit-simulate` |
| Execute create deposit | `POST /protocols/gmx-v2/deposits` | `ardent gmx-create-deposit` |
| Simulate create withdrawal | `POST /protocols/gmx-v2/withdrawals/simulate` | `ardent gmx-create-withdrawal-simulate` |
| Execute create withdrawal | `POST /protocols/gmx-v2/withdrawals` | `ardent gmx-create-withdrawal` |
| Simulate cancel request | `POST /protocols/gmx-v2/requests/cancel/simulate` | `ardent gmx-cancel-simulate` |
| Execute cancel request | `POST /protocols/gmx-v2/requests/cancel` | `ardent gmx-cancel` |
| Simulate claim | `POST /protocols/gmx-v2/claims/simulate` | `ardent gmx-claim-simulate` |
| Execute claim | `POST /protocols/gmx-v2/claims` | `ardent gmx-claim` |

The create-order surface supports:

- `market_swap`
- `limit_swap`
- `market_increase`
- `limit_increase`
- `market_decrease`
- `limit_decrease`
- `stop_loss_decrease`
- `stop_increase`

For create order, Ardent builds:

1. `ERC20.approve(GMX Router, collateralAmount)`
2. `ExchangeRouter.multicall([sendWnt, sendTokens, createOrder])`

That means the GMX execution fee, collateral/input transfer, and `createOrder`
call are bundled atomically in one smart-account operation.

## Arbitrum Sepolia contracts

| Contract | Address |
| --- | --- |
| ExchangeRouter | `0xEd50B2A1eF0C35DAaF08Da6486971180237909c3` |
| Router | `0x72F13a44C8ba16a678CAD549F17bc9e06d2B8bD2` |
| OrderVault | `0x1b8AC606de71686fd2a1AEDEcb6E0EFba28909a2` |
| DepositVault | `0x809Ea82C394beB993c2b6B0d73b8FD07ab92DE5A` |
| WithdrawalVault | `0x7601c9dBbDCf1f5ED1E7Adba4EFd9f2cADa037A5` |

GMX market token addresses, index tokens, long tokens, and short tokens should
be taken from the current GMX V2 Arbitrum Sepolia deployment data before
building an order.

## Read GMX state

```bash
ardent gmx-markets --start 0 --end 50
ardent gmx-positions --agent-id my-agent-001 --start 0 --end 50
ardent gmx-orders --agent-id my-agent-001 --start 0 --end 50
ardent gmx-balances --agent-id my-agent-001 --start 0 --end 50
```

The read endpoints use GMX `Reader` against the Arbitrum Sepolia `DataStore`.
Ranges are capped at 100 items per request.
Market responses include token symbols where ERC-20 metadata is available.
The balances response keeps GM/market LP token balances in `balances` and adds
underlying market asset balances in `token_balances`.
Token metadata is best-effort on GMX testnet. If `symbol()` is unavailable, the
API falls back to a derived GM market label or compact token address, and a
failed token read is reported on that item with `error` instead of failing the
whole response.

## Create a market increase

`size_delta_usd_raw` and `acceptable_price_raw` use GMX 30-decimal precision.
`execution_fee_raw` is wei.

```bash
curl -X POST "$BASE_URL/protocols/gmx-v2/orders/simulate" \
  -H "X-API-Key: $ARDENT_API_KEY" \
  -H "Content-Type: application/json" \
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
```

Execute after the simulation succeeds:

```bash
ardent gmx-create-order \
  --agent-id my-agent-001 \
  --order-type market_increase \
  --market 0xYourGmxMarketToken \
  --initial-collateral-token 0xYourCollateralToken \
  --initial-collateral-delta-amount-raw 1000000 \
  --size-delta-usd-raw 50000000000000000000000000000000000 \
  --acceptable-price-raw 30000000000000000000000000000000000000000 \
  --execution-fee-raw 1000000000000000 \
  --long
```

## Create a market swap

For `market_swap`, provide `min_output_amount_raw` instead of size/price
fields. The `market` argument is treated as the single GMX swap-path market for
this order type; the on-chain GMX order `market` field is encoded as
`address(0)` as required by GMX swap orders.

```bash
ardent gmx-create-order-simulate \
  --agent-id my-agent-001 \
  --order-type market_swap \
  --market 0xYourGmxMarketToken \
  --initial-collateral-token 0xYourInputToken \
  --initial-collateral-delta-amount-raw 1000000 \
  --min-output-amount-raw 1 \
  --execution-fee-raw 1000000000000000
```

## Cancel an order

```bash
ardent gmx-cancel-order-simulate \
  --agent-id my-agent-001 \
  --order-key 0xYourBytes32OrderKey

ardent gmx-cancel-order \
  --agent-id my-agent-001 \
  --order-key 0xYourBytes32OrderKey
```

## Update an order

```bash
ardent gmx-update-order-simulate \
  --agent-id my-agent-001 \
  --order-key 0xYourBytes32OrderKey \
  --size-delta-usd-raw 50000000000000000000000000000000000 \
  --acceptable-price-raw 30000000000000000000000000000000000000000 \
  --trigger-price-raw 0 \
  --min-output-amount-raw 1 \
  --valid-from-time-raw 0
```

## Create LP deposit

```bash
ardent gmx-create-deposit-simulate \
  --agent-id my-agent-001 \
  --market 0xYourGmxMarketToken \
  --initial-long-token 0xLongToken \
  --initial-short-token 0xShortToken \
  --initial-long-token-amount-raw 1000000 \
  --min-market-tokens-raw 1 \
  --execution-fee-raw 1000000000000000
```

## Create LP withdrawal

```bash
ardent gmx-create-withdrawal-simulate \
  --agent-id my-agent-001 \
  --market 0xYourGmxMarketToken \
  --market-token-amount-raw 1000000000000000000 \
  --min-long-token-amount-raw 1 \
  --min-short-token-amount-raw 1 \
  --execution-fee-raw 1000000000000000
```

## Cancel any GMX request

```bash
ardent gmx-cancel-simulate \
  --agent-id my-agent-001 \
  --request-type deposit \
  --key 0xYourBytes32RequestKey
```

`request_type` can be `order`, `deposit`, `withdrawal`, or `shift`.

## Claim fees and rewards

```bash
ardent gmx-claim-simulate \
  --agent-id my-agent-001 \
  --claim-type funding_fees \
  --market 0xYourGmxMarketToken \
  --token 0xClaimToken
```

`claim_type` can be `funding_fees`, `collateral`, `affiliate_rewards`, or
`ui_fees`. Collateral claims also require one or more `--time-key-raw` values.

## Notes for agents

- Always call the `/simulate` endpoint before execution.
- The smart wallet needs enough Arbitrum Sepolia ETH for the GMX execution fee,
  even when gas sponsorship is enabled. Paymasters cover UserOperation gas only;
  they do not cover `execution_fee_raw` or any other native value forwarded to GMX.
- The collateral/input token must already be in the agent smart wallet.
- Use raw integer values only. Human-readable GMX sizing is intentionally not
  guessed by the API because GMX uses token decimals and 30-decimal USD/price
  precision.
