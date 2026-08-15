# Endpoint Reference

This page gives a compact endpoint map for quick lookup.

This reference includes hosted user facing endpoints only.

For a CLI alternative to the curl examples below, see [Agent Integration](agent-integration.md).

## Quick setup

```bash
BASE_URL="https://api.ardentresearch.xyz"
API_KEY="your_api_key"
```

## Public endpoints

1. `GET /health`
2. `GET /feed/recent`

### `GET /health`

```bash
curl -X GET "$BASE_URL/health"
```

### `GET /feed/recent`

```bash
curl -X GET "$BASE_URL/feed/recent?limit=12"
```

## Protected endpoints

1. `GET /wallet`
2. `GET /wallet/balance`
3. `POST /simulate`
4. `POST /execute`
5. `POST /x402/execute`
6. `POST /delegations/register`
7. `GET /delegations/:agent_id`
8. `POST /delegations/:agent_id/revoke/prepare`
9. Aave V3 typed protocol endpoints
10. Compound III typed protocol endpoints
11. Balancer V3 typed protocol endpoints
12. Morpho Blue typed protocol endpoints
13. Uniswap V4 typed protocol endpoints
14. GMX V2 typed protocol endpoints
15. `GET /status/:id`

Authentication:

```bash
X-API-Key: <api_key>
# or
Authorization: Bearer <short-lived-access-token>
```

### `GET /wallet`

```bash
curl -X GET "$BASE_URL/wallet?agent_id=my-agent-001&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

### `GET /wallet/balance`

```bash
curl -X GET "$BASE_URL/wallet/balance?agent_id=my-agent-001&chain=ethereum" \
  -H "X-API-Key: $API_KEY"
```

### `POST /simulate`

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

### `POST /execute`

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

### `GET /status/:id`

```bash
curl -X GET "$BASE_URL/status/your_request_id" \
  -H "X-API-Key: $API_KEY"
```

## Protocol endpoints

### Aave V3 Sepolia

1. `GET /protocols/aave-v3/balances`
2. `GET /protocols/aave-v3/position`
3. `POST /protocols/aave-v3/supply/simulate`
4. `POST /protocols/aave-v3/supply`
5. `POST /protocols/aave-v3/withdraw/simulate`
6. `POST /protocols/aave-v3/withdraw`
7. `POST /protocols/aave-v3/repay/simulate`
8. `POST /protocols/aave-v3/repay`
9. `POST /protocols/aave-v3/borrow/simulate`
10. `POST /protocols/aave-v3/borrow`

See [Aave V3 Sepolia](aave-v3.md).

### Compound III Base Sepolia

1. `GET /protocols/compound-v3/markets`
2. `GET /protocols/compound-v3/position`
3. `GET /protocols/compound-v3/balances`
4. `GET /protocols/compound-v3/borrow-capacity`
5. `POST /protocols/compound-v3/supply/simulate`
6. `POST /protocols/compound-v3/supply`
7. `POST /protocols/compound-v3/withdraw/simulate`
8. `POST /protocols/compound-v3/withdraw`
9. `POST /protocols/compound-v3/repay/simulate`
10. `POST /protocols/compound-v3/repay`
11. `POST /protocols/compound-v3/borrow/simulate`
12. `POST /protocols/compound-v3/borrow`

See [Compound III Base Sepolia](compound-v3.md).

### Morpho Blue Base Sepolia

1. `GET /protocols/morpho/markets`
2. `GET /protocols/morpho/market`
3. `GET /protocols/morpho/position`
4. `POST /protocols/morpho/supply/simulate`
5. `POST /protocols/morpho/supply`
6. `POST /protocols/morpho/withdraw/simulate`
7. `POST /protocols/morpho/withdraw`
8. `POST /protocols/morpho/supply-collateral/simulate`
9. `POST /protocols/morpho/supply-collateral`
10. `POST /protocols/morpho/withdraw-collateral/simulate`
11. `POST /protocols/morpho/withdraw-collateral`
12. `POST /protocols/morpho/borrow/simulate`
13. `POST /protocols/morpho/borrow`
14. `POST /protocols/morpho/repay/simulate`
15. `POST /protocols/morpho/repay`

See [Morpho Blue Base Sepolia](morpho.md).

### Balancer V3 Ethereum Sepolia

1. `GET /protocols/balancer-v3/pools`
2. `GET /protocols/balancer-v3/pool`
3. `GET /protocols/balancer-v3/balances`
4. `POST /protocols/balancer-v3/swap/quote`
5. `POST /protocols/balancer-v3/swap/simulate`
6. `POST /protocols/balancer-v3/swap`
7. `POST /protocols/balancer-v3/liquidity/add/quote`
8. `POST /protocols/balancer-v3/liquidity/add/simulate`
9. `POST /protocols/balancer-v3/liquidity/add`
10. `POST /protocols/balancer-v3/liquidity/remove/quote`
11. `POST /protocols/balancer-v3/liquidity/remove/simulate`
12. `POST /protocols/balancer-v3/liquidity/remove`

See [Balancer V3 Ethereum Sepolia](balancer-v3.md).

### Uniswap V4 Ethereum Sepolia

1. `GET /protocols/uniswap-v4/pool`
2. `GET /protocols/uniswap-v4/pools`
3. `GET /protocols/uniswap-v4/balances`
4. `POST /protocols/uniswap-v4/swap/quote`
5. `POST /protocols/uniswap-v4/swap/simulate`
6. `POST /protocols/uniswap-v4/swap`

See [Uniswap V4 Ethereum Sepolia](uniswap-v4.md).

### GMX V2 Arbitrum Sepolia

1. `POST /protocols/gmx-v2/orders/simulate`
2. `POST /protocols/gmx-v2/orders`
3. `POST /protocols/gmx-v2/orders/cancel/simulate`
4. `POST /protocols/gmx-v2/orders/cancel`
5. `GET /protocols/gmx-v2/markets`
6. `GET /protocols/gmx-v2/positions`
7. `GET /protocols/gmx-v2/orders`
8. `GET /protocols/gmx-v2/balances`
9. `POST /protocols/gmx-v2/orders/update/simulate`
10. `POST /protocols/gmx-v2/orders/update`
11. `POST /protocols/gmx-v2/deposits/simulate`
12. `POST /protocols/gmx-v2/deposits`
13. `POST /protocols/gmx-v2/withdrawals/simulate`
14. `POST /protocols/gmx-v2/withdrawals`
15. `POST /protocols/gmx-v2/requests/cancel/simulate`
16. `POST /protocols/gmx-v2/requests/cancel`
17. `POST /protocols/gmx-v2/claims/simulate`
18. `POST /protocols/gmx-v2/claims`

See [GMX V2 Arbitrum Sepolia](gmx-v2.md).

## Standard content type

For JSON request bodies:

```bash
Content-Type: application/json
```

## Common status codes

1. `200 OK`
2. `400 Bad Request`
3. `401 Unauthorized`
4. `402 Payment Required`
5. `404 Not Found`
6. `429 Too Many Requests`
7. `500 Internal Server Error`
