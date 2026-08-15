# Check Request Status

Use this endpoint to retrieve the latest state for an execution request.

## Endpoint

`GET /status/:id`

## Authentication

`X-API-Key` required.

## Command

```bash

curl "$BASE_URL/status/your_request_id" \
  -H "X-API-Key: $API_KEY"
```

## Success response

Status code: `200 OK`

Example:

```json
{
  "request_id": "your_request_id",
  "status": "broadcasting",
  "chain": "ethereum",
  "tx_hash": "0x1234...abcd",
  "cost_usd": 0.25,
  "created_at": "2026-05-05T10:00:00Z",
  "updated_at": "2026-05-05T10:00:12Z"
}
```

## CLI equivalent

```bash
ardent status --request-id your_request_id
```

See [Agent Integration](../agent-integration.md) for the one-line installer.

## Status lifecycle

Typical progression:

1. `pending`
2. `payment_required`
3. `payment_verified`
4. `queued`
5. `broadcasting`
6. Terminal state
   1. `confirmed`
   2. `reverted`
   3. `failed`

## Polling recommendation

Use interval polling between 2 and 5 seconds until terminal state, then stop.
