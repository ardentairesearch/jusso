# Feed — Recent Activity

Use this endpoint to fetch the most recent public execution activity on the platform.

## Endpoint

`GET /feed/recent`

## Authentication

None. This is a public endpoint.

## Query parameters

1. `limit` optional integer. Number of entries to return. Default is platform controlled.

## Command

```bash
curl -X GET "$BASE_URL/feed/recent?limit=12"
```

## Success response

Status code: `200 OK`

Returns a list of recent execution events visible on the public feed.

## Notes

1. No API key is required.
2. Use this to monitor live platform activity or validate that the API is reachable before making authenticated calls.
3. The `ardent feed` CLI command is a convenience wrapper for this endpoint.

```bash
ardent feed
```
