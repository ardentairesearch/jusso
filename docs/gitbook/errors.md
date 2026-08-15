# Errors and Troubleshooting

This section lists common errors and clear corrective actions.

## 1. Authentication errors

### Missing or invalid credential

Response:

```json
{
  "error": "invalid_credentials",
  "message": "credentials are missing, invalid, expired, or revoked"
}
```

Action:

1. Send exactly one of `X-API-Key` or `Authorization: Bearer <access_token>`.
2. Verify the key is active and unexpired, or obtain a fresh OAuth token.
3. For CLI/MCP usage, set `ARDENT_API_KEY` or `ARDENT_ACCESS_TOKEN`.

### Insufficient scope

The credential is valid but does not grant the route's required scope. Request
the narrow additional scope or use the correct service account. Agent allow-list
and authorization-policy failures similarly return `403`.

## 2. Payment errors

### Execution-fee failure

Response:

```json
{
  "status": "failed",
  "message": "insufficient USDC balance for atomic execution fee"
}
```

Action:

1. Confirm the smart wallet holds enough USDC on the selected chain.
2. Confirm simulation returns `execution_fee_raw`.
3. For delegated accounts, confirm the session allows the USDC transfer to the paymaster.

## 3. Validation errors

Examples include unsupported chain, malformed calldata, invalid target contract, or missing required fields.

Action:

1. Validate request payload schema client side.
2. Use canonical chain names.
3. Ensure calldata is `0x` prefixed and ABI encoded correctly.

## 4. Operational errors

### No bundler configured

Action:

1. Retry once after short delay.
2. If repeated, contact Ardent support with timestamp, chain, and request ID.

### Queue or infrastructure failures

Action:

1. Retry request with backoff.
2. If persistent, contact Ardent support with request ID and failure window.

## 5. Recommended client retry policy

1. Retry idempotent reads such as status polling with jitter.
2. Avoid blind retries for execute on unknown state. Query status first using known request ID.
3. Handle `402` explicitly rather than generic retry.
