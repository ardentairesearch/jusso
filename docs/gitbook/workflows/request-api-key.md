# Request API Key

Hosted API users do not create keys directly through admin endpoints.

Use this workflow to request access credentials.

## 1. Request access

Submit your access request through Ardent Research [onboarding channel](https://www.ardentresearch.xyz/#waitlist).

Recommended request details:

1. Primary technical contact email.
2. Project, team or company name.
3. What you're building or intended use case, including expected request volume.

## 2. Receive credentials

After approval, the Ardent Research team provides an API key or registers an
OAuth service account for autonomous workloads.

Store it immediately in your secret manager.

## 3. Configure your environment [optional]

```bash
BASE_URL="https://api.ardentresearch.xyz"
API_KEY="ard_live_your_api_key"
```

## 4. Verify key quickly [optional]

```bash
curl -G "$BASE_URL/wallet" \
  -H "X-API-Key: $API_KEY" \
  --data-urlencode "agent_id=integration-smoke-test" \
  --data-urlencode "chain=ethereum"
```

A successful response confirms your key is active.

## 5. Rotation and recovery

If your key is exposed or lost, request rotation through the same onboarding or support channel.

For broader Sepolia setup details, see [Testnet Guide](../testnet-guide.md).
