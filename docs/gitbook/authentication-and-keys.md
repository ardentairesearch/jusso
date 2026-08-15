# Authentication and Keys

Ardent supports two authentication methods on protected endpoints. API keys
remain available for simple integrations. Autonomous production agents can use
short-lived OAuth 2.0 access tokens without giving Ardent their private key.

## Identity model

An organization owns its agents, wallets, executions, and webhook secret.
Credentials authenticate a principal inside that organization.

This separation matters during rotation: replacing an API key or service
account does not replace the organization, agent, or smart wallet. Existing
wallet addresses remain unchanged.

## API keys

Send the key in the `X-API-Key` header:

```bash
X-API-Key: ard_live_<public-id>_<secret>
```

Keys can have:

1. An expiry time.
2. A set of scopes.
3. An allow-list of `agent_id` values.
4. A `live` or `test` environment label.

The raw key is returned once. Ardent stores only its SHA-256 hash.

{% hint style="warning" %}
The Beta authentication migration is an intentional credential and managed
wallet reset. Testnet-era API keys and managed wallets are not imported.
Provision new credentials and agents for Beta.
{% endhint %}

## OAuth for autonomous agents

OAuth service accounts use `private_key_jwt`. The agent generates a signing
key locally and Ardent stores only its public JWK.

The flow is:

1. An operator registers the public JWK with `POST /admin/service-accounts`.
2. Ardent returns a `client_id`.
3. The agent signs a client assertion with its private key.
4. The agent exchanges it at `POST /oauth/token`.
5. Ardent returns a scoped bearer token that expires after 15 minutes by
   default.
6. The agent calls the API with `Authorization: Bearer <access_token>`.

The client assertion must use an approved asymmetric algorithm, set `iss` and
`sub` to the `client_id`, set `aud` to the exact token endpoint, include a
unique `jti`, and expire within five minutes. Each `jti` can be used only once.

Example token request:

```bash
curl -X POST https://api.ardentresearch.xyz/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=$ARDENT_CLIENT_ID" \
  --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$SIGNED_ASSERTION" \
  --data-urlencode "scope=wallet:read protocol:read transaction:simulate transaction:execute"
```

OAuth metadata is published at:

```text
/.well-known/oauth-authorization-server
/.well-known/oauth-protected-resource
```

The installed CLI and local MCP runtime can refresh these tokens
automatically. Store the service-account RSA private key in a local PEM file
with mode `0600`, then set:

```bash
export ARDENT_CLIENT_ID="ard_sa_your_client_id"
export ARDENT_CLIENT_PRIVATE_KEY_FILE="$HOME/.ardent/service-account.pem"
export ARDENT_OAUTH_SCOPE="wallet:read protocol:read transaction:simulate transaction:execute"
```

The private key never leaves the agent host. The client uses OpenSSL to sign
assertions and caches only the short-lived access token in memory.

## Scopes

| Scope | Allows |
|---|---|
| `wallet:read` | Resolve wallets and read balances |
| `protocol:read` | Read markets, pools, positions, and protocol balances |
| `execution:read` | Read an execution status owned by the organization |
| `transaction:simulate` | Simulate or quote an action |
| `transaction:execute` | Submit an on-chain action |
| `delegation:read` | Read delegated-account state |
| `delegation:manage` | Register or prepare revocation of a delegation |

An operator can also restrict a principal by chain, protocol, action, and
allowed agent IDs. The API records authorization decisions for audit.

## Credential lifecycle

Admin endpoints use `Authorization: Bearer <BOOTSTRAP_ADMIN_TOKEN>`:

```text
POST   /admin/api-keys
GET    /admin/api-keys?organization_id=<uuid>
POST   /admin/api-keys/<id>/rotate
DELETE /admin/api-keys/<id>

POST   /admin/service-accounts
GET    /admin/service-accounts?organization_id=<uuid>
DELETE /admin/service-accounts/<id>

POST   /admin/authorization-policies
DELETE /admin/authorization-policies/<id>
```

API-key rotation creates a new credential under the same organization and
principal. Service-account revocation also invalidates its unexpired access
tokens immediately.

## Webhook signatures

Webhook signing uses an organization-owned secret, not an API-key hash. A new
organization receives the secret once during API-key creation. Rotate it with:

```text
POST /admin/organizations/<organization_id>/webhook-secret/rotate
```

Webhook secrets are encrypted at rest and are never copied into execution
jobs. The worker loads the current organization secret only when it delivers a
callback, so rotation takes effect without re-queuing executions.

Use a dedicated `AUTH_SECRET_ENCRYPTION_KEY`; do not reuse
`WALLET_ENCRYPTION_KEY` or `OAUTH_SIGNING_SECRET`.

## CLI and local MCP

The current CLI and local MCP server continue to use API keys:

```bash
export ARDENT_API_KEY="ard_live_your_key"
export ARDENT_BASE_URL="https://api.ardentresearch.xyz"
```

Keep credentials in environment variables or a secret manager. Never embed
them in browser code, mobile app bundles, source control, prompts, or logs.
