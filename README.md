# Jusso

Jusso is autonomous stablecoin operations infrastructure for AI agents and
businesses. It turns owner-approved payment rules into durable USDC workflows
on Arc: recurring payouts, balance reserves, and optional surplus sweeps.

Each agent receives a dedicated ERC-4337 smart account owned by a
tenant-isolated Turnkey signer. Alchemy prepares and sponsors UserOperations;
Jusso validates policy, simulates the complete batch, queues it idempotently,
and verifies the onchain result. Agent private keys never enter Jusso.

## Payment Workflows

A payment plan defines:

- one agent wallet and 1-16 fixed USDC recipients;
- a daily, weekly, or monthly schedule in an IANA time zone;
- a USDC balance that must remain after every run;
- an optional surplus destination, minimum transfer, and per-run maximum;
- an optional completion webhook.

Creating, updating, resuming, or cancelling a plan requires an organization
owner's passkey approval. Pausing is immediate so an owner can stop future runs
without waiting for a browser ceremony.

At run time Jusso rechecks the plan version, agent state, current policy,
recipient limits, wallet balance, and execution-fee reserve. Fixed recipients
are all-or-nothing. If the wallet cannot pay every recipient while preserving
the reserve and fee buffer, the run is skipped. Jusso never borrows, partially
pays a list, or silently catches up multiple missed periods after downtime.

```text
Owner or authorized assistant
  -> drafts payment plan
  -> reviews exact schedule, recipients, limits, and effects
  -> approves with passkey

Scheduler
  -> claims one durable run with a database lease
  -> rechecks active plan + current agent policy
  -> reads Arc USDC balance
  -> compiles deterministic ERC-20 transfers
  -> full ERC-4337 simulation + policy-budget reservation
  -> Turnkey signature + Alchemy sponsorship/submission
  -> receipt and UserOperationEvent verification
  -> run history + optional webhook
```

## Funding

The agent MCP can return the smart-account address at any time, including
before first deployment. USDC can be transferred to that address directly.

On Arc mainnet, an optional Onramper integration can create a 15-minute,
single-use checkout URL signed by Jusso and locked to the agent's smart-account
address. Onramper remains responsible for payment methods, quotes, fees,
country availability, KYC/AML, limits, and fiat settlement. Jusso never handles
card or bank credentials.

This is a funding convenience, not a recurring fiat mandate. Payment plans
spend only USDC already present in the agent wallet; generating a checkout link
does not authorize future fiat debits.

Token conversion and treasury yield are deliberately not exposed yet. Turnkey
Swap currently spends from a Turnkey wallet account, while Jusso custody stays
in the agent's ERC-4337 smart account; the Turnkey address is only the account
owner signer and must not receive user deposits. Turnkey Earn does not currently
support Arc. Both capabilities remain release-gated in `TODO.md` rather than
splitting assets across two wallet models or advertising a nonfunctional route.

## Safety Model

- Organization owners control agents, policies, and payment plans.
- Every organization has a separate Turnkey sub-organization.
- Each stable agent has its own Turnkey signer and Arc smart account.
- OAuth tokens are short-lived; local/workload tokens are DPoP-bound.
- Remote MCP authorization binds the selected agent into the access token.
- Payment-plan calls carry exact token-spend, recipient, and risk metadata.
- Per-execution and rolling token/gas budgets are reserved atomically.
- Execution is always fully simulated before queueing.
- Stable idempotency keys and persisted signed operations make retries safe.
- Arbitrary target/calldata submission is not exposed through MCP or HTTP.
- Only Jusso-defined workflows can compile transactions for the execution engine.
- Bring-your-own-wallet is disabled.

## MCP

Jusso exposes remote Streamable HTTP MCP over HTTPS:

| Endpoint | Purpose |
| --- | --- |
| `/mcp/agent` | Wallet and balance reads, funding, payment workflows, run history, owner-approved organization management, policies, connections, passkeys, and signer lifecycle |

The connection is agent-bound, so runtime tools do not repeatedly ask for an
agent ID. Organization management lives on the same connection; sensitive
changes still require an owner passkey approval in the browser. Compatible
clients complete OAuth Authorization Code + PKCE during onboarding.

Owners may also onboard locally:

```bash
cargo run --bin jusso -- onboard --organization "Acme" --agent-id treasury --accept-terms
```

Child agents enroll with a one-time token created by an owner-approved
operation:

```bash
cargo run --bin jusso -- enroll \
  --enrollment-token jso_enroll_REDACTED \
  --display-name "Treasury operator"
```

## HTTP API

| Endpoint | Purpose |
| --- | --- |
| `POST /register` | Public, protected organization onboarding |
| `GET /wallet` | Agent's Arc smart-account address and deployment state |
| `GET /wallet/balance` | Agent's Arc USDC balance |
| `GET /status/{id}` | Execution status and transaction hash |
| `GET /admin/fee-recipient/status` | Fee-recipient and sponsor status |

Payment plans are MCP-first. Jusso compiles each due run into a deterministic
internal batch, then applies simulation, policy, idempotency, queueing, and
receipt verification. Clients cannot submit arbitrary contracts or calldata.

## Local Setup

Required services and accounts:

- Rust, PostgreSQL, and Redis;
- a Turnkey parent organization with a P-256 API key permitted to create tenant
  sub-organizations;
- an Alchemy app with Arc Wallet API access and a funded gas policy;
- an Arc USDC execution-fee recipient.

Core environment variables:

```dotenv
ARC_NETWORK=arc-testnet
ARC_RPC_URL=https://rpc.testnet.arc.io
ALCHEMY_API_KEY=<Alchemy app key>
ALCHEMY_GAS_POLICY_ID=<funded policy ID>
ARC_MAX_SPONSORED_GAS_UNITS=2000000
ARC_MAX_SPONSORED_GAS_COST_WEI=100000000000000000
EXECUTION_FEE_RECIPIENT=0x<Arc address>
GAS_MARKUP_BPS=1000
PLATFORM_FEE_USDC_RAW=10000

TURNKEY_ORGANIZATION_ID=<parent organization ID>
TURNKEY_API_PUBLIC_KEY=<P-256 public key>
TURNKEY_API_PRIVATE_KEY=<P-256 private key>
TURNKEY_CREDENTIAL_ENCRYPTION_KEY=<64 hex characters>

AUTH_SECRET_ENCRYPTION_KEY=<64 hex characters>
OAUTH_SIGNING_SECRET=<32+ random bytes>
BOOTSTRAP_ADMIN_TOKEN=<32+ random bytes>
DATABASE_URL=postgres://...
REDIS_URL=redis://...
```

Optional Arc-mainnet funding integration:

```dotenv
ONRAMPER_API_KEY=<Onramper API key>
ONRAMPER_SIGNING_PRIVATE_KEY_PKCS8_BASE64=<Ed25519 PKCS#8 DER as base64>
ONRAMPER_USDC_ASSET_ID=<Onramper's verified Arc USDC asset ID>
ONRAMPER_ARC_NETWORK_ID=<Onramper's verified Arc network ID>
```

All four Onramper values are required together. The server refuses to enable
fiat funding on Arc testnet or with a non-Onramper widget origin. Verify current
Arc/USDC support and identifiers with the provider before production rollout.

Public registration outside localhost also requires Cloudflare Turnstile and
allowed hostnames. Copy `.env.example` for the complete configuration contract.
For hosted WebAuthn, `PUBLIC_API_BASE_URL`, `OAUTH_ISSUER`, `OAUTH_AUDIENCE`, and
`WEBAUTHN_ORIGIN` should be the same canonical HTTPS API origin, while
`WEBAUTHN_RP_ID` and `REGISTRATION_ALLOWED_HOSTNAMES` contain only its hostname.
Never commit `.env` or provider credentials.

```bash
docker compose up -d
cargo run --bin jusso-arc-probe
cargo run --bin jusso-server
```

Migrations run at startup. `001_init.sql` is the pre-beta baseline and later
migrations upgrade deployed Beta databases. Migration `002` unifies the MCP
resource and revokes existing OAuth connections; remove and reconnect Jusso in
each MCP client once after deploying this revision. Keep one application
replica until the scheduler, queue workers, and recovery paths have completed
multi-replica certification.

## Railway Testnet Deployment

For a first deployment, create a Railway project with three services:
`jusso-api`, PostgreSQL, and Redis. Do not reuse a database from a pre-Beta
Jusso architecture. An existing Beta deployment created from `001_init.sql`
should keep its current database; startup applies later migrations such as
`002_unified_mcp_remove_raw_execution.sql` automatically.

Railway detects the root `Dockerfile`; `railway.toml` selects `/health` as the
deployment health check. Keep the API at one replica because the scheduler and
queue recovery paths have not yet been certified for multiple replicas. Connect
`DATABASE_URL` and `REDIS_URL` using Railway reference variables, not copied
public credentials. Generate the API domain before configuring the canonical
OAuth/WebAuthn origin and Cloudflare Turnstile hostname.

## Verification

```bash
cargo fmt --check
cargo check --all-targets
cargo test --all-targets
```

The live-spend recovery test is ignored by default because it requires real
Turnkey, Alchemy, and Arc testnet credentials and spends testnet USDC. Remaining
production gates are tracked in [TODO.md](TODO.md).

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
