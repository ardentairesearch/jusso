# Jusso

**Base-native execution infrastructure for autonomous AI agents.**

Jusso lets an AI agent own a persistent on-chain account, simulate actions,
pay a predictable stablecoin execution fee, and submit transactions without
holding native gas. The service manages execution policy, wallet custody,
sponsorship, settlement, retries, and transaction status behind one API.

This repository is the new Jusso Beta. It is intentionally focused on Base
and Base native account abstraction. The previous ERC-4337 factory, bundler,
and verifying-paymaster architecture is no longer part of the runtime.

> Current network status: the complete native-account flow is tested on Base
> VibeNet. Persistent public deployment waits for the Cobalt native-account
> upgrade to reach Base Sepolia. Protocol HTTP routes remain disabled until
> then, while their typed action layers are preserved in this repository.

## What Jusso Does

- Creates one organization-owned account for each agent through a
  provider-neutral custody interface, currently backed by Turnkey.
- Uses Base native account abstraction so the agent keeps the same address
  before and after it becomes programmable.
- Simulates every action before accepting it for execution.
- Adds the stablecoin execution fee and the requested action to one atomic
  transaction.
- Signs sender and payer authorizations without exposing private keys to the
  API, database, or agent.
- Pays native gas from an infrastructure payer account and records the
  stablecoin fee received by that same account.
- Supports x402 V2 as an alternative payment path for independently funded
  agents and external wallets.
- Provides short-lived OAuth credentials, scoped authorization, idempotency,
  rate limits, audit events, webhooks, retries, and status tracking.

## Product Model

The default model is deliberately simple:

1. The developer registers an agent identity.
2. Jusso provisions the agent's Base account through the configured wallet
   provider.
3. The agent funds that address with the assets it intends to use and the
   accepted execution-fee stablecoin.
4. The agent requests a simulation.
5. Jusso calculates gas cost plus the configured platform fee.
6. On execution, phase zero transfers the stablecoin fee to the payer and
   phase one performs the requested action.
7. The payer sponsors native gas, the network executes both phases, and
   Jusso returns or pushes the final result.

If the action phase fails, the transaction is reported as reverted. The
receipt is checked against the expected payer and phase count before the result
is accepted.

## Architecture

```text
AI agent or agent application
        |
        | private_key_jwt OAuth or scoped API key
        v
+-------------------------- Jusso API ---------------------------+
| registration | authorization | policy | rate limit | audit    |
| wallet       | simulation    | execution | status  | x402     |
+-----------------------------+----------------------------------+
                              |
                  +-----------+-----------+
                  |                       |
                  v                       v
          PostgreSQL state          Redis job queue
          identities, wallets,      retries, recovery,
          quotes, payments, txs     dead-letter handling
                  |                       |
                  +-----------+-----------+
                              v
                    supervised workers
                              |
              +---------------+----------------+
              |                                |
              v                                v
     provider-neutral custody          Base native-AA client
     Turnkey today                     simulate, sign, submit,
     more providers later              verify receipt
              |                                |
              +---------------+----------------+
                              v
                     Base native account
                phase 0: stablecoin execution fee
                phase 1: requested on-chain action
                     payer: native gas sponsor
```

### Trust boundaries

- Turnkey holds wallet key material. Jusso stores only provider identifiers
  and public addresses.
- Agent authentication keys remain with the agent. Self-service registration
  sends only a public JWK to Jusso.
- PostgreSQL owns durable identity, authorization, idempotency, and execution
  state.
- Redis is a delivery queue, not the source of truth.
- The payer has an explicit maximum sponsored-gas policy and is pinned to an
  expected address in production.

## Current and Planned Networks

| Stage | Network | Fee token | Protocol routes |
| --- | --- | --- | --- |
| Development now | Base VibeNet | USDV | Disabled |
| Local testing | Local native-AA node | Configurable | Disabled |
| Cobalt test phase | Base Sepolia | USDC | Re-enabled after deployment verification |
| Beta launch | Base | USDC | Enabled protocol by protocol |

VibeNet is ephemeral and may rotate its RPC state or native-account contracts.
The VibeNet smoke test detects profile drift before a live execution test is
run.

## Preserved Protocol Layers

The following typed integrations remain compiled and tested:

- Aave V3
- Balancer V3
- Compound III
- GMX V2
- Morpho Blue
- Uniswap V4

They currently translate high-level protocol actions into validated single or
batched calls. Their HTTP routes intentionally return a temporary-unavailable
response. Once Cobalt is available on Base Sepolia, each integration will be
updated to verified Base deployments, connected to the native executor, and
opened independently.

## Authentication and Onboarding

Jusso models identity in four layers: an organization owns stable agents;
principals receive explicit grants to those agents; credentials authenticate a
principal; and cloud runs become short-lived agent instances. Authorization
policies belong to agents and constrain chains, protocols, actions, contract
targets, transaction value, and execution fee.

For local development, the CLI creates a P-256 key on the developer's machine,
registers only its public JWK, stores the private key with `0600` permissions,
configures the returned client ID, exchanges a `private_key_jwt`, and verifies
wallet access automatically:

```bash
cargo run --bin jusso -- onboard \
  --organization "Acme" \
  --agent-id treasury \
  --accept-terms
```

Organization owners can create additional agents and receive a one-time,
15-minute enrollment token. The child runtime generates its own key and calls
`POST /agents/enroll`; neither the owner key nor an API secret is copied into
the new agent. First, the owner creates the stable agent from its saved profile:

```bash
cargo run --bin jusso -- agent create \
  --profile ~/.config/jusso/profiles/jso_client_OWNER.json \
  --agent-id research \
  --display-name "Research agent"
```

That command returns a one-time enrollment token. The child runtime completes
the flow without handling the owner's key material:

```bash
cargo run --bin jusso -- enroll \
  --enrollment-token jso_enroll_REDACTED \
  --display-name "Treasury worker"
```

Each onboarding stores a separate profile under
`~/.config/jusso/profiles/`, so multiple agents can coexist on one machine.

Hosted agents use OAuth token exchange against an organization-configured OIDC
federation trust. Jusso verifies the issuer's HTTPS JWKS, audience, and exact or
trailing-wildcard subject, then records an ephemeral agent instance. Both local
and federated access tokens are short-lived and DPoP-bound, so a stolen token
cannot be used without its private proof key. Assertion and DPoP IDs are
consumed once to reject replay.

API keys remain an administrative compatibility path. Wallet ownership is tied
to the organization and stable agent, so credential rotation never changes an
agent's account.

## Execution Payments

### Atomic stablecoin fee

This is the default path. Jusso quotes the maximum expected native-gas cost,
applies the configured gas markup and platform fee, converts the result to the
execution token's smallest unit, and rounds upward to avoid undercharging.

The fee transfer and requested action are separate phases of one native
transaction. The infrastructure payer both sponsors native gas and receives the
stablecoin execution fee.

### x402 V2

`POST /x402/execute` supports agents that pay through an external x402
facilitator. The challenge locks the exact request, amount, asset, network,
recipient, and idempotency key. Jusso re-simulates before settlement, rejects
underpayment or replayed settlement transactions, and queues the action only
after payment is verified.

## API Surface

| Endpoint | Purpose | Authentication |
| --- | --- | --- |
| `GET /health` | Database and Redis readiness | Public |
| `GET /feed/recent` | Sanitized recent activity | Public |
| `POST /register` | Self-service organization and agent registration | Public, protected in production |
| `POST /agents/enroll` | Redeem a one-time child-agent enrollment grant | Public + one-time token |
| `POST /oauth/token` | Short-lived local or federated token | DPoP + client assertion or workload JWT |
| `GET, POST /agents` | List or create organization agents | `agent:manage` |
| `/credential-bindings/*` | Rotate local public-key credentials | `credential:manage` |
| `/federation-trusts/*` | Configure cloud workload identity | `trust:manage` |
| `/authorization-policies/*` | Create and revoke agent policies | `policy:manage` |
| `GET /wallet` | Resolve or provision an agent account | Protected |
| `GET /wallet/balance` | Read native and execution-token balances | Protected |
| `POST /simulate` | Simulate an action and quote its fee | Protected |
| `POST /execute` | Atomic-fee sponsored execution | Protected + `Idempotency-Key` |
| `POST /x402/execute` | x402 quote, settlement, and execution | Protected + `Idempotency-Key` |
| `GET /status/:id` | Read organization-scoped execution status | Protected |
| `/admin/*` | Emergency API keys, webhook rotation, payer status | Bootstrap admin token |
| `/protocols/*` | Reserved typed protocol API | Temporarily disabled |

Every execution request requires an `Idempotency-Key` between 8 and 128
characters. Repeating the same key and payload returns the original request;
reusing the key with a different payload returns a conflict.

## Repository Layout

```text
jusso/
├── src/
│   ├── agent_wallet/       # organization-owned agent accounts
│   ├── api/                # HTTP routes and orchestration
│   ├── auth/               # OAuth, API keys, scopes, and policies
│   ├── config/             # strict environment configuration
│   ├── db/                 # PostgreSQL repositories and encryption
│   ├── execution_engine/   # validation, simulation, and pricing
│   ├── native_aa/          # Base native transaction encoding and execution
│   ├── payments/           # atomic-fee records and x402 V2
│   ├── protocols/          # preserved typed DeFi integration layers
│   ├── queue/              # reliable Redis queue and recovery
│   ├── wallet_provider/    # provider-neutral custody boundary and Turnkey
│   ├── webhook/            # signed, SSRF-hardened callbacks
│   └── worker/             # supervised execution workers
├── migrations/             # clean Beta database schema
├── contracts/              # local/VibeNet execution fixtures only
├── tests/                  # live VibeNet and profile smoke tests
└── .github/workflows/      # Rust, Solidity, and opt-in live checks
```

The `docs/` directory is intentionally frozen while the Beta runtime and API
stabilize. It describes the previous public version and must not be used as the
source of truth for this branch. This README reflects the current architecture.

## Local Setup

### Requirements

- Rust 1.88 or newer
- PostgreSQL 16
- Redis 7
- A Turnkey organization with a P-256 API key
- Foundry, only for the local Solidity fixtures

### Start dependencies

```bash
docker compose up -d postgres redis
```

### Configure the service

Create an ignored `.env` file. Use independent, cryptographically random
values for every secret.

```env
NETWORK_PROFILE=vibenet
BASE_RPC_URL=https://rpc.vibes.base.org
BASE_PRICE_FEED_URL=https://your-reliable-price-feed.example/eth-usd

DATABASE_URL=postgres://postgres:postgres@localhost:5432/jusso
REDIS_URL=redis://127.0.0.1:6379
HOST=0.0.0.0
PORT=8080
PUBLIC_API_BASE_URL=http://localhost:8080
CORS_ORIGIN=http://localhost:3000,http://localhost:5173

TURNKEY_ORGANIZATION_ID=your_turnkey_organization_id
TURNKEY_API_PUBLIC_KEY=your_turnkey_api_public_key
TURNKEY_API_PRIVATE_KEY=your_turnkey_api_private_key
TURNKEY_PAYER_WALLET_NAME=jusso-beta-payer
TURNKEY_PAYER_EXPECTED_ADDRESS=0xYourPinnedPayerAddress

AUTH_SECRET_ENCRYPTION_KEY=64_hex_characters
OAUTH_SIGNING_SECRET=at_least_32_random_bytes
BOOTSTRAP_ADMIN_TOKEN=at_least_32_random_bytes

PUBLIC_REGISTRATION_ENABLED=true
PER_PRINCIPAL_RATE_LIMIT_RPS=5
PER_PRINCIPAL_RATE_LIMIT_BURST=10
GAS_PRICE_MARKUP_PCT=10
PLATFORM_FEE_USD=0.01
```

For a public deployment, also configure:

```env
OAUTH_ISSUER=https://api.your-domain.example
OAUTH_AUDIENCE=https://api.your-domain.example
REGISTRATION_TURNSTILE_SECRET=your_turnstile_secret
REGISTRATION_ALLOWED_HOSTNAMES=your-domain.example
REGISTRATION_CLIENT_IP_HEADER=x-forwarded-for
X402_FACILITATOR_URL=https://your-facilitator.example
```

`TURNKEY_API_PRIVATE_KEY`, the auth encryption key, OAuth signing secret, and
admin token belong in a managed secret store in deployed environments, not in
repository or container-image layers.

This Beta schema intentionally does not migrate legacy ERC-4337 wallets or
credentials. Use a fresh PostgreSQL database when moving from the previous
architecture.

### Run

```bash
cargo run --bin jusso-server
```

The service starts only after it has reconciled the Turnkey payer, verified the
configured native-account implementation and execution token, and checked the
payer policy.

## Verification

Run the local suite:

```bash
cargo fmt --all -- --check
cargo test --all-targets
```

Run the Solidity fixture suite:

```bash
cd contracts
forge fmt --check
forge test --offline --force
```

The ignored live tests are stateful and use real provider wallets and VibeNet
transactions:

```bash
cargo test --test vibenet_smoke -- --ignored --nocapture
cargo test --test live_vibenet_e2e -- --ignored --nocapture
```

The end-to-end test covers registration, OAuth, wallet provisioning, VibeNet
funding, simulation, Turnkey sender and payer signatures, execution-fee
collection, confirmation, and idempotent replay.

## Security Properties

- No wallet private keys are stored by Jusso.
- Turnkey responses are verified by recovering every signature locally.
- Wallet creation is serialized and reconciled against provider state.
- The configured payer can be pinned to an expected address.
- Fee terms are bound to the execution payload and rechecked before signing.
- Signed transactions are persisted before broadcast for crash-safe replay.
- Per-account nonce preparation is serialized across workers with PostgreSQL
  advisory locks.
- Webhook destinations reject credentials, fragments, local addresses, private
  networks, and unsafe DNS resolution.
- OAuth assertions, DPoP proofs, enrollment grants, and x402 settlements have replay protection.
- Every queued signing request carries an expiring execution permit bound to
  the principal, agent, instance, policy version, payload, wallet, chain, and fee.
- Secrets are redacted from debug output and configured RPC URLs.
- Failed jobs retry with bounded attempts and move to a dead-letter queue.

## Roadmap to Beta

1. Continue VibeNet and local native-AA conformance testing as Base evolves the
   Cobalt implementation.
2. Deploy Jusso against Base Sepolia as soon as native accounts and payer
   transactions are available there.
3. Replace VibeNet USDV with verified Base Sepolia USDC configuration.
4. Revalidate contract addresses and reconnect the preserved protocol layers,
   beginning with the strongest Base test deployments.
5. Update the frozen documentation and agent-integration packages only after
   the Beta API is stable.
6. Complete operational staging: managed secrets, production PostgreSQL and
   Redis, Turnkey policies, monitoring, alerting, backups, and incident runbooks.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).

Jusso is developed by Ardent Research.
