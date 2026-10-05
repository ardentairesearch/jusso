# Jusso

Jusso is execution infrastructure for autonomous AI agents. The Beta runtime
targets Arc testnet. Each agent has a dedicated ERC-4337 smart account; its
Turnkey-managed key is the owner signer, **not** the address to fund. Alchemy
Wallet APIs prepare and submit sponsored UserOperations. A configured recipient
collects the USDC execution fee, while the gas policy pays Arc native USDC gas.

The Arc stack has passed a live Turnkey + Alchemy + Arc testnet execution,
including first-operation account deployment, sponsorship, atomic fee
settlement, and receipt verification. It is not production-ready until the
remaining checks in [TODO.md](TODO.md) are complete. Typed protocol HTTP routes
are enabled only for Uniswap V4 on Arc testnet, using pinned official
deployments. Preserved adapters, including Morpho, remain dormant because they
do not have a verified Arc testnet deployment.

## Execution Flow

1. An organization registers a principal and agent. Jusso provisions a
   tenant-scoped Turnkey signer and a separate counterfactual Arc smart account.
2. `GET /wallet` returns the smart-account address, including before its first
   deployment. Fund **that** address with USDC and assets the action will use.
3. `POST /simulate` or `POST /execute` validates the caller's authorization,
   prepares the full sponsored UserOperation, and estimates a USDC fee from
   the Arc gas cap. The default execution includes the USDC fee transfer and
   requested calls in one atomic smart-account batch.
4. The worker rechecks the permit and immutable request, signs the verified
   UserOperation digest with the agent's Turnkey signer, persists the signed
   operation, and submits it to Alchemy. Retries reuse that same signed payload.
5. The worker confirms the provider call, transaction receipt, and ERC-4337
   `UserOperationEvent` before marking success or recording the fee.

An optional x402 route can collect a settled payment before the action, but it
requires an Arc-capable facilitator configured with `X402_FACILITATOR_URL`.
It is not part of the default managed-wallet payment path.

## Boundaries

```text
Agent or developer
  -> OAuth + DPoP authentication and agent policy
  -> Jusso API: wallet lookup / simulate / execute / status
  -> Postgres permit + idempotent request; Redis execution queue
  -> Arc worker: full sponsored UserOperation validation
       -> tenant Turnkey signer (private key never enters Jusso)
       -> Alchemy Wallet API / bundler / gas policy
       -> Arc EntryPoint v0.7 -> dedicated smart account
            -> atomic USDC execution fee + requested calls
```

Turnkey custody is provider-neutral at the `WalletProvider` boundary. Jusso
organizations have separate Turnkey sub-organizations and tenant runtime
credentials. Smart-account addresses are persisted separately from Turnkey
signer addresses and bound to the agent, chain, and account provider. Native
Arc USDC uses 18 decimals for gas; its ERC-20 interface at
`0x3600000000000000000000000000000000000000` uses 6 decimals for transfers.

Self-service policies are Arc-only, permit only typed protocol routes, reject
native-value transfers, cap execution fees at one USDC, and deny raw execution
unless an organization owner creates and assigns an explicitly opted-in policy.
Every smart-account load independently checks the official factory derivation,
EntryPoint, implementation, and embedded Turnkey owner. Bring-your-own-wallet
is disabled.

## Integration Surfaces

Jusso exposes two remote Streamable HTTP MCP endpoints:

| Endpoint | Audience |
| --- | --- |
| `/mcp/agent` | Agent runtime tools: wallet, balance, Uniswap discovery, quotes, simulation, execution, and status |
| `/mcp/control` | Owner tools: agents, policies, connections, approvals, and signer lifecycle |

Compatible MCP clients connect directly over HTTPS and complete OAuth in a
browser. There is no local stdio MCP server or installer to keep synchronized.
Direct REST/OAuth access remains available for custom runtimes and services.
Client-specific certification is tracked in [TODO.md](TODO.md).

## Authentication

Organizations own stable agents. Principals have grants to those agents;
credentials authenticate principals; hosted runs become short-lived instances.
Local and workload-federated access tokens are short-lived and DPoP-bound.
Remote MCP clients use Authorization Code + PKCE and receive a bearer or
DPoP-bound token according to the client authorization request. Local
onboarding creates a P-256 key on the developer's machine, registers only its
public JWK, stores the key with `0600` permissions, and verifies wallet access:

```bash
cargo run --bin jusso -- onboard --organization "Acme" --agent-id treasury --accept-terms
```

Owners create another stable agent and one-time enrollment token through the
control MCP endpoint. The child runtime then enrolls with its own key, without
receiving the owner key:

```bash
cargo run --bin jusso -- enroll \
  --enrollment-token jso_enroll_REDACTED \
  --display-name "Research worker"
```

Hosted agents can use an organization-configured OIDC federation trust. Jusso
checks issuer, HTTPS JWKS, audience, and subject, and consumes proof IDs once
to prevent replay. Credential rotation does not change the stable agent's
Turnkey signer or Arc smart account.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /register` | Public, protected self-service organization onboarding |
| `GET /wallet` | Agent's dedicated Arc smart-account address and deployment state |
| `GET /wallet/balance` | One USDC balance via Arc's six-decimal interface |
| `POST /simulate` | Prepare sponsored call bundle without submitting |
| `POST /execute` | Idempotently queue a sponsored execution |
| `POST /x402/execute` | Optional facilitator-paid execution |
| `GET /status/{id}` | Execution status and transaction hash |
| `/protocols/uniswap-v4/*` | Arc testnet pool discovery, quotes, balances, simulation, and swaps |
| `GET /admin/fee-recipient/status` | Fee recipient USDC balance and Arc sponsor configuration |

`POST /execute` and `POST /x402/execute` require `Idempotency-Key`. Agent
authorization policies constrain chains, actions, contract targets, value,
and maximum execution fees. All integrations other than Uniswap V4 remain
outside the runtime.

## Local Setup

Requires Rust, PostgreSQL, Redis, a Turnkey parent organization with a P-256
API key permitted to create tenant sub-organizations, an Alchemy app with Arc
testnet Wallet API access and a funded gas sponsorship policy, and an Arc USDC
fee-recipient address. Configure a fresh database; `001_init.sql` contains the
current schema.

```dotenv
ARC_NETWORK=arc-testnet
ARC_RPC_URL=https://rpc.testnet.arc.io
ALCHEMY_API_KEY=<Alchemy app key>
ALCHEMY_GAS_POLICY_ID=<funded sponsorship policy ID>
ARC_MAX_SPONSORED_GAS_UNITS=2000000
ARC_MAX_SPONSORED_GAS_COST_WEI=100000000000000000
EXECUTION_FEE_RECIPIENT=0x<Arc fee-recipient address>
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

Public registration outside localhost additionally requires a Turnstile secret
and allowed hostnames. Review `src/config/mod.rs` for optional auth, rate-limit,
webhook, and x402 settings. Do not commit `.env` or Turnkey credentials. Arc
mainnet is disabled unless `ARC_NETWORK=arc` and `ARC_ENABLE_MAINNET=true`; do
not enable it before the separate mainnet rollout gate.

```bash
docker compose up -d
cargo run --bin jusso-arc-probe
cargo run --bin jusso-server
```

Startup verifies Arc chain ID, USDC decimals, EntryPoint v0.7 bytecode,
Alchemy bundler EntryPoint support, the fee-recipient token interface, and all
pinned Uniswap V4 contracts.
The probe is read-only and accepts `ARC_BALANCE_ADDRESS` or
`ARC_BUNDLER_RPC_URL` for additional checks.

## Railway Deployment

Deploy the repository as one Railway service using the included `Dockerfile`
and `railway.toml`, with separate managed PostgreSQL and Redis services. Give
only the Jusso service a public domain and pass the databases through Railway's
private `DATABASE_URL` and `REDIS_URL` references. Set `PUBLIC_API_BASE_URL`,
`WEBAUTHN_ORIGIN`, and `WEBAUTHN_RP_ID` to the final HTTPS domain before testing
passkey onboarding; WebAuthn credentials are bound to that origin and relying
party ID. The server applies migrations at startup and `/health` verifies both
datastores. Keep one application replica until queue-worker coordination and
multi-replica operations are separately certified.

## Verification

```bash
cargo fmt --check
cargo check --all-targets
cargo test arc:: --lib
cargo test protocols:: --lib
```

The Arc testnet path has passed registration, tenant Turnkey signer creation,
counterfactual account derivation, first-operation deployment, sponsored
execution, and atomic fee settlement. Account loads now independently verify
Alchemy's official MAv2 factory derivation, embedded owner, implementation, and
EntryPoint. Crash recovery, sponsorship rejection, and protocol-specific Arc
deployment tests remain release gates. Other preserved adapters are
intentionally not compiled or routed until they have a verified Arc deployment.

## License

AGPL-3.0-only. See [LICENSE](LICENSE).
