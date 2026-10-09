# Pre-Beta TODO

Only unfinished release work belongs here.

## Payment Workflow Readiness

- [ ] Run end-to-end Arc testnet tests for plan creation, passkey approval,
  scheduled execution, insufficient balance, pause, resume, cancellation,
  webhook delivery, and transaction reconciliation.
- [ ] Certify scheduler crash recovery, lease expiry, retry backoff, duplicate
  prevention, downtime behavior, and multi-replica operation under load.
- [ ] Add owner notification and expiry handling for abandoned approvals and
  failed/skipped payment runs.
- [ ] Add operational alerts for scheduler lag, repeated run failures, queue
  backlog, sponsor rejection, low fee-recipient balance, and webhook failures.
- [ ] Decide and document retention/export rules for plans, run snapshots,
  approvals, audit events, and execution records.

## Funding Readiness

- [ ] Confirm Onramper supports Arc mainnet USDC in each launch market and pin
  the provider's production asset/network identifiers.
- [ ] Complete provider sandbox and production checkout tests for wallet
  locking, signature verification, expiry, replay rejection, KYC handoff,
  cancellation, and successful onchain settlement.
- [ ] Add provider-status observability without storing card, bank, or identity
  data in Jusso.

## Swap And Treasury Yield

- [ ] Keep token-swap tools disabled until the provider can execute from the
  agent's ERC-4337 smart account. Turnkey Swap currently prices and executes
  from a Turnkey wallet account; the Turnkey signer must never be presented as
  a deposit wallet or used as a second custody location.
- [ ] Validate Arc testnet support, smart-account sender support, quote expiry,
  allowance scope, slippage limits, minimum received amounts, route integrity,
  fee disclosure, simulation, and idempotent recovery before enabling swaps.
- [ ] Keep reserve-yield tools disabled until Turnkey Earn supports Arc and the
  owner-approved policy model includes a minimum liquid reserve, allocation
  cap, allowlisted vaults, withdrawal path, loss disclosure, and emergency exit.
- [ ] Require owner approval for enabling either capability and expose separate
  policy actions and rolling limits for swaps, deposits, and withdrawals.

## Arc Production Readiness

- [ ] Configure production Alchemy Gas Manager policy-wide and per-sender
  budgets, sender controls, expiry, billing alerts, and incident thresholds.
- [ ] Complete a separately gated Arc mainnet rollout and rollback exercise.

## MCP Client Certification

- [ ] Run end-to-end remote MCP OAuth tests with supported production clients
  and an official SDK client, covering discovery, PKCE, callback/issuer binding,
  refresh, revocation, and the unified agent-bound tool surface.

## Owner And Agent Lifecycle

- [ ] Complete customer recovery-authenticator rotation and a separately
  controlled, audited, time-bound break-glass process.
- [ ] Reconcile Turnkey sub-organizations left in provisioning or failed states
  after interrupted provider calls.
- [ ] Move `TURNKEY_CREDENTIAL_ENCRYPTION_KEY` to a managed KMS/HSM-backed
  secret service and document rotation procedures.

## Bring Your Own Wallet

- [ ] Certify Circle Agent Wallet on Arc testnet end to end: deployed-wallet
  ownership proof, owner approval, scheduled intent creation, Circle CLI
  transfer, receipt verification, expiry, revocation, and reconnect.
- [ ] Add notifications for pending Circle payment intents so an always-on
  agent runtime can pick them up promptly without aggressive polling.
- [ ] Revisit a delegated Circle server API only if Circle publishes a stable,
  documented authorization flow that does not transfer the owner's CLI session
  or MPC secret material to Jusso.
