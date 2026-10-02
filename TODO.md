# Pre-Beta Security TODO

Only unfinished work belongs in this file. Completed items are removed rather
than retained as a historical checklist.

## Arc Production Readiness

- [ ] Configure production Alchemy Gas Manager policy-wide and per-sender
  budgets, sender controls, expiry, billing alerts, and incident thresholds.
- [ ] Revalidate Morpho only after a verified Arc deployment and active markets
  become available; keep it disabled until then.
- [ ] Complete a separately gated Arc mainnet rollout.

## Bring Your Own Wallet

- [ ] Keep BYOW disabled until the managed-account path is production-proven
  and an external-wallet authorization model is specified and tested.
- [ ] Revalidate Arc account ownership, delegated signing, sponsorship policy,
  replay protection, revocation, and recovery behavior.
- [ ] Require a signed ownership challenge before binding an external account
  to a Jusso organization or agent.
- [ ] Model BYOW as a separate provider capability; never import or retain an
  external wallet private key.
- [ ] Bind every delegated authority to organization, agent, chain, actions,
  targets, value limits, expiry, and a revocation nonce.
- [ ] Add end-to-end tests for enrollment, simulation, execution, expiry,
  revocation, signer rotation, and compromised-agent containment.

## Policy Hardening

- [ ] Add conservative per-transaction and rolling-window limits for token
  spend, borrowed value, execution fees, and sponsored native gas.
- [ ] Require explicit opt-in for borrowing, leverage, withdrawals to new
  recipients, unlimited approvals, and other high-risk protocol actions.
- [ ] Mirror enforceable wallet-signing restrictions into Turnkey policies,
  while keeping Jusso authorization as the first policy boundary.
- [ ] Add policy migration, policy-version pinning, denial audit events, and
  adversarial tests before changing the self-service default.

## Owner And Agent Lifecycle

- [ ] Add owner-facing recovery and passkey addition, replacement, and removal
  without introducing a standing admin secret.
- [ ] Add notification and expiry handling for abandoned approval requests.

## Turnkey Operations

- [ ] Move `TURNKEY_CREDENTIAL_ENCRYPTION_KEY` to a managed KMS/HSM-backed
  secret service and define credential rotation procedures.
- [ ] Add operator reconciliation for Turnkey sub-organizations left in a
  provisioning or failed state after an interrupted API call.
- [ ] Add customer-facing recovery-key rotation and a separately controlled
  Jusso break-glass process with audited, time-bound access.
