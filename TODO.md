# Pre-Beta Security TODO

These items are intentionally deferred, not forgotten. They block the relevant
feature from being declared production-ready.

## Arc Execution Migration

Live Arc testnet validation completed on 2026-09-23. The first operation
deployed the agent's dedicated smart account and confirmed an atomic USDC fee
plus action UserOperation in transaction
`0xa88fd0a189e8030d572326bddcdd783174626debcda0ecdbedd9d4c5b7786522`.

- [x] Separate the agent's Arc smart-account address from its Turnkey signer
  address in the account model and persistence boundary.
- [x] Require explicit non-7702 Modular Account v2 provisioning and reject a
  provider response that returns the signer address as the agent account.
- [x] Verify a dedicated Modular Account v2 ERC-4337 account on Arc testnet
  with a tenant-scoped Turnkey owner signer, Alchemy Wallet APIs, Gas Manager
  sponsorship, and EntryPoint v0.7.
- [x] Validate the sponsored prepare, sign, submit, and receipt flow with a
  live Turnkey tenant signer. Reject responses that are not explicitly
  sponsored or that permit a nonzero user gas payment.
- [x] Independently verify the provider-returned counterfactual smart-account
  address and owner against the deployed factory before production use.
- [x] Wire wallet lookup, simulation, and execution to the dedicated Arc
  smart-account address rather than the Turnkey signer address.
- [x] Test first-operation smart-account deployment with a live tenant signer.
- [x] Replace Base EIP-8130/EIP-8168 signing, simulation, queue submission,
  receipt parsing, and payer policy with ERC-4337 UserOperation handling in code.
- [x] Require successful fee-inclusive sponsored preparation before accepting
  an execution quote, then verify the provider call, transaction receipt, and
  expected `UserOperationEvent` before settlement.
- [x] Verify that the execution fee and requested calls settle atomically while
  Alchemy's configured Gas Manager policy sponsors native gas.
- [x] Enforce independent per-operation sponsored-gas unit and native-USDC cost
  caps in Jusso, and test that Gas Manager policy rejection fails closed.
- [ ] Configure production Alchemy Gas Manager policy-wide and per-sender
  budgets, sender controls, expiry, and billing alerts.
- [x] Verify Arc's 18-decimal native USDC and 6-decimal ERC-20 USDC interface at
  every balance, gas, fee, transfer, and receipt boundary.
- [x] Persist signed UserOperations and call IDs so worker retries reuse the
  same authorization and can recover a submission after a crash.
- [x] Isolate blocking worker Redis connections from API traffic and bound
  failed signed-operation retries before dead-lettering.
- [x] Preserve the sponsorship capability through submission and normalize
  Turnkey recovery IDs to canonical Ethereum signature encoding.
- [x] Atomically finalize the transaction, managed fee record, and terminal
  execution state with conflict-checked replay handling.
- [x] Prove process-interruption recovery and exactly-once settlement with a
  live Arc test that resumes the same signed UserOperation. Validated on
  2026-09-24 in transaction
  `0x306694d70420b3b217e33f620c2d72c0aa8564c2644d19daa9e28dea709f424f`.
- [x] Pin and revalidate the official Uniswap V4 Arc testnet deployment before
  enabling pool reads, discovery, quotes, simulations, and swaps.
- [ ] Revalidate Morpho only after a verified Arc testnet deployment and active
  markets become available; keep it disabled until then.
- [x] Keep every protocol other than Uniswap V4 out of the Arc
  runtime until it has a supported deployment and dedicated validation pass.
- [x] Run registration, OAuth/DPoP, wallet provisioning, funding, simulation,
  first deployment, sponsored execution, fee settlement, and status checks
  end to end on Arc testnet.
- [ ] Complete a separately gated Arc mainnet rollout.

## Bring Your Own Wallet

- [ ] Keep BYOW disabled until the Arc managed-account path is proven and an
  external-wallet authorization model is specified and tested.
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

## Default Policy Hardening

- [x] Replace the broad self-service runtime policy before protocol execution
  routes are re-enabled.
- [x] Default to Arc only, typed protocol actions only, zero arbitrary
  native-value transfer, and a conservative per-execution fee ceiling.
- [x] Pin verified Uniswap V4 Arc targets and keep unsupported protocol targets
  unavailable instead of falling back to assumed deployments.
- [ ] Add conservative per-transaction and rolling-window limits for token
  spend, borrowed value, execution fees, and sponsored native gas.
- [x] Require explicit policy opt-in for arbitrary calldata routes.
- [ ] Require explicit opt-in for borrowing, leverage, withdrawals to new
  recipients, unlimited approvals, and policy changes.
- [ ] Mirror enforceable wallet-signing restrictions into Turnkey policies,
  while keeping Jusso authorization as the first policy boundary.
- [ ] Add policy migration, policy-version pinning, denial audit events, and
  adversarial tests before changing the self-service default.

## Policy Management UX

- [ ] Add owner-facing CLI commands and a dashboard flow to create, review,
  assign, list, and revoke structured authorization policies.
- [ ] Let AI help draft a policy from plain language, but require the owner to
  review and confirm the exact structured permissions before assignment.
- [ ] Show effective agent permissions, dangerous opt-ins, affected targets,
  limits, and policy changes before activation.

## Turnkey Operations

- [ ] Move `TURNKEY_CREDENTIAL_ENCRYPTION_KEY` to a managed KMS/HSM-backed
  secret service and document rotation of encrypted tenant API credentials.
- [ ] Add operator reconciliation for Turnkey sub-organizations left in a
  provisioning or failed state after an interrupted API call.
- [ ] Add customer-facing recovery-key rotation and a separately controlled
  Jusso break-glass process with audited, time-bound access.
