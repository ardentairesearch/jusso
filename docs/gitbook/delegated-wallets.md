# Delegated Wallets

Delegated wallets let Ardent execute autonomously from a user-owned smart account
without receiving the owner's private key.

## Security model

`DelegatedAccount` validates every session-signed ERC-4337 UserOperation on-chain.
The owner configures:

1. Session start and expiry.
2. Allowed contract addresses and four-byte function selectors.
3. Maximum native value per operation.
4. Chain USDC, the VerifyingPaymaster recipient, and a maximum fee per operation.
5. A requirement that the atomic batch contains the approved fee transfer.

The ERC-4337 UserOperation hash binds every signature to the account, EntryPoint,
chain, nonce, calldata, gas fields, and paymaster data. Reconfiguring a session
increments its permission epoch, immediately invalidating its old allowlist.

## Setup

1. Deploy `DelegatedAccountFactory` using the deterministic deployment script.
2. Call `createAccount(owner, salt)` on the factory.
3. Call `POST /delegations/register` with the deployed account and policy.
4. The response contains `enable_transaction`.
5. The account owner sends that transaction to the delegated account.
6. Check activation with `GET /delegations/{agent_id}?chain=...`.
7. Use normal simulate, execute, and protocol endpoints with the same `agent_id`.

Ardent generates and encrypts the session key. The key is never returned, logged,
or stored in plaintext.

## Revocation

Call `POST /delegations/{agent_id}/revoke/prepare`. The returned transaction must
be sent by the account owner. Revocation is enforced by the account immediately.

## Registration example

```bash
curl -X POST "$BASE_URL/delegations/register" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "user-owned-agent",
    "chain": "base",
    "account_address": "0xYourDeployedDelegatedAccount",
    "valid_until": 1798761600,
    "max_native_value_raw": "10000000000000000",
    "max_fee_raw": "1000000",
    "permissions": [
      {
        "target": "0xAllowedProtocolContract",
        "selector": "0x12345678"
      }
    ]
  }'
```

Amounts are unsigned decimal strings in the asset's smallest unit.
