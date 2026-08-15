# Execution Fees

Ardent uses one execution-payment model for normal API calls.

## Atomic USDC fee

Every `POST /execute` and protocol execution endpoint:

1. Simulates the requested protocol action.
2. Calculates sponsored gas cost, markup, and platform fee.
3. Prepends a USDC transfer to the chain's VerifyingPaymaster.
4. Simulates the complete fee-inclusive UserOperation.
5. Submits the UserOperation with native gas sponsored by Ardent.

The USDC fee transfer and protocol action share one atomic `executeBatch`.
Either every call succeeds or every call reverts. A failed protocol action
cannot leave behind a successful execution-fee transfer.

`POST /simulate` uses the same fee-inclusive batch and returns
`execution_fee_token` and `execution_fee_raw`.

## x402 V2

`POST /x402/execute` is an alternative for an independent wallet that pays
USDC while Ardent executes through an Ardent-managed smart wallet.

1. Call without `PAYMENT-SIGNATURE`.
2. Receive HTTP 402 and a base64 JSON `PAYMENT-REQUIRED` header.
3. Sign the advertised `exact` USDC payment requirement.
4. Copy `extensions.ardentRequestId` into the payment payload extensions.
5. Repeat the identical body with `PAYMENT-SIGNATURE`.
6. Ardent verifies and settles through the configured facilitator.
7. Read the settlement result from `PAYMENT-RESPONSE`.

The payment is bound to the payload, locked quote, chain USDC contract,
paymaster recipient, CAIP-2 network, and timeout.

## Delegated accounts

User-owned delegated accounts use the same atomic USDC model. Their on-chain
session policy must allow the USDC transfer to the VerifyingPaymaster and every
protocol target and selector. The account enforces its validity window and
spending limits.
