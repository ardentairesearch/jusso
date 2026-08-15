# Webhooks

You can receive execution completion updates through a callback URL instead of polling only.

## 1. Enable callback

Include `callback_url` in your `POST /execute` request body.

Example field:

```json
"callback_url": "https://your-system.example.com/webhook/execution"
```

## 2. URL requirements

Use a secure HTTPS endpoint you control.

Recommended:

1. Return `200` quickly.
2. Process payload asynchronously in your system.
3. Store webhook payload for audit and retries.

## 3. Signature model

Platform webhook calls are signed with HMAC SHA256.

Header format:

```bash
X-Webhook-Signature: sha256=<hex>
```

Design your receiver to validate signature before processing payload.

## 4. Delivery model

Expect occasional retries due to transient network conditions. Your receiver should be idempotent.

## 5. Recommended receiver checks

1. Verify signature.
2. Validate request schema.
3. Enforce idempotency by request ID.
4. Persist event.
5. Trigger internal workflow updates.
