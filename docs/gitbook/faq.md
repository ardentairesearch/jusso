# FAQ

## 1. Do I need to create a wallet before execute

No separate wallet creation endpoint is required. `GET /wallet` resolves or provisions it for your agent. `POST /execute` also resolves wallet context as part of processing.

## 2. Can I use one API key for many agents

Yes. Agent identity is namespaced under the stable organization, not an
individual credential. Use stable `agent_id` values so each agent maps
consistently to its smart wallet even after key rotation.

## 3. How do I create an agent_id

You do not need to register or create an `agent_id` in advance. It is a free-form string you choose — any stable slug, name, or UUID works (for example `trading-bot-01`, `my-deploy-agent`, or `550e8400-e29b-41d4-a716-446655440000`).

The platform automatically provisions a dedicated ERC-4337 smart wallet the
first time it sees a new `agent_id` in your organization. From that point on,
every authorized credential in that organization maps the same `agent_id` to
the same wallet.

The only rule: keep the value stable. Changing `agent_id` for the same logical agent creates a new wallet.

API keys can be rotated without changing wallet addresses. Autonomous service
accounts use short-lived OAuth tokens and can be revoked immediately.

## 5. Is `chain` required on wallet endpoint

No. If omitted, default is `ethereum`.

## 6. Should frontend code call protected endpoints directly

No long-lived credential should be embedded in frontend or mobile app code.
Use a trusted backend, a remote tool server, or short-lived user-bound tokens.

## 7. How do I monitor execution completion

You can combine both methods.

1. Poll `GET /status/:id`.
2. Provide `callback_url` on execute for push updates.

## 8. Why did execution fail on the USDC fee

Most common causes are:

1. The smart wallet does not hold enough chain USDC.
2. The configured USDC address does not match the active network.
3. The delegated session's maximum fee is too low.
4. The full fee-inclusive UserOperation reverted during simulation.

## 9. Can I execute batch transactions

Yes. Use `batch_calls` with each call containing `target_contract`, `value`, and `calldata`.

## 10. How do I keep integration predictable in production

Use this operating pattern:

1. Simulate first.
2. Execute second.
3. Persist every request ID.
4. Track status until terminal state.
5. Store webhook events and status snapshots for audit.

## 11. Which execution-fee token is accepted

USDC is the only execution-fee token. Circle faucet USDC is available at
`https://faucet.circle.com`.

## 12. Is there a CLI instead of raw curl

Yes. Run the one-line installer:

```bash
curl -fsSL https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration/install.sh | bash
```

This installs an `ardent` command with subcommands for every platform operation: `health`, `feed`, `wallet`, `wallet-balance`, `simulate`, `execute`, `status`, Aave commands, and `self-update`.

See [Agent Integration](agent-integration.md).

## 14. Can I use Ardent tools inside Codex, Claude, ChatGPT, Cursor, or Windsurf

Yes. The installer auto-patches MCP configs for supported apps if they are detected on your machine.

After install, restart the desktop app and Ardent tools such as `ardent_health`, `ardent_get_wallet`, `ardent_simulate`, `ardent_execute`, `ardent_aave_balances`, `ardent_aave_position`, and `ardent_status` will appear in the tool list.

For manual or other MCP-compatible runtimes, point them at:

```bash
python3 ~/.ardent/mcp_server.py
```

## 15. What is the public activity feed endpoint

`GET /feed/recent` returns recent execution activity and requires no authentication.

```bash
curl -X GET "https://api.ardentresearch.xyz/feed/recent?limit=12"
# or
ardent feed
```

Use it to confirm the API is reachable or to monitor platform activity.
