# Agent Integration

The agent integration pack ships everything needed to connect to the AI agent blockchain execution platform — whether you are a developer scripting from the terminal, a team using AI coding tools, or an agent framework that needs a typed API contract.

It includes a one-line installer, a zero-dependency CLI, an MCP server for AI desktop tools, and an OpenAPI 3.1 spec.

Run the installer once to get everything:

```bash
curl -fsSL https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration/install.sh | bash
```

Then set your key:

```bash
export ARDENT_API_KEY="your_api_key"
```

The installer adds `~/.local/bin` to common shell startup files when needed, including zsh login and interactive profiles. Open a new terminal after install. If `ardent` is still not found, run:
>
> ```bash
> export PATH="${HOME}/.local/bin:${PATH}"
> ```

## Who each integration is for

### Developers and engineers — the `ardent` CLI

**Best for:** engineers who want to test, debug, or script against the platform from the terminal without writing HTTP clients.

The CLI is a single Python file with no external dependencies. Install once, run anywhere Python 3.8+ is available.

**When to use it:**

- Smoke testing a new API key before writing integration code.
- Running simulate and execute manually during contract development.
- Scripting execution flows from shell scripts, Makefiles, or CI pipelines.
- Quickly checking execution status without opening a browser or writing curl.

#### Example: verify a new key, resolve a wallet, run a simulation

```bash
ardent health
ardent wallet --agent-id my-agent-001 --chain ethereum
ardent simulate \
  --agent-id my-agent-001 \
  --chain ethereum \
  --target-contract 0xTokenContract \
  --calldata 0xTransferCalldata \
  --value 0
```

#### Example: execute and poll status in a shell script

```bash
ardent execute \
  --agent-id deploy-bot \
  --chain base \
  --target-contract 0xFactory \
  --calldata 0xDeployCalldata \
  --value 0

ardent status --request-id your_request_id
```

**Full command reference:**

```bash
ardent --version
ardent health
ardent feed                             # public activity feed
ardent wallet         --agent-id <id> --chain <chain>
ardent wallet-balance --agent-id <id> --chain <chain>   # native + ERC-20 token balances
ardent simulate --agent-id <id> --chain <chain> --target-contract <addr> --calldata <hex> --value <wei>
ardent execute  --agent-id <id> --chain <chain> --target-contract <addr> --calldata <hex> --value <wei>
ardent aave-balances --agent-id <id>                   # Aave reserve wallet/aToken/debt balances
ardent aave-position --agent-id <id>                   # Aave account data and health factor
ardent compound-balances --agent-id <id>               # Compound wallet/protocol balances
ardent compound-position --agent-id <id>               # Compound base supply, debt, and collateral
ardent compound-borrow-capacity --agent-id <id>        # Compound available borrow and rates
ardent compound-markets                                # Verified Base Sepolia Comet registry
ardent morpho-markets --loan-token <addr>              # Discover risk-filtered Morpho markets
ardent morpho-market                                   # Morpho market parameters and liquidity
ardent morpho-position --agent-id <id>                 # Morpho balances, health, and capacity
ardent balancer-pool --pool <pool>                     # Balancer pool state and registered tokens
ardent balancer-pools --token-in <addr> --token-out <addr> # Discover matching Balancer pools
ardent balancer-balances --agent-id <id> --pool <pool> # Balancer BPT and pool-token balances
ardent balancer-quote --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent balancer-swap-simulate --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent balancer-swap --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent balancer-add-liquidity-quote --agent-id <id> --pool <pool> --amount-in <token=raw>
ardent balancer-add-liquidity-simulate --agent-id <id> --pool <pool> --amount-in <token=raw>
ardent balancer-add-liquidity --agent-id <id> --pool <pool> --amount-in <token=raw>
ardent balancer-remove-liquidity-quote --agent-id <id> --pool <pool> --bpt-amount-in-raw <raw>
ardent balancer-remove-liquidity-simulate --agent-id <id> --pool <pool> --bpt-amount-in-raw <raw>
ardent balancer-remove-liquidity --agent-id <id> --pool <pool> --bpt-amount-in-raw <raw>
ardent uniswap-v4-pools --token-a <addr> --token-b <addr> # Discover matching V4 pool keys
ardent uniswap-v4-quote --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent uniswap-v4-swap-simulate --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent uniswap-v4-swap --agent-id <id> --token-in <addr> --token-out <addr> --amount-raw <raw>
ardent status   --request-id <id>
ardent self-update                      # updates CLI plus ~/.ardent runtime files
ardent self-update --cli-only           # updates only the CLI
```

---

### AI assistant users — the MCP server

**Best for:** developers and power users who run Codex, Claude Desktop, ChatGPT Desktop, Cursor, or Windsurf and want their AI tool to call the Ardent platform directly during a session.

The MCP server (`~/.ardent/mcp_server.py`) speaks the Model Context Protocol over stdio. Once registered, the AI assistant can invoke Ardent tools in response to natural language without you writing any code or curl commands.

The installer configures Codex by default and automatically patches the config file for other supported apps it detects.

| App | Config file patched |
| --- | --- |
| Codex | `~/.codex/config.toml` |
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| ChatGPT Desktop | `~/Library/Application Support/com.openai.chat/mcp_servers.json` |
| Cursor | `~/.cursor/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

> **You must configure a credential after install.**
> The installer writes `your_api_key_here` as a placeholder in the `env` block
> of each patched config. For an API key, replace it with the real value. For
> an autonomous service account, replace the `env` object with:
>
> ```json
> {
>   "ARDENT_CLIENT_ID": "ard_sa_your_client_id",
>   "ARDENT_CLIENT_PRIVATE_KEY_FILE": "/absolute/path/to/service-account.pem",
>   "ARDENT_OAUTH_SCOPE": "wallet:read protocol:read transaction:simulate transaction:execute"
> }
> ```
>
> The PEM file must have `0600` permissions. Fully quit and reopen the app
> after editing its config.
>
> The patched entry looks like this: `"env": { "ARDENT_API_KEY": "your_api_key_here" }`
>
> Re-running the installer preserves existing API-key and service-account
> environment entries.

**When to use it:**

- Asking Claude to simulate a specific contract call and tell you the estimated cost before you commit to running it.
- Using Cursor to execute a transaction mid-session while building a contract integration, without leaving the editor.
- Asking ChatGPT to fetch recent platform activity or check whether an earlier request confirmed.
- Letting Windsurf handle the full simulate → execute → status loop in a guided workflow.

**Example conversations once the MCP server is active:**

> *"What are the current token balances for agent-001 on Base?"*

> *"Show my Aave wallet, supplied, and debt balances for agent-001."*

> *"Show my Compound III supplied balances and debt for agent-001 on Base."*

> *"Show my Morpho collateral, debt, health factor, and available borrow for agent-001."*

> *"Quote and simulate an exact-input Balancer V3 swap for agent-001 on Sepolia."*

> *"Simulate a transfer of 100 USDC from my agent wallet on Base and tell me the gas cost."*

> *"Execute the approve and swap sequence for agent-001 on Ethereum. Use the calldata I just generated."*

> *"What is the current status of request ID abc-123?"*

> *"Show me the last 10 executions on the public feed."*

The assistant calls the appropriate tool (`ardent_simulate`, `ardent_execute`, `ardent_status`, `ardent_feed_recent`) and returns the result directly in the conversation.

**Manual MCP registration** (for any other MCP-compatible AI):

```bash
python3 ~/.ardent/mcp_server.py
```

**MCP tools available:**

| Tool | What it does |
| --- | --- |
| `ardent_health` | Check API reachability |
| `ardent_feed_recent` | Fetch public execution activity |
| `ardent_get_wallet` | Resolve or provision an agent smart wallet |
| `ardent_wallet_balance` | Get native + ERC-20 token balances for an agent wallet |
| `ardent_aave_balances` | Read Aave reserve wallet, supplied aToken, and debt balances |
| `ardent_aave_position` | Read Aave account data, borrowing capacity, and health factor |
| `ardent_compound_balances` | Read Compound wallet and protocol balances |
| `ardent_compound_position` | Read Compound base supply, base debt, and collateral balances |
| `ardent_compound_markets` | List and verify Base Sepolia Comet markets |
| `ardent_morpho_markets` | Discover and rank filtered Morpho markets |
| `ardent_morpho_market` | Read Morpho market parameters, liquidity, utilization, and rate |
| `ardent_morpho_position` | Read Morpho wallet balances, position, health, and capacity |
| `ardent_morpho_supply_collateral_simulate` | Simulate supplying Morpho collateral |
| `ardent_morpho_borrow_simulate` | Simulate borrowing from Morpho |
| `ardent_morpho_repay_simulate` | Simulate partial or full Morpho repayment |
| `ardent_balancer_pool` | Read Balancer pool state, registered tokens, balances, and fee |
| `ardent_balancer_pools` | Discover pair-compatible pools and verify Vault state |
| `ardent_balancer_balances` | Read Balancer BPT and pool-token wallet balances |
| `ardent_balancer_swap_quote` | Discover and quote the best Balancer pool or pin an explicit pool |
| `ardent_balancer_swap_simulate` | Fully simulate the Permit2 plus Router swap batch |
| `ardent_balancer_swap_execute` | Execute an automatically selected or explicitly pinned Balancer pool swap |
| `ardent_balancer_add_liquidity_quote` | Quote BPT output for an unbalanced liquidity addition |
| `ardent_balancer_add_liquidity_simulate` | Fully simulate liquidity addition and approval cleanup |
| `ardent_balancer_add_liquidity_execute` | Add liquidity and receive BPT |
| `ardent_balancer_remove_liquidity_quote` | Quote proportional token outputs for a BPT burn |
| `ardent_balancer_remove_liquidity_simulate` | Fully simulate proportional liquidity removal |
| `ardent_balancer_remove_liquidity_execute` | Burn BPT and receive all pool tokens proportionally |
| `ardent_uniswap_v4_pools` | Discover matching V4 pool keys and current state |
| `ardent_uniswap_v4_swap_quote` | Discover and quote the best direct V4 pool |
| `ardent_uniswap_v4_swap_simulate` | Simulate the selected Universal Router swap bundle |
| `ardent_uniswap_v4_swap_execute` | Execute the selected V4 swap |
| `ardent_simulate` | Simulate a transaction and return estimated cost |
| `ardent_execute` | Submit a transaction for execution |
| `ardent_status` | Poll execution request status |

---

### Product teams and framework builders — the OpenAPI spec

**Best for:** teams building their own agents or products on top of the AI agent blockchain execution layer, and anyone who needs a typed API contract to generate clients or configure tool-calling frameworks.

The spec (`~/.ardent/openapi.yaml`) is OpenAPI 3.1 and covers all user-facing endpoints.

**When to use it:**

- Generating a typed HTTP client in any language using `openapi-generator` or similar tooling.
- Configuring a ChatGPT custom action so your GPT can call Ardent endpoints directly from a product.
- Loading the spec into an agent framework (LangChain, AutoGen, etc.) as a tool schema source.
- Mocking the Ardent API in integration tests.
- Sharing exact request and response shapes with the rest of your team.

#### Example: generate a Python client

```bash
openapi-generator generate \
  -i ~/.ardent/openapi.yaml \
  -g python \
  -o ./ardent-client
```

#### Example: load into a ChatGPT custom action

In your GPT configuration, upload `openapi.yaml` under Actions. The GPT will automatically have access to all Ardent endpoints as callable actions with correct schemas.

---

### LLM agents with direct HTTP access — the agent playbook

**Best for:** autonomous AI agents that already have direct HTTP tool access and need a machine-readable reference for the correct execution flow, guardrails, and canonical request patterns.

The `skills.md` file is designed to be loaded as a system prompt or injected as context. It covers:

1. The canonical simulate → execute → status loop.
2. How to handle `402 payment_required` correctly.
3. Guardrails that prevent common agent mistakes (inventing payment amounts, changing `request_id` between calls, executing without simulating).

Full skills file:
`https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration/skills.md`

---

## Integration files reference

| File | Purpose | Used by |
| --- | --- | --- |
| `install.sh` | One-line installer | Everyone |
| `ardent_cli.py` | Zero-dependency CLI | Developers, scripts, CI |
| `mcp_server.py` | stdio MCP server | Codex, Claude, ChatGPT, Cursor, Windsurf |
| `oauth_client.py` | Automatic service-account token refresh | CLI and MCP runtime |
| `mcp-tools.json` | MCP tool definitions | `mcp_server.py` |
| `openapi.yaml` | Generated bundled OpenAPI 3.1 spec | ChatGPT custom actions, code generators, framework builders |
| `openapi/` | Split OpenAPI source + bundler | Maintainers |
| `skills.md` | Setup guide and agent playbook | Humans and LLM system prompts |
