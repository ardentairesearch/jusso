# AI Agent Blockchain Execution Integration

Everything needed to connect developers, AI agents, and LLM platforms to the AI Agent Blockchain Execution API.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration/install.sh | bash
```

The installer:

- Places the `ardent` CLI in `~/.local/bin`
- Adds `~/.local/bin` to common shell startup files (`.zshrc`, `.zprofile`, `.bashrc`, `.bash_profile`, `.profile`, and fish config when relevant) so new terminals can find `ardent`
- Downloads MCP server + runtime files into `~/.ardent/`
- Configures **Codex** MCP by default, and auto-patches MCP configs for **Claude Desktop, ChatGPT Desktop, Cursor, and Windsurf** when detected
- Preserves existing API-key and service-account environment entries in those configs

## Set credentials

```bash
export ARDENT_API_KEY="your_api_key"
```

Short-lived OAuth tokens are also accepted by the CLI and local MCP proxy:

```bash
export ARDENT_ACCESS_TOKEN="your_short_lived_access_token"
```

For unattended agents, configure the service account instead of pasting an
access token:

```bash
chmod 600 ~/.ardent/service-account.pem
export ARDENT_CLIENT_ID="ard_sa_your_client_id"
export ARDENT_CLIENT_PRIVATE_KEY_FILE="$HOME/.ardent/service-account.pem"
# Optional: request a narrower subset of the account's granted scopes.
export ARDENT_OAUTH_SCOPE="wallet:read protocol:read transaction:simulate transaction:execute"
```

The CLI and MCP server use OpenSSL to sign a five-minute assertion, exchange
it for an access token, and refresh the token in memory before it expires.
Ardent receives only the signed assertion; the PEM file remains local.

Configure one method. The MCP proxy checks a supplied access token, then
service-account OAuth, then an API key. The CLI honors an explicit
`--api-key`/`ARDENT_API_KEY` first, then a supplied access token, then
service-account OAuth.

> If `ardent` is not found after install, add `~/.local/bin` to your PATH:
>
> ```bash
> export PATH="${HOME}/.local/bin:${PATH}"
> ```

## CLI commands

### General

```bash
ardent --version
ardent health
ardent feed                             # public activity feed
ardent wallet         --agent-id my-agent-001 --chain ethereum
ardent wallet-balance --agent-id my-agent-001 --chain ethereum   # native + ERC-20 balances
ardent simulate --agent-id my-agent-001 --chain ethereum --target-contract 0xTargetContract --calldata 0xCalldata --value 0
ardent execute --agent-id my-agent-001 --chain ethereum --target-contract 0xTargetContract --calldata 0xCalldata --value 0
ardent status --request-id your_request_id
```

### Delegated wallets

```bash
ardent delegation-register \
  --agent-id user-owned-agent \
  --chain base \
  --account-address 0xYourDelegatedAccount \
  --valid-until 1798761600 \
  --max-native-value-raw 10000000000000000 \
  --max-fee-raw 1000000 \
  --permission 0xAllowedProtocolContract:0x12345678

ardent delegation-status --agent-id user-owned-agent --chain base
ardent delegation-revoke-prepare --agent-id user-owned-agent
```

Registration returns an `enable_transaction` that the account owner must send.
Revocation preparation likewise returns an owner transaction; Ardent never asks
for or receives the owner key.

### Aave V3 Sepolia

```bash
ardent aave-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent aave-supply --agent-id my-agent-001 --asset USDC --amount 1.25
ardent aave-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-withdraw --agent-id my-agent-001 --asset USDC --amount max
ardent aave-repay-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent aave-repay --agent-id my-agent-001 --asset USDC --amount max
ardent aave-borrow-simulate --agent-id my-agent-001 --asset USDC --amount max --min-health-factor 1.10
ardent aave-borrow --agent-id my-agent-001 --asset USDC --amount max --min-health-factor 1.10
ardent aave-position --agent-id my-agent-001
ardent aave-balances --agent-id my-agent-001
```

### Compound III Base Sepolia

Base Sepolia supports the `usdc` market at `0x571621Ce60Cebb0c1D442B5afb38B1663C6Bf017` and the `weth` market at `0x61490650AbaA31393464C3f34E8B29cd1C44118E`.

```bash
ardent compound-markets
ardent compound-supply-simulate --agent-id my-agent-001 --asset USDC --amount 1.25
ardent compound-supply --agent-id my-agent-001 --asset USDC --amount 1.25
ardent compound-withdraw-simulate --agent-id my-agent-001 --asset USDC --amount max
ardent compound-withdraw --agent-id my-agent-001 --asset USDC --amount max
ardent compound-repay-simulate --agent-id my-agent-001 --amount max
ardent compound-repay --agent-id my-agent-001 --amount max
ardent compound-borrow-simulate --agent-id my-agent-001 --amount 1
ardent compound-borrow --agent-id my-agent-001 --amount 1
ardent compound-position --agent-id my-agent-001
ardent compound-position --agent-id my-agent-001 --market weth
ardent compound-balances --agent-id my-agent-001
ardent compound-borrow-capacity --agent-id my-agent-001
```

### Morpho Blue Base Sepolia

Morpho actions are market-ID driven. The default is an on-chain-checked
USDC/WETH 86% LLTV test market; pass `--market-id` for another Base Sepolia
market. This is a convenience default, not a Morpho endorsement or allowlist.
The default may have no liquidity; supply USDC before borrowing and check
`morpho-market` first.

```bash
ardent morpho-markets \
  --loan-token 0x036CbD53842c5426634e7929541eC2318f3dCF7e \
  --collateral-token 0x4200000000000000000000000000000000000006
ardent morpho-market
ardent morpho-position --agent-id my-agent-001
ardent morpho-supply-simulate --agent-id my-agent-001 --amount 10
ardent morpho-withdraw-simulate --agent-id my-agent-001 --amount max
ardent morpho-supply-collateral-simulate --agent-id my-agent-001 --amount 0.01
ardent morpho-borrow-simulate --agent-id my-agent-001 --amount 5 --min-health-factor 1.10
ardent morpho-repay-simulate --agent-id my-agent-001 --amount max
ardent morpho-withdraw-collateral-simulate --agent-id my-agent-001 --amount 0.001
```

Read `morpho-position` before borrow or collateral withdrawal. It returns wallet
balances, accrued debt, collateral value, LTV, health factor, borrow capacity,
and available market liquidity. If the selected market oracle is unavailable,
oracle-dependent values are `null` while balances and position state remain
readable. Full repay uses borrow shares to avoid debt dust.

### Balancer V3 Ethereum Sepolia

Balancer swaps discover pair-compatible pools through Balancer's API, verify
and on-chain Vault registration events, verify current V3 Vault state, quote
every viable candidate, and select the best result. Pass `--pool` only to pin
an explicit pool. Liquidity actions remain pool-address driven.

```bash
ardent balancer-pool --pool 0xYourBalancerV3Pool
ardent balancer-pools --token-in 0xFirstPoolToken --token-out 0xSecondPoolToken
ardent balancer-balances --agent-id my-agent-001 --pool 0xYourBalancerV3Pool

ardent balancer-quote \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-swap \
  --agent-id my-agent-001 \
  --token-in 0xFirstPoolToken \
  --token-out 0xSecondPoolToken \
  --swap-kind exact_in \
  --amount-raw 1000000

ardent balancer-add-liquidity-simulate \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --amount-in 0xFirstPoolToken=1000000 \
  --amount-in 0xSecondPoolToken=1000000

ardent balancer-remove-liquidity-simulate \
  --agent-id my-agent-001 \
  --pool 0xYourBalancerV3Pool \
  --bpt-amount-in-raw 1000000000000000000
```

The server quotes the Router and derives a 1% slippage limit by default.
Balancer input tokens are approved through Permit2 and both approval layers are
cleared after swaps and liquidity additions inside the same atomic UserOperation
batch. Proportional removal grants the Router an exact, temporary BPT allowance,
executes the removal, and clears the allowance in the same atomic batch.
Liquidity additions accept up to three deposited token addresses per operation.

### Uniswap V4 Ethereum Sepolia

Uniswap V4 pools live in the singleton PoolManager and do not have individual
pool contract addresses. Ardent automatically discovers matching pool keys and
selects the best successful quote when fee, tick spacing, and hooks are omitted.

```bash
ardent uniswap-v4-pool \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency \
  --fee 3000 \
  --tick-spacing 60 \
  --hooks 0xPoolHooksOrZeroAddress

ardent uniswap-v4-pools \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency

ardent uniswap-v4-balances \
  --agent-id my-agent-001 \
  --token-a 0xFirstPoolCurrency \
  --token-b 0xSecondPoolCurrency

ardent uniswap-v4-quote \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --amount-raw 1000000

ardent uniswap-v4-swap-simulate \
  --agent-id my-agent-001 \
  --token-in 0xInputCurrency \
  --token-out 0xOutputCurrency \
  --amount-raw 1000000
```

Use the zero address for native ETH. Automatic mode excludes hook pools by
default, validates candidates through StateView, compares live Quoter results,
and fully simulates the selected Universal Router bundle. ERC-20 allowances
are bounded and cleared atomically after a successful swap.

### GMX V2 Arbitrum Sepolia

Use raw GMX values for order sizing. Market increase `size_delta_usd_raw` and
`acceptable_price_raw` use GMX 30-decimal precision.

```bash
ardent gmx-create-order-simulate \
  --agent-id my-agent-001 \
  --order-type market_increase \
  --market 0xYourGmxMarketToken \
  --initial-collateral-token 0xYourCollateralToken \
  --initial-collateral-delta-amount-raw 1000000 \
  --size-delta-usd-raw 50000000000000000000000000000000000 \
  --acceptable-price-raw 30000000000000000000000000000000000000000 \
  --execution-fee-raw 1000000000000000 \
  --long

ardent gmx-create-order --agent-id my-agent-001 --body-file ./gmx-order.json
ardent gmx-markets --start 0 --end 50
ardent gmx-positions --agent-id my-agent-001
ardent gmx-orders --agent-id my-agent-001
ardent gmx-balances --agent-id my-agent-001
ardent gmx-cancel-order-simulate --agent-id my-agent-001 --order-key 0xYourBytes32OrderKey
ardent gmx-cancel-order --agent-id my-agent-001 --order-key 0xYourBytes32OrderKey
ardent gmx-update-order-simulate --agent-id my-agent-001 --body-file ./gmx-update.json
ardent gmx-create-deposit-simulate --agent-id my-agent-001 --body-file ./gmx-deposit.json
ardent gmx-create-withdrawal-simulate --agent-id my-agent-001 --body-file ./gmx-withdrawal.json
ardent gmx-cancel-simulate --agent-id my-agent-001 --request-type deposit --key 0xYourBytes32RequestKey
ardent gmx-claim-simulate --agent-id my-agent-001 --claim-type funding_fees --market 0xYourGmxMarketToken --token 0xClaimToken
```

`gmx-markets` includes token symbols when ERC-20 metadata is available.
`gmx-balances` returns GM/market LP token balances plus underlying GMX market
asset token balances for the smart wallet.
GMX testnet token metadata is best-effort; unavailable symbols fall back to
derived market labels or compact token addresses.

Update CLI and runtime files:

```bash
ardent self-update              # updates CLI plus ~/.ardent runtime files
ardent self-update --cli-only   # updates only the CLI
```

## Files in this folder

| File | Purpose | Used by |
| --- | --- | --- |
| `install.sh` | One-line installer | Everyone |
| `ardent_cli.py` | Zero-dependency CLI | Developers, scripts, CI |
| `mcp_server.py` | stdio MCP server | Codex, Claude, ChatGPT, Cursor, Windsurf |
| `mcp-tools.json` | MCP tool definitions | `mcp_server.py` |
| `openapi.yaml` | Generated bundled OpenAPI 3.1 spec | ChatGPT custom actions, code generators |
| `openapi/` | Split OpenAPI source + bundler | Maintainers |
| `skills.md` | Setup guide + agent playbook | Humans and LLM system prompts |

When editing the API spec, update files under `openapi/`, then run:

```bash
ruby docs/agent-integration/openapi/bundle.rb
```

## MCP — supported methods

- `initialize`
- `tools/list`
- `tools/call`

## Notes

- MCP tools cover general execution, Aave V3, Compound III, Morpho Blue, Balancer V3, Uniswap V4, and GMX V2 actions and reads. Every protocol write exposes separate simulation and execution tools.
