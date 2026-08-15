# Ardent Research Documentation

Welcome to the official user documentation for Ardent Research.

This guide is written for teams integrating with the hosted Ardent API at `https://api.ardentresearch.xyz`.

## Who we are

Ardent Research is an R&D lab focused on AI infrastructure for a permissionless autonomous economy.

Our vision is to make it easy for AI agents to securely execute real tasks such as payments, on-chain actions, and service calls without centralized gatekeepers.

We build execution infrastructure that helps teams move from agent demos to production systems with strong safety guarantees and operational visibility.

## What is an AI agent blockchain execution platform

An AI agent blockchain execution platform is the trust and execution layer between an agent's intent and real-world settlement.

In practice, it provides:

1. Wallet abstraction and account lifecycle management.
2. Deterministic execution and transaction routing across chains.
3. Payment rails and proof verification for autonomous API usage.
4. Policy, observability, and status tracking for async execution.

Without this layer, teams typically stitch together fragile components and inherit security and reliability risk at the exact point where agents touch value.

## The problem we solve

Many agent systems can reason, plan, and generate actions, but they still fail at the final mile: safe and reliable execution.

Common blockers include:

1. Wallet lifecycle complexity and signing constraints.
2. Non-deterministic transaction handling across chains and RPC environments.
3. Payment handling and verification for API-triggered execution.
4. Poor observability across asynchronous execution flows and retries.
5. Security boundaries between agent logic, keys, relayers, and external services.

## Our goal

Our goal is to make autonomous execution safe by default, programmable, and easy to integrate.

Teams should focus on product logic and agent behavior while Ardent handles execution correctness, payment verification, and lifecycle reliability.

## AI agent blockchain execution platform

The AI agent blockchain execution platform is our hosted execution surface for production agent workflows.

It enables your software agent to execute EVM transactions through an ERC-4337 smart wallet without running your own relayer or custom broadcasting stack.

At a high level, the platform provides:

1. Deterministic smart wallet resolution per agent.
2. Pre-flight simulation before broadcast.
3. Atomic USDC execution fees with native gas sponsorship.
4. Standardized request lifecycle tracking via `request_id` and `GET /status/:id`.
5. Hosted API ergonomics with webhook-friendly asynchronous completion.

For hosted users, the integration flow is straightforward:

1. Request API access.
2. Resolve or provision an agent wallet address.
3. Fund the agent wallet as needed.
4. Simulate or execute transactions.
5. Track execution state until completion.

## Who this guide is for

This documentation is for:

1. AI agent developers and engineers integrating on-chain execution.
2. Product engineers building agent workflows.
3. DevOps engineers operating production integrations.

## Core concepts

Before you begin, keep these platform concepts in mind:

1. API keys are customer scoped and required for protected endpoints.
2. Every agent is mapped to a deterministic smart wallet.
3. Normal execution atomically sends its USDC fee to the VerifyingPaymaster.
4. x402 external-payer execution is available through `POST /x402/execute`.
5. `GET /status/:id` is the source of truth for lifecycle state.

## Base URL

Use the hosted API base URL:

```bash
https://api.ardentresearch.xyz
```

## Agent integration

Ardent Research ships an integration pack that makes it fast to connect any developer, script, or AI tool to the platform.

It includes:

1. A zero-dependency CLI (`ardent`) with a one-line installer.
2. An MCP server that exposes all platform tools to Codex, Claude Desktop, ChatGPT Desktop, Cursor, and Windsurf.
3. An OpenAPI 3.1 spec for ChatGPT custom actions and code generators.

The installer auto-patches desktop AI configs and preserves any existing API key.

See [Agent Integration](agent-integration.md).

## Next step

Start with [Getting Started](getting-started.md).

For Sepolia token details and testnet funding guidance, see [Testnet Guide](testnet-guide.md).
