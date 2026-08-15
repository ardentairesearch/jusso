#!/usr/bin/env python3
"""Ardent API CLI (zero dependencies).

Commands:
- health
- feed
- wallet
- wallet-balance
- delegation-register
- delegation-status
- delegation-revoke-prepare
- simulate
- execute
- aave-balances
- compound-supply
- compound-withdraw
- compound-repay
- compound-borrow
- compound-position
- compound-balances
- compound-borrow-capacity
- compound-markets
- morpho-market
- morpho-position
- morpho-markets
- morpho-supply
- morpho-withdraw
- morpho-supply-collateral
- morpho-withdraw-collateral
- morpho-borrow
- morpho-repay
- balancer-swap
- balancer-quote
- balancer-add-liquidity
- balancer-remove-liquidity
- balancer-pool
- balancer-balances
- balancer-pools
- uniswap-v4-swap
- uniswap-v4-quote
- uniswap-v4-pool
- uniswap-v4-pools
- uniswap-v4-balances
- gmx-create-order
- gmx-cancel-order
- gmx-markets
- gmx-positions
- gmx-orders
- gmx-balances
- gmx-update-order
- gmx-create-deposit
- gmx-create-withdrawal
- gmx-cancel
- gmx-claim
- status
- self-update
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError

import sys


VERSION = "1.0.0"
REPO_RAW_BASE = "https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration"
RUNTIME_DIR = Path(os.getenv("ARDENT_RUNTIME_DIR", str(Path.home() / ".ardent")))
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))


def parse_json_file(path: str) -> Any:
    with Path(path).expanduser().open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def parse_json_string(raw: str) -> Any:
    return json.loads(raw)


def output(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def build_api_key(args: argparse.Namespace) -> str | None:
    api_key = args.api_key or os.getenv("ARDENT_API_KEY")
    if api_key == "your_api_key_here":
        api_key = None
    if api_key:
        return api_key
    access_token = os.getenv("ARDENT_ACCESS_TOKEN")
    if access_token:
        return f"Bearer::{access_token}"
    if os.getenv("ARDENT_CLIENT_ID") or os.getenv("ARDENT_CLIENT_PRIVATE_KEY_FILE"):
        try:
            from oauth_client import service_account_access_token
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "OAuth runtime is missing; run `ardent self-update` or reinstall Ardent"
            ) from exc
        service_token = service_account_access_token(build_base_url(args))
        return f"Bearer::{service_token}" if service_token else None
    return None


def build_base_url(args: argparse.Namespace) -> str:
    return (args.base_url or os.getenv("ARDENT_BASE_URL") or "https://api.ardentresearch.xyz").rstrip("/")


def call_api(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str | None = None,
) -> tuple[int, Any]:
    headers: dict[str, str] = {
        "Accept": "application/json",
        "User-Agent": f"ardent-cli/{VERSION}",
    }

    if api_key and api_key.startswith("Bearer::"):
        headers["Authorization"] = f"Bearer {api_key.removeprefix('Bearer::')}"
    elif api_key:
        headers["X-API-Key"] = api_key


    data: bytes | None = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")

    req = request.Request(url, headers=headers, data=data, method=method.upper())

    try:
        with request.urlopen(req, timeout=30) as response:
            status_code = response.getcode()
            raw = response.read().decode("utf-8", errors="replace")
            return status_code, safe_json(raw)
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return exc.code, safe_json(raw)
    except URLError as exc:
        raise RuntimeError(f"network error: {exc}") from exc


def download_text(url: str) -> str:
    try:
        with request.urlopen(url, timeout=30) as response:
            return response.read().decode("utf-8")
    except URLError as exc:
        raise RuntimeError(f"failed downloading {url}: {exc}") from exc


def safe_json(raw: str) -> Any:
    raw = (raw or "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"raw": raw}


def require_credential(args: argparse.Namespace) -> str:
    api_key = build_api_key(args)
    if not api_key:
        raise ValueError(
            "missing credential: set ARDENT_CLIENT_ID with "
            "ARDENT_CLIENT_PRIVATE_KEY_FILE, --api-key, ARDENT_API_KEY, "
            "or ARDENT_ACCESS_TOKEN"
        )
    return api_key


def resolve_request_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "target_contract": args.target_contract or "",
        "calldata": args.calldata or "",
        "value": args.value,
    }

    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url

    if args.batch_file:
        batch_calls = parse_json_file(args.batch_file)
        if not isinstance(batch_calls, list):
            raise ValueError("batch file must contain a JSON array")
        body["batch_calls"] = batch_calls

    return body



def run_health(args: argparse.Namespace) -> int:
    url = f"{build_base_url(args)}/health"
    status, payload = call_api("GET", url)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_feed(args: argparse.Namespace) -> int:
    qs = parse.urlencode({"limit": args.limit})
    url = f"{build_base_url(args)}/feed/recent?{qs}"
    status, payload = call_api("GET", url)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_wallet(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain})
    url = f"{build_base_url(args)}/wallet?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_wallet_balance(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain})
    url = f"{build_base_url(args)}/wallet/balance?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_delegation_register(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    permissions = []
    for raw in args.permission:
        target, separator, selector = raw.partition(":")
        if not separator:
            raise ValueError("--permission must use TARGET:0xSELECTOR")
        permissions.append({"target": target, "selector": selector})
    body = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "account_address": args.account_address,
        "valid_after": args.valid_after,
        "valid_until": args.valid_until,
        "max_native_value_raw": args.max_native_value_raw,
        "max_fee_raw": args.max_fee_raw,
        "permissions": permissions,
    }
    url = f"{build_base_url(args)}/delegations/register"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_delegation_status(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"chain": args.chain})
    url = (
        f"{build_base_url(args)}/delegations/"
        f"{parse.quote(args.agent_id)}?{qs}"
    )
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_delegation_revoke_prepare(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    url = (
        f"{build_base_url(args)}/delegations/"
        f"{parse.quote(args.agent_id)}/revoke/prepare"
    )
    status, payload = call_api("POST", url, body={}, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_request_body(args)
    url = f"{build_base_url(args)}/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_execute(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_request_body(args)
    url = f"{build_base_url(args)}/execute"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_aave_action_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "asset": args.asset,
    }
    if args.amount is not None:
        body["amount"] = args.amount
    if args.amount_raw is not None:
        body["amount_raw"] = args.amount_raw
    if getattr(args, "referral_code", None) is not None:
        body["referral_code"] = args.referral_code
    if getattr(args, "interest_rate_mode", None) is not None:
        body["interest_rate_mode"] = args.interest_rate_mode
    if getattr(args, "min_health_factor", None):
        body["min_health_factor"] = args.min_health_factor
    if getattr(args, "to", None):
        body["to"] = args.to
    if getattr(args, "on_behalf_of", None):
        body["on_behalf_of"] = args.on_behalf_of
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_aave_supply_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/supply/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_supply(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/supply"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_withdraw_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/withdraw/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_withdraw(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/withdraw"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_repay_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/repay/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_repay(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/repay"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_borrow_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/borrow/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_borrow(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_aave_action_body(args)
    url = f"{build_base_url(args)}/protocols/aave-v3/borrow"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_position(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain})
    url = f"{build_base_url(args)}/protocols/aave-v3/position?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_aave_balances(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain})
    url = f"{build_base_url(args)}/protocols/aave-v3/balances?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_compound_action_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "asset": args.asset,
    }
    if getattr(args, "market", None):
        body["market"] = args.market
    if args.amount is not None:
        body["amount"] = args.amount
    if args.amount_raw is not None:
        body["amount_raw"] = args.amount_raw
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_compound_supply_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/supply/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_supply(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/supply"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_withdraw_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/withdraw/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_withdraw(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/withdraw"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_repay_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/repay/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_repay(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/repay"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_borrow_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/borrow/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_borrow(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_compound_action_body(args)
    url = f"{build_base_url(args)}/protocols/compound-v3/borrow"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_position(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain, "market": args.market})
    url = f"{build_base_url(args)}/protocols/compound-v3/position?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_balances(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain, "market": args.market})
    url = f"{build_base_url(args)}/protocols/compound-v3/balances?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_borrow_capacity(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"agent_id": args.agent_id, "chain": args.chain, "market": args.market})
    url = f"{build_base_url(args)}/protocols/compound-v3/borrow-capacity?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_compound_markets(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    params = {"chain": args.chain}
    if args.base_asset:
        params["base_asset"] = args.base_asset
    qs = parse.urlencode(params)
    url = f"{build_base_url(args)}/protocols/compound-v3/markets?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_morpho_action_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "market_id": args.market_id,
    }
    if args.amount is not None:
        body["amount"] = args.amount
    if args.amount_raw is not None:
        body["amount_raw"] = args.amount_raw
    if getattr(args, "min_health_factor", None) is not None:
        body["min_health_factor"] = args.min_health_factor
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_morpho_action(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_morpho_action_body(args)
    suffix = "" if args.execute else "/simulate"
    url = f"{build_base_url(args)}/protocols/morpho/{args.endpoint}{suffix}"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_morpho_market(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"chain": args.chain, "market_id": args.market_id})
    url = f"{build_base_url(args)}/protocols/morpho/market?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_morpho_markets(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    params: dict[str, Any] = {
        "chain": args.chain,
        "require_available_oracle": str(args.require_available_oracle).lower(),
        "limit": args.limit,
    }
    for name in ("loan_token", "collateral_token", "max_lltv_raw", "min_liquidity_raw"):
        value = getattr(args, name)
        if value is not None:
            params[name] = value
    qs = parse.urlencode(params)
    url = f"{build_base_url(args)}/protocols/morpho/markets?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_morpho_position(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {"agent_id": args.agent_id, "chain": args.chain, "market_id": args.market_id}
    )
    url = f"{build_base_url(args)}/protocols/morpho/position?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_balancer_swap_body(args: argparse.Namespace) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "token_in": args.token_in,
        "token_out": args.token_out,
        "swap_kind": args.swap_kind,
        "amount_raw": args.amount_raw,
        "slippage_bps": args.slippage_bps,
    }
    if args.pool:
        body["pool"] = args.pool
    if args.limit_raw is not None:
        body["limit_raw"] = args.limit_raw
    if args.deadline is not None:
        body["deadline"] = args.deadline
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_balancer_swap_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_balancer_swap_body(args)
    url = f"{build_base_url(args)}/protocols/balancer-v3/swap/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_balancer_swap(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_balancer_swap_body(args)
    url = f"{build_base_url(args)}/protocols/balancer-v3/swap"
    status, payload = call_api(
        "POST",
        url,
        body=body,
        api_key=api_key,
    )
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_balancer_quote(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_balancer_swap_body(args)
    url = f"{build_base_url(args)}/protocols/balancer-v3/swap/quote"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_balancer_pool(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode({"chain": args.chain, "pool": args.pool})
    url = f"{build_base_url(args)}/protocols/balancer-v3/pool?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_balancer_pools(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {"chain": args.chain, "token_in": args.token_in, "token_out": args.token_out}
    )
    url = f"{build_base_url(args)}/protocols/balancer-v3/pools?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_balancer_balances(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {"agent_id": args.agent_id, "chain": args.chain, "pool": args.pool}
    )
    url = f"{build_base_url(args)}/protocols/balancer-v3/balances?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_uniswap_v4_swap_body(args: argparse.Namespace) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "token_in": args.token_in,
        "token_out": args.token_out,
        "hook_data": args.hook_data,
        "include_hooked_pools": args.include_hooked_pools,
        "swap_kind": args.swap_kind,
        "amount_raw": args.amount_raw,
        "slippage_bps": args.slippage_bps,
    }
    if args.fee is not None:
        body["fee"] = args.fee
    if args.tick_spacing is not None:
        body["tick_spacing"] = args.tick_spacing
    if args.hooks is not None:
        body["hooks"] = args.hooks
    if args.limit_raw is not None:
        body["limit_raw"] = args.limit_raw
    if args.deadline is not None:
        body["deadline"] = args.deadline
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_uniswap_v4_swap(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_uniswap_v4_swap_body(args)
    suffix = "" if args.execute else "/simulate"
    url = f"{build_base_url(args)}/protocols/uniswap-v4/swap{suffix}"
    status, payload = call_api(
        "POST", url, body=body, api_key=api_key
    )
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_uniswap_v4_quote(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_uniswap_v4_swap_body(args)
    url = f"{build_base_url(args)}/protocols/uniswap-v4/swap/quote"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_uniswap_v4_pool(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {
            "chain": args.chain,
            "token_a": args.token_a,
            "token_b": args.token_b,
            "fee": args.fee,
            "tick_spacing": args.tick_spacing,
            "hooks": args.hooks,
        }
    )
    url = f"{build_base_url(args)}/protocols/uniswap-v4/pool?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_uniswap_v4_pools(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {
            "chain": args.chain,
            "token_a": args.token_a,
            "token_b": args.token_b,
            "include_hooked_pools": str(args.include_hooked_pools).lower(),
        }
    )
    url = f"{build_base_url(args)}/protocols/uniswap-v4/pools?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_uniswap_v4_balances(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(
        {
            "agent_id": args.agent_id,
            "chain": args.chain,
            "token_a": args.token_a,
            "token_b": args.token_b,
        }
    )
    url = f"{build_base_url(args)}/protocols/uniswap-v4/balances?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def parse_balancer_token_amounts(values: list[str] | None, flag: str) -> list[dict[str, str]]:
    amounts: list[dict[str, str]] = []
    for value in values or []:
        token, separator, amount_raw = value.partition("=")
        if not separator or not token.strip() or not amount_raw.strip():
            raise ValueError(f"{flag} must use TOKEN_ADDRESS=RAW_AMOUNT")
        amounts.append({"token": token.strip(), "amount_raw": amount_raw.strip()})
    return amounts


def resolve_balancer_add_liquidity_body(args: argparse.Namespace) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "pool": args.pool,
        "amounts_in": parse_balancer_token_amounts(args.amount_in, "--amount-in"),
        "slippage_bps": args.slippage_bps,
    }
    if args.min_bpt_amount_out_raw is not None:
        body["min_bpt_amount_out_raw"] = args.min_bpt_amount_out_raw
    if args.deadline is not None:
        body["deadline"] = args.deadline
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def resolve_balancer_remove_liquidity_body(args: argparse.Namespace) -> dict[str, Any]:
    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "pool": args.pool,
        "bpt_amount_in_raw": args.bpt_amount_in_raw,
        "slippage_bps": args.slippage_bps,
    }
    minimums = parse_balancer_token_amounts(args.min_amount_out, "--min-amount-out")
    if minimums:
        body["min_amounts_out"] = minimums
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_balancer_liquidity(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = (
        resolve_balancer_add_liquidity_body(args)
        if args.liquidity_action == "add"
        else resolve_balancer_remove_liquidity_body(args)
    )
    suffix = f"/protocols/balancer-v3/liquidity/{args.liquidity_action}"
    if args.liquidity_mode != "execute":
        suffix += f"/{args.liquidity_mode}"
    status, payload = call_api(
        "POST",
        f"{build_base_url(args)}{suffix}",
        body=body,
        api_key=api_key,
    )
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_gmx_create_order_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "order_type": args.order_type,
        "market": args.market,
        "initial_collateral_token": args.initial_collateral_token,
        "initial_collateral_delta_amount_raw": args.initial_collateral_delta_amount_raw,
        "execution_fee_raw": args.execution_fee_raw,
    }
    optional_fields = [
        "size_delta_usd_raw",
        "acceptable_price_raw",
        "min_output_amount_raw",
        "trigger_price_raw",
        "callback_gas_limit_raw",
        "valid_from_time_raw",
        "referral_code",
        "receiver",
        "cancellation_receiver",
        "callback_contract",
        "ui_fee_receiver",
        "strategy_id",
        "callback_url",
    ]
    for field in optional_fields:
        value = getattr(args, field, None)
        if value is not None:
            body[field] = value
    if args.swap_path:
        body["swap_path"] = args.swap_path
    if args.is_long is not None:
        body["is_long"] = args.is_long
    if args.should_unwrap_native_token:
        body["should_unwrap_native_token"] = True
    if args.auto_cancel:
        body["auto_cancel"] = True
    return body


def resolve_gmx_cancel_order_body(args: argparse.Namespace) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {
        "agent_id": args.agent_id,
        "chain": args.chain,
        "order_key": args.order_key,
    }
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def resolve_gmx_simple_body(args: argparse.Namespace, fields: list[str]) -> dict[str, Any]:
    if args.body_file:
        body = parse_json_file(args.body_file)
        if not isinstance(body, dict):
            raise ValueError("body file must contain a JSON object")
        return body

    body: dict[str, Any] = {"agent_id": args.agent_id, "chain": args.chain}
    for field in fields:
        value = getattr(args, field, None)
        if value is not None:
            body[field] = value
    if args.strategy_id:
        body["strategy_id"] = args.strategy_id
    if args.callback_url:
        body["callback_url"] = args.callback_url
    return body


def run_gmx_update_order_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_simple_body(
        args,
        [
            "order_key",
            "size_delta_usd_raw",
            "acceptable_price_raw",
            "trigger_price_raw",
            "min_output_amount_raw",
            "valid_from_time_raw",
            "auto_cancel",
        ],
    )
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders/update/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_update_order(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_simple_body(
        args,
        [
            "order_key",
            "size_delta_usd_raw",
            "acceptable_price_raw",
            "trigger_price_raw",
            "min_output_amount_raw",
            "valid_from_time_raw",
            "auto_cancel",
        ],
    )
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders/update"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_create_order_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_create_order_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_create_order(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_create_order_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_cancel_order_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_cancel_order_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders/cancel/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_cancel_order(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_cancel_order_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders/cancel"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def build_range_query(args: argparse.Namespace, include_agent: bool = True) -> dict[str, Any]:
    qs: dict[str, Any] = {"chain": args.chain}
    if include_agent:
        qs["agent_id"] = args.agent_id
    if args.start is not None:
        qs["start"] = args.start
    if args.end is not None:
        qs["end"] = args.end
    return qs


def run_gmx_markets(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(build_range_query(args, include_agent=False))
    url = f"{build_base_url(args)}/protocols/gmx-v2/markets?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_positions(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(build_range_query(args))
    url = f"{build_base_url(args)}/protocols/gmx-v2/positions?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_orders(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(build_range_query(args))
    url = f"{build_base_url(args)}/protocols/gmx-v2/orders?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_balances(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    qs = parse.urlencode(build_range_query(args))
    url = f"{build_base_url(args)}/protocols/gmx-v2/balances?{qs}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def resolve_gmx_deposit_body(args: argparse.Namespace) -> dict[str, Any]:
    body = resolve_gmx_simple_body(
        args,
        [
            "market",
            "initial_long_token",
            "initial_short_token",
            "initial_long_token_amount_raw",
            "initial_short_token_amount_raw",
            "min_market_tokens_raw",
            "execution_fee_raw",
            "receiver",
            "callback_contract",
            "ui_fee_receiver",
            "callback_gas_limit_raw",
            "should_unwrap_native_token",
        ],
    )
    if not args.body_file:
        if args.long_token_swap_path:
            body["long_token_swap_path"] = args.long_token_swap_path
        if args.short_token_swap_path:
            body["short_token_swap_path"] = args.short_token_swap_path
    return body


def resolve_gmx_withdrawal_body(args: argparse.Namespace) -> dict[str, Any]:
    body = resolve_gmx_simple_body(
        args,
        [
            "market",
            "market_token_amount_raw",
            "min_long_token_amount_raw",
            "min_short_token_amount_raw",
            "execution_fee_raw",
            "receiver",
            "callback_contract",
            "ui_fee_receiver",
            "callback_gas_limit_raw",
            "should_unwrap_native_token",
        ],
    )
    if not args.body_file:
        if args.long_token_swap_path:
            body["long_token_swap_path"] = args.long_token_swap_path
        if args.short_token_swap_path:
            body["short_token_swap_path"] = args.short_token_swap_path
    return body


def resolve_gmx_claim_body(args: argparse.Namespace) -> dict[str, Any]:
    body = resolve_gmx_simple_body(args, ["claim_type", "receiver"])
    if not args.body_file:
        body["markets"] = args.market or []
        body["tokens"] = args.token or []
        if args.time_key_raw:
            body["time_keys_raw"] = args.time_key_raw
    return body


def run_gmx_create_deposit_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_deposit_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/deposits/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_create_deposit(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_deposit_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/deposits"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_create_withdrawal_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_withdrawal_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/withdrawals/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_create_withdrawal(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_withdrawal_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/withdrawals"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_cancel_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_simple_body(args, ["request_type", "key"])
    url = f"{build_base_url(args)}/protocols/gmx-v2/requests/cancel/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_cancel(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_simple_body(args, ["request_type", "key"])
    url = f"{build_base_url(args)}/protocols/gmx-v2/requests/cancel"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_claim_simulate(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_claim_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/claims/simulate"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_gmx_claim(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    body = resolve_gmx_claim_body(args)
    url = f"{build_base_url(args)}/protocols/gmx-v2/claims"
    status, payload = call_api("POST", url, body=body, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_status(args: argparse.Namespace) -> int:
    api_key = require_credential(args)
    request_id = args.request_id
    url = f"{build_base_url(args)}/status/{parse.quote(request_id)}"
    status, payload = call_api("GET", url, api_key=api_key)
    output({"status": status, "data": payload})
    return 0 if 200 <= status < 300 else 1


def run_self_update(args: argparse.Namespace) -> int:
    cli_path = Path(__file__).resolve()
    cli_url = f"{REPO_RAW_BASE}/ardent_cli.py"

    cli_source = download_text(cli_url)
    cli_path.write_text(cli_source, encoding="utf-8")
    cli_path.chmod(0o755)

    # Parse the version from the downloaded file rather than reporting the current process version
    new_version = VERSION
    for line in cli_source.splitlines():
        if line.startswith("VERSION"):
            try:
                new_version = line.split('"')[1]
            except IndexError:
                pass
            break

    refreshed_files: list[str] = [str(cli_path)]

    if not args.cli_only:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        runtime_files = [
            "mcp_server.py",
            "oauth_client.py",
            "mcp-tools.json",
            "skills.md",
            "openapi.yaml",
        ]
        for name in runtime_files:
            raw = download_text(f"{REPO_RAW_BASE}/{name}")
            target = RUNTIME_DIR / name
            target.write_text(raw, encoding="utf-8")
            if name.endswith(".py"):
                target.chmod(0o755)
            refreshed_files.append(str(target))

    restart_note = None
    if not args.cli_only:
        restart_note = "Restart any AI app/MCP session so it reloads the refreshed Ardent tools."

    output(
        {
            "message": "update complete",
            "version": new_version,
            "updated": refreshed_files,
            "runtime_refreshed": not args.cli_only,
            "restart_note": restart_note,
        }
    )
    return 0


def add_global_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base-url", help="API base URL (default env ARDENT_BASE_URL)")
    parser.add_argument("--api-key", help="API key (default env ARDENT_API_KEY)")


def add_execution_payload_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="ethereum", choices=["ethereum", "base", "arbitrum"], help="Target chain")
    parser.add_argument("--target-contract", help="Target contract address (single-call mode)")
    parser.add_argument("--calldata", help="Hex calldata (single-call mode)")
    parser.add_argument("--value", default="0", help="Value as string (default: 0)")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--batch-file", help="Path to JSON array for batch_calls")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_aave_supply_flags(parser: argparse.ArgumentParser) -> None:
    add_aave_amount_action_flags(parser)
    parser.add_argument("--referral-code", type=int, help="Optional Aave referral code")


def add_aave_amount_action_flags(parser: argparse.ArgumentParser, *, allow_max: bool = False) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="ethereum", choices=["ethereum"], help="Aave V3 Sepolia chain label")
    parser.add_argument(
        "--asset",
        required=True,
        choices=["AAVE", "DAI", "EURS", "GHO", "LINK", "USDC", "USDT", "WBTC", "WETH"],
        help="Aave V3 Sepolia reserve asset",
    )
    amount_help = "Human-readable token amount, e.g. 1.25"
    raw_help = "Raw token base-unit amount"
    if allow_max:
        amount_help += "; also supports max"
        raw_help += "; also supports max"
    parser.add_argument("--amount", help=amount_help)
    parser.add_argument("--amount-raw", help=raw_help)
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_compound_amount_action_flags(parser: argparse.ArgumentParser, *, allow_max: bool = False, base_only: bool = False) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="base", choices=["base"], help="Compound III Base Sepolia chain label")
    parser.add_argument("--market", choices=["usdc", "weth"], help="Compound III market; defaults from asset")
    if base_only:
        parser.add_argument("--asset", default="base", choices=["base", "USDC", "WETH"], help="Compound III base asset")
    else:
        parser.add_argument("--asset", required=True, help="USDC/base, WETH, or token address supported by Comet")
    amount_help = "Human-readable token amount"
    raw_help = "Raw token base-unit amount"
    if allow_max:
        amount_help += "; also supports max"
        raw_help += "; also supports max"
    parser.add_argument("--amount", help=amount_help)
    parser.add_argument("--amount-raw", help=raw_help)
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_morpho_action_flags(
    parser: argparse.ArgumentParser, *, allow_max: bool, health_guard: bool
) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="base", choices=["base"], help="Morpho Base Sepolia chain label")
    parser.add_argument(
        "--market-id",
        default="0x6143c1e52ed45fb9a0551b349abb4a1b8c5962dd39545ac235a9c98610bf97da",
        help="Morpho Blue market ID; defaults to Ardent's preconfigured USDC/WETH 86%% LLTV test market",
    )
    amount_help = "Human-readable action-token amount"
    raw_help = "Raw action-token base-unit amount"
    if allow_max:
        amount_help += "; also supports max"
        raw_help += "; also supports max"
    parser.add_argument("--amount", help=amount_help)
    parser.add_argument("--amount-raw", help=raw_help)
    if health_guard:
        parser.add_argument(
            "--min-health-factor",
            help="Minimum projected health factor; defaults to 1.05 and must be at least 1.0",
        )
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")



def add_gmx_create_order_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument(
        "--order-type",
        required=True,
        choices=[
            "market_swap",
            "limit_swap",
            "market_increase",
            "limit_increase",
            "market_decrease",
            "limit_decrease",
            "stop_loss_decrease",
            "stop_increase",
        ],
        help="GMX order type",
    )
    parser.add_argument("--market", required=True, help="GMX market token address")
    parser.add_argument("--initial-collateral-token", required=True, help="Collateral/input token address")
    parser.add_argument(
        "--initial-collateral-delta-amount-raw",
        required=True,
        help="Raw collateral/input token amount",
    )
    parser.add_argument("--size-delta-usd-raw", help="Raw 30-decimal USD size delta; required for market_increase")
    parser.add_argument("--acceptable-price-raw", help="Raw 30-decimal acceptable price; required for market_increase")
    parser.add_argument("--min-output-amount-raw", help="Raw minimum output amount; required for market_swap")
    parser.add_argument("--execution-fee-raw", required=True, help="Raw ETH execution fee in wei")
    direction = parser.add_mutually_exclusive_group()
    direction.add_argument("--long", dest="is_long", action="store_true", help="Create long increase order")
    direction.add_argument("--short", dest="is_long", action="store_false", help="Create short increase order")
    parser.set_defaults(is_long=None)
    parser.add_argument("--receiver", help="Optional receiver; defaults to agent wallet")
    parser.add_argument("--cancellation-receiver", help="Optional cancellation receiver; defaults to receiver")
    parser.add_argument("--callback-contract", help="Optional GMX callback contract")
    parser.add_argument("--ui-fee-receiver", help="Optional UI fee receiver")
    parser.add_argument("--swap-path", action="append", help="Optional GMX swap path market address; repeatable")
    parser.add_argument("--trigger-price-raw", help="Raw 30-decimal trigger price")
    parser.add_argument("--callback-gas-limit-raw", help="Raw callback gas limit")
    parser.add_argument("--valid-from-time-raw", help="Raw timestamp from which the GMX order is valid")
    parser.add_argument("--referral-code", help="bytes32 hex or short ASCII referral code")
    parser.add_argument("--should-unwrap-native-token", action="store_true", help="Ask GMX to unwrap native output when supported")
    parser.add_argument("--auto-cancel", action="store_true", help="Set GMX autoCancel flag")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_cancel_order_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--order-key", required=True, help="GMX bytes32 order key")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_range_flags(parser: argparse.ArgumentParser, *, include_agent: bool = True) -> None:
    if include_agent:
        parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--start", type=int, help="Start index, default 0")
    parser.add_argument("--end", type=int, help="End index, default start + 50; max range 100")


def add_gmx_update_order_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--order-key", required=True, help="GMX bytes32 order key")
    parser.add_argument("--size-delta-usd-raw", required=True, help="Raw 30-decimal USD size delta")
    parser.add_argument("--acceptable-price-raw", required=True, help="Raw 30-decimal acceptable price")
    parser.add_argument("--trigger-price-raw", required=True, help="Raw 30-decimal trigger price")
    parser.add_argument("--min-output-amount-raw", required=True, help="Raw minimum output amount")
    parser.add_argument("--valid-from-time-raw", required=True, help="Raw timestamp from which the order is valid")
    parser.add_argument("--auto-cancel", action="store_true", help="Set GMX autoCancel flag")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_deposit_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--market", required=True, help="GMX market token address")
    parser.add_argument("--initial-long-token", required=True, help="Initial long token address")
    parser.add_argument("--initial-short-token", required=True, help="Initial short token address")
    parser.add_argument("--initial-long-token-amount-raw", help="Raw initial long token amount")
    parser.add_argument("--initial-short-token-amount-raw", help="Raw initial short token amount")
    parser.add_argument("--min-market-tokens-raw", required=True, help="Raw minimum GM market tokens")
    parser.add_argument("--execution-fee-raw", required=True, help="Raw ETH execution fee in wei")
    parser.add_argument("--receiver", help="Optional receiver; defaults to agent wallet")
    parser.add_argument("--callback-contract", help="Optional GMX callback contract")
    parser.add_argument("--ui-fee-receiver", help="Optional UI fee receiver")
    parser.add_argument("--long-token-swap-path", action="append", help="Optional long token swap path market address; repeatable")
    parser.add_argument("--short-token-swap-path", action="append", help="Optional short token swap path market address; repeatable")
    parser.add_argument("--callback-gas-limit-raw", help="Raw callback gas limit")
    parser.add_argument("--should-unwrap-native-token", action="store_true", help="Ask GMX to unwrap native output when supported")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_withdrawal_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--market", required=True, help="GMX market token address")
    parser.add_argument("--market-token-amount-raw", required=True, help="Raw GM market token amount")
    parser.add_argument("--min-long-token-amount-raw", required=True, help="Raw minimum long token amount")
    parser.add_argument("--min-short-token-amount-raw", required=True, help="Raw minimum short token amount")
    parser.add_argument("--execution-fee-raw", required=True, help="Raw ETH execution fee in wei")
    parser.add_argument("--receiver", help="Optional receiver; defaults to agent wallet")
    parser.add_argument("--callback-contract", help="Optional GMX callback contract")
    parser.add_argument("--ui-fee-receiver", help="Optional UI fee receiver")
    parser.add_argument("--long-token-swap-path", action="append", help="Optional long token swap path market address; repeatable")
    parser.add_argument("--short-token-swap-path", action="append", help="Optional short token swap path market address; repeatable")
    parser.add_argument("--callback-gas-limit-raw", help="Raw callback gas limit")
    parser.add_argument("--should-unwrap-native-token", action="store_true", help="Ask GMX to unwrap native output when supported")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_cancel_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--request-type", required=True, choices=["order", "deposit", "withdrawal", "shift"], help="GMX request type")
    parser.add_argument("--key", required=True, help="GMX bytes32 request key")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_gmx_claim_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument("--chain", default="arbitrum", choices=["arbitrum"], help="GMX V2 Arbitrum Sepolia chain label")
    parser.add_argument("--claim-type", required=True, choices=["funding_fees", "collateral", "affiliate_rewards", "ui_fees"], help="GMX claim type")
    parser.add_argument("--market", action="append", help="GMX market address; repeatable")
    parser.add_argument("--token", action="append", help="GMX claim token address; repeatable")
    parser.add_argument("--time-key-raw", action="append", help="Collateral claim time key; repeatable")
    parser.add_argument("--receiver", help="Optional receiver; defaults to agent wallet")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")
    parser.add_argument("--body-file", help="Path to full request JSON object (overrides payload flags)")


def add_balancer_swap_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument(
        "--chain",
        default="ethereum",
        choices=["ethereum"],
        help="Balancer V3 Ethereum Sepolia chain label",
    )
    parser.add_argument(
        "--pool",
        help="Optional Balancer V3 pool address; omit for automatic discovery",
    )
    parser.add_argument("--token-in", required=True, help="Input token address")
    parser.add_argument("--token-out", required=True, help="Output token address")
    parser.add_argument(
        "--swap-kind",
        default="exact_in",
        choices=["exact_in", "exact_out"],
        help="Exact input or exact output swap",
    )
    parser.add_argument(
        "--amount-raw",
        required=True,
        help="Exact input amount for exact_in, or exact output amount for exact_out",
    )
    parser.add_argument(
        "--limit-raw",
        help="Minimum output for exact_in, or maximum input for exact_out",
    )
    parser.add_argument(
        "--slippage-bps",
        type=int,
        default=100,
        help="Quote-derived slippage limit in basis points when --limit-raw is omitted",
    )
    parser.add_argument(
        "--deadline",
        type=int,
        help="Optional future Unix timestamp; defaults to 20 minutes",
    )
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")


def add_balancer_liquidity_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    parser.add_argument(
        "--chain",
        default="ethereum",
        choices=["ethereum"],
        help="Balancer V3 Ethereum Sepolia chain label",
    )
    parser.add_argument("--pool", required=True, help="Balancer V3 pool address")
    parser.add_argument(
        "--slippage-bps",
        type=int,
        default=100,
        help="Quote-derived slippage limit in basis points",
    )
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")


def add_balancer_add_liquidity_flags(parser: argparse.ArgumentParser) -> None:
    add_balancer_liquidity_common_flags(parser)
    parser.add_argument(
        "--amount-in",
        action="append",
        required=True,
        help="Token and raw amount as TOKEN_ADDRESS=RAW_AMOUNT; repeatable up to 3 times",
    )
    parser.add_argument(
        "--min-bpt-amount-out-raw",
        help="Optional explicit minimum BPT output",
    )
    parser.add_argument(
        "--deadline",
        type=int,
        help="Optional future Unix timestamp for expiring Permit2 allowances",
    )


def add_balancer_remove_liquidity_flags(parser: argparse.ArgumentParser) -> None:
    add_balancer_liquidity_common_flags(parser)
    parser.add_argument(
        "--bpt-amount-in-raw",
        required=True,
        help="Exact raw BPT amount to burn",
    )
    parser.add_argument(
        "--min-amount-out",
        action="append",
        help="Optional token minimum as TOKEN_ADDRESS=RAW_AMOUNT; repeatable",
    )


def parse_uniswap_v4_fee(value: str) -> int:
    fee = int(value)
    if 0 <= fee <= 1_000_000 or fee == 0x800000:
        return fee
    raise argparse.ArgumentTypeError(
        "fee must be between 0 and 1000000, or 8388608 for a dynamic-fee pool"
    )


def add_uniswap_v4_pool_key_flags(
    parser: argparse.ArgumentParser, *, swap: bool, pool_key_required: bool
) -> None:
    parser.add_argument(
        "--chain",
        default="ethereum",
        choices=["ethereum"],
        help="Uniswap V4 Ethereum Sepolia chain label",
    )
    if swap:
        parser.add_argument(
            "--token-in",
            required=True,
            help="Input currency address; use 0x000...000 for native ETH",
        )
        parser.add_argument(
            "--token-out",
            required=True,
            help="Output currency address; use 0x000...000 for native ETH",
        )
    else:
        parser.add_argument("--token-a", required=True, help="First pool currency")
        parser.add_argument("--token-b", required=True, help="Second pool currency")
    parser.add_argument(
        "--fee",
        required=pool_key_required,
        type=parse_uniswap_v4_fee,
        help="Pool LP fee; omit with --tick-spacing and --hooks for automatic selection",
    )
    parser.add_argument(
        "--tick-spacing",
        required=pool_key_required,
        type=int,
        help="Pool tick spacing; omit with --fee and --hooks for automatic selection",
    )
    parser.add_argument(
        "--hooks",
        default=(
            "0x0000000000000000000000000000000000000000"
            if pool_key_required
            else None
        ),
        help="Pool hooks contract; defaults to no hooks",
    )


def add_uniswap_v4_swap_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--agent-id", required=True, help="Agent identifier")
    add_uniswap_v4_pool_key_flags(
        parser, swap=True, pool_key_required=False
    )
    parser.add_argument(
        "--include-hooked-pools",
        action="store_true",
        help="Allow automatic selection to consider hook-enabled pools",
    )
    parser.add_argument(
        "--hook-data", default="0x", help="Hex hook data required by the selected pool"
    )
    parser.add_argument(
        "--swap-kind",
        default="exact_in",
        choices=["exact_in", "exact_out"],
        help="Exact input or exact output swap",
    )
    parser.add_argument(
        "--amount-raw",
        required=True,
        help="Exact input for exact_in, or exact output for exact_out, in raw units",
    )
    parser.add_argument(
        "--limit-raw",
        help="Minimum output for exact_in, or maximum input for exact_out",
    )
    parser.add_argument(
        "--slippage-bps",
        type=int,
        default=100,
        help="Quote-derived slippage limit when --limit-raw is omitted",
    )
    parser.add_argument("--deadline", type=int, help="Future Unix timestamp")
    parser.add_argument("--strategy-id", help="Optional strategy ID")
    parser.add_argument("--callback-url", help="Optional callback webhook URL")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Ardent API CLI")
    parser.add_argument("--version", action="version", version=f"ardent {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_health = subparsers.add_parser("health", help="GET /health")
    add_global_flags(p_health)
    p_health.set_defaults(func=run_health)

    p_feed = subparsers.add_parser("feed", help="GET /feed/recent")
    add_global_flags(p_feed)
    p_feed.add_argument("--limit", type=int, default=12, help="Feed item limit (1-50)")
    p_feed.set_defaults(func=run_feed)

    p_wallet = subparsers.add_parser("wallet", help="GET /wallet")
    add_global_flags(p_wallet)
    p_wallet.add_argument("--agent-id", required=True, help="Agent identifier")
    p_wallet.add_argument("--chain", default="ethereum", choices=["ethereum", "base", "arbitrum"], help="Target chain")
    p_wallet.set_defaults(func=run_wallet)

    p_wallet_balance = subparsers.add_parser("wallet-balance", help="GET /wallet/balance")
    add_global_flags(p_wallet_balance)
    p_wallet_balance.add_argument("--agent-id", required=True, help="Agent identifier")
    p_wallet_balance.add_argument("--chain", default="ethereum", choices=["ethereum", "base", "arbitrum"], help="Target chain")
    p_wallet_balance.set_defaults(func=run_wallet_balance)

    p_delegation_register = subparsers.add_parser(
        "delegation-register",
        help="Register a DelegatedAccount and prepare its owner authorization",
    )
    add_global_flags(p_delegation_register)
    p_delegation_register.add_argument("--agent-id", required=True)
    p_delegation_register.add_argument(
        "--chain", required=True, choices=["ethereum", "base", "arbitrum"]
    )
    p_delegation_register.add_argument("--account-address", required=True)
    p_delegation_register.add_argument("--valid-after", type=int, default=0)
    p_delegation_register.add_argument("--valid-until", type=int, required=True)
    p_delegation_register.add_argument("--max-native-value-raw", default="0")
    p_delegation_register.add_argument("--max-fee-raw", required=True)
    p_delegation_register.add_argument(
        "--permission",
        action="append",
        required=True,
        help="Allowed contract and selector as TARGET:0xSELECTOR; repeatable",
    )
    p_delegation_register.set_defaults(func=run_delegation_register)

    p_delegation_status = subparsers.add_parser(
        "delegation-status", help="Read a delegated session policy on-chain"
    )
    add_global_flags(p_delegation_status)
    p_delegation_status.add_argument("--agent-id", required=True)
    p_delegation_status.add_argument(
        "--chain", required=True, choices=["ethereum", "base", "arbitrum"]
    )
    p_delegation_status.set_defaults(func=run_delegation_status)

    p_delegation_revoke = subparsers.add_parser(
        "delegation-revoke-prepare",
        help="Prepare the owner transaction that revokes a delegated session",
    )
    add_global_flags(p_delegation_revoke)
    p_delegation_revoke.add_argument("--agent-id", required=True)
    p_delegation_revoke.set_defaults(func=run_delegation_revoke_prepare)

    p_sim = subparsers.add_parser("simulate", help="POST /simulate")
    add_global_flags(p_sim)
    add_execution_payload_flags(p_sim)
    p_sim.set_defaults(func=run_simulate)

    p_exec = subparsers.add_parser("execute", help="POST /execute")
    add_global_flags(p_exec)
    add_execution_payload_flags(p_exec)
    p_exec.set_defaults(func=run_execute)

    p_aave_sim = subparsers.add_parser("aave-supply-simulate", help="POST /protocols/aave-v3/supply/simulate")
    add_global_flags(p_aave_sim)
    add_aave_supply_flags(p_aave_sim)
    p_aave_sim.set_defaults(func=run_aave_supply_simulate)

    p_aave_exec = subparsers.add_parser("aave-supply", help="POST /protocols/aave-v3/supply")
    add_global_flags(p_aave_exec)
    add_aave_supply_flags(p_aave_exec)
    p_aave_exec.set_defaults(func=run_aave_supply)

    p_aave_withdraw_sim = subparsers.add_parser("aave-withdraw-simulate", help="POST /protocols/aave-v3/withdraw/simulate")
    add_global_flags(p_aave_withdraw_sim)
    add_aave_amount_action_flags(p_aave_withdraw_sim, allow_max=True)
    p_aave_withdraw_sim.add_argument("--to", help="Optional recipient address; defaults to agent wallet")
    p_aave_withdraw_sim.set_defaults(func=run_aave_withdraw_simulate)

    p_aave_withdraw = subparsers.add_parser("aave-withdraw", help="POST /protocols/aave-v3/withdraw")
    add_global_flags(p_aave_withdraw)
    add_aave_amount_action_flags(p_aave_withdraw, allow_max=True)
    p_aave_withdraw.add_argument("--to", help="Optional recipient address; defaults to agent wallet")
    p_aave_withdraw.set_defaults(func=run_aave_withdraw)

    p_aave_repay_sim = subparsers.add_parser("aave-repay-simulate", help="POST /protocols/aave-v3/repay/simulate")
    add_global_flags(p_aave_repay_sim)
    add_aave_amount_action_flags(p_aave_repay_sim, allow_max=True)
    p_aave_repay_sim.add_argument("--interest-rate-mode", type=int, choices=[1, 2], default=2, help="1 stable, 2 variable")
    p_aave_repay_sim.add_argument("--on-behalf-of", help="Optional debt owner; defaults to agent wallet")
    p_aave_repay_sim.set_defaults(func=run_aave_repay_simulate)

    p_aave_repay = subparsers.add_parser("aave-repay", help="POST /protocols/aave-v3/repay")
    add_global_flags(p_aave_repay)
    add_aave_amount_action_flags(p_aave_repay, allow_max=True)
    p_aave_repay.add_argument("--interest-rate-mode", type=int, choices=[1, 2], default=2, help="1 stable, 2 variable")
    p_aave_repay.add_argument("--on-behalf-of", help="Optional debt owner; defaults to agent wallet")
    p_aave_repay.set_defaults(func=run_aave_repay)

    p_aave_borrow_sim = subparsers.add_parser("aave-borrow-simulate", help="POST /protocols/aave-v3/borrow/simulate")
    add_global_flags(p_aave_borrow_sim)
    add_aave_amount_action_flags(p_aave_borrow_sim, allow_max=True)
    p_aave_borrow_sim.add_argument("--interest-rate-mode", type=int, choices=[1, 2], default=2, help="1 stable, 2 variable")
    p_aave_borrow_sim.add_argument("--referral-code", type=int, help="Optional Aave referral code")
    p_aave_borrow_sim.add_argument("--on-behalf-of", help="Optional debt owner; defaults to agent wallet")
    p_aave_borrow_sim.add_argument("--min-health-factor", help="Minimum projected health factor after borrow; default 1.05")
    p_aave_borrow_sim.set_defaults(func=run_aave_borrow_simulate)

    p_aave_borrow = subparsers.add_parser("aave-borrow", help="POST /protocols/aave-v3/borrow")
    add_global_flags(p_aave_borrow)
    add_aave_amount_action_flags(p_aave_borrow, allow_max=True)
    p_aave_borrow.add_argument("--interest-rate-mode", type=int, choices=[1, 2], default=2, help="1 stable, 2 variable")
    p_aave_borrow.add_argument("--referral-code", type=int, help="Optional Aave referral code")
    p_aave_borrow.add_argument("--on-behalf-of", help="Optional debt owner; defaults to agent wallet")
    p_aave_borrow.add_argument("--min-health-factor", help="Minimum projected health factor after borrow; default 1.05")
    p_aave_borrow.set_defaults(func=run_aave_borrow)

    p_aave_position = subparsers.add_parser("aave-position", help="GET /protocols/aave-v3/position")
    add_global_flags(p_aave_position)
    p_aave_position.add_argument("--agent-id", required=True, help="Agent identifier")
    p_aave_position.add_argument("--chain", default="ethereum", choices=["ethereum"], help="Aave V3 Sepolia chain label")
    p_aave_position.set_defaults(func=run_aave_position)

    p_aave_balances = subparsers.add_parser("aave-balances", help="GET /protocols/aave-v3/balances")
    add_global_flags(p_aave_balances)
    p_aave_balances.add_argument("--agent-id", required=True, help="Agent identifier")
    p_aave_balances.add_argument("--chain", default="ethereum", choices=["ethereum"], help="Aave V3 Sepolia chain label")
    p_aave_balances.set_defaults(func=run_aave_balances)

    p_compound_supply_sim = subparsers.add_parser("compound-supply-simulate", help="POST /protocols/compound-v3/supply/simulate")
    add_global_flags(p_compound_supply_sim)
    add_compound_amount_action_flags(p_compound_supply_sim, allow_max=True)
    p_compound_supply_sim.set_defaults(func=run_compound_supply_simulate)

    p_compound_supply = subparsers.add_parser("compound-supply", help="POST /protocols/compound-v3/supply")
    add_global_flags(p_compound_supply)
    add_compound_amount_action_flags(p_compound_supply, allow_max=True)
    p_compound_supply.set_defaults(func=run_compound_supply)

    p_compound_withdraw_sim = subparsers.add_parser("compound-withdraw-simulate", help="POST /protocols/compound-v3/withdraw/simulate")
    add_global_flags(p_compound_withdraw_sim)
    add_compound_amount_action_flags(p_compound_withdraw_sim, allow_max=True)
    p_compound_withdraw_sim.set_defaults(func=run_compound_withdraw_simulate)

    p_compound_withdraw = subparsers.add_parser("compound-withdraw", help="POST /protocols/compound-v3/withdraw")
    add_global_flags(p_compound_withdraw)
    add_compound_amount_action_flags(p_compound_withdraw, allow_max=True)
    p_compound_withdraw.set_defaults(func=run_compound_withdraw)

    p_compound_repay_sim = subparsers.add_parser("compound-repay-simulate", help="POST /protocols/compound-v3/repay/simulate")
    add_global_flags(p_compound_repay_sim)
    add_compound_amount_action_flags(p_compound_repay_sim, allow_max=True, base_only=True)
    p_compound_repay_sim.set_defaults(func=run_compound_repay_simulate)

    p_compound_repay = subparsers.add_parser("compound-repay", help="POST /protocols/compound-v3/repay")
    add_global_flags(p_compound_repay)
    add_compound_amount_action_flags(p_compound_repay, allow_max=True, base_only=True)
    p_compound_repay.set_defaults(func=run_compound_repay)

    p_compound_borrow_sim = subparsers.add_parser("compound-borrow-simulate", help="POST /protocols/compound-v3/borrow/simulate")
    add_global_flags(p_compound_borrow_sim)
    add_compound_amount_action_flags(p_compound_borrow_sim, base_only=True)
    p_compound_borrow_sim.set_defaults(func=run_compound_borrow_simulate)

    p_compound_borrow = subparsers.add_parser("compound-borrow", help="POST /protocols/compound-v3/borrow")
    add_global_flags(p_compound_borrow)
    add_compound_amount_action_flags(p_compound_borrow, base_only=True)
    p_compound_borrow.set_defaults(func=run_compound_borrow)

    p_compound_position = subparsers.add_parser("compound-position", help="GET /protocols/compound-v3/position")
    add_global_flags(p_compound_position)
    p_compound_position.add_argument("--agent-id", required=True, help="Agent identifier")
    p_compound_position.add_argument("--chain", default="base", choices=["base"], help="Compound III Base Sepolia chain label")
    p_compound_position.add_argument("--market", default="usdc", choices=["usdc", "weth"], help="Compound III market")
    p_compound_position.set_defaults(func=run_compound_position)

    p_compound_balances = subparsers.add_parser("compound-balances", help="GET /protocols/compound-v3/balances")
    add_global_flags(p_compound_balances)
    p_compound_balances.add_argument("--agent-id", required=True, help="Agent identifier")
    p_compound_balances.add_argument("--chain", default="base", choices=["base"], help="Compound III Base Sepolia chain label")
    p_compound_balances.add_argument("--market", default="usdc", choices=["usdc", "weth"], help="Compound III market")
    p_compound_balances.set_defaults(func=run_compound_balances)

    p_compound_borrow_capacity = subparsers.add_parser("compound-borrow-capacity", help="GET /protocols/compound-v3/borrow-capacity")
    add_global_flags(p_compound_borrow_capacity)
    p_compound_borrow_capacity.add_argument("--agent-id", required=True, help="Agent identifier")
    p_compound_borrow_capacity.add_argument("--chain", default="base", choices=["base"], help="Compound III Base Sepolia chain label")
    p_compound_borrow_capacity.add_argument("--market", default="usdc", choices=["usdc", "weth"], help="Compound III market")
    p_compound_borrow_capacity.set_defaults(func=run_compound_borrow_capacity)

    p_compound_markets = subparsers.add_parser(
        "compound-markets", help="GET /protocols/compound-v3/markets"
    )
    add_global_flags(p_compound_markets)
    p_compound_markets.add_argument("--chain", default="base", choices=["base"])
    p_compound_markets.add_argument(
        "--base-asset", choices=["USDC", "WETH"], help="Optional base-asset filter"
    )
    p_compound_markets.set_defaults(func=run_compound_markets)

    morpho_default_market = "0x6143c1e52ed45fb9a0551b349abb4a1b8c5962dd39545ac235a9c98610bf97da"
    p_morpho_market = subparsers.add_parser("morpho-market", help="GET /protocols/morpho/market")
    add_global_flags(p_morpho_market)
    p_morpho_market.add_argument("--chain", default="base", choices=["base"])
    p_morpho_market.add_argument("--market-id", default=morpho_default_market)
    p_morpho_market.set_defaults(func=run_morpho_market)

    p_morpho_markets = subparsers.add_parser(
        "morpho-markets", help="GET /protocols/morpho/markets"
    )
    add_global_flags(p_morpho_markets)
    p_morpho_markets.add_argument("--chain", default="base", choices=["base"])
    p_morpho_markets.add_argument("--loan-token", help="Loan-token address filter")
    p_morpho_markets.add_argument("--collateral-token", help="Collateral-token address filter")
    p_morpho_markets.add_argument("--max-lltv-raw", help="Maximum LLTV scaled by 1e18")
    p_morpho_markets.add_argument("--min-liquidity-raw", help="Minimum raw loan-token liquidity")
    p_morpho_markets.add_argument(
        "--allow-unavailable-oracle",
        action="store_false",
        dest="require_available_oracle",
        help="Include markets whose oracle is currently stale, unavailable, or zero",
    )
    p_morpho_markets.set_defaults(require_available_oracle=True)
    p_morpho_markets.add_argument("--limit", type=int, default=20)
    p_morpho_markets.set_defaults(func=run_morpho_markets)

    p_morpho_position = subparsers.add_parser("morpho-position", help="GET /protocols/morpho/position")
    add_global_flags(p_morpho_position)
    p_morpho_position.add_argument("--agent-id", required=True, help="Agent identifier")
    p_morpho_position.add_argument("--chain", default="base", choices=["base"])
    p_morpho_position.add_argument("--market-id", default=morpho_default_market)
    p_morpho_position.set_defaults(func=run_morpho_position)

    morpho_actions = [
        ("supply", True, False),
        ("withdraw", True, False),
        ("supply-collateral", True, False),
        ("withdraw-collateral", True, True),
        ("borrow", False, True),
        ("repay", True, False),
    ]
    for endpoint, allow_max, health_guard in morpho_actions:
        command = f"morpho-{endpoint}"
        simulate = subparsers.add_parser(
            f"{command}-simulate",
            help=f"POST /protocols/morpho/{endpoint}/simulate",
        )
        add_global_flags(simulate)
        add_morpho_action_flags(
            simulate, allow_max=allow_max, health_guard=health_guard
        )
        simulate.set_defaults(
            func=run_morpho_action, endpoint=endpoint, execute=False
        )

        execute = subparsers.add_parser(
            command,
            help=f"POST /protocols/morpho/{endpoint}",
        )
        add_global_flags(execute)
        add_morpho_action_flags(
            execute, allow_max=allow_max, health_guard=health_guard
        )
        execute.set_defaults(func=run_morpho_action, endpoint=endpoint, execute=True)

    p_balancer_swap_sim = subparsers.add_parser(
        "balancer-swap-simulate",
        help="POST /protocols/balancer-v3/swap/simulate",
    )
    add_global_flags(p_balancer_swap_sim)
    add_balancer_swap_flags(p_balancer_swap_sim)
    p_balancer_swap_sim.set_defaults(func=run_balancer_swap_simulate)

    p_balancer_swap = subparsers.add_parser(
        "balancer-swap",
        help="POST /protocols/balancer-v3/swap",
    )
    add_global_flags(p_balancer_swap)
    add_balancer_swap_flags(p_balancer_swap)
    p_balancer_swap.set_defaults(func=run_balancer_swap)

    p_balancer_quote = subparsers.add_parser(
        "balancer-quote",
        help="POST /protocols/balancer-v3/swap/quote",
    )
    add_global_flags(p_balancer_quote)
    add_balancer_swap_flags(p_balancer_quote)
    p_balancer_quote.set_defaults(func=run_balancer_quote)

    for command, action, mode, help_text in [
        (
            "balancer-add-liquidity-quote",
            "add",
            "quote",
            "POST /protocols/balancer-v3/liquidity/add/quote",
        ),
        (
            "balancer-add-liquidity-simulate",
            "add",
            "simulate",
            "POST /protocols/balancer-v3/liquidity/add/simulate",
        ),
        (
            "balancer-add-liquidity",
            "add",
            "execute",
            "POST /protocols/balancer-v3/liquidity/add",
        ),
    ]:
        liquidity_parser = subparsers.add_parser(command, help=help_text)
        add_global_flags(liquidity_parser)
        add_balancer_add_liquidity_flags(liquidity_parser)
        liquidity_parser.set_defaults(
            func=run_balancer_liquidity,
            liquidity_action=action,
            liquidity_mode=mode,
        )

    for command, action, mode, help_text in [
        (
            "balancer-remove-liquidity-quote",
            "remove",
            "quote",
            "POST /protocols/balancer-v3/liquidity/remove/quote",
        ),
        (
            "balancer-remove-liquidity-simulate",
            "remove",
            "simulate",
            "POST /protocols/balancer-v3/liquidity/remove/simulate",
        ),
        (
            "balancer-remove-liquidity",
            "remove",
            "execute",
            "POST /protocols/balancer-v3/liquidity/remove",
        ),
    ]:
        liquidity_parser = subparsers.add_parser(command, help=help_text)
        add_global_flags(liquidity_parser)
        add_balancer_remove_liquidity_flags(liquidity_parser)
        liquidity_parser.set_defaults(
            func=run_balancer_liquidity,
            liquidity_action=action,
            liquidity_mode=mode,
        )

    p_balancer_pool = subparsers.add_parser(
        "balancer-pool",
        help="GET /protocols/balancer-v3/pool",
    )
    add_global_flags(p_balancer_pool)
    p_balancer_pool.add_argument(
        "--chain", default="ethereum", choices=["ethereum"], help="Ethereum Sepolia"
    )
    p_balancer_pool.add_argument("--pool", required=True, help="Balancer V3 pool address")
    p_balancer_pool.set_defaults(func=run_balancer_pool)

    p_balancer_pools = subparsers.add_parser(
        "balancer-pools",
        help="GET /protocols/balancer-v3/pools",
    )
    add_global_flags(p_balancer_pools)
    p_balancer_pools.add_argument(
        "--chain", default="ethereum", choices=["ethereum"], help="Ethereum Sepolia"
    )
    p_balancer_pools.add_argument("--token-in", required=True, help="Input token address")
    p_balancer_pools.add_argument("--token-out", required=True, help="Output token address")
    p_balancer_pools.set_defaults(func=run_balancer_pools)

    p_balancer_balances = subparsers.add_parser(
        "balancer-balances",
        help="GET /protocols/balancer-v3/balances",
    )
    add_global_flags(p_balancer_balances)
    p_balancer_balances.add_argument("--agent-id", required=True, help="Agent identifier")
    p_balancer_balances.add_argument(
        "--chain", default="ethereum", choices=["ethereum"], help="Ethereum Sepolia"
    )
    p_balancer_balances.add_argument(
        "--pool", required=True, help="Balancer V3 pool address"
    )
    p_balancer_balances.set_defaults(func=run_balancer_balances)

    for command, execute, help_text in [
        (
            "uniswap-v4-swap-simulate",
            False,
            "POST /protocols/uniswap-v4/swap/simulate",
        ),
        ("uniswap-v4-swap", True, "POST /protocols/uniswap-v4/swap"),
    ]:
        uniswap_swap = subparsers.add_parser(command, help=help_text)
        add_global_flags(uniswap_swap)
        add_uniswap_v4_swap_flags(uniswap_swap)
        uniswap_swap.set_defaults(func=run_uniswap_v4_swap, execute=execute)

    p_uniswap_quote = subparsers.add_parser(
        "uniswap-v4-quote", help="POST /protocols/uniswap-v4/swap/quote"
    )
    add_global_flags(p_uniswap_quote)
    add_uniswap_v4_swap_flags(p_uniswap_quote)
    p_uniswap_quote.set_defaults(func=run_uniswap_v4_quote)

    p_uniswap_pool = subparsers.add_parser(
        "uniswap-v4-pool", help="GET /protocols/uniswap-v4/pool"
    )
    add_global_flags(p_uniswap_pool)
    add_uniswap_v4_pool_key_flags(
        p_uniswap_pool, swap=False, pool_key_required=True
    )
    p_uniswap_pool.set_defaults(func=run_uniswap_v4_pool)

    p_uniswap_pools = subparsers.add_parser(
        "uniswap-v4-pools", help="GET /protocols/uniswap-v4/pools"
    )
    add_global_flags(p_uniswap_pools)
    p_uniswap_pools.add_argument(
        "--chain", default="ethereum", choices=["ethereum"]
    )
    p_uniswap_pools.add_argument("--token-a", required=True)
    p_uniswap_pools.add_argument("--token-b", required=True)
    p_uniswap_pools.add_argument(
        "--include-hooked-pools", action="store_true"
    )
    p_uniswap_pools.set_defaults(func=run_uniswap_v4_pools)

    p_uniswap_balances = subparsers.add_parser(
        "uniswap-v4-balances", help="GET /protocols/uniswap-v4/balances"
    )
    add_global_flags(p_uniswap_balances)
    p_uniswap_balances.add_argument(
        "--agent-id", required=True, help="Agent identifier"
    )
    p_uniswap_balances.add_argument(
        "--chain", default="ethereum", choices=["ethereum"]
    )
    p_uniswap_balances.add_argument("--token-a", required=True)
    p_uniswap_balances.add_argument("--token-b", required=True)
    p_uniswap_balances.set_defaults(func=run_uniswap_v4_balances)

    p_gmx_create_order_sim = subparsers.add_parser("gmx-create-order-simulate", help="POST /protocols/gmx-v2/orders/simulate")
    add_global_flags(p_gmx_create_order_sim)
    add_gmx_create_order_flags(p_gmx_create_order_sim)
    p_gmx_create_order_sim.set_defaults(func=run_gmx_create_order_simulate)

    p_gmx_create_order = subparsers.add_parser("gmx-create-order", help="POST /protocols/gmx-v2/orders")
    add_global_flags(p_gmx_create_order)
    add_gmx_create_order_flags(p_gmx_create_order)
    p_gmx_create_order.set_defaults(func=run_gmx_create_order)

    p_gmx_cancel_order_sim = subparsers.add_parser("gmx-cancel-order-simulate", help="POST /protocols/gmx-v2/orders/cancel/simulate")
    add_global_flags(p_gmx_cancel_order_sim)
    add_gmx_cancel_order_flags(p_gmx_cancel_order_sim)
    p_gmx_cancel_order_sim.set_defaults(func=run_gmx_cancel_order_simulate)

    p_gmx_cancel_order = subparsers.add_parser("gmx-cancel-order", help="POST /protocols/gmx-v2/orders/cancel")
    add_global_flags(p_gmx_cancel_order)
    add_gmx_cancel_order_flags(p_gmx_cancel_order)
    p_gmx_cancel_order.set_defaults(func=run_gmx_cancel_order)

    p_gmx_markets = subparsers.add_parser("gmx-markets", help="GET /protocols/gmx-v2/markets")
    add_global_flags(p_gmx_markets)
    add_gmx_range_flags(p_gmx_markets, include_agent=False)
    p_gmx_markets.set_defaults(func=run_gmx_markets)

    p_gmx_positions = subparsers.add_parser("gmx-positions", help="GET /protocols/gmx-v2/positions")
    add_global_flags(p_gmx_positions)
    add_gmx_range_flags(p_gmx_positions)
    p_gmx_positions.set_defaults(func=run_gmx_positions)

    p_gmx_orders = subparsers.add_parser("gmx-orders", help="GET /protocols/gmx-v2/orders")
    add_global_flags(p_gmx_orders)
    add_gmx_range_flags(p_gmx_orders)
    p_gmx_orders.set_defaults(func=run_gmx_orders)

    p_gmx_balances = subparsers.add_parser(
        "gmx-balances",
        help="GET /protocols/gmx-v2/balances (GM market tokens + underlying market assets)",
    )
    add_global_flags(p_gmx_balances)
    add_gmx_range_flags(p_gmx_balances)
    p_gmx_balances.set_defaults(func=run_gmx_balances)

    p_gmx_update_order_sim = subparsers.add_parser("gmx-update-order-simulate", help="POST /protocols/gmx-v2/orders/update/simulate")
    add_global_flags(p_gmx_update_order_sim)
    add_gmx_update_order_flags(p_gmx_update_order_sim)
    p_gmx_update_order_sim.set_defaults(func=run_gmx_update_order_simulate)

    p_gmx_update_order = subparsers.add_parser("gmx-update-order", help="POST /protocols/gmx-v2/orders/update")
    add_global_flags(p_gmx_update_order)
    add_gmx_update_order_flags(p_gmx_update_order)
    p_gmx_update_order.set_defaults(func=run_gmx_update_order)

    p_gmx_deposit_sim = subparsers.add_parser("gmx-create-deposit-simulate", help="POST /protocols/gmx-v2/deposits/simulate")
    add_global_flags(p_gmx_deposit_sim)
    add_gmx_deposit_flags(p_gmx_deposit_sim)
    p_gmx_deposit_sim.set_defaults(func=run_gmx_create_deposit_simulate)

    p_gmx_deposit = subparsers.add_parser("gmx-create-deposit", help="POST /protocols/gmx-v2/deposits")
    add_global_flags(p_gmx_deposit)
    add_gmx_deposit_flags(p_gmx_deposit)
    p_gmx_deposit.set_defaults(func=run_gmx_create_deposit)

    p_gmx_withdrawal_sim = subparsers.add_parser("gmx-create-withdrawal-simulate", help="POST /protocols/gmx-v2/withdrawals/simulate")
    add_global_flags(p_gmx_withdrawal_sim)
    add_gmx_withdrawal_flags(p_gmx_withdrawal_sim)
    p_gmx_withdrawal_sim.set_defaults(func=run_gmx_create_withdrawal_simulate)

    p_gmx_withdrawal = subparsers.add_parser("gmx-create-withdrawal", help="POST /protocols/gmx-v2/withdrawals")
    add_global_flags(p_gmx_withdrawal)
    add_gmx_withdrawal_flags(p_gmx_withdrawal)
    p_gmx_withdrawal.set_defaults(func=run_gmx_create_withdrawal)

    p_gmx_cancel_sim = subparsers.add_parser("gmx-cancel-simulate", help="POST /protocols/gmx-v2/requests/cancel/simulate")
    add_global_flags(p_gmx_cancel_sim)
    add_gmx_cancel_flags(p_gmx_cancel_sim)
    p_gmx_cancel_sim.set_defaults(func=run_gmx_cancel_simulate)

    p_gmx_cancel = subparsers.add_parser("gmx-cancel", help="POST /protocols/gmx-v2/requests/cancel")
    add_global_flags(p_gmx_cancel)
    add_gmx_cancel_flags(p_gmx_cancel)
    p_gmx_cancel.set_defaults(func=run_gmx_cancel)

    p_gmx_claim_sim = subparsers.add_parser("gmx-claim-simulate", help="POST /protocols/gmx-v2/claims/simulate")
    add_global_flags(p_gmx_claim_sim)
    add_gmx_claim_flags(p_gmx_claim_sim)
    p_gmx_claim_sim.set_defaults(func=run_gmx_claim_simulate)

    p_gmx_claim = subparsers.add_parser("gmx-claim", help="POST /protocols/gmx-v2/claims")
    add_global_flags(p_gmx_claim)
    add_gmx_claim_flags(p_gmx_claim)
    p_gmx_claim.set_defaults(func=run_gmx_claim)

    p_status = subparsers.add_parser("status", help="GET /status/{id}")
    add_global_flags(p_status)
    p_status.add_argument("--request-id", required=True, help="Request UUID")
    p_status.set_defaults(func=run_status)

    p_update = subparsers.add_parser("self-update", help="Update CLI and runtime files from GitHub")
    p_update.add_argument(
        "--cli-only",
        action="store_true",
        help="Update only the ardent CLI and leave ~/.ardent runtime files unchanged",
    )
    p_update.set_defaults(func=run_self_update)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "feed" and not (1 <= args.limit <= 50):
        parser.error("--limit must be between 1 and 50")

    try:
        return args.func(args)
    except ValueError as exc:
        output({"error": str(exc)})
        return 2
    except Exception as exc:
        output({"error": f"unexpected error: {exc}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
