#!/usr/bin/env python3
"""
Minimal stdio MCP server for Ardent API.

Implements a practical subset of the MCP JSON-RPC methods:
- initialize
- tools/list
- tools/call

It loads tool definitions from `mcp-tools.json` and proxies HTTP calls to Ardent API.
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parent
TOOLS_FILE = ROOT / "mcp-tools.json"


def load_config() -> dict[str, Any]:
    with TOOLS_FILE.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


class ArdentMcpServer:
    def __init__(self) -> None:
        self.config = load_config()
        self.tools = {tool["name"]: tool for tool in self.config.get("tools", [])}

    def get_base_url(self) -> str:
        env_name = self.config.get("baseUrlEnv", "ARDENT_BASE_URL")
        return os.getenv(env_name, self.config.get("defaultBaseUrl", "https://api.ardentresearch.xyz"))

    def get_auth_header(self, base_url: str) -> tuple[str, str] | None:
        auth_cfg = self.config.get("auth", {})
        access_token_env = auth_cfg.get("accessTokenEnv", "ARDENT_ACCESS_TOKEN")
        access_token = os.getenv(access_token_env, "").strip()
        if access_token:
            return "Authorization", f"Bearer {access_token}"
        if os.getenv("ARDENT_CLIENT_ID") or os.getenv("ARDENT_CLIENT_PRIVATE_KEY_FILE"):
            try:
                from oauth_client import service_account_access_token
            except ModuleNotFoundError as exc:
                raise RuntimeError(
                    "OAuth runtime is missing; run `ardent self-update` or reinstall Ardent"
                ) from exc
            service_token = service_account_access_token(base_url)
            if service_token:
                return "Authorization", f"Bearer {service_token}"
        token_env = auth_cfg.get("tokenEnv", "ARDENT_API_KEY")
        token_header = auth_cfg.get("header", "X-API-Key")
        token_value = os.getenv(token_env, "").strip()
        if not token_value or token_value == "your_api_key_here":
            return None
        return token_header, token_value

    def tool_list(self) -> list[dict[str, Any]]:
        output = []
        for tool in self.config.get("tools", []):
            output.append(
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "inputSchema": tool.get("inputSchema", {"type": "object", "properties": {}}),
                }
            )
        return output

    def call_tool(self, name: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        if name not in self.tools:
            raise ValueError(f"unknown tool: {name}")

        tool = self.tools[name]
        arguments = arguments or {}

        base_url = self.get_base_url().rstrip("/")
        method = tool["method"].upper()
        path_template = tool["path"]

        path, remaining = self._render_path(path_template, arguments)

        headers: dict[str, str] = {
            "User-Agent": "ardent-mcp-server/1.0.0",
            "Accept": "application/json",
        }

        if tool.get("authRequired", False):
            auth = self.get_auth_header(base_url)
            if not auth:
                raise ValueError(
                    "missing credential. set ARDENT_CLIENT_ID with "
                    "ARDENT_CLIENT_PRIVATE_KEY_FILE, ARDENT_API_KEY, or "
                    "ARDENT_ACCESS_TOKEN"
                )
            headers[auth[0]] = auth[1]

        data: bytes | None = None
        final_url = f"{base_url}{path}"

        if method == "GET":
            if remaining:
                final_url = f"{final_url}?{parse.urlencode(remaining, doseq=True)}"
        elif method == "POST":
            body, extra_headers = self._build_post_body(tool_name=name, tool=tool, args=remaining)
            headers.update(extra_headers)
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        else:
            raise ValueError(f"unsupported method in tool config: {method}")

        req = request.Request(final_url, data=data, headers=headers, method=method)

        try:
            with request.urlopen(req, timeout=30) as response:
                status_code = response.getcode()
                body_bytes = response.read()
                body_text = body_bytes.decode("utf-8", errors="replace")
                body_json = self._safe_json_parse(body_text)
                return {
                    "status": status_code,
                    "url": final_url,
                    "method": method,
                    "body": body_json if body_json is not None else body_text,
                }
        except HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            parsed = self._safe_json_parse(error_body)
            return {
                "status": exc.code,
                "url": final_url,
                "method": method,
                "body": parsed if parsed is not None else error_body,
            }
        except URLError as exc:
            raise RuntimeError(f"network error calling {final_url}: {exc}") from exc

    def _render_path(self, path_template: str, arguments: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        remaining = dict(arguments)
        path = path_template

        for key in list(remaining.keys()):
            marker = "{" + key + "}"
            if marker in path:
                path = path.replace(marker, parse.quote(str(remaining.pop(key))))

        unresolved = [segment for segment in path.split("/") if segment.startswith("{") and segment.endswith("}")]
        if unresolved:
            raise ValueError(f"missing required path params: {', '.join(unresolved)}")

        return path, remaining

    def _build_post_body(self, tool_name: str, tool: dict[str, Any], args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        body = dict(args)
        headers: dict[str, str] = {}

        return body, headers

    @staticmethod
    def _safe_json_parse(body_text: str) -> Any | None:
        body_text = body_text.strip()
        if not body_text:
            return None
        try:
            return json.loads(body_text)
        except json.JSONDecodeError:
            return None


def write_message(message: dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def success_result(message_id: Any, result: dict[str, Any]) -> None:
    write_message({"jsonrpc": "2.0", "id": message_id, "result": result})


def error_result(message_id: Any, code: int, message: str, data: Any = None) -> None:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        payload["error"]["data"] = data
    write_message(payload)


def handle_request(server: ArdentMcpServer, message: dict[str, Any]) -> None:
    method = message.get("method")
    message_id = message.get("id")
    params = message.get("params", {})

    if method == "initialize":
        success_result(
            message_id,
            {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "ardent-mcp", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        )
        return

    if method == "notifications/initialized":
        return

    if method == "tools/list":
        success_result(message_id, {"tools": server.tool_list()})
        return

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments", {})
        if not tool_name:
            error_result(message_id, -32602, "missing tools/call params.name")
            return

        try:
            response = server.call_tool(tool_name, tool_args)
            success_result(
                message_id,
                {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(response, indent=2),
                        }
                    ]
                },
            )
        except Exception as exc:
            error_result(message_id, -32000, str(exc), data=traceback.format_exc())
        return

    error_result(message_id, -32601, f"method not found: {method}")


def main() -> int:
    server = ArdentMcpServer()
    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue

        try:
            message = json.loads(stripped)
        except json.JSONDecodeError as exc:
            error_result(None, -32700, f"invalid json: {exc}")
            continue

        try:
            handle_request(server, message)
        except Exception as exc:
            error_result(message.get("id"), -32000, f"internal error: {exc}", traceback.format_exc())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
