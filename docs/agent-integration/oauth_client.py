#!/usr/bin/env python3
"""Short-lived OAuth token acquisition for Ardent service accounts."""

from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError

_cached_token: str | None = None
_cached_token_expires_at = 0.0
_cached_token_key: tuple[str, str, str, str] | None = None


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _private_key_path() -> Path:
    raw_path = os.getenv("ARDENT_CLIENT_PRIVATE_KEY_FILE", "").strip()
    if not raw_path:
        raise ValueError("ARDENT_CLIENT_PRIVATE_KEY_FILE is required with ARDENT_CLIENT_ID")
    path = Path(raw_path).expanduser()
    file_stat = path.stat()
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError("ARDENT_CLIENT_PRIVATE_KEY_FILE must be a regular file")
    if os.name == "posix" and file_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("service-account private key permissions must be 0600 or stricter")
    return path


def _client_assertion(client_id: str, token_url: str, key_path: Path) -> str:
    now = int(time.time())
    header = _base64url(
        json.dumps({"alg": "RS256", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    claims = _base64url(
        json.dumps(
            {
                "iss": client_id,
                "sub": client_id,
                "aud": token_url,
                "iat": now,
                "exp": now + 300,
                "jti": str(uuid.uuid4()),
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    command = ["openssl", "dgst", "-sha256", "-sign", str(key_path)]
    if os.getenv("ARDENT_CLIENT_PRIVATE_KEY_PASSWORD"):
        command.extend(["-passin", "env:ARDENT_CLIENT_PRIVATE_KEY_PASSWORD"])
    try:
        result = subprocess.run(
            command,
            input=signing_input,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("OpenSSL is required for service-account authentication") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"could not sign OAuth client assertion: {detail}")
    return f"{header}.{claims}.{_base64url(result.stdout)}"


def service_account_access_token(base_url: str) -> str | None:
    """Return a cached or newly issued token, or None when OAuth is not configured."""
    global _cached_token, _cached_token_expires_at, _cached_token_key

    client_id = os.getenv("ARDENT_CLIENT_ID", "").strip()
    key_env = os.getenv("ARDENT_CLIENT_PRIVATE_KEY_FILE", "").strip()
    if not client_id and not key_env:
        return None
    if not client_id or not key_env:
        raise ValueError(
            "set both ARDENT_CLIENT_ID and ARDENT_CLIENT_PRIVATE_KEY_FILE"
        )

    scope = os.getenv("ARDENT_OAUTH_SCOPE", "").strip()
    token_url = os.getenv(
        "ARDENT_OAUTH_TOKEN_URL", f"{base_url.rstrip('/')}/oauth/token"
    ).strip()
    cache_key = (client_id, key_env, scope, token_url)
    if (
        _cached_token
        and _cached_token_key == cache_key
        and time.time() < _cached_token_expires_at
    ):
        return _cached_token

    assertion = _client_assertion(client_id, token_url, _private_key_path())
    form: dict[str, Any] = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_assertion_type": (
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ),
        "client_assertion": assertion,
    }
    if scope:
        form["scope"] = scope
    token_request = request.Request(
        token_url,
        data=parse.urlencode(form).encode("ascii"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "ardent-auth-client/1.0.0",
        },
        method="POST",
    )
    try:
        with request.urlopen(token_request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"OAuth token exchange failed ({exc.code}): {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"OAuth token exchange failed: {exc}") from exc

    access_token = payload.get("access_token")
    expires_in = payload.get("expires_in")
    if not isinstance(access_token, str) or not isinstance(expires_in, int):
        raise RuntimeError("OAuth token response is missing access_token or expires_in")
    _cached_token = access_token
    _cached_token_key = cache_key
    _cached_token_expires_at = time.time() + max(expires_in - 30, 1)
    return access_token
