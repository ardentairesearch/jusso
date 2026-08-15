#!/usr/bin/env bash
set -euo pipefail

REPO_RAW_BASE="https://raw.githubusercontent.com/Ardent-Ai-Research/agent-execution-platform/master/docs/agent-integration"

INSTALL_DIR="${ARDENT_INSTALL_DIR:-${HOME}/.local/bin}"
RUNTIME_DIR="${ARDENT_RUNTIME_DIR:-${HOME}/.ardent}"

# Require Python 3.8+
if ! command -v python3 &>/dev/null; then
  echo "❌ python3 is required but was not found. Install it from https://python.org and re-run."
  exit 1
fi
PY_VERSION=$(python3 -c 'import sys; print("%d%02d" % sys.version_info[:2])')
if [[ "${PY_VERSION}" -lt 308 ]]; then
  echo "❌ python3.8 or newer is required (found $(python3 --version)). Please upgrade."
  exit 1
fi

mkdir -p "${INSTALL_DIR}" "${RUNTIME_DIR}"

echo "Installing Ardent CLI..."
curl -fsSL "${REPO_RAW_BASE}/ardent_cli.py" -o "${INSTALL_DIR}/ardent"
chmod +x "${INSTALL_DIR}/ardent"

ensure_path_persisted() {
  local line
  local display_dir
  if [[ "${INSTALL_DIR}" == "${HOME}/"* ]]; then
    display_dir="\${HOME}/${INSTALL_DIR#"${HOME}/"}"
  else
    display_dir="${INSTALL_DIR}"
  fi
  line="export PATH=\"${display_dir}:\${PATH}\""
  local updated=0
  local candidates=()

  case "${SHELL:-}" in
    */zsh)
      candidates+=("${HOME}/.zshrc" "${HOME}/.zprofile")
      ;;
    */bash)
      candidates+=("${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.profile")
      ;;
    */fish)
      candidates+=("${HOME}/.profile" "${HOME}/.zprofile" "${HOME}/.zshrc" "${HOME}/.bashrc")
      ;;
    *)
      candidates+=("${HOME}/.profile" "${HOME}/.zprofile" "${HOME}/.zshrc" "${HOME}/.bashrc")
      ;;
  esac

  # Include common shell files so login shells, interactive shells, and a missing
  # SHELL env all keep the CLI available after a terminal restart.
  candidates+=("${HOME}/.zshrc" "${HOME}/.zprofile" "${HOME}/.bashrc" "${HOME}/.bash_profile" "${HOME}/.profile")

  local seen=":"
  local profile
  for profile in "${candidates[@]}"; do
    [[ "${seen}" == *":${profile}:"* ]] && continue
    seen="${seen}${profile}:"
    [[ -e "${profile}" || "${profile}" == "${HOME}/.zshrc" || "${profile}" == "${HOME}/.zprofile" || "${profile}" == "${HOME}/.profile" ]] || continue
    touch "${profile}"
    if ! grep -Fq "${INSTALL_DIR}" "${profile}" && ! grep -Fq "${display_dir}" "${profile}"; then
      {
        echo
        echo "# Ardent CLI"
        echo "${line}"
      } >> "${profile}"
      echo "  ✅ Added ${display_dir} to PATH in ${profile}"
      updated=1
    fi
  done

  local fish_config="${HOME}/.config/fish/config.fish"
  if [[ "${SHELL:-}" == */fish || -e "${fish_config}" ]]; then
    mkdir -p "$(dirname "${fish_config}")"
    touch "${fish_config}"
    if ! grep -Fq "${INSTALL_DIR}" "${fish_config}" && ! grep -Fq "${display_dir}" "${fish_config}"; then
      {
        echo
        echo "# Ardent CLI"
        echo "fish_add_path -g \"${INSTALL_DIR}\""
      } >> "${fish_config}"
      echo "  ✅ Added ${display_dir} to PATH in ${fish_config}"
      updated=1
    fi
  fi

  if [[ "${updated}" -eq 0 ]]; then
    echo "  ✅ ${display_dir} already appears in your shell PATH config."
  fi
}

ensure_path_persisted

echo "Installing optional MCP runtime files..."
curl -fsSL "${REPO_RAW_BASE}/mcp_server.py" -o "${RUNTIME_DIR}/mcp_server.py"
curl -fsSL "${REPO_RAW_BASE}/oauth_client.py" -o "${RUNTIME_DIR}/oauth_client.py"
curl -fsSL "${REPO_RAW_BASE}/mcp-tools.json" -o "${RUNTIME_DIR}/mcp-tools.json"
curl -fsSL "${REPO_RAW_BASE}/skills.md" -o "${RUNTIME_DIR}/skills.md"
curl -fsSL "${REPO_RAW_BASE}/openapi.yaml" -o "${RUNTIME_DIR}/openapi.yaml"

# ── Shared helper: patch an mcpServers-style config (Claude, Cursor, Windsurf)
patch_mcp_servers_config() {
  local config_path="${1}"
  local mcp_script="${2}"
  local label="${3}"
  python3 - "${config_path}" "${mcp_script}" "${label}" <<'PYEOF'
import json, sys, pathlib

config_path = pathlib.Path(sys.argv[1])
mcp_script  = sys.argv[2]
label       = sys.argv[3]

try:
    config = json.loads(config_path.read_text(encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    config = {}

existing = config.get("mcpServers", {}).get("ardent", {})
existing_env = existing.get("env", {}) if isinstance(existing, dict) else {}
updated_env = dict(existing_env)
if not any(
    updated_env.get(name)
    for name in ("ARDENT_API_KEY", "ARDENT_CLIENT_ID", "ARDENT_ACCESS_TOKEN")
):
    updated_env["ARDENT_API_KEY"] = "your_api_key_here"

config.setdefault("mcpServers", {})["ardent"] = {
    "command": "python3",
    "args": [mcp_script],
    "env": updated_env
}

config_path.parent.mkdir(parents=True, exist_ok=True)
config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
print(f"  ✅ {label} config updated.")
print(f"  ⚠️  Set your real API key in: {config_path}")
PYEOF
}

# ── Codex ────────────────────────────────────────────────────────────────────
patch_codex_config() {
  local codex_config="${1}"
  local mcp_script="${2}"

  mkdir -p "$(dirname "${codex_config}")"
  touch "${codex_config}"

  if grep -Eq '^\[mcp_servers\.ardent\]' "${codex_config}"; then
    echo "  ✅ Codex config already has an Ardent MCP server entry."
    echo "  ⚠️  Confirm an Ardent credential is set in: ${codex_config}"
    return
  fi

  cat >> "${codex_config}" <<EOF

[mcp_servers.ardent]
command = "python3"
args = ["${mcp_script}"]

[mcp_servers.ardent.env]
ARDENT_API_KEY = "your_api_key_here"
EOF

  echo "  ✅ Codex config updated."
  echo "  ⚠️  Set your real API key in: ${codex_config}"
}

CODEX_HOME_DIR="${CODEX_HOME:-${HOME}/.codex}"
if [[ "${ARDENT_SKIP_CODEX_MCP:-}" == "1" ]]; then
  echo "Codex MCP config skipped because ARDENT_SKIP_CODEX_MCP=1."
else
  echo "Configuring Codex MCP..."
  patch_codex_config \
    "${CODEX_HOME_DIR}/config.toml" \
    "${RUNTIME_DIR}/mcp_server.py"
fi

# ── Claude Desktop ───────────────────────────────────────────────────────────
CLAUDE_CONFIG_DIR="${HOME}/Library/Application Support/Claude"
if [[ -d "${CLAUDE_CONFIG_DIR}" ]]; then
  echo "Detected Claude Desktop — patching MCP config..."
  patch_mcp_servers_config \
    "${CLAUDE_CONFIG_DIR}/claude_desktop_config.json" \
    "${RUNTIME_DIR}/mcp_server.py" \
    "Claude Desktop"
else
  echo "Claude Desktop not detected — skipping."
fi

# ── ChatGPT Desktop ──────────────────────────────────────────────────────────
CHATGPT_CONFIG_DIR="${HOME}/Library/Application Support/com.openai.chat"
CHATGPT_CONFIG="${CHATGPT_CONFIG_DIR}/mcp_servers.json"

if [[ -d "${CHATGPT_CONFIG_DIR}" ]]; then
  echo "Detected ChatGPT Desktop — patching MCP config..."
  python3 - "${CHATGPT_CONFIG}" "${RUNTIME_DIR}/mcp_server.py" <<'PYEOF'
import json, sys, pathlib

config_path = pathlib.Path(sys.argv[1])
mcp_script  = sys.argv[2]

try:
    config = json.loads(config_path.read_text(encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    config = {}

# ChatGPT Desktop: file IS the servers object — no wrapper key
existing = config.get("ardent", {})
existing_env = existing.get("env", {}) if isinstance(existing, dict) else {}
updated_env = dict(existing_env)
if not any(
    updated_env.get(name)
    for name in ("ARDENT_API_KEY", "ARDENT_CLIENT_ID", "ARDENT_ACCESS_TOKEN")
):
    updated_env["ARDENT_API_KEY"] = "your_api_key_here"

config["ardent"] = {
    "command": "python3",
    "args": [mcp_script],
    "env": updated_env
}

config_path.parent.mkdir(parents=True, exist_ok=True)
config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
print("  ✅ ChatGPT Desktop config updated.")
print("  ⚠️  Set your real API key in:", config_path)
PYEOF
else
  echo "ChatGPT Desktop not detected — skipping."
fi

# ── Cursor ───────────────────────────────────────────────────────────────────
CURSOR_CONFIG_DIR="${HOME}/.cursor"
if [[ -d "${CURSOR_CONFIG_DIR}" ]]; then
  echo "Detected Cursor — patching MCP config..."
  patch_mcp_servers_config \
    "${CURSOR_CONFIG_DIR}/mcp.json" \
    "${RUNTIME_DIR}/mcp_server.py" \
    "Cursor"
else
  echo "Cursor not detected — skipping."
fi

# ── Windsurf ─────────────────────────────────────────────────────────────────
WINDSURF_CONFIG_DIR="${HOME}/.codeium/windsurf"
if [[ -d "${WINDSURF_CONFIG_DIR}" ]]; then
  echo "Detected Windsurf — patching MCP config..."
  patch_mcp_servers_config \
    "${WINDSURF_CONFIG_DIR}/mcp_config.json" \
    "${RUNTIME_DIR}/mcp_server.py" \
    "Windsurf"
else
  echo "Windsurf not detected — skipping."
fi

echo
echo "✅ Install complete"
echo "CLI path: ${INSTALL_DIR}/ardent"
echo "Runtime files: ${RUNTIME_DIR}"
echo
echo "Next steps:"
echo "  1. Replace 'your_api_key_here' with your real key in any config files updated above"
echo "  2. Fully quit and reopen any patched apps (Cmd+Q) — Codex, Claude, ChatGPT, Cursor, Windsurf"
echo "  3. Restart your terminal, or run: export PATH=\"${INSTALL_DIR}:\${PATH}\""
echo "  4. Look for the tools icon/list in your AI app to confirm Ardent is loaded"
echo
echo "Or use the CLI directly:"
echo "  export ARDENT_API_KEY=\"your_api_key\""
echo "  ${INSTALL_DIR}/ardent health"
echo
echo "If 'ardent' is not found, add ${INSTALL_DIR} to PATH:"
echo "  export PATH=\"${INSTALL_DIR}:${PATH}\""
