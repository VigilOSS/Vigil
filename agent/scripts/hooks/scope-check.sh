#!/bin/bash
# scope-check.sh — Claude Code PreToolUse hook
# Reads hook JSON from stdin and blocks host-side target-facing commands.
# In-scope target work must go through the Kali MCP session rather than Bash.
# Hook format: {"tool_name":"Bash","tool_input":{"command":"..."}}
#
# Exit codes: 0 = allow, 2 = block

# No set -e: grep returning no matches (exit 1) is expected, not an error.

INPUT=$(cat)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/engagement.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/scope.sh"

# Only check Bash tool calls
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)
[ "$TOOL_NAME" != "Bash" ] && exit 0

# Extract command
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -z "$COMMAND" ] && exit 0

# Block common target-facing host-side execution paths even if the target is indirect
# via environment variables, scope.json, or helper scripts.
if printf '%s\n' "$COMMAND" | grep -Eq '(^|[[:space:];|&(])((/usr/bin/)?curl|nmap|ffuf|wfuzz|gobuster|dirb|sqlmap|nikto|whatweb|hydra|katana|arjun|subfinder|httpx|nc|netcat|msfconsole|msfrpcd)([[:space:]]|$)'; then
  echo "BLOCKED: Host-side target-facing tool execution is not allowed. Use the attached Kali MCP tools for in-scope work." >&2
  exit 2
fi

case "$COMMAND" in
  *run_tool*|*rtcurl*|*container.sh*|*katana_ingest.sh*|*check_metasploit_runtime.sh*)
    echo "BLOCKED: Deprecated host-side execution helper detected. Use the attached Kali MCP tools for in-scope work." >&2
    exit 2
    ;;
esac

# Skip local-only commands (no network traffic)
# Match first token of command (handles VAR=val && cmd, compound commands)
FIRST_TOKEN=$(echo "$COMMAND" | grep -oE '^[A-Za-z_][A-Za-z0-9_]*' 2>/dev/null || true)
case "$FIRST_TOKEN" in
  cat|ls|git|echo|test|mkdir|cp|mv|rm|jq|sqlite3|grep|sed|awk|sort|head|tail|chmod|source|export|read|DIR|ENG*|DB|DATE|TIME|HOSTNAME*|TARGET|PATH|PARENT*|BATCH*)
    exit 0 ;;
esac

# Also skip by first non-variable command in compound statements
case "$COMMAND" in
  *dispatcher.sh*|*assess.py*|*schema.sql*) exit 0 ;;
  *"cat "*|*"mkdir "*|*"jq "*|*"sqlite3 "*|*"grep "*|*"sed "*) exit 0 ;;
esac

# Find active engagement directory
ENG_DIR=$(resolve_engagement_dir "$(pwd)" || true)
HOST_LIST=()
while IFS= read -r host; do
  [ -n "$host" ] && HOST_LIST+=("$host")
done < <(extract_command_hosts "$COMMAND")
[ "${#HOST_LIST[@]}" -eq 0 ] && exit 0

if [ -z "$ENG_DIR" ] || [ ! -f "$ENG_DIR/scope.json" ]; then
  echo "BLOCKED: Scope metadata is missing; cannot validate host targets safely." >&2
  exit 2
fi

# Extract allowed scope entries
SCOPE_LIST=()
while IFS= read -r scope_entry; do
  [ -n "$scope_entry" ] && SCOPE_LIST+=("$scope_entry")
done < <(scope_entries "$ENG_DIR")
[ "${#SCOPE_LIST[@]}" -eq 0 ] && {
  echo "BLOCKED: Scope metadata is empty; cannot validate host targets safely." >&2
  exit 2
}

OUT_OF_SCOPE_LIST=()
while IFS= read -r scope_entry; do
  [ -n "$scope_entry" ] && OUT_OF_SCOPE_LIST+=("$scope_entry")
done < <(out_of_scope_entries "$ENG_DIR")

# Check each host against scope
for HOST in "${HOST_LIST[@]}"; do
  AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // "operator"' 2>/dev/null || echo "unknown")
  if [ "${#OUT_OF_SCOPE_LIST[@]}" -gt 0 ] && host_in_scope "$HOST" "${OUT_OF_SCOPE_LIST[@]}"; then
    echo "BLOCKED: Host '$HOST' is explicitly out of scope. (agent: $AGENT_TYPE)" >&2
    echo "Allowed scope: ${SCOPE_LIST[*]}" >&2
    exit 2
  fi
  if host_in_scope "$HOST" "${SCOPE_LIST[@]}"; then
    echo "BLOCKED: Host-side Bash command targets in-scope host '$HOST'. Use the attached Kali MCP tools instead. (agent: $AGENT_TYPE)" >&2
    exit 2
  fi

  echo "BLOCKED: Host '$HOST' is not in scope. (agent: $AGENT_TYPE)" >&2
  echo "Allowed scope: ${SCOPE_LIST[*]}" >&2
  exit 2
done

exit 0
