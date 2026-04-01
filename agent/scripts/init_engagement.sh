#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/auth.sh"

TARGET=""
HOSTS_RAW=""
AUTH_MODE=""
EXPLOIT_POLICY=""

normalize_target() {
  local raw="$1"
  if [[ "$raw" == *"://"* ]]; then
    printf '%s\n' "$raw"
  else
    printf 'https://%s\n' "$raw"
  fi
}

usage() {
  cat <<'EOF'
Usage: ./scripts/init_engagement.sh [target-url-or-host] [options]

The positional target is optional when --hosts is provided; the first
host becomes the target automatically.

Options:
  --hosts host1,host2,*.domain,...   Scope list. Use *.domain for subdomain enum.
  --auth-mode none|auth_json|manual|proxy_capture
  --exploit-policy pause|full_send|selected

Any host NOT in --hosts is out of scope. Wildcard entries (*.example.com) enable
subdomain enumeration and allow discovered subdomains of that domain in scope.

Examples:
  # Single host
  ./scripts/init_engagement.sh https://example.com

  # Multiple hosts — only these are in scope
  ./scripts/init_engagement.sh --hosts app.example.com,api.example.com,admin.example.com

  # Multiple hosts with subdomain enum on one domain
  ./scripts/init_engagement.sh --hosts app.example.com,*.api.example.com,other.com

  # Single host with subdomain enum
  ./scripts/init_engagement.sh --hosts example.com,*.example.com
EOF
}

prompt_choice() {
  local prompt="${1:?prompt required}"
  local default_value="${2:-}"
  shift
  shift
  local options=("$@")
  local choice

  while true; do
    printf '%s\n' "$prompt" >&2
    local i=1
    for option in "${options[@]}"; do
      if [[ -n "$default_value" && "$option" == "$default_value" ]]; then
        printf '  %s. %s [default]\n' "$i" "$option" >&2
      else
        printf '  %s. %s\n' "$i" "$option" >&2
      fi
      i=$((i + 1))
    done
    printf '> ' >&2
    read -r choice
    if [[ -z "$choice" && -n "$default_value" ]]; then
      printf '%s\n' "$default_value"
      return 0
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
      printf '%s\n' "${options[$((choice - 1))]}"
      return 0
    fi
    printf 'Invalid selection. Enter a number from the list.\n' >&2
  done
}

prompt_text() {
  local prompt="${1:?prompt required}"
  local default_value="${2:-}"
  local value

  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  read -r value
  if [[ -z "$value" && -n "$default_value" ]]; then
    value="$default_value"
  fi
  printf '%s\n' "$value"
}

csv_to_json_array() {
  local raw="${1:-}"
  python3 - <<'PY' "$raw"
import json
import sys

raw = sys.argv[1]
items = []
for part in raw.split(","):
    item = part.strip()
    if item:
        items.append(item)
print(json.dumps(items, ensure_ascii=True))
PY
}

default_orchestrator_base_url() {
  printf '%s\n' "http://127.0.0.1:18000"
}

install_client_kind() {
  local has_codex=0
  local has_claude=0

  [[ -f "$ROOT_DIR/AGENTS.md" && -d "$ROOT_DIR/.codex" ]] && has_codex=1
  [[ -f "$ROOT_DIR/CLAUDE.md" && -d "$ROOT_DIR/.claude" ]] && has_claude=1

  case "${AI_THREAT_HUNTING_CLIENT:-}" in
    codex|claude)
      printf '%s\n' "$AI_THREAT_HUNTING_CLIENT"
      return 0
      ;;
  esac

  if [[ "$has_codex" -eq 1 && "$has_claude" -eq 0 ]]; then
    printf '%s\n' "codex"
  elif [[ "$has_codex" -eq 0 && "$has_claude" -eq 1 ]]; then
    printf '%s\n' "claude"
  else
    printf '%s\n' "both"
  fi
}

write_engagement_prompt_wrappers() {
  local eng_dir="${1:?engagement dir required}"
  local client_kind="${2:?client kind required}"

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/AGENTS.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/AGENTS.md

This engagement directory is only the run-artifact root. When you start Codex here, use these workspace locations before concluding that a prompt, agent, rule, skill, reference, or script is unavailable:
- Install root: ${ROOT_DIR}/..
- Agent workspace root: ${ROOT_DIR}
- Operator prompt: ${ROOT_DIR}/AGENTS.md
- Specialist wrappers: ${ROOT_DIR}/.codex/agents
- Specialist prompt sources: ${ROOT_DIR}/agents
- Always-active rules: ${ROOT_DIR}/rules
- Skill index: ${ROOT_DIR}/SKILL.md
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts

Artifact sync:
- Use ${ROOT_DIR}/scripts/assess.py for all assessment operations (record-finding, record-surface, fetch, post, etc.)
- When a shared prompt references \`./scripts/...\`, resolve it against ${ROOT_DIR}/scripts from this engagement session
- Start Codex for this engagement with ${eng_dir}/start_codex.sh so ENGAGEMENT_DIR is exported automatically
- The local ${eng_dir}/.orchestrator.env provides the default orchestrator base URL for backend-sync scripts; install-root .env can override it
EOF
  fi

  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/CLAUDE.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/CLAUDE.md

This engagement directory is only the run-artifact root. When you start Claude here, use these workspace locations before concluding that a prompt, agent, rule, skill, reference, or script is unavailable:
- Install root: ${ROOT_DIR}/..
- Agent workspace root: ${ROOT_DIR}
- Operator prompt: ${ROOT_DIR}/CLAUDE.md
- Specialist wrappers: ${ROOT_DIR}/.claude/agents
- Specialist prompt sources: ${ROOT_DIR}/agents
- Always-active rules: ${ROOT_DIR}/rules
- Skill index: ${ROOT_DIR}/SKILL.md
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts

Artifact sync:
- Use ${ROOT_DIR}/scripts/assess.py for all assessment operations (record-finding, record-surface, fetch, post, etc.)
- When a shared prompt references \`./scripts/...\`, resolve it against ${ROOT_DIR}/scripts from this engagement session
- Start Claude for this engagement with ${eng_dir}/start_claude.sh so ENGAGEMENT_DIR is exported automatically
- The local ${eng_dir}/.orchestrator.env provides the default orchestrator base URL for backend-sync scripts; install-root .env can override it
EOF
  fi
}

write_engagement_launchers() {
  local eng_dir="${1:?engagement dir required}"
  local client_kind="${2:?client kind required}"

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/start_codex.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENGAGEMENT_DIR
AGENT_ROOT="$(cd "$ENGAGEMENT_DIR/../.." && pwd)"

exec codex "$@"
EOF
  fi

  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/start_claude.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENGAGEMENT_DIR
AGENT_ROOT="$(cd "$ENGAGEMENT_DIR/../.." && pwd)"

exec claude "$@"
EOF
  fi

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    chmod +x "$eng_dir/start_codex.sh"
  fi
  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    chmod +x "$eng_dir/start_claude.sh"
  fi
}

require_interactive_or_die() {
  local missing_label="${1:?missing label required}"
  if [[ -t 0 ]]; then
    return 0
  fi
  echo "Missing required value for ${missing_label}. Re-run with flags or use an interactive TTY." >&2
  usage >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --hosts)
      HOSTS_RAW="${2:-}"
      [[ -n "$HOSTS_RAW" ]] || { echo "--hosts requires a value" >&2; exit 1; }
      shift 2
      ;;
    --auth-mode)
      AUTH_MODE="${2:-}"
      [[ -n "$AUTH_MODE" ]] || { echo "--auth-mode requires a value" >&2; exit 1; }
      shift 2
      ;;
    --exploit-policy)
      EXPLOIT_POLICY="${2:-}"
      [[ -n "$EXPLOIT_POLICY" ]] || { echo "--exploit-policy requires a value" >&2; exit 1; }
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "Only one target may be provided" >&2
        exit 1
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

# Derive target from --hosts when no positional target given
if [[ -z "$TARGET" && -n "$HOSTS_RAW" ]]; then
  # Use the first non-wildcard host, falling back to first host with *. stripped
  TARGET=$(python3 - <<'PY' "$HOSTS_RAW"
import sys
raw = sys.argv[1]
hosts = [h.strip() for h in raw.split(",") if h.strip()]
non_wild = [h for h in hosts if not h.startswith("*.")]
print(non_wild[0] if non_wild else hosts[0].removeprefix("*.") if hosts else "")
PY
  )
fi

if [[ -z "$TARGET" ]]; then
  require_interactive_or_die "target"
  TARGET="$(prompt_text "Target URL or host")"
fi

if [[ -z "$AUTH_MODE" ]]; then
  if [[ -t 0 ]]; then
    AUTH_MODE="$(prompt_choice "Auth mode" "none" "none" "auth_json" "manual" "proxy_capture")"
  else
    AUTH_MODE="none"
  fi
fi
case "$AUTH_MODE" in
  none|auth_json|manual|proxy_capture) ;;
  *)
    echo "--auth-mode must be one of: none, auth_json, manual, proxy_capture" >&2
    exit 1
    ;;
esac

if [[ -z "$EXPLOIT_POLICY" ]]; then
  if [[ -t 0 ]]; then
    EXPLOIT_POLICY="$(prompt_choice "Exploit policy" "pause" "pause" "full_send" "selected")"
  else
    EXPLOIT_POLICY="pause"
  fi
fi
case "$EXPLOIT_POLICY" in
  pause|full_send|selected) ;;
  *)
    echo "--exploit-policy must be one of: pause, full_send, selected" >&2
    exit 1
    ;;
esac

cd "$ROOT_DIR"
mkdir -p engagements

TARGET_NORMALIZED=$(normalize_target "$TARGET")

HOSTNAME_RAW=$(
  TARGET="$TARGET_NORMALIZED" python3 - <<'PY'
import os
from urllib.parse import urlparse

target = os.environ["TARGET"]
parsed = urlparse(target)
print(parsed.hostname or target)
PY
)

# If no --hosts given, the parsed hostname is the sole host
if [[ -z "$HOSTS_RAW" ]]; then
  HOSTS_RAW="$HOSTNAME_RAW"
fi

DATE=$(date +%Y-%m-%d)
TIME=$(date +%H%M%S)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

HOSTNAME_CLEAN=$(printf '%s' "$HOSTNAME_RAW" | tr '.:' '-' | tr -cd '[:alnum:]-')
DIR="$ROOT_DIR/engagements/${DATE}-${TIME}-${HOSTNAME_CLEAN}"
ENGAGEMENT_KEY="$(basename "$DIR")"
mkdir -p "$DIR/tools" "$DIR/downloads" "$DIR/scans" "$DIR/pids" "$DIR/sessions"

HOSTS_JSON="$(csv_to_json_array "$HOSTS_RAW")"

cat > "$DIR/scope.json" <<EOF
{
  "hostname": "${HOSTNAME_RAW}",
  "hosts": ${HOSTS_JSON},
  "exploit_policy": "${EXPLOIT_POLICY}",
  "exploit_review_state": "pending",
  "approved_findings": [],
  "status": "in_progress",
  "current_phase": "recon"
}
EOF

cat > "$DIR/log.md" <<EOF
# Engagement Log

- **Target**: ${TARGET_NORMALIZED}
- **Date**: ${DATE}
- **Status**: In Progress
- **Hosts**: $(printf '%s' "$HOSTS_RAW" | tr ',' ', ')
- **Auth Mode**: ${AUTH_MODE}
- **Exploit Policy**: ${EXPLOIT_POLICY}

---
EOF

cat > "$DIR/findings.md" <<EOF
# Findings

- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Finding Count**: 0

---
EOF

cat > "$DIR/report.md" <<EOF
# Engagement Report

- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Status**: Pending — report not yet generated

---
EOF

: > "$DIR/surfaces.jsonl"
write_auth_scaffold "$DIR" "$AUTH_MODE" "$START_TIME"
printf '[]\n' > "$DIR/sessions/index.json"
printf '[]\n' > "$DIR/agent-registry.json"

cat > "$DIR/engagement.json" <<EOF
{
  "key": "${ENGAGEMENT_KEY}",
  "target": "${TARGET_NORMALIZED}",
  "hostname": "${HOSTNAME_RAW}",
  "created_at": "${START_TIME}"
}
EOF

printf 'ORCHESTRATOR_BASE_URL=%q\n' "$(default_orchestrator_base_url)" > "$DIR/.orchestrator.env"

sqlite3 "$DIR/cases.db" < "$SCRIPT_DIR/schema.sql" >/dev/null

if [[ -f "$SCRIPT_DIR/templates/intel.md" ]]; then
  cp "$SCRIPT_DIR/templates/intel.md" "$DIR/intel.md"
else
  printf '# Intelligence Collection\n' > "$DIR/intel.md"
fi

CLIENT_KIND="$(install_client_kind)"
write_engagement_prompt_wrappers "$DIR" "$CLIENT_KIND"
write_engagement_launchers "$DIR" "$CLIENT_KIND"

printf '%s\n' "$DIR"
