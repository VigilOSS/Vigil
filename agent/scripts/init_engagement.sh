#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/auth.sh"

TARGET=""
SCOPE_MODE=""
SCOPE_HOSTS_RAW=""
OUT_OF_SCOPE_RAW=""
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
Usage: ./scripts/init_engagement.sh <target-url-or-host> [options]

Options:
  --scope-mode host_only|explicit_hosts|wildcard
  --scope-hosts host1,host2,...
  --out-of-scope-hosts host1,host2,...
  --auth-mode none|auth_json|manual|proxy_capture
  --exploit-policy pause|full_send|selected

Examples:
  ./scripts/init_engagement.sh https://example.com
  ./scripts/init_engagement.sh app.example.com --scope-mode host_only --auth-mode none --exploit-policy pause
  ./scripts/init_engagement.sh https://api.example.com --scope-mode explicit_hosts --scope-hosts api.example.com,admin.example.com --auth-mode proxy_capture --exploit-policy selected
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

write_engagement_prompt_wrappers() {
  local eng_dir="${1:?engagement dir required}"
  cat > "$eng_dir/AGENTS.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/AGENTS.md

This engagement directory is only the run-artifact root. When you start Codex here, use these workspace locations before concluding that a skill, reference, or script is unavailable:
- Workspace root: ${ROOT_DIR}
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts
- Operator wrapper: ${ROOT_DIR}/.codex/agents/operator.toml

Artifact sync:
- Use ${ROOT_DIR}/scripts/record_finding.sh and ${ROOT_DIR}/scripts/append_surface.sh
- If ${eng_dir}/.orchestrator.env exists and ORCHESTRATOR_* is unset, load it before backend-sync scripts or let the scripts auto-load it
EOF

  cat > "$eng_dir/CLAUDE.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/CLAUDE.md

This engagement directory is only the run-artifact root. When you start Claude here, use these workspace locations before concluding that a skill, reference, or script is unavailable:
- Workspace root: ${ROOT_DIR}
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts
- Operator wrapper: ${ROOT_DIR}/.claude/agents/operator.md

Artifact sync:
- Use ${ROOT_DIR}/scripts/record_finding.sh and ${ROOT_DIR}/scripts/append_surface.sh
- If ${eng_dir}/.orchestrator.env exists and ORCHESTRATOR_* is unset, load it before backend-sync scripts or let the scripts auto-load it
EOF
}

derive_scope_hosts_json() {
  local hostname="${1:?hostname required}"
  local scope_mode="${2:?scope_mode required}"
  local explicit_hosts_raw="${3:-}"
  python3 - <<'PY' "$hostname" "$scope_mode" "$explicit_hosts_raw"
import json
import sys

hostname, scope_mode, explicit_hosts_raw = sys.argv[1:]
hosts = []
if scope_mode == "host_only":
    hosts = [hostname]
elif scope_mode == "wildcard":
    hosts = [hostname, f"*.{hostname}"]
elif scope_mode == "explicit_hosts":
    for part in explicit_hosts_raw.split(","):
        item = part.strip()
        if item:
            hosts.append(item)
    if hostname not in hosts:
        hosts.insert(0, hostname)
else:
    raise SystemExit(f"unsupported scope mode: {scope_mode}")

deduped = []
seen = set()
for host in hosts:
    lowered = host.lower()
    if lowered not in seen:
        seen.add(lowered)
        deduped.append(host)
print(json.dumps(deduped, ensure_ascii=True))
PY
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
    --scope-mode)
      SCOPE_MODE="${2:-}"
      [[ -n "$SCOPE_MODE" ]] || { echo "--scope-mode requires a value" >&2; exit 1; }
      shift 2
      ;;
    --scope-hosts)
      SCOPE_HOSTS_RAW="${2:-}"
      [[ -n "$SCOPE_HOSTS_RAW" ]] || { echo "--scope-hosts requires a value" >&2; exit 1; }
      shift 2
      ;;
    --out-of-scope-hosts)
      OUT_OF_SCOPE_RAW="${2:-}"
      [[ -n "${2:-}" ]] || { echo "--out-of-scope-hosts requires a value" >&2; exit 1; }
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

if [[ -z "$TARGET" ]]; then
  require_interactive_or_die "target"
  TARGET="$(prompt_text "Target URL or host")"
fi

if [[ -z "$SCOPE_MODE" ]]; then
  if [[ -t 0 ]]; then
    SCOPE_MODE="$(prompt_choice "Scope mode" "host_only" "host_only" "explicit_hosts" "wildcard")"
  else
    SCOPE_MODE="host_only"
  fi
fi
case "$SCOPE_MODE" in
  host_only|explicit_hosts|wildcard) ;;
  *)
    echo "--scope-mode must be one of: host_only, explicit_hosts, wildcard" >&2
    exit 1
    ;;
esac

if [[ "$SCOPE_MODE" == "explicit_hosts" && -z "$SCOPE_HOSTS_RAW" ]]; then
  require_interactive_or_die "scope hosts"
  SCOPE_HOSTS_RAW="$(prompt_text "Comma-separated in-scope hosts")"
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

if [[ -z "$OUT_OF_SCOPE_RAW" && -t 0 ]]; then
  OUT_OF_SCOPE_RAW="$(prompt_text "Optional comma-separated out-of-scope hosts" "")"
fi

DATE=$(date +%Y-%m-%d)
TIME=$(date +%H%M%S)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

HOSTNAME_CLEAN=$(printf '%s' "$HOSTNAME_RAW" | tr '.:' '-' | tr -cd '[:alnum:]-')
DIR="$ROOT_DIR/engagements/${DATE}-${TIME}-${HOSTNAME_CLEAN}"
mkdir -p "$DIR/tools" "$DIR/downloads" "$DIR/scans" "$DIR/pids" "$DIR/sessions"
printf '%s\n' "$DIR" > engagements/.active

SCOPE_HOSTS_JSON="$(derive_scope_hosts_json "$HOSTNAME_RAW" "$SCOPE_MODE" "$SCOPE_HOSTS_RAW")"
OUT_OF_SCOPE_JSON="$(csv_to_json_array "$OUT_OF_SCOPE_RAW")"

cat > "$DIR/scope.json" <<EOF
{
  "hostname": "${HOSTNAME_RAW}",
  "scope_mode": "${SCOPE_MODE}",
  "scope_hosts": ${SCOPE_HOSTS_JSON},
  "scope": ${SCOPE_HOSTS_JSON},
  "out_of_scope_hosts": ${OUT_OF_SCOPE_JSON},
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
- **Scope Mode**: ${SCOPE_MODE}
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

: > "$DIR/surfaces.jsonl"
printf '[]\n' > "$DIR/intel-secrets.json"
write_auth_scaffold "$DIR" "$AUTH_MODE" "$START_TIME"
printf '[]\n' > "$DIR/sessions/index.json"

if [[ -n "${ORCHESTRATOR_BASE_URL:-}" && -n "${ORCHESTRATOR_TOKEN:-}" && -n "${ORCHESTRATOR_PROJECT_ID:-}" && -n "${ORCHESTRATOR_RUN_ID:-}" ]]; then
  printf 'ORCHESTRATOR_BASE_URL=%q\n' "$ORCHESTRATOR_BASE_URL" > "$DIR/.orchestrator.env"
  printf 'ORCHESTRATOR_TOKEN=%q\n' "$ORCHESTRATOR_TOKEN" >> "$DIR/.orchestrator.env"
  printf 'ORCHESTRATOR_PROJECT_ID=%q\n' "$ORCHESTRATOR_PROJECT_ID" >> "$DIR/.orchestrator.env"
  printf 'ORCHESTRATOR_RUN_ID=%q\n' "$ORCHESTRATOR_RUN_ID" >> "$DIR/.orchestrator.env"
elif [[ -f "$ROOT_DIR/.orchestrator.env" ]]; then
  cp "$ROOT_DIR/.orchestrator.env" "$DIR/.orchestrator.env"
fi

sqlite3 "$DIR/cases.db" < "$SCRIPT_DIR/schema.sql" >/dev/null

if [[ -f "$SCRIPT_DIR/templates/intel.md" ]]; then
  cp "$SCRIPT_DIR/templates/intel.md" "$DIR/intel.md"
else
  printf '# Intelligence Collection\n' > "$DIR/intel.md"
fi

write_engagement_prompt_wrappers "$DIR"

printf '%s\n' "$DIR"
