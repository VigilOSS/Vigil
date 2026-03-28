#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

AUTO_MODE=0
PARALLELISM=3
TARGET=""
SCOPE_MODE=""
SCOPE_HOSTS_RAW=""
OUT_OF_SCOPE_RAW=""
SCAN_INTENSITY=""
AUTH_MODE=""
EXPLOIT_POLICY=""
ENGAGEMENT_NAME=""

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
  --auto
  --parallel N
  --scope-mode host_only|explicit_hosts|wildcard
  --scope-hosts host1,host2,...
  --out-of-scope-hosts host1,host2,...
  --scan-intensity stealth|normal|aggressive
  --auth-mode none|auth_json|manual
  --exploit-policy pause|full_send|selected
  --engagement-name LABEL

Examples:
  ./scripts/init_engagement.sh https://example.com
  ./scripts/init_engagement.sh app.example.com --scope-mode host_only --scan-intensity normal --auth-mode none --exploit-policy pause --engagement-name app-review
  ./scripts/init_engagement.sh https://api.example.com --scope-mode explicit_hosts --scope-hosts api.example.com,admin.example.com --scan-intensity aggressive --auth-mode auth_json --exploit-policy selected --engagement-name api-deep-dive
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
    --auto)
      AUTO_MODE=1
      shift
      ;;
    --parallel)
      PARALLELISM="${2:-}"
      [[ -n "$PARALLELISM" ]] || { echo "--parallel requires a value" >&2; exit 1; }
      shift 2
      ;;
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
    --scan-intensity)
      SCAN_INTENSITY="${2:-}"
      [[ -n "$SCAN_INTENSITY" ]] || { echo "--scan-intensity requires a value" >&2; exit 1; }
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
    --engagement-name)
      ENGAGEMENT_NAME="${2:-}"
      [[ -n "$ENGAGEMENT_NAME" ]] || { echo "--engagement-name requires a value" >&2; exit 1; }
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

if ! [[ "$PARALLELISM" =~ ^[0-9]+$ ]] || [[ "$PARALLELISM" -lt 1 ]]; then
  echo "--parallel must be a positive integer" >&2
  exit 1
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

if [[ -z "$SCAN_INTENSITY" ]]; then
  if [[ -t 0 ]]; then
    SCAN_INTENSITY="$(prompt_choice "Scan intensity" "normal" "stealth" "normal" "aggressive")"
  else
    SCAN_INTENSITY="normal"
  fi
fi
case "$SCAN_INTENSITY" in
  stealth|normal|aggressive) ;;
  *)
    echo "--scan-intensity must be one of: stealth, normal, aggressive" >&2
    exit 1
    ;;
esac

if [[ -z "$AUTH_MODE" ]]; then
  if [[ -t 0 ]]; then
    AUTH_MODE="$(prompt_choice "Auth mode" "none" "none" "auth_json" "manual")"
  else
    AUTH_MODE="none"
  fi
fi
case "$AUTH_MODE" in
  none|auth_json|manual) ;;
  *)
    echo "--auth-mode must be one of: none, auth_json, manual" >&2
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

PORT=$(
  TARGET="$TARGET_NORMALIZED" python3 - <<'PY'
import os
from urllib.parse import urlparse

target = os.environ["TARGET"]
parsed = urlparse(target)
if parsed.port:
    print(parsed.port)
elif parsed.scheme == "http":
    print(80)
else:
    print(443)
PY
)

if [[ -z "$OUT_OF_SCOPE_RAW" && -t 0 ]]; then
  OUT_OF_SCOPE_RAW="$(prompt_text "Optional comma-separated out-of-scope hosts" "")"
fi

DATE=$(date +%Y-%m-%d)
TIME=$(date +%H%M%S)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CONFIRM_MODE="auto"
if [[ "$AUTO_MODE" -eq 0 ]]; then
  CONFIRM_MODE="manual"
fi

DEFAULT_ENGAGEMENT_NAME="$(printf '%s-%s' "$HOSTNAME_RAW" "$DATE" | tr '.:' '-' | tr -cd '[:alnum:]-')"
if [[ -z "$ENGAGEMENT_NAME" ]]; then
  if [[ -t 0 ]]; then
    ENGAGEMENT_NAME="$(prompt_text "Engagement name" "$DEFAULT_ENGAGEMENT_NAME")"
  else
    ENGAGEMENT_NAME="$DEFAULT_ENGAGEMENT_NAME"
  fi
fi

HOSTNAME_CLEAN=$(printf '%s' "$HOSTNAME_RAW" | tr '.:' '-' | tr -cd '[:alnum:]-')
DIR="$ROOT_DIR/engagements/${DATE}-${TIME}-${HOSTNAME_CLEAN}"
mkdir -p "$DIR/tools" "$DIR/downloads" "$DIR/scans" "$DIR/pids" "$DIR/sessions"
printf '%s\n' "$DIR" > engagements/.active

SCOPE_HOSTS_JSON="$(derive_scope_hosts_json "$HOSTNAME_RAW" "$SCOPE_MODE" "$SCOPE_HOSTS_RAW")"
OUT_OF_SCOPE_JSON="$(csv_to_json_array "$OUT_OF_SCOPE_RAW")"

cat > "$DIR/scope.json" <<EOF
{
  "target": "${TARGET_NORMALIZED}",
  "hostname": "${HOSTNAME_RAW}",
  "port": ${PORT},
  "scope_mode": "${SCOPE_MODE}",
  "scope_hosts": ${SCOPE_HOSTS_JSON},
  "scope": ${SCOPE_HOSTS_JSON},
  "out_of_scope_hosts": ${OUT_OF_SCOPE_JSON},
  "scan_intensity": "${SCAN_INTENSITY}",
  "auth_mode": "${AUTH_MODE}",
  "exploit_policy": "${EXPLOIT_POLICY}",
  "exploit_review_state": "pending",
  "approved_findings": [],
  "engagement_name": "${ENGAGEMENT_NAME}",
  "status": "in_progress",
  "start_time": "${START_TIME}",
  "phases_completed": [],
  "current_phase": "recon",
  "confirm_mode": "${CONFIRM_MODE}",
  "parallelism": ${PARALLELISM}
}
EOF

cat > "$DIR/log.md" <<EOF
# Engagement Log

- **Target**: ${TARGET_NORMALIZED}
- **Engagement Name**: ${ENGAGEMENT_NAME}
- **Date**: ${DATE}
- **Status**: In Progress
- **Scope Mode**: ${SCOPE_MODE}
- **Scan Intensity**: ${SCAN_INTENSITY}
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
printf '{}\n' > "$DIR/auth.json"
printf '[]\n' > "$DIR/sessions/index.json"

sqlite3 "$DIR/cases.db" < "$SCRIPT_DIR/schema.sql" >/dev/null

if [[ -f "$SCRIPT_DIR/templates/intel.md" ]]; then
  cp "$SCRIPT_DIR/templates/intel.md" "$DIR/intel.md"
else
  printf '# Intelligence Collection\n' > "$DIR/intel.md"
fi

printf '%s\n' "$DIR"
