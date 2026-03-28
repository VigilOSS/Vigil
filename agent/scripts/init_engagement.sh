#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

AUTO_MODE=0
PARALLELISM=3
TARGET=""

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
Usage: ./scripts/init_engagement.sh <target-url-or-host> [--auto] [--parallel N]

Examples:
  ./scripts/init_engagement.sh https://example.com
  ./scripts/init_engagement.sh example.com --auto
  ./scripts/init_engagement.sh http://127.0.0.1:8080 --parallel 6
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto)
      AUTO_MODE=1
      shift
      ;;
    --parallel)
      PARALLELISM="${2:-}"
      if [[ -z "$PARALLELISM" ]]; then
        echo "--parallel requires a value" >&2
        exit 1
      fi
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
  usage >&2
  exit 1
fi

if ! [[ "$PARALLELISM" =~ ^[0-9]+$ ]] || [[ "$PARALLELISM" -lt 1 ]]; then
  echo "--parallel must be a positive integer" >&2
  exit 1
fi

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

HOSTNAME_CLEAN=$(printf '%s' "$HOSTNAME_RAW" | tr '.:' '-' | tr -cd '[:alnum:]-')
DATE=$(date +%Y-%m-%d)
TIME=$(date +%H%M%S)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CONFIRM_MODE="auto"
if [[ "$AUTO_MODE" -eq 0 ]]; then
  CONFIRM_MODE="manual"
fi

DIR="engagements/${DATE}-${TIME}-${HOSTNAME_CLEAN}"
mkdir -p "$DIR/tools" "$DIR/downloads" "$DIR/scans" "$DIR/pids"
printf '%s\n' "$DIR" > engagements/.active

cat > "$DIR/scope.json" <<EOF
{
  "target": "${TARGET_NORMALIZED}",
  "hostname": "${HOSTNAME_RAW}",
  "port": ${PORT},
  "scope": ["${HOSTNAME_RAW}", "*.${HOSTNAME_RAW}"],
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
- **Date**: ${DATE}
- **Status**: In Progress

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

sqlite3 "$DIR/cases.db" < "$SCRIPT_DIR/schema.sql"

if [[ -f "$SCRIPT_DIR/templates/intel.md" ]]; then
  cp "$SCRIPT_DIR/templates/intel.md" "$DIR/intel.md"
else
  printf '# Intelligence Collection\n' > "$DIR/intel.md"
fi

awk '
  /^[[:space:]]*#/ { next }
  /^[[:space:]]*$/ { next }
  { lines[++count] = $0 }
  END {
    srand()
    if (count > 0) {
      print lines[int(rand() * count) + 1]
    }
  }
' "$SCRIPT_DIR/templates/user-agents.txt" > "$DIR/user-agent.txt"

printf '%s\n' "$DIR"
