#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/orchestrator_env.sh"

EVENT_TYPE="${1:?usage: emit_runtime_event.sh <event_type> <phase> <task_name> <agent_name> <summary>}"
PHASE="${2:?usage: emit_runtime_event.sh <event_type> <phase> <task_name> <agent_name> <summary>}"
TASK_NAME="${3:?usage: emit_runtime_event.sh <event_type> <phase> <task_name> <agent_name> <summary>}"
AGENT_NAME="${4:?usage: emit_runtime_event.sh <event_type> <phase> <task_name> <agent_name> <summary>}"
SUMMARY="${5:?usage: emit_runtime_event.sh <event_type> <phase> <task_name> <agent_name> <summary>}"

load_orchestrator_env "${ENGAGEMENT_DIR:-}" || true

ENGAGEMENT_KEY="$(current_engagement_key "${ENGAGEMENT_DIR:-}")"

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" || -z "$ENGAGEMENT_KEY" ]]; then
    exit 0
fi

payload="$(python3 - <<'PY' "$EVENT_TYPE" "$PHASE" "$TASK_NAME" "$AGENT_NAME" "$SUMMARY"
import json
import sys

event_type, phase, task_name, agent_name, summary = sys.argv[1:]
print(json.dumps({
    "event_type": event_type,
    "phase": phase,
    "task_name": task_name,
    "agent_name": agent_name,
    "summary": summary,
}, ensure_ascii=True))
PY
)"

(
  curl -fsS \
    --connect-timeout 1 \
    --max-time 2 \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$payload" \
    "${ORCHESTRATOR_BASE_URL%/}/engagements/${ENGAGEMENT_KEY}/events" >/dev/null || {
      printf 'warning: failed to emit runtime event %s\n' "$EVENT_TYPE" >&2
      exit 0
    }
) >/dev/null 2>&1 &
