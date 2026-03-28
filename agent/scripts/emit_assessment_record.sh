#!/usr/bin/env bash
set -euo pipefail

ENDPOINT="${1:?usage: emit_assessment_record.sh <endpoint> <json-payload>}"
PAYLOAD="${2:?usage: emit_assessment_record.sh <endpoint> <json-payload>}"

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" || -z "${ORCHESTRATOR_TOKEN:-}" || -z "${ORCHESTRATOR_PROJECT_ID:-}" || -z "${ORCHESTRATOR_RUN_ID:-}" ]]; then
    exit 0
fi

(
  curl -fsS \
    --connect-timeout 1 \
    --max-time 3 \
    -H "Authorization: Bearer ${ORCHESTRATOR_TOKEN}" \
    -H "Content-Type: application/json" \
    -X POST \
    --data "$PAYLOAD" \
    "${ORCHESTRATOR_BASE_URL%/}/projects/${ORCHESTRATOR_PROJECT_ID}/runs/${ORCHESTRATOR_RUN_ID}/assessment/${ENDPOINT}" >/dev/null || {
      printf 'warning: failed to emit assessment record to %s\n' "$ENDPOINT" >&2
      exit 0
    }
) >/dev/null 2>&1 &
