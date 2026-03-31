#!/usr/bin/env bash
set -euo pipefail

ENDPOINT="${1:?usage: post_assessment_record.sh <endpoint> <json-payload> [method]}"
PAYLOAD="${2:?usage: post_assessment_record.sh <endpoint> <json-payload> [method]}"
METHOD="${3:-POST}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/orchestrator_env.sh"

load_orchestrator_env "${ENGAGEMENT_DIR:-}" || true

ENGAGEMENT_KEY="$(current_engagement_key "${ENGAGEMENT_DIR:-}")"

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" || -z "$ENGAGEMENT_KEY" ]]; then
    exit 1
fi

curl -fsS \
    --connect-timeout 2 \
    --max-time 10 \
    -H "Content-Type: application/json" \
    -X "$METHOD" \
    --data "$PAYLOAD" \
    "${ORCHESTRATOR_BASE_URL%/}/engagements/${ENGAGEMENT_KEY}/assessment/${ENDPOINT}"
