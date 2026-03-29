#!/usr/bin/env bash
set -euo pipefail

ENDPOINT="${1:?usage: fetch_assessment_record.sh <endpoint>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/orchestrator_env.sh"

load_orchestrator_env "${ENGAGEMENT_DIR:-}" || true

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" || -z "${ORCHESTRATOR_TOKEN:-}" || -z "${ORCHESTRATOR_PROJECT_ID:-}" || -z "${ORCHESTRATOR_RUN_ID:-}" ]]; then
    echo "fetch_assessment_record.sh: orchestrator runtime variables are required" >&2
    exit 1
fi

curl -fsS \
    --connect-timeout 2 \
    --max-time 10 \
    -H "Authorization: Bearer ${ORCHESTRATOR_TOKEN}" \
    "${ORCHESTRATOR_BASE_URL%/}/projects/${ORCHESTRATOR_PROJECT_ID}/runs/${ORCHESTRATOR_RUN_ID}/assessment/${ENDPOINT}"
