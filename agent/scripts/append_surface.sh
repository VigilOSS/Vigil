#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/surfaces.sh"
EMIT_RUNTIME_EVENT="$SCRIPT_DIR/emit_runtime_event.sh"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"

ENG_DIR="${1:?usage: append_surface.sh <engagement_dir> <surface_type> <target> <source> <rationale> [evidence_ref] [status]}"
SURFACE_TYPE="${2:?usage: append_surface.sh <engagement_dir> <surface_type> <target> <source> <rationale> [evidence_ref] [status]}"
TARGET="${3:?usage: append_surface.sh <engagement_dir> <surface_type> <target> <source> <rationale> [evidence_ref] [status]}"
SOURCE_NAME="${4:?usage: append_surface.sh <engagement_dir> <surface_type> <target> <source> <rationale> [evidence_ref] [status]}"
RATIONALE="${5:-}"
EVIDENCE_REF="${6:-}"
STATUS="${7:-discovered}"
export ENGAGEMENT_DIR="$ENG_DIR"

payload="$(python3 - <<'PY' "$SURFACE_TYPE" "$TARGET" "$SOURCE_NAME" "$RATIONALE" "$EVIDENCE_REF" "$STATUS"
import json
import sys

surface_type, target_descriptor, source_name, rationale, evidence_ref, status_value = sys.argv[1:]
print(json.dumps({
    "surface_type": surface_type,
    "target_descriptor": target_descriptor,
    "source_name": source_name,
    "rationale": rationale,
    "evidence_ref": evidence_ref,
    "status": status_value,
}, ensure_ascii=True))
PY
)"

response="$(bash "$POST_ASSESSMENT_RECORD" "surfaces" "$payload")"
if ! printf '%s' "$response" | jq -e '.surface_type and .target_descriptor' >/dev/null 2>&1; then
    echo "append_surface.sh: orchestrator backend did not return a canonical surface record" >&2
    exit 1
fi

upsert_surface_record "$ENG_DIR" "$SURFACE_TYPE" "$TARGET" "$SOURCE_NAME" "$RATIONALE" "$EVIDENCE_REF" "$STATUS"

if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
    bash "$EMIT_RUNTIME_EVENT" \
        "surface.updated" \
        "${ORCHESTRATOR_PHASE:-unknown}" \
        "$SURFACE_TYPE" \
        "$SOURCE_NAME" \
        "${SURFACE_TYPE} ${STATUS}: ${TARGET}"
fi
