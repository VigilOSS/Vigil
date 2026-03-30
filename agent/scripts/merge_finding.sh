#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"
EMIT_RUNTIME_EVENT="$SCRIPT_DIR/emit_runtime_event.sh"

ENG_DIR="${1:?usage: merge_finding.sh <engagement_dir> <source_slug> <target_slug> <reason>}"
SOURCE_SLUG="${2:?usage: merge_finding.sh <engagement_dir> <source_slug> <target_slug> <reason>}"
TARGET_SLUG="${3:?usage: merge_finding.sh <engagement_dir> <source_slug> <target_slug> <reason>}"
REASON="${4:?usage: merge_finding.sh <engagement_dir> <source_slug> <target_slug> <reason>}"
export ENGAGEMENT_DIR="$ENG_DIR"

[[ -f "$POST_ASSESSMENT_RECORD" ]] || { echo "post_assessment_record.sh not found" >&2; exit 1; }

payload="$(python3 - <<'PY' "$SOURCE_SLUG" "$TARGET_SLUG" "$REASON"
import json, sys
source_slug, target_slug, reason = sys.argv[1:]
print(json.dumps({
    "source_slug": source_slug,
    "target_slug": target_slug,
    "reason": reason,
    "source_name": "operator",
}, ensure_ascii=True))
PY
)"

response="$(bash "$POST_ASSESSMENT_RECORD" "findings/merge" "$payload")"

if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
    bash "$EMIT_RUNTIME_EVENT" \
        "finding.merged" \
        "${ORCHESTRATOR_PHASE:-unknown}" \
        "$SOURCE_SLUG" \
        "operator" \
        "Merged $SOURCE_SLUG into $TARGET_SLUG: $REASON" 2>/dev/null || true
fi

printf 'Merged %s into %s\n' "$SOURCE_SLUG" "$TARGET_SLUG"
