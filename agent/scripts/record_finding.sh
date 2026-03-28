#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/findings.sh"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"
EMIT_RUNTIME_EVENT="$SCRIPT_DIR/emit_runtime_event.sh"
SCHEMA_FILE="$SCRIPT_DIR/../schemas/finding-record.schema.json"

ENG_DIR="${1:?usage: record_finding.sh <engagement_dir> <agent-name> <finding-json-file>}"
AGENT_NAME="${2:?usage: record_finding.sh <engagement_dir> <agent-name> <finding-json-file>}"
FINDING_JSON_FILE="${3:?usage: record_finding.sh <engagement_dir> <agent-name> <finding-json-file>}"
FINDINGS_FILE="$ENG_DIR/findings.md"

[[ -f "$FINDINGS_FILE" ]] || { echo "findings.md not found in $ENG_DIR" >&2; exit 1; }
[[ -f "$FINDING_JSON_FILE" ]] || { echo "finding json file not found: $FINDING_JSON_FILE" >&2; exit 1; }
[[ -f "$POST_ASSESSMENT_RECORD" ]] || { echo "post_assessment_record.sh not found" >&2; exit 1; }
[[ -f "$SCHEMA_FILE" ]] || { echo "finding schema not found: $SCHEMA_FILE" >&2; exit 1; }

python3 - <<'PY' "$FINDING_JSON_FILE" "$SCHEMA_FILE"
import json
import sys

payload_path, schema_path = sys.argv[1:]
payload = json.load(open(payload_path, "r", encoding="utf-8"))
schema = json.load(open(schema_path, "r", encoding="utf-8"))

if not isinstance(payload, dict):
    raise SystemExit("finding payload must be a JSON object")

required = schema.get("required", [])
properties = schema.get("properties", {})
missing = [key for key in required if key not in payload]
if missing:
    raise SystemExit(f"finding payload missing required fields: {', '.join(missing)}")

unknown = sorted(set(payload.keys()) - set(properties.keys()))
if unknown:
    raise SystemExit(f"finding payload has unsupported fields: {', '.join(unknown)}")
PY

lock_dir="$(acquire_finding_lock "$ENG_DIR")"
trap 'release_finding_lock "$lock_dir"' EXIT

candidate_slug="$(python3 - <<'PY' "$FINDING_JSON_FILE"
import json
import sys

payload = json.load(open(sys.argv[1], "r", encoding="utf-8"))
print(payload.get("slug", ""))
PY
)"
if [[ -z "$candidate_slug" ]]; then
    candidate_slug="$(next_finding_id "$ENG_DIR" "$AGENT_NAME")"
fi

payload="$(python3 - <<'PY' "$FINDING_JSON_FILE" "$candidate_slug" "$AGENT_NAME"
import json
import sys

path, slug, agent_name = sys.argv[1:]
payload = json.load(open(path, "r", encoding="utf-8"))
payload["slug"] = slug
payload.setdefault("source_name", agent_name)
payload.setdefault("severity", "medium")
payload.setdefault("status", "confirmed")
payload.setdefault("defect_family", payload.get("title", slug))
payload.setdefault("root_cause_key", "")
payload.setdefault("auth_context", "anonymous")
payload.setdefault("canonical_location", "")
payload.setdefault("summary", payload.get("title", slug))
payload.setdefault("evidence_ref", "")
payload.setdefault("notes", "")
details = payload.get("details") or {}
if not isinstance(details, dict):
    details = {}
details.setdefault("discovered_by", agent_name)
payload["details"] = details
provenance = payload.get("provenance") or {}
if not isinstance(provenance, dict):
    provenance = {}
provenance.setdefault("agent_name", agent_name)
provenance.setdefault("artifact", "findings.md")
payload["provenance"] = provenance
payload.setdefault("links", [])
print(json.dumps(payload, ensure_ascii=True))
PY
)"

response="$(bash "$POST_ASSESSMENT_RECORD" "findings" "$payload")"
if ! printf '%s' "$response" | jq -e '.finding.slug and .finding.title' >/dev/null 2>&1; then
    echo "record_finding.sh: orchestrator backend did not return a canonical finding record" >&2
    exit 1
fi
finding_slug="$(printf '%s' "$response" | jq -r '.finding.slug')"

python3 - <<'PY' "$FINDINGS_FILE" "$response"
import json
import re
import sys
from pathlib import Path

findings_path = Path(sys.argv[1])
payload = json.loads(sys.argv[2])
finding = payload["finding"]
details = json.loads(finding.get("details_json") or "{}")

slug = finding["slug"]
title = finding["title"]
severity = (finding.get("severity") or "medium").upper()
status = finding.get("status") or "confirmed"
source_name = finding.get("source_name") or details.get("discovered_by") or "unknown"
defect_family = finding.get("defect_family") or ""
location = finding.get("canonical_location") or details.get("parameter") or ""
auth_context = finding.get("auth_context") or "anonymous"
evidence = details.get("evidence") or finding.get("evidence_ref") or ""
impact = details.get("impact") or finding.get("summary") or ""
notes = (finding.get("notes") or "").strip()

lines = [
    f"## [{slug}] {title}",
    f"- **Discovered by**: {source_name}",
    f"- **Severity**: {severity}",
    f"- **Status**: {status}",
]
if defect_family:
    lines.append(f"- **Type**: {defect_family}")
if location:
    lines.append(f"- **Location**: {location}")
if auth_context:
    lines.append(f"- **Auth Context**: {auth_context}")
if evidence:
    lines.append(f"- **Evidence**: {evidence}")
if impact:
    lines.append(f"- **Impact**: {impact}")

block = "\n".join(lines).rstrip()
if notes:
    block = f"{block}\n\n{notes}"
block = block.strip() + "\n"

text = findings_path.read_text(encoding="utf-8")
pattern = re.compile(rf"(?ms)^## \[{re.escape(slug)}\].*?(?=^## \[FINDING-[A-Z]{{2}}-[0-9]{{3}}\]|\Z)")
if pattern.search(text):
    text = pattern.sub(block + "\n", text, count=1)
else:
    text = text.rstrip() + "\n\n" + block + "\n"
findings_path.write_text(text, encoding="utf-8")
PY

update_finding_count "$FINDINGS_FILE"

if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
    bash "$EMIT_RUNTIME_EVENT" \
        "finding.created" \
        "${ORCHESTRATOR_PHASE:-unknown}" \
        "$finding_slug" \
        "$AGENT_NAME" \
        "Recorded $finding_slug"
fi

printf '%s\n' "$finding_slug"
