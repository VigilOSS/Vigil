#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SESSION_SCHEMA_FILE="$SCRIPT_DIR/../schemas/session-proposal.schema.json"
FINDING_SCHEMA_FILE="$SCRIPT_DIR/../schemas/finding-record.schema.json"
PROBE_SCHEMA_FILE="$SCRIPT_DIR/../schemas/probe-run.schema.json"

SESSION_DIR="${1:?usage: record_session_proposal.sh <session_dir> <proposal-json-file>}"
PROPOSAL_FILE="${2:?usage: record_session_proposal.sh <session_dir> <proposal-json-file>}"
PROPOSALS_FILE="$SESSION_DIR/proposals/proposals.jsonl"

[[ -d "$SESSION_DIR" ]] || { echo "session directory not found: $SESSION_DIR" >&2; exit 1; }
[[ -f "$PROPOSAL_FILE" ]] || { echo "proposal file not found: $PROPOSAL_FILE" >&2; exit 1; }
[[ -f "$SESSION_SCHEMA_FILE" ]] || { echo "session proposal schema not found" >&2; exit 1; }
[[ -f "$FINDING_SCHEMA_FILE" ]] || { echo "finding schema not found" >&2; exit 1; }
[[ -f "$PROBE_SCHEMA_FILE" ]] || { echo "probe schema not found" >&2; exit 1; }
mkdir -p "$(dirname "$PROPOSALS_FILE")"
touch "$PROPOSALS_FILE"

normalized_proposal="$(
python3 - <<'PY' "$PROPOSAL_FILE" "$SESSION_SCHEMA_FILE" "$FINDING_SCHEMA_FILE" "$PROBE_SCHEMA_FILE"
import json
import sys

proposal_path, session_schema_path, finding_schema_path, probe_schema_path = sys.argv[1:]
proposal = json.load(open(proposal_path, "r", encoding="utf-8"))
session_schema = json.load(open(session_schema_path, "r", encoding="utf-8"))
finding_schema = json.load(open(finding_schema_path, "r", encoding="utf-8"))
probe_schema = json.load(open(probe_schema_path, "r", encoding="utf-8"))

if not isinstance(proposal, dict):
    raise SystemExit("session proposal must be a JSON object")

required = session_schema.get("required", [])
missing = [key for key in required if key not in proposal]
if missing:
    raise SystemExit(f"session proposal missing required fields: {', '.join(missing)}")

proposal_type = proposal.get("type")
payload = proposal.get("payload")
if not isinstance(payload, dict):
    raise SystemExit("session proposal payload must be a JSON object")

schema = finding_schema if proposal_type == "finding_record" else probe_schema if proposal_type == "probe_run" else None
if schema is None:
    raise SystemExit(f"unsupported proposal type: {proposal_type}")

schema_required = schema.get("required", [])
schema_properties = schema.get("properties", {})
missing_payload = [key for key in schema_required if key not in payload]
if missing_payload:
    raise SystemExit(f"{proposal_type} payload missing required fields: {', '.join(missing_payload)}")

unknown_payload = sorted(set(payload.keys()) - set(schema_properties.keys()))
if unknown_payload:
    raise SystemExit(f"{proposal_type} payload has unsupported fields: {', '.join(unknown_payload)}")

def check_nested(obj, obj_schema, path):
    if not isinstance(obj, dict) or obj_schema.get("type") != "object":
        return
    nested_props = obj_schema.get("properties", {})
    if not obj_schema.get("additionalProperties", True) and nested_props:
        bad = sorted(set(obj.keys()) - set(nested_props.keys()))
        if bad:
            raise SystemExit(f"{path} has unsupported fields: {', '.join(bad)}")
    nested_required = obj_schema.get("required", [])
    missing_nested = [k for k in nested_required if k not in obj]
    if missing_nested:
        raise SystemExit(f"{path} missing required fields: {', '.join(missing_nested)}")

for nested_key in ("details", "provenance"):
    if nested_key in payload and isinstance(payload[nested_key], dict):
        check_nested(payload[nested_key], schema_properties.get(nested_key, {}), f"{proposal_type}.{nested_key}")

print(json.dumps(proposal, ensure_ascii=True, separators=(",", ":")))
PY
)"

printf '%s\n' "$normalized_proposal" >> "$PROPOSALS_FILE"
printf 'Recorded proposal in %s\n' "$PROPOSALS_FILE"
