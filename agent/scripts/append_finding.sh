#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RECORD_FINDING="$SCRIPT_DIR/record_finding.sh"
SCHEMA_FILE="$SCRIPT_DIR/../schemas/finding-record.schema.json"

ENG_DIR="${1:?usage: append_finding.sh <engagement_dir> <agent-name> <finding-body-file>}"
AGENT_NAME="${2:?usage: append_finding.sh <engagement_dir> <agent-name> <finding-body-file>}"
BODY_FILE="${3:?usage: append_finding.sh <engagement_dir> <agent-name> <finding-body-file>}"

[[ -f "$BODY_FILE" ]] || { echo "finding body file not found: $BODY_FILE" >&2; exit 1; }
[[ -f "$RECORD_FINDING" ]] || { echo "record_finding.sh not found" >&2; exit 1; }
[[ -f "$SCHEMA_FILE" ]] || { echo "finding schema not found: $SCHEMA_FILE" >&2; exit 1; }

if jq -e . "$BODY_FILE" >/dev/null 2>&1; then
    bash "$RECORD_FINDING" "$ENG_DIR" "$AGENT_NAME" "$BODY_FILE"
    exit 0
fi

cat >&2 <<EOF
append_finding.sh no longer converts markdown findings into canonical backend state.
Provide a structured JSON finding document and call:
  ./scripts/record_finding.sh "$ENG_DIR" "$AGENT_NAME" <finding-json-file>

Expected schema file:
  $SCHEMA_FILE

Minimal example:
{
  "title": "Blind SQL injection in search",
  "severity": "high",
  "status": "confirmed",
  "defect_family": "sql-injection",
  "root_cause_key": "search-id-sqli",
  "auth_context": "anonymous",
  "canonical_location": "https://target.example/search?q",
  "summary": "Boolean-blind SQL injection on the search endpoint",
  "evidence_ref": "scans/sqlmap.txt",
  "notes": "Payloads AND 1=1 and AND 1=2 caused consistent divergence.",
  "details": {
    "evidence": "Replayable request/response pair in scans/sqlmap.txt",
    "impact": "Attackers can extract data from the backing store"
  }
}
EOF

exit 1
