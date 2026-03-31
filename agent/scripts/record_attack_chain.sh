#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"
EMIT_RUNTIME_EVENT="$SCRIPT_DIR/emit_runtime_event.sh"

ENG_DIR="${1:?usage: record_attack_chain.sh <engagement_dir> <agent-name> <chain-json-file>}"
AGENT_NAME="${2:?usage: record_attack_chain.sh <engagement_dir> <agent-name> <chain-json-file>}"
CHAIN_JSON_FILE="${3:?usage: record_attack_chain.sh <engagement_dir> <agent-name> <chain-json-file>}"
export ENGAGEMENT_DIR="$ENG_DIR"

[[ -f "$CHAIN_JSON_FILE" ]] || { echo "chain json file not found: $CHAIN_JSON_FILE" >&2; exit 1; }
[[ -f "$POST_ASSESSMENT_RECORD" ]] || { echo "post_assessment_record.sh not found" >&2; exit 1; }

# Inject provenance defaults if missing
payload="$(python3 - <<'PY' "$CHAIN_JSON_FILE" "$AGENT_NAME"
import json, sys

chain_path, agent_name = sys.argv[1:]
chain = json.load(open(chain_path, "r", encoding="utf-8"))

if not isinstance(chain, dict):
    print("chain payload must be a JSON object", file=sys.stderr)
    sys.exit(1)

if "title" not in chain or not chain["title"]:
    print("chain payload must have a non-empty title", file=sys.stderr)
    sys.exit(1)

prov = chain.get("provenance") or {}
prov.setdefault("agent_name", agent_name)
chain["provenance"] = prov

print(json.dumps(chain, ensure_ascii=True))
PY
)"

response="$(bash "$POST_ASSESSMENT_RECORD" "attack-chains" "$payload")"

chain_key="$(printf '%s' "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['chain']['chain_key'])" 2>/dev/null)" || chain_key=""

if [[ -z "$chain_key" ]]; then
    echo "record_attack_chain.sh: backend did not return a valid chain" >&2
    exit 1
fi

if [[ -f "$EMIT_RUNTIME_EVENT" ]]; then
    bash "$EMIT_RUNTIME_EVENT" \
        "chain.created" \
        "${ORCHESTRATOR_PHASE:-unknown}" \
        "$chain_key" \
        "$AGENT_NAME" \
        "Attack chain recorded: $chain_key" 2>/dev/null || true
fi

printf '%s\n' "$chain_key"
