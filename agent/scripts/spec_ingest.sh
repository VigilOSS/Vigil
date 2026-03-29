#!/usr/bin/env bash
# spec_ingest.sh — Parse OpenAPI 3.x / Swagger 2.0 spec and generate durable coverage records.
# The local SQLite queue remains available only as a transient batching buffer.
# Usage: ./scripts/spec_ingest.sh <db_path> <local_spec_file>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/params.sh"
source "$SCRIPT_DIR/lib/classify.sh"
source "$SCRIPT_DIR/lib/db.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/auth.sh"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"

# --- Validate arguments ---
if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <db_path> <local_spec_file>" >&2
    exit 1
fi

DB_PATH="$1"
SPEC_INPUT="$2"
ENGAGEMENT_DIR="$(cd "$(dirname "$DB_PATH")" && pwd)"
ASSESSMENT_AUTH_CONTEXT="${ASSESSMENT_AUTH_CONTEXT:-$(auth_active_context "$ENGAGEMENT_DIR")}"

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: database not found: $DB_PATH" >&2
    exit 1
fi

db_init "$DB_PATH"

SPEC_FILE="$SPEC_INPUT"

if [[ "$SPEC_INPUT" == http* ]]; then
    echo "ERROR: spec_ingest.sh no longer fetches target URLs directly." >&2
    echo "Fetch the spec through the Kali MCP command-execution tool first, save it locally, then rerun spec_ingest.sh with the saved file." >&2
    exit 1
fi

if [[ ! -f "$SPEC_FILE" ]]; then
    echo "ERROR: spec file not found: $SPEC_FILE" >&2
    exit 1
fi

# --- Detect spec version ---
OPENAPI_VER=$(jq -r '.openapi // empty' "$SPEC_FILE" 2>/dev/null || true)
SWAGGER_VER=$(jq -r '.swagger // empty' "$SPEC_FILE" 2>/dev/null || true)

if [[ -n "$OPENAPI_VER" ]]; then
    SPEC_VERSION="3"
elif [[ -n "$SWAGGER_VER" ]]; then
    SPEC_VERSION="2"
else
    echo "ERROR: cannot detect spec version (no .openapi or .swagger field)" >&2
    exit 1
fi

# --- Extract base URL ---
if [[ "$SPEC_VERSION" == "3" ]]; then
    BASE_URL=$(jq -r '(.servers[0].url // "")' "$SPEC_FILE" 2>/dev/null || true)
else
    # Swagger 2.0: build from host + basePath + schemes
    HOST=$(jq -r '.host // ""' "$SPEC_FILE" 2>/dev/null || true)
    BASE_PATH=$(jq -r '.basePath // ""' "$SPEC_FILE" 2>/dev/null || true)
    SCHEME=$(jq -r '(.schemes[0] // "https")' "$SPEC_FILE" 2>/dev/null || true)
    if [[ -n "$HOST" ]]; then
        BASE_URL="${SCHEME}://${HOST}${BASE_PATH}"
    else
        BASE_URL=""
    fi
fi

# Remove trailing slash from base URL
BASE_URL="${BASE_URL%/}"

count=0

# --- Extract endpoints ---
# Get all path+method combinations as JSON lines
ENDPOINTS=$(jq -r '
  .paths | to_entries[] | .key as $path | .value | to_entries[] |
  select(.key | test("^(get|post|put|delete|patch)$")) |
  "\(.key|ascii_upcase) \($path)"
' "$SPEC_FILE" 2>/dev/null)

while IFS= read -r endpoint; do
    [[ -z "$endpoint" ]] && continue

    method="${endpoint%% *}"
    path="${endpoint#* }"
    method_lower=$(printf '%s' "$method" | tr '[:upper:]' '[:lower:]')

    full_url="${BASE_URL}${path}"

    # Extract query parameters with examples
    query_params=$(jq -r --arg path "$path" --arg method "${method_lower}" '
      (.paths[$path][$method].parameters // [])
      | [.[] | select(.in == "query")]
      | if length == 0 then "{}"
        else reduce .[] as $p ({}; . + {($p.name): (($p.example // $p.default // "") | tostring)})
        end
    ' "$SPEC_FILE" 2>/dev/null || echo "{}")

    # Extract path parameters with examples
    path_params=$(jq -r --arg path "$path" --arg method "${method_lower}" '
      (.paths[$path][$method].parameters // [])
      | [.[] | select(.in == "path")]
      | if length == 0 then "{}"
        else reduce .[] as $p ({}; . + {($p.name): (($p.example // $p.default // "") | tostring)})
        end
    ' "$SPEC_FILE" 2>/dev/null || echo "{}")

    # Extract body parameters (OpenAPI 3.x)
    body_params="{}"
    if [[ "$SPEC_VERSION" == "3" ]]; then
        body_params=$(jq -r --arg path "$path" --arg method "${method_lower}" '
          (.paths[$path][$method].requestBody.content."application/json".schema.properties // {})
          | if . == {} then "{}"
            else to_entries | reduce .[] as $p ({}; . + {($p.key): (($p.value.example // "") | tostring)})
            end
        ' "$SPEC_FILE" 2>/dev/null || echo "{}")
    else
        # Swagger 2.0: look for body parameter
        body_params=$(jq -r --arg path "$path" --arg method "${method_lower}" '
          (.paths[$path][$method].parameters // [])
          | [.[] | select(.in == "body")]
          | if length == 0 then "{}"
            else .[0].schema.properties // {} |
              if . == {} then "{}"
              else to_entries | reduce .[] as $p ({}; . + {($p.key): (($p.value.example // "") | tostring)})
              end
            end
        ' "$SPEC_FILE" 2>/dev/null || echo "{}")
    fi

    # Build URL with query parameters if any
    url_with_query="$full_url"
    has_query=$(echo "$query_params" | jq 'length > 0' 2>/dev/null || echo "false")
    if [[ "$has_query" == "true" ]]; then
        qs=$(echo "$query_params" | jq -r 'to_entries | map("\(.key)=\(.value)") | join("&")' 2>/dev/null)
        if [[ -n "$qs" ]]; then
            url_with_query="${full_url}?${qs}"
        fi
    fi

    # Extract url_path
    url_path=$(extract_url_path "$url_with_query")

    # Classify type
    case_type=$(classify_type "$method" "$url_path" "" "")

    # Generate dedup signature
    params_sig=$(generate_params_sig "$query_params" "$body_params")

    payload=""
    if [[ "$url_with_query" =~ ^https?:// ]]; then
        payload="$(python3 - <<'PY' "$url_with_query" "$method" "$query_params" "$body_params" "$path_params" "$ASSESSMENT_AUTH_CONTEXT"
import json
import sys
from urllib.parse import urlparse

url, method, query_params, body_params, path_params, auth_context = sys.argv[1:]
parsed = urlparse(url)
print(json.dumps({
    "url": url,
    "method": method,
    "auth_context": auth_context,
    "content_type_family": "spec-derived",
    "query_schema": json.loads(query_params),
    "body_schema": json.loads(body_params),
    "path_schema": json.loads(path_params),
    "cookie_schema": {},
    "header_schema": {},
    "path_template": parsed.path or "",
    "discovery_source": "api-spec",
    "notes": "Derived from accessible API specification.",
    "response_status": None,
    "evidence_ref": "",
    "observation_payload": {"source": "api-spec"},
    "target_identity": parsed.hostname or "",
    "target_kind": "host",
    "target_notes": "",
    "target_ip_address": None,
    "target_hostname": parsed.hostname,
    "banner": "",
    "coverage_candidates": [],
    "auto_generate_coverage": True,
}, ensure_ascii=True))
PY
)"
    fi

    if [[ -n "$payload" ]]; then
        assessment_response="$(bash "$POST_ASSESSMENT_RECORD" "request-observations" "$payload")"
        request_variant_id="$(printf '%s' "$assessment_response" | jq -r '.request_variant.id // empty' 2>/dev/null)"
        service_id="$(printf '%s' "$assessment_response" | jq -r '.service.id // empty' 2>/dev/null)"
        if [[ -z "$request_variant_id" && -z "$service_id" ]]; then
            echo "spec_ingest.sh: backend response missing request_variant.id/service.id for $url_with_query" >&2
            exit 1
        fi
        queue_key=""
        if [[ -n "$request_variant_id" ]]; then
            queue_key="variant:${request_variant_id}:${case_type}"
        elif [[ -n "$service_id" ]]; then
            queue_key="service:${service_id}:${case_type}"
        fi
        DB_AUTH_CONTEXT="$ASSESSMENT_AUTH_CONTEXT" \
        DB_QUEUE_KEY="$queue_key" \
        DB_REQUEST_VARIANT_ID="${request_variant_id:-}" \
        DB_SERVICE_ID="${service_id:-}" \
        db_insert_case "$DB_PATH" \
            "$method" "$url_with_query" "$url_path" \
            "$query_params" "$body_params" "$path_params" "{}" \
            "" "" "" "0" \
            "0" "" "0" "" \
            "$case_type" "api-spec" "$params_sig"
    else
        echo "spec_ingest.sh: endpoint $url_with_query is missing an absolute http(s) URL for backend ingestion" >&2
        exit 1
    fi

    count=$((count + 1))
done <<< "$ENDPOINTS"

# Downloaded spec file is kept in scans/ for reference (not cleaned up)

echo "[spec_ingest] Ingested $count endpoints from spec (version $SPEC_VERSION)"
