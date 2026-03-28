#!/usr/bin/env bash
# recon_ingest.sh — Read endpoint lists from stdin and ingest them into assessment state.
# The local SQLite work buffer remains available only as a transient batching buffer.
# Usage: echo "endpoints" | ./scripts/recon_ingest.sh <db_path> <source_name>
#
# Input formats (auto-detected per line):
#   Simple URL:    GET https://example.com/api/users?id=1
#   Plain URL:     https://example.com/app.js   (defaults to GET)
#   JSON line:     {"method":"GET","url":"https://example.com/api/users","type":"api"}

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/params.sh"
source "$SCRIPT_DIR/lib/classify.sh"
source "$SCRIPT_DIR/lib/db.sh"
POST_ASSESSMENT_RECORD="$SCRIPT_DIR/post_assessment_record.sh"
ASSESSMENT_AUTH_CONTEXT="${ASSESSMENT_AUTH_CONTEXT:-anonymous}"

if [[ $# -lt 2 ]]; then
    echo "Usage: echo 'endpoints' | $0 <db_path> <source_name>" >&2
    exit 1
fi

DB_PATH="$1"
SOURCE="$2"

if [[ ! -f "$DB_PATH" ]]; then
    echo "ERROR: database not found: $DB_PATH" >&2
    exit 1
fi

db_init "$DB_PATH"

count=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    method=""
    url=""
    override_type=""
    query_params=""
    body_params=""
    path_params=""
    cookie_params="{}"

    if [[ "$line" == "{"* ]]; then
        method=$(echo "$line" | jq -r '.method // "GET"' 2>/dev/null)
        url=$(echo "$line" | jq -r '.url // empty' 2>/dev/null)
        url_path=$(echo "$line" | jq -r '.url_path // empty' 2>/dev/null)
        override_type=$(echo "$line" | jq -r '.type // empty' 2>/dev/null)
        query_params=$(echo "$line" | jq -c '.query_params // {}' 2>/dev/null || echo '{}')
        body_params=$(echo "$line" | jq -c '.body_params // {}' 2>/dev/null || echo '{}')
        path_params=$(echo "$line" | jq -c '.path_params // {}' 2>/dev/null || echo '{}')
        cookie_params=$(echo "$line" | jq -c '.cookie_params // {}' 2>/dev/null || echo '{}')
        [[ -z "$url" ]] && continue
    elif [[ "$line" =~ ^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)[[:space:]] ]]; then
        method="${line%% *}"
        url="${line#* }"
    else
        method="GET"
        url="$line"
    fi

    url=$(printf '%s' "$url" | awk '{print $1}')
    method=$(printf '%s' "$method" | tr '[:lower:]' '[:upper:]')

    if [[ "$url" == *"FUZZ"* || "$url" == *"PARAM"* || "$url" == *"{{"* ]]; then
        continue
    fi
    [[ -z "$url" ]] && continue

    if [[ ! "$url" =~ ^https?:// ]]; then
        if echo "$url" | grep -qE '^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}'; then
            url="https://$url"
        fi
    fi

    if [[ -z "${url_path:-}" || "$url_path" == "null" ]]; then
        url_path=$(extract_url_path "$url")
    fi
    if [[ -z "$query_params" || "$query_params" == "null" ]]; then
        query_params=$(extract_query_params "$url")
    fi
    if [[ -z "$path_params" || "$path_params" == "null" ]]; then
        path_params=$(extract_path_params "$url_path")
    fi
    if [[ -z "$body_params" || "$body_params" == "null" ]]; then
        body_params="{}"
    fi

    if [[ -n "$override_type" ]]; then
        case_type="$override_type"
    else
        case_type=$(classify_type "$method" "$url_path" "" "")
    fi

    params_sig=$(generate_params_sig "$query_params" "$body_params")

    payload="$(python3 - <<'PY' "$url" "$method" "$query_params" "$body_params" "$path_params" "$cookie_params" "$SOURCE" "$ASSESSMENT_AUTH_CONTEXT"
import json
import sys
from urllib.parse import urlparse

url, method, query_params, body_params, path_params, cookie_params, source_name, auth_context = sys.argv[1:]
parsed = urlparse(url)
print(json.dumps({
    "url": url,
    "method": method,
    "auth_context": auth_context,
    "content_type_family": "unknown",
    "query_schema": json.loads(query_params),
    "body_schema": json.loads(body_params),
    "path_schema": json.loads(path_params),
    "cookie_schema": json.loads(cookie_params),
    "header_schema": {},
    "path_template": "",
    "discovery_source": source_name,
    "notes": "",
    "response_status": None,
    "evidence_ref": "",
    "observation_payload": {"source": source_name},
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

    assessment_response="$(bash "$POST_ASSESSMENT_RECORD" "request-observations" "$payload")"
    request_variant_id="$(printf '%s' "$assessment_response" | jq -r '.request_variant.id // empty' 2>/dev/null)"
    service_id="$(printf '%s' "$assessment_response" | jq -r '.service.id // empty' 2>/dev/null)"
    if [[ -z "$request_variant_id" && -z "$service_id" ]]; then
        echo "recon_ingest.sh: backend response missing request_variant.id/service.id for $url" >&2
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
        "$method" "$url" "$url_path" \
        "$query_params" "$body_params" "$path_params" "$cookie_params" \
        "" "" "" "0" \
        "0" "" "0" "" \
        "$case_type" "$SOURCE" "$params_sig"

    count=$((count + 1))
done

echo "[recon_ingest] Ingested $count work items from source '$SOURCE'"
