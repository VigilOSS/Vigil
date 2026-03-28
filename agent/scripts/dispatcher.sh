#!/bin/bash
set -euo pipefail

# dispatcher.sh — Zero-token transient work-buffer consumption engine
# Manages the SQLite work_items buffer without consuming LLM tokens.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/params.sh"
source "$SCRIPT_DIR/lib/db.sh"

DB="${1:-}"
ACTION="${2:-}"
TABLE="work_items"

if [[ -z "$DB" || -z "$ACTION" ]]; then
  echo "Usage: $0 <db_path> <action> [args...]"
  echo ""
  echo "Actions:"
  echo "  stats                          Show work-buffer statistics"
  echo "  fetch <type> <limit> <agent>   Atomic consume batch (JSON output)"
  echo "  done <id_list>                 Mark comma-separated IDs as done"
  echo "  error <id_list>                Mark comma-separated IDs as error"
  echo "  reset-stale <minutes>          Recover stuck processing work items"
  echo "  retry-errors [max_retries]     Retry error work items (default max: 2)"
  echo "  migrate                        Ensure work-buffer schema exists"
  echo "  requeue                        Read JSON lines from stdin, insert as pending"
  exit 1
fi

db_init "$DB"

sql() {
  sqlite3 "$DB" ".timeout 5000" "$1"
}

case "$ACTION" in
  stats)
    echo "--- Work Buffer Statistics ---"
    sql "SELECT status, type, COUNT(*) as count FROM ${TABLE} GROUP BY status, type ORDER BY status, type;"
    echo ""
    echo "--- Summary ---"
    sql "SELECT status, COUNT(*) as count FROM ${TABLE} GROUP BY status ORDER BY status;"
    echo ""
    sql "SELECT 'TOTAL', COUNT(*) FROM ${TABLE};"
    ;;

  fetch)
    TYPE="${3:?Missing type argument}"
    LIMIT="${4:?Missing limit argument}"
    AGENT="${5:?Missing agent argument}"

    TYPE="${TYPE//\'/\'\'}"
    AGENT="${AGENT//\'/\'\'}"
    if ! [[ "$LIMIT" =~ ^[0-9]+$ ]]; then
      echo "ERROR: limit must be a positive integer" >&2
      exit 1
    fi

    sqlite3 "$DB" ".timeout 5000" -json "
      UPDATE ${TABLE}
      SET status = 'processing',
          assigned_agent = '${AGENT}',
          consumed_at = datetime('now')
      WHERE id IN (
        SELECT id FROM ${TABLE}
        WHERE status = 'pending' AND type = '${TYPE}'
        LIMIT ${LIMIT}
      )
      RETURNING *;
    "
    ;;

  done)
    ID_LIST="${3:?Missing id_list argument}"
    if ! [[ "$ID_LIST" =~ ^[0-9,]+$ ]]; then
      echo "ERROR: id_list must contain only numeric IDs separated by commas" >&2
      exit 1
    fi
    sql "UPDATE ${TABLE} SET status='done' WHERE id IN (${ID_LIST});"
    echo "Marked done: ${ID_LIST}"
    ;;

  error)
    ID_LIST="${3:?Missing id_list argument}"
    if ! [[ "$ID_LIST" =~ ^[0-9,]+$ ]]; then
      echo "ERROR: id_list must contain only numeric IDs separated by commas" >&2
      exit 1
    fi
    sql "UPDATE ${TABLE} SET status='error', retry_count = COALESCE(retry_count,0) + 1 WHERE id IN (${ID_LIST});"
    echo "Marked error: ${ID_LIST}"
    ;;

  migrate)
    db_init "$DB"
    ;;

  retry-errors)
    MAX_RETRIES="${3:-2}"
    if ! [[ "$MAX_RETRIES" =~ ^[0-9]+$ ]]; then
      echo "ERROR: max_retries must be a positive integer" >&2
      exit 1
    fi
    BEFORE=$(sql "SELECT COUNT(*) FROM ${TABLE} WHERE status='error' AND COALESCE(retry_count,0) < ${MAX_RETRIES};")
    sql "UPDATE ${TABLE} SET status='pending', assigned_agent=NULL, consumed_at=NULL WHERE status='error' AND COALESCE(retry_count,0) < ${MAX_RETRIES};"
    echo "Retried ${BEFORE} error work item(s) (max retries: ${MAX_RETRIES})"
    ;;

  reset-stale)
    MINUTES="${3:?Missing minutes argument}"
    if ! [[ "$MINUTES" =~ ^[0-9]+$ ]]; then
      echo "ERROR: minutes must be a positive integer" >&2
      exit 1
    fi
    BEFORE=$(sql "SELECT COUNT(*) FROM ${TABLE} WHERE status='processing' AND consumed_at < datetime('now', '-${MINUTES} minutes');")
    sql "UPDATE ${TABLE} SET status='pending', assigned_agent=NULL, consumed_at=NULL WHERE status='processing' AND consumed_at < datetime('now', '-${MINUTES} minutes');"
    echo "Reset ${BEFORE} stale work item(s) (stuck > ${MINUTES} min)"
    ;;

  requeue)
    COUNT=0
    while IFS= read -r line; do
      [[ -z "$line" ]] && continue

      METHOD=$(echo "$line" | jq -r '.method')
      URL=$(echo "$line" | jq -r '.url')
      URL_PATH=$(echo "$line" | jq -r '.url_path // empty')
      TYPE=$(echo "$line" | jq -r '.type')
      SOURCE=$(echo "$line" | jq -r '.source // "requeue"')
      QUERY_PARAMS=$(echo "$line" | jq -r 'if .query_params == null then empty elif (.query_params | type) == "string" then .query_params else (.query_params | tojson) end')
      BODY_PARAMS=$(echo "$line" | jq -r 'if .body_params == null then empty elif (.body_params | type) == "string" then .body_params else (.body_params | tojson) end')
      PATH_PARAMS=$(echo "$line" | jq -r 'if .path_params == null then empty elif (.path_params | type) == "string" then .path_params else (.path_params | tojson) end')
      COOKIE_PARAMS=$(echo "$line" | jq -r 'if .cookie_params == null then empty elif (.cookie_params | type) == "string" then .cookie_params else (.cookie_params | tojson) end')
      HEADERS=$(echo "$line" | jq -r 'if .headers == null then empty elif (.headers | type) == "string" then .headers else (.headers | tojson) end')
      BODY=$(echo "$line" | jq -r '.body // ""')
      CONTENT_TYPE=$(echo "$line" | jq -r '.content_type // ""')
      CONTENT_LENGTH=$(echo "$line" | jq -r '.content_length // 0')
      RESPONSE_STATUS=$(echo "$line" | jq -r '.response_status // 0')
      RESPONSE_HEADERS=$(echo "$line" | jq -r 'if .response_headers == null then empty elif (.response_headers | type) == "string" then .response_headers else (.response_headers | tojson) end')
      RESPONSE_SIZE=$(echo "$line" | jq -r '.response_size // 0')
      RESPONSE_SNIPPET=$(echo "$line" | jq -r '.response_snippet // ""')
      PARAMS_KEY_SIG=$(echo "$line" | jq -r '.params_key_sig // empty')
      AUTH_CONTEXT=$(echo "$line" | jq -r '.auth_context // "anonymous"')
      REQUEST_VARIANT_ID=$(echo "$line" | jq -r '.request_variant_id // empty')
      SERVICE_ID=$(echo "$line" | jq -r '.service_id // empty')
      COVERAGE_ITEM_ID=$(echo "$line" | jq -r '.coverage_item_id // empty')
      QUEUE_KEY=$(echo "$line" | jq -r '.queue_key // empty')

      [[ "$METHOD" == "null" || -z "$METHOD" ]] && METHOD="GET"
      [[ "$URL" == "null" ]] && URL=""
      [[ "$TYPE" == "null" || -z "$TYPE" ]] && TYPE="unknown"
      [[ "$SOURCE" == "null" || -z "$SOURCE" ]] && SOURCE="requeue"
      [[ "$AUTH_CONTEXT" == "null" || -z "$AUTH_CONTEXT" ]] && AUTH_CONTEXT="anonymous"
      [[ -z "$URL_PATH" ]] && URL_PATH="$(extract_url_path "$URL")"
      [[ -z "$QUERY_PARAMS" ]] && QUERY_PARAMS="$(extract_query_params "$URL" | jq -c '.')"
      [[ -z "$BODY_PARAMS" ]] && BODY_PARAMS="{}"
      [[ -z "$PATH_PARAMS" ]] && PATH_PARAMS="$(extract_path_params "$URL_PATH" | jq -c '.')"
      [[ -z "$COOKIE_PARAMS" ]] && COOKIE_PARAMS="{}"
      [[ -z "$HEADERS" ]] && HEADERS="{}"
      [[ -z "$RESPONSE_HEADERS" ]] && RESPONSE_HEADERS="{}"
      [[ -z "$PARAMS_KEY_SIG" ]] && PARAMS_KEY_SIG="$(generate_params_sig "$QUERY_PARAMS" "$BODY_PARAMS")"

      if [[ -z "$QUEUE_KEY" || "$QUEUE_KEY" == "null" ]]; then
        if [[ -n "$REQUEST_VARIANT_ID" && "$REQUEST_VARIANT_ID" != "null" ]]; then
          QUEUE_KEY="variant:${REQUEST_VARIANT_ID}:${TYPE}"
        elif [[ -n "$SERVICE_ID" && "$SERVICE_ID" != "null" ]]; then
          QUEUE_KEY="service:${SERVICE_ID}:${TYPE}"
        elif [[ -n "$COVERAGE_ITEM_ID" && "$COVERAGE_ITEM_ID" != "null" ]]; then
          QUEUE_KEY="coverage:${COVERAGE_ITEM_ID}:${TYPE}"
        else
          QUEUE_KEY="legacy:${AUTH_CONTEXT}:${METHOD}:${URL}:${PARAMS_KEY_SIG}:${TYPE}"
        fi
      fi

      if [[ -z "$URL" || -z "$URL_PATH" ]]; then
        echo "ERROR: requeue line missing usable url/url_path" >&2
        exit 1
      fi

      [[ "$CONTENT_LENGTH" =~ ^-?[0-9]+$ ]] || CONTENT_LENGTH=0
      [[ "$RESPONSE_STATUS" =~ ^-?[0-9]+$ ]] || RESPONSE_STATUS=0
      [[ "$RESPONSE_SIZE" =~ ^-?[0-9]+$ ]] || RESPONSE_SIZE=0

      METHOD="${METHOD//\'/\'\'}"
      URL="${URL//\'/\'\'}"
      URL_PATH="${URL_PATH//\'/\'\'}"
      TYPE="${TYPE//\'/\'\'}"
      SOURCE="${SOURCE//\'/\'\'}"
      QUERY_PARAMS="${QUERY_PARAMS//\'/\'\'}"
      BODY_PARAMS="${BODY_PARAMS//\'/\'\'}"
      PATH_PARAMS="${PATH_PARAMS//\'/\'\'}"
      COOKIE_PARAMS="${COOKIE_PARAMS//\'/\'\'}"
      HEADERS="${HEADERS//\'/\'\'}"
      BODY="${BODY//\'/\'\'}"
      CONTENT_TYPE="${CONTENT_TYPE//\'/\'\'}"
      RESPONSE_HEADERS="${RESPONSE_HEADERS//\'/\'\'}"
      RESPONSE_SNIPPET="${RESPONSE_SNIPPET//\'/\'\'}"
      PARAMS_KEY_SIG="${PARAMS_KEY_SIG//\'/\'\'}"
      AUTH_CONTEXT="${AUTH_CONTEXT//\'/\'\'}"
      QUEUE_KEY="${QUEUE_KEY//\'/\'\'}"

      REQUEST_VARIANT_SQL="NULL"
      SERVICE_SQL="NULL"
      COVERAGE_ITEM_SQL="NULL"
      [[ "$REQUEST_VARIANT_ID" =~ ^[0-9]+$ ]] && REQUEST_VARIANT_SQL="$REQUEST_VARIANT_ID"
      [[ "$SERVICE_ID" =~ ^[0-9]+$ ]] && SERVICE_SQL="$SERVICE_ID"
      [[ "$COVERAGE_ITEM_ID" =~ ^[0-9]+$ ]] && COVERAGE_ITEM_SQL="$COVERAGE_ITEM_ID"

      RESULT=$(sql "INSERT OR IGNORE INTO ${TABLE} (
          queue_key, request_variant_id, service_id, coverage_item_id, auth_context,
          method, url, url_path,
          query_params, body_params, path_params, cookie_params,
          headers, body, content_type, content_length,
          response_status, response_headers, response_size, response_snippet,
          type, source, status, params_key_sig,
          assigned_agent, consumed_at
        ) VALUES (
          '${QUEUE_KEY}', ${REQUEST_VARIANT_SQL}, ${SERVICE_SQL}, ${COVERAGE_ITEM_SQL}, '${AUTH_CONTEXT}',
          '${METHOD}', '${URL}', '${URL_PATH}',
          '${QUERY_PARAMS}', '${BODY_PARAMS}', '${PATH_PARAMS}', '${COOKIE_PARAMS}',
          '${HEADERS}', '${BODY}', '${CONTENT_TYPE}', ${CONTENT_LENGTH},
          ${RESPONSE_STATUS}, '${RESPONSE_HEADERS}', ${RESPONSE_SIZE}, '${RESPONSE_SNIPPET}',
          '${TYPE}', '${SOURCE}', 'pending', '${PARAMS_KEY_SIG}',
          NULL, NULL
        );
        SELECT changes();")

      COUNT=$((COUNT + RESULT))
    done

    echo "Requeued ${COUNT} new work item(s)"
    ;;

  *)
    echo "Unknown action: ${ACTION}"
    echo "Usage: $0 <db_path> {stats|fetch|done|error|reset-stale|retry-errors|migrate|requeue}"
    exit 1
    ;;
esac
