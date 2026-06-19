#!/bin/bash
# post-tool-log.sh — Claude Code / Codex PostToolUse hook
# Reads hook JSON from stdin, extracts tool info + agent context, POSTs to the
# orchestrator's /engagements/{key}/activity-entries endpoint.
#
# The backend is now authoritative for the narrative activity log (formerly
# log.md). This script constructs a JSON payload and delegates the HTTP call
# to `vigil assess log`, which centralizes URL resolution, retry, and auth.
#
# Hook JSON fields used:
#   tool_name        — Bash, Write, Edit, Agent, etc.
#   tool_input       — command (Bash), file_path (Write/Edit), prompt+subagent_type (Agent)
#   tool_response    — stdout/stderr object (Claude Bash) or stable response
#                      string/object (Codex Bash/apply_patch/MCP)
#   agent_type       — which subagent is running (only present in subagent context)
#   hook_event_name  — PostToolUse

# No set -e: jq/grep returning empty is expected, not an error.

INPUT=$(cat)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/engagement.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/scope.sh"

ASSESS_PY="$SCRIPT_DIR/../assess.py"

# Parse fields
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)
[ -z "$TOOL_NAME" ] && exit 0

AGENT_TYPE=$(echo "$INPUT" | jq -r '.agent_type // .agent_name // "operator"' 2>/dev/null || echo "operator")
HOOK_CWD=$(echo "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

# Find active engagement directory
ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" || true)
[ -z "$ENG_DIR" ] && exit 0

# Check scope.json status — only log in-progress engagements.
STATUS=$(jq -r '.status // "unknown"' "$ENG_DIR/scope.json" 2>/dev/null || echo "unknown")
[ "$STATUS" != "in_progress" ] && exit 0

# --- Deduplication ---
# Use a stamp file to track last logged command (within this engagement).
# Skip if the same command was logged within the last 3 seconds. This prevents
# loud hooks from flooding the activity_entries table when a command triggers
# multiple PostToolUse events.
DEDUP_FILE="$ENG_DIR/.last_hook_log"
TOOL_USE_ID=$(echo "$INPUT" | jq -r '.tool_use_id // empty' 2>/dev/null || true)

if [ -n "$TOOL_USE_ID" ]; then
  SEEN_FILE="$ENG_DIR/.hook_seen_tool_uses"
  if [ -f "$SEEN_FILE" ] && grep -Fxq "$TOOL_USE_ID" "$SEEN_FILE" 2>/dev/null; then
    exit 0
  fi
  printf '%s\n' "$TOOL_USE_ID" >> "$SEEN_FILE" 2>/dev/null || true
fi

tool_response_text() {
  echo "$INPUT" | jq -r '
    .tool_response as $r
    | if ($r | type) == "object" then
        ($r.stdout // $r.output // $r.result // $r.message // ($r | tostring))
      elif $r == null then
        ""
      else
        ($r | tostring)
      end
  ' 2>/dev/null || true
}

tool_response_exit_code() {
  echo "$INPUT" | jq -r '
    .tool_response as $r
    | if ($r | type) == "object" then
        ($r.exitCode // $r.exit_code // $r.return_code // empty)
      else
        empty
      end
  ' 2>/dev/null || true
}

json_preview() {
  jq -c . 2>/dev/null | head -c "${1:-300}" || true
}

# post_activity_entry <actor_kind> <title> <action> <result>
# Delegates to vigil assess log so URL resolution, retry, and schema shaping all
# live in one place. The hook is best-effort: failure is logged to stderr but
# does not block the agent's next step.
post_activity_entry() {
  local actor_kind="$1"
  local title="$2"
  local action="$3"
  local result="$4"

  ENGAGEMENT_DIR="$ENG_DIR" \
    python3 "$ASSESS_PY" --engagement-dir "$ENG_DIR" log \
      --actor-kind "$actor_kind" \
      "$AGENT_TYPE" \
      "$title" \
      "$action" \
      "$result" \
      >/dev/null 2>&1 \
    || true
}

case "$TOOL_NAME" in
  Bash)
    COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
    [ -z "$COMMAND" ] && exit 0

    # Skip noise: pure file reads, git ops, test commands — but NEVER skip a
    # command that is security-relevant, because the post-run taint audit
    # (vigil_cli/bench/taint.py) scans these logged activity entries for cheat
    # signatures. A skipped `cat /…/flag`, `cat /…/factory/…/dag.yaml`, or
    # `cat /engagements/<other>/captured-flag.txt` would be INVISIBLE to that
    # audit, letting a host-side flag/answer-key read or a cross-attempt steal go
    # unrecorded. So the noise skip applies only when the command does NOT touch a
    # taint-relevant surface: a flag artifact, the benchmark store / factory source
    # (the answer key), an engagements path, or a host net/docker tool. These
    # mirror taint.py's signatures so logging and auditing stay in lockstep.
    case "$COMMAND" in
      cat\ *|ls\ *|git\ *|echo\ *|test\ *|"["*|pwd*)
        if printf '%s' "$COMMAND" | grep -Eqi \
            'flag|\.vigil-bench|xbow-benchmarks|validation-benchmarks|vigil_cli/bench|bench/factory|factory/families|dag\.yaml|injection\.yaml|family\.yaml|engagements/|(^|[^[:alnum:]_])(curl|wget|nc|ncat|nmap|masscan|httpie|telnet|socat|docker)([^[:alnum:]_]|$)'
        then
          : # security-relevant — fall through and log it for the taint audit
        else
          exit 0
        fi
        ;;
    esac

    # Dedup check: compare first 200 chars + timestamp within 3s window
    CMD_KEY=$(echo "$COMMAND" | head -c 200)
    if [ -f "$DEDUP_FILE" ]; then
      LAST_KEY=$(head -1 "$DEDUP_FILE" 2>/dev/null || true)
      LAST_TS=$(tail -1 "$DEDUP_FILE" 2>/dev/null || echo "0")
      NOW_TS=$(date +%s)
      if [ "$CMD_KEY" = "$LAST_KEY" ] && [ -n "$LAST_TS" ] && [ $((NOW_TS - LAST_TS)) -lt 3 ]; then
        exit 0
      fi
    fi
    printf '%s\n%s\n' "$CMD_KEY" "$(date +%s)" > "$DEDUP_FILE"

    # Extract output summary (first 300 chars). Claude sends a response object;
    # Codex sends a stable response string for Bash/unified exec.
    OUTPUT_SUMMARY=$(tool_response_text | head -c 300 || true)
    EXIT_CODE=$(tool_response_exit_code)

    SHORT_CMD=$(echo "$COMMAND" | head -c 200)

    ACTION="bash: $SHORT_CMD"
    RESULT=""
    if [ -n "$EXIT_CODE" ] && [ "$EXIT_CODE" != "0" ]; then
      RESULT="exit=${EXIT_CODE}"
    fi
    if [ -n "$OUTPUT_SUMMARY" ]; then
      if [ -n "$RESULT" ]; then
        RESULT="${RESULT} | ${OUTPUT_SUMMARY}"
      else
        RESULT="$OUTPUT_SUMMARY"
      fi
    fi
    if command_hits_in_scope_target_with_raw_curl "$ENG_DIR" "$COMMAND"; then
      RESULT="VIOLATION: host-side target traffic bypassed 'vigil assess kali'. ${RESULT}"
    fi

    post_activity_entry "hook" "Bash" "$ACTION" "$RESULT"
    ;;

  Agent)
    SUBAGENT=$(echo "$INPUT" | jq -r '.tool_input.subagent_type // .tool_input.description // empty' 2>/dev/null || true)
    DESCRIPTION=$(echo "$INPUT" | jq -r '.tool_input.description // empty' 2>/dev/null || true)
    PROMPT_PREVIEW=$(echo "$INPUT" | jq -r '.tool_input.prompt // empty' 2>/dev/null | head -c 150 || true)

    TITLE="Dispatch: ${SUBAGENT:-unknown}"
    ACTION="${DESCRIPTION:-dispatch}"
    RESULT="${PROMPT_PREVIEW:-}"

    post_activity_entry "hook" "$TITLE" "$ACTION" "$RESULT"
    ;;

  Write|Edit)
    FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
    [ -z "$FILE_PATH" ] && exit 0

    # Only log engagement-related file writes (skip tmp, etc.)
    case "$FILE_PATH" in
      *engagements/*|*findings.md|*scope.json|*auth.json)
        SHORT_PATH=$(echo "$FILE_PATH" | sed 's|.*/engagements/|engagements/|')
        post_activity_entry "hook" "$TOOL_NAME" "file=${SHORT_PATH}" ""
        ;;
    esac
    ;;

  apply_patch)
    FILES=$(echo "$INPUT" \
      | jq -r '.tool_input.command // empty' 2>/dev/null \
      | sed -nE 's/^\*\*\* (Add|Update|Delete) File: //p' \
      | sort -u \
      | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = ", " } END { if (sep != "") print "" }' \
      2>/dev/null || true)
    [ -z "$FILES" ] && FILES="unknown files"
    RESULT=$(tool_response_text | head -c 300 || true)
    post_activity_entry "hook" "apply_patch" "files=${FILES}" "$RESULT"
    ;;

  mcp__*)
    ARG_PREVIEW=$(echo "$INPUT" | jq '.tool_input // {}' 2>/dev/null | json_preview 300)
    RESULT=$(tool_response_text | head -c 300 || true)
    post_activity_entry "hook" "$TOOL_NAME" "mcp args=${ARG_PREVIEW}" "$RESULT"
    ;;

  *)
    # Skip Read, Glob, Grep, WebFetch — too noisy for engagement log
    exit 0
    ;;
esac

exit 0
