#!/bin/bash
# post-tool-log.sh — Claude Code / Codex PostToolUse hook
# Reads hook JSON from stdin, extracts tool info + agent context, POSTs to the
# orchestrator's /engagements/{key}/activity-entries endpoint.
#
# The backend owns the narrative activity log. This script constructs a
# JSON payload and delegates the HTTP call
# to `vigil assess log`, which centralizes URL resolution, retry, and auth.
#
# Hook JSON fields used:
#   tool_name        — Bash, Write, Edit, Agent, etc.
#   tool_input       — command (Bash), file_path (Write/Edit), prompt+subagent_type (Agent)
#   tool_response    — stdout/stderr object (Claude Bash) or stable response
#                      string/object (Codex Bash/apply_patch/MCP)
#   agent_type       — which subagent is running (only present in subagent context)
#   client_name      — native client namespace (optional)
#   session_id       — native conversation namespace (optional)
#   tool_use_id      — native call identity (optional)
#   occurred_at      — when the call finished, as an ISO-8601 instant (optional;
#                      a queued native logger sends it; without it, or when
#                      `vigil assess log` finds it unusable, the backend dates
#                      the row when it records it)
#   hook_event_name  — PostToolUse

# No set -e: jq/grep returning empty is expected, not an error.

# NUL bytes. A command substitution drops each NUL byte it reads, and bash 5 says so
# on stderr. Every substitution that can read payload bytes drops them itself with
# `LC_ALL=C tr -d '\000'`, after any byte prefix is cut, so the hook stays silent and its
# fields are the bytes the substitution alone would keep.
INPUT=$(LC_ALL=C tr -d '\000')

# --- Ignored tools ---
# Read, Grep, WebFetch and every other tool without a row below are settled from
# the raw payload before the libraries, jq or a claim. Only an unambiguous payload
# is settled here: no \u escape (one could spell the key), and the "tool_name"
# token exactly once, as a key with a plain name. A JSON string cannot hold that
# token unescaped, so it is the payload's own key, or a nested one when the payload
# has none (jq then finds no name and exits too). Every other shape reaches the
# same answer through jq below.
case "$INPUT" in
  *'\u'* | *'"tool_name"'*'"tool_name"'*) ;;
  *)
    if [[ "$INPUT" =~ \"tool_name\"[[:space:]]*:[[:space:]]*\"([A-Za-z0-9_.:-]+)\" ]]; then
      case "${BASH_REMATCH[1]}" in
        Bash | Agent | Write | Edit | apply_patch | mcp__*) ;;
        *) exit 0 ;;
      esac
    fi
    ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/engagement.sh"
# shellcheck source=/dev/null
source "$SCRIPT_DIR/../lib/scope.sh"

ASSESS_PY="$SCRIPT_DIR/../assess.py"

# --- Hook fields ---
# Every field the hook reads is one jq filter, named below. hook_field_filter
# NAME sets HOOK_FILTER to it, HOOK_FIELD_FORM to how jq prints it (raw: `-r`;
# compact: `-c`) and HOOK_FIELD_PREFIX to the leading bytes its consumer keeps
# (empty when the whole value is used).
HOOK_FIELD_NAMES="tool_name agent cwd tool_use_id identity occurred_at command response_text exit_code subagent description prompt file_path mcp_args"
# shellcheck disable=SC2016 # the filters are jq programs, not shell expansions
hook_field_filter() {
  HOOK_FIELD_FORM=raw
  HOOK_FIELD_PREFIX=""
  case "$1" in
    tool_name) HOOK_FILTER='.tool_name // empty' ;;
    agent) HOOK_FILTER='.agent_type // .agent_name // "operator"' ;;
    cwd) HOOK_FILTER='.cwd // empty' ;;
    tool_use_id) HOOK_FILTER='.tool_use_id // empty' ;;
    # Any string, up to a bound that only keeps the logger's argv small;
    # `vigil assess log` judges the value.
    occurred_at) HOOK_FILTER='.occurred_at | strings | select(length <= 4096)' ;;
    identity)
      HOOK_FILTER='[.client_name // $client, .session_id // "legacy", .tool_use_id]'
      HOOK_FIELD_FORM=compact
      ;;
    command) HOOK_FILTER='.tool_input.command // empty' ;;
    # Claude sends a Bash response object; Codex sends a stable response string
    # for Bash/unified exec, apply_patch and MCP.
    response_text)
      HOOK_FILTER='
        .tool_response as $r
        | if ($r | type) == "object" then
            ($r.stdout // $r.output // $r.result // $r.message // ($r | tostring))
          elif $r == null then
            ""
          else
            ($r | tostring)
          end'
      HOOK_FIELD_PREFIX=300
      ;;
    exit_code)
      HOOK_FILTER='
        .tool_response as $r
        | if ($r | type) == "object" then
            ($r.exitCode // $r.exit_code // $r.return_code // empty)
          else
            empty
          end'
      ;;
    subagent) HOOK_FILTER='.tool_input.subagent_type // .tool_input.description // empty' ;;
    description) HOOK_FILTER='.tool_input.description // empty' ;;
    prompt) HOOK_FILTER='.tool_input.prompt // empty'; HOOK_FIELD_PREFIX=150 ;;
    file_path) HOOK_FILTER='.tool_input.file_path // empty' ;;
    mcp_args) HOOK_FILTER='.tool_input // {}'; HOOK_FIELD_FORM=compact; HOOK_FIELD_PREFIX=300 ;;
  esac
}

# One jq process reads every field: each is printed exactly as its own
# `jq -r`/`jq -c` call would print it, NUL-terminated (`--raw-output0`), with a
# kept prefix cut to that many characters, which still holds every byte the
# consumer keeps. The read is used only when it is provably whole: one JSON
# document, one value per field, no NUL inside a value, and jq exiting zero.
# Otherwise (including a jq without --raw-output0) each field runs its own jq
# call, so the rows are the same either way.
HOOK_FIELDS_READ=""
read_hook_fields() {
  local name value expected=0 program
  local -a values=()
  program='def one(f): [try f] | if length == 1 then .[0] elif length == 0 then "" else error("ambiguous hook field") end;'
  for name in $HOOK_FIELD_NAMES; do
    hook_field_filter "$name"
    value="($HOOK_FILTER)"
    [ "$HOOK_FIELD_FORM" = compact ] && value="$value | tojson"
    [ -n "$HOOK_FIELD_PREFIX" ] && value="$value | if type == \"string\" then .[:$HOOK_FIELD_PREFIX] else . end"
    program="$program one($value),"
    expected=$((expected + 1))
  done
  program="$program \"end-of-hook-fields\""
  while IFS= read -r -d '' value; do
    values[${#values[@]}]=$value
  done < <(
    printf '%s' "$INPUT" \
      | jq --raw-output0 --arg client "${VIGIL_CLIENT_NAME:-legacy}" "$program" 2>/dev/null
    printf 'rc=%s\0' "$?"
  )
  [ "${#values[@]}" -eq $((expected + 2)) ] || return 1
  [ "${values[$expected]}" = "end-of-hook-fields" ] || return 1
  [ "${values[$((expected + 1))]}" = "rc=0" ] || return 1
  expected=0
  for name in $HOOK_FIELD_NAMES; do
    printf -v "HOOK_FIELD_$name" '%s' "${values[$expected]}"
    expected=$((expected + 1))
  done
  HOOK_FIELDS_READ=1
}

# hook_field_output NAME prints what the field's own jq call prints, so a
# pipeline over it (`| head -c 300`) sees the same bytes. Only that jq call can
# print a NUL byte (from a \u0000 escape); a field read by read_hook_fields holds none.
hook_field_output() {
  if [ -n "$HOOK_FIELDS_READ" ]; then
    local ref="HOOK_FIELD_$1"
    printf '%s\n' "${!ref}"
    return 0
  fi
  hook_field_filter "$1"
  if [ "$HOOK_FIELD_FORM" = compact ]; then
    printf '%s' "$INPUT" | jq -c --arg client "${VIGIL_CLIENT_NAME:-legacy}" "$HOOK_FILTER" 2>/dev/null
  else
    printf '%s' "$INPUT" | jq -r --arg client "${VIGIL_CLIENT_NAME:-legacy}" "$HOOK_FILTER" 2>/dev/null
  fi
}

# hook_value VAR NAME [ON_JQ_FAILURE] sets VAR to what `$(jq ...)` yields for
# the field: its output without trailing newlines, followed on a separate line by
# ON_JQ_FAILURE when jq exits non-zero.
hook_value() {
  local value
  if [ -n "$HOOK_FIELDS_READ" ]; then
    local ref="HOOK_FIELD_$2"
    value=${!ref}
    while [ "${value%$'\n'}" != "$value" ]; do
      value=${value%$'\n'}
    done
  elif [ $# -ge 3 ]; then
    value=$({ hook_field_output "$2" || echo "$3"; } | LC_ALL=C tr -d '\000')
  else
    value=$(hook_field_output "$2" | LC_ALL=C tr -d '\000')
  fi
  printf -v "$1" '%s' "$value"
}

# hook_field_prefix NAME BYTES prints the field's first BYTES bytes, NUL bytes dropped.
hook_field_prefix() {
  if [ -n "$HOOK_FIELDS_READ" ]; then
    hook_field_output "$1" | head -c "$2"
  else
    hook_field_output "$1" | head -c "$2" | LC_ALL=C tr -d '\000'
  fi
}

read_hook_fields || true

hook_value TOOL_NAME tool_name
[ -z "$TOOL_NAME" ] && exit 0

hook_value AGENT_TYPE agent operator
hook_value HOOK_CWD cwd
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

# Find active engagement directory
ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" || true)
[ -z "$ENG_DIR" ] && exit 0

# Check scope.json status — only log in-progress engagements.
STATUS=$(jq -r '.status // "unknown"' "$ENG_DIR/scope.json" 2>/dev/null || echo "unknown")
[ "$STATUS" != "in_progress" ] && exit 0

# --- Deduplication ---
# Native calls are claimed atomically by client/session/call identity. Bash
# noclobber uses exclusive creation without depending on mkdir utility behavior.
# Flat hashed names keep raw IDs (including slashes/newlines) out of paths.
# Successful claims persist; definite write failures release this process's
# marker for later retry.
# Calls without native identity retain the short command/time fallback.
DEDUP_FILE="$ENG_DIR/.last_hook_log"
hook_value TOOL_USE_ID tool_use_id
NATIVE_CLAIM=""

if [ -n "$TOOL_USE_ID" ]; then
  hook_value IDENTITY identity
  DIGEST=""
  if command -v sha256sum >/dev/null 2>&1; then
    DIGEST=$(printf '%s' "$IDENTITY" | sha256sum 2>/dev/null)
  elif command -v shasum >/dev/null 2>&1; then
    DIGEST=$(printf '%s' "$IDENTITY" | shasum -a 256 2>/dev/null)
  fi
  DIGEST=${DIGEST%% *}
  # Without a valid digest, do not pretend duplicate suppression succeeded.
  # Logging remains best-effort and does not fall back to command-text identity.
  if [[ "$DIGEST" =~ ^[a-f0-9]{64}$ ]]; then
    NATIVE_CLAIM="$ENG_DIR/.hook_tool_use_$DIGEST"
    # Existing directories, symlinks and nonregular objects are already claimed;
    # do not open a FIFO/device. Concurrent hooks create only regular markers.
    # Operator filesystem replacements are outside this protocol (ADR 0019).
    if [ -e "$NATIVE_CLAIM" ] || [ -L "$NATIVE_CLAIM" ]; then
      exit 0
    fi
    (umask 077; set -o noclobber; : > "$NATIVE_CLAIM") 2>/dev/null || exit 0
  fi
fi

# A finish time is forwarded as one `--occurred-at=` word, so a value shaped like
# an option stays the flag's value. `vigil assess log` alone judges it: a value
# that does not date the row is ignored there and the backend dates the row. Only
# a string over 4096 characters stays here, so the logger's argv stays small.
hook_value OCCURRED_AT occurred_at
OCCURRED_AT_ARGS=()
if [ -n "$OCCURRED_AT" ]; then
  OCCURRED_AT_ARGS=("--occurred-at=$OCCURRED_AT")
fi

# post_activity_entry <actor_kind> <title> <action> <result>
# Delegates to vigil assess log so URL resolution, retry, and schema shaping all
# live in one place.
#
# The runner is `vigil` when it is on PATH, and otherwise assess.py executed
# DIRECTLY — never `python3 assess.py`. assess.py is a PEP 723 script whose
# `#!/usr/bin/env -S uv run --script` shebang provisions its inline dependency
# set (psutil, the tree-sitter grammars); invoking it under a bare interpreter
# skips that provisioning. Use the same resolution order as session-end.sh
# so both hooks reach the CLI with its declared dependencies.
#
# `--` ends the options: every field is payload-derived text, and one shaped like
# an option (`-n`, `--help`, `--engagement-dir`) is still that field's value.
#
# Best-effort and SILENT on every path. This fires after each tool call, so a
# diagnostic on failure would be noise on a per-command cadence, and a non-zero
# exit must never turn a successful tool call into a failed one.
post_activity_entry() {
  local actor_kind="$1"
  local title="$2"
  local action="$3"
  local result="$4"

  if command -v vigil >/dev/null 2>&1; then
    if ENGAGEMENT_DIR="$ENG_DIR" \
      vigil assess --engagement-dir "$ENG_DIR" log \
        --actor-kind "$actor_kind" \
        "${OCCURRED_AT_ARGS[@]}" \
        -- \
        "$AGENT_TYPE" \
        "$title" \
        "$action" \
        "$result" \
        >/dev/null 2>&1
    then
      return 0
    fi
    return 1
  fi

  if [ -x "$ASSESS_PY" ]; then
    if ENGAGEMENT_DIR="$ENG_DIR" \
      "$ASSESS_PY" --engagement-dir "$ENG_DIR" log \
        --actor-kind "$actor_kind" \
        "${OCCURRED_AT_ARGS[@]}" \
        -- \
        "$AGENT_TYPE" \
        "$title" \
        "$action" \
        "$result" \
        >/dev/null 2>&1
    then
      return 0
    fi
  fi
  return 1
}

release_dedup_claim() {
  if [ -n "$NATIVE_CLAIM" ]; then
    rm -f "$NATIVE_CLAIM" 2>/dev/null || true
  fi
  if [ -n "${CMD_KEY:-}" ] && [ -f "$DEDUP_FILE" ]; then
    local claimed_key
    claimed_key=$(head -1 "$DEDUP_FILE" 2>/dev/null || true)
    if [ "$claimed_key" = "$CMD_KEY" ]; then
      rm -f "$DEDUP_FILE" 2>/dev/null || true
    fi
  fi
}

post_activity_entry_or_release() {
  post_activity_entry "$@" || release_dedup_claim
  return 0
}

case "$TOOL_NAME" in
  Bash)
    hook_value COMMAND command
    [ -z "$COMMAND" ] && exit 0

    # Skip routine local-only noise; target-facing commands remain auditable.
    case "$COMMAND" in
      cat\ *|ls\ *|git\ *|echo\ *|test\ *|"["*|pwd*)
        exit 0
        ;;
    esac

    SHORT_CMD=$(echo "$COMMAND" | head -c 200)

    # A different native ID is a different call, even with identical command
    # text. Only callers without identity use the historical short window.
    if [ -z "$TOOL_USE_ID" ]; then
      CMD_KEY=$SHORT_CMD
      if [ -f "$DEDUP_FILE" ]; then
        LAST_KEY=$(head -1 "$DEDUP_FILE" 2>/dev/null || true)
        LAST_TS=$(tail -1 "$DEDUP_FILE" 2>/dev/null || echo "0")
        NOW_TS=$(date +%s)
        if [ "$CMD_KEY" = "$LAST_KEY" ] && [ -n "$LAST_TS" ] && [ $((NOW_TS - LAST_TS)) -lt 3 ]; then
          exit 0
        fi
      fi
      printf '%s\n%s\n' "$CMD_KEY" "$(date +%s)" > "$DEDUP_FILE"
    fi

    # Output summary: the first 300 bytes of the tool response.
    OUTPUT_SUMMARY=$(hook_field_prefix response_text 300 || true)
    hook_value EXIT_CODE exit_code

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

    post_activity_entry_or_release "hook" "Bash" "$ACTION" "$RESULT"
    ;;

  Agent)
    hook_value SUBAGENT subagent
    hook_value DESCRIPTION description
    PROMPT_PREVIEW=$(hook_field_prefix prompt 150 || true)

    TITLE="Dispatch: ${SUBAGENT:-unknown}"
    ACTION="${DESCRIPTION:-dispatch}"
    RESULT="${PROMPT_PREVIEW:-}"

    post_activity_entry_or_release "hook" "$TITLE" "$ACTION" "$RESULT"
    ;;

  Write|Edit)
    hook_value FILE_PATH file_path
    [ -z "$FILE_PATH" ] && exit 0

    # Only log engagement-related file writes (skip tmp, etc.)
    case "$FILE_PATH" in
      *engagements/*|*findings.md|*scope.json)
        SHORT_PATH=$(echo "$FILE_PATH" | sed 's|.*/engagements/|engagements/|')
        post_activity_entry_or_release "hook" "$TOOL_NAME" "file=${SHORT_PATH}" ""
        ;;
    esac
    ;;

  apply_patch)
    # NULs go before sed: BSD sed ends a line at one, GNU sed keeps it.
    FILES=$(hook_field_output command | LC_ALL=C tr -d '\000' \
      | sed -nE 's/^\*\*\* (Add|Update|Delete) File: //p' \
      | sort -u \
      | awk 'BEGIN { sep = "" } { printf "%s%s", sep, $0; sep = ", " } END { if (sep != "") print "" }' \
      2>/dev/null || true)
    [ -z "$FILES" ] && FILES="unknown files"
    RESULT=$(hook_field_prefix response_text 300 || true)
    post_activity_entry_or_release "hook" "apply_patch" "files=${FILES}" "$RESULT"
    ;;

  mcp__*)
    ARG_PREVIEW=$(hook_field_prefix mcp_args 300 || true)
    RESULT=$(hook_field_prefix response_text 300 || true)
    post_activity_entry_or_release "hook" "$TOOL_NAME" "mcp args=${ARG_PREVIEW}" "$RESULT"
    ;;

  *)
    # Skip Read, Glob, Grep, WebFetch — too noisy for engagement log
    exit 0
    ;;
esac

exit 0
