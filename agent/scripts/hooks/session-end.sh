#!/bin/bash
# session-end.sh — Claude Code / Codex SessionEnd hook
#
# Records ONE activity receipt per client session, so a session that ends —
# cleanly or otherwise — leaves a durable, timestamped event in the backend.
# It deliberately does not write an operator checkpoint: that table is the
# operator's meaningful save-my-place chain, and an automatic lifecycle receipt
# must not become the current resume note.
#
# WHAT THIS HOOK DELIBERATELY DOES NOT DO
#
# It does not invent an intent narrative. The hook cannot know what the operator
# was doing, what they concluded, or what they intended next. It records only
# client, session, reason, and the backend's timestamp in the ordinary activity
# ledger.
#
# For the same reason it carries no finding, agent, command-run, or artifact
# references. The hook has no way to know which records this session touched.
#
# FAIL-SAFE AND IDEMPOTENT
#
# Always exits 0. A hook that errors on the way out of a session turns a clean
# exit into a confusing one and can wedge a client shutdown; nothing this hook
# records is worth that. Every failure is swallowed to stderr at most.
#
# A marker file (`.hook_session_end_seen` in the engagement dir, the same idiom as
# `.hook_seen_tool_uses` / `.last_hook_log`) makes a repeat event a no-op. Claude
# Code fires SessionEnd on `/clear` and `/resume` as well as on exit, so one
# session legitimately produces more than one event; the key is (client, session,
# reason) so those are distinguishable while a repeat of the same client event is
# not recorded twice. Client is load-bearing when a hook payload supplies neither
# session id nor transcript path and the session component is `unknown-session`.
#
# The marker is claimed BEFORE the backend call, not after. Claude Code 2.1.261
# gives all SessionEnd hooks a shared 1500ms budget by default (raised here by an
# explicit `timeout` in the generated settings), so this process can be killed
# between the backend write and the marker write. Claiming first makes the failure
# mode "a receipt was lost" instead of "a duplicate activity row was appended."
# On a DEFINITE failure (the command ran and returned non-zero) the claim is
# released so a later event can still record.
#
# DURABILITY CAVEAT: a hook is invoked BY the running client, so a hard crash,
# SIGKILL, OOM or host timeout fires nothing at all — and even on a clean exit the
# budget above can cut the call short. This hook is a convenience receipt, NOT
# the resume durability mechanism. The reliable save-my-place write is the
# operator's explicit `vigil assess operator-checkpoint record`.

# No `set -e`: a missing jq / absent backend is expected, not fatal.

INPUT=$(cat 2>/dev/null || true)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/../lib/engagement.sh" 2>/dev/null || true

ASSESS_PY="$SCRIPT_DIR/../assess.py"

HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

ENG_DIR=""
if command -v resolve_engagement_dir >/dev/null 2>&1; then
  ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" 2>/dev/null || true)
fi
[ -z "$ENG_DIR" ] && exit 0

# Only record against a live engagement. A closed or archived engagement must not
# grow new rows because a client happened to be reopened in its directory.
STATUS=$(jq -r '.status // "unknown"' "$ENG_DIR/scope.json" 2>/dev/null || echo "unknown")
[ "$STATUS" != "in_progress" ] && exit 0

SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.session_id // empty' 2>/dev/null || true)
if [ -z "$SESSION_ID" ]; then
  # No session id in the payload: fall back to the transcript path, which is
  # per-session too. If neither is present the marker degrades to one row per
  # engagement per client, which is still bounded.
  SESSION_ID=$(printf '%s' "$INPUT" | jq -r '.transcript_path // empty' 2>/dev/null || true)
fi
[ -z "$SESSION_ID" ] && SESSION_ID="unknown-session"

REASON=$(printf '%s' "$INPUT" | jq -r '.reason // empty' 2>/dev/null || true)
[ -z "$REASON" ] && REASON="unspecified"

# Launchers export a closed client-name set. Collapse anything else to unknown so
# arbitrary environment content never changes the receipt shape.
CLIENT_NAME=""
case "${VIGIL_CLIENT_NAME:-}" in
  claude|codex|goose|kimi|opencode|pi) CLIENT_NAME="$VIGIL_CLIENT_NAME" ;;
esac
NORMALIZED_CLIENT_NAME="${CLIENT_NAME:-unknown}"

# --- Idempotence -------------------------------------------------------------
# One row per (client, session, reason). Keyed on all three so two clients whose
# payloads both degrade to `unknown-session` remain distinct, a `/clear`
# mid-session and the eventual exit remain distinct, and a repeated identical
# event is not recorded twice.
SEEN_FILE="$ENG_DIR/.hook_session_end_seen"
SEEN_KEY="${NORMALIZED_CLIENT_NAME}|${SESSION_ID}|${REASON}"
if [ -f "$SEEN_FILE" ] && grep -Fxq "$SEEN_KEY" "$SEEN_FILE" 2>/dev/null; then
  exit 0
fi

ACTION="client=${NORMALIZED_CLIENT_NAME} session=${SESSION_ID} reason=${REASON}"
RESULT="Resume from the current operator checkpoint and authoritative backend state."

# The engagement is selected by the EXPLICIT --engagement-dir flag on both
# branches. `ENGAGEMENT_DIR` is an artifact-path variable only: per
# agent/scripts/assess/lib/config.py it never selects assessment state, and a
# value that disagrees with the resolved engagement emits a loud warning — which
# is precisely what a silent exit-path hook must not do.
record_activity_receipt() {
  if command -v vigil >/dev/null 2>&1; then
    vigil assess --engagement-dir "$ENG_DIR" --actor-kind hook log \
      session-end-hook \
      "Client session ended" \
      "$ACTION" \
      "$RESULT" \
      >/dev/null 2>&1
    return $?
  fi
  # Fallback: exec assess.py DIRECTLY, never via `python3`. It is a PEP 723
  # script whose `#!/usr/bin/env -S uv run --script` shebang resolves its inline
  # dependency set; `python3 assess.py` bypasses uv and fails to import them.
  if [ -x "$ASSESS_PY" ]; then
    "$ASSESS_PY" --engagement-dir "$ENG_DIR" --actor-kind hook log \
      session-end-hook \
      "Client session ended" \
      "$ACTION" \
      "$RESULT" \
      >/dev/null 2>&1
    return $?
  fi
  return 2
}

# Claim the slot before calling out (see the idempotence note in the header).
printf '%s\n' "$SEEN_KEY" >> "$SEEN_FILE" 2>/dev/null || true

record_activity_receipt
record_status=$?
if [ "$record_status" -ne 0 ]; then
  # Definite failure: the command ran and returned non-zero, or no runner was
  # available at all. Release the claim so a later event can still record.
  if [ -f "$SEEN_FILE" ]; then
    if released=$(grep -Fxv "$SEEN_KEY" "$SEEN_FILE" 2>/dev/null); then
      printf '%s\n' "$released" > "$SEEN_FILE" 2>/dev/null || true
    else
      : > "$SEEN_FILE" 2>/dev/null || true
    fi
  fi
  echo "session-end.sh: activity receipt not recorded (backend unavailable or verb missing)" >&2
fi

exit 0
