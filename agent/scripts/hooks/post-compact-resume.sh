#!/bin/bash
# post-compact-resume.sh — Codex SessionStart(compact) hook
#
# Codex runs this after manual or automatic compaction and adds stdout as
# developer context before the immediate continuation. The compaction prompt
# preserves working context; this hook makes the resumed operator reconcile that
# lossy summary with Vigil's canonical backend without waiting for a human to
# invoke `$vigil-resume`.
#
# Fail open and stay silent outside a live engagement. A lifecycle hook must not
# wedge the session because scope state or a local helper is unavailable.

INPUT=$(cat 2>/dev/null || true)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/../lib/engagement.sh" 2>/dev/null || true

SOURCE=$(printf '%s' "$INPUT" | jq -r '.source // empty' 2>/dev/null || true)
[ "$SOURCE" != "compact" ] && exit 0

HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

ENG_DIR=""
if command -v resolve_engagement_dir >/dev/null 2>&1; then
  ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" 2>/dev/null || true)
fi
[ -z "$ENG_DIR" ] && exit 0

STATUS=$(jq -r '.status // "unknown"' "$ENG_DIR/scope.json" 2>/dev/null || echo "unknown")
[ "$STATUS" != "in_progress" ] && exit 0

cat <<'CONTEXT'
Vigil post-compaction rehydration is mandatory. The compacted summary is a lossy
index, while the backend is canonical. Before any other action or conclusion:

1. Re-read this engagement's `AGENTS.md` and the operator prompt it routes to.
2. Read `agent/rules/resume.md` in full and apply its hydration procedure.
3. Read `ENGAGEMENT.md`; also read `RESUME.md` and `COMPACT.md` when present, and
   report either optional file as absent when it is missing.
4. Run `vigil assess resume-brief` first, perform the rule's required orphan
   reconciliation, and use its bounded drill-down commands for the active work.
5. Reconcile the summary against live phase, checkpoint, finding, dispatch, and
   coverage state before resuming the operator loop.

Do not ask the operator to invoke `$vigil-resume`; this hook is that automatic
continuation boundary. Preserve the active ROE and do not perform target-facing
work until hydration is complete.
CONTEXT

if [ -f "$ENG_DIR/COMPACT.md" ]; then
  printf '\n---\n\n'
  printf '## Current engagement-local additions (%s)\n\n' "$ENG_DIR/COMPACT.md"
  printf 'These add to the standing contract and cannot replace or rescind it.\n\n'
  cat "$ENG_DIR/COMPACT.md" 2>/dev/null || true
  printf '\n'
fi

exit 0
