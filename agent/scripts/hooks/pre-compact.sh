#!/bin/bash
# pre-compact.sh — Claude Code PreCompact hook
#
# Emits the STANDING COMPACTION CONTRACT on stdout so every compaction — manual
# `/compact` and automatic context-window compaction alike — is steered rather
# than left to the client's generic summarizer.
#
# Why a hook and not a pasted prompt: an auto-compaction fires without warning,
# mid-turn, at exactly the moment the operator is not watching. A contract that
# has to be pasted is a contract that is absent when it matters. Registered with
# NO matcher in .claude/settings.json, the hook covers both triggers; the hook
# JSON on stdin carries `trigger: "manual" | "auto"`, which this script reports
# back in the header so the operator can tell from the transcript which one ran.
#
# MECHANISM (verified against the Claude Code 2.1.261 binary, not inferred from
# docs). PreCompact does NOT use the generic "stdout goes to the debug log" path.
# It has a dedicated one: the hook runner collects the trimmed stdout of every
# succeeded, non-blocked PreCompact hook and returns it as `newCustomInstructions`,
# which every compaction call site (manual /compact, auto/reactive, precomputed,
# and the fork/up-to variants) passes to the summarizer as its customInstructions.
# On a manual /compact the operator's own `/compact also keep X` text is MERGED
# with this stdout rather than replacing it. So printing the contract here really
# does steer the summary.
#
# One documented limitation: inside a SUBAGENT context the runner drops
# `newCustomInstructions` and keeps only the blocking decision. This hook
# therefore steers the OPERATOR session's compaction, not a specialist's.
#
# NEVER exit 2 from this script. Exit 2 (or a `decision: "block"` JSON body) is
# how a PreCompact hook BLOCKS compaction outright; a context-window compaction
# that cannot run leaves the session wedged. Emitting nothing is a bad outcome;
# preventing the compaction is a worse one.
#
# An engagement may ADD rules without editing this shared hook by dropping a
# `COMPACT.md` in its engagement directory. It is appended, clearly delimited,
# AFTER the standing contract — additive only; it cannot rescind a standing rule.
# Absent file = no-op.
#
# Codex cannot consume this stdout from PreCompact. Its engagement installer
# renders the standing output into Codex's stable `compact_prompt`, excluding
# mutable COMPACT.md content; the post-compaction hook injects the current local
# additions instead. This script remains the source for both clients' contract.
#
# Fail-safe: this script never blocks a compaction. Every failure path exits 0
# with (at worst) a note on stderr. Compaction proceeding unsteered is bad;
# compaction failing to happen at all is worse.

# No `set -e`: jq being absent or the payload being empty is expected, not fatal.

INPUT=$(cat 2>/dev/null || true)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/../lib/engagement.sh" 2>/dev/null || true

TRIGGER=$(printf '%s' "$INPUT" | jq -r '.trigger // empty' 2>/dev/null || true)
[ -z "$TRIGGER" ] && TRIGGER="unknown"

INCLUDE_ENGAGEMENT_ADDITIONS=$(
  printf '%s' "$INPUT" |
    jq -r 'if .include_engagement_additions == false then "false" else "true" end' \
      2>/dev/null || true
)
[ -z "$INCLUDE_ENGAGEMENT_ADDITIONS" ] && INCLUDE_ENGAGEMENT_ADDITIONS="true"

HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

ENG_DIR=""
if command -v resolve_engagement_dir >/dev/null 2>&1; then
  ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" 2>/dev/null || true)
fi

ENGAGEMENT_TYPE=""
if [ -n "$ENG_DIR" ] && [ -f "$ENG_DIR/scope.json" ]; then
  ENGAGEMENT_TYPE=$(jq -r '.engagement_type // empty' "$ENG_DIR/scope.json" 2>/dev/null || true)
fi

emit_mode_intro() {
  case "$ENGAGEMENT_TYPE" in
    web)
      printf '%s\n' \
        'This summary replaces the working context of a live red-team web engagement.' \
        'Preserve its web phase and the state of every phase-exit pass.'
      ;;
    code)
      printf '%s\n' \
        'This summary replaces the working context of a live source-code security review.' \
        'Preserve the code phase, admitted-file queue, review batches, and readiness debt.'
      ;;
    both)
      printf '%s\n' \
        'This summary replaces the working context of a live combined web and source-code engagement.' \
        'Preserve both the web phase and code phase; neither track may disappear into the other.'
      ;;
    android)
      printf '%s\n' \
        'This summary replaces the working context of a live Android application security engagement.' \
        'Preserve the artifact/package identity and whether dynamic backend hosts are explicitly in scope.'
      ;;
    blue)
      printf '%s\n' \
        'This summary replaces the working context of a live blue incident-response engagement.' \
        'Preserve its incident phase, alert timeline, tenant/platform context, and every containment approval.'
      ;;
    *)
      printf '%s\n' \
        'This summary replaces the working context of a live Vigil engagement. Its mode is' \
        'unavailable here, so do not infer a red, blue, web, or code workflow from this hook;' \
        "re-read scope.json and the engagement's operator prompt after compaction."
      ;;
  esac
}

emit_mode_hydration() {
  case "$ENGAGEMENT_TYPE" in
    web)
      printf '    vigil assess check-phase-readiness --phase report # web report readiness\n'
      ;;
    code)
      printf '    vigil assess code-coverage                       # code-track coverage/readiness\n'
      ;;
    both)
      printf '    vigil assess check-phase-readiness --phase report # web report readiness\n'
      printf '    vigil assess code-coverage                       # code-track coverage/readiness\n'
      ;;
  esac
}

emit_mode_prompt_route() {
  case "$ENGAGEMENT_TYPE" in
    web)
      printf '%s\n' 'For this web engagement, `AGENTS.md` supplies the red-team web operator core.'
      ;;
    code)
      printf '%s\n' 'For this code engagement, follow the `AGENTS.md` routing gate into `agent/operator-core-code.md`.'
      ;;
    both)
      printf '%s\n' "For this combined engagement, follow \`AGENTS.md\` plus \`agent/operator-core-code.md\`'s integration-with-web guidance."
      ;;
    android)
      printf '%s\n' 'For this Android engagement, follow the Android routing branch in `AGENTS.md`; do not infer live-host authorization from the artifact.'
      ;;
    blue)
      printf '%s\n' 'For this blue engagement, `AGENTS.md` is the rendered blue incident operator prompt; do not fall through to the red core loop.'
      ;;
    *)
      printf '%s\n' "Use \`scope.json\` and the engagement's \`AGENTS.md\` routing gate to select the operator contract; do not guess the mode."
      ;;
  esac
}

printf '# Vigil compaction contract (trigger: %s)\n\n' "$TRIGGER"
emit_mode_intro

cat <<'CONTRACT'

Treat this summary as a lossy index into the backend, never as the record itself.

## Write the summary under these headings

Use every heading, in this order. Write `none` under one that is genuinely empty
— an empty section and a forgotten section are indistinguishable to the next
reader, and only one of them is safe.

    ## Scope and ROE
    ## Phase and exit passes
    ## In-flight lanes        (agent id, surface owned, what it was asked to prove)
    ## Claims — verified      (claim + where the evidence lives)
    ## Claims — unverified
    ## Open decisions         (awaiting the user)
    ## Settled decisions      (already made; do not re-litigate)
    ## Auth state

Per-item structure is the point: prose loses the one-lane-per-line shape that
makes "two specialists on one surface" visible at a glance.

## Carry forward verbatim — losing any of these is an incident

- **ROE and scope.** In-scope hosts, out-of-scope hosts, forbidden techniques,
  the exploitation policy, and any standing constraint the user imposed. A
  compaction that drops scope produces an out-of-scope action on the next turn.
- **In-flight dispatch ownership.** Every specialist currently running, what
  surface it owns, and what it was asked to prove. Two specialists sent at one
  surface because the summary forgot the first is the most common post-compaction
  waste.
- **The phase**, and which phase-exit passes have and have not been run.
- **Verified vs unverified status of every claim.** Preserve the distinction
  explicitly and per claim. Never promote "a specialist reported X" to "X" while
  compacting. If the evidence for a claim is not in the summary, the claim is
  unverified in the summary regardless of how it was labelled before.
- **Open decisions awaiting the user**, and decisions the user has already made
  (so they are not re-litigated after the compaction).
- **Credentials, identities and auth state in use.** Reproduce them as they are.
  Vigil does not mask, redact or shape-project operator-facing data (ADR 0019);
  a summary that abbreviates a token to its prefix has destroyed it.

## Safe to drop

- Raw output from any `vigil assess` record/log/ingest call that returned
  success, and raw output whose conclusion is restated later in the transcript.
  It is retrievable; re-reading it is cheap. (Stated as something visible in the
  transcript: you cannot tell from here what reached the backend.)
- Superseded drafts, abandoned hypotheses that were explicitly ruled out, and
  the reasoning that led to a decision already recorded.
- Full file contents that can be re-read on demand.

## After the compaction

Re-hydrate from the BACKEND, not from this summary. Lead with the bounded
core hydration, then drill down only where you need to:

    vigil assess resume-brief                        # core hydration; run this first
    vigil assess operator-checkpoint show            # your own last recorded intent
    vigil assess agent list --status in-progress     # who is running, and what they own
    vigil assess finding list                        # the real finding set
CONTRACT
emit_mode_hydration
cat <<'CONTRACT'

A checkpoint's intent text is UNVERIFIED operator intent, not a finding — read it
as "what I was about to do", never as established fact.

The backend is canonical. A lane you remember may have returned; a lane you do
not remember may still be running. Then reload the operator prompt from the
engagement's `AGENTS.md` before acting.
CONTRACT
emit_mode_prompt_route
cat <<'CONTRACT'
Operator discipline (dispatch instead of probing, the lane budget, the phase-exit
passes) is the first thing that decays after a compaction.
CONTRACT

if [ "$INCLUDE_ENGAGEMENT_ADDITIONS" = "true" ] && \
   [ -n "$ENG_DIR" ] && [ -f "$ENG_DIR/COMPACT.md" ]; then
  printf '\n---\n\n'
  printf '## Engagement-local additions (%s)\n\n' "$ENG_DIR/COMPACT.md"
  printf 'These ADD to the standing contract above. They do not replace or rescind it.\n\n'
  cat "$ENG_DIR/COMPACT.md" 2>/dev/null || true
  printf '\n'
fi

exit 0
