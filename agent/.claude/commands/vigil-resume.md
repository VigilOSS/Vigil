---
description: Re-hydrate the engagement's generated operator role after compaction, restart, or handoff
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-resume.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Resume the Vigil engagement in the current directory. Its generated operator contract decides
whether the role is web/red, code, combined, Android, or blue; current context and prior summaries
do not.

**1. Adopt the engagement's operator role.** Read this engagement's `AGENTS.md` first, follow
its pointer to the canonical operator prompt, and read that prompt in full. Adopt the exact
operator identity, workflow, phases, execution boundaries, and approval gates it defines before
acting on remembered or persisted state. Operator discipline is the first thing lost at a context
boundary, so the generated contract must be restored before hydration.

Use `/vigil-start` if this engagement has no work in it yet.

**2. Reload engagement-owned constraints.** Read `ENGAGEMENT.md`, then `scope.json`, plus the
additional files required by the operator prompt you loaded. Treat those files as authoritative
over a compaction summary, handoff, or remembered instruction.

**3. Apply only the guidance for the loaded mode.** The loaded operator prompt decides the mode.
For `both`, use the Combined section and restore both tracks.

### Web/red mode

Reconfirm the hosts in `scope.json`, current `exploit_policy`, authentication material, target
profile, and severity model before resuming web/red dispatches. Use `vigil assess kali` only as
the loaded web/red operator contract directs.

### Code mode

Reconfirm the selected repository, current source generation, sealed snapshot, outstanding code
queues, and coverage obligations named by the loaded code operator prompt. Resume from backend
generation and lease state rather than from paths remembered before the context boundary.

### Combined mode

Restore both independent tracks. Reconfirm the web hosts, `exploit_policy`, auth and target profile
before target-facing work through `vigil assess kali`; separately reconfirm repositories, source
generation, sealed snapshots, code queues, and coverage obligations. Read both `current_phase` and
`code_phase`, and never infer that progress or completion on one track settles the other.

### Android mode

Reconfirm the declared APK/AAB artifact or package, its version/hash, dynamic mode, device or
emulator boundary, and the Android skill's outstanding static and dynamic coverage. Static artifact
analysis is not target-facing. Treat discovered endpoints as leads, not authorization; confirm each
live API host was admitted with `vigil engagement add-host <engagement-key> <host>` before sending
traffic. At the initial artifact `ingest` state, resume from the Android skill's coverage checklist;
in a canonical web-core phase, refresh that phase with
`vigil assess check-phase-readiness --phase <active-web-phase>`.

### Blue mode

Reconfirm the tenant, platforms, tenant references, open investigation lanes, and any pending
containment proposal or approval named by the loaded blue operator prompt. Resume from recorded
evidence and decisions rather than narrative memory.

**4. Load optional engagement memory named by the active mode.** Inspect the files below, then read
the ones that exist and are relevant to the loaded operator contract. Missing optional files are
not errors; report which relevant ones were absent.

!`for f in RESUME.md TASKS.md PROFILE.md SEVERITY-MODEL.md AUTH.md COMPACT.md; do if [ -f "$f" ]; then printf 'present  %-20s %s bytes\n' "$f" "$(wc -c < "$f" | tr -d ' ')"; else printf 'absent   %s\n' "$f"; fi; done`

**5. Re-establish live state from the backend.** The backend is canonical; recollection is not.

The brief is the bounded core hydration: it already carries your operator checkpoint, the finding
queues, stale dispatches, handoff gaps, and the newest dispatch and handoff rows. Read it first,
then pull only the sections it tells you that you need. Capped lists print `… showing N of M` —
read the M before assuming you have the whole picture, and page rather than widening the default.

!`vigil assess resume-brief 2>&1 || true`

Drill down from the brief, not by re-listing everything. Each of these narrows or pages:

    vigil assess resume-brief --finding <slug>      # one finding's context
    vigil assess resume-brief --agent-id <id>       # one dispatch's handoff detail
    vigil assess resume-brief --q <topic>           # command and artifact context for a topic
    vigil assess agent list --status in-progress    # add --limit N when the roster is long
    vigil assess finding list --status active --limit 25 [--offset N]
    vigil assess finding list --severity <sev> | --slug <slug> | --root-cause <slug>
    vigil assess operator-checkpoint show

Prefer a narrowed query over a full listing: `finding list` defaults to `--limit 100` at roughly
twenty fields a row, and resume runs when context is scarcest. Nothing here is off limits — page
through as far as you need — but pull it because the brief pointed at it, not by reflex.

A checkpoint's intent is the operator's prior **save my place** note, not verified evidence. The
automatic session-end hook writes a separate activity receipt and never supersedes that checkpoint.
If a hydration command fails, report the failure and stop; proceeding would restart work blindly.

**6. Re-anchor on the loaded operator seat.** Choose specialists, frame dispatches, judge evidence,
and use the execution boundary named by the active operator prompt. For every finding or incident
claim, separate backend-supported facts from specialist assertions before carrying it forward.

Operator focus for this resume (may be empty): $ARGUMENTS

Report the role and mode you loaded, live work in flight, material changes, relevant missing memory,
and the next action; then continue the active workflow.
