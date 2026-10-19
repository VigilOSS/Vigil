---
name: vigil-resume
description: Re-hydrate the engagement's generated operator role in a new session on an existing engagement, or after a restart or handoff
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-resume.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Resume the Vigil engagement in the current directory. The launched session selects one
operator mode; the engagement's enabled tracks do not select a combined role.

**1. Resolve and restore the session role.** Run `vigil engagement mode` as a standalone
command. It resolves the selected mode from the session environment; confirm the reported
`mode:` matches the selected operator seat, and read only the canonical file shown as `prompt:`.
Read this engagement's `AGENTS.md` router first, then the selected prompt in bounded parts,
following its Map of This File. If mode resolution fails, the values disagree, or no mode is
selected, STOP before target-facing work. Start a new client with
`vigil engagement start <key> --mode <mode> --client <client>`; do not infer a role from
`scope.json`, another track's findings, a handoff, or this session's summary. Operator
discipline is the first thing lost at a context boundary, so restore the selected contract
before acting on remembered or persisted state.

Use `$vigil-start` if this engagement has no work in it yet.

**2. Reload the remaining engagement-owned constraints.** Read `ENGAGEMENT.md` plus the additional
files the loaded operator prompt names, and treat them as authoritative over a compaction summary,
handoff, or remembered instruction.

**3. Load optional engagement memory.** Read `RESUME.md` and `COMPACT.md` when present; report
their absence. Also report whether the canonical `ISSUES-AND-ENHANCEMENTS.md` exists, as a pointer
to reusable engagement lessons. Open it only when those lessons are relevant.

Inspect these optional files with the client's read tool. A missing optional file is a normal
result; it does not bypass required role resolution or backend hydration.

**4. Re-establish live state from the backend.** Run each named command separately so a
restricted client can match its `vigil` allowlist and preserve failure status. The backend is
canonical; recollection is not.
For `remediation`, read `PROJECT.md`, run
`vigil remediation -k <key> list`, then `vigil remediation -k <key> show <case-id>`
for the selected case. Follow the case's evidence and approval state in the
remediation operator prompt. For other modes, `agent/rules/resume.md` owns the
brief's drill-downs, orphan reconciliation before new target-facing work, and
bounds that keep resume affordable. Start with the brief:

After step 1 confirms a non-remediation mode, run this simple command and read its
complete output. In remediation mode use only the case commands above.

    vigil assess resume-brief

If a hydration command fails, report the failure and stop; proceeding would restart work blindly.

**5. Re-anchor on the loaded operator seat.** Choose specialists, frame dispatches, judge evidence,
and use the execution boundary named by the active operator prompt. For every finding or incident
claim, separate backend-supported facts from specialist assertions before carrying it forward.

If the operator named a focus in the message, apply it within the active mode and recorded ROE.

Report in the loaded prompt's own output conventions — `[operator]` prefix, numbered choices, phase
tracker — the role and mode you loaded, live work in flight, material changes, relevant missing
memory, and the next action; then continue the active workflow.
