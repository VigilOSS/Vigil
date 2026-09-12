---
description: Open an authorized engagement — adopt its generated operator role and run that workflow from the top
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/vigil-start.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

Open the authorized Vigil engagement in the current directory. The engagement's generated
operator contract decides whether this is a web/red, code, combined, Android, or blue workflow;
do not choose a role from this command's name.

**1. Adopt the engagement's operator role.** Read this engagement's `AGENTS.md` first, follow
its pointer to the canonical operator prompt, and read that prompt in full. Adopt the exact
operator identity, workflow, phases, execution boundaries, and approval gates it defines before
interpreting any engagement state. This command supplies startup mechanics, not a competing
operator doctrine.

**2. Check whether this is actually a start.** A fresh start over live backend state can
duplicate ownership and repeat completed work.

Use `/vigil-resume` if this engagement is already under way.

!`vigil assess resume-brief 2>&1`

If the brief shows findings, dispatched agents, or progress beyond the loaded workflow's first
phase, report that the engagement is in progress and switch to `vigil-resume`. If the backend is
empty or the engagement is new, continue.

**3. Load engagement-owned constraints.** Read `ENGAGEMENT.md`, then `scope.json`, plus the
additional files required by the operator prompt you loaded. Engagement-owned ROE and scope are
authoritative. Optional files may be absent on a new engagement.

**4. Apply only the guidance for the loaded mode.** The loaded operator prompt decides the mode.
For `both`, use the Combined section rather than treating either single-track section as the whole
engagement.

### Web/red mode

Treat the hosts in `scope.json` as the hard target boundary. Read `exploit_policy` from that file
instead of assuming it:

!`jq -r '.exploit_policy // "unset"' scope.json 2>/dev/null || echo unset`

On `pause` or `selected`, stop at proof of reachability and obtain the approval defined by the
operator contract before exploit work. On `full_send`, proceed within scope. Treat a missing or
unknown value as `pause` and report that choice. Route target tooling through
`vigil assess kali` as the web/red operator prompt directs.

### Code mode

Use the repository, sealed-source, generation, and dispatch boundaries named by the loaded code
operator prompt. Open the code workflow's first phase and use its source-analysis helpers; network
work and live validation occur only where that prompt and the engagement's ROE authorize them.

### Combined mode

Run the web/red and code workflows together as the loaded operator prompt directs. Apply the web
hosts and `exploit_policy` boundary to target-facing work, route that work through
`vigil assess kali`, and apply the repository, sealed-source, generation, and source-analysis
boundaries to code work. Keep `current_phase` and `code_phase` as separate track state; neither
track's progress or completion stands in for the other.

### Android mode

Begin from the declared APK/AAB artifact or package and load
`agent/skills/android-app-security/SKILL.md`. Static artifact analysis is not target-facing. Device,
emulator, and live backend work must stay within the loaded operator contract and engagement ROE;
an endpoint discovered in the app is not authorization. Admit each authorized live API host with
`vigil engagement add-host <engagement-key> <host>` before sending it traffic. During the initial
artifact `ingest` state, use the Android skill's coverage checklist because there is no separate
Android readiness verb; after entering a canonical web-core phase, use
`vigil assess check-phase-readiness --phase <active-web-phase>` for that phase.

### Blue mode

Use the tenant, platform, evidence, containment-proposal, and approval boundaries named by the
loaded blue operator prompt. Open the blue workflow's first phase and load the engagement's tenant
references before dispatching investigation work.

**5. Take the loaded operator seat.** Choose specialists, frame dispatches, judge evidence, and
record durable state through the surfaces named by that operator prompt. Dispatch in parallel where
its phase permits and give substantial work enough scope to go deep.

Additional context from the operator (may be empty): $ARGUMENTS

Report the operator role and mode you loaded, the opening phase, the applicable approval boundary,
and the lanes you are about to dispatch; then begin.
