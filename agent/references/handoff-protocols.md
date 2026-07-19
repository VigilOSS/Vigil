---
description: Agent-to-agent handoff rules and expected downstream actions
category: Shared Runtime References
---

# Agent Handoff Protocols

Quick-reference for processing each agent's return output. These rules are subordinate
to the phase docs (`agent/phases/`, via the Phase Index in `operator-core.md`) — agent output is processed within the current
phase, then queued for later phases where appropriate. Exploit-developer dispatch is
governed by `exploit_policy` in scope.json and belongs after Verify (Phase 5), in Phase 6, not earlier phases.

## Closing Sequence Per Specialist

Every specialist writes a structured handoff before its dispatch returns:

```bash
vigil assess agent handoff --from-json <handoff-json>
```

The handoff captures summary, coverage gaps, next steps, runtime issues, working
artifacts, open questions, and role-specific extras. This row is canonical for "what
was done, what's missing, what's next" — schema in
`agent/references/runtime-guides/handoff-schema.md`. The operator pulls a bounded
markdown blob via `vigil assess agent render-handoff <agent-id>` and pastes it into
the next dispatch's prompt.

**Set `handoff_status` on the FINAL handoff.** Specialists MUST set
`handoff_status=ready` when the dispatch's objective is complete and the
operator can close it, or `handoff_status=blocked` when the work cannot
finish (auth expired, scope ambiguity, tool missing, etc.). Intermediate
checkpoints stay at the default `checkpointed`. Without `ready`/`blocked`
on the final handoff, `vigil assess agent close <agent-id>` will refuse to
close the dispatch and the row stays `in-progress` — which then surfaces as
a `stale_dispatch_ready_handoff` or `handoff_gap` blocker in report
readiness.

## Skill Passing Protocol

Every handoff specifies **which skill the next agent should load**. The operator includes
this in the dispatch context. Each agent's `## Handoffs` section names the specific skill
or skill-selection rule. Use the "Use when:" lines from `vigil assess list-skills` to select the right
skill when the handoff says "bring the matching vuln-class skill."

## Phase 1 Returns

### RECON-SPECIALIST

Output: endpoint lists, technologies, JS file URLs, parameters, surface candidates, coverage gaps

1. **Read `#### Coverage Gaps` first** — this drives the Recon Coverage Gate. If material gaps exist, re-dispatch recon-specialist with a targeted objective and specific skill before proceeding. See Phase 1 gate checklist in operator-core.
2. Pass JS file URLs → dispatch source-analyzer (if not already running in parallel) — **bring `agent/skills/source-analysis/SKILL.md`**
3. Record technology stack → durable state update via `vigil assess intel record tech-component <json-file>` (intel_tech_components table)
4. Turn auth boundaries, framework clues, and proxy hints into hypotheses for Phase 4-6

### SOURCE-ANALYZER

Output: new API endpoints, routes, secrets/tokens, config objects, coverage gaps

1. **Read `#### Coverage Gaps` first** — if JS analysis was incomplete (files behind auth, opaque minification), re-dispatch with additional context before proceeding.
2. New requestable endpoints → `vigil assess ingest endpoints source-analysis`
3. Secrets/tokens → durable findings immediately via `vigil assess finding record` + credential backend record via `vigil assess post credentials <credential-json-file>` (assessment_credentials table)
4. API routes, object references, mutation paths, parameter names → queued for Phase 4 dispatch (these enter the work buffer via endpoint ingestion, not via immediate agent dispatch)

### Phase 1 → Phase 2 Transition

After both recon-specialist and source-analyzer return:
1. Verify coverage gaps are resolved or accepted
2. Dispatch surface-collector with Phase 1 endpoint artifacts, targets from scope.json, and credential state (from `vigil auth status`) — **bring `agent/skills/surface-collection/SKILL.md`**

## Phase 2 Returns

### SURFACE-COLLECTOR

Output: priority manifest, work-buffer stats, intelligence, coverage gaps, recorded surfaces and findings

1. Translate each `#### Intelligence` row into a JSON payload and record it via `vigil assess intel record <type> <json-file>` (one call per row). Verify with `vigil assess intel list`.
2. Review `#### Priority Attack Surfaces` for Phase 4 dispatch ordering
3. Inspect work-buffer stats: `vigil assess work-buffer stats`
4. Update scope.json phase to `consume-test`

## Phase 4 Returns (CONSUME & TEST)

### VULNERABILITY-ANALYST

Output: prioritized findings (HIGH/MEDIUM/LOW), test commands, FUZZER_NEEDED signals

1. Record all findings durably via `vigil assess finding record` — this is the immediate obligation
2. Queue live findings for Phase 5 Verify, not exploitation. Verification decides which findings become confirmed, downgraded, killed, or chain-required before exploit work is spent.
3. When a finding is real only as part of a chain, keep it in the normal finding table and set `details.chain_required`, `details.chain_rationale`, and `details.required_followup` via `finding record`'s JSON payload or `vigil assess finding update <slug> --details-inline '{"chain_required": true, "chain_rationale": "...", "required_followup": ["..."]}'`
4. FUZZER_NEEDED → dispatch fuzzer within Phase 4 — **bring `agent/skills/parameter-fuzzing/SKILL.md` or `agent/skills/directory-fuzzing/SKILL.md`**, feed results back through vuln-analyst
5. Mark work-buffer batch done: `vigil assess work-buffer "$DB" done "id1,id2,..."`
6. Continue the Phase 4 consumption loop (steps b–f in `agent/phases/phase-4-consume-test.md`)

### FUZZER

Output: discovered paths, valid parameters, anomalous responses, confirmed findings

1. New paths/endpoints → ingest into backend coverage state via `vigil assess ingest endpoints`
2. Anomalous responses → dispatch vuln-analyst for analysis within Phase 4
3. Confirmed findings (e.g., valid credentials) → durable findings directly via `vigil assess finding record`

## Phase 5 Returns (VERIFY)

### VULNERABILITY-ANALYST IN REVIEW MODE

Output: confirmed, downgraded, disputed, or killed findings with updated evidence

1. Confirmed or downgraded findings remain eligible for later exploit review
2. Killed findings are suppressed from exploit and final report output
3. Chain-only findings stay in the normal finding table and carry `details.chain_required` metadata instead of a special workflow status
4. Duplicate findings are merged before moving into exploit or report readiness

## Phase 6 Returns (EXPLOIT)

Exploit-developer dispatch is gated by `exploit_policy` in scope.json:
- `pause` → present backend exploit candidates to the human, ask which are approved
- `selected` → exploit only the approved target slugs that are still current backend exploit candidates
- `full_send` → dispatch exploit-developer immediately on the current backend exploit candidates

### EXPLOIT-DEVELOPER

Output: CONFIRMED/PARTIAL/FAILED status, extracted data, PoC, chains, credentials

1. CONFIRMED → durable finding update with full evidence
2. CONFIRMED + credentials/access/credential tests → verify exploit-developer recorded them, then run the credential auto-use workflow (see operator-core)
3. CONFIRMED + multi-step chain → verify `vigil assess record-chain` was called and steps are linked
4. CONFIRMED + new attack surface → ingest auth-aware variants and retest obligations
5. PARTIAL → record as MEDIUM, validate partial signals in stages before giving up
6. FAILED → record the result via `vigil assess log exploit-developer "<title>" "<action>" "<result>"` (activity_entries), move to next finding
7. Needs OSINT context → dispatch osint-analyst within Phase 6 — **bring `agent/skills/osint-recon/SKILL.md`**
8. Exploit failed, lead needs targeted re-evaluation → dispatch vulnerability-analyst for a single-finding retest (this is a Phase 6 feedback loop, not a return to the Phase 4 work-buffer consumption loop) — **bring the same vuln-class skill**

### OSINT-ANALYST

Output: backend intel-table updates via `intel record` (technology, CVE, breach, credential intel, people, domains, social, org facts, notes)

1. Read Intelligence Assessment section
2. HIGH-value CVE + PoC match → record via `vigil assess intel record cve <json-file>` and dispatch exploit-developer to **validate** against the live target — **name the matching skill (discoverable via `vigil assess list-skills`) so the operator includes it in the dispatch**. Promote to a finding only after exploit-developer confirms exploitability — version-only CVE matches are intel, not findings, because backported patches and disabled modules routinely invalidate version-only matches.
3. Breached credentials with target-specific proof → record finding + credential via `vigil assess post credentials` + dispatch exploit-developer to test access
4. Historical endpoints → ingest into backend coverage state via `vigil assess ingest endpoints`
5. MEDIUM/LOW intel without target proof → keep in backend intel tables via `intel record` only — do not promote to findings

## Phase 8 (REPORT)

### REPORT-WRITER ← backend API (self-service)

For final reports, run `vigil assess check-phase-readiness --phase report` first. Report-writer queries the backend
directly via `vigil assess finding report --mode final --json` for final output or
`vigil assess finding report --mode draft --json` for interim output, plus `attack-chains`,
`surfaces`, and `summary`. The operator does not pre-assemble findings context.

Before dispatching a final report, resolve readiness blockers so `vigil assess finding report --mode final --json` succeeds:
- Check for overlapping `root_cause_key` or `canonical_location` + `defect_family` across agent findings
- Use `vigil assess finding link <sibling-slug> --root-cause <root-slug>` for intentional root/sibling groups
- Use `vigil assess finding merge <source-slug> <target-slug> "<reason>"` only for true duplicates
- The source finding's status becomes `merged` and is excluded from final report output

After draft generation, dispatch a fresh `report-writer` in review-and-fix QA mode. The QA writer
checks the rendered `report.md` against backend report state and the consolidated post-generation
self-review checklist, fixes report-local issues, and returns `QA PASS` or `QA BLOCKED`. Only publish the
report, mark findings `reported`, and complete the engagement after `QA PASS`.

## Wildcard Mode Specifics

- BACKEND-ONLY FINDING WRITE: every finding lands in the backend via `vigil assess finding record`. No local file sync required.
- Parent prefix: `## [sub.domain.com / XX-NNN] Title`
- Set ENGAGEMENT_DIR to specific child directory before each operation
