# Agent Handoff Protocols

Quick-reference for processing each agent's return output. These rules are subordinate
to the Phase Flow in `operator-core.md` — agent output is processed within the current
phase, then queued for later phases where appropriate. Exploit-developer dispatch is
governed by `exploit_policy` in scope.json and belongs after Verify in Phase 5, not earlier phases.

## Skill Passing Protocol

Every handoff specifies **which skill the next agent should load**. The operator includes
this in the dispatch context. Each agent's `## Handoffs` section names the specific skill
or skill-selection rule. Use the "Use when:" lines in `agent/SKILL.md` to select the right
skill when the handoff says "bring the matching vuln-class skill."

## Phase 1 Returns

### RECON-SPECIALIST

Output: endpoint lists, technologies, JS file URLs, parameters, surface candidates, coverage gaps

1. **Read `#### Coverage Gaps` first** — this drives the Recon Coverage Gate. If material gaps exist, re-dispatch recon-specialist with a targeted objective and specific skill before proceeding. See Phase 1 gate checklist in operator-core.
2. Pass JS file URLs → dispatch source-analyzer (if not already running in parallel) — **bring `agent/skills/source-analysis/SKILL.md`**
3. Record technology stack → durable state update via `aith assess record-intel tech-component <json-file>` (intel_tech_components table)
4. Turn auth boundaries, framework clues, and proxy hints into hypotheses for Phase 3-5

### SOURCE-ANALYZER

Output: new API endpoints, routes, secrets/tokens, config objects, coverage gaps

1. **Read `#### Coverage Gaps` first** — if JS analysis was incomplete (files behind auth, opaque minification), re-dispatch with additional context before proceeding.
2. New requestable endpoints → `aith assess ingest-endpoints "$DIR/cases.db" source-analysis`
3. Secrets/tokens → durable findings immediately via `aith assess record-finding` + credential backend record via `aith assess post credentials <credential-json-file>` (assessment_credentials table)
4. API routes, object references, mutation paths, parameter names → queued for Phase 3 dispatch (these enter the work buffer via endpoint ingestion, not via immediate agent dispatch)

### Phase 1 → Phase 2 Transition

After both recon-specialist and source-analyzer return:
1. Verify coverage gaps are resolved or accepted
2. Dispatch surface-collector with Phase 1 endpoint artifacts, targets from scope.json, auth.json state, and `$DIR/cases.db` path — **bring `agent/skills/surface-collection/SKILL.md`**

## Phase 2 Returns

### SURFACE-COLLECTOR

Output: priority manifest, work-buffer stats, intelligence, coverage gaps, recorded surfaces and findings

1. Translate each `#### Intelligence` row into a JSON payload and record it via `aith assess record-intel <type> <json-file>` (one call per row). Verify with `aith assess list-intel`.
2. Review `#### Priority Attack Surfaces` for Phase 3 dispatch ordering
3. Inspect work-buffer stats: `aith assess dispatch "$DIR/cases.db" stats`
4. Update scope.json phase to `consume-test`

## Phase 3 Returns (CONSUME & TEST)

### VULNERABILITY-ANALYST

Output: prioritized findings (HIGH/MEDIUM/LOW), test commands, FUZZER_NEEDED signals

1. Record all findings durably via `aith assess record-finding` — this is the immediate obligation
2. Queue live findings for Phase 4 Verify, not exploitation. Verification decides which findings become confirmed, downgraded, killed, or chain-required before exploit work is spent.
3. When a finding is real only as part of a chain, keep it in the normal finding table and set `details.chain_required`, `details.chain_rationale`, and `details.required_followup` via `record-finding` or `update-finding`
4. FUZZER_NEEDED → dispatch fuzzer within Phase 3 — **bring `agent/skills/parameter-fuzzing/SKILL.md` or `agent/skills/directory-fuzzing/SKILL.md`**, feed results back through vuln-analyst
5. Mark work-buffer batch done: `aith assess dispatch "$DB" done "id1,id2,..."`
6. Continue the Phase 3 consumption loop (steps b–f in Phase Flow)

### FUZZER

Output: discovered paths, valid parameters, anomalous responses, confirmed findings

1. New paths/endpoints → ingest into backend coverage state via `aith assess ingest-endpoints`
2. Anomalous responses → dispatch vuln-analyst for analysis within Phase 3
3. Confirmed findings (e.g., valid credentials) → durable findings directly via `aith assess record-finding`

## Phase 4 Returns (VERIFY)

### VULNERABILITY-ANALYST IN REVIEW MODE

Output: confirmed, downgraded, disputed, or killed findings with updated evidence

1. Confirmed or downgraded findings remain eligible for later exploit review
2. Killed findings are suppressed from exploit and final report output
3. Chain-only findings stay in the normal finding table and carry `details.chain_required` metadata instead of a special workflow status
4. Duplicate findings are merged before moving into exploit or report readiness

## Phase 5 Returns (EXPLOIT)

Exploit-developer dispatch is gated by `exploit_policy` in scope.json:
- `pause` → present backend exploit candidates to the human, ask which are approved
- `selected` → exploit only the approved target slugs that are still current backend exploit candidates
- `full_send` → dispatch exploit-developer immediately on the current backend exploit candidates

### EXPLOIT-DEVELOPER

Output: CONFIRMED/PARTIAL/FAILED status, extracted data, PoC, chains, credentials

1. CONFIRMED → durable finding update with full evidence
2. CONFIRMED + credentials/access/credential tests → verify exploit-developer recorded them, then run the credential auto-use workflow (see operator-core)
3. CONFIRMED + multi-step chain → verify `aith assess record-chain` was called and steps are linked
4. CONFIRMED + new attack surface → ingest auth-aware variants and retest obligations
5. PARTIAL → record as MEDIUM, validate partial signals in stages before giving up
6. FAILED → record the result via `aith assess log exploit-developer "<title>" "<action>" "<result>"` (activity_entries), move to next finding
7. Needs OSINT context → dispatch osint-analyst within Phase 5 — **bring `agent/skills/osint-recon/SKILL.md`**
8. Exploit failed, lead needs targeted re-evaluation → dispatch vulnerability-analyst for a single-finding retest (this is a Phase 5 feedback loop, not a return to the Phase 3 work-buffer consumption loop) — **bring the same vuln-class skill**

### OSINT-ANALYST

Output: backend intel-table updates via `record-intel` (technology, CVE, breach, credential intel, people, domains, social, org facts, notes)

1. Read Intelligence Assessment section
2. HIGH-value CVE + PoC match → record via `aith assess record-intel cve <json-file>` and dispatch exploit-developer to **validate** against the live target — **bring the matching skill from `agent/SKILL.md`**. Do NOT record a finding until exploit-developer confirms exploitability. Version-only CVE matches are intel, not findings.
3. Breached credentials with target-specific proof → record finding + credential via `aith assess post credentials` + dispatch exploit-developer to test access
4. Historical endpoints → ingest into backend coverage state via `aith assess ingest-endpoints`
5. MEDIUM/LOW intel without target proof → keep in backend intel tables via `record-intel` only — do not promote to findings

## Phase 7 (REPORT)

### REPORT-WRITER ← backend API (self-service)

For final reports, run `aith assess check-report-readiness` first. Report-writer queries the backend
directly via `aith assess fetch "report-findings?mode=final"` for final output or
`aith assess fetch "report-findings?mode=draft"` for interim output, plus `attack-chains`,
`surfaces`, and `summary`. The operator does not pre-assemble findings context.

Before dispatching a final report, resolve readiness blockers so `report-findings?mode=final` succeeds:
- Check for overlapping `root_cause_key` or `canonical_location` + `defect_family` across agent findings
- `aith assess merge-finding <source-slug> <target-slug> "<reason>"`
- The source finding's status becomes `merged` and is excluded from final report output

After draft generation, dispatch a fresh `report-writer` in review-and-fix QA mode. The QA writer
checks the rendered `report.md` against backend report state and the 12-step post-generation
self-review, fixes report-local issues, and returns `QA PASS` or `QA BLOCKED`. Only publish the
report, mark findings `reported`, and complete the engagement after `QA PASS`.

## Wildcard Mode Specifics

- BACKEND-ONLY FINDING WRITE: every finding lands in the backend via `aith assess record-finding`. No local file sync required.
- Parent prefix: `## [sub.domain.com / XX-NNN] Title`
- Set ENGAGEMENT_DIR to specific child directory before each operation
