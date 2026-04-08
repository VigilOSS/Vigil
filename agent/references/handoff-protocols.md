# Agent Handoff Protocols

Detailed rules for how each agent's output flows to the next through the operator.

## Skill Passing Protocol

Every handoff specifies **which skill the next agent should load**. The operator is responsible for including
this in the dispatch context. Each agent's `## Handoffs` section names the specific skill or skill-selection
rule for downstream agents.

General rule: use the "Use when:" lines in `agent/SKILL.md` to select the right skill when the handoff says
"bring the matching vuln-class skill" or "bring the skill matching the finding class."

## RECON-SPECIALIST → next agents

recon outputs: endpoint list, technologies, JS file URLs, parameters, surface candidates, **coverage gaps**

Operator does:
1. **Read `#### Coverage Gaps` first** — this drives the Recon Coverage Gate decision. If material gaps exist, re-dispatch recon-specialist with a targeted objective and specific skill before proceeding. See Phase 1 in the operator core prompt for the full gate checklist and re-dispatch recipes.
2. Pass JS file URLs → dispatch source-analyzer — **bring `agent/skills/source-analysis/SKILL.md`**
3. Import ALL endpoints → `assess.py ingest-endpoints` → orchestrator backend state (with the local queue only as transient batching)
4. Record technology stack → durable finding/state update + intel.md
5. Turn auth boundaries, framework clues, and proxy hints into explicit hypotheses for exploit or source-analysis follow-up
6. Requestable endpoints, object references, auth inconsistencies → dispatch vulnerability-analyst — **bring the vuln-class skill from `agent/SKILL.md` matching the candidate surface**
7. If obvious vulns found (default creds, open admin) → dispatch exploit-developer directly — **bring `agent/skills/auth-bypass/SKILL.md`** or the relevant skill for the specific path

## SOURCE-ANALYZER → work buffer + findings

source outputs: new API endpoints, routes, secrets/tokens, config objects, **coverage gaps**

Operator does:
1. **Read `#### Coverage Gaps` first** — if JS analysis was incomplete (files behind auth, opaque minification), decide whether to re-dispatch source-analyzer with additional context before proceeding.
2. New requestable endpoints → `echo ... | ./scripts/assess.py ingest-endpoints "$DIR/cases.db" source-analysis`
3. Secrets/tokens → durable findings immediately (HIGH/MEDIUM) + credential backend record with full secret value + intel.md Credentials table for preview/reference only
4. API routes, object references, mutation paths → dispatch vulnerability-analyst — **bring the vuln-class skill from `agent/SKILL.md` matching the candidate** (e.g., `idor-testing` for object refs, `sqli-testing` for query params)
5. Parameter names, format hints, upload paths → dispatch fuzzer — **bring `agent/skills/parameter-fuzzing/SKILL.md`**
6. Exploitable secrets or high-confidence abuse paths → dispatch exploit-developer — **bring the skill matching the specific finding class**

## VULNERABILITY-ANALYST → exploit-developer / fuzzer

### During CONSUME & TEST:

vuln-analyst returns: prioritized findings (HIGH/MEDIUM/LOW), test commands, FUZZER_NEEDED blocks

Operator does:
1. HIGH/MEDIUM confidence → IMMEDIATELY dispatch exploit-developer with finding slug(s) and objective — **bring the skill matching the finding class** (e.g., `agent/skills/ssrf-testing/SKILL.md` for SSRF, `agent/skills/idor-testing/SKILL.md` for IDOR, `agent/skills/xss-testing/SKILL.md` for XSS). The agent self-serves the full endpoint map, surfaces, and coverage gaps from the backend via `assess.py fetch` — do not pre-filter B candidates (chain-target endpoints) for it.
2. LOW confidence → record as durable draft finding, do NOT dispatch yet
3. FUZZER_NEEDED → dispatch fuzzer — **bring `agent/skills/parameter-fuzzing/SKILL.md` or `agent/skills/directory-fuzzing/SKILL.md`** as appropriate, feed results back through vuln-analyst
4. Report-ready findings → dispatch report-writer (only after durable + evidenced + severity-disciplined) — **bring `agent/skills/report-generation/SKILL.md`**

### During EXPLOIT phase:

1. Dispatch exploit-developer with finding slug(s) and objective plus the matching skill. The agent queries the backend for the full engagement landscape (findings, request-variants, surfaces, services, coverage gaps) before building chains.
2. Exploit ALL remaining findings (including LOW and INFO)
3. Identify chains (multiple INFO/LOW → combined HIGH impact)
4. Reassess severity based on actual exploitation

## FUZZER → vuln-analyst / findings

fuzzer outputs: discovered paths, valid parameters, anomalous responses

Operator does:
1. New paths/endpoints → ingest into backend request/service coverage state; use the local queue only if batching is helpful
2. Anomalous responses → dispatch vuln-analyst for analysis
3. Confirmed findings (e.g., valid credentials) → durable findings directly

## EXPLOIT-DEVELOPER → findings + next steps

exploit outputs: CONFIRMED/PARTIAL/FAILED status, extracted data, PoC

Operator does:
1. CONFIRMED → durable finding update with full evidence (HIGH severity)
2. CONFIRMED + credentials / access / credential tests → verify exploit-developer recorded them via the assessment API, then run the credential auto-use workflow (see operator prompt)
3. CONFIRMED + multi-step chain → verify exploit-developer recorded the chain via `assess.py record-chain` and linked the finding steps
4. CONFIRMED + new attack surface → ingest auth-aware variants and retest obligations into backend state
5. PARTIAL → record as MEDIUM, validate partial signals in stages before giving up
6. FAILED → log.md, move to next finding
7. Report-ready → dispatch report-writer — **bring `agent/skills/report-generation/SKILL.md`**
8. Needs OSINT context → dispatch osint-analyst — **bring `agent/skills/osint-recon/SKILL.md`**
9. Exploit branch failed, lead needs retest → dispatch back to vulnerability-analyst — **bring the same vuln-class skill used for the original finding**

## OSINT-ANALYST → operator → exploit-developer

osint-analyst writes intel.md only. Promote intel to findings through the durable backend path when it becomes actionable.

Operator does after completion:
1. Read Intelligence Assessment section
2. HIGH-value CVE + PoC match → dispatch exploit-developer to **validate** against the live target — **bring the skill matching the CVE/finding class from `agent/SKILL.md`**. Do NOT record a finding until exploit-developer confirms exploitability. Version-only CVE matches are intel, not findings (backported patches, missing binaries, and disabled modules routinely invalidate them).
3. Breached credentials with target-specific proof → write finding + dispatch exploit-developer to test access
4. Historical endpoints → ingest into backend coverage state, preserving provenance and auth context
5. MEDIUM/LOW intel without target proof → keep in intel.md only, do not promote to findings

## REPORT-WRITER ← backend API (self-service)

Report-writer queries the backend directly via `assess.py fetch report-findings`, `attack-chains`, `surfaces`, and `summary`. The operator does not need to manually assemble findings context.

Engagement directory path with: scope.json, log.md, findings.md, intel.md, plus canonical orchestrator backend findings, coverage, services, and chain state.

## Cross-Agent Finding Deduplication

When multiple agents report findings against the same endpoint, defect family, or root cause:

1. The operator checks for duplicate `root_cause_key` or overlapping `canonical_location` + `defect_family`
   across all agent findings before dispatching the next phase.
2. Use `./scripts/assess.py merge-finding <source-slug> <target-slug> <reason>` to merge
   the weaker finding into the stronger one. The merge preserves evidence and notes from both.
3. Always merge duplicates before dispatching `report-writer` to ensure `report-findings` returns a clean set.
4. The source finding's status becomes `merged` and is excluded from `report-findings`.

Dedup triggers:
- Same `root_cause_key` across different agent prefixes (e.g., FINDING-VA-001 and FINDING-EX-001)
- Same `canonical_location` + `defect_family` combination
- Operator judgment that two findings describe the same underlying issue

## Wildcard Mode Specifics

- BACKEND-FIRST FINDING WRITE: every finding lands in canonical backend state, then synchronize child's findings.md and parent's findings.md exports
- Parent prefix: `## [sub.domain.com / FINDING-XX-NNN] Title`
- Set ENGAGEMENT_DIR to specific child directory before each operation
