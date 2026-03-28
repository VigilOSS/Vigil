# Agent Handoff Protocols

Detailed rules for how each agent's output flows to the next through the operator.

## RECON-SPECIALIST → next agents

recon outputs: endpoint list, technologies, JS file URLs, parameters

Operator does:
1. Pass JS file URLs → dispatch source-analyzer
2. Import ALL endpoints → `recon_ingest.sh` → orchestrator backend state (with the local queue only as transient batching)
3. Record technology stack → durable finding/state update + intel.md
4. Turn auth boundaries, framework clues, and proxy hints into explicit hypotheses for exploit or source-analysis follow-up
5. If obvious vulns found (default creds, open admin) → dispatch exploit-developer directly

## SOURCE-ANALYZER → work buffer + findings

source outputs: new API endpoints, routes, secrets/tokens, config objects

Operator does:
1. New requestable endpoints → `echo ... | ./scripts/recon_ingest.sh "$ENGAGEMENT_DIR/cases.db" source-analysis`
2. Secrets/tokens → durable findings immediately (HIGH/MEDIUM) + `intel-secrets.json` for full values + intel.md Credentials table for preview/reference only
3. Interesting routes → ingest into backend coverage state and optionally the transient local queue for batching
4. Web3/NFT/unusual endpoints → preserve the hypothesis they imply, not just the path list

## VULNERABILITY-ANALYST → exploit-developer / fuzzer

### During CONSUME & TEST:

vuln-analyst returns: prioritized findings (HIGH/MEDIUM/LOW), test commands, FUZZER_NEEDED blocks

Operator does:
1. HIGH/MEDIUM confidence → IMMEDIATELY dispatch exploit-developer with:
   - Vulnerability type, location (endpoint+param), evidence, recommended test, objective
2. LOW confidence → record as durable draft finding, do NOT dispatch yet
3. FUZZER_NEEDED → dispatch fuzzer, feed results back through vuln-analyst

### During EXPLOIT phase:

1. Dispatch exploit-developer with full durable finding state plus the synchronized findings.md export for human readability
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
2. CONFIRMED + credentials → auth.json, login, POST-AUTH RE-COLLECTION
3. CONFIRMED + new attack surface → ingest auth-aware variants and retest obligations into backend state
4. PARTIAL → record as MEDIUM, validate partial signals in stages before giving up
5. FAILED → log.md, move to next finding

## OSINT-ANALYST → operator → exploit-developer

osint-analyst writes intel.md only. Promote intel to findings through the durable backend path when it becomes actionable.

Operator does after completion:
1. Read Intelligence Assessment section
2. HIGH-value CVE + PoC match → write finding + dispatch exploit-developer
3. Breached credentials → write finding + dispatch exploit-developer
4. Historical endpoints → ingest into backend coverage state, preserving provenance and auth context
5. MEDIUM/LOW → record as INFO/draft in durable findings

## REPORT-WRITER ← operator provides

Engagement directory path with: scope.json, log.md, findings.md, intel.md, plus canonical orchestrator backend findings, coverage, services, and chain state

## Wildcard Mode Specifics

- BACKEND-FIRST FINDING WRITE: every finding lands in canonical backend state, then synchronize child's findings.md and parent's findings.md exports
- Parent prefix: `## [sub.domain.com / FINDING-XX-NNN] Title`
- Set ENGAGEMENT_DIR to specific child directory before each operation
