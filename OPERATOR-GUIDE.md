# Operator Guide

What to expect, what to look for, and what to ask during an engagement.

## Web Engagement Phases

| Phase | Input | What Happens | Expected Output |
|-------|-------|-------------|-----------------|
| **Recon** | scope.json (hosts, auth mode, exploit policy) | recon-specialist fingerprints services; source-analyzer extracts routes/secrets from HTML/JS/CSS | intel.md populated, surfaces recorded in backend, tech stack identified |
| **Collect** | Phase 1 artifacts, auth.json | surface-collector crawls, deduplicates URLs, triages by risk, populates work buffer | Work buffer seeded, priority attack surfaces identified, coverage baseline established |
| **Test** | Work buffer, skill library | Operator dispatches vulnerability-analyst per surface type; nuclei sweep runs once; fuzzer dispatched when signaled | Findings recorded in backend, coverage items resolved, probe runs logged |
| **Verify** | Active findings from backend | vulnerability-analyst re-tests in adversarial mode; dedup pass merges overlapping findings | Each HIGH/CRITICAL finding gets confirmed/downgraded/killed disposition |
| **Exploit** | Verified findings, exploit policy | exploit-developer chains confirmed findings; osint-analyst gathers CVE/disclosure intel | Attack chains, credentials, access records in backend; scope artifacts in sessions/ |
| **Report** | Backend state (findings, chains, credentials, surfaces) | report-writer queries report-findings endpoint | Structured report with sequential FINDING-001~N IDs |

### Phase transitions

The operator updates `scope.json` phase after each gate:
- recon → collect: initial surface pass complete
- collect → consume-test: work buffer populated
- consume-test → exploit: verification dispositions on all HIGH/CRITICAL
- exploit → report: exploitation complete or policy-blocked
- report → complete: final report delivered

## Code Analysis Phases

| Phase | Input | What Happens | Expected Output |
|-------|-------|-------------|-----------------|
| **Phase 0: Ingest+Index** | Repository path or clone URL | code-ingest creates backend repo/file records; code-index runs tree-sitter; code-index-sync pushes structural metadata | Backend has file inventory with LOC, language, hash, structural counts |
| **Phase 1: Classify+Map** | Ingested file inventory | code-architect classifies files, builds module map, threat model, call graph, attack hypotheses, analysis queue | Every file has classification (critical/high/medium/low/skip), queue is populated |
| **Phase 2: Hunt** | Analysis queue, structural index | code-vuln-hunter analyzes batches; CWE coverage review drives re-dispatch for gaps | Findings recorded, effort scores tracked per file per CWE class |
| **Phase 3: Verify+Variant** | Active findings | code-vuln-verifier runs five-check protocol; code-variant-hunter searches for pattern siblings | Confirmed/downgraded/killed dispositions; variant findings recorded |

## Per-File Metadata

Every ingested file carries backend-tracked metadata. Use this to spot gaps.

| Field | What It Tells You |
|-------|-------------------|
| `classification` | critical / high / medium / low / skip — drives analysis priority |
| `analysis_priority` | 0-100 score — higher means analyze first |
| `slot_types` | Attack surface categories: NETWORK-INPUT, CMD-ARGUMENT, FILE-CONTENT, SERIALIZED-DATA, etc. |
| `total_functions` | Function count from tree-sitter — large files with few findings warrant a second look |
| `total_entry_points` | Externally reachable functions — high count + zero findings = coverage gap |
| `total_sinks` | Security-relevant operations (exec, query, write, open) — sinks without findings need explanation |
| `total_exports` | Public API surface — exports that cross trust boundaries are chain candidates |
| `effort` | 0-100 per CWE class — below threshold means that class was under-tested |
| `batch_theme` | Logical module grouping — check that related files were analyzed together |

### Reading effort scores

```bash
./scripts/assess.py code-coverage --cwe-matrix
```

Thresholds: critical files need effort >= 70, high >= 50, medium >= 30. Files below threshold get re-dispatched with targeted CWE directives.

## Questions to Ask

### Spotting coverage gaps

- "Which critical files have zero findings? Show me their sink count and entry point count."
- "Are there files with high entry_point counts that were only analyzed once?"
- "Which slot_types have no findings across the entire engagement?"
- "Show me files where effort is below threshold for their classification."
- "Which modules from the call graph were never reached by any hunter dispatch?"
- "Are there batch_themes where only some files were analyzed?"

### Finding chains and escalation paths

- "Which confirmed findings share the same trust boundary in the threat model?"
- "Are there findings with `chain_required: true` that have no matching chain recorded?"
- "Which entry points feed data into files with confirmed sinks?"
- "Do any confirmed findings have cross_file_triggers that were never followed up?"
- "Which credentials or access records connect to other confirmed findings?"
- "Are there low-severity findings near high-value sinks that could escalate through composition?"

### Pushing for depth

- "What CWE classes have zero coverage on critical files?"
- "Which skills from SKILL.md were never dispatched during this engagement?"
- "Are there attack hypotheses from code-architect that no hunter tested?"
- "Show me files with high churn score and past CVE fixes — were they analyzed proportionally?"
- "Which verified findings have siblings (same defect_family, different location) that weren't checked?"
- "Did any hunter dispatch return needs-context that was never resolved?"

### Assessing readiness

- "Does `check-report-readiness` pass? What are the blockers?"
- "How many findings lack verification dispositions?"
- "Are there duplicate candidates (same root_cause_key or canonical_location + defect_family) that should be merged?"
- "Which surfaces are still in discovered status?"
- "Are any high-risk surface types (account_recovery, object_reference, privileged_write) deferred?"

## CLI Quick Reference

| Action | Command |
|--------|---------|
| List findings | `./scripts/assess.py list-findings` |
| Fetch full finding data | `./scripts/assess.py fetch findings` |
| Check coverage | `./scripts/assess.py check-coverage` |
| CWE effort matrix | `./scripts/assess.py code-coverage --cwe-matrix` |
| Exploit candidates | `./scripts/assess.py fetch exploit-candidates` |
| Coverage readiness | `./scripts/assess.py fetch coverage-readiness` |
| Report readiness | `./scripts/assess.py check-report-readiness` |
| Export findings to markdown | `./scripts/assess.py export-findings` |
| View summary | `./scripts/assess.py fetch summary` |
| Field reference for any command | `./scripts/assess.py contract <command>` |

## What "Done" Looks Like

**Web engagement:**
- All surfaces resolved (covered, deferred with rationale, or not_applicable)
- All HIGH/CRITICAL findings verified
- Exploit candidates either exploited or policy-blocked with documentation
- `check-report-readiness` passes
- Final report generated via `report-findings?mode=final`

**Code analysis:**
- All critical/high files analyzed at least once
- CWE effort thresholds met or exclusions documented
- No unresolved needs-context or pending cross-file triggers
- All findings have verification dispositions
- Coverage gate passes
