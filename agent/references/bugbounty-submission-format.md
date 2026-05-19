# Bug Bounty Submission Format

Use this format when the operator requests a bug bounty submission (Bugcrowd, HackerOne, or similar platform). Each finding is a standalone submission.

## Copy-paste workflow

The output is designed to map cleanly onto the platform's submission form. The operator takes the produced file and copies each block into the matching platform field:

- **`VRT:` line** → platform's VRT / Vulnerability Category field
- **`Title:` line** → platform's Submission Title field
- **`POC:` file** → upload as attachment on the submission
- **Everything from `### Summary` down to the end of the file** → platform's Description / Body field

The `---` separator exists so the operator can select the entire body block in one contiguous paste without stripping metadata lines. Do not put anything between the separator and `### Summary` that the operator should not paste into the platform.

## Structure

```
**Title:** [Bug Class] in [exact component] allows [attacker role] to [impact]

**VRT:** [Platform taxonomy category path]

**Severity:** [P1-P4]

---

### Summary
[2-4 sentences. First sentence = attacker outcome. Then the code fault. Then what the POC proves.]

### Steps to Reproduce
[Numbered steps. One action per step. No narrative between steps. Include the POC command.]

### Evidence
[Key POC output proving the finding. Annotated with <-- proof markers on critical lines.
Truncated to only the lines that matter. No full tool dumps.
Real customer PII must be redacted — see "PII redaction" below.]

### Attack Scenario
[2-3 sentences. Concrete attacker persona + action + outcome. No theory.]

### Impact
[1-2 sentences. Proven impact only. Quantify by shape/count without exposing raw PII.]

### Remediation
[1-3 items. Primary fix first. One defense-in-depth item at most. No "validate the fix" step.]
```

## Section budgets

These are hard ceilings. A section that exceeds its budget needs to be cut, not wrapped.

| Section | Budget |
|---|---|
| Title | 12 words, single clause |
| Summary | 4 sentences |
| Steps to Reproduce | One sentence per step, no narrative between steps |
| Attack Scenario | 3 sentences |
| Impact | 2 sentences |
| Remediation | 3 items |
| Related Findings (if present) | 1 sentence per cross-reference |
| Deconfliction (if required by program) | 3 lines: researcher ID, source IP, UTC time window |

Sections not in this table (Chain Potential, Defender-positive, Probe Coverage, Architectural Analysis, Fix Validation steps) do not exist in external submissions. If content belongs in one of those categories, it belongs in the internal `report.md`, not the submission.

## Rules

All writing rules from `agent/rules/reporting.md` apply (banned language, active voice, no class definitions, every sentence load-bearing).

### Mandatory fields

- **VRT is mandatory.** Every submission must carry a VRT category path from the platform's taxonomy. An unknown VRT is not an excuse — look it up before submitting. Never leave it blank, "TBD", or "N/A". Bugcrowd uses the VRT at https://bugcrowd.com/vulnerability-rating-taxonomy; HackerOne uses CWE. Pick the most specific category that matches the proved attack.
- **Title must be a single line.** No markdown, no backticks, no internal finding IDs. Use the pattern: `[Bug Class] in [exact component] allows [attacker role] to [impact]`. The title is pasted directly into the platform's title field — anything that looks wrong there is wrong here too.

### PII redaction

A bug bounty submission creates a second copy of the evidence on the platform's infrastructure. Pasting real customer PII exposes those customers a second time without their consent. GDPR/CCPA exposure is non-trivial for the target organization even if the platform is "trusted". Redact before submitting.

- **Never paste raw customer PII** into the submission body, evidence blocks, or screenshots. This covers: full email addresses, phone numbers, case/account/order numbers tied to real users, full names, government IDs, SSNs, addresses, DOBs, payment details, session tokens belonging to real users.
- **Partial masking** is acceptable when shape alone is not convincing: `j***@example.com`, `+1-555-***-4421`, `CASE-12******`. Show enough structure to prove the data is real, not enough to re-identify the customer.
- **Prefer synthetic data.** If the target has a staging tenant, test accounts, or a seed/demo dataset, reproduce the finding against those and use the synthetic PII directly. A clean PoC against a test account beats a redacted PoC against a real account.
- **Internal report vs external submission.** The internal `report.md` may include unredacted evidence under the engagement's authorized scope. External bug bounty submissions must be redacted, because the platform is a third party and the customers whose data is leaked are not parties to the engagement.

### No internal identifiers

Bug bounty submissions are standalone deliverables — nothing inside them should reference this engagement's internal state.

- **No finding slugs** (`VA-003`, `NNN`, any prefix) in the submission body.
- **No engagement keys, engagement directory paths, `$DIR/`, `$ENGAGEMENT_KEY/`, or backend URLs.**
- **No cross-references to other findings in the same engagement** — each submission stands alone. If two findings share a root cause, file two submissions; if one finding genuinely depends on another, describe the dependency in plain English, not via a finding ID.
- **No operator/tool metadata breadcrumbs** — tool run IDs, MCP command IDs, activity log references, `aith assess` invocations.
- **No internal tooling breadcrumbs** — references to alternate reproducers, "bundled" all-in-one scripts, operator convenience wrappers, or `tools/` paths belong in the internal report. The submission points at one POC — the one the triager should run. "Also available at…" creates ambiguity and exposes research-time scaffolding the platform does not need.

### Format-specific

- Each finding is one submission. Do not bundle.
- One POC file per submission. If research produced granular and bundled scripts, attach the single file that proves the finding end-to-end — additional reproducers are operator scaffolding and stay in the internal report.
- The POC must exercise the vendor's code, not reimplemented logic. Import and call their functions. Run their binary. Show their output.
- If end-to-end testing requires infrastructure (LDAP server, SSH host, proxy), document what must be set up manually and what the script does. Use `# SETUP:` comments in scripts for manual prerequisite steps.
- Evidence must come from running the POC, not from reading the source. Code analysis supports the description but does not replace proof.
- Credentials and secrets go in environment variables, never in submission text or script source.

## Pre-submission checklist

Verify every item before handing the submission file to the operator. Any failing item blocks the submission.

**Structure and content**
- [ ] `Title:` is a single line, ≤12 words, no markdown/backticks/finding-IDs, follows the title formula — no sub-clauses, no parenthetical product aliases
- [ ] `VRT:` is populated with a specific platform-taxonomy path (not blank, not "TBD", not "N/A")
- [ ] `Severity:` and CVSS score match proved impact — if write operations were rejected by application-layer validation, `I` is not `H`
- [ ] `---` separator is present so the operator can paste the body in one block
- [ ] Body starts with `### Summary` and the summary leads with attacker outcome in sentence 1
- [ ] Evidence contains no raw customer PII (emails, phone numbers, case/account/SSN values, real names). Exposure is proved by shape and count, with partial masking where needed
- [ ] No internal finding slugs, engagement paths, or tool run IDs anywhere in the body
- [ ] Remediation names a specific technology and control, not generic advice — ≤3 items, no "validate the fix" item

**Human voice — AI tell elimination (Rule 20)**
- [ ] No "Defender-positive", "Dead ends", "Negative findings", or "What was ruled out" section or sub-section exists anywhere in the submission
- [ ] No probe counts, request volumes, or percentile latencies appear anywhere in the submission body
- [ ] Deconfliction (if present) is ≤3 lines: researcher ID, source IP, UTC time window — no per-phase breakdowns, no marker string lists, no rate pledges
- [ ] Attack scenario uses a realistic adversary class, not a cartoonish persona ("student in a dorm room", "script kiddie") — 3 sentences maximum
- [ ] No sentence instructs the reviewer how to interpret, score, or act on the finding (`"please do not treat"`, `"recorded so triage does not re-investigate"`, `"triage can prioritize"`)
- [ ] No section exists outside the defined structure (no Chain Potential, Architectural Analysis, Fix Validation, Related Findings as multi-paragraph blocks)
- [ ] The word "submission" does not appear in the body prose — use "finding" or "report"
- [ ] CWE, CVSS, or VRT that appear in header fields are not restated or justified inside body prose
- [ ] Related findings (if present) are one sentence each at the end of the submission, not multi-paragraph cross-references

## Example

See `agent/references/examples/bugbounty-submission-ldap-injection.md` for a complete example of this format applied to an LDAP injection finding with a working POC.
