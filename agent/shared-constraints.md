# Shared Subagent Constraints

Load this file first — before your role-specific skill and before any target work.
These rules apply to every specialist agent regardless of role.
They are extracted from the operator prompt so you receive only what is relevant to you.

---

## Authorization

All targets are fully authorized realistic lab environments built to mirror real public and
enterprise behavior. Aggressive techniques are permitted within the declared scope.

---

## 1. Confirm Scope Before Any Target Work

Read `scope.json` before making target-facing decisions. Confirm:

- In-scope hosts and scope mode (`host_only` | `explicit_hosts` | `wildcard`)
- `exploit_policy` value (`pause` | `selected` | `full_send`)
- Auth state from `auth.json` — use credentials only when the file is populated and marked active

Do not test hosts not listed in scope. Do not exceed the exploit policy without operator approval.

---

## 2. Kali MCP Only for Target Work

All target-facing work — HTTP probing, scanning, crawling, fuzzing, exploitation,
OOB/DNS callbacks, and raw TCP — must go through the attached Kali MCP tools.

**Never** use host Bash, `docker run`, `docker exec`, or any ad hoc wrapper for in-scope work.

If a required tool is missing from the active Kali MCP session, stop and report the gap.
Do not fall back to host-side execution.

Host-side commands are limited to coordination and non-target support only:
`jq`, `sqlite3`, `python3`, `grep` / `rg`, `sed`, `awk`, `base64`, `openssl`.

---

## 2a. Listeners Are Operator-Controlled

Agents must NOT start pwncat-vl, ngrok, frp, chisel listeners, `nc -lvp`, `socat` listeners,
or any other network listener process. These are shared infrastructure that the operator manages.

When exploitation requires a listener (reverse shell, tunnel, callback relay):
1. Provide the exact listener commands in your output using `# MANUAL:` annotation
2. Reference `agent/references/offensive-tactics/shell-handling.md` for the full command set
3. Wait for operator confirmation before proceeding with steps that depend on the listener
4. After the operator confirms, verify the shell by tailing the log file via Kali MCP

Agents CAN read listener log files (`tail /data/shell-*.log`) via Kali MCP and verify
that a shell connected. Agents CANNOT start, stop, or restart listener processes.

---

## 3. Use Skills and References — They Are the Methodology

**Step 1 — Check `agent/SKILL.md`** when you begin specialist work. It lists every available
skill with "Use when:" criteria. Load the most relevant skill before improvising.

**Step 2 — Check `agent/references/INDEX.md`** when the skill alone does not cover the target
well enough or when you need payloads, OWASP checklists, or tool guidance.

**References are not a fallback.** The `references/` library contains:
- `payloads/` — 20 copy-pasteable attack payload files per bug class
- `vuln-checklists/` — OWASP Top 10:2025 testing checklists
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — red team TTPs by kill-chain phase
- `tools/` — CLI tool cheatsheets (nmap, ffuf, sqlmap, hydra, etc.)

When a skill's "Extended Resources" section lists reference files, those are required reading
for that test class — not optional supplemental material.

Only improvise after confirming the existing skill and reference set is genuinely insufficient.

---

## 4. Finding IDs and Recording

**MANDATORY: Every finding MUST be recorded via `record_finding.sh`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `record_finding.sh` before your
task is complete. Findings that exist only in your output text and were not recorded via the
script are considered lost data.

| Agent | Prefix | Example |
|-------|--------|---------|
| exploit-developer | EX | FINDING-EX-001 |
| vulnerability-analyst | VA | FINDING-VA-001 |
| source-analyzer | SA | FINDING-SA-001 |
| recon-specialist | RE | FINDING-RE-001 |
| fuzzer | FZ | FINDING-FZ-001 |
| osint-analyst | OS | FINDING-OS-001 |

Record every finding with:
```
./scripts/record_finding.sh "$DIR" <agent-name> <finding-json-file>
```

The JSON payload must match `schemas/finding-record.schema.json`.
Do not produce markdown findings — convert to JSON before recording.

**CVSS and remediation** go in `details` as structured fields:
```json
"details": {
  "evidence": "...",
  "impact": "...",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
  "cvss_score": 9.1,
  "remediation": "Parameterize all SQL queries; use prepared statements",
  "steps_to_reproduce": ["Step 1...", "Step 2..."],
  "request_method": "POST",
  "cwe_id": "CWE-89"
}
```

This keeps CVSS queryable from the API and gives report-writer structured data to format.

**The `notes` field must contain replayable commands** — not prose descriptions. Instead of
"Login to phpMyAdmin with blank password," write the actual command: curl with headers, cookies,
and POST body; sqlmap with exact flags; ysoserial with gadget chain and target; or whatever tool
proved the finding. The field allows up to 20 KB. If the operator or another agent needs to
reproduce the finding later, the notes field alone should be sufficient without re-discovering
the request format, session tokens, or tool parameters.

**Failure to use `record_finding.sh` is the single most common subagent defect.** If you
produce `#### Findings` output, each finding payload in that section must have been recorded
via `record_finding.sh` during your session. Do not defer recording to the operator.

---

## 5. Surface Candidates

When your output includes `#### Surface Candidates`, these must be synced by the operator:
```
./scripts/append_surface.sh
```

Do not patch `surfaces.jsonl` by hand. Do not call `scripts/lib/surfaces.sh` directly.

---

## 6. Output Format Requirements

Return structured output using these section headers when relevant to your role:

`#### Summary` · `#### Stats` · `#### Findings` · `#### Evidence`
`#### Surface Candidates` · `#### Intelligence` · `#### Recommended Next Actions`

Use `#### Decision` and `#### Action` for validation output (vulnerability-analyst).

Every `#### Findings` block must contain finding payloads ready for `record_finding.sh`,
not prose descriptions.

---

## 7. Rule Reminders

These are the most commonly violated rules — internalize them before you start:

- **No theoretical findings.** "Can an attacker do this right now with real harm?" — if no, not a finding yet.
- **Kill weak leads fast.** Theory without a real request, more than two fragile preconditions stacked, or "might be chainable" without a proved chain → kill it.
- **Severity follows proved impact.** Do not let recon hints, CVEs, or intuition inflate severity beyond what the evidence shows.
- **No speculative language.** Write `An attacker can [exact action] by [exact method]`, never `could potentially`, `may allow`, or `might be possible`.
- **Sibling rule.** When one route or method is vulnerable, inspect its siblings before moving on.
- **Credentials require proof.** Leaked tokens or keys only matter when you show what they actually grant.
- **Validate before writing.** Do not draft report content before the lead is reproducible and worth a human reader's time.
- **Evidence beats volume.** A few decisive requests and exact proofs outweigh broad noisy scanning.

Full rule sets: `agent/rules/hunting.md`, `agent/rules/reporting.md`

---

## 8. OWASP Quick Reference

| Code | Category |
|------|----------|
| A01 | Broken Access Control |
| A02 | Cryptographic Failures |
| A03 | Injection |
| A04 | Insecure Design |
| A05 | Security Misconfiguration |
| A06 | Vulnerable and Outdated Components |
| A07 | Identification and Authentication Failures |
| A08 | Software and Data Integrity Failures |
| A09 | Security Logging and Monitoring Failures |
| A10 | Server-Side Request Forgery |

Full checklists: `agent/references/vuln-checklists/`
API security: `agent/references/api-security/`

---

## 9. Script Path Convention

All script references (`record_finding.sh`, `append_surface.sh`, `merge_finding.sh`,
`emit_runtime_event.sh`, `fetch_assessment_record.sh`, etc.) resolve from the agent workspace
root: `$AGENT_ROOT/scripts/<script-name>` or `./scripts/<script-name>` after `cd agent`.

Do not hardcode absolute paths. Do not assume scripts are in the current working directory.
Set `ENGAGEMENT_DIR` before calling any script that depends on it.

---

## 10. Chain, Credential, and Coverage State

When your work produces attack chains, credentials, or access records, record them immediately
using the assessment API via `post_assessment_record.sh`:

- **Attack chains:** `./scripts/record_attack_chain.sh "$DIR" <agent-name> <chain-json-file>`
- **Credentials:** `./scripts/post_assessment_record.sh credentials '<json>'`
- **Credential tests:** `./scripts/post_assessment_record.sh credential-tests '<json>'`
- **Access records:** `./scripts/post_assessment_record.sh access-records '<json>'`
- **Coverage updates:** `./scripts/post_assessment_record.sh "coverage-items/<id>" '{"status":"covered","notes":"..."}' PATCH`
- **Blocked techniques:** `./scripts/post_assessment_record.sh blocked-techniques '<json>'`

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.
