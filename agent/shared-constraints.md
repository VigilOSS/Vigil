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

- In-scope hosts from the `hosts` array (includes `*.domain` entries for subdomain enum)
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

## 2a. Listeners, Tunnels & OOB Are Operator-Controlled

Agents must NOT start pwncat-vl, frp tunnels, chisel listeners, `nc -lvp`, `socat` listeners,
interactsh servers, or any other network listener process. These are shared infrastructure that
the operator manages.

When exploitation requires a listener, tunnel, or OOB callback:
1. Provide the exact commands in your output using `# MANUAL:` annotation
2. Reference `agent/references/offensive-tactics/shell-handling.md` for shell listener commands
3. Reference `agent/references/offensive-tactics/frp-tunneling.md` for tunnel exposure and OOB callback setup
4. Wait for operator confirmation before proceeding with steps that depend on the listener/tunnel
5. After the operator confirms, verify connection by tailing log files via Kali MCP

Agents CAN read log files via Kali MCP to check for activity:
- `/data/shell-*.log` — shell session I/O (verify shell connected)
- `/data/oob-server.log` — interactsh callback hits (confirm blind vulns)
- `/data/frpc.log` — tunnel connection status

Agents CANNOT start, stop, or restart listener, tunnel, or OOB processes.

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

Only improvise after confirming the e erence set is genuinely insufficient.

---

## 4. Finding IDs and Recording

**MANDATORY: Every finding MUST be recorded via `assess.py record-finding`.** Never hand-allocate
finding IDs. Never write findings only to markdown. Never skip the recording step. If you
produce a finding in any output section, you MUST also call `assess.py record-finding` before your
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

**Title formula:** `[Bug Class] in [endpoint] allows [attacker role] to [impact] [victim/scope]`
Bad: "IDOR vulnerability found." Good: "IDOR in /api/users/{id} allows anonymous attacker to read any user's PII."

**CVSS↔severity must match:**

| Severity | CVSS range |
|----------|------------|
| critical | 9.0–10.0 |
| high | 7.0–8.9 |
| medium | 4.0–6.9 |
| low | 0.1–3.9 |
| info | 0.0 |

If your CVSS score does not fall within the matching severity range, adjust one or the other before recording.

**Deduplication:** Before recording, query existing findings via `assess.py fetch report-findings`. If the same root cause on the same endpoint already exists, update the existing finding rather than creating a new one. Same vulnerability class across multiple parameter values of the same endpoint is one finding, not one per value.

Record every finding with:
```
./scripts/assess.py record-finding <agent-name> <finding-json-file>
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

**Failure to use `assess.py record-finding` is the single most common subagent defect.** If you
produce `#### Findings` output, each finding payload in that section must have been recorded
via `assess.py record-finding` during your session. Do not defer recording to the operator.

---

## 5. Surface Candidates

When your output includes `#### Surface Candidates`, these must be synced by the operator:
```
./scripts/assess.py record-surface <type> <target> <source> [--rationale TEXT] [--status STATUS]
```

Do not patch `surfaces.jsonl` by hand.

---

## 6. Output Format Requirements

Return structured output using these section headers when relevant to your role:

`#### Summary` · `#### Stats` · `#### Findings` · `#### Evidence`
`#### Surface Candidates` · `#### Intelligence` · `#### Recommended Next Actions`

Use `#### Decision` and `#### Action` for validation output (vulnerability-analyst).

Every `#### Findings` block must contain finding payloads ready for `assess.py record-finding`,
not prose descriptions.

---

## 7. Rule Reminders

These are the most commonly violated rules — internalize them before you start:

- **No theoretical findings.** "Can an attacker do this right now with real harm?" — if no, not a finding yet.
- **Kill weak leads fast.** Theory without a real request, more than two fragile preconditions stacked, or "might be chainable" without a proved chain → kill it.
- **Severity follows proved impact.** Do not let recon hints, CVEs, or intuition inflate severity beyond what the evidence shows.
- **No speculative language.** Write `An attacker can [exact action] by [exact method]`, never `could potentially`, `may allow`, or `might be possible`.
- **No filler or padding.** Do not use `Furthermore`, `Additionally`, `It should be noted`, or similar filler transitions. Do not restate titles in descriptions. Do not define standard vulnerability classes to a security audience. Every sentence must contribute new information.
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

All assessment operations use `./scripts/assess.py <subcommand>` resolved from the agent workspace
root after `cd agent`. JSON payloads are always in files, never inline shell arguments.

Do not hardcode absolute paths. Set `ENGAGEMENT_DIR` before calling assess.py, or pass `--engagement-dir`.

---

## 10. Chain, Credential, and Coverage State

Record state immediately using `assess.py` with JSON files:

- **Attack chains:** `./scripts/assess.py record-chain <agent-name> <chain-json-file>`
- **Credentials:** `./scripts/assess.py post credentials <credential-json-file>`
- **Credential tests:** `./scripts/assess.py post credential-tests <json-file>`
- **Access records:** `./scripts/assess.py post access-records <json-file>`
- **Coverage updates:** `./scripts/assess.py patch coverage-items/<id> <json-file>`
- **Blocked techniques:** `./scripts/assess.py post blocked-techniques <json-file>`
- **Probe runs:** `./scripts/assess.py post probe-runs <json-file>`

Write payloads to `/tmp/<type>-<slug>.json` before calling.
Never pass JSON as an inline shell argument.

These follow the same backend-first principle as finding recording. Do not defer chain or credential
recording to the operator. The agent that proves the state writes it; the operator verifies it landed in
canonical backend state and avoids writing duplicate rows.
