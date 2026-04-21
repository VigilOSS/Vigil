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

**Do not `echo` as commentary, section headers, or breadcrumbs inside Kali MCP commands.**
Stdout is captured to the audit log, not shown to the user, and commentary-echoes bloat
the preview and pollute FTS search without adding retrievable signal. Use the `X-Intent`
header for a one-line purpose annotation. `echo` is only legitimate when its output is the
command's real purpose — writing to a file (`echo X > file`), piping into another tool, or
generating a payload.

### Command Metadata

Every target-facing Kali MCP call supports four optional audit headers. Set them when they
apply; the runtime stores them on the audit row where they become filterable in
`list-command-runs` and the Commands tab.

- **`X-Technique`** — the vulnerability class this command tests. One of `SSRF`, `XSS`,
  `XXE`, `SQLI`, `NOSQLI`, `SSTI`, `RCE`, `CMDI`, `IDOR`, `LFI`, `RFI`, `OPEN-REDIRECT`,
  `AUTH`, `JWT`, `CSRF`, `CORS`, `REQUEST-SMUGGLING`, `RATE-LIMIT`, `INFO-DISCLOSURE`,
  `RECON`, `DISCOVERY`, `FUZZ`, `OSINT`, `CVE-VALIDATION`, `EXPLOIT-CHAIN`, `OTHER`. Use
  the value from the skill you loaded.
- **`X-Intent`** — a ≤200-char one-liner describing what this specific command is trying to
  accomplish. Replaces the `echo "=== label ==="` pattern.
- **`X-Probe-Kind`** — the kind of work this command represents:
  - `fingerprint` — learning the target (versions, headers, tech stack), no payload
  - `baseline` — vanilla control request against the target surface, for diff
  - `payload` — crafted attack payload testing a hypothesis
  - `exploit` — attacker-outcome proof (extract token, read a file, prove the impact)
  - `replay` — captured primitive used against a new surface (lateral)
  - `cleanup` — undoing target-side changes
- **`X-Destructive`** — `1` when the command attempts a write, edit, or delete on the
  target (POST/PUT/PATCH/DELETE, file upload, account creation, config change, shell exec
  that modifies state). `0` for read-only probes. Used by cleanup-tracking workflows.

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
- `/data/oob-client.log` — correlated interactsh callback hits (preferred for confirming blind vulns — filters AWS noise)
- `/data/oob-server.log` — raw interactsh log (noisy, includes health check traffic — use only when client log is unavailable)
- `/data/frpc.log` — tunnel connection status

Full OOB setup, verification, and log interpretation: `agent/references/offensive-tactics/frp-tunneling.md`

Agents CANNOT start, stop, or restart listener, tunnel, or OOB processes.

---

## 2b. Coverage Check Before Probing

Every Kali MCP call records its command, argv, tool, agent, phase, exit code,
timeout state, timings, and an output preview (or artifact ref) to the
orchestrator backend. Treat that history as a **coverage map** — a record of
what's already been probed so your next probe goes somewhere the engagement
hasn't covered yet.

Before issuing a probing, scanning, fuzzing, or credential-testing command,
search for prior work on this surface:

```bash
./scripts/assess.py list-command-runs --q <keyword>
```

Default to an unscoped search so you see every agent's and every phase's
prior work on the target; narrow with `--agent-name` or `--phase` only if the
broad result is overwhelming. Cross-agent and cross-phase context is usually
the most valuable coverage signal.

Read the results as a coverage map, not a reuse gate. Red-team depth comes
from variants — different SQLi techniques, different SSRF payload encodings,
different XXE entity styles, different wordlists, different auth contexts.
If `sqlmap` already ran against this endpoint with `--technique=U`, your
next probe picks a different technique. If `ffuf` ran `raft-medium-directories`,
try `quickhits` or a tech-specific wordlist.

**The only probe you should skip is an identical command against identical
input.** Any variant — different payload family, different tool, different
flag, different target scope, different credentials — is new coverage and
belongs in the engagement. Don't ask for permission to probe a variant.

When a prior run genuinely covers your current question, cite its id in your
output — but first fetch the preview with `./scripts/assess.py get-command-run <id>`
and confirm the stored evidence actually answers that question. A row with
`success=true` only means `return_code=0`, not that the output is on-point.
Open the preview to rule out soft-failure pages, WAF intercepts, and
rate-limited stubs that exit cleanly. Citing an id you never looked at is
worse than running a fresh probe.

Full coverage-vs-duplicate decision table and output-field interpretation:
`agent/references/runtime-guides/command-history-auditing.md`.

---

## 3. Use Skills and References — They Are the Methodology

**Step 1 — Read `agent/SKILL.md`** before starting any specialist work. It lists every available
skill with "Use when:" criteria. Select and load the matching skill before doing anything else.

**Step 2 — Read `agent/references/INDEX.md`** after loading the skill. Identify the paired
payload files, tool cheatsheets, and OWASP checklists that apply to your task and load them.

**Do not begin target-facing work until both reads are complete.** Improvising a technique that
already exists in the skill/reference set wastes tokens, produces inconsistent results, and
misses methodology that the skill encodes (e.g., mitmproxy setup, payload libraries, tool flags).

**References are not a fallback.** The `references/` library contains:
- `payloads/` — 20 copy-pasteable attack payload files per bug class
- `api-security/` — OWASP API Security Top 10:2023 checklists
- `offensive-tactics/` — red team TTPs by kill-chain phase
- `tools/` — CLI tool cheatsheets (nmap, ffuf, sqlmap, hydra, etc.)

When a skill's "Extended Resources" section lists reference files, those are required reading
for that test class — not optional supplemental material.

Only improvise after confirming the reference set is genuinely insufficient.

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
| surface-collector | SC | FINDING-SC-001 |

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

**Deduplication:** Before recording, query existing findings via `assess.py fetch findings`. If the same root cause on the same endpoint already exists, update the existing finding rather than creating a new one. Same vulnerability class across multiple parameter values of the same endpoint is one finding, not one per value.

Record every finding with:
```
./scripts/assess.py record-finding <agent-name> <finding-json-file>
```

The JSON payload must match `schemas/finding-record.schema.json`.
Do not produce markdown findings — convert to JSON before recording.
If you need the canonical field list or examples, run `./scripts/assess.py contract record-finding`.
Do not invent lifecycle fields from memory — `record-finding` fills the initial finding lifecycle defaults.

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

When a finding is only reportable as part of a chain, keep it in the same finding lifecycle and
set chain metadata in `details` during `record-finding` or `update-finding`:
```json
"details": {
  "chain_required": true,
  "chain_rationale": "This primitive becomes meaningful only after pivoting into the admin export flow.",
  "required_followup": ["Test sibling privileged write routes", "Attempt authenticated export with stolen token"]
}
```
Use this instead of inventing a special workflow status for chain-only findings.

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

Use only the supported `record-surface` types: `account_recovery`, `api_documentation`,
`auth_entry`, `dynamic_render`, `file_handling`, `object_reference`, `privileged_write`,
`workflow_token`. Do not invent local taxonomy labels.

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
