# Shared Subagent Constraints — Code Analysis Mode

Load this file first — before your role-specific skill and before any source code work.
These rules apply to every code analysis specialist agent regardless of role.

---

## Authorization

All source code under analysis is authorized for deep security review.
This is a white-box engagement. You have full access to read and analyze all source code files.

---

## 1. Confirm Scope Before Any Analysis Work

Read `code-scope.json` (or `scope.json` with `source_repos` array) before starting. Confirm:

- Repository path and name from the active repo record
- Current analysis phase (ingest/classify/context/analyze/variant/verify)
- Which files are in scope for your current dispatch (module, classification level, queue items)

Do not analyze files outside the scoped repository without operator approval.

---

## 2. Source Code Reading Is Host-Side

Source code is read directly from the local filesystem via host Bash or Claude Code's Read tool.
This is NOT target-facing network work — Kali MCP is not needed for reading source files.

Host-side commands permitted for code analysis:
- `cat`, `head`, `tail`, `grep`, `rg`, `find` — for reading source files
- `python3`, `jq`, `sqlite3` — for data processing and backend interaction
- `git log`, `git blame`, `git diff` — for history analysis
- `wc -l`, `file`, `sha256sum` — for file metadata

---

## 3. Findings Use the Existing Backend

Code analysis findings record in the **same** `assessment_findings` table as web findings.
Use `./scripts/assess.py record-finding <agent-name> <finding-json-file>` to record.

**Code finding conventions:**
- `canonical_location` format: `file:<relative-path>:<line-number>` (e.g., `file:lib/url.c:547`)
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `evidence` must include: the vulnerable code snippet, the taint path from untrusted input to sink, and why existing guards are insufficient

---

## 4. No Theoretical Findings

The same rule from web testing applies to code review:
- **Can this be exploited by an attacker controlling the identified input?** If yes, it's a finding.
- **Is the vulnerable code reachable from an external entry point?** If no, it's not a finding (yet).
- A missing bounds check in dead code is not a finding.
- A potential overflow that requires impossible input is not a finding.
- Document the specific attacker-controlled input and the concrete impact.

---

## 5. Disposition Every Analyzed Function

Every function you analyze must receive exactly one disposition:

- `finding` — Confirmed vulnerability with CWE, evidence, and exploitability assessment
- `suspicious` — Anomalous pattern needing variant analysis or deeper context to confirm
- `clean` — No vulnerabilities found in current analysis
- `needs-context` — Analysis blocked on missing information (specify exactly what is needed)

Record dispositions via `./scripts/assess.py code-record-analysis`.

---

## 6. Skills and References Are Methodology

Before analyzing code, load the relevant skill from `agent/SKILL.md` and read the extended
references it lists. The `agent/references/code-vuln-patterns/` files contain the reasoning
patterns for SAST-surviving bugs — these are your methodology, not optional depth.

---

## 7. Context Expansion Protocol

When your analysis is blocked because a cross-module function call is load-bearing for the
vulnerability assessment:

1. Output `#### Context Expansion Requests` with the specific function/file needed
2. Explain WHY this context is needed (what hypothesis depends on it)
3. Mark the analysis queue item as `needs-context`
4. The operator will fetch the requested code and re-dispatch you with expanded context

Do NOT guess at the behavior of unresolved functions. If it matters, request expansion.

---

## 8. Recording Format

Use the standard finding JSON schema. Code-specific fields:

```json
{
  "title": "Heap buffer overflow in URL parser via overlong scheme",
  "severity": "high",
  "status": "confirmed",
  "defect_family": "buffer-overflow",
  "canonical_location": "file:lib/urlapi.c:342",
  "summary": "Attacker-controlled URL scheme exceeding 64 bytes overflows stack buffer in parseurl()",
  "details": {
    "cwe_id": "CWE-122",
    "impact": "Remote code execution via heap corruption",
    "evidence": "In parseurl() at line 342, scheme is copied via memcpy(buf, scheme, schemelen) where schemelen is derived from user input without bounds check...",
    "taint_path": "curl_url_set(CURLURLPART_URL, attacker_url) → parseurl() → memcpy(buf, scheme, schemelen)",
    "guards_evaluated": "No bounds check on schemelen before memcpy. The MAX_SCHEME_LEN check at line 298 uses signed int comparison, allowing negative values to bypass.",
    "remediation": "Add size_t bounds check: if (schemelen > MAX_SCHEME_LEN) return CURLUE_BAD_SCHEME;",
    "slot_type": "URL-COMPONENT",
    "steps_to_reproduce": ["Construct URL with scheme > 64 chars", "Pass to curl_url_set()", "Observe heap corruption"]
  }
}
```
