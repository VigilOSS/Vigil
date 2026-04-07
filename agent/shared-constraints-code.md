# Shared Subagent Constraints -- Code Analysis Mode

Load this file first -- before your role-specific skill and before any source code work.
These rules apply to every code analysis specialist agent regardless of role.

---

## 1. Authorization and Scope

All source code under analysis is authorized for deep security review.
This is a white-box engagement. You have full access to read and analyze all source code files.

Read `scope.json` (with `source_repos` array) before starting. Confirm:

- Repository path and name from the active repo record
- Current analysis phase (ingest/classify-map/hunt/verify-variant)
- Which files are in scope for your current dispatch (module, classification level, queue items)

Limit analysis to files within the scoped repository -- request operator approval before
analyzing files outside the current scope.

---

## 2. Source Code Is Primary

You receive actual source code files -- read directly from the filesystem with structural
index navigation when available -- not JSON metadata about code. Read the code directly.

If code beyond the provided file batch is needed, use ctags + grep + Read to find it yourself.
Full filesystem access is always available. Never guess at the behavior of code you have
not read. Never request operator-mediated expansion when you can resolve it with a file read.

---

## 3. Full Filesystem Access

Source code is read directly from the local filesystem via host Bash or Claude Code tools.
This is NOT target-facing network work -- Kali MCP is not needed for reading source files.

**Available tools:**

| Tool | Use |
|---|---|
| `Read` / `cat` / `head` / `tail` | Read source files |
| `Grep` / `rg` / `grep` | Search code patterns, find call sites |
| `Glob` / `find` | Locate files by pattern |
| `python3`, `jq`, `sqlite3` | Data processing and backend interaction |
| `git log`, `git blame`, `git diff` | History analysis |

### Cross-Reference Tools (priority order)

1. **ctags index** (fast definition lookup -- generated during code-ingest)
   - Query: `grep '^<symbol>\t' <repo>/tags` to find definition file and line number
   - Example: `grep '^packet_read_with_status\t' /path/to/repo/tags` returns the file and line
   - Use for: locating function/type definitions across the codebase

2. **grep/rg** (call sites, patterns, and anything ctags cannot resolve)
   - Use for: finding all callers, tracing data flow, cross-module references
   - Example: `rg 'packet_read_with_status\(' --type c` for call sites

3. **Direct file reads** when ctags/grep point to a location

When your analysis references a cross-module function that is load-bearing for the
vulnerability assessment, resolve it yourself by looking up the definition with ctags,
reading the file, and continuing your analysis. You have full filesystem access -- use it.

---

## 4. Findings Use the Existing Backend

Code analysis findings record in the **same** `assessment_findings` table as web findings.
Use `./scripts/assess.py record-finding <agent-name> <finding-json-file>` to record.

**Code finding conventions:**
- `canonical_location` format: `file:<relative-path>:<line-number>` (e.g., `file:lib/url.c:547`)
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `evidence` must include: the vulnerable code snippet, the taint path from untrusted input to sink, and why existing guards are insufficient

---

## 5. No Theoretical Findings

The same rule from web testing applies to code review:
- **Can this be exploited by an attacker controlling the identified input?** If yes, it is a finding.
- **Is the vulnerable code reachable from an external entry point?** If no, it is not a finding (yet).
- A missing bounds check in dead code is not a finding.
- A potential overflow that requires impossible input is not a finding.
- Document the specific attacker-controlled input and the concrete impact.

---

## 6. Disposition Every Analyzed Function

Every function you analyze must receive exactly one disposition:

- `finding` -- Confirmed vulnerability with CWE, evidence, and exploitability assessment
- `suspicious` -- Anomalous pattern needing variant analysis or deeper context to confirm
- `clean` -- No vulnerabilities found in current analysis
- `needs-context` -- Analysis blocked on missing information (specify exactly what is needed)

Record dispositions via `./scripts/assess.py code-record-analysis`.

---

## 7. Anti-Rationalization Rules

Every code analysis agent must avoid these rationalizations. When you catch yourself
thinking any of these, stop and apply the required action instead.

| Rationalization | Why It Fails | Required Action |
|---|---|---|
| "I get the gist" | Gist-level misses edge cases | Read line by line |
| "This function is simple" | Simple functions compose into complex bugs | Apply full analysis anyway |
| "This looks safe" | Must verify, not assume | Trace every taint path to every sink |
| "The guard seems sufficient" | Must verify on ALL paths | Check guard covers all branches |
| "External call is probably fine" | External = potentially adversarial | Read the callee or model as hostile |
| "I can skip this helper" | Helpers contain propagating assumptions | Trace full call chain |
| "I don't see any issues" | Must document what was checked | List every pattern checked and why it does not apply |

Treat the entire call chain as one continuous execution flow. Never reset context between
functions. A guard in function A does not protect function B unless B re-validates.

---

## 8. Skills and References Are Methodology -- Required, Not Optional

**Step 1 -- Check `agent/SKILL.md`** when you begin specialist work. It lists every code
analysis skill with "Use when:" criteria. Load the matching skill before doing any analysis.

**Step 2 -- Read the skill's Extended Resources section.** Every code analysis skill lists
specific reference files. Load them.

**Step 3 -- Load the CWE pattern references** from `agent/references/code-vuln-patterns/`
matching the slot types and defect families in your dispatch context. The operator's
slot-type to reference mapping table (in operator-core-code.md Phase 2) selects which
files to include per dispatch.

**References are not supplemental depth.** The `agent/references/code-vuln-patterns/` files contain:
- "What SAST Already Catches (Skip These)" -- so you do not waste time on patterns static tools find
- "What You're Hunting (LLM-Advantage Patterns)" -- the specific multi-function and semantic patterns only deep analysis can find
- Language-specific idioms and real CVE examples that ground pattern matching in reality

When a skill's Extended Resources section marks a reference as **(REQUIRED)**, you must load
it before producing any findings or dispositions. Without it, your analysis lacks the pattern
depth that distinguishes this pipeline from a static analysis tool.

Only improvise after confirming the reference set is genuinely insufficient for the code under review.

---

## 9. Recording Format

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
    "taint_path": "curl_url_set(CURLURLPART_URL, attacker_url) -> parseurl() -> memcpy(buf, scheme, schemelen)",
    "guards_evaluated": "No bounds check on schemelen before memcpy. The MAX_SCHEME_LEN check at line 298 uses signed int comparison, allowing negative values to bypass.",
    "remediation": "Add size_t bounds check: if (schemelen > MAX_SCHEME_LEN) return CURLUE_BAD_SCHEME;",
    "slot_type": "URL-COMPONENT",
    "steps_to_reproduce": ["Construct URL with scheme > 64 chars", "Pass to curl_url_set()", "Observe heap corruption"]
  }
}
```
