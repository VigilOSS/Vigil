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
Start with the function map as your completeness anchor, then use entry points, exports,
sinks, and import targets as advisory navigation aids to prioritize where you deepen.
The structural index helps you navigate; it does not limit what you look for. Do not
substitute metadata summaries for source reads.

If code beyond the provided file batch is needed, use ctags + grep + Read to find it yourself.
Full filesystem access is always available. Never guess at the behavior of code you have
not read. Never request operator-mediated expansion when you can resolve it with a file read.

---

## 3. Full Filesystem Access

Source code is read directly from the local filesystem via host Bash or Claude Code tools.
This is NOT target-facing network work -- `aith assess kali` is not needed for reading source files.

**When code analysis does reach for `aith assess kali ...`** (for example, a fuzz campaign or
binary-triage pass that runs a tool through the runtime), the same coverage-check
rule as the web mode applies: every call carries `engagement_key`/`agent_name`/`phase`
and runs land in `assessment_command_runs`. Treat that history as a coverage
map — a record of what harnesses/corpora/sanitizer configs have already been
run so your next campaign picks a variant that hasn't been tried. Search with
an unscoped query first so you see every agent's and every phase's prior work
— `aith assess list-command-runs --q <keyword>` — and narrow with
`--agent-name` or `--phase` only if the broad result is overwhelming.
The only campaign to skip is the identical binary + corpus + flags combination
already run to completion; any variant (new sanitizer, new dictionary, new
seed corpus, harness change) is new coverage. Before citing a prior run,
fetch its preview with `aith assess get-command-run <id>` —
`success=true` only means `return_code=0`, and a campaign that exited cleanly
under its time budget but produced no crashes is not the same as one that
exhausted the search space. Full coverage-vs-duplicate decision table:
`agent/references/runtime-guides/command-history-auditing.md`.

**Available tools:**

| Tool | Use |
|---|---|
| `Read` | Read source files |
| `rg` | Search code patterns, find call sites |
| `Glob` | Locate files by pattern |
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
Use `aith assess record-finding <agent-name> <finding-json-file>` to record.

**Code finding prefixes:**

| Agent | Prefix | Example |
|---|---|---|
| `code-architect` | `CA` | `CA-001` |
| `code-vuln-hunter` | `CH` | `CH-001` |
| `code-variant-hunter` | `CV` | `CV-001` |
| `code-vuln-verifier` | `VF` | `VF-001` (spot-check only — verifier updates existing findings, not new ones) |
| `code-fuzz-engineer` | `CF` | `CF-001` |

**Title formula:** `[Bug Class] in [file:line or component] allows [attacker role] to [impact]`

**CVSS<->severity must match:**

| Severity | CVSS range |
|---|---|
| `critical` | 9.0-10.0 |
| `high` | 7.0-8.9 |
| `medium` | 4.0-6.9 |
| `low` | 0.1-3.9 |
| `info` | 0.0 |

If your CVSS score does not fall within the matching severity range, adjust one or the other
before recording. A memory corruption primitive with attacker-controlled reachability needs the
same severity discipline as a web auth bug because the report pipeline consumes one shared
finding table.

**Code finding conventions:**
- `canonical_location` format: `file:<relative-path>:<line-number>` (e.g., `file:lib/url.c:547`)
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `details.evidence` must include: the vulnerable code snippet, the taint path from untrusted input to sink, and why existing guards are insufficient
- `details.entry_point` and `details.sink` decompose the taint path into structured fields — populate both alongside the narrative `details.taint_path`
- `details.references` is an array of CVE links, advisory URLs, or CWE documentation links
- `details.poc_code` holds a PoC exploit script; for web findings use `details.poc_request` / `details.poc_response` for structured HTTP pairs

**Deduplication:** Before recording, query existing findings via `aith assess fetch findings`.
If the same root cause at the same canonical location already exists, update or merge that finding
instead of creating a duplicate. Variant instances in different files or materially different sink
sites are new findings; repeated commentary on the same `file:path:line` is not.

**The `notes` field must contain replayable proof commands** such as the exact build flags, PoC
input file generation, sanitizer invocation, unit-test repro command, or debugger invocation used
to confirm the bug. The goal is reproduction without rediscovery: another analyst should be able to
rerun the proof from `notes` plus the referenced source files alone.

---

## 5. No Theoretical Findings

The same rule from web testing applies to code review:
- **Can this be exploited by an attacker controlling the identified input?** If yes, it is a finding.
- **Is the vulnerable code reachable from an external entry point?** If no, it is not a finding (yet).
- A missing bounds check in dead code is not a finding.
- A potential overflow that requires impossible input is not a finding.
- Document the specific attacker-controlled input and the concrete impact.

---

## 6. Account For Every Analyzed Function

Every function you analyze must still receive exactly one disposition because the backend
records one result per function:

- `finding` -- Confirmed vulnerability with CWE, evidence, and exploitability assessment
- `suspicious` -- Anomalous pattern needing variant analysis or deeper context to confirm
- `clean` -- No vulnerabilities found in current analysis
- `needs-context` -- Analysis blocked on missing information (specify exactly what is needed)

Coverage must be explicit, but write-up depth can be proportional:
- Attack-facing, sink-bearing, stateful, or ambiguous functions need full reasoning.
- Obviously mechanical helpers can use concise `clean` dispositions once you have verified they
  do not hide sinks, trust-boundary assumptions, or material error behavior.

Record dispositions via `aith assess code-record-analysis`.
`finding` dispositions record durable finding state through `record-finding`; `suspicious`,
`clean`, and `needs-context` still record through `code-record-analysis` so backend coverage knows
which functions were reviewed and why the queue can advance or re-dispatch.

---

## 7. Anti-Rationalization Rules

Every code analysis agent must avoid these rationalizations. When you catch yourself
thinking any of these, stop and apply the required action instead.

| Rationalization | Why It Fails | Required Action |
|---|---|---|
| "I get the gist" | Gist-level misses edge cases | Read the code directly. Use structure-first triage, then line-by-line on risky or ambiguous spans |
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

## 9. Script Path Convention

All assessment operations use `aith assess <subcommand>` resolved from the agent workspace
root after `cd agent`. JSON payloads belong in files, not inline shell arguments, because payload
files are auditable and avoid shell escaping damage.

Do not hardcode absolute paths. Set `ENGAGEMENT_DIR` before calling assess helpers, or pass
`--engagement-dir` when the helper supports it.

---

## 10. Recording Format

Use the standard finding JSON schema. If you need the canonical field list or examples, run
`aith assess contract record-finding`. Do not invent lifecycle fields from memory —
`record-finding` fills the initial lifecycle defaults (`workflow_status=active`,
`verification_state=unreviewed`, `verification_disposition=none`) when omitted.
For later finding lifecycle changes, use the dedicated helpers instead of raw `post` or `patch`:
`verify-finding` for confirm/downgrade/dispute decisions, `kill-finding` for false-positive
verification with kill metadata, `reset-finding` to reopen a previously verified or false-positive
finding, and `update-finding` for non-verification metadata or workflow updates.

Code-specific fields:

```json
{
  "title": "Heap buffer overflow in URL parser via overlong scheme",
  "severity": "high",
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
