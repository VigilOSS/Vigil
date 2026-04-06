---
name: code-finding-verification
description: False positive elimination via constrained attacker persona and full entry-to-sink traces
origin: AI Threat Hunting
---

# Code Finding Verification

## When to Activate

- Phase 5 of code analysis pipeline. Runs before the final report is produced.
- Every finding (from vulnerability analysis and variant analysis) must pass through this verification before being reported.
- Goal: eliminate false positives, adjust severity based on full context, synthesize attack chains from related findings, and produce a final set of verified findings.

## Tools

- Host-side file reading — for tracing full entry-to-sink paths through the codebase
- `git blame` — understanding code provenance, identifying recent changes, correlating with known fixes
- `rg` / `grep` — locating upstream guards, build configuration, and related code paths

Cross-reference tools:
- **ctags index** — `grep '^<symbol>\t' <repo>/tags` to resolve function definitions for guard evaluation and call chain tracing
- **grep / rg** — trace complete call chains from entry points to sinks, verify upstream guards on all paths

Audit trail requirement:
- Every verification memo should state whether ctags or grep was used for full-path tracing.
- If verification results are recorded in machine-readable form, include `audit_metadata.cross_ref_usage` with the concrete lookups used.

## Methodology — The 5-Check Protocol

Every finding must survive all 5 checks. Failure at any check results in KILL or DOWNGRADE. This protocol is adversarial toward the finding — assume it is a false positive and force it to prove otherwise.

### Check 1: Reachability from External Entry

Trace backward from the vulnerable function to the nearest external entry point (main function, protocol handler, file reader, CLI parser, API handler).

**Process:**
1. Start at the vulnerable function
2. Read its callers (from context slice call graph)
3. For each caller, read ITS callers
4. Continue until you reach an external entry point OR exhaust the call chain

**Decision:**
- Entry point found with untrusted data flowing to vulnerable function: PASS
- Entry point found but data is hardcoded/constant by the time it reaches vulnerable function: KILL ("unreachable with untrusted data — all callers pass constants")
- No external entry point found (dead code, internal-only function): KILL ("no external entry point — function is unreachable from attack surface")
- Entry point found but only through test code: KILL ("only reachable from test harness, not production code")

```bash
# Find all callers of the vulnerable function
rg "function_name\s*\(" --type c -n

# Trace upward through the call chain
rg "caller_function\s*\(" --type c -n
```

### Check 2: Upstream Guards

The vulnerability analysis (Phase 3) evaluated guards within the vulnerable function and its immediate callers. This check extends the search to 3+ levels up the call chain.

**Process:**
1. For each caller path identified in Check 1, read functions 3-5 levels up
2. Look for guards that validate the untrusted data before it reaches the vulnerable function
3. Check if the guard is complete (correct variable, correct bound, all paths, before use)

**Decision:**
- Complete guard found upstream that covers all paths: KILL ("upstream guard in `validate_request()` at request.c:85 bounds-checks length before passing to vulnerable function")
- Partial guard found (some paths, wrong bound): finding survives but note the partial guard — it may affect severity
- No upstream guard found: PASS

**Common upstream guard locations:**
- Request validation layers (input sanitization before dispatch)
- Protocol framing layers (length checks during deserialization)
- API gateway or middleware (request size limits, content-type enforcement)
- Configuration-based limits (max_header_size, max_body_size)

### Check 3: Build Configuration

Determine whether the vulnerable code is actually compiled and linked in the default/production build.

**Process:**
1. Check for conditional compilation: `#ifdef`, `#if`, `#[cfg(...)]`, `//go:build`, build system feature flags
2. Determine if the flag is enabled in default configuration
3. Check if the code is behind a debug-only, test-only, or experimental flag

```bash
# Check for #ifdef around vulnerable code
rg "#ifdef|#if defined|#if " [vulnerable-file] -n -C3

# Check build system for feature flags
rg "FEATURE_NAME|CONFIG_OPTION" Makefile CMakeLists.txt Cargo.toml configure.ac
```

**Decision:**
- Code compiled in default production build: PASS
- Code behind debug-only flag (`#ifdef DEBUG`, `#[cfg(test)]`): KILL ("debug-only code, not compiled in production")
- Code behind optional feature flag: DOWNGRADE severity + note the flag ("vulnerable code requires `--enable-experimental-parser` flag, not enabled by default")
- Code excluded on common platforms: DOWNGRADE + note platforms affected

### Check 4: Exploitation Feasibility

Apply the constrained attacker persona with maximum rigor. This is the most detailed check.

**Process:**
1. **Exact input needed**: What specific bytes must the attacker send? Can they actually construct these bytes given protocol constraints?
2. **Entry point**: Through which specific protocol field, parameter, or file format field does the input enter?
3. **Path constraints**: What conditions must be true along the path? (specific branch taken, specific state, specific configuration)
4. **Concrete impact**: What exactly happens when the vulnerable code executes with attacker input?
   - Buffer overflow: how many bytes overflow, where do they land, what can be overwritten?
   - Integer overflow: what value results, how is it used subsequently?
   - Use-after-free: what object is freed, what reuses the memory, what attacker-controlled data fills it?
   - Auth bypass: what access does the attacker gain?
5. **Mitigations**: What system-level protections apply?
   - ASLR: does the attack require knowing addresses? Is there an info leak to defeat ASLR?
   - Stack canaries: is the overflow on the stack? Does the canary protect the overwritten data?
   - Seccomp/sandbox: does the sandbox prevent the attacker's desired operation?
   - CFI/CET: does control-flow integrity prevent the attacker's code redirection?
   - W^X (NX): does the attacker need to execute injected code, or is ROP sufficient?

**Decision:**
- Concrete exploit path exists even with mitigations: PASS with full exploit description
- Exploit theoretically possible but mitigations make it impractical: DOWNGRADE severity + document mitigation effectiveness
- No concrete exploit path constructable: KILL ("exploitation requires [specific impossible condition]")

### Check 5: Real-World Impact

Even if technically exploitable, assess whether the finding is advisory-worthy.

**Process:**
1. Is the vulnerable code path exercised during normal operation by real users?
2. What is the realistic impact to a user or organization? (data breach, denial of service, code execution, privilege escalation)
3. Is the vulnerable code path only reachable in unusual configurations or edge cases?
4. Would an attacker choose this path over simpler alternatives?

**Decision:**
- Real users hit this path, meaningful impact: PASS
- Edge case path, limited impact: DOWNGRADE severity
- Code path effectively unreachable in practice: KILL or DOWNGRADE with explanation

## Dispositions

| Disposition | Meaning | Report Action |
|-------------|---------|---------------|
| `confirmed` | Finding survives all 5 checks at stated severity | Include in report as-is |
| `downgraded` | Finding survives but at lower severity | Include in report with adjusted severity + reasoning for downgrade |
| `killed` | Finding is a false positive | Exclude from report, record kill reason for audit trail |

### Kill Reasons (for audit trail)

Every killed finding must record a specific, verifiable kill reason:

```
KILL: [Finding ID]
Check Failed: [1-5]
Reason: [specific, verifiable statement]
Evidence: [code location, build config line, or upstream guard location that proves the kill]
```

Examples:
- "Check 1 KILL: only caller is `test_parser()` in test/unit_tests.c — no production entry point"
- "Check 2 KILL: `validate_header_length()` at http.c:92 bounds-checks to 8192 bytes on all paths before data reaches vulnerable `parse_header_value()`"
- "Check 3 KILL: code inside `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, not compiled in release"
- "Check 4 KILL: overflow is 1 byte (null terminator), lands on padding between stack variables, no exploitable overwrite"
- "Check 5 DOWNGRADE: path requires Content-Encoding: identity which no browser sends by default; downgrade from HIGH to MEDIUM"

## Attack Chain Synthesis

After individual finding verification, examine the full set of surviving findings for composable chains.

**Chain detection process:**
1. Group findings by affected component (same module, same data structure, same protocol handler)
2. For each group, check: does an info leak finding exist alongside a memory corruption finding?
3. Check: does a lower-severity finding enable a higher-severity finding? (e.g., integer overflow controls allocation size, separate heap overflow writes into that allocation)
4. Check: does a logic bug provide a primitive that enables exploitation of a memory safety bug? (e.g., auth bypass reaches an authenticated-only code path with a buffer overflow)

**Chain documentation:**

```
ATTACK CHAIN: [Chain title]
Components:
  1. [Finding-A] — [role in chain: info leak provides heap layout]
  2. [Finding-B] — [role in chain: controlled allocation size via integer overflow]
  3. [Finding-C] — [role in chain: heap overflow writes attacker data into controlled allocation]
Composite Impact: [e.g., Remote Code Execution as service user]
Composite Severity: [may be higher than any individual finding]
Prerequisites: [what the attacker needs: network access, specific request sequence, timing window]
```

## Output Format

The verification phase produces:

1. **Verified Findings**: confirmed findings with full evidence, ready for report
2. **Downgraded Findings**: findings with adjusted severity and reasoning
3. **Kill List**: killed findings with specific check failure and evidence
4. **Attack Chains**: composite chains linking multiple findings
5. **Verification Summary**: statistics (X findings in, Y confirmed, Z killed, W downgraded, N chains identified)

When you persist structured verification state, include:

```json
{
  "audit_metadata": {
    "cross_ref_usage": {
      "tool": "mixed",
      "queries": [
        "grep '^parse_header_value\t' tags",
        "rg 'parse_header_value\\s*\\(' --type c",
        "rg 'validate_header_length\\s*\\(' --type c"
      ],
      "notes": "Used ctags for definition lookup and rg to prove full reachability and upstream guard coverage"
    }
  }
}
```

## Extended Resources

- Build system configuration — `Makefile`, `CMakeLists.txt`, `Cargo.toml`, `configure.ac`, `.config` files for understanding compile-time flag state
- Compile-time flag documentation — project docs explaining feature flags, debug modes, and optional components
- Architecture map from Phase 1 — entry points and trust boundaries for reachability tracing
- Context slices from Phase 2 — call graphs for upstream guard search
- **CWE pattern reference (REQUIRED)** — load the `agent/references/code-vuln-patterns/*.md` file matching each finding's CWE. Pattern knowledge is needed for guard completeness evaluation (Check 2: are ALL variant forms of this bug class guarded?) and exploitation feasibility assessment (Check 4: what does a real exploit look like for this pattern?).
