---
name: code-finding-verification
description: False-positive elimination using five-check verification protocol with devil's advocate and multi-perspective voting
origin: AI Threat Hunting
---

# Code Finding Verification

## When to Activate

- Phase 3 of code analysis pipeline. Runs on confirmed and suspicious findings from Phase 2.
- Every finding (from vulnerability analysis and variant analysis) must pass through this verification before being reported.
- Goal: eliminate false positives, adjust severity based on full context, synthesize attack chains from related findings, and produce a final set of verified findings.

## Tools

Full filesystem access (same as hunter):

- **Read** — read source files to verify taint paths, guards, and call chains independently
- **Grep** — locate all callers, upstream guards, build configuration, and related code paths
- **Glob** — find files by pattern for build system analysis and related module discovery
- **ctags** — `grep '^<symbol>\t' <repo>/tags` to resolve function definitions for guard evaluation and call chain tracing
- **git blame** — understanding code provenance, identifying recent changes, correlating with known fixes

Audit trail requirement:
- Every verification memo must state the concrete Read/Grep/ctags lookups used
- If verification results are recorded in machine-readable form, include `audit_metadata.cross_ref_usage` with the actual queries executed

## Division of Labor

- **Operator provides**: findings list with evidence, source code paths, CWE pattern refs, variant context
- **Verifier performs**: independent verification reading actual source code — never trust hunter annotations without independent confirmation

## Methodology — Five-Check Protocol

Every finding must survive all 5 checks. Failure at any check results in KILL or DOWNGRADE. This protocol is adversarial toward the finding — assume it is a false positive and force it to prove otherwise.

### Check 1: Reachability from External Entry

Trace backward from the vulnerable function to the nearest external entry point (main function, protocol handler, file reader, CLI parser, API handler).

**Process:**
1. Start at the vulnerable function — Read the file, confirm the vulnerability exists as described
2. grep/ctags to find all callers of the vulnerable function
3. For each caller, Read its source and find ITS callers
4. Continue until you reach an external entry point OR exhaust the call chain
5. Verify that untrusted data flows along the path (not hardcoded constants or derived values)

```bash
# Find all callers of the vulnerable function
rg "function_name\s*\(" --type c -n

# Trace upward through the call chain
rg "caller_function\s*\(" --type c -n

# Use ctags for definition lookup
grep '^parse_header_value\t' tags
```

**Decision:**
- Entry point found with untrusted data flowing to vulnerable function: **PASS**
- Entry point found but data is hardcoded/constant by the time it reaches vulnerable function: **KILL** ("unreachable with untrusted data — all callers pass constants")
- No external entry point found (dead code, internal-only function): **KILL** ("no external entry point — function is unreachable from attack surface")
- Entry point found but only through test code: **KILL** ("only reachable from test harness, not production code")

### Check 2: Upstream Guards

The vulnerability analysis (Phase 3) evaluated guards within the vulnerable function and its immediate callers. This check extends the search to 3+ levels up the call chain.

**Process:**
1. For each caller path identified in Check 1, Read functions 3-5 levels up
2. Look for guards that validate the untrusted data before it reaches the vulnerable function
3. Check if the guard is complete: correct variable, correct bound, all paths, before use
4. Read each caller's source code independently — do not trust the hunter's guard evaluation

**Decision:**
- Complete guard found upstream that covers all paths: **KILL** ("upstream guard in `validate_request()` at request.c:85 bounds-checks length before passing to vulnerable function")
- Partial guard found (some paths, wrong bound): finding survives but note the partial guard — it may affect severity
- No upstream guard found: **PASS**

**Common upstream guard locations:**
- Request validation layers (input sanitization before dispatch)
- Protocol framing layers (length checks during deserialization)
- API gateway or middleware (request size limits, content-type enforcement)
- Configuration-based limits (max_header_size, max_body_size)
- Macro wrappers that expand to bounds checks

### Check 3: Build Configuration

Determine whether the vulnerable code is actually compiled and linked in the default/production build.

**Process:**
1. Check for conditional compilation around the vulnerable code:
   - C/C++: `#ifdef`, `#if`, `#ifndef`, `#if defined`
   - Rust: `#[cfg(...)]`, `#[cfg(test)]`, `#[cfg(feature = "...")]`
   - Go: `//go:build`, build tags
   - Other: build system feature flags, platform-specific directories
2. Determine if the flag is enabled in default configuration
3. Check if the code is behind a debug-only, test-only, or experimental flag

```bash
# Check for #ifdef around vulnerable code
rg "#ifdef|#if defined|#if " [vulnerable-file] -n -C3

# Check build system for feature flags
rg "FEATURE_NAME|CONFIG_OPTION" Makefile CMakeLists.txt Cargo.toml configure.ac

# Check default configuration
rg "FEATURE_NAME" .config defconfig
```

**Decision:**
- Code compiled in default production build: **PASS**
- Code behind debug-only flag (`#ifdef DEBUG`, `#[cfg(test)]`): **KILL** ("debug-only code, not compiled in production")
- Code behind optional feature flag: **DOWNGRADE** severity + note the flag ("vulnerable code requires `--enable-experimental-parser` flag, not enabled by default")
- Code excluded on common platforms: **DOWNGRADE** + note platforms affected

### Check 4: Exploitation Feasibility (PoC-or-Proof Required)

Apply the constrained attacker persona with maximum rigor. This check has a hard requirement: you must either construct a concrete exploit scenario OR prove why exploitation is impossible. "Unclear" is not an acceptable outcome.

**Process:**

1. **Construct the exploit** (attempt this first):
   - What specific bytes must the attacker send?
   - Through which entry point (protocol field, parameter, file format field)?
   - What is the exact code path from entry to vulnerability trigger?
   - What is the concrete impact when triggered?
     - Buffer overflow: how many bytes overflow, where do they land, what gets overwritten?
     - Integer overflow: what value results, how is it used subsequently?
     - Use-after-free: what object is freed, what reuses the memory, what fills it?
     - Auth bypass: what access does the attacker gain?
     - Injection: what command/query executes, with what privileges?

2. **OR prove exploitation is impossible** (if you cannot construct the exploit):
   - What specific constraint prevents the attacker input from reaching the sink?
   - What specific mitigation prevents the impact even if the sink is reached?
   - What specific system property makes the exploit non-functional?

3. **Check system mitigations** (either way):
   - ASLR: does the attack require knowing addresses? Is there an info leak to defeat ASLR?
   - Stack canaries: is the overflow on the stack? Does the canary protect the overwritten data?
   - Seccomp/sandbox: does the sandbox prevent the attacker's desired operation?
   - CFI/CET: does control-flow integrity prevent the attacker's code redirection?
   - W^X (NX): does the attacker need injected code, or is ROP sufficient?

**Decision:**
- Concrete exploit path exists even with mitigations: **PASS** with full exploit description
- Exploit theoretically possible but mitigations make it impractical: **DOWNGRADE** severity + document mitigation effectiveness
- No concrete exploit path constructable AND specific blocking constraint identified: **KILL** ("exploitation requires [specific impossible condition]")

### Check 5: Devil's Advocate (Trail of Bits fp-check methodology)

**ASSUME THE FINDING IS WRONG.** This check is mandatory for every finding that reaches it. Systematically attempt to disprove:

**Step 1 — Guard search:**
Read the ENTIRE file containing the vulnerability, not just the function. Look for:
- Guards the hunter missed in other branches
- Callers within the same file that validate before calling
- Macros that expand to guards (grep the macro definition)
- Assertion macros or debug checks that may be active in release builds

**Step 2 — Constraint search:**
What implicit constraints make the input non-exploitable?
- Protocol framing limits input sizes (e.g., HTTP header limits, TLS record sizes)
- Caller validates before passing (even if not an explicit "guard", the call site may constrain values)
- Type system prevents dangerous values (unsigned type prevents negative, enum restricts range)
- Memory allocator rejects unreasonable sizes (malloc fails, allocation cap)
- String functions null-terminate, preventing unbounded reads

**Step 3 — Intent search:**
Was this code DESIGNED to handle this case?
- Read git blame for the vulnerable lines — was this a deliberate fix or refactor?
- Check for comments explaining the design intent
- Check test files for test cases covering this exact path
- Check commit messages for security-related changes to this function

```bash
# Read git blame for the vulnerable lines
git blame -L start,end [vulnerable-file]

# Check for related test cases
rg "test.*function_name|function_name.*test" --type-add 'test:*test*' -t test
```

**Step 4 — Mitigation search:**
What external protections exist?
- Compiler flags: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fsanitize=...`
- OS protections: ASLR, NX/W^X, seccomp profiles
- Application sandboxing: chroot, namespaces, pledge/unveil
- Network protections: rate limiting, connection limits, WAF rules
- Deployment configuration: read-only filesystem, dropped capabilities

**Outcome:**
- If you construct a convincing counter-argument with specific code evidence: **KILL** with full counter-argument documentation
- If you cannot construct a convincing counter-argument after all 4 steps: the finding **SURVIVES** with higher confidence
- If the counter-argument is plausible but not conclusive: escalate to **multi-perspective voting**

Document: what you tried to disprove, what evidence you found for and against, and the final determination. This documentation strengthens confirmed findings and makes kills auditable.

## Multi-Perspective Voting Protocol

For findings where Check 5 produces an ambiguous result — the counter-argument is plausible but not conclusive:

**When to invoke voting:**
- Devil's advocate found a partial guard but it may be bypassable
- Exploitation feasibility depends on configuration assumptions you cannot verify in code
- The counter-argument relies on implicit invariants not enforced in code
- Two reasonable security engineers could disagree on the disposition

**Voting procedure:**
1. Document the argument FOR the finding:
   - Hunter's original evidence
   - Your verification of the taint path (Checks 1-4)
   - Why the devil's advocate counter-argument fails or is incomplete
2. Document the argument AGAINST the finding:
   - Devil's advocate evidence from Check 5
   - Specific code locations supporting the counter-argument
   - What assumption would need to hold for this to be safe
3. Present both perspectives to the operator with your recommendation
4. Operator may dispatch a third agent with both perspectives for independent assessment
5. Majority vote (2 of 3) determines final disposition
6. Record the vote outcome and reasoning for audit trail

**Output format for voting request:**
```
VOTING REQUEST: [Finding ID]
FOR:    [summary of evidence supporting the finding]
AGAINST: [summary of devil's advocate evidence]
RECOMMENDATION: [your lean, with confidence level]
BLOCKER: [what specific evidence would resolve the ambiguity]
```

## Variant-Aware Verification

When variant findings exist (from code-variant-hunter in Phase 3):

- **If the original finding is killed**: do NOT automatically kill variants. Each variant may have independent paths, guards, and feasibility. Verify each variant through the full 5-check protocol. The kill reason for the original may not apply to the variant (different callers, different guards, different build flags).

- **If the original is confirmed**: the original's confirmed taint path provides supporting evidence for variants with similar paths. Variants still need independent verification, but you can reference the original's Check 1-4 evidence where the code paths overlap.

- **If a variant has a stronger guard than the original**: the variant may be clean even if the original is not. Verify independently.

- **Cross-variant chains**: two variants in different modules may compose into a chain even if neither is individually critical. Check for composability after individual verification.

## Attack Chain Synthesis (Enhanced)

After individual finding verification, examine the full set of surviving findings for composable chains.

**Chain detection process:**
1. Group findings by affected component (same module, same data structure, same protocol handler)
2. For each group, check: does an info leak finding exist alongside a memory corruption finding?
3. Check: does a lower-severity finding enable a higher-severity finding?
4. Check: does a logic bug provide a primitive that enables exploitation of a memory safety bug?

**For each potential chain, verify:**
1. Does finding A's output actually enable finding B's exploitation? (trace the data flow)
2. Can the attacker control the transition from A to B? (timing, state, protocol sequence)
3. What is the composite impact? (may be higher than either individual finding)
4. What are the prerequisites? (network access, specific request sequence, timing window)

**Chain documentation:**
```
ATTACK CHAIN: [Chain title]
Components:
  1. [Finding-A] — [role: info leak provides heap layout]
  2. [Finding-B] — [role: controlled allocation size via integer overflow]
  3. [Finding-C] — [role: heap overflow writes attacker data into controlled allocation]
Composite Impact: [e.g., Remote Code Execution as service user]
Composite Severity: [may be higher than any individual finding]
Prerequisites: [what attacker needs: network access, specific request sequence, timing]
Data Flow: [how A's output feeds B's input — specific variables and functions]
```

Record chains via `./scripts/assess.py record-chain code-vuln-verifier <chain-json>`

## FP Context

False positives are expected in any AI-assisted vulnerability pipeline. Your verification
standards:
- Confirm findings ONLY when ALL 5 checks pass with specific evidence
- Kill findings when you can construct a convincing counter-argument with code evidence
- Do not soften kills into downgrades — either the finding is real or it isn't
- Apply equal rigor to high-confidence and low-confidence findings alike

Conversely, if you kill >95% of findings, you may be too aggressive — verify that your kill
reasons are specific and verifiable, not generic dismissals.

## Dispositions

| Disposition | Meaning | Report Action |
|-------------|---------|---------------|
| `confirmed` | Finding survives all 5 checks at stated severity | Include in report as-is |
| `downgraded` | Finding survives but at lower severity | Include with adjusted severity + reasoning |
| `killed` | Finding is a false positive | Exclude from report, persist a `false_positive` verification on the canonical finding, record kill reason for audit |
| `voting` | Ambiguous — escalated to multi-perspective voting | Hold pending operator decision |

### Kill Reason Format (for audit trail)

Every killed finding must record a specific, verifiable kill reason:

```
KILL: [Finding ID]
Check Failed: [1-5]
Reason: [specific, verifiable statement]
Evidence: [code location, build config line, or upstream guard that proves the kill]
Devil's Advocate: [if Check 5 — the counter-argument that succeeded]
```

Examples:
- "Check 1 KILL: only caller is `test_parser()` in test/unit_tests.c — no production entry point"
- "Check 2 KILL: `validate_header_length()` at http.c:92 bounds-checks to 8192 bytes on all paths before data reaches vulnerable `parse_header_value()`"
- "Check 3 KILL: code inside `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, not compiled in release"
- "Check 4 KILL: overflow is 1 byte (null terminator), lands on padding between stack variables, no exploitable overwrite. Attempted to construct exploit — cannot overwrite return address or any function pointer."
- "Check 5 KILL: git blame shows lines were refactored in commit abc123 specifically to add the size check. Test case `test_oversized_header` in test/http_tests.c exercises this exact path and asserts rejection. The implicit MAX_HEADER_SIZE constraint (checked via the `ENSURE_SIZE` macro at line 89, which expands to a bounds check) prevents the attacker input from reaching the vulnerable arithmetic."

When you persist a false positive in structured finding state, include:
- `details.kill_check` — integer 1-5 for the failed verification check
- `details.kill_reason` — concise verifier rationale suitable for later query/reporting
- Use `./scripts/assess.py kill-finding <slug> ...` when you already have the kill rationale in hand, because it enforces the required false-positive fields before the request leaves the CLI
- Use `./scripts/assess.py verify-finding <slug> <verification-json>` for confirm/downgrade/dispute flows or when the verification payload already exists on disk, because the verification transition belongs in the audit ledger rather than a generic finding patch

## Output Format

The verification phase produces:

1. **Verification Results**: per-finding table with all 5 check results and final disposition
2. **Kill List**: killed findings with specific check failure, evidence, and devil's advocate reasoning
3. **Downgrades**: findings with adjusted severity, original severity, and evidence
4. **Voting Requests**: ambiguous findings with FOR/AGAINST arguments for operator review
5. **Attack Chains**: composite chains linking multiple findings with data flow evidence
6. **Verification Summary**: statistics (X in, Y confirmed, Z killed, W downgraded, V voting) and confirmation rate

When you persist structured verification state, include:

```json
{
  "audit_metadata": {
    "cross_ref_usage": {
      "tool": "mixed",
      "queries": [
        "grep '^parse_header_value\t' tags",
        "rg 'parse_header_value\\s*\\(' --type c",
        "rg 'validate_header_length\\s*\\(' --type c",
        "Read http.c lines 80-100",
        "git blame -L 445,495 parser.c"
      ],
      "notes": "Used ctags for definition lookup, rg for caller enumeration, Read for full guard verification, git blame for intent analysis in Check 5"
    },
    "fp_rate": {
      "total_findings": 12,
      "confirmed": 3,
      "downgraded": 2,
      "killed": 6,
      "voting": 1,
      "confirmation_rate": 0.25
    }
  }
}
```

## Extended Resources

- Build system configuration — `Makefile`, `CMakeLists.txt`, `Cargo.toml`, `configure.ac`, `.config` files for understanding compile-time flag state
- Compile-time flag documentation — project docs explaining feature flags, debug modes, and optional components
- Architecture map from Phase 1 — entry points and trust boundaries for reachability tracing
- Call graph from Phase 1 — cross-module call chains for upstream guard search and reachability verification
- Full filesystem access — read source files directly for independent verification of taint paths and guards
- **CWE pattern reference (REQUIRED)** — load the `agent/references/code-vuln-patterns/*.md` file matching each finding's CWE. Pattern knowledge is needed for guard completeness evaluation (Check 2: are ALL variant forms of this bug class guarded?) and exploitation feasibility assessment (Check 4: what does a real exploit look like for this pattern?)
- Variant findings from Phase 3 — load variant context for variant-aware verification
