---
name: code-finding-verification
description: False-positive elimination using five-check verification protocol with devil's advocate and multi-perspective voting
origin: AI Threat Hunting
---

# Code Finding Verification

## When to Activate

- Phase 3 of code analysis pipeline. Runs on confirmed findings from Phase 2.
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

Every check produces one of four outcomes: PASS, KILL, DOWNGRADE, or ESCALATE. PASS and KILL carry the same evidence cost — PASS requires cited supporting evidence at the hunter's rigor bar, KILL requires cited counter-evidence at the same bar. DOWNGRADE applies when counter-evidence reduces exploitability but does not eliminate the bug. ESCALATE routes to the Multi-Perspective Voting Protocol section when evidence fits neither PASS nor KILL — absence of counter-evidence is not PASS evidence, and plausibility of counter-evidence is not KILL evidence.

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
- **PASS**: cite the external entry point (network handler, file parser, CLI argv, IPC endpoint), the concrete function chain from that entry to the sink (file:line for each hop), and at least one caller where attacker-controlled bytes reach the sink without being normalized to a constant. Naming the entry point alone is not sufficient — the taint must be traced.
- Entry point found but data is hardcoded/constant by the time it reaches vulnerable function: **KILL** ("unreachable with untrusted data — all callers pass constants")
- No external entry point found (dead code, internal-only function): **KILL** ("no external entry point — function is unreachable from attack surface")
- Entry point found but only through test code: **KILL** ("only reachable from test harness, not production code")
- **ESCALATE**: the evidence does not fit PASS or KILL — record the specific ambiguity (missing reachability witness, unresolved indirect call, callback registered at runtime, plugin-dispatched sink) and route to the **Multi-Perspective Voting Protocol** section below. Do not default to KILL or PASS.

### Check 2: Upstream Guards

The vulnerability analysis (Phase 3) evaluated guards within the vulnerable function and its immediate callers. This check extends the search to 3+ levels up the call chain.

**Process:**
1. For each caller path identified in Check 1, Read functions 3-5 levels up
2. Look for guards that validate the untrusted data before it reaches the vulnerable function
3. Check if the guard is complete: correct variable, correct bound, all paths, before use
4. Read each caller's source code independently — do not trust the hunter's guard evaluation

**Decision:**
- Complete guard found upstream that covers all paths: **KILL** ("upstream guard in `validate_request()` at request.c:85 bounds-checks length before passing to vulnerable function")
- Partial guard found (some paths guarded, wrong bound, incomplete coverage): **DOWNGRADE** — the bug is real but exploitability is reduced. Document which paths are guarded and which remain unguarded. Do not KILL on a partial guard; partial means the attacker still has at least one unguarded path.
- **PASS**: cite the specific callers examined 3-5 levels up (file:line for each) and confirm no guard is present on the tainted variable, OR name a present-but-ineffective check and show why it does not constrain the attacker-controlled value (wrong variable, wrong bound, wrong branch, executed after use). "No guard found" asserted without naming the callers inspected is not PASS evidence.
- **ESCALATE**: a guard exists but its completeness is contested — macro-expanded check whose definition is conditional, guard enforced by a caller invariant that may or may not hold, compile-time check whose predicate depends on unverified config. Record the specific ambiguity and route to the **Multi-Perspective Voting Protocol** section.

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
- **PASS**: cite the build-system evidence that the vulnerable code is compiled into the default production build — the Makefile/CMakeLists/Cargo.toml/build.rs line enabling the relevant translation unit, the defconfig or release profile that sets the guarding symbol, or confirmation that no `#ifdef`/`#[cfg(...)]`/build-tag wraps the sink. If a guarding symbol exists, name it and show the config line that enables it. "No conditional compilation" asserted without the grep result is not PASS evidence.
- Code behind debug-only flag (`#ifdef DEBUG`, `#[cfg(test)]`): **KILL** ("debug-only code, not compiled in production")
- Code behind optional feature flag: **DOWNGRADE** severity + note the flag ("vulnerable code requires `--enable-experimental-parser` flag, not enabled by default")
- Code excluded on common platforms: **DOWNGRADE** + note platforms affected
- **ESCALATE**: the guarding symbol's default state is contested (vendor patch flips it, distro configs disagree, feature is on-by-default upstream but off in common downstreams). Record the specific config ambiguity and route to the **Multi-Perspective Voting Protocol** section.

### Check 4: Exploitation Feasibility (PoC-or-Proof Required)

Apply the constrained attacker persona with maximum rigor. You must reach one of three outcomes — "unclear" is not acceptable, but "probabilistic" is a valid and common result.

**Process:**

1. **Construct the exploit** (attempt this first):
   - When the finding claims a library/stdlib function is the sink (e.g., `extractall()`, `exec()`, `deserialize()`), call that function with adversarial input and observe the result before reasoning about feasibility. If the function handles the attack correctly, KILL.
   - What specific bytes must the attacker send?
   - Through which entry point (protocol field, parameter, file format field)?
   - What is the exact code path from entry to vulnerability trigger?
   - What is the concrete impact when triggered?
     - Buffer overflow: how many bytes overflow, where do they land, what gets overwritten?
     - Integer overflow: what value results, how is it used subsequently?
     - Use-after-free: what object is freed, what reuses the memory, what fills it?
     - Auth bypass: what access does the attacker gain?
     - Injection: what command/query executes, with what privileges?

2. **OR determine exploitation is probabilistic but feasible:**
   - Does exploitation require multiple attempts, favorable heap layout, race condition timing, or chaining with a separate info leak?
   - Are these standard attacker techniques (heap spray, ASLR brute-force, race window widening)?
   - Real-world exploitation is often probabilistic, not deterministic — do not KILL a finding simply because the exploit requires multiple attempts or favorable conditions.

3. **OR prove exploitation is impossible** (if you cannot construct any exploit path):
   - What specific constraint prevents the attacker input from reaching the sink?
   - What specific mitigation prevents the impact even if the sink is reached?
   - What specific system property makes the exploit non-functional?

4. **Check system mitigations** (either way):
   - ASLR: does the attack require knowing addresses? Is there an info leak to defeat ASLR?
   - Stack canaries: is the overflow on the stack? Does the canary protect the overwritten data?
   - Seccomp/sandbox: does the sandbox prevent the attacker's desired operation?
   - CFI/CET: does control-flow integrity prevent the attacker's code redirection?
   - W^X (NX): does the attacker need injected code, or is ROP sufficient?

**Decision:**
- **PASS (concrete)**: cite the exact bytes, entry point, end-to-end code path (file:line per hop), and concrete impact (bytes overflowed and what they overwrite, command executed and its privileges, object freed and what reuses it, access gained). A high-level "attacker sends oversized input" narrative without the byte-level trigger and landing-site description is not PASS evidence.
- **PASS (probabilistic)**: cite the standard attacker technique that closes the gap (heap spray shape, ASLR brute-force budget, race-window widening mechanism, info-leak chain partner) and the conditions under which it succeeds. Name the technique — "probabilistic but feasible" asserted without naming the technique is not PASS evidence.
- Exploit theoretically possible but mitigations make it impractical: **DOWNGRADE** severity + document mitigation effectiveness
- No concrete or probabilistic exploit path AND specific blocking constraint identified: **KILL** — you must cite (a) the specific constraint (guard, type-system limit, allocator cap, mitigation) with file:line, AND (b) demonstrate that the attacker cannot route around it. Enumerate and rule out: alternative input channels that bypass the constraint, encoding/normalization mismatches (UTF-8 vs. byte count, canonicalization before vs. after the check), partial-match or prefix bypasses, pre-guard-state mutation (TOCTOU on the checked value), integer-width or signedness escapes, and chained primitives that satisfy the constraint's precondition under attacker control. "Mitigation exists" is not sufficient; "mitigation exists AND these N routes around it are each closed by [specific evidence]" is.
- **ESCALATE**: exploit construction is blocked by a condition whose attacker-controllability is contested (heap grooming feasibility on this allocator, timing window width on this scheduler, availability of a companion info leak). Record the specific ambiguity and route to the **Multi-Perspective Voting Protocol** section.

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

**Rigor requirement:** A DA counter-argument must meet the same evidence bar as the original finding. The hunter provided CWE, taint path, guard failure analysis, and concrete attacker impact. Your counter-argument must be equally specific: the exact guard code, proof it covers ALL paths (not just one branch), and a concrete explanation of why the attacker's input cannot reach the sink. Circumstantial evidence — a test case exists, a commit message mentions security, the code "looks well-written" — is not sufficient to kill.

**Outcome:**
- Counter-argument with specific code evidence **as rigorous as the original finding**: **KILL** with full counter-argument documentation
- Counter-evidence weakens but does not fully refute the finding: **DOWNGRADE** severity — the bug is real but the counter-evidence reduces impact or exploitability
- **PASS (survives)**: cite what you tried to disprove in each of the 4 steps (guard search, constraint search, intent search, mitigation search), the file:line evidence you inspected in each, and why the counter-hypotheses fail. A survival asserted without naming the disproof attempts is not PASS evidence — silence across the 4 steps is not the same as discharge of the 4 steps.
- **ESCALATE (multi-perspective voting)**: counter-argument is plausible but rests on assumptions, implicit invariants, or incomplete coverage proof — route to the **Multi-Perspective Voting Protocol** section. Do not kill on uncertainty, do not pass on absence of counter-evidence. Record the specific ambiguity that blocks a clean PASS or KILL.

Document: what you tried to disprove, what evidence you found for and against, and the final determination. This documentation strengthens confirmed findings and makes kills auditable.

### Protocol/Resource-Limit Severity Check

Use this when a finding depends on bypassing a size limit, timeout, buffer cap,
request spool, negotiation limit, compression ratio, or other resource control.
Before confirming High/Critical, answer all of the following with source-backed
evidence:

1. **Intended boundary:** Read the docs, comments, blame, or introducing commit for
   the limit. Is it documented or historically intended to cap total attacker work,
   or only a local implementation detail such as an in-memory spool buffer?
2. **Equivalent entry points:** Compare sibling transports and protocol modes. If
   the same logical byte stream can already be sent over SSH, raw TCP, local IPC,
   chunked HTTP, or another default path, the wrapper-specific bypass is usually
   hardening/documentation unless it crosses an independent default deployment
   boundary.
3. **Default reachability:** Prove the path is enabled by default for the attacker
   role. Downgrade when the path needs non-default config, authenticated service
   selection, repository-controlled config, or write access that already implies a
   stronger primitive.
4. **Second-order impact:** Prove what the downstream component does with the extra
   bytes. Look for superlinear CPU, unbounded retained memory, duplicate state that
   survives deduplication, output amplification, child-process fanout, pack/build
   amplification, crash, memory corruption, or privilege-boundary crossing. Linear
   parsing of more valid protocol bytes is not enough for High.
5. **Negative controls:** Test or inspect duplicate handling, feature gates, per-line
   caps, parser state resets, and downstream deduplication. Record the result even
   when it weakens the finding.

Severity guidance: a resource-limit bypass can be High only when the proved default
path creates service-level impact that ordinary protocol access cannot already
create. If the best proof is "small compressed/request body becomes a larger valid
protocol stream" and downstream work remains linear with bounded memory, treat it
as Medium at most, often hardening or documentation. See
`agent/references/code-vuln-patterns/algorithmic-dos.md` "Decompression Bombs"
for concrete examples of the boundary between High and Medium.

## Multi-Perspective Voting Protocol

Entered when any of Checks 1-5 returns **ESCALATE** — the evidence fits neither the PASS bar nor the KILL bar for that check. Check 5 is one entry point; Checks 1-4 may also escalate when their specific ambiguity is recorded.

**When to invoke voting:**
- Reachability witness is indirect (runtime callback, plugin dispatch, FFI boundary) and the taint trace cannot be closed from source alone
- Upstream guard's completeness depends on a macro, caller invariant, or compile-time predicate that cannot be resolved from the source checked out
- Build-config default state is contested across vendors, distros, or release profiles
- Exploit construction is blocked by a condition whose attacker-controllability is contested (heap grooming, timing window, info-leak availability)
- Devil's advocate found a partial guard but it may be bypassable
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

Record chains via `aith assess record-chain code-vuln-verifier <chain-json>`

## FP Context

False positives are expected in any AI-assisted vulnerability pipeline. Your verification
standards:
- Confirm findings when the supporting evidence cited across the 5 checks is at least as concrete as the hunter's original claim. Kill findings when counter-evidence cited across the 5 checks reaches the same bar. When the evidence fits neither, escalate to the voting step — do not default to either outcome. KILL and CONFIRM carry equal evidence cost; neither is the path of least resistance.
- Use DOWNGRADE when counter-evidence reduces severity or exploitability but does not eliminate the bug — partial guards, mitigations that narrow the attack window, or constraints that limit impact are downgrades, not kills
- Escalate to voting when evidence is ambiguous — do not resolve uncertainty by defaulting to kill, and do not resolve it by defaulting to confirm
- Apply equal rigor to high-confidence and low-confidence findings alike

**Kill rate calibration:** If you kill >80% of findings, you are likely too aggressive. Review
each kill and verify the counter-evidence is as specific and complete as the hunter's original
evidence. Common over-kill patterns: treating partial guards as complete, treating probabilistic
exploits as infeasible, treating test existence as proof of correctness, treating implicit
constraints as enforced guarantees. Track which check produces the most kills — if Check 5
accounts for the majority, your DA is likely over-interpreting circumstantial evidence.

## Dispositions

| Disposition | Meaning | Report Action |
|-------------|---------|---------------|
| `confirmed` | Supporting evidence across the 5 checks is at least as concrete as the hunter's claim; stated severity holds | Include in report as-is |
| `downgraded` | Finding survives but at lower severity | Include with adjusted severity + reasoning |
| `killed` | Counter-evidence across the 5 checks reaches the same bar as the hunter's claim; finding is a false positive | Exclude from report, persist a `false_positive` verification on the canonical finding, record kill reason for audit |
| `voting` | Evidence fits neither the PASS bar nor the KILL bar at one or more checks — escalated to multi-perspective voting | Hold pending operator decision |

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
- Use `aith assess kill-finding <slug> ...` when you already have the kill rationale in hand, because it enforces the required false-positive fields before the request leaves the CLI
- Use `aith assess verify-finding <slug> <verification-json>` for confirm/downgrade/dispute flows or when the verification payload already exists on disk, because the verification transition belongs in the audit ledger rather than a generic finding patch
- Use `aith assess reset-finding <slug> ...` when new evidence disproves an earlier verified or false-positive verdict, because reopening is its own lifecycle transition and should clear the prior verification state instead of patching fields by hand

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
