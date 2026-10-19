---
name: code-finding-verification
description: False-positive elimination using five-check verification, devil's advocate review, and evidence-weighted adjudication
origin: Vigil
---

# Code Finding Verification

Together with `agent/shared-constraints-code.md` §5, this skill owns the code verification
contract: independently re-read the current sealed path, charge PASS and KILL the same evidence
cost, apply the net-new capability ceiling, and preserve genuine uncertainty for evidence
adjudication. The web
hunting rules are not required to reach or record a verdict.

## When to Activate

- Phase 3 of code analysis pipeline. Runs on confirmed findings from Phase 2.
- Every finding (from vulnerability analysis and variant analysis) must pass through this verification before being reported.
- Goal: eliminate false positives, adjust severity based on full context, synthesize attack chains from related findings, and produce a final set of verified findings.

## Tools

Full sealed-source access (same as hunter):

- **Read** — read files beneath `snapshot_path` to verify taint paths, guards, and call chains
- **rg** — search beneath `snapshot_path` for callers, guards, build configuration, and related paths
- **Glob** — find files beneath `snapshot_path` for build-system and module analysis
- **ctags** — `grep '^<symbol>\t' <ctags_path>` using the generation-bound Code Source Identity path

Use only ingest-time Git provenance/churn supplied in the backend repo envelope. The sealed source
contains no `.git`; never run ambient Git against the mutable `source_origin_path`.

Audit trail requirement:
- Every verification memo must state the concrete Read/rg/ctags lookups used
- If verification results are recorded in machine-readable form, include `audit_metadata.cross_ref_usage` with the actual queries executed

## Division of Labor

- **Operator provides**: findings with stored source identity/evidence, the current Code Source
  Identity and matching structural-index manifest, plus the complete backend threat-model envelope
  only when `current: true` and its generation/digest match that identity. CWE pattern refs,
  variant context, and any clipped threat summary are supplemental.
- **Verifier performs**: independent verification reading actual source code — never trust hunter annotations without independent confirmation

## Methodology — Five-Check Protocol

Every check produces one of four outcomes: PASS, KILL, DOWNGRADE, or ESCALATE. PASS and KILL carry the same evidence cost — PASS requires cited supporting evidence at the hunter's rigor bar, KILL requires cited counter-evidence at the same bar. DOWNGRADE applies when counter-evidence reduces exploitability but does not eliminate the bug. ESCALATE routes to the Evidence Adjudication Protocol section when evidence fits neither PASS nor KILL — absence of counter-evidence is not PASS evidence, and plausibility of counter-evidence is not KILL evidence.

### Check 1: Target-Kind Product Reachability

Apply the canonical product-reachability policy in `agent/shared-constraints-code.md` §5. Verify
the shipped surface first, then evaluate attacker control separately; otherwise an application-only
caller search silently kills valid library/framework, CLI, and plugin defects.

**Process:**
1. Verify the current threat model's per-module product surface against sealed build targets,
   package/export manifests, installed headers, registration code, and documentation.
2. Start at the vulnerable function, independently confirm the described defect, and enumerate its
   callers/exports/registrations with grep/ctags.
3. For an application/service, trace callers to a runtime route, protocol handler, job/event
   consumer, or other externally driven production entry and follow the actor-controlled data.
4. For a library/framework, cite the supported public/exported API, parser, callback, or codec and
   trace a valid supported invocation sequence from that boundary to the defect. Enumerate in-repo
   adapters, but treat an absent embedding consumer as missing attacker/impact context rather than
   proof that the public product path is dead.
5. For a CLI, trace from argv/stdin/environment/config/files accepted by the shipped command. For a
   plugin/extension, trace from its manifest/export/registration and documented host callback.
6. Record separately what the caller or attacker controls, which asset is affected, and which
   consumer/host preconditions remain unproved.

```bash
# Find all callers of the vulnerable function
rg "function_name\s*\(" --type c -n

# Trace upward through the call chain
rg "caller_function\s*\(" --type c -n

# Use ctags for definition lookup
grep '^parse_header_value\t' "$ctags_path"
```

**Decision:**
- **PASS:** cite the target-kind entry evidence and concrete path. Application/service claims need
  the runtime entry and actor-controlled taint. Library/framework claims need the public/export
  evidence, exact supported API sequence, and API-to-defect path. CLI/plugin claims need the shipped
  input or registered host contract. Naming a symbol without proving the applicable product surface
  is not sufficient.
- **DOWNGRADE:** the supported product path and defect are proved, but consumer/host evidence does
  not establish the claimed attacker role, asset, or blast radius. Preserve defect validity and cap
  the impact; do not convert missing downstream context into a false-positive kill.
- Hardcoded data defeats the claimed application attacker path: **KILL** that path. If the finding
  independently claims a concrete invariant failure on a supported public API sequence, adjudicate
  that claim instead of using the hardcoded application caller to erase it.
- No applicable shipped product entry exists (dead/internal code or an unexported helper): **KILL**
  ("unreachable from the target-kind product surface").
- The trigger violates documented API preconditions or requires an unsupported/impossible object
  state: **KILL** ("unsupported caller sequence, not product reachability").
- A test-only helper with no supported production/exported path: **KILL**. A test harness that calls
  the same supported production API may prove behavior; the harness is evidence, not the entry.
- **ESCALATE**: the evidence does not fit PASS or KILL — record the specific ambiguity (missing reachability witness, unresolved indirect call, callback registered at runtime, plugin-dispatched sink) and route to the **Evidence Adjudication Protocol** section below. Do not default to KILL or PASS.

### Check 2: Upstream Guards

The vulnerability analysis (Phase 3) evaluated guards within the vulnerable function and its immediate callers. This check extends the search to 3+ levels up the call chain.

**Process:**
1. For application/CLI/plugin caller paths identified in Check 1, Read functions 3-5 levels up. For
   a public library/framework boundary, read the API implementation and documented preconditions
   downstream to the sink; an absent consumer is not an implicit upstream guard.
2. Look for guards that validate the relevant data or state before it reaches the vulnerable function
3. Check if the guard is complete: correct variable, correct bound, all paths, before use
4. Read each caller's source code independently — do not trust the hunter's guard evaluation

**Decision:**
- Complete guard found upstream that covers all paths: **KILL** ("upstream guard in `validate_request()` at request.c:85 bounds-checks length before passing to vulnerable function")
- Partial guard found (some paths guarded, wrong bound, incomplete coverage): **DOWNGRADE** — the bug is real but exploitability is reduced. Document which paths are guarded and which remain unguarded. Do not KILL on a partial guard; partial means the attacker still has at least one unguarded path.
- **PASS**: cite the specific application/CLI/plugin callers examined 3-5 levels up, or the public
  API implementation and documented preconditions examined for a library/framework (file:line for
  each), then confirm no guard is present on the relevant value/state. Alternatively, name a
  present-but-ineffective check and show why it does not constrain the trigger. "No guard found"
  without the inspected path is not PASS evidence.
- **ESCALATE**: a guard exists but its completeness is contested — macro-expanded check whose definition is conditional, guard enforced by a caller invariant that may or may not hold, compile-time check whose predicate depends on unverified config. Record the specific ambiguity and route to the **Evidence Adjudication Protocol** section.

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

A test-only call site does not make an internal helper production-reachable. Conversely, a test or
sanitizer harness may reproduce a defect in a public API that the release build exports; decide
production reachability from the built/exported product path, not from where the proof driver lives.

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
- **ESCALATE**: the guarding symbol's default state is contested (vendor patch flips it, distro configs disagree, feature is on-by-default upstream but off in common downstreams). Record the specific config ambiguity and route to the **Evidence Adjudication Protocol** section.

### Check 4: Exploitation Feasibility (PoC-or-Proof Required)

Apply the constrained attacker or supported-product persona with maximum rigor. Reach a concrete,
probabilistic, downgraded/context-bound, or impossible/quality-only verdict; "unclear" is not an
acceptable terminal result.

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

   For an intrinsic library/framework, CLI, or plugin security invariant, the concrete proof may be
   a valid supported invocation sequence rather than a complete embedding application. Cite the
   public/registered entry, exact sequence or input, and observed harmful invariant failure (for
   example an invalid certificate accepted, a sanitizer-confirmed memory-safety violation, unsafe
   parser state, or attacker-scaled resource consumption). A surprising return value or generic
   caller-selected capability without a security boundary remains correctness/hardening, not an
   exploit.

2. **OR determine exploitation is probabilistic but feasible:**
   - Does exploitation require multiple attempts, favorable heap layout, race condition timing, or chaining with a separate info leak?
   - Are these standard attacker techniques (heap spray, ASLR brute-force, race window widening)?
   - Real-world exploitation is often probabilistic, not deterministic — do not KILL a finding simply because the exploit requires multiple attempts or favorable conditions.

3. **OR prove exploitation is impossible** (if you cannot construct any exploit path):
   - What specific constraint prevents the attacker input or valid supported invocation from
     reaching the sink?
   - What specific mitigation prevents the impact even if the sink is reached?
   - What specific system property makes the exploit non-functional?

4. **Check system mitigations** (either way):
   - ASLR: does the attack require knowing addresses? Is there an info leak to defeat ASLR?
   - Stack canaries: is the overflow on the stack? Does the canary protect the overwritten data?
   - Seccomp/sandbox: does the sandbox prevent the attacker's desired operation?
   - CFI/CET: does control-flow integrity prevent the attacker's code redirection?
   - W^X (NX): does the attacker need injected code, or is ROP sufficient?

**Decision:**
- **PASS (concrete)**: for an attacker-driven path, cite the exact bytes, target-kind entry,
  end-to-end code path, and concrete impact. For an intrinsic supported-API path, cite the exact
  valid invocation sequence, broken security invariant, end-to-end implementation path, and
  observed harmful outcome. A high-level narrative without the trigger and landing-site/invariant
  evidence is not PASS.
- Supported product path and concrete defect proved, but consumer-specific attacker control or
  blast radius unproved: **DOWNGRADE** the claim/severity to the evidenced product impact and state
  the missing consumer precondition; do not kill the defect merely because the embedding source is
  absent.
- **PASS (probabilistic)**: cite the standard attacker technique that closes the gap (heap spray shape, ASLR brute-force budget, race-window widening mechanism, info-leak chain partner) and the conditions under which it succeeds. Name the technique — "probabilistic but feasible" asserted without naming the technique is not PASS evidence.
- Exploit theoretically possible but mitigations make it impractical: **DOWNGRADE** severity + document mitigation effectiveness
- No concrete or probabilistic exploit path AND specific blocking constraint identified: **KILL** — you must cite (a) the specific constraint (guard, type-system limit, allocator cap, mitigation) with file:line, AND (b) demonstrate that the attacker cannot route around it. Enumerate and rule out: alternative input channels that bypass the constraint, encoding/normalization mismatches (UTF-8 vs. byte count, canonicalization before vs. after the check), partial-match or prefix bypasses, pre-guard-state mutation (TOCTOU on the checked value), integer-width or signedness escapes, and chained primitives that satisfy the constraint's precondition under attacker control. "Mitigation exists" is not sufficient; "mitigation exists AND these N routes around it are each closed by [specific evidence]" is.
- **ESCALATE**: exploit construction is blocked by a condition whose attacker-controllability is contested (heap grooming feasibility on this allocator, timing window width on this scheduler, availability of a companion info leak). Record the specific ambiguity and route to the **Evidence Adjudication Protocol** section.

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
- Check for comments explaining the design intent
- Check test files for test cases covering this exact path
- For a library/framework, check public API documentation, installed headers/exports, and stated
  preconditions. A precondition is counter-evidence only when the trigger actually violates it;
  downstream consumers cannot be assumed to add a guard the library contract does not require.
- Check the supplied ingest-time churn/security-history summary when it names this function or file;
  use it only to select evidence to inspect in the sealed source

```bash
# Check for related test cases
rg "test.*function_name|function_name.*test" --type-add 'test:*test*' -t test "$snapshot_path"
```

**Step 4 — Mitigation search:**
What external protections exist?
- Compiler flags: `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fsanitize=...`
- OS protections: ASLR, NX/W^X, seccomp profiles
- Application sandboxing: chroot, namespaces, pledge/unveil
- Network protections: rate limiting, connection limits, WAF rules
- Deployment configuration: read-only filesystem, dropped capabilities

**Rigor requirement:** A DA counter-argument must meet the same evidence bar as the original
finding. The hunter provided CWE, path, guard-failure analysis, and concrete security impact. Your
counter-argument must be equally specific: the exact guard code, proof it covers ALL paths (not
just one branch), and a concrete explanation of why the attacker input or supported invocation
cannot reach the sink/invariant failure. Circumstantial evidence — a test case exists, a commit
message mentions security, the code "looks well-written" — is not sufficient to kill.

**Outcome:**
- Counter-argument with specific code evidence **as rigorous as the original finding**: **KILL** with full counter-argument documentation
- Counter-evidence weakens but does not fully refute the finding: **DOWNGRADE** severity — the bug is real but the counter-evidence reduces impact or exploitability
- **PASS (survives)**: cite what you tried to disprove in each of the 4 steps (guard search, constraint search, intent search, mitigation search), the file:line evidence you inspected in each, and why the counter-hypotheses fail. A survival asserted without naming the disproof attempts is not PASS evidence — silence across the 4 steps is not the same as discharge of the 4 steps.
- **ESCALATE (evidence adjudication)**: counter-argument is plausible but rests on assumptions, implicit invariants, or incomplete coverage proof — route to the **Evidence Adjudication Protocol** section. Do not kill on uncertainty, do not pass on absence of counter-evidence. Record the specific ambiguity that blocks a clean PASS or KILL.

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

### Severity Calibration — defer to the shared impact gate (before `confirmed`)

Checks 1–5 establish the bug is **real** (existence); they do not judge whether a *real* bug's impact
is **overclaimed** — a separate, cross-track axis. Before recording `confirmed` at the hunter's
severity, run the shared gate (`agent/references/finding-fp-and-severity-gate.md`): **C5** (per-metric
CVSS discipline), **C6** (real-object proof, not an orphan/unvalidated write), **C7**
(by-design/documented/precedent), and the **`shared-constraints-code.md` §5 net-new test**
(a real injection that only reproduces what the attacker's own controlled repo/PR/template/build
already achieves grants zero net-new capability). A finding can PASS all five existence checks and
still DOWNGRADE/KILL there — cite the gate check, not a failed existence check. This calibration's
absence is what let real-but-redundant build-tool injections ship as High.

For library/framework, CLI, and plugin targets, carry the Check-1 distinction through this gate:
product reachability can confirm the defect, while missing consumer/host evidence limits the
attacker vector, affected asset, and severity. Generic API capability and correctness-only behavior
still fail C6/C7 or the net-new test; a concrete TLS/authentication, memory-safety, unsafe-parser, or
resource invariant is not false merely because deployment-specific impact remains conditional.

## Evidence Adjudication Protocol

Entered when any of Checks 1-5 returns **ESCALATE** — the evidence fits neither the PASS bar nor the KILL bar for that check. Check 5 is one entry point; Checks 1-4 may also escalate when their specific ambiguity is recorded.

**When to invoke adjudication:**
- Reachability witness is indirect (runtime callback, plugin dispatch, FFI boundary) and the taint trace cannot be closed from source alone
- Upstream guard's completeness depends on a macro, caller invariant, or compile-time predicate that cannot be resolved from the source checked out
- Build-config default state is contested across vendors, distros, or release profiles
- Exploit construction is blocked by a condition whose attacker-controllability is contested (heap grooming, timing window, info-leak availability)
- Devil's advocate found a partial guard but it may be bypassable
- The counter-argument relies on implicit invariants not enforced in code
- Two reasonable security engineers could disagree on the disposition

**Adjudication procedure:**
1. Document the argument FOR the finding:
   - Hunter's original evidence
   - Your verification of the taint path (Checks 1-4)
   - Why the devil's advocate counter-argument fails or is incomplete
2. Document the argument AGAINST the finding:
   - Devil's advocate evidence from Check 5
   - Specific code locations supporting the counter-argument
   - What assumption would need to hold for this to be safe
3. Group reviews that share a premise, trace, source excerpt, or derived assumption into one
   evidence group. Correlated reviews are one evidentiary observation, regardless of reviewer count.
4. Present both perspectives to the operator. The operator may dispatch an independent verifier
   for missing evidence, but an additional opinion does not increase evidentiary weight by itself.
5. Decide from the strongest complete proof. A cited source-to-sink, guard, build, state-sequence,
   or runtime proof that closes the disputed condition outweighs any number of correlated opinions.
   Never decide from reviewer count.
6. If no side closes the disputed condition, record `disputed`, retain every argument and evidence
   group, and identify the exact proof needed to resolve it.
7. Record the adjudication outcome, evidence groups, and decisive proof for the audit trail.

**Output format for adjudication request:**
```
ADJUDICATION REQUEST: [Finding ID]
FOR:    [summary of evidence supporting the finding]
AGAINST: [summary of devil's advocate evidence]
RECOMMENDATION: [your lean, with confidence level]
EVIDENCE GROUPS: [which observations share a premise or trace]
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

Record chains via `vigil assess record-chain code-vuln-verifier <chain-json>`

## FP Context

False positives are expected in any AI-assisted vulnerability pipeline. Your verification
standards:
- Confirm findings when the supporting evidence cited across the 5 checks is at least as concrete as the hunter's original claim. Kill findings when counter-evidence cited across the 5 checks reaches the same bar. When the evidence fits neither, escalate to evidence adjudication — do not default to either outcome. KILL and CONFIRM carry equal evidence cost; neither is the path of least resistance.
- Use DOWNGRADE when counter-evidence reduces severity or exploitability but does not eliminate the bug — partial guards, mitigations that narrow the attack window, or constraints that limit impact are downgrades, not kills
- Escalate to evidence adjudication when evidence is ambiguous — do not resolve uncertainty by defaulting to kill, and do not resolve it by defaulting to confirm
- Apply equal rigor to high-confidence and low-confidence findings alike

**Every kill needs cited counter-evidence at the same specificity a pass would need** — that
symmetric bar, not a target ratio, is what separates a real kill from over-kill. Verify each kill's
counter-evidence is as specific and complete as the hunter's original evidence before recording it.
Common over-kill patterns: treating partial guards as complete, treating probabilistic exploits as
infeasible, treating test existence as proof of correctness, treating implicit constraints as
enforced guarantees. When Check 5 (devil's advocate) is doing most of the killing on a finding,
confirm its counter-hypothesis is cited and concrete, not circumstantial.

## Dispositions

| Disposition | Meaning | Report Action |
|-------------|---------|---------------|
| `confirmed` | Supporting evidence across the 5 checks is at least as concrete as the hunter's claim; stated severity holds | Include in report as-is |
| `downgraded` | Finding survives but at lower severity | Include with adjusted severity + reasoning |
| `pending_runtime_proof` | Static/code evidence is strong (Checks 1-3 + 5 survive) but the claimed invariant failure still lacks executable or equivalently decisive proof — accepted into the holding area, not yet report-ready. An executable valid supported-API driver counts; absence of an embedding app alone does not force this disposition. | Hold in the theoretical holding area; excluded from the report and from exploit-candidates, and BLOCKS report-readiness, until a controlled proof pass re-verifies it `confirmed`/`downgraded` |
| `killed` | Counter-evidence across the 5 checks reaches the same bar as the hunter's claim; finding is a false positive | Exclude from report, persist a `false_positive` verification on the canonical finding, record kill reason for audit |
| `disputed` | Evidence fits neither the PASS bar nor the KILL bar at one or more checks after evidence adjudication | Hold with all arguments and evidence groups pending decisive proof |

### Phase-4 Debate Protocol — persisted Ideator-vs-Tracer narrative

Before recording a `confirmed` or `pending_runtime_proof` disposition, write the
adversarial debate to a durable note and register it so the decision is auditable
later. The Ideator argues the finding is real; the Tracer challenges the causal
chain with code/PoC evidence. Capture both, then the verdict.

Template — write to `notes/<slug>-debate.md`:

```
# <slug> — Ideator-vs-Tracer debate

## Claim (Ideator)
<the attacker outcome, or bounded intrinsic product outcome, with the path / sink or invariant>

## Causal challenge (Tracer)
<the specific link in the chain being contested: reachability, guard,
build-config, or exploitation feasibility — name the file:line>

## Evidence
<code citations (file:line), grep/ctags queries run, and any PoC bytes or
runtime observation that resolve the challenge>

## Verdict
disposition=<confirmed|pending_runtime_proof|downgraded|killed>
rationale=<why the evidence supports this disposition; for
pending_runtime_proof, state exactly which runtime proof is still owed>
```

Register it on the verify call so it links to the finding:

```bash
vigil assess finding verify <slug> --status pending_runtime_proof \
  --reason "static evidence accepted; runtime PoC outstanding" \
  --next-test-file next-test.json \
  --narrative notes/<slug>-debate.md
```

`--narrative` registers the file as a `kind=verification-narrative` artifact with
`related_finding_slug=<slug>`; retrieve later with
`vigil assess artifact search --finding <slug> --kind verification-narrative`.

`pending_runtime_proof` requires `--next-test-file`: the runtime proof still owed, written as the
plan the operator prepares from. It states the hypothesis, the observation that would confirm it,
the observation that would falsify it, and a `local`/`live`/`unknown` route hint (a supported-API
driver or local build is `local`). Make the falsifier as concrete as the confirmer, because a proof
pass that can only succeed cannot disprove the claim. Read `vigil assess contract finding verify`
for the exact fields; the route hint is a suggestion and grants no scope or approval.

### Structured Counter-Check Format (for audit trail)

Every killed finding must record a specific, verifiable kill reason:

```
KILL: [Finding ID]
Check Failed: [1-5]
Reason: [specific, verifiable statement]
Evidence: [code location, build config line, or upstream guard that proves the kill]
Devil's Advocate: [if Check 5 — the counter-argument that succeeded]
```

Examples:
- "Check 1 KILL: `test_parser()` calls an unexported helper with an impossible state; no shipped
  application, public API, CLI, or registered plugin path reaches it"
- "Check 2 KILL: `validate_header_length()` at http.c:92 bounds-checks to 8192 bytes on all paths before data reaches vulnerable `parse_header_value()`"
- "Check 3 KILL: code inside `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, not compiled in release"
- "Check 4 KILL: overflow is 1 byte (null terminator), lands on padding between stack variables, no exploitable overwrite. Attempted to construct exploit — cannot overwrite return address or any function pointer."
- "Check 5 KILL: `test_oversized_header` in test/http_tests.c exercises this exact path and asserts
  rejection. The `ENSURE_SIZE` macro at parser.c:89 expands to a bounds check, and every applicable
  shipped product caller reaches that macro before the vulnerable arithmetic."

When you persist a false positive, write `counter-check.json` with `method`,
`expected_result`, `observed_result`, `falsified_claim`, `completed: true`, and
`proof_receipt_ids`, then use `vigil assess finding verify <slug> --status false_positive
--counter-check-file counter-check.json --reason "<rationale>"`. If the counter-check
could not run, record `blocked` or `pending_runtime_proof`, never `false_positive`.
Use `finding verify --status <verdict> --reason "<rationale>"` for other flows;
terminal decisions include `--proof-receipt-id`. Use `finding update <slug> --status
draft ...` when new evidence disproves a prior decision so the audited invalidation
returns it to `verification_status=unreviewed`.

## Output Format

The verification phase produces:

1. **Verification Results**: per-finding table with all 5 check results and final disposition
2. **Kill List**: killed findings with specific check failure, evidence, and devil's advocate reasoning
3. **Downgrades**: findings with adjusted severity, original severity, and evidence
4. **Adjudication Requests**: ambiguous findings with FOR/AGAINST arguments and evidence groups for operator review
5. **Attack Chains**: composite chains linking multiple findings with data flow evidence
6. **Verification Summary**: statistics (X in, Y confirmed, Z killed, W downgraded, V disputed) and confirmation rate

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
        "Read test/http_tests.c test_oversized_header"
      ],
      "notes": "Used ctags for definition lookup, rg for caller enumeration, and independent source/test reads for guard and intent analysis"
    },
    "fp_rate": {
      "total_findings": 12,
      "confirmed": 3,
      "downgraded": 2,
      "killed": 6,
      "disputed": 1,
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
- Full sealed-source access — read source files beneath `snapshot_path` for independent verification of taint paths and guards
- **CWE pattern reference (REQUIRED)** — load the `agent/references/code-vuln-patterns/*.md` file matching each finding's CWE. Pattern knowledge is needed for guard completeness evaluation (Check 2: are ALL variant forms of this bug class guarded?) and exploitation feasibility assessment (Check 4: what does a real exploit look like for this pattern?)
- Variant findings from Phase 3 — load variant context for variant-aware verification
- **Shared impact & severity-calibration gate** — `agent/references/finding-fp-and-severity-gate.md` (see "Severity Calibration" above). Shared with the live/web verifier, not web-only.
