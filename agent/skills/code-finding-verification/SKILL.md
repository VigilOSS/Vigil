---
name: code-finding-verification
description: False-positive elimination using five-check verification, devil's advocate review, and evidence-weighted adjudication
origin: Vigil
---

# Code Finding Verification

Together with `agent/shared-constraints-code.md` §5, this skill owns the code verification
contract: independently re-read the current sealed path, charge PASS and KILL the same evidence
cost, apply the net-new capability ceiling, and preserve genuine uncertainty for adjudication. The
web hunting rules are not required. `agent/agents/code-vuln-verifier.md` owns report-readiness,
re-banding, `honest_bounds`, and the closing verbs; the shared specialist core owns approval and
receipt discipline.

## When to Activate

Phase 3 of the code pipeline, on every finding from vulnerability and variant analysis before it is
reported. Inputs: the findings with stored source identity and evidence, the current Code Source
Identity and structural-index manifest, and the threat-model envelope when `current: true` with
matching generation/digest; pattern references, variant context, and clipped summaries are
supplemental. Never trust hunter annotations without reading the source.

## Tools

Read, `rg`, Glob, and ctags beneath the sealed `snapshot_path`; Git provenance only from the repo
envelope. Name the lookups you ran in each memo (`audit_metadata.cross_ref_usage` when recorded).
Before building native source or using sanitizers, load `agent/skills/code-fuzz-campaign/SKILL.md`
**Generation-Bound Build Workspace** and **Source-build and allocator preflight**, and record the
toolchain and allocator settings with the receipt. Keep a diagnostic allocator configuration
separate from the production configuration that supports the impact claim: a crash under one does
not prove behavior under the other.

## Methodology — Five-Check Protocol

Every check returns PASS, KILL, DOWNGRADE, or ESCALATE. PASS and KILL carry the same evidence cost: PASS cites supporting evidence at the hunter's rigor bar, KILL cites counter-evidence at the same bar. DOWNGRADE applies when counter-evidence reduces exploitability without eliminating the bug. ESCALATE routes to evidence adjudication when the evidence fits neither PASS nor KILL — absence of counter-evidence is not PASS evidence, and plausibility of counter-evidence is not KILL evidence.

Finish reproduction and evidence documentation on the same finding before the terminal verdict.
Once cited code settles a check, move on; when source cannot settle it, record the specific
ambiguity and escalate instead of re-arguing it.

### Check 1: Target-Kind Product Reachability

Apply `agent/shared-constraints-code.md` §5 per surface kind: verify the shipped surface first,
then attacker control separately, because an application-only caller search silently kills valid
library, CLI, and plugin defects. Check the threat model's product surface against sealed build
targets, export manifests, installed headers, registration code, and docs; its trusted-inputs set
is advisory and never a KILL alone, so read the writer. Record control, asset, and unproved
consumer preconditions separately.

- **PASS:** entry evidence and concrete path for the applicable surface, not just a symbol name.
- **DOWNGRADE:** path and defect proved; the claimed attacker role, asset, or blast radius is not.
- **KILL:** hardcoded data defeats the claimed application path (adjudicate any independent
  public-API invariant claim separately); no applicable shipped entry; a trigger that violates
  documented preconditions or needs impossible state; a test-only helper. A harness calling the
  supported API is evidence, not the entry.
- **ESCALATE:** an indirect call, runtime-registered callback, or plugin-dispatched sink that source
  cannot close.

### Check 2: Upstream Guards

Read three to five caller levels up the application, CLI, or plugin path yourself; for a library,
read the API implementation and documented preconditions down to the sink (an absent consumer is
not a guard). Guards hide in request validation, protocol framing, gateway or middleware limits,
configuration caps, and macro wrappers.

- **KILL:** a complete guard on all paths, cited ("`validate_request()` at request.c:85").
- **DOWNGRADE:** a partial guard — never KILL on one; an unguarded path remains.
- **PASS:** the callers or API code examined (file:line) with no effective guard, or a present check
  shown not to constrain the trigger.
- **ESCALATE:** completeness depends on a conditional macro, an unverified caller invariant, or a
  compile-time predicate over unverified config.

### Check 3: Build Configuration

Is the code compiled into the default production build? Check `#if`/`#ifdef`, `#[cfg(...)]`,
`//go:build`, build-system feature flags, platform directories, and each guarding symbol's default.
A test-only call site does not make an internal helper reachable, while a harness can reproduce a
defect in an API the release build exports.

- **PASS:** the build-file, defconfig, or release-profile line, or the search showing no gate.
- **KILL:** debug- or test-only (`#ifdef DEBUG`, `#[cfg(test)]`,
  `FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`).
- **DOWNGRADE:** a non-default feature flag, or exclusion on common platforms (name them).
- **ESCALATE:** a contested default (vendor patches, distro configs, upstream on but downstream off).

### Check 4: Exploitation Feasibility (PoC-or-Proof Required)

"Unclear" is not terminal. Construct the exploit first: when the claimed sink is a library or stdlib
function (`extractall()`, `exec()`, a deserializer), call it with adversarial input and observe the
result before reasoning; if it handles the attack, KILL. Otherwise name the bytes, entry field,
path, and landing site (what the overflow overwrites, how the wrapped value is used, what reuses the
freed object, the access or command gained). For an intrinsic library, CLI, or plugin invariant, a
valid supported invocation with an observed harmful failure is the proof (invalid certificate
accepted, sanitizer-confirmed memory error, unsafe parser state, attacker-scaled resource use); a
surprising return value or caller-selected capability without a boundary is hardening.

- **PASS (concrete):** trigger, entry, end-to-end path, landing-site or invariant evidence.
- **PASS (probabilistic):** name the technique that closes the gap (heap shaping, ASLR brute-force
  budget, race-window widening, a companion leak) and its conditions; needing several attempts is
  not a KILL.
- **DOWNGRADE:** defect proved but consumer-specific control or blast radius is not, or mitigations
  (ASLR without a leak, canaries over the overwritten data, seccomp scope, CFI/CET, W^X) make it
  impractical.
- **KILL:** the specific constraint with file:line, plus proof the attacker cannot route around it:
  other input channels, encoding or canonicalization order, prefix or partial matches, TOCTOU on
  the checked value, integer-width or signedness escapes, and chained primitives that satisfy the
  constraint. "Mitigation exists" is not a KILL.
- **ESCALATE:** attacker-controllability of the blocker is contested (grooming on this allocator,
  window width on this scheduler, leak availability).

### Check 5: Devil's Advocate (Trail of Bits fp-check methodology)

Assume the finding is wrong. Guard search: the whole file, other branches, same-file callers,
macros that expand to checks, assertions live in release. Constraint search: framing limits,
call-site value constraints, type limits, allocator caps, NUL termination. Intent search: comments,
tests on this exact path, API docs and preconditions (counter-evidence only when the trigger
violates them), the supplied security-history summary as a pointer. Mitigation search: compiler
hardening, OS protections, sandboxing, rate limits, deployment config.

A counter-argument must be as specific as the finding: the exact guard, proof it covers every path,
and why the input cannot reach the failure. A test existing, a security-sounding commit, or tidy code
is circumstantial. KILL at that bar; DOWNGRADE when it weakens without refuting; PASS by naming what
you tried in each search and the file:line you read; ESCALATE when it rests on unenforced invariants.

### Protocol/Resource-Limit Severity Check

Use this when a finding depends on bypassing a size limit, timeout, buffer cap, request spool,
negotiation limit, or compression ratio. Before High/Critical, answer with source-backed evidence:

1. **Intended boundary:** do docs, comments, blame, or the introducing commit show the limit caps
   total attacker work, or is it a local detail such as an in-memory spool buffer?
2. **Equivalent entry points:** if the same byte stream already flows over SSH, raw TCP, local IPC,
   chunked HTTP, or another default path, a wrapper-specific bypass is usually hardening unless it
   crosses an independent default deployment boundary.
3. **Default reachability:** downgrade when the path needs non-default config, authenticated service
   selection, repository-controlled config, or write access implying a stronger primitive.
4. **Second-order impact:** superlinear CPU, unbounded retained memory, state surviving
   deduplication, output amplification, process fanout, pack/build amplification, crash, memory
   corruption, or a privilege crossing. Linear parsing of more valid bytes is not High.
5. **Negative controls:** duplicate handling, feature gates, per-line caps, parser resets,
   downstream deduplication — record the result even when it weakens the finding.

High needs service-level impact on the default path that ordinary protocol access cannot already
cause; "a small compressed body becomes a larger valid stream" with linear work and bounded memory
is Medium at most. `agent/references/code-vuln-patterns/algorithmic-dos.md` "Decompression Bombs"
draws the line with examples.

### Severity Calibration

Checks 1-5 establish that the bug is real; overclaim is a separate axis. Before `confirmed` at the
hunter's severity, run `agent/references/finding-fp-and-severity-gate.md` C5-C7 and the
`agent/shared-constraints-code.md` §5 net-new test, citing the gate check when it downgrades or kills (the role's "Severity & Report-Readiness
Gate" lists the steps). For library, CLI, and plugin targets, missing consumer evidence limits
vector, asset, and severity; a concrete TLS/authentication, memory-safety, unsafe-parser, or
resource invariant is not false because deployment impact stays conditional, while generic API
capability and correctness-only behavior fail C6/C7.

## Evidence Adjudication

On ESCALATE, argue for and against, group observations that share a premise, trace, or assumption
into one evidence group, and decide from the strongest complete proof — never reviewer count. If no
side closes the condition, record `disputed` with every argument and the proof that would resolve
it. Procedure and request format: `agent/references/runtime-guides/code-verification-adjudication.md`.

## Variant-Aware Verification

A killed original does not kill its variants; each has its own callers, guards, and build flags and
gets all five checks. A confirmed original's Check 1-4 evidence supports a variant only where the
code is the same, and a variant behind a stronger guard can be clean. Check whether variants in
different modules compose.

## Attack Chain Synthesis

After the individual verdicts, look for an info leak beside a memory corruption, a lower-severity
bug enabling a higher one, or a logic bug supplying a primitive. Verify that A's output feeds B,
that the attacker controls the transition, and the composite impact and prerequisites, then record
it with `vigil assess record-chain code-vuln-verifier <chain-json>` (template in the adjudication
reference).

## FP Context

Over-kill is as real as false positives. Confirm when support across the checks is as concrete as
the claim, kill at the same bar, downgrade for partial guards and narrowing mitigations, escalate
when neither bar is met, and hold high- and low-confidence findings to the same rigor. Before
closing, check every kill for the over-kill patterns: a partial guard treated as complete, a
probabilistic exploit treated as infeasible, a test treated as proof of correctness, an implicit
constraint treated as enforced. When Check 5 does most of the killing, confirm its
counter-hypothesis is cited and concrete.

## Dispositions

| Disposition | Meaning | Report action |
|-------------|---------|---------------|
| `confirmed` | Support is as concrete as the claim; severity holds | Report as-is |
| `downgraded` | Survives at a strictly lower band | Report with adjusted severity and reasoning |
| `pending_runtime_proof` | Checks 1-3 and 5 survive but the invariant failure lacks executable or equally decisive proof (a supported-API driver counts; a missing embedding app alone does not force this) | Held out of the report and exploit candidates; blocks report-readiness until a controlled proof pass re-verifies it |
| `killed` | Counter-evidence reaches the claim's bar | Excluded; persisted as a `false_positive` verification |
| `disputed` | Neither bar met after adjudication | Held with arguments and evidence groups pending decisive proof |

**Recording.** `vigil assess contract finding verify` owns the payload. The judgments it leaves to
you:
- `false_positive` rests on a counter-check that ran to its end (`--counter-check-file`;
  `vigil assess contract finding verify --field counter_check`). If the settling experiment could
  not run (no second tenant for a cross-tenant check, a build that would not link), the verdict is
  `blocked` or `pending_runtime_proof`. Name the numbered check behind a kill in `details.kill_check`, and a
  test that would remove residual doubt in `details.required_followup`; readiness lists it as an
  advisory until the field is cleared or the verdict changes.
- `pending_runtime_proof` carries a next test: hypothesis, confirming observation, falsifying
  observation as concrete as the confirmer (a proof pass that can only succeed disproves nothing),
  and a `local`/`live`/`unknown` route hint that grants no scope or approval.
- No longer standing behind a claim you cannot counter-check: `--status disputed --reason "<why>"`.
- New evidence disproving a prior decision: `finding update <slug> --status draft`.
- A verdict on static evidence, inference, or an unexecuted chain gets the persisted
  Ideator-vs-Tracer debate (`--narrative`); a runtime-proven finding records its evidence directly.

## Output Format

Per-finding check results and disposition; a kill list (check, evidence, devil's-advocate
reasoning); downgrades (original and adjusted severity); adjudication requests; attack chains with
their data flow; and counts in, confirmed, killed, downgraded, disputed.

## Extended Resources

- **CWE pattern reference (REQUIRED once a finding is opened):** the
  `agent/references/code-vuln-patterns/*.md` file for each finding's CWE — it decides whether every
  variant form is guarded (Check 2) and what a real exploit looks like (Check 4).
- `agent/references/runtime-guides/code-verification-adjudication.md` — when a check escalates, a
  verdict needs the debate, you record a kill, or you document a chain.
- `agent/references/finding-fp-and-severity-gate.md` — the shared C1-C7 gate.
- Phase 1 architecture map and call graph, the project's build files and flag docs (Check 3), and
  Phase 3 variant findings.
