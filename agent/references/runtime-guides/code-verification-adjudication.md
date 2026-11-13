---
description: Code-verifier appendix — evidence-adjudication procedure and request format, the persisted Ideator-vs-Tracer debate, the structured kill format with examples, and the attack-chain template
skill: code-finding-verification
---

# Code Verification: Adjudication, Debate, Kill and Chain Formats

Load this from `agent/skills/code-finding-verification/SKILL.md` when a check returns ESCALATE,
when a verdict needs the persisted debate, when you record a kill, or when you document a chain.
The skill's five checks and disposition table stay authoritative.

## Evidence Adjudication Protocol

Enter it when any check returns ESCALATE (each check's ESCALATE line in the skill names the typical
triggers), when a counter-argument rests on invariants the code does not enforce, or when two
reasonable engineers would disagree. Write the argument for the finding (the hunter's evidence,
your Check 1-4 verification, and why the devil's-advocate argument fails or is incomplete) and the
argument against (the Check 5 evidence, its code locations, and the assumption that would have to
hold for the code to be safe). Group reviews that share a premise, trace, source excerpt, or
derived assumption into one evidence group: correlated reviews are one observation however many
reviewers produced them. Present both sides to the operator, who may dispatch an independent
verifier for the missing evidence; another opinion adds no evidentiary weight by itself. Decide
from the strongest complete proof (a cited source-to-sink, guard, build, state-sequence, or runtime
proof that closes the disputed condition), or record `disputed` as the skill says, and record the
outcome, the evidence groups, and the decisive proof.

```
ADJUDICATION REQUEST: [Finding ID]
FOR:     [evidence supporting the finding]
AGAINST: [devil's-advocate evidence]
RECOMMENDATION: [your lean, with confidence]
EVIDENCE GROUPS: [which observations share a premise or trace]
BLOCKER: [the specific evidence that would resolve it]
```

## Persisted Ideator-vs-Tracer Debate

Before recording `confirmed` or `pending_runtime_proof` on static evidence, inference, or a chain
not executed end to end, write the debate to a note and register it so the decision stays
auditable. A runtime-proven finding (PoC executed, attacker outcome captured) records its evidence
directly, since the run already settled what the debate exists to settle; it still passes the C1-C7
gate in `agent/references/finding-fp-and-severity-gate.md`.

`notes/<slug>-debate.md`:

```
# <slug> — Ideator-vs-Tracer debate

## Claim (Ideator)
<the attacker outcome, or bounded intrinsic product outcome, with the path / sink or invariant>

## Causal challenge (Tracer)
<the contested link — reachability, guard, build-config, or feasibility — with file:line>

## Evidence
<file:line citations, the queries run, and any PoC bytes or runtime observation>

## Verdict
disposition=<confirmed|pending_runtime_proof|downgraded|killed>
rationale=<why; for pending_runtime_proof, exactly which runtime proof is still owed>
```

Register it on the verify call with `--narrative notes/<slug>-debate.md`; it becomes a
`kind=verification-narrative` artifact linked to the finding, retrievable with
`vigil assess artifact search --finding <slug> --kind verification-narrative`. A
`pending_runtime_proof` verdict also takes `--next-test-file`; `vigil assess contract finding
verify` owns both shapes.

## Structured Kill Format

```
KILL: [Finding ID]
Check Failed: [1-5]
Reason: [specific, verifiable statement]
Evidence: [code location, build config line, or upstream guard that proves the kill]
Devil's Advocate: [Check 5 only — the counter-argument that succeeded]
```

- Check 1: `test_parser()` calls an unexported helper with an impossible state; no shipped
  application, public API, CLI, or registered plugin path reaches it.
- Check 2: `validate_header_length()` at http.c:92 bounds-checks to 8192 bytes on every path before
  the data reaches `parse_header_value()`.
- Check 3: the code sits inside `#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION`, not compiled in
  release.
- Check 4: the overflow is one NUL byte landing on padding between stack variables; attempted
  construction cannot reach the return address or any function pointer.
- Check 5: `test_oversized_header` in test/http_tests.c exercises this exact path and asserts
  rejection, the `ENSURE_SIZE` macro at parser.c:89 expands to a bounds check, and every applicable
  shipped caller reaches that macro before the arithmetic.

A check that falsifies one sub-claim while the finding stands is not a kill; the sub-claim goes in
`details.honest_bounds`
(`agent/agents/code-vuln-verifier.md` "Severity & Report-Readiness Gate").

## Attack Chain Template

```
ATTACK CHAIN: [title]
Components:
  1. [Finding-A] — [role, e.g. info leak provides heap layout]
  2. [Finding-B] — [role, e.g. controlled allocation size via integer overflow]
  3. [Finding-C] — [role, e.g. heap overflow writes attacker data into that allocation]
Composite Impact: [e.g. remote code execution as the service user]
Composite Severity: [may exceed any single component]
Prerequisites: [network access, request sequence, timing]
Data Flow: [how A's output feeds B's input — variables and functions]
```

The template is what the chain has to establish; record it with `vigil assess record-chain
code-vuln-verifier <chain-json>`, whose JSON shape `vigil assess contract record-chain` owns.
