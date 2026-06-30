# ADR 0009 — Operator orchestrates, specialists originate hypotheses

- Status: Accepted
- Date: 2026-06-29

## Context

Across engagements, a recurring degradation was observed: the **operator** tells dispatched
**specialists** exactly which vulnerabilities/checks/payloads to run, instead of operating the
engagement (phases, rules, dispatch pass-off/follow-up, continuity, recording) and letting specialists
hunt. Two harms follow:

1. **Depth is capped at the operator's imagination.** The specialist tests what it was told, so the
   sibling/variant/adjacent-class bugs the on-surface expert would have found are never generated.
2. **Specialists become checklist-followers.** A role framed as "validate this named candidate" stops
   originating hypotheses.

Diagnosis confirmed this is a *prompt-contract* problem, not a missing-capability one. Vigil already
contains the correct philosophy in two places:

- The `exploit-developer` fan-out already mandates "a deliberately OPEN objective… NOT a pre-named
  bug. Pre-pointing biases the hunt and hides chains" (`operator-core.md`, Depth Doctrine).
- The developer-weakness mindset is rich and correct in `rules/adversarial-mindset.md` and
  `rules/hunting.md §19`.

But the **default** dispatch contract contradicts it: it instructed the operator to author the security
hypothesis and hand the specialist an execution order —
- `operator-core.md` "specific task objective … name the hypothesis or the variant being checked",
- "Coverage gap statement: name the specific … payload family … do not leave the gap inference to the
  specialist",
- the `vulnerability-analyst` dispatch line "the specific hypothesis to test",
- and `vulnerability-analyst.md` framed the role as a *validator of someone else's candidate*.

The good pattern was quarantined to one role; the default was the opposite.

### Research basis

- **Orchestrator/worker division of labor** (Anthropic multi-agent research system; orchestration
  literature): the lead owns decomposition, boundaries, outcome, and output shape; the worker owns the
  exploration trajectory. Pushing method-detail up to the orchestrator defeats the context-window
  division that is the whole point of delegation.
- **Anchoring bias in LLMs** (arXiv 2412.06593, 2511.05766): an authoritative in-prompt "expert" cue
  narrows the model's reasoning and *suppresses* hypothesis diversity, and the effect is **not**
  correctable by also telling the model to think for itself. The operator is the most authoritative
  voice in a specialist's context, so an operator-named vuln is a hard anchor — the fix must *remove*
  the anchor, not add a "but also explore" caveat.
- **Under-specification → duplication** (Anthropic): vague dispatches cause workers to redo each
  other's work. The cure is more *boundary/coverage context*, not more *method prescription*. This is
  why the operator's cross-dispatch coverage view is kept and protected.
- **Persona/objective framing** (role-prompting + prompt-design literature): autonomous expert behavior
  comes from priming an expert identity + goal + constraints while withholding the solution.

## Decision

Reframe the division of labor so the operator supplies **what / where / rules / what's-covered** and the
specialist supplies **how / which-weakness**. Concretely:

- **P0 — rules (no render coupling).** `adversarial-mindset.md` gains an ownership preamble: when you
  are a specialist you originate hypotheses on the surface and treat an operator-named class as a
  starting lead, not a fence; when you are the operator you use the lens to spot gaps and route.
  `hunting.md §18` redefines "frame the dispatch tightly" = surface/scope/auth/rules/outcome, explicitly
  NOT a pre-chosen vuln. `hunting.md §19` retargets its heuristics to the specialist as *their* lens.
- **P1 — operator dispatch contract (`operator-core.md` → re-render `AGENTS.md`).** "specific task
  objective: name the hypothesis" → "specific **outcome** objective: name the surface + result wanted,
  not a pre-named vuln". The "Coverage gap statement" is **split**: kept as *coverage continuity*
  (what's covered / untouched, which the operator alone sees) and stripped of payload prescription. The
  `vulnerability-analyst` dispatch line drops "the specific hypothesis to test". The orchestrator-brain
  paragraph and the Pre-Dispatch Checklist are aligned to outcome-objective + no-pre-named-bug.
- **P2 — specialist role openings (`agents/*.md` → re-render wrappers).** `vulnerability-analyst`
  (highest priority), `source-analyzer`, and `recon-specialist` are re-primed as autonomous expert
  hunters that originate hypotheses; they already *load* the mindset rules, so this activates them for
  origination rather than validation.

P1 and P2 ship together: naming-bugs-off on the operator while the VA still waits to be told would
leave a half-state, and (per the anchoring research) the residual anchor would win.

## Guardrails (what the operator still injects)

To avoid over-correcting into "operator gives no direction", these operator injections are kept — they
are context/continuity, not security analysis, and the specialist cannot reconstruct them:

1. **Cross-dispatch coverage** — what surfaces/classes/identities already have a recorded verdict vs.
   are untouched (the anti-duplication boundary), stated as coverage, not a payload order.
2. **Cross-surface / cross-lane chain seams** — "lane A found an auth bypass, lane B an IDOR on a
   sibling host — look at the chain". Synthesis only the operator sees; the operator's highest-value
   direction.
3. **Engagement rules / ROE / rate budget / scope / auth state / OOB availability / cleanup**.
4. **Phase gates, hand-off pass-forward, dispatch-mode, skill selection, model/reasoning** — the
   engagement-running machinery the operator owns.
5. **A genuinely actionable lead already in hand** (e.g. recon surfaced default creds) — handing over a
   finding-in-hand is not pre-deciding the hypothesis space.

The line drawn everywhere: *operator supplies the what-where-rules-and-what's-covered; specialist
supplies the how-and-which-weakness.*

## Consequences

- Specialist depth is no longer bounded by the operator's hypothesis; siblings/variants/adjacent classes
  get generated on the surface where the relevant assumptions are actually visible.
- The operator's identity sharpens around orchestration + continuity (the half that was under-reinforced).
- `operator-core.md` and `agents/*.md` are sources; after editing, `cd agent && ./scripts/render-operator-prompts.sh repo`
  regenerates `AGENTS.md` and the per-runtime wrappers, and `render-check` must be clean. Rules
  (`hunting.md`, `adversarial-mindset.md`) are loaded by reference — no render step.
- No automated test asserts on the changed phrases; the only coupling is the mechanical render-check.

## Alternatives considered

- **Add "think for yourself" to specialists without changing the operator contract.** Rejected: the
  anchoring research shows an explicit "ignore the anchor" instruction does not undo the anchor; the
  operator-named bug would still dominate.
- **Remove operator direction entirely.** Rejected: under-specification causes worker duplication
  (Anthropic); the operator's coverage/chain/rules context is irreplaceable and is explicitly retained.
- **Leave the philosophy quarantined to `exploit-developer`.** Rejected: that is the status quo that
  produced the reported pattern for the other roles.

## Follow-ups

- Mirror P1/P2 into `operator-core-code.md` + the `code-*` roster if the philosophy should be
  system-wide (the code roster already leans autonomous, so this is lower priority).
