# Prompt Authoring Standards

All prompts in this system — operator doctrine (`agent/operator-core*.md`), role prompts
(`agent/agents/*.md`), skill definitions (`agent/skills/*/SKILL.md`), shared constraint layers
(`agent/shared-constraints*.md`), and always-active rules (`agent/rules/*.md`) — follow the
conventions below, based on
[Anthropic's prompt engineering guidance](https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering/overview).
Apply them when writing a new prompt or editing an existing one.

This document has two parts:

- **[The prompt health ruleset](#the-prompt-health-ruleset)** — the twelve-rule checklist that
  governs every prompt/doc edit. This is the operative gate: run each edit through it.
- **[Authoring principles](#authoring-principles)** — the foundations the ruleset builds on
  (positive instructions with reasoning, division of labor, role clarity, checklists).

The root [`AGENTS.md`](../AGENTS.md) maintainer guide points here from its **Prompt system flow**
section. Apply this alongside the **Prompt edit checklist** there — that checklist runs the
cross-layer coherence pass; this ruleset governs prompt-health quality.

## The prompt health ruleset

The twelve rules below are the standing health checklist for every prompt/doc edit — role files
(`agent/agents/*.md`), shared layers (`agent/shared-constraints*.md`), rules (`agent/rules/*.md`),
and operator doctrine (`agent/operator-core*.md`). They exist because a specialist's real context
is not just its role file — it is the role file **plus every `## Load First` entry**, and that
standing load grows silently whenever a rule gets re-authored in a second place instead of
pointed to.

### 1. State a per-role Load-First budget

A role's real context cost is its own body plus every file listed under **MANDATORY** in its
`## Load First` section — not the role file's line count in isolation. When you add a role or a
mandatory Load-First entry, note the resulting total against the role's stated budget (or set one
if none exists). Growth past the budget is a signal to trim or hoist content out (per Rule 3),
not to accept a creeping standing load.

Run `vigil assess prompt-census` for the advisory structural and approximate-byte view. Pass
`--read-bytes <n>` when a reader reports a bounded read so the census shows whether that boundary
missed or cut through the Load First section; this is visibility, never a progress gate.

Three things to know when reading its output. It measures the tree it names in `prompt_root` —
`vigil assess` execs the *installed* agent tree, so running it inside a checkout measures the
installed prompts unless you pass `--prompt-root`, and the output names any checkout tree it did
not measure. A role whose mandatory bundle is an exclusive choice (`exploit-developer`,
`source-analyzer`) reports one total per track rather than a single figure, because summing both
halves describes a dispatch that never happens. And `agent/operator-core*.md` is reported
separately, by measured size only: it is session load, not per-dispatch load, and this ruleset
sets no budget for it. Nor do the cores set their own consistently today —
`operator-core-code.md` is the only one that states a figure in its header, and it currently
declares itself over that figure; `operator-core.md` and `operator-core-blue.md` state none. Read
the census output as the measurement, and set core budgets after the prompt-reduction pass, at
what the trimmed files measure — not from a number invented ahead of the trim.

### 2. Split Load First into MANDATORY vs LOAD-ON-FIRST-USE

Every role's `## Load First` section separates what is loaded unconditionally from what is loaded
lazily, trigger-gated on the situation that needs it — see `agent/agents/recon-specialist.md`
(`## Load First`) for the canonical shape: a **MANDATORY (before any work)** list and a
**LOAD-ON-FIRST-USE (lazy)** list where each entry states the trigger inline (e.g. "when you run
the L1 ffuf pass (step 6)"). A file that only a subset of dispatches ever need belongs in the lazy
list with its trigger named, not in MANDATORY by default.

### 3. DRY — a rule lives in one file

Author a procedure, contract, or piece of judgment exactly once, in its owning file; every other
site gets a short pointer, not a restatement. Duplication drifts (two copies of the same OOB
mint→poll sequence, or a CVSS-table cross-reference that goes stale when the table moves) and each
copy adds standing-load weight the specialist pays on every dispatch. Use a pointer, not a
paraphrase — for example, the canonical cross-family pointer used by every offensive/code role for
context-isolation, finding-recording format, and closing-sequence wrapper is:

> **Specialist context isolation, finding-recording format, closing-sequence wrapper, and output hygiene:** see agent/shared-specialist-core.md (in your Load First). This role adds only its own closing verbs below.

Write the owning rule for the agent doing the work now, not as repository archaeology. Historical
mechanisms, superseded names, migration rationale, and commentary addressed to a future editor
belong in plans, ADRs, or history—not in the runtime prompt. Keep rationale that tells the agent
what breaks during the engagement; remove rationale whose only purpose is to explain what an older
prompt used to say.

### 4. Single responsibility, mode-gated

A role prompt covers one specialist's job. Content that only applies in one operating mode (a
review pass, a final-report run, an exploit-review gate) is gated behind an explicit mode check
in the prompt, not always-loaded prose the specialist must mentally filter on every dispatch.
Prefer "Iteration mode: ... **Default when omitted:** ..." framing (see
`agent/agents/recon-specialist.md`'s "Iteration mode:" line) over one role file quietly doing two
jobs.

### 5. Injected content gets a named top-of-dispatch field

Position beats verbosity: content that is specific to one dispatch (a mindset lens, `hunt_scope`,
coverage/ROE state) goes in a named field at the very TOP of the dispatch prompt, ahead of the
~400-line role body. Content buried after a long fixed role body is the "lost in the middle"
failure mode — the per-dispatch instruction that should govern the run gets out-competed by
generic role prose the model read first.

### 6. Must-reads are conditional pointers with a stated trigger

When a role's Load First list points at another doc instead of inlining it, the pointer states the
trigger condition, not just the filename — a bare filename forces the specialist to load it
defensively (paying the cost anyway) or skip it wrongly. Model wording: *"load in full only
immediately before authoring a confirmed/upgraded finding's report-ready details, in review mode,
or when drafting an external submission — not for exploration/kill."*

### 7. Every dispatch names its FP gate

Any dispatch that produces or reviews a finding cites its false-positive/severity-downgrade gate
by name — e.g. `agent/references/finding-fp-and-severity-gate.md` — so the specialist knows which
document governs disposition before it writes a verdict, rather than inferring it from role prose
scattered across the file.

### 8. New per-dispatch dimensions extend the header, never fork a role

When you add a new axis a dispatch can vary along (e.g. a depth split, a mindset selection), add
it as a field in the existing Dispatch Context Template / Specialist Dispatch Contract header in
`agent/operator-core.md`, and thread it through the existing role file. Do not fork a second role
file to carry the new dimension — that reintroduces the duplication Rule 3 forbids and splits a
single specialist's contract across two authoritative sources.

### 9. Length changes restate the budget

When a role file's or shared layer's line count changes meaningfully, restate its new total against
the Rule 1 budget in the same change — a trim that isn't reflected in the stated budget, or a
growth that silently blows past it, is exactly the drift this checklist exists to catch.

### 10. No self-reported or wording-only gates

No quota, percentage, effort score, iteration count, or threshold that the agent can satisfy by
shaping its own prose may gate progress. Express the evidence-bearing judgment directly: name the
privileged operations or input boundaries traced, the unresolved ones, and the evidence supporting
closure. Never tell the agent how many bugs exist or imply that a clean target must contain a
finding; unknown facts remain unknown.

Per the **Markdown prompt/doc testing policy** in [`AGENTS.md`](../AGENTS.md), prompt/doc health
(including any per-role line-count check) is enforced as a human authoring checklist plus, at most,
an advisory WARN — never a blocking CI wording test. A wording or line-count assertion that fails
the build turns normal prompt editing into fixture maintenance and rewards preserving stale
phrasing over improving the instructions; keep any automated signal non-blocking.

### 11. Root-cause every prohibition before writing a "do not"

Before you write a "do not" / "never" / "must not," diagnose why the unwanted behavior happens —
is it a **missing WHY** (the model doesn't know the reason, so state the reason and the positive
action), a **structural problem** (the prompt makes the wrong thing easy or the right thing
unavailable, so fix the structure), or a **division-of-labor issue** (the work belongs to a
different role/command, so route it there per the **Division of labor over prohibition** principle
below)? Fix the cause; a bare prohibition is the last resort, used only when no root-cause fix
applies. A prohibition that survives this pass keeps the mechanism it protects adjacent to it (see
`agent/agents/ir-lead.md`'s prohibition + protected-mechanism shape) so a future editor can see
what it guards.

### 12. Propagate a primitive to every role it applies to, then grep-verify

A primitive added to one role is a **prototype, not a direction, until it is propagated and
grep-verified across every role it applies to. "Added to VA/EX" is never "done."** When you
introduce a shared primitive (a new Load-First shape, a dispatch field, a disposition vocabulary,
a pointer form), finish the change with an explicit list of the roles it applies to plus a grep
pattern that must return **0 residual matches** (of the old form) across all `agent/agents/*.md` —
otherwise the rollout re-creates the exact duplication Rule 3 exists to kill.

## Authoring principles

These four principles are the foundation the ruleset above enforces. Reach for them whenever a
prompt is tempted toward a prohibition list or an ambiguous instruction.

### Positive instructions with reasoning

State what to do, then explain why — in terms of what breaks if the instruction is violated. A
negative instruction ("don't do X") only tells the model what to avoid and leaves the desired
behavior unspecified, so the model must infer what to do instead. A positive instruction with a
reason specifies the behavior directly and grounds it in something the model can evaluate, which
lets it generalize to edge cases the literal rule doesn't cover.

The shape for a load-bearing constraint (one where safety, correctness, or quality depends on it):

```
[What to do] — [why, in terms of what breaks if violated]
```

Instead of *"Do NOT test directly with host-side commands,"* write: *"Dispatch to the appropriate
subagent for testing — analysis and testing belong to specialist agents because they carry the
skill context and methodology depth that the operator prompt lacks."* The reasoning ("because they
carry the skill context") is what lets the model judge novel situations, rather than
pattern-matching on the prohibition. More examples from this prompt set:

- "Use `vigil assess record-surface` for all surface writes — calling the library directly bypasses backend sync"
- "Finding IDs are allocated by `vigil assess finding record` under a lock — hand-allocating risks collisions"
- "Route all in-scope target work through the `vigil assess kali` CLI — host-side probes bypass the runtime's network isolation"

### Division of labor over prohibition

When the operator (or any role) should not do something, frame it as belonging to a specific agent
rather than as a prohibition. Instead of *"The operator must not evaluate guards or sinks,"* write:
*"Guard and sink evaluation belong to code-vuln-hunter — the operator provides the context slices
and records the results."* This is the routing fix Rule 11 reaches for before any bare "do not."

### Role clarity in agent prompts

Each agent prompt starts with a single sentence that establishes identity and scope. This focuses
the model's behavior without requiring prohibition lists. Example: *"You are the primary
vulnerability analyst for source code. You receive pre-built context slices and your job is to
determine whether an attacker controlling the identified inputs can cause harm."*

### Checklist format for verification

Use markdown checkboxes for pre-work and pre-output verification steps. Checklists are more
reliable than prose because the model can evaluate each item independently rather than holding a
paragraph of conditions in mind at once.
