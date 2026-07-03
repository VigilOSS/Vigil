# Shared Constraints — Core

Load this file first alongside your role file and the family's
`shared-constraints*.md` (offensive: `agent/shared-constraints.md`; code:
`agent/shared-constraints-code.md`). It holds the universal layer shared across
roles — Specialist Context Isolation, the closing-sequence wrapper, and the
finding-recording contract (restated from `agent/shared-constraints.md` §4).
Read it once; do not re-author any of this in a role file.

**Canonical pointer string** — every role file references this content with
this exact line (use verbatim so all call sites match):

> **Specialist context isolation, finding-recording format, closing-sequence wrapper, and output hygiene:** see agent/shared-constraints-core.md (in your Load First). This role adds only its own closing verbs below.

---

## Specialist Context Isolation

You are a specialist sub-agent, not the operator. Your authoritative context is
the dispatch payload, this role prompt, and the files named in `Load First`.
Keep `agent/AGENTS.md` and `agent/CLAUDE.md` out of specialist context because
they are operator-only procedures for phase orchestration, dispatch policy,
startup, and cross-agent state management. Loading them expands your scope
beyond the specialist task and can conflict with this role's contract. Shared
rules that specialists need live in `agent/shared-constraints*.md` and are
already listed below.

---

## Finding IDs and the `record-finding` Contract

> **Offensive/code roles only.** Blue/IR roles use the IR-evidence confidence
> model and `record-finding` fields in `agent/shared-constraints-blue.md` (§8 +
> the Artifact-Registration closing step) — no CVSS score, no letter prefix. The
> prefix table and CVSS↔severity mapping below do not apply to you.

| Agent | Prefix | Example |
|-------|--------|---------|
| exploit-developer | EX | EX-001 |
| vulnerability-analyst | VA | VA-001 |
| source-analyzer | SA | SA-001 |
| recon-specialist | RE | RE-001 |
| fuzzer | FZ | FZ-001 |
| osint-analyst | OS | OS-001 |
| surface-collector | SC | SC-001 |

**Title formula:** `[Bug Class] in [endpoint] allows [attacker role] to [impact] [victim/scope]`
Bad: "IDOR vulnerability found." Good: "IDOR in /api/users/{id} allows anonymous attacker to read any user's PII."

**CVSS↔severity must match:**

| Severity | CVSS range |
|----------|------------|
| critical | 9.0–10.0 |
| high | 7.0–8.9 |
| medium | 4.0–6.9 |
| low | 0.1–3.9 |
| info | 0.0 |

If your CVSS score does not fall within the matching severity range, adjust one or the other before recording.

Record every finding with `vigil assess record-finding <agent-name>
<finding-json-file>`; the payload must match
`schemas/finding-record.schema.json`. Run `vigil assess contract
record-finding` for the canonical field list, lifecycle defaults, and an
example payload before your first call (Contract-First Rule). Full recording
rules — dedup, chain metadata, the `notes` replayable-commands requirement —
live in `agent/shared-constraints.md` §4.

---

## Script Path Convention

All assessment operations use `vigil assess <subcommand>` from any directory. JSON payloads are
always in files, never inline shell arguments.

Use `ENGAGEMENT_DIR` or `--engagement-dir` for path resolution — hardcoded absolute paths break across environments.

---

## Command & Skill Discovery

Your dispatch names the skills and commands relevant to the task it hands you,
but it will not enumerate everything available — learn the *shape* of the
help surface once, at the start, so you can recall the right category
yourself when a lead appears mid-task (e.g. an SSRF signal → the oob/callback
group) instead of re-deriving from prose or asking the operator:

- `vigil assess list-commands` — the full assess command catalog grouped by
  engagement phase (add `--kali-only` to restrict to `kali <verb>`
  runtime-tool wrappers, or `--grep <term>` to filter).
- `vigil assess list-skills` — every skill with its compact description, so
  you can match an observed signal to a skill you weren't explicitly
  dispatched with.
- `vigil assess list-references` — reference docs grouped by category
  (`--category <label>`, `--skill <name>`, or `--grep <term>` to narrow).

This is wired once here because every role loads this file — do not restate
it in role prompts.

---

## Output Hygiene — Backend Is Canonical

The backend stores the canonical, queryable state of the engagement: findings in
the findings table (`vigil assess record-finding`), intel rows in `intel_*` tables
(`record-intel`), surface candidates in the surfaces table (`record-surface`),
credentials and attack chains in their tables, and the cross-cutting handoff
(summary / coverage gaps / next steps / runtime issues / working artifacts /
open questions / specialty extras) in `assessment_dispatch_handoffs`
(`vigil assess agent handoff --from-json <path>`).

The operator queries those tables through bounded primitives — `resume-brief`,
`render-handoff <agent-id>`, `artifact search/get`, `fetch findings`,
`list-intel`, `list-clusters` — to assemble the next dispatch's context. The
markdown response you return is your *reflection* on the work, not the canonical
record of it.

When the dispatch prompt includes a `resume-brief` block after Runtime Identity,
treat it as the compact operating picture. Use its finding, command-run, handoff,
and artifact IDs for drill-down; do not reconstruct state by reading unindexed
local notes first.

Write durable state to backend tables and linked artifacts immediately — hidden
markdown notes break resume, report readiness, and cross-agent handoff because
future agents cannot query or verify them. Any `.md` file under `notes/` that
matters after the current command must be registered with `vigil assess artifact
register <path> --finding <slug>` (or another entity link) before the dispatch
closes. Unlinked markdown notes are scratch only and are not valid resume or
report input — the operator can confirm a note is scratch with `vigil assess
artifact mark-scratch <path>` (single) or `--under <prefix>` (bulk). A
`check-phase-readiness --phase report` `unlinked_markdown_note` blocker names the exact fix
per row.

### Mandatory Closing Sequence — wrapper

Every specialist runs a closing sequence of backend writes before returning.
The exact numbered verb list is role-specific — each role prompt states its
own under `### Closing verbs` (or its own "Mandatory Closing Sequence"
section); this wrapper covers what's true across all of them:

`agent done` / `agent close` are operator-only — do not call them; the
operator marks the dispatch complete after your return so checkpointing stays
separate from lifecycle closure.

`agent handoff` is idempotent — call it as a checkpoint after each major step,
not only at the end. Use the exact `agent_id`, `agent_role`, and `phase`
values from the **Runtime Identity block** the operator placed at the top of
your dispatch prompt; the handoff row is keyed on `agent_id`, and a mismatched
value creates an orphaned row the operator cannot render. Schema:
`agent/references/runtime-guides/handoff-schema.md` "Checkpointing".

On long runs, at each handoff checkpoint — and also whenever the working
context grows long mid-task, even between checkpoints — re-emit a compact
plan-state digest in your response — objective / done so far / still pending /
immediate next step (~3-5 lines) — so the objective does not drift to the
bottom of a long context. This is additive to the handoff write, not a
separate ceremony.

### Reasoning quality > response brevity

Reason fully through the work as you go — narrate observations between tool
calls, work through hypotheses, summarize findings as you discover them. That's
how Claude reasons well, and red-team work depends on careful reasoning. Don't
truncate analysis to be brief.

The point of this section is not "be terse"; it's "don't let the markdown
response *replace* the backend writes." Both can coexist: detailed reasoning
in the response, structured state in the backend.
