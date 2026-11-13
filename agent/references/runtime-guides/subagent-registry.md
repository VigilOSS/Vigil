---
description: Backend dispatch tables (assessment_dispatches, assessment_dispatch_handoffs, assessment_dispatch_decisions) and their vigil assess agent ... CLI verbs — engagement audit trail, DEDUP input, handoff renderer source, decision audit
---

# Subagent Dispatch Registry — Backend Tables

Dispatch tracking, structured handoffs and decision rows live in three backend tables, which you
reach through `vigil assess agent …`. `vigil assess agent --help` lists every verb. For a verb's
fields and write rules, read `vigil assess contract agent <verb>` before hand-authoring a payload
for a verb you haven't used this session; a refusal prints the section you need.

| Table | Written by | Verbs | Holds |
|---|---|---|---|
| `assessment_dispatches` | operator | `agent start` / `start-swarm` / `continue` / `done` / `close` / `reconcile-stale` / `list` / `get` / `bind-client-handle` / `abort-duplicate` | One row per specialist dispatch: role, task, application unit, requested model/reasoning, dispatch mode, assessment mode, skills, status, finding slugs, prompt packet and instruction identity. |
| `assessment_dispatch_handoffs` | specialist | `agent handoff` / `render-handoff` | The structured per-dispatch handoff. Lifecycle columns (`handoff_status`, `handoff_version`, `last_checkpoint_at`, `closed_dispatch_status`) keep checkpointing separate from closure. Schema and field guidance: [`handoff-schema.md`](handoff-schema.md). |
| `assessment_dispatch_decisions` | operator + specialist | `agent decision` | Cross-dispatch decisions: scope, egress, dispatch_blocked, deferrals, QC and claim verdicts, and others. The kind list and the gated kinds are in `vigil assess contract agent decision`. |

## Dispatch lifecycle

```bash
# 1. Register. This writes the audit row and captures the packet; it launches nothing.
vigil assess agent start --agent-id recon_a3f9 --role recon-specialist \
    --task "Phase 1 recon on acme-social.example" --model claude-opus-5 --reasoning high \
    --dispatch-mode hypothesis-driven --skills web-recon \
    --rate-budget "<exact operator-authored rate/concurrency instruction>" \
    --prompt-context-json dispatch-context.json
# 2. Launch the specialist with the client-native agent tool, passing only the receipt's launch_message.
# 3. After the native return, once its owned commands have ended:
vigil assess agent render-handoff recon_a3f9
vigil assess agent close recon_a3f9
# No final handoff on return: keep its checkpoint and record the failed recovery.
vigil assess agent close recon_a3f9 --status failed --reason "Worker returned; owned commands ended"
```

`agent close` reads a `ready` or `blocked` handoff and applies its `closed_dispatch_status`.
`agent reconcile-stale [--dry-run]` lists in-progress dispatches past the age threshold and closes
the ones whose handoff can be closed. Both write a `dispatch_closed_from_handoff` decision row, so
every closure is auditable.

`--rate-budget "<authored>"` or `--no-target-traffic` is required on every start. The declaration
is printed with the receipt and rendered into the prompt, but it is not stored on the row. The
prompt-only context fields come from `dispatch-template.md`. Unknown keys and explicitly empty
values are refused before the row is written; an omitted field stays unknown in the packet and
grants no authority (an omitted `authorized_phase` makes the specialist stop and ask for a
corrected packet).

Launcher-effective and provider-observed model, reasoning and client values are audit fields
that callers cannot write. They stay `unknown`/null until a trusted launcher or session integration
attests them for that invocation. Client configuration files (OpenCode frontmatter,
`opencode.json`, Goose recipes) show what was available, not what a given child ran with.

## What the tables are for

- **DEDUP.** Before dispatching, run `vigil assess agent list --task-q "<keyword>"` (or
  `--filter-role`, `--status`, `--since`) so the same role isn't sent twice at the same objective.
  `vigil assess fetch activity-entries` adds the narrative log.
- **Continuity.** Every dispatch is a fresh agent. Paste `vigil assess agent render-handoff
  <prior-agent-id>` output verbatim into the next dispatch alongside the base template. The new
  agent resolves slugs, file paths and credential ids from durable state (`vigil assess fetch`,
  `get-finding`) instead of inline copies, which keeps the prompt small and the state canonical.
- **Decision audit.** Scope, egress and deferral rows are cross-dispatch state the next dispatch
  decision depends on. When a specialist cannot launch, record `dispatch_blocked` with
  `--surfaced-to-user`, then fix the runtime or defer the scope entry. Moving the work silently
  into the operator loop hides the gap.

## Making handoffs cheap

- Findings, credentials, access records, credential tests, chains, surfaces and probes go in
  through their `vigil assess` helpers, and the next agent queries them rather than receiving
  copies.
- Transient state goes in engagement files. Session cookies, captured JWTs, CSRF tokens and upload
  paths go under `$DIR/tools/`, `$DIR/scans/` or `$DIR/downloads/`, and working PoC scripts under
  `$DIR/scripts/`. List them in the handoff's `working_artifacts` so the renderer shows whether
  each one is present or missing.
- A condensed narrative goes to `vigil assess log <agent> <title> <action> <result>`
  (engagement-scoped and FTS-searchable through `vigil assess fetch activity-entries`).
