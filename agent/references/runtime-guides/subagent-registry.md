# Subagent Dispatch Registry — Backend Tables

Dispatch tracking, structured handoffs, and decision rows live in three backend
tables. The operator and specialists interact with these tables via `aith assess dispatch ...`
CLI verbs.

| Table | Owner | CLI verbs | Purpose |
|---|---|---|---|
| `assessment_dispatches` | operator | `dispatch register` / `update-status` / `list` / `get` | Audit trail of every specialist dispatch (role, task, contract, status, finding slugs). |
| `assessment_dispatch_handoffs` | specialist | `dispatch record-handoff` / `render-handoff` | Structured per-dispatch handoff: summary, coverage gaps, next steps, runtime issues, working artifacts, open questions, role-specific extras. Schema: [`handoff-schema.md`](handoff-schema.md). |
| `assessment_dispatch_decisions` | operator + specialist | `dispatch record-decision` | Cross-cutting decision rows (vendor-SaaS scope, egress reputation, dispatch_blocked, scope_decision). |

## Table 1 — `assessment_dispatches`

The operator's audit trail. One row per dispatched specialist agent.

### Fields

| Field | Type | Source |
|---|---|---|
| `agent_id` | string (PK) | Operator-assigned at `dispatch register` time. |
| `agent_role` | string | `recon-specialist` / `vulnerability-analyst` / etc. |
| `task` | string | One-paragraph dispatch objective. |
| `scope_host` | string | The host the dispatch operated against (or `multi` for multi-host). |
| `dispatched_at` | ISO datetime | Set on `register`. |
| `completed_at` | ISO datetime | Set on `update-status` when status moves to a terminal value. |
| `status` | enum | `in-progress` / `completed` / `failed` / `aborted` / `blocked`. |
| `model` | string | The model id (`claude-opus-4-7`, `gpt-5.4`, ...). |
| `reasoning` | string | `low` / `medium` / `high`. |
| `dispatch_mode` | string | `hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation`. |
| `finding_slugs_json` | JSON array | Finding slugs the dispatch produced (set on `update-status`). |

### CLI

```bash
# Register a dispatch (operator does this when they launch a specialist).
aith assess dispatch register \
    --agent-id recon_a3f9 \
    --agent-role recon-specialist \
    --task "Phase 1 wildcard subdomain enum + recon on saas.acme.example" \
    --scope-host saas.acme.example \
    --model claude-opus-4-7 \
    --reasoning high \
    --dispatch-mode hypothesis-driven \
    --skills subdomain-enumeration,web-recon

# Update status when the dispatch returns.
aith assess dispatch update-status recon_a3f9 \
    --status completed \
    --finding-slugs RECON-2026-01-15-001,RECON-2026-01-15-002

# List dispatches (DEDUP input — replaces the old JSON-file scan).
aith assess dispatch list --role recon-specialist --since 2026-01-15T00:00:00Z
aith assess dispatch list --task-q "wildcard subdomain"

# Inspect one dispatch's full row.
aith assess dispatch get recon_a3f9
```

The contract fields (`model`, `reasoning`, `dispatch_mode`) capture the dispatch
shape alongside the audit fields. Report-writer and later operators read these
to audit not only what was dispatched but also the dispatch configuration.

## Contract Schema

The contract fields recorded on every `dispatch register` call:

| Field | Type | Values |
|---|---|---|
| `dispatch_mode` | string | `hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation` (see "Dispatch-Mode Declaration" in `agent/operator-core.md`) |
| `skills` | string | Comma-separated skill names loaded by the specialist; required for non-operator roles. |
| `model` | string (optional) | model id (`claude-opus-4-7`, `claude-sonnet-4-6`, `gpt-5.4`) |
| `reasoning` | string (optional) | `low` / `medium` / `high` |

## Table 2 — `assessment_dispatch_handoffs`

The specialist's structured handoff. One row per dispatch, written immediately
before the dispatch returns.

Schema, per-role examples, and field-by-field guidance:
[`handoff-schema.md`](handoff-schema.md).

### CLI

```bash
# Specialist writes the handoff at the end of its dispatch.
aith assess dispatch record-handoff --from-json /tmp/handoff-recon-a3f9.json

# Operator renders the bounded markdown blob into the next dispatch's prompt.
aith assess dispatch render-handoff recon_a3f9
aith assess dispatch render-handoff recon_a3f9 --max-lines 60 --include-evidence
```

The renderer reads the handoff row, fetches each finding slug from the backend
(404 → "slug missing in backend"), checks every `working_artifacts` path on disk
(missing → "(state: missing)"), and emits a markdown blob hard-capped at
`--max-lines` (default 40). Findings list collapses to "... and N more" before
runtime_issues / working_artifacts. Summary, coverage gaps, and next steps are
never trimmed.

## Table 3 — `assessment_dispatch_decisions`

Decision rows that don't fit the dispatch table or the handoff blob. Used for
vendor-SaaS scope, egress reputation, dispatch_blocked, and similar
operator/specialist decisions.

### Fields

| Field | Type | Notes |
|---|---|---|
| `kind` | enum | `scope_decision` / `egress_decision` / `dispatch_blocked` / other operator-defined kinds. |
| `host` | string (optional) | The host the decision concerns. |
| `vendor` | string (optional) | The vendor / SaaS platform when relevant. |
| `choice` | string (optional) | `pending` / `in-scope` / `out-of-scope` / `partial-scope` / `accept-gap` / etc. |
| `phase` | string (optional) | The phase the decision was recorded in. |
| `reason` | string (optional) | Plain-language reason for the decision. |
| `note` | string (optional) | Additional commentary. |
| `payload_json` | JSON (optional) | Free-form structured detail. |
| `surfaced_to_user` | bool | True when the decision was raised to the human operator. |
| `recorded_at` | ISO datetime | Set automatically. |

### CLI

```bash
# Vendor-SaaS scope decision (recon-specialist surfaces; operator updates).
aith assess dispatch record-decision \
    --kind scope_decision \
    --host saas.acme.example \
    --vendor "Vendor SaaS" \
    --choice pending \
    --note "CNAME points at vendor; awaiting VDP scope confirmation" \
    --surfaced-to-user

# Egress reputation decision after the four-option checkpoint resolves.
aith assess dispatch record-decision \
    --kind egress_decision \
    --choice browser-based-tool \
    --payload-json '{"egress_block_pct": 67, "second_sample_pct": 64}' \
    --reason "Cloudflare bot-fight on direct egress; presenting browser fingerprint via runtime browser tool"

# Dispatch-blocked record when a specialist cannot launch.
aith assess dispatch record-decision \
    --kind dispatch_blocked \
    --phase recon \
    --reason "subdomain-enumeration skill missing required massdns binary in runtime image" \
    --surfaced-to-user
```

`dispatch_blocked` is non-negotiable for ANALYSIS/COVERAGE work. The operator
never silently moves blocked work back into the operator loop — surface the
blocker, record it, and either fix the runtime or mark the scope entry deferred
before advancing.

## Why these tables exist

- **Audit trail.** `dispatch list` shows what was tried, by whom, against which
  target and finding cluster. Read back during report-writing and
  log-investigation phases.
- **DEDUP input.** The pre-dispatch checklist runs
  `aith assess dispatch list --task-q "<keyword>"` to avoid re-dispatching the
  same role for the same objective. Cross-checks against the activity log
  (`aith assess fetch activity-entries`) for narrative dedup.
- **Handoff source.** The handoff row is the input
  `aith assess dispatch render-handoff <agent-id>` reads. Bounded, deterministic,
  pulls finding metadata from the findings table and artifact state from disk.
- **Decision audit.** Vendor-SaaS scope and egress-reputation decisions are
  cross-dispatch state — the dispatcher needs them when choosing the next
  dispatch's scope shape.

## Continuing work across dispatches

Every dispatch launches a fresh agent — continuity lives in what the operator
hands the new agent. The canonical path is the renderer:

```bash
aith assess dispatch render-handoff <prior-agent-id>
```

Paste the rendered blob verbatim into the new dispatch's prompt. The blob is
bounded (≤40 lines by default), every field comes from durable state, and the
next-step list is always emitted.

### Example rendered blob

```markdown
#### Handoff from exploit-developer dispatch exp_g8h3
- **Prior task:** RCE chain: phpMyAdmin → template injection → webshell
- **Scope host:** target.example
- **Phase:** exploit (status: completed)
- **Summary:** Chained EX-001 (auth-bypass) → EX-002 (RCE) into authenticated webshell on app.target.example; full chain recorded; one credential captured.
- **Findings recorded:**
  - `EX-2026-01-15-001` — Authenticated phpMyAdmin RCE via SQL UDF [severity=high]
  - `EX-2026-01-15-002` — Template injection in admin error page [severity=medium]
- **Coverage gaps:** none
- **Next steps:**
  - draft final report including chain narrative — engagement → report-writer (rationale: exploitation phase complete)
- **Working artifacts:**
  - `tools/exploit-state/EX-001-payload.sql` (state: present)
  - `tools/exploit-state/EX-002-poc.py` (state: missing)
- **Credentials captured:** 1 row (id: 17)
- **Recommended next agent:** report-writer
```

### Field flow

1. **Same base dispatch template** — role, target, phase, skill to load.
2. **Renderer-produced blob** — paste the `render-handoff` output verbatim. The
   new agent rebuilds its mental model from finding slugs, artifact paths, and
   the next-step list.
3. **Durable-state pointers** — finding slugs, file paths under `$DIR/`,
   credential ids. The new agent resolves these with `aith assess fetch` /
   `get-finding` instead of relying on stale inline copies, which keeps the
   prompt small and the state canonical.

## Making handoffs cheap

Capture transient state during the prior dispatch so it survives the handoff:

- **Backend state first.** Findings, credentials, access records,
  credential-tests, attack-chains, surfaces, and probes go in via
  `aith assess` helpers. The next agent queries the backend directly
  (`aith assess fetch ...`) rather than being handed inline copies.
- **Engagement files for transient state.** Session cookies, captured JWTs,
  CSRF tokens, upload paths, and working PoC scripts go under `$DIR/tools/`,
  `$DIR/scans/`, or `$DIR/downloads/` so the next dispatch can reference them
  by path. List them in the handoff's `working_artifacts` so the renderer
  surfaces present/missing state.
- **Backend activity log for narrative.** A condensed per-dispatch summary
  goes to the `activity_entries` table via
  `aith assess log <agent> <title> <action> <result>`. Query with
  `aith assess fetch activity-entries` — the log is engagement-scoped and
  FTS-searchable.
- **Handoff row for the structured cross-cutting fields.** Coverage gaps, next
  steps, runtime issues, working artifacts, open questions, role-specific
  extras — all live in `assessment_dispatch_handoffs`. Schema:
  [`handoff-schema.md`](handoff-schema.md).
