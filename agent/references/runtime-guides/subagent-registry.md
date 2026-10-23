---
description: Backend dispatch tables (assessment_dispatches, assessment_dispatch_handoffs, assessment_dispatch_decisions) and their vigil assess agent ... CLI verbs — engagement audit trail, DEDUP input, handoff renderer source, decision audit
---

# Subagent Dispatch Registry — Backend Tables

Dispatch tracking, structured handoffs, and decision rows live in three backend
tables. The operator and specialists interact with these tables via `vigil assess agent ...`
CLI verbs.

| Table | Owner | CLI verbs | Purpose |
|---|---|---|---|
| `assessment_dispatches` | operator | `vigil assess agent start` / `done` / `list` / `get` / `close` / `reconcile-stale` | Audit trail of every specialist dispatch (role, task, contract, status, finding slugs). Closure: `agent close <id>` reads the handoff and applies `closed_dispatch_status` when handoff status is `ready` or `blocked`; `agent reconcile-stale [--dry-run]` lists in-progress dispatches past the age threshold and closes the ones whose handoff is closable. Both paths write a `dispatch_closed_from_handoff` decision row so closure is auditable. |
| `assessment_dispatch_handoffs` | specialist | `vigil assess agent handoff` / `render-handoff` | Structured per-dispatch handoff: summary, coverage gaps, next steps, runtime issues, working artifacts, open questions, role-specific extras. Lifecycle columns (`handoff_status`, `handoff_version`, `last_checkpoint_at`, `closed_dispatch_status`) separate checkpointing from closure. Schema: [`handoff-schema.md`](handoff-schema.md). |
| `assessment_dispatch_decisions` | operator + specialist | `vigil assess agent decision` | Cross-cutting decision rows. Kinds: `scope_decision`, `egress_decision`, `dispatch_blocked`, `coverage_deferral`, `dispatch_closed_from_handoff`. |

## Table 1 — `assessment_dispatches`

The operator's audit trail. One row per dispatched specialist agent.

### Fields

| Field | Type | Source |
|---|---|---|
| `agent_id` | string (PK) | Operator-assigned at `vigil assess agent start` time. Must match the spawned specialist's runtime identity (`AGENT_NAME` / wrapper label). |
| `agent_role` | string | `recon-specialist` / `vulnerability-analyst` / etc. |
| `assessment_mode` | `code` / `web` (optional by schema) | Required for mixed-role ordinary dispatches (`exploit-developer`, `source-analyzer`); proof-work derives it from its authoritative route. |
| `task` | string | One-paragraph dispatch objective. |
| `application_unit_id` | positive integer (optional) | Concrete application unit assigned to a dedicated lane; validated against the current engagement. |
| `dispatched_at` | ISO datetime | Set on agent start (`POST /dispatches`). |
| `completed_at` | ISO datetime | Set by `agent close` or an explicit `agent done --status` when status moves to a terminal value. |
| `status` | enum | `in-progress` / `completed` / `failed` / `aborted` / `blocked`. |
| `requested_model` | string | Operator-requested model id (`claude-opus-4-7`, …). |
| `launcher_effective_model` | string or null | Exact model attested for this child invocation by a trusted launcher/session integration; currently null for ordinary dispatches. |
| `actual_model` | string | Provider-observed model, or `unknown`; read-only to dispatch callers. |
| `requested_reasoning` | string | Requested reasoning level. |
| `launcher_effective_reasoning` | string or null | Exact reasoning configuration attested for this child invocation; currently null for ordinary dispatches. |
| `launcher_effective_source` | string or null | Attributable launcher/session evidence for the effective value; currently null for ordinary dispatches. |
| `actual_reasoning` | string | Provider-observed reasoning level, or `unknown`; read-only to dispatch callers. |
| `dispatch_mode` | string | `hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation` / `swarm`. |
| `finding_slugs_json` | JSON array | Finding slugs the dispatch produced (`agent close` copies the handoff; raw `agent done` may append additively). |

### CLI

```bash
# Register a dispatch. This writes the audit row; it does not launch a specialist.
vigil assess agent start \
    --agent-id recon_a3f9 \
    --role recon-specialist \
    --task "Phase 1 wildcard subdomain enum + recon on acme-social.example" \
    --model claude-opus-4-7 \
    --reasoning high \
    --dispatch-mode hypothesis-driven \
    --skills subdomain-enumeration,web-recon \
    --rate-budget "<exact operator-authored rate/concurrency instruction>" \
    --prompt-context-json dispatch-context.json


# Then launch the specialist with the client-native agent tool and pass it
# only launch_message from the successful receipt, pointing to its captured packet and SHA-256.

# After observed native return and checking owned execution ended, close its final handoff.
vigil assess agent render-handoff recon_a3f9
vigil assess agent close recon_a3f9

# If native return left no final handoff, preserve its checkpoint and record failed recovery.
vigil assess agent close recon_a3f9 --status failed --reason "Worker returned; owned commands ended"

# List dispatches (DEDUP input — replaces the old JSON-file scan).
vigil assess agent list --filter-role recon-specialist --since 2026-01-15T00:00:00Z
vigil assess agent list --task-q "wildcard subdomain"

# Inspect one dispatch's full row.
vigil assess agent get recon_a3f9
```

The request fields (`application_unit_id`, `requested_model`,
`requested_reasoning`, `dispatch_mode`, `assessment_mode`, `skills`) capture the
intended dispatch shape. Launcher-effective values remain null for every ordinary client. Static
OpenCode agent frontmatter, `opencode.json`, and Goose recipe settings describe
available configuration, but do not prove that a specific child invocation ran
or what arguments it ultimately received. Only a future trusted launcher/session
integration tied to that invocation may populate the nullable stored fields.
Responses also expose provider-observed actual model/reasoning when a trusted
integration has supplied them; otherwise both remain `unknown`.

## Contract Schema

The public fields accepted on every `vigil assess agent start` / `POST /dispatches` call:

| Field | Type | Values |
|---|---|---|
| `application_unit_id` | positive integer (optional) | Concrete application unit for depth attribution; must belong to the current engagement. |
| `assessment_mode` | `code` / `web` (optional by schema) | Required for mixed-role ordinary dispatches; proof-work sets it from `proof_route`. |
| `dispatch_mode` | string | `hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation` / `swarm` (see "Iteration-mode (dispatch_mode) Declaration" in `agent/operator-core.md`) |
| `skills` | string | Comma-separated skill names loaded by the specialist; required for non-operator roles. |
| `requested_model` | string (optional) | Intended model id from the operator |
| `requested_reasoning` | string (optional) | Intended reasoning level (`low` / `medium` / `high`) |

The CLI also requires exactly one non-persisted traffic declaration:
`--rate-budget "<exact authored instruction>"` or `--no-target-traffic`. It
prints that declaration on every start path; `--emit-prompt` renders it into the
complete prompt. Emission also requires `--prompt-context-json` (or top-level
`prompt_context` in `--from-json`) with every canonical prompt-only field listed
in `dispatch-template.md`; missing or empty values fail before the dispatch
write. These presentation fields are intentionally not duplicated in the
backend dispatch schema.

`launcher_effective_model`, `launcher_effective_reasoning`,
`launcher_effective_source`, `actual_model`, and `actual_reasoning` are audit
response/storage fields, not public write inputs. Caller-provided launcher or
provider observations are rejected rather than treated as proof.

## Table 2 — `assessment_dispatch_handoffs`

The specialist's structured handoff. One row per dispatch, written immediately
before the dispatch returns.

Schema, per-role examples, and field-by-field guidance:
[`handoff-schema.md`](handoff-schema.md).

### CLI

```bash
# Specialist writes the handoff at the end of its dispatch.
vigil assess agent handoff --from-json /tmp/handoff-recon-a3f9.json

# Operator renders the bounded markdown blob into the next dispatch's prompt.
vigil assess agent render-handoff recon_a3f9
vigil assess agent render-handoff recon_a3f9 --max-lines 60 --include-evidence
```

The renderer reads the handoff row, fetches each finding slug from the backend
(404 → "slug missing in backend"), checks every `working_artifacts` path on disk
(missing → "(state: missing)"), and emits a markdown blob hard-capped at
`--max-lines` (default 40). Findings list collapses to "... and N more" before
runtime_issues / working_artifacts. Summary, coverage gaps, and next steps are
preserved through the normal list-collapse passes; if their multiline prose
alone exceeds the hard cap, the renderer marks the remaining lines as truncated
and names the `--max-lines` recovery path.

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
vigil assess agent decision \
    --kind scope_decision \
    --host sso-vendor.acme-social.example \
    --vendor "Vendor SaaS" \
    --choice pending \
    --note "CNAME points at vendor; awaiting VDP scope confirmation" \
    --surfaced-to-user

# Egress reputation decision after the four-option checkpoint resolves.
vigil assess agent decision \
    --kind egress_decision \
    --choice browser-based-tool \
    --payload-json '{"egress_block_pct": 67, "second_sample_pct": 64}' \
    --reason "Cloudflare bot-fight on direct egress; presenting browser fingerprint via runtime browser tool"

# Dispatch-blocked record when a specialist cannot launch.
vigil assess agent decision \
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

- **Audit trail.** `vigil assess agent list` shows what was tried, by whom, against which
  target and finding cluster. Read back during report-writing and
  log-investigation phases.
- **DEDUP input.** The pre-dispatch checklist runs
  `vigil assess agent list --task-q "<keyword>"` to avoid re-dispatching the
  same role for the same objective. Cross-checks against the activity log
  (`vigil assess fetch activity-entries`) for narrative dedup.
- **Handoff source.** The handoff row is the input
  `vigil assess agent render-handoff <agent-id>` reads. Bounded, deterministic,
  pulls finding metadata from the findings table and artifact state from disk.
- **Decision audit.** Vendor-SaaS scope and egress-reputation decisions are
  cross-dispatch state — the dispatcher needs them when choosing the next
  dispatch objective.

## Continuing work across dispatches

Every dispatch launches a fresh agent — continuity lives in what the operator
hands the new agent. The canonical path is the renderer:

```bash
vigil assess agent render-handoff <prior-agent-id>
```

Paste the rendered blob verbatim into the new dispatch's prompt. The blob is
bounded (≤40 lines by default), every field comes from durable state, and the
next-step list is always emitted.

### Example rendered blob

```markdown
#### Handoff from exploit-developer dispatch exp_g8h3
- **Prior task:** RCE chain: phpMyAdmin → template injection → webshell
- **Application unit:** 42
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
   credential ids. The new agent resolves these with `vigil assess fetch` /
   `get-finding` instead of relying on stale inline copies, which keeps the
   prompt small and the state canonical.

## Making handoffs cheap

Capture transient state during the prior dispatch so it survives the handoff:

- **Backend state first.** Findings, credentials, access records,
  credential-tests, attack-chains, surfaces, and probes go in via
  `vigil assess` helpers. The next agent queries the backend directly
  (`vigil assess fetch ...`) rather than being handed inline copies.
- **Engagement files for transient state.** Session cookies, captured JWTs,
  CSRF tokens, upload paths, and working PoC scripts go under `$DIR/tools/`,
  `$DIR/scans/`, or `$DIR/downloads/` so the next dispatch can reference them
  by path. List them in the handoff's `working_artifacts` so the renderer
  surfaces present/missing state.
- **Backend activity log for narrative.** A condensed per-dispatch summary
  goes to the `activity_entries` table via
  `vigil assess log <agent> <title> <action> <result>`. Query with
  `vigil assess fetch activity-entries` — the log is engagement-scoped and
  FTS-searchable.
- **Handoff row for the structured cross-cutting fields.** Coverage gaps, next
  steps, runtime issues, working artifacts, open questions, role-specific
  extras — all live in `assessment_dispatch_handoffs`. Schema:
  [`handoff-schema.md`](handoff-schema.md).
