# Subagent Registry

Maintain `$DIR/agent-registry.json` as the engagement audit trail of subagent
dispatches. Each entry records who was dispatched, to which role, for which
objective, and with which finding slugs attached. The registry is an array —
multiple agents per role are common (e.g., two exploit-developer agents working
different finding clusters in parallel).

After every dispatch that returns an agentId, append to the registry. Each record carries the
specialist dispatch contract (see "Specialist Dispatch Contract" in `agent/operator-core.md`)
alongside the audit fields, so the registry records both what was dispatched and what the
dispatch was authorized to do:

```json
[
  {
    "role": "exploit-developer",
    "agent_id": "a424a88b02054913d",
    "task": "RCE chain: phpMyAdmin → template injection → webshell",
    "finding_slugs": ["EX-001", "EX-002"],
    "skill_loaded": "agent/skills/command-injection/SKILL.md",
    "scope_host": "target.example",
    "dispatched_at": "2026-03-30T15:30:00Z",
    "status": "returned",
    "model": "claude-opus-4-7",
    "reasoning": "high",
    "files_allowed": [
      "agent/agents/exploit-developer.md",
      "agent/shared-constraints.md",
      "agent/rules/hunting.md",
      "agent/rules/reporting.md",
      "agent/SKILL.md",
      "agent/skills/command-injection/SKILL.md"
    ],
    "files_forbidden": ["agent/AGENTS.md", "agent/CLAUDE.md"],
    "permission": "target-facing",
    "command_budget": 40,
    "output": "#### Findings, #### Chain Analysis, #### Evidence",
    "dispatch_mode": "deep-manual"
  },
  {
    "role": "exploit-developer",
    "agent_id": "b535bb9c13165a24e",
    "task": "IDOR escalation on user API",
    "finding_slugs": ["VA-003"],
    "skill_loaded": "agent/skills/idor-testing/SKILL.md",
    "scope_host": "target.example",
    "dispatched_at": "2026-03-30T16:45:00Z",
    "status": "returned",
    "model": "gpt-5.4",
    "reasoning": "high",
    "files_allowed": [
      "agent/agents/exploit-developer.md",
      "agent/shared-constraints.md",
      "agent/rules/hunting.md",
      "agent/SKILL.md",
      "agent/skills/idor-testing/SKILL.md"
    ],
    "files_forbidden": ["agent/AGENTS.md", "agent/CLAUDE.md"],
    "permission": "target-facing",
    "command_budget": 25,
    "output": "#### Findings, #### Evidence",
    "dispatch_mode": "deep-manual"
  }
]
```

## Contract Schema

The contract fields layered onto the audit record are:

| Field | Type | Values |
|---|---|---|
| `model` | string | model id (e.g. `claude-opus-4-7`, `claude-sonnet-4-6`, `gpt-5.4`) |
| `reasoning` | string | `low` / `medium` / `high` |
| `files_allowed` | string[] | role file plus `Load First` items and any extra references the task needs |
| `files_forbidden` | string[] | always includes `agent/AGENTS.md` and `agent/CLAUDE.md` (operator-only bootstrap) |
| `permission` | string | `artifact-only` / `passive-probe` / `target-facing` / `target-facing-destructive` |
| `command_budget` | integer | upper bound on `aith assess kali ...` calls |
| `output` | string | structured payload schema the agent returns |
| `dispatch_mode` | string | `hypothesis-driven` / `item-iterating` / `deep-manual` / `variant-rotation` (see "Dispatch-Mode Declaration" in `agent/operator-core.md`) |

The optional handoff fields the renderer reads alongside the contract record are:

| Field | Type | Purpose |
|---|---|---|
| `next_step` | string (optional) | The exact action the new dispatch should take ("replay captured token at `/api/vault` and read the victim's items"). Always emitted by `render-handoff`; when missing, the rendered blob says "not recorded — set explicitly in this dispatch" so the new prompt cannot silently drop the next action. |
| `working_artifacts` | string[] (optional) | Paths under `$DIR/` (typically `tools/`, `scans/`, or `downloads/`) the prior dispatch produced. Each entry is checked on disk by the renderer; missing files surface as `(state: missing)` so the new agent doesn't chase deleted state. |

When a specialist cannot be launched (missing skill, missing wrapper, runtime down), append a
blocker record instead of a contract record:

```json
{
  "kind": "dispatch_blocked",
  "phase": "1a",
  "role": "recon-specialist",
  "reason": "subdomain-enumeration skill missing required massdns binary in runtime image",
  "surfaced_to_user": true,
  "blocked_at": "2026-03-30T15:35:00Z"
}
```

Phase 1 dispatch is non-negotiable; the operator never silently moves blocked work back into
its own loop. Surface the blocker, record it, and either fix the runtime or mark the scope
entry deferred before advancing.

## Why the Registry Exists

- **Audit trail** — records what was tried, by whom, against which target and
  finding cluster. Read back during report-writing and log-investigation phases.
- **DEDUP input** — the pre-dispatch checklist checks the registry and the
  backend activity log (`aith assess fetch activity-entries`) to avoid
  re-dispatching the same role for the same objective.
- **Handoff source** — when continuing a multi-step task, the registry entry for
  the prior dispatch is the input the handoff renderer reads. Run
  `aith assess dispatch render-handoff <agent-id>` to produce the markdown
  blob; the renderer pulls findings from the backend, checks artifact paths
  on disk, and emits the always-present next-step line directly from the
  registry's `next_step` field.

## Continuing Work Across Dispatches

Every dispatch launches a fresh agent, so continuity lives in what the operator
hands to the new agent. When the current task continues work the registry shows
was already started, build the new dispatch prompt from the prior agent's
relevant output and durable state.

The canonical path is the renderer:

```bash
aith assess dispatch render-handoff <prior-agent-id>
```

It reads `$DIR/agent-registry.json`, fetches each finding slug from the
backend, checks every `working_artifacts` path on disk, and emits a markdown
blob hard-capped at `--max-lines` (default 40). Paste the rendered output
verbatim into the new dispatch's prompt. The renderer is what turns "two or
three excerpted lines from the prior transcript" from operator discipline
into a deterministic helper: the blob is bounded, every field comes from
durable state, and the next-step line is always emitted.

### Example rendered blob

```markdown
#### Handoff from exploit-developer dispatch a424a88b02054913d
- **Prior task:** RCE chain: phpMyAdmin → template injection → webshell
- **Skill loaded:** agent/skills/command-injection/SKILL.md
- **Scope host:** target.example
- **Dispatched at:** 2026-03-30T15:30:00Z (status: returned)
- **Findings recorded:**
  - `EX-001` — Authenticated phpMyAdmin RCE via SQL UDF [severity=high]
  - `EX-002` — Template injection in admin error page [severity=medium]
- **Working artifacts:**
  - `tools/exploit-state/EX-001-payload.sql` (state: present)
  - `tools/exploit-state/EX-002-poc.py` (state: missing)
- **Credentials captured:** 1 rows (ids: 17)
- **Next step (per registry):** Use captured admin cookie to chain EX-002 into the phpMyAdmin login form and validate RCE primitive end-to-end.
```

### Field flow

1. **Same base dispatch template** — role, target, phase, skill to load.
2. **Renderer-produced blob** — paste the `render-handoff` output verbatim.
   The new agent rebuilds its mental model from finding slugs, artifact paths,
   credential ids, and the next-step line.
3. **Durable-state pointers** — finding slugs, file paths under `$DIR/`, credential
   ids. The new agent resolves these with `aith assess fetch` instead of relying on
   stale inline copies, which keeps the prompt small and the state canonical.
4. **Specific next step** — the exact action the prior agent would have taken
   next ("replay captured token at `/api/vault` and read the victim's items"), not
   a rehash of the original objective. Recorded in the registry as `next_step`
   so the renderer surfaces it without operator intervention.

## Making Handoffs Cheap

The cheaper the handoff, the more productive each dispatch is — if the prior
agent left state on the floor, the next dispatch spends its context window
re-discovering session tokens, endpoints, and partial PoCs instead of moving the
attack forward.

Capture transient state during the prior dispatch so it survives the handoff:

- **Backend state first.** Findings, credentials, access records, credential-tests,
  attack-chains, surfaces, and probes go in via `aith assess` helpers.
  The next agent queries the backend directly (`aith assess fetch ...`) rather than
  being handed this inline.
- **Engagement files for transient state.** Session cookies, captured JWTs, CSRF
  tokens, upload paths, and working PoC scripts go under `$DIR/tools/`,
  `$DIR/scans/`, or `$DIR/downloads/` so the next dispatch can reference them
  by path.
- **Backend activity log for the narrative.** A condensed per-dispatch summary
  (what was tried, what worked, what the next step is) goes to the
  `activity_entries` table via `aith assess log <agent> <title>
  <action> <result>`. Query with `aith assess fetch activity-entries`
  — the log is engagement-scoped and FTS-searchable.
