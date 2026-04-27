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
  the prior dispatch identifies which output transcript the new dispatch prompt
  pulls context from.

## Continuing Work Across Dispatches

Every dispatch launches a fresh agent, so continuity lives in what the operator
hands to the new agent. When the current task continues work the registry shows
was already started, build the new dispatch prompt from the prior agent's
relevant output and durable state:

1. **Same base dispatch template** — role, target, phase, skill to load.
2. **Prior agent's output excerpts** — paste the specific commands, captured
   tokens, intermediate PoC steps, and observations from the previous transcript.
   Narrative continuity (what was tried and why it matters) lives in the prompt,
   because the new agent rebuilds its mental model from what the dispatch carries.
3. **Durable-state pointers** — finding slugs, file paths under `$DIR/`, credential
   ids. The new agent resolves these with `aith assess fetch` instead of relying on
   stale inline copies, which keeps the prompt small and the state canonical.
4. **Specific next step** — the exact action the prior agent would have taken
   next ("replay captured token at `/api/vault` and read the victim's items"), not
   a rehash of the original objective.

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
