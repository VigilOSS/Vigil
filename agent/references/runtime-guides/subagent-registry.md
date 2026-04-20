# Subagent Registry

Maintain `$DIR/agent-registry.json` as the engagement audit trail of subagent
dispatches. Each entry records who was dispatched, to which role, for which
objective, and with which finding slugs attached. The registry is an array —
multiple agents per role are common (e.g., two exploit-developer agents working
different finding clusters in parallel).

After every dispatch that returns an agentId, append to the registry:
```json
[
  {
    "role": "exploit-developer",
    "agent_id": "a424a88b02054913d",
    "task": "RCE chain: phpMyAdmin → template injection → webshell",
    "finding_slugs": ["FINDING-EX-001", "FINDING-EX-002"],
    "skill_loaded": "agent/skills/command-injection/SKILL.md",
    "scope_host": "target.example",
    "dispatched_at": "2026-03-30T15:30:00Z",
    "status": "returned"
  },
  {
    "role": "exploit-developer",
    "agent_id": "b535bb9c13165a24e",
    "task": "IDOR escalation on user API",
    "finding_slugs": ["FINDING-VA-003"],
    "skill_loaded": "agent/skills/idor-testing/SKILL.md",
    "scope_host": "target.example",
    "dispatched_at": "2026-03-30T16:45:00Z",
    "status": "returned"
  }
]
```

## Why the Registry Exists

- **Audit trail** — records what was tried, by whom, against which target and
  finding cluster. Read back during report-writing and log-investigation phases.
- **DEDUP input** — the pre-dispatch checklist checks the registry and the
  backend activity log (`assess.py fetch activity-entries`) to avoid
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
   ids. The new agent resolves these with `assess.py fetch` instead of relying on
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
  attack-chains, surfaces, and probes go in via `./scripts/assess.py` helpers.
  The next agent queries the backend directly (`assess.py fetch ...`) rather than
  being handed this inline.
- **Engagement files for transient state.** Session cookies, captured JWTs, CSRF
  tokens, upload paths, and working PoC scripts go under `$DIR/tools/`,
  `$DIR/scans/`, or `$DIR/downloads/` so the next dispatch can reference them
  by path.
- **Backend activity log for the narrative.** A condensed per-dispatch summary
  (what was tried, what worked, what the next step is) goes to the
  `activity_entries` table via `./scripts/assess.py log <agent> <title>
  <action> <result>`. Query with `./scripts/assess.py fetch activity-entries`
  — the log is engagement-scoped and FTS-searchable.
