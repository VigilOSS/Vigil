# Subagent Registry

Maintain `$DIR/agent-registry.json` to track subagent identities for resumption.
The registry is an array — multiple agents per role are common (e.g., two exploit-developer
agents working different finding clusters in parallel).

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

## Resume vs Fresh Dispatch

**Resume before re-dispatch.** Before spawning a new agent:
1. Check `agent-registry.json` for `returned` entries matching the role
2. **Resume** (via `SendMessage` to the existing `agent_id`) when ALL of:
   - Same `scope_host` (the hostname from scope.json, not a single URL — agents work many endpoints at one host)
   - At least one overlapping `finding_slug`, OR new task continues the same exploit chain
   - Dispatched within the current session (agents from prior sessions are stale — their context is gone)
3. **Dispatch fresh** when ANY of:
   - No matching entry exists
   - Different `scope_host` or unrelated finding cluster
   - The entry is from a prior session (check `dispatched_at` vs session start)
   - The new task needs a different skill than `skill_loaded`

## Why This Matters

A resumed agent retains its full context: session tokens, cookie jars, CSRF values, discovered
endpoints, and intermediate state from prior tool calls. Re-dispatching from scratch forces the
agent to re-discover all of that — the most expensive failure mode in multi-step exploitation.
