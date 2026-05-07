# Resume Rule

Resume hydration runs before new work in an existing engagement because backend state is the
operator's durable memory for findings, intel, dispatch handoffs, null results, and raw command
coverage. Skipping it causes duplicate dispatches, repeated probes, lost kill rationale, and
stale phase decisions.

Apply this rule after locating the engagement directory and reading `scope.json` when any of these
are true:
- `scope.json` shows `status: in_progress`
- The current phase is past initialization
- Findings, dispatch rows, activity entries, or command runs may already exist
- You are unsure whether the engagement is fresh

Run the core resume hydration before target-facing commands, specialist dispatch, phase
transitions, finding writes, or report work:

```bash
aith assess list-findings
aith assess list-intel
aith assess fetch activity-entries
aith assess dispatch list --limit 10
aith assess dispatch render-handoff <last-agent-id>
aith assess list-command-runs --q <scope-host-or-keyword>
```

Use the most recent relevant dispatch `agent_id` for `render-handoff`. If no dispatch has a
recorded handoff, state that explicitly and continue with the other resume checks. Use the primary
scope host for `list-command-runs --q`; if the target is code-only or hostless, use the repo/app
keyword only when runtime, fuzz, or Kali command history exists.

After hydration, summarize the resume state in one compact operator note:
- confirmed, suspicious, killed, and open findings
- intel that changes targeting or exploitability
- recent operator decisions and null results
- last dispatch owner, skills, result, and handoff gaps
- command-run coverage already performed against the host or keyword

Only then decide the next action.
