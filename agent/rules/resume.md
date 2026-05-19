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
aith assess resume-brief
```

For targeted continuation, narrow the brief instead of manually reconstructing state:

```bash
aith assess resume-brief --finding <finding-slug-or-alias>
aith assess resume-brief --q "<scope-host-or-keyword>"
aith assess resume-brief --agent-id <agent-id>
```

The brief includes finding queues, recent decisions, stale dispatches, handoff gaps,
relevant command-history matches, and indexed artifacts. Use the drill-down commands it
prints for exact evidence:

```bash
aith assess get-command-run <id>
aith assess artifact search <query>
aith assess artifact get <id>
aith assess agent render-handoff <agent-id>
```

Use command history as a coverage map, not as a reuse gate. If you cite a prior run
instead of re-running, fetch it with `aith assess get-command-run <id>` first because
a successful return code does not prove the preview answers the current question.

Treat unlinked markdown notes as scratch, not engagement memory. State that must
survive resume goes into backend rows or into an indexed artifact linked to a
finding, chain, dispatch/agent, surface, request variant, or command run.

### Do not, during resume

- Do not fetch `coverage-items`, `request-variants`, or full work-buffer dumps —
  they are not part of the resume picture. The brief already names the surfaces
  and command runs you need; drill down by id with `get-command-run`,
  `artifact get`, or `fetch findings/<slug>`.
- Do not read unindexed `.md` files under the engagement directory. A note that
  is not in `artifact search` is scratch and is not part of engagement memory.
- Do not paste prior dispatch transcripts. Use
  `aith assess agent render-handoff <agent-id>` so the next prompt stays bounded.
- Do not re-run a probe just because it is faster than reading prior coverage.
  The command history is canonical; rerun only when the variant differs.

After hydration, summarize the resume state in one compact operator note:
- confirmed, suspicious, killed, and open findings
- intel that changes targeting or exploitability
- recent operator decisions and null results
- last dispatch owner, skills, result, and handoff gaps
- command-run coverage already performed against the host or keyword
- indexed artifacts that matter to the next action

Only then decide the next action.
