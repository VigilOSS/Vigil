# Command History and Reuse

Every Kali MCP call made during an engagement lands in the orchestrator
backend's `assessment_command_runs` table with a searchable index. This
guide covers when to reuse a prior run, when a re-run is justified, and how
to interpret the audit fields.

## Quickstart

```bash
# Broad search for prior work on an objective
./scripts/assess.py list-command-runs --q "nmap 10.0.0.1"

# Scoped to a specific agent and phase
./scripts/assess.py list-command-runs \
    --agent-name recon-specialist --phase recon

# Only successful runs with a specific tool
./scripts/assess.py list-command-runs --tool-name nmap_scan --success

# Runs that timed out (prior coverage likely incomplete)
./scripts/assess.py list-command-runs --timed-out

# Fetch one run with previews and artifact refs
./scripts/assess.py get-command-run 142
```

## Reuse Decision Table

| Prior run state | Current need | Decision |
| --- | --- | --- |
| Same tool, same target, success, retained output covers the question | Same objective | **Reuse.** Quote the prior run id in your output. |
| Same tool, same target, success, output suppressed by retention policy | Same objective, need raw bytes | **Fetch artifact** via `get-command-run` before re-running — artifact is the canonical copy. |
| Same tool, same target, `timed_out=true` | Same objective, full coverage needed | **Re-run with tuned timeout or narrower input.** Cite the timeout in your justification. |
| Same tool, same target, `return_code != 0` | Same objective | **Investigate stderr first.** Re-run only if the failure reason is known and addressable. |
| Same tool, different target, success | Similar objective on a new target | **New run justified.** The audit table indexes by target via command text, not by auto-correlation, so the reviewer expects a fresh row. |
| Same tool and target, success, but stored before an auth change | Same objective with new credentials | **Re-run.** Note `auth context changed` in the dispatch reason. |
| Same tool and target, success, new hypothesis (different payload family) | Different objective | **New run justified.** Different payloads mean different coverage. |

## Data Volume — Default to the Lightweight Listing

`list-command-runs` returns **lightweight rows by default** so a sub-agent
can scan 50 prior runs without flooding its context. Each row carries
metadata, hashes, retention status, suppression reasons, artifact refs,
and `stdout_preview_chars` / `stderr_preview_chars` (the preview length
the backend has stored), but the preview text itself is omitted. Rule of
thumb: ~1 KiB per row in JSON, ~80 bytes per row in the CLI table.

When you have identified the one run worth inspecting, drill in:

```bash
./scripts/assess.py get-command-run <id>
```

That returns the full preview (up to 64 KiB) and any artifact refs.

`list-command-runs --include-output` and the equivalent
`?include_output=true` query param force previews into the listing — only
use this when you genuinely need bulk preview text (e.g. an operator
diff'ing two scans). A single run with retained 64 KiB output will fall
through ~16,000 LLM tokens worth of payload, so this is the wrong default
for sub-agent introspection.

## Interpreting Key Fields

- `output_retention_status`: `retained` (preview + full bytes in DB), `artifact` (preview in DB, full bytes in artifact file — fetch via `stdout_artifact_ref`/`stderr_artifact_ref`), `suppressed` (preview dropped by retention policy; `stdout_sha256` still uniquely identifies the output), `empty` (tool produced no output on that stream).
- `stdout_preview_chars` / `stderr_preview_chars`: the size of the preview the backend holds for this run. Lightweight listings omit the text but expose this so a caller can decide whether `get-command-run` is worth a follow-up call.
- `stdout_suppression_reason` / `stderr_suppression_reason`: populated when retention policy skipped the preview (for example `static-asset-filter` for grep'd URL lists, `binary-dump` for xxd/hexdump). The command and the hash are still recorded, so a reuse check by command text still succeeds.
- `timed_out`: the command exceeded its tool timeout. `return_code` will be `-1`. Treat coverage as incomplete.
- `success`: `true` when the command exited cleanly, or when it timed out with partial output the upstream Kali tool flags as usable. Always cross-check `timed_out` before accepting a success.
- `command_hash`: sha256 over the command string. Use it when you expect to see many re-runs of the same command — grouping by this hash deduplicates noise.

## When to Record the Reuse Decision

If you reuse a prior run instead of re-running, cite the prior `id` in your
output so a reviewer can audit the decision:

> Reused command-run #142 (nmap TCP top-1000 on 10.0.0.5 from recon-specialist, success, stdout retained). No re-scan required — target state unchanged since 2026-04-17T09:12Z.

If you re-run anyway, state which of the three re-run conditions applied
(state changed, prior partial/timed-out, different hypothesis) and why.

## Scope

- Records are keyed by engagement. `list-command-runs` only returns rows for
  the current engagement.
- The backend never shares command history across engagements — each
  engagement's audit log is isolated by `engagement_id`.
- The retention policy lives in
  `orchestrator/backend/app/config/command_run_retention.json` and is
  reloadable via the `COMMAND_RUN_RETENTION_CONFIG` environment variable.
