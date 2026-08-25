---
description: How to read vigil assess command-run list as a coverage map — use it to pick variants that haven't been probed, not to gate-keep reruns; includes field-interpretation guide for retention/suppression
---

# Command History — Coverage Check Before Probing

Every `vigil assess kali` call made during an engagement lands in the orchestrator
backend's `assessment_command_runs` table with a searchable index. Treat
this as a **coverage map** — a record of what's already been probed so your
next probe can go somewhere the engagement hasn't covered yet.

The table is not a reuse gate. Red-team depth comes from variants:
different SQLi techniques, different SSRF payload encodings, different XXE
entity styles, different wordlists, different auth contexts. The point of
checking history is to see what's *already been tried* so you can pick
something that hasn't.

## What to do with the history

1. **Before probing, search the table for prior work on this surface.**
   Default to an unscoped search so you see every agent's and every phase's
   prior work on the target — cross-agent and cross-phase context is
   usually the most valuable coverage signal:

   ```bash
   vigil assess command-run list --q <keyword> --show-matches
   ```

   Narrow with `--agent-name` or `--phase` only if the broad result is
   overwhelming.

2. **Read the prior runs as a coverage map.** If `sqlmap` has run against
   this endpoint with `--technique=U`, your next probe picks a different
   technique — don't re-run `-U`. If `ffuf` ran `raft-medium-directories`,
   try `quickhits` or a tech-specific wordlist. If SSRF was tested with
   `http://169.254.169.254/`, try DNS rebinding or `gopher://` next.

3. **Only avoid the identical command.** The audit table exists to stop you
   re-running the *exact same probe* against the *exact same input*. Any
   variant — different payload family, different tool, different flag,
   different target scope, different credentials — is new coverage and
   belongs in the engagement. Don't ask for permission to probe a variant.

4. **When a prior run is genuinely on-point for your current question,
   cite its id** in your output (e.g. "reused command-run #142"). Before
   citing, open the preview with `vigil assess command-run get <id>` — `success=true`
   only means `return_code=0`, not that the output answers your question.
   Soft-failure pages, WAF intercepts, and rate-limited stubs all exit
   cleanly.

## Quickstart

```bash
# Broad search for prior work on an objective
vigil assess command-run list --q "nmap 10.0.0.1" --show-matches

# Scoped to a specific agent and phase
vigil assess command-run list \
    --agent-name recon-specialist --phase recon

# Only successful runs with a specific typed verb
vigil assess command-run list --tool-name nmap_scan --success

# Filter by the underlying binary, even when it ran inside the generic
# execute_command wrapper. The backend derives tool_bin from the command
# string (peeling off timeout/sudo/env/sh -c wrappers), so --tool-bin catches
# generic-wrapper rows that --tool-name would miss.
vigil assess command-run list --q nuclei --tool-bin nuclei --show-matches
vigil assess command-run list --tool-bin sqlmap
vigil assess command-run list --tool-bin httpx --success

# Table rendering shows `tool_bin(tool_name)` whenever the two differ — e.g.
# `nuclei(command)` means nuclei was invoked through the execute_command wrapper.

# Runs that timed out (prior coverage likely incomplete)
vigil assess command-run list --timed-out

# Output that must not silently count as trustworthy evidence. Resume/sweep
# warnings point here when their bounded row-id sample omits additional rows;
# paginate with --offset 1000, 2000, ... until the result is empty.
vigil assess command-run list --output-attention --json --limit 1000

# Fetch one run with previews and artifact refs
vigil assess command-run get 142
```

## Coverage-vs-duplicate decision table

| Prior run state | Current probe | Decision |
| --- | --- | --- |
| Same tool, same target, same flags, success, preview answers your question | Same objective | **Skip.** Cite the prior run id. |
| Same tool, same target, **different technique / payload family / wordlist / flag** | Variant | **Run it.** This is new coverage, not a duplicate — no justification needed. |
| Same tool, same target, `timed_out=true` | Same objective, full coverage | **Re-run with tuned timeout or narrower input.** Prior coverage is incomplete. |
| Same tool, same target, `return_code != 0` | Same objective | **Investigate stderr first.** Re-run only once you know why it failed. |
| Same tool, different target, success | New target | **Run it.** The audit layer does not correlate by target — there's no `target_host` column — so prior runs against other targets tell you nothing about this one. |
| Same tool and target, success, but before an auth change | Now authenticated | **Run it.** Auth context changed; prior coverage doesn't map. |
| Same tool, same target, inline output with `output_retention_status=suppressed` | Need raw bytes | **Re-run with a narrower/quieter configuration.** Inline raw bytes were discarded; only the byte count and SHA256 remain. |
| Same tool, same target, host output with `output_retention_status=suppression_pending` or `suppression_deferred` | Need raw bytes | **Do not treat the run as cleanly retained or erased.** The bytes are excluded from artifact search, but the private `scans/host-exec` spill may still contain them. `--require-audit` fails until isolation-backed cleanup can prove erasure. |
| Host output with `output_retention_status=untrusted` or `integrity_failure` | Any coverage decision | **Do not use it as evidence.** The process could not be quiesced or the verified snapshot changed. Re-run after resolving the process/integrity failure. |

## Data Volume — Default to the Lightweight Listing

`command-run list` returns **lightweight rows by default** so a sub-agent
can scan 50 prior runs without flooding its context. Each row carries
metadata, hashes, retention status, suppression reasons, artifact refs,
and `stdout_preview_chars` / `stderr_preview_chars` (the preview length
the backend has stored), but the preview text itself is omitted. Rule of
thumb: ~1 KiB per row in JSON, ~80 bytes per row in the CLI table.

When you've identified the one run worth inspecting, drill in:

```bash
vigil assess command-run get <id>
```

That returns the full preview (up to 64 KiB) and any artifact refs.

`command-run list --include-output` and the equivalent
`?include_output=true` query param force previews into the listing — only
use this when you genuinely need bulk preview text (e.g. an operator
diff'ing two scans). A single run with retained 64 KiB output is ~16,000
LLM tokens of payload, so this is the wrong default for sub-agent
introspection.

## Interpreting Key Fields

- `stdout_bytes` / `stderr_bytes` / `stdout_sha256` / `stderr_sha256`: the size and digest of what
  the run actually WROTE, measured by the wrapper from the file it owns. On `kali` rows (sync and
  async-job alike) the full bytes live in the wrapper spill named by `stdout_path`/`stderr_path`,
  not in the bounded preview — so a large scan shows a real byte count here even though the preview
  is truncated. A row that reports no byte count is one whose wrapper could not read its spill, or
  one the orphan sweeper finalized without proving the process had quiesced; treat the absence as
  "not measured", never as "no output".
- `output_retention_status`: `retained` (bounded preview retained — and, on a `kali` row, the full
  bytes still on disk at `stdout_path`/`stderr_path`), `artifact` (bounded preview plus a descriptor-verified snapshot at `stdout_artifact_ref`/`stderr_artifact_ref`), `suppressed` (one-shot inline bytes were discarded), `suppression_pending` (logical suppression committed but post-commit validation did not finish), `suppression_deferred` (logically suppressed and blocked from artifact indexing, while raw 0600 spill bytes may remain), `untrusted` (a host process group could not be quiesced, so no output hash or artifact was claimed), `integrity_failure` (a retained snapshot failed its post-commit identity/content check), or `empty`.
- `output_cleanup_status` / `output_cleanup_warning`: physical-cleanup truth for host spills. `deferred` is not success: raw bytes may remain in the private host-exec directory, and `--require-audit` exits nonzero. `pending` is a crash-recoverable transaction state owned by an exact duplicate terminal PATCH and by `vigil assess kali sweep-orphans` (also run by `resume-brief`); `warning` is terminal and requires operator attention.
- `output_integrity_status` / `output_integrity_warning`: snapshot publication truth. Trust an artifact ref only when this is `verified`. `pending` has the same deterministic PATCH/sweep recovery owner; `warning` is a terminal audit failure.
- `output_recovery_observed_at`: backend-owned recovery baseline. New finalizations stamp it in the same transaction as terminal state; migrated terminal-pending rows stamp the time the upgraded backend first observes them, which deliberately starts a fresh grace period without pretending to know their historical commit time. Reconciliation ages pending work only from this field, never client-supplied `completed_at` or process `started_at`.
- `stdout_preview_chars` / `stderr_preview_chars`: the size of the preview the backend holds for this run. Lightweight listings omit the text but expose this so a caller can decide whether `command-run get` is worth a follow-up call.
- `stdout_suppression_reason` / `stderr_suppression_reason`: populated when retention policy skipped the preview (for example `static-asset-filter` for grep'd URL lists, `binary-dump` for xxd/hexdump). The command and the hash are still recorded, so a coverage check by command text still succeeds.
- `timed_out`: the command exceeded its tool timeout. `return_code` will be `-1`. Treat coverage as incomplete.
- `success`: `true` when the command exited cleanly, or when it timed out with partial output the upstream Kali tool flags as usable. Always cross-check `timed_out` before accepting a success.
- `command_hash`: sha256 over the command string. Grouping by this hash shows which commands have been repeated (true duplicates) and which are variants (new coverage).

## Scope

- Records are keyed by engagement. `command-run list` only returns rows for
  the current engagement.
- The backend never shares command history across engagements — each
  engagement's audit log is isolated by `engagement_id`.
- The retention policy lives in
  `orchestrator/backend/app/config/command_run_retention.json` and is
  reloadable via the `COMMAND_RUN_RETENTION_CONFIG` environment variable.
