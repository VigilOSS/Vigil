---
description: How to read vigil assess command-run list as a coverage map — use it to pick variants that haven't been probed, not to gate-keep reruns; includes field-interpretation guide for retention/suppression
---

# Command History — Coverage Check Before Probing

Every `vigil assess kali` call (and `vigil assess host-exec`) lands in the backend's
`assessment_command_runs` table. `agent/shared-constraints.md` §2b owns the rule: search it before
probing and read it as a coverage map, not a reuse gate, so that any variant is new coverage. This
file covers the query shapes, the duplicate decision, and how to read a row's fields. The search
modes, filters and paging are in `vigil assess contract command-run list`.

When a prior run genuinely answers your current question, cite its id ("reused command-run
#142"). Open it with `vigil assess command-run get <id>` first: `success=true` means only
`return_code=0`, and soft-failure pages, WAF intercepts and rate-limited stubs all exit cleanly.

## Quickstart

```bash
vigil assess command-run list --q "nmap 10.0.0.1" --show-matches     # broad, cross-agent, cross-phase
vigil assess command-run list --agent-name recon-specialist --phase recon
vigil assess command-run list --tool-bin sqlmap --success           # argv[0] binary, even inside a generic exec wrapper
vigil assess command-run list --target-host app.example.com         # parsed target for httpx / nuclei / ffuf / sqlmap rows
vigil assess command-run list --timed-out                           # coverage likely incomplete
vigil assess command-run list --output-attention --json --limit 1000  # output that must not count as trustworthy evidence
vigil assess command-run get 142                                    # previews and artifact refs
```

`--tool-name` is the route-derived label (`nmap`, `command`). The table shows
`tool_bin(tool_name)` when the two differ, so `nuclei(command)` means nuclei ran through the
generic exec wrapper. Resume and sweep warnings point at `--output-attention` when their bounded
row-id sample left rows out. Page through with `--offset 1000, 2000, …` until the result is empty.

## Coverage-vs-duplicate decision table

| Prior run state | Current probe | Decision |
| --- | --- | --- |
| Same tool, same target, same flags, success, preview answers your question | Same objective | **Skip.** Cite the prior run id. |
| Same tool, same target, **different technique / payload family / wordlist / flag** | Variant | **Run it.** This is new coverage, not a duplicate — no justification needed. |
| Same tool, same target, `timed_out=true` | Same objective, full coverage | **Re-run with tuned timeout or narrower input.** Prior coverage is incomplete. |
| Same tool, same target, `return_code != 0` | Same objective | **Investigate stderr first.** Re-run only once you know why it failed. |
| Same tool, different target, success | New target | **Run it.** Prior runs against another target say nothing about this one. `target_host` is parsed only for httpx / nuclei / ffuf / sqlmap, so search other tools with `--q`. |
| Same tool and target, success, but before an auth change | Now authenticated | **Run it.** Auth context changed; prior coverage doesn't map. |
| Same tool, same target, inline output with `output_retention_status=suppressed` | Need raw bytes | **Re-run with a narrower/quieter configuration.** Inline raw bytes were discarded; only the byte count and SHA256 remain. |
| Same tool, same target, host output with `output_retention_status=suppression_pending` or `suppression_deferred` | Need raw bytes | **Do not treat the run as cleanly retained or erased.** The bytes are excluded from artifact search, but the private `scans/host-exec` spill may still contain them. `--require-audit` fails until isolation-backed cleanup can prove erasure. |
| Host output with `output_retention_status=untrusted` or `integrity_failure` | Any coverage decision | **Do not use it as evidence.** The process could not be quiesced or the verified snapshot changed. Re-run after resolving the process/integrity failure. |

## Data Volume — Default to the Lightweight Listing

`command-run list` returns lightweight rows by default, at about 1 KiB per JSON row. They carry
metadata, hashes, retention status, suppression reasons, artifact refs and
`stdout_preview_chars` / `stderr_preview_chars`, but not the preview text. Use `command-run get
<id>` for the full preview (up to 64 KiB, roughly 16k tokens). `--include-output` forces previews
into a listing; use it only when you need bulk preview text, such as diffing two scans.

## Interpreting Key Fields

- `stdout_bytes` / `stderr_bytes` / `stdout_sha256` / `stderr_sha256`: the size and digest of what
  the run actually WROTE, measured by the wrapper from the file it owns. On `kali` rows (sync and
  async-job alike) the full bytes live in the wrapper spill named by `stdout_path`/`stderr_path`,
  not in the bounded preview — so a large scan shows a real byte count here even though the preview
  is truncated. The integer columns retain zero as their storage default when a wrapper reports no
  byte measurements, so interpret them together with `output_retention_status`: `unmeasured` and
  `preview_only` never mean zero output. An orphan finalized without proving the process quiesced is
  `untrusted`, not empty.
- `output_retention_status`: `retained` (bounded preview retained — and, on a `kali` row, the full
  bytes still on disk at `stdout_path`/`stderr_path`), `artifact` (bounded preview plus a descriptor-verified snapshot at `stdout_artifact_ref`/`stderr_artifact_ref`), `suppressed` (one-shot inline bytes were discarded), `suppression_pending` (logical suppression committed but post-commit validation did not finish), `suppression_deferred` (logically suppressed and blocked from artifact indexing, while raw 0600 spill bytes may remain), `untrusted` (a host process group could not be quiesced, so no output hash or artifact was claimed), `integrity_failure` (a retained snapshot failed its post-commit identity/content check), or `empty`.
  `preview_only` means output was observed but total bytes were not measured;
  `partially_measured` means only one stream carried a total;
  `measurement_conflict` means a preview contradicted reported zero-byte totals;
  `unmeasured` means neither preview nor complete byte measurements were reported.
  Only `empty` means both streams were measured at zero bytes.
- `output_cleanup_status` / `output_cleanup_warning`: physical-cleanup truth for host spills. `deferred` is not success: raw bytes may remain in the private host-exec directory, and `--require-audit` exits nonzero. `pending` is a crash-recoverable transaction state owned by an exact duplicate terminal PATCH and by `vigil assess kali sweep-orphans` (also run by `resume-brief`); `warning` is terminal and requires operator attention.
- `output_integrity_status` / `output_integrity_warning`: snapshot publication truth. Trust an artifact ref only when this is `verified`. `pending` has the same deterministic PATCH/sweep recovery owner; `warning` is a terminal audit failure.
- `output_recovery_observed_at`: backend-owned recovery baseline. New finalizations stamp it in the same transaction as terminal state; migrated terminal-pending rows stamp the time the upgraded backend first observes them, which deliberately starts a fresh grace period without pretending to know their historical commit time. Reconciliation ages pending work only from this field, never client-supplied `completed_at` or process `started_at`.
- `stdout_preview_chars` / `stderr_preview_chars`: the size of the preview the backend holds for this run. Lightweight listings omit the text but expose this so a caller can decide whether `command-run get` is worth a follow-up call.
- `stdout_suppression_reason` / `stderr_suppression_reason`: populated when retention policy skipped the preview (for example `static-asset-filter` for grep'd URL lists, `binary-dump` for xxd/hexdump). The command and the hash are still recorded, so a coverage check by command text still succeeds.
- `timed_out`: the command exceeded its tool timeout. `return_code` will be `-1`. Treat coverage as incomplete.
- `success`: `true` when the command exited cleanly, or when it timed out with partial output the upstream Kali tool flags as usable. Always cross-check `timed_out` before accepting a success.
- `command_hash`: sha256 over the command string. Grouping by this hash shows which commands have been repeated (true duplicates) and which are variants (new coverage).

## Scope

Rows are isolated per engagement, so `command-run list` returns only the current engagement's
rows. Retention policy is in `orchestrator/backend/app/config/command_run_retention.json`
(override with `COMMAND_RUN_RETENTION_CONFIG`).
