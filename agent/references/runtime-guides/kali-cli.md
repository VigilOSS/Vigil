---
description: "vigil assess kali troubleshooting and runtime maintenance: install drift (missing verb/flag/skill), backend unreachable, macOS host timeouts and BSD grep, discovery failures, image-drift and .local-host restarts, sizing, dispatch-time guardrails (no broad pkill, docker-exec parallelism), common errors (audit POST 422 phase required, dedup window, dtach missing), and the canonical smoke test"
skill: kali-exec
---

# Kali CLI Troubleshooting

Use this when `vigil assess kali --help` errors, a verb fails unexpectedly, an audit POST returns
an unexpected status, a verb, flag or skill a prompt names is missing, the backend is unreachable,
or a host-side command times out oddly. The execution rules (synchronous calls, the `--timeout`
ceiling, signalling only your own run, no host-side target traffic) are in
`agent/shared-constraints.md` §2.

## Install drift: a documented verb, flag, or skill is missing

`vigil assess ...` runs the scripts, prompts and skills of the application release recorded for
your workspace. When that record falls behind the application content, the older verb and skill
set runs. A documented flag then comes back as argparse "invalid choice", or a documented skill is
missing from disk. `vigil status` and the `vigil assess` passthrough print a non-fatal
`[vigil] WARN: install root <path> is stale ...` line that names `vigil install`. Treat that as the
first hypothesis when something a prompt names doesn't exist: run `vigil install` and retry before
you conclude the feature was never built. Upgrading the binary and reconciling the workspace are
separate steps (`docs/installation.md` "Upgrade").

## Backend unreachable

A connection error from any backend write (`record-surface`, `finding record`, …) means the
orchestrator is not answering on its base URL. Check `vigil status`, run `vigil orchestrator start`
if needed, and confirm the engagement key. The base URL resolves in this order:

1. the `ORCHESTRATOR_BASE_URL` env var
2. the engagement's `.orchestrator.env`
3. `vigil config get orchestrator_base_url`
4. the default `http://127.0.0.1:18000`

To change the port persistently, run `vigil config set orchestrator_base_url
http://127.0.0.1:<port>`.

## Host-side timeouts on macOS

Stock macOS has no `timeout(1)`, so `timeout: command not found` on the host says nothing about the
tool, target or sealed source. Use a Vigil command's own `--timeout`, or `vigil assess host-exec
--timeout <seconds>` for an audited host command. Use `gtimeout` only after confirming GNU coreutils
is installed. BSD grep has no `-P`, so use `grep -E` or `rg`.

## Diagnosis

1. **`vigil doctor` and `vigil status`.** `doctor` checks dtach inside the runtime, the backend,
   the engagement layout, and orphaned `<run_uuid>.failed-audit` markers under `scans/kali/`. A
   marker means the pre-exec audit POST failed for that run, so investigate connectivity. `status`
   shows the configured resource tier and live cgroup state.
2. **`vigil runtime status`.** Check that the container is up, the image ID matches the configured
   tag, and the `/engagements` bind mount is current.
3. **`vigil runtime resources`.** This prints the configured memory, cpus, pids and shm, and the
   live cgroup values. It does not print a tier name, so match the numbers against "Runtime sizing
   tiers" in `agent/references/runtime-guides/dispatch-resource-policy.md`, which also names the
   env vars that change them. Check this first when audit rows show OOM.
4. **Engagement context.** An engagement-not-found error from `vigil assess kali --help` means
   there is no binding. Start the client through `vigil engagement start`, work inside the
   engagement tree, or pass `--engagement-dir`. That session binding is independent of
   `vigil use` and `ENGAGEMENT_DIR`. The engagement also needs a backend record.
5. **`vigil runtime restart`.** This recreates the container with the current image and bind mount.
   Engagement data stays where it is; only the container is replaced. `vigil logs runtime --lines
   120` tails its output.

## Runtime maintenance

- **Image drift.** `vigil runtime start` refuses to run when the container's image ID differs from
  the configured tag. After any image rebuild or upgrade, run `vigil runtime restart`. A new
  resource size also takes effect only on restart.
- **Local `.local` replica hosts.** A `*.com.local` / `*.us.local` host resolves to loopback on the
  host, and reaches the runtime only through a docker `extra_hosts` mapping generated from
  `scope.json` when the container is created. `vigil engagement add-host` prints a restart prompt
  when a new exact `.local` host isn't wired yet. Before you run `vigil runtime restart`, confirm
  that no other engagement is using the shared runtime, because a restart interrupts concurrent
  work. Wildcard entries are never injected, so enumerate the exact subdomains you need.
- **Missing target-facing tool.** Rebuild the image (`vigil runtime build`, then `vigil runtime
  restart`). Don't ferry the binary in or run it from the host. Host-side `docker ps` / `inspect`
  / `logs` are for diagnosis only, because `docker exec` probes bypass the audit pipeline.

## Dispatch-time guardrails

- **`docker exec` parallelism.** Nothing in the CLI caps concurrent `vigil assess kali` calls,
  and each one is its own `docker exec`, which stalls at high parallelism
  ([moby#45595](https://github.com/moby/moby/issues/45595)). Keep concurrent synchronous calls
  across all live dispatches to about five.
- **No broad `pkill`** (`agent/shared-constraints.md` §2). The recipes below are the safe
  alternatives.

## Process cleanup discipline

### Long-running probes — `kali job` lifecycle (operator only)

Specialists run every call synchronously. A job is for the operator launching one authorized
sweep that must outlive a shell, such as nmap full-port, a deep sqlmap crawl, a large nuclei
sweep, ffuf with a deep wordlist, or multi-host puredns.

```bash
JOB_ID=$(vigil assess kali job start \
  --technique RECON --intent "phase 1 nmap full-tcp scan" \
  --probe-kind fingerprint --phase recon --timeout 7200 \
  -- nmap -p- -sV --max-rate 100 -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_full \
     www.example.gov \
  | jq -r '.job_id')
vigil assess kali job stop "$JOB_ID"   # SIGTERMs only this job's in-container PID and updates its row
```

### Stopping one synchronous run

Synchronous `kali exec` and every typed verb write the in-container PID to
`/tmp/vigil-pid-<run_uuid>.pid` for the duration of the run. To stop one from another shell:

```bash
vigil assess command-run list --q ffuf --json | jq -r '.[] | select(.status=="running") | .run_uuid'
vigil assess kali exec --technique META --intent "stop ffuf cleanly" \
  --probe-kind cleanup --phase recon --timeout 30 -- \
  sh -c 'kill -TERM "$(cat /tmp/vigil-pid-<run_uuid>.pid)"'
```

A timed-out run needs no cleanup. The CLI cascades SIGTERM→SIGKILL into the in-container PID
before the row finalizes, so a manual `pkill` afterwards could only hit a sibling's later run of
the same binary.

## Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `engagement directory not set` | No explicit flag, engagement-tree CWD, or launcher session binding | `vigil engagement start`, `cd` into the engagement, or `--engagement-dir <path>` |
| `dtach: command not found` in the runtime | Image lacks `dtach` | `vigil runtime build`, then `vigil runtime restart` |
| `audit POST 404` after a kali verb | Backend not running | `vigil orchestrator start`, then `vigil status` |
| `audit POST 422` / `phase required` | `--phase` missing or unknown | Pass a tag from `vigil assess contract kali <verb>` (source: `kali_audit.ALLOWED_PHASES`). A code lane passes its audit tag (`code-hunt`, `code-verify`, …), not the track phase name. |
| `audit POST 422` / `technique not in enum` | Unknown `--technique` | Choose from `vigil assess kali <verb> --help`. Use `OTHER` only when no class fits. |
| `--intent exceeds 200 characters` | Intent too long | Use one line. Context goes in the prompt or notes. |
| `dedup window` warning | Same `(command, argv_json)` within `KALI_CLI_DEDUP_WINDOW_SECONDS` (default 30 s). The command still runs, and its row links to the one it supersedes. | Usually an accidental double dispatch, so check first. `--force` marks an intentional re-run: it skips both the warning and the supersede link. |
| Container not running | Manual stop, OOM kill, host restart | `vigil runtime start`. If it keeps OOMing, check `vigil runtime resources` and raise the tier. |
| `nikto` `-h` confusion | argparse reserves `-h` | Pass the target as `--host <h>`. The wrapper builds `nikto -h <host>`. |
| Rows stuck at `status=running` | A finalize PATCH failed: backend restart, host crash, runtime OOM kill or a network blip | See `kali sweep-orphans` below. |

## When to run `kali sweep-orphans`

`vigil assess kali sweep-orphans` reconciles `assessment_command_runs` rows stuck at
`status=running` past a threshold age (default 3600 s). It probes each wrapper-recorded PID with
`kill -0`. It leaves live processes alone and finalizes rows whose process or pid file is gone to
`status=lost`. Run `--dry-run` first, then the real sweep, after any backend restart or host crash,
or periodically on long engagements. Exit code `7` from a verb (response present, terminal row not
durable) is reconciled the same way.

## Verifying the vocabulary

After an install or image rebuild, this smoke test confirms the CLI is healthy. If any step
fails, start the diagnosis at `vigil doctor`.

```bash
vigil assess kali --help
vigil assess kali nmap-scan --help
vigil assess contract kali nmap-scan
vigil runtime status
vigil runtime resources
```
