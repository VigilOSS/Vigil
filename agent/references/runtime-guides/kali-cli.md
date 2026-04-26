# Kali CLI Troubleshooting

Use when `aith assess kali --help` errors, a verb fails unexpectedly, or an audit POST returns an unexpected status.

## Diagnosis

1. **Local readiness and live state.** `aith doctor` and `aith status`. `aith doctor` checks dtach reachability inside the runtime, the orchestrator backend on `127.0.0.1:18000`, and the engagement directory layout. `aith status` shows the configured runtime resource tier and live cgroup state.
2. **Runtime container state.** `aith runtime status` confirms the container is up, the image ID matches the configured tag, and the `/engagements` bind mount is current.
3. **Configured resource tier.** `aith runtime resources` prints the tier (`Lab/CTF` / `Standard` / `Heavy` / `Comfortable`) and the live cgroup values from inside the container (`/sys/fs/cgroup/memory.max`, `cpu.max`). When OOM events show up in audit rows, this is the first thing to check.
4. **Engagement context.** If `aith assess kali --help` errors with an engagement-not-found message, run `aith engagement list` to confirm `ENGAGEMENT_DIR` is set and the engagement has a backend record. The CLI reads `engagement.json` and `.orchestrator.env` from the engagement directory; missing or stale either one breaks the audit POST.
5. **Restart the runtime if unhealthy.** `aith runtime restart` recreates the container with the current image and bind mount. No engagement data moves; only the container is replaced.
6. **Inspect runtime logs when needed.** `aith logs runtime --lines 120` tails container stdout/stderr.

## Boundary

The CLI runs on the host and execs into the runtime container with `docker exec`. Host-side `docker` commands (`docker ps`, `docker inspect`, `docker logs`) are for diagnostic inspection only — running probes through `docker exec` directly bypasses the audit pipeline. When a target-facing tool is missing from the runtime image, rebuild the image rather than ferrying the binary in or running it from the host. The host boundary is for orchestration, not target traffic.

## Dispatch-time guardrails

These are CLI-side rules that prevent foot-guns when many agents share one runtime:

- **No broad `pkill` by binary name.** Cleaning up "all the nmaps" via `pkill -f nmap` will kill another specialist's parallel scan. Agents only kill processes they spawned via tracked PIDs (the audit row carries `pid` for synchronous runs and `job_id` for async ones). The full process-cleanup discipline lives in `agent/scripts/assess/lib/kali.py`.
- **Per-agent binary copy pattern for very-long parallel runs.** When two specialists run multi-hour nmap sweeps in parallel and one finishes, naive cleanup can kill the other. The pattern is `cp /usr/bin/nmap /usr/local/bin/nmap-${AGENT_ID}` so each specialist invokes a uniquely-named binary; a later `pkill -f nmap-${AGENT_ID}` only kills that agent's processes. Use this only when the dispatch genuinely needs hours-long parallel execution; for shorter runs, the tracked-PID approach is enough.
- **`docker exec` parallelism cap.** Concurrent `aith assess kali ...` calls are capped at 5 by an internal CLI semaphore. This is the documented mitigation for [moby#45595](https://github.com/moby/moby/issues/45595) — `docker exec` becomes unresponsive at high parallelism, and capping at 5 keeps the runtime responsive while still allowing the operator to dispatch multiple specialists. The cap is implemented in `agent/scripts/assess/lib/kali.py`.

## Common errors

| Error | Cause | Fix |
|-------|-------|-----|
| `aith assess kali --help` errors with `engagement directory not set` | `ENGAGEMENT_DIR` env var missing or pointing at a non-existent path | `aith engagement list` to confirm engagement keys; export `ENGAGEMENT_DIR=$(aith engagement path <key>)` or `cd` into the engagement directory |
| `dtach: command not found` inside the runtime | Image was built before Phase 3 added `dtach` to the package list | Rebuild the runtime image: `docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .` then `aith runtime restart` |
| `audit POST 404` after a kali verb runs | Orchestrator backend not running | `aith orchestrator start`, then re-check with `aith status` |
| `audit POST 422` with `phase required` | Agent forgot to pass `--phase` (or passed an unknown value) | Add `--phase <enum>` to the invocation. Allowed values: `recon`, `collect`, `consume-test`, `verify`, `exploit`, `report`, `code-ingest`, `code-classify`, `code-hunt`, `code-verify`, `recon-pivot`, `exploit-recon`. The CLI fails closed on unknown phases so the backend never sees a malformed row |
| `audit POST 422` with `technique not in enum` | `--technique` passed a value not in `TECHNIQUE_ENUM` | Pick an enum value from `agent/skills/kali-exec/SKILL.md` (the audit-flag table) — use `OTHER` only when no specific class fits |
| `--intent exceeds 200 characters` | Intent string too long | Trim the intent to a one-liner; long context belongs in the prompt or the audit notes, not the intent field |
| `dedup window` warning blocks the call | Same `(command, argv_json)` ran within `KALI_CLI_DEDUP_WINDOW_SECONDS` (default 30s) | Either wait the window out, or pass `--force` if the re-run is intentional. Don't bypass dedup as a habit — the warning is catching accidental double-dispatch |
| Container not running | Runtime stopped (manual stop, OOM kill, host restart) | `aith runtime start`. If the container repeatedly OOMs, check `aith runtime resources` and bump the tier |
| `nikto: -h reserved by argparse` confusion | Trying to use `-h` as the target host | Use `--host <h>` instead — argparse reserves `-h` for help, so the typed wrapper exposes the target as `--host`. The underlying nikto invocation builds `nikto -h <host>` correctly |
| Stale orphan rows in `assessment_command_runs` | A previous run was killed by host OOM or the container was force-stopped before the CLI could finalize the row | Documented as a follow-up — `aith assess kali sweep-orphans` is the planned helper. Until it lands, the row stays in `running` status until manually patched via `aith assess patch command-runs/<id>` |

## Verifying the vocabulary

After install or an image rebuild, the canonical smoke test is:

```bash
aith assess kali --help                       # lists all 15 verbs
aith assess kali nmap-scan --help             # shows the typed flag set
aith assess contract kali nmap-scan           # canonical schema + helper defaults + example
aith runtime status                           # container up, image current, mount current
aith runtime resources                        # configured tier matches expectation
```

If all five succeed, the CLI is healthy. If any fail, walk the diagnosis steps above starting at `aith doctor`.

## See also

- `agent/skills/kali-exec/SKILL.md` — verb menu, audit-flag mapping, sync-vs-async decision, examples per verb.
- `agent/references/runtime-guides/command-history-auditing.md` — how to read `aith assess list-command-runs` as a coverage map.
