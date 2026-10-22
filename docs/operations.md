# Operations

The runtime container, its sizing and kernel limits, and orchestrator data management for a
running Vigil install.

## Runtime container

`vigil up` (or `vigil runtime start`) starts one long-lived Kali container named `vigil`.
Target-facing commands run through `vigil assess kali ...` via `docker exec`.

The container mounts the runtime data directory at `/data` (`state/runtime/` on a fresh workspace,
`.runtime-data/` on an adopted one, or `VIGIL_RUNTIME_DATA_DIR`), bind-mounts the engagement root
at `/engagements`, and receives the root `.env` when present. Fresh workspaces keep artifacts under
`engagements/<key>/`; adopted workspaces keep their existing paths. For non-interactive
maintenance, use `vigil runtime shell-exec "<cmd>"` so quoting and exit codes stay under the CLI.

`agent/docker/runtime-full/Dockerfile` is the only supported runtime for target-facing execution.
`agent/docker/runtime-lightweight/Dockerfile` is for faster Dockerfile iteration only
(`vigil runtime build lightweight --dev`).

## Resource sizing

The Kali runtime container is started with `--memory`, `--memory-swap` pinned
equal to `--memory` (so the container cannot swap), `--memory-swappiness=0`,
`--pids-limit`, and `--shm-size`. Memory, CPU, process, and shared-memory limits are configurable through
the process environment, then the selected workspace `.env`, then the defaults below.
The working directory does not select a different `.env`, and configuration reads do not
mutate the process environment. These are limits, not reserved resources;
the backend and proxy have separate resource use:

| Variable | Default | Effect |
|---|---|---|
| `VIGIL_RUNTIME_MEMORY_GB` | `2` | `--memory` and `--memory-swap` |
| `VIGIL_RUNTIME_CPUS` | `1` | `--cpus` |
| `VIGIL_RUNTIME_PIDS_LIMIT` | `512` | `--pids-limit` |
| `VIGIL_RUNTIME_SHM_SIZE` | `1g` | `--shm-size` |

```bash
VIGIL_RUNTIME_MEMORY_GB=16 VIGIL_RUNTIME_CPUS=8 vigil runtime start
```

Sizing guidance:

| Workload | Memory | CPU |
|---|---|---|
| Light, sequential testing (default) | 2 GiB | 1 |
| Single-target testing with larger tools | 4 GiB | 2 |
| Small bounty target, 2-3 parallel agents | 8 GiB | 4 |
| Large enterprise scope, 4-6 parallel specialists | 16 GiB | 8 |
| All tools warm, continuous engagement | 32 GiB | 12 |

`vigil up` and `vigil runtime start` refuse a memory limit of 85% or more of
Docker memory, and warn at 60% or more. This checks configured headroom, not
current memory usage. Lower `VIGIL_RUNTIME_MEMORY_GB` or increase Docker memory.
An intentional override is available with `vigil up --allow-oversubscribe` or
`vigil runtime start --allow-oversubscribe`. Restart checks run before replacing
the existing container. Existing containers keep their limits until recreated.

The 2 GiB default suits light work; larger tools and parallel workloads may need
an explicit higher limit. `vigil up --json` emits one result with service states
and any startup error; progress and resource warnings go to stderr. Inspect
configured and live limits with `vigil runtime resources --json`.

### Host gotchas

- **Docker Desktop on macOS:** check Settings → Resources when increasing
  the runtime limit; Docker memory must leave room for the daemon and other containers.
- **WSL2** defaults to 50% of host RAM capped at 8 GB — pin it in
  `%USERPROFILE%\.wslconfig`: `[wsl2] memory=12GB processors=8 swap=4GB`.
- **Apple Silicon** unified memory tolerates up to 50% of host RAM.

## File-descriptor and process limits

Vigil does not set container rlimits. `docker exec`-launched tools inherit
dockerd's daemon defaults — generous on Linux hosts (`nofile=1048576`,
`nproc=unlimited`) but tighter on Docker Desktop (`nofile=8192`, `nproc=4096`).

`vigil runtime start` probes the live limits and prints a stderr WARN when they
fall below the recommended `nofile=65536` / `nproc=8192`.

To raise them for every container, including `docker exec`-launched specialists,
edit `/etc/docker/daemon.json` (Linux) or Docker Desktop → Settings → Docker
Engine, then restart dockerd:

```json
{
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 131072, "Soft": 131072 },
    "nproc":  { "Name": "nproc",  "Hard": 16384,  "Soft": 16384 }
  }
}
```

Container-side `/etc/security/limits.conf` has no effect, because `docker exec`
does not invoke a PAM session.

## Orchestrator data and backups

The orchestrator UI is served from the backend at `http://127.0.0.1:18000` once
`vigil up` — or `vigil orchestrator start` for a targeted start — is running.

- **Live DB**: `<workspace>/state/orchestrator.sqlite3` in a fresh workspace
- **Scheduled backups**:
  `<workspace>/state/backups/orchestrator.<UTC-timestamp>.sqlite3`
  — an hourly WAL-coherent snapshot, last four copies retained by default
  (override with `VIGIL_BACKUP_MAX_COPIES`), written by the backend process
  itself.

Adopted workspaces keep their original database and backup paths, registered in
`workspace.json`; initialization does not relocate them.

`VIGIL_BACKUP_DISABLED=1` turns the scheduled backup off entirely. Running several
backend workers against one database means several concurrent backups, so set it
on all but one.

```bash
vigil backup create
vigil backup list
vigil backup show <backup-name>
vigil backup restore <backup-name-or-path>
```

### Where the data lives

The backend resolves its data directory in this order:

1. `VIGIL_DATA_DIR` — absolute path to the directory holding
   `orchestrator.sqlite3` and `backups/`
2. `REDTEAM_ORCHESTRATOR_DATA_DIR` — legacy alias of the same setting
3. `<backend>/data`

The CLI resolves private paths from workspace metadata and passes explicit
`VIGIL_DATA_DIR` and `VIGIL_ENGAGEMENTS_DIR` values to the backend, alongside
`VIGIL_INSTALL_DIR` for the workspace and `VIGIL_APPLICATION_DIR` for release
assets. If running the backend directly or relocating its data, set
`VIGIL_DATA_DIR` consistently for both CLI and backend.

### Deletion

Engagement deletion is explicit: `DELETE /engagements/<key>?confirm=<key>`, or the
frontend delete button with a typed-key confirmation. Renaming or removing an
engagement directory under the registered engagements path leaves the DB row intact — there
is no cascade delete.

## Backend ownership and recovery

Managed backend status and stop use a durable receipt containing process birth identity,
workspace and endpoint. A reused PID or an unrelated listener is not authority to stop it.
Preflight checks endpoint ownership before creating or starting engagement work and refuses
known-stale managed backends with a restart instruction. Explicit remote endpoints retain
remote ownership and upgrade guidance. Unknown ownership remains visible and blocks restore
until the backend's stopped state is established.

An unavailable Docker daemon reports runtime/proxy state as unknown or uninspected. Start
Docker and inspect again to distinguish an absent container from one that could not be queried.
