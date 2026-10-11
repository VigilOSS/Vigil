# Operations

Runtime sizing, kernel limits, and orchestrator data management for a running
Vigil install.

## Resource sizing

The Kali runtime container is started with `--memory`, `--memory-swap` pinned
equal to `--memory` (so the container cannot swap), `--memory-swappiness=0`,
`--pids-limit`, and `--shm-size`. Those four values are the only container
resources Vigil sets, and each is an environment variable read before
`vigil runtime start`:

| Variable | Default | Effect |
|---|---|---|
| `VIGIL_RUNTIME_MEMORY_GB` | `8` | `--memory` and `--memory-swap` |
| `VIGIL_RUNTIME_CPUS` | `4` | `--cpus` |
| `VIGIL_RUNTIME_PIDS_LIMIT` | `512` | `--pids-limit` |
| `VIGIL_RUNTIME_SHM_SIZE` | `1g` | `--shm-size` |

```bash
VIGIL_RUNTIME_MEMORY_GB=16 VIGIL_RUNTIME_CPUS=8 vigil runtime start
```

Sizing guidance:

| Workload | Memory | CPU |
|---|---|---|
| Single-target sequential testing | 4 GB | 2 |
| Small bounty target, 2-3 parallel agents (default) | 8 GB | 4 |
| Large enterprise scope, 4-6 parallel specialists | 16 GB | 8 |
| All tools warm, continuous engagement | 32 GB | 12 |

`vigil runtime start` refuses a tier that claims too large a fraction of the
Docker VM, and prints an upward hint when the host has RAM to spare. Live cgroup
state: `vigil runtime resources`.

### Host gotchas

- **Docker Desktop on macOS** defaults to 4 GB — raise it under Settings →
  Resources before running the 8 GB default tier.
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
  — a WAL-coherent snapshot every 15 minutes, last 12 copies retained by default
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
