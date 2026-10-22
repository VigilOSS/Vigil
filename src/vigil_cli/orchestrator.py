from __future__ import annotations

import os
import json
import hashlib
import math
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import restart_manifest, term
from .application import application_root_for_workspace
from .paths import engagements_root, resolve_logs_dir, resolve_orchestrator_data_dir, resolve_runtime_state_dir
from .workspace import workspace_path
from .process_identity import _process_identity
from .service_locks import service_start_lock


# E1: opt-in multi-worker uvicorn. Default stays 1 (single-process) so existing
# single-engagement runs are unchanged; raise it only on a dedicated/heavy-tier
# host where many agents call the backend concurrently. ``workers=None`` means
# "resolve from the VIGIL_ORCHESTRATOR_WORKERS env" so callers that don't pass an
# explicit value still pick up the knob.
WORKERS_ENV = "VIGIL_ORCHESTRATOR_WORKERS"
ORCHESTRATOR_START_TIMEOUT_SECONDS = 600.0
START_TIMEOUT_ENV = "VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS"
BACKEND_DEPENDENCY_SYNC_TIMEOUT_SECONDS = 120.0
_PROC_ROOT = Path("/proc")


def _emit(record: str, *, state: str | None = None) -> None:
    """Render one orchestrator lifecycle record without changing piped output."""
    if not term.is_terminal(sys.stdout):
        print(record)
        return
    fields = record.split("\t")
    detail = " · ".join(fields[1:])
    if state is None:
        state = "warn" if len(fields) > 1 and fields[1] == "warn" else "info"
    print(term.row(state, "Orchestrator", detail, stream=sys.stdout))


@dataclass(frozen=True, slots=True)
class OrchestratorOptions:
    install_root: Path
    host: str = "127.0.0.1"
    port: int = 18000
    build: bool = False
    foreground: bool = False
    allow_existing: bool = False
    # None -> read VIGIL_ORCHESTRATOR_WORKERS (default 1). An explicit int (e.g.
    # from a future `--workers N` flag) overrides the env.
    workers: int | None = None


def _resolve_worker_count(options: OrchestratorOptions) -> int:
    """Resolve the uvicorn worker count: explicit option > env > default 1.

    Returns a value >= 1. A malformed env value falls back to 1 with a warning
    rather than failing the launch.
    """
    if options.workers is not None:
        return max(1, int(options.workers))
    raw = os.environ.get(WORKERS_ENV, "").strip()
    if not raw:
        return 1
    try:
        value = int(raw)
    except ValueError:
        _emit(f"orchestrator\twarn\tignoring non-integer {WORKERS_ENV}={raw!r}; using workers=1", state="warn")
        return 1
    if value < 1:
        _emit(f"orchestrator\twarn\t{WORKERS_ENV}={raw!r} < 1; using workers=1", state="warn")
        return 1
    return value


def _startup_timeout_seconds() -> float:
    raw = os.environ.get(START_TIMEOUT_ENV, "").strip()
    if not raw:
        return ORCHESTRATOR_START_TIMEOUT_SECONDS
    try:
        seconds = float(raw)
    except ValueError:
        seconds = math.nan
    if not math.isfinite(seconds) or seconds <= 0:
        raise SystemExit(f"{START_TIMEOUT_ENV} must be a finite positive number of seconds; got {raw!r}.")
    return seconds


def start_orchestrator(options: OrchestratorOptions) -> None:
    with service_start_lock(f"orchestrator:{options.host}:{options.port}"):
        _start_orchestrator_locked(options)


def _start_orchestrator_locked(options: OrchestratorOptions) -> None:
    startup_timeout = _startup_timeout_seconds()
    endpoint = f"http://{'[' + options.host + ']' if ':' in options.host else options.host}:{options.port}"
    install_root = options.install_root.expanduser().resolve()
    application_root = application_root_for_workspace(install_root)
    runtime_dir = resolve_runtime_state_dir(install_root)
    pid_file = runtime_dir / "pids" / "orchestrator.pid"
    log_file = resolve_logs_dir(install_root) / "orchestrator.log"
    runtime_dir.joinpath("pids").mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    print(term.paint("Starting Vigil", "bold", stream=sys.stdout), flush=True)
    if _frontend_build_needed(application_root, force=options.build):
        print(term.row("info", "Web interface", "building", stream=sys.stdout), flush=True)
        _build_frontend(application_root)
    print(term.row("ok", "Web interface", "ready", stream=sys.stdout), flush=True)

    if _report_build_needed(application_root, force=options.build):
        print(term.row("info", "Report renderer", "building", stream=sys.stdout), flush=True)
        _build_report(application_root)
    print(term.row("ok", "Report renderer", "ready", stream=sys.stdout), flush=True)

    process_state = orchestrator_status_payload(install_root, host=options.host, port=options.port, local_only=True)
    if process_state["state"] == "running":
        pid = str(process_state["pid"])
        if options.allow_existing:
            _emit(f"orchestrator\talready running\tpid={pid}", state="ok")
            return
        raise SystemExit(_already_running_message(pid_file, pid, options.host, options.port))

    if process_state["state"] in {"unknown", "foreign"}:
        raise SystemExit(f"Cannot start backend: {process_state['detail']}")
    _check_port_available(options.host, options.port)

    env = {
        **os.environ,
        "VIGIL_INSTALL_DIR": str(install_root),
        "VIGIL_APPLICATION_DIR": str(application_root),
        "VIGIL_ENGAGEMENTS_DIR": str(engagements_root(install_root)),
        "VIGIL_DATA_DIR": str(resolve_orchestrator_data_dir(install_root)),
        "UV_PROJECT_ENVIRONMENT": str(_backend_environment(install_root, application_root)),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    cli_directory = application_root / ("cli" if (application_root / "cli/vigil_cli").is_dir() else "src")
    inherited_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(cli_directory) + (os.pathsep + inherited_pythonpath if inherited_pythonpath else "")
    executable = str(_backend_environment(install_root, application_root) / "bin" / "python")
    argv = [executable, "-m", "uvicorn", "app.main:app", "--host", options.host, "--port", str(options.port)]
    # E1: only append --workers when explicitly raised above the default 1. A bare
    # uvicorn launch is already single-worker, so the default argv is byte-for-byte
    # unchanged — opt-in only.
    workers = _resolve_worker_count(options)
    if workers > 1:
        argv += ["--workers", str(workers)]
        _warn_multiworker_caveats(workers)
    _sync_backend_environment(application_root, env=env, log_file=log_file)
    if options.foreground:
        os.chdir(application_root / "orchestrator" / "backend")
        os.execvpe(executable, argv, env)
    print(term.row("info", "Backend", "starting", stream=sys.stdout), flush=True)
    with log_file.open("ab") as log, open(os.devnull, "rb") as stdin:
        process = subprocess.Popen(
            argv,
            cwd=application_root / "orchestrator" / "backend",
            env=env,
            stdin=stdin,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    try:
        identity = _process_identity(process.pid)
        if identity is None:
            raise SystemExit(f"Backend exited before ownership could be recorded (exit code {process.poll()}; see {log_file}).")
        receipt = {"pid": process.pid, "process_identity": identity, "workspace": str(install_root),
                   "host": options.host, "port": options.port, "process_group": process.pid}
        _write_process_receipt(pid_file.with_suffix(".json"), receipt)
    except BaseException:
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        raise
    startup_deadline = time.monotonic() + startup_timeout
    if not _wait_for_health(options.host, options.port, process=process, timeout=startup_timeout):
        exit_code = process.poll()
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        pid_file.with_suffix(".json").unlink(missing_ok=True)
        if exit_code is not None:
            raise SystemExit(f"Orchestrator exited with code {exit_code} during startup (see {log_file}).")
        raise SystemExit(
            f"Orchestrator did not become healthy on {endpoint}/healthz "
            f"within the {startup_timeout:g}s startup budget (see {log_file}). "
            f"For a large database migration, inspect the log before retrying with a larger {START_TIMEOUT_ENV}."
        )
    remaining = max(0.0, startup_deadline - time.monotonic())
    if not _wait_for_readiness(options.host, options.port, process=process, timeout=remaining):
        exit_code = process.poll()
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        pid_file.with_suffix(".json").unlink(missing_ok=True)
        if exit_code is not None:
            raise SystemExit(f"Orchestrator exited with code {exit_code} during startup (see {log_file}).")
        raise SystemExit(
            f"Orchestrator did not become ready on {endpoint}/readyz "
            f"within the {startup_timeout:g}s startup budget (see {log_file}). "
            f"Inspect the log before retrying with a larger {START_TIMEOUT_ENV}."
        )
    print(term.row("ok", "Backend", "ready", stream=sys.stdout))
    print(f"\nVigil is ready: {endpoint}")
    print("Logs: vigil logs orchestrator")


def _backend_environment(workspace: Path, application_root: Path) -> Path:
    """Keep backend dependencies outside immutable release assets."""
    digest = hashlib.sha256(str(application_root).encode())
    for name in ("pyproject.toml", "uv.lock"):
        path = application_root / "orchestrator" / "backend" / name
        digest.update(path.read_bytes() if path.is_file() else b"<absent>")
    return workspace_path(workspace, "cache") / f"backend-{digest.hexdigest()[:24]}"


def _sync_backend_environment(application_root: Path, *, env: dict[str, str], log_file: Path) -> None:
    """Provision only locked dependencies outside the immutable application."""
    environment = env["UV_PROJECT_ENVIRONMENT"]
    print(term.row("info", "Backend dependencies", "checking", stream=sys.stdout), flush=True)
    argv = ["uv", "sync", "--frozen", "--no-install-project", "--directory", "orchestrator/backend"]
    try:
        with log_file.open("ab") as log:
            subprocess.run(
                argv, cwd=application_root, env=env, stdout=log, stderr=subprocess.STDOUT,
                check=True, timeout=BACKEND_DEPENDENCY_SYNC_TIMEOUT_SECONDS,
            )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit(
            f"Backend dependency synchronization timed out after {BACKEND_DEPENDENCY_SYNC_TIMEOUT_SECONDS:g}s "
            f"(environment {environment}; see {log_file}); no backend was started."
        ) from exc
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            f"Backend dependency synchronization failed (environment {environment}; see {log_file}); "
            "check uv and dependency availability, then retry. No backend was started."
        ) from exc


def _warn_multiworker_caveats(workers: int) -> None:
    """Surface the two known single-process assumptions before going multi-worker.

    These are intentionally WARN-only (the operator opted in via the env/flag),
    but they must be visible because both regress silently otherwise:
      * The live-UI WebSocket broadcaster (app/ws.py) keeps connections in an
        in-process dict, so a write handled by worker A cannot push to a socket
        held by worker B — the dashboard sees only the events from its own worker.
      * The hourly backup scheduler (app/services/backup.py) arms a per-process
        timer in each worker's lifespan, so N workers run N concurrent backups
        unless VIGIL_BACKUP_DISABLED is set on all but one.
    Workers greater than one therefore remain an explicitly caveated opt-in
    until cross-process WebSocket fan-out and single-leader backup scheduling
    are implemented.
    """
    _emit(
        f"orchestrator\twarn\tworkers={workers}: live-UI WebSocket broadcast is per-worker "
        f"(dashboard may miss cross-worker events) and the backup scheduler arms once per "
        f"worker — set VIGIL_BACKUP_DISABLED=1 on all but one to avoid N concurrent backups. "
        f"The API read/write paths are safe under load: reads run in the threadpool and "
        f"async write handlers off-load their SQLite work to it too (anyio.to_thread), so a "
        f"sync write never blocks the event loop, atop SQLite WAL + short-lived per-request "
        f"connections.",
        state="warn",
    )


def _write_process_receipt(path: Path, receipt: dict[str, object]) -> None:
    from .install_fs import atomic_write_bytes, open_pinned_directory
    pin = open_pinned_directory(path.parent, create=True)
    assert pin is not None
    with pin:
        atomic_write_bytes(pin.fd, path.name, (json.dumps(receipt) + "\n").encode(), mode=0o600, display=path)


def stop_orchestrator(install_root: Path, *, host: str = "127.0.0.1", port: int = 18000) -> None:
    state = orchestrator_status_payload(install_root, host=host, port=port, local_only=True)
    if state["state"] == "stopped":
        return
    if state["state"] != "running" or state.get("ownership") != "owned":
        raise SystemExit(f"Cannot stop backend: {state.get('detail', 'process ownership is unknown')}. Inspect the owning workspace and endpoint first.")
    pid = int(str(state["pid"]))
    if _process_identity(pid) != state.get("process_identity"):
        raise SystemExit("Backend process identity changed before stop; inspect status again.")
    _emit(f"orchestrator\tstopping\tpid={pid}", state="info")
    group = state.get("process_group")
    signal_process = _signal_process_group if group == pid else os.kill
    signal_process(pid, signal.SIGTERM)
    if not _wait_for_pid_exit(pid, timeout=2.0):
        if _process_identity(pid) == state.get("process_identity"):
            signal_process(pid, signal.SIGKILL)
            _wait_for_pid_exit(pid, timeout=1.0)
    pid_file = Path(str(state["pid_file"]))
    pid_file.unlink(missing_ok=True)
    pid_file.with_suffix(".json").unlink(missing_ok=True)
    if not _wait_for_port_release(str(state["host"]), int(str(state["port"])), timeout=3.0):
        holder = _port_listener_pid(str(state["host"]), int(str(state["port"])))
        holder_text = f" (PID {holder})" if holder is not None else ""
        _emit(f"orchestrator\twarn\t{state['host']}:{state['port']} still held{holder_text} after stop; inspect its ownership", state="warn")
        return
    _emit("orchestrator\tstopped", state="ok")


def orchestrator_status(install_root: Path) -> str:
    return str(orchestrator_status_payload(install_root)["state"])


def _listener_application_matches(pid: int, install_root: Path) -> bool:
    """Require an actual uvicorn process in the selected application, not just a port."""
    import shlex
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-ww", "-o", "command="], capture_output=True, text=True, timeout=2)
        argv = shlex.split(result.stdout)
        if result.returncode != 0 or "uvicorn" not in argv or "app.main:app" not in argv:
            return False
        proc_cwd = Path(f"/proc/{pid}/cwd")
        if Path("/proc").is_dir():
            cwd = proc_cwd.resolve(strict=True)
        else:
            result = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"], capture_output=True, text=True, timeout=2)
            locations = [line[1:] for line in result.stdout.splitlines() if line.startswith("n")]
            if result.returncode != 0 or len(locations) != 1:
                return False
            cwd = Path(locations[0]).resolve()
        application = application_root_for_workspace(install_root).resolve()
        return cwd in {application, application / "orchestrator" / "backend", install_root.resolve(),
                       install_root.resolve() / "orchestrator" / "backend"}
    except (OSError, ValueError, subprocess.TimeoutExpired, SystemExit):
        return False


def orchestrator_status_payload(install_root: Path, *, host: str = "127.0.0.1", port: int = 18000,
                                local_only: bool = False) -> dict[str, object]:
    """Inspect ownership; explicit local lifecycle never targets a configured remote URL.

    Default status includes remote uncertainty so restore cannot mistake an
    unreachable shared-database backend for a stopped process.
    """
    from .engagements import inspect_backend_ownership, BackendInstallRootStatus
    install_root = install_root.expanduser().resolve()
    pid_file = resolve_runtime_state_dir(install_root) / "pids" / "orchestrator.pid"
    receipt: dict[str, object] = {}
    try:
        parsed = json.loads(pid_file.with_suffix(".json").read_text())
        if isinstance(parsed, dict):
            receipt = parsed
    except (OSError, ValueError):
        pass
    pid = _read_pid(pid_file)
    identity = None
    detail = ""
    owned = False
    if pid is not None and pid > 0:
        try:
            identity = _process_identity(pid)
        except SystemExit as exc:
            detail = str(exc)
        owned = bool(identity and receipt.get("pid") == pid and receipt.get("process_identity") == identity
                     and receipt.get("workspace") == str(install_root))
    endpoint = f"http://{'[' + host + ']' if ':' in host else host}:{port}"
    local_endpoint = True
    if owned:
        receipt_port = receipt.get("port", port)
        receipt_host = receipt.get("host", host)
        if (not isinstance(receipt_port, int) or isinstance(receipt_port, bool)
                or not 0 < receipt_port <= 65535 or not isinstance(receipt_host, str) or not receipt_host):
            owned = False
            detail = "backend process receipt has an invalid endpoint; ownership requires inspection"
        else:
            host, port = receipt_host, receipt_port
        endpoint = f"http://{'[' + host + ']' if ':' in host else host}:{port}"
    elif host == "127.0.0.1" and port == 18000:
        from urllib.parse import urlsplit
        import ipaddress
        from .paths import resolve_orchestrator_base_url
        configured_endpoint = resolve_orchestrator_base_url(install_root)
        configured_host, configured_port = host, port
        try:
            parsed = urlsplit(configured_endpoint)
            configured_host = parsed.hostname or host
            configured_port = parsed.port or (443 if parsed.scheme == "https" else 80)
            configured_local = configured_host == "localhost" or ipaddress.ip_address(configured_host).is_loopback
        except ValueError:
            configured_local = False
        if configured_local or not local_only:
            endpoint, host = configured_endpoint, configured_host
            port, local_endpoint = configured_port, configured_local
    port_in_use = _port_in_use(host, port)
    if identity and not receipt and not port_in_use and pid is not None:
        if _listener_application_matches(pid, install_root):
            detail = (f"legacy backend PID {pid} has no process receipt and is not listening; "
                      "wait for startup or inspect and stop that process manually before retrying")
    state = "running" if owned else "unknown" if (port_in_use or not local_endpoint or detail) else "stopped"
    ownership = "owned" if owned else "unknown" if state == "unknown" else "none"
    owner = None
    if identity and receipt.get("process_identity") == identity and receipt.get("workspace") != str(install_root):
        state, ownership = "foreign", "foreign"
        owner = receipt.get("workspace")
        detail = f"process receipt belongs to workspace {owner}; copied receipts cannot authorize lifecycle actions"
    if (port_in_use or not local_endpoint) and not owned:
        observed = inspect_backend_ownership(install_root, base_url=endpoint)
        owner = observed.install_root
        if observed.state == BackendInstallRootStatus.FOREIGN:
            state, ownership = "foreign", "foreign"
            detail = f"endpoint {observed.base_url} serves workspace {owner}; this workspace cannot stop it"
        elif observed.state == BackendInstallRootStatus.VERIFIED and local_endpoint:
            listener = _port_listener_pid(host, port)
            try:
                birth = _process_identity(listener) if listener else None
                if (listener and birth and _listener_application_matches(listener, install_root)
                        and _process_identity(listener) == birth):
                    pid, identity, owned = listener, birth, True
                    state, ownership = "running", "owned"
                    receipt = {}  # An orphan listener does not authorize signaling its entire group.
            except SystemExit as exc:
                detail = str(exc)
        if not owned and not detail:
            if not local_endpoint:
                detail = (f"configured remote endpoint {endpoint} has {observed.state.value} ownership; "
                          "inspect and stop it on its owning host before restoring a shared database. "
                          "Local orchestrator start/stop manage the local listener only")
            else:
                detail = (f"listener at {host}:{port} has no verifiable process receipt; "
                          f"inspect its PID with `lsof -nP -iTCP:{port} -sTCP:LISTEN` or "
                          f"`ss -ltnp 'sport = :{port}'`, verify its workspace, then stop it manually if necessary")
    return {"state": state, "ownership": ownership, "owner_workspace": owner, "detail": detail,
            "pid": pid if owned else None, "process_identity": identity if owned else None,
            "process_group": receipt.get("process_group") if owned else None,
            "pid_file": str(pid_file), "host": host, "port": port,
            "url": endpoint, "port_in_use": port_in_use}


def _already_running_message(pid_file: Path, pid: str, host: str, port: int) -> str:
    return (
        "Orchestrator is already running.\n"
        f"  PID: {pid}\n"
        f"  PID file: {pid_file}\n"
        f"  URL: http://{host}:{port}\n"
        "Use `vigil orchestrator status` or `vigil logs orchestrator` to inspect it.\n"
        "Use `vigil orchestrator restart` to restart it, or `vigil orchestrator stop` to stop it."
    )


def _npm_ci(project_dir: Path) -> None:
    """`npm ci` in ``project_dir``, retrying once against a stale tree.

    `npm ci` wipes `node_modules` before installing, and on macOS that rmdir
    fails with ENOTEMPTY when a previous interrupted install left the
    directory in a half-removed state — the failure then repeats on every
    subsequent run because npm hits the same tree. Removing the tree
    ourselves and retrying clears it; a second failure is a real one.
    """
    first = subprocess.run(["npm", "ci"], cwd=project_dir, stdout=sys.stdout)
    if first.returncode == 0:
        return
    node_modules = project_dir / "node_modules"
    if not node_modules.exists():
        raise subprocess.CalledProcessError(first.returncode, first.args)
    print(f"npm ci failed; clearing {node_modules} and retrying")
    shutil.rmtree(node_modules, ignore_errors=True)
    subprocess.run(["npm", "ci"], cwd=project_dir, check=True, stdout=sys.stdout)


def _build_frontend(install_root: Path) -> None:
    _require_editable_build(install_root)
    frontend_dir = install_root / "orchestrator" / "frontend"
    _npm_ci(frontend_dir)
    subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True, stdout=sys.stdout)
    # Stamp AFTER the build: vite empties `dist/` on the way in, so a stamp
    # written first would not survive. An unstamped build can never be proven
    # current, and would be rebuilt on every launch forever.
    restart_manifest.record_frontend_build(install_root)


def build_frontend(install_root: Path, *, force: bool = False) -> None:
    """Public entrypoint for `vigil orchestrator build`.

    Builds the install-side `orchestrator/frontend/dist/` even when the
    backend was already started without it. Use this when a direct
    `uv run uvicorn ...` launch bypassed `start_orchestrator`'s implicit
    build step and `/` returns 503 with `frontend build not found`. Also
    builds the single-file report template alongside it so
    `report-export` has a template to inject into.
    """
    install_root = application_root_for_workspace(install_root)
    if not _frontend_build_needed(install_root, force=force):
        print(f"frontend already built: {install_root / 'orchestrator' / 'frontend' / 'dist' / 'index.html'}")
    else:
        _build_frontend(install_root)
        print(f"frontend built: {install_root / 'orchestrator' / 'frontend' / 'dist'}")

    report_template = install_root / "orchestrator" / "report" / "dist" / "template.html"
    if not _report_build_needed(install_root, force=force):
        print(f"report already built: {report_template}")
    else:
        _build_report(install_root)
        print(f"report built: {report_template}")


def _build_report(install_root: Path) -> None:
    _require_editable_build(install_root)
    report_dir = install_root / "orchestrator" / "report"
    _npm_ci(report_dir)
    subprocess.run(["npm", "run", "build"], cwd=report_dir, check=True, stdout=sys.stdout)
    restart_manifest.record_report_build(install_root)


def _require_editable_build(application_root: Path) -> None:
    if (application_root / "bundle.json").is_file():
        raise SystemExit(
            "This application release includes prebuilt frontend/report assets. "
            "Upgrade or reinstall Vigil to replace release assets; rebuild only in an editable checkout."
        )


def _report_build_needed(install_root: Path, *, force: bool = False) -> bool:
    """True unless the built template is provably the current inputs' output.

    ``not-packaged`` (an install predating the report template) is nothing to
    build rather than a failure; every other non-``current`` answer — missing,
    unstamped, or content-changed — rebuilds once and stamps.
    """
    if force:
        return True
    state = restart_manifest.report_build_state(install_root)
    return state not in {"current", "not-packaged"}


def _frontend_build_needed(install_root: Path, *, force: bool = False) -> bool:
    """True unless ``dist/`` is provably the current inputs' output.

    Content, never mtime: ``vigil install`` rewrites every managed file
    unconditionally, so the mtime high-water mark this replaced made the next
    ``vigil up`` run a full ``npm run build`` after every single install, for a
    byte-identical frontend.
    """
    if force:
        return True
    return restart_manifest.frontend_build_state(install_root) != "current"


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    _terminate_process_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    _terminate_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _terminate_process_group(process: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        return
    except OSError:
        if sig == signal.SIGTERM:
            process.terminate()
        else:
            process.kill()


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_pid(pid_file: Path) -> int | None:
    try:
        return int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _signal_process_group(pid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pid, sig)
        return
    except ProcessLookupError:
        return
    except PermissionError:
        pass
    try:
        os.kill(pid, sig)
    except (OSError, ProcessLookupError):
        pass


def _wait_for_pid_exit(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.05)
    return not _pid_alive(pid)


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        try:
            sock.connect((host, port))
            return True
        except ConnectionRefusedError:
            return False
        except OSError:
            # Timeout or unreachable — for 127.0.0.1 this realistically means
            # the port is free, since the loopback stack does not drop SYNs.
            return False


def _wait_for_port_release(host: str, port: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _port_in_use(host, port):
            return True
        time.sleep(0.1)
    return not _port_in_use(host, port)


def _port_listener_pid(host: str, port: int) -> int | None:
    """Identify one listener owner through lsof or Linux socket-inode ownership."""
    address = f"[{host}]" if ":" in host else host
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP@{address}:{port}", "-sTCP:LISTEN", "-t"],
            text=True, capture_output=True, check=False, timeout=2,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _proc_listener_pid(host, port)
    owners = {int(line.strip()) for line in result.stdout.splitlines()
              if line.strip().isdigit() and int(line.strip()) > 0}
    if owners:
        return next(iter(owners)) if len(owners) == 1 else None
    return _proc_listener_pid(host, port)


def _proc_listener_pid(host: str, port: int) -> int | None:
    """Resolve LISTEN sockets to a unique visible PID in this network namespace.

    This only supplies a candidate: the caller still verifies backend endpoint
    ownership, application identity and process birth before signaling it.
    """
    import ipaddress
    try:
        targets = ({ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
                   if host == "localhost" else {ipaddress.ip_address(host)})
    except ValueError:
        return None
    inodes = set()
    for table in ("tcp", "tcp6"):
        try:
            rows = (_PROC_ROOT / "net" / table).read_text().splitlines()
        except OSError:
            continue
        for row in rows:
            fields = row.split()
            if len(fields) < 10 or fields[3] != "0A":
                continue
            try:
                encoded, encoded_port = fields[1].split(":")
                if int(encoded_port, 16) != port:
                    continue
                raw = b"".join(int(encoded[index:index + 8], 16).to_bytes(4, sys.byteorder)
                               for index in range(0, len(encoded), 8))
                bound = ipaddress.ip_address(raw)
                # A tcp6 wildcard may accept IPv4 (IPV6_V6ONLY is not in
                # this table). Keep it as a candidate; multiple owners refuse
                # recovery, and the caller must verify the responding backend.
                mapped = bound.ipv4_mapped if isinstance(bound, ipaddress.IPv6Address) else None
                wildcard = bound.is_unspecified and (
                    bound.version == 6 or any(target.version == bound.version for target in targets)
                )
                if bound in targets or mapped in targets or wildcard:
                    inodes.add(fields[9])
            except (ValueError, OverflowError):
                continue
    if not inodes:
        return None
    owners = set()
    try:
        processes = list(_PROC_ROOT.iterdir())
    except OSError:
        return None
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            descriptors = list((process / "fd").iterdir())
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except OSError:
                continue
            if target.startswith("socket:[") and target[8:-1] in inodes:
                owners.add(int(process.name))
                break
        if len(owners) > 1:
            return None
    return next(iter(owners)) if owners else None


def _check_port_available(host: str, port: int) -> None:
    """Pre-flight: refuse to spawn uvicorn if something is already on host:port.

    The previous implementation relied on uvicorn discovering EADDRINUSE on
    bind and crashing seconds later. With the pid file already written, the
    operator would see `vigil orchestrator status` flip running → stopped
    and have no obvious cue that the port was the problem. Catching it here
    turns that into a clear SystemExit naming the holding PID.
    """
    if not _port_in_use(host, port):
        return
    holder = _port_listener_pid(host, port)
    holder_str = f" (PID {holder})" if holder is not None else ""
    raise SystemExit(
        f"Cannot start orchestrator: {host}:{port} is already in use{holder_str}.\n"
        f"Inspect with `lsof -nP -iTCP:{port} -sTCP:LISTEN`, stop the holder, then retry.\n"
        "Inspect the listener's owning workspace before stopping it."
    )


def _wait_for_health(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None,
                     timeout: float | None = None) -> bool:
    url = f"http://{'[' + host + ']' if ':' in host else host}:{port}/healthz"
    return _wait_for_http_200(
        url, process=process, timeout=_startup_timeout_seconds() if timeout is None else timeout
    )


def _wait_for_readiness(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None,
                        timeout: float | None = None) -> bool:
    url = f"http://{'[' + host + ']' if ':' in host else host}:{port}/readyz"
    return _wait_for_http_200(
        url, process=process, timeout=_startup_timeout_seconds() if timeout is None else timeout
    )


def _wait_for_http_200(
    url: str,
    *,
    process: subprocess.Popen[bytes] | None = None,
    timeout: float,
) -> bool:
    deadline = time.monotonic() + timeout
    next_notice = deadline - timeout + 15.0
    while True:
        if process is not None and process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            pass
        now = time.monotonic()
        remaining = deadline - now
        if remaining <= 0:
            return False
        if now >= next_notice:
            print(
                term.row("info", "Backend", f"waiting for readiness; {remaining:.0f}s remain. Logs: vigil logs orchestrator", stream=sys.stdout),
                flush=True,
            )
            next_notice = now + 15.0
        time.sleep(min(0.2, remaining))
