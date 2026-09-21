from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import restart_manifest


# E1: opt-in multi-worker uvicorn. Default stays 1 (single-process) so existing
# single-engagement runs are unchanged; raise it only on a dedicated/heavy-tier
# host where many agents call the backend concurrently. ``workers=None`` means
# "resolve from the VIGIL_ORCHESTRATOR_WORKERS env" so callers that don't pass an
# explicit value still pick up the knob.
WORKERS_ENV = "VIGIL_ORCHESTRATOR_WORKERS"
ORCHESTRATOR_START_TIMEOUT_SECONDS = 30.0


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
        print(f"orchestrator\twarn\tignoring non-integer {WORKERS_ENV}={raw!r}; using workers=1")
        return 1
    if value < 1:
        print(f"orchestrator\twarn\t{WORKERS_ENV}={raw!r} < 1; using workers=1")
        return 1
    return value


def start_orchestrator(options: OrchestratorOptions) -> None:
    install_root = options.install_root.expanduser().resolve()
    runtime_dir = install_root / ".runtime-data"
    pid_file = runtime_dir / "pids" / "orchestrator.pid"
    log_file = runtime_dir / "logs" / "orchestrator.log"
    runtime_dir.joinpath("pids").mkdir(parents=True, exist_ok=True)
    runtime_dir.joinpath("logs").mkdir(parents=True, exist_ok=True)

    if _frontend_build_needed(install_root, force=options.build):
        print("frontend\tbuilding")
        _build_frontend(install_root)
    else:
        print("frontend\tcurrent")

    if _report_build_needed(install_root, force=options.build):
        print("report\tbuilding")
        _build_report(install_root)
    else:
        print("report\tcurrent")

    if _pid_running(pid_file):
        pid = pid_file.read_text(encoding="utf-8").strip()
        if options.allow_existing:
            print(f"orchestrator\talready running\tpid={pid}")
            return
        raise SystemExit(_already_running_message(pid_file, pid, options.host, options.port))

    _check_port_available(options.host, options.port)

    env = {
        **os.environ,
        "VIGIL_INSTALL_DIR": str(install_root),
    }
    argv = [
        "uv",
        "run",
        "--directory",
        "orchestrator/backend",
        "python",
        "-m",
        "uvicorn",
        "app.main:app",
        "--host",
        options.host,
        "--port",
        str(options.port),
    ]
    # E1: only append --workers when explicitly raised above the default 1. A bare
    # uvicorn launch is already single-worker, so the default argv is byte-for-byte
    # unchanged — opt-in only.
    workers = _resolve_worker_count(options)
    if workers > 1:
        argv += ["--workers", str(workers)]
        _warn_multiworker_caveats(workers)
    if options.foreground:
        os.chdir(install_root)
        os.execvpe("uv", argv, env)
    print(f"orchestrator\tstarting\thost={options.host}\tport={options.port}")
    with log_file.open("ab") as log, open(os.devnull, "rb") as stdin:
        process = subprocess.Popen(
            argv,
            cwd=install_root,
            env=env,
            stdin=stdin,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if not _wait_for_health(options.host, options.port, process=process):
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        raise SystemExit(
            f"Orchestrator did not become healthy on http://{options.host}:{options.port}/healthz "
            f"(see {log_file} for uvicorn errors)"
        )
    if not _wait_for_readiness(options.host, options.port, process=process):
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        raise SystemExit(
            f"Orchestrator did not become ready on http://{options.host}:{options.port}/readyz "
            f"(see {log_file} for uvicorn errors)"
        )
    print(
        f"orchestrator\trunning\thealthy=True\tpid={process.pid}\t"
        f"url=http://{options.host}:{options.port}"
    )


def _warn_multiworker_caveats(workers: int) -> None:
    """Surface the two known single-process assumptions before going multi-worker.

    These are intentionally WARN-only (the operator opted in via the env/flag),
    but they must be visible because both regress silently otherwise:
      * The live-UI WebSocket broadcaster (app/ws.py) keeps connections in an
        in-process dict, so a write handled by worker A cannot push to a socket
        held by worker B — the dashboard sees only the events from its own worker.
      * The 15-minute backup scheduler (app/services/backup.py) arms a per-process
        timer in each worker's lifespan, so N workers run N concurrent backups
        unless VIGIL_BACKUP_DISABLED is set on all but one.
    Workers greater than one therefore remain an explicitly caveated opt-in
    until cross-process WebSocket fan-out and single-leader backup scheduling
    are implemented.
    """
    print(
        f"orchestrator\twarn\tworkers={workers}: live-UI WebSocket broadcast is per-worker "
        f"(dashboard may miss cross-worker events) and the backup scheduler arms once per "
        f"worker — set VIGIL_BACKUP_DISABLED=1 on all but one to avoid N concurrent backups. "
        f"The API read/write paths are safe under load: reads run in the threadpool and "
        f"async write handlers off-load their SQLite work to it too (anyio.to_thread), so a "
        f"sync write never blocks the event loop, atop SQLite WAL + short-lived per-request "
        f"connections."
    )


def stop_orchestrator(install_root: Path, *, host: str = "127.0.0.1", port: int = 18000) -> None:
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    if not pid_file.exists():
        return
    pid = _read_pid(pid_file)
    pid_file.unlink(missing_ok=True)
    if pid is None or not _pid_alive(pid):
        return
    print(f"orchestrator\tstopping\tpid={pid}")
    _signal_process_group(pid, signal.SIGTERM)
    if not _wait_for_pid_exit(pid, timeout=2.0):
        # SIGTERM was not enough: the worker is hung or its lifespan shutdown
        # is taking longer than the next `start` can tolerate. Escalating to
        # SIGKILL is the only thing that reliably frees port 18000 before the
        # follow-up start races into EADDRINUSE.
        _signal_process_group(pid, signal.SIGKILL)
        _wait_for_pid_exit(pid, timeout=1.0)
    # Even after the parent PID is gone, the kernel may hold the listening
    # socket briefly while child sockets close. Wait for the port to release
    # so `start_orchestrator`'s pre-check (and uvicorn's bind) see a clean
    # state.
    if not _wait_for_port_release(host, port, timeout=3.0):
        holder = _port_listener_pid(host, port)
        holder_str = f" (PID {holder})" if holder is not None else ""
        print(
            f"orchestrator\twarn\t{host}:{port} still held{holder_str} "
            f"after stop; `vigil orchestrator start` will surface the conflict"
        )
        return
    print("orchestrator\tstopped")


def orchestrator_status(install_root: Path) -> str:
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    return "running" if _pid_running(pid_file) else "stopped"


def orchestrator_status_payload(install_root: Path, *, host: str = "127.0.0.1", port: int = 18000) -> dict[str, object]:
    """Structured status — backs `vigil orchestrator status --json`."""
    install_root = install_root.expanduser().resolve()
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    pid = _read_pid(pid_file)
    alive = pid is not None and _pid_alive(pid)
    return {
        "state": "running" if alive else "stopped",
        "pid": pid if alive else None,
        "pid_file": str(pid_file),
        "host": host,
        "port": port,
        "url": f"http://{host}:{port}",
        "port_in_use": _port_in_use(host, port),
    }


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
    first = subprocess.run(["npm", "ci"], cwd=project_dir)
    if first.returncode == 0:
        return
    node_modules = project_dir / "node_modules"
    if not node_modules.exists():
        raise subprocess.CalledProcessError(first.returncode, first.args)
    print(f"npm ci failed; clearing {node_modules} and retrying")
    shutil.rmtree(node_modules, ignore_errors=True)
    subprocess.run(["npm", "ci"], cwd=project_dir, check=True)


def _build_frontend(install_root: Path) -> None:
    frontend_dir = install_root / "orchestrator" / "frontend"
    _npm_ci(frontend_dir)
    subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True)
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
    install_root = install_root.expanduser().resolve()
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
    report_dir = install_root / "orchestrator" / "report"
    _npm_ci(report_dir)
    subprocess.run(["npm", "run", "build"], cwd=report_dir, check=True)
    restart_manifest.record_report_build(install_root)


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


def _pid_running(pid_file: Path) -> bool:
    try:
        return _pid_alive(int(pid_file.read_text(encoding="utf-8").strip()))
    except (OSError, ValueError):
        return False


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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
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
    """Return the PID holding host:port via lsof, or None if lsof isn't usable."""
    try:
        result = subprocess.run(
            ["lsof", "-nP", f"-iTCP@{host}:{port}", "-sTCP:LISTEN", "-t"],
            text=True,
            capture_output=True,
            check=False,
            timeout=2,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    for line in result.stdout.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            return int(candidate)
        except ValueError:
            continue
    return None


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
        "If this is a stale vigil instance, run `vigil orchestrator stop` first."
    )


def _wait_for_health(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None) -> bool:
    url = f"http://{host}:{port}/healthz"
    return _wait_for_http_200(
        url, process=process, timeout=ORCHESTRATOR_START_TIMEOUT_SECONDS
    )


def _wait_for_readiness(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None) -> bool:
    url = f"http://{host}:{port}/readyz"
    return _wait_for_http_200(
        url, process=process, timeout=ORCHESTRATOR_START_TIMEOUT_SECONDS
    )


def _wait_for_http_200(
    url: str,
    *,
    process: subprocess.Popen[bytes] | None = None,
    timeout: float,
) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if process is not None and process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.2, remaining))
