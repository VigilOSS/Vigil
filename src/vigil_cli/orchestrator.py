from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class OrchestratorOptions:
    install_root: Path
    host: str = "127.0.0.1"
    port: int = 18000
    build: bool = False
    foreground: bool = False
    allow_existing: bool = False


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
        "uvicorn",
        "app.main:app",
        "--host",
        options.host,
        "--port",
        str(options.port),
    ]
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


def _build_frontend(install_root: Path) -> None:
    frontend_dir = install_root / "orchestrator" / "frontend"
    subprocess.run(["npm", "ci"], cwd=frontend_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True)


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
    subprocess.run(["npm", "ci"], cwd=report_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=report_dir, check=True)


def _report_build_needed(install_root: Path, *, force: bool = False) -> bool:
    if force:
        return True
    report_dir = install_root / "orchestrator" / "report"
    # The package directory may not exist on an install that predates the
    # report template — treat that as "nothing to build" rather than failing
    # the orchestrator launch.
    if not report_dir.is_dir():
        return False
    report_dist = report_dir / "dist" / "template.html"
    if not report_dist.exists():
        return True
    latest_input = _latest_report_input_mtime(report_dir)
    return latest_input is not None and latest_input > report_dist.stat().st_mtime


def _latest_report_input_mtime(report_dir: Path) -> float | None:
    candidates = [
        report_dir / "package.json",
        report_dir / "package-lock.json",
        report_dir / "index.html",
        report_dir / "vite.config.ts",
        report_dir / "tsconfig.json",
    ]
    latest: float | None = None
    for path in candidates:
        if path.is_file():
            latest = max(latest or 0, path.stat().st_mtime)
    src_dir = report_dir / "src"
    if src_dir.is_dir():
        for path in src_dir.rglob("*"):
            if path.is_file():
                latest = max(latest or 0, path.stat().st_mtime)
    return latest


def _frontend_build_needed(install_root: Path, *, force: bool = False) -> bool:
    if force:
        return True
    frontend_dir = install_root / "orchestrator" / "frontend"
    frontend_dist = frontend_dir / "dist" / "index.html"
    if not frontend_dist.exists():
        return True
    latest_input = _latest_frontend_input_mtime(frontend_dir)
    return latest_input is not None and latest_input > frontend_dist.stat().st_mtime


def _latest_frontend_input_mtime(frontend_dir: Path) -> float | None:
    candidates = [
        frontend_dir / "package.json",
        frontend_dir / "package-lock.json",
        frontend_dir / "index.html",
        frontend_dir / "vite.config.ts",
        frontend_dir / "vite.config.js",
        frontend_dir / "tsconfig.json",
        frontend_dir / "tsconfig.app.json",
        frontend_dir / "tsconfig.node.json",
    ]
    latest: float | None = None
    for path in candidates:
        if path.is_file():
            latest = max(latest or 0, path.stat().st_mtime)
    src_dir = frontend_dir / "src"
    if src_dir.is_dir():
        for path in src_dir.rglob("*"):
            if path.is_file():
                latest = max(latest or 0, path.stat().st_mtime)
    return latest


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
    return _wait_for_http_200(url, process=process)


def _wait_for_readiness(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None) -> bool:
    url = f"http://{host}:{port}/readyz"
    return _wait_for_http_200(url, process=process)


def _wait_for_http_200(url: str, *, process: subprocess.Popen[bytes] | None = None) -> bool:
    for _ in range(30):
        if process is not None and process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return True
        except OSError:
            time.sleep(0.2)
    return False
