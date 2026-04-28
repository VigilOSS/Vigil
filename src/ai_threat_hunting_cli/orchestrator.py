from __future__ import annotations

import os
import signal
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
        _build_frontend(install_root)

    if _pid_running(pid_file):
        pid = pid_file.read_text(encoding="utf-8").strip()
        if options.allow_existing:
            print(f"orchestrator\talready running\tpid={pid}")
            return
        raise SystemExit(_already_running_message(pid_file, pid, options.host, options.port))

    env = {
        **os.environ,
        "AI_THREAT_HUNTING_INSTALL_DIR": str(install_root),
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
    with log_file.open("ab") as log:
        process = subprocess.Popen(argv, cwd=install_root, env=env, stdout=log, stderr=subprocess.STDOUT)
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if not _wait_for_health(options.host, options.port, process=process):
        _terminate_process(process)
        pid_file.unlink(missing_ok=True)
        raise SystemExit(f"Orchestrator did not become healthy on http://{options.host}:{options.port}/healthz")


def stop_orchestrator(install_root: Path) -> None:
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not _pid_alive(pid):
                break
            time.sleep(0.1)
    except (OSError, ValueError):
        pass
    pid_file.unlink(missing_ok=True)


def orchestrator_status(install_root: Path) -> str:
    pid_file = install_root / ".runtime-data" / "pids" / "orchestrator.pid"
    return "running" if _pid_running(pid_file) else "stopped"


def _already_running_message(pid_file: Path, pid: str, host: str, port: int) -> str:
    return (
        "Orchestrator is already running.\n"
        f"  PID: {pid}\n"
        f"  PID file: {pid_file}\n"
        f"  URL: http://{host}:{port}\n"
        "Use `aith orchestrator status` or `aith logs orchestrator` to inspect it.\n"
        "Use `aith orchestrator restart` to restart it, or `aith orchestrator stop` to stop it."
    )


def _build_frontend(install_root: Path) -> None:
    frontend_dir = install_root / "orchestrator" / "frontend"
    subprocess.run(["npm", "install"], cwd=frontend_dir, check=True)
    subprocess.run(["npm", "run", "build"], cwd=frontend_dir, check=True)


def build_frontend(install_root: Path, *, force: bool = False) -> None:
    """Public entrypoint for `aith orchestrator build`.

    Builds the install-side `orchestrator/frontend/dist/` even when the
    backend was already started without it. Use this when a direct
    `uv run uvicorn ...` launch bypassed `start_orchestrator`'s implicit
    build step and `/` returns 503 with `frontend build not found`.
    """
    install_root = install_root.expanduser().resolve()
    if not _frontend_build_needed(install_root, force=force):
        print(f"frontend already built: {install_root / 'orchestrator' / 'frontend' / 'dist' / 'index.html'}")
        return
    _build_frontend(install_root)
    print(f"frontend built: {install_root / 'orchestrator' / 'frontend' / 'dist'}")


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
    process.terminate()
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


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


def _wait_for_health(host: str, port: int, *, process: subprocess.Popen[bytes] | None = None) -> bool:
    url = f"http://{host}:{port}/healthz"
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
