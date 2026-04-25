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


def start_orchestrator(options: OrchestratorOptions) -> None:
    install_root = options.install_root.expanduser().resolve()
    runtime_dir = install_root / ".runtime-data"
    pid_file = runtime_dir / "pids" / "orchestrator.pid"
    log_file = runtime_dir / "logs" / "orchestrator.log"
    runtime_dir.joinpath("pids").mkdir(parents=True, exist_ok=True)
    runtime_dir.joinpath("logs").mkdir(parents=True, exist_ok=True)

    if _pid_running(pid_file):
        print(f"orchestrator already running: pid {pid_file.read_text(encoding='utf-8').strip()}")
        return

    frontend_dist = install_root / "orchestrator" / "frontend" / "dist" / "index.html"
    if options.build or not frontend_dist.exists():
        subprocess.run(["npm", "install"], cwd=install_root / "orchestrator" / "frontend", check=True)
        subprocess.run(["npm", "run", "build"], cwd=install_root / "orchestrator" / "frontend", check=True)

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
