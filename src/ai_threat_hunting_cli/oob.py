from __future__ import annotations

import json
import re
import shlex
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from . import docker

DEFAULT_FRP_HOST = "oob-relay.example.com"
DEFAULT_FRP_PORT = 7000
DEFAULT_OOB_DOMAIN = "oob.example.com"
# Server-side resources hardcoded in the OOB profile. Globally unique on frps:
# any other client holding these blocks our registration with port already used /
# router config conflict. Stays in sync with _render_runtime_files() below.
OOB_TCP_REMOTE_PORT = 8443
OOB_UDP_REMOTE_PORT = 53
OOB_ROOT = "/data/oob"
FRPC_READY_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True, slots=True)
class OobOptions:
    install_root: Path
    frp_host: str = DEFAULT_FRP_HOST
    frp_port: int = DEFAULT_FRP_PORT
    frp_token: str = ""
    oob_domain: str = DEFAULT_OOB_DOMAIN
    container_name: str = "security-research"


def start_oob(
    options: OobOptions,
    *,
    runner: docker.Runner = docker.run_command,
    frpc_ready_timeout: float = FRPC_READY_TIMEOUT_SECONDS,
) -> None:
    _require_runtime(options.container_name, runner=runner)
    if not options.frp_token:
        raise SystemExit("Missing OOB FRP token. Set it with `aith config set oob.frp_token <token>`.")
    _require_runtime_tools(options.container_name, runner=runner)
    _kill_stale_oob_processes(options.container_name, runner=runner)
    _render_runtime_files(options, runner=runner)
    _ensure_tmux_session(
        options.container_name,
        "oob-server",
        f"python3 {OOB_ROOT}/oob_server_watch.py 2>&1 | tee -a {OOB_ROOT}/watch.log",
        runner=runner,
    )
    _reset_frpc_log(options.container_name, runner=runner)
    frpc_cmd = (
        f"while true; do "
        f"frpc -c {OOB_ROOT}/frpc.toml 2>&1 | tee {OOB_ROOT}/frpc.log; "
        f"echo '[frpc] exited, restarting in 30s...' >> {OOB_ROOT}/frpc.log; "
        f"sleep 30; done"
    )
    _ensure_tmux_session(
        options.container_name,
        "frpc",
        frpc_cmd,
        runner=runner,
    )
    if frpc_ready_timeout > 0:
        _check_frpc_for_conflicts(options, runner=runner, timeout=frpc_ready_timeout)


def stop_oob(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> None:
    for session in ("frpc", "oob-server"):
        _run_exec(container_name, f"tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true", runner=runner, check=False)
    _kill_stale_oob_processes(container_name, runner=runner)


def oob_status(
    container_name: str = "security-research",
    *,
    oob_domain: str | None = None,
    runner: docker.Runner = docker.run_command,
) -> dict[str, object]:
    if not docker.container_running(container_name, runner=runner):
        return {"state": "stopped", "server": False, "frpc": False, "clients": [], "domain": oob_domain}
    server = _tmux_has_session(container_name, "oob-server", runner=runner)
    frpc = _tmux_has_session(container_name, "frpc", runner=runner)
    clients = list_oob_clients(container_name, runner=runner)
    if server and frpc:
        state = "running"
    elif server or frpc or clients:
        state = "partial"
    else:
        state = "stopped"
    return {
        "state": state,
        "server": server,
        "frpc": frpc,
        "clients": clients,
        "domain": oob_domain,
    }


def start_oob_client(
    options: OobOptions,
    name: str,
    *,
    engagement: str | None = None,
    agent: str | None = None,
    runner: docker.Runner = docker.run_command,
) -> None:
    _require_runtime(options.container_name, runner=runner)
    client_name = sanitize_name(name)
    session = f"oob-client-{client_name}"
    _run_exec(options.container_name, f"mkdir -p {OOB_ROOT}/clients", runner=runner)
    metadata = {"name": client_name, "engagement": engagement, "agent": agent, "server": options.oob_domain}
    _write_runtime_file(options.container_name, f"{OOB_ROOT}/clients/{client_name}.json", json.dumps(metadata, indent=2) + "\n", runner=runner)
    log_path = f"{OOB_ROOT}/clients/{client_name}.log"
    session_file = f"{OOB_ROOT}/clients/{client_name}.session"
    inner = (
        f"interactsh-client -server {shlex.quote(options.oob_domain)} "
        f"-session-file {shlex.quote(session_file)} -v -poll-interval 5 "
        f"2>&1 | tee -a {shlex.quote(log_path)}"
    )
    command = f"while true; do {inner}; echo '[oob-client] exited, retrying in 10s...' | tee -a {shlex.quote(log_path)}; sleep 10; done"
    _ensure_tmux_session(options.container_name, session, command, runner=runner)


def stop_oob_client(name: str, container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> None:
    client_name = sanitize_name(name)
    _run_exec(container_name, f"tmux kill-session -t oob-client-{shlex.quote(client_name)} 2>/dev/null || true", runner=runner, check=False)


def list_oob_clients(container_name: str = "security-research", *, runner: docker.Runner = docker.run_command) -> list[str]:
    live: set[str] = set()
    result = _run_exec(container_name, "tmux list-sessions -F '#S' 2>/dev/null | sed -n 's/^oob-client-//p'", runner=runner, check=False)
    if result.returncode == 0:
        live = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    configured: set[str] = set()
    cfg_result = _run_exec(
        container_name,
        f"ls {OOB_ROOT}/clients/*.json 2>/dev/null | xargs -I{{}} basename {{}} .json",
        runner=runner, check=False,
    )
    if cfg_result.returncode == 0:
        configured = {line.strip() for line in cfg_result.stdout.splitlines() if line.strip()}
    return sorted(live | configured)


def test_oob(options: OobOptions, *, runner: docker.Runner = docker.run_command) -> None:
    marker = "aith-test"
    command = (
        f"dig +short {marker}.{shlex.quote(options.oob_domain)} @8.8.8.8 >/dev/null 2>&1 || true; "
        f"curl -fsS --max-time 5 http://{marker}.{shlex.quote(options.oob_domain)}/ >/dev/null 2>&1 || true; "
        f"tail -n 40 {OOB_ROOT}/server.log {OOB_ROOT}/clients/*.log 2>/dev/null || true"
    )
    result = _run_exec(options.container_name, command, runner=runner, check=False)
    print(result.stdout, end="")


def sanitize_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-")
    if not cleaned:
        raise SystemExit("OOB client name cannot be empty")
    return cleaned[:80]


def _kill_stale_oob_processes(container_name: str, *, runner: docker.Runner) -> None:
    """Kill leftover interactsh-server and frpc processes before (re)starting."""
    for proc in ("interactsh-server", "frpc"):
        _run_exec(container_name, f"pkill -f {shlex.quote(proc)} 2>/dev/null || true", runner=runner, check=False)


def _reset_frpc_log(container_name: str, *, runner: docker.Runner) -> None:
    _run_exec(container_name, f"mkdir -p {OOB_ROOT} && : > {OOB_ROOT}/frpc.log", runner=runner)


def _require_runtime(container_name: str, *, runner: docker.Runner) -> None:
    if not docker.container_running(container_name, runner=runner):
        raise SystemExit("Kali runtime is not running. Start it with `aith runtime start`.")


def _require_runtime_tools(container_name: str, *, runner: docker.Runner) -> None:
    for tool in ("tmux", "frpc", "interactsh-server", "interactsh-client", "dig", "curl", "python3"):
        result = _run_exec(container_name, f"command -v {shlex.quote(tool)} >/dev/null", runner=runner, check=False)
        if result.returncode != 0:
            raise SystemExit(f"OOB runtime tool missing: {tool}")


_FRPC_CONFLICT_PATTERNS = (
    "port already used",
    "router config conflict",
    "proxy name [",
)
_FRPC_SUCCESS_PATTERNS = (
    "start proxy success",
    "new proxy [",
)
_FRPC_EXPECTED_PROXY_LABELS = frozenset(("dns", "http", "reverse"))
_FRPC_PROXY_LABEL_HINTS = {
    "dns": "*-oob-dns",
    "http": "*-oob",
    "reverse": "*-oob-rev",
}


def _check_frpc_for_conflicts(
    options: OobOptions,
    *,
    runner: docker.Runner,
    timeout: float,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Post-flight: confirm frpc registered our proxies, surface conflicts loudly.

    The OOB profile is single-tenant — `remotePort = 53/8443` and
    `customDomains = oob.example.com` are globally unique on frps. If
    another client holds them when we register, frps rejects our registration
    and frpc retries silently every ~30s (`loginFailExit = false`). Polling
    `/data/oob/frpc.log` for the success/conflict lines lets us turn that
    silent loop into a clear SystemExit without needing any extra channel
    beyond the frp control connection we already have.
    """
    deadline = time.monotonic() + timeout
    last_log = ""
    while time.monotonic() < deadline:
        result = _run_exec(
            options.container_name,
            f"tail -n 200 {OOB_ROOT}/frpc.log 2>/dev/null || true",
            runner=runner,
            check=False,
        )
        last_log = result.stdout or ""
        conflicts = [
            line.strip()
            for line in last_log.splitlines()
            if any(pat in line for pat in _FRPC_CONFLICT_PATTERNS)
        ]
        if conflicts:
            _kill_oob_sessions(options.container_name, runner=runner)
            raise SystemExit(
                "OOB resources are already held by another frpc client. frps reported:\n"
                + "\n".join(f"  {line}" for line in conflicts[:10])
                + f"\n\nThe OOB profile is single-tenant: remotePort {OOB_UDP_REMOTE_PORT}/{OOB_TCP_REMOTE_PORT} and "
                + f"customDomains {options.oob_domain!r} can only be served by one client at a time.\n"
                "Stop the other `aith oob start` instance, then retry. To inspect:\n"
                f"  docker exec {options.container_name} tail -n 200 {OOB_ROOT}/frpc.log\n"
                "(See README §Callback, Listener & Tunnel Handling — TODO: per-tenant OOB.)"
            )
        registered = _frpc_registered_proxy_labels(last_log)
        if registered >= _FRPC_EXPECTED_PROXY_LABELS:
            return
        sleep(1.0)
    missing = sorted(_FRPC_EXPECTED_PROXY_LABELS - _frpc_registered_proxy_labels(last_log))
    missing_hint = ", ".join(_FRPC_PROXY_LABEL_HINTS[label] for label in missing)
    target_hint = f" for {missing_hint}" if missing_hint else ""
    print(
        f"oob check\tfrpc did not confirm proxy registration{target_hint} within {int(timeout)}s; "
        f"if callbacks do not land, run `docker exec {options.container_name} tail -n 200 {OOB_ROOT}/frpc.log`"
    )


def _frpc_registered_proxy_labels(log_text: str) -> set[str]:
    labels: set[str] = set()
    for line in log_text.splitlines():
        if not any(pat in line for pat in _FRPC_SUCCESS_PATTERNS):
            continue
        for token in re.findall(r"\[([^\]]+)\]", line):
            if token.endswith("-oob-dns"):
                labels.add("dns")
            elif token.endswith("-oob-rev"):
                labels.add("reverse")
            elif token.endswith("-oob"):
                labels.add("http")
    return labels


def _kill_oob_sessions(container_name: str, *, runner: docker.Runner) -> None:
    for session in ("frpc", "oob-server"):
        _run_exec(
            container_name,
            f"tmux kill-session -t {shlex.quote(session)} 2>/dev/null || true",
            runner=runner,
            check=False,
        )
    _kill_stale_oob_processes(container_name, runner=runner)


def _render_runtime_files(options: OobOptions, *, runner: docker.Runner) -> None:
    _run_exec(options.container_name, f"mkdir -p {OOB_ROOT}/clients", runner=runner)
    render = f"""python3 - <<'PY'
from pathlib import Path
import socket

root = Path({OOB_ROOT!r})
root.mkdir(parents=True, exist_ok=True)
container_ip = socket.gethostbyname(socket.gethostname())
prefix = socket.gethostname().split(".")[0].lower()[:8]
Path({f"{OOB_ROOT}/frpc.toml"!r}).write_text(f'''serverAddr = {options.frp_host!r}
serverPort = {options.frp_port}
auth.token = {options.frp_token!r}
loginFailExit = false
transport.heartbeatInterval = 10
transport.heartbeatTimeout = 30

[[proxies]]
name = "{{prefix}}-oob-dns"
type = "udp"
localIP = "{{container_ip}}"
localPort = 53
remotePort = 53

[[proxies]]
name = "{{prefix}}-oob"
type = "http"
localIP = "{{container_ip}}"
localPort = 80
customDomains = [{options.oob_domain!r}, "*.{options.oob_domain}"]

[[proxies]]
name = "{{prefix}}-oob-rev"
type = "tcp"
localIP = "{{container_ip}}"
localPort = 4444
remotePort = 8443
''', encoding='utf-8')
PY"""
    _run_exec(options.container_name, render, runner=runner)
    _write_runtime_file(options.container_name, f"{OOB_ROOT}/oob_server_watch.py", _server_watch_source(options), runner=runner)


def _server_watch_source(options: OobOptions) -> str:
    return f"""from __future__ import annotations

import subprocess
import time

DOMAIN = {options.oob_domain!r}
FRP_HOST = {options.frp_host!r}
CHECK_INTERVAL = 60
current_ip = ""
process = None

while True:
    lookup = subprocess.run(["dig", "+short", FRP_HOST, "A"], text=True, capture_output=True, check=False)
    new_ip = next((line.strip() for line in lookup.stdout.splitlines() if line.strip()), "")
    if not new_ip:
        print(f"[oob-watch] DNS lookup failed for {{FRP_HOST}}", flush=True)
        time.sleep(CHECK_INTERVAL)
        continue
    if new_ip != current_ip or process is None or process.poll() is not None:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        subprocess.run(["pkill", "-f", "interactsh-server"], check=False)
        current_ip = new_ip
        log = open("/data/oob/server.log", "ab", buffering=0)
        process = subprocess.Popen(
            ["interactsh-server", "-d", DOMAIN, "-listen-ip", "0.0.0.0", "-ip", current_ip, "-skip-acme", "-v", "-debug"],
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        print(f"[oob-watch] interactsh-server started pid={{process.pid}} ip={{current_ip}}", flush=True)
    time.sleep(CHECK_INTERVAL)
"""


def _write_runtime_file(container_name: str, path: str, contents: str, *, runner: docker.Runner) -> None:
    script = (
        "python3 - <<'PY'\n"
        "from pathlib import Path\n"
        f"path = Path({path!r})\n"
        "path.parent.mkdir(parents=True, exist_ok=True)\n"
        f"path.write_text({contents!r}, encoding='utf-8')\n"
        "PY"
    )
    _run_exec(container_name, script, runner=runner)


def _tmux_has_session(container_name: str, session: str, *, runner: docker.Runner) -> bool:
    return _run_exec(container_name, f"tmux has-session -t {shlex.quote(session)}", runner=runner, check=False).returncode == 0


def _ensure_tmux_session(container_name: str, session: str, command: str, *, runner: docker.Runner) -> None:
    quoted_session = shlex.quote(session)
    quoted_command = shlex.quote(command)
    shell = (
        f"tmux has-session -t {quoted_session} 2>/dev/null "
        f"|| tmux new-session -d -s {quoted_session} {quoted_command} "
        f"|| tmux has-session -t {quoted_session} 2>/dev/null"
    )
    _run_exec(container_name, shell, runner=runner)


def _run_exec(container_name: str, command: str, *, runner: docker.Runner, check: bool = True) -> docker.DockerResult:
    argv = ["docker", "exec", container_name, "sh", "-lc", command]
    result = runner(argv)
    if check:
        docker.require_success(result, argv)
    return result
