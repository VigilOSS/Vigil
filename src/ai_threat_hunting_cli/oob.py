from __future__ import annotations

import base64
import json
import os
import re
import shlex
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import docker

DEFAULT_FRP_HOST = "researcher.example"
DEFAULT_FRP_PORT = 7000
DEFAULT_OOB_DOMAIN = "researcher.example"
DEFAULT_DASHBOARD_URL = "http://127.0.0.1:7500"
DEFAULT_DASHBOARD_USER = "admin"
DEFAULT_DASHBOARD_PASSWORD = "frp-dash-example"
# Server-side resources hardcoded in the OOB profile. Globally unique on frps:
# any other client holding these blocks our registration with port already used /
# router config conflict. Stays in sync with _render_runtime_files() below.
OOB_TCP_REMOTE_PORT = 8443
OOB_UDP_REMOTE_PORT = 53
OOB_ROOT = "/data/oob"


@dataclass(frozen=True, slots=True)
class OobOptions:
    install_root: Path
    frp_host: str = DEFAULT_FRP_HOST
    frp_port: int = DEFAULT_FRP_PORT
    frp_token: str = ""
    oob_domain: str = DEFAULT_OOB_DOMAIN
    container_name: str = "security-research"


def start_oob(options: OobOptions, *, runner: docker.Runner = docker.run_command) -> None:
    _require_runtime(options.container_name, runner=runner)
    if not options.frp_token:
        raise SystemExit("Missing OOB FRP token. Set it with `aith config set oob.frp_token <token>`.")
    _require_runtime_tools(options.container_name, runner=runner)
    _kill_stale_oob_processes(options.container_name, runner=runner)
    _check_oob_resources_free(options, runner=runner)
    _render_runtime_files(options, runner=runner)
    _ensure_tmux_session(
        options.container_name,
        "oob-server",
        f"python3 {OOB_ROOT}/oob_server_watch.py 2>&1 | tee -a {OOB_ROOT}/watch.log",
        runner=runner,
    )
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


def _require_runtime(container_name: str, *, runner: docker.Runner) -> None:
    if not docker.container_running(container_name, runner=runner):
        raise SystemExit("Kali runtime is not running. Start it with `aith runtime start`.")


def _require_runtime_tools(container_name: str, *, runner: docker.Runner) -> None:
    for tool in ("tmux", "frpc", "interactsh-server", "interactsh-client", "dig", "curl", "python3"):
        result = _run_exec(container_name, f"command -v {shlex.quote(tool)} >/dev/null", runner=runner, check=False)
        if result.returncode != 0:
            raise SystemExit(f"OOB runtime tool missing: {tool}")


def _check_oob_resources_free(options: OobOptions, *, runner: docker.Runner) -> None:
    """Pre-flight check: abort if another frpc client owns our OOB resources.

    The OOB profile is single-tenant by design — `remotePort = 53/8443` and
    `customDomains = researcher.example` are globally unique on frps. If
    another client holds them when we register, frps replies with
    `port already used` / `router config conflict` forever (frpc retries
    silently every 33s with `loginFailExit = false`).

    Best-effort: needs the frps dashboard reachable, typically via a port-forward
    started by `infra/frp/dashboard.sh`. Skips with a warning if unreachable.
    """
    url = (os.environ.get("AI_THREAT_HUNTING_FRP_DASHBOARD_URL") or "").strip() or DEFAULT_DASHBOARD_URL
    user = os.environ.get("AI_THREAT_HUNTING_FRP_DASHBOARD_USER") or DEFAULT_DASHBOARD_USER
    password = os.environ.get("AI_THREAT_HUNTING_FRP_DASHBOARD_PASSWORD") or DEFAULT_DASHBOARD_PASSWORD

    own_prefix = _own_frpc_prefix(options.container_name, runner=runner)

    conflicts: list[str] = []
    for proxy_type, predicate in (
        ("udp", lambda p: p.get("conf", {}).get("remotePort") == OOB_UDP_REMOTE_PORT),
        ("tcp", lambda p: p.get("conf", {}).get("remotePort") == OOB_TCP_REMOTE_PORT),
        ("http", lambda p: options.oob_domain in (p.get("conf", {}).get("customDomains") or [])),
    ):
        try:
            data = _frp_dashboard_get(f"{url.rstrip('/')}/api/proxy/{proxy_type}", user, password)
        except _DashboardUnreachable as exc:
            print(f"oob preflight\tdashboard unreachable at {url} ({exc}); skipping conflict check")
            print("oob preflight\trun `infra/frp/dashboard.sh` in another terminal to enable this guard")
            return
        for proxy in data.get("proxies") or []:
            if proxy.get("status") != "online":
                continue
            if proxy.get("conf") is None:
                continue
            name = proxy.get("name") or ""
            if own_prefix and name.startswith(f"{own_prefix}-"):
                continue
            if predicate(proxy):
                conflicts.append(
                    f"  - {proxy_type} proxy {name!r} clientID={proxy.get('clientID')} (status={proxy.get('status')})"
                )

    if not conflicts:
        return

    raise SystemExit(
        "OOB resources are already held by another frpc client:\n"
        + "\n".join(conflicts)
        + "\n\nThe OOB profile is single-tenant: remotePort 53/8443 and "
        f"customDomains {options.oob_domain!r} can only be served by one client at a time.\n"
        "Stop the other `aith oob start` instance, then retry. To inspect:\n"
        f"  curl -s -u {DEFAULT_DASHBOARD_USER}:{DEFAULT_DASHBOARD_PASSWORD} {url}/api/proxy/http | jq\n"
        "(See README §Callback, Listener & Tunnel Handling — TODO: per-tenant OOB.)"
    )


class _DashboardUnreachable(Exception):
    pass


def _frp_dashboard_get(url: str, user: str, password: str) -> dict:
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    request = urllib.request.Request(url, headers={"Authorization": f"Basic {auth}"})
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise _DashboardUnreachable(f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise _DashboardUnreachable(str(exc.reason)) from exc
    except (TimeoutError, ConnectionError, OSError) as exc:
        raise _DashboardUnreachable(str(exc)) from exc
    except json.JSONDecodeError as exc:
        raise _DashboardUnreachable(f"non-JSON response: {exc}") from exc


def _own_frpc_prefix(container_name: str, *, runner: docker.Runner) -> str:
    """Mirrors the prefix derivation in `_render_runtime_files`."""
    result = _run_exec(container_name, "hostname", runner=runner, check=False)
    if result.returncode != 0:
        return ""
    return result.stdout.split(".", 1)[0].strip().lower()[:8]


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
