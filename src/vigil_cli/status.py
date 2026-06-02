from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import docker
from .backup import latest_backup
from .config import get_config_value
from .engagements import list_engagements
from .oob import DEFAULT_OOB_DOMAIN, oob_status
from .orchestrator import orchestrator_status
from .paths import engagements_root, resolve_orchestrator_base_url
from .runtime import runtime_mounts_ok, runtime_resource_state, runtime_status


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str = ""


def collect_status(install_root: Path, *, runner: docker.Runner = docker.run_command) -> dict[str, object]:
    install_root = install_root.expanduser().resolve()
    rows = list_engagements(install_root)
    # C36: surface legacy engagement_type=both engagements that predate
    # dual-track phase tracking. They are not broken — they just have no
    # `code_phase` field, which makes `vigil assess transition-phase --track
    # code` confusing. `vigil engagement migrate-scope` sets the default.
    from .engagements import _both_engagements_missing_code_phase
    legacy_both_missing_code_phase = [
        eng_dir.name for eng_dir in _both_engagements_missing_code_phase(install_root)
    ]
    runtime_state = runtime_status(runner=runner)
    mitm_running = docker.container_running("vigil-proxy", runner=runner)
    backup = latest_backup(install_root)
    oob_token_configured = bool(os.environ.get("VIGIL_FRP_TOKEN") or get_config_value("oob.frp_token"))
    oob_domain = (
        os.environ.get("VIGIL_OOB_DOMAIN")
        or get_config_value("oob.domain", DEFAULT_OOB_DOMAIN)
        or DEFAULT_OOB_DOMAIN
    )
    return {
        "install_root": str(install_root),
        "install_exists": install_root.exists(),
        "engagement_count": len(rows),
        "orchestrator": {
            "state": orchestrator_status(install_root),
            "base_url": resolve_orchestrator_base_url(install_root),
            **(_orchestrator_readyz_bundle(install_root)),
        },
        "runtime": {
            "state": runtime_state,
            "image_exists": docker.image_exists("vigil:latest", runner=runner),
            "mounts_ok": runtime_mounts_ok(install_root, runner=runner) if runtime_state == "running" else None,
            "resources": runtime_resource_state(runner=runner),
        },
        "mitmproxy": {
            "state": "running" if mitm_running else "stopped",
            "image_exists": docker.image_exists("vigil-proxy:latest", runner=runner),
            "ca_volume": docker.volume_exists("mitmproxy-ca", runner=runner),
        },
        "oob": oob_status(oob_domain=oob_domain, runner=runner) | {"frp_token_configured": oob_token_configured},
        "backup": {
            "latest": str(backup.path) if backup else None,
            "modified_at": backup.modified_at if backup else None,
        },
        "legacy_both_missing_code_phase": legacy_both_missing_code_phase,
    }


def print_status(status: dict[str, object], *, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(status, indent=2))
        return
    print(f"install\t{status['install_root']}")
    orchestrator_blk = status["orchestrator"]  # type: ignore[index]
    runtime = status["runtime"]  # type: ignore[index]
    mitmproxy = status["mitmproxy"]  # type: ignore[index]
    oob = status["oob"]  # type: ignore[index]
    backup = status["backup"]  # type: ignore[index]
    readiness = orchestrator_blk.get("readiness") if isinstance(orchestrator_blk, dict) else None
    ready_bits = ""
    if isinstance(readiness, dict):
        if readiness.get("reachable"):
            ready_bits = f"\treadyz_status={readiness.get('status')}\thttp={readiness.get('http_status')}"
        else:
            ready_bits = "\treadyz=unreachable"
    print(
        f"orchestrator\t{orchestrator_blk['state']}\thealthy={orchestrator_blk['healthy']}{ready_bits}"  # type: ignore[index]
    )
    print(f"runtime\t{runtime['state']}\tmounts_ok={runtime['mounts_ok']}")  # type: ignore[index]
    resources = runtime.get("resources") if isinstance(runtime, dict) else None  # type: ignore[union-attr]
    if isinstance(resources, dict):
        configured = resources.get("configured") or {}
        live = resources.get("live") or {}
        configured_str = (
            f"memory={configured.get('memory_gb', '?')}g cpus={configured.get('cpus', '?')} "
            f"pids={configured.get('pids_limit', '?')} shm={configured.get('shm_size', '?')}"
        )
        live_str = ""
        if isinstance(live, dict) and live:
            live_str = (
                f"\tlive=memory.max={live.get('memory_max', '?')} "
                f"cpu.max={live.get('cpu_max', '?')} pids.max={live.get('pids_max', '?')}"
            )
        print(f"runtime-tier\t{configured_str}{live_str}")
    print(f"mitmproxy\t{mitmproxy['state']}\tca_volume={mitmproxy['ca_volume']}")  # type: ignore[index]
    print(f"oob\t{oob['state']}\tclients={len(oob['clients'])}\tdomain={oob.get('domain') or '-'}")  # type: ignore[index]
    print(f"backup\t{backup['latest'] or '-'}")  # type: ignore[index]
    legacy_keys = status.get("legacy_both_missing_code_phase") or []
    if isinstance(legacy_keys, list) and legacy_keys:
        preview = ", ".join(legacy_keys[:3]) + (" ..." if len(legacy_keys) > 3 else "")
        print(
            f"warn\t{len(legacy_keys)} legacy `engagement_type=both` engagement(s) "
            f"missing `code_phase` ({preview}); run `vigil engagement migrate-scope`"
        )


def collect_doctor_checks(install_root: Path, *, runner: docker.Runner = docker.run_command) -> list[Check]:
    checks: list[Check] = []
    binary_status: dict[str, str] = {}
    for command in ("uv", "docker", "npm", "codex", "claude", "fzf"):
        check = _binary_check(command)
        checks.append(check)
        binary_status[command] = check.status
    install_root = install_root.expanduser().resolve()
    checks.append(Check("install-root", "OK" if install_root.exists() else "MISSING", str(install_root)))
    checks.append(Check("agent-dir", "OK" if (install_root / "agent").is_dir() else "MISSING", str(install_root / "agent")))
    data_dir = install_root / "orchestrator" / "backend" / "data"
    checks.append(Check("backend-data", "OK" if data_dir.is_dir() else "MISSING"))
    checks.append(_database_check(data_dir / "orchestrator.sqlite3"))
    if binary_status.get("docker") == "OK":
        checks.append(Check("docker-daemon", "OK" if docker.daemon_available(runner=runner) else "FAIL"))
        checks.append(Check("runtime-image", "OK" if docker.image_exists("vigil:latest", runner=runner) else "MISSING"))
        checks.append(Check("mitmproxy-image", "OK" if docker.image_exists("vigil-proxy:latest", runner=runner) else "MISSING"))
        if runtime_status(runner=runner) == "running":
            checks.append(Check("runtime-mounts", "OK" if runtime_mounts_ok(install_root, runner=runner) else "FAIL"))
            for tool in ("dtach", "tmux", "frpc", "interactsh-server", "interactsh-client"):
                result = runner(["docker", "exec", "vigil", "sh", "-lc", f"command -v {tool} >/dev/null"])
                checks.append(Check(f"runtime-tool:{tool}", "OK" if result.returncode == 0 else "MISSING"))
    else:
        detail = "docker CLI not found" if binary_status.get("docker") == "MISSING" else "docker --version failed"
        checks.append(Check("docker-daemon", "SKIPPED", detail))
        checks.append(Check("runtime-image", "SKIPPED", detail))
        checks.append(Check("mitmproxy-image", "SKIPPED", detail))
    if orchestrator_status(install_root) == "running":
        healthy, readiness = _orchestrator_readyz_snapshot(install_root)
        detail = ""
        if not healthy:
            if not readiness.get("reachable"):
                detail = "/readyz unreachable"
            elif readiness.get("status") == "not_ready":
                detail = "/readyz reports not_ready (schema/database)"
            elif readiness.get("http_status") is not None:
                detail = f"/readyz HTTP {readiness['http_status']}"
        checks.append(Check("orchestrator-health", "OK" if healthy else "FAIL", detail))
    backup = latest_backup(install_root)
    checks.append(Check("backup-latest", "OK" if backup else "MISSING", str(backup.path) if backup else ""))
    checks.append(_failed_audit_marker_check(install_root))
    checks.append(Check("oob.frp_token", "OK" if os.environ.get("VIGIL_FRP_TOKEN") or get_config_value("oob.frp_token") else "MISSING"))
    return checks


def print_doctor(checks: list[Check]) -> None:
    for check in checks:
        suffix = f"\t{check.detail}" if check.detail else ""
        print(f"{check.status}\t{check.name}{suffix}")


def _binary_check(command: str) -> Check:
    if shutil.which(command) is None:
        return Check(command, "MISSING")
    try:
        result = subprocess.run([command, "--version"], text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return Check(command, "MISSING")
    return Check(command, "OK" if result.returncode == 0 else "FAIL")


def _database_check(path: Path) -> Check:
    if not path.exists():
        return Check("orchestrator-db", "MISSING", str(path))
    try:
        with sqlite3.connect(str(path)) as connection:
            connection.execute("PRAGMA quick_check").fetchone()
    except sqlite3.Error as exc:
        return Check("orchestrator-db", "FAIL", str(exc))
    return Check("orchestrator-db", "OK", str(path))


def _orchestrator_readyz_snapshot(install_root: Path) -> tuple[bool, dict[str, object]]:
    """Fetch ``/readyz`` and return ``(healthy, readiness)``.

    ``healthy`` is True when the endpoint returns HTTP 200 (orchestrator ready for work).
    ``readiness`` surfaces connection reachability, HTTP status, and parsed JSON fields
    when the response body is JSON (mirrors the backend ``/readyz`` payload shape).
    """
    url = f"{resolve_orchestrator_base_url(install_root)}/readyz"
    readiness: dict[str, object] = {
        "reachable": False,
        "http_status": None,
        "status": None,
        "database_connected": None,
        "assessment_schema_ready": None,
        "code_analysis_schema_ready": None,
    }
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            readiness["reachable"] = True
            readiness["http_status"] = response.status
            _merge_readyz_payload(readiness, response.read())
            healthy = response.status == 200
            return healthy, readiness
    except urllib.error.HTTPError as exc:
        readiness["reachable"] = True
        readiness["http_status"] = exc.code
        _merge_readyz_payload(readiness, exc.read())
        return False, readiness
    except OSError:
        return False, readiness


def _merge_readyz_payload(readiness: dict[str, object], raw: bytes) -> None:
    try:
        parsed = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(parsed, dict):
        return
    for key in (
        "status",
        "database_connected",
        "assessment_schema_ready",
        "code_analysis_schema_ready",
    ):
        if key in parsed:
            readiness[key] = parsed[key]


def _orchestrator_readyz_bundle(install_root: Path) -> dict[str, object]:
    healthy, readiness = _orchestrator_readyz_snapshot(install_root)
    return {"healthy": healthy, "readiness": readiness}


def list_failed_audit_markers(engagement_dir: Path) -> list[Path]:
    """Return ``<run_uuid>.failed-audit`` markers under ``scans/kali/`` for one engagement.

    Each marker is written by ``agent/scripts/assess/lib/kali.py`` when the
    pre-exec audit POST to the orchestrator backend fails — the assess CLI
    keeps running the subprocess so the operator sees results, but the audit
    row never lands. A pile of these on a long engagement signals silent
    coverage drift, so any surface that wants to nag the operator (doctor,
    a future cleanup verb) can call this helper.

    Returns the markers sorted newest-first by mtime so callers can show the
    most recent ones without re-sorting. Missing directories return ``[]``.
    """
    marker_dir = engagement_dir / "scans" / "kali"
    if not marker_dir.is_dir():
        return []
    markers = [path for path in marker_dir.glob("*.failed-audit") if path.is_file()]
    markers.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return markers


def _failed_audit_marker_check(install_root: Path) -> Check:
    """Surface orphaned ``<run_uuid>.failed-audit`` markers across engagements.

    The marker is the only on-disk signal that an ``vigil assess kali`` run
    proceeded without a backend audit row. Nothing else inspects them —
    ``sweep-orphans`` ignores them, the runtime never re-tries the POST —
    so they accumulate silently. Surface a WARN with per-engagement counts
    plus the most recent marker paths (capped at 5 per engagement) so the
    operator can decide whether to investigate or sweep.
    """
    root = engagements_root(install_root)
    if not root.is_dir():
        return Check("failed-audit-markers", "OK", "no engagements directory")
    per_engagement: list[tuple[Path, list[Path]]] = []
    total = 0
    for eng_dir in sorted(root.glob("*")):
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        markers = list_failed_audit_markers(eng_dir)
        if markers:
            per_engagement.append((eng_dir, markers))
            total += len(markers)
    if total == 0:
        return Check("failed-audit-markers", "OK", "no orphaned markers")
    parts: list[str] = [f"{total} orphaned marker(s) across {len(per_engagement)} engagement(s)"]
    for eng_dir, markers in per_engagement:
        recent = markers[:5]
        recent_paths = ", ".join(str(path) for path in recent)
        suffix = f" (+{len(markers) - len(recent)} more)" if len(markers) > len(recent) else ""
        parts.append(f"{eng_dir.name}: {len(markers)} — {recent_paths}{suffix}")
    return Check("failed-audit-markers", "WARN", "; ".join(parts))
