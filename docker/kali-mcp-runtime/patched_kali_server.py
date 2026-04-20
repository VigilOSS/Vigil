#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import logging
import os
import subprocess
import sys
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


UPSTREAM_SERVER_PATH = Path("/usr/share/mcp-kali-server/server.py")

# Target-facing routes require audit headers. Health, metrics, discovery,
# and MCP capability routes stay open so container health checks and tool
# discovery keep working without audit context. The upstream Kali API
# exposes both ``/health`` and ``/api/health`` depending on the probe —
# both must be open or container health probes return 400 and the
# operator sees a confusing "GET /api/health 400" in the log.
AUDIT_OPEN_PATHS = {
    "/health",
    "/api/health",
    "/api/status",
    "/api/version",
    "/metrics",
    "/api/metrics",
    "/favicon.ico",
    "/",
    "/mcp/capabilities",
}

AUDIT_REQUIRED = os.environ.get("KALI_MCP_AUDIT_REQUIRED", "1") != "0"
# This module ONLY runs inside the Kali MCP Docker container. ``127.0.0.1``
# inside the container is the container's own loopback, not the Mac host
# where the orchestrator runs — using it here silently routes every audit
# POST to nothing and returns ECONNREFUSED. Docker Desktop exposes the
# host via ``host.docker.internal`` (automatically resolved on macOS and
# Windows; Linux needs ``--add-host=host.docker.internal:host-gateway``,
# which ``start_kali_mcp_runtime.sh`` sets on recreate). Also normalize
# any loopback values the operator passed through env to the same host
# alias so a stale ``.env`` with ``127.0.0.1:18000`` still works.
# Empty string and missing are both "no value" — without the strip/``or``
# fallback, passing ``-e ORCHESTRATOR_BASE_URL=`` (empty) silently disables
# audit because the URL becomes the empty string instead of the default.
_raw_orchestrator_url = (
    os.environ.get("ORCHESTRATOR_BASE_URL", "").strip()
    or "http://host.docker.internal:18000"
).rstrip("/")
ORCHESTRATOR_BASE_URL = (
    _raw_orchestrator_url
    .replace("://127.0.0.1", "://host.docker.internal")
    .replace("://localhost", "://host.docker.internal")
)

# Load the audit poster module that lives beside this file in the
# container. Pure stdlib, zero upstream-server dependencies.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import kali_mcp_audit  # noqa: E402

# Per-field env-fallback policy. engagement_key and artifact_dir are
# session- or install-static and can honestly be defaulted from env.
# agent_name and phase change per-dispatch — falling back to env would
# silently mis-attribute every call to whatever role was set at container
# start, which breaks `list-command-runs --agent-name <self>` queries and
# the entire dedup story. Attribution fields MUST come from headers.
_ENV_FALLBACK_ALLOWED = {"engagement_key", "artifact_dir"}
_ENV_FALLBACK_WARNED: set[str] = set()

# Tool-name detection from the Flask request path. The upstream server exposes
# routes like /api/tools/nmap/scan and /api/generic/execute, so we derive the
# tool_name from the path segments rather than hard-coding it.
logger = logging.getLogger("patched_kali_server")


def load_upstream():
    spec = importlib.util.spec_from_file_location("kali_upstream_server", UPSTREAM_SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load upstream server from {UPSTREAM_SERVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upstream = load_upstream()


def _flask_g():
    """Return flask.g or None if no request context is active."""
    try:
        from flask import g  # type: ignore
        return g
    except Exception:  # pragma: no cover — upstream should pull flask in
        return None


def _tool_name_from_path(path: str) -> str:
    parts = [p for p in (path or "").split("/") if p]
    if not parts:
        return "unknown"
    if parts[0] == "api" and len(parts) >= 3 and parts[1] == "tools":
        return parts[2]
    if parts[0] == "api" and len(parts) >= 2:
        return parts[1]
    return parts[-1]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PatchedCommandExecutor(upstream.CommandExecutor):
    def execute(self) -> Dict[str, Any]:
        upstream.logger.info("Executing command: %s", self.command)

        if not isinstance(self.command, (str, list)):
            raise ValueError(
                f"CommandExecutor expects a string or list, but got {type(self.command).__name__}"
            )

        use_shell = isinstance(self.command, str)

        started_at = _now_iso()
        started_mono = time.monotonic()
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            self.stdout_thread = upstream.threading.Thread(target=self._read_stdout, daemon=True)
            self.stderr_thread = upstream.threading.Thread(target=self._read_stderr, daemon=True)
            self.stdout_thread.start()
            self.stderr_thread.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                upstream.logger.warning(
                    "Command timed out after %s seconds. Terminating process.",
                    self.timeout,
                )
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    upstream.logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                self.return_code = -1

            success = (
                True
                if self.timed_out and (self.stdout_data or self.stderr_data)
                else (self.return_code == 0)
            )

            result = {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
            }
        except Exception as exc:
            upstream.logger.error("Error executing command: %s", exc)
            upstream.logger.error(traceback.format_exc())
            result = {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {exc}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
            }

        completed_at = _now_iso()
        duration_ms = int((time.monotonic() - started_mono) * 1000)

        g = _flask_g()
        if g is not None:
            command_snapshot = self.command
            argv: list[str] | None
            if isinstance(command_snapshot, list):
                argv = [str(x) for x in command_snapshot]
                command_text = " ".join(argv)
            else:
                argv = None
                command_text = str(command_snapshot)
            existing = getattr(g, "command_runs", [])
            existing.append(
                {
                    "command": command_text,
                    "argv": argv,
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "duration_ms": duration_ms,
                    "return_code": result["return_code"],
                    "timed_out": bool(result["timed_out"]),
                    "success": bool(result["success"]),
                    "stdout": result["stdout"] or "",
                    "stderr": result["stderr"] or "",
                }
            )
            g.command_runs = existing

        return result


def execute_command(command):
    executor = PatchedCommandExecutor(command)
    return executor.execute()


upstream.CommandExecutor = PatchedCommandExecutor
upstream.execute_command = execute_command


def _is_audit_eligible_path(path: str) -> bool:
    """True when the request path represents target-facing tool work that
    should be audited. /health, /static, /mcp/capabilities, and other
    infra endpoints are excluded so they neither require audit headers
    nor pollute the log."""
    if path in AUDIT_OPEN_PATHS:
        return False
    if path.startswith("/static"):
        return False
    return True


def _should_require_audit(path: str) -> bool:
    if not AUDIT_REQUIRED:
        return False
    return _is_audit_eligible_path(path)


def _rollup_audit_source(sources: dict[str, str]) -> str:
    """Roll up per-field source labels into a single row provenance value.
    attribution fields (agent_name, phase) carry more weight than infra
    fields (engagement_key, artifact_dir) because filtering queries key
    off attribution. A call with headers for agent_name+phase but env
    fallback for engagement_key still reads as 'header' — the part that
    matters for query-by-agent is trustworthy."""
    attribution = [sources.get("agent_name"), sources.get("phase")]
    if all(s == "header" for s in attribution):
        return "header"
    if all(s in ("header", "env_fallback") for s in attribution):
        return "mixed"
    return "env_fallback"


def _install_audit_hooks(flask_app) -> None:
    from flask import g, jsonify, request  # type: ignore

    @flask_app.before_request
    def _capture_audit_context():  # pragma: no cover — wired at import
        # Per-field resolution. Each field gets either header
        # (authoritative) or env fallback (only when policy allows).
        # Track the source so the audit row records attribution
        # provenance.
        fields = {
            "engagement_key": ("X-Engagement-Key", "KALI_MCP_DEFAULT_ENGAGEMENT_KEY"),
            "agent_name": ("X-Agent-Name", "KALI_MCP_DEFAULT_AGENT_NAME"),
            "phase": ("X-Phase", "KALI_MCP_DEFAULT_PHASE"),
            "artifact_dir": ("X-Engagement-Artifact-Dir", "KALI_MCP_DEFAULT_ARTIFACT_DIR"),
        }
        sources: dict[str, str] = {}
        values: dict[str, str] = {}
        for key, (header, env_var) in fields.items():
            header_value = request.headers.get(header, "").strip()
            if header_value:
                values[key] = header_value
                sources[key] = "header"
                continue
            if key in _ENV_FALLBACK_ALLOWED:
                env_value = os.environ.get(env_var, "").strip()
                if env_value:
                    values[key] = env_value
                    sources[key] = "env_fallback"
                    if key not in _ENV_FALLBACK_WARNED:
                        _ENV_FALLBACK_WARNED.add(key)
                        logger.warning(
                            "audit field '%s' fell back to env var %s — per-call headers preferred for per-dispatch attribution",
                            key,
                            env_var,
                        )
                    continue
            values[key] = ""
            sources[key] = "missing"

        g.audit_engagement_key = values["engagement_key"]
        g.audit_agent_name = values["agent_name"]
        g.audit_phase = values["phase"]
        g.audit_artifact_dir = values["artifact_dir"]
        g.audit_sources = sources
        g.command_runs = []

        if not _should_require_audit(request.path):
            return None

        missing = [
            name
            for name, value in (
                ("X-Engagement-Key", g.audit_engagement_key),
                ("X-Agent-Name", g.audit_agent_name),
                ("X-Phase", g.audit_phase),
            )
            if not value
        ]
        if missing:
            return jsonify(
                {
                    "error": "audit-headers-missing",
                    "missing": missing,
                    "message": (
                        "Kali MCP target-facing calls require X-Engagement-Key, "
                        "X-Agent-Name, and X-Phase audit headers. Set "
                        "KALI_MCP_AUDIT_REQUIRED=0 to disable this check during "
                        "backfill or development."
                    ),
                }
            ), 400
        return None

    @flask_app.after_request
    def _record_command_runs(response):  # pragma: no cover — wired at import
        # Recording is independent of header-rejection: even when
        # KALI_MCP_AUDIT_REQUIRED=0 (env defaults supplying audit context),
        # we still want every tool call recorded. Only skip infra paths
        # so health-check probes like `which nmap` don't pollute the log.
        if not _is_audit_eligible_path(request.path):
            return response
        runs = getattr(g, "command_runs", [])
        if not runs:
            return response
        engagement_key = getattr(g, "audit_engagement_key", "")
        if not engagement_key:
            return response
        agent_name = getattr(g, "audit_agent_name", "") or "unknown"
        phase = getattr(g, "audit_phase", "") or "unknown"
        raw_artifact_dir = getattr(g, "audit_artifact_dir", "") or ""
        # The backend writer drops files directly into the supplied dir;
        # by convention we organize command-run logs under
        # <root>/scans/command-runs/ so they don't mingle with unrelated
        # scan outputs. Append the subdir when the runtime only supplied
        # the scans root.
        if raw_artifact_dir and not raw_artifact_dir.rstrip("/").endswith("command-runs"):
            artifact_dir = str(Path(raw_artifact_dir) / "command-runs")
        else:
            artifact_dir = raw_artifact_dir or None
        sources = getattr(g, "audit_sources", {}) or {}
        audit_source = _rollup_audit_source(sources)
        tool_name = _tool_name_from_path(request.path)
        route = request.path

        for run in runs:
            payload = {
                "command": run["command"],
                "argv": run.get("argv"),
                "tool_name": tool_name,
                "route": route,
                "agent_name": agent_name,
                "phase": phase,
                "return_code": run["return_code"],
                "timed_out": run["timed_out"],
                "success": run["success"],
                "started_at": run["started_at"],
                "completed_at": run["completed_at"],
                "duration_ms": run["duration_ms"],
                "stdout": run["stdout"],
                "stderr": run["stderr"],
                "audit_source": audit_source,
                "command_hash": hashlib.sha256(
                    run["command"].encode("utf-8", errors="replace")
                ).hexdigest(),
                "engagement_artifact_dir": artifact_dir,
                "run_uuid": uuid.uuid4().hex,
            }
            kali_mcp_audit.default_poster().enqueue(engagement_key, payload)
        return response


def main() -> None:
    args = upstream.parse_args()

    if args.debug:
        upstream.DEBUG_MODE = True
        upstream.os.environ["DEBUG_MODE"] = "1"
        upstream.logger.setLevel(upstream.logging.DEBUG)

    if args.port != upstream.API_PORT:
        upstream.API_PORT = args.port

    _install_audit_hooks(upstream.app)
    # Eagerly boot the background audit worker so the first tool call
    # doesn't pay the cost of lazy initialization.
    kali_mcp_audit.default_poster()

    upstream.logger.info(
        "Starting Kali Linux Tools API Server on %s:%s (audit_required=%s, orchestrator=%s)",
        args.ip,
        upstream.API_PORT,
        AUDIT_REQUIRED,
        ORCHESTRATOR_BASE_URL,
    )
    upstream.app.run(host=args.ip, port=upstream.API_PORT, debug=upstream.DEBUG_MODE)


if __name__ == "__main__":
    main()
