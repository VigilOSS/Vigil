#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import logging
import os
import subprocess
import time
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict


UPSTREAM_SERVER_PATH = Path("/usr/share/mcp-kali-server/server.py")

# Target-facing routes require audit headers. /health and metadata routes
# stay open so container health checks and MCP tool discovery keep working.
AUDIT_OPEN_PATHS = {
    "/health",
    "/metrics",
    "/favicon.ico",
    "/",
}

AUDIT_REQUIRED = os.environ.get("KALI_MCP_AUDIT_REQUIRED", "1") != "0"
ORCHESTRATOR_BASE_URL = os.environ.get("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:18000").rstrip("/")
RECORDING_TIMEOUT_SECONDS = float(os.environ.get("KALI_MCP_AUDIT_TIMEOUT", "3"))

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
    should be audited. /health, /static, and other infra endpoints are
    excluded so they neither require audit headers nor pollute the log."""
    if path in AUDIT_OPEN_PATHS:
        return False
    if path.startswith("/static"):
        return False
    return True


def _should_require_audit(path: str) -> bool:
    if not AUDIT_REQUIRED:
        return False
    return _is_audit_eligible_path(path)


def _install_audit_hooks(flask_app) -> None:
    from flask import g, jsonify, request  # type: ignore

    @flask_app.before_request
    def _capture_audit_context():  # pragma: no cover — wired at import
        # Headers win over env fallbacks so per-call audit context from the
        # MCP client (once client.py exposes the fields) supersedes session
        # defaults. Env fallbacks make v1 usable before the client schema
        # patch lands.
        g.audit_engagement_key = (
            request.headers.get("X-Engagement-Key", "").strip()
            or os.environ.get("KALI_MCP_DEFAULT_ENGAGEMENT_KEY", "").strip()
        )
        g.audit_agent_name = (
            request.headers.get("X-Agent-Name", "").strip()
            or os.environ.get("KALI_MCP_DEFAULT_AGENT_NAME", "").strip()
        )
        g.audit_phase = (
            request.headers.get("X-Phase", "").strip()
            or os.environ.get("KALI_MCP_DEFAULT_PHASE", "").strip()
        )
        g.audit_artifact_dir = (
            request.headers.get("X-Engagement-Artifact-Dir", "").strip()
            or os.environ.get("KALI_MCP_DEFAULT_ARTIFACT_DIR", "").strip()
        )
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
        artifact_dir = getattr(g, "audit_artifact_dir", "") or None
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
                "command_hash": hashlib.sha256(
                    run["command"].encode("utf-8", errors="replace")
                ).hexdigest(),
                "engagement_artifact_dir": artifact_dir,
                "run_uuid": uuid.uuid4().hex,
            }
            _post_command_run(engagement_key, payload)
        return response


def _post_command_run(engagement_key: str, payload: dict[str, Any]) -> None:
    url = f"{ORCHESTRATOR_BASE_URL}/engagements/{engagement_key}/assessment/command-runs"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=RECORDING_TIMEOUT_SECONDS):
            pass
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.warning(
            "command-run audit POST failed (%s %s): %s — tool output returned unchanged",
            engagement_key,
            payload.get("tool_name"),
            exc,
        )


def main() -> None:
    args = upstream.parse_args()

    if args.debug:
        upstream.DEBUG_MODE = True
        upstream.os.environ["DEBUG_MODE"] = "1"
        upstream.logger.setLevel(upstream.logging.DEBUG)

    if args.port != upstream.API_PORT:
        upstream.API_PORT = args.port

    _install_audit_hooks(upstream.app)

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
