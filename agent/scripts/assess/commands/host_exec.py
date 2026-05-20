"""aith assess host-exec — audited host-machine command execution for blue and non-kali red flows.

Wraps an arbitrary host-machine command (gam, gcloud, az, splunk, crowdstrike,
defender, jq, python3, ...) with the same audit pipeline that backs
``aith assess kali ...`` — every invocation lands in ``assessment_command_runs``
via the orchestrator's ``record_command_run()`` writer. Distinguished from
kali-runtime rows by ``route='host_exec'``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config


# Conservative destructive-token list. Operators must pass --allow-destructive
# to bypass. Tokens are matched as substrings in the joined argv after stripping
# leading/trailing whitespace per arg — intentionally narrow to limit false
# positives.
_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "rm -r",
    "dd of=/dev/",
    "format",
    "delete",
    "--force",
)

_AUDIT_SOURCE_CHOICES = ("header", "stdin", "argv")
_DEFAULT_TIMEOUT_SECONDS = 600
_INTENT_MAX_LEN = 200


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "host-exec",
        help=(
            "Run an arbitrary host-machine command with full audit recording "
            "(non-kali tools: gam, gcloud, az, splunk, jq, python3, ...)."
        ),
    )
    p.add_argument(
        "command",
        nargs="*",
        help=(
            "Command and arguments. Use `--` to separate from host-exec flags "
            "if any argv tokens look like options. Omit when using --from-json."
        ),
    )
    p.add_argument(
        "--tool",
        dest="tool",
        default=None,
        help="Tool name for audit (gam, gcloud, az, splunk, jq, python3, ...). Required unless --from-json supplies it.",
    )
    p.add_argument(
        "--intent",
        dest="intent",
        default=None,
        help="Short intent string (<=200 chars). Required unless --from-json supplies it.",
    )
    p.add_argument(
        "--technique",
        dest="technique",
        default=None,
        help="Technique identifier (MITRE ID like T1078.004 or kebab string).",
    )
    p.add_argument(
        "--phase",
        dest="phase",
        default=None,
        help="Engagement phase (intake|triage|investigate|verify|respond|report for blue; red phase names otherwise).",
    )
    p.add_argument(
        "--target-host",
        dest="target_host",
        default="",
        help="Specific host or service identity the command targets (optional).",
    )
    p.add_argument(
        "--agent-name",
        dest="agent_name",
        default=None,
        help="Agent name for audit attribution (defaults to AITH_AGENT_NAME, AGENT_NAME, then operator).",
    )
    p.add_argument(
        "--scope-host",
        dest="scope_host",
        default="",
        help="Tenant slug (blue) or IP/hostname (red); stored in notes JSON.",
    )
    p.add_argument(
        "--cwd",
        dest="cwd",
        default=None,
        help="Working directory override (defaults to engagement_dir).",
    )
    p.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=_DEFAULT_TIMEOUT_SECONDS,
        help=f"Wall-clock timeout in seconds (default: {_DEFAULT_TIMEOUT_SECONDS}).",
    )
    p.add_argument(
        "--audit-source",
        dest="audit_source",
        choices=_AUDIT_SOURCE_CHOICES,
        default="header",
        help="How the command was supplied for audit replay (default: header).",
    )
    p.add_argument(
        "--from-json",
        dest="from_json",
        default=None,
        help="Read payload from JSON file instead of CLI flags; same field names.",
    )
    p.add_argument(
        "--allow-destructive",
        dest="allow_destructive",
        action="store_true",
        help="Explicit opt-in for destructive operations (rm -r, dd of=/dev/, format, delete, --force).",
    )
    p.add_argument(
        "--require-audit",
        dest="require_audit",
        action="store_true",
        help="Exit non-zero if the backend audit row cannot be recorded; use for blue WRITE actions.",
    )
    p.set_defaults(func=run)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_str(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _contains_destructive_token(argv: list[str]) -> str | None:
    joined = " ".join(argv)
    for token in _DESTRUCTIVE_TOKENS:
        if token in joined:
            return token
    return None


def _load_from_json(path: str) -> dict:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"host-exec: cannot read --from-json {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"host-exec: invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    if not isinstance(payload, dict):
        print(f"host-exec: --from-json must be a JSON object, got {type(payload).__name__}", file=sys.stderr)
        sys.exit(2)
    return payload


def _merge_from_json(args: argparse.Namespace, doc: dict) -> None:
    """Overlay a --from-json payload onto args. CLI flags take precedence
    only when the JSON does not supply the field; this keeps scripted
    invocations deterministic by treating the JSON as authoritative."""
    field_map = {
        "command": "command",
        "argv": "command",
        "tool": "tool",
        "tool_name": "tool",
        "intent": "intent",
        "technique": "technique",
        "phase": "phase",
        "target_host": "target_host",
        "agent_name": "agent_name",
        "scope_host": "scope_host",
        "cwd": "cwd",
        "timeout": "timeout",
        "audit_source": "audit_source",
        "allow_destructive": "allow_destructive",
        "require_audit": "require_audit",
    }
    for json_key, attr in field_map.items():
        if json_key in doc and doc[json_key] is not None:
            setattr(args, attr, doc[json_key])


def _resolve_argv(args: argparse.Namespace) -> list[str]:
    cmd = args.command
    if isinstance(cmd, str):
        # --from-json may supply a string; split on whitespace.
        cmd = cmd.split()
    if not cmd:
        print("host-exec: command argv is required (positional or --from-json)", file=sys.stderr)
        sys.exit(2)
    return [str(token) for token in cmd]


def _validate_required(args: argparse.Namespace) -> None:
    missing: list[str] = []
    if not (args.tool or "").strip():
        missing.append("--tool")
    if not (args.intent or "").strip():
        missing.append("--intent")
    if not (args.technique or "").strip():
        missing.append("--technique")
    if not (args.phase or "").strip():
        missing.append("--phase")
    if missing:
        print(
            f"host-exec: missing required field(s): {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(2)


def _build_notes(scope_host: str) -> str:
    """Encode CLI-only fields (currently scope_host) as a small JSON blob in
    notes so they remain auditable even though the SQL schema has no dedicated
    column. Empty string when nothing to record so we don't pollute the column.
    """
    payload: dict[str, str] = {}
    if (scope_host or "").strip():
        payload["scope_host"] = scope_host.strip()
    if not payload:
        return ""
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _resolve_agent_name(args: argparse.Namespace) -> str:
    for value in (
        getattr(args, "agent_name", None),
        os.environ.get("AITH_AGENT_NAME"),
        os.environ.get("AGENT_NAME"),
        "operator",
    ):
        text = str(value or "").strip()
        if text:
            return text
    return "operator"


def run(args) -> None:
    if args.from_json:
        _merge_from_json(args, _load_from_json(args.from_json))

    argv = _resolve_argv(args)
    _validate_required(args)

    if not args.allow_destructive:
        token = _contains_destructive_token(argv)
        if token is not None:
            print(
                f"host-exec: refusing to run — argv contains destructive token "
                f"'{token}'. Re-invoke with --allow-destructive to override.",
                file=sys.stderr,
            )
            sys.exit(3)

    cfg = load_config(args.engagement_dir)

    cwd = args.cwd or cfg.engagement_dir
    timeout_seconds = int(args.timeout or _DEFAULT_TIMEOUT_SECONDS)

    run_uuid = uuid.uuid4().hex
    started_at = _utcnow_iso()
    started_monotonic = time.monotonic()

    stdout_text = ""
    stderr_text = ""
    return_code: int = -1
    timed_out = False

    try:
        completed = subprocess.run(  # noqa: S603 — host-exec deliberately invokes operator-supplied argv
            argv,
            cwd=cwd,
            timeout=timeout_seconds,
            capture_output=True,
            text=True,
        )
        stdout_text = completed.stdout or ""
        stderr_text = completed.stderr or ""
        return_code = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        # TimeoutExpired exposes partial stdout/stderr as bytes when text=True
        # has not yet decoded; coerce defensively.
        stdout_text = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, (bytes, bytearray))
            else (exc.stdout or "")
        )
        stderr_text = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, (bytes, bytearray))
            else (exc.stderr or "")
        )
        return_code = 124  # conventional timeout exit code
    except FileNotFoundError as exc:
        stderr_text = f"host-exec: command not found: {exc}\n"
        return_code = 127

    completed_at = _utcnow_iso()
    duration_ms = int((time.monotonic() - started_monotonic) * 1000)
    success = (return_code == 0) and not timed_out

    command_str = " ".join(argv)
    command_hash = _sha256_str(command_str)
    stdout_sha256 = _sha256_str(stdout_text)
    stderr_sha256 = _sha256_str(stderr_text)

    # Stream the wrapped command's output to the operator's fds first so the
    # audit POST cannot delay or swallow it.
    if stdout_text:
        sys.stdout.write(stdout_text)
        sys.stdout.flush()
    if stderr_text:
        sys.stderr.write(stderr_text)
        sys.stderr.flush()

    payload: dict = {
        "command": command_str,
        "argv": argv,
        "tool_name": args.tool.strip(),
        # Server forces route='host_exec' regardless; sending it here keeps
        # the audit trail consistent if the server-side guard is ever bypassed.
        "route": "host_exec",
        "agent_name": _resolve_agent_name(args),
        "phase": args.phase.strip(),
        "return_code": return_code,
        "timed_out": timed_out,
        "success": success,
        "started_at": started_at,
        "completed_at": completed_at,
        "duration_ms": duration_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "command_hash": command_hash,
        "stdout_sha256": stdout_sha256,
        "stderr_sha256": stderr_sha256,
        "notes": _build_notes(args.scope_host),
        "technique": args.technique.strip(),
        "intent": args.intent.strip()[:_INTENT_MAX_LEN],
        "destructive": bool(args.allow_destructive),
        "target_host": (args.target_host or "").strip(),
        "audit_source": args.audit_source,
        "working_dir": cwd,
        "timeout_seconds_requested": timeout_seconds,
        "run_uuid": run_uuid,
        "status": "timed_out" if timed_out else ("completed" if success else "failed"),
    }

    record_run_id: int | str = ""
    audit_record_failed = False
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        endpoint = f"command-runs/host-exec"
        try:
            response = client.post(endpoint, payload)
        except AssessError as exc:
            audit_record_failed = True
            print(
                f"[host-exec] WARN: audit record failed -- {exc}",
                file=sys.stderr,
            )
            response = None
        except Exception as exc:  # noqa: BLE001 — must never eat the exit code
            audit_record_failed = True
            print(
                f"[host-exec] WARN: audit record failed -- {exc}",
                file=sys.stderr,
            )
            response = None
        if isinstance(response, dict):
            record_run_id = response.get("run_id") or response.get("id") or ""
    finally:
        client.close()

    audit_line = (
        f"[host-exec] recorded run_uuid={run_uuid} "
        f"tool={args.tool.strip()} phase={args.phase.strip()} "
        f"rc={return_code} ms={duration_ms}"
    )
    if record_run_id:
        audit_line += f" run_id={record_run_id}"
    print(audit_line, file=sys.stderr)

    if getattr(args, "require_audit", False) and (audit_record_failed or not record_run_id):
        print(
            "[host-exec] required audit record was not created; refusing success for this invocation",
            file=sys.stderr,
        )
        sys.exit(4)

    sys.exit(return_code)
