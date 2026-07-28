"""vigil assess host-exec — audited host-machine command execution for blue and non-kali red flows.

Wraps an arbitrary host-machine command (gam, gcloud, az, splunk, crowdstrike,
defender, jq, python3, ...) with the same audit pipeline that backs
``vigil assess kali ...`` — every invocation lands in ``assessment_command_runs``
via the orchestrator's ``record_command_run()`` writer. Distinguished from
kali-runtime rows by ``route='host_exec'``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from assess.lib import host_processes
from assess.lib import scope as scope_lib
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.kali import prepare_execution_command
from assess.lib.rate_leases import aggregate_rate_reservation, target_rate_lease

# Conservative destructive-token list. Operators must pass --allow-destructive
# to bypass. Tokens are matched as substrings in the joined argv after stripping
# leading/trailing whitespace per arg, except command names which match only
# argv[0] so read-only flags such as --format do not trip the gate.
_DESTRUCTIVE_TOKENS: tuple[str, ...] = (
    "rm -r",
    "dd of=/dev/",
    "delete",
    "--force",
)
_DESTRUCTIVE_COMMANDS: tuple[str, ...] = ("format",)

_AUDIT_SOURCE_CHOICES = ("header", "stdin", "argv")
_DEFAULT_TIMEOUT_SECONDS = 600
_INTENT_MAX_LEN = 200
_PROCESS_TERM_GRACE_SECONDS = 5
_PROCESS_KILL_GRACE_SECONDS = 2
_OUTPUT_PREVIEW_BYTES = 64 * 1024


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
        help="Agent name for audit attribution (defaults to VIGIL_AGENT_NAME, AGENT_NAME, then operator).",
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
        help="Explicit opt-in for destructive operations (rm -r, dd of=/dev/, format command, delete, --force).",
    )
    p.add_argument(
        "--require-audit",
        dest="require_audit",
        action="store_true",
        help="Exit non-zero if the backend audit row cannot be recorded; use for blue WRITE actions.",
    )
    p.add_argument(
        "--rate-override-reason",
        default="",
        help="Reason for an authorized aggregate target-rate override.",
    )
    p.add_argument(
        "--finding",
        dest="finding",
        default="",
        help=(
            "Optional finding slug (or numeric id) to link this command-run to on "
            "record (assessment_command_runs.finding_id). Resolved to the finding's "
            "id at audit time; a bad ref WARNs and records the run unlinked."
        ),
    )
    p.add_argument(
        "--identity",
        default=None,
        help="Named credential identity to inject into supported HTTP tools.",
    )
    p.add_argument(
        "--identity-scope",
        dest="identity_scope",
        default="",
        help="Logical liveness scope used to resolve a scoped identity alias.",
    )
    p.set_defaults(func=run)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _sha256_str(text: str) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _contains_destructive_token(argv: list[str]) -> str | None:
    normalized = [str(arg).strip() for arg in argv if str(arg).strip()]
    if normalized:
        command_name = PureWindowsPath(Path(normalized[0]).name).name.lower()
        for command in _DESTRUCTIVE_COMMANDS:
            if command_name == command or command_name in (
                f"{command}.bat",
                f"{command}.cmd",
                f"{command}.com",
                f"{command}.exe",
            ):
                return command
    joined = " ".join(normalized)
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
        "rate_override_reason": "rate_override_reason",
        "finding": "finding",
        "finding_id": "finding",
        "identity": "identity",
        "identity_scope": "identity_scope",
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


def _build_notes(
    scope_host: str,
    execution_policy: dict | None = None,
    *,
    policy_refusal: str = "",
) -> str:
    """Encode CLI-only fields (currently scope_host) as a small JSON blob in
    notes so they remain auditable even though the SQL schema has no dedicated
    column. Empty string when nothing to record so we don't pollute the column.
    """
    payload: dict[str, Any] = {}
    if (scope_host or "").strip():
        payload["scope_host"] = scope_host.strip()
    if execution_policy:
        payload.update(execution_policy)
    if policy_refusal:
        payload["policy_refusal"] = policy_refusal
    if not payload:
        return ""
    return scope_lib.execution_policy_notes(payload)


def _resolve_finding_id(client: AssessmentClient, ref: str) -> int:
    """Resolve a ``--finding`` reference (slug or numeric id) to a finding_id int.

    A bare integer is used directly (the backend re-validates ownership). Any
    other value is treated as a finding slug and looked up so the operator can
    pass the human slug (e.g. VA-047) they already hold.
    """
    ref = str(ref).strip()
    try:
        return int(ref)
    except ValueError:
        pass
    row = client.get(f"findings/{ref}")
    if not isinstance(row, dict) or not row.get("id"):
        raise AssessError(f"finding {ref!r} not found")
    return int(row["id"])


def _resolve_agent_name(args: argparse.Namespace) -> str:
    for value in (
        getattr(args, "agent_name", None),
        os.environ.get("VIGIL_AGENT_NAME"),
        os.environ.get("AGENT_NAME"),
        "operator",
    ):
        text = str(value or "").strip()
        if text:
            return text
    return "operator"


def _bounded_text(value: Any, limit: int = _OUTPUT_PREVIEW_BYTES) -> str:
    if value is None:
        return ""
    raw = value if isinstance(value, bytes) else str(value).encode("utf-8", errors="replace")
    if len(raw) <= limit:
        return _clip_utf8(raw.decode("utf-8", errors="replace"), limit)
    marker = f"\n... {len(raw) - limit} or more bytes omitted ...\n"
    return _bounded_head_tail(
        raw[:limit], raw[-limit:], marker=marker, limit=limit
    )


def _clip_utf8(value: str, limit: int, *, from_end: bool = False) -> str:
    """Clip text to an encoded-byte budget without returning partial UTF-8."""
    if limit <= 0:
        return ""
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value
    window = encoded[-limit:] if from_end else encoded[:limit]
    return window.decode("utf-8", errors="ignore")


def _bounded_head_tail(head: bytes, tail: bytes, *, marker: str, limit: int) -> str:
    marker = _clip_utf8(marker, limit)
    available = max(limit - len(marker.encode("utf-8")), 0)
    head_budget = available // 2
    tail_budget = available - head_budget
    head_text = _clip_utf8(
        head.decode("utf-8", errors="replace"), head_budget
    )
    tail_text = _clip_utf8(
        tail.decode("utf-8", errors="replace"), tail_budget, from_end=True
    )
    return head_text + marker + tail_text


def _bounded_file_preview(path: Path, limit: int = _OUTPUT_PREVIEW_BYTES) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size <= limit:
                return _clip_utf8(
                    fh.read(limit).decode("utf-8", errors="replace"), limit
                )
            head = fh.read(limit)
            fh.seek(max(size - limit, 0))
            tail = fh.read(limit)
    except OSError:
        return ""
    marker = f"\n... output omitted; full output: {path} ...\n"
    return _bounded_head_tail(
        head, tail, marker=marker, limit=limit
    )


def _run_host_process(
    argv: list[str],
    *,
    cwd: str,
    timeout_seconds: int,
    engagement_dir: str,
    run_uuid: str,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> tuple[int, str, str, bool]:
    """Run one host process with line-one spill and precise group ownership."""
    output_dir = Path(engagement_dir) / "scans" / "host-exec"
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = stdout_path or output_dir / f"{run_uuid}.out"
    stderr_path = stderr_path or output_dir / f"{run_uuid}.err"
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)

    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        try:
            process = subprocess.Popen(  # noqa: S603 - operator-supplied argv is the contract
                argv,
                cwd=cwd,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True,
            )
        except FileNotFoundError as exc:
            return 127, "", f"host-exec: command not found: {exc}\n", False

        registered = False
        return_code = int(process.returncode) if process.returncode is not None else 1
        timed_out = False
        communicated = False
        captured_stdout = ""
        captured_stderr = ""
        try:
            host_processes.register_process(
                engagement_dir, run_uuid=run_uuid, pid=process.pid
            )
            registered = True
        except Exception:
            # A very short-lived command may exit between Popen and the identity
            # lookup. It cannot become an orphan, so collect its completed result.
            if process.poll() is not None:
                captured_stdout, captured_stderr = process.communicate(timeout=1)
                communicated = True
                return_code = int(process.returncode)
            else:
                _terminate_process_group(process)
                raise

        try:
            if not communicated:
                captured_stdout, captured_stderr = process.communicate(
                    timeout=timeout_seconds
                )
            return_code = int(process.returncode)
        except subprocess.TimeoutExpired:
            _terminate_process_group(process)
            return_code = 124
            timed_out = True
        finally:
            if registered and process.returncode is not None:
                group_alive = host_processes.registered_group_alive(
                    engagement_dir, run_uuid=run_uuid
                )
                if group_alive is False:
                    host_processes.unregister_process(
                        engagement_dir, run_uuid=run_uuid
                    )

    stdout_text = _bounded_file_preview(stdout_path)
    stderr_text = _bounded_file_preview(stderr_path)
    if not stdout_text and captured_stdout:
        stdout_text = _bounded_text(captured_stdout)
    if not stderr_text and captured_stderr:
        stderr_text = _bounded_text(captured_stderr)
    return return_code, stdout_text, stderr_text, timed_out


def _terminate_process_group(process: subprocess.Popen) -> tuple[str, str]:
    """Boundedly terminate and reap the whole process group created by Popen."""
    try:
        process_group = os.getpgid(process.pid)
    except ProcessLookupError:
        try:
            return process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            return "", ""

    for sig, grace in (
        (signal.SIGTERM, _PROCESS_TERM_GRACE_SECONDS),
        (signal.SIGKILL, _PROCESS_KILL_GRACE_SECONDS),
    ):
        try:
            os.killpg(process_group, sig)
        except ProcessLookupError:
            pass
        try:
            stdout_text, stderr_text = process.communicate(timeout=grace)
            return stdout_text or "", stderr_text or ""
        except subprocess.TimeoutExpired:
            continue
    return "", ""


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
    output_dir = Path(cfg.engagement_dir) / "scans" / "host-exec"
    output_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = output_dir / f"{run_uuid}.out"
    stderr_path = output_dir / f"{run_uuid}.err"
    started_at = _utcnow_iso()
    started_monotonic = time.monotonic()

    auth_context = "anonymous"
    try:
        auth_context = prepare_execution_command(
            argv,
            tool_name=args.tool.strip(),
            engagement_dir=Path(cfg.engagement_dir),
            identity=getattr(args, "identity", None),
            identity_scope=getattr(args, "identity_scope", "") or "",
        )
        execution_policy = scope_lib.enforce_execution_policy(
            argv,
            tool_name=args.tool.strip(),
            engagement_dir=cfg.engagement_dir,
            require_declared_tool=True,
        )
    except scope_lib.ScopePolicyError as exc:
        reason = str(exc)
        refusal_payload = {
            "command": " ".join(argv),
            "argv": argv,
            "tool_name": args.tool.strip(),
            "route": "host_exec",
            "agent_name": _resolve_agent_name(args),
            "phase": args.phase.strip(),
            "return_code": None,
            "timed_out": False,
            "success": False,
            "started_at": started_at,
            "completed_at": _utcnow_iso(),
            "duration_ms": 0,
            "stdout": "",
            "stderr": reason,
            "notes": _build_notes(args.scope_host, policy_refusal=reason),
            "technique": args.technique.strip(),
            "intent": args.intent.strip()[:_INTENT_MAX_LEN],
            "destructive": bool(args.allow_destructive),
            "target_host": (args.target_host or "").strip(),
            "audit_source": args.audit_source,
            "working_dir": cwd,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "timeout_seconds_requested": timeout_seconds,
            "run_uuid": run_uuid,
            "status": "failed",
            "auth_context": auth_context,
        }
        try:
            with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
                client.post("command-runs/host-exec", refusal_payload)
        except Exception as audit_exc:  # noqa: BLE001 - target traffic remains blocked
            print(f"[host-exec] WARN: policy refusal audit failed -- {audit_exc}", file=sys.stderr)
        print(f"host-exec: refusing to run — {reason}", file=sys.stderr)
        sys.exit(3)

    command_str = " ".join(argv)
    command_hash = _sha256_str(command_str)
    notes = _build_notes(args.scope_host, execution_policy)

    pre_payload: dict = {
        "command": command_str,
        "argv": argv,
        "tool_name": args.tool.strip(),
        "route": "host_exec",
        "agent_name": _resolve_agent_name(args),
        "phase": args.phase.strip(),
        "return_code": None,
        "timed_out": False,
        "success": None,
        "started_at": started_at,
        "completed_at": "",
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "command_hash": command_hash,
        "stdout_sha256": "",
        "stderr_sha256": "",
        "notes": notes,
        "technique": args.technique.strip(),
        "intent": args.intent.strip()[:_INTENT_MAX_LEN],
        "destructive": bool(args.allow_destructive),
        "target_host": (args.target_host or "").strip(),
        "audit_source": args.audit_source,
        "working_dir": cwd,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "timeout_seconds_requested": timeout_seconds,
        "run_uuid": run_uuid,
        "status": "running",
        "auth_context": auth_context,
    }

    record_run_id: int | str = ""
    audit_record_failed = False
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    finding_ref = str(getattr(args, "finding", "") or "").strip()
    if finding_ref:
        try:
            pre_payload["finding_id"] = _resolve_finding_id(client, finding_ref)
        except Exception as exc:  # noqa: BLE001 - linkage is best-effort
            print(
                f"[host-exec] WARN: could not link finding {finding_ref!r}: {exc}; "
                "recording the run unlinked.",
                file=sys.stderr,
            )
    try:
        try:
            response = client.post("command-runs/host-exec", pre_payload)
        except Exception as exc:  # noqa: BLE001 - honor require-audit below
            if "finding_id" in pre_payload:
                bad_id = pre_payload.pop("finding_id")
                print(
                    f"[host-exec] WARN: could not link finding id={bad_id}: {exc}; "
                    "recording the run unlinked.",
                    file=sys.stderr,
                )
                try:
                    response = client.post("command-runs/host-exec", pre_payload)
                except Exception as retry_exc:  # noqa: BLE001
                    response = None
                    audit_record_failed = True
                    print(f"[host-exec] WARN: pre-exec audit failed -- {retry_exc}", file=sys.stderr)
            else:
                response = None
                audit_record_failed = True
                print(f"[host-exec] WARN: pre-exec audit failed -- {exc}", file=sys.stderr)
        if isinstance(response, dict):
            record_run_id = response.get("run_id") or response.get("id") or ""

        if getattr(args, "require_audit", False) and not record_run_id:
            print(
                "[host-exec] required pre-exec audit record was not created; refusing execution",
                file=sys.stderr,
            )
            sys.exit(4)

        stdout_text = ""
        stderr_text = ""
        return_code: int = -1
        timed_out = False

        try:
            reservation = aggregate_rate_reservation(
                cfg.engagement_dir,
                argv,
                args.tool.strip(),
                execution_policy,
            )
            if reservation is None:
                return_code, stdout_text, stderr_text, timed_out = _run_host_process(
                    argv,
                    cwd=cwd,
                    timeout_seconds=timeout_seconds,
                    engagement_dir=cfg.engagement_dir,
                    run_uuid=run_uuid,
                    stdout_path=stdout_path,
                    stderr_path=stderr_path,
                )
            else:
                numeric_run_id = int(record_run_id) if str(record_run_id).isdigit() else None
                with target_rate_lease(
                    config=cfg,
                    owner=f"host-exec:{run_uuid}",
                    effective_rate_rps=reservation,
                    ttl_seconds=max(timeout_seconds + 60, 60),
                    override_reason=str(
                        getattr(args, "rate_override_reason", "") or ""
                    ).strip(),
                    command_run_id=numeric_run_id,
                ):
                    return_code, stdout_text, stderr_text, timed_out = _run_host_process(
                        argv,
                        cwd=cwd,
                        timeout_seconds=timeout_seconds,
                        engagement_dir=cfg.engagement_dir,
                        run_uuid=run_uuid,
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                    )
        except Exception as exc:  # noqa: BLE001 - finalize the running audit row
            return_code = 1
            stderr_text = f"host-exec: process setup failed: {exc}\n"

        completed_at = _utcnow_iso()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        success = (return_code == 0) and not timed_out

        # Stream the wrapped command's output only after the process exits; the
        # pre-exec audit already exists at this point.
        if stdout_text:
            sys.stdout.write(stdout_text)
            sys.stdout.flush()
        if stderr_text:
            sys.stderr.write(stderr_text)
            sys.stderr.flush()

        finalize_payload: dict = {
            "return_code": return_code,
            "timed_out": timed_out,
            "ended_at": completed_at,
            "duration_ms": duration_ms,
            "stdout_preview": stdout_text,
            "stderr_preview": stderr_text,
            "status": "timed_out" if timed_out else ("completed" if success else "failed"),
            "partial_results": bool(stdout_text or stderr_text) and not success,
        }
        if record_run_id:
            try:
                client.patch(f"command-runs/{record_run_id}", finalize_payload)
            except Exception as exc:  # noqa: BLE001
                audit_record_failed = True
                print(f"[host-exec] WARN: audit finalize failed -- {exc}", file=sys.stderr)
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
