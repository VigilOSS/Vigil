"""vigil assess host-exec — audited host-machine command execution for blue and non-kali red flows.

Wraps an arbitrary host-machine command (gam, gcloud, az, splunk, crowdstrike,
defender, jq, python3, ...) with the same audit pipeline that backs
``vigil assess kali ...`` — every invocation lands in ``assessment_command_runs``
via the orchestrator's ``record_command_run()`` writer. Distinguished from
kali-runtime rows by ``route='host_exec'``.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Any

from assess.lib import host_processes
from assess.lib import scope as scope_lib
from assess.lib.client import (
    AssessError,
    AssessmentClient,
    require_command_run_finalize_response,
)
from assess.lib.config import load_config
from assess.lib.execution_recency import emit_foreign_lane_recency
from assess.lib.kali import prepare_execution_command

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
_OUTPUT_DIRECTORY_MODE = 0o700
_SPILL_FILE_MODE = 0o600


class HostProcessNotQuiescent(AssessError):
    """The registered process group may still be able to mutate spill output."""


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "host-exec",
        help=(
            "Run an arbitrary host-machine command with full audit recording "
            "(non-kali tools: gam, gcloud, az, splunk, jq, python3, ...)."
        ),
    )
    p.add_argument(
        "exec_argv",
        nargs="*",
        metavar="command",
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
        help=(
            "Also exit non-zero when terminal audit integrity or physical cleanup "
            "is not trustworthy; pre-exec audit is mandatory for every host command."
        ),
    )
    p.add_argument(
        "--finding",
        dest="finding",
        default="",
        help=(
            "Optional finding slug (or numeric id) to link this command-run to on "
            "record (assessment_command_runs.finding_id). Resolved to the finding's "
            "id at audit time; an unresolved or rejected explicit link fails closed "
            "before command execution."
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
        "command": "exec_argv",
        "argv": "exec_argv",
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
        "finding": "finding",
        "finding_id": "finding",
        "identity": "identity",
        "identity_scope": "identity_scope",
    }
    for json_key, attr in field_map.items():
        if json_key in doc and doc[json_key] is not None:
            setattr(args, attr, doc[json_key])


def _resolve_argv(args: argparse.Namespace) -> list[str]:
    cmd = getattr(args, "exec_argv", getattr(args, "command", []))
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


def _bounded_descriptor_preview(
    handle: Any,
    path: Path,
    limit: int = _OUTPUT_PREVIEW_BYTES,
) -> str:
    """Read a bounded preview from the exact spill descriptor given to Popen."""
    try:
        handle.flush()
        size = os.fstat(handle.fileno()).st_size
        handle.seek(0)
        if size <= limit:
            return _clip_utf8(
                handle.read(limit).decode("utf-8", errors="replace"), limit
            )
        head = handle.read(limit)
        handle.seek(max(size - limit, 0))
        tail = handle.read(limit)
    except OSError:
        return ""
    marker = f"\n... output omitted; full output: {path} ...\n"
    return _bounded_head_tail(
        head, tail, marker=marker, limit=limit
    )


def _directory_open_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _close_descriptors(*descriptors: int | None) -> None:
    first_error: OSError | None = None
    for descriptor in descriptors:
        if descriptor is None:
            continue
        try:
            os.close(descriptor)
        except OSError as exc:
            if first_error is None:
                first_error = exc
    if first_error is not None:
        raise first_error


def _open_directory_nofollow(path: Path) -> int:
    """Open every component of an absolute directory without following links."""
    absolute = path.absolute()
    if not absolute.is_absolute():
        raise AssessError(f"host-exec output directory must be absolute: {path}")
    parts = absolute.parts
    if any(part in {".", ".."} for part in parts[1:]):
        raise AssessError(f"host-exec output directory is not normalized: {path}")

    descriptor = os.open(absolute.anchor, _directory_open_flags())
    try:
        for part in parts[1:]:
            next_descriptor = os.open(
                part,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise AssessError(f"host-exec output component is not a directory: {path}")
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _open_host_exec_output_directory(engagement_dir: str | os.PathLike[str]) -> int:
    """Create/open ``scans/host-exec`` beneath a no-follow engagement root."""
    descriptor = _open_directory_nofollow(Path(engagement_dir))
    try:
        for part in ("scans", "host-exec"):
            try:
                os.mkdir(part, _OUTPUT_DIRECTORY_MODE, dir_fd=descriptor)
            except FileExistsError:
                pass
            next_descriptor = os.open(
                part,
                _directory_open_flags(),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            component_metadata = os.fstat(descriptor)
            if not stat.S_ISDIR(component_metadata.st_mode):
                raise AssessError(
                    f"host-exec output component is not a directory: {part}"
                )
            if part == "host-exec":
                if component_metadata.st_uid != os.geteuid():
                    raise AssessError(
                        "host-exec output directory is not owned by the current user"
                    )
                if stat.S_IMODE(component_metadata.st_mode) != _OUTPUT_DIRECTORY_MODE:
                    os.fchmod(descriptor, _OUTPUT_DIRECTORY_MODE)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _create_output_spills(
    stdout_path: Path,
    stderr_path: Path,
    *,
    directory_descriptor: int | None = None,
) -> tuple[int, int]:
    """Claim both spill leaves and return descriptors that remain identity-bound."""
    if stdout_path.parent != stderr_path.parent:
        raise AssessError("host-exec stdout and stderr spills must share one directory")
    owned_directory_descriptor = directory_descriptor is None
    if directory_descriptor is None:
        directory_descriptor = _open_directory_nofollow(stdout_path.parent)

    flags = (
        os.O_RDWR
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptors: list[int] = []
    try:
        for path in (stdout_path, stderr_path):
            descriptor = os.open(
                path.name,
                flags,
                _SPILL_FILE_MODE,
                dir_fd=directory_descriptor,
            )
            descriptors.append(descriptor)
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AssessError(f"host-exec spill is not a regular file: {path}")
        return descriptors[0], descriptors[1]
    except Exception:
        # Never unlink by a mutable pathname here.  A concurrent rename and
        # replacement must not let failure cleanup delete an attacker's file.
        _close_descriptors(*descriptors)
        raise
    finally:
        if owned_directory_descriptor:
            os.close(directory_descriptor)


def _append_spill_text(descriptor: int, path: Path, text: str) -> None:
    if not text:
        return
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        raise AssessError(f"host-exec spill is not a regular file: {path}")
    raw = text.encode("utf-8", errors="replace")
    os.lseek(descriptor, 0, os.SEEK_END)
    while raw:
        written = os.write(descriptor, raw)
        if written <= 0:
            raise OSError(f"could not append host-exec spill: {path}")
        raw = raw[written:]
    os.fsync(descriptor)


def _spill_identity_claim(descriptor: int, path: Path) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise AssessError(f"host-exec spill is not a regular file: {path}")
    device = int(metadata.st_dev)
    inode = int(metadata.st_ino)
    if not (0 <= device <= 2**63 - 1 and 0 <= inode <= 2**63 - 1):
        raise AssessError(f"host-exec spill identity is outside the audit contract: {path}")
    return device, inode


def _post_pre_exec_audit(
    client: AssessmentClient,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Replay one identical POST when its response may have been lost.

    ``run_uuid`` and the spill identity claims make the request an idempotency
    key at the dedicated backend endpoint.  The extra replay is deliberately
    byte-for-byte equivalent: mutating linkage or metadata here could turn an
    already-committed execution into a conflicting second audit attempt.
    """
    try:
        return client.post("command-runs/host-exec", payload)
    except AssessError as exc:
        # A concrete HTTP rejection reached the caller and is not ambiguous.
        # Connection exhaustion is wrapped as ``AssessError`` without this
        # prefix, so that case still gets the exact idempotent replay.
        if str(exc).startswith("HTTP "):
            raise
        return client.post("command-runs/host-exec", payload)
    except Exception:  # noqa: BLE001 - malformed/lost response is ambiguous
        return client.post("command-runs/host-exec", payload)


def _validate_terminal_finalize_response(
    finalized: Any,
    attempted: dict[str, Any],
) -> dict[str, Any]:
    """Accept a replayed terminal row only when its core facts are ours."""
    if not isinstance(finalized, dict):
        raise AssessError("audit finalize returned a non-object response")
    require_command_run_finalize_response(
        finalized,
        run_id=attempted["id"],
        run_uuid=attempted["run_uuid"],
        requested_status=attempted["status"],
    )
    mismatches: list[str] = []
    for field in ("status", "return_code", "timed_out", "duration_ms"):
        if field not in finalized or finalized[field] != attempted[field]:
            mismatches.append(
                f"{field} expected={attempted[field]!r} got={finalized.get(field)!r}"
            )
    expected_partial = bool(attempted["partial_results"])
    if attempted.get("output_quiesced") is False:
        expected_partial = False
    partial_value = finalized.get("partial_results")
    if not (
        isinstance(partial_value, (bool, int))
        and not isinstance(partial_value, float)
        and partial_value in (0, 1)
        and bool(partial_value) is expected_partial
    ):
        mismatches.append(
            "partial_results "
            f"expected={expected_partial!r} got={partial_value!r}"
        )
    try:
        expected_completed_at = datetime.fromisoformat(
            str(attempted["ended_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
        actual_completed_at = datetime.fromisoformat(
            str(finalized["completed_at"]).replace("Z", "+00:00")
        ).astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError):
        actual_completed_at = None
        expected_completed_at = object()
    if actual_completed_at != expected_completed_at:
        mismatches.append(
            "completed_at "
            f"expected={attempted.get('ended_at')!r} "
            f"got={finalized.get('completed_at')!r}"
        )
    if mismatches:
        raise AssessError(
            "audit finalize returned terminal facts owned by another finalizer: "
            + "; ".join(mismatches)
        )
    return finalized


def _run_host_process(
    argv: list[str],
    *,
    cwd: str,
    timeout_seconds: int,
    engagement_dir: str,
    run_uuid: str,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
    stdout_descriptor: int | None = None,
    stderr_descriptor: int | None = None,
) -> tuple[int, str, str, bool]:
    """Run one host process with line-one spill and precise group ownership."""
    output_dir = Path(engagement_dir) / "scans" / "host-exec"
    stdout_path = stdout_path or output_dir / f"{run_uuid}.out"
    stderr_path = stderr_path or output_dir / f"{run_uuid}.err"
    if (stdout_descriptor is None) != (stderr_descriptor is None):
        raise AssessError("host-exec requires both precreated spill descriptors")

    owns_descriptors = stdout_descriptor is None
    if owns_descriptors:
        if stdout_path.parent == output_dir and stderr_path.parent == output_dir:
            directory_descriptor = _open_host_exec_output_directory(engagement_dir)
            try:
                stdout_descriptor, stderr_descriptor = _create_output_spills(
                    stdout_path,
                    stderr_path,
                    directory_descriptor=directory_descriptor,
                )
            finally:
                os.close(directory_descriptor)
        else:
            stdout_descriptor, stderr_descriptor = _create_output_spills(
                stdout_path, stderr_path
            )

    assert stdout_descriptor is not None
    assert stderr_descriptor is not None
    stdout_process_descriptor = os.dup(stdout_descriptor)
    try:
        stderr_process_descriptor = os.dup(stderr_descriptor)
    except Exception:
        os.close(stdout_process_descriptor)
        if owns_descriptors:
            _close_descriptors(stdout_descriptor, stderr_descriptor)
        raise
    try:
        with (
            os.fdopen(stdout_process_descriptor, "r+b") as stdout_file,
            os.fdopen(stderr_process_descriptor, "r+b") as stderr_file,
        ):
            try:
                process = subprocess.Popen(  # noqa: S603 - operator-supplied argv is the contract
                    argv,
                    cwd=cwd,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                message = f"host-exec: command not found: {exc}\n"
                stderr_file.write(message.encode("utf-8", errors="replace"))
                stderr_file.flush()
                return 127, "", message, False

            registered = False
            registered_ownership: host_processes.ProcessOwnership | None = None
            return_code = int(process.returncode) if process.returncode is not None else 1
            timed_out = False
            communicated = False
            captured_stdout = ""
            captured_stderr = ""
            try:
                registered_ownership = host_processes.capture_process_ownership(
                    process.pid
                )
                host_processes.register_owned_process(
                    engagement_dir,
                    run_uuid=run_uuid,
                    pid=process.pid,
                    ownership=registered_ownership,
                )
                registered = True
            except Exception as exc:
                if registered_ownership is not None:
                    if not host_processes.terminate_owned_process(
                        registered_ownership
                    ):
                        raise HostProcessNotQuiescent(
                            "cannot establish quiescence after host-process "
                            f"registration failed for run_uuid={run_uuid}; "
                            "recording its output as untrusted"
                        ) from exc
                    raise

                # Identity capture can lose a race with a very short-lived
                # command. Completed output is trustworthy only when the leader
                # is reaped and the process group is confirmed absent: an exited
                # leader may otherwise have left descendants behind.
                if (
                    process.poll() is not None
                    and _host_process_group_alive(process.pid) is False
                ):
                    captured_stdout, captured_stderr = process.communicate(timeout=1)
                    communicated = True
                    return_code = int(process.returncode)
                else:
                    raise HostProcessNotQuiescent(
                        "cannot establish ownership after host-process "
                        f"registration failed for run_uuid={run_uuid}; "
                        "recording its output as untrusted"
                    ) from exc

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
            except BaseException:
                # ``communicate`` can fail independently of the child. Reap the
                # leader first, then the registry-backed finally block proves
                # that no descendant remains before the exception can escape.
                _terminate_process_group(process)
                raise
            finally:
                if registered:
                    _quiesce_registered_host_process(
                        engagement_dir=engagement_dir,
                        run_uuid=run_uuid,
                        ownership=registered_ownership,
                    )

            stdout_text = _bounded_descriptor_preview(stdout_file, stdout_path)
            stderr_text = _bounded_descriptor_preview(stderr_file, stderr_path)
            if not stdout_text and captured_stdout:
                stdout_text = _bounded_text(captured_stdout)
            if not stderr_text and captured_stderr:
                stderr_text = _bounded_text(captured_stderr)

        return return_code, stdout_text, stderr_text, timed_out
    finally:
        if owns_descriptors:
            _close_descriptors(stdout_descriptor, stderr_descriptor)


def _host_process_group_alive(process_group: int) -> bool | None:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return None
    return True


def _wait_for_host_process_group_exit(process_group: int, deadline: float) -> bool:
    while True:
        alive = _host_process_group_alive(process_group)
        if alive is False:
            return True
        if alive is None or time.monotonic() >= deadline:
            return False
        time.sleep(min(0.05, max(deadline - time.monotonic(), 0)))


def _terminate_process_group(process: subprocess.Popen) -> tuple[str, str]:
    """Boundedly terminate, reap, and prove exit of a newly owned process group."""
    process_group = int(process.pid)
    try:
        observed_group = os.getpgid(process.pid)
    except ProcessLookupError:
        observed_group = None
    except (PermissionError, OSError) as exc:
        raise HostProcessNotQuiescent(
            f"cannot verify host process group for pid={process.pid}"
        ) from exc
    if observed_group is not None and int(observed_group) != process_group:
        raise HostProcessNotQuiescent(
            f"host process pid={process.pid} no longer owns its process group"
        )

    captured_stdout = ""
    captured_stderr = ""
    for sig, grace in (
        (signal.SIGTERM, _PROCESS_TERM_GRACE_SECONDS),
        (signal.SIGKILL, _PROCESS_KILL_GRACE_SECONDS),
    ):
        alive = _host_process_group_alive(process_group)
        if alive is False:
            try:
                stdout_text, stderr_text = process.communicate(timeout=1)
                captured_stdout = stdout_text or captured_stdout
                captured_stderr = stderr_text or captured_stderr
            except subprocess.TimeoutExpired:
                pass
            return captured_stdout, captured_stderr
        if alive is None:
            raise HostProcessNotQuiescent(
                f"cannot verify host process group pgid={process_group}"
            )
        deadline = time.monotonic() + grace
        try:
            os.killpg(process_group, sig)
        except ProcessLookupError:
            return captured_stdout, captured_stderr
        except (PermissionError, OSError) as exc:
            raise HostProcessNotQuiescent(
                f"cannot terminate host process group pgid={process_group}"
            ) from exc
        try:
            stdout_text, stderr_text = process.communicate(timeout=grace)
            captured_stdout = stdout_text or captured_stdout
            captured_stderr = stderr_text or captured_stderr
        except subprocess.TimeoutExpired:
            pass
        if _wait_for_host_process_group_exit(process_group, deadline):
            return captured_stdout, captured_stderr
    raise HostProcessNotQuiescent(
        f"host process group pgid={process_group} survived bounded termination"
    )


def _quiesce_registered_host_process(
    *,
    engagement_dir: str,
    run_uuid: str,
    ownership: host_processes.ProcessOwnership | None,
) -> None:
    """Prove exit from the immutable ownership token captured after spawn."""
    try:
        quiescent = ownership is not None and host_processes.terminate_owned_process(
            ownership
        )
    except Exception as exc:  # noqa: BLE001 - output must fail closed
        raise HostProcessNotQuiescent(
            "cannot establish quiescence for registered host process "
            f"run_uuid={run_uuid}; recording its output as untrusted"
        ) from exc
    if not quiescent:
        raise HostProcessNotQuiescent(
            "cannot establish quiescence for registered host process "
            f"run_uuid={run_uuid}; recording its output as untrusted"
        )

    try:
        host_processes.unregister_process(engagement_dir, run_uuid=run_uuid)
    except OSError:
        # Process-group exit is the output-integrity boundary. A stale registry
        # record remains visible to orphan reconciliation but cannot mutate output.
        pass


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
            "host_record_kind": "policy_refusal",
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
            "stdout_path": None,
            "stderr_path": None,
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

    finding_ref = str(getattr(args, "finding", "") or "").strip()
    resolved_finding_id: int | None = None
    if finding_ref:
        finding_client = AssessmentClient(cfg.base_url, cfg.engagement_key)
        try:
            resolved_finding_id = _resolve_finding_id(finding_client, finding_ref)
        except Exception as exc:  # noqa: BLE001 - explicit linkage is mandatory
            print(
                f"[host-exec] ERROR: explicit finding {finding_ref!r} could not "
                f"be resolved -- {exc}; refusing execution.",
                file=sys.stderr,
            )
            try:
                finding_client.close()
            except Exception:  # noqa: BLE001 - preserve the fail-closed exit
                pass
            sys.exit(4)
        finding_client.close()

    stdout_descriptor: int | None = None
    stderr_descriptor: int | None = None
    try:
        output_directory_descriptor = _open_host_exec_output_directory(
            cfg.engagement_dir
        )
        try:
            stdout_descriptor, stderr_descriptor = _create_output_spills(
                stdout_path,
                stderr_path,
                directory_descriptor=output_directory_descriptor,
            )
            stdout_spill_device, stdout_spill_inode = _spill_identity_claim(
                stdout_descriptor, stdout_path
            )
            stderr_spill_device, stderr_spill_inode = _spill_identity_claim(
                stderr_descriptor, stderr_path
            )
        finally:
            os.close(output_directory_descriptor)
    except Exception as exc:  # noqa: BLE001 - fail closed before the audit row
        _close_descriptors(stdout_descriptor, stderr_descriptor)
        print(f"host-exec: could not create output spills: {exc}", file=sys.stderr)
        sys.exit(1)

    assert stdout_descriptor is not None
    assert stderr_descriptor is not None

    command_str = " ".join(argv)
    notes = _build_notes(args.scope_host, execution_policy)

    pre_payload: dict = {
        "host_record_kind": "pre_exec",
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
        "stdout_spill_device": stdout_spill_device,
        "stdout_spill_inode": stdout_spill_inode,
        "stderr_spill_device": stderr_spill_device,
        "stderr_spill_inode": stderr_spill_inode,
        "timeout_seconds_requested": timeout_seconds,
        "run_uuid": run_uuid,
        "status": "running",
        "auth_context": auth_context,
    }
    if resolved_finding_id is not None:
        pre_payload["finding_id"] = resolved_finding_id

    record_run_id: int | str = ""
    audit_record_failed = False
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        try:
            response = _post_pre_exec_audit(client, pre_payload)
        except Exception as exc:  # noqa: BLE001 - honor require-audit below
            response = None
            audit_record_failed = True
            linkage = " with required finding linkage" if finding_ref else ""
            print(
                f"[host-exec] WARN: pre-exec audit{linkage} failed -- {exc}",
                file=sys.stderr,
            )
        if isinstance(response, dict):
            record_run_id = response.get("run_id") or response.get("id") or ""

        if not record_run_id:
            print(
                "[host-exec] pre-exec audit record was not confirmed; refusing execution",
                file=sys.stderr,
            )
            sys.exit(4)

        stdout_text = ""
        stderr_text = ""
        return_code: int = -1
        timed_out = False
        process_quiescent = True

        try:
            if execution_policy.get("target_facing"):
                emit_foreign_lane_recency(
                    client, current_agent=str(pre_payload["agent_name"] or "operator")
                )
            return_code, stdout_text, stderr_text, timed_out = _run_host_process(
                argv,
                cwd=cwd,
                timeout_seconds=timeout_seconds,
                engagement_dir=cfg.engagement_dir,
                run_uuid=run_uuid,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                stdout_descriptor=stdout_descriptor,
                stderr_descriptor=stderr_descriptor,
            )
        except HostProcessNotQuiescent as exc:
            return_code = 1
            process_quiescent = False
            audit_record_failed = True
            stderr_text = f"host-exec: {exc}\n"
            print(f"[host-exec] WARN: {exc}", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 - finalize the running audit row
            return_code = 1
            stderr_text = f"host-exec: process setup failed: {exc}\n"
            try:
                _append_spill_text(stderr_descriptor, stderr_path, stderr_text)
            except Exception as append_exc:  # noqa: BLE001 - finalization must still run
                stderr_text = _bounded_text(
                    stderr_text
                    + f"host-exec: could not append failure to stderr spill: {append_exc}\n"
                )

        completed_at = _utcnow_iso()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)
        success = (return_code == 0) and not timed_out
        console_output_failed = False

        finalize_payload: dict = {
            "return_code": return_code,
            "timed_out": timed_out,
            "ended_at": completed_at,
            "duration_ms": duration_ms,
            "stdout_preview": stdout_text,
            "stderr_preview": stderr_text,
            "status": (
                "lost"
                if not process_quiescent
                else ("timed_out" if timed_out else ("completed" if success else "failed"))
            ),
            "partial_results": bool(stdout_text or stderr_text) and not success,
            "output_quiesced": process_quiescent,
        }
        if record_run_id:
            try:
                finalized = _validate_terminal_finalize_response(
                    client.patch(
                        f"command-runs/{record_run_id}",
                        finalize_payload,
                        accept_409=True,
                    ),
                    {
                        **finalize_payload,
                        "id": int(record_run_id),
                        "run_uuid": run_uuid,
                    },
                )
                if isinstance(finalized, dict):
                    for label in ("cleanup", "integrity"):
                        output_status = str(
                            finalized.get(f"output_{label}_status") or ""
                        ).strip().lower()
                        output_warning = str(
                            finalized.get(f"output_{label}_warning") or ""
                        ).strip()
                        detail = f": {output_warning}" if output_warning else ""
                        if output_status in {"warning", "pending"}:
                            audit_record_failed = True
                            print(
                                f"[host-exec] WARN: output {label} is "
                                f"{output_status}{detail}",
                                file=sys.stderr,
                            )
                        elif label == "cleanup" and output_status == "deferred":
                            audit_record_failed = True
                            print(
                                f"[host-exec] WARN: output cleanup is deferred{detail}",
                                file=sys.stderr,
                            )
            except Exception as exc:  # noqa: BLE001
                audit_record_failed = True
                print(f"[host-exec] WARN: audit finalize failed -- {exc}", file=sys.stderr)

        # Console delivery cannot precede or prevent durable finalization.
        if process_quiescent:
            try:
                if stdout_text:
                    sys.stdout.write(stdout_text)
                    sys.stdout.flush()
                if stderr_text:
                    sys.stderr.write(stderr_text)
                    sys.stderr.flush()
            except OSError as exc:
                console_output_failed = True
                try:
                    print(
                        f"[host-exec] WARN: console output failed after audit finalize -- {exc}",
                        file=sys.stderr,
                    )
                except OSError:
                    pass
    finally:
        try:
            client.close()
        finally:
            _close_descriptors(stdout_descriptor, stderr_descriptor)

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

    sys.exit(1 if console_output_failed and return_code == 0 else return_code)
