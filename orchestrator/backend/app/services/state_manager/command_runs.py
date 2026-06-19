from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import sqlite3
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404
from ..search import (
    fts_escape as _fts_escape_shared,
    expanded_fts_query,
    finding_aliases_in_text,
)

from . import _common
from ._common import (
    _remove_written_command_run_artifacts,
    COMMAND_RUN_TERMINAL_STATUSES as _FINALIZE_TERMINAL_STATUSES,
    COMMAND_RUN_FINALIZE_ALLOWED_STATUSES as _FINALIZE_ALLOWED_STATUSES,
    COMMAND_RUN_MUTABLE_STATUSES as _FINALIZE_MUTABLE_STATUSES,
    JOB_STATUSES as _JOB_VALID_STATUSES,
    JOB_TERMINAL_STATUSES as _JOB_TERMINAL_STATUSES,
    JOB_PRE_TERMINAL_STATUSES as _JOB_PRE_TERMINAL_STATUSES,
)



# ── Command-run audit ───────────────────────────────────────────────

_DEFAULT_PREVIEW_BYTES = 65_536

_DEFAULT_RETENTION_CONFIG = Path(__file__).resolve().parents[2] / "config" / "command_run_retention.json"

_RUN_UUID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_ARTIFACT_LABEL_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")

@lru_cache(maxsize=1)
def _retention_config() -> dict[str, Any]:
    override = os.environ.get("COMMAND_RUN_RETENTION_CONFIG")
    path = Path(override) if override else _DEFAULT_RETENTION_CONFIG
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {"preview_bytes": _DEFAULT_PREVIEW_BYTES, "suppress_patterns": []}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"preview_bytes": _DEFAULT_PREVIEW_BYTES, "suppress_patterns": []}
    try:
        preview = int(data.get("preview_bytes") or _DEFAULT_PREVIEW_BYTES)
    except (TypeError, ValueError):
        preview = _DEFAULT_PREVIEW_BYTES
    if preview <= 0:
        preview = _DEFAULT_PREVIEW_BYTES
    patterns: list[dict[str, Any]] = []
    for entry in data.get("suppress_patterns") or []:
        if not isinstance(entry, dict):
            continue
        regex_src = entry.get("command_regex", "")
        if not regex_src:
            continue
        try:
            compiled = re.compile(regex_src)
        except re.error:
            continue
        patterns.append(
            {
                "tool_name": entry.get("tool_name", "*"),
                "reason": entry.get("reason", "suppressed"),
                "regex": compiled,
            }
        )
    return {"preview_bytes": preview, "suppress_patterns": patterns}

def _match_suppress_rule(command: str, tool_name: str) -> dict[str, Any] | None:
    config = _retention_config()
    for rule in config["suppress_patterns"]:
        if rule["tool_name"] not in ("*", tool_name):
            continue
        if rule["regex"].search(command):
            return rule
    return None

def _apply_output_retention(
    stream_bytes: bytes,
    *,
    suppression_reason: str,
    preview_bytes: int,
    artifact_writer,
    artifact_label: str,
) -> dict[str, Any]:
    size = len(stream_bytes)
    sha = hashlib.sha256(stream_bytes).hexdigest() if size else ""
    result: dict[str, Any] = {
        "sha256": sha,
        "bytes": size,
        "preview": "",
        "suppression_reason": "",
        "artifact_ref": "",
        "status": "empty",
    }
    if size == 0:
        return result
    if suppression_reason:
        result["suppression_reason"] = suppression_reason
        result["status"] = "suppressed"
        return result
    if size <= preview_bytes:
        result["preview"] = stream_bytes.decode("utf-8", errors="replace")
        result["status"] = "retained"
        return result
    # large — store preview + full artifact
    result["preview"] = stream_bytes[:preview_bytes].decode("utf-8", errors="replace")
    artifact_ref = artifact_writer(artifact_label, stream_bytes)
    result["artifact_ref"] = artifact_ref
    result["status"] = "artifact"
    return result

def _write_command_run_artifact(
    engagement_artifact_dir: str | None,
    run_uuid: str,
) -> Any:
    """Return a closure(label, bytes) → artifact_ref. Empty string when
    disabled. ``engagement_artifact_dir`` is the exact directory files
    land in — callers and the resolver are responsible for any subdir
    conventions (e.g. ``<root>/scans/command-runs/``)."""

    if not engagement_artifact_dir:

        def _noop(_label: str, _data: bytes) -> str:
            return ""

        return _noop

    base = Path(engagement_artifact_dir).expanduser().resolve()

    def _write(label: str, data: bytes) -> str:
        if not _ARTIFACT_LABEL_RE.fullmatch(label):
            raise RuntimeError(f"invalid command-run artifact label: {label}")
        base.mkdir(parents=True, exist_ok=True)
        target = (base / f"{run_uuid}.{label}.log").resolve()
        if target.parent != base:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="command-run artifact path escaped its base directory",
            )
        try:
            with target.open("xb") as handle:
                handle.write(data)
        except FileExistsError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="command-run artifact already exists for run_uuid",
            ) from exc
        return str(target)

    return _write

def _ensure_command_run_uuid_available(run_uuid: str) -> None:
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT id FROM assessment_command_runs WHERE run_uuid = ?",
            (run_uuid,),
        ).fetchone()
    if row:
        _raise_duplicate_command_run_uuid()

def _raise_duplicate_command_run_uuid() -> None:
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="command-run run_uuid already exists",
    )

def _normalize_run_uuid(value: str) -> str:
    run_uuid = str(value or "").strip()
    if not _RUN_UUID_RE.fullmatch(run_uuid):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run_uuid must contain only letters, numbers, underscores, or hyphens",
        )
    return run_uuid

_SHELL_TOOL_WRAPPERS = {"bash", "dash", "ksh", "sh", "zsh"}

_PREFIX_TOOL_WRAPPERS = {
    "command",
    "env",
    "gtimeout",
    "ionice",
    "nice",
    "nohup",
    "stdbuf",
    "sudo",
    "timeout",
}

_SINGLE_ARG_WRAPPER_OPTIONS = {
    "env": {"-C", "--chdir", "-S", "--split-string", "-u", "--unset"},
    "gtimeout": {"-k", "--kill-after", "-s", "--signal"},
    "ionice": {"-c", "--class", "-n", "--classdata"},
    "nice": {"-n", "--adjustment"},
    "stdbuf": {"-e", "-i", "-o"},
    "sudo": {"-C", "-g", "-h", "-p", "-r", "-T", "-t", "-u"},
    "timeout": {"-k", "--kill-after", "-s", "--signal"},
}

_TIMEOUT_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")

_SHELL_COMMAND_SEPARATORS = {"&&", "||", ";", "|", "|&", "&"}

_SHELL_PREAMBLE_BUILTINS = {
    ".",
    "alias",
    "cd",
    "export",
    "local",
    "popd",
    "pushd",
    "readonly",
    "set",
    "shopt",
    "source",
    "typeset",
    "ulimit",
    "umask",
    "unalias",
    "unset",
}

def _shell_tokens(command: str) -> list[str]:
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return command.split()

def _is_env_assignment(token: str) -> bool:
    if "=" not in token:
        return False
    name, _value = token.split("=", 1)
    return bool(name) and name.replace("_", "").isalnum()

def _strip_wrapper_options(wrapper: str, tokens: list[str]) -> list[str]:
    remaining = list(tokens)
    options_with_arg = _SINGLE_ARG_WRAPPER_OPTIONS.get(wrapper, set())
    while remaining:
        token = remaining[0]
        if wrapper == "env" and _is_env_assignment(token):
            remaining.pop(0)
            continue
        if not token.startswith("-") or token == "-":
            break
        option = remaining.pop(0)
        option_name = option.split("=", 1)[0]
        if option_name in options_with_arg and "=" not in option and remaining:
            remaining.pop(0)
    if wrapper in {"timeout", "gtimeout"} and remaining and _TIMEOUT_DURATION_RE.fullmatch(remaining[0]):
        remaining.pop(0)
    return remaining

def _derive_tool_bin_from_tokens(tokens: list[str], *, depth: int = 0) -> str:
    if depth > 4:
        return ""
    remaining = list(tokens)
    while remaining:
        token = remaining.pop(0).strip()
        if not token:
            continue
        if _is_env_assignment(token):
            continue
        bare = Path(token).name
        if bare in _SHELL_TOOL_WRAPPERS:
            for idx, arg in enumerate(remaining):
                if _is_shell_command_string_flag(arg):
                    if idx + 1 < len(remaining):
                        return _derive_tool_bin_from_tokens(
                            _shell_tokens(remaining[idx + 1]),
                            depth=depth + 1,
                        )
                    break
            return bare
        if bare in _PREFIX_TOOL_WRAPPERS:
            remaining = _strip_wrapper_options(bare, remaining)
            continue
        if bare in _SHELL_PREAMBLE_BUILTINS:
            post_preamble = _skip_shell_preamble_tokens(remaining)
            if post_preamble is not None:
                remaining = post_preamble
                continue
        return bare.split(";", 1)[0].split("|", 1)[0].strip() or bare
    return ""

def _is_shell_command_string_flag(arg: str) -> bool:
    if not arg.startswith("-"):
        return False
    if arg == "-c":
        return True
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    short_flags = arg[1:]
    return bool(short_flags) and short_flags.endswith("c") and set(short_flags) <= {"l", "i", "s", "r", "c"}

def _skip_shell_preamble_tokens(tokens: list[str]) -> list[str] | None:
    for idx, token in enumerate(tokens):
        if token in _SHELL_COMMAND_SEPARATORS:
            return tokens[idx + 1 :]
    return None

def _derive_tool_bin(command: str, argv: list[str] | None) -> str:
    """Return the first executable token of the command. The route-derived
    ``tool_name`` collapses every /api/command call to ``command``; tool_bin
    is the discriminator (cat vs curl vs sqlmap) that operator filtering
    actually needs."""
    if argv:
        derived = _derive_tool_bin_from_tokens([str(token) for token in argv])
        if derived:
            return derived
    text = (command or "").strip()
    if not text:
        return ""
    derived = _derive_tool_bin_from_tokens(_shell_tokens(text))
    return derived or text.split()[0]

def _resolve_artifact_dir(engagement, override: str | None) -> str | None:
    root = getattr(engagement, "engagement_root", "") or ""
    if not root:
        return None
    engagement_root = Path(root).expanduser().resolve()
    if override:
        candidate = Path(override).expanduser().resolve()
        try:
            candidate.relative_to(engagement_root)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="engagement_artifact_dir must be inside the engagement root",
            ) from exc
        if candidate == engagement_root:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="engagement_artifact_dir must be an engagement-root subdirectory",
            )
        return str(candidate)
    return str(engagement_root / "scans" / "command-runs")

_DEFAULT_DEDUP_WINDOW_SECONDS = 30

def _dedup_window_seconds() -> int:
    raw = os.environ.get("KALI_AUDIT_DEDUP_WINDOW_SECONDS", "")
    if not raw:
        return _DEFAULT_DEDUP_WINDOW_SECONDS
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_DEDUP_WINDOW_SECONDS
    return max(value, 0)

def _find_dedup_predecessor(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    command: str,
    argv_json: str,
    window_seconds: int,
) -> int | None:
    if window_seconds <= 0:
        return None
    cutoff = (
        f"datetime('now', '-{int(window_seconds)} seconds')"
    )
    row = connection.execute(
        f"""
        SELECT id FROM assessment_command_runs
        WHERE engagement_id = ?
          AND command = ?
          AND argv_json = ?
          AND status IN ('queued', 'running')
          AND datetime(created_at) >= {cutoff}
        ORDER BY id DESC
        LIMIT 1
        """,
        (engagement_id, command, argv_json),
    ).fetchone()
    if row is None:
        return None
    return int(row[0])

def record_command_run(
    engagement_id: int,
    *,
    command: str,
    argv: list[str] | None = None,
    tool_name: str,
    route: str = "",
    agent_name: str,
    phase: str,
    return_code: int | None = None,
    timed_out: bool = False,
    success: bool | None = None,
    started_at: str,
    completed_at: str,
    duration_ms: int = 0,
    stdout: str = "",
    stderr: str = "",
    command_hash: str = "",
    stdout_sha256: str = "",
    stderr_sha256: str = "",
    notes: str = "",
    engagement_artifact_dir: str | None = None,
    run_uuid: str | None = None,
    audit_source: str = "header",
    technique: str | None = None,
    intent: str | None = None,
    probe_kind: str | None = None,
    destructive: bool | int | None = None,
    status: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    peak_rss_bytes: int | None = None,
    cpu_user_seconds: float | None = None,
    cpu_system_seconds: float | None = None,
    working_dir: str | None = None,
    scope_version: str | None = None,
    auth_context: str | None = None,
    target_host: str = "",
    timeout_seconds_requested: int | None = None,
    force: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    if not (phase or "").strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="phase is required and cannot be empty",
        )

    run_uuid = _normalize_run_uuid(run_uuid or uuid.uuid4().hex)
    _ensure_command_run_uuid_available(run_uuid)
    command_hash = command_hash or hashlib.sha256(command.encode("utf-8", errors="replace")).hexdigest()
    tool_bin = _derive_tool_bin(command, argv)

    effective_success = bool(success) if success is not None else (return_code == 0 and not timed_out)

    config = _retention_config()
    preview_bytes = int(config["preview_bytes"])

    suppress_rule = _match_suppress_rule(command, tool_name)
    suppress_reason = suppress_rule["reason"] if suppress_rule else ""

    effective_artifact_dir = _resolve_artifact_dir(engagement, engagement_artifact_dir)
    artifact_writer = _write_command_run_artifact(effective_artifact_dir, run_uuid)

    stdout_raw = stdout.encode("utf-8", errors="replace") if isinstance(stdout, str) else bytes(stdout or b"")
    stderr_raw = stderr.encode("utf-8", errors="replace") if isinstance(stderr, str) else bytes(stderr or b"")

    stdout_retention = _apply_output_retention(
        stdout_raw,
        suppression_reason=suppress_reason,
        preview_bytes=preview_bytes,
        artifact_writer=artifact_writer,
        artifact_label="stdout",
    )
    stderr_retention = _apply_output_retention(
        stderr_raw,
        suppression_reason=suppress_reason,
        preview_bytes=preview_bytes,
        artifact_writer=artifact_writer,
        artifact_label="stderr",
    )

    stdout_sha256 = stdout_sha256 or stdout_retention["sha256"]
    stderr_sha256 = stderr_sha256 or stderr_retention["sha256"]

    # Row-level retention status rolls up stream statuses.
    statuses = {stdout_retention["status"], stderr_retention["status"]}
    if "artifact" in statuses:
        row_status = "artifact"
    elif "suppressed" in statuses and "retained" not in statuses:
        row_status = "suppressed"
    elif "retained" in statuses:
        row_status = "retained"
    else:
        row_status = "empty"

    # Normalise the four command-metadata fields. Validation is intentionally
    # soft — the API/runtime layer follows the `audit_source` precedent and
    # stores values verbatim so we can add new technique/probe_kind values
    # without a backend redeploy. We only trim/coerce shape here.
    technique_value: str | None
    if technique is None:
        technique_value = None
    else:
        technique_stripped = str(technique).strip()
        technique_value = technique_stripped or None

    intent_value: str | None
    if intent is None:
        intent_value = None
    else:
        intent_stripped = str(intent).strip()
        intent_value = intent_stripped[:400] or None

    probe_kind_value: str | None
    if probe_kind is None:
        probe_kind_value = None
    else:
        probe_kind_stripped = str(probe_kind).strip()
        probe_kind_value = probe_kind_stripped or None

    destructive_value: int | None
    if destructive is None:
        destructive_value = None
    else:
        destructive_value = 1 if bool(destructive) else 0

    status_value = _infer_command_run_status(
        status,
        return_code=return_code,
        timed_out=timed_out,
        success=success,
    )
    argv_json_value = json.dumps(list(argv) if argv else [], ensure_ascii=False)

    with _common.get_connection() as connection:
        # Dedup-at-write-time: if an in-flight row exists with the same
        # (command, argv_json) for this engagement inside the configurable
        # window, ALWAYS insert a new row but link it to the predecessor via
        # ``superseded_by_id`` so the supersession is a relationship between
        # two rows rather than a row-merge. ``force=True`` is the deliberate-
        # retry escape hatch that suppresses both the warning (CLI-side) and
        # the supersede link (here) — operator says "I know there's a peer,
        # run it anyway as an independent retry."
        #
        # Audit-truthfulness rationale: the previous behavior returned the
        # predecessor's row id on dedup hit. Under the CLI's warn-and-continue
        # default the second subprocess still ran, so two executions collapsed
        # to one audit row and ``list-command-runs`` lied about coverage. By
        # always inserting we get one row per execution attempt; readers that
        # want to filter to "primary" runs can join on
        # ``superseded_by_id IS NULL``. The predecessor lookup itself scans all
        # in-flight peers, including already-linked duplicate rows, so duplicate
        # chains continue when the original primary finishes before later peers.
        superseded_by_id: int | None = None
        if not force:
            superseded_by_id = _find_dedup_predecessor(
                connection,
                engagement_id=engagement.id,
                command=command,
                argv_json=argv_json_value,
                window_seconds=_dedup_window_seconds(),
            )
        try:
            cursor = connection.execute(
                """
                INSERT INTO assessment_command_runs (
                    engagement_id, run_uuid, command, argv_json, tool_name, tool_bin, route,
                    agent_name, phase, audit_source, status,
                    return_code, timed_out, success,
                    started_at, completed_at, duration_ms,
                    command_hash, stdout_sha256, stderr_sha256,
                    stdout_preview, stderr_preview, output_retention_status,
                    stdout_suppression_reason, stderr_suppression_reason,
                    stdout_artifact_ref, stderr_artifact_ref,
                    stdout_bytes, stderr_bytes, notes,
                    technique, intent, probe_kind, destructive,
                    stdout_path, stderr_path,
                    peak_rss_bytes, cpu_user_seconds, cpu_system_seconds,
                    working_dir, scope_version, auth_context, target_host,
                    superseded_by_id, timeout_seconds_requested
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?, ?,
                    ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?,
                    ?, ?, ?,
                    ?, ?, ?, ?,
                    ?, ?
                )
                """,
                (
                    engagement.id,
                    run_uuid,
                    command,
                    argv_json_value,
                    tool_name,
                    tool_bin,
                    route,
                    agent_name,
                    phase,
                    audit_source or "header",
                    status_value,
                    return_code,
                    1 if timed_out else 0,
                    1 if effective_success else 0,
                    started_at,
                    completed_at,
                    int(duration_ms or 0),
                    command_hash,
                    stdout_sha256,
                    stderr_sha256,
                    stdout_retention["preview"],
                    stderr_retention["preview"],
                    row_status,
                    stdout_retention["suppression_reason"],
                    stderr_retention["suppression_reason"],
                    stdout_retention["artifact_ref"],
                    stderr_retention["artifact_ref"],
                    stdout_retention["bytes"],
                    stderr_retention["bytes"],
                    notes,
                    technique_value,
                    intent_value,
                    probe_kind_value,
                    destructive_value,
                    stdout_path,
                    stderr_path,
                    peak_rss_bytes,
                    cpu_user_seconds,
                    cpu_system_seconds,
                    working_dir,
                    scope_version,
                    auth_context,
                    (target_host or "").strip(),
                    superseded_by_id,
                    timeout_seconds_requested,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if "run_uuid" in str(exc):
                _remove_written_command_run_artifacts(
                    str(stdout_retention["artifact_ref"] or ""),
                    str(stderr_retention["artifact_ref"] or ""),
                )
                _raise_duplicate_command_run_uuid()
            raise
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        serialized = _serialize_command_run(row, include_output=True)
        # Surface the dedup relationship to the caller so the CLI can warn-
        # and-continue. ``superseded_by_id`` already lives on the row payload;
        # ``dedup_predecessor_id`` is a separate hint surface so consumers can
        # tell "this row was inserted as a dedup peer" without re-querying the
        # predecessor row to check its status.
        if superseded_by_id is not None:
            serialized["dedup_predecessor_id"] = superseded_by_id
    for artifact_ref in (
        serialized.get("stdout_artifact_ref"),
        serialized.get("stderr_artifact_ref"),
        serialized.get("stdout_path"),
        serialized.get("stderr_path"),
    ):
        _common._register_artifact_reference(
            engagement.id,
            str(artifact_ref or ""),
            kind="command-run-output",
            producer_command_run_id=int(serialized["id"]),
            producer_agent_role=agent_name,
        )
    return serialized

def _infer_command_run_status(
    status_value: str | None,
    *,
    return_code: int | None,
    timed_out: bool,
    success: bool | None,
) -> str:
    explicit = (status_value or "").strip()
    if explicit:
        return explicit
    if timed_out:
        return "timed_out"
    if return_code is not None:
        return "completed" if return_code == 0 else "failed"
    if success is True:
        return "completed"
    if success is False:
        return "failed"
    return "running"

# Status membership sets are now sourced from the CommandRunStatus enum in
# _common (imported above under their original private names).

def finalize_command_run(
    engagement_id: int,
    *,
    command_run_id: int,
    status_value: str,
    return_code: int | None = None,
    ended_at: str,
    duration_ms: int | None = None,
    stdout_preview: str | None = None,
    stderr_preview: str | None = None,
    timed_out: bool = False,
    partial_results: bool = False,
    peak_rss_bytes: int | None = None,
    cpu_user_seconds: float | None = None,
    cpu_system_seconds: float | None = None,
) -> dict[str, Any]:
    """Apply a status update to a pre-exec command-run row.

    Idempotency contract (B4): a row already in a terminal state must not be
    overwritten — the second writer is signalled with HTTP 409 carrying the
    existing row. ``queued`` and ``running`` are mutable pre-terminal states.
    A ``running``-to-``running`` PATCH is a refresh no-op that surfaces
    ``noop=true`` so the caller can distinguish it from a fresh write."""
    engagement = _engagement_or_404(engagement_id)
    if status_value not in _FINALIZE_ALLOWED_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"finalize status must be one of {sorted(str(s) for s in _FINALIZE_ALLOWED_STATUSES)}",
        )
    with _common.get_connection() as connection:
        existing_row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, command_run_id),
        ).fetchone()
        if existing_row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="command run not found",
            )
        existing_status = (existing_row["status"] or "").strip()
        if existing_status in _FINALIZE_TERMINAL_STATUSES:
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} already finalized with "
                        f"status='{existing_status}'; refusing to overwrite"
                    ),
                    "existing": serialized,
                },
            )
        if status_value == "running" and existing_status == "running":
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            return serialized
        if status_value == "running":
            serialized = _serialize_command_run(existing_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} is status='{existing_status or 'unknown'}'; "
                        "running refresh only applies to rows already in status='running'"
                    ),
                    "existing": serialized,
                },
            )
        success_flag = 1 if (status_value == "completed" and (return_code in (0, None) and not timed_out)) else 0
        if return_code is not None and return_code != 0:
            success_flag = 0
        sets: list[str] = [
            "status = ?",
            "completed_at = ?",
            "timed_out = ?",
            "success = ?",
        ]
        values: list[Any] = [
            status_value,
            ended_at,
            1 if timed_out else 0,
            success_flag,
        ]
        if return_code is not None:
            sets.append("return_code = ?")
            values.append(int(return_code))
        if duration_ms is not None:
            sets.append("duration_ms = ?")
            values.append(int(duration_ms))
        if stdout_preview is not None:
            sets.append("stdout_preview = ?")
            values.append(stdout_preview)
        if stderr_preview is not None:
            sets.append("stderr_preview = ?")
            values.append(stderr_preview)
        if peak_rss_bytes is not None:
            sets.append("peak_rss_bytes = ?")
            values.append(int(peak_rss_bytes))
        if cpu_user_seconds is not None:
            sets.append("cpu_user_seconds = ?")
            values.append(float(cpu_user_seconds))
        if cpu_system_seconds is not None:
            sets.append("cpu_system_seconds = ?")
            values.append(float(cpu_system_seconds))
        sets.append("partial_results = ?")
        values.append(1 if partial_results else 0)
        mutable_statuses = tuple(sorted(str(s) for s in _FINALIZE_MUTABLE_STATUSES))
        values.append(command_run_id)
        values.extend(mutable_statuses)
        # Guard against the read→update race when two finalize PATCHes arrive
        # simultaneously: both can pass the SELECT-based terminal check above,
        # but the UPDATE must only land when the row is still pre-terminal.
        # The loser hits rowcount=0 and is funnelled into the same 409 path
        # with the canonical row payload that the SELECT-based check uses.
        mutable_placeholders = ", ".join("?" for _ in mutable_statuses)
        cursor = connection.execute(
            f"UPDATE assessment_command_runs SET {', '.join(sets)} WHERE id = ? AND status IN ({mutable_placeholders})",
            tuple(values),
        )
        if cursor.rowcount == 0:
            current_row = connection.execute(
                "SELECT * FROM assessment_command_runs WHERE id = ?",
                (command_run_id,),
            ).fetchone()
            if current_row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="command run not found",
                )
            serialized = _serialize_command_run(current_row, include_output=True)
            serialized["noop"] = True
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": (
                        f"command run id={command_run_id} already finalized with "
                        f"status='{(current_row['status'] or '').strip()}'; refusing to overwrite"
                    ),
                    "existing": serialized,
                },
            )
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE id = ?",
            (command_run_id,),
        ).fetchone()
        assert row is not None
        return _serialize_command_run(row, include_output=True)

# ── Assessment job lifecycle ────────────────────────────────────────


# Job status membership sets are sourced from the JobStatus enum in _common
# (imported above under their original private names).

def _serialize_job(row) -> dict[str, Any]:
    data = dict(row)
    raw_meta = data.pop("audit_metadata_json", None) or ""
    if raw_meta:
        try:
            data["audit_metadata"] = json.loads(raw_meta)
        except json.JSONDecodeError:
            data["audit_metadata"] = None
    else:
        data["audit_metadata"] = None
    return data

def record_job(
    engagement_id: int,
    *,
    parent_command_run_id: int | None = None,
    status_value: str = "queued",
    started_at: str | None = None,
    ended_at: str | None = None,
    exit_code: int | None = None,
    dtach_socket_path: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    audit_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if status_value not in _JOB_VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"job status must be one of {sorted(str(s) for s in _JOB_VALID_STATUSES)}",
        )
    metadata_json = json.dumps(audit_metadata, ensure_ascii=False) if audit_metadata is not None else None
    with _common.get_connection() as connection:
        if parent_command_run_id is not None:
            row = connection.execute(
                "SELECT id FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
                (engagement.id, int(parent_command_run_id)),
            ).fetchone()
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="parent_command_run_id does not reference an existing command run for this engagement",
                )
        cursor = connection.execute(
            """
            INSERT INTO assessment_jobs (
                engagement_id, parent_command_run_id, status,
                started_at, ended_at, exit_code,
                dtach_socket_path, stdout_path, stderr_path,
                audit_metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                parent_command_run_id,
                status_value,
                started_at,
                ended_at,
                exit_code,
                dtach_socket_path,
                stdout_path,
                stderr_path,
                metadata_json,
            ),
        )
        out_row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert out_row is not None
        return _serialize_job(out_row)

def update_job(
    engagement_id: int,
    *,
    job_id: int,
    status_value: str | None = None,
    started_at: str | None = None,
    ended_at: str | None = None,
    exit_code: int | None = None,
    dtach_socket_path: str | None = None,
    stdout_path: str | None = None,
    stderr_path: str | None = None,
    audit_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    sets: list[str] = []
    values: list[Any] = []
    if status_value is not None:
        if status_value not in _JOB_VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"job status must be one of {sorted(str(s) for s in _JOB_VALID_STATUSES)}",
            )
        sets.append("status = ?")
        values.append(status_value)
    if started_at is not None:
        sets.append("started_at = ?")
        values.append(started_at)
    if ended_at is not None:
        sets.append("ended_at = ?")
        values.append(ended_at)
    if exit_code is not None:
        sets.append("exit_code = ?")
        values.append(int(exit_code))
    if dtach_socket_path is not None:
        sets.append("dtach_socket_path = ?")
        values.append(dtach_socket_path)
    if stdout_path is not None:
        sets.append("stdout_path = ?")
        values.append(stdout_path)
    if stderr_path is not None:
        sets.append("stderr_path = ?")
        values.append(stderr_path)
    if audit_metadata is not None:
        sets.append("audit_metadata_json = ?")
        values.append(json.dumps(audit_metadata, ensure_ascii=False))
    if not sets:
        return get_job(engagement.id, job_id)
    sets.append("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')")
    with _common.get_connection() as connection:
        existing = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="job not found",
            )
        existing_status = str(existing["status"] or "")
        if (
            status_value is not None
            and existing_status in _JOB_TERMINAL_STATUSES
            and status_value != existing_status
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "job already terminal",
                    "existing": _serialize_job(existing),
                },
            )
        where = "WHERE engagement_id = ? AND id = ?"
        where_values: list[Any] = [engagement.id, int(job_id)]
        guard_terminal_update = (
            status_value in _JOB_TERMINAL_STATUSES
            and existing_status in _JOB_PRE_TERMINAL_STATUSES
        )
        if guard_terminal_update:
            pre_terminal_statuses = tuple(sorted(str(s) for s in _JOB_PRE_TERMINAL_STATUSES))
            placeholders = ", ".join("?" for _ in pre_terminal_statuses)
            where += f" AND status IN ({placeholders})"
            where_values.extend(pre_terminal_statuses)
        cursor = connection.execute(
            f"UPDATE assessment_jobs SET {', '.join(sets)} {where}",
            tuple(values + where_values),
        )
        if cursor.rowcount == 0:
            current = connection.execute(
                "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
                (engagement.id, int(job_id)),
            ).fetchone()
            if current is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="job not found",
                )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "message": "job already terminal",
                    "existing": _serialize_job(current),
                },
            )
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE id = ?",
            (int(job_id),),
        ).fetchone()
        assert row is not None
        return _serialize_job(row)

def list_jobs(
    engagement_id: int,
    *,
    status_value: str = "",
    parent_command_run_id: int | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if status_value:
        where.append("status = ?")
        params.append(status_value)
    if parent_command_run_id is not None:
        where.append("parent_command_run_id = ?")
        params.append(int(parent_command_run_id))
    params.extend([int(limit), int(offset)])
    query = (
        f"SELECT * FROM assessment_jobs "
        f"WHERE {' AND '.join(where)} "
        "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [_serialize_job(row) for row in rows]

def get_job(engagement_id: int, job_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_jobs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(job_id)),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="job not found")
    return _serialize_job(row)

def _serialize_command_run(row, *, include_output: bool) -> dict[str, Any]:
    data = dict(row)
    try:
        data["argv"] = json.loads(data.pop("argv_json", None) or "[]")
    except json.JSONDecodeError:
        data["argv"] = []
    data["timed_out"] = bool(data.get("timed_out"))
    data["success"] = bool(data.get("success"))
    # Command-metadata fields — surfaced explicitly so callers don't rely on
    # sqlite3.Row dict coercion to include them. Default to None so rows
    # written before this migration (where dict(row) simply won't have the
    # key if the schema matched pre-ALTER) still serialize with a null
    # present. `destructive` is stored as 0/1 INTEGER; coerce back to a
    # Python bool for API consumers, preserving NULL.
    data["technique"] = data.get("technique")
    data["intent"] = data.get("intent")
    data["probe_kind"] = data.get("probe_kind")
    destructive_raw = data.get("destructive")
    if destructive_raw is None:
        data["destructive"] = None
    else:
        data["destructive"] = bool(destructive_raw)
    data["partial_results"] = bool(data.get("partial_results"))
    if not include_output:
        # Listings default to lightweight rows so a sub-agent fetching 50
        # records does not load 50 × 64 KiB of preview text into context.
        # Hashes, suppression reasons, artifact refs, and byte counts stay
        # so the caller can decide whether a follow-up get-command-run is
        # warranted. The full preview is always available via that detail
        # endpoint or by passing include_output=true on the list call.
        stdout_len = len(data.get("stdout_preview") or "")
        stderr_len = len(data.get("stderr_preview") or "")
        data["stdout_preview"] = ""
        data["stderr_preview"] = ""
        data["stdout_preview_chars"] = stdout_len
        data["stderr_preview_chars"] = stderr_len
    return data

def _fts_escape(term: str) -> str:
    """Back-compat shim; real implementation lives in ``services.search``."""
    return _fts_escape_shared(term)

def list_command_runs(
    engagement_id: int,
    *,
    q: str = "",
    agent_name: str = "",
    phase: str = "",
    tool_name: str = "",
    tool_bin: str = "",
    target_host: str = "",
    audit_source: str = "",
    route: str = "",
    success: bool | None = None,
    timed_out: bool | None = None,
    technique: str = "",
    probe_kind: str = "",
    destructive: bool | None = None,
    intent_q: str = "",
    sort: str = "",
    exact: bool = False,
    require_all: bool = False,
    show_matches: bool = False,
    limit: int = 100,
    offset: int = 0,
    include_output: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)

    # Track WHERE filters as (clause, params) tuples so the distant-search
    # helper can drop the MATCH filter cleanly. Positional zip() against a
    # flat base_params list breaks when a filter takes >1 param.
    filters: list[tuple[str, list[Any]]] = [("r.engagement_id = ?", [engagement.id])]

    # ``q`` is a global FTS match across all content columns. ``intent_q`` is
    # a scoped FTS match against the intent column only — SQLite FTS5 uses
    # the ``column:term`` syntax for this. When both are provided the
    # queries are AND-combined via an additional MATCH (FTS5 supports two
    # MATCH clauses against the same virtual table via two JOINs; simpler
    # here is to merge them into a single MATCH term joined with AND).
    join_sql = ""
    match_terms: list[str] = []
    fts_term = expanded_fts_query(q, exact=exact, require_all=require_all) if q else ""
    if fts_term:
        match_terms.append(fts_term)
    intent_term = _fts_escape(intent_q) if intent_q else ""
    if intent_term:
        # Scope every escaped token to the intent column. ``_fts_escape``
        # returns space-separated quoted phrases (implicit AND); prefixing
        # each with ``intent:`` restricts the match to that column.
        scoped_tokens = [f"intent:{tok}" for tok in intent_term.split(" ") if tok]
        if scoped_tokens:
            match_terms.append(" ".join(scoped_tokens))
    match_filter: tuple[str, list[Any]] | None = None
    if match_terms:
        join_sql = "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id"
        match_filter = ("assessment_command_runs_fts MATCH ?", [" ".join(match_terms)])
        filters.append(match_filter)

    if agent_name:
        filters.append(("r.agent_name = ?", [agent_name]))
    if phase:
        filters.append(("r.phase = ?", [phase]))
    if tool_name:
        filters.append(("r.tool_name = ?", [tool_name]))
    if tool_bin:
        filters.append(("r.tool_bin = ?", [tool_bin]))
    if target_host:
        # Case-insensitive exact match against the parsed target_host column.
        # NULL-tolerant (LOWER(NULL) = NULL, which will not match the literal).
        filters.append(("LOWER(r.target_host) = ?", [target_host.strip().lower()]))
    if audit_source:
        filters.append(("r.audit_source = ?", [audit_source]))
    if route:
        # Provenance-lane filter so host-side katana/httpx coverage is visible.
        # host-exec rows are stamped route='host_exec'; container/kali typed-verb
        # rows are stamped route='vigil assess kali/<tool>'. 'kali' is therefore a
        # prefix match, 'host_exec' an exact match, and any other value an exact
        # match against the stored route string.
        if route == "kali":
            # Transitional back-compat: rows recorded before the aith->vigil
            # rename are stamped route='aith assess kali/<tool>'. Match both
            # the new prefix and the old one so pre-rename rows still return.
            filters.append(
                ("(r.route LIKE 'vigil assess kali/%' OR r.route LIKE 'aith assess kali/%')", [])
            )
        else:
            filters.append(("r.route = ?", [route]))
    if success is not None:
        filters.append(("r.success = ?", [1 if success else 0]))
    if timed_out is not None:
        filters.append(("r.timed_out = ?", [1 if timed_out else 0]))
    if technique:
        filters.append(("r.technique = ?", [technique]))
    if probe_kind:
        filters.append(("r.probe_kind = ?", [probe_kind]))
    if destructive is not None:
        filters.append(("r.destructive = ?", [1 if destructive else 0]))

    base_where = [clause for clause, _ in filters]
    base_params: list[Any] = [param for _, params in filters for param in params]

    sort_value = (sort or "").strip().lower()
    if not sort_value:
        sort_value = "relevance" if match_terms else "recent"
    if sort_value not in {"relevance", "recent", "distant"}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid command-run sort: {sort}")

    if sort_value == "distant":
        return _list_distant_command_runs(
            engagement.id,
            q=q,
            filters=filters,
            match_filter=match_filter,
            match_terms=match_terms,
            limit=limit,
            offset=offset,
            include_output=include_output,
            show_matches=show_matches,
            exact=exact,
        )

    params = list(base_params)
    params.extend([int(limit), int(offset)])
    rank_select = ", bm25(assessment_command_runs_fts) AS search_rank" if match_terms else ""
    if sort_value == "relevance" and match_terms:
        order_sql = "ORDER BY search_rank ASC, r.created_at DESC, r.id DESC"
    else:
        order_sql = "ORDER BY r.created_at DESC, r.id DESC"
    query = (
        f"SELECT r.*{rank_select} FROM assessment_command_runs r {join_sql} "
        f"WHERE {' AND '.join(base_where)} "
        f"{order_sql} LIMIT ? OFFSET ?"
    )

    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    return [
        _serialize_command_run_with_matches(row, include_output=include_output, q=q, show_matches=show_matches, exact=exact)
        for row in rows
    ]

def _list_distant_command_runs(
    engagement_id: int,
    *,
    q: str,
    filters: list[tuple[str, list[Any]]],
    match_filter: tuple[str, list[Any]] | None,
    match_terms: list[str],
    limit: int,
    offset: int,
    include_output: bool,
    show_matches: bool,
    exact: bool = False,
) -> list[dict[str, Any]]:
    """Return nonmatching rows in the same inferred command scope.

    This is a coverage-gap view: first find direct matches, infer scope from
    their structured fields, then list older/nonmatching command families in
    that scope.
    """

    distant_filters = [(clause, list(params)) for clause, params in filters if (clause, params) != match_filter]
    if not distant_filters:
        distant_filters = [("r.engagement_id = ?", [engagement_id])]
    distant_where = [clause for clause, _ in distant_filters]
    distant_params: list[Any] = [p for _, ps in distant_filters for p in ps]

    direct_rows: list[Any] = []
    direct_ids: list[int] = []
    if match_terms:
        base_where = [clause for clause, _ in filters]
        base_params = [p for _, ps in filters for p in ps]
        direct_query = (
            "SELECT r.* FROM assessment_command_runs r "
            "JOIN assessment_command_runs_fts ON assessment_command_runs_fts.rowid = r.id "
            f"WHERE {' AND '.join(base_where)} "
            "ORDER BY r.created_at DESC, r.id DESC LIMIT 200"
        )
        with _common.get_connection() as connection:
            direct_rows = connection.execute(direct_query, tuple(base_params)).fetchall()
        direct_ids = [int(row["id"]) for row in direct_rows]

    if direct_ids:
        placeholders = ", ".join("?" for _ in direct_ids)
        distant_where.append(f"r.id NOT IN ({placeholders})")
        distant_params.extend(direct_ids)
        scope_clauses: list[str] = []
        for column in ("target_host", "tool_bin", "technique", "probe_kind", "phase"):
            values = sorted({str(row[column] or "") for row in direct_rows if str(row[column] or "").strip()})
            if values:
                scope_placeholders = ", ".join("?" for _ in values)
                scope_clauses.append(f"r.{column} IN ({scope_placeholders})")
                distant_params.extend(values)
        if scope_clauses:
            distant_where.append("(" + " OR ".join(scope_clauses) + ")")
    elif match_terms:
        # No direct match means there is no safe inferred scope. Return no
        # distant rows rather than flooding resume output with unrelated runs.
        return []

    distant_params.extend([int(limit), int(offset)])
    query = (
        "SELECT r.* FROM assessment_command_runs r "
        f"WHERE {' AND '.join(distant_where)} "
        "ORDER BY r.created_at ASC, r.id ASC LIMIT ? OFFSET ?"
    )
    with _common.get_connection() as connection:
        rows = connection.execute(query, tuple(distant_params)).fetchall()
    return [
        _serialize_command_run_with_matches(row, include_output=include_output, q=q, show_matches=show_matches, exact=exact)
        for row in rows
    ]

def _serialize_command_run_with_matches(
    row,
    *,
    include_output: bool,
    q: str,
    show_matches: bool,
    exact: bool = False,
) -> dict[str, Any]:
    data = _serialize_command_run(row, include_output=include_output)
    if show_matches:
        data["matches"] = _command_run_match_reasons(data, q, exact=exact)
    return data

def _command_run_match_reasons(row: dict[str, Any], q: str, *, exact: bool = False) -> list[str]:
    reasons: list[str] = []
    # In exact mode the FTS query is the user's raw phrase only — alias
    # expansion never ran, so attributing the match to an alias would be
    # misleading. Plain-token reasons still apply because the input phrase
    # itself was searched.
    if not exact:
        aliases = finding_aliases_in_text(q)
        if aliases:
            for canonical, values in aliases.items():
                needle_values = {value.lower() for value in values}
                for field in (
                    "command",
                    "tool_name",
                    "tool_bin",
                    "agent_name",
                    "phase",
                    "notes",
                    "intent",
                    "technique",
                    "stdout_suppression_reason",
                    "stderr_suppression_reason",
                    "stdout_artifact_ref",
                    "stderr_artifact_ref",
                ):
                    value = str(row.get(field) or "").lower()
                    if value and any(needle in value for needle in needle_values):
                        reasons.append(f"finding_alias:{canonical}:{field}")
    plain_terms = [term.lower() for term in str(q or "").split() if len(term) >= 3]
    for field in ("command", "tool_name", "tool_bin", "agent_name", "phase", "notes", "intent", "technique"):
        value = str(row.get(field) or "").lower()
        for term in plain_terms:
            if term in value:
                reasons.append(f"token:{term}:{field}")
                break
    return sorted(set(reasons))

def get_command_run(engagement_id: int, command_run_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_command_runs WHERE engagement_id = ? AND id = ?",
            (engagement.id, int(command_run_id)),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="command run not found")
    return _serialize_command_run(row, include_output=True)

# ── Host liveness ledger ──────────────────────────────────────────────────
# Authoritative per-host reachability, upserted from httpx probes via
# `vigil assess ingest-httpx`. A verdict older than the TTL is reported as
# 'stale' by the read projection (not stored as 'stale'), forcing a re-probe
# rather than trusting it across the shifting-egress boundary (§9).
_HOST_LIVENESS_TTL_SECONDS = 120 * 60  # 2h

_HOST_LIVENESS_DECAYS = frozenset({"live", "blackholed", "dead"})

def _normalize_liveness_host(value: str) -> str:
    """Canonical liveness key: lowercased, scheme- and port-stripped authority.

    Must stay byte-for-byte in sync with ``discovery.normalize_host`` (CLI side)
    so a GET ?host= lookup matches stored rows.
    """
    h = (value or "").strip().lower().rstrip(".")
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    if h.startswith("["):  # [ipv6](:port)?
        end = h.find("]")
        if end != -1:
            h = h[: end + 1]
    elif h.count(":") == 1:
        # exactly one colon → host:port (a bare IPv6 has >=2 colons; leave it intact)
        h = h.split(":", 1)[0]
    return h

def _parse_probed_at(probed_at):
    """Parse an ISO probed_at into an aware UTC datetime, or None."""
    import datetime as _dt

    if not probed_at:
        return None
    raw = str(probed_at).strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        parsed = _dt.datetime.fromisoformat(raw)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed.astimezone(_dt.timezone.utc)

def _canonical_probed_at(probed_at):
    """Normalize probed_at to a single lexicographically-sortable UTC form so the
    keep-newest TEXT comparison in the upsert is correct across mixed input
    formats (fractional precision, ``+HH:MM`` offsets, naive). Returns None when
    unparseable/empty (the upsert then treats it as "no probe time")."""
    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return parsed.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

def _liveness_age_seconds(probed_at) -> float | None:
    import datetime as _dt

    parsed = _parse_probed_at(probed_at)
    if parsed is None:
        return None
    return (_dt.datetime.now(_dt.timezone.utc) - parsed).total_seconds()

def upsert_host_liveness(engagement_id: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Bulk-upsert host-liveness rows keyed by (engagement, host).

    The caller (ingest-httpx) supplies the already-classified ``reachability_class``
    — the backend stores it verbatim and keeps the newest probe per host (an
    incoming row with an older ``probed_at`` does not overwrite a newer one).
    """
    _engagement_or_404(engagement_id)
    upserted = 0
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for r in rows:
            host = _normalize_liveness_host(str(r.get("host", "")))
            if not host:
                continue
            connection.execute(
                """
                INSERT INTO assessment_host_liveness (
                    engagement_id, host, status_code, scheme, final_url, host_ip,
                    tech, title, webserver, tls, failed, reachability_class,
                    probed_at, source, source_run_id, source_run_uuid
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, host) DO UPDATE SET
                    status_code = excluded.status_code,
                    scheme = excluded.scheme,
                    final_url = excluded.final_url,
                    host_ip = excluded.host_ip,
                    tech = excluded.tech,
                    title = excluded.title,
                    webserver = excluded.webserver,
                    tls = excluded.tls,
                    failed = excluded.failed,
                    reachability_class = excluded.reachability_class,
                    probed_at = excluded.probed_at,
                    source = excluded.source,
                    source_run_id = excluded.source_run_id,
                    source_run_uuid = excluded.source_run_uuid,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
                -- Keep the newest probe: overwrite only when the existing row has
                -- no probe time, or the incoming probe is at-or-after it. A NULL
                -- incoming probed_at must NOT clobber a real timestamped verdict.
                -- probed_at is canonicalized to one sortable UTC form on the way
                -- in, so this TEXT comparison is correct across input formats.
                WHERE assessment_host_liveness.probed_at IS NULL
                   OR (excluded.probed_at IS NOT NULL
                       AND excluded.probed_at >= assessment_host_liveness.probed_at)
                """,
                (
                    engagement_id,
                    host,
                    r.get("status_code"),
                    str(r.get("scheme") or ""),
                    str(r.get("final_url") or ""),
                    str(r.get("host_ip") or ""),
                    str(r.get("tech") or ""),
                    str(r.get("title") or ""),
                    str(r.get("webserver") or ""),
                    str(r.get("tls") or ""),
                    1 if r.get("failed") else 0,
                    str(r.get("reachability_class") or "unknown"),
                    _canonical_probed_at(r.get("probed_at")),
                    str(r.get("source") or "httpx"),
                    r.get("source_run_id"),
                    str(r.get("source_run_uuid") or ""),
                ),
            )
            upserted += 1
    return {"upserted": upserted}

def host_liveness(
    engagement_id: int,
    *,
    hosts: list[str] | None = None,
    fresh_only: bool = False,
) -> list[dict[str, Any]]:
    """Read host-liveness rows with the freshness overlay applied.

    A stored verdict older than the TTL is reported as ``reachability_class``
    'stale' (the stored value is preserved under ``stored_reachability_class``)
    and each row carries ``age_seconds``. With ``fresh_only`` the stale/unprobed
    rows are dropped.
    """
    _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        if hosts:
            norm = sorted({_normalize_liveness_host(h) for h in hosts if _normalize_liveness_host(h)})
            if not norm:
                return []
            placeholders = ",".join("?" for _ in norm)
            cursor = connection.execute(
                f"SELECT * FROM assessment_host_liveness "
                f"WHERE engagement_id = ? AND host IN ({placeholders}) ORDER BY host",
                (engagement_id, *norm),
            )
        else:
            cursor = connection.execute(
                "SELECT * FROM assessment_host_liveness WHERE engagement_id = ? ORDER BY host",
                (engagement_id,),
            )
        rows = cursor.fetchall()

    out: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        age = _liveness_age_seconds(data.get("probed_at"))
        data["age_seconds"] = age
        stored = data.get("reachability_class") or "unknown"
        is_fresh = age is not None and age <= _HOST_LIVENESS_TTL_SECONDS
        if not is_fresh and stored in _HOST_LIVENESS_DECAYS:
            data["stored_reachability_class"] = stored
            data["reachability_class"] = "stale"
        if fresh_only and not is_fresh:
            continue
        out.append(data)
    return out
