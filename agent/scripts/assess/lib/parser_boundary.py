"""Parent-owned process boundary for structural source parsers."""
from __future__ import annotations

import hashlib
import json
import math
import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from assess.lib.treesitter_index import (
    STREAMING_SCAN_WINDOW_BYTES,
    streaming_security_fallback,
)


PARSER_PROTOCOL_SCHEMA = "vigil-structural-parser/v1"
DEFAULT_PARSER_TIMEOUT_SECONDS = 15.0
DEFAULT_MAX_RESULT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_EXACT_SOURCE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024
MAX_WORKER_DIAGNOSTIC_BYTES = 64 * 1024
PARSER_CAPABILITY_DENIED_EXIT = 78
PARSER_MEMORY_LIMIT_EXIT = 79
_READ_SIZE = 64 * 1024


class ParserBoundaryCancelled(Exception):
    """Raised when the caller cancels an in-flight parser worker."""


class _DuplicateJSONKeyError(ValueError):
    pass


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError(f"duplicate parser result key: {key}")
        result[key] = value
    return result


def _fallback(
    file_path: str,
    language: str,
    source: bytes,
    *,
    reason: str,
) -> dict[str, Any]:
    return streaming_security_fallback(
        file_path,
        language,
        (
            source[offset : offset + STREAMING_SCAN_WINDOW_BYTES]
            for offset in range(0, len(source), STREAMING_SCAN_WINDOW_BYTES)
        ),
        degradation_reason=reason,
    )


def _has_giant_line(source: bytes, *, max_line_bytes: int) -> bool:
    if len(source) <= max_line_bytes:
        return False
    start = 0
    source_size = len(source)
    while start < source_size:
        newline = source.find(b"\n", start)
        carriage = source.find(b"\r", start)
        boundaries = [value for value in (newline, carriage) if value >= 0]
        end = min(boundaries) if boundaries else source_size
        if end - start > max_line_bytes:
            return True
        start = end + 1
    return False


def _terminate_worker(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=0.25)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    process.wait(timeout=1)


def _worker_environment(
    *,
    timeout_seconds: float,
    max_result_bytes: int,
    memory_limit_bytes: int,
) -> dict[str, str]:
    scripts_root = Path(__file__).resolve().parents[2]
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8:strict",
        "VIGIL_PARSER_CPU_SECONDS": str(max(1, math.ceil(timeout_seconds) + 1)),
        "VIGIL_PARSER_MEMORY_BYTES": str(memory_limit_bytes),
        "VIGIL_PARSER_MAX_RESULT_BYTES": str(max_result_bytes),
    }
    existing_python_path = os.environ.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(scripts_root), existing_python_path) if value
    )
    return environment


def _process_resident_bytes(pid: int) -> int | None:
    proc_statm = Path("/proc") / str(pid) / "statm"
    if proc_statm.is_file():
        try:
            fields = proc_statm.read_text(encoding="ascii").split()
            return int(fields[1]) * int(os.sysconf("SC_PAGE_SIZE"))
        except (IndexError, OSError, ValueError):
            return None
    ps_path = Path("/bin/ps")
    if not ps_path.is_file():
        return None
    try:
        completed = subprocess.run(
            [str(ps_path), "-o", "rss=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=0.25,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return None
        return int(completed.stdout.strip()) * 1024
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _collect_worker_output(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    max_result_bytes: int,
    memory_limit_bytes: int,
    cancellation_requested: Callable[[], bool] | None,
) -> tuple[bytes, bytes, str | None]:
    if process.stdout is None or process.stderr is None:
        raise RuntimeError("parser worker pipes were not created")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    stdout = bytearray()
    stderr = bytearray()
    deadline = time.monotonic() + timeout_seconds
    failure: str | None = None
    try:
        while selector.get_map():
            if cancellation_requested is not None and cancellation_requested():
                _terminate_worker(process)
                raise ParserBoundaryCancelled("structural parser cancelled")
            resident_bytes = _process_resident_bytes(process.pid)
            if resident_bytes is not None and resident_bytes > memory_limit_bytes:
                failure = "parser_worker_memory_limit"
                _terminate_worker(process)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "parser_worker_timeout"
                _terminate_worker(process)
                break
            events = selector.select(timeout=min(0.05, remaining))
            for key, _ in events:
                chunk = os.read(key.fileobj.fileno(), _READ_SIZE)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                destination = stdout if key.data == "stdout" else stderr
                destination.extend(chunk)
                cap = (
                    max_result_bytes
                    if key.data == "stdout"
                    else MAX_WORKER_DIAGNOSTIC_BYTES
                )
                if len(destination) > cap:
                    failure = (
                        "parser_worker_result_limit"
                        if key.data == "stdout"
                        else "parser_worker_diagnostic_limit"
                    )
                    _terminate_worker(process)
                    break
            if failure is not None:
                break
    finally:
        selector.close()
        if process.poll() is None:
            _terminate_worker(process)
    process.wait(timeout=1)
    return bytes(stdout), bytes(stderr), failure


def _decode_worker_result(
    output: bytes,
    *,
    source_size: int,
    result_validator: Callable[[dict[str, Any]], None] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    try:
        text = output.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None, "parser_worker_invalid_utf8_output"
    try:
        envelope = json.loads(text, object_pairs_hook=_unique_json_object)
    except (json.JSONDecodeError, _DuplicateJSONKeyError, RecursionError):
        return None, "parser_worker_malformed_output"
    if not isinstance(envelope, dict) or envelope.get("schema") != PARSER_PROTOCOL_SCHEMA:
        return None, "parser_worker_malformed_output"
    status = envelope.get("status")
    if status == "error":
        if set(envelope) != {"schema", "status", "reason"}:
            return None, "parser_worker_malformed_output"
        reason = envelope.get("reason")
        if not isinstance(reason, str) or not reason.startswith("parser_worker_"):
            return None, "parser_worker_malformed_output"
        return None, reason
    if status != "ok" or set(envelope) != {"schema", "status", "result"}:
        return None, "parser_worker_malformed_output"
    result = envelope.get("result")
    if not isinstance(result, dict):
        return None, "parser_worker_invalid_result"
    if (
        type(result.get("source_size")) is not int
        or result.get("source_size") != source_size
        or type(result.get("bytes_scanned")) is not int
        or result.get("bytes_scanned") != source_size
    ):
        return None, "parser_worker_invalid_result"
    if result_validator is not None:
        try:
            result_validator(result)
        except (TypeError, ValueError):
            return None, "parser_worker_invalid_result"
    return result, None


def index_file(
    file_path: str,
    language: str,
    source: bytes | None = None,
    *,
    timeout_seconds: float = DEFAULT_PARSER_TIMEOUT_SECONDS,
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES,
    memory_limit_bytes: int = DEFAULT_MEMORY_LIMIT_BYTES,
    worker_command: Sequence[str] | None = None,
    cancellation_requested: Callable[[], bool] | None = None,
    result_validator: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Parse one materialized source value in a resource-bounded child process."""
    if source is None:
        raise ValueError("bounded structural parsing requires materialized source bytes")
    if not isinstance(source, bytes):
        raise TypeError("source must be bytes")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or timeout_seconds <= 0
    ):
        raise ValueError("parser timeout must be a positive finite number")
    if type(max_result_bytes) is not int or max_result_bytes < 256:
        raise ValueError("parser result cap must be an integer of at least 256 bytes")
    if type(memory_limit_bytes) is not int or memory_limit_bytes < 16 * 1024 * 1024:
        raise ValueError("parser memory cap must be an integer of at least 16 MiB")
    if cancellation_requested is not None and cancellation_requested():
        raise ParserBoundaryCancelled("structural parser cancelled")
    try:
        source.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return _fallback(
            file_path, language, source, reason="invalid_utf8_source"
        )
    if len(source) > DEFAULT_MAX_EXACT_SOURCE_BYTES:
        return _fallback(
            file_path, language, source, reason="exact_parser_source_limit"
        )
    if _has_giant_line(source, max_line_bytes=DEFAULT_MAX_LINE_BYTES):
        return _fallback(
            file_path, language, source, reason="giant_line_resource_limit"
        )

    with tempfile.TemporaryDirectory(prefix="vigil-structural-parser-") as temporary:
        root = Path(temporary)
        source_path = root / "source.bin"
        request_path = root / "request.json"
        source_path.write_bytes(source)
        source_path.chmod(0o400)
        request = {
            "schema": PARSER_PROTOCOL_SCHEMA,
            "file_path": file_path,
            "language": language,
            "source_path": str(source_path),
            "source_size": len(source),
            "source_sha256": hashlib.sha256(source).hexdigest(),
        }
        request_path.write_text(
            json.dumps(request, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        request_path.chmod(0o400)
        command = list(worker_command) if worker_command is not None else [
            sys.executable,
            "-m",
            "assess.lib.parser_worker",
            str(request_path),
        ]
        try:
            process = subprocess.Popen(
                command,
                cwd=root,
                env=_worker_environment(
                    timeout_seconds=float(timeout_seconds),
                    max_result_bytes=max_result_bytes,
                    memory_limit_bytes=memory_limit_bytes,
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                close_fds=True,
            )
        except OSError:
            return _fallback(
                file_path, language, source, reason="parser_worker_launch_error"
            )
        output, _diagnostics, failure = _collect_worker_output(
            process,
            timeout_seconds=float(timeout_seconds),
            max_result_bytes=max_result_bytes,
            memory_limit_bytes=memory_limit_bytes,
            cancellation_requested=cancellation_requested,
        )
        if failure is None and process.returncode != 0:
            failure = {
                PARSER_CAPABILITY_DENIED_EXIT: "parser_worker_capability_denied",
                PARSER_MEMORY_LIMIT_EXIT: "parser_worker_memory_limit",
            }.get(process.returncode, "parser_worker_crash")
        if failure is None:
            result, failure = _decode_worker_result(
                output,
                source_size=len(source),
                result_validator=result_validator,
            )
            if result is not None:
                return result
        return _fallback(
            file_path,
            language,
            source,
            reason=failure or "parser_worker_malformed_output",
        )
