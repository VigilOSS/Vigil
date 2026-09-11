from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from assess.lib import parser_boundary, treesitter_index


def _python_command(source: str) -> list[str]:
    return [sys.executable, "-c", source]


def _worker_envelope(*, status: str, **fields: object) -> str:
    return json.dumps(
        {
            "schema": parser_boundary.PARSER_PROTOCOL_SCHEMA,
            "status": status,
            **fields,
        },
        separators=(",", ":"),
    )


def _assert_full_byte_fallback(result: dict[str, object], source: bytes, reason: str) -> None:
    assert result["analysis_status"] == "degraded"
    assert result["analysis_mode"] == "streaming_security_fallback"
    assert result["degradation_reason"] == reason
    assert result["source_size"] == len(source)
    assert result["bytes_scanned"] == len(source)
    assert result["unavailable_dimensions"]


def test_exact_parser_executes_outside_the_parent_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_pids: list[int] = []
    real_popen = parser_boundary.subprocess.Popen

    def observe_worker(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        worker_pids.append(process.pid)
        return process

    monkeypatch.setattr(parser_boundary.subprocess, "Popen", observe_worker)
    source = b"def parse(value):\n    return value\n"

    result = parser_boundary.index_file("parse.py", "python", source=source)

    assert worker_pids and all(pid != os.getpid() for pid in worker_pids)
    assert result["source_size"] == len(source)
    assert result["bytes_scanned"] == len(source)
    assert result["analysis_status"] == "complete"
    assert result["analysis_mode"] == "tree_sitter"


@pytest.mark.parametrize(
    ("command", "expected_reason"),
    [
        (_python_command("import os; os._exit(73)"), "parser_worker_crash"),
        (_python_command("print('{')"), "parser_worker_malformed_output"),
        (
            _python_command("import os; os.write(1, b'\\xff\\xfe')"),
            "parser_worker_invalid_utf8_output",
        ),
    ],
    ids=["crash", "malformed-json", "invalid-utf8-output"],
)
def test_worker_failure_falls_back_over_every_source_byte(
    command: list[str], expected_reason: str
) -> None:
    source = b"eval(user_input)\n" * 64

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        worker_command=command,
    )

    _assert_full_byte_fallback(result, source, expected_reason)


def test_worker_timeout_terminates_and_falls_back_over_every_source_byte() -> None:
    source = b"subprocess.run(user_input)\n"

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        timeout_seconds=0.1,
        worker_command=_python_command("import signal; signal.pause()"),
    )

    _assert_full_byte_fallback(result, source, "parser_worker_timeout")


def test_worker_result_flood_is_killed_at_the_parent_owned_cap() -> None:
    source = b"eval(user_input)\n"

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        max_result_bytes=512,
        worker_command=_python_command("import os; os.write(1, b'x' * 4096)"),
    )

    _assert_full_byte_fallback(result, source, "parser_worker_result_limit")


def test_parent_kills_worker_that_crosses_resident_memory_cap() -> None:
    source = b"eval(user_input)\n"

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        memory_limit_bytes=32 * 1024 * 1024,
        worker_command=_python_command(
            "import signal; blocks = [bytearray(1024 * 1024) for _ in range(128)]; "
            "signal.pause()"
        ),
    )

    _assert_full_byte_fallback(result, source, "parser_worker_memory_limit")


def test_socket_denial_is_reported_by_the_parent_boundary() -> None:
    source = b"eval(user_input)\n"
    command = _python_command(
        "import os; from assess.lib import parser_worker as worker; "
        "worker.install_parser_audit_guard(); import socket; "
        "\ntry:\n socket.socket()\nexcept PermissionError:\n "
        "os._exit(worker.PARSER_CAPABILITY_DENIED_EXIT)\nos._exit(0)"
    )

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        worker_command=command,
    )

    _assert_full_byte_fallback(result, source, "parser_worker_capability_denied")


def test_invalid_worker_result_uses_explicit_fallback_debt() -> None:
    source = b"eval(user_input)\n"
    envelope = _worker_envelope(status="ok", result={})

    def reject(_result: dict[str, object]) -> None:
        raise ValueError("missing structural fields")

    result = parser_boundary.index_file(
        "app.py",
        "python",
        source=source,
        worker_command=_python_command("print(" + repr(envelope) + ")"),
        result_validator=reject,
    )

    _assert_full_byte_fallback(result, source, "parser_worker_invalid_result")


def test_invalid_utf8_source_never_receives_exact_complete_status() -> None:
    source = b"def parse():\n    return b'" + bytes([0xFF]) + b"'\n"

    result = parser_boundary.index_file("invalid.py", "python", source=source)

    _assert_full_byte_fallback(result, source, "invalid_utf8_source")


def test_giant_line_uses_bounded_streaming_fallback() -> None:
    source = b"value = '" + (b"a" * (1024 * 1024 + 1)) + b"'\n"

    result = parser_boundary.index_file("giant.py", "python", source=source)

    _assert_full_byte_fallback(result, source, "giant_line_resource_limit")


def test_cancellation_terminates_in_flight_worker_without_returning_partial_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"def parse():\n    return 1\n"
    callback_calls = 0
    worker_pids: list[int] = []
    real_popen = parser_boundary.subprocess.Popen

    def observe_worker(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        worker_pids.append(process.pid)
        return process

    def cancellation_requested() -> bool:
        nonlocal callback_calls
        callback_calls += 1
        return callback_calls >= 3

    monkeypatch.setattr(parser_boundary.subprocess, "Popen", observe_worker)

    with pytest.raises(parser_boundary.ParserBoundaryCancelled):
        parser_boundary.index_file(
            "app.py",
            "python",
            source=source,
            worker_command=_python_command("import signal; signal.pause()"),
            cancellation_requested=cancellation_requested,
        )

    assert callback_calls >= 3
    assert worker_pids
    for pid in worker_pids:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


def test_parser_worker_audit_guard_denies_socket_creation() -> None:
    scripts_root = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(scripts_root), env.get("PYTHONPATH", "")) if value
    )
    probe = subprocess.run(
        _python_command(
            "from assess.lib.parser_worker import install_parser_audit_guard; "
            "install_parser_audit_guard(); import socket; "
            "socket.socket()"
        ),
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )

    assert probe.returncode != 0
    assert "parser worker denied capability: socket" in probe.stderr


def test_exact_extractor_does_not_swallow_memory_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        treesitter_index,
        "_index_lightweight",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(MemoryError()),
    )

    with pytest.raises(MemoryError):
        treesitter_index.index_file("Dockerfile", "dockerfile", source=b"RUN true\n")
