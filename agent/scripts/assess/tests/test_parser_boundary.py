from __future__ import annotations

import json
import os
import signal
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
    tmp_path: Path,
) -> None:
    source = b"def parse():\n    return 1\n"
    pid_file = tmp_path / "worker.pid"
    command = _python_command(
        "import os, pathlib, signal; "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); signal.pause()"
    )
    callback_calls = 0

    def cancellation_requested() -> bool:
        nonlocal callback_calls
        callback_calls += 1
        return pid_file.exists() and bool(pid_file.read_text())

    with parser_boundary.ParserWorker() as worker:
        with pytest.raises(parser_boundary.ParserBoundaryCancelled):
            parser_boundary.index_file(
                "app.py",
                "python",
                source=source,
                worker=worker,
                worker_command=command,
                cancellation_requested=cancellation_requested,
            )
        with pytest.raises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        parsed = parser_boundary.index_file("app.py", "python", source=source, worker=worker)

    assert callback_calls >= 3
    assert parsed["analysis_status"] == "complete"


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


@pytest.mark.parametrize("separator", [b"\n", b"\r", b"\r\n", b"\n\r"])
def test_giant_line_preflight_scans_each_byte_a_bounded_number_of_times(separator):
    class CountedBytes(bytes):
        scanned = 0

        def find(self, sub, start=0, end=None):
            end = len(self) if end is None else end
            result = super().find(sub, start, end)
            self.scanned += (end if result < 0 else result + len(sub)) - start
            return result

    source = CountedBytes((b"x" + separator) * 4096)
    assert not parser_boundary._has_giant_line(source, max_line_bytes=32)
    assert source.scanned <= 4 * len(source)


@pytest.mark.parametrize("prefix", [b"", b"\n", b"\r\n"])
@pytest.mark.parametrize("extra", [0, 1])
def test_giant_line_threshold_across_scan_chunks(prefix, extra):
    limit = parser_boundary._READ_SIZE + 17
    source = prefix + b"x" * (limit + extra) + b"\r\nshort\n"
    assert parser_boundary._has_giant_line(source, max_line_bytes=limit) is bool(extra)


@pytest.mark.parametrize("source", [
    b"\n" * (2 * 1024 * 1024),
    b"x" * (parser_boundary.DEFAULT_MAX_EXACT_SOURCE_BYTES + 1),
    b"\xff" + b"\n" * (2 * 1024 * 1024),
], ids=["many-lines", "source-limit", "invalid-utf8"])
def test_parent_preprocessing_observes_cancellation_before_worker_launch(source, monkeypatch):
    calls = 0
    launches = []
    real_popen = parser_boundary.subprocess.Popen

    def observe_worker(*args, **kwargs):
        launches.append(True)
        return real_popen(*args, **kwargs)

    def cancelled():
        nonlocal calls
        calls += 1
        return calls >= 3

    monkeypatch.setattr(parser_boundary.subprocess, "Popen", observe_worker)
    with pytest.raises(parser_boundary.ParserBoundaryCancelled):
        parser_boundary.index_file(
            "app.py", "python", source=source,
            worker_command=_python_command("print('{}')"),
            cancellation_requested=cancelled,
        )
    assert not launches


def test_giant_line_preflight_observes_cancellation(monkeypatch):
    scanning = False
    real_scan = parser_boundary._has_giant_line
    launches = []
    real_popen = parser_boundary.subprocess.Popen

    def scan(*args, **kwargs):
        nonlocal scanning
        scanning = True
        return real_scan(*args, **kwargs)

    def observe_worker(*args, **kwargs):
        launches.append(True)
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(parser_boundary, "_has_giant_line", scan)
    monkeypatch.setattr(parser_boundary, "DEFAULT_MAX_LINE_BYTES", 32)
    monkeypatch.setattr(parser_boundary.subprocess, "Popen", observe_worker)
    with pytest.raises(parser_boundary.ParserBoundaryCancelled):
        parser_boundary.index_file(
            "app.py", "python", source=b"\n" * parser_boundary._READ_SIZE,
            worker_command=_python_command("print('{}')"),
            cancellation_requested=lambda: scanning,
        )
    assert not launches


@pytest.mark.parametrize(("suffix", "reason"), [
    (b"\xe2\x82\xac\n", "parser_worker_crash"),
    (b"\xe2\x82", "invalid_utf8_source"),
])
def test_preflight_decodes_utf8_across_chunks_and_checks_final_sequence(suffix, reason):
    source = b"#" + b"x" * (parser_boundary.STREAMING_SCAN_WINDOW_BYTES - 2) + suffix
    result = parser_boundary.index_file(
        "app.py", "python", source=source,
        worker_command=_python_command("import os; os._exit(73)"),
    )
    _assert_full_byte_fallback(result, source, reason)


def _real_worker_after(prelude: str) -> list[str]:
    """A worker command that runs *prelude* and then the real parser worker."""
    return _python_command(
        prelude
        + "\nimport sys\nfrom assess.lib.parser_worker import main\n"
        + "raise SystemExit(main(sys.argv[1:]))"
    )


def test_pooled_worker_times_out_a_cpu_bound_file_and_serves_the_next_one() -> None:
    source = b"def parse(value):\n    return value\n"
    with parser_boundary.ParserWorker() as worker:
        exhausted = parser_boundary.index_file(
            "spin.py",
            "python",
            source=source,
            timeout_seconds=0.5,
            worker=worker,
            worker_command=_python_command("while True:\n    pass"),
        )
        parsed = parser_boundary.index_file("parse.py", "python", source=source, worker=worker)

    _assert_full_byte_fallback(exhausted, source, "parser_worker_timeout")
    assert parsed["analysis_status"] == "complete"
    assert parsed["analysis_mode"] == "tree_sitter"


def test_waiting_for_a_cpu_does_not_spend_the_parser_time_budget() -> None:
    source = b"def parse(value):\n    return value\n"

    result = parser_boundary.index_file(
        "parse.py",
        "python",
        source=source,
        timeout_seconds=0.5,
        worker_command=_real_worker_after("import time\ntime.sleep(1.0)"),
    )

    assert result["analysis_status"] == "complete"
    assert result["analysis_mode"] == "tree_sitter"


@pytest.mark.parametrize(
    ("command", "memory_limit_bytes", "expected_reason"),
    [
        (
            _python_command("import os; os._exit(73)"),
            parser_boundary.DEFAULT_MEMORY_LIMIT_BYTES,
            "parser_worker_crash",
        ),
        (
            _python_command(
                "import signal; blocks = [bytearray(1024 * 1024) for _ in range(256)]; "
                "signal.pause()"
            ),
            128 * 1024 * 1024,
            "parser_worker_memory_limit",
        ),
    ],
    ids=["crash", "memory-limit"],
)
def test_pooled_worker_survives_a_failed_file(
    command: list[str], memory_limit_bytes: int, expected_reason: str
) -> None:
    source = b"def parse(value):\n    return value\n"
    with parser_boundary.ParserWorker() as worker:
        failed = parser_boundary.index_file(
            "app.py",
            "python",
            source=source,
            memory_limit_bytes=memory_limit_bytes,
            worker=worker,
            worker_command=command,
        )
        parsed = parser_boundary.index_file("parse.py", "python", source=source, worker=worker)

    _assert_full_byte_fallback(failed, source, expected_reason)
    assert parsed["analysis_status"] == "complete"


def test_pooled_worker_restarts_a_server_lost_mid_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    servers: list[int] = []
    real_popen = parser_boundary.subprocess.Popen

    def observe_server(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        servers.append(process.pid)
        return process

    monkeypatch.setattr(parser_boundary.subprocess, "Popen", observe_server)
    source = b"def parse(value):\n    return value\n"
    pid_file = tmp_path / "worker.pid"
    command = _python_command(
        "import os, pathlib, time; "
        f"pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(0.5)"
    )

    killed: list[int] = []

    def lose_server() -> bool:
        if not killed and pid_file.exists() and pid_file.read_text():
            os.kill(servers[0], signal.SIGKILL)
            killed.append(servers[0])
        return False

    with parser_boundary.ParserWorker() as worker:
        lost = parser_boundary.index_file(
            "app.py", "python", source=source, worker=worker, worker_command=command,
            cancellation_requested=lose_server,
        )
        parsed = parser_boundary.index_file("parse.py", "python", source=source, worker=worker)

    _assert_full_byte_fallback(lost, source, "parser_worker_crash")
    assert parsed["analysis_status"] == "complete"
    assert len(servers) == 2
