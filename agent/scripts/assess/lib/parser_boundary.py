"""Parent-owned process boundary for structural source parsers.

Every file parses in its own child process. A ``ParserWorker`` owns one warm
fork server (``parser_worker --serve``) that forks that child, so a build pays
interpreter start-up and grammar loading once per worker instead of once per
file. The parent still owns each child's limits: it reads the child's kernel
CPU and resident-memory accounting while it collects the output, kills the
child's process group on any limit, and only then lets the server reap it.

The time limit is CPU time the child itself spent, so a file waiting for a
core behind other parsers keeps its whole budget. A wall-clock backstop of
``PARSER_WALL_TIMEOUT_FACTOR`` times the budget still ends a child that stops
making progress without using CPU. Where the platform exposes no per-process
CPU accounting, the budget is wall-clock time.
"""
from __future__ import annotations

import codecs
import ctypes
import ctypes.util
import hashlib
import json
import math
import os
import queue
import re
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from assess.lib.parser_worker import (
    PARSER_CAPABILITY_DENIED_EXIT,
    PARSER_MEMORY_LIMIT_EXIT,
    PARSER_PROTOCOL_SCHEMA,
    REQUEST_NAME,
    REQUEST_SOURCE_NAME,
    decode_server_frame,
    encode_server_frame,
    kill_process_group,
)
from assess.lib.treesitter_index import (
    STREAMING_SCAN_WINDOW_BYTES,
    streaming_security_fallback,
)


DEFAULT_PARSER_TIMEOUT_SECONDS = 15.0
PARSER_WALL_TIMEOUT_FACTOR = 4
MAX_DEFAULT_PARSER_JOBS = 8
PARSER_SERVER_STARTUP_SECONDS = 60.0
PARSER_REAP_SECONDS = 2.0
DEFAULT_MAX_RESULT_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_EXACT_SOURCE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_LINE_BYTES = 1024 * 1024
DEFAULT_MEMORY_LIMIT_BYTES = 1024 * 1024 * 1024
MAX_WORKER_DIAGNOSTIC_BYTES = 64 * 1024
_READ_SIZE = 64 * 1024
_WIDE_UNICODE_BOMS = (
    codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE,
)


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


def _source_chunks(
    source: bytes, cancellation_requested: Callable[[], bool] | None,
) -> Iterator[bytes]:
    for offset in range(0, len(source), STREAMING_SCAN_WINDOW_BYTES):
        if cancellation_requested is not None and cancellation_requested():
            raise ParserBoundaryCancelled("structural parser cancelled")
        yield source[offset : offset + STREAMING_SCAN_WINDOW_BYTES]


def _fallback(
    file_path: str,
    language: str,
    source: bytes,
    *,
    reason: str,
    cancellation_requested: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    return streaming_security_fallback(
        file_path,
        language,
        _source_chunks(source, cancellation_requested),
        degradation_reason=reason,
    )


def _has_giant_line(
    source: bytes, *, max_line_bytes: int,
    cancellation_requested: Callable[[], bool] | None = None,
) -> bool:
    if len(source) <= max_line_bytes:
        return False
    line_bytes = 0
    for chunk in _source_chunks(source, cancellation_requested):
        # Bounded chunks avoid rescanning the remaining suffix for an absent CR/LF.
        lengths = [len(line) for line in re.split(rb"[\r\n]+", chunk)]
        lengths[0] += line_bytes
        if max(lengths) > max_line_bytes:
            return True
        line_bytes = lengths[-1]
    return False


def _worker_environment() -> dict[str, str]:
    scripts_root = Path(__file__).resolve().parents[2]
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8:strict",
    }
    existing_python_path = os.environ.get("PYTHONPATH", "")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in (str(scripts_root), existing_python_path) if value
    )
    return environment


def _request_limits(
    *,
    timeout_seconds: float,
    max_result_bytes: int,
    memory_limit_bytes: int,
) -> dict[str, str]:
    return {
        "VIGIL_PARSER_CPU_SECONDS": str(max(1, math.ceil(timeout_seconds) + 1)),
        "VIGIL_PARSER_MEMORY_BYTES": str(memory_limit_bytes),
        "VIGIL_PARSER_MAX_RESULT_BYTES": str(max_result_bytes),
    }


class _DarwinRUsage(ctypes.Structure):
    _fields_ = [
        ("ri_uuid", ctypes.c_uint8 * 16),
        ("ri_user_time", ctypes.c_uint64),
        ("ri_system_time", ctypes.c_uint64),
        ("ri_pkg_idle_wkups", ctypes.c_uint64),
        ("ri_interrupt_wkups", ctypes.c_uint64),
        ("ri_pageins", ctypes.c_uint64),
        ("ri_wired_size", ctypes.c_uint64),
        ("ri_resident_size", ctypes.c_uint64),
        ("ri_phys_footprint", ctypes.c_uint64),
        ("ri_proc_start_abstime", ctypes.c_uint64),
        ("ri_proc_exit_abstime", ctypes.c_uint64),
    ]


class _MachTimebase(ctypes.Structure):
    _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]


def _darwin_usage_probe() -> Callable[[int], tuple[int | None, float | None]] | None:
    library = ctypes.util.find_library("proc")
    if sys.platform != "darwin" or library is None:
        return None
    try:
        libproc = ctypes.CDLL(library, use_errno=True)
        libc = ctypes.CDLL(None)
        timebase = _MachTimebase()
        if libc.mach_timebase_info(ctypes.byref(timebase)) != 0 or not timebase.denom:
            return None
    except (AttributeError, OSError):
        return None
    # rusage CPU times are Mach absolute-time ticks.
    seconds_per_tick = timebase.numer / timebase.denom / 1e9

    def probe(pid: int) -> tuple[int | None, float | None]:
        usage = _DarwinRUsage()
        if libproc.proc_pid_rusage(pid, 0, ctypes.byref(usage)) != 0:
            return None, None
        cpu = (usage.ri_user_time + usage.ri_system_time) * seconds_per_tick
        return int(usage.ri_resident_size), cpu

    return probe


def _proc_usage(pid: int) -> tuple[int | None, float | None]:
    base = Path("/proc") / str(pid)
    try:
        resident = int((base / "statm").read_text(encoding="ascii").split()[1])
        # The command name is parenthesized and may hold spaces.
        fields = (base / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
        ticks = int(fields[11]) + int(fields[12])
    except (IndexError, OSError, ValueError):
        return None, None
    return resident * _PAGE_SIZE, ticks / _CLOCK_TICKS


def _ps_usage(pid: int) -> tuple[int | None, float | None]:
    ps_path = Path("/bin/ps")
    if not ps_path.is_file():
        return None, None
    try:
        completed = subprocess.run(
            [str(ps_path), "-o", "rss=", "-p", str(pid)],
            check=False,
            capture_output=True,
            text=True,
            timeout=0.25,
        )
        if completed.returncode != 0 or not completed.stdout.strip():
            return None, None
        return int(completed.stdout.strip()) * 1024, None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None, None


if Path("/proc/self/stat").is_file():
    _PAGE_SIZE = int(os.sysconf("SC_PAGE_SIZE"))
    _CLOCK_TICKS = float(os.sysconf("SC_CLK_TCK"))
    _process_usage: Callable[[int], tuple[int | None, float | None]] = _proc_usage
    CPU_TIME_LIMITS = True
else:
    _darwin_probe = _darwin_usage_probe()
    _process_usage = _darwin_probe or _ps_usage
    CPU_TIME_LIMITS = _darwin_probe is not None


def _write_request_file(path: Path, data: bytes) -> None:
    """Create a read-only request file; never reuse or follow an existing entry."""
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    )
    path.unlink(missing_ok=True)
    fd = os.open(path, flags, 0o400)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    finally:
        os.close(fd)


def _performance_cpu_count() -> int | None:
    """Apple silicon's performance cores: efficiency cores stretch CPU time."""
    if sys.platform != "darwin":
        return None
    try:
        libc = ctypes.CDLL(None)
        value = ctypes.c_int(0)
        size = ctypes.c_size_t(ctypes.sizeof(value))
        if libc.sysctlbyname(
            b"hw.perflevel0.logicalcpu", ctypes.byref(value), ctypes.byref(size), None, 0,
        ) != 0:
            return None
    except (AttributeError, OSError):
        return None
    return value.value if value.value > 0 else None


_CGROUP_ROOT = Path("/sys/fs/cgroup")
_PROC_SELF_CGROUP = Path("/proc/self/cgroup")


def _scheduler_cpu_count() -> int:
    """CPUs this process may be scheduled on (its affinity mask where known)."""
    count = getattr(os, "process_cpu_count", None)
    if count is not None:
        return count() or 1
    if hasattr(os, "sched_getaffinity"):
        return len(os.sched_getaffinity(0)) or 1
    return os.cpu_count() or 1


def _cpu_quota(quota_text: str, period_text: str) -> int | None:
    try:
        quota, period = int(quota_text), int(period_text)
    except ValueError:
        return None  # `max`: no quota
    if quota <= 0 or period <= 0:
        return None
    return max(1, math.ceil(quota / period))


def _cgroup_cpu_limit() -> int | None:
    """Whole CPUs a Linux cgroup quota grants, rounded up, or None when unlimited.

    A quota on the process's own cgroup or any parent of it bounds the process,
    so the tightest one along that path wins (cgroup v2, then the v1 CFS files).
    """
    relative = ""
    try:
        for line in _PROC_SELF_CGROUP.read_text(encoding="utf-8").splitlines():
            if line.startswith("0::"):
                relative = line[3:].strip().lstrip("/")
    except OSError:
        pass
    directory = _CGROUP_ROOT / relative if relative else _CGROUP_ROOT
    limits: list[int] = []
    while True:
        try:
            fields = (directory / "cpu.max").read_text(encoding="ascii").split()
        except OSError:
            fields = []
        if len(fields) >= 2 and (limit := _cpu_quota(fields[0], fields[1])) is not None:
            limits.append(limit)
        if directory == _CGROUP_ROOT or _CGROUP_ROOT not in directory.parents:
            break
        directory = directory.parent
    if not limits:
        try:
            v1 = _CGROUP_ROOT / "cpu"
            limit = _cpu_quota(
                (v1 / "cpu.cfs_quota_us").read_text(encoding="ascii").strip(),
                (v1 / "cpu.cfs_period_us").read_text(encoding="ascii").strip(),
            )
        except OSError:
            limit = None
        if limit is not None:
            limits.append(limit)
    return min(limits) if limits else None


def default_parser_jobs() -> int:
    """Concurrent parses for a build: the usable cores, at most a fixed cap.

    The per-file CPU budget is the same for every job count; staying on fast
    cores, and within a container's CPU quota, keeps a file's CPU time and wall
    clock, and so its outcome, independent of the count.
    """
    usable = _scheduler_cpu_count()
    for limit in (_cgroup_cpu_limit(), _performance_cpu_count()):
        if limit is not None:
            usable = min(usable, limit)
    return max(1, min(usable, MAX_DEFAULT_PARSER_JOBS))


class ParserWorkerUnavailable(OSError):
    """Raised when the warm parser server cannot start or answer a request."""


class ParserWorker:
    """One warm fork server that runs each parse request in a fresh child.

    A worker serves one request at a time. It starts on first use, and a server
    that fails or stops answering is discarded and restarted by the next
    request, so one file's failure never reaches another file.
    """

    def __init__(self) -> None:
        self._process: subprocess.Popen[bytes] | None = None
        self._control: socket.socket | None = None
        self._root: Path | None = None
        self._buffer = bytearray()

    def __enter__(self) -> ParserWorker:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._discard()
        if self._root is not None:
            shutil.rmtree(self._root, ignore_errors=True)
            self._root = None

    def _discard(self) -> None:
        control, process = self._control, self._process
        self._control = None
        self._process = None
        self._buffer.clear()
        if control is not None:
            # The server kills and reaps an in-flight child when its socket closes.
            control.close()
        if process is not None:
            try:
                process.wait(timeout=PARSER_REAP_SECONDS)
            except subprocess.TimeoutExpired:
                kill_process_group(process.pid)
                process.wait(timeout=PARSER_REAP_SECONDS)

    def _start(self) -> socket.socket:
        if self._control is not None and self._process is not None:
            if self._process.poll() is None:
                return self._control
            self._discard()
        if self._root is None:
            self._root = Path(tempfile.mkdtemp(prefix="vigil-structural-parser-"))
            (self._root / "request").mkdir(mode=0o700)
        try:
            parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        except OSError as exc:
            raise ParserWorkerUnavailable("parser server socket could not open") from exc
        try:
            self._process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "assess.lib.parser_worker",
                    "--serve",
                    str(child.fileno()),
                ],
                # An empty private directory: `-m` puts the cwd on sys.path.
                cwd=self._root,
                env=_worker_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                close_fds=True,
                pass_fds=(child.fileno(),),
            )
        except OSError as exc:
            parent.close()
            raise ParserWorkerUnavailable("parser server did not start") from exc
        finally:
            child.close()
        self._control = parent
        ready = self._reply(time.monotonic() + PARSER_SERVER_STARTUP_SECONDS)
        if ready != {"ready": True}:
            self._discard()
            raise ParserWorkerUnavailable("parser server did not become ready")
        return parent

    def _reply(self, deadline: float) -> dict[str, Any] | None:
        """Wait for one server frame; None means the server is unusable."""
        control = self._control
        if control is None:
            return None
        # A selector, unlike select(), polls a descriptor numbered past 1023.
        with selectors.DefaultSelector() as selector:
            selector.register(control, selectors.EVENT_READ)
            while True:
                try:
                    frame = decode_server_frame(self._buffer)
                except ValueError:
                    return None
                if frame is not None:
                    return frame
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                if not selector.select(timeout=remaining):
                    return None
                try:
                    data = control.recv(4096)
                except OSError:
                    return None
                if not data:
                    return None
                self._buffer.extend(data)

    def run(
        self,
        *,
        file_path: str,
        language: str,
        source: bytes,
        command: Sequence[str] | None,
        timeout_seconds: float,
        max_result_bytes: int,
        memory_limit_bytes: int,
        cancellation_requested: Callable[[], bool] | None,
    ) -> tuple[bytes, int | None, str | None]:
        """Parse one source; return the child's stdout, exit status, and limit failure."""
        self._start()
        if self._root is None:
            raise ParserWorkerUnavailable("parser server has no request directory")
        request_dir = self._root / "request"
        source_path = request_dir / REQUEST_SOURCE_NAME
        request_path = request_dir / REQUEST_NAME
        request = {
            "schema": PARSER_PROTOCOL_SCHEMA,
            "file_path": file_path,
            "language": language,
            "source_path": str(source_path),
            "source_size": len(source),
            "source_sha256": hashlib.sha256(source).hexdigest(),
        }
        try:
            _write_request_file(source_path, source)
            _write_request_file(
                request_path,
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            )
            return self._run_request(
                request_path,
                command=command,
                timeout_seconds=timeout_seconds,
                max_result_bytes=max_result_bytes,
                memory_limit_bytes=memory_limit_bytes,
                cancellation_requested=cancellation_requested,
            )
        finally:
            request_path.unlink(missing_ok=True)
            source_path.unlink(missing_ok=True)

    def _run_request(
        self,
        request_path: Path,
        *,
        command: Sequence[str] | None,
        timeout_seconds: float,
        max_result_bytes: int,
        memory_limit_bytes: int,
        cancellation_requested: Callable[[], bool] | None,
    ) -> tuple[bytes, int | None, str | None]:
        control = self._control
        if control is None:
            raise ParserWorkerUnavailable("parser server is not running")
        try:
            stdout_read, stdout_write = os.pipe()
        except OSError as exc:
            raise ParserWorkerUnavailable("parser request pipes could not open") from exc
        try:
            stderr_read, stderr_write = os.pipe()
        except OSError as exc:
            os.close(stdout_read)
            os.close(stdout_write)
            raise ParserWorkerUnavailable("parser request pipes could not open") from exc
        frame = encode_server_frame(
            {
                "op": "run",
                "request": str(request_path),
                "cwd": str(request_path.parent),
                "command": list(command) if command is not None else None,
                "limits": _request_limits(
                    timeout_seconds=timeout_seconds,
                    max_result_bytes=max_result_bytes,
                    memory_limit_bytes=memory_limit_bytes,
                ),
            }
        )
        try:
            sent = socket.send_fds(control, [frame], [stdout_write, stderr_write])
            if sent < len(frame):
                control.sendall(frame[sent:])
        except OSError as exc:
            os.close(stdout_read)
            os.close(stderr_read)
            self._discard()
            raise ParserWorkerUnavailable("parser server rejected the request") from exc
        finally:
            os.close(stdout_write)
            os.close(stderr_write)
        started = time.monotonic()
        wall_seconds = (
            timeout_seconds * PARSER_WALL_TIMEOUT_FACTOR if CPU_TIME_LIMITS else timeout_seconds
        )
        launched = self._reply(started + wall_seconds)
        pid = launched.get("pid") if launched is not None else None
        if type(pid) is not int or pid <= 0:
            os.close(stdout_read)
            os.close(stderr_read)
            self._discard()
            raise ParserWorkerUnavailable("parser server could not fork a request")
        try:
            return self._collect(
                pid,
                stdout_read=stdout_read,
                stderr_read=stderr_read,
                deadline=started + wall_seconds,
                timeout_seconds=timeout_seconds,
                max_result_bytes=max_result_bytes,
                memory_limit_bytes=memory_limit_bytes,
                cancellation_requested=cancellation_requested,
            )
        except BaseException:
            # The server kills the unreaped child when its socket closes.
            self._discard()
            raise
        finally:
            os.close(stdout_read)
            os.close(stderr_read)

    def _collect(
        self,
        pid: int,
        *,
        stdout_read: int,
        stderr_read: int,
        deadline: float,
        timeout_seconds: float,
        max_result_bytes: int,
        memory_limit_bytes: int,
        cancellation_requested: Callable[[], bool] | None,
    ) -> tuple[bytes, int | None, str | None]:
        control = self._control
        if control is None:
            raise ParserWorkerUnavailable("parser server is not running")
        selector = selectors.DefaultSelector()
        selector.register(stdout_read, selectors.EVENT_READ, "stdout")
        selector.register(stderr_read, selectors.EVENT_READ, "stderr")
        stdout = bytearray()
        stderr = bytearray()
        open_streams = 2
        reaping = False
        returncode: int | None = None
        failure: str | None = None
        try:
            while returncode is None:
                if cancellation_requested is not None and cancellation_requested():
                    kill_process_group(pid)
                    self._reap(pid, reaping=reaping)
                    raise ParserBoundaryCancelled("structural parser cancelled")
                resident_bytes, cpu_seconds = _process_usage(pid)
                if resident_bytes is not None and resident_bytes > memory_limit_bytes:
                    failure = "parser_worker_memory_limit"
                    break
                if cpu_seconds is not None and cpu_seconds > timeout_seconds:
                    failure = "parser_worker_timeout"
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "parser_worker_timeout"
                    break
                for key, _ in selector.select(timeout=min(0.05, remaining)):
                    if key.data == "control":
                        returncode = self._status_reply(control)
                        if returncode is None and self._control is None:
                            failure = "parser_worker_crash"
                        break
                    chunk = os.read(key.fd, _READ_SIZE)
                    if not chunk:
                        selector.unregister(key.fd)
                        open_streams -= 1
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
                        break
                if failure is not None:
                    break
                if open_streams == 0 and not reaping:
                    # Both pipes closed: ask the server for the exit status
                    # while the CPU, memory, and wall limits keep running.
                    try:
                        control.sendall(encode_server_frame({"op": "reap"}))
                    except OSError:
                        self._discard()
                        failure = "parser_worker_crash"
                        break
                    selector.register(control, selectors.EVENT_READ, "control")
                    reaping = True
        finally:
            selector.close()
        if failure is not None:
            kill_process_group(pid)
            if self._control is not None:
                returncode = self._reap(pid, reaping=reaping)
        return bytes(stdout), returncode, failure

    def _status_reply(self, control: socket.socket) -> int | None:
        """Read toward the reap reply; discard a server that closes or garbles it."""
        try:
            data = control.recv(4096)
            if data:
                self._buffer.extend(data)
                reply = decode_server_frame(self._buffer)
                if reply is None:
                    return None
                status = reply.get("returncode")
                if type(status) is int:
                    return status
        except (OSError, ValueError):
            pass
        self._discard()
        return None

    def _reap(self, pid: int, *, reaping: bool) -> int | None:
        """Collect a killed child's status, discarding a server that stalls."""
        control = self._control
        try:
            if control is None:
                raise ParserWorkerUnavailable("parser server is not running")
            if not reaping:
                control.sendall(encode_server_frame({"op": "reap"}))
            reply = self._reply(time.monotonic() + PARSER_REAP_SECONDS)
        except OSError:
            reply = None
        status = reply.get("returncode") if reply is not None else None
        if type(status) is not int:
            kill_process_group(pid)
            self._discard()
            return None
        return status


class ParserWorkerPool:
    """A fixed set of parser workers, each leased to one parse at a time."""

    def __init__(self, size: int) -> None:
        if type(size) is not int or size < 1:
            raise ValueError("parser worker pool size must be a positive integer")
        self._workers = [ParserWorker() for _ in range(size)]
        self._idle: queue.SimpleQueue[ParserWorker] = queue.SimpleQueue()
        for worker in self._workers:
            self._idle.put(worker)

    def __enter__(self) -> ParserWorkerPool:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @contextmanager
    def lease(self) -> Iterator[ParserWorker]:
        worker = self._idle.get()
        try:
            yield worker
        finally:
            self._idle.put(worker)

    def close(self) -> None:
        for worker in self._workers:
            worker.close()


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
    worker: ParserWorker | None = None,
    cancellation_requested: Callable[[], bool] | None = None,
    result_validator: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Parse one materialized source value in a resource-bounded child process.

    *timeout_seconds* is the child's CPU-time budget where the platform
    accounts it. *worker* reuses a warm server across files; without one, a
    single-use server parses this file. *worker_command* replaces the parser
    program the child runs and receives the request path as its last argument.
    """
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
    # Ordered, and short-circuiting: a wide-Unicode file is reported as such
    # and never scanned for giant lines.
    fallback_reason = (
        "utf16_or_utf32_source" if source.startswith(_WIDE_UNICODE_BOMS)
        else "exact_parser_source_limit" if len(source) > DEFAULT_MAX_EXACT_SOURCE_BYTES
        else "giant_line_resource_limit" if _has_giant_line(
            source, max_line_bytes=DEFAULT_MAX_LINE_BYTES,
            cancellation_requested=cancellation_requested,
        )
        else ""
    )
    if fallback_reason:
        return _fallback(
            file_path, language, source, reason=fallback_reason,
            cancellation_requested=cancellation_requested,
        )

    # A caller's warm worker outlives this call, so only a single-use server is
    # closed on the way out.
    with (ParserWorker() if worker is None else nullcontext(worker)) as active:
        return _parse_in_worker(
            active, file_path, language, source,
            timeout_seconds=float(timeout_seconds),
            max_result_bytes=max_result_bytes,
            memory_limit_bytes=memory_limit_bytes,
            worker_command=worker_command,
            cancellation_requested=cancellation_requested,
            result_validator=result_validator,
        )


def _parse_in_worker(
    worker: ParserWorker,
    file_path: str,
    language: str,
    source: bytes,
    *,
    timeout_seconds: float,
    max_result_bytes: int,
    memory_limit_bytes: int,
    worker_command: Sequence[str] | None,
    cancellation_requested: Callable[[], bool] | None,
    result_validator: Callable[[dict[str, Any]], None] | None,
) -> dict[str, Any]:
    try:
        output, returncode, failure = worker.run(
            file_path=file_path,
            language=language,
            source=source,
            command=worker_command,
            timeout_seconds=timeout_seconds,
            max_result_bytes=max_result_bytes,
            memory_limit_bytes=memory_limit_bytes,
            cancellation_requested=cancellation_requested,
        )
    except ParserWorkerUnavailable:
        return _fallback(
            file_path, language, source, reason="parser_worker_launch_error",
            cancellation_requested=cancellation_requested,
        )
    if failure is None and returncode != 0:
        failure = {
            PARSER_CAPABILITY_DENIED_EXIT: "parser_worker_capability_denied",
            PARSER_MEMORY_LIMIT_EXIT: "parser_worker_memory_limit",
            -signal.SIGXCPU: "parser_worker_timeout",
        }.get(returncode, "parser_worker_crash")
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
        cancellation_requested=cancellation_requested,
    )
