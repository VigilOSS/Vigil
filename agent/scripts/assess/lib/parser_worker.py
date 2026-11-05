"""Resource-limited child process for structural parser execution.

``--serve <fd>`` runs the warm fork server a parent ``ParserWorker`` drives
over a Unix socket. The server never reads source bytes: it loads every
grammar once, then forks one fresh child per request. Each child takes the
request's resource limits and the audit guard before it opens the request, so
every file still parses in its own limited process from the same warm state.
"""
from __future__ import annotations

import gc
import hashlib
import json
import os
import resource
import signal
import socket
import stat
import struct
import sys
import traceback
import warnings
from pathlib import Path
from typing import Any, NoReturn


PARSER_PROTOCOL_SCHEMA = "vigil-structural-parser/v1"
PARSER_CAPABILITY_DENIED_EXIT = 78
PARSER_MEMORY_LIMIT_EXIT = 79
SERVER_PROTOCOL_ERROR_EXIT = 65
# What a ParserWorker writes into the server's private `request/` directory.
REQUEST_SOURCE_NAME = "source.bin"
REQUEST_NAME = "request.json"
SERVER_FRAME_HEADER = struct.Struct("!I")
MAX_SERVER_FRAME_BYTES = 64 * 1024
_REQUEST_FIELDS = frozenset(
    {
        "schema",
        "file_path",
        "language",
        "source_path",
        "source_size",
        "source_sha256",
    }
)
_WRITE_OPEN_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
_MUTATION_EVENTS = frozenset(
    {
        "os.chdir",
        "os.chmod",
        "os.chown",
        "os.link",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.symlink",
        "os.truncate",
        "shutil.copyfile",
        "shutil.copymode",
        "shutil.copystat",
        "shutil.rmtree",
    }
)


def install_parser_audit_guard() -> None:
    """Deny network, process creation, and filesystem mutation in the worker."""

    def audit(event: str, args: tuple[object, ...]) -> None:
        if event.startswith("socket."):
            raise PermissionError("parser worker denied capability: socket")
        if (
            event == "subprocess.Popen"
            or event == "os.system"
            or event.startswith("os.exec")
            or event.startswith("os.spawn")
            or event in {"os.fork", "os.forkpty", "pty.spawn"}
        ):
            raise PermissionError("parser worker denied capability: process")
        if event == "open":
            mode = args[1] if len(args) > 1 else None
            flags = args[2] if len(args) > 2 else None
            if (
                isinstance(mode, str)
                and any(marker in mode for marker in ("w", "a", "+", "x"))
            ) or (
                isinstance(flags, int) and bool(flags & _WRITE_OPEN_FLAGS)
            ):
                raise PermissionError(
                    "parser worker denied capability: filesystem-write"
                )
        if event in _MUTATION_EVENTS:
            raise PermissionError("parser worker denied capability: filesystem-write")

    sys.addaudithook(audit)


def _set_resource_limits() -> None:
    cpu_seconds = int(os.environ["VIGIL_PARSER_CPU_SECONDS"])
    memory_bytes = int(os.environ["VIGIL_PARSER_MEMORY_BYTES"])
    if cpu_seconds < 1 or memory_bytes < 16 * 1024 * 1024:
        raise ValueError("invalid parser resource limits")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    address_limit = getattr(resource, "RLIMIT_AS", None)
    if address_limit is not None:
        try:
            resource.setrlimit(address_limit, (memory_bytes, memory_bytes))
        except (OSError, ValueError):
            # Darwin cannot lower RLIMIT_AS below already-mapped interpreter
            # regions. The parent independently enforces the resident cap.
            pass
    nofile_soft, nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    nofile_limit = min(64, nofile_soft, nofile_hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (nofile_limit, nofile_limit))


def _read_request(path: Path) -> tuple[dict[str, Any], bytes]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16 * 1024:
        raise ValueError("invalid parser request file")
    request = json.loads(path.read_bytes())
    if not isinstance(request, dict) or set(request) != _REQUEST_FIELDS:
        raise ValueError("invalid parser request")
    if request.get("schema") != PARSER_PROTOCOL_SCHEMA:
        raise ValueError("invalid parser protocol schema")
    source_path = Path(str(request.get("source_path") or ""))
    source_metadata = source_path.lstat()
    source_size = request.get("source_size")
    if (
        not stat.S_ISREG(source_metadata.st_mode)
        or type(source_size) is not int
        or source_size < 0
        or source_metadata.st_size != source_size
    ):
        raise ValueError("invalid parser source file")
    source = source_path.read_bytes()
    if (
        len(source) != source_size
        or hashlib.sha256(source).hexdigest() != request.get("source_sha256")
    ):
        raise ValueError("parser source identity mismatch")
    if not isinstance(request.get("file_path"), str) or not isinstance(
        request.get("language"), str
    ):
        raise ValueError("invalid parser source identity")
    return request, source


def _write_envelope(payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    maximum = int(os.environ["VIGIL_PARSER_MAX_RESULT_BYTES"])
    if len(encoded) > maximum:
        encoded = json.dumps(
            {
                "schema": PARSER_PROTOCOL_SCHEMA,
                "status": "error",
                "reason": "parser_worker_result_limit",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    offset = 0
    while offset < len(encoded):
        offset += os.write(sys.stdout.fileno(), encoded[offset:])


def encode_server_frame(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_SERVER_FRAME_BYTES:
        raise ValueError("parser server frame is too large")
    return SERVER_FRAME_HEADER.pack(len(body)) + body


def decode_server_frame(buffer: bytearray) -> dict[str, Any] | None:
    """Pop one complete frame from *buffer*, or return None while it is partial."""
    if len(buffer) < SERVER_FRAME_HEADER.size:
        return None
    (size,) = SERVER_FRAME_HEADER.unpack_from(buffer)
    if size > MAX_SERVER_FRAME_BYTES:
        raise ValueError("parser server frame is too large")
    end = SERVER_FRAME_HEADER.size + size
    if len(buffer) < end:
        return None
    payload = json.loads(bytes(buffer[SERVER_FRAME_HEADER.size : end]))
    del buffer[:end]
    if not isinstance(payload, dict):
        raise ValueError("parser server frame is not an object")  # noqa: TRY004
    return payload


def _receive_frame(
    control: socket.socket, buffer: bytearray, *, max_fds: int = 0,
) -> tuple[dict[str, Any] | None, list[int]]:
    fds: list[int] = []
    while True:
        frame = decode_server_frame(buffer)
        if frame is not None:
            return frame, fds
        if max_fds and not fds:
            data, received, flags, _address = socket.recv_fds(control, 4096, max_fds)
            fds.extend(received)
            if flags & getattr(socket, "MSG_CTRUNC", 0):
                raise ValueError("parser server descriptors were truncated")
        else:
            data = control.recv(4096)
        if not data:
            for fd in fds:
                os.close(fd)
            return None, []
        buffer.extend(data)


def _close_inherited_descriptors() -> None:
    directory = "/proc/self/fd" if os.path.isdir("/proc/self/fd") else "/dev/fd"
    try:
        descriptors = [int(name) for name in os.listdir(directory)]
    except (OSError, ValueError):
        descriptors = list(range(3, 1024))
    for fd in descriptors:
        if fd > 2:
            try:
                os.close(fd)
            except OSError:
                pass


def _run_forked_request(frame: dict[str, Any], fds: list[int]) -> NoReturn:
    code = 1
    try:
        os.setsid()
        os.dup2(fds[0], 1)
        os.dup2(fds[1], 2)
        _close_inherited_descriptors()
        os.chdir(str(frame["cwd"]))
        os.environ.update({str(key): str(value) for key, value in frame["limits"].items()})
        request_path = str(frame["request"])
        command = frame.get("command")
        if command:
            for restored in (signal.SIGPIPE, signal.SIGXFSZ):
                signal.signal(restored, signal.SIG_DFL)
            arguments = [str(item) for item in command] + [request_path]
            os.execvpe(arguments[0], arguments, dict(os.environ))
        code = main([request_path])
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    except BaseException:  # noqa: BLE001 - report like an uncaught child exception
        try:
            traceback.print_exc()
        except BaseException:  # noqa: BLE001, S110 - the exit status still reports the crash
            pass
        code = 1
    finally:
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except BaseException:  # noqa: BLE001, S110 - unflushed diagnostics are capped anyway
                pass
        os._exit(code)


def kill_process_group(pid: int) -> None:
    """SIGKILL a request child's session, or the child alone before setsid."""
    for kill in (os.killpg, os.kill):
        try:
            kill(pid, signal.SIGKILL)
            return
        except OSError:
            continue


def _warm_parsers() -> None:
    """Load every grammar and query plan once so forked children start warm."""
    from assess.lib.treesitter_index import SUPPORTED_LANGUAGES, index_file

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for language in sorted(SUPPORTED_LANGUAGES):
            try:
                index_file("warm", language, source=b"\n")
            except Exception:  # noqa: BLE001, S112 - the child reports its own grammar failure
                continue
    # Children's collections then skip the warm objects instead of copying
    # their pages on write; new objects are collected as before.
    gc.freeze()


def serve(control_fd: int) -> int:
    """Fork one limited child per request; never read request bytes here."""
    control = socket.socket(fileno=control_fd)
    buffer = bytearray()
    active: int | None = None
    _warm_parsers()
    try:
        control.sendall(encode_server_frame({"ready": True}))
        while True:
            frame, fds = _receive_frame(control, buffer, max_fds=2)
            if frame is None:
                return 0
            if frame.get("op") != "run" or len(fds) != 2:
                for fd in fds:
                    os.close(fd)
                return SERVER_PROTOCOL_ERROR_EXIT
            try:
                pid = os.fork()
            except OSError:
                pid = -1
            if pid == 0:
                _run_forked_request(frame, fds)
            for fd in fds:
                os.close(fd)
            if pid < 0:
                control.sendall(encode_server_frame({"error": "fork"}))
                continue
            active = pid
            control.sendall(encode_server_frame({"pid": pid}))
            # The parent may kill the child's group until it asks for the
            # reap, so the pid cannot be recycled under it.
            reap, _ = _receive_frame(control, buffer)
            if reap is None or reap.get("op") != "reap":
                return 0 if reap is None else SERVER_PROTOCOL_ERROR_EXIT
            _, status = os.waitpid(pid, 0)
            active = None
            control.sendall(
                encode_server_frame({"returncode": os.waitstatus_to_exitcode(status)})
            )
    except (BrokenPipeError, ConnectionResetError):
        return 0
    except ValueError:
        return SERVER_PROTOCOL_ERROR_EXIT
    finally:
        # A parent that leaves mid-request never leaves its child running, and
        # one killed before its own cleanup leaves no copy of the source behind.
        if active is not None:
            kill_process_group(active)
            os.waitpid(active, 0)
        for name in (REQUEST_SOURCE_NAME, REQUEST_NAME):
            try:
                os.unlink(os.path.join("request", name))
            except OSError:
                pass


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) == 2 and arguments[0] == "--serve":
        return serve(int(arguments[1]))
    if len(arguments) != 1:
        return 64
    try:
        _set_resource_limits()
        install_parser_audit_guard()
        request, source = _read_request(Path(arguments[0]))
        from assess.lib.treesitter_index import index_file

        result = index_file(
            str(request["file_path"]),
            str(request["language"]),
            source=source,
        )
        _write_envelope(
            {
                "schema": PARSER_PROTOCOL_SCHEMA,
                "status": "ok",
                "result": result,
            }
        )
    except MemoryError:
        return PARSER_MEMORY_LIMIT_EXIT
    except PermissionError as exc:
        if "parser worker denied capability" not in str(exc):
            raise
        return PARSER_CAPABILITY_DENIED_EXIT
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
