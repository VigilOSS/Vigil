"""Resource-limited child process for structural parser execution."""
from __future__ import annotations

import hashlib
import json
import os
import resource
import stat
import sys
from pathlib import Path
from typing import Any


PARSER_PROTOCOL_SCHEMA = "vigil-structural-parser/v1"
PARSER_CAPABILITY_DENIED_EXIT = 78
PARSER_MEMORY_LIMIT_EXIT = 79
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


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
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
