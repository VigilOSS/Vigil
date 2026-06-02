"""vigil assess kali nuclei — typed wrapper around nuclei inside the runtime."""
from __future__ import annotations

import fcntl
import os
import sys
from contextlib import contextmanager
from pathlib import Path

from assess.lib.client import AssessError
from assess.lib.config import load_config
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


_NUCLEI_LOCK_BASENAME = ".nuclei.lock"


@contextmanager
def _nuclei_engagement_lock(engagement_dir: Path):
    """C32: per-engagement file lock so two concurrent ``vigil assess kali nuclei``
    invocations cannot corrupt each other's output. The lockfile records the
    PID of the holding process. If a stale lockfile exists for a PID that is
    no longer alive (crashed run), force-release and acquire.

    Raises AssessError on contention with a clear message naming the holding
    PID and the lockfile path so the operator can debug quickly.
    """
    scans_dir = engagement_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    lock_path = scans_dir / _NUCLEI_LOCK_BASENAME
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # Read prior PID, check liveness, force-release if stale.
            os.lseek(fd, 0, os.SEEK_SET)
            prior_pid_raw = os.read(fd, 64).decode("ascii", errors="ignore").strip()
            prior_pid = None
            try:
                prior_pid = int(prior_pid_raw) if prior_pid_raw else None
            except ValueError:
                prior_pid = None
            stale = False
            if prior_pid is not None:
                try:
                    os.kill(prior_pid, 0)
                except (ProcessLookupError, PermissionError):
                    # PermissionError means the PID exists but is owned by
                    # another user — treat as alive (cannot safely force-release).
                    if isinstance(sys.exc_info()[1], ProcessLookupError):
                        stale = True
                except OSError:
                    stale = True
            else:
                # No recorded PID — the previous holder crashed before writing
                # its PID. Treat as stale and force-release.
                stale = True
            if stale:
                # Force-acquire: re-flock LOCK_EX | LOCK_NB after the prior
                # owner released by dying. If the re-flock itself races
                # (another writer is mid-acquire — lock taken but PID not yet
                # written), convert BlockingIOError into the same actionable
                # AssessError as a normal contention so operators see a clean
                # message instead of an internal traceback.
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    os.close(fd)
                    raise AssessError(
                        f"nuclei lock contention on retry "
                        f"(lockfile: {lock_path}). Another process is "
                        "mid-acquire (lock taken but PID not yet recorded). "
                        "Wait a moment and re-run, or remove the lockfile "
                        "manually if no nuclei process is actually running."
                    ) from exc
            else:
                os.close(fd)
                raise AssessError(
                    f"nuclei lock already held by PID {prior_pid or '<unknown>'} "
                    f"(lockfile: {lock_path}). Concurrent nuclei runs in the same "
                    "engagement can corrupt each other's jsonl output. Wait for the "
                    "prior run to finish, or if it has crashed remove the lockfile "
                    "manually."
                )
        # Record this process's PID so a future contender can detect staleness.
        os.lseek(fd, 0, os.SEEK_SET)
        os.ftruncate(fd, 0)
        os.write(fd, f"{os.getpid()}\n".encode("ascii"))
        yield lock_path
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            os.close(fd)
        except OSError:
            pass


def _resolve_output_host_path(output_arg: str, engagement_dir: Path | None) -> Path | None:
    """Map the operator-supplied `-o` path (engagement-relative inside the
    container) to a path on the host filesystem under the engagement mount.

    - `scans/foo.jsonl`               → `<engagement_dir>/scans/foo.jsonl`
    - `/engagements/<key>/scans/foo`  → `<engagement_dir>/scans/foo`
    - `/some/absolute/host/path`      → returned as-is when it exists on host

    Returns None when no plausible host path can be derived (no engagement
    context, or path shape we do not recognize).
    """
    if not output_arg or engagement_dir is None:
        return None
    candidate = Path(output_arg)
    if candidate.is_absolute():
        parts = candidate.parts
        # /engagements/<key>/<rest...> → <engagement_dir>/<rest...>
        if len(parts) >= 4 and parts[1] == "engagements":
            return engagement_dir.joinpath(*parts[3:])
        # Some non-mount absolute path — fall back to the literal path so a
        # test or operator running nuclei with a host-side `-o` still gets
        # inspected.
        return candidate
    return engagement_dir / candidate


def _zero_byte_post_check(args, result, engagement_dir: Path | None) -> None:
    """C32: distinguish "no nuclei matches" (legitimate zero result) from
    "template loader failed at startup" (failure mode). The stderr line
    'Templates loaded for current scan: N' is the source of truth — if the
    output file is empty AND that line is absent, treat as failure.

    Does NOT raise — the audit row already records the run. Surfaces a warning
    so the operator does not record a phantom "no matches" finding when nuclei
    actually failed to start.

    Inspects the `-o` output artifact (resolved to a host path under the
    engagement mount), NOT the wrapper's stdout capture: `-jsonl`/`-silent`
    workflows route findings through the `-o` file while stdout stays quiet,
    so keying on `stdout_path` would warn on legitimate runs and miss real
    loader failures.
    """
    output_arg = (getattr(args, "output", "") or "").strip()
    if not output_arg:
        return
    host_path = _resolve_output_host_path(output_arg, engagement_dir)
    # No engagement context or unresolvable path: cannot stat the artifact.
    # The audit row still records the run, and the operator can spot the
    # failure via stderr — fail-open rather than warn on incomplete data.
    if host_path is None or not host_path.exists():
        return
    try:
        size = host_path.stat().st_size
    except OSError:
        return
    if size > 0:
        return
    stderr_preview = ""
    if isinstance(result, dict):
        stderr_preview = result.get("stderr_preview") or ""
    else:
        stderr_preview = getattr(result, "stderr_preview", "") or ""
    if "Templates loaded for current scan:" not in stderr_preview:
        print(
            f"WARN nuclei: output file {host_path} is zero bytes AND "
            "'Templates loaded for current scan:' is absent from stderr — "
            "template loader likely failed at startup, NOT a legitimate no-match "
            "run. Re-run with explicit -t paths and confirm the template set "
            "loads cleanly. (See agent/skills/nuclei-scanning/SKILL.md "
            "'Known fingerprint-suppression cases' for context.)",
            file=sys.stderr,
        )


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "nuclei",
        help="Run nuclei inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Single target URL.")
    p.add_argument("-l", dest="target_list", default="", help="File of newline-separated targets.")
    p.add_argument("-t", dest="templates", default="", help="Comma-separated template list.")
    p.add_argument("-tags", dest="tags", default="", help="Filter by tag list (comma-separated).")
    p.add_argument("-as", dest="automatic_scan", action="store_true", help="-as automatic scan.")
    p.add_argument("-severity", dest="severity", default="", help="Comma-separated severity list.")
    p.add_argument("-rate-limit", dest="rate_limit", default="", help="Requests per second.")
    p.add_argument("-c", dest="concurrency", default="", help="Worker concurrency.")
    p.add_argument("-bs", dest="bulk_size", default="", help="Bulk batch size.")
    p.add_argument("-stream", dest="stream", action="store_true", help="-stream output mode.")
    p.add_argument("-jsonl", dest="jsonl", action="store_true", help="-jsonl output.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("nuclei: pass -u <url> or -l <list>", file=sys.stderr)
        raise AssessError("missing -u or -l")
    cmd: list[str] = ["nuclei"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.templates:
        cmd.extend(["-t", args.templates])
    if args.tags:
        cmd.extend(["-tags", args.tags])
    if args.automatic_scan:
        cmd.append("-as")
    if args.severity:
        cmd.extend(["-severity", args.severity])
    if args.rate_limit:
        cmd.extend(["-rate-limit", str(args.rate_limit)])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.bulk_size:
        cmd.extend(["-bs", str(args.bulk_size)])
    if args.stream:
        cmd.append("-stream")
    if args.jsonl:
        cmd.append("-jsonl")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    # C32: lock + zero-byte post-check. Lock is per-engagement so concurrent
    # invocations cannot corrupt each other's jsonl artifacts. Test contexts
    # that do not provide an engagement directory (argv-shape tests) skip the
    # lock — the only operational guarantee it provides is concurrency
    # safety, which is moot when no real exec happens.
    engagement_dir: Path | None = None
    try:
        cfg = load_config(getattr(args, "engagement_dir", None))
        engagement_dir = Path(cfg.engagement_dir)
    except SystemExit:
        engagement_dir = None
    if engagement_dir is not None:
        with _nuclei_engagement_lock(engagement_dir):
            result = kali_exec(cmd, tool_name="nuclei", **kali_args_to_kwargs(args))
    else:
        result = kali_exec(cmd, tool_name="nuclei", **kali_args_to_kwargs(args))
    _zero_byte_post_check(args, result, engagement_dir)
    emit_result(result)
