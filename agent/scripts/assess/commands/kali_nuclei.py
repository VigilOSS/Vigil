"""vigil assess kali nuclei — typed wrapper around nuclei inside the runtime."""
from __future__ import annotations

import fcntl
import hashlib
import os
import shlex
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from assess.lib.client import AssessError
from assess.lib.config import load_config
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    count_list_targets,
    safe_engagement_dir,
    emit_result,
    extend_cmd_with_extra_args,
    incomplete_list_run_warning,
    kali_args_to_kwargs,
    kali_exec,
)

# Pre-flight budget helpers (kali_cli argparse seam); imported directly so this
# unit need not touch the shared kali facade module.
from assess.lib.kali_cli import (
    coerce_float,
    estimate_list_sweep_seconds,
    preflight_timeout_guard,
)


_NUCLEI_LOCK_TIMEOUT_S = 1800.0

# nuclei CLI defaults used by the pre-flight runtime floor when a knob is unset:
# -timeout 10s/request, -c 25 workers, -rl 150 req/s. The floor assumes ≥1
# request-round per host (nuclei fires many templates per host, so this UNDER-
# counts — a conservative floor that only fires when even it exceeds --timeout).
_NUCLEI_DEFAULT_HTTP_TIMEOUT = 10.0
_NUCLEI_DEFAULT_CONCURRENCY = 25
_NUCLEI_DEFAULT_RATE_LIMIT = 150.0

# Politeness/safety exclude-tags injected by default when the operator does not
# supply their own. Keeps broad sweeps from firing DoS/fuzz/intrusive/brute-force
# templates against production-like in-scope targets (CR-27).
_DEFAULT_EXCLUDE_TAGS = "dos,fuzz,intrusive,brute-force"
_EXCLUDE_TAGS_FLAGS = ("-exclude-tags", "-etags")


def _operator_passed_exclude_tags(args) -> bool:
    """True when the operator supplied an exclude-tags flag via --extra-args.

    The typed -exclude-tags/-etags flag is handled by argparse; this covers the
    raw passthrough path so the default injection stays idempotent and never
    double-adds an exclude-tags flag.
    """
    extra = getattr(args, "extra_args", "") or ""
    if not extra:
        return False
    try:
        tokens = shlex.split(extra)
    except ValueError:
        return False
    return any(tok in _EXCLUDE_TAGS_FLAGS for tok in tokens)


def _lock_holder_is_stale(fd: int) -> bool:
    """True when the PID recorded in the lockfile is no longer alive.

    Stale lockfiles (the holder crashed) must be reclaimable so a dead run
    can't wedge the output path forever. A PID owned by another user is treated
    as ALIVE (we can't safely force-release it). No recorded PID means the
    holder crashed before writing one — stale.
    """
    os.lseek(fd, 0, os.SEEK_SET)
    prior_pid_raw = os.read(fd, 64).decode("ascii", errors="ignore").strip()
    if not prior_pid_raw:
        return True
    try:
        prior_pid = int(prior_pid_raw)
    except ValueError:
        return True
    try:
        os.kill(prior_pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    except OSError:
        return True
    return False


@contextmanager
def _nuclei_output_lock(lock_path: Path, *, timeout_s: float = _NUCLEI_LOCK_TIMEOUT_S):
    """Serialize only the nuclei runs that share the SAME ``-o`` output file.

    L3-1: a per-*engagement* exclusive lock hard-failed every concurrent
    ``vigil assess kali nuclei`` after the first, killing the 4-6-agent swarm.
    But two nuclei runs corrupt each other ONLY when they append to the same
    jsonl artifact — so the lock is keyed on the OUTPUT PATH. Runs with distinct
    ``-o`` files (or none) take different locks and run fully in parallel.

    When two runs genuinely target the same file, the contender BLOCKS (up to
    ``timeout_s``, polling) until the holder finishes and then runs — instead of
    hard-failing the dispatch. A stale lockfile (holder PID dead) is reclaimed
    immediately. Only a genuinely hung holder past the timeout raises.
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    deadline = time.monotonic() + timeout_s
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if _lock_holder_is_stale(fd):
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        pass
                if time.monotonic() >= deadline:
                    os.close(fd)
                    raise AssessError(
                        f"nuclei output lock on {lock_path} still held after "
                        f"{int(timeout_s)}s — a concurrent run targeting the same "
                        "-o file has not finished. Use a distinct -o path per run "
                        "so sweeps run in parallel, or remove the lockfile if no "
                        "nuclei process is actually running."
                    )
                time.sleep(0.5)
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


def _nuclei_lock_path_for(output_arg: str, engagement_dir: Path | None) -> Path | None:
    """Return the lockfile path that guards ``output_arg``, or None for no lock.

    No ``-o`` output → None (the wrapper's stdout capture is per-run-uuid, so
    nothing is shared and nothing needs a lock). Otherwise the lock is a sidecar
    next to the resolved host output path, so distinct outputs never contend.
    """
    if engagement_dir is None:
        return None
    output_arg = (output_arg or "").strip()
    if not output_arg:
        return None
    host_out = _resolve_output_host_path(output_arg, engagement_dir)
    if host_out is not None:
        return host_out.parent / f".{host_out.name}.lock"
    digest = hashlib.sha1(output_arg.encode("utf-8")).hexdigest()[:16]
    return engagement_dir / "scans" / f".nuclei-{digest}.lock"


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
    p.add_argument(
        "-exclude-tags",
        "-etags",
        dest="exclude_tags",
        default="",
        help=(
            "Comma-separated tags to exclude. When unset, the wrapper injects a "
            "politeness/safety default of 'dos,fuzz,intrusive,brute-force'. Pass "
            "your own value to override (it is used verbatim — no merge)."
        ),
    )
    p.add_argument("-as", dest="automatic_scan", action="store_true",
                   help="-as automatic (tech-matched) scan. Additive — lead with explicit -t, "
                        "because a CDN/WAF defeats tech fingerprinting so -as under-fires alone.")
    p.add_argument("-severity", dest="severity", default="", help="Comma-separated severity list.")
    p.add_argument("-rate-limit", dest="rate_limit", default="", help="Requests per second.")
    p.add_argument(
        "-mhe",
        "-max-host-error",
        dest="max_host_error",
        default="50",
        help=(
            "Max errors per host before nuclei abandons it (default 50). nuclei's own "
            "default (~30) makes a WAF's 403 storm silently kill template coverage on the "
            "hardest hosts; the raised default keeps the sweep on-host. Pass 0 only after "
            "confirming the installed nuclei treats 0 as unlimited (vigil assess kali "
            "tool-help nuclei)."
        ),
    )
    p.add_argument("-random-agent", dest="random_agent", action="store_true",
                   help="-random-agent: rotate the User-Agent so a UA-based scanner block does "
                        "not drop every request.")
    p.add_argument("-H", "-header", dest="headers", action="append", default=None,
                   help="Extra request header (repeatable), e.g. -H 'Cookie: s=...'. Program "
                        "attribution headers are injected automatically on top of these.")
    p.add_argument("-timeout", dest="timeout_http", default="", help="Per-request timeout (seconds).")
    p.add_argument("-retries", dest="retries", default="", help="Retries per request.")
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
    # Default-inject a politeness/safety exclude-tags guard so broad sweeps do
    # not fire DoS/fuzz/intrusive/brute-force templates against production-like
    # in-scope targets (CR-27). Idempotent + operator-overridable: skip when the
    # operator supplied -exclude-tags/-etags as a typed flag OR via --extra-args.
    exclude_tags = (getattr(args, "exclude_tags", "") or "").strip()
    if exclude_tags:
        cmd.extend(["-exclude-tags", exclude_tags])
    elif not _operator_passed_exclude_tags(args):
        cmd.extend(["-exclude-tags", _DEFAULT_EXCLUDE_TAGS])
        print(
            f"nuclei: injected default -exclude-tags '{_DEFAULT_EXCLUDE_TAGS}' "
            "(politeness/safety; pass your own -exclude-tags to override). The "
            "resolved_argv in the result shows the full command that ran.",
            file=sys.stderr,
        )
    if args.automatic_scan:
        cmd.append("-as")
    if args.severity:
        cmd.extend(["-severity", args.severity])
    if args.rate_limit:
        cmd.extend(["-rate-limit", str(args.rate_limit)])
    # WAF-resilience: keep nuclei on a host through a 403 storm instead of
    # abandoning it after ~30 errors. Always passed (default 50) unless overridden.
    mhe = (getattr(args, "max_host_error", "") or "").strip()
    if mhe:
        cmd.extend(["-mhe", str(mhe)])
    if getattr(args, "random_agent", False):
        cmd.append("-random-agent")
    for header in getattr(args, "headers", None) or []:
        cmd.extend(["-H", header])
    if getattr(args, "timeout_http", ""):
        cmd.extend(["-timeout", str(args.timeout_http)])
    if getattr(args, "retries", ""):
        cmd.extend(["-retries", str(args.retries)])
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

    engagement_dir: Path | None = None
    try:
        cfg = load_config(getattr(args, "engagement_dir", None))
        engagement_dir = Path(cfg.engagement_dir)
    except SystemExit:
        engagement_dir = None

    # Count the -l host list once: it feeds BOTH the pre-flight sizing floor and
    # the post-run incompleteness guard below.
    total = count_list_targets(
        args.target_list, engagement_dir=safe_engagement_dir(args)
    ) if args.target_list else 0

    # Pre-flight sizing floor (I-9b#1). A nuclei sweep over a large host LIST under
    # a low -rl / per-request -timeout cannot finish before the wrapper --timeout —
    # it is SIGTERM-killed part-way and the unscanned remainder reads as a clean
    # negative. Warn BEFORE the run (the floor under-counts the per-host template
    # volume, so warn-only). The post-run incompleteness guard catches the rest.
    if total > 1:
        est = estimate_list_sweep_seconds(
            targets=total,
            passes=1,
            per_request_seconds=coerce_float(
                getattr(args, "timeout_http", ""), _NUCLEI_DEFAULT_HTTP_TIMEOUT
            ),
            workers=int(coerce_float(getattr(args, "concurrency", ""), _NUCLEI_DEFAULT_CONCURRENCY)),
            rate_limit=coerce_float(getattr(args, "rate_limit", ""), _NUCLEI_DEFAULT_RATE_LIMIT),
        )
        preflight_timeout_guard(
            verb="nuclei",
            internal_budget_s=est,
            timeout=getattr(args, "timeout", None),
            warn=lambda m: print(f"WARN {m}", file=sys.stderr),
            sizing_hint=(
                "Split the host list, raise --timeout to fit, or raise -rl/-c so the "
                "sweep finishes before the wall."
            ),
        )

    lock_path = _nuclei_lock_path_for(getattr(args, "output", ""), engagement_dir)
    if lock_path is not None:
        with _nuclei_output_lock(lock_path):
            result = kali_exec(cmd, tool_name="nuclei", **kali_args_to_kwargs(args))
    else:
        result = kali_exec(cmd, tool_name="nuclei", **kali_args_to_kwargs(args))
    _zero_byte_post_check(args, result, engagement_dir)

    # Incomplete-run guard: a timed-out nuclei sweep over a host LIST scanned only
    # part of it, so the absence of findings for the unscanned remainder is not a
    # clean negative. (Distinct from _zero_byte_post_check, which catches a
    # template-loader failure.)
    note = incomplete_list_run_warning(
        tool="nuclei", total_targets=total,
        timed_out=getattr(result, "timed_out", False),
        return_code=getattr(result, "return_code", None),
        stdout_preview=getattr(result, "stdout_preview", "") or "",
        stderr_preview=getattr(result, "stderr_preview", "") or "",
    )
    if note:
        print(f"WARN {note}", file=sys.stderr)
    emit_result(result)
