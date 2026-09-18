"""vigil assess kali cero — typed wrapper around cero (TLS-handshake SAN scraper)."""
from __future__ import annotations

import shlex
import sys

from assess.lib import runtime_route
from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "cero",
        help="Run cero inside the runtime container with audit recording (TLS SAN scraper).",
    )
    add_required_kali_flags(p)
    # `-d` is intentionally NOT bound to argparse here: cero's native `-d` is a
    # toggle (filter results to valid domain names only), not a target argument.
    # The target is `--target`/`--domain` or `-l`/`--input-list`; cero's `-d`
    # toggle is exposed as `--only-domains`.
    p.add_argument("--target", "--domain", dest="domain", default="", help="Single domain or CIDR target.")
    p.add_argument(
        "-l",
        "--input-list",
        dest="input_list",
        default="",
        help="File of newline-separated domains/CIDRs (piped to cero on stdin).",
    )
    p.add_argument(
        "-p",
        "--ports",
        dest="ports",
        default="",
        help="Comma-separated ports to probe (default: 443,8443 — cero default).",
    )
    p.add_argument(
        "-c",
        "--concurrency",
        dest="concurrency",
        default="",
        help="Number of concurrent workers (cero default: 100).",
    )
    p.add_argument(
        "-t",
        "--timeout-seconds",
        dest="timeout_seconds",
        default="",
        help="Per-host TCP/TLS timeout in seconds (cero default: 4).",
    )
    p.add_argument(
        "--only-domains",
        dest="only_domains",
        action="store_true",
        help="cero -d toggle: filter results to valid domain names only (strip IPs / wildcards / gibberish).",
    )
    p.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        action="store_true",
        help="cero -v: print 'addr -- [results]' lines and stderr errors.",
    )
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file.")
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def _build_cero_argv(args) -> list[str]:
    cmd: list[str] = ["cero"]
    if args.ports:
        cmd.extend(["-p", args.ports])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.timeout_seconds:
        cmd.extend(["-t", str(args.timeout_seconds)])
    if args.only_domains:
        cmd.append("-d")
    if args.verbose:
        cmd.append("-v")
    if args.output:
        cmd.extend(["-o", args.output])
    if args.domain:
        cmd.append(args.domain)
    return cmd


def _target_entries(args) -> list[str]:
    """Collect cero's target entries from the single-target arg + the -l file.

    The -l file is read HOST-side, best-effort: a missing/unreadable file (cero
    runs in-container, so the path may not exist host-side) just contributes no
    file entries — the fan-out guard warns, it never hard-depends on the file.
    """
    entries: list[str] = []
    if args.domain:
        entries.append(args.domain)
    if args.input_list:
        try:
            with open(args.input_list, encoding="utf-8", errors="ignore") as fh:
                entries.extend(fh.read().splitlines())
        except OSError:
            pass
    return entries


def _warn_excessive_target_ips(args) -> None:
    """CR-22 — estimate cero's distinct target-IP fan-out and WARN if it's too big.

    cero is dispatched via kali_exec, which is in-container-only, so the route is
    fixed to ``container``. (A host path for cero is a separate, larger change.)

    The runtime is resolved ONCE here and threaded explicitly into the guard, so
    the Docker-Desktop gate comes from a single, visible ``detect_runtime()``
    call rather than a hidden re-detect inside ``warn_excessive_target_ips`` —
    keeping the guard deterministic and independently testable.
    """
    runtime = runtime_route.detect_runtime()
    n = runtime_route.count_distinct_target_ips(_target_entries(args))
    runtime_route.warn_excessive_target_ips(n, route="container", tool="cero", runtime=runtime)


def run(args) -> None:
    if not args.domain and not args.input_list:
        print("cero: pass --target/--domain <host-or-cidr> or -l <file>", file=sys.stderr)
        raise AssessError("missing --target/--domain or -l/--input-list")

    cero_argv = _build_cero_argv(args)
    extend_cmd_with_extra_args(cero_argv, args)

    # CR-22 — WARN (never raise) when target-IP fan-out is too large for the
    # in-container path on macOS Docker Desktop.
    _warn_excessive_target_ips(args)

    if args.input_list:
        # cero reads targets from stdin when no positional args are provided.
        # Pipe the file via a sh -c wrapper so the audit row records the
        # canonical invocation (`cat <file> | cero ...`).
        inner = "cat {input} | {cero}".format(
            input=shlex.quote(args.input_list),
            cero=" ".join(shlex.quote(tok) for tok in cero_argv),
        )
        cmd = ["sh", "-c", inner]
    else:
        cmd = cero_argv

    result = kali_exec(cmd, tool_name="cero", **kali_args_to_kwargs(args))
    emit_result(result)
