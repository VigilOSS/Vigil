"""vigil assess kali subfinder — typed wrapper around subfinder inside the runtime.

Provider keys: subfinder reads API keys ONLY from its on-disk
``~/.config/subfinder/provider-config.yaml`` (its native default lookup path),
NOT from arbitrary ``SUBFINDER_*`` env vars. That file is generated at
``vigil runtime start`` from the non-empty ``SUBFINDER_*`` vars in ``.env``
(src/vigil_cli/runtime.py :: ``generate_subfinder_provider_config``), so this
wrapper does not pass ``-provider-config`` — subfinder finds the generated file
automatically. Keys are fail-open: when none are configured subfinder still runs
over its free sources (~60-70% coverage); this wrapper only WARNs.

Per-domain: prefer running subfinder per apex (``-d <apex>``) with a sane
``-timeout`` rather than one ``-dL <list> -all`` mega-run, so one slow/unkeyed
source on one domain cannot stall the whole batch. The composed
``dns-discovery`` verb keeps the ``-dL`` form for throughput but caps it with a
``-timeout`` too (its ``--subfinder-timeout``, default 20s — the same default as
this wrapper), so the ``-all`` batch there is likewise bounded per source.
"""
from __future__ import annotations

import subprocess
import sys

from assess.lib.client import AssessError, default_runtime_container
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)

# Default per-source response timeout (subfinder's ``-timeout``, in seconds:
# "seconds to wait before timing out"). subfinder's own default is 30; a slow or
# unkeyed source can hang a run near that ceiling, so we default to 20 to bound
# per-domain wall time. Operators can override with ``-timeout <n>``.
_DEFAULT_TIMEOUT_SECONDS = 20


def _runtime_has_subfinder_keys(container_name: str | None = None):
    """Best-effort probe: does the runtime have a non-empty subfinder provider
    config (or any SUBFINDER_* key env var)?

    Returns True if keys appear configured, False if definitively absent, or None
    if the probe could not run (docker unreachable / container down). Used only to
    emit a fail-open WARN — subfinder is useful keyless, so we never block on it.
    """
    container_name = container_name or default_runtime_container()
    # Non-empty generated provider-config, OR any SUBFINDER_* var set in the env.
    probe = (
        'test -s "${HOME:-/root}/.config/subfinder/provider-config.yaml"'
        ' || test -s /root/.config/subfinder/provider-config.yaml'
        ' || env | grep -q "^SUBFINDER_[A-Z_]*=."'
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", probe],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "subfinder",
        help="Run subfinder inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-d", dest="domain", default="", help="Single domain.")
    p.add_argument("-dL", dest="domain_list", default="", help="File of newline-separated domains.")
    p.add_argument("-all", dest="all_sources", action="store_true", help="-all sources (slow but exhaustive).")
    p.add_argument("-recursive", dest="recursive", action="store_true", help="-recursive resolution.")
    p.add_argument("-t", dest="threads", default="", help="Worker threads.")
    p.add_argument(
        "-timeout",
        dest="timeout_seconds",
        default=str(_DEFAULT_TIMEOUT_SECONDS),
        help=f"subfinder -timeout: seconds to wait per source before timing out "
             f"(default {_DEFAULT_TIMEOUT_SECONDS}; bounds per-domain wall time). "
             f"Pass '' / 0 to use subfinder's own default.",
    )
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent (suppress info).")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.domain and not args.domain_list:
        print("subfinder: pass -d <domain> or -dL <list>", file=sys.stderr)
        raise AssessError("missing -d or -dL")
    cmd: list[str] = ["subfinder"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.domain_list:
        cmd.extend(["-dL", args.domain_list])
    if args.all_sources:
        cmd.append("-all")
    if args.recursive:
        cmd.append("-recursive")
    if args.threads:
        cmd.extend(["-t", str(args.threads)])
    # Per-source -timeout default (CR-7): bound per-domain wall time. Idempotent —
    # skip the typed value when the operator already passed -timeout via --extra-args
    # so we never emit a duplicate flag.
    timeout_seconds = str(getattr(args, "timeout_seconds", "") or "").strip()
    passthrough_has_timeout = "-timeout" in (getattr(args, "extra_args", "") or "").split()
    if timeout_seconds and timeout_seconds != "0" and not passthrough_has_timeout:
        cmd.extend(["-timeout", timeout_seconds])
    if args.output:
        cmd.extend(["-o", args.output])
    if args.silent:
        cmd.append("-silent")
    extend_cmd_with_extra_args(cmd, args)

    # Fail-open keyless WARN (CR-7): subfinder is useful without provider keys, so
    # never block — just surface that a keyless run is happening and how to fix it.
    if _runtime_has_subfinder_keys() is False:
        print(
            "subfinder: no provider keys configured — running keyless (free sources only, "
            "~60-70% coverage). For the free-key minimum set SUBFINDER_CHAOS_API_KEY + "
            "SUBFINDER_GITHUB_TOKEN in <install>/.env and re-run `vigil runtime start`. "
            "See agent/references/tools/recon/subfinder.md.",
            file=sys.stderr,
        )

    result = kali_exec(cmd, tool_name="subfinder", **kali_args_to_kwargs(args))
    emit_result(result)
