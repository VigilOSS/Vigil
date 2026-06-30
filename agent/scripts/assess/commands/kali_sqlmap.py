"""vigil assess kali sqlmap — typed wrapper around sqlmap inside the runtime."""
from __future__ import annotations

import sys

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)

# Pre-flight budget guard (kali_cli argparse seam); imported directly so this
# unit need not touch the shared kali facade module.
from assess.lib.kali_cli import coerce_float, preflight_timeout_guard

# A "heavy" sqlmap config (deep --level/--risk payload set, or table enumeration/
# dump) routinely runs many minutes against a single injectable param. sqlmap has
# no total-runtime cap flag, so the foot-gun is a heavy config under a short
# --timeout: it is SIGTERM-killed mid-enumeration and the aborted run reads as
# "not injectable" / "nothing to dump". This conservative floor is the wall-clock
# below which a heavy run is flagged pre-flight (I-9b#1 class).
_SQLMAP_HEAVY_FLOOR_S = 600
_SQLMAP_HEAVY_LEVEL = 4
_SQLMAP_HEAVY_RISK = 3


def _sqlmap_is_heavy(args) -> bool:
    """True when the config implies a long, payload-heavy run.

    Deep ``--level``/``--risk`` multiply the payload set per param; ``--dump``/
    ``--tables`` add enumeration that walks the DBMS over the (slow) injection.
    """
    if coerce_float(getattr(args, "level", ""), 0) >= _SQLMAP_HEAVY_LEVEL:
        return True
    if coerce_float(getattr(args, "risk", ""), 0) >= _SQLMAP_HEAVY_RISK:
        return True
    return bool(getattr(args, "dump", False) or getattr(args, "tables", False))


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "sqlmap",
        help="Run sqlmap inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Target URL with parameters.")
    p.add_argument("-r", dest="request_file", default="", help="HTTP request file.")
    p.add_argument("--data", dest="post_data", default="", help="POST data string.")
    p.add_argument("--method", dest="method", default="", help="HTTP method.")
    # Note: --technique here is sqlmap's own flag (BEUSTQ); it's distinct
    # from the audit-flag --technique that add_required_kali_flags registers.
    # We rename the destination to sql_technique so they don't collide.
    p.add_argument(
        "--sql-technique",
        dest="sql_technique",
        default="",
        help="sqlmap --technique flag (e.g. BEUSTQ).",
    )
    p.add_argument("--level", dest="level", default="", help="sqlmap --level (1-5).")
    p.add_argument("--risk", dest="risk", default="", help="sqlmap --risk (1-3).")
    p.add_argument("--threads", dest="threads", default="", help="sqlmap --threads.")
    p.add_argument("--batch", dest="batch", action="store_true", help="--batch (non-interactive).")
    p.add_argument("--dbms", dest="dbms", default="", help="Force DBMS detection.")
    p.add_argument("--tables", dest="tables", action="store_true", help="--tables enumeration.")
    p.add_argument("--dump", dest="dump", action="store_true", help="--dump table contents.")
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.target_url and not args.request_file:
        print("sqlmap: pass -u <url> or -r <request-file>", file=sys.stderr)
        raise AssessError("missing -u or -r")
    cmd: list[str] = ["sqlmap"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.request_file:
        cmd.extend(["-r", args.request_file])
    if args.post_data:
        cmd.extend(["--data", args.post_data])
    if args.method:
        cmd.extend(["--method", args.method])
    if args.sql_technique:
        cmd.append(f"--technique={args.sql_technique}")
    if args.level:
        cmd.extend(["--level", str(args.level)])
    if args.risk:
        cmd.extend(["--risk", str(args.risk)])
    if args.threads:
        cmd.extend(["--threads", str(args.threads)])
    if args.batch:
        cmd.append("--batch")
    if args.dbms:
        cmd.extend(["--dbms", args.dbms])
    if args.tables:
        cmd.append("--tables")
    if args.dump:
        cmd.append("--dump")
    extend_cmd_with_extra_args(cmd, args)

    # Pre-flight sizing guard (I-9b#1 class). A heavy --level/--risk/--dump/--tables
    # run under a short --timeout is SIGTERM-killed mid-enumeration and the aborted
    # run reads as a clean "not injectable" / "nothing to dump". Warn (warn-only —
    # the floor is a heuristic, not a contract) so the budget is sized up front.
    if _sqlmap_is_heavy(args):
        preflight_timeout_guard(
            verb="sqlmap",
            internal_budget_s=_SQLMAP_HEAVY_FLOOR_S,
            timeout=getattr(args, "timeout", None),
            warn=lambda m: print(f"WARN {m}", file=sys.stderr),
            sizing_hint=(
                "A deep --level/--risk or --dump/--tables run routinely takes many "
                f"minutes; size --timeout to ≥{_SQLMAP_HEAVY_FLOOR_S}s or narrow the "
                "config so a SIGTERM mid-enumeration is not misread as a negative."
            ),
        )

    result = kali_exec(cmd, tool_name="sqlmap", **kali_args_to_kwargs(args))
    emit_result(result)
