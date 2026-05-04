"""aith assess kali sqlmap — typed wrapper around sqlmap inside the runtime."""
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

    result = kali_exec(cmd, tool_name="sqlmap", **kali_args_to_kwargs(args))
    emit_result(result)
