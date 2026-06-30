"""vigil assess kali robots — pre-crawl known-file fetch (robots/sitemap/security.txt).

A high-signal single-fetch stage that runs BEFORE the katana crawl: probe each
in-scope host for `/robots.txt`, `/sitemap.xml`, and `/.well-known/security.txt`.
robots `Disallow:` lines and sitemap URLs routinely name admin paths, staging
hosts, and endpoints the crawler would otherwise never reach; security.txt names
a disclosure contact. Seeding those into recon before the crawl makes the crawl
land on real surfaces faster.

SCOPE: this is ONLY the marginal pre-crawl fetch. katana's own `-kf` (known-files)
flag already expands robots/sitemap/well-known DURING the crawl (see
`kali_katana.py`); this verb does not re-implement that — run it first for the
high-signal seed, then crawl.

The engine is `httpx` probing the well-known paths (`-path`), so `tool_name`
stays `httpx`: it inherits httpx's required-header injection (the program marker
rides every probe on a required-headers engagement) and the shared scope/exec
posture. Read-only GETs: leave `--destructive` off.
"""
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

# The marginal pre-crawl known-file set. Kept tight on purpose: these three are
# the high-signal pre-crawl fetches; katana `-kf` covers the broader in-crawl
# known-files expansion.
_DEFAULT_KNOWN_PATHS = "/robots.txt,/sitemap.xml,/.well-known/security.txt"

# Match present-but-protected as well as 200, so a 401/403 robots.txt (it exists,
# it is just gated) still surfaces rather than being silently dropped.
_DEFAULT_MATCH_CODES = "200,301,302,401,403"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "robots",
        help="Pre-crawl fetch of robots.txt/sitemap.xml/.well-known/security.txt per host (httpx-backed).",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("target", nargs="?", default="", help="Single host or URL (positional). Mutually usable with -l.")
    p.add_argument("-u", dest="target_opt", default="", help="Single host/URL (alias for the positional target).")
    p.add_argument("-l", "-list", dest="input_list", default="", help="File of newline-separated hosts/URLs.")
    p.add_argument(
        "--paths",
        dest="paths",
        default=_DEFAULT_KNOWN_PATHS,
        help=f"Comma-separated known-file paths to fetch (default: {_DEFAULT_KNOWN_PATHS}).",
    )
    p.add_argument(
        "-mc",
        dest="match_codes",
        default=_DEFAULT_MATCH_CODES,
        help=f"httpx -mc status match list (default: {_DEFAULT_MATCH_CODES}; keeps 401/403 so a gated-but-present file still surfaces).",
    )
    p.add_argument("-json", dest="json_out", action="store_true", help="Structured JSON output.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    target = (args.target or args.target_opt or "").strip()
    if not target and not args.input_list:
        print("robots: pass <host> / -u <host> or -l <list>", file=sys.stderr)
        raise AssessError("missing <host> or -l")

    cmd: list[str] = ["httpx"]
    if target:
        cmd.extend(["-u", target])
    if args.input_list:
        cmd.extend(["-l", args.input_list])
    cmd.extend(["-path", args.paths])
    cmd.extend(["-status-code", "-content-length", "-title", "-location"])
    if args.match_codes:
        cmd.extend(["-mc", args.match_codes])
    if args.json_out:
        cmd.append("-json")
    cmd.append("-silent")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    # tool_name=httpx so required-header injection + scope posture are inherited
    # from the httpx classification (the engine that actually reaches the host).
    result = kali_exec(cmd, tool_name="httpx", **kali_args_to_kwargs(args))
    emit_result(result)
