"""vigil assess kali katana — typed wrapper around katana inside the runtime.

The wrapper bakes the crawl DOCTRINE from ``references/tools/recon/katana.md``
into safe defaults so depth no longer rides in a hand-quoted ``--extra-args``
blob the LLM has to remember:

  * deep by default (``-d 5``) — depth is decoupled from politeness;
  * disk-bounded by default (``-or -ob``) — a deep crawl streams routes, not the
    multi-GB body/raw blobs that fill the runtime disk;
  * JS-aware by default — the wrapper sends raw katana ``-jc -jsl`` unless disabled;
  * static assets excluded by default (``-ef <image/font/media set>``);
  * politely rated by default (``-rl 10``, hard cap 20, clamps to the program
    ceiling) — so ``-d 5`` cannot turn into "depth 5 at katana's built-in
    150 req/s".

Every default is overridable with one explicit flag. ``--extra-args`` stays the
safety net for unmodeled katana flags.
"""
from __future__ import annotations

import argparse
import sys

from assess.lib import scope as scope_lib
from assess.lib.client import AssessError
from assess.lib.config import load_config
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
    resolve_crawl_rate_limit,
)

# The pre-flight budget guard lives in the kali_cli argparse seam (which the kali
# facade re-exports the rest of this verb's helpers from); import it directly so
# this unit need not touch the shared facade module.
from assess.lib.kali_cli import coerce_float, preflight_timeout_guard

# Static / binary extensions excluded from crawling by default (injected as
# katana ``-ef``). Crawling these wastes requests on assets that hold no routes.
_DEFAULT_EXCLUDE_EXT = (
    "png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,mp3,avi,mov,zip,tar,gz,7z,pdf"
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "katana",
        help="Run katana inside the runtime container with audit recording.",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-u", dest="target_url", default="", help="Target URL.")
    p.add_argument("-list", dest="target_list", default="", help="File of newline-separated URLs.")
    # JS-aware crawl is ON by default. Keep old positive toggles parseable for
    # copied commands, but advertise only the negative opt-outs.
    p.add_argument("-jc", dest="legacy_jc", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("-jsl", dest="legacy_jsl", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--no-jc", dest="no_jc", action="store_true",
                   help="Disable JavaScript endpoint crawling (enabled by default).")
    p.add_argument("--no-jsl", dest="no_jsl", action="store_true",
                   help="Disable jsluice endpoint extraction (enabled by default).")
    p.add_argument("-d", dest="depth", default="5",
                   help="-d max crawl depth (default 5 — deep by default; depth is decoupled from rate).")
    p.add_argument("-c", dest="concurrency", default="5", help="-c concurrency (default 5).")
    p.add_argument("-rl", dest="rate_limit", default="",
                   help="-rl request rate (req/s). Default 10; hard-capped at 20 unless "
                        "--allow-fast-crawl; always clamped DOWN to the program rate ceiling.")
    p.add_argument("--crawl-budget", dest="crawl_budget", default="",
                   help="Crawl runtime budget in SECONDS — the crawl's max-runtime "
                        "ceiling. Emitted to katana as -crawl-duration so the crawl "
                        "self-stops at this budget, and cross-checked against --timeout "
                        "pre-flight: a budget larger than the wall-clock would be "
                        "SIGTERM-truncated and misread as 'nothing found', so --timeout "
                        "is auto-raised to fit it. (For request RATE, use -rl.)")
    p.add_argument("--allow-fast-crawl", dest="allow_fast_crawl", action="store_true",
                   help="Permit -rl above the 20 req/s safety cap (operator opt-in).")
    p.add_argument("-fs", dest="field_scope", default="",
                   help="Explicit Katana -fs field-scope.")
    p.add_argument("-kf", dest="known_files", default="",
                   help="-kf known-files expansion (e.g. 'all' for robots/sitemap/well-known).")
    p.add_argument("-cos", dest="crawl_out_scope", default="",
                   help="Explicit Katana -cos crawl-out-of-scope regex.")
    p.add_argument("-H", dest="headers", action="append", default=None,
                   help="Extra request header (repeatable), e.g. -H 'Cookie: s=...'. Program "
                        "attribution headers are injected automatically on top of these.")
    p.add_argument("--keep-bodies", dest="keep_bodies", action="store_true",
                   help="Keep full response body + raw in -jsonl output (default omits them via "
                        "-or -ob to bound disk on deep crawls). Use for a bounded source pass.")
    p.add_argument("--include-static", dest="include_static", action="store_true",
                   help="Crawl static/binary assets too (default excludes image/font/media/archive "
                        "extensions via -ef).")
    p.add_argument("-headless", dest="headless", action="store_true", help="-headless mode.")
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.add_argument("-jsonl", dest="jsonl", action="store_true", help="-jsonl output.")
    p.set_defaults(func=run)


def _resolve_rate_cap(args):
    """Best-effort read of the engagement's program req/s ceiling (scope.rate_limit).

    Returns None when no engagement context is resolvable — the crawl then uses
    the verb's own safe default (10) rather than failing.
    """
    try:
        cfg = load_config(getattr(args, "engagement_dir", None))
    except SystemExit:
        return None
    try:
        rate_cap, _ = scope_lib.rate_caps_for_dir(cfg.engagement_dir)
    except Exception:  # noqa: BLE001 — rate cap is best-effort, never fatal to a crawl
        return None
    return rate_cap


def run(args) -> None:
    if not args.target_url and not args.target_list:
        print("katana: pass -u <url> or -list <file>", file=sys.stderr)
        raise AssessError("missing -u or -list")
    cmd: list[str] = ["katana"]
    if args.target_url:
        cmd.extend(["-u", args.target_url])
    if args.target_list:
        cmd.extend(["-list", args.target_list])

    # JS-aware crawl on by default (doctrine baseline).
    if not args.no_jc:
        cmd.append("-jc")
    if not args.no_jsl:
        cmd.append("-jsl")

    if args.depth:
        cmd.extend(["-d", str(args.depth)])
    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])

    # Safe-by-default crawl rate: never inherit katana's built-in 150 req/s.
    rate_cap = _resolve_rate_cap(args)
    rl = resolve_crawl_rate_limit(
        args.rate_limit,
        rate_cap=rate_cap,
        allow_fast=bool(args.allow_fast_crawl),
        warn=lambda m: print(f"WARN katana: {m}", file=sys.stderr),
    )
    cmd.extend(["-rl", str(rl)])

    if args.field_scope:
        cmd.extend(["-fs", str(args.field_scope)])
    if args.known_files:
        cmd.extend(["-kf", str(args.known_files)])
    authored_exclusion = str(args.crawl_out_scope or "").strip()
    if authored_exclusion:
        cmd.extend(["-cos", authored_exclusion])
    for header in args.headers or []:
        cmd.extend(["-H", header])

    # Disk-bound deep crawls by default: omit body + raw from -jsonl records.
    if not args.keep_bodies:
        cmd.extend(["-or", "-ob"])
    # Skip static/binary assets by default.
    if not args.include_static:
        cmd.extend(["-ef", _DEFAULT_EXCLUDE_EXT])

    if args.headless:
        cmd.append("-headless")
    if args.output:
        cmd.extend(["-o", args.output])
    if args.jsonl:
        cmd.append("-jsonl")
    extend_cmd_with_extra_args(cmd, args)

    # Pre-flight crawl-budget vs --timeout guard (I-9b#1). A declared crawl budget
    # is passed to katana as -crawl-duration so the crawl self-stops at it, and
    # --timeout is auto-raised to fit (boost-only) — so a deep crawl is never
    # SIGTERM-truncated mid-flight and its partial output misread as a clean
    # negative (run 36937: killed at --timeout 180 with 1801 lines / 201 JS bodies).
    crawl_budget = coerce_float(getattr(args, "crawl_budget", ""), 0.0)
    if crawl_budget > 0:
        cmd.extend(["-crawl-duration", str(int(crawl_budget))])
        args.timeout = preflight_timeout_guard(
            verb="katana",
            internal_budget_s=crawl_budget,
            timeout=getattr(args, "timeout", None),
            warn=lambda m: print(f"WARN {m}", file=sys.stderr),
            auto_raise=True,
            exact=True,
        )

    result = kali_exec(cmd, tool_name="katana", **kali_args_to_kwargs(args))
    emit_result(result)
