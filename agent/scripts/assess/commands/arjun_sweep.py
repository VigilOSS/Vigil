"""vigil assess arjun-sweep — gated hidden-parameter discovery, end to end.

Collapses the three-step flow the LLM routinely gets wrong into ONE synchronous,
audited command:

    arjun-select (live + dynamic + template-deduped + param-poor, per method)
      -> kali arjun -i <list>.<M> -m <M>   (one blocking call per method)
      -> ingest-arjun                       (fold discovered params into the buffer)

The three recurring foot-guns this removes:
  * running the union list under a SINGLE ``-m`` (so POST/JSON/XML body surfaces
    get scanned as GET and their hidden body params are missed) — arjun-sweep
    scans each method-list under its own ``-m``;
  * forgetting ``ingest-arjun`` (so discovered params never reach the work buffer
    and never auto-route to gf:ssrf/lfi/idor/sqli) — arjun-sweep always ingests;
  * a run SIZED TO NOT FINISH (slow rate × ``--stable`` multi-pass × high ``-T``
    × a large/junk list) that is SIGTERM-killed after a couple of targets and
    reports a FALSE 0 — arjun-sweep favours COMPLETION by default (``--stable``
    is opt-in, ``-T`` is short so dead targets fail fast, and ``--max-targets``
    caps each method-list to a size that can actually finish in the budget) and
    flags any run that still times out as INCOMPLETE rather than a negative.

``--passive`` is intentionally NOT offered here (it needs a single ``-u`` host to
harvest, which the ``-i`` batch flow has no place for — run a focused
``vigil assess kali arjun -u <url> --passive`` for that).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

from assess.commands import arjun_select, ingest_arjun
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.kali import (
    add_required_kali_flags,
    count_list_targets,
    incomplete_list_run_warning,
    kali_args_to_kwargs,
    kali_exec,
)

# Per-method total target cap. Sized so a sweep at the default config (rate 10,
# no --stable, -T 7) plausibly FINISHES inside --stage-timeout instead of being
# killed mid-list. select_targets orders param-poor (highest-yield) first, so the
# cap keeps the best targets; the rest are deferred and reported, never silently
# dropped. 0 = unlimited (opt out of sizing).
_DEFAULT_MAX_TARGETS = 100


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "arjun-sweep",
        help="Gated hidden-param discovery end to end: select -> per-method arjun -> ingest.",
    )
    add_required_kali_flags(p)
    p.add_argument("db_path", help="Path to cases.db")
    # Selection gates (mirror arjun-select).
    p.add_argument("--include-unknown", dest="include_unknown", action="store_true",
                   help="Also include rows with NULL/unknown live_status (default: live only). "
                        "Admits historic/Wayback junk that arjun wastes a slow pass on — prefer "
                        "confirming liveness with ingest-httpx first.")
    p.add_argument("--max-per-host", dest="max_per_host", type=int, default=0,
                   help="Cap selected templates per origin (politeness; 0 = unlimited).")
    p.add_argument("--param-poor-only", dest="param_poor_only", action="store_true",
                   help="Emit ONLY rows with <=1 known param (highest hidden-param yield).")
    p.add_argument("--max-targets", dest="max_targets", type=int, default=_DEFAULT_MAX_TARGETS,
                   help=f"Cap targets scanned PER METHOD so the run finishes in --stage-timeout "
                        f"(default {_DEFAULT_MAX_TARGETS}; 0 = unlimited). Deferred targets are reported, "
                        "not dropped — raise it or re-run for the remainder.")
    # Arjun tuning — defaults favour COMPLETION over per-target thoroughness,
    # because a sweep that does not finish reports a false 0.
    p.add_argument("--rate-limit", dest="rate_limit", default="10",
                   help="arjun --rate-limit req/s (default 10; gated lists are still real traffic).")
    p.add_argument("--stable", dest="stable", action="store_true",
                   help="Enable arjun --stable (multi-pass, higher accuracy but MUCH slower). OFF by "
                        "default so the sweep finishes; turn on for a small focused re-run.")
    p.add_argument("-T", "--http-timeout", dest="http_timeout", default="7",
                   help="arjun -T per-request HTTP timeout in seconds (default 7 so a dead/slow "
                        "target fails fast instead of burning the budget).")
    p.add_argument("-w", dest="wordlist", default="",
                   help="arjun -w wordlist (default arjun's full db/large.txt; pass a smaller list to go faster).")
    p.add_argument("-t", dest="threads", default="", help="arjun -t threads.")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800,
                   help="Per-method arjun call timeout in seconds (default 1800).")
    p.set_defaults(func=run)


_SELECT_QUERY = (
    "SELECT url, url_path, method, type, status, live_status, "
    "query_params, body_params, path_params FROM work_items"
)


def run(args: argparse.Namespace) -> None:
    db_path = anchor_engagement_relative(args.db_path, getattr(args, "engagement_dir", None))
    if not Path(db_path).is_file():
        print(f"arjun-sweep: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(getattr(args, "engagement_dir", None))
    eng_dir = Path(cfg.engagement_dir)
    eng_key = cfg.engagement_key

    from assess.lib.db import db_query

    rows = db_query(db_path, _SELECT_QUERY)
    drop_stats: dict = {}
    targets = arjun_select.select_targets(
        rows,
        include_unknown=bool(args.include_unknown),
        max_per_host=int(args.max_per_host),
        param_poor_only=bool(args.param_poor_only),
        stats=drop_stats,
    )
    if not targets:
        msg = "arjun-sweep: 0 targets after gating."
        if rows and not args.include_unknown:
            msg += (
                " work_items may have no live_status — run `vigil assess ingest-httpx` "
                "to populate liveness, or pass --include-unknown."
            )
        print(msg, file=sys.stderr)
        print(json.dumps({"verb": "arjun-sweep", "selected": 0, "drops": drop_stats}, indent=2))
        return

    if args.include_unknown:
        print(
            f"arjun-sweep: --include-unknown admitted unconfirmed-live targets ({len(targets)} "
            "total). Historic/Wayback rows (dead .nsf/.do, 301s, PDFs) make arjun burn a slow "
            "pass for nothing — confirm liveness with `vigil assess ingest-httpx` and drop "
            "--include-unknown for a trustworthy run.",
            file=sys.stderr,
        )

    by_method: dict[str, list[str]] = {}
    for method, url in targets:
        by_method.setdefault(method, []).append(url)

    out_dir = eng_dir / "scans" / "arjun-sweep"
    out_dir.mkdir(parents=True, exist_ok=True)

    max_targets = int(args.max_targets)
    per_method: list[dict] = []
    for method, urls in sorted(by_method.items()):
        deferred = 0
        if max_targets > 0 and len(urls) > max_targets:
            deferred = len(urls) - max_targets
            print(
                f"arjun-sweep: {method} list has {len(urls)} targets; scanning the first "
                f"{max_targets} (param-poor first) to finish in --stage-timeout, deferring "
                f"{deferred}. Raise --max-targets or re-run for the rest.",
                file=sys.stderr,
            )
            urls = urls[:max_targets]

        list_host = out_dir / f"{method}.txt"
        list_host.write_text("\n".join(urls) + "\n", encoding="utf-8")
        list_container = f"/engagements/{eng_key}/scans/arjun-sweep/{method}.txt"
        json_host = out_dir / f"{method}.json"
        json_container = f"/engagements/{eng_key}/scans/arjun-sweep/{method}.json"

        cmd = ["arjun", "-i", list_container, "-m", method, "-oJ", json_container]
        if args.wordlist:
            cmd.extend(["-w", args.wordlist])
        if args.stable:
            cmd.append("--stable")
        if args.rate_limit:
            cmd.extend(["--rate-limit", str(args.rate_limit)])
        if args.http_timeout:
            cmd.extend(["-T", str(args.http_timeout)])
        if args.threads:
            cmd.extend(["-t", str(args.threads)])

        kw = kali_args_to_kwargs(args)
        kw["intent"] = f"arjun-sweep: hidden {method} param discovery on {len(urls)} gated routes"
        kw["timeout"] = int(args.stage_timeout)
        print(f"arjun-sweep: scanning {len(urls)} {method} route(s)...", file=sys.stderr)
        result = kali_exec(cmd, tool_name="arjun", **kw)

        # Incomplete-run guard: a method run that times out scanned only part of
        # its list, so its params are NOT a negative. Flag it loudly and mark the
        # per-method record incomplete so the summary never reads as "swept GET+POST".
        note = incomplete_list_run_warning(
            tool=f"arjun ({method})",
            total_targets=count_list_targets(list_host),
            timed_out=getattr(result, "timed_out", False),
            return_code=getattr(result, "return_code", None),
            stdout_preview=getattr(result, "stdout_preview", "") or "",
            stderr_preview=getattr(result, "stderr_preview", "") or "",
        )
        if note:
            print(f"WARN {note}", file=sys.stderr)

        # arjun writes no -oJ file on 0 findings; guarantee one so ingest always
        # has a file to read (mirrors kali_arjun._ensure_json_artifact).
        if not json_host.exists():
            json_host.write_text("{}", encoding="utf-8")

        ingest_arjun.run(SimpleNamespace(
            db_path=db_path,
            json_file=str(json_host),
            source="arjun",
            default_method=method,
            engagement_dir=str(eng_dir),
        ))
        per_method.append({
            "method": method,
            "routes": len(urls),
            "deferred": deferred,
            "status": getattr(result, "status", "unknown"),
            "incomplete": bool(note),
            "run_id": getattr(result, "run_id", None),
            "json": str(json_host),
        })

    any_incomplete = any(r["incomplete"] for r in per_method)
    print(json.dumps({
        "verb": "arjun-sweep",
        "db_path": db_path,
        "selected": len(targets),
        "by_method": {m: len(u) for m, u in sorted(by_method.items())},
        "runs": per_method,
        "incomplete": any_incomplete,
        "drops": drop_stats,
    }, ensure_ascii=False, indent=2))
