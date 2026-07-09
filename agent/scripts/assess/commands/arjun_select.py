"""vigil assess arjun-select — build a GATED Arjun target list from the work buffer.

Implements plan §6 (the scale story). Arjun must NEVER be aimed at a raw URL
dump or at inert assets — on a content-heavy target that is thousands of
requests for nothing. This command emits a disciplined target list:

  1. LIVE only          — work_items.live_status = 'live' (skip dead/blackholed;
                          --include-unknown opts NULL/unknown rows back in).
  2. DYNAMIC, non-inert — exclude classify_buckets.INERT_TYPES and skipped rows.
  3. DEDUP by template  — collapse id/uuid/hex/year-varied paths to ONE route via
                          classify_buckets.normalize_route_template, so
                          /explore/2024/M0004 and /explore/2023/G0058 test once.
                          The dedup key is (origin, method, template): distinct
                          sibling routes (/api/users/search vs /api/users/export),
                          verb variants (GET vs POST /api/search), and same-host
                          different-port services (app:8443 vs app:443) all stay
                          separate. This is the single biggest volume cut.
  4. PREFER param-poor  — endpoints with 0-1 known params first (hidden-param
                          yield is highest where the surface looks "empty").
  5. PER-ORIGIN budget  — --max-per-host caps templates per scheme/host/port
                          service (politeness).

`vigil assess kali arjun -i <file>` applies a SINGLE global `-m`, so this command
writes per-method sidecar lists (<out>.GET, <out>.POST, ...) alongside the union
`--out`, letting each verb's surface be scanned under its own `-m`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.classify_buckets import INERT_TYPES, normalize_route_template
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def _param_count(row: dict) -> int:
    """Count distinct known param keys across the row's param columns.

    Param-poor rows (0-1 keys) are the prime Arjun fishing ground — they look
    empty but may silently accept hidden params. Malformed JSON counts as 0.
    """
    total = 0
    for col in ("query_params", "body_params", "path_params"):
        raw = row.get(col)
        if not raw:
            continue
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(decoded, dict):
            total += len(decoded)
    return total


def _origin_of(url: str) -> str:
    """Scheme + host + port identity of ``url`` (empty string if unparseable).

    Used as the dedup/budget unit instead of the bare hostname so the SAME
    hostname exposed on two ports (``https://app:8443/login`` vs
    ``https://app/login``) is two distinct services — collapsing them would skip
    a live listener Arjun never scans. The scheme's DEFAULT port is normalized
    away (an explicit ``https://app:443`` and a bare ``https://app`` are one
    service), so only a genuinely non-default port forks the origin.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    scheme = (parsed.scheme or "").lower()
    try:
        port = parsed.port
    except ValueError:  # malformed port (e.g. "host:abc") — treat as unspecified
        port = None
    default_port = {"http": 80, "https": 443}.get(scheme)
    if port is None or port == default_port:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _method_of(row: dict) -> str:
    """Uppercased HTTP method of ``row`` (defaults to GET when absent/blank).

    The method is part of the dedup identity: a host can expose the same route
    under multiple verbs (a GET query surface AND a POST/JSON body surface), and
    Arjun's body-param discovery only fires under the right ``-m``. Collapsing
    GET and POST ``/api/search`` to one entry would silently drop the body
    surface from the scan.
    """
    return (row.get("method") or "GET").strip().upper() or "GET"


def select_targets(
    rows: list[dict],
    *,
    include_unknown: bool = False,
    max_per_host: int = 0,
    param_poor_only: bool = False,
    stats: dict | None = None,
) -> list[tuple[str, str]]:
    """Pure selection over already-fetched work_items rows (unit-testable).

    Applies the live / non-inert / template-dedup / param-poor-preference /
    per-origin-budget gates and returns a deduped, ordered list of
    ``(method, url)`` pairs. Ordering: param-poor rows first (ascending param
    count), then by (method, url) for determinism.

    Dedup key is (origin, method, normalized-path-template) so id-varied URLs
    collapse but distinct method variants and same-host-different-port services
    are kept separate — each needs its own Arjun run (a single global ``-m``,
    one scan per listener). The per-host budget is applied per ORIGIN
    (scheme/host/port) so politeness is enforced per live service.

    Every gate DROPS rows; that reduction is coverage the operator did not scan.
    Pass a ``stats`` dict to receive a per-gate drop breakdown (scanned, dropped_*,
    collapsed_by_dedup, dropped_by_budget, selected) so a truncated run is never
    mistaken for full coverage. ``select_targets(rows)`` (no stats) returns the
    same ordering as before, now as (method, url) pairs.
    """
    s = {
        "scanned": len(rows),
        "dropped_no_url": 0,
        "dropped_non_http": 0,
        "dropped_inert": 0,
        "dropped_skipped_status": 0,
        "dropped_not_live": 0,
        "dropped_param_rich": 0,
        "eligible": 0,
        "templates_after_dedup": 0,
        "collapsed_by_dedup": 0,
        "dropped_by_budget": 0,
        "selected": 0,
    }

    inert = {t.lower() for t in INERT_TYPES}
    # (param_count, origin, method, template, url)
    eligible: list[tuple[int, str, str, str, str]] = []
    for row in rows:
        url = (row.get("url") or "").strip()
        if not url:
            s["dropped_no_url"] += 1
            continue
        # Arjun speaks HTTP(S) to an absolute URL only; a ws://, mailto:, or
        # relative entry that slipped into the buffer is unusable and would just
        # make arjun print "not a valid URL" and skip — keep it out of the list.
        try:
            parsed = urlparse(url)
        except ValueError:
            s["dropped_non_http"] += 1
            continue
        if (parsed.scheme or "").lower() not in ("http", "https") or not parsed.hostname:
            s["dropped_non_http"] += 1
            continue
        case_type = (row.get("type") or "").lower()
        if case_type in inert:
            s["dropped_inert"] += 1
            continue
        status = (row.get("status") or "").lower()
        if status == "skipped":
            s["dropped_skipped_status"] += 1
            continue
        live = (row.get("live_status") or "").strip().lower()
        if live == "live":
            pass
        elif include_unknown and live in ("", "unknown"):
            pass
        else:
            s["dropped_not_live"] += 1
            continue
        pcount = _param_count(row)
        if param_poor_only and pcount > 1:
            s["dropped_param_rich"] += 1
            continue
        origin = _origin_of(url)
        method = _method_of(row)
        template = normalize_route_template(row.get("url_path") or urlparse(url).path)
        eligible.append((pcount, origin, method, template, url))

    s["eligible"] = len(eligible)

    # Dedup by (origin, method, template): keep the lowest param-count
    # representative. Method and port (carried by origin) stay in the key so a
    # GET/POST verb pair or a same-host-different-port service is never collapsed.
    best: dict[tuple[str, str, str], tuple[int, str]] = {}
    for pcount, origin, method, template, url in eligible:
        key = (origin, method, template)
        if key not in best or pcount < best[key][0]:
            best[key] = (pcount, url)

    s["templates_after_dedup"] = len(best)
    s["collapsed_by_dedup"] = len(eligible) - len(best)

    # Order param-poor first, then deterministic by (method, url).
    chosen = sorted(
        (
            (pcount, origin, method, url)
            for (origin, method, _t), (pcount, url) in best.items()
        ),
        key=lambda x: (x[0], x[2], x[3]),
    )

    # Per-host budget — a HARD cap that drops covered routes; count what it sheds.
    # Keyed on ORIGIN (scheme/host/port) so politeness is enforced per live
    # service: two ports on one hostname each get their own budget (distinct
    # listeners), while method variants on the SAME origin share it (they hit one
    # listener, so the request volume the cap protects against is shared).
    if max_per_host and max_per_host > 0:
        seen_per_origin: dict[str, int] = {}
        budgeted: list[tuple[int, str, str, str]] = []
        for pcount, origin, method, url in chosen:
            n = seen_per_origin.get(origin, 0)
            if n >= max_per_host:
                s["dropped_by_budget"] += 1
                continue
            seen_per_origin[origin] = n + 1
            budgeted.append((pcount, origin, method, url))
        chosen = budgeted

    s["selected"] = len(chosen)
    if stats is not None:
        stats.update(s)

    return [(method, url) for _pc, _origin, method, url in chosen]


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "arjun-select",
        help="Build a gated Arjun target list (live + dynamic + template-deduped + param-poor) from the work buffer.",
    )
    p.add_argument(
        "-o",
        "--out",
        dest="out",
        required=True,
        help=(
            "Output file path for the gated URL list. The union of all methods is "
            "written here; a per-method sidecar (<out>.<METHOD>) is also written so "
            "`kali arjun -i <out>.POST -m POST` scans the body surface separately."
        ),
    )
    p.add_argument(
        "--include-unknown",
        dest="include_unknown",
        action="store_true",
        help="Also include rows with NULL/unknown live_status (default: live only).",
    )
    p.add_argument(
        "--max-per-host",
        dest="max_per_host",
        type=int,
        default=0,
        help="Cap selected templates per host (politeness; 0 = unlimited).",
    )
    p.add_argument(
        "--param-poor-only",
        dest="param_poor_only",
        action="store_true",
        help="Emit ONLY rows with <=1 known param (param-rich rows already have plenty to test).",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    # The work buffer now lives in the orchestrator backend; read every row over
    # HTTP (the rows carry url/url_path/method/type/status/live_status and the
    # param columns select_targets gates on) instead of opening a local cases.db.
    cfg = load_config(getattr(args, "engagement_dir", None))
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows = client.get_all_pages("work-items")

    drop_stats: dict = {}
    targets = select_targets(
        rows,
        include_unknown=bool(args.include_unknown),
        max_per_host=int(args.max_per_host),
        param_poor_only=bool(args.param_poor_only),
        stats=drop_stats,
    )

    # A per-host budget silently truncates coverage; make the truncation visible so
    # a capped run is never mistaken for "I scanned that host". (Template-dedup is
    # by-design collapse, reported separately as collapsed_by_dedup.)
    if drop_stats.get("dropped_by_budget"):
        print(
            f"arjun-select: --max-per-host={args.max_per_host} dropped "
            f"{drop_stats['dropped_by_budget']} additional templates beyond the cap; "
            "raise --max-per-host (or rerun without it) to cover them.",
            file=sys.stderr,
        )

    # Junk-list guard. --include-unknown admits rows with NULL/unknown live_status
    # — typically historic gau/Wayback URLs (dead .nsf/.do paths, http->https 301s,
    # PDFs). Arjun wastes a full slow detection pass on each dead/redirecting
    # target and finds nothing, so a list padded with these is the classic
    # "arjun timed out having scanned 2 of N, reported 0 params" trap. Warn loudly
    # and point at the real fix: confirm liveness first.
    if args.include_unknown and targets:
        print(
            f"arjun-select: --include-unknown admitted unconfirmed-live targets into "
            f"this {len(targets)}-target list (historic/Wayback rows may be dead .nsf/.do "
            "paths, 301 redirects, or PDFs). Arjun burns a full slow pass on each and "
            "finds nothing — a large junk list is the #1 cause of an arjun timeout that "
            "reports a false 0. Prefer confirming liveness first (`vigil assess ingest-httpx` "
            "then drop --include-unknown), and keep the list small enough to FINISH "
            "(`--max-per-host`, fewer targets).",
            file=sys.stderr,
        )

    # Common foot-gun: an engagement whose liveness ledger was never populated
    # (no `ingest-httpx`) has empty live_status on every row, so the default
    # live-only gate selects nothing. Surface the fix instead of failing silent.
    if not targets and rows and not args.include_unknown:
        print(
            "arjun-select: 0 targets — work_items appear to have no live_status. "
            "Run `vigil assess ingest-httpx` to populate liveness, or pass "
            "--include-unknown to include NULL/unknown rows.",
            file=sys.stderr,
        )

    # Group selected targets by method so the operator can apply the right `-m` to
    # each list. `kali arjun -i <file>` takes a SINGLE global `-m`, so a list that
    # mixes GET (query surface) and POST/JSON (body surface) would scan every URL
    # with one method and miss the others' hidden params. Per-method sidecars
    # (<out>.GET, <out>.POST, ...) let each surface be scanned under its own verb.
    by_method: dict[str, list[str]] = {}
    for method, url in targets:
        by_method.setdefault(method, []).append(url)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Primary --out keeps the full URL union (backward-compatible).
    union_urls = [url for _m, url in targets]
    out_path.write_text("\n".join(union_urls) + ("\n" if union_urls else ""), encoding="utf-8")

    method_outputs: dict[str, str] = {}
    for method, urls in sorted(by_method.items()):
        sidecar = out_path.with_name(f"{out_path.name}.{method}")
        sidecar.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")
        method_outputs[method] = str(sidecar)

    summary = {
        "verb": "arjun-select",
        "out": str(out_path),
        # Per-method sidecar files: scan each with its own `-m` so POST/JSON body
        # surfaces are not silently scanned under GET (or vice versa).
        "method_outputs": method_outputs,
        "selected_by_method": {m: len(u) for m, u in sorted(by_method.items())},
        "scanned_rows": len(rows),
        "selected": len(targets),
        "include_unknown": bool(args.include_unknown),
        "max_per_host": int(args.max_per_host),
        "param_poor_only": bool(args.param_poor_only),
        # Per-gate drop breakdown: every non-selected row, and why. The sum of
        # drops + selected accounts for every scanned row, so coverage lost to any
        # gate (liveness, inert filter, dedup collapse, host budget) is explicit.
        "drops": drop_stats,
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
