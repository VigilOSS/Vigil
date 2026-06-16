"""vigil assess arjun-select — build a GATED Arjun target list from the work buffer.

Implements plan §6 (the scale story). Arjun must NEVER be aimed at a raw URL
dump or at inert assets — on a content-heavy target that is thousands of
requests for nothing. This command emits a disciplined target list:

  1. LIVE only          — work_items.live_status = 'live' (skip dead/blackholed;
                          --include-unknown opts NULL/unknown rows back in).
  2. DYNAMIC, non-inert — exclude classify_buckets.INERT_TYPES and skipped rows.
  3. DEDUP by template  — collapse id/uuid/hex/year-varied paths to ONE route via
                          classify_buckets.normalize_path_for_cluster, so
                          /explore/2024/M0004 and /explore/2023/G0058 test once.
                          This is the single biggest volume cut.
  4. PREFER param-poor  — endpoints with 0-1 known params first (hidden-param
                          yield is highest where the surface looks "empty").
  5. PER-HOST budget    — --max-per-host caps templates/host (politeness).

The output file is what `vigil assess kali arjun -i <file>` consumes.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.classify_buckets import INERT_TYPES, normalize_path_for_cluster


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


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def select_targets(
    rows: list[dict],
    *,
    include_unknown: bool = False,
    max_per_host: int = 0,
    param_poor_only: bool = False,
) -> list[str]:
    """Pure selection over already-fetched work_items rows (unit-testable).

    Applies the live / non-inert / template-dedup / param-poor-preference /
    per-host-budget gates and returns a deduped, ordered URL list. Ordering:
    param-poor rows first (ascending param count), then by URL for determinism.
    Dedup key is (host, normalized-path-template) so id-varied URLs collapse.
    """
    inert = {t.lower() for t in INERT_TYPES}
    eligible: list[tuple[int, str, str, str]] = []  # (param_count, host, template, url)
    for row in rows:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        case_type = (row.get("type") or "").lower()
        if case_type in inert:
            continue
        status = (row.get("status") or "").lower()
        if status == "skipped":
            continue
        live = (row.get("live_status") or "").strip().lower()
        if live == "live":
            pass
        elif include_unknown and live in ("", "unknown"):
            pass
        else:
            continue
        pcount = _param_count(row)
        if param_poor_only and pcount > 1:
            continue
        host = _host_of(url)
        template = normalize_path_for_cluster(row.get("url_path") or urlparse(url).path)
        eligible.append((pcount, host, template, url))

    # Dedup by (host, template): keep the lowest param-count representative.
    best: dict[tuple[str, str], tuple[int, str]] = {}
    for pcount, host, template, url in eligible:
        key = (host, template)
        if key not in best or pcount < best[key][0]:
            best[key] = (pcount, url)

    # Order param-poor first, then deterministic by url.
    chosen = sorted(
        ((pcount, host, url) for (host, _t), (pcount, url) in best.items()),
        key=lambda x: (x[0], x[2]),
    )

    # Per-host budget.
    if max_per_host and max_per_host > 0:
        seen_per_host: dict[str, int] = {}
        budgeted: list[tuple[int, str, str]] = []
        for pcount, host, url in chosen:
            n = seen_per_host.get(host, 0)
            if n >= max_per_host:
                continue
            seen_per_host[host] = n + 1
            budgeted.append((pcount, host, url))
        chosen = budgeted

    return [url for _pc, _host, url in chosen]


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "arjun-select",
        help="Build a gated Arjun target list (live + dynamic + template-deduped + param-poor) from the work buffer.",
    )
    p.add_argument("db_path", help="Path to cases.db")
    p.add_argument(
        "-o",
        "--out",
        dest="out",
        required=True,
        help="Output file path for the gated URL list (consumed by `kali arjun -i`).",
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
    db_path = args.db_path
    if not Path(db_path).is_file():
        print(f"ERROR: database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    from assess.lib.db import db_query

    rows = db_query(
        db_path,
        "SELECT url, url_path, type, status, live_status, "
        "query_params, body_params, path_params FROM work_items",
    )
    targets = select_targets(
        rows,
        include_unknown=bool(args.include_unknown),
        max_per_host=int(args.max_per_host),
        param_poor_only=bool(args.param_poor_only),
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

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(targets) + ("\n" if targets else ""), encoding="utf-8")

    summary = {
        "verb": "arjun-select",
        "db_path": db_path,
        "out": str(out_path),
        "scanned_rows": len(rows),
        "selected": len(targets),
        "include_unknown": bool(args.include_unknown),
        "max_per_host": int(args.max_per_host),
        "param_poor_only": bool(args.param_poor_only),
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
