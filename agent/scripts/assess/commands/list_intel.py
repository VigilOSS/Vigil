"""vigil assess intel list — read-only intel listing / search.

If ``<type>`` is given, list rows of that type (backed by
``GET /engagements/{key}/intel/{type-plural}``). If ``<type>`` is omitted,
list the per-type counts via ``GET /engagements/{key}/intel/summary``.

``--q`` forwards to ``GET /engagements/{key}/intel/search?q=...`` and
mixes results across tables, narrowed by ``--entity-type`` if given.
"""
from __future__ import annotations

import argparse
import json
import shlex
from urllib.parse import urlencode

from assess.commands.record_intel import INTEL_TYPES
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.list_output import (
    lookahead_limit,
    page_from_backend,
    report_page,
)

INTEL_ENTITY_TYPES = {
    "tech-component": "tech_component",
    "person": "person",
    "email": "email",
    "domain": "domain",
    "cve": "cve",
    "dns-record": "dns_record",
    "social-profile": "social_profile",
    "breach-record": "breach_record",
    "org-fact": "org_fact",
    "note": "note",
}
_CLI_TYPE_BY_ENTITY = {value: key for key, value in INTEL_ENTITY_TYPES.items()}
_MAX_SEARCH_LIMIT = 500
_IDENTIFYING_FIELDS = (
    "component",
    "name",
    "address",
    "identity",
    "cve_id",
    "handle",
    "fact_key",
    "title",
    "record_type",
    "breach_name",
)


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    p = subparsers.add_parser(
        "list",
        help="List intel records (per-type or FTS search)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess intel list                           # counts per type (summary)\n"
            "  vigil assess intel list tech-component            # all tech components\n"
            "  vigil assess intel list --q 'nginx'               # FTS search across all intel\n"
            "  vigil assess intel list cve --q '2024'            # FTS search narrowed to cves\n"
            f"\nValid types: {types_list}"
        ),
    )
    p.add_argument("intel_type", nargs="?", default=None, help=f"Optional intel type ({types_list})")
    p.add_argument("--q", dest="q", default="", help="FTS search query (uses /intel/search)")
    p.add_argument("--limit", type=int, default=50, help="Maximum rows to print (default: 50)")
    p.add_argument("--offset", type=int, default=0, help="Result offset for pagination")
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Print compact pointer rows as JSON",
    )
    p.set_defaults(func=run)


def _format_row(row: dict) -> str:
    # Compact display that works across intel types — prefer identifying key.
    id_val = row.get("id", "?")
    # `intel list` includes superseded rows by design (they are the audit trail),
    # but an unmarked superseded row is byte-identical to the live one and gets
    # acted on as current. Label it and point at the row that replaced it; the
    # stored lead_status is left alone — rewriting a historical status to satisfy
    # a renderer would destroy the record this row exists to be.
    superseded_by = row.get("superseded_by_id")
    prefix = f"[SUPERSEDED -> {superseded_by}] " if superseded_by else ""
    for key in _IDENTIFYING_FIELDS:
        value = row.get(key)
        if value:
            return f"{prefix}{id_val} | {key}={value} | source={row.get('source_name', '')}"
    return f"{prefix}{id_val} | source={row.get('source_name', '')} | (no display key)"


def _point_read(intel_type: str, intel_id: object) -> str:
    return f"vigil assess intel get {intel_type} {intel_id}"


def _compact_type_json_row(row: dict, intel_type: str) -> dict:
    compact: dict[str, object] = {
        "id": row.get("id"),
        "intel_type": intel_type,
    }
    for key in _IDENTIFYING_FIELDS:
        if row.get(key) not in (None, ""):
            compact[key] = row[key]
            break
    for key in (
        "source_name",
        "lead_status",
        "validation_status",
        "live_status",
        "superseded_by_id",
        "canonical_id",
        "updated_at",
    ):
        if key in row:
            compact[key] = row[key]
    if row.get("id") is not None:
        compact["_point_read"] = _point_read(intel_type, row["id"])
    return compact


def _compact_search_json_row(row: dict) -> dict:
    compact = {
        key: row[key]
        for key in ("entity_type", "source_id", "key", "source_name", "rank")
        if key in row
    }
    intel_type = _CLI_TYPE_BY_ENTITY.get(str(row.get("entity_type") or ""))
    if intel_type and row.get("source_id") is not None:
        compact["_point_read"] = _point_read(intel_type, row["source_id"])
    return compact


def _format_search_row(row: dict) -> str:
    record = row.get("record")
    if isinstance(record, dict):
        rendered = _format_row(record)
    else:
        rendered = f"{row.get('source_id', '?')} | key={row.get('key', '')}"
    return f"{row.get('entity_type', 'unknown')} | {rendered}"


def _continuation_command(args, offset: int) -> str:
    parts = ["vigil", "assess", "intel", "list"]
    if args.intel_type:
        parts.append(shlex.quote(str(args.intel_type)))
    if args.q:
        parts.extend(("--q", shlex.quote(str(args.q))))
    parts.extend(("--limit", str(int(args.limit)), "--offset", str(offset)))
    return " ".join(parts)


def run(args) -> None:
    limit = int(args.limit)
    offset = int(getattr(args, "offset", 0))
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if args.q:
            # FTS search across intel tables.
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_SEARCH_LIMIT
            )
            params = {"q": args.q, "limit": request_limit, "offset": offset}
            if args.intel_type:
                if args.intel_type not in INTEL_TYPES:
                    print(
                        f"unknown intel type '{args.intel_type}'. Valid: "
                        f"{', '.join(sorted(INTEL_TYPES))}"
                    )
                    return
                params["entity_type"] = INTEL_ENTITY_TYPES[args.intel_type]
            result = client.get_engagement("intel/search", query=urlencode(params))
        elif args.intel_type:
            if args.intel_type not in INTEL_TYPES:
                print(
                    f"unknown intel type '{args.intel_type}'. Valid: "
                    f"{', '.join(sorted(INTEL_TYPES))}"
                )
                return
            _, endpoint_segment = INTEL_TYPES[args.intel_type]
            request_limit, used_lookahead = lookahead_limit(
                limit, maximum=_MAX_SEARCH_LIMIT
            )
            result = client.get_engagement(
                f"intel/{endpoint_segment}",
                query=urlencode({"limit": request_limit, "offset": offset}),
            )
        else:
            result = client.get_engagement("intel/summary")

    if not isinstance(result, list):
        if not args.q and not args.intel_type and isinstance(result, dict):
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return
        raise AssessError("intel list: expected a JSON array from the backend")

    if args.q or args.intel_type:
        page = page_from_backend(
            result,
            limit=limit,
            offset=offset,
            used_lookahead=used_lookahead,
        )
    else:
        raise AssertionError("intel summary cannot reach row pagination")
    result = page.rows
    report_page(
        page,
        noun="intel rows",
        continuation_command=_continuation_command(
            args, page.offset + len(page.rows)
        ),
        point_read_hint="`vigil assess intel get <type> <id>`",
    )

    if result:
        warn_untrusted_data()

    if args.as_json:
        if args.q:
            output = [_compact_search_json_row(row) for row in result]
        else:
            output = [_compact_type_json_row(row, args.intel_type) for row in result]
        print(json.dumps(output, indent=2, ensure_ascii=False))
        return

    if not result:
        print("No intel records matched.")
        return

    for row in result:
        if isinstance(row, dict):
            print(_format_search_row(row) if args.q else _format_row(row))
        else:
            print(row)
