"""vigil assess coverage — the coverage ledger.

A READ-ONLY, REPORTING projection: per in-scope host it shows route count,
real_app?, dedicated_lane?, finding verdict, the computed coverage-state, and
the C40 objectives — so an uncovered in-scope host is obvious at a glance.

The ledger joins three sources:
  * local cases.db work buffer  → distinct LIVE url_path (route count) +
    API/auth/GraphQL surface signal (``coverage_checks.load_route_stats_by_host``);
  * the backend per-host C40 projection (``coverage-readiness/by-host``), which
    now also carries the per-host finding-VERDICT join;
  * the dispatch list (``dispatches``) → which hosts had a dedicated lane.

A host is "covered" ONLY with a RECORDED VERDICT (a finding, or an
evidence-backed-negative decision such as a ``false_positive`` finding) — NOT a
mere completed dispatch. This command does NOT gate anything; the blocking gate
is a later phase. It only measures and surfaces.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib import coverage_checks as cc
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.scope import load_scope


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "coverage",
        help=(
            "Per-host coverage ledger: route count, real_app, dedicated lane, "
            "finding verdict, and the computed coverage-state (read-only)."
        ),
    )
    p.add_argument(
        "--route-threshold",
        dest="route_threshold",
        type=int,
        default=6,
        help=(
            "Distinct LIVE url_path count at/above which a host counts as a "
            "real_app on routes alone (default: 6). BLUNT heuristic; a small "
            "high-value API/auth/GraphQL surface UNDER the threshold is still "
            "treated as a real_app via OR-inclusion."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the structured ledger as JSON.",
    )
    p.set_defaults(func=run)


def _empty_per_host_payload() -> dict:
    return {
        "objectives": list(cc._PER_HOST_OBJECTIVES),
        "hosts": [],
        "finding_verdicts": {},
        "engagement_signals": {},
    }


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    scope_data = load_scope(cfg.engagement_dir)

    db_path = Path(cfg.engagement_dir) / "cases.db"
    route_stats = cc.load_route_stats_by_host(db_path)

    per_host_payload = _empty_per_host_payload()
    dispatched_hosts: dict[str, list[str]] = {}

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            payload = client.get("coverage-readiness/by-host")
            if isinstance(payload, dict):
                per_host_payload = payload
        except AssessError as exc:
            print(
                f"coverage: backend per-host fetch failed ({exc}); "
                "rendering route/scope-only ledger",
                file=sys.stderr,
            )
        try:
            dispatches = client.list_dispatches(limit=1000)
            dispatched_hosts = cc.dispatched_hosts_from_rows(dispatches)
        except AssessError:
            dispatched_hosts = {}

    ledger = cc.build_coverage_ledger(
        scope_data=scope_data,
        route_stats_by_host=route_stats,
        per_host_payload=per_host_payload,
        dispatched_hosts=dispatched_hosts,
        route_threshold=args.route_threshold,
    )

    if args.as_json:
        print(json.dumps(ledger, indent=2, ensure_ascii=False))
        return

    for line in cc.render_coverage_ledger_text(ledger):
        print(line)
