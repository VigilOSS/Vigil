"""vigil assess coverage — the coverage ledger.

A READ-ONLY, REPORTING projection: per in-scope host it shows route count,
real_app?, dedicated_lane?, finding verdict, the computed coverage-state, and
the C40 objectives — so an uncovered in-scope host is obvious at a glance.

The ledger joins three sources:
  * backend work buffer  → distinct LIVE url_path (route count) +
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

from assess.lib import coverage_checks as cc
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.scope import load_scope


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "coverage",
        help=(
            "Coverage ledger (read-only). Default: per-host route count, "
            "real_app, dedicated lane, finding verdict, computed coverage-state. "
            "--by-family: the per application-unit × attack-family GAP grid. "
            "--for-dispatch --host <h>: a paste-ready COVERAGE block for a "
            "dispatch prompt."
        ),
        description=(
            "Three read-only views over engagement coverage:\n"
            "  (default)        per-host coverage ledger.\n"
            "  --by-family      per application-unit × attack-family grid "
            "(GAP cells have no covering probe).\n"
            "  --for-dispatch   a COVERAGE: block scoped to --host [--path-prefix], "
            "reusing the by-family grid, to paste into a specialist dispatch "
            "instead of a prescriptive technique cage.\n\n"
            "Scoping vocabulary: on `coverage`, --host / --path-prefix select "
            "application-units (grid rows). This is distinct from --surface on "
            "`list-attempts`, which is a surface-id."
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
            "treated as a real_app via OR-inclusion. (default per-host view only.)"
        ),
    )
    p.add_argument(
        "--by-family",
        dest="by_family",
        action="store_true",
        help=(
            "Render the per application-unit × attack-family coverage grid from "
            "`coverage-readiness/by-family`: GAP cells (missing_block/missing_warn "
            "or zero covering probes) are marked, covered cells show the verdict + "
            "covering/total probe counts, and finding-linked cells are flagged."
        ),
    )
    p.add_argument(
        "--for-dispatch",
        dest="for_dispatch",
        action="store_true",
        help=(
            "Emit a paste-ready COVERAGE: block for a dispatch prompt, scoped to "
            "--host (required) and optional --path-prefix. Reuses the by-family "
            "grid (no extra backend call) and lists covered vs OPEN-gap families "
            "so the dispatch hands the specialist a map + open objective, not a "
            "technique cage."
        ),
    )
    p.add_argument(
        "--host",
        dest="host",
        default="",
        help=(
            "Application-unit host to scope --for-dispatch to (REQUIRED for that "
            "mode). NOTE: this is a host, NOT the --surface surface-id used by "
            "`list-attempts`."
        ),
    )
    p.add_argument(
        "--path-prefix",
        dest="path_prefix",
        default="",
        help="Optional application-unit path-prefix to further scope --for-dispatch.",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the structured payload as JSON (raw by-family payload under --by-family/--for-dispatch).",
    )
    p.set_defaults(func=run)


def _empty_per_host_payload() -> dict:
    return {
        "objectives": list(cc._PER_HOST_OBJECTIVES),
        "hosts": [],
        "finding_verdicts": {},
        "engagement_signals": {},
    }


def _fetch_by_family(cfg) -> dict:
    """Fetch the by-family coverage grid; empty grid on backend failure."""
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            payload = client.get("coverage-readiness/by-family")
        except AssessError as exc:
            print(
                f"coverage: backend by-family fetch failed ({exc}); "
                "rendering an empty grid",
                file=sys.stderr,
            )
            return {"units": [], "totals": {}}
    return payload if isinstance(payload, dict) else {"units": [], "totals": {}}


def _run_for_dispatch(args: argparse.Namespace, cfg) -> None:
    host = (getattr(args, "host", "") or "").strip()
    if not host:
        print(
            "coverage --for-dispatch: --host <h> is required "
            "(scopes the COVERAGE block to one application-unit host)",
            file=sys.stderr,
        )
        sys.exit(2)
    path_prefix = (getattr(args, "path_prefix", "") or "").strip()
    payload = _fetch_by_family(cfg)
    if getattr(args, "as_json", False):
        # Scope the JSON to --host [--path-prefix] too — the same filter the text
        # COVERAGE block applies — so `--for-dispatch --json` doesn't silently
        # dump the whole grid.
        host_l = host.lower()
        units = [
            u
            for u in (payload.get("units") or [])
            if isinstance(u, dict)
            and str(u.get("host") or "").strip().lower() == host_l
            and (not path_prefix or str(u.get("path_prefix") or "") == path_prefix)
        ]
        scoped = {"scope": {"host": host_l, "path_prefix": path_prefix or None}, "units": units}
        print(json.dumps(scoped, indent=2, ensure_ascii=False))
        return
    for line in cc.render_dispatch_coverage_block(
        payload, host=host, path_prefix=path_prefix or None
    ):
        print(line)


def _run_by_family(args: argparse.Namespace, cfg) -> None:
    payload = _fetch_by_family(cfg)
    if getattr(args, "as_json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return
    for line in cc.render_family_ledger_text(payload):
        print(line)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)

    # A1 / C4a: the by-family grid and the --for-dispatch COVERAGE block both
    # project the SAME `coverage-readiness/by-family` route; --for-dispatch
    # additionally filters it client-side to --host [--path-prefix]. Both are
    # guarded by getattr so the existing per-host path (and its tests, which
    # build args without these flags) is untouched.
    if getattr(args, "for_dispatch", False):
        _run_for_dispatch(args, cfg)
        return
    if getattr(args, "by_family", False):
        _run_by_family(args, cfg)
        return

    scope_data = load_scope(cfg.engagement_dir)

    route_stats: dict[str, dict] = {}
    per_host_payload = _empty_per_host_payload()
    dispatched_hosts: dict[str, list[str]] = {}

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        try:
            route_stats = cc.load_route_stats_by_host(client)
        except AssessError as exc:
            print(
                f"coverage: backend work-buffer fetch failed ({exc}); "
                "rendering ledger without route stats",
                file=sys.stderr,
            )
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
