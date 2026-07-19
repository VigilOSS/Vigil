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
from urllib.parse import quote, urlencode

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
            "dispatch prompt. --attempts: the recorded probe-attempt ledger."
        ),
        description=(
            "Four read-only views over engagement coverage:\n"
            "  (default)        per-host coverage ledger.\n"
            "  --by-family      per application-unit × attack-family grid "
            "(GAP cells have no covering probe).\n"
            "  --for-dispatch   a COVERAGE: block scoped to --host [--path-prefix], "
            "reusing the by-family grid, to paste into a specialist dispatch "
            "instead of a prescriptive technique cage.\n"
            "  --attempts       the recorded probe-attempt ledger (read side of "
            "record-probe), grouped by lens × result_status with finding linkage.\n\n"
            "Scoping vocabulary: on the default/grid views, --host / --path-prefix "
            "select application-units (grid rows). Under --attempts, --surface is a "
            "surface-id and --host is the target-host filter — keep the two straight."
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
        "--attempts",
        dest="attempts",
        action="store_true",
        help=(
            "Read the recorded probe-attempt ledger (the read side of record-probe) "
            "grouped by lens × result_status, each row carrying its finding linkage. "
            "Filters: --finding <slug> / --surface <id> / --host / --attack-family / "
            "--result-status / --lens / --limit / --offset. Use it to dedup against "
            "what a lens/family already tried on a host before dispatching more."
        ),
    )
    p.add_argument(
        "--host",
        dest="host",
        default="",
        help=(
            "Application-unit host to scope --for-dispatch to (REQUIRED for that "
            "mode), or the target-host filter under --attempts. NOTE: for the "
            "grid this is a host, NOT the --surface surface-id."
        ),
    )
    p.add_argument(
        "--path-prefix",
        dest="path_prefix",
        default="",
        help="Optional application-unit path-prefix to further scope --for-dispatch.",
    )
    # --attempts filters (a surface-ID here, NOT a host; use --host for host).
    p.add_argument("--finding", dest="finding", default="",
                   help="(--attempts) Filter to attempts linked to this finding slug (e.g. VA-047).")
    p.add_argument("--surface", dest="surface", default="",
                   help="(--attempts) Filter to attempts under this surface id (a surface-ID, not a host).")
    p.add_argument("--attack-family", dest="attack_family", default="",
                   help="(--attempts) Filter to a vuln-class attack_family token (e.g. idor, ssrf, sqli).")
    p.add_argument("--result-status", dest="result_status", default="", metavar="TOKEN",
                   help="(--attempts) Filter to an EXACT result_status token (tested|signal|attempted|blocked|no-signal|error).")
    p.add_argument("--lens", dest="lens", default="",
                   help="(--attempts) Filter to the free-text lens/mindset the probe ran under.")
    p.add_argument("--limit", type=int, default=50, help="(--attempts) Max rows (default 50).")
    p.add_argument("--offset", type=int, default=0, help="(--attempts) Row offset.")
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the structured payload as JSON (raw by-family payload under --by-family/--for-dispatch; raw attempts payload under --attempts).",
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


# ── --attempts: the read side of the probe ledger (folded in from list-attempts)
def _attempts_query(args: argparse.Namespace) -> str:
    params: list[tuple[str, str]] = []
    if getattr(args, "finding", ""):
        params.append(("finding", args.finding))
    if getattr(args, "surface", ""):
        params.append(("surface_id", args.surface))
    if getattr(args, "host", ""):
        params.append(("target_host", args.host))
    if getattr(args, "attack_family", ""):
        params.append(("attack_family", args.attack_family))
    if getattr(args, "result_status", ""):
        params.append(("result_status", args.result_status))
    if getattr(args, "lens", ""):
        params.append(("lens", args.lens))
    params.append(("limit", str(args.limit)))
    params.append(("offset", str(args.offset)))
    return "attempts?" + urlencode(params, quote_via=quote)


def _attempt_finding_cell(row: dict) -> str:
    """Render a row's finding linkage as ``slug (severity)`` — or ``-`` if unlinked."""
    slug = str(row.get("finding_slug") or "").strip()
    if not slug:
        return "-"
    severity = str(row.get("finding_severity") or "").strip()
    return f"{slug} ({severity})" if severity else slug


def _render_attempts_table(rows: list[dict]) -> str:
    """Render attempts as a table GROUPED by ``lens × result_status``.

    Rows with no lens group under ``(no-lens)``; each group prints a header line
    then its member rows, so "which mindset produced which verdict" reads at a
    glance. Every row carries its finding linkage (slug + severity).
    """
    if not rows:
        return "(no attempts matched)"

    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        lens = str(row.get("lens") or "").strip() or "(no-lens)"
        status = str(row.get("result_status") or "").strip() or "(no-status)"
        groups.setdefault((lens, status), []).append(row)

    header = [
        "id", "host", "path", "port", "auth_context", "attack_family",
        "http", "signal", "tool", "agent", "finding", "created_at",
    ]
    out: list[str] = []
    for (lens, status) in sorted(groups):
        members = groups[(lens, status)]
        out.append(f"== lens={lens} | result_status={status} ({len(members)}) ==")
        out.append("\t".join(header))
        for row in members:
            http = row.get("observed_http_status")
            http_str = "-" if http is None else str(http)
            values = [
                str(row.get("id", "")),
                str(row.get("target_host") or ""),
                str(row.get("target_path") or ""),
                str(row.get("target_port") or "-"),
                str(row.get("auth_context") or "-"),
                str(row.get("attack_family") or "-"),
                http_str,
                str(row.get("signal_type") or "-"),
                str(row.get("tool_name") or "-"),
                str(row.get("agent_name") or "-"),
                _attempt_finding_cell(row),
                str(row.get("created_at") or ""),
            ]
            out.append("\t".join(values))
        out.append("")
    return "\n".join(out).rstrip("\n")


def _run_attempts(args: argparse.Namespace, cfg) -> None:
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        payload = client.get(_attempts_query(args))

    if getattr(args, "as_json", False):
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    # Pinned shape: {"attempts": [...], "count": N}. Tolerate a bare list too.
    if isinstance(payload, dict):
        rows = payload.get("attempts") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    rows = [r for r in rows if isinstance(r, dict)]
    print(_render_attempts_table(rows))


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)

    # A1 / C4a: the by-family grid and the --for-dispatch COVERAGE block both
    # project the SAME `coverage-readiness/by-family` route; --for-dispatch
    # additionally filters it client-side to --host [--path-prefix]. Both are
    # guarded by getattr so the existing per-host path (and its tests, which
    # build args without these flags) is untouched.
    if getattr(args, "attempts", False):
        _run_attempts(args, cfg)
        return
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
