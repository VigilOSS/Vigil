"""aith assess check-scope-coverage — per-scope-entry coverage audit.

This is a higher-level sibling of `check-coverage`: where that command audits
the backend's `assessment_surfaces` table for surface-level resolution,
`check-scope-coverage` walks every entry in `scope.json` (bare hosts,
wildcards, or http URLs) and reports coverage state across the enumeration,
collection, and consumption phases.

Unlike earlier revisions, this command does not re-parse raw command-run argv
to infer which enumeration/collection tool ran. Instead, coverage is read
directly from durable state the recon/collection specialists already produce:

- Backend `GET /engagements/{key}/assessment/services` — the live endpoints
  each scope entry resolves to. Wildcards require at least one live service
  under them; apex-only deployments satisfy that trivially.
- Backend `GET /engagements/{key}/assessment/surfaces` — recorded surface
  candidates keyed by host. Any surface under a scope entry's host proves
  collection produced something.
- Local `$DIR/cases.db` `work_items` grouped by status (pending / processing
  / done / skipped / error). Rows under a scope entry's host prove URL-level
  collection happened, and the pending/terminal_reason split drives the
  consumption gate.

The gate asks "did enumeration and collection produce evidence under this
scope entry?" not "did a specific tool binary run?". That shift is intentional:
the tool-binary question used to be answered by shell-parsing every stored
command run, which was fragile against wrappers, shell prefixes, and
file-driven target lists. The state we check instead is what downstream phases
actually consume, so a pass here means later phases have real data to work
with.

Scope-entry → host match heuristics:

- ``bare_host`` and ``url`` entries match hosts equal to the entry host.
- ``wildcard`` entries match the apex and any subdomain under it.

Exit codes:

- ``0`` — all required-stage gates clean (or no stage required).
- ``1`` — one or more scope entries fail the required stage gate, or a
  backend/CLI error prevented audit completion.
- ``2`` — invocation-time failure (missing scope.json, unparseable config).

The ``--require-stage`` flag gates only the exit code. All discovery still
happens regardless, so a ``--verbose`` run without a stage gate is still a
useful full-scope overview.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.scope import (
    classify_scope_entry,
    entry_matches_host,
    host_from_token,
    host_is_vendor_saas,
)


def _explicit_literal_scope_hosts(entries: list[dict[str, Any]]) -> set[str]:
    """Hosts authored explicitly in ``scope.json`` (bare host or URL entry).

    Wildcard entries are excluded — those expand to subdomains the operator
    did not enumerate by hand, and a vendor-SaaS subdomain that appears
    under wildcard expansion is the genuinely ambiguous case the
    Vendor-SaaS scope checkpoint exists to resolve. An explicit literal
    (e.g. ``customer.my.salesforce.com`` typed directly into scope.json) is
    already the operator's in-scope decision; making the gate fire on it
    is theatre.
    """
    return {
        entry["host"]
        for entry in entries
        if entry.get("entry_kind") in ("bare_host", "url") and entry.get("host")
    }


def _vendor_saas_decided_hosts(client: AssessmentClient) -> set[str]:
    """Return the set of hosts that already carry a vendor-SaaS scope decision.

    Round 9: the Vendor-SaaS scope checkpoint records the user's choice in
    the orchestrator backend's ``assessment_dispatch_decisions`` table with
    ``kind='scope_decision'``. Hosts in that set are excluded from the
    phase-advance gate. A backend failure returns the empty set (the gate
    fires conservatively).
    """
    try:
        rows = client.list_decisions(kind="scope_decision")
    except AssessError:
        return set()
    decisions: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        host = payload.get("host")
        if isinstance(host, str) and host.strip():
            decisions.add(host.strip().rstrip(".").lower())
    return decisions


# Services count as "live" when the backend state is anything except
# `down`/`filtered`/`unreachable`. We prefer an allow list over a block list
# so new backend state values default to counting as live (they'd have to opt
# out explicitly), which keeps the audit optimistic during backend schema
# evolution.
_NON_LIVE_SERVICE_STATES: frozenset[str] = frozenset({"down", "filtered", "unreachable"})


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "check-scope-coverage",
        help="Audit coverage state per scope.json entry across enum/collect/consume phases",
    )
    p.add_argument(
        "--require-stage",
        dest="require_stage",
        choices=("enum", "collection", "consumption"),
        default=None,
        help=(
            "Gate the exit code on a stage. 'enum' requires every scope entry "
            "to have enumeration evidence (bare hosts satisfy this trivially; "
            "wildcards require at least one live service, surface, or work "
            "item under them). 'collection' additionally requires at least "
            "one surface or work item per entry. 'consumption' additionally "
            "requires pending==0 or every remaining pending item to carry "
            "terminal_reason."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the full JSON report to stdout instead of the human-readable summary",
    )
    p.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Dump per-entry detail rows even when the summary passes (default: compact)",
    )
    p.add_argument(
        "--strict-vendor-saas",
        dest="strict_vendor_saas",
        action="store_true",
        help=(
            "Fail the coverage gate on undecided vendor-SaaS discoveries. "
            "Without this flag, pending vendor-SaaS decisions are reported "
            "but do not block phase advance."
        ),
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    scope_path = Path(cfg.engagement_dir) / "scope.json"
    if not scope_path.is_file():
        print(f"check-scope-coverage: scope.json not found at {scope_path}", file=sys.stderr)
        sys.exit(2)

    try:
        scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check-scope-coverage: unable to read scope.json: {exc}", file=sys.stderr)
        sys.exit(2)

    raw_hosts = scope_data.get("hosts") or []
    if not isinstance(raw_hosts, list):
        print("check-scope-coverage: scope.json `hosts` must be a list", file=sys.stderr)
        sys.exit(2)

    entries = [classify_scope_entry(h) for h in raw_hosts if isinstance(h, str) and h.strip()]
    entries = [e for e in entries if e is not None]

    scope_metadata = _extract_scope_metadata(scope_data)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        try:
            services = client.get("services")
        except AssessError as exc:
            print(f"check-scope-coverage: backend services fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        try:
            surfaces = client.get("surfaces")
        except AssessError as exc:
            print(f"check-scope-coverage: backend surfaces fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        decided_hosts = _vendor_saas_decided_hosts(client)
    finally:
        client.close()

    services_list = services if isinstance(services, list) else []
    surfaces_list = surfaces if isinstance(surfaces, list) else []

    db_path = Path(cfg.engagement_dir) / "cases.db"
    try:
        work_by_host = _load_work_items_by_host(db_path)
    except sqlite3.Error as exc:
        print(f"check-scope-coverage: unable to read work buffer: {exc}", file=sys.stderr)
        sys.exit(1)

    report_entries: list[dict[str, Any]] = []
    for entry in entries:
        report_entries.append(
            _build_entry_report(
                entry=entry,
                services=services_list,
                surfaces=surfaces_list,
                work_by_host=work_by_host,
                scope_metadata=scope_metadata,
                required_stage=args.require_stage,
            )
        )

    # Vendor-SaaS undecided hosts: any host known to services/surfaces/work
    # that matches a vendor-SaaS suffix and has no recorded scope_decision
    # blocks the gate. The user-facing checkpoint must record a decision
    # (in-scope, out-of-scope, partial-scope) before phase advance — UNLESS
    # the operator already authored the host as an explicit literal entry in
    # scope.json (a bare-host or url entry that resolves exactly to this
    # host). Wildcard-matched discoveries still gate; those are the genuinely
    # ambiguous case (the operator wrote ``*.example.test`` and a vendor
    # subdomain showed up under expansion). An explicit literal in scope.json
    # is already an unambiguous in-scope decision.
    explicit_literal_hosts = _explicit_literal_scope_hosts(entries)
    vendor_saas_pending = _vendor_saas_hosts_pending_decision(
        services=services_list,
        surfaces=surfaces_list,
        work_by_host=work_by_host,
        decided_hosts=decided_hosts | explicit_literal_hosts,
    )

    overall_gaps = _collect_overall_gaps(report_entries, args.require_stage)
    strict_vendor_saas = bool(getattr(args, "strict_vendor_saas", False))
    if vendor_saas_pending and args.require_stage is not None and strict_vendor_saas:
        for host, vendor in vendor_saas_pending:
            overall_gaps.append(
                f"vendor-saas: {host} (vendor={vendor}) has no scope_decision recorded "
                f"(record via `aith assess dispatch record-decision --kind scope_decision --host {host} --vendor {vendor} --choice ...`)"
            )
    ready = not overall_gaps

    report = {
        "engagement_key": cfg.engagement_key,
        "required_stage": args.require_stage,
        "entries": report_entries,
        "overall_gaps": overall_gaps,
        "vendor_saas_pending_decision": [
            {"host": host, "vendor": vendor} for host, vendor in vendor_saas_pending
        ],
        "strict_vendor_saas": strict_vendor_saas,
        "ready": ready,
    }

    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_text(report, verbose=args.verbose)

    if not ready:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Host extraction helpers
# ---------------------------------------------------------------------------


def _endpoint_host(endpoint: str) -> str:
    """Return the lowercased host portion of a service endpoint or surface
    target descriptor.

    Services store `endpoint` as either a bare host, a host:port, or a full
    URL. Surfaces store `target_descriptor` in the same shapes plus the
    occasional space-separated "<host> <path>" form. We unify them all to a
    lowercased host string for matching.
    """
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    first = raw.split()[0]
    if "://" in first:
        return host_from_token(first)
    ipv6_host = _ipv6_endpoint_host(first)
    if ipv6_host:
        return ipv6_host
    return host_from_token(first)


def _ipv6_endpoint_host(endpoint: str) -> str:
    first = endpoint.strip().strip("'\"<>()").rstrip(",;").rstrip(".").lower()
    if not first or first.count(":") < 2:
        return ""
    if first.startswith("["):
        return host_from_token(first)
    host, _, port = first.rpartition(":")
    if port.isdigit() and _ip_literal(host):
        return _ip_literal(host)
    return _ip_literal(first)


def _ip_literal(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return ""


# ---------------------------------------------------------------------------
# Per-entry roll-up
# ---------------------------------------------------------------------------


def _build_entry_report(
    *,
    entry: dict[str, Any],
    services: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    work_by_host: dict[str, dict[str, int]],
    scope_metadata: dict[str, dict[str, Any]],
    required_stage: str | None,
) -> dict[str, Any]:
    live_hosts_set: set[str] = set()
    live_host_samples: list[str] = []
    total_services = 0

    for svc in services:
        endpoint_host = _endpoint_host(str(svc.get("endpoint") or ""))
        if not entry_matches_host(entry, endpoint_host):
            continue
        total_services += 1
        state = str(svc.get("state") or "").lower()
        if state in _NON_LIVE_SERVICE_STATES:
            continue
        if endpoint_host and endpoint_host not in live_hosts_set:
            live_hosts_set.add(endpoint_host)
            if len(live_host_samples) < 10:
                live_host_samples.append(endpoint_host)

    surface_hosts: set[str] = set()
    surfaces_count = 0
    for surface in surfaces:
        descriptor = str(surface.get("target_descriptor") or "")
        host = _endpoint_host(descriptor)
        if not entry_matches_host(entry, host):
            continue
        surfaces_count += 1
        if host:
            surface_hosts.add(host)

    host_work = (
        _aggregate_wildcard_work(entry, work_by_host)
        if entry["entry_kind"] == "wildcard"
        else work_by_host.get(entry["host"], {})
    )
    work_queued = {
        "pending": int(host_work.get("pending", 0)),
        "processing": int(host_work.get("processing", 0)),
        "done": int(host_work.get("done", 0)),
        "skipped": int(host_work.get("skipped", 0)),
        "error": int(host_work.get("error", 0)),
        "pending_without_terminal_reason": int(host_work.get("pending_without_terminal_reason", 0)),
    }
    work_total = sum(
        work_queued[key] for key in ("pending", "processing", "done", "skipped", "error")
    )

    # Enum evidence: what does the downstream state actually show under this
    # scope entry? "We expanded and something is there" is what enumeration
    # was supposed to produce; checking that is more honest than "did a tool
    # whose name we recognize run against it".
    enum_evidence: list[str] = []
    if entry["entry_kind"] in ("bare_host", "url"):
        enum_evidence.append("bare_host")
    if live_hosts_set:
        enum_evidence.append("services")
    if surface_hosts:
        enum_evidence.append("surfaces")
    if work_total > 0:
        enum_evidence.append("work_items")
    enum_attempted = bool(enum_evidence)

    collection_evidence: list[str] = []
    if surfaces_count > 0:
        collection_evidence.append("surfaces")
    if work_total > 0:
        collection_evidence.append("work_items")
    collection_attempted = bool(collection_evidence)

    metadata = scope_metadata.get(_scope_metadata_lookup_key(entry), {})
    entry_status = str(metadata.get("status") or "").lower()

    gaps: list[str] = []
    # Informational: wildcard produced no live hosts even though *something*
    # (a surface or work item) gave us enum evidence. Useful signal for the
    # operator to review scope relevance; not a --require-stage enum failure.
    if entry["entry_kind"] == "wildcard" and enum_attempted and not live_hosts_set:
        gaps.append("no-live-hosts")
    if required_stage is None:
        pass
    elif required_stage == "enum":
        if not enum_attempted:
            gaps.append("no-enum")
    elif required_stage == "collection":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
    elif required_stage == "consumption":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
        if not _consumption_satisfied(work_queued, entry_status):
            gaps.append("pending-work-remains")

    return {
        "scope_entry": entry["scope_entry"],
        "entry_kind": entry["entry_kind"],
        "host": entry["host"],
        "enum_attempted": enum_attempted,
        "enum_evidence": enum_evidence,
        "total_services": total_services,
        "live_hosts": len(live_hosts_set),
        "live_host_samples": live_host_samples,
        "surfaces_count": surfaces_count,
        "collection_attempted": collection_attempted,
        "collection_evidence": collection_evidence,
        "work_queued": work_queued,
        "status": entry_status or None,
        "gaps": gaps,
    }


def _aggregate_wildcard_work(
    entry: dict[str, Any],
    work_by_host: dict[str, dict[str, int]],
) -> dict[str, int]:
    """Sum per-host work counts for a wildcard entry.

    We can't pre-index the work map by wildcard because new subdomains come
    and go between runs — iterate every host key once per wildcard and fold
    in the matching counts. Cheap for the sizes we care about (< 1k hosts).
    """
    aggregate: dict[str, int] = {}
    for host, counts in work_by_host.items():
        if not entry_matches_host(entry, host):
            continue
        for key, val in counts.items():
            aggregate[key] = aggregate.get(key, 0) + int(val)
    return aggregate


def _consumption_satisfied(work_queued: dict[str, int], entry_status: str) -> bool:
    """Return True when the consumption gate is satisfied.

    A scope entry marked `status=deferred` in scope metadata is terminal —
    the operator decided to skip it, which is a valid terminal state that
    shouldn't block report-time readiness. Otherwise: pending==0 or every
    remaining pending item has terminal_reason set (= implicit consumption
    via classify-work's inert/skipped pipeline).
    """
    if entry_status == "deferred":
        return True
    if int(work_queued.get("pending", 0)) == 0:
        return True
    if int(work_queued.get("pending_without_terminal_reason", 0)) == 0:
        return True
    return False


# ---------------------------------------------------------------------------
# scope.json metadata helpers
# ---------------------------------------------------------------------------


def _extract_scope_metadata(scope_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Parse optional per-host status metadata from scope.json.

    Supported shapes (in priority order):

    - ``host_metadata``: a dict keyed by host string, value is a dict with
      at least a `status` field.
    - ``deferred_hosts``: a list of hosts to treat as status=deferred.

    New schemas can be added by extending this parser rather than adding a
    new CLI flag — the CLI treats the metadata as advisory.
    """
    metadata: dict[str, dict[str, Any]] = {}
    raw_map = scope_data.get("host_metadata")
    if isinstance(raw_map, dict):
        for host, info in raw_map.items():
            if isinstance(host, str) and isinstance(info, dict):
                normalized_key = _normalize_scope_metadata_key(host)
                if normalized_key:
                    metadata[normalized_key] = dict(info)

    raw_deferred = scope_data.get("deferred_hosts")
    if isinstance(raw_deferred, list):
        for host in raw_deferred:
            if isinstance(host, str):
                normalized_key = _normalize_scope_metadata_key(host)
                if not normalized_key:
                    continue
                bucket = metadata.setdefault(normalized_key, {})
                if "status" not in bucket:
                    bucket["status"] = "deferred"
    return metadata


def _normalize_scope_metadata_key(raw: str) -> str:
    entry = classify_scope_entry(raw)
    if entry is None:
        return ""
    return _scope_metadata_lookup_key(entry)


def _scope_metadata_lookup_key(entry: dict[str, Any]) -> str:
    if entry["entry_kind"] == "wildcard":
        return f"wildcard:{entry['host']}"
    return f"host:{entry['host']}"


# ---------------------------------------------------------------------------
# cases.db work buffer
# ---------------------------------------------------------------------------


def _load_work_items_by_host(db_path: Path) -> dict[str, dict[str, int]]:
    """Return a ``{host: {status: count, ...}}`` rollup from the local DB.

    The mapping also tracks ``pending_without_terminal_reason`` so the
    consumption gate can distinguish "really pending" from "pending but
    deferred by classify-work". A missing DB yields an empty map rather
    than an error — offline/local-only workflows should still render
    audits so operators can spot drift.
    """
    if not db_path.is_file():
        return {}

    rows: list[tuple[str, str, int]] = []
    rows_with_reason: list[tuple[str, str, int]] = []
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            """
            SELECT url, status, COUNT(*) AS total
            FROM work_items
            GROUP BY url, status
            """
        )
        rows = [(str(r[0] or ""), str(r[1] or ""), int(r[2] or 0)) for r in cursor.fetchall()]
        cursor = conn.execute(
            """
            SELECT url, COUNT(*) AS total
            FROM work_items
            WHERE status = 'pending' AND (terminal_reason IS NULL OR terminal_reason = '')
            GROUP BY url
            """
        )
        rows_with_reason = [(str(r[0] or ""), "pending_without_terminal_reason", int(r[1] or 0)) for r in cursor.fetchall()]
    finally:
        conn.close()

    agg: dict[str, dict[str, int]] = {}
    for url, status, count in rows + rows_with_reason:
        host = _endpoint_host(url)
        if not host:
            continue
        bucket = agg.setdefault(host, {})
        bucket[status] = bucket.get(status, 0) + count
    return agg


# ---------------------------------------------------------------------------
# Overall gate and rendering
# ---------------------------------------------------------------------------


def _vendor_saas_hosts_pending_decision(
    *,
    services: list[dict[str, Any]],
    surfaces: list[dict[str, Any]],
    work_by_host: dict[str, dict[str, int]],
    decided_hosts: set[str],
) -> list[tuple[str, str]]:
    """Return ``[(host, vendor), ...]`` for vendor-SaaS hosts lacking a decision.

    Walks every host present in services / surfaces / work_items, classifies
    each via :func:`host_is_vendor_saas`, and excludes any host that already
    carries a ``scope_decision`` row in the orchestrator's
    ``assessment_dispatch_decisions`` table. Output is sorted by host string for
    deterministic output.
    """
    seen: dict[str, str] = {}
    for svc in services:
        host = _endpoint_host(str(svc.get("endpoint") or ""))
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    for surface in surfaces:
        host = _endpoint_host(str(surface.get("target_descriptor") or ""))
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    for host in work_by_host.keys():
        vendor = host_is_vendor_saas(host)
        if host and vendor and host not in decided_hosts and host not in seen:
            seen[host] = vendor
    return sorted(seen.items())


def _collect_overall_gaps(entries: list[dict[str, Any]], required_stage: str | None) -> list[str]:
    if required_stage is None:
        return []
    messages: list[str] = []
    for entry in entries:
        stage_gaps = [g for g in entry.get("gaps", []) if g != "no-live-hosts"]
        if not stage_gaps:
            continue
        for gap in stage_gaps:
            messages.append(f"scope-entry: {entry['scope_entry']} — {gap}")
    return messages


def _render_text(report: dict[str, Any], *, verbose: bool) -> None:
    entries = report["entries"]
    ready = report["ready"]
    stage = report["required_stage"]
    header = f"scope-coverage: {'ok' if ready else 'blocked'}"
    if stage:
        header = f"{header} (stage={stage})"
    print(header)
    if not entries:
        print("  (no scope entries in scope.json `hosts`)")
        return

    if not verbose and ready:
        for entry in entries:
            live = entry["live_hosts"]
            samples = ", ".join(entry["live_host_samples"][:3]) if entry["live_host_samples"] else "-"
            print(
                f"  - {entry['scope_entry']} [{entry['entry_kind']}] live={live} "
                f"surfaces={entry['surfaces_count']} "
                f"enum={'y' if entry['enum_attempted'] else 'n'} "
                f"collect={'y' if entry['collection_attempted'] else 'n'} "
                f"pending={entry['work_queued']['pending']} samples={samples}"
            )
        return

    for entry in entries:
        print(
            f"  - {entry['scope_entry']} [{entry['entry_kind']}] host={entry['host']}"
        )
        print(
            f"      enum: attempted={entry['enum_attempted']} evidence={entry['enum_evidence']}"
        )
        print(
            f"      live_hosts={entry['live_hosts']} total_services={entry['total_services']} samples={entry['live_host_samples']}"
        )
        print(
            f"      collection: attempted={entry['collection_attempted']} evidence={entry['collection_evidence']} surfaces={entry['surfaces_count']}"
        )
        print(
            f"      work_queued={entry['work_queued']}"
        )
        if entry.get("status"):
            print(f"      status={entry['status']}")
        if entry["gaps"]:
            print(f"      gaps={entry['gaps']}")

    if report["overall_gaps"]:
        print("gaps:")
        for msg in report["overall_gaps"]:
            print(f"  - {msg}")

    vendor_saas_pending = report.get("vendor_saas_pending_decision") or []
    if vendor_saas_pending:
        print("vendor-saas-pending-decision:")
        for row in vendor_saas_pending:
            print(
                f"  - {row['host']} (vendor={row['vendor']}) — record a "
                f"scope_decision via `aith assess dispatch record-decision "
                f"--kind scope_decision --host {row['host']} --vendor {row['vendor']} "
                f"--choice ...` before recon dispatch"
            )
