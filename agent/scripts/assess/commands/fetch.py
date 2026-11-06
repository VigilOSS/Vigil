"""vigil assess fetch — GET assessment endpoint and print JSON.

``--list-routes`` prints the declared catalog below; it is the discovery surface
for a generic read verb whose whole argument is a route name.

Special-case: ``fetch intel`` hits ``/engagements/{key}/intel/summary`` (the
engagement-scoped intel summary lives outside ``/assessment/``). ``fetch
intel/<sub>`` reaches arbitrary intel routes (e.g. ``intel/tech-components``,
``intel/search``, ``intel/by-url``). ``fetch activity-entries`` follows the
same pattern for the activity log.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import parse_qsl, urlencode

from assess.commands.list_findings import compact_finding_list_row
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.code_structural_identity import parse_code_file_page
from assess.lib.config import load_config
from assess.lib.contracts import MAX_VARIANT_RECEIPT_PAGE
from assess.lib.finding_render import warn_untrusted_data
from assess.lib.intel_types import INTEL_TYPES


_ENGAGEMENT_SCOPED_PREFIXES = ("intel", "activity-entries")
_DEFAULT_PAGE_SIZE = 100

# How many pages one `--paginate` walk may request before it refuses, for the
# bare-array and the object-wrapped route alike: termination must not depend
# on which response shape a route happens to use.
# A walk stops on `has_more: false` or a short page, so a backend that keeps
# answering FULL pages never stops it — a route that drops `offset` re-serves
# page one for ever while the combined rows grow without bound. The bound buys
# termination: the read ends in a refusal that names the window to resume from
# instead of looping until the operator kills the command. At a route's own
# `?limit=` ceiling it still covers millions of rows, so a settled engagement
# never reaches it.
_MAX_PAGE_WALK = 500

# Assessment list routes `fetch` can traverse, mapped to the backend's own
# `?limit=` ceiling. Registration is not cosmetic: an unregistered route takes
# the raw-GET short-circuit below, which means the backend's bounded default
# truncates the answer, `--paginate` is never read, and the bounded-page notice
# never prints. Every catalog route the backend bounds by default therefore has
# to appear in one of these two tables, and the test suite asserts that against
# the routers rather than against a second hand-kept list.
#
# Before adding a route, read its backend query: it must honour `offset` on
# EVERY filter it accepts, under a total order (a final `id` tie-break). A
# route that drops `offset` makes the paging loop re-read page one for ever,
# and one ordered by a non-unique key silently duplicates and drops rows
# across pages — both worse than the truncation registration fixes.
_PAGED_ASSESSMENT_ENDPOINTS = {
    "artifacts/search": 1000,
    "assessment-runs": 1000,
    "code/fuzz/campaign-receipts": 100,
    "code/fuzz/decisions": 100,
    "code/variant-checks": MAX_VARIANT_RECEIPT_PAGE,
    "command-runs": 5000,
    "coverage-items": 5000,
    "dispatch-decisions": 1000,
    "dispatch-handoffs": 5000,
    "dispatches": 5000,
    "finding-links": 5000,
    "findings": 5000,
    "http-flows": 5000,
    "jobs": 1000,
    "probe-runs": 5000,
    "proof-receipts": 1000,
    "request-observations": 5000,
    "request-variants": 5000,
    "surfaces": 5000,
    "work-items": 10000,
}

# List routes that answer with a JSON OBJECT wrapping the page instead of a bare
# array, mapped to (rows key, backend `?limit=` ceiling). `get_all_pages` and
# `_require_assessment_list` both require an array, so registering one of these
# in the table above would turn a working read into a hard error.
_PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS = {
    "attempts": ("attempts", 5000),
    "code/files": ("items", 10000),
}

_PAGED_ENGAGEMENT_LIST_ENDPOINTS = {
    *(f"intel/{metadata[1]}" for metadata in INTEL_TYPES.values()),
    "intel/credentials",
    "intel/search",
}
_ACTIVITY_LIST_ENDPOINT = "activity-entries"
_ENGAGEMENT_LIST_PAGE_CAP = 500
_ACTIVITY_LIST_PAGE_CAP = 1000

# The declared catalog of read routes `fetch` exists to reach, as
# (route, what it returns). This is the ONLY place route names are written: the
# `endpoint` help points at `--list-routes` rather than repeating a sample set,
# and the paginated marker is read from the paging tables above. A route an
# operator cannot name is a route they cannot use — `code/repos/<repo-id>` was
# unreachable in practice for exactly that reason.
#
# Routes are curated, not exhaustive: these are the engagement-owned reads that
# are safe and useful to pull raw. The backend routers
# (app/api/assessment.py, app/api/code_analysis.py, app/api/intel.py) remain
# authoritative — `fetch <route>` still reaches any route they serve.
_FETCH_ROUTES: tuple[tuple[str, str], ...] = (
    ("summary", "Engagement rollup: phase, counts, and readiness headline."),
    ("phase-readiness", "Per-phase gate status for the current engagement."),
    ("report-readiness", "What still blocks a report-ready verdict."),
    ("coverage-readiness", "Coverage obligations and their standing."),
    ("resume-brief", "Rehydration brief for an interrupted engagement."),
    ("findings", "Recorded findings as compact rows."),
    ("report-findings", "Findings admitted to the report."),
    ("finding-groups", "Duplicate/variant groupings by root slug."),
    ("finding-links", "Typed relationships between findings."),
    ("attack-chains", "Recorded multi-step attack chains."),
    ("exploit-candidates", "Findings an exploit dispatch may be authorized against; pending_runtime_proof is excluded."),
    ("surfaces", "Catalogued attack surfaces."),
    ("coverage-items", "Coverage ledger collection."),
    ("coverage-items/<id>", "One coverage item: note history, linked work items and probe runs, blocked techniques on its host or endpoint."),
    ("work-items", "Open work queue collection; no work-items/<id> point read."),
    ("probe-runs", "Recorded probe attempts and their results."),
    ("request-variants", "Stored request variant collection."),
    ("request-variants/<id>", "One stored request variant."),
    ("request-observations", "Observed request/response pairs."),
    ("command-runs", "Audited command executions."),
    ("attempts", "Exploit/verification attempts."),
    ("proof-receipts", "Reproducible proof receipts."),
    ("artifacts/search?q=<text>", "Indexed engagement artifacts matching a query."),
    ("targets", "In-scope targets."),
    ("services", "Discovered services."),
    ("host-liveness", "Host reachability observations."),
    ("credentials", "Credentials captured for the engagement."),
    ("access-records", "Access obtained and how it was reached."),
    ("blocked-techniques", "Techniques recorded as blocked, with reasons."),
    ("application-units", "Application units used for depth attribution."),
    ("assessment-runs", "Assessment run history."),
    ("dispatches", "Specialist dispatch audit rows."),
    ("dispatch-handoffs", "Handoffs recorded by finished dispatches."),
    ("dispatch-decisions", "Recorded agent/operator decision rows; filter by ?kind=<kind> (containment_proposal, coverage_deferral, blind_triage_verdict, ...) and ?resolved=<bool>."),
    ("jobs", "Background runtime jobs."),
    ("oob-probes", "Out-of-band probe registrations and callbacks."),
    ("http-flows", "Captured proxy flows."),
    ("capture-policy", "Current proxy capture policy."),
    ("code/repos", "Ingested repositories: generation, manifest digest, git_churn."),
    ("code/repos/<repo-id>", "One repository record, git_churn included."),
    ("code/files", "Sealed source files with classification and priority; filter by repo_id, module_id, classification, analysis_status, search=<path text>, and repeatable path_prefix/path_glob; order with sort=analysis_priority|file_path|loc|git_churn_score|id and order=asc|desc. An unknown query param is REFUSED (HTTP 400), not ignored."),
    ("code/files/<file-id>", "One sealed file record."),
    ("code/modules", "Recorded architectural modules."),
    ("code/threat-model/<repo-id>", "Persisted repository threat model."),
    ("code/analysis-queue/stats", "Queue status counts and accounting debt."),
    ("code/triggers", "Cross-file triggers and their resolution state."),
    ("code/analysis-results", "Source-review receipts."),
    ("code/variant-checks", "Variant-check receipts."),
    ("code/readiness", "Code phase readiness detail."),
    ("code/coverage", "Code coverage projection by file and family."),
    ("code/fuzz/decisions", "Recorded fuzz required/not-required decisions."),
    ("code/fuzz/state", "Current fuzz campaign state."),
    ("code/fuzz/campaign-receipts", "Completed fuzz campaign receipts."),
    ("intel", "Intel summary (shorthand for intel/summary)."),
    ("intel/search?q=<text>", "Free-text search across every intel type."),
    ("intel/credentials", "Credential intel rows."),
    ("activity-entries", "Engagement activity log."),
)


def _fetch_route_catalog() -> tuple[tuple[str, str], ...]:
    """The declared routes plus one row per registered intel type.

    Intel routes are generated from INTEL_TYPES so a new intel type is
    discoverable the moment it is registered, instead of waiting for someone to
    remember this list.
    """
    intel_routes = tuple(
        (f"intel/{segment}", f"Recorded `{intel_type}` intel rows.")
        for intel_type, (_schema, segment) in sorted(INTEL_TYPES.items())
    )
    return _FETCH_ROUTES + intel_routes


def _route_page_cap(normalized_path: str) -> int | None:
    """The backend's ``?limit=`` ceiling for a route ``fetch`` can page.

    One number per route, because the ceilings are not one number: the sealed
    source inventory stops at 10000, the assessment lists at 5000, variant-check
    receipts at 500 and the fuzz history reads at 100. ``None`` means ``fetch``
    cannot traverse this route at all.
    """
    cap = _PAGED_ASSESSMENT_ENDPOINTS.get(normalized_path)
    if cap is not None:
        return cap
    envelope = _PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS.get(normalized_path)
    if envelope is not None:
        return envelope[1]
    if normalized_path == _ACTIVITY_LIST_ENDPOINT:
        return _ACTIVITY_LIST_PAGE_CAP
    if normalized_path in _PAGED_ENGAGEMENT_LIST_ENDPOINTS:
        return _ENGAGEMENT_LIST_PAGE_CAP
    return None


def _render_route_catalog() -> str:
    rows = _fetch_route_catalog()
    width = max(len(route) for route, _purpose in rows)
    assessment: list[str] = []
    engagement: list[str] = []
    for route, purpose in rows:
        cap = _route_page_cap(route.partition("?")[0].strip("/"))
        line = f"  {route.ljust(width)}  {purpose}"
        if cap is not None:
            line += f"  [--paginate; max limit {cap}]"
        (engagement if _is_engagement_scoped(route) else assessment).append(line)
    return "\n".join(
        [
            "Assessment routes — vigil assess fetch <route>:",
            *assessment,
            "",
            "Engagement-scoped routes — same command, resolved outside /assessment/:",
            *engagement,
            "",
            "Routes marked [--paginate] return one bounded page by default; the stated",
            "max is that route's own backend ceiling for an explicit ?limit=N.",
            "This catalog is curated; `fetch` still reaches any route the backend serves.",
        ]
    )


def register(subparsers) -> None:
    p = subparsers.add_parser("fetch", help="GET /assessment/{endpoint} or engagement-scoped routes")
    p.add_argument(
        "endpoint",
        nargs="?",
        help="Route to read; run `vigil assess fetch --list-routes` for the catalog.",
    )
    p.add_argument(
        "--list-routes",
        action="store_true",
        help="Print the declared catalog of fetchable routes and exit.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="No-op: fetch always returns JSON. Accepted for symmetry with list-* commands.",
    )
    p.add_argument(
        "--compact",
        action="store_true",
        help="One-line JSON output (indent=None) for piping to jq/jsonl tooling.",
    )
    p.add_argument(
        "--paginate",
        action="store_true",
        help=(
            "Explicitly fetch every page for known paginated list endpoints. "
            "Without this flag, fetch returns one bounded page. An explicit "
            "?limit=N is bounded by each route's own backend maximum — printed "
            "beside its [--paginate] marker in --list-routes — and a larger "
            "value is rejected, not clamped (HTTP 422 from the backend)."
        ),
    )
    p.add_argument(
        "--jq",
        default="",
        help="Optional jq expression to apply to the JSON response. "
        "Requires `jq` on $PATH; emits the post-jq text directly so the operator "
        "can pipeline filters without a shell pipe (e.g. --jq '.[] | select(.severity==\"high\")').",
    )
    p.set_defaults(func=run)


def _is_engagement_scoped(endpoint: str) -> bool:
    head = endpoint.strip("/").split("/", 1)[0]
    return head in _ENGAGEMENT_SCOPED_PREFIXES


def _point_read_hint(endpoint: str) -> str | None:
    """Return the canonical command for common singular point-route mistakes.

    ``fetch findings/<slug>`` and the plural intel REST paths remain valid for
    compatibility. The diagnostics cover only shapes that cannot name a backend
    route, so the generic fetch escape hatch stays generic.
    """
    path = endpoint.partition("?")[0].strip("/")
    parts = path.split("/")
    if len(parts) == 2 and parts[0] == "finding" and parts[1]:
        return f"vigil assess finding get {parts[1]}"
    if (
        len(parts) == 3
        and parts[0] == "intel"
        and parts[1] in INTEL_TYPES
        and parts[2].isdigit()
    ):
        return f"vigil assess intel get {parts[1]} {parts[2]}"
    return None


def _fetch_assessment_endpoint(
    client: AssessmentClient,
    endpoint: str,
    *,
    paginate: bool = False,
) -> Any:
    path, _sep, raw_query = endpoint.partition("?")
    normalized_path = path.strip("/")
    envelope = _PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS.get(normalized_path)
    if envelope is not None:
        rows_key, envelope_limit = envelope
        return _fetch_assessment_envelope(
            client,
            normalized_path=normalized_path,
            raw_query=raw_query,
            rows_key=rows_key,
            page_limit=envelope_limit,
            paginate=paginate,
        )
    page_limit = _PAGED_ASSESSMENT_ENDPOINTS.get(normalized_path)
    if page_limit is None:
        return client.get(endpoint)

    query_items = parse_qsl(raw_query, keep_blank_values=True)
    has_limit = any(key == "limit" for key, _value in query_items)
    has_offset = any(key == "offset" for key, _value in query_items)
    if paginate and (has_limit or has_offset):
        limit_values = [value for key, value in query_items if key == "limit"]
        offset_values = [value for key, value in query_items if key == "offset"]
        try:
            if len(limit_values) > 1 or len(offset_values) > 1:
                raise ValueError
            requested_page_size = (
                int(limit_values[0]) if limit_values else int(page_limit)
            )
            next_offset = int(offset_values[0]) if offset_values else 0
        except ValueError as exc:
            raise AssessError(
                f"fetch {normalized_path}: limit and offset must each be one integer"
            ) from exc
        if not 1 <= requested_page_size <= page_limit or next_offset < 0:
            raise AssessError(
                f"fetch {normalized_path}: limit must be 1..{page_limit} and offset non-negative"
            )
        base_query = [
            item for item in query_items if item[0] not in {"limit", "offset"}
        ]
        rows: list[Any] = []
        print(
            f"fetch: auto-paging {normalized_path} with "
            f"page_size={requested_page_size} from offset={next_offset}; "
            "stdout will be one combined JSON array.",
            file=sys.stderr,
        )
        for _page_index in range(_MAX_PAGE_WALK):
            page_query = urlencode(
                [
                    *base_query,
                    ("limit", str(requested_page_size)),
                    ("offset", str(next_offset)),
                ]
            )
            page = _require_assessment_list(
                client.get(f"{normalized_path}?{page_query}"), normalized_path
            )
            rows.extend(page)
            if len(page) < requested_page_size:
                break
            next_offset += len(page)
        else:
            raise AssessError(
                f"fetch {normalized_path}: stopped after {_MAX_PAGE_WALK} "
                f"page(s) of {requested_page_size} ({len(rows)} row(s)) with the "
                "list still unfinished, so the backend is not advancing; resume "
                f"the read from ?limit={requested_page_size}&offset={next_offset}"
            )
        print(
            f"fetch: fetched {len(rows)} {normalized_path} row(s) across all pages.",
            file=sys.stderr,
        )
        return rows
    if has_limit:
        rows = _require_assessment_list(client.get(endpoint), normalized_path)
        _warn_if_array_window_truncated(
            normalized_path, rows, query_items=query_items
        )
        return rows
    if paginate and not has_offset:
        paged_endpoint = normalized_path if not raw_query else endpoint
        print(
            f"fetch: auto-paging {normalized_path} with page_size={page_limit}; "
            "stdout will be one combined JSON array.",
            file=sys.stderr,
        )
        rows = _require_assessment_list(
            client.get_all_pages(paged_endpoint, page_size=page_limit),
            normalized_path,
        )
        print(
            f"fetch: fetched {len(rows)} {normalized_path} row(s) across all pages.",
            file=sys.stderr,
        )
        return rows

    # A route whose own ceiling is below the default page would 422 on the very
    # request meant to be the safe one.
    bounded_page_size = min(_DEFAULT_PAGE_SIZE, page_limit)
    bounded_query = [*query_items, ("limit", str(bounded_page_size))]
    if not has_offset:
        bounded_query.append(("offset", "0"))
    bounded_endpoint = f"{normalized_path}?{urlencode(bounded_query)}"
    rows = _require_assessment_list(client.get(bounded_endpoint), normalized_path)
    if normalized_path == "findings":
        rows = [
            compact_finding_list_row(row) if isinstance(row, dict) else row
            for row in rows
        ]
    print(
        f"fetch: returned one bounded page of up to {bounded_page_size} "
        f"{normalized_path} row(s); use --paginate to fetch every page or set "
        "?limit=N&offset=M explicitly.",
        file=sys.stderr,
    )
    return rows


def _warn_if_array_window_truncated(
    normalized_path: str, rows: list[Any], *, query_items: list[tuple[str, str]]
) -> None:
    """Say so when the caller's own ``?limit=`` is all that ended a bare-array read.

    The explicit window is still honoured exactly as written; what changes is
    that the loss is said out loud. A bare array carries neither ``has_more``
    nor ``total``, and ``_incomplete_envelope_notice`` reads envelopes only, so
    this was the one read with no truncation signal at all: ``?limit=5000``
    over 12000 rows printed 5000 rows and exited 0. A page that came back
    exactly as large as the caller asked for cannot be told apart from more
    rows waiting, which is what the notice says — the same evidence
    ``_envelope_truncation_reason`` uses for an envelope with no marker.
    """
    limit_values = [value for key, value in query_items if key == "limit"]
    offset_values = [value for key, value in query_items if key == "offset"]
    if len(limit_values) != 1 or len(offset_values) > 1:
        return
    try:
        requested_page_size = int(limit_values[0])
        start_offset = int(offset_values[0]) if offset_values else 0
    except ValueError:
        return
    if requested_page_size < 1 or start_offset < 0 or len(rows) != requested_page_size:
        return
    print(
        f"fetch: {normalized_path} was TRUNCATED at your own "
        f"?limit={requested_page_size}: the page came back exactly full at "
        f"{len(rows)} row(s), which a bare array cannot tell apart from more "
        f"rows waiting. Continue with ?limit={requested_page_size}"
        f"&offset={start_offset + len(rows)}, or re-run with --paginate to "
        "fetch every page.",
        file=sys.stderr,
    )


def _require_assessment_list(result: Any, endpoint: str) -> list[Any]:
    if not isinstance(result, list):
        raise AssessError(f"fetch {endpoint} expected a JSON array")
    if endpoint == "findings" and any(
        not isinstance(row, dict)
        or not isinstance(row.get("slug"), str)
        or not row["slug"].strip()
        for row in result
    ):
        raise AssessError("fetch findings received a finding row without a slug")
    return result


def _require_assessment_envelope_page(
    result: Any,
    *,
    normalized_path: str,
    rows_key: str,
    expected_offset: int,
) -> tuple[list[dict[str, Any]], int | None, bool | None]:
    """Validate one page of an object-wrapped assessment list route.

    ``code/files`` carries a full ``{total, offset, count, has_more, items}``
    envelope and ``parse_code_file_page`` is its canonical validator — including
    the internal consistency checks that make a merged read trustworthy.
    ``attempts`` answers ``{attempts, count}`` with no total and no ``has_more``,
    so the walk there can only stop on a short page; the returned ``total`` and
    ``has_more`` are ``None`` to say so.
    """
    if normalized_path == "code/files":
        try:
            return parse_code_file_page(
                result,
                expected_offset=expected_offset,
                context=f"fetch {normalized_path} response",
            )
        except ValueError as exc:
            raise AssessError(str(exc)) from exc
    if not isinstance(result, dict):
        raise AssessError(f"fetch {normalized_path} expected a JSON object")
    rows = result.get(rows_key)
    count = result.get("count")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise AssessError(
            f"fetch {normalized_path} expected an object with a {rows_key} array"
        )
    if type(count) is not int or count != len(rows):
        raise AssessError(f"fetch {normalized_path} count does not match {rows_key}")
    return rows, None, None


def _envelope_truncation_reason(
    rows: list[dict[str, Any]],
    total: int | None,
    has_more: bool | None,
    *,
    start_offset: int,
    requested_page_size: int,
) -> str | None:
    """Why one envelope page is not the whole answer, or ``None`` if it is.

    An explicit ``?limit=`` is honoured as written, which is exactly where
    truncation hides: the page is complete by its own contract and the command
    exits 0. ``has_more`` and ``total`` each prove more rows exist. An envelope
    carrying neither (``attempts``) can only report that the page came back
    exactly as large as the caller asked for, which it cannot tell apart from
    more rows waiting — so the notice says that instead of claiming either way.
    """
    if has_more is True:
        return "the envelope reports has_more"
    if total is not None and start_offset + len(rows) < total:
        return f"{start_offset + len(rows)} of {total} row(s) were returned"
    if total is None and has_more is None and len(rows) == requested_page_size:
        return (
            f"the page came back exactly full at {len(rows)} row(s), which this "
            "envelope cannot tell apart from more rows waiting"
        )
    return None


def _fetch_assessment_envelope(
    client: AssessmentClient,
    *,
    normalized_path: str,
    raw_query: str,
    rows_key: str,
    page_limit: int,
    paginate: bool,
) -> dict[str, Any]:
    """Read an object-wrapped list route, one bounded page or all of them.

    The array paging loop and ``client.get_all_pages`` both require a JSON
    array, so these routes cannot share it. What they can share is the contract:
    one bounded page with a notice by default, every page under ``--paginate``
    up to ``_MAX_PAGE_WALK``, and the operator's explicit window
    honoured as written — but never truncated in silence, because a window
    smaller than the list carries the same loss the default page does.
    """
    query_items = parse_qsl(raw_query, keep_blank_values=True)
    limit_values = [value for key, value in query_items if key == "limit"]
    offset_values = [value for key, value in query_items if key == "offset"]
    try:
        if len(limit_values) > 1 or len(offset_values) > 1:
            raise ValueError
        implicit_page_size = (
            page_limit if paginate else min(_DEFAULT_PAGE_SIZE, page_limit)
        )
        requested_page_size = (
            int(limit_values[0]) if limit_values else implicit_page_size
        )
        start_offset = int(offset_values[0]) if offset_values else 0
    except ValueError as exc:
        raise AssessError(
            f"fetch {normalized_path}: limit and offset must each be one integer"
        ) from exc
    if not 1 <= requested_page_size <= page_limit or start_offset < 0:
        raise AssessError(
            f"fetch {normalized_path}: limit must be 1..{page_limit} and offset non-negative"
        )
    base_query = [item for item in query_items if item[0] not in {"limit", "offset"}]

    def _page(offset: int) -> Any:
        page_query = urlencode(
            [
                *base_query,
                ("limit", str(requested_page_size)),
                ("offset", str(offset)),
            ]
        )
        return client.get(f"{normalized_path}?{page_query}")

    if not paginate:
        page = _page(start_offset)
        rows, total, has_more = _require_assessment_envelope_page(
            page,
            normalized_path=normalized_path,
            rows_key=rows_key,
            expected_offset=start_offset,
        )
        if not limit_values:
            print(
                f"fetch: returned one bounded page of up to {requested_page_size} "
                f"{normalized_path} row(s); use --paginate to fetch every page or "
                "set ?limit=N&offset=M explicitly.",
                file=sys.stderr,
            )
        else:
            # A caller who named their own window still gets one page, and a
            # window smaller than the list truncates the answer with nothing
            # in the JSON that says so. `?limit=5000` over 12000 rows is a
            # silent 7000-row loss, so the notice fires on the truncation
            # rather than on the absence of a `?limit=`.
            truncation = _envelope_truncation_reason(
                rows,
                total,
                has_more,
                start_offset=start_offset,
                requested_page_size=requested_page_size,
            )
            if truncation is not None:
                print(
                    f"fetch: {normalized_path} was TRUNCATED at your own "
                    f"?limit={requested_page_size}: {truncation}. Continue with "
                    f"?limit={requested_page_size}"
                    f"&offset={start_offset + len(rows)}, or re-run with "
                    "--paginate to fetch every page.",
                    file=sys.stderr,
                )
        return page

    print(
        f"fetch: auto-paging {normalized_path} with "
        f"page_size={requested_page_size} from offset={start_offset}; "
        "stdout will be one combined JSON object.",
        file=sys.stderr,
    )
    combined: list[dict[str, Any]] = []
    first_page: dict[str, Any] | None = None
    expected_total: int | None = None
    offset = start_offset
    for _page_index in range(_MAX_PAGE_WALK):
        page = _page(offset)
        rows, total, has_more = _require_assessment_envelope_page(
            page,
            normalized_path=normalized_path,
            rows_key=rows_key,
            expected_offset=offset,
        )
        if first_page is None:
            first_page = page
        if total is not None:
            if expected_total is None:
                expected_total = total
            elif total != expected_total:
                raise AssessError(
                    f"fetch {normalized_path}: total changed from {expected_total} "
                    f"to {total} while paging, so the combined read would drop or "
                    "duplicate rows; re-run against a settled engagement"
                )
        combined.extend(rows)
        offset += len(rows)
        if has_more is None:
            if len(rows) < requested_page_size:
                break
        elif not has_more:
            break
    else:
        raise AssessError(
            f"fetch {normalized_path}: stopped after {_MAX_PAGE_WALK} "
            f"page(s) of {requested_page_size} ({len(combined)} row(s) from "
            f"offset={start_offset}) with the list still unfinished, so the "
            "backend is not advancing; resume the read from "
            f"?limit={requested_page_size}&offset={offset}"
        )
    assert first_page is not None
    print(
        f"fetch: fetched {len(combined)} {normalized_path} row(s) across all pages.",
        file=sys.stderr,
    )
    merged = {**first_page, rows_key: combined, "count": len(combined)}
    if "has_more" in first_page:
        merged["offset"] = start_offset
        merged["has_more"] = False
    if expected_total is not None:
        merged["total"] = expected_total
    return merged


def _incomplete_envelope_notice(endpoint: str, result: Any) -> str | None:
    """Warn when a response envelope says the page ``fetch`` printed is partial.

    ``_PAGED_ASSESSMENT_ENDPOINTS`` and ``_PAGED_ASSESSMENT_ENVELOPE_ENDPOINTS``
    cover the routes ``fetch`` knows how to traverse. Any OTHER route that
    answers with ``has_more: true`` — a backend envelope nobody has registered
    yet — would print a truncated page and exit 0, which is how a repo-wide
    ``code/files`` read silently capped at one page. A bare array page carries no
    equivalent marker, so this catches envelopes only.
    """
    if not isinstance(result, dict) or result.get("has_more") is not True:
        return None
    normalized_path = endpoint.partition("?")[0].strip("/")
    offset = result.get("offset")
    count = result.get("count")
    resume = "an explicit ?limit=N&offset=M"
    if isinstance(offset, int) and not isinstance(offset, bool):
        advanced = (
            count if isinstance(count, int) and not isinstance(count, bool) else None
        )
        if advanced is None:
            rows = next(
                (value for value in result.values() if isinstance(value, list)), None
            )
            advanced = len(rows) if rows is not None else None
        if advanced is not None:
            resume = f"?offset={offset + advanced}"
    if _route_page_cap(normalized_path) is not None:
        return (
            f"fetch: {normalized_path} reported has_more; this is a PARTIAL page. "
            f"Continue with {resume}, or re-run with --paginate."
        )
    return (
        f"fetch: {normalized_path} reported has_more; this is a PARTIAL page and "
        f"fetch cannot traverse this route. Continue with {resume}."
    )


def _fetch_engagement_endpoint(
    client: AssessmentClient,
    endpoint: str,
    *,
    paginate: bool = False,
    page_size: int | None = None,
) -> Any:
    path, _sep, raw_query = endpoint.partition("?")
    normalized_path = path.strip("/")
    is_bare_list = normalized_path in _PAGED_ENGAGEMENT_LIST_ENDPOINTS
    is_activity = normalized_path == _ACTIVITY_LIST_ENDPOINT
    if not is_bare_list and not is_activity:
        return client.get_engagement(endpoint)

    query_items = parse_qsl(raw_query, keep_blank_values=True)
    has_limit = any(key == "limit" for key, _value in query_items)
    has_offset = any(key == "offset" for key, _value in query_items)
    if (has_limit or has_offset) and not paginate:
        return client.get_engagement(normalized_path, query=urlencode(query_items))

    if not paginate:
        bounded_query = urlencode(
            [*query_items, ("limit", _DEFAULT_PAGE_SIZE), ("offset", 0)]
        )
        result = client.get_engagement(normalized_path, query=bounded_query)
        print(
            f"fetch: returned one bounded page of up to {_DEFAULT_PAGE_SIZE} "
            f"{normalized_path} row(s); use --paginate to fetch every page or "
            "set ?limit=N&offset=M explicitly.",
            file=sys.stderr,
        )
        return result

    page_cap = _ACTIVITY_LIST_PAGE_CAP if is_activity else _ENGAGEMENT_LIST_PAGE_CAP
    effective_page_size = int(page_size or page_cap)
    offset = 0
    if has_limit or has_offset:
        limit_values = [value for key, value in query_items if key == "limit"]
        offset_values = [value for key, value in query_items if key == "offset"]
        try:
            if len(limit_values) > 1 or len(offset_values) > 1:
                raise ValueError
            if limit_values:
                effective_page_size = int(limit_values[0])
            if offset_values:
                offset = int(offset_values[0])
        except ValueError as exc:
            raise AssessError(
                f"fetch {normalized_path}: limit and offset must each be one integer"
            ) from exc
        if not 1 <= effective_page_size <= page_cap or offset < 0:
            raise AssessError(
                f"fetch {normalized_path}: limit must be 1..{page_cap} and offset non-negative"
            )
        query_items = [
            item for item in query_items if item[0] not in {"limit", "offset"}
        ]
    combined: list[Any] = []
    first_activity: dict[str, Any] | None = None
    for _page_index in range(_MAX_PAGE_WALK):
        query = urlencode(
            [*query_items, ("limit", effective_page_size), ("offset", offset)]
        )
        page = client.get_engagement(normalized_path, query=query)
        if is_activity:
            if not isinstance(page, dict) or not isinstance(page.get("items"), list):
                raise AssessError(
                    "fetch activity-entries expected an object with an items array"
                )
            if first_activity is None:
                first_activity = dict(page)
            page_rows = page["items"]
            total = page.get("total")
            if not isinstance(total, int) or isinstance(total, bool) or total < 0:
                raise AssessError(
                    "fetch activity-entries expected a non-negative total"
                )
        else:
            if not isinstance(page, list):
                raise AssessError(f"fetch {normalized_path} expected a JSON array")
            page_rows = page
            total = None
        combined.extend(page_rows)
        offset += len(page_rows)
        if len(page_rows) < effective_page_size or (
            total is not None and offset >= total
        ):
            break
    else:
        raise AssessError(
            f"fetch {normalized_path}: stopped after {_MAX_PAGE_WALK} page(s) of "
            f"{effective_page_size} ({len(combined)} row(s)) with the list still "
            "unfinished, so the backend is not advancing; resume the read from "
            f"?limit={effective_page_size}&offset={offset}"
        )
    print(
        f"fetch: fetched {len(combined)} {normalized_path} row(s) across all pages.",
        file=sys.stderr,
    )
    if is_activity:
        assert first_activity is not None
        return {**first_activity, "total": len(combined), "items": combined}
    return combined


_JQ_AVAILABLE: bool | None = None


def _jq_is_installed() -> bool:
    """Cache jq's presence so repeated --jq calls don't re-fork ``jq --version``."""
    global _JQ_AVAILABLE
    if _JQ_AVAILABLE is not None:
        return _JQ_AVAILABLE
    if not shutil.which("jq"):
        _JQ_AVAILABLE = False
        return False
    try:
        completed = subprocess.run(
            ["jq", "--version"], capture_output=True, text=True, check=False
        )
        _JQ_AVAILABLE = completed.returncode == 0
    except OSError:
        _JQ_AVAILABLE = False
    return _JQ_AVAILABLE


def _apply_jq(expression: str, json_text: str, *, compact: bool = False) -> str:
    """Run ``jq <expression>`` against ``json_text`` and return jq's stdout."""
    if not _jq_is_installed():
        print(
            "fetch --jq: `jq` not installed; install with "
            "`brew install jq` (macOS) or `apt install jq` (Debian/Ubuntu)",
            file=sys.stderr,
        )
        sys.exit(1)
    argv = ["jq"]
    if compact:
        argv.append("-c")
    argv.append(expression)
    try:
        completed = subprocess.run(
            argv,
            input=json_text,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        print(f"fetch --jq: failed to invoke jq: {exc}", file=sys.stderr)
        sys.exit(1)
    if completed.returncode != 0:
        if completed.stderr:
            print(completed.stderr.rstrip(), file=sys.stderr)
        sys.exit(completed.returncode or 1)
    return completed.stdout


def run(args) -> None:
    if getattr(args, "list_routes", False):
        print(_render_route_catalog())
        return
    if not args.endpoint:
        print(
            "fetch: an endpoint is required; run `vigil assess fetch --list-routes` "
            "to see the declared catalog of fetchable routes.",
            file=sys.stderr,
        )
        sys.exit(1)

    endpoint = args.endpoint.strip("/")
    point_read_hint = _point_read_hint(endpoint)
    if point_read_hint:
        print(
            f"fetch: '{endpoint}' is not a valid API route. "
            f"Did you mean `{point_read_hint}`?",
            file=sys.stderr,
        )
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if _is_engagement_scoped(endpoint):
            # Shorthand: `fetch intel` → `fetch intel/summary`. Users who want
            # the raw list of routes can still call e.g. `intel/tech-components`.
            if endpoint == "intel":
                endpoint = "intel/summary"
            result = _fetch_engagement_endpoint(
                client,
                endpoint,
                paginate=getattr(args, "paginate", False),
            )
        else:
            result = _fetch_assessment_endpoint(
                client,
                endpoint,
                paginate=getattr(args, "paginate", False),
            )

    # Raw fetch is an escape hatch across engagement-owned routes. Even
    # apparently structural projections can embed target names, excerpts, or
    # tool output, so mark the trust boundary on stderr without changing JSON.
    warn_untrusted_data()

    # Generic backstop for a route the paging tables do not cover: print the
    # partial page the operator already paid for, say plainly that it is
    # partial, and fail the command when they asked for every page.
    incomplete = _incomplete_envelope_notice(endpoint, result)
    if incomplete:
        print(incomplete, file=sys.stderr)

    if isinstance(result, str):
        if args.jq:
            print(_apply_jq(args.jq, result, compact=args.compact), end="")
        else:
            print(result)
    else:
        indent = None if args.compact else 2
        json_text = json.dumps(result, indent=indent, ensure_ascii=False)
        if args.jq:
            # jq accepts both compact and pretty input; always feed the result
            # as serialised JSON so the expression sees a uniform shape.
            compact_input = json.dumps(result, ensure_ascii=False)
            print(_apply_jq(args.jq, compact_input, compact=args.compact), end="")
        else:
            print(json_text)

    if incomplete and getattr(args, "paginate", False):
        sys.exit(1)
