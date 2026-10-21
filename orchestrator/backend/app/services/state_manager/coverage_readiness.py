from __future__ import annotations

import enum
import json
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException

from ..events import _engagement_or_404

from . import _common
from ._common import (
    SEVERITY_RANK,
    WORKFLOW_STATUS_RANK,
    _fetch_all,
    _normalize_severity,
    _normalize_verification_status,
    _normalize_workflow_status,
    _scalar_row,
)
from .dispatches import _serialize_decision


class SurfaceStatus(enum.StrEnum):
    """Per-surface resolution status stored in ``assessment_surfaces.status``."""

    DISCOVERED = "discovered"
    COVERED = "covered"
    NOT_APPLICABLE = "not_applicable"
    DEFERRED = "deferred"
    PARTIALLY_COVERED = "partially-covered"
    ADMINISTRATIVELY_CLOSED = "administratively-closed"


SURFACE_STATUSES = frozenset(SurfaceStatus)
SURFACE_RESOLUTION_STATUSES = SURFACE_STATUSES - {SurfaceStatus.DISCOVERED}
# A surface is retired only when it is covered or ruled not applicable; every
# other status — including administratively closed, which never earns coverage —
# is open work. The summary badge and each surface row's ``open`` flag read this.
OPEN_SURFACE_STATUSES = SURFACE_STATUSES - {SurfaceStatus.COVERED, SurfaceStatus.NOT_APPLICABLE}


def surface_is_open(status_value: str | None) -> bool:
    return status_value in OPEN_SURFACE_STATUSES
HIGH_RISK_DEFERRED_SURFACE_TYPES: frozenset[str] = frozenset(
    {"account_recovery", "dynamic_render", "object_reference", "privileged_write"}
)

def _active_finding_hosts(engagement_id: int) -> set[str]:
    """Hosts that carry at least one ACTIVE (reportable, non-draft) finding.

    Surfaces have no FK to findings (depth-gate S16), so "this surface is
    linked to an active finding" is resolved by matching the surface's host to
    a reportable finding's ``canonical_location`` host. Draft / false-positive /
    merged findings are excluded — only a finding the engagement is actually
    standing behind makes its surface a real (non-advisory) blocker (L1-2).
    """
    reportable_statuses = (
        "active",
        "blocked",
        "exploited",
        "contained",
        "eradicated",
        "recovered",
        "reported",
    )
    engagement = _engagement_or_404(engagement_id)
    placeholders = ", ".join("?" for _ in reportable_statuses)
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"SELECT canonical_location FROM assessment_findings "
            f"WHERE engagement_id = ? AND status IN ({placeholders})",
            (engagement.id, *reportable_statuses),
        ).fetchall()
    hosts: set[str] = set()
    for row in rows:
        host = _coverage_endpoint_host(str(row["canonical_location"] or ""))
        if host:
            hosts.add(host)
    return hosts


def _surface_is_finding_linked(surface: dict[str, Any], active_hosts: set[str]) -> bool:
    host = _coverage_endpoint_host(str(surface.get("target_descriptor") or ""))
    return bool(host) and host in active_hosts


def _deferral_exempt_surface_types(engagement_id: int) -> set[str]:
    """Surface types an operator has exempted from the high-risk deferral block
    via a recorded engagement-wide policy decision (L1-10).

    The policy is a durable ``surface_deferral_exemption`` decision row whose
    payload lists ``surface_types`` (or ``surface_type``). This is the bounded,
    visible escape valve the doctrine requires — an exemption is an audited
    decision, not a transient ``--force`` flag.
    """
    engagement = _engagement_or_404(engagement_id)
    exempt: set[str] = set()
    with _common.get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0",
            (engagement.id, "surface_deferral_exemption"),
        ).fetchall()
    for row in rows:
        payload = _serialize_decision(row).get("payload") or {}
        if not isinstance(payload, dict):
            continue
        names = payload.get("surface_types")
        if isinstance(names, str):
            names = [names]
        if not isinstance(names, list):
            single = payload.get("surface_type")
            names = [single] if isinstance(single, str) else []
        for name in names:
            if isinstance(name, str) and name.strip():
                exempt.add(name.strip())
    return exempt


def _partial_followup_resolved(surface: dict[str, Any]) -> bool:
    """True when a ``partially-covered`` surface's follow-up is satisfied so it
    should stop blocking (L1-9 accept-partial path).

    Resolution is recorded durably on the surface itself: clearing the
    ``followup_condition`` (the follow-up was met — mirrors the existing
    "covered clears followup_condition" transition in ``update_surface``) marks
    the partial as accepted. An empty ``followup_condition`` on a
    partially-covered surface therefore means "the follow-up obligation is
    resolved" and the surface no longer blocks; a still-present condition keeps
    it as an advisory item.
    """
    return not str(surface.get("followup_condition") or "").strip()


def coverage_readiness(engagement_id: int) -> dict[str, Any]:
    """Surface-coverage readiness for the web/code/blue tracks.

    NOTE (cross-track invariant): this function is shared and NOT
    engagement_type-gated. The CODE track has no surfaces, so ``list_surfaces``
    returns ``[]`` and every bucket below is empty → ``ready=True`` trivially.
    The return SHAPE is load-bearing (``report_readiness`` relays ``ready`` /
    ``blocker_count`` and the surface buckets); keys are preserved. Advisory
    handling only changes WHICH surfaces count toward
    ``blocker_count`` and adds advisory buckets — it never changes the shape.
    """
    # The ledger owns surface persistence. A function-local import keeps the
    # decision module independent from its compatibility import surface.
    from .coverage import list_surfaces

    surfaces = list_surfaces(engagement_id, limit=None)

    if not surfaces:
        return {
            "track": "web",
            "ready": True,
            "blocker_count": 0,
            "unresolved_surfaces": [],
            "partially_covered_surfaces": [],
            "high_risk_deferred_surfaces": [],
            "advisory_surfaces": [],
        }

    active_hosts = _active_finding_hosts(engagement_id)
    exempt_types = _deferral_exempt_surface_types(engagement_id)

    discovered = [row for row in surfaces if row.get("status") == "discovered"]
    partial = [row for row in surfaces if row.get("status") == "partially-covered"]
    deferred_high_risk = [
        row
        for row in surfaces
        if row.get("status") == "deferred"
        and row.get("surface_type") in HIGH_RISK_DEFERRED_SURFACE_TYPES
    ]
    administratively_closed = [
        row
        for row in surfaces
        if row.get("status") == SurfaceStatus.ADMINISTRATIVELY_CLOSED.value
    ]

    unresolved_blocking = [
        row for row in discovered if _surface_is_finding_linked(row, active_hosts)
    ]
    unresolved_advisory = [
        row for row in discovered if not _surface_is_finding_linked(row, active_hosts)
    ]

    partial_blocking: list[dict[str, Any]] = []
    partial_advisory: list[dict[str, Any]] = []
    for row in partial:
        if _partial_followup_resolved(row):
            partial_advisory.append(row)
        elif _surface_is_finding_linked(row, active_hosts):
            partial_blocking.append(row)
        else:
            partial_advisory.append(row)

    deferred_blocking = [
        row
        for row in deferred_high_risk
        if row.get("surface_type") not in exempt_types
    ]
    deferred_advisory = [
        row
        for row in deferred_high_risk
        if row.get("surface_type") in exempt_types
    ]

    blocker_count = (
        len(unresolved_blocking) + len(partial_blocking) + len(deferred_blocking)
    )
    advisory_surfaces = (
        unresolved_advisory
        + partial_advisory
        + deferred_advisory
        + administratively_closed
    )

    return {
        "track": "web",
        "ready": blocker_count == 0,
        "blocker_count": blocker_count,
        "unresolved_surfaces": unresolved_blocking,
        "partially_covered_surfaces": partial_blocking,
        "high_risk_deferred_surfaces": deferred_blocking,
        "advisory_surfaces": advisory_surfaces,
    }

# C40 — outcome-based per-host coverage projection
# The five sub-objectives the recon phase nominally produces per host. None of
# them check `assessment_command_runs` — every signal is a row in an outcome
# table the specialists are already writing to. That is the contract: rename
# wafw00f → wafw00f-ng tomorrow and the gate keeps working as long as the
# tech-component row still gets recorded.


PER_HOST_OBJECTIVES: tuple[str, ...] = (
    "waf_tier",
    "service_inventory",
    "directory_fuzz",
    "tech_fingerprint",
    "osint",
)

# WAF families operators classify hosts into. Matched case-insensitively as a
# substring of the `component` field on `intel_tech_components`. Extending this
# tuple (e.g., new CDN entrant) is the canonical drift-prone seam — keep it
# small and additive.
_WAF_FAMILY_TOKENS: tuple[str, ...] = (
    "cloudflare",
    "akamai",
    "f5",
    "aws waf",
    "awswaf",
    "imperva",
    "fastly",
    "incapsula",
    "sucuri",
    "cloudfront",
    "azure front door",
    "barracuda",
)

# Tokens that suggest a tech-component row came from a "nikto-equivalent"
# scanner (whatweb, httpx -tech-detect, wappalyzer, nuclei tech templates,
# nmap http-* scripts, nikto itself). We do NOT hardcode tool names in the
# CLI side of the gate — this list is the BACKEND'S read-only interpretation
# of "scanner that produced a tech fingerprint". Operators recording intel
# manually still satisfy the gate because they set `source_name` to their
# agent identity.
_TECH_SCAN_SOURCE_TOKENS: tuple[str, ...] = (
    "whatweb",
    "httpx",
    "wappalyzer",
    "nuclei",
    "nikto",
    "nmap",
    "recon-specialist",
    "wafw00f",
    "wafw0of",
    "source-analyzer",
    "operator",
)

_NON_LIVE_SERVICE_STATES_FOR_INVENTORY: frozenset[str] = frozenset(
    {"down", "filtered", "unreachable"}
)

def _coverage_endpoint_host(endpoint: str) -> str:
    """Lowercased host portion of a service endpoint or surface descriptor.

    Mirrors `_endpoint_host` in `lib/coverage_checks.py` but the CLI version
    cannot be imported here. Keep the two in sync — they extract the same
    host string from the same shapes (bare host, host:port, full URL).
    """
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    first = raw.split()[0]
    if "://" in first:
        parsed = urlparse(first)
        return (parsed.hostname or "").strip("[]")
    # Strip leading/trailing wrappers and trailing punctuation.
    stripped = first.strip("'\"<>()").rstrip(",;").rstrip(".")
    if stripped.startswith("[") and "]" in stripped:
        # Bracketed IPv6 with optional :port suffix.
        host = stripped[1 : stripped.find("]")]
        return host
    if stripped.count(":") >= 2:
        # IPv6 literal without brackets (e.g., 2001:db8::1 or 2001:db8::1:443).
        # Splitting on rpartition risks chopping the address; only strip a
        # trailing port if the suffix is purely numeric AND the prefix parses
        # as an IPv6 address.
        host, _, port = stripped.rpartition(":")
        if port.isdigit():
            try:
                import ipaddress

                ipaddress.ip_address(host)
                return host
            except ValueError:
                return stripped
        return stripped
    host, _, port = stripped.rpartition(":")
    if port.isdigit() and host:
        return host
    return stripped

def _string_contains_host(haystack: str, host: str) -> bool:
    """True when `host` appears as a token in `haystack` (case-insensitive).

    Avoids substring false positives like "evil.target.example" matching
    "target.example" — we require the match to be on a word boundary so
    `notes='banner=cf-cf'` does not falsely satisfy `host='cf'`.
    """
    if not haystack or not host:
        return False
    lower_hay = haystack.lower()
    lower_host = host.lower()
    if lower_host not in lower_hay:
        return False
    idx = 0
    while True:
        pos = lower_hay.find(lower_host, idx)
        if pos == -1:
            return False
        left_ok = pos == 0 or not (lower_hay[pos - 1].isalnum() or lower_hay[pos - 1] in ".-")
        end = pos + len(lower_host)
        right_ok = end == len(lower_hay) or not (
            lower_hay[end].isalnum() or lower_hay[end] in ".-"
        )
        if left_ok and right_ok:
            return True
        idx = pos + 1

def _intel_row_references_host(row: dict[str, Any], host: str) -> bool:
    """True when an intel row's evidence/notes/provenance mentions the host."""
    if not host:
        return False
    for key in ("evidence_ref", "notes", "source_name"):
        if _string_contains_host(str(row.get(key, "") or ""), host):
            return True
    raw_provenance = row.get("provenance_json", row.get("provenance"))
    provenance: Any = raw_provenance
    if isinstance(raw_provenance, str) and raw_provenance:
        try:
            provenance = json.loads(raw_provenance)
        except (ValueError, TypeError):
            return _string_contains_host(raw_provenance, host)
    if isinstance(provenance, dict):
        for k in ("host", "target", "url", "endpoint"):
            val = provenance.get(k)
            if isinstance(val, str) and _string_contains_host(val, host):
                return True
        return _string_contains_host(json.dumps(provenance, ensure_ascii=False), host)
    return False

def _row_is_waf_classification(row: dict[str, Any]) -> bool:
    component = str(row.get("component", "") or "").lower()
    if not component:
        return False
    for token in _WAF_FAMILY_TOKENS:
        if token in component:
            return True
    return False

def _row_is_tech_scan_evidence(row: dict[str, Any]) -> bool:
    """True when a tech-component row plausibly came from a 'nikto-equivalent'
    scanner — i.e., any active fingerprinting tool or operator recording."""
    source = str(row.get("source_name", "") or "").lower()
    if not source:
        # An empty source_name is still a tech-component row that records a
        # real classification — count it as satisfying the trigger.
        return True
    for token in _TECH_SCAN_SOURCE_TOKENS:
        if token in source:
            return True
    return False

def _coverage_deferral_payload_hosts(payload: dict[str, Any]) -> list[str]:
    """Return host strings referenced by a coverage_deferral decision payload.

    Normalizes each value through ``_coverage_endpoint_host`` so URL or
    host:port shapes (``https://api.example.com/v1``, ``api.example.com:8443``)
    collapse to the same bare-hostname key used by ``services_by_host`` /
    ``surfaces_by_host``. Without this, an operator-recorded deferral with a
    URL value silently fails to match and the gate stays unmet.
    """
    candidates: list[str] = []
    for key in ("host", "target", "hostname"):
        val = payload.get(key)
        if isinstance(val, str) and val.strip():
            normalized = _coverage_endpoint_host(val) or val.strip().lower()
            candidates.append(normalized)
    hosts_field = payload.get("hosts")
    if isinstance(hosts_field, list):
        for entry in hosts_field:
            if isinstance(entry, str) and entry.strip():
                normalized = _coverage_endpoint_host(entry) or entry.strip().lower()
                candidates.append(normalized)
    return candidates

def _coverage_deferral_objectives(payload: dict[str, Any]) -> list[str]:
    raw = payload.get("deferred_objectives")
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out

def _active_coverage_deferrals(engagement_id: int) -> list[dict[str, Any]]:
    """Return every active (``resolved=0``) coverage_deferral decision row
    for the engagement, ordered newest-first.

    Reads directly through ``get_connection`` to avoid the public
    ``list_decisions`` endpoint's ``limit`` cap — large wildcard engagements
    can legitimately accumulate thousands of operator-approved deferrals,
    and a silent truncation would let objectives reappear as unmet in the
    per-host gate.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "coverage_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]

def _active_coverage_completeness_deferrals(engagement_id: int) -> list[dict[str, Any]]:
    """Active (``resolved=0``) ``coverage_completeness_deferral`` decision rows,
    newest-first.

    W3 override reader — mirrors :func:`_active_coverage_deferrals` (same direct
    ``get_connection`` read to dodge the ``list_decisions`` ``limit`` cap) but
    for the report-time completeness escape. The decision is recorded free-form
    via ``vigil assess agent decision --kind coverage_completeness_deferral``;
    its payload is ``{host, reason}`` (or aliases ``hosts``/``target``/
    ``hostname``) for a per-host carve-out, or ``{engagement_wide: true}`` to
    accept residual uncovered hosts program-wide at the report boundary.
    """
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "coverage_completeness_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]

def _completeness_deferral_index(
    rows: list[dict[str, Any]],
) -> tuple[set[str], bool]:
    """Split completeness-deferral rows into ``(deferred_hosts, engagement_wide)``.

    A row tagged ``engagement_wide=true`` clears EVERY uncovered host; otherwise
    the payload's host fields (normalized through ``_coverage_deferral_payload_hosts``
    so URL / host:port shapes collapse to the bare-host key) name the hosts it
    clears.
    """
    deferred_hosts: set[str] = set()
    engagement_wide = False
    for row in rows:
        payload = row.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if payload.get("engagement_wide") is True:
            engagement_wide = True
            continue
        for host in _coverage_deferral_payload_hosts(payload):
            deferred_hosts.add(host)
    return deferred_hosts, engagement_wide

def _coverage_engagement_wide_deferrals(
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return active deferral rows tagged ``engagement_wide=true``.

    These apply to EVERY host with signal — operators use them for objectives
    that are not host-scoped (e.g., "OSINT is out of scope for this whole
    engagement"). Validated at POST time to be mutually exclusive with host
    fields, so a row is either engagement-wide or per-host but not both.
    """
    out: list[dict[str, Any]] = []
    for row in rows:
        payload = row.get("payload") or {}
        if isinstance(payload, dict) and payload.get("engagement_wide") is True:
            out.append(row)
    return out

def _empty_finding_verdict() -> dict[str, Any]:
    """The "no verdict on this host" cell. Stable shape so the CLI ledger never
    has to special-case a missing key."""
    return {
        "has_finding": False,
        "finding_count": 0,
        "verified_count": 0,
        "strongest_status": None,
        "max_severity": None,
        "auth_contexts": [],
        "verification_statuses": [],
        "slugs": [],
    }


def _build_finding_verdicts_by_host(
    finding_rows: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Project finding rows into ``{host: verdict}``.

    A ``merged`` finding (or one with a ``merged_into_finding_id``) is excluded —
    it is no longer the canonical record. Every other finding counts as a
    RECORDED VERDICT for its host (a ``false_positive`` finding is the canonical
    evidence-backed negative: "we tested it, here is why it is not a bug").
    Host is taken from ``canonical_location`` via the same normalizer used for
    services/surfaces so the ledger join lands on one key. The ``slugs`` list is
    capped to keep the payload bounded on noisy hosts.
    """
    by_host: dict[str, dict[str, Any]] = {}
    for row in finding_rows:
        if row.get("merged_into_finding_id") is not None:
            continue
        try:
            status_value = _normalize_workflow_status(str(row.get("status") or "draft"))
        except HTTPException:
            status_value = "draft"  # tolerate a legacy/invalid status on read
        if status_value == "merged":
            continue
        host = _coverage_endpoint_host(str(row.get("canonical_location") or ""))
        if not host:
            continue
        verdict = by_host.setdefault(host, _empty_finding_verdict())
        verdict["has_finding"] = True
        verdict["finding_count"] += 1

        try:
            verification_status = str(
                _normalize_verification_status(
                    str(row.get("verification_status") or "unreviewed")
                )
            )
        except HTTPException:
            verification_status = "unreviewed"
        if verification_status not in {"unreviewed", "disputed"}:
            verdict["verified_count"] += 1
        if verification_status not in verdict["verification_statuses"]:
            verdict["verification_statuses"].append(verification_status)

        severity = _normalize_severity(str(row.get("severity") or "info"))
        if verdict["max_severity"] is None or (
            SEVERITY_RANK[severity] > SEVERITY_RANK[verdict["max_severity"]]
        ):
            verdict["max_severity"] = severity

        current_strongest = verdict["strongest_status"]
        if current_strongest is None or (
            WORKFLOW_STATUS_RANK[status_value] > WORKFLOW_STATUS_RANK[current_strongest]
        ):
            verdict["strongest_status"] = str(status_value)

        auth_context = str(row.get("auth_context") or "").strip()
        if auth_context and auth_context not in verdict["auth_contexts"]:
            verdict["auth_contexts"].append(auth_context)

        slug = str(row.get("slug") or "").strip()
        if slug and len(verdict["slugs"]) < 25 and slug not in verdict["slugs"]:
            verdict["slugs"].append(slug)

    for verdict in by_host.values():
        verdict["auth_contexts"].sort()
        verdict["verification_statuses"].sort()
        verdict["slugs"].sort()
    return by_host


def per_host_coverage(engagement_id: int) -> dict[str, Any]:
    """Outcome-based per-host coverage projection (C40).

    Five sub-objectives per host, each evaluated against an outcome table:

    1. ``waf_tier`` — an ``intel_tech_components`` row whose ``component`` matches
       a known WAF family. Engagement-level WAF intel (no host evidence in
       evidence_ref/notes/provenance) counts for every host: CDN-class WAFs
       typically sit in front of an entire property, and demanding per-host
       evidence would produce false negatives that don't reflect operator
       reality.
    2. ``service_inventory`` — at least one ``assessment_services`` row in a live
       state for the host, OR at least one ``assessment_surfaces`` row.
    3. ``directory_fuzz`` — at least one ``assessment_surfaces`` row for the host.
       Specialists running ffuf / feroxbuster / dirsearch record their
       findings as surfaces (via ``record-surface``) so the gate cares about
       the surface row, not the binary that produced it.
    4. ``tech_fingerprint`` — at least one ``intel_tech_components`` row whose
       ``source_name`` plausibly came from a fingerprinting scanner (whatweb,
       httpx, wappalyzer, nuclei, nmap, nikto, recon-specialist, etc.). The
       trigger is "did fingerprinting happen", which the operator can satisfy
       with any of those tools — or by recording the row manually.
    5. ``osint`` — engagement-level. ≥1 row in any of ``intel_tech_components``,
       ``intel_people``, or ``intel_breach_records`` proves OSINT happened.
       OSINT is not naturally host-keyed (people, breach corpora, org facts
       are organization-level), so this objective is the same answer for
       every host in the engagement.

    A host with an active ``coverage_deferral`` decision row whose payload
    lists an objective passes that objective regardless of the underlying
    signal. The deferral is the operator's explicit "we decided not to do
    this for this host" record; the gate trusts it.

    NOTE: this function deliberately does NOT consult
    ``assessment_command_runs``. The whole point of the C40 reframe is that
    the gate reads outcomes, not tool runs. Adding a `command-runs` join
    here is the regression we're trying to prevent — `test_check_scope_coverage`
    asserts the CLI does not query it.
    """
    engagement = _engagement_or_404(engagement_id)
    eng_id = engagement.id

    with _common.get_connection() as connection:
        services = _fetch_all(
            connection,
            "SELECT endpoint, state FROM assessment_services WHERE engagement_id = ?",
            (eng_id,),
        )
        surfaces = _fetch_all(
            connection,
            "SELECT surface_type, target_descriptor, status FROM assessment_surfaces "
            "WHERE engagement_id = ?",
            (eng_id,),
        )
        tech_components = _fetch_all(
            connection,
            "SELECT component, version, source_name, evidence_ref, notes, "
            "provenance_json, superseded_by_id "
            "FROM intel_tech_components WHERE engagement_id = ?",
            (eng_id,),
        )
        people_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM intel_people WHERE engagement_id = ? "
            "AND superseded_by_id IS NULL",
            (eng_id,),
        )
        breach_count = _scalar_row(
            connection,
            "SELECT COUNT(*) FROM intel_breach_records WHERE engagement_id = ? "
            "AND superseded_by_id IS NULL",
            (eng_id,),
        )
        finding_rows = _fetch_all(
            connection,
            "SELECT slug, canonical_location, status, verification_status, "
            "severity, auth_context, merged_into_finding_id "
            "FROM assessment_findings WHERE engagement_id = ?",
            (eng_id,),
        )

    # W2 — per-host finding VERDICT join. A host is only "covered" with a
    # RECORDED VERDICT; this map is what the coverage ledger reads to tell a
    # real_app gap (routes but no verdict) from a closed one. Keyed by the same
    # ``_coverage_endpoint_host`` normalization as services/surfaces so the join
    # lands on one host key. Includes finding-only hosts (a host with a finding
    # but no recon service/surface) so a crown-jewel verdict is never dropped.
    finding_verdicts_by_host = _build_finding_verdicts_by_host(finding_rows)

    # Filter out superseded tech-component rows from outcome consideration —
    # the current row is the canonical answer.
    live_tech_components = [
        row for row in tech_components if row.get("superseded_by_id") is None
    ]

    # Discover every host the engagement actually has signal for.
    hosts: set[str] = set()
    services_by_host: dict[str, list[dict[str, Any]]] = {}
    surfaces_by_host: dict[str, list[dict[str, Any]]] = {}
    for row in services:
        host = _coverage_endpoint_host(str(row.get("endpoint") or ""))
        if not host:
            continue
        hosts.add(host)
        services_by_host.setdefault(host, []).append(row)
    for row in surfaces:
        host = _coverage_endpoint_host(str(row.get("target_descriptor") or ""))
        if not host:
            continue
        hosts.add(host)
        surfaces_by_host.setdefault(host, []).append(row)

    all_deferral_rows = _active_coverage_deferrals(eng_id)
    deferrals_by_host: dict[str, list[dict[str, Any]]] = {}
    for row in all_deferral_rows:
        payload = row.get("payload") or {}
        if not isinstance(payload, dict):
            continue
        if payload.get("engagement_wide") is True:
            continue  # handled below — applies to every host with signal
        row_hosts = _coverage_deferral_payload_hosts(payload)
        if not row_hosts:
            continue
        for host in row_hosts:
            deferrals_by_host.setdefault(host, []).append(row)
    for host in deferrals_by_host.keys():
        hosts.add(host)

    engagement_wide_deferral_rows = _coverage_engagement_wide_deferrals(all_deferral_rows)
    engagement_wide_deferred_objectives: set[str] = set()
    for row in engagement_wide_deferral_rows:
        for obj in _coverage_deferral_objectives(row.get("payload") or {}):
            engagement_wide_deferred_objectives.add(obj)

    # Engagement-level signals (apply to every host).
    osint_met = (
        len(live_tech_components) > 0 or people_count > 0 or breach_count > 0
    )
    osint_evidence: list[str] = []
    if live_tech_components:
        osint_evidence.append(f"tech_components:{len(live_tech_components)}")
    if people_count:
        osint_evidence.append(f"people:{int(people_count)}")
    if breach_count:
        osint_evidence.append(f"breach_records:{int(breach_count)}")

    waf_rows = [row for row in live_tech_components if _row_is_waf_classification(row)]
    engagement_has_waf_intel = bool(waf_rows)

    tech_fingerprint_rows = [row for row in live_tech_components if _row_is_tech_scan_evidence(row)]
    engagement_has_tech_fingerprint = bool(tech_fingerprint_rows)

    host_outcomes: list[dict[str, Any]] = []
    for host in sorted(hosts):
        host_services = services_by_host.get(host, [])
        host_surfaces = surfaces_by_host.get(host, [])

        # waf_tier — engagement-level WAF intel is sufficient; per-host
        # specificity is a tighter signal when the evidence_ref/notes
        # mention the host.
        waf_host_specific = any(_intel_row_references_host(row, host) for row in waf_rows)
        waf_met = waf_host_specific or engagement_has_waf_intel
        waf_evidence: list[str] = []
        for row in waf_rows:
            label = str(row.get("component") or "").strip()
            if not label:
                continue
            host_specific = _intel_row_references_host(row, host)
            waf_evidence.append(f"{label}{'(host)' if host_specific else ''}")

        # service_inventory — live service or surface row for the host
        live_services = [
            row
            for row in host_services
            if str(row.get("state") or "").lower() not in _NON_LIVE_SERVICE_STATES_FOR_INVENTORY
        ]
        service_met = bool(live_services) or bool(host_surfaces)
        service_evidence: list[str] = []
        if live_services:
            service_evidence.append(f"services:{len(live_services)}")
        if host_surfaces:
            service_evidence.append(f"surfaces:{len(host_surfaces)}")

        # directory_fuzz — surface presence proves URL-level discovery.
        # Backend cannot see the local cases.db `work_items` count, so the
        # CLI layer (`--by-host`) may upgrade this outcome based on the
        # local work-buffer rollup. From the backend's perspective a
        # surface is the durable proof.
        dirfuzz_met = bool(host_surfaces)
        dirfuzz_evidence: list[str] = []
        if host_surfaces:
            dirfuzz_evidence.append(f"surfaces:{len(host_surfaces)}")

        # tech_fingerprint — any fingerprinting-equivalent intel row, host-specific
        # preferred but engagement-level acceptable.
        tech_fingerprint_host_specific = any(
            _intel_row_references_host(row, host) for row in tech_fingerprint_rows
        )
        tech_fingerprint_met = tech_fingerprint_host_specific or engagement_has_tech_fingerprint
        tech_fingerprint_evidence: list[str] = []
        for row in tech_fingerprint_rows:
            label = str(row.get("source_name") or "").strip() or "unknown"
            host_specific = _intel_row_references_host(row, host)
            tech_fingerprint_evidence.append(f"{label}{'(host)' if host_specific else ''}")
            if len(tech_fingerprint_evidence) >= 5:
                break

        deferral_rows = deferrals_by_host.get(host, [])
        deferred_objectives: set[str] = set(engagement_wide_deferred_objectives)
        for row in deferral_rows:
            for obj in _coverage_deferral_objectives(row.get("payload") or {}):
                deferred_objectives.add(obj)
        # Surface engagement-wide rows in the per-host audit list too so
        # operators can see WHY an objective is marked deferred for this host.
        deferral_rows = deferral_rows + engagement_wide_deferral_rows

        outcomes: dict[str, dict[str, Any]] = {
            "waf_tier": {
                "met": waf_met,
                "evidence": waf_evidence,
                "deferred": "waf_tier" in deferred_objectives,
            },
            "service_inventory": {
                "met": service_met,
                "evidence": service_evidence,
                "deferred": "service_inventory" in deferred_objectives,
            },
            "directory_fuzz": {
                "met": dirfuzz_met,
                "evidence": dirfuzz_evidence,
                "deferred": "directory_fuzz" in deferred_objectives,
            },
            "tech_fingerprint": {
                "met": tech_fingerprint_met,
                "evidence": tech_fingerprint_evidence,
                "deferred": "tech_fingerprint" in deferred_objectives,
            },
            "osint": {
                "met": osint_met,
                "evidence": osint_evidence,
                "deferred": "osint" in deferred_objectives,
            },
        }

        unmet = [
            name
            for name, info in outcomes.items()
            if not info["met"] and not info["deferred"]
        ]

        host_outcomes.append(
            {
                "host": host,
                "outcomes": outcomes,
                "unmet_objectives": unmet,
                "deferred_objectives": sorted(deferred_objectives),
                "deferrals": [
                    {
                        "id": int(row.get("id", 0)),
                        "kind": str(row.get("kind", "") or ""),
                        "payload": row.get("payload") or {},
                        "created_at": row.get("created_at"),
                    }
                    for row in deferral_rows
                ],
                "finding_verdict": finding_verdicts_by_host.get(
                    host, _empty_finding_verdict()
                ),
            }
        )

    return {
        "objectives": list(PER_HOST_OBJECTIVES),
        "hosts": host_outcomes,
        # Superset of the per-host inline verdict: also carries finding-only
        # hosts (no recon service/surface) so the ledger never loses a verdict.
        "finding_verdicts": finding_verdicts_by_host,
        "engagement_signals": {
            "waf_intel_count": len(waf_rows),
            "tech_scan_intel_count": len(tech_fingerprint_rows),
            "osint_intel_total": len(live_tech_components) + int(people_count) + int(breach_count),
        },
    }
