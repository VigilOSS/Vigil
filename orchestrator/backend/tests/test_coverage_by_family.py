"""A1 — engagement-wide (application-unit × vuln-family) coverage grid.

Covers ``by_family_coverage`` (state_manager.depth_ledger) via the
``GET /engagements/{key}/assessment/coverage-readiness/by-family`` route.

The grid walks EVERY application unit (deep_required or not) and, for each,
emits one cell per vuln family in ``union(expected, probed)`` so an operator can
tell a never-probed gap (missing_* + covering_probe_count 0) from a
probed-and-walled family (probe_count > 0, covering 0) from a finding-linked one
(has_finding). These tests seed units + variants + probes + a linked finding on
real fixtures and assert the pinned response shape + totals.
"""
from __future__ import annotations

from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-07-09-100000-byfamily"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"

DEEP_HOST = "app.example.com"
THIN_HOST = "thin.example.com"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _insert_unit(eng_id: int, *, host: str, path_prefix: str, deep_required: int) -> None:
    with state_manager.get_connection() as connection:
        connection.execute(
            "INSERT INTO assessment_application_units "
            "(engagement_id, host, port_class, path_prefix, deep_required) "
            "VALUES (?, ?, 'web', ?, ?)",
            (eng_id, host, path_prefix, deep_required),
        )


def _variant(eng_id: int, *, url: str, query: dict | None = None) -> None:
    state_manager.record_request_variant(
        eng_id, url=url, method="GET", auth_context="anonymous",
        content_type_family="json", query_schema=query or {}, body_schema={},
        path_schema={}, cookie_schema={}, header_schema={}, path_template="",
        discovery_source="proxy", notes="", response_status=200,
        evidence_ref="", observation_payload={},
    )


def _probe(eng_id: int, *, attack_family: str, result_status: str,
           target_path: str, tool_name: str = "curl",
           target_host: str = DEEP_HOST, finding_id: int | None = None,
           auth_context: str = "anonymous") -> None:
    state_manager.record_probe_run(
        eng_id, request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context=auth_context, input_slot="query", attack_family=attack_family,
        payload_family="", payload_value=f"{attack_family}:{target_path}",
        tool_name=tool_name, agent_name="va-1", result_status=result_status,
        observed_http_status=None, signal_type="", evidence_ref="", notes="",
        target_host=target_host, target_path=target_path, target_port=443,
        finding_id=finding_id,
    )


def _object_reference_surface(eng_id: int, *, descriptor: str) -> None:
    """Record an object_reference surface so access-control (BLOCK_HIGH) becomes
    an EXPECTED family for the unit it is contained by."""
    state_manager.record_surface(
        eng_id, surface_type="object_reference", target_descriptor=descriptor,
        source_name="recon-specialist", rationale="live endpoint",
        evidence_ref="", status_value="discovered",
    )


def _eng_id(client) -> int:
    return int(client.get(f"/engagements/{ENGAGEMENT_KEY}").json()["id"])


def _create_finding(client, slug: str) -> int:
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": "SQLi in /api/items search parameter",
            "severity": "high",
            "workflow_status": "active",
            "defect_family": "injection",
            "root_cause_key": "unparameterized-query",
            "auth_context": "anonymous",
            "canonical_location": f"https://{DEEP_HOST}/api/items",
            "summary": "SQL injection",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Replayable request.", "impact": "DB read."},
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["finding"]["id"])


def _create_finding_distinct(client, slug: str, *, root_cause_key: str,
                             canonical_location: str) -> int:
    """Create a finding with a DISTINCT dedup tuple (root_cause_key +
    canonical_location) so two findings can coexist without a dedup clobber."""
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": f"SQLi at {canonical_location}",
            "severity": "high",
            "workflow_status": "active",
            "defect_family": "injection",
            "root_cause_key": root_cause_key,
            "auth_context": "anonymous",
            "canonical_location": canonical_location,
            "summary": "SQL injection",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Replayable request.", "impact": "DB read."},
        },
    )
    assert response.status_code == 201, response.text
    return int(response.json()["finding"]["id"])


def _families(unit_row: dict) -> dict[str, dict]:
    return {cell["family"]: cell for cell in unit_row["families"]}


def _by_unit(body: dict) -> dict[str, dict]:
    return {row["host"]: row for row in body["units"]}


def _seed_grid(client, isolate_settings) -> int:
    eng_id = _seed(client, isolate_settings)
    # A deep_required unit with a param-bearing variant (expects injection +
    # client-side + disclosure) and a NON-deep unit that must still appear.
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    _insert_unit(eng_id, host=THIN_HOST, path_prefix="/", deep_required=0)
    _variant(eng_id, url=f"https://{DEEP_HOST}/api/items", query={"search": "string"})

    finding_id = _create_finding(client, "VA-001")
    # Covering injection probe carrying the finding linkage.
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_path="/api/items", tool_name="sqlmap", finding_id=finding_id)
    # Probed-and-walled client-side family (non-covering result).
    _probe(eng_id, attack_family="xss", result_status="blocked",
           target_path="/api/items", tool_name="xsstrike")
    return finding_id


def test_by_family_grid_shape_and_statuses(client, isolate_settings):
    finding_id = _seed_grid(client, isolate_settings)

    response = client.get(f"{BASE}/coverage-readiness/by-family")
    assert response.status_code == 200, response.text
    body = response.json()

    units = _by_unit(body)
    assert set(units) == {DEEP_HOST, THIN_HOST}

    deep = units[DEEP_HOST]
    assert deep["deep_required"] is True
    fams = _families(deep)
    assert set(fams) == {"injection", "client-side", "disclosure"}

    # A covered family: covering probe present, finding linked.
    injection = fams["injection"]
    assert injection["status"] == "covered"
    assert injection["covering_probe_count"] > 0
    assert injection["probe_count"] == 1
    assert injection["has_finding"] is True
    assert injection["finding_id"] == finding_id
    assert injection["expected_reason"] is not None

    # An expected-but-unprobed family: missing, no probes, no finding.
    disclosure = fams["disclosure"]
    assert disclosure["status"].startswith("missing")
    assert disclosure["covering_probe_count"] == 0
    assert disclosure["probe_count"] == 0
    assert disclosure["has_finding"] is False
    assert disclosure["finding_id"] is None

    # A probed-and-walled family: probed but no covering result → still missing.
    client_side = fams["client-side"]
    assert client_side["status"] == "missing_warn"
    assert client_side["probe_count"] == 1
    assert client_side["covering_probe_count"] == 0
    assert client_side["has_finding"] is False


def test_by_family_non_deep_unit_appears_in_grid(client, isolate_settings):
    _seed_grid(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    units = _by_unit(body)
    # The deep_required=0 unit is NOT dropped (unlike the depth ledger, which
    # only scores deep_required units).
    assert THIN_HOST in units
    thin = units[THIN_HOST]
    assert thin["deep_required"] is False
    # disclosure is expected for every unit; it is uncovered/never-probed here.
    thin_fams = _families(thin)
    assert "disclosure" in thin_fams
    assert thin_fams["disclosure"]["status"].startswith("missing")


def test_by_family_totals_are_accurate(client, isolate_settings):
    _seed_grid(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    totals = body["totals"]

    assert totals["units"] == 2
    # deep: injection + client-side + disclosure (3); thin: disclosure (1).
    assert totals["cells"] == 4
    assert totals["covered"] == 1              # injection
    assert totals["missing_block"] == 0
    assert totals["missing_warn"] == 3         # client-side + 2x disclosure
    assert totals["deferred"] == 0
    assert totals["with_finding"] == 1         # injection cell

    # covered + missing_block + missing_warn + deferred partitions every cell.
    partition = (
        totals["covered"] + totals["missing_block"]
        + totals["missing_warn"] + totals["deferred"]
    )
    assert partition == totals["cells"]


def test_by_family_active_deferral_marks_cell_deferred(client, isolate_settings):
    """An active depth_deferral covering an expected-but-uncovered family flips
    that cell from missing_* to ``deferred`` (same classification the depth
    ledger uses); covered families are unaffected (covered wins over deferred)."""
    _seed_grid(client, isolate_settings)
    # client-side (xss) is expected + probed-but-walled on the deep unit; defer it.
    resp = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": DEEP_HOST,
                "path_prefix": "/api",
                "vuln_classes": ["xss"],
                "reason": "client-side deferred to next sprint; documented risk",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    fams = _families(_by_unit(body)[DEEP_HOST])
    assert fams["client-side"]["status"] == "deferred"
    # injection stays covered (covered precedence), disclosure stays missing.
    assert fams["injection"]["status"] == "covered"
    assert fams["disclosure"]["status"].startswith("missing")
    assert body["totals"]["deferred"] == 1
    assert body["totals"]["missing_warn"] == 2  # was 3; client-side moved to deferred


def test_by_family_empty_engagement_returns_zero_grid(client, isolate_settings):
    _seed(client, isolate_settings)
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    assert body["units"] == []
    assert body["totals"] == {
        "units": 0, "cells": 0, "covered": 0, "missing_block": 0,
        "missing_warn": 0, "deferred": 0, "with_finding": 0,
    }


def test_by_family_uncovered_access_control_is_missing_block(client, isolate_settings):
    """An object_reference surface makes access-control (BLOCK_HIGH) EXPECTED. With
    no covering access-control probe the cell is ``missing_block`` (the BLOCK_HIGH
    arm of the cell classifier). No other test produces a missing_block cell, so
    this is the sole guard on that branch and the ``totals["missing_block"]`` tally.

    Non-vacuous: if the classifier mislabeled an uncovered BLOCK_HIGH family as
    ``missing_warn`` (or dropped the block-level map), ``status`` would read
    ``missing_warn`` and both asserts below flip."""
    _seed_grid(client, isolate_settings)
    _object_reference_surface(_eng_id(client), descriptor=f"{DEEP_HOST} /api/items")

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    fams = _families(_by_unit(body)[DEEP_HOST])
    ac = fams["access-control"]
    assert ac["status"] == "missing_block"
    assert ac["expected_reason"] == "object_reference surface"
    assert ac["covering_probe_count"] == 0
    # injection is covered (sqli probe) so it is NOT a block-gap; access-control is
    # the only missing_block cell in the whole grid.
    assert body["totals"]["missing_block"] == 1


def test_by_family_access_control_needs_two_identities(client, isolate_settings):
    """Access-control is a SPECIAL case: covered iff >=2 distinct auth_context
    identities probed it, NOT merely ``fam in covered_families``. A single-identity
    ``idor``/``tested`` probe IS a covering probe (covering_probe_count == 1) yet
    the cell stays ``missing_block``; a second probe under a DIFFERENT identity
    flips it to ``covered``.

    Non-vacuous: a regression to the generic ``fam in covered_families`` fallback
    would mark the single-identity case ``covered`` (idor tested is in
    covered_families), flipping the first block of asserts."""
    eng_id = _seed(client, isolate_settings)
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    _variant(eng_id, url=f"https://{DEEP_HOST}/api/items", query={"search": "string"})
    _object_reference_surface(eng_id, descriptor=f"{DEEP_HOST} /api/items")

    # ONE idor probe under a single identity — a covering probe, but not >=2 ids.
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_path="/api/items", tool_name="idor-fuzzer", auth_context="user_a")
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    ac = _families(_by_unit(body)[DEEP_HOST])["access-control"]
    assert ac["status"] == "missing_block"
    assert ac["probe_count"] == 1
    assert ac["covering_probe_count"] == 1  # it IS covering, just single-identity

    # SECOND idor probe under a DIFFERENT identity → >=2 identities → covered.
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_path="/api/items", tool_name="idor-fuzzer", auth_context="user_b")
    body2 = client.get(f"{BASE}/coverage-readiness/by-family").json()
    ac2 = _families(_by_unit(body2)[DEEP_HOST])["access-control"]
    assert ac2["status"] == "covered"
    assert ac2["probe_count"] == 2


def test_by_family_probed_but_unexpected_family_appears_via_union(client, isolate_settings):
    """Each unit emits one cell per family in ``union(expected, probed)``. An
    ``ssrf`` probe on a unit that does NOT expect ssrf (no url/redirect param, no
    webhook path) must still surface a cell — via the PROBED arm — with
    ``expected_reason is None`` (it was not expected) and ``probe_count == 1``.

    Non-vacuous: today every probed family is also expected, so the union arm is
    never exercised. If the grid iterated ``expected.keys()`` only, ``ssrf`` would
    be absent and ``"ssrf" in fams`` fails; ``expected_reason is None`` confirms it
    arrived via the probed arm, not the expected arm."""
    eng_id = _seed(client, isolate_settings)
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    _variant(eng_id, url=f"https://{DEEP_HOST}/api/items", query={"search": "string"})
    _probe(eng_id, attack_family="ssrf", result_status="tested",
           target_path="/api/items", tool_name="ssrf-probe")

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    fams = _families(_by_unit(body)[DEEP_HOST])
    assert "ssrf" in fams
    ssrf = fams["ssrf"]
    assert ssrf["expected_reason"] is None
    assert ssrf["probe_count"] == 1
    # sanity: an expected family still carries a reason (union's expected arm works).
    assert fams["injection"]["expected_reason"] is not None


def test_by_family_grid_agrees_with_depth_ledger(client, isolate_settings):
    """Cross-consistency guard for the shared ``_expected_families`` /
    ``_covered_families_for_unit`` helpers: on ONE fixture, every family the depth
    ledger marks COVERED must be ``covered`` in the grid, and every family the
    ledger marks a BLOCK-GAP (missing_block) must be ``missing_block`` in the grid.

    Fixture covers access-control (two-identity idor) and leaves injection an
    uncovered BLOCK_HIGH gap, so BOTH arms are non-empty (asserted), and any drift
    between the two projections' classification flips a per-family assert."""
    eng_id = _seed(client, isolate_settings)
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    _variant(eng_id, url=f"https://{DEEP_HOST}/api/items", query={"search": "string"})
    _object_reference_surface(eng_id, descriptor=f"{DEEP_HOST} /api/items")
    # access-control covered by two-identity idor; injection left as a block-gap.
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_path="/api/items", tool_name="idor-fuzzer", auth_context="user_a")
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_path="/api/items", tool_name="idor-fuzzer", auth_context="user_b")

    ledger = state_manager.depth_ledger(eng_id)
    assert ledger["skipped"] is False
    ledger_unit = next(
        u for u in ledger["units"]
        if u["unit"]["host"] == DEEP_HOST and u["unit"]["path_prefix"] == "/api"
    )
    ledger_covered = {e["family"] for e in ledger_unit["covered"]}
    ledger_block_gap = {e["family"] for e in ledger_unit["missing_block"]}

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    grid_fams = _families(_by_unit(body)[DEEP_HOST])

    for fam in ledger_covered:
        assert grid_fams[fam]["status"] == "covered", (fam, grid_fams[fam])
    for fam in ledger_block_gap:
        assert grid_fams[fam]["status"] == "missing_block", (fam, grid_fams[fam])

    # Guard the fixture actually exercises BOTH arms (else the loops are vacuous).
    assert "access-control" in ledger_covered
    assert "injection" in ledger_block_gap


def test_by_family_covered_family_wins_over_deferral(client, isolate_settings):
    """Covered PRECEDES deferred in the cell classifier. A depth_deferral naming a
    family that IS already covered (``sqli`` → injection, covered by the seed's
    sqlmap probe) must leave the cell ``covered``, NOT ``deferred``.

    Non-vacuous: the existing deferral test defers an UNCOVERED family, so the
    covered-vs-deferred precedence is never exercised. If the classifier checked
    ``deferred`` before ``covered``, injection would read ``deferred`` and the
    ``deferred``/``covered`` totals below flip."""
    _seed_grid(client, isolate_settings)
    resp = client.post(
        f"/engagements/{ENGAGEMENT_KEY}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": DEEP_HOST,
                "path_prefix": "/api",
                "vuln_classes": ["sqli"],
                "reason": "injection already covered; a deferral must not override it",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    fams = _families(_by_unit(body)[DEEP_HOST])
    assert fams["injection"]["status"] == "covered"
    assert body["totals"]["covered"] == 1
    assert body["totals"]["deferred"] == 0


def test_by_family_finding_id_is_deterministic_min(client, isolate_settings):
    """A (unit, family) bucket with [no-finding probe, probe→finding B, probe→
    finding A] reports ``finding_id == min(A, B)`` and ``has_finding is True``
    (code fix #1). Findings A/B are created A-then-B so ``A < B``; the LARGER-id
    finding (B) is linked to the earlier-inserted probe.

    Non-vacuous: this pins the ``min`` aggregation contract — a regression to a
    last-wins / unconditional-overwrite or ``max`` reducer returns B, flipping the
    final assert (verified: with ``st["finding_id"] = int(fid)`` the endpoint
    returns B). It also carries the determinism guard fix #1 exists for: the
    ``by_family`` probe SELECT currently scans the ``(engagement_id, finding_id)``
    index (finding_id-ascending), but if that plan ever changed to insertion order
    the pre-fix 'first non-null' would return B here — ``min`` keeps it A either
    way. ``has_finding`` stays true whenever ANY probe in the bucket is linked."""
    eng_id = _seed(client, isolate_settings)
    _insert_unit(eng_id, host=DEEP_HOST, path_prefix="/api", deep_required=1)
    finding_a = _create_finding_distinct(
        client, "VA-101", root_cause_key="rc-a",
        canonical_location=f"https://{DEEP_HOST}/api/a")  # smaller id (created first)
    finding_b = _create_finding_distinct(
        client, "VA-102", root_cause_key="rc-b",
        canonical_location=f"https://{DEEP_HOST}/api/b")  # larger id
    assert finding_a < finding_b

    # Three sqli probes (→ injection family bucket), distinct target paths so each
    # is a distinct probe_key row. The larger-id finding is linked FIRST.
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_path="/api/p0", tool_name="sqlmap")                    # no finding
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_path="/api/p1", tool_name="sqlmap", finding_id=finding_b)
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_path="/api/p2", tool_name="sqlmap", finding_id=finding_a)

    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    injection = _families(_by_unit(body)[DEEP_HOST])["injection"]
    assert injection["probe_count"] == 3
    assert injection["has_finding"] is True
    assert injection["finding_id"] == min(finding_a, finding_b) == finding_a


def test_by_family_disclosure_expected_reason_accurate_on_shallow_unit(client, isolate_settings):
    """disclosure is expected for EVERY unit, incl. ``deep_required=0``. Its
    ``expected_reason`` label must be accurate for a shallow unit (code fix #2):
    the pre-fix label ``"deep_required unit (always expected)"`` is factually wrong
    on THIN_HOST (deep_required=0).

    Non-vacuous: the old label contains the substring ``deep_required``, so
    ``assert "deep_required" not in reason`` fails on the old code."""
    _seed_grid(client, isolate_settings)  # THIN_HOST unit is deep_required=0
    body = client.get(f"{BASE}/coverage-readiness/by-family").json()
    thin_row = _by_unit(body)[THIN_HOST]
    assert thin_row["deep_required"] is False
    reason = _families(thin_row)["disclosure"]["expected_reason"]
    assert reason is not None
    assert "deep_required" not in reason
    assert reason == "every application unit (always expected)"
