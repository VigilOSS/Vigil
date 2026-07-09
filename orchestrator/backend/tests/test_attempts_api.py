"""A4a — finding-joined, surface-aware read of recorded probe attempts.

Covers ``list_attempts`` (state_manager.coverage) via the
``GET /engagements/{key}/assessment/attempts`` route.

The read LEFT JOINs findings so each attempt carries the linked finding's
slug/title/severity (null when unlinked) and supports:
  * ``finding`` — a finding SLUG, resolved slug→id server-side.
  * ``target_host`` — exact ``target_host``.
  * ``surface_id`` — matches a probe whose ``request_variant_id`` is FK-linked to
    the surface OR whose ``target_host``/``target_path`` is contained by the
    surface descriptor. The containment arm is the regression these tests pin:
    most CLI-recorded probes carry a NULL ``request_variant_id``, so a
    link-table-only match would silently drop them.
"""
from __future__ import annotations

from app.services import state_manager
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-07-09-110000-attempts"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"

HOST = "app.example.com"
OTHER_HOST = "other.example.com"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _variant(eng_id: int, *, url: str) -> int:
    record = state_manager.record_request_variant(
        eng_id, url=url, method="GET", auth_context="anonymous",
        content_type_family="json", query_schema={}, body_schema={},
        path_schema={}, cookie_schema={}, header_schema={}, path_template="",
        discovery_source="proxy", notes="", response_status=200,
        evidence_ref="", observation_payload={},
    )
    return int(record["id"])


def _surface(eng_id: int, *, descriptor: str) -> int:
    record = state_manager.record_surface(
        eng_id, surface_type="object_reference", target_descriptor=descriptor,
        source_name="recon-specialist", rationale="live endpoint",
        evidence_ref="", status_value="discovered",
    )
    return int(record["id"])


def _probe(eng_id: int, *, attack_family: str, payload_value: str,
           request_variant_id: int | None = None, target_host: str = "",
           target_path: str = "", lens: str = "", result_status: str = "tested",
           finding_id: int | None = None) -> None:
    state_manager.record_probe_run(
        eng_id, request_variant_id=request_variant_id, service_id=None,
        coverage_item_id=None, auth_context="anonymous", input_slot="query",
        attack_family=attack_family, payload_family="", payload_value=payload_value,
        tool_name="curl", agent_name="va-1", result_status=result_status,
        observed_http_status=403, signal_type="", evidence_ref="", notes="",
        target_host=target_host, target_path=target_path,
        target_port=443 if target_host else None, lens=lens, finding_id=finding_id,
    )


def _create_finding(client, slug: str) -> tuple[int, str]:
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": "BOLA on /api/users/{id}",
            "severity": "high",
            "workflow_status": "active",
            "defect_family": "access-control",
            "root_cause_key": "missing-object-authz",
            "auth_context": "anonymous",
            "canonical_location": f"https://{HOST}/api/users",
            "summary": "Broken object level authorization",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Replayable request.", "impact": "PII read."},
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()["finding"]
    return int(body["id"]), str(body["slug"])


def _seed_attempts(client, isolate_settings) -> dict:
    eng_id = _seed(client, isolate_settings)
    surface_id = _surface(eng_id, descriptor=f"{HOST} /api")
    variant_id = _variant(eng_id, url=f"https://{HOST}/api/users/1")
    state_manager.create_surface_request_variant_link(
        eng_id, surface_id=surface_id, request_variant_id=variant_id,
    )
    finding_id, finding_slug = _create_finding(client, "VA-010")

    # P1 — FK-linked to the surface AND carrying the finding linkage.
    _probe(eng_id, attack_family="bola", payload_value="p1",
           request_variant_id=variant_id, target_host=HOST,
           target_path="/api/users/1", lens="idor-horizontal", finding_id=finding_id)
    # P2 — NULL request_variant_id but target host/path CONTAINED by the surface.
    _probe(eng_id, attack_family="idor", payload_value="p2", target_host=HOST,
           target_path="/api/users/2", lens="idor-vertical")
    # P3 — different host, matches neither the surface nor the host filter.
    _probe(eng_id, attack_family="sqli", payload_value="p3", target_host=OTHER_HOST,
           target_path="/x")
    return {
        "eng_id": eng_id, "surface_id": surface_id, "variant_id": variant_id,
        "finding_id": finding_id, "finding_slug": finding_slug,
    }


def test_attempts_unfiltered_returns_all_with_shape(client, isolate_settings):
    ctx = _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts").json()
    assert body["count"] == 3
    assert len(body["attempts"]) == 3
    expected_fields = {
        "id", "target_host", "target_path", "target_port", "auth_context",
        "attack_family", "lens", "result_status", "observed_http_status",
        "signal_type", "tool_name", "agent_name", "finding_id", "finding_slug",
        "finding_title", "finding_severity", "created_at",
    }
    for attempt in body["attempts"]:
        assert set(attempt) == expected_fields
    # request_variant_id is used internally for surface matching but never emitted.
    assert all("request_variant_id" not in a for a in body["attempts"])
    _ = ctx


def test_attempts_finding_filter_joins_title_and_severity(client, isolate_settings):
    ctx = _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts?finding={ctx['finding_slug']}").json()
    assert body["count"] == 1
    attempt = body["attempts"][0]
    assert attempt["attack_family"] == "bola"
    assert attempt["finding_id"] == ctx["finding_id"]
    assert attempt["finding_slug"] == ctx["finding_slug"]
    assert attempt["finding_title"] == "BOLA on /api/users/{id}"
    assert attempt["finding_severity"] == "high"


def test_attempts_finding_filter_unknown_slug_is_404(client, isolate_settings):
    _seed_attempts(client, isolate_settings)
    response = client.get(f"{BASE}/attempts?finding=VA-999")
    assert response.status_code == 404, response.text


def test_attempts_host_filter(client, isolate_settings):
    _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts?target_host={HOST}").json()
    assert body["count"] == 2
    assert {a["attack_family"] for a in body["attempts"]} == {"bola", "idor"}
    assert all(a["target_host"] == HOST for a in body["attempts"])


def test_attempts_surface_filter_matches_fk_link_and_containment(client, isolate_settings):
    ctx = _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts?surface_id={ctx['surface_id']}").json()
    # BOTH the FK-linked probe (P1) AND the NULL-request_variant_id containment
    # probe (P2) match — the containment arm is the regression guard.
    assert body["count"] == 2
    families = {a["attack_family"] for a in body["attempts"]}
    assert families == {"bola", "idor"}
    # The off-surface probe (different host) is excluded.
    assert "sqli" not in families


def test_attempts_rows_without_finding_have_null_finding_fields(client, isolate_settings):
    _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts?attack_family=idor").json()
    assert body["count"] == 1
    attempt = body["attempts"][0]
    assert attempt["finding_id"] is None
    assert attempt["finding_slug"] is None
    assert attempt["finding_title"] is None
    assert attempt["finding_severity"] is None


def test_attempts_surface_unknown_id_is_404(client, isolate_settings):
    _seed_attempts(client, isolate_settings)
    response = client.get(f"{BASE}/attempts?surface_id=999999")
    assert response.status_code == 404, response.text


def test_attempts_pagination_no_surface_branch(client, isolate_settings):
    """No-surface branch: pagination is SQL ``LIMIT/OFFSET``. With 3 probes on one
    host, single-row windows at offsets 0,1,2 must each return one row, together
    reproduce the full ordered match set with NO overlap/loss, and an offset past
    the end returns zero. ``count == len(attempts)`` throughout.

    Non-vacuous: drop the SQL LIMIT and offset=0 returns 3 (count 1 fails); ignore
    OFFSET and offset=1 repeats offset=0's id (``!=`` fails); mishandle past-end
    and the empty window is non-zero."""
    ctx = _seed_attempts(client, isolate_settings)
    # A 3rd distinguishable probe on HOST (seed has P1 bola + P2 idor on HOST).
    _probe(ctx["eng_id"], attack_family="xss", payload_value="p4",
           target_host=HOST, target_path="/api/other")

    full = client.get(f"{BASE}/attempts?target_host={HOST}").json()
    assert full["count"] == 3 == len(full["attempts"])
    ids_full = [a["id"] for a in full["attempts"]]  # created_at DESC, id DESC

    windows = []
    for off in (0, 1, 2):
        body = client.get(f"{BASE}/attempts?target_host={HOST}&limit=1&offset={off}").json()
        assert body["count"] == 1 == len(body["attempts"])
        windows.append(body["attempts"][0]["id"])

    past = client.get(f"{BASE}/attempts?target_host={HOST}&limit=1&offset=10").json()
    assert past["count"] == 0 == len(past["attempts"])

    # Consecutive single-row windows partition the full match set: same order, no
    # overlap, no loss.
    assert windows == ids_full
    assert len(set(windows)) == 3


def test_attempts_pagination_surface_branch(client, isolate_settings):
    """Surface branch: the window is a Python slice ``rows[offset:offset+limit]``
    applied AFTER the containment filter, ONCE. With the 2 surface-matching probes,
    offsets 0 and 1 each return one (the OTHER), offset 2 returns zero, and the two
    windows partition ``{bola, idor}``.

    Non-vacuous: if the slice applied to the RAW pre-filter rows (which include the
    off-host P3 at the top), ``offset=0`` would slice out P3 and then filter it away
    → count 0, failing the ``count == 1`` assert; a double-applied slice or an
    SQL-pushed LIMIT would break the partition."""
    ctx = _seed_attempts(client, isolate_settings)
    sid = ctx["surface_id"]

    full = client.get(f"{BASE}/attempts?surface_id={sid}").json()
    assert full["count"] == 2 == len(full["attempts"])
    ids_full = [a["id"] for a in full["attempts"]]
    assert {a["attack_family"] for a in full["attempts"]} == {"bola", "idor"}

    w0 = client.get(f"{BASE}/attempts?surface_id={sid}&limit=1&offset=0").json()
    assert w0["count"] == 1 == len(w0["attempts"])
    w1 = client.get(f"{BASE}/attempts?surface_id={sid}&limit=1&offset=1").json()
    assert w1["count"] == 1 == len(w1["attempts"])
    assert w1["attempts"][0]["id"] != w0["attempts"][0]["id"]
    w2 = client.get(f"{BASE}/attempts?surface_id={sid}&limit=1&offset=2").json()
    assert w2["count"] == 0 == len(w2["attempts"])

    paged = [w0["attempts"][0]["id"], w1["attempts"][0]["id"]]
    assert paged == ids_full
    assert {w0["attempts"][0]["attack_family"], w1["attempts"][0]["attack_family"]} == {
        "bola", "idor"
    }


def test_attempts_surface_over_match_guard(client, isolate_settings):
    """The surface containment is SEGMENT-WISE, not a raw ``startswith``. A probe on
    the same host under ``/apixyz/thing`` is NOT contained by surface ``/api`` and
    must be ABSENT from the surface result.

    Non-vacuous: a ``startswith`` regression would treat ``/apixyz`` as under
    ``/api`` (``"/apixyz/thing".startswith("/api")`` is True), pulling the probe in
    → count 3 and ``xss`` present, flipping both asserts."""
    ctx = _seed_attempts(client, isolate_settings)
    _probe(ctx["eng_id"], attack_family="xss", payload_value="overmatch",
           target_host=HOST, target_path="/apixyz/thing")  # NULL request_variant_id

    body = client.get(f"{BASE}/attempts?surface_id={ctx['surface_id']}").json()
    assert body["count"] == 2
    fams = {a["attack_family"] for a in body["attempts"]}
    assert fams == {"bola", "idor"}
    assert "xss" not in fams
    assert "/apixyz/thing" not in {a["target_path"] for a in body["attempts"]}


def test_attempts_lens_filter(client, isolate_settings):
    """``lens`` is an exact-match SQL filter. Only P2 carries ``idor-vertical``."""
    _seed_attempts(client, isolate_settings)
    body = client.get(f"{BASE}/attempts?lens=idor-vertical").json()
    assert body["count"] == 1
    attempt = body["attempts"][0]
    assert attempt["attack_family"] == "idor"
    assert attempt["lens"] == "idor-vertical"


def test_attempts_result_status_filter(client, isolate_settings):
    """``result_status`` is an exact-match SQL filter. The seed's 3 probes are all
    ``tested``; a 4th ``blocked`` probe is isolated by ``?result_status=blocked``."""
    ctx = _seed_attempts(client, isolate_settings)
    _probe(ctx["eng_id"], attack_family="xss", payload_value="walled",
           target_host=HOST, target_path="/api/users/9", result_status="blocked")

    blocked = client.get(f"{BASE}/attempts?result_status=blocked").json()
    assert blocked["count"] == 1
    assert blocked["attempts"][0]["result_status"] == "blocked"

    tested = client.get(f"{BASE}/attempts?result_status=tested").json()
    assert tested["count"] == 3
    assert all(a["result_status"] == "tested" for a in tested["attempts"])


def test_attempts_surface_and_attack_family_two_axis(client, isolate_settings):
    """Two-axis combo: ``surface_id`` (Python containment) AND ``attack_family``
    (SQL) must BOTH hold. ``idor`` is on-surface → 1; ``sqli`` exists but is the
    off-surface P3 → 0.

    Non-vacuous: ignore the surface axis and ``attack_family=sqli`` returns the
    off-surface P3 (count 1, not 0); ignore the family axis and ``surface_id&
    attack_family=idor`` returns both surface probes (count 2, not 1)."""
    ctx = _seed_attempts(client, isolate_settings)
    sid = ctx["surface_id"]

    on_surface = client.get(f"{BASE}/attempts?surface_id={sid}&attack_family=idor").json()
    assert on_surface["count"] == 1
    assert on_surface["attempts"][0]["attack_family"] == "idor"

    off_surface = client.get(f"{BASE}/attempts?surface_id={sid}&attack_family=sqli").json()
    assert off_surface["count"] == 0
