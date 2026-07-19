"""A3: POST /probe-runs work-buffer drain + opt-in surface resolve.

Recording a probe with ``work_item_ids`` marks those ``assessment_work_items``
rows ``done`` in the SAME transaction as the probe insert, so "remaining work"
bucket counts (``/work-items/stats``) decrement as probes land. Unknown ids are
skipped rather than crashing the probe write. The opt-in ``resolve_surface_id``
advances a mapped surface to ``partially-covered``; omitting it leaves surface
state untouched (recording never auto-mutates it).
"""
import json

ENGAGEMENT_KEY = "2026-07-08-000000-probedrain"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    eng = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "Drain", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _make_work_item(client, url: str, case_type: str = "api") -> int:
    """Derive one pending work item from a request-observation; return its id."""
    resp = client.post(
        f"{BASE}/request-observations",
        json={
            "url": url,
            "method": "GET",
            "query_schema": {"q": "string"},
            "discovery_source": "test",
            "work_item": {"case_type": case_type, "status": "pending"},
        },
    )
    assert resp.status_code == 201, resp.text
    return int(resp.json()["work_item"]["id"])


def _pending_count(client) -> int:
    stats = client.get(f"{BASE}/work-items/stats").json()
    return {row["status"]: row["count"] for row in stats["status"]}.get("pending", 0)


def _probe_payload(**overrides) -> dict:
    base = {
        "attack_family": "idor",
        "tool_name": "manual",
        "target_host": "app.example",
        "target_path": "/api/a",
        "auth_context": "member",
        "input_slot": "path:id",
        "result_status": "tested",
        "evidence_ref": "scans/idor.txt",
    }
    base.update(overrides)
    return base


def test_probe_run_drains_work_items(client, isolate_settings):
    _seed(client, isolate_settings)
    a = _make_work_item(client, "https://app.example/api/a")
    b = _make_work_item(client, "https://app.example/api/b")
    assert _pending_count(client) == 2

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload(work_item_ids=[a, b]))
    assert resp.status_code == 201, resp.text
    assert resp.json()["work_items_done"]["affected"] == 2

    # The two ids are now done → pending count dropped to 0.
    assert _pending_count(client) == 0
    done_rows = client.get(f"{BASE}/work-items?status=done").json()
    assert {row["id"] for row in done_rows} == {a, b}


def test_probe_run_unknown_work_item_id_is_skipped(client, isolate_settings):
    _seed(client, isolate_settings)
    a = _make_work_item(client, "https://app.example/api/only")

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            attack_family="sqli",
            target_path="/api/only",
            input_slot="query:q",
            evidence_ref="scans/sqli.txt",
            work_item_ids=[a, 999999],
        ),
    )
    # A stale id neither 4xxs nor rolls back the probe write — only the real id
    # drains (mirrors POST /work-items/done).
    assert resp.status_code == 201, resp.text
    assert resp.json()["work_items_done"]["affected"] == 1
    assert _pending_count(client) == 0


def test_probe_run_without_work_item_ids_leaves_buffer(client, isolate_settings):
    _seed(client, isolate_settings)
    _make_work_item(client, "https://app.example/api/a")
    assert _pending_count(client) == 1

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload())
    assert resp.status_code == 201, resp.text
    # No drain requested → buffer untouched, no drain summary on the response.
    assert "work_items_done" not in resp.json()
    assert _pending_count(client) == 1


def _make_surface(client, descriptor: str) -> int:
    resp = client.post(
        f"{BASE}/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": descriptor,
            "source_name": "test",
            "rationale": "seed",
            "evidence_ref": "",
            "status": "discovered",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "discovered"
    return int(body["id"])


def test_probe_run_opt_in_resolves_surface(client, isolate_settings):
    _seed(client, isolate_settings)
    sid = _make_surface(client, "app.example/api/orders/{id}")

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(target_path="/api/orders/1", resolve_surface_id=sid),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["surface_resolved"]["status"] == "partially-covered"


def test_probe_run_without_resolve_surface_leaves_surface_untouched(client, isolate_settings):
    _seed(client, isolate_settings)
    sid = _make_surface(client, "app.example/api/carts/{id}")

    resp = client.post(f"{BASE}/probe-runs", json=_probe_payload(target_path="/api/carts/1"))
    assert resp.status_code == 201, resp.text
    # No opt-in → no surface mutation, no resolve summary on the response.
    assert "surface_resolved" not in resp.json()
    assert "surfaces_advanced" not in resp.json()
    surfaces = client.get(f"{BASE}/surfaces").json()
    by_id = {row["id"]: row for row in surfaces}
    assert by_id[sid]["status"] == "discovered"


# --------------------------------------------------------------------------- #
# 1b — DEFAULT-ON FK-derived cascade
# --------------------------------------------------------------------------- #
def _make_linked_observation(client, url: str, case_type: str = "api") -> dict:
    """Ingest one observation (auto-generates coverage items) and return the full
    record: its request_variant, coverage_items, and the derived work item — the
    work item is FK-linked to the deterministic endpoint-slot coverage item."""
    resp = client.post(
        f"{BASE}/request-observations",
        json={
            "url": url,
            "method": "GET",
            "query_schema": {"q": "string"},
            "discovery_source": "test",
            "work_item": {"case_type": case_type, "status": "pending"},
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _coverage_item_status(client, coverage_item_id: int) -> str:
    rows = client.get(f"{BASE}/coverage-items").json()
    by_id = {int(r["id"]): r for r in rows}
    return str(by_id[coverage_item_id]["status"])


def _link_surface(client, surface_id: int, request_variant_id: int) -> None:
    resp = client.post(
        f"{BASE}/surface-request-variant-links",
        json={"surface_id": surface_id, "request_variant_id": request_variant_id},
    )
    assert resp.status_code == 201, resp.text


def test_covering_probe_default_drains_and_advances_and_keeps_coverage_item(client, isolate_settings):
    """The Tier-1 invariant: recording ONE covering record-probe carrying a
    --coverage-item-id (a) drains the FK-linked work-items and (b) advances the
    FK-linked surface to partially-covered BY DEFAULT (no --work-item-ids /
    --resolve-surface), WHILE the coverage-item status stays un-promoted (never
    auto-`covered`). So the work-buffer, surface, and probe ledgers agree without
    extra verbs, but the human `covered` verdict is never self-attested."""
    _seed(client, isolate_settings)
    obs = _make_linked_observation(client, "https://app.example/api/orders")
    wi_id = int(obs["work_item"]["id"])
    cov_id = int(obs["work_item"]["coverage_item_id"])
    rv_id = int(obs["request_variant"]["id"])
    assert _pending_count(client) == 1
    assert _coverage_item_status(client, cov_id) == "pending"

    sid = _make_surface(client, "app.example/api/orders/{id}")
    _link_surface(client, sid, rv_id)

    # ONE covering probe, carrying only its FK links — NO --work-item-ids, NO
    # --resolve-surface, NO --no-drain.
    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            target_path="/api/orders/1",
            coverage_item_id=cov_id,
            request_variant_id=rv_id,
        ),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()

    # (a) work-item drained by DEFAULT.
    assert body["work_items_done"]["affected"] == 1
    assert body["work_items_done"]["ids"] == [wi_id]
    assert _pending_count(client) == 0
    assert {r["id"] for r in client.get(f"{BASE}/work-items?status=done").json()} == {wi_id}

    # (b) surface advanced by DEFAULT.
    assert len(body["surfaces_advanced"]) == 1
    assert body["surfaces_advanced"][0]["id"] == sid
    assert body["surfaces_advanced"][0]["status"] == "partially-covered"
    by_id = {r["id"]: r for r in client.get(f"{BASE}/surfaces").json()}
    assert by_id[sid]["status"] == "partially-covered"

    # INVARIANT: coverage-item status is NEVER auto-promoted to covered.
    assert _coverage_item_status(client, cov_id) == "pending"


def test_noncovering_probe_does_not_cascade_by_default(client, isolate_settings):
    """The covering gate: a non-covering attempt (blocked) carrying the SAME FK
    links must NOT auto-drain or auto-advance — only whitelisted tested/signal
    counts; a wall is a lead, not coverage."""
    _seed(client, isolate_settings)
    obs = _make_linked_observation(client, "https://app.example/api/carts")
    cov_id = int(obs["work_item"]["coverage_item_id"])
    rv_id = int(obs["request_variant"]["id"])
    sid = _make_surface(client, "app.example/api/carts/{id}")
    _link_surface(client, sid, rv_id)
    assert _pending_count(client) == 1

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            result_status="blocked",
            target_path="/api/carts/1",
            coverage_item_id=cov_id,
            request_variant_id=rv_id,
        ),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "work_items_done" not in body
    assert "surfaces_advanced" not in body
    assert _pending_count(client) == 1  # buffer untouched
    by_id = {r["id"]: r for r in client.get(f"{BASE}/surfaces").json()}
    assert by_id[sid]["status"] == "discovered"  # surface untouched


def test_no_drain_suppresses_the_default_cascade(client, isolate_settings):
    """--no-drain suppresses BOTH halves of the default cascade even for a
    covering probe with FK links; the probe row is still written."""
    _seed(client, isolate_settings)
    obs = _make_linked_observation(client, "https://app.example/api/items")
    cov_id = int(obs["work_item"]["coverage_item_id"])
    rv_id = int(obs["request_variant"]["id"])
    sid = _make_surface(client, "app.example/api/items/{id}")
    _link_surface(client, sid, rv_id)
    assert _pending_count(client) == 1

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            target_path="/api/items/1",
            coverage_item_id=cov_id,
            request_variant_id=rv_id,
            no_drain=True,
        ),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert "work_items_done" not in body
    assert "surfaces_advanced" not in body
    assert _pending_count(client) == 1
    by_id = {r["id"]: r for r in client.get(f"{BASE}/surfaces").json()}
    assert by_id[sid]["status"] == "discovered"


def test_default_advance_never_regresses_a_resolved_surface(client, isolate_settings):
    """The default advance only touches DISCOVERED surfaces — a human verdict
    (covered) FK-linked to the variant is left untouched (no regression)."""
    _seed(client, isolate_settings)
    obs = _make_linked_observation(client, "https://app.example/api/users")
    cov_id = int(obs["work_item"]["coverage_item_id"])
    rv_id = int(obs["request_variant"]["id"])
    sid = _make_surface(client, "app.example/api/users/{id}")
    _link_surface(client, sid, rv_id)
    # Human resolves the surface to `covered` (deliberate verdict).
    patched = client.patch(
        f"{BASE}/surfaces/{sid}",
        json={"status": "covered", "rationale": "reviewed both identities"},
    )
    assert patched.status_code == 200, patched.text

    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            target_path="/api/users/1",
            coverage_item_id=cov_id,
            request_variant_id=rv_id,
        ),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Work-item still drains; surface stays covered (no downgrade), not advanced.
    assert body["work_items_done"]["affected"] == 1
    assert "surfaces_advanced" not in body
    by_id = {r["id"]: r for r in client.get(f"{BASE}/surfaces").json()}
    assert by_id[sid]["status"] == "covered"


def test_explicit_work_item_ids_override_the_default_derivation(client, isolate_settings):
    """Explicit --work-item-ids NARROWS the drain to those exact ids instead of
    the coverage-item-derived set (and fires regardless of the covering gate)."""
    _seed(client, isolate_settings)
    obs_a = _make_linked_observation(client, "https://app.example/api/a")
    obs_b = _make_linked_observation(client, "https://app.example/api/b")
    cov_a = int(obs_a["work_item"]["coverage_item_id"])
    wi_b = int(obs_b["work_item"]["id"])
    assert _pending_count(client) == 2

    # Carry coverage_item_id for A but explicitly drain ONLY B — the override wins.
    resp = client.post(
        f"{BASE}/probe-runs",
        json=_probe_payload(
            target_path="/api/a",
            coverage_item_id=cov_a,
            work_item_ids=[wi_b],
        ),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["work_items_done"]["ids"] == [wi_b]
    done_ids = {r["id"] for r in client.get(f"{BASE}/work-items?status=done").json()}
    assert done_ids == {wi_b}  # A stayed pending (override narrowed to B)
    assert _pending_count(client) == 1
