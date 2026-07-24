"""Scope-admission + hostname-validation guards on the depth ledger, app-unit
scorer, and work-buffer dispatch, plus the coverage-item-resolution work drain.

Covers three verified defects:

  * I-07 — wildcard co-tenant / out-of-scope leakage: the depth ledger, app-unit
    scorer, and work-buffer claim projections now route every host through the
    SAME ``_host_admitted_by_scope`` primitive ``web_uncovered_high_route_hosts``
    uses, so a host the engagement does not own (a wildcard co-tenant like
    ``otherchurch.acme-portal.example`` under a specific-host allowlist, or an
    explicit ``out_of_scope`` carve-out) is never a depth blocker nor a dispatch
    target — while a legitimately in-scope subdomain still is.
  * I-08 — malformed host keys: the maximally-lenient surface/probe parser is
    gated by a backend hostname validator, so a descriptor like ``us-east-1`` (a
    region label, not a host) can no longer mint a bogus ``deep_required`` app
    unit that hard-blocks the terminal report edge.
  * I-09 — work-buffer drain: resolving a coverage item to ``covered`` /
    ``not_applicable`` drains its FK-linked pending work items (the SAME drain
    the covering-probe path runs), so work for an explicitly-closed endpoint slot
    stops being dispatchable.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services import state_manager
from app.services.state_manager import app_units as app_units_mod


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _write_engagement(
    engagements_dir: Path,
    *,
    key: str,
    scope_hosts: list[str],
    out_of_scope: list[str] | None = None,
    engagement_type: str = "web",
) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-07-24T09:00:00Z",
                "engagement_type": engagement_type,
            }
        ),
        encoding="utf-8",
    )
    scope: dict = {
        "hostname": "example.com",
        "hosts": list(scope_hosts),
        "scope_hosts": list(scope_hosts),
        "engagement_type": engagement_type,
        "status": "in_progress",
        "current_phase": "consume-test",
    }
    if out_of_scope is not None:
        scope["out_of_scope"] = list(out_of_scope)
    (eng / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")
    return eng


def _register(client, key: str) -> tuple[int, str]:
    resp = client.get(f"/engagements/{key}")
    assert resp.status_code == 200, resp.text
    return int(resp.json()["id"]), f"/engagements/{key}/assessment"


def _surface(client, base: str, *, surface_type: str, descriptor: str) -> None:
    resp = client.post(
        f"{base}/surfaces",
        json={
            "surface_type": surface_type,
            "target_descriptor": descriptor,
            "source_name": "recon-specialist",
            "rationale": "live endpoint",
        },
    )
    assert resp.status_code == 201, resp.text


def _variant(eng_id: int, *, url: str, method: str = "GET") -> None:
    state_manager.record_request_variant(
        eng_id,
        url=url,
        method=method,
        auth_context="anonymous",
        content_type_family="html",
        query_schema={"q": "string"},
        body_schema={},
        path_schema={},
        cookie_schema={},
        header_schema={},
        path_template="",
        discovery_source="proxy",
        notes="",
        response_status=200,
        evidence_ref="",
        observation_payload={},
    )


def _probe(client, base: str, *, target_host: str, target_path: str = "/x") -> None:
    resp = client.post(
        f"{base}/probe-runs",
        json={
            "attack_family": "idor",
            "tool_name": "manual",
            "target_host": target_host,
            "target_path": target_path,
            "auth_context": "anonymous",
            "input_slot": "path:id",
            "result_status": "attempted",
            "evidence_ref": "",
        },
    )
    assert resp.status_code == 201, resp.text


def _observe_linked(client, base: str, url: str, case_type: str = "api") -> dict:
    """Ingest an observation that auto-creates coverage items and derives ONE work
    item FK-linked to the deterministic endpoint-slot coverage item."""
    resp = client.post(
        f"{base}/request-observations",
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


def _hosts(units: list[dict]) -> set[str]:
    return {u["host"] for u in units}


def _pending_hosts(client, base: str) -> set[str]:
    rows = client.get(f"{base}/work-items?status=pending").json()
    return {r["host"] for r in rows}


# --------------------------------------------------------------------------- #
# I-08 — backend hostname validator (unit)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "host,valid",
    [
        ("app.example.com", True),
        ("example.com", True),
        ("a.b", True),
        ("10.0.0.5", True),
        ("2001:db8::1", True),
        ("localhost", True),
        ("api.example.com", True),
        # rejected — not a host
        ("us-east-1", False),
        ("register", False),
        ("auth", False),
        ("<placeholder>", False),
        ("/api/orders", False),
        ("admin@rock.example.com", False),
        ("-lead.example.com", False),
        ("", False),
    ],
)
def test_is_valid_hostname(host: str, valid: bool) -> None:
    assert app_units_mod._is_valid_hostname(host) is valid


def test_surface_parser_rejects_nonhost_but_split_keeps_raw() -> None:
    # The validating ingest parser drops a non-host descriptor's host...
    assert app_units_mod._surface_host_path("us-east-1 /login") == ("", "/login")
    # ...while the raw split (used to compare against a TRUSTED unit host) keeps it.
    assert app_units_mod._split_host_path("us-east-1 /login") == ("us-east-1", "/login")
    # Real descriptors are unaffected.
    assert app_units_mod._surface_host_path("https://app.example.com/login") == (
        "app.example.com",
        "/login",
    )
    assert app_units_mod._surface_host_path("api.example.com:8443 /admin/login") == (
        "api.example.com",
        "/admin/login",
    )


# --------------------------------------------------------------------------- #
# I-08 — garbage descriptors never mint app units / depth blockers
# --------------------------------------------------------------------------- #
def test_garbage_surface_descriptor_mints_no_unit(client, isolate_settings) -> None:
    key = "2026-07-24-000000-i08-surface"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    _eng_id, base = _register(client, key)
    eng_id = _eng_id
    # A region label parsed as a host by the lenient splitter — must be dropped.
    _surface(client, base, surface_type="auth_entry", descriptor="us-east-1 /login")
    # A real decisive surface for an in-scope host — must materialize deep_required.
    _surface(client, base, surface_type="auth_entry", descriptor="app.example.com /login")

    state_manager.score_application_units(eng_id)
    units = state_manager.list_application_units(eng_id)
    hosts = _hosts(units)
    assert "app.example.com" in hosts
    assert "us-east-1" not in hosts
    assert any(u["host"] == "app.example.com" and u["deep_required"] for u in units)

    # The terminal depth edge blocks on the real host, never on the garbage one.
    block = state_manager.terminal_depth_block(eng_id)
    blocked_hosts = {b["unit"]["host"] for b in block["blocking"]}
    assert "app.example.com" in blocked_hosts
    assert "us-east-1" not in blocked_hosts


def test_garbage_probe_target_host_mints_no_under_observed_unit(client, isolate_settings) -> None:
    key = "2026-07-24-000000-i08-probe"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    eng_id, base = _register(client, key)
    _probe(client, base, target_host="us-east-1")  # garbage → dropped
    _probe(client, base, target_host="lonely.example.com")  # valid in-scope → under-observed unit

    state_manager.score_application_units(eng_id)
    hosts = _hosts(state_manager.list_application_units(eng_id))
    assert "lonely.example.com" in hosts
    assert "us-east-1" not in hosts


# --------------------------------------------------------------------------- #
# I-07 — out-of-scope / co-tenant hosts excluded from scorer + depth ledger
# --------------------------------------------------------------------------- #
def test_scorer_drops_wildcard_co_tenant_variant_host(client, isolate_settings) -> None:
    """A specific-host allowlist (``mychurch.acme-portal.example``) must NOT admit a
    co-tenant (``otherchurch.acme-portal.example``) discovered via proxy/redirect."""
    key = "2026-07-24-000000-i07-cotenant"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["mychurch.acme-portal.example"],
    )
    eng_id, _base = _register(client, key)
    _variant(eng_id, url="https://mychurch.acme-portal.example/giving/account")
    _variant(eng_id, url="https://otherchurch.acme-portal.example/giving/account")

    state_manager.score_application_units(eng_id)
    hosts = _hosts(state_manager.list_application_units(eng_id))
    assert "mychurch.acme-portal.example" in hosts
    assert "otherchurch.acme-portal.example" not in hosts


def test_legit_wildcard_scope_admits_all_subdomains(client, isolate_settings) -> None:
    """The don't-over-block guard: when the operator authored ``*.acme-portal.example``
    the co-tenant IS in scope and must still score (no regression)."""
    key = "2026-07-24-000000-i07-wildcard-ok"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["*.acme-portal.example"],
    )
    eng_id, _base = _register(client, key)
    _variant(eng_id, url="https://mychurch.acme-portal.example/giving/account")
    _variant(eng_id, url="https://otherchurch.acme-portal.example/giving/account")

    state_manager.score_application_units(eng_id)
    hosts = _hosts(state_manager.list_application_units(eng_id))
    assert {"mychurch.acme-portal.example", "otherchurch.acme-portal.example"} <= hosts


def test_depth_block_excludes_out_of_scope_carveout_surface(client, isolate_settings) -> None:
    """An in-apex host named in ``out_of_scope`` (denylist wins) never becomes a
    depth blocker, while a sibling in-scope host still does."""
    key = "2026-07-24-000000-i07-depth-carveout"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["example.com"],
        out_of_scope=["legacy.example.com"],
    )
    eng_id, base = _register(client, key)
    _surface(client, base, surface_type="object_reference", descriptor="app.example.com /account")
    _surface(client, base, surface_type="object_reference", descriptor="legacy.example.com /account")

    block = state_manager.terminal_depth_block(eng_id)
    blocked_hosts = {b["unit"]["host"] for b in block["blocking"]}
    assert "app.example.com" in blocked_hosts
    assert "legacy.example.com" not in blocked_hosts


def test_depth_ledger_read_side_filters_out_of_scope_unit(client, isolate_settings) -> None:
    """Defense-in-depth: even a unit already persisted (in-scope at score time)
    disappears from the depth-ledger projection once scope is tightened, before a
    re-score runs."""
    key = "2026-07-24-000000-i07-ledger-readside"
    eng_dir = _write_engagement(
        isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"]
    )
    eng_id, base = _register(client, key)
    _surface(client, base, surface_type="object_reference", descriptor="sub.example.com /account")
    _surface(client, base, surface_type="object_reference", descriptor="app.example.com /account")
    state_manager.score_application_units(eng_id)
    assert "sub.example.com" in _hosts(state_manager.list_application_units(eng_id))

    # Tighten scope to carve out sub.example.com, then read the ledger WITHOUT a
    # re-score. The read-side scope filter must already drop the stale unit.
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["out_of_scope"] = ["sub.example.com"]
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")

    ledger = state_manager.depth_ledger(eng_id)
    ledger_hosts = {u["unit"]["host"] for u in ledger["units"]}
    assert "app.example.com" in ledger_hosts
    assert "sub.example.com" not in ledger_hosts


def test_rescore_prunes_now_out_of_scope_unit(client, isolate_settings) -> None:
    """I-07 repair path: no new command needed — once a host is carved out of
    scope, a normal re-score prunes its stale unit via ``_prune_stale_units``."""
    key = "2026-07-24-000000-i07-repair"
    eng_dir = _write_engagement(
        isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"]
    )
    eng_id, base = _register(client, key)
    _surface(client, base, surface_type="object_reference", descriptor="sub.example.com /account")
    _surface(client, base, surface_type="object_reference", descriptor="app.example.com /account")
    state_manager.score_application_units(eng_id)
    assert "sub.example.com" in _hosts(state_manager.list_application_units(eng_id))

    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["out_of_scope"] = ["sub.example.com"]
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")

    state_manager.score_application_units(eng_id)  # idempotent re-score
    hosts = _hosts(state_manager.list_application_units(eng_id))
    assert "app.example.com" in hosts
    assert "sub.example.com" not in hosts


# --------------------------------------------------------------------------- #
# I-07 — work-buffer dispatch scope guard
# --------------------------------------------------------------------------- #
def _bulk_pending(eng_id: int, *, host: str, path_id: str, priority: int, queue: str) -> None:
    state_manager.record_work_items_bulk(
        eng_id,
        [
            {
                "url": f"https://{host}/api/{path_id}",
                "host": host,
                "queue_key": queue,
                "type": "api",
                "status": "pending",
                "priority_score": priority,
            }
        ],
    )


def test_fetch_by_priority_never_claims_out_of_scope_host(client, isolate_settings) -> None:
    key = "2026-07-24-000000-i07-wb-priority"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["mychurch.acme-portal.example"],
    )
    eng_id, _base = _register(client, key)
    _bulk_pending(eng_id, host="mychurch.acme-portal.example", path_id="a", priority=10, queue="wi:in")
    # Higher priority, but an out-of-scope co-tenant → must be skipped.
    _bulk_pending(eng_id, host="otherchurch.acme-portal.example", path_id="b", priority=90, queue="wi:oos")

    res = state_manager.fetch_work_items_by_priority(eng_id, limit=10, agent="auto")
    claimed_hosts = {c["host"] for c in res["claimed"]}
    assert claimed_hosts == {"mychurch.acme-portal.example"}


def test_fetch_by_type_never_claims_out_of_scope_host(client, isolate_settings) -> None:
    key = "2026-07-24-000000-i07-wb-type"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["mychurch.acme-portal.example"],
    )
    eng_id, base = _register(client, key)
    _bulk_pending(eng_id, host="mychurch.acme-portal.example", path_id="a", priority=10, queue="wi:in")
    _bulk_pending(eng_id, host="otherchurch.acme-portal.example", path_id="b", priority=90, queue="wi:oos")

    res = state_manager.fetch_work_items(eng_id, type_val="api", limit=10, agent="vulnerability-analyst")
    claimed_hosts = {c["host"] for c in res["claimed"]}
    assert "mychurch.acme-portal.example" in claimed_hosts
    assert "otherchurch.acme-portal.example" not in claimed_hosts
    # The out-of-scope row is neither claimed nor consumed — it stays pending.
    assert _pending_hosts(client, base) == {"otherchurch.acme-portal.example"}


def test_fetch_by_unit_skips_out_of_scope_candidate(client, isolate_settings) -> None:
    """The by-unit claim path skips an out-of-scope work row even when it is
    (contrived) linked to an in-scope unit."""
    key = "2026-07-24-000000-i07-wb-unit"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    eng_id, _base = _register(client, key)
    _variant(eng_id, url="https://app.example.com/api/orders")
    state_manager.score_application_units(eng_id)
    unit = next(u for u in state_manager.list_application_units(eng_id) if u["host"] == "app.example.com")
    uid = int(unit["id"])

    state_manager.record_work_items_bulk(
        eng_id,
        [
            {
                "url": "https://app.example.com/api/orders",
                "host": "app.example.com",
                "queue_key": "wi:unit:in",
                "type": "api",
                "status": "pending",
                "priority_score": 10,
                "application_unit_id": uid,
            },
            {
                "url": "https://evil.other.io/api/orders",
                "host": "evil.other.io",
                "queue_key": "wi:unit:oos",
                "type": "api",
                "status": "pending",
                "priority_score": 90,
                "application_unit_id": uid,
            },
        ],
    )

    res = state_manager.fetch_work_items_by_unit(
        eng_id, unit_id=uid, path="", work_class="", limit=None, agent="auto"
    )
    claimed_hosts = {c["host"] for c in res["claimed"]}
    assert "app.example.com" in claimed_hosts
    assert "evil.other.io" not in claimed_hosts


def test_no_scope_allowlist_fails_open_for_dispatch(client, isolate_settings) -> None:
    """When scope has no allowlist, ``_engagement_scope_admission`` is None and the
    dispatch guard fails OPEN — every routable row is still claimable."""
    key = "2026-07-24-000000-i07-wb-failopen"
    eng = isolate_settings["engagements_dir"] / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "OpenScope", "engagement_type": "web"}),
        encoding="utf-8",
    )
    eng_id, _base = _register(client, key)
    _bulk_pending(eng_id, host="anything.example.com", path_id="a", priority=10, queue="wi:a")
    _bulk_pending(eng_id, host="third.party.io", path_id="b", priority=20, queue="wi:b")

    res = state_manager.fetch_work_items_by_priority(eng_id, limit=10, agent="auto")
    claimed_hosts = {c["host"] for c in res["claimed"]}
    assert claimed_hosts == {"anything.example.com", "third.party.io"}


# --------------------------------------------------------------------------- #
# I-09 — coverage-item resolution drains FK-linked work items
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("terminal_status", ["covered", "not_applicable"])
def test_resolving_coverage_item_drains_linked_work(client, isolate_settings, terminal_status) -> None:
    key = f"2026-07-24-000000-i09-{terminal_status}"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    _eng_id, base = _register(client, key)
    obs = _observe_linked(client, base, "https://app.example.com/api/orders")
    wi_id = int(obs["work_item"]["id"])
    cov_id = int(obs["work_item"]["coverage_item_id"])
    assert _pending_hosts(client, base) == {"app.example.com"}

    resp = client.patch(
        f"{base}/coverage-items/{cov_id}",
        json={"status": terminal_status, "notes": "tested idor; 403 on cross-tenant read"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == terminal_status
    assert body["work_items_done"]["affected"] == 1
    assert body["work_items_done"]["ids"] == [wi_id]

    # The buffered row is now done — no longer pending / dispatchable.
    assert _pending_hosts(client, base) == set()
    done_rows = client.get(f"{base}/work-items?status=done").json()
    assert {r["id"] for r in done_rows} == {wi_id}


def test_resolving_coverage_item_with_no_linked_work_is_noop(client, isolate_settings) -> None:
    """No FK-linked pending work → no drain summary, no error (idempotent path)."""
    key = "2026-07-24-000000-i09-nowork"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    eng_id, base = _register(client, key)
    item = state_manager.record_coverage_item(
        eng_id,
        request_variant_id=None,
        service_id=None,
        auth_context="anonymous",
        input_slot="query",
        attack_family="idor",
        status_value="pending",
        notes="",
    )
    resp = client.patch(
        f"{base}/coverage-items/{int(item['id'])}",
        json={"status": "covered", "notes": "not reachable in this build"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "covered"
    assert "work_items_done" not in resp.json()


def test_non_terminal_coverage_status_does_not_drain(client, isolate_settings) -> None:
    """Resolving to a non-covered/NA status leaves the linked work pending."""
    key = "2026-07-24-000000-i09-partial"
    _write_engagement(isolate_settings["engagements_dir"], key=key, scope_hosts=["example.com"])
    _eng_id, base = _register(client, key)
    obs = _observe_linked(client, base, "https://app.example.com/api/orders")
    cov_id = int(obs["work_item"]["coverage_item_id"])

    resp = client.patch(
        f"{base}/coverage-items/{cov_id}",
        json={"status": "blocked", "notes": "one leg tested; blocked on the rest"},
    )
    assert resp.status_code == 200, resp.text
    assert "work_items_done" not in resp.json()
    assert _pending_hosts(client, base) == {"app.example.com"}


@pytest.mark.parametrize(
    "host,admitted",
    [
        # A LITERAL carve-out covers the apex host and NOTHING beneath it.
        ("example.com", False),
        ("app.example.com", True),
        ("api.example.com", True),
        ("deep.app.example.com", True),
        # An explicitly enumerated literal carve-out still wins.
        ("legacy.example.com", False),
        # A WILDCARD carve-out still covers its apex AND every subdomain.
        ("staging.example.com", False),
        ("a.staging.example.com", False),
        ("b.a.staging.example.com", False),
    ],
)
def test_literal_deny_entry_does_not_apex_expand(host: str, admitted: bool) -> None:
    """Unit-level contract for the admission primitive every projection shares."""
    from app.services.state_manager.coverage import _host_admitted_by_scope

    allow = ["example.com"]
    deny = ["example.com", "legacy.example.com", "*.staging.example.com"]
    assert _host_admitted_by_scope(host, allow, deny) is admitted


def test_apex_carveout_keeps_enumerated_subdomain_units(client, isolate_settings) -> None:
    """End-to-end: an engagement that carves out the bare apex while listing its
    subdomains as in-scope keeps every subdomain app unit and depth-ledger row.

    This is the exact scope.json shape that regressed: the apex is out of scope,
    a handful of named subdomains are carved out individually, and the product
    subdomains are explicitly enumerated as in-scope.
    """
    key = "2026-07-24-000000-i10-apex-carveout"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["app.example.com", "api.example.com", "*.cc.example.net"],
        out_of_scope=["example.com", "www.example.com", "*.staging.example.com"],
    )
    eng_id, base = _register(client, key)
    for host in (
        "app.example.com",
        "api.example.com",
        "mychurch.cc.example.net",
        "www.example.com",
        "old.staging.example.com",
    ):
        _surface(client, base, surface_type="object_reference", descriptor=f"{host} /account")

    state_manager.score_application_units(eng_id)
    hosts = _hosts(state_manager.list_application_units(eng_id))
    # The apex carve-out must not swallow the enumerated in-scope subdomains.
    assert {"app.example.com", "api.example.com", "mychurch.cc.example.net"} <= hosts
    # Literal + wildcard carve-outs still bite.
    assert "www.example.com" not in hosts
    assert "old.staging.example.com" not in hosts

    ledger_hosts = {u["unit"]["host"] for u in state_manager.depth_ledger(eng_id)["units"]}
    assert {"app.example.com", "api.example.com"} <= ledger_hosts
    assert "www.example.com" not in ledger_hosts


def test_apex_carveout_keeps_subdomain_work_dispatchable(client, isolate_settings) -> None:
    """The work-buffer claim projection shares the primitive: an apex carve-out
    must not make every subdomain's buffered work undispatchable."""
    key = "2026-07-24-000000-i10-wb-apex"
    _write_engagement(
        isolate_settings["engagements_dir"],
        key=key,
        scope_hosts=["app.example.com", "api.example.com"],
        out_of_scope=["example.com"],
    )
    eng_id, _base = _register(client, key)
    _bulk_pending(eng_id, host="app.example.com", path_id="a", priority=50, queue="wi:app")
    _bulk_pending(eng_id, host="api.example.com", path_id="b", priority=40, queue="wi:api")

    res = state_manager.fetch_work_items_by_priority(eng_id, limit=10, agent="auto")
    assert {c["host"] for c in res["claimed"]} == {"app.example.com", "api.example.com"}
