"""Wave 6a — app-unit prefix discovery + depth scorer (depth-gate §5.2).

These tests seed SYNTHETIC backends matching the §5.2.3 worked examples and
assert the resulting depth tier / deep_required, plus the load-bearing
doctrine invariants:

  * CRUD web app  -> ``application`` / deep_required
  * REST API (/v2 with /v1 present) -> version-skew risk -> ``application``
  * SSO /login (small but decisive auth_entry surface) -> deep_required via
    decisive-surface auto-promote
  * static CDN (200 GET-only no-param) -> ``thin``, NOT deep_required
  * probe activity but zero request_variants -> under-observed WARN, NOT thin

Plus: web-only guard (code/blue persist nothing), detection NEVER hard-blocks,
the recompute pass populates ``application_unit_id`` on coverage_items /
probe_runs, and manual mark-deep/clear-deep overrides win over the scorer.
"""
from __future__ import annotations

import json
from pathlib import Path

from app.services import state_manager
from tests.test_engagements_api import write_engagement


def _write_typed_engagement(engagements_dir: Path, key: str, engagement_type: str) -> Path:
    """write_engagement + force scope.json engagement_type (web/code/blue)."""
    eng_dir = write_engagement(engagements_dir, key=key)
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["engagement_type"] = engagement_type
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    return eng_dir


def _seed(client, isolate_settings, key: str, engagement_type: str = "web") -> int:
    _write_typed_engagement(isolate_settings["engagements_dir"], key, engagement_type)
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body.get("engagement_type") == engagement_type
    return int(body["id"])


def _variant(eng_id, *, url, method="GET", auth="anonymous",
             ctf="html", query=None, body=None, path=None, cookie=None,
             status_code=200, source="proxy"):
    state_manager.record_request_variant(
        eng_id,
        url=url,
        method=method,
        auth_context=auth,
        content_type_family=ctf,
        query_schema=query or {},
        body_schema=body or {},
        path_schema=path or {},
        cookie_schema=cookie or {},
        header_schema={},
        path_template="",
        discovery_source=source,
        notes="",
        response_status=status_code,
        evidence_ref="",
        observation_payload={},
    )


def _surface(client, key, *, surface_type, descriptor):
    response = client.post(
        f"/engagements/{key}/assessment/surfaces",
        json={
            "surface_type": surface_type,
            "target_descriptor": descriptor,
            "source_name": "recon-specialist",
            "rationale": "live endpoint",
        },
    )
    assert response.status_code == 201, response.text


def _tech(client, key, component):
    response = client.post(
        f"/engagements/{key}/intel/tech-components",
        json={"component": component, "source_name": "whatweb", "confidence": "high"},
    )
    assert response.status_code in (200, 201), response.text


def _coverage(eng_id, *, variant_id, attack_family):
    state_manager.record_coverage_item(
        eng_id,
        request_variant_id=variant_id,
        service_id=None,
        auth_context="anonymous",
        input_slot="query",
        attack_family=attack_family,
        status_value="pending",
        notes="",
    )


def _variant_id_for(eng_id, path):
    for v in state_manager.list_request_variants(eng_id):
        if v["normalized_path"] == path:
            return v["id"]
    raise AssertionError(f"no variant for path {path}")


def _units_by_prefix(eng_id):
    return {(u["host"], u["path_prefix"]): u for u in state_manager.list_application_units(eng_id)}


def test_crud_web_app_scores_application(client, isolate_settings):
    key = "2026-06-09-100000-crud"
    eng_id = _seed(client, isolate_settings, key)

    base = "https://rock.example.com/giving"
    for i in range(24):
        _variant(eng_id, url=f"{base}/page{i}", ctf="html")
    _variant(eng_id, url=f"{base}/donations", method="POST", ctf="json",
             body={"amount": "int", "account_id": "str"}, cookie={"session": "str"},
             status_code=200)
    _variant(eng_id, url=f"{base}/donations/edit", method="PUT", ctf="json",
             body={"id": "int"}, status_code=200)
    _variant(eng_id, url=f"{base}/donations/del", method="DELETE", status_code=204)
    _variant(eng_id, url=f"{base}/account", method="GET", ctf="json",
             query={"user_id": "int"}, auth="user_a", status_code=200)
    _variant(eng_id, url=f"{base}/admin/payouts", method="POST", ctf="json",
             body={"amount": "int"}, auth="user_b", status_code=403)

    _surface(client, key, surface_type="auth_entry", descriptor="rock.example.com /giving/login")
    _surface(client, key, surface_type="object_reference", descriptor="rock.example.com /giving/account")
    _surface(client, key, surface_type="privileged_write", descriptor="rock.example.com /giving/admin")
    _surface(client, key, surface_type="workflow_token", descriptor="rock.example.com /giving/donations")
    _tech(client, key, "Rock RMS (.NET)")

    vid = _variant_id_for(eng_id, "/giving/account")
    _coverage(eng_id, variant_id=vid, attack_family="idor")
    _coverage(eng_id, variant_id=vid, attack_family="sqli")

    result = state_manager.score_application_units(eng_id)
    assert result["skipped"] is False
    units = _units_by_prefix(eng_id)
    giving = units[("rock.example.com", "/giving")]
    assert giving["depth_tier"] == "application", giving
    assert giving["deep_required"] is True
    assert giving["structure_score"] >= 6
    assert giving["risk_score"] >= 6


def test_rest_api_version_skew_scores_application(client, isolate_settings):
    key = "2026-06-09-100001-api"
    eng_id = _seed(client, isolate_settings, key)

    for i in range(40):
        _variant(eng_id, url=f"https://api.example.com/api/v2/res{i}", ctf="json",
                 query={"id": "int"}, status_code=200)
    _variant(eng_id, url="https://api.example.com/api/v2/orders", method="POST",
             ctf="json", body={"id": "int"}, status_code=401)
    _variant(eng_id, url="https://api.example.com/api/v2/orders", method="PUT",
             ctf="json", body={"id": "int"}, status_code=200)
    _variant(eng_id, url="https://api.example.com/api/v2/orders", method="DELETE",
             status_code=200)
    _variant(eng_id, url="https://api.example.com/api/v1/legacy", ctf="json",
             query={"id": "int"}, status_code=200)

    _surface(client, key, surface_type="api_documentation",
             descriptor="api.example.com /api/v2/swagger.json")
    _surface(client, key, surface_type="object_reference",
             descriptor="api.example.com /api/v2/orders")
    _tech(client, key, "Express")

    vid = _variant_id_for(eng_id, "/api/v2/orders")
    _coverage(eng_id, variant_id=vid, attack_family="idor")
    _coverage(eng_id, variant_id=vid, attack_family="sqli")
    _coverage(eng_id, variant_id=vid, attack_family="ssrf")

    state_manager.score_application_units(eng_id)
    units = _units_by_prefix(eng_id)
    v2 = units[("api.example.com", "/api/v2")]
    assert v2["depth_tier"] == "application", v2
    assert v2["deep_required"] is True
    ev = v2["evidence"]
    assert ev["risk"]["version_skew"]["version_skew"] is True


def test_sso_login_auto_promotes_via_decisive_surface(client, isolate_settings):
    key = "2026-06-09-100002-sso"
    eng_id = _seed(client, isolate_settings, key)

    _variant(eng_id, url="https://auth.example.com/login", method="GET",
             query={"redirect": "str"}, status_code=200)
    _variant(eng_id, url="https://auth.example.com/login", method="POST",
             body={"user": "str", "pass": "str"}, status_code=302)

    _surface(client, key, surface_type="auth_entry", descriptor="auth.example.com /login")

    state_manager.score_application_units(eng_id)
    units = _units_by_prefix(eng_id)
    login = units[("auth.example.com", "/login")]
    assert login["deep_required"] is True, login
    assert login["depth_tier"] in ("app-unit", "application")
    assert login["evidence"]["decisive_surface"] is True


def test_static_cdn_scores_thin_not_deep(client, isolate_settings):
    key = "2026-06-09-100003-cdn"
    eng_id = _seed(client, isolate_settings, key)

    for i in range(200):
        _variant(eng_id, url=f"https://cdn.example.com/assets/img{i}.png",
                 method="GET", ctf="unknown", status_code=200)

    state_manager.score_application_units(eng_id)
    units = _units_by_prefix(eng_id)
    assets = units[("cdn.example.com", "/assets")]
    assert assets["depth_tier"] == "thin", assets
    assert assets["deep_required"] is False
    assert assets["risk_score"] == 0
    assert "static_only" in assets["evidence"]["suppressors"]


def test_under_observed_host_warns_not_thin(client, isolate_settings):
    key = "2026-06-09-100004-underobs"
    eng_id = _seed(client, isolate_settings, key)

    state_manager.record_probe_run(
        eng_id,
        request_variant_id=None,
        service_id=None,
        coverage_item_id=None,
        auth_context="anonymous",
        input_slot="unknown",
        attack_family="sqli",
        payload_family="",
        payload_value="",
        tool_name="sqlmap",
        agent_name="va",
        result_status="no-signal",
        observed_http_status=None,
        signal_type="",
        evidence_ref="",
        notes="",
        target_host="blind.example.com",
        target_path="/",
        target_port=443,
    )

    result = state_manager.score_application_units(eng_id)
    warned_hosts = {w["host"] for w in result["warnings"]}
    assert "blind.example.com" in warned_hosts
    units = _units_by_prefix(eng_id)
    unit = units[("blind.example.com", "/")]
    assert unit["confidence"] == "low"
    assert unit["evidence"].get("under_observed") is True
    warn = next(w for w in result["warnings"] if w["host"] == "blind.example.com")
    assert "under-observed" in warn["reason"]


def test_web_only_guard_code_engagement_persists_nothing(client, isolate_settings):
    key = "2026-06-09-100005-code"
    eng_id = _seed(client, isolate_settings, key, engagement_type="code")

    _variant(eng_id, url="https://repo.example.com/api/x", ctf="json",
             query={"id": "int"}, status_code=200)

    result = state_manager.score_application_units(eng_id)
    assert result["skipped"] is True
    assert "non-web" in result["reason"]
    assert state_manager.list_application_units(eng_id) == []


def test_web_only_guard_blue_engagement_persists_nothing(client, isolate_settings):
    key = "2026-06-09-100006-blue"
    eng_id = _seed(client, isolate_settings, key, engagement_type="blue")
    result = state_manager.score_application_units(eng_id)
    assert result["skipped"] is True
    assert state_manager.list_application_units(eng_id) == []


def test_detection_never_hard_blocks(client, isolate_settings):
    key = "2026-06-09-100007-noblock"
    eng_id = _seed(client, isolate_settings, key)
    result = state_manager.score_application_units(eng_id)
    assert result["skipped"] is False
    assert result["units"] == []
    result2 = state_manager.score_application_units(eng_id)
    assert result2["skipped"] is False


def test_recompute_populates_application_unit_id(client, isolate_settings):
    key = "2026-06-09-100008-link"
    eng_id = _seed(client, isolate_settings, key)

    for i in range(8):
        _variant(eng_id, url=f"https://app.example.com/shop/p{i}", ctf="json",
                 query={"id": "int"}, status_code=200)
    vid = _variant_id_for(eng_id, "/shop/p0")
    _coverage(eng_id, variant_id=vid, attack_family="idor")
    state_manager.record_probe_run(
        eng_id, request_variant_id=vid, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="query", attack_family="idor",
        payload_family="", payload_value="", tool_name="manual", agent_name="va",
        result_status="tested", observed_http_status=200, signal_type="",
        evidence_ref="", notes="",
    )
    state_manager.record_probe_run(
        eng_id, request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="unknown", attack_family="sqli",
        payload_family="", payload_value="", tool_name="sqlmap", agent_name="va",
        result_status="tested", observed_http_status=200, signal_type="",
        evidence_ref="", notes="", target_host="app.example.com",
        target_path="/shop/p3", target_port=443,
    )

    state_manager.score_application_units(eng_id)

    units = _units_by_prefix(eng_id)
    shop_id = units[("app.example.com", "/shop")]["id"]
    cov = state_manager.list_coverage_items(eng_id)
    assert all(c["application_unit_id"] == shop_id for c in cov), cov
    probes = state_manager.list_probe_runs(eng_id)
    assert {p["application_unit_id"] for p in probes} == {shop_id}, probes


def test_service_id_not_overloaded(client, isolate_settings):
    key = "2026-06-09-100009-svc"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(8):
        _variant(eng_id, url=f"https://svc.example.com/api/r{i}", ctf="json",
                 query={"id": "int"}, status_code=200)
    vid = _variant_id_for(eng_id, "/api/r0")
    _coverage(eng_id, variant_id=vid, attack_family="idor")
    state_manager.score_application_units(eng_id)
    cov = state_manager.list_coverage_items(eng_id)
    row = next(c for c in cov if c["request_variant_id"] == vid)
    assert row["service_id"] is None
    assert row["application_unit_id"] is not None


def test_mark_deep_override_wins(client, isolate_settings):
    key = "2026-06-09-100010-override"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(5):
        _variant(eng_id, url=f"https://mark.example.com/static/f{i}.css",
                 method="GET", ctf="style", status_code=200)
    state_manager.score_application_units(eng_id)
    units = _units_by_prefix(eng_id)
    unit = units[("mark.example.com", "/static")]
    assert unit["deep_required"] is False
    unit_id = unit["id"]

    updated = state_manager.set_app_unit_override(
        eng_id, unit_id, override="mark-deep", reason="known tenant config app",
    )
    assert bool(updated["deep_required"]) is True
    assert updated["override"] == "mark-deep"
    assert updated["override_reason"] == "known tenant config app"

    state_manager.score_application_units(eng_id)
    after = _units_by_prefix(eng_id)[("mark.example.com", "/static")]
    assert after["deep_required"] is True
    assert after["override"] == "mark-deep"

    state_manager.set_app_unit_override(eng_id, unit_id, override="clear-deep")
    state_manager.set_app_unit_override(eng_id, unit_id, override=None)
    reverted = _units_by_prefix(eng_id)[("mark.example.com", "/static")]
    assert reverted["deep_required"] is False
    assert reverted["override"] is None


def test_override_endpoint_round_trips(client, isolate_settings):
    key = "2026-06-09-100011-ep"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(5):
        _variant(eng_id, url=f"https://ep.example.com/x/f{i}", method="GET",
                 ctf="html", status_code=200)
    score = client.post(f"/engagements/{key}/assessment/application-units/score")
    assert score.status_code == 200, score.text
    units = client.get(f"/engagements/{key}/assessment/application-units").json()
    unit_id = units[0]["id"]
    resp = client.patch(
        f"/engagements/{key}/assessment/application-units/{unit_id}",
        json={"override": "mark-deep", "reason": "manual"},
    )
    assert resp.status_code == 200, resp.text
    assert bool(resp.json()["deep_required"]) is True


def test_stale_app_unit_pruned_when_boundaries_change(client, isolate_settings):
    """An app unit whose path-prefix is no longer observed must be
    pruned on re-score, so a stale parent can't double-count child variants by
    containment or block terminal readiness on a unit that no longer exists."""
    from app.services.state_manager import _common

    eng_id = _seed(client, isolate_settings, "2026-06-09-220000-prune")
    for i in range(14):
        _variant(eng_id, url=f"https://a.example.com/api/v2/items/{i}",
                 ctf="json", query={"order_id": "int"}, status_code=200)
    state_manager.score_application_units(eng_id)
    assert _units_by_prefix(eng_id), "precondition: a current unit was scored"

    with _common.get_connection() as conn:
        conn.execute(
            "INSERT INTO assessment_application_units "
            "(engagement_id, host, port_class, path_prefix, deep_required, depth_tier, "
            " structure_score, risk_score, suppressor_score, total_score, confidence, evidence_json) "
            "VALUES (?, 'a.example.com', 'web', '/ghost', 1, 'application', 9, 9, 0, 18, 'high', '{}')",
            (eng_id,),
        )
    assert ("a.example.com", "/ghost") in _units_by_prefix(eng_id)

    state_manager.score_application_units(eng_id)
    after = _units_by_prefix(eng_id)
    assert ("a.example.com", "/ghost") not in after, "stale unit must be pruned"
    assert after, "current units must survive the prune"


def test_clear_override_preserves_surface_only_decisive_unit(client, isolate_settings):
    """A decisive-surface-only unit (object_reference, no request variants) must
    stay deep_required after its manual override is cleared. Clearing recomputes
    the scorer verdict; if it downgraded the unit to thin, the S17 terminal block
    would stop firing on a decisive surface that still demands depth."""
    key = "2026-06-09-220100-clearsurf"
    eng_id = _seed(client, isolate_settings, key)
    _surface(client, key, surface_type="object_reference",
             descriptor="api.example.com /v2/orders/{id}")
    state_manager.score_application_units(eng_id)
    unit = _units_by_prefix(eng_id)[("api.example.com", "/v2")]
    assert unit["deep_required"], "surface-only decisive unit must score deep_required"

    cleared = state_manager.set_app_unit_override(eng_id, unit["id"], override=None, reason="")
    assert cleared["deep_required"], "cleared decisive surface-only unit must stay deep"


def test_decisive_surface_on_observed_host_sibling_prefix_materializes(client, isolate_settings):
    """A decisive surface on an UNOBSERVED sibling prefix of a host that has
    variants elsewhere must still materialize its own deep_required unit. The
    host having variants under /public must not suppress an /admin surface (a
    host-level skip would drop it; the check is containment-based)."""
    key = "2026-06-09-220200-sibling"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(3):
        _variant(eng_id, url=f"https://app.example.com/public/page{i}", ctf="html")
    _surface(client, key, surface_type="object_reference",
             descriptor="app.example.com /admin/users/{id}")
    state_manager.score_application_units(eng_id)
    units = _units_by_prefix(eng_id)
    assert ("app.example.com", "/admin") in units, f"sibling decisive surface must materialize; got {list(units)}"
    assert units[("app.example.com", "/admin")]["deep_required"]


def test_decisive_surface_covered_by_custom_port_unit_no_duplicate(client, isolate_settings):
    """A decisive surface whose host/path is already a scored unit on a NON-standard
    port must not spawn a duplicate 'web' unit (surface attribution is port-agnostic).
    A duplicate would sit untouched and block while probes hit the real port unit."""
    key = "2026-06-09-220300-port"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(3):
        _variant(eng_id, url=f"https://api.example.com:8443/admin/page{i}", ctf="html")
    _surface(client, key, surface_type="auth_entry", descriptor="api.example.com:8443 /admin/login")
    state_manager.score_application_units(eng_id)
    admin = [u for u in state_manager.list_application_units(eng_id)
             if u["host"] == "api.example.com" and u["path_prefix"] == "/admin"]
    assert len(admin) == 1, f"must not duplicate the unit across port classes; got {admin}"
    assert admin[0]["port_class"] != "web"
