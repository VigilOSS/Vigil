"""Wave 6c — the depth ledger (depth-gate §5.3).

These tests seed a deep_required app unit and assert the executable §5.3
predicate table, the Covered definition, the STRUCTURED dedicated-dispatch
match, the disclosure-requires-concrete-signal guard, and the depth_deferral
mechanism — plus the load-bearing doctrine invariant that the ledger is
ADVISORY and NEVER hard-blocks / exits non-zero.

Scenarios:
  * object_reference surface under the unit  -> access-control EXPECTED + block
  * tested `idor` probe mapped to the unit   -> access-control COVERED
  * params present                           -> injection EXPECTED
  * disclosure NOT satisfied by a bare probe; only by a gau-secrets/trufflehog
    (or JS-source) probe tied to the unit's host
  * completed `variant-rotation` dispatch with vuln_classes=idor + matching
    scope_path_prefix AND a covering probe -> dedicated-dispatch satisfied
  * status=completed ALONE (no work evidence) -> NOT satisfied
  * depth_deferral for unit+class -> covered-or-deferred
  * the ledger never hard-blocks / exits non-zero
"""
from __future__ import annotations

import json

from app.services import state_manager
from tests.test_engagements_api import write_engagement


def _seed(client, isolate_settings, key: str, engagement_type: str = "web") -> int:
    eng_dir = write_engagement(isolate_settings["engagements_dir"], key=key)
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["engagement_type"] = engagement_type
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _variant(eng_id, *, url, method="GET", auth="anonymous", ctf="html",
             query=None, body=None, path=None, cookie=None, status_code=200):
    state_manager.record_request_variant(
        eng_id, url=url, method=method, auth_context=auth,
        content_type_family=ctf, query_schema=query or {}, body_schema=body or {},
        path_schema=path or {}, cookie_schema=cookie or {}, header_schema={},
        path_template="", discovery_source="proxy", notes="",
        response_status=status_code, evidence_ref="", observation_payload={},
    )


def _surface(client, key, *, surface_type, descriptor):
    response = client.post(
        f"/engagements/{key}/assessment/surfaces",
        json={"surface_type": surface_type, "target_descriptor": descriptor,
              "source_name": "recon-specialist", "rationale": "live endpoint"},
    )
    assert response.status_code == 201, response.text


def _variant_id_for(eng_id, path):
    for v in state_manager.list_request_variants(eng_id):
        if v["normalized_path"] == path:
            return v["id"]
    raise AssertionError(f"no variant for path {path}")


def _probe(eng_id, *, attack_family, result_status="tested", variant_id=None,
           target_host="", target_path="", tool_name="ffuf", payload_value="x",
           auth_context="anonymous"):
    state_manager.record_probe_run(
        eng_id, request_variant_id=variant_id, service_id=None, coverage_item_id=None,
        auth_context=auth_context, input_slot="query", attack_family=attack_family,
        payload_family="", payload_value=payload_value, tool_name=tool_name,
        agent_name="vulnerability-analyst", result_status=result_status,
        observed_http_status=None, signal_type="", evidence_ref="", notes="",
        target_host=target_host, target_path=target_path, target_port=None,
    )


def _deep_unit(eng_id):
    """Return the (only) deep_required unit's ledger after scoring."""
    state_manager.score_application_units(eng_id)
    ledger = state_manager.depth_ledger(eng_id)
    assert ledger["skipped"] is False
    assert ledger["units"], "expected at least one deep_required unit"
    return ledger


def _by_host_prefix(ledger, host, prefix):
    for u in ledger["units"]:
        if u["unit"]["host"] == host and u["unit"]["path_prefix"] == prefix:
            return u
    raise AssertionError(f"no ledger unit for {host}{prefix}")


def _expected_families(unit_ledger) -> set[str]:
    return {e["family"] for e in unit_ledger["expected"]}


def _covered_families(unit_ledger) -> set[str]:
    return {e["family"] for e in unit_ledger["covered"]}


def _missing_block_families(unit_ledger) -> set[str]:
    return {e["family"] for e in unit_ledger["missing_block"]}


def _seed_giving_unit(client, isolate_settings, key):
    eng_id = _seed(client, isolate_settings, key)
    base = "https://rock.example.com/giving"
    for i in range(8):
        _variant(eng_id, url=f"{base}/page{i}", ctf="html")
    _variant(eng_id, url=f"{base}/account", method="GET", ctf="json",
             query={"user_id": "int"}, auth="user_a", status_code=200)
    _variant(eng_id, url=f"{base}/admin/payouts", method="POST", ctf="json",
             body={"amount": "int"}, auth="user_b", status_code=403)
    _surface(client, key, surface_type="object_reference",
             descriptor="rock.example.com /giving/account")
    _surface(client, key, surface_type="auth_entry",
             descriptor="rock.example.com /giving/login")
    return eng_id


def test_object_reference_makes_access_control_expected_and_block(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200000-ac")
    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")

    expected = _expected_families(unit)
    assert "access-control" in expected
    assert "auth" in expected
    assert "injection" in expected
    assert "disclosure" in expected

    ac = next(e for e in unit["expected"] if e["family"] == "access-control")
    assert ac["block_level"] == "high"
    assert "object_reference" in ac["predicate_fired_on"]

    assert "access-control" in _missing_block_families(unit)
    assert unit["depth_satisfied"] is False


def test_single_identity_idor_probe_not_cross_identity(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200001-cov")
    vid = _variant_id_for(eng_id, "/giving/account")
    _probe(eng_id, attack_family="idor", result_status="tested", variant_id=vid,
           tool_name="idor-fuzzer", auth_context="user_a")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" not in _covered_families(unit)
    assert "access-control" in _missing_block_families(unit)
    ac_missing = next(e for e in unit["missing_block"] if e["family"] == "access-control")
    assert ac_missing["needs"] == "a second identity"
    assert ac_missing["identities_seen"] == ["user_a"]


def test_two_identity_idor_probes_cover_access_control(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200001b-cov")
    vid = _variant_id_for(eng_id, "/giving/account")
    _probe(eng_id, attack_family="idor", result_status="tested", variant_id=vid,
           tool_name="idor-fuzzer", auth_context="user_a", payload_value="a")
    _probe(eng_id, attack_family="idor", result_status="tested", variant_id=vid,
           tool_name="idor-fuzzer", auth_context="user_b", payload_value="b")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" in _covered_families(unit)
    assert "access-control" not in _missing_block_families(unit)
    ac = next(e for e in unit["covered"] if e["family"] == "access-control")
    assert ac["via"] == "cross-identity (user_a, user_b)"


def test_failed_probe_does_not_cover(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200002-fail")
    vid = _variant_id_for(eng_id, "/giving/account")
    _probe(eng_id, attack_family="idor", result_status="no-signal", variant_id=vid)
    _probe(eng_id, attack_family="idor", result_status="blocked", variant_id=vid,
           payload_value="y")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" in _missing_block_families(unit)


def test_disclosure_requires_concrete_signal(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200003-disc")
    vid = _variant_id_for(eng_id, "/giving/account")
    _probe(eng_id, attack_family="info-disclosure", result_status="tested",
           variant_id=vid, tool_name="curl")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "disclosure" not in _covered_families(unit)
    assert "disclosure" in {e["family"] for e in unit["missing_warn"]}

    _probe(eng_id, attack_family="secrets-exposure", result_status="tested",
           target_host="rock.example.com", target_path="/giving",
           tool_name="gau-secrets", payload_value="scan")
    ledger2 = _deep_unit(eng_id)
    unit2 = _by_host_prefix(ledger2, "rock.example.com", "/giving")
    assert "disclosure" in _covered_families(unit2)


def test_dedicated_dispatch_requires_work_evidence(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200004-disp")

    state_manager.record_dispatch(
        eng_id, agent_id="va-1", agent_role="vulnerability-analyst",
        task="rotate IDOR variants", scope_host="rock.example.com",
        scope_path_prefix="/giving", vuln_classes="idor,auth-bypass,sqli",
        status_value="completed",
    )
    state_manager.update_dispatch(eng_id, agent_id="va-1", status_value="completed",
                                  completed_at="2026-06-09T12:00:00Z")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert unit["dedicated_dispatch_satisfied"] is False, \
        "completed-without-evidence must not satisfy the obligation (S7)"

    vid = _variant_id_for(eng_id, "/giving/account")
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_host="rock.example.com", target_path="/giving/account",
           tool_name="idor-rotator", payload_value="rot-a", auth_context="user_a")
    _probe(eng_id, attack_family="idor", result_status="tested",
           target_host="rock.example.com", target_path="/giving/account",
           tool_name="idor-rotator", payload_value="rot-b", auth_context="user_b")
    _probe(eng_id, attack_family="auth-bypass", result_status="tested", variant_id=vid,
           tool_name="auth-tester", payload_value="auth")
    _probe(eng_id, attack_family="sqli", result_status="tested", variant_id=vid,
           tool_name="sqlmap", payload_value="inj")

    ledger2 = _deep_unit(eng_id)
    unit2 = _by_host_prefix(ledger2, "rock.example.com", "/giving")
    assert unit2["dedicated_dispatch_satisfied"] is True
    assert "access-control" in _covered_families(unit2)
    assert not unit2["missing_block"], unit2["missing_block"]
    assert unit2["depth_satisfied"] is True


def test_dispatch_skills_resolve_to_classes(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200005-skill")
    vid = _variant_id_for(eng_id, "/giving/account")
    state_manager.record_dispatch(
        eng_id, agent_id="va-2", agent_role="vulnerability-analyst",
        task="idor pass", scope_host="rock.example.com",
        scope_path_prefix="/giving", skills="idor-testing",
        status_value="completed",
    )
    _probe(eng_id, attack_family="idor", result_status="tested", variant_id=vid,
           tool_name="idor-testing", payload_value="rot-a", auth_context="user_a")
    _probe(eng_id, attack_family="idor", result_status="tested", variant_id=vid,
           tool_name="idor-testing", payload_value="rot-b", auth_context="user_b")

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" in _covered_families(unit)


def test_depth_deferral_covers_block_class(client, isolate_settings):
    key = "2026-06-09-200006-defer"
    eng_id = _seed_giving_unit(client, isolate_settings, key)

    resp = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": "rock.example.com",
                "path_prefix": "/giving",
                "vuln_classes": ["idor", "auth-bypass"],
                "reason": "auth + IDOR deferred to next sprint; documented risk",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text

    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")

    deferred_fams = {e["family"] for e in unit["deferred"]}
    assert "access-control" in deferred_fams
    assert "auth" in deferred_fams
    assert "access-control" not in _missing_block_families(unit)
    assert "auth" not in _missing_block_families(unit)
    ac = next(e for e in unit["covered"] if e["family"] == "access-control")
    assert ac["via"] == "deferral"


def test_depth_deferral_payload_rejects_bad_shape(client, isolate_settings):
    key = "2026-06-09-200007-badshape"
    _seed_giving_unit(client, isolate_settings, key)
    resp = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={"kind": "depth_deferral",
              "payload": {"vuln_classes": ["idor"], "reason": "x"}},
    )
    assert resp.status_code == 422, resp.text
    resp2 = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={"kind": "depth_deferral",
              "payload": {"host": "rock.example.com", "engagement_wide": True,
                          "vuln_classes": ["idor"], "reason": "x"}},
    )
    assert resp2.status_code == 422, resp2.text
    resp3 = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={"kind": "depth_deferral",
              "payload": {"engagement_wide": True, "vuln_classes": [], "reason": "x"}},
    )
    assert resp3.status_code == 422, resp3.text


def test_engagement_wide_depth_deferral_applies(client, isolate_settings):
    key = "2026-06-09-200008-ew"
    eng_id = _seed_giving_unit(client, isolate_settings, key)
    resp = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={"kind": "depth_deferral",
              "payload": {"engagement_wide": True, "vuln_classes": ["idor"],
                          "reason": "access-control out of scope program-wide"}},
    )
    assert resp.status_code == 201, resp.text
    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" not in _missing_block_families(unit)


def test_ledger_is_advisory_never_blocks(client, isolate_settings):
    key = "2026-06-09-200009-advisory"
    eng_id = _seed_giving_unit(client, isolate_settings, key)
    state_manager.score_application_units(eng_id)

    ledger = state_manager.depth_ledger(eng_id)
    assert ledger["skipped"] is False
    assert ledger["summary"]["deep_required"] >= 1
    assert ledger["summary"]["depth_unsatisfied"] >= 1
    assert all(isinstance(u["depth_satisfied"], bool) for u in ledger["units"])

    resp = client.get(f"/engagements/{key}/assessment/application-units/depth-ledger")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["skipped"] is False
    ranks = [u["ev_rank"] for u in body["units"]]
    assert ranks == sorted(ranks, reverse=True)


def test_depth_ledger_web_only(client, isolate_settings):
    eng_id = _seed(client, isolate_settings, "2026-06-09-200010-code", engagement_type="code")
    ledger = state_manager.depth_ledger(eng_id)
    assert ledger["skipped"] is True
    assert ledger["units"] == []


def test_null_target_probe_never_counts(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200011-null")
    _probe(eng_id, attack_family="idor", result_status="tested",
           variant_id=None, target_host="", tool_name="idor-fuzzer")
    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "access-control" in _missing_block_families(unit)


def test_coverage_item_requires_rationale(client, isolate_settings):
    eng_id = _seed_giving_unit(client, isolate_settings, "2026-06-09-200012-cov-rat")
    vid = _variant_id_for(eng_id, "/giving/account")
    state_manager.record_coverage_item(
        eng_id, request_variant_id=vid, service_id=None, auth_context="anonymous",
        input_slot="query", attack_family="sqli", status_value="covered", notes="",
    )
    ledger = _deep_unit(eng_id)
    unit = _by_host_prefix(ledger, "rock.example.com", "/giving")
    assert "injection" in _missing_block_families(unit)

    state_manager.record_coverage_item(
        eng_id, request_variant_id=vid, service_id=None, auth_context="anonymous",
        input_slot="query", attack_family="sqli", status_value="covered",
        notes="fuzzed user_id with sqlmap payloads; parameterized, no injection",
    )
    ledger2 = _deep_unit(eng_id)
    unit2 = _by_host_prefix(ledger2, "rock.example.com", "/giving")
    assert "injection" in _covered_families(unit2)
