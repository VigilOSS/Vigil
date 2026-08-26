"""Tests for the single terminal depth backstop.

This is the ONE hard block in the whole system. ``terminal_depth_block`` returns
the units that BLOCK the terminal ``report``/``complete`` edge on the WEB track:
the UNION of (a) high-confidence ``deep_required`` units AND (b) units carrying a
DECISIVE risk surface (auth_entry / object_reference / privileged_write /
api_documentation), intersected with unsatisfied + undeferred + UNTOUCHED.

These tests assert, at the backend block-set level:
  * an untouched high-confidence deep_required unit is in ``blocking``;
  * a decisive-surface unit (auth_entry) blocks even at low/medium structure
    (confidence-INDEPENDENT);
  * the same unit covered by an active depth_deferral does NOT block;
  * an under-observed (low-confidence, non-decisive) unit is WARNed, not blocked;
  * a TOUCHED-but-unsatisfied unit is WARNed, not blocked (started, not finished);
  * code/blue engagements get ``skipped=True`` and ALWAYS-empty ``blocking``;
  * S16 ACCEPTANCE GATE — a surface attributes to its app unit (a unit with an
    object_reference surface under its prefix is correctly in the block-set).

The wiring into ``transition-phase report``/``complete`` (severity="block", the
escape valves, the recon->report walk) is covered by ``test_vigil_cli.py``.
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
           target_host="", target_path="", tool_name="ffuf", payload_value="x"):
    state_manager.record_probe_run(
        eng_id, request_variant_id=variant_id, service_id=None, coverage_item_id=None,
        auth_context="anonymous", input_slot="query", attack_family=attack_family,
        payload_family="", payload_value=payload_value, tool_name=tool_name,
        agent_name="vulnerability-analyst", result_status=result_status,
        observed_http_status=None, signal_type="", evidence_ref="", notes="",
        target_host=target_host, target_path=target_path, target_port=None,
    )


def _coverage_item(eng_id, *, attack_family, variant_id, status_value="pending",
                   notes="gf bucket matched at ingest", auth="anonymous"):
    """Record a gf-style coverage_item flagging a specific vuln CLASS. A
    ``pending`` item marks the class an EXPECTED per-class signal without
    covering it; ``covered`` + notes marks it covered."""
    state_manager.record_coverage_item(
        eng_id, request_variant_id=variant_id, service_id=None,
        auth_context=auth, input_slot="endpoint", attack_family=attack_family,
        status_value=status_value, notes=notes,
    )


def _block(eng_id):
    state_manager.score_application_units(eng_id)
    return state_manager.terminal_depth_block(eng_id)


def _unit_id_for(engagement_id: int, host: str, prefix: str) -> int:
    state_manager.score_application_units(engagement_id)
    for unit in state_manager.list_application_units(engagement_id):
        if unit["host"] == host and unit["path_prefix"] == prefix:
            return int(unit["id"])
    raise AssertionError(f"no application unit for {host}{prefix}")


def _labels(units):
    return {(u["unit"]["host"], u["unit"]["path_prefix"]) for u in units}


def _seed_high_conf_api(client, isolate_settings, key):
    eng_id = _seed(client, isolate_settings, key)
    base = "https://api.example.com/v2"
    for i in range(14):
        _variant(eng_id, url=f"{base}/items/{i}", ctf="json",
                 query={"order_id": "int"}, status_code=200)
    _variant(eng_id, url=f"{base}/items", method="POST", ctf="json",
             body={"name": "str"}, auth="user_a", status_code=201)
    _variant(eng_id, url=f"{base}/items/1", method="DELETE", ctf="json",
             auth="user_b", status_code=403)
    _variant(eng_id, url="https://api.example.com/v1/items", ctf="json",
             query={"id": "int"}, status_code=200)
    return eng_id


def test_high_confidence_deep_required_untouched_blocks(client, isolate_settings):
    eng_id = _seed_high_conf_api(client, isolate_settings, "2026-06-09-210000-hc")
    result = _block(eng_id)
    assert result["skipped"] is False
    blocking = result["blocking"]
    api_units = [b for b in blocking if b["unit"]["host"] == "api.example.com"]
    assert api_units, result
    entry = api_units[0]
    assert entry["block_set_via"] == "high-confidence deep_required"
    assert entry["decisive_surface"] is False
    assert entry["unit"]["confidence"] == "high"
    assert entry["missing_block_families"], "expected unmet block-level classes"


def _seed_decisive_small_unit(client, isolate_settings, key):
    eng_id = _seed(client, isolate_settings, key)
    base = "https://auth.example.com/login"
    _variant(eng_id, url=base, method="GET", ctf="html", status_code=200)
    _variant(eng_id, url=base, method="POST", ctf="form",
             body={"user": "str", "pass": "str"}, status_code=302)
    _surface(client, key, surface_type="auth_entry",
             descriptor="auth.example.com /login")
    _surface(client, key, surface_type="object_reference",
             descriptor="auth.example.com /login/session")
    return eng_id


def test_s16_surface_attributes_to_unit_and_blocks(client, isolate_settings):
    eng_id = _seed_decisive_small_unit(client, isolate_settings, "2026-06-09-210001-s16")
    result = _block(eng_id)
    blocking = result["blocking"]
    assert ("auth.example.com", "/login") in _labels(blocking), result
    entry = next(b for b in blocking if b["unit"]["path_prefix"] == "/login")
    assert entry["block_set_via"] == "decisive risk surface"
    assert entry["decisive_surface"] is True
    assert "access-control" in entry["missing_block_families"]


def test_depth_deferral_removes_unit_from_blocking(client, isolate_settings):
    key = "2026-06-09-210002-defer"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    resp = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": "auth.example.com",
                "path_prefix": "/login",
                "vuln_classes": ["auth-bypass", "idor", "sqli"],
                "reason": "auth + IDOR + injection formally deferred; risk accepted",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text
    result = _block(eng_id)
    assert ("auth.example.com", "/login") not in _labels(result["blocking"]), result
    assert result["deferral_count"] >= 1
    assert ("auth.example.com", "/login") in _labels(result["deferred"])


def test_under_observed_non_decisive_unit_warns_not_blocks(client, isolate_settings):
    key = "2026-06-09-210003-uo"
    eng_id = _seed(client, isolate_settings, key)
    _variant(eng_id, url="https://blog.example.com/about", ctf="html")
    state_manager.score_application_units(eng_id)
    units = state_manager.list_application_units(eng_id)
    unit = next(u for u in units if u["host"] == "blog.example.com")
    state_manager.set_app_unit_override(
        eng_id, unit["id"], override="mark-deep", reason="operator hunch",
    )
    result = state_manager.terminal_depth_block(eng_id)
    assert ("blog.example.com", "/about") not in _labels(result["blocking"])
    assert ("blog.example.com", "/about") in _labels(result["warned_under_observed"])


def test_touched_but_unsatisfied_warns_not_blocks(client, isolate_settings):
    eng_id = _seed_decisive_small_unit(client, isolate_settings, "2026-06-09-210004-touch")
    _probe(eng_id, attack_family="auth-bypass", result_status="tested",
           target_host="auth.example.com", target_path="/login",
           tool_name="auth-tester", payload_value="t")
    result = _block(eng_id)
    assert ("auth.example.com", "/login") not in _labels(result["blocking"]), result
    assert ("auth.example.com", "/login") in _labels(result["warned_under_observed"])


def test_terminal_block_web_only_for_code(client, isolate_settings):
    eng_id = _seed(client, isolate_settings, "2026-06-09-210005-code",
                   engagement_type="code")
    result = state_manager.terminal_depth_block(eng_id)
    assert result["skipped"] is True
    assert result["blocking"] == []


def test_terminal_block_web_only_for_blue(client, isolate_settings):
    eng_id = _seed(client, isolate_settings, "2026-06-09-210006-blue",
                   engagement_type="blue")
    result = state_manager.terminal_depth_block(eng_id)
    assert result["skipped"] is True
    assert result["blocking"] == []


def test_terminal_block_endpoint_is_read_only_200(client, isolate_settings):
    key = "2026-06-09-210007-endpoint"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    state_manager.score_application_units(eng_id)
    resp = client.get(f"/engagements/{key}/assessment/application-units/terminal-block")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["skipped"] is False
    assert ("auth.example.com", "/login") in _labels(body["blocking"])
    assert "deferral_count" in body


def test_no_block_set_units_means_empty_blocking(client, isolate_settings):
    key = "2026-06-09-210008-clean"
    eng_id = _seed(client, isolate_settings, key)
    for i in range(5):
        _variant(eng_id, url=f"https://cdn.example.com/assets/a{i}.png", ctf="image")
    result = _block(eng_id)
    assert result["blocking"] == []
    assert result["skipped"] is False


def test_terminal_block_scores_app_units_even_if_never_scored(client, isolate_settings):
    """The backstop is reached via transition-phase report/complete and
    the GET endpoint, NEITHER of which runs the scorer. It must score-then-read,
    so a web engagement that discovered deep-required-worthy variants but NEVER
    ran `app-unit score` is still caught — otherwise the one hard block silently
    passes on an empty app-units table (false-confidence completion)."""
    eng_id = _seed_high_conf_api(client, isolate_settings, "2026-06-09-210009-unscored")
    assert state_manager.list_application_units(eng_id) == [], "precondition: not yet scored"
    result = state_manager.terminal_depth_block(eng_id)
    assert result["skipped"] is False
    api_units = [b for b in result["blocking"] if b["unit"]["host"] == "api.example.com"]
    assert api_units, f"backstop must score-then-read; got {result}"
    assert state_manager.list_application_units(eng_id), "score must have persisted units"


def test_surface_only_decisive_host_materializes_and_blocks(client, isolate_settings):
    """A decisive surface recorded with NO request_variants (e.g. from
    source analysis) must still materialize a deep_required unit so the S17
    confidence-independent terminal block fires — otherwise report/complete could
    pass without forcing the depth a decisive surface demands."""
    key = "2026-06-09-210010-surfonly"
    eng_id = _seed(client, isolate_settings, key)
    _surface(client, key, surface_type="object_reference",
             descriptor="api.example.com /v2/orders/{id}")
    result = _block(eng_id)
    assert result["skipped"] is False
    units = [b for b in result["blocking"] if b["unit"]["host"] == "api.example.com"]
    assert units, f"surface-only decisive host must block; got {result}"
    entry = units[0]
    assert entry["decisive_surface"] is True
    assert entry["block_set_via"] == "decisive risk surface"
    assert "access-control" in entry["missing_block_families"]


# ---------------------------------------------------------------------------
# Coverage-grain unbundle (ADR 0012): the CLASS-LEVEL block for decisive /
# high-confidence units. `signal_classes_uncovered` — a specific BLOCK_HIGH
# CLASS flagged (via gf coverage_items) but never class-specifically covered —
# is promoted to a hard block for decisive units, EVEN when a sibling class
# covered the family (the single-class blind spot the family gate misses) and
# even when the unit is otherwise touched. Non-decisive units keep family-level
# behaviour. The escape valves (covering probe, depth_deferral, --force) stay.
# ---------------------------------------------------------------------------


def test_decisive_unit_uncovered_block_high_class_blocks_at_report(client, isolate_settings):
    """A DECISIVE unit with a `sqli` (injection/BLOCK_HIGH) class flagged but only
    a sibling-class (`ssti`) probe — which covers the injection FAMILY and marks
    the unit touched — now HARD-BLOCKS on the class. Under the old family gate
    this touched unit only WARNed; the class grain is the whole point."""
    key = "2026-07-05-220000-classblock"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    vid = _variant_id_for(eng_id, "/login")
    _coverage_item(eng_id, attack_family="sqli", variant_id=vid)
    _probe(eng_id, attack_family="ssti", result_status="tested",
           target_host="auth.example.com", target_path="/login",
           tool_name="tplmap", payload_value="ssti")

    result = _block(eng_id)
    label = ("auth.example.com", "/login")
    assert label in _labels(result["blocking"]), result
    assert label not in _labels(result["warned_under_observed"]), result
    entry = next(b for b in result["blocking"] if b["unit"]["path_prefix"] == "/login")
    assert entry["block_grain"] == "class"
    assert "sqli" in entry["uncovered_classes"]
    # sanity: the injection FAMILY is NOT what blocks — a sibling probe covered it.
    assert "injection" not in entry.get("missing_block_families", [])


def test_non_decisive_unit_same_class_gap_does_not_block(client, isolate_settings):
    """REGRESSION GUARD for 'decisive only': a NON-decisive, low-confidence unit
    with the SAME uncovered BLOCK_HIGH class gap is WARNed, never blocked. If this
    ever flips to blocking, the decisive-only invariant is broken."""
    key = "2026-07-05-220001-nondecisive"
    eng_id = _seed(client, isolate_settings, key)
    _variant(eng_id, url="https://blog.example.com/about", ctf="html")
    state_manager.score_application_units(eng_id)
    unit = next(u for u in state_manager.list_application_units(eng_id)
                if u["host"] == "blog.example.com")
    state_manager.set_app_unit_override(
        eng_id, unit["id"], override="mark-deep", reason="operator hunch")
    vid = _variant_id_for(eng_id, "/about")
    _coverage_item(eng_id, attack_family="sqli", variant_id=vid)

    result = state_manager.terminal_depth_block(eng_id)
    label = ("blog.example.com", "/about")
    assert label not in _labels(result["blocking"]), result
    assert label in _labels(result["warned_under_observed"]), result
    warn = next(w for w in result["warned_under_observed"]
                if w["unit"]["path_prefix"] == "/about")
    # the class gap is still surfaced (advisory) on the warned entry, not blocked.
    assert "sqli" in (warn.get("signal_classes_uncovered") or [])


def test_depth_deferral_clears_class_block(client, isolate_settings):
    """A `depth_deferral` naming the class removes it from
    `signal_classes_uncovered`, clearing the class block (same valve as family)."""
    key = "2026-07-05-220002-classdefer"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    vid = _variant_id_for(eng_id, "/login")
    _coverage_item(eng_id, attack_family="sqli", variant_id=vid)
    _probe(eng_id, attack_family="ssti", result_status="tested",
           target_host="auth.example.com", target_path="/login",
           tool_name="tplmap", payload_value="ssti")
    assert ("auth.example.com", "/login") in _labels(_block(eng_id)["blocking"])

    resp = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={
            "kind": "depth_deferral",
            "payload": {
                "host": "auth.example.com", "path_prefix": "/login",
                "vuln_classes": ["sqli"],
                "reason": "injection formally deferred on login; risk accepted",
                "approved_by": "operator",
            },
            "surfaced_to_user": True,
        },
    )
    assert resp.status_code == 201, resp.text
    result = _block(eng_id)
    assert ("auth.example.com", "/login") not in _labels(result["blocking"]), result
    assert result["deferral_count"] >= 1


def test_block_warn_class_never_class_blocks(client, isolate_settings):
    """A BLOCK_WARN-family class (`info-disclosure` → disclosure) flagged as a
    per-class signal must NEVER enter the hard set — even for a decisive unit.
    `signal_classes_uncovered` is restricted to BLOCK_HIGH classes, so the unit
    never produces a `block_grain='class'` entry from the warn class."""
    key = "2026-07-05-220003-warnclass"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    vid = _variant_id_for(eng_id, "/login")
    _coverage_item(eng_id, attack_family="info-disclosure", variant_id=vid)
    _probe(eng_id, attack_family="ssti", result_status="tested",
           target_host="auth.example.com", target_path="/login",
           tool_name="tplmap", payload_value="ssti")

    state_manager.score_application_units(eng_id)
    ledger = state_manager.depth_ledger(eng_id)
    unit = next(u for u in ledger["units"] if u["unit"]["path_prefix"] == "/login")
    assert "info-disclosure" not in (unit.get("signal_classes_uncovered") or [])

    result = state_manager.terminal_depth_block(eng_id)
    class_blocks = [b for b in result["blocking"] if b.get("block_grain") == "class"]
    assert not any(b["unit"]["path_prefix"] == "/login" for b in class_blocks), result


def test_self_attested_class_signal_never_covers_class(client, isolate_settings):
    """ANTI-SELF-ATTESTATION: neither an evidence-FREE `covered` coverage_item nor
    a non-covering (`attempted`) probe clears the class — only a whitelisted
    covering `result_status` (`tested`/`signal`) or an evidence-BEARING
    coverage_item counts. `status='covered'`/`completed` claims alone never count,
    so the unit still class-blocks on `sqli`."""
    key = "2026-07-05-220004-selfattested"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    vid = _variant_id_for(eng_id, "/login")
    # `covered` but with NO evidence/notes — a self-attested claim that must not
    # count (also makes `sqli` an EXPECTED per-class signal).
    _coverage_item(eng_id, attack_family="sqli", variant_id=vid,
                   status_value="covered", notes="")
    # a probe that merely `attempted` (not `tested`/`signal`) — must not cover.
    _probe(eng_id, attack_family="sqli", result_status="attempted",
           target_host="auth.example.com", target_path="/login",
           tool_name="sqlmap", payload_value="inj")

    result = _block(eng_id)
    entry = next((b for b in result["blocking"]
                  if b["unit"]["path_prefix"] == "/login"), None)
    assert entry is not None, result
    assert entry["block_grain"] == "class"
    assert "sqli" in entry["uncovered_classes"]


def test_class_specific_covering_probe_clears_class_block(client, isolate_settings):
    """POSITIVE path: a class-specific `sqli` probe with a covering status
    (`tested`) drains the class, so the unit no longer class-blocks."""
    key = "2026-07-05-220005-classcover"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    vid = _variant_id_for(eng_id, "/login")
    _coverage_item(eng_id, attack_family="sqli", variant_id=vid)
    _probe(eng_id, attack_family="sqli", result_status="tested",
           target_host="auth.example.com", target_path="/login",
           tool_name="sqlmap", payload_value="inj")

    result = _block(eng_id)
    class_blocks = [b for b in result["blocking"]
                    if b.get("block_grain") == "class"
                    and b["unit"]["path_prefix"] == "/login"]
    assert not class_blocks, result


def test_self_attested_handoff_does_not_downgrade_block(client, isolate_settings):
    """A completed dispatch covering the unit plus ONLY a bare handoff summary
    (no covering probe, no finding) must NOT mark the unit 'touched' — the
    decisive unit stays in `blocking`. A self-attested handoff cannot defeat
    the one hard block (S7)."""
    key = "2026-06-09-210011-handoff"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    unit_id = _unit_id_for(eng_id, "auth.example.com", "/login")
    state_manager.record_dispatch(
        eng_id, agent_id="va-x", agent_role="vulnerability-analyst",
        task="review the login area", application_unit_id=unit_id,
        vuln_classes="idor", status_value="completed",
    )
    state_manager.update_dispatch(eng_id, agent_id="va-x", status_value="completed",
                                  completed_at="2026-06-09T12:00:00Z")
    state_manager.record_handoff(
        eng_id, agent_id="va-x", agent_role="vulnerability-analyst",
        summary="looked at the login flow; nothing obvious",
    )
    result = _block(eng_id)
    assert ("auth.example.com", "/login") in _labels(result["blocking"]), result
    assert ("auth.example.com", "/login") not in _labels(result["warned_under_observed"])


def _probe_as(eng_id, *, attack_family, auth_context, target_path="/login"):
    state_manager.record_probe_run(
        eng_id, request_variant_id=None, service_id=None, coverage_item_id=None,
        auth_context=auth_context, input_slot="query", attack_family=attack_family,
        payload_family="", payload_value="p", tool_name="curl",
        agent_name="vulnerability-analyst", result_status="tested",
        observed_http_status=None, signal_type="", evidence_ref="ev.txt", notes="",
        target_host="auth.example.com", target_path=target_path, target_port=None,
    )


def _cover_all_block_families(eng_id):
    """Cover every BLOCK_HIGH family the decisive /login unit expects, using
    recorded probe evidence only. access-control needs two distinct identities."""
    _probe_as(eng_id, attack_family="sqli", auth_context="anonymous")
    _probe_as(eng_id, attack_family="auth-bypass", auth_context="anonymous")
    _probe_as(eng_id, attack_family="idor", auth_context="user_a")
    _probe_as(eng_id, attack_family="idor", auth_context="user_b")


def test_undeclared_vuln_classes_clear_the_dedicated_dispatch_obligation(
    client, isolate_settings
):
    """A dispatch that declares NO `vuln_classes` but whose probes covered every
    block-level family satisfies the dedicated-dispatch obligation.

    Coverage is read from recorded probe `attack_family`, never from what a
    dispatch declared about itself, so an open-objective dispatch that never
    named a vulnerability class up front is neither blocked nor flagged as an
    unmet obligation.
    """
    key = "2026-07-27-000001-undeclared"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    unit_id = _unit_id_for(eng_id, "auth.example.com", "/login")
    state_manager.record_dispatch(
        eng_id, agent_id="va-undeclared", agent_role="vulnerability-analyst",
        task="hunt the login surface; prove any attacker outcome you find",
        application_unit_id=unit_id,
        status_value="completed",
    )
    state_manager.update_dispatch(eng_id, agent_id="va-undeclared",
                                  status_value="completed",
                                  completed_at="2026-07-27T12:00:00Z")
    _cover_all_block_families(eng_id)

    result = _block(eng_id)
    label = ("auth.example.com", "/login")
    assert label not in _labels(result["blocking"]), result
    unmet = [w for w in result["warned_under_observed"]
             if "dedicated-dispatch obligation" in (w.get("reason") or "")]
    assert label not in _labels(unmet), result


def test_dedicated_dispatch_obligation_still_needs_work_evidence(
    client, isolate_settings
):
    """A completed dispatch with declared classes but NO probe and NO finding
    does not satisfy the obligation — declaring classes is self-attestation, and
    the unit still owes durable evidence that the work happened (S7)."""
    key = "2026-07-27-000002-noevidence"
    eng_id = _seed_decisive_small_unit(client, isolate_settings, key)
    unit_id = _unit_id_for(eng_id, "auth.example.com", "/login")
    state_manager.record_dispatch(
        eng_id, agent_id="va-talker", agent_role="vulnerability-analyst",
        task="cover the login surface", application_unit_id=unit_id,
        vuln_classes="sqli,idor,auth-bypass",
        status_value="completed",
    )
    state_manager.update_dispatch(eng_id, agent_id="va-talker",
                                  status_value="completed",
                                  completed_at="2026-07-27T12:00:00Z")

    result = _block(eng_id)
    assert ("auth.example.com", "/login") in _labels(result["blocking"]), result
