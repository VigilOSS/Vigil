"""An engagement ruling can put a review family out of bounds for every file.

A program that accepts no DoS findings should not have its depth floors demand
`algorithmic-dos` effort. The ruling is structured: a current, unresolved
`vuln_family_exclusion` decision naming canonical `vuln_classes` and quoting the
`ruling`. Claims list each excluded family with the ruling, `done` records none
of them at effort 0, the depth floor and the effort harness never measure them,
and a depth_floor trigger already raised on one stops counting as Phase 2B
work. Nothing is read from prose: a malformed decision excludes nothing and is
named. Resolving the decision lifts the exclusion.
"""
from __future__ import annotations

from test_code_analysis_api import (
    _claim_file_for_analysis,
    _claim_file_for_reanalysis,
    _network_input_coverage,
)
from test_code_depth_floor_triggers import _close, _floor_triggers, _seed

_RULING = "Acme program rule 7: DoS and algorithmic-complexity reports are out of scope."


def _exclude(client, key, payload):
    response = client.post(
        f"/engagements/{key}/assessment/dispatch-decisions",
        json={"kind": "vuln_family_exclusion", "payload": payload, "surfaced_to_user": True},
    )
    assert response.status_code in (200, 201), response.text
    return response.json()


def test_an_excluded_family_is_owed_by_no_file_and_names_its_ruling(client, isolate_settings):
    key = "2026-11-15-acme-family-exclusion"
    base, repo, parser = _seed(client, isolate_settings, key)
    first = _claim_file_for_analysis(client, key, int(parser["id"]))
    _close(client, key, first, _network_input_coverage(
        default_effort=80, overrides={"algorithmic-dos": {"effort": 20}}
    ))
    (raised,) = _floor_triggers(client, base)
    assert raised["vuln_class"] == "algorithmic-dos"
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert gate["trigger_summary"]["depth_floor_pending"] == 1

    decision = _exclude(client, key, {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING})

    coverage = client.get(f"{base}/coverage?repo_id={repo['id']}").json()
    assert coverage["trigger_summary"]["depth_floor_pending"] == 0
    assert coverage["trigger_summary"]["depth_floor_ruled_out"] == 1
    assert not any("depth-floor" in reason for reason in coverage["gate"]["reasons"])
    exclusions = coverage["gate"]["family_exclusions"]
    assert [(row["family"], row["decision_id"], row["ruling"]) for row in exclusions["families"]] == [
        ("algorithmic-dos", decision["id"], _RULING),
    ]
    assert exclusions["families"][0]["recorded_by"] == {"agent_id": None, "agent_role": "operator"}
    assert "algorithmic-dos" not in {
        group["family"] for group in (coverage["gate"].get("effort_gaps") or {}).get("groups", [])
    }
    readiness = client.get(f"{base}/readiness?target_phase=verify-variant").json()
    assert "depth_floor_triggers" not in {row["code"] for row in readiness["blockers"]}
    assert readiness["family_exclusions"]["families"][0]["family"] == "algorithmic-dos"

    again = _claim_file_for_reanalysis(
        client, key, int(parser["id"]), reason="Acme recheck under the program ruling"
    )
    assert "algorithmic-dos" not in again["applicable_vuln_classes"]
    assert again["excluded_vuln_classes"] == [{
        "family": "algorithmic-dos", "decision_id": decision["id"], "ruling": _RULING,
        "recorded_at": exclusions["families"][0]["recorded_at"],
        "recorded_by": {"agent_id": None, "agent_role": "operator"},
    }]
    body = _close(client, key, again, [
        entry for entry in _network_input_coverage(default_effort=80)
        if entry["family"] != "algorithmic-dos"
    ])
    assert "unreviewed_families_recorded" not in body
    assert body.get("depth_floor_triggers") is None

    lifted = client.patch(
        f"/engagements/{key}/assessment/dispatch-decisions/{decision['id']}",
        json={"resolved": True, "resolution": {"note": "Acme program now accepts DoS."}},
    )
    assert lifted.status_code == 200, lifted.text
    claim = client.get(f"{base}/analysis-queue/{again['id']}/progress").json()
    assert "algorithmic-dos" in claim["applicable_vuln_classes"]
    assert claim["excluded_vuln_classes"] == []


def test_a_malformed_exclusion_is_refused_and_records_nothing(client, isolate_settings):
    key = "2026-11-15-acme-family-exclusion-invalid"
    base, repo, _parser = _seed(client, isolate_settings, key)
    url = f"/engagements/{key}/assessment/dispatch-decisions"

    refused = client.post(url, json={
        "kind": "vuln_family_exclusion", "payload": {"vuln_classes": ["dos-ish"], "ruling": ""},
        "surfaced_to_user": True,
    })
    assert refused.status_code == 422, refused.text
    assert "dos-ish" in refused.text and "ruling" in refused.text

    unsurfaced = client.post(url, json={
        "kind": "vuln_family_exclusion", "payload": {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING},
    })
    assert unsurfaced.status_code == 422, unsurfaced.text
    assert "surfaced_to_user" in unsurfaced.text

    misspelt = client.post(url, json={
        "kind": "vuln_family_exclusions", "payload": {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING},
        "surfaced_to_user": True,
    })
    assert misspelt.status_code == 422, misspelt.text
    assert "vuln_family_exclusion" in misspelt.json()["detail"]

    rows = client.get(url).json()
    rows = rows.get("decisions", rows) if isinstance(rows, dict) else rows
    assert not [row for row in rows if "family" in str(row.get("kind"))]
    assert client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"].get("family_exclusions") is None


def test_an_exclusion_spelled_another_way_is_stored_under_the_gated_kind(client, isolate_settings):
    key = "2026-11-15-acme-family-exclusion-folded"
    base, _repo, parser = _seed(client, isolate_settings, key)
    response = client.post(f"/engagements/{key}/assessment/dispatch-decisions", json={
        "kind": "Vuln-Family-Exclusion", "payload": {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING},
        "surfaced_to_user": True,
    })
    assert response.status_code == 201, response.text
    assert response.json()["kind"] == "vuln_family_exclusion"
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    assert "algorithmic-dos" not in claim["applicable_vuln_classes"]


def test_an_exclusion_no_longer_surfaced_to_the_user_excludes_nothing_and_is_named(client, isolate_settings):
    key = "2026-11-15-acme-family-exclusion-unsurfaced"
    base, repo, parser = _seed(client, isolate_settings, key)
    decision = _exclude(client, key, {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING})
    withdrawn = client.patch(
        f"/engagements/{key}/assessment/dispatch-decisions/{decision['id']}", json={"surfaced_to_user": False},
    )
    assert withdrawn.status_code == 200, withdrawn.text

    claim = _claim_file_for_analysis(client, key, int(parser["id"]))

    assert "algorithmic-dos" in claim["applicable_vuln_classes"]
    assert claim["excluded_vuln_classes"] == []
    (invalid,) = client.get(
        f"{base}/coverage?repo_id={repo['id']}"
    ).json()["gate"]["family_exclusions"]["invalid_decisions"]
    assert invalid["decision_id"] == decision["id"]
    assert any("surfaced_to_user" in problem for problem in invalid["problems"])


def test_an_exclusion_whose_ruling_is_not_text_is_refused(client, isolate_settings):
    key = "2026-11-15-acme-family-exclusion-ruling-type"
    _seed(client, isolate_settings, key)
    url = f"/engagements/{key}/assessment/dispatch-decisions"

    for ruling in ({"rule": 7}, ["rule 7"], 7, True):
        refused = client.post(url, json={
            "kind": "vuln_family_exclusion",
            "payload": {"vuln_classes": ["algorithmic-dos"], "ruling": ruling},
            "surfaced_to_user": True,
        })
        assert refused.status_code == 422, (ruling, refused.text)
        assert "ruling" in refused.json()["detail"]


def test_a_specialist_cannot_record_an_exclusion(client, isolate_settings):
    # The ruling is a program's or the user's and must be surfaced to the user,
    # which only the operator does; a dispatched specialist recording one is refused
    # by its structured identity.
    key = "2026-11-15-acme-family-exclusion-specialist"
    base, repo, parser = _seed(client, isolate_settings, key)
    registered = client.post(f"/engagements/{key}/assessment/dispatches", json={
        "agent_id": "cvh-acme-1", "agent_role": "code-vuln-hunter", "task": "Acme parser review",
    })
    assert registered.status_code == 201, registered.text

    refused = client.post(f"/engagements/{key}/assessment/dispatch-decisions", json={
        "kind": "vuln_family_exclusion",
        "payload": {"vuln_classes": ["algorithmic-dos"], "ruling": _RULING},
        "surfaced_to_user": True,
        "recorded_by_agent_id": "cvh-acme-1",
    })

    assert refused.status_code == 422, refused.text
    detail = refused.json()["detail"]
    assert "cvh-acme-1" in detail and "code-vuln-hunter" in detail
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    assert "algorithmic-dos" in claim["applicable_vuln_classes"]
