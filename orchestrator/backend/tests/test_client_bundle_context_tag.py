"""A `client-bundle` context tag makes the server-only families optional.

A browser bundle reaches no server file system, makes no server-side request
and parses no server XML, so on paper its slot types owe families it cannot
hold: a closeout either scored them for nothing or left them as depth-floor
triggers. The architect records `client-bundle` on the classification; the
server-only families (`CLIENT_BUNDLE_OPTIONAL_FAMILIES`) then stop being
required and are listed as optional, and the browser families it does owe stay
required. An untagged file keeps owing every family, so nothing narrows
without the tag.
"""
from __future__ import annotations

from app.services import code_analysis
from app.services.state_manager.taxonomy_bridge import vuln_taxonomy
from test_code_analysis_api import (
    _claim_file_for_analysis,
    _close_queue_item,
    _publish_structural_callables,
    _record_fixture_source_receipt,
    _seed_repo_files,
)

_BUNDLE_SLOTS = ["NETWORK-INPUT", "URL-COMPONENT", "SERIALIZED-DATA", "CALLBACK-DATA"]
_SERVER_ONLY = {
    "ssrf", "file-upload", "deserialization", "path-traversal", "race-condition",
    "algorithmic-dos",
}
_BROWSER = {
    "web-app-injection", "open-redirect", "prototype-pollution", "secrets-exposure",
    "injection",
}


def _families(context_tags):
    return (
        set(code_analysis._applicable_families_for_file(
            _BUNDLE_SLOTS, language="javascript", context_tags=context_tags
        )),
        set(code_analysis._optional_families_for_file(
            _BUNDLE_SLOTS, language="javascript", context_tags=context_tags
        )),
    )


def test_a_client_bundle_owes_the_browser_families_and_not_the_server_ones():
    required, optional = _families(["client-bundle"])

    assert _BROWSER <= required
    assert not required & _SERVER_ONLY
    assert optional == _SERVER_ONLY
    # Families a browser can still hold stay required.
    assert {"web-app-auth", "auth-bypass", "error-handling", "type-confusion"} <= required


def test_an_untagged_bundle_keeps_owing_every_family():
    required, optional = _families([])

    assert _SERVER_ONLY <= required
    assert optional == set()


def test_another_tag_on_a_client_bundle_does_not_restore_a_server_only_family():
    required, optional = _families(["client-bundle", "value-transfer", "authentication"])

    assert "business-logic" in required and "web-app-auth" in required
    assert {"race-condition", "rate-limit"} <= optional
    assert not required & optional


def test_a_bundle_with_no_slot_type_still_owes_browser_injection():
    """String evaluation, wrong-context escaping and formula cells run in the browser."""
    required = set(code_analysis._applicable_families_for_file(
        [], language="javascript", context_tags=["client-bundle"]
    ))

    assert "injection" in required


def test_a_bundle_tagged_response_data_keeps_owing_data_exposure():
    """A bundle that queries its data store directly selects the records itself."""
    with_data, without_data = (
        set(code_analysis._applicable_families_for_file(
            ["NETWORK-INPUT"], language="javascript", context_tags=tags
        ))
        for tags in (["client-bundle", "response-data"], ["client-bundle"])
    )
    assert "web-app-data-exposure" in with_data
    assert "web-app-data-exposure" not in without_data
    assert "web-app-data-exposure" not in code_analysis._optional_families_for_file(
        ["NETWORK-INPUT"], language="javascript",
        context_tags=["client-bundle", "response-data"],
    )


def test_every_optional_family_is_canonical_and_says_why():
    for family, reason in code_analysis.CLIENT_BUNDLE_OPTIONAL_FAMILIES.items():
        assert family in vuln_taxonomy.VULN_CLASSES, family
        assert reason.strip(), family
    assert not set(code_analysis.CLIENT_BUNDLE_OPTIONAL_FAMILIES) & set(
        code_analysis.CONTEXT_TAG_VULN_CLASSES[code_analysis.CLIENT_BUNDLE_CONTEXT_TAG]["all"]
    )


def _seed_bundle(client, isolate_settings, key, context_tags):
    repo, files = _seed_repo_files(client, isolate_settings, key, repo_key=f"{key}-repo")
    parser = next(f for f in files if f["file_path"] == "src/parser.py")
    helper = next(f for f in files if f["file_path"] == "src/helpers.py")
    classified = client.post(f"/engagements/{key}/assessment/code/files/bulk-classify", json={
        "classifications": [
            {
                "file_id": int(parser["id"]), "classification": "critical", "role": "bundle",
                "slot_types": _BUNDLE_SLOTS, "analysis_priority": 90,
                "language": "javascript", "context_tags": context_tags,
            },
            {
                "file_id": int(helper["id"]), "classification": "low", "role": "helper",
                "slot_types": [], "analysis_priority": 10, "context_tags": [],
            },
        ]
    })
    assert classified.status_code == 200, classified.text
    _publish_structural_callables(client, key, int(repo["id"]), files, {})
    return f"/engagements/{key}/assessment/code", repo, parser


def _close_browser_families_only(client, key, base, parser):
    claim = _claim_file_for_analysis(client, key, int(parser["id"]))
    claim["_receipt_id"] = _record_fixture_source_receipt(client, key, claim)["id"]
    closed = _close_queue_item(
        client, key, claim, disposition="clean", notes="Acme bundle review",
        cwe_coverage=[
            {"family": family, "effort": 80}
            for family in sorted(set(claim["applicable_vuln_classes"]) - _SERVER_ONLY)
        ],
    )
    assert closed.status_code == 200, closed.text
    floor = [
        row["vuln_class"]
        for row in client.get(f"{base}/triggers?status=pending").json()["items"]
        if row["origin"] == "depth_floor"
    ]
    return claim, floor


def test_a_tagged_bundle_closes_without_server_only_depth_floor_triggers(
    client, isolate_settings
):
    key = "2026-11-14-acme-client-bundle"
    base, repo, parser = _seed_bundle(client, isolate_settings, key, ["client-bundle"])

    claim, floor = _close_browser_families_only(client, key, base, parser)

    assert _BROWSER <= set(claim["applicable_vuln_classes"])
    assert set(claim["optional_vuln_classes"]) == _SERVER_ONLY
    assert floor == []
    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    gap_families = {group["family"] for group in (gate.get("effort_gaps") or {}).get("groups", [])}
    assert not gap_families & _SERVER_ONLY


def test_an_untagged_bundle_still_owes_the_server_only_families(client, isolate_settings):
    key = "2026-11-14-acme-client-bundle-untagged"
    base, _repo, parser = _seed_bundle(client, isolate_settings, key, [])

    claim, floor = _close_browser_families_only(client, key, base, parser)

    assert claim["optional_vuln_classes"] == []
    assert _SERVER_ONLY <= set(floor)


def test_coverage_and_readiness_name_optional_families_and_server_signals(
    client, isolate_settings
):
    key = "2026-11-15-acme-client-bundle-advisories"
    base, repo, parser = _seed_bundle(client, isolate_settings, key, ["client-bundle"])
    # The helper is python: a client-bundle tag on it contradicts its language.
    helper = next(
        row for row in client.get(f"{base}/files?limit=50").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    tagged = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": int(helper["id"]), "classification": "low", "role": "helper",
        "slot_types": [], "analysis_priority": 10, "context_tags": ["client-bundle"],
    }]})
    assert tagged.status_code == 200, tagged.text

    gate = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"]
    optional = gate["optional_families"]
    assert optional["files"] >= 1 and "src/parser.py" in optional["sample_paths"]
    assert set(optional["by_family"]) == _SERVER_ONLY
    conflicts = gate["client_bundle_conflicts"]
    assert conflicts["count"] == 1 and conflicts["omitted"] == 0
    assert conflicts["sample"] == [
        {"file_path": "src/helpers.py", "signals": ["language python"]}
    ]
    assert not any("client-bundle" in reason for reason in gate["reasons"])
    listed = client.get(
        f"{base}/files?client_bundle_conflict=true&repo_id={repo['id']}"
    ).json()
    assert [row["file_path"] for row in listed["items"]] == ["src/helpers.py"]
    assert {
        row["file_path"]
        for row in client.get(f"{base}/files?context_tag=client-bundle").json()["items"]
    } == {"src/parser.py", "src/helpers.py"}

    readiness = client.get(f"{base}/readiness?target_phase=hunt").json()
    assert readiness["client_bundle_conflicts"]["count"] == 1
    assert readiness["optional_families"]["by_family"] == optional["by_family"]


def test_a_bundle_whose_tags_or_slot_types_say_server_code_is_named(
    client, isolate_settings
):
    """Server-only tags and slot types are structured signals the bundle tag may be wrong."""
    key = "2026-11-15-acme-client-bundle-server-signals"
    base, repo, parser = _seed_bundle(
        client, isolate_settings, key, ["client-bundle", "value-transfer"]
    )
    helper = next(
        row for row in client.get(f"{base}/files?limit=50").json()["items"]
        if row["file_path"] == "src/helpers.py"
    )
    tagged = client.post(f"{base}/files/bulk-classify", json={"classifications": [{
        "file_id": int(helper["id"]), "classification": "high", "role": "helper",
        "slot_types": ["CMD-ARGUMENT"], "analysis_priority": 60,
        "language": "typescript", "context_tags": ["client-bundle", "one-time-secret"],
    }]})
    assert tagged.status_code == 200, tagged.text

    conflicts = client.get(f"{base}/coverage?repo_id={repo['id']}").json()["gate"][
        "client_bundle_conflicts"
    ]

    assert conflicts["count"] == 2
    signals = {row["file_path"]: row["signals"] for row in conflicts["sample"]}
    assert signals == {
        "src/parser.py": ["tag value-transfer"],
        "src/helpers.py": ["tag one-time-secret", "slot type CMD-ARGUMENT"],
    }
    listed = client.get(
        f"{base}/files?client_bundle_conflict=true&repo_id={repo['id']}"
    ).json()
    assert {row["file_path"] for row in listed["items"]} == set(signals)
