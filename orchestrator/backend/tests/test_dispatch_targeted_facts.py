"""Lane preparation reads selected facts rather than projecting the corpus."""
from test_code_queue_path_scope import _seed


def test_queue_selected_ids_filter_before_pagination_and_include_lane_facts(client, isolate_settings):
    base, _, ids = _seed(client, isolate_settings, "2026-11-08-acme-selected")
    selected = list(ids.values())[-2:]
    response = client.get(base + "/analysis-queue", params=[
        ("item_id", str(selected[0])), ("item_id", str(selected[1])), ("limit", "1")
    ])
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 2
    assert page["count"] == 1
    assert page["items"][0]["id"] in selected
    item = page["items"][0]
    assert item["loc"] == 20
    assert item["applicable_vuln_classes"]
    assert isinstance(item["path_suggested_vuln_classes"], list)


def test_exact_file_paths_do_not_match_nearby_files(client, isolate_settings):
    base, files, _ = _seed(client, isolate_settings, "2026-11-08-acme-exact")
    selected = list(files)[:2]
    response = client.get(base + "/files", params=[("file_path", path) for path in selected])
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 2
    assert {item["file_path"] for item in response.json()["items"]} == set(selected)


def test_finding_count_does_not_project_evidence(client, isolate_settings, monkeypatch):
    from tests.test_report_readiness_evidence_basis import BASE, _recorded
    from app.services.state_manager import proofs
    _recorded(client, isolate_settings, "VA-501")
    def unexpected(*args, **kwargs):
        raise AssertionError("Counting findings must not read their evidence")
    monkeypatch.setattr(proofs, "_serialize_receipts", unexpected)
    response = client.get(BASE + "/findings/count")
    assert response.status_code == 200, response.text
    assert response.json() == {"total": 1}


def test_exact_file_lookup_supports_full_file_path_contract(client, isolate_settings):
    base, _, _ = _seed(client, isolate_settings, "2026-11-08-acme-long-path")
    response = client.get(base + "/files", params={"file_path": "acme/" + "x" * 1500 + ".php"})
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 0


def test_body_file_lookup_accepts_paths_too_large_for_a_query_string(client, isolate_settings):
    base, _, _ = _seed(client, isolate_settings, "2026-11-08-acme-body-facts")
    first = client.get(base + "/files", params={"limit": 1}).json()["items"][0]
    response = client.post(base + "/files/lookup", json={
        "repo_id": first["repo_id"], "file_paths": [first["file_path"], "acme/" + "界" * 3000 + ".php"]
    })
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 1
    assert response.json()["items"][0]["id"] == first["id"]
