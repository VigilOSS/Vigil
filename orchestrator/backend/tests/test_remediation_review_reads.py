from __future__ import annotations

import time
import json

from app.services import remediation
from test_remediation_policy import KEY, _rebased_case


def review_case(client, isolate_settings):
    _repo, path, endpoint, _first, _base = _rebased_case(client, isolate_settings, "git")
    root = isolate_settings["engagements_dir"] / KEY
    item = client.get(endpoint).json()
    assert client.patch(endpoint + "/verification-plan", json={
        "verification_plan": "Account controls", "requirements": [{"kind": "api-test", "methods": ["pytest"]}],
        "alternatives_reason": "Native account controls",
    }).status_code == 200
    evidence = []
    for index in range(3):
        proof = root / "remediation/cases" / str(item["id"]) / f"proof-{index}.txt"
        proof.parent.mkdir(parents=True, exist_ok=True)
        proof.write_text("passed account controls\n" * 200)
        response = client.post(endpoint + "/evidence", json={
            "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest",
            "outcome": "passed", "observed": "Pass", "proved": "Account isolation", "revision": item["worktree_revision"],
            "executed_revision": item["worktree_revision"], "artifact_path": str(proof.relative_to(root)),
        })
        assert response.status_code == 201, response.text
        evidence.append(response.json())
    return root, path, endpoint, item, evidence


def test_diff_reads_review_inputs_once_per_request(client, isolate_settings, monkeypatch):
    _root, _path, endpoint, _item, _evidence = review_case(client, isolate_settings)
    diff_calls = []
    hash_calls = []
    original_diff = remediation._bounded_vcs_diff
    original_hash = remediation._sha256_stream

    def diff(*args, **kwargs):
        diff_calls.append(args)
        return original_diff(*args, **kwargs)

    def digest(source):
        hash_calls.append(source.name)
        return original_hash(source)

    monkeypatch.setattr(remediation, "_bounded_vcs_diff", diff)
    monkeypatch.setattr(remediation, "_sha256_stream", digest)
    start = time.perf_counter()
    response = client.get(endpoint + "/diff")
    elapsed = time.perf_counter() - start
    assert response.status_code == 200, response.text
    print(f"diff fixture: {elapsed * 1000:.1f} ms; VCS diffs={len(diff_calls)}; artifact hashes={len(hash_calls)}")
    assert len(diff_calls) == 3  # committed diff, local diff, dirty-content digest
    assert len(hash_calls) == 3


def test_case_pages_preserve_complete_verification_and_expose_matches(client, isolate_settings):
    _root, _path, endpoint, _item, evidence = review_case(client, isolate_settings)
    for status in ("review", "fixing", "review"):
        assert client.post(endpoint + "/transition", json={"status": status, "actor": "owner", "reason": "Review progress"}).status_code == 200
    response = client.get(endpoint + "?evidence_limit=1&history_limit=1")
    assert response.status_code == 200, response.text
    package = response.json()
    assert len(package["evidence"]) == 1
    assert package["evidence_total"] == 3
    assert len(package["transitions"]) == 1
    assert package["history_total"] == 3
    assert package["review_evidence_ready"]
    assert package["verification_matches"] == [{"requirement_index": 0, "evidence_ids": [item["id"] for item in evidence], "missing": None}]
    page = client.get(endpoint + "/evidence?limit=1&offset=1").json()
    assert page == {"items": [evidence[1]], "total": 3, "limit": 1, "offset": 1}
    assert client.get(endpoint + f"/evidence/{evidence[2]['id']}").json() == evidence[2]
    assert client.get(endpoint + "/evidence/99999").status_code == 404
    assert client.get(endpoint + "/history?limit=1&offset=0").json()["items"] == package["transitions"]
    assert client.get(endpoint + "/evidence?limit=0").status_code == 422


def test_next_review_request_detects_changed_artifact_and_dirty_source(client, isolate_settings):
    root, path, endpoint, _item, evidence = review_case(client, isolate_settings)
    before = client.get(endpoint).json()
    (root / evidence[0]["artifact_path"]).write_text("Altered receipt\n")
    changed = client.get(endpoint).json()
    assert changed["review_digest"] != before["review_digest"]
    assert evidence[0]["id"] not in changed["verification_matches"][0]["evidence_ids"]
    (path / "fix.py").write_text("changed source\n")
    dirty = client.get(endpoint).json()
    assert dirty["review_digest"] != changed["review_digest"]


def test_publication_projection_tracks_review_and_artifact_integrity(client, isolate_settings):
    root, _path, endpoint, item, _evidence = review_case(client, isolate_settings)
    assert client.patch(endpoint + "/baseline", json={"outcome": "runtime_reproduced", "method": "pytest", "proved": "Original account failure"}).status_code == 200
    assert client.post(endpoint + "/transition", json={"status": "review", "actor": "owner", "reason": "Ready"}).status_code == 200
    digest = client.get(endpoint).json()["review_digest"]
    assert client.post(endpoint + "/approve", json={"reviewer": "owner", "expected_review_digest": digest, "approval_method": "ui"}).status_code == 201
    publication = {"url": "https://github.example/acme/app/pull/1", "revision": item["worktree_revision"], "branch": item["worktree_branch"],
                   "base_branch": item["base_branch"], "review_digest": digest, "body_sha256": "a" * 64}
    artifact = root / "remediation/cases" / str(item["id"]) / "publication.json"
    artifact.write_text(json.dumps(publication))
    receipt = client.post(endpoint + "/evidence", json={
        "kind": "pr_publication", "method": "github", "environment": "not_applicable", "command": "create-pr",
        "observed": "Verified draft PR", "proved": "Published reviewed revision", "revision": item["worktree_revision"],
        "artifact_path": str(artifact.relative_to(root)),
    })
    assert receipt.status_code == 201, receipt.text
    package = client.get(endpoint + "?evidence_limit=1").json()
    assert package["pull_request"] == {**publication, "evidence_id": receipt.json()["id"], "current": True}
    assert client.patch(endpoint + "/verification-plan", json={"verification_plan": "Updated owner steps"}).status_code == 200
    assert not client.get(endpoint).json()["pull_request"]["current"]
    artifact.write_text(json.dumps({**publication, "url": "https://github.example/acme/app/pull/2"}))
    assert client.get(endpoint).json()["pull_request"] is None
