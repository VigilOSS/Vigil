from __future__ import annotations

import json
import subprocess

import pytest

from app import db
from app.services import remediation
from test_remediation_policy import KEY, _commit, _rebased_case, _rebase_onto_develop


@pytest.mark.parametrize("vcs", ["git", "jj"])
@pytest.mark.parametrize("kind", ["api-test", "profile-check"])
@pytest.mark.parametrize("rewrite", ["description", "squash"])
def test_identical_tree_rewrite_keeps_evidence_but_requires_new_approval(client, isolate_settings, vcs, kind, rewrite):
    _repo, path, endpoint, _first, _base = _rebased_case(client, isolate_settings, vcs)
    if rewrite == "squash":
        if vcs == "jj":
            subprocess.run(["jj", "-R", str(path), "new", "-m", "Account regression"], check=True, capture_output=True)
            (path / "regression.txt").write_text("Account control\n")
        else:
            _commit(path, "regression.txt", "Account control\n")
        assert client.patch(endpoint, json={"worktree_revision": remediation._vcs.revision(path)}).status_code == 200
    root = isolate_settings["engagements_dir"] / KEY
    item = client.get(endpoint).json()
    old = item["worktree_revision"]
    if kind == "profile-check":
        policy = item["review_policy"]
        policy["remediation"]["check_commands"] = [{"name": "pytest", "command": "pytest", "directory": "."}]
        with db.get_connection() as connection:
            connection.execute("UPDATE remediation_cases SET review_policy_json=? WHERE id=?", (json.dumps(policy), item["id"]))
    assert client.patch(endpoint + "/verification-plan", json={
        "verification_plan": "Check account controls", "requirements": [{"kind": kind, "methods": ["pytest"]}],
        "alternatives_reason": "Native account controls cover the boundary",
    }).status_code == 200
    proof = root / "remediation/cases" / str(item["id"]) / "output.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("2 passed\n")
    registered = client.post(endpoint + "/evidence", json={
        "kind": kind, "method": "pytest", "environment": "local", "command": "pytest",
        "outcome": "passed", "observed": "2 passed", "proved": "Account controls", "revision": old,
        "executed_revision": old, "executed_directory": str(path), "artifact_path": str(proof.relative_to(root)),
    })
    assert registered.status_code == 201, registered.text
    evidence_id = registered.json()["id"]
    assert client.get(endpoint).json()["review_evidence_ready"]
    assert client.patch(endpoint + "/baseline", json={"outcome": "runtime_reproduced", "method": "pytest", "proved": "Original failure"}).status_code == 200
    assert client.post(endpoint + "/transition", json={"status": "review", "actor": "owner", "reason": "Ready"}).status_code == 200
    before = client.get(endpoint).json()
    assert client.post(endpoint + "/approve", json={"reviewer": "owner", "expected_review_digest": before["review_digest"], "approval_method": "ui"}).status_code == 201
    if rewrite == "squash" and vcs == "jj":
        subprocess.run(["jj", "-R", str(path), "squash", "--from", "@", "--into", "@-", "-m", "Fix and regression"], check=True, capture_output=True)
    elif rewrite == "squash":
        subprocess.run(["git", "-C", str(path), "reset", "--soft", "HEAD~2"], check=True)
        subprocess.run(["git", "-C", str(path), "-c", "user.name=Acme Test", "-c", "user.email=test@example.com", "commit", "-qm", "Fix and regression"], check=True)
    elif vcs == "jj":
        subprocess.run(["jj", "-R", str(path), "describe", "-m", "Reviewed fix description"], check=True, capture_output=True)
    else:
        subprocess.run(["git", "-C", str(path), "-c", "user.name=Acme Test", "-c", "user.email=test@example.com", "commit", "--amend", "-qm", "Reviewed fix description"], check=True)
    new = remediation._vcs.revision(path)
    assert new != old
    synced = client.patch(endpoint, json={"worktree_revision": new})
    assert synced.status_code == 200, synced.text
    current = synced.json()
    assert current["review_evidence_ready"], current["review_evidence_missing"]
    assert not current["approval_current"]
    assert current["evidence"][0]["revision"] == old
    assert current["evidence_carries"] == [{"evidence_id": evidence_id, "from_revision": old, "to_revision": new, "tree_id": registered.json()["tree_id"]}]
    assert any(f"evidence carried from {old} to {new}, same tree" in transition["reason"] for transition in current["transitions"])
    # A repeated sync must not produce duplicate history records.
    assert len(client.patch(endpoint, json={"worktree_revision": new}).json()["transitions"]) == len(current["transitions"])
    from vigil_cli.remediation import _render_case_handoff
    handoff = _render_case_handoff(root, current, current["review_policy"])
    context = json.loads(handoff.read_text().split("```json\n", 1)[1].split("\n```", 1)[0])
    assert context["evidence_carries"] == current["evidence_carries"]
    proof.write_text("Evidence changed after registration\n")
    invalidated = client.get(endpoint).json()
    assert not invalidated["review_evidence_ready"]
    assert invalidated["evidence_carries"] == []


@pytest.mark.parametrize("vcs", ["git", "jj"])
def test_same_patch_on_changed_base_does_not_carry_evidence(client, isolate_settings, vcs):
    repo, path, endpoint, _first, _base = _rebased_case(client, isolate_settings, vcs)
    root = isolate_settings["engagements_dir"] / KEY
    item = client.get(endpoint).json()
    assert client.patch(endpoint + "/verification-plan", json={
        "verification_plan": "Check account controls", "requirements": [{"kind": "api-test", "methods": ["pytest"]}],
        "alternatives_reason": "Native account controls",
    }).status_code == 200
    proof = root / "remediation/cases" / str(item["id"]) / "output.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("2 passed\n")
    assert client.post(endpoint + "/evidence", json={
        "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest", "outcome": "passed",
        "observed": "2 passed", "proved": "Account controls", "revision": item["worktree_revision"],
        "executed_revision": item["worktree_revision"], "artifact_path": str(proof.relative_to(root)),
    }).status_code == 201
    _commit(repo, "OTHER.md", "Changed dependency behavior\n")
    _rebase_onto_develop(repo, path, vcs)
    current = client.patch(endpoint, json={"worktree_revision": remediation._vcs.revision(path)}).json()
    assert not current["review_evidence_ready"]
    assert current.get("evidence_carries", []) == []


@pytest.mark.parametrize("restriction", [
    {"runtime_required": True}, {"runtime_revision": "served"}, {"method": "browse"},
    {"method": "stagehand"}, {"environment": "development"}, {"environment": "production"},
])
def test_runtime_proof_remains_bound_to_exact_revision(monkeypatch, restriction):
    row = {"worktree_path": "/acme", "worktree_revision": "new"}
    item = {"revision": "old", "tree_id": "same", "environment": "local", "method": "pytest"}
    runtime_required = restriction.get("runtime_required", False)
    item.update({key: value for key, value in restriction.items() if key != "runtime_required"})
    monkeypatch.setattr(remediation._vcs, "tree_id", lambda *_: "same")
    assert not remediation._evidence_matches_revision(row, item, runtime_required=runtime_required)
    item["revision"] = "new"
    assert remediation._evidence_matches_revision(row, item, runtime_required=runtime_required)


def test_evidence_content_can_be_resolved_from_original_receipt(monkeypatch):
    row = {"worktree_path": "/acme", "worktree_revision": "new"}
    item = {"id": 1, "revision": "old", "tree_id": None, "environment": "local", "method": "pytest",
            "execution": "executed", "executed_revision": "old"}
    monkeypatch.setattr(remediation._vcs, "tree_id", lambda *_: "same")
    assert remediation._evidence_matches_revision(row, item)
    monkeypatch.setattr(remediation._vcs, "tree_id", lambda _path, revision: revision)
    assert not remediation._evidence_matches_revision(row, item)


@pytest.mark.parametrize("restriction", [
    {"environment": "not_applicable"}, {"execution": "reasoned"},
    {"executed_revision": "different"}, {"shared_environment": "shared-tests"},
])
def test_tree_carry_requires_local_execution_without_shared_runtime(monkeypatch, restriction):
    row = {"worktree_path": "/acme", "worktree_revision": "new"}
    item = {"revision": "old", "tree_id": "same", "environment": "local", "method": "pytest",
            "execution": "executed", "executed_revision": "old"}
    item.update(restriction)
    monkeypatch.setattr(remediation._vcs, "tree_id", lambda *_: "same")
    assert not remediation._evidence_matches_revision(row, item)


def test_carry_projection_respects_runtime_requirements_and_failed_evidence(client, isolate_settings):
    _repo, path, endpoint, _first, _base = _rebased_case(client, isolate_settings, "git")
    root = isolate_settings["engagements_dir"] / KEY
    item = client.get(endpoint).json()
    proof = root / "remediation/cases" / str(item["id"]) / "local.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("Acme local output\n")
    assert client.patch(endpoint + "/verification-plan", json={
        "verification_plan": "Verify account behavior against its served runtime",
        "requirements": [{"kind": "api-test", "methods": ["pytest"], "runtime_identity_required": True}],
        "alternatives_reason": "Served behavior needs runtime confirmation",
    }).status_code == 200
    for outcome in ("passed", "failed"):
        response = client.post(endpoint + "/evidence", json={
            "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest",
            "outcome": outcome, "observed": "Local output", "proved": "Local behavior only",
            "revision": item["worktree_revision"], "executed_revision": item["worktree_revision"],
            "executed_directory": str(path), "artifact_path": str(proof.relative_to(root)),
        })
        assert response.status_code == 201, response.text
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Acme Test", "-c", "user.email=test@example.com",
                    "commit", "--amend", "-qm", "Clarify account fix"], check=True)
    current = client.patch(endpoint, json={"worktree_revision": remediation._vcs.revision(path)}).json()
    assert not current["review_evidence_ready"]
    assert current["evidence_carries"] == []
