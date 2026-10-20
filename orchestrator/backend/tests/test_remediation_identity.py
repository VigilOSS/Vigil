from __future__ import annotations

from app import db
from test_remediation_api import BASE, _engagement


def test_report_without_external_key_gets_case_identity(client, isolate_settings):
    _engagement(isolate_settings)
    payload = {"source_type": "report", "title": "Potential account scope bug", "snapshot": {"description": "Example report"}}
    first = client.post(f"{BASE}/cases", json=payload)
    assert first.status_code == 201, first.text
    case = first.json()
    assert case["source_key"] == f"case-{case['id']}"
    assert case["external_key"] is None
    second = client.post(f"{BASE}/cases", json=payload)
    assert second.status_code == 201, second.text
    assert second.json()["id"] != case["id"]


def test_external_identity_is_separate_unique_and_compare_and_swap(client, isolate_settings):
    _engagement(isolate_settings)
    payload = {"source_type": "manual", "title": "Potential account scope bug", "snapshot": {"description": "Keep this report"}}
    case = client.post(f"{BASE}/cases", json=payload).json()
    endpoint = f"{BASE}/cases/{case['id']}/identity"
    identity = {"expected_external_provider": None, "expected_external_key": None,
                "external_provider": "acme-tracker", "external_key": "RISK/123"}
    updated = client.post(endpoint, json=identity)
    assert updated.status_code == 200, updated.text
    assert updated.json()["source_key"] == case["source_key"]
    assert updated.json()["snapshot"] == case["snapshot"]
    assert updated.json()["review_digest"] != case["review_digest"]
    assert client.post(endpoint, json=identity).status_code == 200
    assert client.post(endpoint, json={**identity, "external_key": "RISK/456"}).status_code == 409
    other = client.post(f"{BASE}/cases", json=payload).json()
    assert client.post(f"{BASE}/cases/{other['id']}/identity", json=identity).status_code == 409
    assert client.post(endpoint, json={"external_provider": "acme-tracker", "external_key": "RISK/456"}).status_code == 422
    assert client.post(endpoint, json={**identity, "external_key": None}).status_code == 422
    summary = next(item for item in client.get(f"{BASE}/cases").json() if item["id"] == case["id"])
    assert summary["external_provider"] == "acme-tracker"


def test_identity_cannot_change_after_publication(client, isolate_settings):
    _engagement(isolate_settings)
    case = client.post(f"{BASE}/cases", json={"source_type": "report", "title": "Example bug", "snapshot": {}}).json()
    with db.get_connection() as connection:
        connection.execute("INSERT INTO remediation_evidence(case_id,kind,method,environment,observed,proved) VALUES(?,?,?,?,?,?)",
                           (case["id"], "pr_publication", "gh", "local", "Published", "Historical receipt"))
    response = client.post(f"{BASE}/cases/{case['id']}/identity", json={
        "expected_external_provider": None, "expected_external_key": None,
        "external_provider": "tracker", "external_key": "BUG-12"})
    assert response.status_code == 409, response.text


def _workspace_case(client, isolate_settings):
    import json
    import subprocess

    root = _engagement(isolate_settings)
    repo = isolate_settings["data_dir"] / "acme-repository"
    repo.mkdir()

    def git(*args, directory=repo):
        return subprocess.check_output(["git", "-C", str(directory), *args], text=True).strip()

    git("init", "-q", "--initial-branch=main")
    git("-c", "user.name=Acme", "-c", "user.email=maintainer@example.com", "commit", "--allow-empty", "-qm", "Base")
    (root / "PROJECT.md").write_text('+++\nrepository = ' + json.dumps(str(repo)) + '\n+++\n')
    response = client.post(f"{BASE}/cases", json={"source_type": "report", "title": "Example bug", "snapshot": {}})
    assert response.status_code == 201, response.text
    case = response.json()
    path = repo.parent / f"case-{case['id']}"
    git("worktree", "add", "-qb", "remediation/provisional", str(path))
    revision = git("rev-parse", "HEAD", directory=path)
    response = client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(path), "worktree_branch": "remediation/provisional", "worktree_revision": revision})
    assert response.status_code == 200, response.text
    return response.json(), path, git


def test_branch_finalization_preserves_workspace_revision_and_is_retryable(client, isolate_settings):
    case, path, git = _workspace_case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{case['id']}/finalize-branch"
    payload = {"old_branch": case["worktree_branch"], "new_branch": "fix/BUG-123", "revision": case["worktree_revision"]}
    assert client.post(endpoint, json=payload).status_code == 409
    git("branch", "-m", payload["new_branch"], directory=path)
    updated = client.post(endpoint, json=payload)
    assert updated.status_code == 200, updated.text
    value = updated.json()
    assert value["worktree_branch"] == payload["new_branch"]
    assert value["worktree_revision"] == case["worktree_revision"]
    assert value["worktree_path"] == case["worktree_path"]
    assert value["base_revision"] == case["base_revision"]
    assert value["review_digest"] != case["review_digest"]
    assert client.post(endpoint, json=payload).json()["review_digest"] == value["review_digest"]
    assert client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_branch": "fix/other"}).status_code == 409
    (path / "uncommitted.txt").write_text("Changed content")
    assert client.post(endpoint, json=payload).status_code == 409


def test_identity_clearing_does_not_restore_original_review_digest(client, isolate_settings):
    _engagement(isolate_settings)
    case = client.post(f"{BASE}/cases", json={"source_type": "report", "title": "Example bug", "snapshot": {}}).json()
    endpoint = f"{BASE}/cases/{case['id']}/identity"
    response = client.post(endpoint, json={"expected_external_provider": None, "expected_external_key": None,
                                          "external_provider": "tracker", "external_key": "BUG-123"})
    assert response.status_code == 200, response.text
    cleared = client.post(endpoint, json={"expected_external_provider": "tracker", "expected_external_key": "BUG-123",
                                         "external_provider": None, "external_key": None})
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["review_digest"] != case["review_digest"]


def test_generated_source_collision_skips_reserved_key_and_allows_later_imports(client, isolate_settings):
    _engagement(isolate_settings)
    payload = {"source_type": "manual", "title": "Example bug", "snapshot": {}}
    first = client.post(f"{BASE}/cases", json={**payload, "source_key": "case-2"})
    assert first.status_code == 201, first.text
    assert first.json()["id"] == 1
    response = client.post(f"{BASE}/cases", json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["source_key"] == "case-3"
    subsequent = client.post(f"{BASE}/cases", json=payload)
    assert subsequent.status_code == 201, subsequent.text
    assert subsequent.json()["source_key"] == "case-4"
    assert len(client.get(f"{BASE}/cases").json()) == 3


def test_finalization_rejects_wrong_revision_stale_cas_and_published_receipt(client, isolate_settings):
    case, path, git = _workspace_case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{case['id']}/finalize-branch"
    payload = {"old_branch": case["worktree_branch"], "new_branch": "fix/BUG-123", "revision": case["worktree_revision"]}
    git("branch", "-m", payload["new_branch"], directory=path)
    assert client.post(endpoint, json={**payload, "revision": "0" * 40}).status_code == 409
    assert client.post(endpoint, json={**payload, "old_branch": "unrelated"}).status_code == 409
    with db.get_connection() as connection:
        connection.execute("INSERT INTO remediation_evidence(case_id,kind,method,environment,observed,proved) VALUES(?,?,?,?,?,?)",
                           (case["id"], "pr_publication", "gh", "local", "Old publication", "Receipt"))
    assert client.post(endpoint, json=payload).status_code == 409


def test_ticket_requirement_is_generic_and_preserves_provider_backed_cases(client, isolate_settings):
    import json
    from test_remediation_api import _approve

    case, _, _ = _workspace_case(client, isolate_settings)
    with db.get_connection() as connection:
        connection.execute("UPDATE remediation_cases SET status='review',verification_plan='Verify behavior',review_policy_json=? WHERE id=?",
                           (json.dumps({**case["review_policy"], "remediation": {"development_ticket_required": True}}), case["id"]))
    projected = client.get(f"{BASE}/cases/{case['id']}").json()
    assert "external reference required by project policy" in projected["review_evidence_missing"]
    assert not projected["review_evidence_ready"]
    response = _approve(client, case["id"])
    assert response.status_code == 409
    assert response.json()["detail"] == "Project policy requires an external reference before approval"
    response = client.post(f"{BASE}/cases/{case['id']}/identity", json={
        "expected_external_provider": None, "expected_external_key": None,
        "external_provider": "custom-tracker", "external_key": "arbitrary/key"})
    assert response.status_code == 200, response.text
    # The next lifecycle gate is baseline evidence, demonstrating the identity gate passes.
    assert _approve(client, case["id"]).json()["detail"] == "Baseline outcome has not been recorded"
    with db.get_connection() as connection:
        connection.execute("UPDATE remediation_cases SET external_provider=NULL,external_key=NULL,source_type='custom-tracker',source_key='arbitrary/key' WHERE id=?", (case["id"],))
    assert _approve(client, case["id"]).json()["detail"] == "Baseline outcome has not been recorded"


def test_external_identity_is_provider_qualified_on_creation(client, isolate_settings):
    _engagement(isolate_settings)
    payload = {"source_type": "report", "title": "Example bug", "snapshot": {},
               "external_provider": "tracker-a", "external_key": "123"}
    first = client.post(f"{BASE}/cases", json=payload)
    assert first.status_code == 201, first.text
    assert client.post(f"{BASE}/cases", json=payload).status_code == 409
    second = client.post(f"{BASE}/cases", json={**payload, "external_provider": "tracker-b"})
    assert second.status_code == 201, second.text
    assert first.json()["id"] != second.json()["id"]


def test_null_external_identity_preserves_legacy_review_digest(client, isolate_settings):
    from app.services import remediation

    root = _engagement(isolate_settings)
    case = client.post(f"{BASE}/cases", json={"source_type": "tracker", "source_key": "123",
                                             "title": "Example bug", "snapshot": {}}).json()
    with db.get_connection() as connection:
        row = dict(connection.execute("SELECT * FROM remediation_cases WHERE id=?", (case["id"],)).fetchone())
    legacy_row = {name: value for name, value in row.items() if name not in {"external_provider", "external_key", "identity_version"}}
    assert remediation._review_digest(row, [], root, []) == remediation._review_digest(legacy_row, [], root, [])


def test_finalization_api_rejects_alias_without_actual_rename(client, isolate_settings):
    case, path, git = _workspace_case(client, isolate_settings)
    git("checkout", "-qb", "fix/BUG-123", directory=path)
    response = client.post(f"{BASE}/cases/{case['id']}/finalize-branch", json={
        "old_branch": case["worktree_branch"], "new_branch": "fix/BUG-123", "revision": case["worktree_revision"]})
    assert response.status_code == 409, response.text
    assert client.get(f"{BASE}/cases/{case['id']}").json()["worktree_branch"] == case["worktree_branch"]


def test_finalization_api_rejects_branch_published_without_local_tracking_ref(client, isolate_settings):
    import subprocess

    case, path, git = _workspace_case(client, isolate_settings)
    remote = path.parent / "acme-origin.git"
    subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
    git("remote", "add", "origin", str(remote), directory=path)
    git("push", "-q", "origin", f"{case['worktree_revision']}:refs/heads/{case['worktree_branch']}", directory=path)
    git("update-ref", "-d", f"refs/remotes/origin/{case['worktree_branch']}", directory=path)
    git("branch", "-m", "fix/BUG-123", directory=path)
    response = client.post(f"{BASE}/cases/{case['id']}/finalize-branch", json={
        "old_branch": case["worktree_branch"], "new_branch": "fix/BUG-123", "revision": case["worktree_revision"]})
    assert response.status_code == 409, response.text


def test_publication_intent_blocks_identity_and_finalization_before_receipt(client, isolate_settings):
    import json

    case, path, git = _workspace_case(client, isolate_settings)
    git("branch", "-m", "fix/BUG-123", directory=path)
    case_root = isolate_settings["engagements_dir"] / "acme-remediation" / "remediation" / "cases" / str(case["id"])
    publication = case_root / "pr" / "publication-intent.json"
    publication.parent.mkdir(parents=True)
    publication.write_text(json.dumps({"branch": case["worktree_branch"], "revision": case["worktree_revision"]}))
    response = client.post(f"{BASE}/cases/{case['id']}/identity", json={
        "expected_external_provider": None, "expected_external_key": None,
        "external_provider": "tracker", "external_key": "BUG-123"})
    assert response.status_code == 409, response.text
    response = client.post(f"{BASE}/cases/{case['id']}/finalize-branch", json={
        "old_branch": case["worktree_branch"], "new_branch": "fix/BUG-123", "revision": case["worktree_revision"]})
    assert response.status_code == 409, response.text
    unchanged = client.get(f"{BASE}/cases/{case['id']}").json()
    assert unchanged["external_key"] is None
    assert unchanged["worktree_branch"] == case["worktree_branch"]


def _approved_workspace_case(client, isolate_settings):
    case, path, git = _workspace_case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{case['id']}"
    proof = isolate_settings["engagements_dir"] / "acme-remediation" / "remediation" / "cases" / str(case["id"]) / "proof.txt"
    proof.parent.mkdir(parents=True)
    proof.write_text("Account boundary verified\n")
    response = client.patch(endpoint + "/verification-plan", json={
        "verification_plan": "Verify account boundary", "requirements": [{"kind": "api-test", "methods": ["pytest"]}],
        "alternatives_reason": "Native API tests cover the account boundary"})
    assert response.status_code == 200, response.text
    response = client.post(endpoint + "/evidence", json={
        "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest test_accounts.py",
        "outcome": "passed", "observed": "Account boundary verified", "proved": "Account isolation",
        "artifact_path": f"remediation/cases/{case['id']}/proof.txt", "revision": case["worktree_revision"],
        "execution": "executed", "executed_revision": case["worktree_revision"]})
    assert response.status_code == 201, response.text
    assert client.patch(endpoint + "/baseline", json={"outcome": "runtime_reproduced", "method": "pytest", "proved": "Original failure"}).status_code == 200
    assert client.post(endpoint + "/transition", json={"status": "review", "actor": "owner", "reason": "Ready"}).status_code == 200
    case = client.get(endpoint).json()
    response = client.post(endpoint + "/approve", json={"reviewer": "owner", "expected_review_digest": case["review_digest"], "approval_method": "ui"})
    assert response.status_code == 201, response.text
    return client.get(endpoint).json(), path, git


def test_backend_publication_intent_validates_approval_and_locks_identity(client, isolate_settings):
    case, _, _ = _approved_workspace_case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{case['id']}"
    intent = {"review_digest": case["review_digest"], "branch": case["worktree_branch"], "revision": case["worktree_revision"]}
    for field in intent:
        response = client.post(endpoint + "/publication-intent", json={**intent, field: "stale-value"})
        assert response.status_code == 409, response.text
    response = client.post(endpoint + "/publication-intent", json=intent)
    assert response.status_code == 200, response.text
    assert client.post(endpoint + "/publication-intent", json=intent).status_code == 200
    assert client.get(endpoint).json()["approval_current"]
    response = client.post(endpoint + "/identity", json={"expected_external_provider": None, "expected_external_key": None,
                                                        "external_provider": "tracker", "external_key": "BUG-123"})
    assert response.status_code == 409, response.text


def test_backend_publication_intent_rejects_approval_staled_by_identity(client, isolate_settings):
    case, _, _ = _approved_workspace_case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{case['id']}"
    response = client.post(endpoint + "/identity", json={"expected_external_provider": None, "expected_external_key": None,
                                                        "external_provider": "tracker", "external_key": "BUG-123"})
    assert response.status_code == 200, response.text
    intent = {"review_digest": case["review_digest"], "branch": case["worktree_branch"], "revision": case["worktree_revision"]}
    assert client.post(endpoint + "/publication-intent", json=intent).status_code == 409
    current = client.get(endpoint).json()
    assert client.post(endpoint + "/publication-intent", json={**intent, "review_digest": current["review_digest"]}).status_code == 409
