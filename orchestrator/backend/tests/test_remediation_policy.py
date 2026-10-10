from __future__ import annotations

import subprocess
import sqlite3
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from app import db
from app.services import remediation
from conftest import _real_init_db


KEY = "acme-remediation"
BASE = f"/engagements/{KEY}/remediation"


def case(client, isolate_settings, source_type="jira", source_key="SEC-123"):
    root = isolate_settings["engagements_dir"] / KEY
    root.mkdir(exist_ok=True)
    if db.get_engagement_by_key(KEY) is None:
        db.create_engagement(KEY, "Acme", "in_progress", str(root), "remediation")
    response = client.post(f"{BASE}/cases", json={
        "source_type": source_type, "source_key": source_key,
        "title": "Account boundary", "snapshot": {"report": "Original report"},
    })
    assert response.status_code == 201, response.text
    return root, response.json()


def workspace(client, root, item):
    path = root / "remediation" / "cases" / str(item["id"]) / "worktree"
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(path)], check=True)
    (path / "fix.py").write_text("fixed = True\n")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Acme Test", "-c",
                    "user.email=test@example.com", "commit", "-qm", "Boundary fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    response = client.patch(f"{BASE}/cases/{item['id']}", json={
        "worktree_path": str(path), "worktree_revision": revision,
    })
    assert response.status_code == 200, response.text
    return path, revision


def test_explicit_native_verification_does_not_require_browser_or_laravel(client, isolate_settings):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    endpoint = f"{BASE}/cases/{item['id']}"
    response = client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Check legitimate and cross-account API operations",
        "requirements": [{"kind": "api-test", "methods": ["pytest"], "outcome": "passed",
                          "revision": "current", "execution": "executed"}],
        "alternatives_reason": "An API-only boundary has no browser path; native tests cover both controls",
    })
    assert response.status_code == 200, response.text
    proof = root / "remediation" / "cases" / str(item["id"]) / "api.txt"
    proof.write_text("2 passed: positive and negative account controls\n")
    response = client.post(f"{endpoint}/evidence", json={
        "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest test_accounts.py",
        "outcome": "passed", "observed": "2 passed", "proved": "Account isolation and legitimate access",
        "artifact_path": str(proof.relative_to(root)), "revision": revision,
        "execution": "executed", "executed_revision": revision,
    })
    assert response.status_code == 201, response.text
    assert client.get(endpoint).json()["review_evidence_ready"] is True
    client.patch(f"{endpoint}/baseline", json={
        "outcome": "runtime_reproduced", "method": "pytest", "proved": "Original access crossed accounts",
    })
    client.post(f"{endpoint}/transition", json={"status": "review", "actor": "owner", "reason": "Ready"})
    digest = client.get(endpoint).json()["review_digest"]
    assert client.post(f"{endpoint}/approve", json={"reviewer": "owner", "expected_review_digest": digest,
                                                "approval_method": "ui"}).status_code == 201


def test_alternative_verification_requires_reason_and_cannot_be_empty(client, isolate_settings):
    _, item = case(client, isolate_settings)
    endpoint = f"{BASE}/cases/{item['id']}/verification-plan"
    requirement = {"kind": "caller-analysis", "methods": ["code-review"], "execution": "reasoned"}
    assert client.patch(endpoint, json={"verification_plan": "Inspect callers", "requirements": [requirement]}).status_code == 422
    assert client.patch(endpoint, json={"verification_plan": "Skip all", "requirements": [], "alternatives_reason": "No tests"}).status_code == 422


def test_evidence_cannot_claim_different_executed_revision(client, isolate_settings):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    response = client.post(f"{BASE}/cases/{item['id']}/evidence", json={
        "kind": "api-test", "method": "pytest", "environment": "local", "command": "pytest",
        "outcome": "passed", "observed": "Pass", "proved": "Boundary", "revision": revision,
        "execution": "executed", "executed_revision": "0" * 40,
    })
    assert response.status_code == 400, response.text


def test_source_resolution_reports_existing_case_without_merging(client, isolate_settings):
    _, original = case(client, isolate_settings)
    _, pending = case(client, isolate_settings, "reference", "https://jira.example.com/browse/SEC-123")
    response = client.post(f"{BASE}/cases/{pending['id']}/resolve-source", json={
        "source_type": "jira", "source_key": "SEC-123", "title": "Retrieved ticket",
        "snapshot": {"original_report": "Retrieved report", "retrieved_at": "2026-01-01"},
    })
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["existing_case_id"] == original["id"]
    assert client.get(f"{BASE}/cases/{pending['id']}").json()["source_type"] == "reference"
    assert client.get(f"{BASE}/cases/{original['id']}").json()["snapshot"] == {"report": "Original report"}


def test_shared_environment_ownership_is_atomic_and_revision_bound(client, isolate_settings):
    root, first = case(client, isolate_settings)
    _, revision = workspace(client, root, first)
    _, second = case(client, isolate_settings, source_key="SEC-124")
    _, second_revision = workspace(client, root, second)
    def acquire(item, rev):
        return client.post(f"{BASE}/environments/acquire", json={
            "environment": "compose-api", "case_id": item["id"], "revision": rev, "actor": "developer",
        })
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda args: acquire(*args), [(first, revision), (second, second_revision)]))
    assert sorted(response.status_code for response in responses) == [201, 409]
    winner = next(response.json() for response in responses if response.status_code == 201)
    assert winner.get("created") is True
    reused = acquire(first if winner["case_id"] == first["id"] else second, winner["revision"])
    assert reused.status_code == 201
    assert reused.json()["token"] == winner["token"]
    assert reused.json().get("created") is False
    denied = client.post(f"{BASE}/environments/release", json={
        "environment": "compose-api", "case_id": winner["case_id"], "token": "incorrect", "actor": "developer",
    })
    assert denied.status_code == 409
    released = client.post(f"{BASE}/environments/release", json={
        "environment": "compose-api", "case_id": winner["case_id"], "token": winner["token"], "actor": "developer",
    })
    assert released.status_code == 200


@pytest.mark.parametrize("vcs", ["git", "jj"])
def test_registered_external_workspace_pins_profile_base_and_requires_profile_checks(client, isolate_settings, vcs):
    root, item = case(client, isolate_settings)
    repo = root.parent / "acme-repo"
    subprocess.run(["git", "init", "-q", "--initial-branch=develop", str(repo)], check=True)
    (repo / "README.md").write_text("Acme app\n")
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Acme Test", "-c", "user.email=test@example.com", "commit", "-qm", "Base"], check=True)
    base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    profile = repo / "PROJECT.md"
    profile.write_text('+++\nrepository = "."\nbase_branch = "develop"\nworkspace_directory = "worktrees"\n'
                       '[remediation]\ncheck_commands = [{ name = "lint", command = "python -m compileall app" }]\n+++\n')
    (root / "PROJECT.md").symlink_to(profile)
    path = repo / "worktrees" / "fix" / "SEC-123"
    if vcs == "jj":
        subprocess.run(["jj", "git", "init", "--colocate", str(repo)], check=True, capture_output=True)
    remediation._vcs.create_workspace(repo, path, "fix/SEC-123", "develop")
    endpoint = f"{BASE}/cases/{item['id']}"
    registered = client.patch(endpoint, json={"worktree_path": str(path), "worktree_branch": "fix/SEC-123", "worktree_revision": base})
    assert registered.status_code == 200, registered.text
    assert registered.json()["base_branch"] == "develop"
    assert registered.json()["base_revision"] == base
    assert client.get(f"{endpoint}/diff").json()["base_revision"] == base
    assert client.patch(endpoint, json={"base_branch": "main"}).status_code == 409
    plan = {"verification_plan": "Inspect removed callers", "requirements": [{
        "kind": "caller-analysis", "methods": ["code-review"], "execution": "reasoned",
    }], "alternatives_reason": "The deletion needs caller analysis rather than a test asserting code absence"}
    assert client.patch(f"{endpoint}/verification-plan", json=plan).status_code == 200
    assert "profile check: lint" in client.get(endpoint).json()["review_evidence_missing"]
    proof = root / "remediation" / "cases" / str(item["id"]) / "check.txt"
    proof.parent.mkdir(parents=True, exist_ok=True)
    proof.write_text("Compiler check passed\n")
    payload = {
        "kind": "profile-check", "method": "lint", "command": "python -m compileall app",
        "outcome": "passed", "observed": "Pass", "proved": "Configured compiler check",
        "execution": "executed", "revision": base, "executed_revision": base,
        "environment": "local", "artifact_path": str(proof.relative_to(root)),
    }
    assert client.post(f"{endpoint}/evidence", json={**payload, "executed_directory": str(repo)}).status_code == 201
    assert "profile check: lint" in client.get(endpoint).json()["review_evidence_missing"]
    assert client.post(f"{endpoint}/evidence", json={**payload, "executed_directory": str(path)}).status_code == 201
    assert "profile check: lint" not in client.get(endpoint).json()["review_evidence_missing"]
    assert client.post(f"{endpoint}/evidence", json={
        "kind": "caller-analysis", "method": "code-review", "outcome": "passed",
        "observed": "Only intended caller removed", "proved": "Other account operations remain reachable",
        "execution": "reasoned", "revision": base, "environment": "not_applicable",
        "artifact_path": str(proof.relative_to(root)),
    }).status_code == 201
    assert client.get(endpoint).json()["review_evidence_ready"] is True
    profile.write_text(profile.read_text().replace('base_branch = "develop"', 'base_branch = "main"'))
    current = client.get(endpoint).json()
    assert current["base_branch"] == "develop" and current["base_revision"] == base
    assert current["review_digest"] != registered.json()["review_digest"]


def test_generic_source_schema_migration_preserves_approval_and_finding_history(client, isolate_settings):
    _, item = case(client, isolate_settings)
    with db.get_connection() as connection:
        connection.execute("INSERT INTO remediation_approvals(case_id,reviewer,review_digest,approved_revision) VALUES(?, 'owner', 'old-digest', 'revision')", (item["id"],))
    db.close_thread_connection()
    with sqlite3.connect(db.database_path()) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        schema = connection.execute("SELECT sql FROM sqlite_master WHERE name='remediation_cases'").fetchone()[0]
        connection.execute(schema.replace("CREATE TABLE remediation_cases", "CREATE TABLE remediation_old", 1).replace(
            "source_type TEXT NOT NULL", "source_type TEXT NOT NULL CHECK(source_type IN ('jira', 'bounty', 'finding'))", 1))
        connection.execute("INSERT INTO remediation_old SELECT * FROM remediation_cases")
        connection.execute("DROP TABLE remediation_cases")
        connection.execute("ALTER TABLE remediation_old RENAME TO remediation_cases")
    _real_init_db()
    with db.get_connection() as connection:
        assert connection.execute("SELECT review_digest FROM remediation_approvals WHERE case_id=?", (item["id"],)).fetchone()[0] == "old-digest"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    response = client.post(f"{BASE}/cases", json={"source_type": "report", "source_key": "manual-1", "title": "Manual report", "snapshot": {"report": "Original"}})
    assert response.status_code == 201, response.text


def test_shared_runtime_confirmation_rejects_wrong_code_and_retains_provenance(client, isolate_settings):
    root, item = case(client, isolate_settings)
    path, old_revision = workspace(client, root, item)
    (path / "fix.py").write_text("fixed = 'new'\n")
    subprocess.run(["git", "-C", str(path), "add", "."], check=True)
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Acme Test", "-c", "user.email=test@example.com", "commit", "-qm", "Current fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True).strip()
    endpoint = f"{BASE}/cases/{item['id']}"
    assert client.patch(endpoint, json={"worktree_revision": revision}).status_code == 200
    acquired = client.post(f"{BASE}/environments/acquire", json={
        "environment": "shared-api", "case_id": item["id"], "revision": revision, "actor": "developer",
    })
    assert acquired.status_code == 201, acquired.text
    lease = acquired.json()
    payload = {"environment": "shared-api", "case_id": item["id"], "token": lease["token"], "actor": "developer"}
    assert client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Replay API boundary against the confirmed shared runtime",
        "requirements": [{"kind": "api-test", "methods": ["HTTP"], "shared_environment": "shared-api", "runtime_identity_required": True}],
        "alternatives_reason": "API controls cover the boundary without a browser",
    }).status_code == 200
    proof = root / "remediation" / "cases" / str(item["id"]) / "api.txt"
    proof.write_text("Positive and negative controls passed\n")
    evidence = {"kind": "api-test", "method": "HTTP", "environment": "local", "command": "local API boundary test",
                "observed": "Passed", "proved": "Account boundary", "outcome": "passed", "revision": revision,
                "execution": "executed", "executed_revision": revision, "shared_environment": "shared-api",
                "environment_token": lease["token"], "artifact_path": str(proof.relative_to(root))}
    assert client.post(f"{endpoint}/evidence", json=evidence).status_code == 201
    wrong = client.post(f"{BASE}/environments/confirm", json={**payload, "observed_revision": old_revision})
    assert wrong.status_code == 409, wrong.text
    confirmed = client.post(f"{BASE}/environments/confirm", json={**payload, "observed_revision": revision})
    assert confirmed.status_code == 200, confirmed.text
    assert confirmed.json()["observed_revision"] == revision
    assert confirmed.json()["confirmed_by"] == "developer"
    assert client.get(endpoint).json()["review_evidence_ready"] is False
    assert client.post(f"{endpoint}/evidence", json=evidence).status_code == 201
    assert client.get(endpoint).json()["review_evidence_ready"] is True
    assert client.post(f"{BASE}/environments/release", json=payload).status_code == 200
    history = client.get(endpoint).json()["environment_leases"]
    assert history[0]["observed_revision"] == revision and history[0]["released_at"]


def test_empty_profile_base_defaults_to_main_at_workspace_registration(client, isolate_settings):
    root, item = case(client, isolate_settings)
    path, revision = workspace(client, root, item)
    (root / "PROJECT.md").write_text('+++\nrepository = "' + str(path) + '"\nbase_branch = ""\n+++\n')
    response = client.patch(f"{BASE}/cases/{item['id']}", json={
        "worktree_path": str(path), "worktree_branch": "main", "worktree_revision": revision,
    })
    assert response.status_code == 200, response.text
    assert response.json()["base_branch"] == "main"


def _browser_requirements(purpose, driver="stagehand"):
    return [{"kind": driver, "methods": [driver], "browser_purpose": purpose}, {
        "kind": "legitimate-api", "methods": ["pytest"], "legitimate_use_control": True,
        "rationale": "An owner can still update their own account",
    }]


def _register_browser_run(client, root, item, revision, purpose, driver="stagehand", screenshot=False, result_override=None):
    endpoint = f"{BASE}/cases/{item['id']}"
    lease = client.post(f"{BASE}/environments/acquire", json={
        "environment": "shared-browser", "case_id": item["id"], "revision": revision, "actor": "developer",
    }).json()
    response = client.post(f"{BASE}/environments/confirm", json={
        "environment": "shared-browser", "case_id": item["id"], "token": lease["token"],
        "observed_revision": revision, "actor": "developer",
    })
    assert response.status_code == 200, response.text
    run = root / "remediation" / "cases" / str(item["id"]) / driver / purpose
    run.mkdir(parents=True)
    (run / "script.py").write_text("async def run(browser, output_dir): pass\n")
    (run / "result.json").write_text(json.dumps({
        "status": "passed", "purpose": purpose, "observed": "Cross-account change rejected",
        "proved": "Account boundary enforced", "served_revision": revision,
        "steps": [{"action": "Submit other account ID", "observation": "Access denied"}],
        **(result_override or {}),
    }))
    if driver == "browse":
        (run / "commands.json").write_text(json.dumps([{
            "argv": ["browse", "--local", "open", "http://localhost"], "returncode": 0,
            "stdout": "Page opened", "stderr": "",
        }]))
    if screenshot:
        (run / "screen.png").write_bytes(
            b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + (1).to_bytes(4, "big")
            + (1).to_bytes(4, "big") + b"\x08\x02\0\0\0" + b"x" * 12 + b"IEND" + b"\0" * 4
        )
    for file in run.iterdir():
        response = client.post(f"{endpoint}/evidence", json={
            "kind": "screenshot" if file.suffix == ".png" else driver, "method": driver,
            "environment": "local", "command": "trusted browser run", "outcome": "passed",
            "observed": "Passed", "proved": "Boundary enforced", "revision": revision,
            "executed_revision": revision, "shared_environment": "shared-browser",
            "environment_token": lease["token"], "artifact_path": str(file.relative_to(root)),
        })
        assert response.status_code == 201, response.text
    return run


@pytest.mark.parametrize("driver", ["stagehand", "browse"])
@pytest.mark.parametrize("purpose", ["bad-path", "other"])
def test_explicit_browser_purpose_accepts_focused_run_with_separate_legitimate_control(
    client, isolate_settings, driver, purpose,
):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    endpoint = f"{BASE}/cases/{item['id']}"
    response = client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Browser checks the denied operation; API checks owner access",
        "requirements": _browser_requirements(purpose, driver),
        "alternatives_reason": "A focused browser check needs no screenshot rehearsal of the owner path",
    })
    assert response.status_code == 200, response.text
    run = _register_browser_run(client, root, item, revision, purpose, driver)
    assert client.get(endpoint).json()["review_evidence_ready"] is False
    proof = run.parent / "legitimate-api.txt"
    proof.write_text("Owner account update passed\n")
    response = client.post(f"{endpoint}/evidence", json={
        "kind": "legitimate-api", "method": "pytest", "environment": "local",
        "command": "pytest test_owner_update.py", "outcome": "passed",
        "observed": "Owner update accepted", "proved": "Legitimate access preserved", "revision": revision,
        "executed_revision": revision, "artifact_path": str(proof.relative_to(root)),
    })
    assert response.status_code == 201, response.text
    assert client.get(endpoint).json()["review_evidence_ready"] is True
    result = run / "result.json"
    result.write_text(result.read_text().replace(f'"purpose": "{purpose}"', '"purpose": "happy-path"'))
    assert client.get(endpoint).json()["review_evidence_ready"] is False


@pytest.mark.parametrize("invalid_control", [None, "reasoned", "ancestor"])
def test_focused_browser_plan_requires_current_executed_legitimate_control(client, isolate_settings, invalid_control):
    _, item = case(client, isolate_settings)
    requirements = _browser_requirements("bad-path")
    if invalid_control is None:
        requirements.pop()
    elif invalid_control == "reasoned":
        requirements[1]["execution"] = "reasoned"
    else:
        requirements[1]["revision"] = "ancestor"
    response = client.patch(f"{BASE}/cases/{item['id']}/verification-plan", json={
        "verification_plan": "Only denied access", "requirements": requirements,
        "alternatives_reason": "Focused browser check",
    })
    assert response.status_code == 422, response.text


def test_explicit_happy_browser_plan_retains_screenshot_gate(client, isolate_settings):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    endpoint = f"{BASE}/cases/{item['id']}"
    response = client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Rehearse owner update", "requirements": [{
            "kind": "stagehand", "methods": ["stagehand"], "browser_purpose": "happy-path",
        }], "alternatives_reason": "An owner rehearsal covers the product control",
    })
    assert response.status_code == 200, response.text
    run = _register_browser_run(client, root, item, revision, "happy-path")
    assert client.get(endpoint).json()["review_evidence_ready"] is False
    file = run / "screen.png"
    file.write_bytes(
        b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big") + b"\x08\x02\0\0\0" + b"x" * 12 + b"IEND" + b"\0" * 4
    )
    response = client.post(f"{endpoint}/evidence", json={
        "kind": "screenshot", "method": "stagehand", "environment": "local", "command": "trusted browser run",
        "outcome": "passed", "observed": "Owner update accepted", "proved": "Legitimate owner access preserved",
        "revision": revision, "executed_revision": revision, "artifact_path": str(file.relative_to(root)),
    })
    assert response.status_code == 201, response.text
    assert client.get(endpoint).json()["review_evidence_ready"] is True


@pytest.mark.parametrize("result_override", [{"purpose": "happy-path"}, {"status": "failed"}, {"steps": []}])
def test_focused_browser_plan_rejects_mismatched_or_incomplete_result(client, isolate_settings, result_override):
    root, item = case(client, isolate_settings)
    _, revision = workspace(client, root, item)
    endpoint = f"{BASE}/cases/{item['id']}"
    response = client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Browser checks the denied operation; API checks owner access",
        "requirements": _browser_requirements("bad-path"), "alternatives_reason": "Focused boundary check",
    })
    assert response.status_code == 200, response.text
    _register_browser_run(client, root, item, revision, "bad-path", result_override=result_override)
    assert "stagehand (executed, current revision)" in client.get(endpoint).json()["review_evidence_missing"]
