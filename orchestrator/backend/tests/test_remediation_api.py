from __future__ import annotations

from pathlib import Path
import json
import random
import subprocess

import pytest
from fastapi import HTTPException

from app import db
from app.services import remediation


KEY = "acme-remediation"
BASE = f"/engagements/{KEY}/remediation"


def _engagement(isolate_settings) -> Path:
    root = isolate_settings["engagements_dir"] / KEY
    root.mkdir(parents=True)
    db.create_engagement(KEY, "Acme", "in_progress", str(root), "remediation")
    return root


def _case(client, isolate_settings, **overrides):
    _engagement(isolate_settings)
    payload = {
        "source_type": "jira",
        "source_key": "SEC-101",
        "title": "Incorrect account scope",
        "snapshot": {"description": "Untrusted report text", "attachments": ["report.pdf"]},
    }
    payload.update(overrides)
    response = client.post(f"{BASE}/cases", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _approve(client, case_id: int):
    digest = client.get(f"{BASE}/cases/{case_id}").json()["review_digest"]
    return client.post(f"{BASE}/cases/{case_id}/approve", json={
        "reviewer": "security-dev", "expected_review_digest": digest,
        "approval_method": "ui",
    })


def _red_baseline(worktree: Path) -> None:
    subprocess.run([
        "git", "-C", str(worktree), "-c", "user.name=Vigil Test",
        "-c", "user.email=test@example.invalid", "commit", "--allow-empty", "-qm", "Pre-fix",
    ], check=True)


def _review_evidence(
    client, root: Path, case_id: int, revision: str, *,
    stagehand_steps: bool = True, screenshot_valid: bool = True,
    red_revision: str | None = None,
    green_revision: str | None = None, stagehand_revision: str | None = None,
    stagehand_artifact_revisions: dict[str, str] | None = None,
) -> None:
    case_root = root / "remediation" / "cases" / str(case_id)
    if red_revision is None:
        red_revision = subprocess.check_output(
            ["git", "-C", str(case_root / "worktree"), "rev-parse", f"{revision}^"], text=True,
        ).strip()
    proof_dir = case_root / "proofs"
    proof_dir.mkdir(parents=True, exist_ok=True)
    for kind, outcome in (("red-test", "failed_as_expected"), ("green-test", "passed")):
        file = proof_dir / f"{kind}.txt"
        file.write_text(f"{kind}: {outcome}\n")
        response = client.post(f"{BASE}/cases/{case_id}/evidence", json={
            "kind": kind, "method": "Laravel", "environment": "local", "outcome": outcome,
            "command": "php artisan test --filter AccountScopeTest",
            "observed": outcome, "proved": "Security boundary regression",
            "artifact_path": str(file.relative_to(root)),
            "revision": red_revision if kind == "red-test" else (green_revision or revision),
        })
        assert response.status_code == 201, response.text
    run = case_root / "stagehand" / "local-happy"
    run.mkdir(parents=True, exist_ok=True)
    (run / "script.py").write_text("async def run(stagehand, output_dir): pass\n")
    (run / "result.json").write_text(
        '{"status":"passed","purpose":"happy-path","observed":"Form worked",'
        '"proved":"Owner update saved","steps":'
        + ('[{"action":"Submit own form","observation":"Own account changed"}]}' if stagehand_steps else '[]}')
    )
    (run / "screen.png").write_bytes(
        (b"\x89PNG\r\n\x1a\n" + b"\0\0\0\rIHDR" + (1).to_bytes(4, "big")
         + (1).to_bytes(4, "big") + b"\x08\x02\0\0\0" + b"x" * 12 + b"IEND" + b"\0" * 4)
        if screenshot_valid else b"not an image"
    )
    for file in sorted(run.iterdir()):
        response = client.post(f"{BASE}/cases/{case_id}/evidence", json={
            "kind": "screenshot" if file.suffix == ".png" else "stagehand",
            "method": "stagehand", "environment": "local", "command": "trusted script via Chrome CDP",
            "observed": "passed", "proved": "Human happy path rehearsed",
            "artifact_path": str(file.relative_to(root)),
            "revision": (stagehand_artifact_revisions or {}).get(file.name, stagehand_revision or revision),
        })
        assert response.status_code == 201, response.text


def test_remediation_intake_preserves_snapshot_and_hints_without_merging(client, isolate_settings):
    first = _case(client, isolate_settings)
    second = client.post(f"{BASE}/cases", json={
        "source_type": "bounty", "source_key": "H1-88",
        "title": "Incorrect account scope", "snapshot": {"report": "Original text"},
    })
    assert second.status_code == 201, second.text
    assert second.json()["id"] != first["id"]
    assert first["id"] in second.json()["duplicate_hints"]
    assert second.json()["snapshot"]["report"] == "Original text"
    assert client.post(f"{BASE}/cases", json={
        "source_type": "jira", "source_key": "SEC-101", "title": "Again", "snapshot": {},
    }).status_code == 409


def test_remediation_duplicate_hint_uses_root_cause_across_different_titles(client, isolate_settings):
    first = _case(client, isolate_settings, snapshot={"root_cause_key": "account-scope", "route": "/manage/profile"})
    second = client.post(f"{BASE}/cases", json={
        "source_type": "bounty", "source_key": "H1-99", "title": "Profile update crosses tenant",
        "snapshot": {"root_cause_key": "account-scope", "route": "/manage/profile"},
    })
    assert second.status_code == 201, second.text
    assert first["id"] in second.json()["duplicate_hints"]
    assert "root_cause_key" in second.json()["duplicate_hint_details"][0]["reasons"]


def test_remediation_evidence_file_confined_to_engagement(client, isolate_settings):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    image = root / "remediation" / "cases" / str(case["id"]) / "proof.png"
    image.parent.mkdir(parents=True)
    image.write_bytes(b"PNG evidence")
    created = client.post(f"{BASE}/cases/{case['id']}/evidence", json={
        "kind": "screenshot", "method": "stagehand", "environment": "local", "observed": "Page loaded",
        "proved": "Legitimate workflow works", "artifact_path": f"remediation/cases/{case['id']}/proof.png",
    })
    assert created.status_code == 201, created.text
    evidence_id = created.json()["id"]
    fetched = client.get(f"{BASE}/cases/{case['id']}/evidence/{evidence_id}/file")
    assert fetched.content == b"PNG evidence"
    assert fetched.headers["content-type"] == "image/png"
    outside = root.parent / "secret.png"
    outside.write_bytes(b"outside")
    (root / "escape.png").symlink_to(outside)
    for path in ("../secret.png", "escape.png"):
        rejected = client.post(f"{BASE}/cases/{case['id']}/evidence", json={
            "kind": "screenshot", "method": "stagehand", "environment": "local", "observed": "x",
            "proved": "x", "artifact_path": path,
        })
        assert rejected.status_code == 400, rejected.text
    sibling = root / "remediation" / "cases" / "999" / "other.png"
    sibling.parent.mkdir(parents=True)
    sibling.write_bytes(b"sibling")
    assert client.post(f"{BASE}/cases/{case['id']}/evidence", json={
        "kind": "screenshot", "method": "stagehand", "environment": "local", "observed": "x", "proved": "x",
        "artifact_path": "remediation/cases/999/other.png",
    }).status_code == 400


def test_remediation_evidence_requires_and_persists_environment(client, isolate_settings):
    case = _case(client, isolate_settings)
    payload = {"kind": "baseline", "method": "HTTP", "observed": "403",
               "proved": "Cross-account request denied"}
    endpoint = f"{BASE}/cases/{case['id']}/evidence"
    assert client.post(endpoint, json=payload).status_code == 422
    assert client.post(endpoint, json={**payload, "environment": " "}).status_code == 422
    assert client.post(endpoint, json={**payload, "environment": "staging"}).status_code == 422
    assert client.post(endpoint, json={**payload, "environment": "unknown-place"}).status_code == 422
    created = client.post(endpoint, json={**payload, "environment": "development"})
    assert created.status_code == 201, created.text
    assert created.json()["environment"] == "development"
    detail = client.get(f"{BASE}/cases/{case['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence"][0]["environment"] == "development"


def test_historical_null_environment_keeps_review_digest(monkeypatch, tmp_path):
    from app.services import remediation

    monkeypatch.setattr(remediation, "_review_patch", lambda _: ("base", "head", b"patch", False, 5))
    monkeypatch.setattr(remediation, "_actual_revision", lambda _: "head")
    monkeypatch.setattr(remediation, "_worktree_digest", lambda _: "contents")
    row = {"id": 1, "title": "Case", "snapshot_json": "{}", "worktree_path": "unused", "worktree_branch": None, "worktree_revision": "head",
           "verification_plan": "Plan", "baseline_json": "{}", "release_plan_json": "{}"}
    old = {"id": 1, "case_id": 1, "kind": "baseline", "method": "HTTP", "command": "curl",
           "observed": "403", "proved": "Denied", "outcome": None, "artifact_path": None,
           "artifact_sha256": None, "revision": "head", "created_at": "2026-01-01"}
    assert remediation._review_digest(row, [old], tmp_path, []) == remediation._review_digest(
        row, [{**old, "environment": None}], tmp_path, [])


def test_remediation_approval_invalidated_by_code_and_plan_changes(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    code = worktree / "fix.php"
    code.write_text("fixed v1")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    patched = client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(worktree), "worktree_revision": revision,
    })
    assert patched.status_code == 200, patched.text
    plan = client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={
        "verification_plan": "Open page; submit form; verify success",
    })
    assert plan.status_code == 200, plan.text
    transition = client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Evidence ready",
    })
    assert transition.status_code == 200, transition.text
    client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel HTTP test", "proved": "Reported route fails",
    })
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revision)
    approved = _approve(client, case["id"])
    assert approved.status_code == 201, approved.text
    assert client.get(f"{BASE}/cases/{case['id']}").json()["approval_current"] is True
    code.write_text("fixed v2")
    assert client.get(f"{BASE}/cases/{case['id']}").json()["approval_current"] is False
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "pr_draft", "actor": "operator", "reason": "Ready",
    }).status_code == 409


def test_remediation_rejects_claimed_revision_that_is_not_worktree_head(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"], check=True)
    client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(worktree), "worktree_revision": "a" * 40,
    })
    client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={"verification_plan": "Open tested page"})
    client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Ready",
    })
    assert _approve(client, case["id"]).status_code == 409


@pytest.mark.parametrize(
    ("red_revision_kind", "expected_ready"),
    [("sibling", False), ("same-commit", False), ("ancestor", True)],
)
def test_remediation_review_requires_red_test_commit_ancestor(
    client, isolate_settings, red_revision_kind, expected_ready,
):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    code = worktree / "fix.php"
    code.write_text("base")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)

    def commit(message: str) -> str:
        subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
        subprocess.run([
            "git", "-C", str(worktree), "-c", "user.name=Vigil Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", message,
        ], check=True)
        return subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()

    ancestor = commit("Base")
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "red-branch"], check=True)
    code.write_text("red branch")
    sibling = commit("Unrelated red test")
    subprocess.run(["git", "-C", str(worktree), "switch", "-q", "main"], check=True)
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "feature"], check=True)
    code.write_text("fixed")
    revision = commit("Fix")
    red_revision = {
        "sibling": sibling,
        "same-commit": revision, "ancestor": ancestor,
    }[red_revision_kind]

    assert client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(worktree), "worktree_revision": revision,
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={
        "verification_plan": "Run Laravel regression and rehearse happy path",
    }).status_code == 200
    _review_evidence(client, root, case["id"], revision, red_revision=red_revision)
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Ready",
    }).status_code == 200
    detail = client.get(f"{BASE}/cases/{case['id']}").json()
    assert detail["review_evidence_ready"] is expected_ready
    assert _approve(client, case["id"]).status_code == (201 if expected_ready else 409)


@pytest.mark.parametrize("revision_form", ["HEAD", "abbreviated", "uppercase"])
def test_remediation_evidence_resolves_green_and_stagehand_commit_refs(
    client, isolate_settings, revision_form,
):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    submitted = {"HEAD": "HEAD", "abbreviated": revision[:12], "uppercase": revision.upper()}[revision_form]
    endpoint = f"{BASE}/cases/{case['id']}"
    assert client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_revision": revision}).status_code == 200
    _review_evidence(
        client, root, case["id"], revision,
        green_revision=submitted, stagehand_revision=submitted,
    )
    detail = client.get(endpoint).json()
    assert detail["review_evidence_ready"] is True
    assert all(item["revision"] == revision for item in detail["evidence"] if item["kind"] != "red-test")


@pytest.mark.parametrize("stale_artifact", ["script.py", "screen.png"])
def test_remediation_review_rejects_stagehand_artifact_from_older_revision(
    client, isolate_settings, stale_artifact,
):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    code = worktree / "fix.php"
    code.write_text("before")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Before"], check=True)
    older = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    code.write_text("fixed")
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    endpoint = f"{BASE}/cases/{case['id']}"
    assert client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_revision": revision}).status_code == 200
    assert client.patch(f"{endpoint}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    }).status_code == 200
    assert client.patch(f"{endpoint}/verification-plan", json={
        "verification_plan": "Follow rehearsed UI steps",
    }).status_code == 200
    _review_evidence(
        client, root, case["id"], revision,
        stagehand_artifact_revisions={stale_artifact: older},
    )
    assert client.post(f"{endpoint}/transition", json={
        "status": "review", "actor": "operator", "reason": "Ready",
    }).status_code == 200
    detail = client.get(endpoint).json()
    assert detail["review_evidence_ready"] is False
    assert _approve(client, case["id"]).status_code == 409


@pytest.mark.parametrize("revision", ["missing-revision", ""])
def test_remediation_evidence_rejects_unresolvable_revision(client, isolate_settings, revision):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    assert client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree)}).status_code == 200
    response = client.post(f"{BASE}/cases/{case['id']}/evidence", json={
        "kind": "green-test", "method": "Laravel", "environment": "local",
        "command": "php artisan test", "observed": "passed", "proved": "Regression passed",
        "revision": revision,
    })
    assert response.status_code == 400, response.text
    assert client.get(f"{BASE}/cases/{case['id']}").json()["evidence"] == []


def test_remediation_legacy_approval_requires_valid_red_evidence_at_approval_cutoff(client, isolate_settings):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run([
        "git", "-C", str(worktree), "-c", "user.name=Vigil Test",
        "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix",
    ], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    assert client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(worktree), "worktree_revision": revision,
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={
        "verification_plan": "Run Laravel test and rehearse happy path",
    }).status_code == 200
    _review_evidence(client, root, case["id"], revision)
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Ready",
    }).status_code == 200
    assert _approve(client, case["id"]).status_code == 201

    with db.get_connection() as connection:
        connection.execute(
            "UPDATE remediation_evidence SET revision=? WHERE case_id=? AND kind='red-test'",
            (revision, case["id"]),
        )
    historical_digest = client.get(f"{BASE}/cases/{case['id']}").json()["review_digest"]
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE remediation_approvals SET review_digest=? WHERE case_id=?",
            (historical_digest, case["id"]),
        )
    proof = root / "remediation" / "cases" / str(case["id"]) / "proofs" / "later-red.txt"
    proof.write_text("failing test at pre-fix commit\n")
    ancestor = subprocess.check_output([
        "git", "-C", str(worktree), "rev-parse", "HEAD^",
    ], text=True).strip()
    later = client.post(f"{BASE}/cases/{case['id']}/evidence", json={
        "kind": "red-test", "method": "Laravel", "environment": "local",
        "outcome": "failed_as_expected", "command": "php artisan test --filter AccountScopeTest",
        "observed": "failed", "proved": "Security boundary regression",
        "artifact_path": str(proof.relative_to(root)), "revision": ancestor,
    })
    assert later.status_code == 201, later.text
    detail = client.get(f"{BASE}/cases/{case['id']}").json()
    assert detail["review_evidence_ready"] is True
    assert detail["approval_current"] is False
    transition = client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "pr_draft", "actor": "operator", "reason": "Ready for PR",
    })
    assert transition.status_code == 409
    assert transition.json()["detail"] == "Review approval is no longer current"


def test_remediation_pr_transition_rejects_deferred_canary_decision(client, isolate_settings, monkeypatch):
    from app.services import remediation

    case = _case(client, isolate_settings)
    with db.get_connection() as connection:
        connection.execute(
            "UPDATE remediation_cases SET status='approved', release_plan_json=? WHERE id=?",
            ('{"production_canary_decision":"defer","production_canary_rationale":"Pending owner decision","coralogix_monitoring":"Watch errors"}', case["id"]),
        )
    monkeypatch.setattr(remediation, "_details", lambda *_: {"approval_current": True})
    response = client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "pr_draft", "actor": "operator", "reason": "Ready",
    })
    assert response.status_code == 409
    assert "Production canary decision" in response.json()["detail"]


def test_remediation_diff_explains_missing_worktree(client, isolate_settings):
    case = _case(client, isolate_settings)
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 409
    assert response.json()["detail"] == "Case worktree is not registered"


def test_remediation_review_diff_shows_local_change(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("old")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    (worktree / "fix.php").write_text("fixed")
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 200, response.text
    assert "+fixed" in response.json()["text"]
    assert response.json()["truncated"] is False


def test_remediation_diff_requires_main_base(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=feature", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 409, response.text
    client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    })
    client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={"verification_plan": "Follow tested UI steps"})
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revision)
    client.post(f"{BASE}/cases/{case['id']}/transition", json={"status": "review", "actor": "operator", "reason": "Ready"})
    assert _approve(client, case["id"]).status_code == 409


def test_remediation_review_digest_changes_when_main_base_moves(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    code = worktree / "fix.php"
    code.write_text("old")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "feature"], check=True)
    code.write_text("fixed")
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    before = client.get(f"{BASE}/cases/{case['id']}").json()["review_digest"]
    subprocess.run(["git", "-C", str(worktree), "branch", "-f", "main", "HEAD"], check=True)
    after = client.get(f"{BASE}/cases/{case['id']}").json()["review_digest"]
    assert after != before


def test_remediation_diff_does_not_read_untracked_symlink_target(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    outside = isolate_settings["data_dir"] / "outside.txt"
    outside.write_text("SECRET-OUTSIDE-CONTENT")
    (worktree / "linked.txt").symlink_to(outside)
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 200, response.text
    assert "SECRET-OUTSIDE-CONTENT" not in response.json()["text"]
    assert "linked.txt" in response.json()["text"]


def test_remediation_diff_bounds_untracked_file_reads(client, isolate_settings, monkeypatch):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    large = worktree / "oversized.txt"
    large.write_text("x" * (remediation._REVIEW_DIFF_LIMIT + 1))
    original_open = Path.open

    def guard_oversized_read(path, *args, **kwargs):
        if path == large:
            raise AssertionError("The review must not read an oversized untracked file")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard_oversized_read)
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 200, response.text
    assert response.json()["truncated"] is True
    assert "oversized.txt" in response.json()["text"]
    assert response.json()["bytes_total"] > remediation._REVIEW_DIFF_LIMIT


def test_remediation_diff_stops_at_aggregate_untracked_limit(client, isolate_settings, monkeypatch):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    (worktree / "a.txt").write_text("a" * (remediation._REVIEW_DIFF_LIMIT // 2 + 100))
    skipped = worktree / "b.txt"
    skipped.write_text("b" * (remediation._REVIEW_DIFF_LIMIT // 2 + 100))
    original_open = Path.open

    def guard_second_read(path, *args, **kwargs):
        if path == skipped:
            raise AssertionError("The aggregate review limit must stop file reads")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guard_second_read)
    assert client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision}).status_code == 200
    response = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert response.status_code == 200, response.text
    assert response.json()["truncated"] is True
    assert "a.txt" in response.json()["text"]
    assert "b.txt" in response.json()["text"]


@pytest.mark.parametrize("change_kind", ["committed", "committed_binary", "local"])
def test_remediation_diff_bounds_tracked_git_output(client, isolate_settings, monkeypatch, change_kind):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    code = worktree / "fix.php"
    code.write_text("base")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    if change_kind != "local":
        subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "feature"], check=True)
    if change_kind == "committed_binary":
        code.write_bytes(random.Random(0).randbytes(remediation._REVIEW_DIFF_LIMIT + 1024))
    else:
        code.write_text("x" * (remediation._REVIEW_DIFF_LIMIT + 1024))
    if change_kind != "local":
        subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
        subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Large fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    original_run = subprocess.run

    def reject_unbounded_capture(args, *positional, **kwargs):
        if args[0] == "git" and "diff" in args and kwargs.get("capture_output"):
            raise AssertionError("Tracked diffs must not be buffered without a limit")
        return original_run(args, *positional, **kwargs)

    monkeypatch.setattr(subprocess, "run", reject_unbounded_capture)
    endpoint = f"{BASE}/cases/{case['id']}"
    assert client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_revision": revision}).status_code == 200
    assert client.get(endpoint).status_code == 200
    response = client.get(f"{endpoint}/diff")
    assert response.status_code == 200, response.text
    assert response.json()["truncated"] is True
    assert response.json()["bytes_total"] > remediation._REVIEW_DIFF_LIMIT
    assert len(response.json()["text"].encode()) <= remediation._REVIEW_DIFF_LIMIT


def test_remediation_rejects_approval_of_truncated_review_diff(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("base")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "feature"], check=True)
    (worktree / "big.txt").write_text("x" * (1024 * 1024 + 1000) + "\n")
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "big.txt"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Large fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    })
    client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={"verification_plan": "Follow tested UI steps"})
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revision)
    client.post(f"{BASE}/cases/{case['id']}/transition", json={"status": "review", "actor": "operator", "reason": "Ready"})
    diff = client.get(f"{BASE}/cases/{case['id']}/diff")
    assert diff.status_code == 200, diff.text
    assert diff.json()["truncated"] is True
    assert _approve(client, case["id"]).status_code == 409


@pytest.mark.parametrize("method", ["GET", "PATCH"])
@pytest.mark.parametrize(
    ("result", "result_missing"),
    [
        ([], True), (None, True), ("passed", True), (42, True), (True, True),
        ({}, True),
        ({"status": "passed", "purpose": "happy-path", "observed": "Form worked",
          "proved": "Owner update saved", "steps": [
              {"action": "Submit own form", "observation": "Own account changed"},
          ]}, False),
    ],
    ids=["array", "null", "string", "number", "boolean", "incomplete-object", "valid-object"],
)
def test_remediation_stagehand_result_shape_preserves_case_access(
    client, isolate_settings, method, result, result_missing,
):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    artifact = root / "remediation" / "cases" / str(case["id"]) / "stagehand" / "result.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(json.dumps(result))
    endpoint = f"{BASE}/cases/{case['id']}"
    evidence = client.post(f"{endpoint}/evidence", json={
        "kind": "stagehand", "method": "stagehand", "environment": "local",
        "command": "trusted script via Chrome CDP", "observed": "Browser run",
        "proved": "Happy path", "artifact_path": str(artifact.relative_to(root)),
    })
    assert evidence.status_code == 201, evidence.text

    response = client.request(method, endpoint, **({"json": {"title": "Updated case"}} if method == "PATCH" else {}))
    assert response.status_code == 200, response.text
    detail = response.json()
    assert detail["review_evidence_ready"] is False
    assert ("passed browser happy-path result.json at current revision" in detail["review_evidence_missing"]) is result_missing
    assert detail["evidence"][0]["id"] == evidence.json()["id"]
    if method == "PATCH":
        assert detail["title"] == "Updated case"
        assert client.get(endpoint).json()["title"] == "Updated case"


@pytest.mark.parametrize(
    ("stagehand_steps", "screenshot_valid"),
    [(False, True), (True, False)],
    ids=["missing-observed-steps", "invalid-screenshot"],
)
def test_remediation_api_rejects_unrehearsed_stagehand_evidence(
    client, isolate_settings, stagehand_steps, screenshot_valid,
):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Reproduced",
    })
    client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={"verification_plan": "Follow tested UI steps"})
    _review_evidence(
        client, isolate_settings["engagements_dir"] / KEY, case["id"], revision,
        stagehand_steps=stagehand_steps, screenshot_valid=screenshot_valid,
    )
    client.post(f"{BASE}/cases/{case['id']}/transition", json={"status": "review", "actor": "operator", "reason": "Ready"})
    detail = client.get(f"{BASE}/cases/{case['id']}").json()
    assert detail["review_evidence_ready"] is False
    assert _approve(client, case["id"]).status_code == 409


def test_remediation_review_requires_baseline_outcome(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    client.patch(f"{BASE}/cases/{case['id']}", json={"worktree_path": str(worktree), "worktree_revision": revision})
    client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={"verification_plan": "Open page"})
    client.post(f"{BASE}/cases/{case['id']}/transition", json={"status": "review", "actor": "operator", "reason": "Ready"})
    assert _approve(client, case["id"]).status_code == 409
    rejected = client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "code_test_confirmed", "method": "Laravel", "proved": "Failing test",
    })
    assert rejected.status_code == 200, rejected.text
    assert _approve(client, case["id"]).status_code == 409
    allowed = client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "code_test_confirmed", "method": "Laravel", "proved": "Failing test",
        "owner_decision": "proceed", "owner_actor": "security-dev", "owner_reason": "Safe local run unavailable",
    })
    assert allowed.status_code == 200, allowed.text
    assert _approve(client, case["id"]).status_code == 409
    missing = client.get(f"{BASE}/cases/{case['id']}").json()["review_evidence_missing"]
    assert "red test" in " ".join(missing)
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revision)
    assert _approve(client, case["id"]).status_code == 201
    client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "security-dev", "reason": "Reapprove via CLI",
    })
    digest = client.get(f"{BASE}/cases/{case['id']}").json()["review_digest"]
    missing_instruction = client.post(f"{BASE}/cases/{case['id']}/approve", json={
        "reviewer": "security-dev", "expected_review_digest": digest,
        "approval_method": "cli_instruction",
    })
    assert missing_instruction.status_code == 400
    instruction = "Approve the reviewed SEC-101 case snapshot for a draft PR."
    approved = client.post(f"{BASE}/cases/{case['id']}/approve", json={
        "reviewer": "security-dev", "expected_review_digest": digest,
        "approval_method": "cli_instruction", "owner_instruction": instruction,
    })
    assert approved.status_code == 201, approved.text
    assert approved.json()["approval_method"] == "cli_instruction"
    assert approved.json()["owner_instruction"] == instruction


def test_remediation_deployment_requires_approved_revision(client, isolate_settings):
    case = _case(client, isolate_settings)
    denied = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy-dev", "run_id": "123", "environment": "development",
        "expected_revision": "a" * 40, "observed_revision": "b" * 40,
        "actor": "security-dev",
    })
    assert denied.status_code == 409, denied.text


@pytest.mark.parametrize(
    ("suffix", "payload"),
    [
        ("", {"title": "Changed after close"}),
        ("/verification-plan", {"verification_plan": "Changed after close"}),
        ("/baseline", {"outcome": "unreproduced", "method": "HTTP", "proved": "Changed after close"}),
        ("/release-plan", {
            "production_canary_decision": "defer", "production_canary_rationale": "Changed after close",
            "coralogix_monitoring": "Monitor",
        }),
    ],
    ids=["case", "verification-plan", "baseline", "release-plan"],
)
def test_remediation_closed_case_rejects_patches(client, isolate_settings, suffix, payload):
    case = _case(client, isolate_settings)
    with db.get_connection() as connection:
        connection.execute("UPDATE remediation_cases SET status='closed' WHERE id=?", (case["id"],))
    endpoint = f"{BASE}/cases/{case['id']}"
    before = client.get(endpoint).json()
    response = client.patch(endpoint + suffix, json=payload)
    assert response.status_code == 409, response.text
    after = client.get(endpoint).json()
    assert after["status"] == "closed"
    assert after["review_digest"] == before["review_digest"]


def test_remediation_closed_case_rejects_new_evidence(client, isolate_settings):
    case = _case(client, isolate_settings)
    with db.get_connection() as connection:
        connection.execute("UPDATE remediation_cases SET status='closed' WHERE id=?", (case["id"],))
    endpoint = f"{BASE}/cases/{case['id']}"
    before = client.get(endpoint).json()
    response = client.post(f"{endpoint}/evidence", json={
        "kind": "baseline", "method": "HTTP", "environment": "local",
        "observed": "Changed after close", "proved": "Changed after close",
    })
    assert response.status_code == 409, response.text
    after = client.get(endpoint).json()
    assert after["evidence"] == before["evidence"]
    assert after["review_digest"] == before["review_digest"]


@pytest.mark.parametrize("environment", ["test", "production"])
def test_remediation_deployment_rejects_unsupported_environment(client, isolate_settings, environment):
    case = _case(client, isolate_settings)
    response = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy", "run_id": "1", "environment": environment,
        "expected_revision": "a" * 40, "observed_revision": "a" * 40, "actor": "security-dev",
    })
    assert response.status_code == 422, response.text


def test_remediation_deployment_service_rejects_unsupported_environment(client, isolate_settings):
    case = _case(client, isolate_settings)
    with pytest.raises(HTTPException) as exc:
        remediation.deployment(KEY, case["id"], {
            "workflow": "deploy", "run_id": "1", "environment": "production",
            "expected_revision": "a" * 40, "observed_revision": "a" * 40, "actor": "security-dev",
        })
    assert exc.value.status_code == 400


def test_remediation_rejects_non_remediation_engagement(client, isolate_settings):
    root = isolate_settings["engagements_dir"] / KEY
    root.mkdir()
    db.create_engagement(KEY, "Example", "in_progress", str(root), "web")
    assert client.get(f"{BASE}/cases").status_code == 404


def test_remediation_link_can_reference_finding_in_assessment_engagement(client, isolate_settings):
    _engagement(isolate_settings)
    source_root = isolate_settings["engagements_dir"] / "original-assessment"
    source_root.mkdir()
    assessment = db.create_engagement("original-assessment", "Acme assessment", "in_progress", str(source_root), "web")
    with db.get_connection() as connection:
        finding_id = connection.execute(
            "INSERT INTO assessment_findings(engagement_id,slug,title) VALUES(?,?,?)",
            (assessment.id, "SEC-001", "Original vulnerability"),
        ).lastrowid
    linked = client.post(f"{BASE}/cases", json={
        "source_type": "jira", "source_key": "SEC-42", "title": "Fix original vulnerability",
        "snapshot": {}, "finding_ids": [finding_id],
    })
    assert linked.status_code == 201, linked.text
    assert linked.json()["linked_findings"][0]["engagement_key"] == "original-assessment"


def test_remediation_worktree_must_belong_to_case(client, isolate_settings):
    case = _case(client, isolate_settings)
    outside = isolate_settings["data_dir"] / "other-worktree"
    outside.mkdir()
    assert client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(outside), "worktree_revision": "a" * 40,
    }).status_code == 400


def test_remediation_case_binds_registered_worktree_branch_across_revision_sync(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "fix/custom-case"], check=True)
    (isolate_settings["engagements_dir"] / KEY / "PROJECT.md").write_text(
        '+++\nrepository = ' + json.dumps(str(worktree)) + '\n+++\n'
    )
    endpoint = f"{BASE}/cases/{case['id']}"
    registered = client.patch(endpoint, json={
        "worktree_path": str(worktree), "worktree_branch": "fix/custom-case",
        "worktree_revision": "a" * 40,
    })
    assert registered.status_code == 200, registered.text
    assert registered.json()["worktree_branch"] == "fix/custom-case"
    synced = client.patch(endpoint, json={"worktree_revision": "b" * 40})
    assert synced.status_code == 200, synced.text
    assert synced.json()["worktree_branch"] == "fix/custom-case"
    assert client.get(endpoint).json()["worktree_branch"] == "fix/custom-case"
    with db.get_connection() as connection:
        row = connection.execute("SELECT worktree_branch FROM remediation_cases WHERE id=?", (case["id"],)).fetchone()
    assert row["worktree_branch"] == "fix/custom-case"


def test_remediation_case_rejects_branch_mismatch_or_rebinding(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=fix/custom-case", str(worktree)], check=True)
    endpoint = f"{BASE}/cases/{case['id']}"
    assert client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_branch": "fix/other"}).status_code == 400
    assert client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_branch": " "}).status_code == 422
    assert client.patch(endpoint, json={"worktree_branch": "fix/custom-case"}).status_code == 400
    registered = client.patch(endpoint, json={"worktree_path": str(worktree), "worktree_branch": "fix/custom-case"})
    assert registered.status_code == 200, registered.text
    assert client.patch(endpoint, json={"worktree_branch": "fix/other"}).status_code == 409
    assert client.get(endpoint).json()["worktree_branch"] == "fix/custom-case"


def test_remediation_case_rejects_revision_sync_after_checkout_switch(client, isolate_settings):
    case = _case(client, isolate_settings)
    worktree = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "fix/custom-case"], check=True)
    (isolate_settings["engagements_dir"] / KEY / "PROJECT.md").write_text(
        '+++\nrepository = ' + json.dumps(str(worktree)) + '\n+++\n'
    )
    endpoint = f"{BASE}/cases/{case['id']}"
    registered = client.patch(endpoint, json={
        "worktree_path": str(worktree), "worktree_branch": "fix/custom-case",
        "worktree_revision": "a" * 40,
    })
    assert registered.status_code == 200, registered.text
    subprocess.run(["git", "-C", str(worktree), "symbolic-ref", "HEAD", "refs/heads/fix/other"], check=True)
    changed = client.patch(endpoint, json={"worktree_revision": "b" * 40})
    assert changed.status_code == 409, changed.text
    detail = client.get(endpoint).json()
    assert detail["worktree_branch"] == "fix/custom-case"
    assert detail["worktree_revision"] == "a" * 40


def test_remediation_case_rejects_rebound_worktree_path(client, isolate_settings):
    case = _case(client, isolate_settings)
    case_root = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"])
    first = case_root / "worktree"
    second = case_root / "replacement"
    first.mkdir(parents=True)
    second.mkdir()
    endpoint = f"{BASE}/cases/{case['id']}"
    assert client.patch(endpoint, json={"worktree_path": str(first)}).status_code == 200
    assert client.patch(endpoint, json={"worktree_path": str(second)}).status_code == 409
    assert client.get(endpoint).json()["worktree_path"] == str(first)


def test_remediation_configured_project_rejects_foreign_worktree(client, isolate_settings):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    repo = isolate_settings["data_dir"] / "source-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(repo)], check=True)
    (root / "PROJECT.md").write_text('+++\nrepository = ' + json.dumps(str(repo)) + '\n+++\n')
    foreign = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    foreign.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "--initial-branch=fix/case", str(foreign)], check=True)
    response = client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(foreign), "worktree_branch": "fix/case",
    })
    assert response.status_code == 400, response.text


def test_remediation_revision_sync_rejects_foreign_checkout_with_same_branch(client, isolate_settings):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    repo = isolate_settings["data_dir"] / "source-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(repo)], check=True)
    (repo / "base.txt").write_text("base")
    subprocess.run(["git", "-C", str(repo), "add", "base.txt"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    (root / "PROJECT.md").write_text('+++\nrepository = ' + json.dumps(str(repo)) + '\n+++\n')
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.parent.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-qb", "fix/custom-case", str(worktree)], check=True)
    endpoint = f"{BASE}/cases/{case['id']}"
    registered = client.patch(endpoint, json={
        "worktree_path": str(worktree), "worktree_branch": "fix/custom-case",
        "worktree_revision": "a" * 40,
    })
    assert registered.status_code == 200, registered.text
    subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(worktree)], check=True)
    worktree.mkdir()
    subprocess.run(["git", "init", "-q", "--initial-branch=fix/custom-case", str(worktree)], check=True)
    changed = client.patch(endpoint, json={"worktree_revision": "b" * 40})
    assert changed.status_code == 409, changed.text
    assert client.get(endpoint).json()["worktree_revision"] == "a" * 40


def test_remediation_approval_rejects_same_revision_on_another_branch(client, isolate_settings):
    case = _case(client, isolate_settings)
    root = isolate_settings["engagements_dir"] / KEY
    repo = isolate_settings["data_dir"] / "source-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(repo)], check=True)
    (repo / "fix.php").write_text("base")
    subprocess.run(["git", "-C", str(repo), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Base"], check=True)
    (root / "PROJECT.md").write_text('+++\nrepository = ' + json.dumps(str(repo)) + '\n+++\n')
    worktree = root / "remediation" / "cases" / str(case["id"]) / "worktree"
    worktree.parent.mkdir(parents=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-qb", "fix/custom-case", str(worktree)], check=True)
    (worktree / "fix.php").write_text("fixed")
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    endpoint = f"{BASE}/cases/{case['id']}"
    registered = client.patch(endpoint, json={
        "worktree_path": str(worktree), "worktree_branch": "fix/custom-case", "worktree_revision": revision,
    })
    assert registered.status_code == 200, registered.text
    assert client.patch(f"{endpoint}/verification-plan", json={"verification_plan": "Check account scope"}).status_code == 200
    assert client.patch(f"{endpoint}/baseline", json={
        "outcome": "runtime_reproduced", "method": "Laravel", "proved": "Cross-account write blocked",
    }).status_code == 200
    _review_evidence(client, root, case["id"], revision)
    assert client.post(f"{endpoint}/transition", json={
        "status": "review", "actor": "operator", "reason": "Ready",
    }).status_code == 200
    digest = client.get(endpoint).json()["review_digest"]
    subprocess.run(["git", "-C", str(worktree), "switch", "-qc", "fix/other"], check=True)
    assert _approve(client, case["id"]).status_code == 409
    subprocess.run(["git", "-C", str(worktree), "switch", "-q", "fix/custom-case"], check=True)
    assert client.get(endpoint).json()["review_digest"] == digest
    assert _approve(client, case["id"]).status_code == 201
    subprocess.run(["git", "-C", str(worktree), "switch", "-q", "fix/other"], check=True)
    assert client.get(endpoint).json()["approval_current"] is False
    assert client.post(f"{endpoint}/transition", json={
        "status": "pr_draft", "actor": "operator", "reason": "Ready",
    }).status_code == 409
    (root / "PROJECT.md").unlink()
    assert client.get(endpoint).json()["approval_current"] is False


def test_remediation_verification_requires_human_result(client, isolate_settings):
    case = _case(client, isolate_settings)
    denied = client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": "a" * 40,
        "notes": "Rehearsed form worked",
    })
    assert denied.status_code == 409, denied.text


def test_remediation_engagement_has_own_track_without_offensive_phase(client, isolate_settings):
    _engagement(isolate_settings)
    response = client.get(f"/engagements/{KEY}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert list(body["track_state"]) == ["remediation"]
    assert body["current_phase"] == "remediation"


def test_remediation_fixture_flow_preserves_approval_through_development_evidence(client, isolate_settings):
    case = _case(client, isolate_settings)
    case_root = isolate_settings["engagements_dir"] / KEY / "remediation" / "cases" / str(case["id"])
    worktree = case_root / "worktree"
    worktree.mkdir(parents=True)
    (worktree / "fix.php").write_text("authorized update only")
    subprocess.run(["git", "init", "-q", "--initial-branch=main", str(worktree)], check=True)
    _red_baseline(worktree)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "add", "fix.php"], check=True)
    subprocess.run(["git", "-C", str(worktree), "-c", "user.name=Vigil Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "Fix account scope"], check=True)
    revision = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    assert client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_path": str(worktree), "worktree_revision": revision,
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/baseline", json={
        "outcome": "code_test_confirmed", "method": "Laravel HTTP test", "proved": "Failing test",
        "owner_decision": "proceed", "owner_actor": "security-dev", "owner_reason": "Local runtime unavailable",
    }).status_code == 200
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revision)
    assert client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={
        "verification_plan": "Open Manage; sign in as owner; submit test update; confirm only own account changed; clean up test data",
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/release-plan", json={
        "production_canary_decision": "not_required",
        "production_canary_rationale": "Laravel boundary test and development human proof cover this route",
        "safe_procedure": "", "coralogix_monitoring": "Watch account update errors and denied cross-account writes",
    }).status_code == 200
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Evidence ready",
    }).status_code == 200
    reviewed_digest = client.get(f"{BASE}/cases/{case['id']}").json()["review_digest"]
    stale = client.post(f"{BASE}/cases/{case['id']}/approve", json={
        "reviewer": "security-dev", "expected_review_digest": "0" * 64,
        "approval_method": "ui",
    })
    assert stale.status_code == 409
    approved = client.post(f"{BASE}/cases/{case['id']}/approve", json={
        "reviewer": "security-dev", "expected_review_digest": reviewed_digest,
        "approval_method": "ui",
    })
    assert approved.status_code == 201, approved.text
    assert approved.json()["approval_method"] == "ui"
    for status in ("pr_draft", "development"):
        transition = client.post(f"{BASE}/cases/{case['id']}/transition", json={
            "status": status, "actor": "operator", "reason": "Ready",
        })
        assert transition.status_code == 200, transition.text
    dev = client.post(f"{BASE}/cases/{case['id']}/evidence", json={
        "kind": "development-stagehand", "method": "stagehand", "environment": "development", "observed": "Fixed happy path on dev",
        "proved": "Development browser route works", "revision": revision,
    })
    assert dev.status_code == 201, dev.text
    assert client.get(f"{BASE}/cases/{case['id']}").json()["approval_current"] is True
    wrong = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy-dev", "run_id": "1", "environment": "development",
        "expected_revision": revision, "observed_revision": "b" * 40, "actor": "security-dev",
    })
    assert wrong.status_code == 409
    deployed = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy-dev", "run_id": "1", "environment": "development",
        "expected_revision": revision, "observed_revision": revision, "actor": "security-dev",
    })
    assert deployed.status_code == 201, deployed.text
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "Dev proof",
    }).status_code == 409
    human = client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": revision,
        "notes": "Followed rehearsed Manage steps and saw own account update only",
    })
    assert human.status_code == 201, human.text
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "Human check passed",
    }).status_code == 200

    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Second fix needed",
    }).status_code == 200
    (worktree / "fix.php").write_text("authorized update only, revised")
    subprocess.run(["git", "-C", str(worktree), "add", "fix.php"], check=True)
    subprocess.run([
        "git", "-C", str(worktree), "-c", "user.name=Vigil Test",
        "-c", "user.email=test@example.invalid", "commit", "-qm", "Revise account scope fix",
    ], check=True)
    revised = subprocess.check_output(["git", "-C", str(worktree), "rev-parse", "HEAD"], text=True).strip()
    assert client.patch(f"{BASE}/cases/{case['id']}", json={
        "worktree_revision": revised,
    }).status_code == 200
    _review_evidence(client, isolate_settings["engagements_dir"] / KEY, case["id"], revised)
    assert _approve(client, case["id"]).status_code == 201
    for status in ("pr_draft", "development"):
        assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
            "status": status, "actor": "operator", "reason": "Revised fix ready",
        }).status_code == 200

    stale_transition = client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "Earlier dev proof",
    })
    assert stale_transition.status_code == 409
    stale_human = client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": revision,
        "notes": "Earlier revision still worked",
    })
    assert stale_human.status_code == 409

    deployed_revised = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy-dev", "run_id": "2", "environment": "development",
        "expected_revision": revised, "observed_revision": revised, "actor": "security-dev",
    })
    assert deployed_revised.status_code == 201, deployed_revised.text
    human_revised = client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": revised,
        "notes": "Revised fix passed development check",
    })
    assert human_revised.status_code == 201, human_revised.text
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "Revised fix verified",
    }).status_code == 200

    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "review", "actor": "operator", "reason": "Verification plan changed",
    }).status_code == 200
    assert client.patch(f"{BASE}/cases/{case['id']}/verification-plan", json={
        "verification_plan": "Open Manage; retest owner and cross-account changes; clean up test data",
    }).status_code == 200
    assert _approve(client, case["id"]).status_code == 201
    for status in ("pr_draft", "development"):
        assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
            "status": status, "actor": "operator", "reason": "New plan approved",
        }).status_code == 200
    assert client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": revised,
        "notes": "Old deployment is still live",
    }).status_code == 409
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "Proof from prior approval",
    }).status_code == 409
    current_approval = client.get(f"{BASE}/cases/{case['id']}").json()["approvals"][-1]
    redeployed = client.post(f"{BASE}/cases/{case['id']}/deployment", json={
        "workflow": "deploy-dev", "run_id": "3", "environment": "development",
        "expected_revision": revised, "observed_revision": revised, "actor": "security-dev",
    })
    assert redeployed.status_code == 201, redeployed.text
    assert redeployed.json()["approval_id"] == current_approval["id"]
    assert client.post(f"{BASE}/cases/{case['id']}/human-verification", json={
        "actor": "security-dev", "result": "passed", "observed_revision": revised,
        "notes": "Retested under the newly approved plan",
    }).status_code == 201
    assert client.post(f"{BASE}/cases/{case['id']}/transition", json={
        "status": "verified", "actor": "operator", "reason": "New plan verified",
    }).status_code == 200


@pytest.mark.parametrize("damage", [None, "commands.json", "script.py", "screen.png", "served_revision", "failed_command"])
def test_remediation_review_accepts_complete_browse_bundle(client, isolate_settings, damage):
    case = _case(client, isolate_settings)
    root = isolate_settings['engagements_dir'] / KEY
    worktree = root / 'remediation' / 'cases' / str(case['id']) / 'worktree'
    worktree.mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', '--initial-branch=main', str(worktree)], check=True)
    _red_baseline(worktree)
    _red_baseline(worktree)
    revision = subprocess.check_output(['git', '-C', str(worktree), 'rev-parse', 'HEAD'], text=True).strip()
    endpoint = f'{BASE}/cases/{case["id"]}'
    assert client.patch(endpoint, json={'worktree_path': str(worktree), 'worktree_revision': revision}).status_code == 200
    _review_evidence(client, root, case['id'], revision)
    run = root / 'remediation' / 'cases' / str(case['id']) / 'stagehand' / 'local-happy'
    result = json.loads((run / 'result.json').read_text())
    result['served_revision'] = revision
    (run / 'result.json').write_text(json.dumps(result))
    (run / 'commands.json').write_text(json.dumps([{'argv': ['browse', 'snapshot', '--local', '--session', 'case'], 'returncode': 0, 'stdout': 'Form visible', 'stderr': ''}]))
    if damage == "served_revision":
        result["served_revision"] = "other"
        (run / "result.json").write_text(json.dumps(result))
    elif damage == "failed_command":
        commands = json.loads((run / "commands.json").read_text())
        commands[0]["returncode"] = 1
        (run / "commands.json").write_text(json.dumps(commands))
    with db.get_connection() as conn:
        conn.execute('DELETE FROM remediation_evidence WHERE case_id=? AND method=?', (case['id'], 'stagehand'))
    for file in run.iterdir():
        response = client.post(endpoint + '/evidence', json={
            'kind': 'screenshot' if file.suffix == '.png' else 'browse', 'method': 'browse',
            'environment': 'local', 'command': 'trusted script with browse tools',
            'observed': 'Form worked', 'proved': 'Owner update saved',
            'artifact_path': str(file.relative_to(root)), 'revision': revision,
        })
        assert response.status_code == 201, response.text
    if damage in {"commands.json", "script.py", "screen.png"}:
        (run / damage).write_text("tampered")
    assert client.get(endpoint).json()['review_evidence_ready'] is (damage is None)
