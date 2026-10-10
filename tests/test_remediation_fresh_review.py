from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import threading
from types import SimpleNamespace

from vigil_cli import remediation


def test_approval_uses_registered_case_repository_after_profile_changes(monkeypatch, tmp_path):
    repository = tmp_path / "original"
    repository.mkdir()
    workspace = repository / "worktree"
    workspace.mkdir()
    case = {
        "id": 1, "worktree_revision": "a" * 40, "review_digest": "b" * 64,
        "review_policy": {"repository": str(repository)},
    }
    monkeypatch.setattr(remediation, "_project", lambda *_: (
        tmp_path, {"repository": str(tmp_path / "replacement")},
    ))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    checked = []

    def require_case_workspace(_case, selected):
        checked.append(selected)
        assert selected == repository
        return workspace

    monkeypatch.setattr(remediation, "_require_case_worktree", require_case_workspace)
    monkeypatch.setattr(remediation, "_require_clean_worktree", lambda *_: None)
    monkeypatch.setattr(remediation, "_revision", lambda *_: "a" * 40)
    monkeypatch.setattr(remediation, "_api", lambda *_: {})
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest="command"))
    args = parser.parse_args([
        "remediation", "-k", "acme", "approve", "1", "--reviewer", "owner",
        "--owner-instruction", "Approve this case", "--review-digest", "b" * 64,
    ])
    remediation.run_remediation(args, tmp_path)
    assert checked == [repository]


def test_identical_concurrent_deployment_requests_dispatch_once(monkeypatch, tmp_path):
    revision = "a" * 40
    config = {"repository": str(tmp_path), "deployment_workflow": "development.yml"}
    case = {"id": 1, "status": "pr_draft", "worktree_branch": "fix/SEC-123",
            "worktree_revision": revision, "evidence": []}
    args = argparse.Namespace(case_id="1", actor="owner", owner_instruction="Deploy development",
                              input=[], additional_tests_decision=None, new_request=False)
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_approved_current", lambda *_: tmp_path)
    monkeypatch.setattr(remediation, "_github_repository", lambda *_: "acme/application")
    monkeypatch.setattr(remediation, "_vcs", lambda: SimpleNamespace(origin_revision=lambda *_: revision))
    monkeypatch.setattr(remediation, "_api", lambda *_: {})
    barrier = threading.Barrier(2)
    dispatches = []
    seen = threading.local()

    def run(command, **_kwargs):
        if command[:3] == ["gh", "workflow", "run"]:
            dispatches.append(command)
            return SimpleNamespace(returncode=0, stdout="Accepted", stderr="")
        if not getattr(seen, "listed", False):
            seen.listed = True
            # Both callers reach the initial inventory before either writes the marker.
            try:
                barrier.wait(timeout=1)
            except threading.BrokenBarrierError:
                pass
        return SimpleNamespace(returncode=0, stdout=json.dumps([]), stderr="")

    monkeypatch.setattr(remediation.subprocess, "run", run)
    with ThreadPoolExecutor(max_workers=2) as workers:
        results = list(workers.map(lambda _: remediation._run_deployment(
            tmp_path, tmp_path, "acme", args, config,
        ), range(2)))
    assert all(result["request_state"] == "accepted" for result in results)
    assert len(dispatches) == 1
