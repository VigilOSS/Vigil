from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from vigil_cli import remediation


def parse(*arguments):
    parser = argparse.ArgumentParser()
    remediation.register_remediation_parser(parser.add_subparsers(dest="command"))
    return parser.parse_args(["remediation", *arguments])


def test_direct_report_intake_does_not_need_an_external_key():
    args = parse("import", "--source", "manual", "--title", "Potential account boundary bug",
                 "--snapshot-file", "report.json")
    assert args.source_key is None


def test_external_reference_resolves_to_stable_case_id(monkeypatch, tmp_path):
    cases = [{"id": 42, "external_provider": "tracker", "external_key": "ACME-7"},
             {"id": 43, "external_provider": "other", "external_key": "ACME-7"},
             {"id": 44, "external_provider": "tracker", "external_key": "123"}]
    monkeypatch.setattr(remediation, "_case_summaries", lambda *_: cases)
    assert remediation._resolve_case_id(tmp_path, tmp_path, "acme", "tracker:ACME-7") == "42"
    assert remediation._resolve_case_id(tmp_path, tmp_path, "acme", "tracker:123") == "44"
    assert remediation._resolve_case_id(tmp_path, tmp_path, "acme", "123") == "123"
    with pytest.raises(SystemExit, match="ambiguous"):
        remediation._resolve_case_id(tmp_path, tmp_path, "acme", "ACME-7")
    with pytest.raises(SystemExit, match="No case"):
        remediation._resolve_case_id(tmp_path, tmp_path, "acme", "tracker:missing")


def test_identity_and_finalization_have_separate_explicit_commands():
    identity = parse("identity", "42", "--provider", "tracker", "--key", "ACME-7")
    assert identity.provider == "tracker" and identity.external_key == "ACME-7"
    finalize = parse("finalize-branch", "42", "--branch", "fix/ACME-7-account-boundary")
    assert finalize.branch == "fix/ACME-7-account-boundary"


def test_current_external_key_is_used_in_navigation():
    case = {"id": 42, "title": "Account boundary", "status": "intake", "source_type": "manual",
            "source_key": "case-42", "external_provider": "tracker", "external_key": "ACME-7"}
    assert "tracker:ACME-7" in remediation._case_metadata(case)


def test_publication_checks_are_opt_in_during_investigation():
    assert parse("checks", "42", "--actor", "developer").stage == "verification"
    assert parse("checks", "42", "--actor", "developer", "--stage", "publication").stage == "publication"


def test_verification_runs_code_checks_before_ticket_is_available(monkeypatch, tmp_path):
    workspace = tmp_path / "source"
    workspace.mkdir()
    config = {"repository": str(tmp_path), "remediation": {"check_commands": [
        {"name": "unit", "command": "printf 'account controls passed'"},
        {"name": "ticket", "command": "exit 9", "stage": "publication"},
    ]}}
    case = {"id": 42, "worktree_revision": "revision", "review_policy": config}
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: workspace)
    monkeypatch.setattr(remediation, "_require_clean_worktree", lambda *_: None)
    monkeypatch.setattr(remediation, "_revision", lambda *_: "revision")
    monkeypatch.setattr(remediation, "_worktree_status", lambda *_: "")
    evidence = []
    monkeypatch.setattr(remediation, "_api", lambda *a: evidence.append(a[-1]) or {})
    result = remediation._run_profile_checks(tmp_path, tmp_path, "acme", case, config, "developer")
    assert [item["name"] for item in result["checks"]] == ["unit"]
    assert evidence[-1]["outcome"] == "passed"
    with pytest.raises(SystemExit, match="ticket failed"):
        remediation._run_profile_checks(tmp_path, tmp_path, "acme", case, config, "developer", stage="publication")
    assert evidence[-1]["method"] == "ticket" and evidence[-1]["outcome"] == "failed"


def test_branch_finalization_recovers_after_backend_registration_failure(monkeypatch, tmp_path):
    workspace = tmp_path / "source"
    workspace.mkdir()
    config = {"repository": str(tmp_path)}
    case = {"id": 42, "status": "fixing", "worktree_path": str(workspace), "worktree_branch": "provisional",
            "worktree_revision": "revision", "evidence": [], "review_policy": config}
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_is_registered_worktree", lambda *_: True)
    renames = []
    monkeypatch.setattr(remediation, "_vcs", lambda: SimpleNamespace(
        prepare_branch_finalization=lambda *_: True,
        ensure_unpublished_branches=lambda *_: None,
        finalize_branch=lambda *a: renames.append(a),
    ))
    calls = []
    def api(*args):
        calls.append(args[-1])
        if len(calls) == 1:
            raise SystemExit("backend temporarily unavailable")
        return {**case, "worktree_branch": "fix/ACME-7"}
    monkeypatch.setattr(remediation, "_api", api)
    with pytest.raises(SystemExit, match="backend temporarily unavailable"):
        remediation._finalize_case_branch(tmp_path, tmp_path, "acme", case, config, "fix/ACME-7")
    marker = tmp_path / "remediation/cases/42/branch-finalization.json"
    assert json.loads(marker.read_text())["old_branch"] == "provisional"
    result = remediation._finalize_case_branch(tmp_path, tmp_path, "acme", case, config, "fix/ACME-7")
    assert result["worktree_branch"] == "fix/ACME-7" and calls[0] == calls[1]
    assert renames[0] == renames[1]


def test_invalid_final_branch_does_not_block_corrected_request(monkeypatch, tmp_path):
    workspace = tmp_path / "source"
    workspace.mkdir()
    config = {"repository": str(tmp_path)}
    case = {"id": 42, "status": "fixing", "worktree_path": str(workspace), "worktree_branch": "provisional",
            "worktree_revision": "revision", "evidence": [], "review_policy": config}
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_is_registered_worktree", lambda *_: True)
    def prepare(_path, _old, new, _revision):
        if " " in new:
            raise ValueError("invalid branch name")
        return True
    monkeypatch.setattr(remediation, "_vcs", lambda: SimpleNamespace(
        prepare_branch_finalization=prepare, ensure_unpublished_branches=lambda *_: None,
        finalize_branch=lambda *_: None,
    ))
    monkeypatch.setattr(remediation, "_api", lambda *a: {**case, "worktree_branch": a[-1]["new_branch"]})
    with pytest.raises(SystemExit, match="invalid branch name"):
        remediation._finalize_case_branch(tmp_path, tmp_path, "acme", case, config, "fix/invalid name")
    result = remediation._finalize_case_branch(tmp_path, tmp_path, "acme", case, config, "fix/ACME-7")
    assert result["worktree_branch"] == "fix/ACME-7"


@pytest.mark.parametrize("command", ["identity", "create-pr"])
def test_publication_lock_uses_canonical_numeric_case_id(monkeypatch, tmp_path, command):
    args = argparse.Namespace(remediation_command=command, engagement_key="acme", case_id="042")
    monkeypatch.setattr(remediation, "_engagement_key", lambda *_: "acme")
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    observed = []
    monkeypatch.setattr(remediation, "_run_remediation", lambda args, *_: observed.append(args.case_id))
    remediation.run_remediation(args, tmp_path)
    assert observed == ["42"]
    assert (tmp_path / "remediation/cases/42/.publication.lock").is_file()


@pytest.mark.parametrize("identifier", ["42_0", "0", "-1", "１２", " 42"])
def test_case_artifacts_require_unambiguous_numeric_identity(tmp_path, identifier):
    args = argparse.Namespace(remediation_command="identity", engagement_key="acme", case_id=identifier)
    with pytest.raises(SystemExit, match="positive integer|positive"):
        remediation.run_remediation(args, tmp_path)


def test_generated_publication_content_uses_primary_external_reference(monkeypatch):
    case = {"id": 42, "title": "Fix account authorization", "external_provider": "tracker", "external_key": "ACME-7",
            "verification_plan": "Verify account ownership and legitimate access", "approvals": [{"evidence_cutoff_id": 1}],
            "verification_requirements": {"requirements": [{"kind": "api-test"}]},
            "verification_matches": [{"requirement_index": 0, "evidence_ids": [1], "missing": None}],
            "evidence": [{"id": 1, "kind": "api-test", "method": "pytest", "outcome": "passed", "observed": "Account controls passed"}]}
    monkeypatch.setattr(remediation, "_release_plan", lambda *_: {
        "production_canary_rationale": "Local authorization controls", "safe_procedure": "None needed",
        "monitoring": "Watch authorization failures",
    })
    body = remediation._pr_body(case, {}, "A record was selected without account ownership",
                                "Require matching ownership before returning the record")
    assert "ACME-7" in body
    assert remediation._publication_title(case) == "ACME-7 Fix account authorization"
