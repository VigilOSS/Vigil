from __future__ import annotations

import json
import argparse
import base64
import subprocess
from pathlib import Path

import pytest

from vigil_cli.engagements import CreateEngagementOptions, plan_engagement


@pytest.mark.parametrize("environment", ["test", "production"])
def test_deployment_parser_only_accepts_development(environment: str, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli.remediation import register_remediation_parser

    parser = argparse.ArgumentParser()
    register_remediation_parser(parser.add_subparsers(dest="command"))
    args = ["remediation", "-k", "project", "deployment", "1", "--workflow", "develop.yml",
            "--run-id", "123", "--expected-revision", "sha", "--observed-revision", "sha",
            "--actor", "owner", "--environment", environment]
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(args)
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_remediation_engagement_is_case_queue_without_offensive_phase(tmp_path: Path) -> None:
    repo = tmp_path / "acme"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    plan = plan_engagement(
        CreateEngagementOptions(
            install_root=tmp_path,
            engagement_type="remediation",
            name="Acme",
            repos=[str(repo)],
        )
    )
    assert plan.scope["engagement_type"] == "remediation"
    assert plan.scope["current_phase"] == "intake"
    assert "exploit_policy" not in plan.scope
    assert "cases" in plan.subdirs
    assert plan.manifest["repos"] == [{"path": str(tmp_path / "acme"), "name": "acme"}]


def test_remediation_engagement_requires_one_local_repo(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="exactly one repository"):
        plan_engagement(CreateEngagementOptions(install_root=tmp_path, engagement_type="remediation", name="Acme"))
    with pytest.raises(SystemExit, match="exactly one repository"):
        plan_engagement(CreateEngagementOptions(install_root=tmp_path, engagement_type="remediation", name="Acme", repos=["a", "b"]))


def test_stagehand_gate_requires_approved_model_and_loopback_browser() -> None:
    from vigil_cli.remediation import validate_stagehand_config
    config = {
        "browser_cdp_url": "http://127.0.0.1:9222",
        "stagehand": {"model": "openai/gpt-5.6-sol", "approved_account": "company-openai", "api_key_env": "TEST_STAGEHAND_KEY"},
    }
    with pytest.raises(SystemExit, match="approved provider key"):
        validate_stagehand_config(config, {})
    assert validate_stagehand_config(config, {"TEST_STAGEHAND_KEY": "key"}) == ("http://127.0.0.1:9222", "openai/gpt-5.6-sol", "key")
    config["browser_cdp_url"] = "http://remote.example:9222"
    with pytest.raises(SystemExit, match="loopback"):
        validate_stagehand_config(config, {"TEST_STAGEHAND_KEY": "key"})


def test_remediation_project_config_is_saved_in_plan(tmp_path: Path) -> None:
    config = {"development_url": "https://dev.example", "deployment_workflow": "develop.yml"}
    repo = tmp_path / "acme"
    repo.mkdir()
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    plan = plan_engagement(CreateEngagementOptions(
        install_root=tmp_path, engagement_type="remediation", name="Acme",
        repos=[str(repo)], remediation_config=config,
    ))
    assert plan.manifest["remediation_project"] == config
    assert "remediation_project" not in plan.scope
    assert plan.scope["hosts"] == []


def test_remediation_engagement_rejects_missing_or_non_git_repository(tmp_path: Path) -> None:
    with pytest.raises(SystemExit, match="existing local Git repository"):
        plan_engagement(CreateEngagementOptions(install_root=tmp_path, engagement_type="remediation", name="Acme", repos=[str(tmp_path / "missing")]))
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(SystemExit, match="existing local Git repository"):
        plan_engagement(CreateEngagementOptions(install_root=tmp_path, engagement_type="remediation", name="Acme", repos=[str(empty)]))


def test_pr_requires_final_production_canary_decision() -> None:
    from vigil_cli.remediation import _release_plan

    with pytest.raises(SystemExit, match="final canary decision"):
        _release_plan({"release_plan": {
            "production_canary_decision": "defer",
            "production_canary_rationale": "Awaiting owner decision",
            "safe_procedure": "",
            "coralogix_monitoring": "Watch authorization failures",
        }})


def test_prepare_pr_refuses_stale_approval_and_revision(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    case = {"approval_current": False, "worktree_path": str(tmp_path), "worktree_revision": "reviewed"}
    with pytest.raises(SystemExit, match="no current approval"):
        remediation._approved_current(case, tmp_path)
    case["approval_current"] = True
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: tmp_path)
    monkeypatch.setattr(remediation, "_revision", lambda _: "changed")
    with pytest.raises(SystemExit, match="revision changed"):
        remediation._approved_current(case, tmp_path)


def test_import_preserves_snapshot_and_attachments(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    source = tmp_path / "issue.json"
    source.write_text('{"report":"untrusted report text"}', encoding="utf-8")
    attachment = tmp_path / "report.txt"
    attachment.write_text("untrusted attachment", encoding="utf-8")
    calls: list[tuple[str, str, dict | None]] = []
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))

    def fake_api(_root: Path, _eng: Path, _key: str, method: str, path: str, payload: dict | None = None) -> dict:
        calls.append((method, path, payload))
        return {"id": 1}

    monkeypatch.setattr(remediation, "_api", fake_api)
    args = argparse.Namespace(engagement_key="project", remediation_command="import", source="jira", source_key="SEC-1", title="A bug", snapshot_file=source, attachment=[attachment], finding_id=[3, 4], resume_case_id=None)
    remediation.run_remediation(args, tmp_path)
    snapshot = calls[0][2]["snapshot"]
    assert calls[0][2]["finding_ids"] == [3, 4]
    assert "linked_finding_slug" not in calls[0][2]
    assert snapshot["report"] == "untrusted report text"
    assert (eng / "remediation/cases/1/source/snapshot.json").is_file()
    assert (eng / "remediation/cases/1/source/1-report.txt").read_text() == "untrusted attachment"
    assert calls[1][1] == "/cases/1/evidence"
    assert '"id": 1' in capsys.readouterr().out


def test_finding_intake_names_destination_without_fabricating_external_source(monkeypatch, tmp_path):
    from vigil_cli import remediation

    calls = []
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    monkeypatch.setattr(remediation, "_api", lambda *args: calls.append(args) or {"id": 7})
    args = argparse.Namespace(engagement_key="repairs", remediation_command="from-finding", finding_engagement="assessment", finding="SEC/1", title=None)
    remediation.run_remediation(args, tmp_path)
    assert calls[0][2:6] == ("assessment", "POST", "/findings/SEC%2F1/cases", {"remediation_engagement_key": "repairs"})


def test_create_pr_requires_current_approval_before_push(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    body = tmp_path / "body.md"
    body.write_text("Reviewed PR content", encoding="utf-8")
    case = {"approval_current": False, "worktree_path": str(tmp_path), "worktree_revision": "abc"}
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    invoked: list[list[str]] = []
    monkeypatch.setattr(remediation.subprocess, "run", lambda command, **kwargs: invoked.append(command))
    args = argparse.Namespace(engagement_key="project", remediation_command="create-pr", case_id="1", body_file=body, actor="owner")
    with pytest.raises(SystemExit, match="no current approval"):
        remediation.run_remediation(args, tmp_path)
    assert not invoked


def test_stagehand_happy_path_requires_screenshot_and_observed_steps(tmp_path: Path) -> None:
    from vigil_cli.remediation import validate_stagehand_result

    with pytest.raises(SystemExit, match="observed UI steps"):
        validate_stagehand_result({"status": "passed", "observed": "worked", "proved": "happy path"}, tmp_path, "happy-path")
    (tmp_path / "screen.png").write_bytes(b"png")
    with pytest.raises(SystemExit, match="valid screenshot"):
        validate_stagehand_result({"status": "passed", "steps": [{"action": "Open form", "observation": "Form visible"}], "observed": "worked", "proved": "happy path"}, tmp_path, "happy-path")
    (tmp_path / "screen.png").write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLttAAAAABJRU5ErkJggg=="))
    with pytest.raises(SystemExit, match="observed UI steps"):
        validate_stagehand_result({"status": "passed", "steps": [], "observed": "worked", "proved": "happy path"}, tmp_path, "happy-path")
    assert validate_stagehand_result({"status": "passed", "steps": [{"action": "Open form", "observation": "Form visible"}], "observed": "worked", "proved": "happy path"}, tmp_path, "happy-path") is None


def test_pr_gate_refuses_uncommitted_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    case = {"approval_current": True, "worktree_path": str(tmp_path), "worktree_revision": "abc"}
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: tmp_path)
    monkeypatch.setattr(remediation, "_revision", lambda _: "abc")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: " M app.php")
    with pytest.raises(SystemExit, match="uncommitted"):
        remediation._approved_current(case, tmp_path)


def test_pr_body_requires_production_decision_and_monitoring() -> None:
    from vigil_cli.remediation import _pr_body

    evidence = [{"id": index, "kind": kind, "method": "Laravel" if kind != "stagehand" else "stagehand",
                 "environment": "local" if kind != "stagehand" else "development",
                 "observed": "observed", "proved": "proved"}
                for index, kind in enumerate(("red-test", "green-test", "stagehand"), 1)]
    case = {"title": "Fix", "review_digest": "newer-digest", "approval_current": True, "approvals": [{"review_digest": "approved-digest", "evidence_cutoff_id": 3}], "evidence": evidence, "worktree_revision": "sha", "verification_plan": "Open Manage and verify result"}
    with pytest.raises(SystemExit, match="release plan"):
        _pr_body(case, {}, "Controller authorizes wrong tenant context", "Validate tenant ownership before update")
    case["release_plan"] = {"production_canary_decision": "required", "production_canary_rationale": "Infrastructure behavior", "safe_procedure": "Use test account", "coralogix_monitoring": "Watch errors"}
    body = _pr_body(case, {}, "Controller authorizes wrong tenant context", "Validate tenant ownership before update")
    assert "approved-digest" in body
    assert "newer-digest" not in body
    assert "Controller authorizes wrong tenant context" in body
    assert "Infrastructure behavior" in body
    assert "Use test account" in body
    assert "Watch errors" in body


def test_pr_body_includes_reviewed_evidence_environments() -> None:
    from vigil_cli.remediation import _pr_body, _required_reviewed_evidence_lines

    evidence = [{"id": index, "kind": kind, "method": method, "environment": environment,
                 "revision": "sha", "observed": "observed", "proved": "proved"}
                for index, (kind, method, environment) in enumerate((
                    ("red-test", "Laravel", "local"),
                    ("green-test", "Laravel", "test"),
                    ("stagehand", "stagehand", "development"),
                ), 1)]
    case = {"title": "Fix", "approval_current": True,
            "approvals": [{"review_digest": "a" * 64, "evidence_cutoff_id": 3}],
            "evidence": evidence, "worktree_revision": "sha",
            "verification_plan": "Open the tested form and verify the saved result",
            "release_plan": {"production_canary_decision": "not_required", "production_canary_rationale": "Route coverage",
                             "safe_procedure": "", "coralogix_monitoring": "Watch errors"}}

    body = _pr_body(case, {}, "Controller selects an unscoped record by ID", "Load records through the authorized tenant relation")

    assert "environment: local" in body
    assert "environment: test" in body
    assert "environment: development" in body
    assert all(line in body for line in _required_reviewed_evidence_lines(case))


def test_compose_identity_requires_served_source_mount(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    import subprocess

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    compose = worktree / "compose.yml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(remediation, "_revision", lambda _: "abc123")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "compose"]:
            return subprocess.CompletedProcess(command, 0, "container-1\n", "")
        return subprocess.CompletedProcess(command, 0, json.dumps([{
            "Id": "container-1", "Image": "sha256:image", "Config": {"Labels": {}},
            "Mounts": [{"Type": "bind", "Source": str(tmp_path / "other"), "Destination": "/app"}],
        }]), "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    unproven = remediation.inspect_compose_identity(worktree, compose, "web", "/app")
    assert unproven["status"] == "unproven"
    assert unproven["containers"][0]["image_id"] == "sha256:image"


@pytest.mark.parametrize("mount_source,image_revision", [("worktree", ""), ("other", "abc123")])
def test_compose_identity_accepts_proven_mount_or_image_revision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mount_source: str, image_revision: str,
) -> None:
    from vigil_cli import remediation
    import subprocess

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    compose = worktree / "compose.yml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(remediation, "_revision", lambda _: "abc123")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")
    source = worktree if mount_source == "worktree" else tmp_path / "other"

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "compose"]:
            return subprocess.CompletedProcess(command, 0, "container-1\n", "")
        return subprocess.CompletedProcess(command, 0, json.dumps([{
            "Id": "container-1", "Image": "sha256:image",
            "Config": {"Labels": {"org.opencontainers.image.revision": image_revision}},
            "Mounts": [{"Type": "bind", "Source": str(source), "Destination": "/app"}] if mount_source == "worktree" else [],
        }]), "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    result = remediation.inspect_compose_identity(worktree, compose, "web", "/app", "abc123")
    assert result["status"] == "matched"
    assert result["containers"][0]["matched"] is True


def test_compose_identity_unproven_when_no_container_or_case_revision_changes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    import subprocess

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    compose = worktree / "compose.yml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(remediation, "_revision", lambda _: "new-sha")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")
    monkeypatch.setattr(remediation.subprocess, "run", lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""))
    result = remediation.inspect_compose_identity(worktree, compose, "web", "/app", "old-sha")
    assert result["status"] == "unproven"
    assert result["containers"] == []


def test_compose_overlay_mount_overrides_worktree_and_image_label(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    import subprocess

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    compose = worktree / "compose.yml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(remediation, "_revision", lambda _: "abc")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "compose"]:
            return subprocess.CompletedProcess(command, 0, "c1\n", "")
        return subprocess.CompletedProcess(command, 0, json.dumps([{
            "Id": "c1", "Image": "image", "Config": {"Labels": {"org.opencontainers.image.revision": "abc"}},
            "Mounts": [
                {"Type": "bind", "Source": str(worktree), "Destination": "/app"},
                {"Type": "volume", "Source": "stale-data", "Destination": "/app/current"},
            ],
        }]), "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    result = remediation.inspect_compose_identity(worktree, compose, "web", "/app/current")
    assert result["status"] == "unproven"
    assert result["containers"][0]["served_source"] == "unproven"


def test_compose_nested_external_mount_blocks_root_match(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    import subprocess

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    compose = worktree / "compose.yml"
    compose.write_text("services: {}", encoding="utf-8")
    monkeypatch.setattr(remediation, "_revision", lambda _: "abc")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "compose"]:
            return subprocess.CompletedProcess(command, 0, "c1\n", "")
        return subprocess.CompletedProcess(command, 0, json.dumps([{
            "Id": "c1", "Image": "image", "Config": {"Labels": {}},
            "Mounts": [
                {"Type": "bind", "Source": str(worktree), "Destination": "/app"},
                {"Type": "volume", "Source": "external-config", "Destination": "/app/config"},
            ],
        }]), "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    result = remediation.inspect_compose_identity(worktree, compose, "web", "/app")
    assert result["status"] == "unproven"
    assert result["containers"][0]["descendant_overlay"] is True


def test_stagehand_failed_status_cannot_claim_happy_path(tmp_path: Path) -> None:
    from vigil_cli.remediation import validate_stagehand_result

    (tmp_path / "screen.png").write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4z8DwHwAFgAI/ScLttAAAAABJRU5ErkJggg=="))
    result = {"status": "failed", "observed": "form visible", "proved": "nothing", "steps": [{"action": "open", "observation": "visible"}]}
    with pytest.raises(SystemExit, match="passed status"):
        validate_stagehand_result(result, tmp_path, "happy-path")


@pytest.mark.parametrize("case_response", [None, {"id": 7, "status": "closed"}])
def test_stagehand_checks_case_before_browser_actions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, case_response: dict | None,
) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    script = tmp_path / "rehearsal.py"
    script.write_text("async def run(stagehand, output_dir): pass\n", encoding="utf-8")
    args = argparse.Namespace(case_id="7", script=script, revision="abc123", environment="local",
                              purpose="bad-path", production_decision=None, production_evidence_policy=None)
    monkeypatch.setattr(remediation, "validate_stagehand_config", lambda *_: None)
    calls: list[str] = []

    def fake_api(_root: Path, _eng: Path, _key: str, method: str, path: str, _payload=None) -> dict:
        calls.append(f"{method} {path}")
        if case_response is None:
            raise SystemExit("case not found")
        return case_response

    async def fake_execute(*_args) -> dict:
        calls.append("browser executed")
        return {"status": "passed"}

    monkeypatch.setattr(remediation, "_api", fake_api)
    monkeypatch.setattr(remediation, "_execute_stagehand", fake_execute)

    with pytest.raises(SystemExit, match="case not found|closed"):
        remediation._run_stagehand(tmp_path, eng, "project", args, {})

    assert "browser executed" not in calls
    assert not (eng / "remediation" / "cases" / "7").exists()


def test_production_stagehand_requires_decision_and_evidence_policy(tmp_path: Path) -> None:
    from vigil_cli.remediation import validate_production_stagehand_policy

    args = argparse.Namespace(environment="production", purpose="bad-path", production_decision="Owner approved", production_evidence_policy=None)
    with pytest.raises(SystemExit, match="evidence policy"):
        validate_production_stagehand_policy(args, tmp_path)
    args.production_evidence_policy = "no-screenshots"
    (tmp_path / "screen.png").write_bytes(b"unexpected screenshot")
    with pytest.raises(SystemExit, match="forbids screenshots"):
        validate_production_stagehand_policy(args, tmp_path)


def test_import_registration_failure_exposes_resume_case_id(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    source = tmp_path / "issue.json"
    source.write_text('{"report":"text"}', encoding="utf-8")
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {}))

    def fake_api(_root: Path, _eng: Path, _key: str, method: str, _path: str, _payload: dict | None = None) -> dict:
        if method == "POST" and _path == "/cases":
            return {"id": 7}
        raise SystemExit("backend unavailable")

    monkeypatch.setattr(remediation, "_api", fake_api)
    args = argparse.Namespace(engagement_key="project", remediation_command="import", source="jira", source_key="SEC-7", title="Issue", snapshot_file=source, attachment=[], finding_id=[], resume_case_id=None)
    with pytest.raises(SystemExit, match="--resume-case-id 7"):
        remediation.run_remediation(args, tmp_path)
    assert (eng / "remediation/cases/7/source/snapshot.json").is_file()


def test_worktree_retry_reuses_existing_case_branch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/3/worktree"
    repo = tmp_path / "source"
    subprocess.run(["git", "init", "--initial-branch=main", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", "codex/remediation-project-3", str(worktree)], check=True, capture_output=True)
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(repo)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"id": 3, "worktree_path": None})
    calls: list[dict] = []
    monkeypatch.setattr(remediation, "_api", lambda _root, _eng, _key, method, path, payload: calls.append(payload) or {"worktree_path": str(worktree)})
    args = argparse.Namespace(engagement_key="project", remediation_command="worktree", case_id="3", base="main", branch=None)
    remediation.run_remediation(args, tmp_path)
    assert calls == [{"worktree_path": str(worktree), "worktree_branch": "codex/remediation-project-3",
                      "worktree_revision": remediation._revision(worktree), "base_branch": "main",
                      "base_revision": remediation._revision(worktree)}]


def test_worktree_retry_rejects_matching_branch_from_unrelated_repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    source = tmp_path / "source"
    foreign = tmp_path / "foreign"
    worktree = tmp_path / "eng/remediation/cases/3/worktree"
    for repo in (source, foreign):
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(foreign), "branch", "codex/remediation-project-3"], check=True)
    subprocess.run(["git", "-C", str(foreign), "worktree", "add", str(worktree), "codex/remediation-project-3"], check=True, capture_output=True)

    eng = tmp_path / "eng"
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(source)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"id": 3, "worktree_path": None})
    monkeypatch.setattr(remediation, "_api", lambda *_args, **_kwargs: pytest.fail("foreign worktree must not be recorded"))
    args = argparse.Namespace(engagement_key="project", remediation_command="worktree", case_id="3", base="main", branch=None)

    with pytest.raises(SystemExit, match="configured repository"):
        remediation.run_remediation(args, tmp_path)


def test_worktree_retry_rejects_case_path_symlink_to_another_registered_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    source = tmp_path / "source"
    other_worktree = tmp_path / "other-worktree"
    case_worktree = tmp_path / "eng/remediation/cases/3/worktree"
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "worktree", "add", "-b", "codex/remediation-project-3", str(other_worktree)], check=True, capture_output=True)
    case_worktree.parent.mkdir(parents=True)
    case_worktree.symlink_to(other_worktree, target_is_directory=True)

    eng = tmp_path / "eng"
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(source)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"id": 3, "worktree_path": None})
    monkeypatch.setattr(remediation, "_api", lambda *_args, **_kwargs: pytest.fail("symlinked worktree must not be recorded"))
    args = argparse.Namespace(engagement_key="project", remediation_command="worktree", case_id="3", base="main", branch=None)

    with pytest.raises(SystemExit, match="configured repository"):
        remediation.run_remediation(args, tmp_path)


def test_sync_revision_records_clean_case_worktree_head(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/3/worktree"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(worktree), "worktree_revision": "old-sha"})
    monkeypatch.setattr(remediation, "_is_registered_worktree", lambda *_: True)
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: worktree)
    monkeypatch.setattr(remediation, "_revision", lambda _: "fixed-sha")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")
    calls: list[tuple[str, str, dict]] = []
    monkeypatch.setattr(remediation, "_api", lambda _root, _eng, _key, method, path, payload: calls.append((method, path, payload)) or {"worktree_revision": "fixed-sha"})

    args = argparse.Namespace(engagement_key="project", remediation_command="sync-revision", case_id="3")
    remediation.run_remediation(args, tmp_path)

    assert calls == [("PATCH", "/cases/3", {"worktree_revision": "fixed-sha"})]


def test_sync_revision_rejects_replaced_worktree_from_unrelated_repository(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    source = tmp_path / "source"
    foreign = tmp_path / "foreign"
    worktree = tmp_path / "eng/remediation/cases/3/worktree"
    for repo in (source, foreign):
        subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "worktree", "add", "-b", "case-3", str(worktree)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "worktree", "remove", str(worktree)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(foreign), "worktree", "add", "-b", "case-3", str(worktree)], check=True, capture_output=True)

    eng = tmp_path / "eng"
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(source)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(worktree), "worktree_revision": "old-sha"})
    monkeypatch.setattr(remediation, "_api", lambda *_args, **_kwargs: pytest.fail("foreign revision must not be recorded"))
    args = argparse.Namespace(engagement_key="project", remediation_command="sync-revision", case_id="3")

    with pytest.raises(SystemExit, match="configured repository"):
        remediation.run_remediation(args, tmp_path)


@pytest.mark.parametrize("command", ["sync-revision", "approve"])
def test_case_operation_rejects_different_branch_in_registered_worktree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, command: str,
) -> None:
    from vigil_cli import remediation

    repo = tmp_path / "source"
    worktree = tmp_path / "eng/remediation/cases/3/worktree"
    subprocess.run(["git", "init", str(repo)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", "case-3", str(worktree)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(worktree), "switch", "-c", "other-case"], check=True, capture_output=True)
    case = {"worktree_path": str(worktree), "worktree_branch": "case-3", "worktree_revision": remediation._revision(worktree),
            "review_digest": "reviewed"}
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path / "eng", {"repository": str(repo)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("wrong branch must not be recorded"))

    args = argparse.Namespace(engagement_key="project", remediation_command=command, case_id="3",
                              owner_instruction="Approve reviewed case", reviewer="owner", review_digest="reviewed")
    with pytest.raises(SystemExit, match="case worktree branch"):
        remediation.run_remediation(args, tmp_path)


def test_create_pr_rejects_replaced_foreign_worktree_with_same_revision(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    source = tmp_path / "source"
    foreign = tmp_path / "foreign"
    worktree = tmp_path / "eng/remediation/cases/3/worktree"
    subprocess.run(["git", "init", str(source)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.com"], check=True)
    subprocess.run(["git", "-C", str(source), "config", "user.name", "Test"], check=True)
    subprocess.run(["git", "-C", str(source), "commit", "--allow-empty", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "clone", str(source), str(foreign)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(source), "worktree", "add", "-b", "case-3", str(worktree)], check=True, capture_output=True)
    revision = remediation._revision(worktree)
    subprocess.run(["git", "-C", str(source), "worktree", "remove", str(worktree)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(foreign), "worktree", "add", "-b", "case-3", str(worktree)], check=True, capture_output=True)
    assert remediation._revision(worktree) == revision
    case = {"status": "approved", "approval_current": True, "worktree_path": str(worktree),
            "worktree_branch": "case-3", "worktree_revision": revision}
    body = tmp_path / "body.md"
    body.write_text("reviewed", encoding="utf-8")
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path / "eng", {"repository": str(source)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("foreign worktree must not be recorded"))

    args = argparse.Namespace(engagement_key="project", remediation_command="create-pr", case_id="3",
                              body_file=body, actor="owner", template_mapped=True)
    with pytest.raises(SystemExit, match="configured repository"):
        remediation.run_remediation(args, tmp_path)


@pytest.mark.parametrize("dirty", [" M app.php", "?? new.php"])
def test_sync_revision_rejects_dirty_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dirty: str) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/3/worktree"
    worktree.mkdir(parents=True)
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(worktree), "worktree_revision": "old-sha"})
    monkeypatch.setattr(remediation, "_is_registered_worktree", lambda *_: True)
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: worktree)
    monkeypatch.setattr(remediation, "_revision", lambda _: "fixed-sha")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: dirty)
    calls: list[dict] = []
    monkeypatch.setattr(remediation, "_api", lambda *_args: calls.append(_args[-1]))

    args = argparse.Namespace(engagement_key="project", remediation_command="sync-revision", case_id="3")
    with pytest.raises(SystemExit, match="uncommitted or untracked"):
        remediation.run_remediation(args, tmp_path)
    assert calls == []


def test_sync_revision_rejects_foreign_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(foreign)})
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("foreign revision must not be recorded"))

    args = argparse.Namespace(engagement_key="project", remediation_command="sync-revision", case_id="3")
    with pytest.raises(SystemExit, match="case worktree"):
        remediation.run_remediation(args, tmp_path)


def test_create_pr_reconciles_existing_draft_without_second_push(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    monkeypatch.setattr(remediation, "_github_repository", lambda *_: None)
    monkeypatch.setattr(remediation, "_record_publication", lambda *_: None)
    import subprocess

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/1/worktree"
    worktree.mkdir(parents=True)
    digest = "a" * 64
    root_cause = "Missing ownership check in update controller"
    fix = "Validate ownership before performing the update"
    release = {"production_canary_decision": "not_required", "production_canary_rationale": "Laravel route coverage", "safe_procedure": "", "coralogix_monitoring": "Watch authorization failures"}
    evidence = [{"id": index, "kind": kind, "method": "Laravel" if kind != "stagehand" else "stagehand",
                 "environment": "local" if kind != "stagehand" else "development",
                 "observed": "observed", "proved": "proved"}
                for index, kind in enumerate(("red-test", "green-test", "stagehand"), 1)]
    case = {"status": "approved", "approval_current": True, "approvals": [{"review_digest": digest, "evidence_cutoff_id": 3}], "evidence": evidence, "worktree_path": str(worktree), "worktree_branch": "codex/remediation-project-1", "worktree_revision": "sha", "release_plan": release, "verification_plan": "Open Manage and confirm the fixed result", "title": "Fix"}
    content = eng / "remediation/cases/1/pr-content.json"
    content.write_text(json.dumps({"approval_digest": digest, "root_cause": root_cause, "fix_summary": fix}), encoding="utf-8")
    body = tmp_path / "body.md"
    required_evidence = remediation._required_reviewed_evidence_lines(case)
    body.write_text(f"{digest}\nsha\nnot_required\nLaravel route coverage\nWatch authorization failures\n{root_cause}\n{fix}\n{case['verification_plan']}\n" + "\n".join(required_evidence), encoding="utf-8")
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: worktree)
    monkeypatch.setattr(remediation, "_revision", lambda _: "sha")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")
    remote_body = {"value": "Outdated draft content"}
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["gh", "pr", "list"]:
            row = {"url": "https://github.com/example/repo/pull/1", "state": "OPEN", "isDraft": True,
                   "headRefName": "codex/remediation-project-1", "baseRefName": "main", "headRefOid": "sha",
                   "body": remote_body["value"]}
            return subprocess.CompletedProcess(command, 0, json.dumps([row]), "")
        return subprocess.CompletedProcess(command, 0, "codex/remediation-project-1\n", "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    transitions: list[dict] = []

    def fake_api(*api_args: object) -> dict:
        if str(api_args[4]).endswith("/evidence"):
            case["evidence"].append({"id": 4, "kind": "pr_body", "artifact_path": api_args[-1]["artifact_path"]})
            return {"id": 4}
        transitions.append(api_args[-1])
        if len(transitions) == 1:
            raise SystemExit("connection lost after PR creation")
        return {"status": "pr_draft"}

    monkeypatch.setattr(remediation, "_api", fake_api)
    args = argparse.Namespace(engagement_key="project", remediation_command="create-pr", case_id="1", body_file=body, actor="owner", template_mapped=True)
    full_body = body.read_text(encoding="utf-8")
    body.write_text(full_body.replace(case["verification_plan"], ""), encoding="utf-8")
    with pytest.raises(SystemExit, match="missing reviewed plan"):
        remediation.run_remediation(args, tmp_path)
    assert not commands
    body.write_text(full_body.replace("[environment: development]", ""), encoding="utf-8")
    with pytest.raises(SystemExit, match="missing reviewed plan, evidence"):
        remediation.run_remediation(args, tmp_path)
    assert not commands
    body.write_text(full_body, encoding="utf-8")
    with pytest.raises(SystemExit, match="draft PR body differs"):
        remediation.run_remediation(args, tmp_path)
    assert not transitions
    remote_body["value"] = full_body
    with pytest.raises(SystemExit, match="draft PR exists at https://github.com/example/repo/pull/1"):
        remediation.run_remediation(args, tmp_path)
    remediation.run_remediation(args, tmp_path)
    assert all(command[:3] == ["gh", "pr", "list"] for command in commands)
    assert transitions[0]["status"] == "pr_draft"


def test_existing_draft_pr_rejects_remote_head_that_differs_from_case_worktree(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    monkeypatch.setattr(remediation, "_github_repository", lambda *_: None)

    worktree = tmp_path / "worktree"
    worktree.mkdir()
    monkeypatch.setattr(remediation, "_revision", lambda _: "approved-sha")
    row = {"url": "https://github.com/example/repo/pull/1", "state": "OPEN", "isDraft": True,
           "headRefName": "codex/remediation-1", "baseRefName": "main", "headRefOid": "different-sha",
           "body": "reviewed body"}
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps([row]), "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)

    with pytest.raises(SystemExit, match="head revision"):
        remediation._existing_draft_pr(worktree, "codex/remediation-1", "reviewed body")
    assert "headRefOid" in commands[0][-1]
    row["headRefOid"] = "approved-sha"
    assert remediation._existing_draft_pr(worktree, "codex/remediation-1", "reviewed body") == row["url"]


def test_create_pr_creates_and_verifies_new_draft_before_transition(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation
    monkeypatch.setattr(remediation, "_github_repository", lambda *_: None)
    monkeypatch.setattr(remediation, "_record_publication", lambda *_: None)

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/1/worktree"
    worktree.mkdir(parents=True)
    digest = "a" * 64
    root_cause = "Controller selects a record without its tenant scope"
    fix = "Load records through the authorized tenant relation"
    plan = "Open the tested page and confirm the saved value"
    release = {"production_canary_decision": "not_required", "production_canary_rationale": "Laravel route coverage",
               "safe_procedure": "", "coralogix_monitoring": "Watch authorization failures"}
    evidence = [{"id": index, "kind": kind, "method": "Laravel" if kind != "stagehand" else "stagehand", "observed": "observed", "proved": "proved"}
                for index, kind in enumerate(("red-test", "green-test", "stagehand"), 1)]
    case = {"status": "approved", "approval_current": True, "approvals": [{"review_digest": digest, "evidence_cutoff_id": 3}],
            "evidence": evidence, "worktree_path": str(worktree), "worktree_branch": "codex/remediation-1",
            "worktree_revision": "sha", "release_plan": release,
            "verification_plan": plan, "title": "Fix"}
    content = eng / "remediation/cases/1/pr-content.json"
    content.write_text(json.dumps({"approval_digest": digest, "root_cause": root_cause, "fix_summary": fix}), encoding="utf-8")
    body = tmp_path / "body.md"
    required_evidence = remediation._required_reviewed_evidence_lines(case)
    body.write_text(f"{digest}\nsha\nnot_required\nLaravel route coverage\nWatch authorization failures\n{root_cause}\n{fix}\n{plan}\n" + "\n".join(required_evidence), encoding="utf-8")
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_approved_current", lambda *_: worktree)
    monkeypatch.setattr(remediation, "_revision", lambda *_: "sha")
    monkeypatch.setattr(remediation, "_register_pr_body", lambda *_: body)
    remote_body = {"value": "Stale body after creation"}
    created = {"value": False}
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[:3] == ["gh", "pr", "list"]:
            rows = [{"url": "https://github.com/example/repo/pull/1", "state": "OPEN", "isDraft": True,
                     "headRefName": "codex/remediation-1", "baseRefName": "main", "headRefOid": "sha",
                     "body": remote_body["value"]}] if created["value"] else []
            return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")
        if command[-2:] == ["branch", "--show-current"] or "symbolic-ref" in command:
            return subprocess.CompletedProcess(command, 0, "codex/remediation-1\n", "")
        if "rev-parse" in command:
            return subprocess.CompletedProcess(command, 0, "sha\n", "")
        if command[:3] == ["gh", "pr", "create"]:
            created["value"] = True
            return subprocess.CompletedProcess(command, 0, "https://github.com/example/repo/pull/1\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(remediation.subprocess, "run", fake_run)
    transitions: list[dict] = []
    monkeypatch.setattr(remediation, "_api", lambda *_args: transitions.append(_args[-1]) or {"status": "pr_draft"})
    args = argparse.Namespace(engagement_key="project", remediation_command="create-pr", case_id="1", body_file=body, actor="owner", template_mapped=True)

    with pytest.raises(SystemExit, match="draft PR body differs"):
        remediation.run_remediation(args, tmp_path)
    assert not transitions
    with pytest.raises(SystemExit, match="draft PR body differs"):
        remediation.run_remediation(args, tmp_path)
    remote_body["value"] = body.read_text(encoding="utf-8")
    remediation.run_remediation(args, tmp_path)

    assert sum(command[:3] == ["gh", "pr", "create"] for command in commands) == 1
    assert sum(command[:4] == ["git", "-C", str(worktree), "push"] for command in commands) == 1
    assert transitions == [{"status": "pr_draft", "actor": "owner", "reason": "Draft PR: https://github.com/example/repo/pull/1"}]


def test_cli_approval_sends_instruction_and_reviewed_digest(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    worktree = eng / "remediation/cases/1/worktree"
    worktree.mkdir(parents=True)
    digest = "b" * 64
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(worktree), "worktree_revision": "sha", "review_digest": digest})
    monkeypatch.setattr(remediation, "_require_case_worktree", lambda *_: worktree)
    monkeypatch.setattr(remediation, "_revision", lambda _: "sha")
    monkeypatch.setattr(remediation, "_worktree_status", lambda _: "")
    seen: list[dict] = []
    monkeypatch.setattr(remediation, "_api", lambda *_args: seen.append(_args[-1]) or {"id": 9})
    args = argparse.Namespace(engagement_key="project", remediation_command="approve", case_id="1", reviewer="owner", owner_instruction="Approve this reviewed snapshot", review_digest=digest)
    remediation.run_remediation(args, tmp_path)
    assert seen == [{"reviewer": "owner", "expected_review_digest": digest, "approval_method": "cli_instruction", "owner_instruction": "Approve this reviewed snapshot"}]


def test_development_handoff_rechecks_worktree_before_transition(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {
        "repository": str(tmp_path), "deployment_workflow": "develop.yml",
    }))
    monkeypatch.setattr(remediation, "_case", lambda *_: {"worktree_path": str(tmp_path), "worktree_revision": "approved-sha"})
    checks = iter([tmp_path, SystemExit("case worktree is not registered to the configured repository")])

    def check(*_args: object) -> Path:
        result = next(checks)
        if isinstance(result, SystemExit):
            raise result
        return result

    monkeypatch.setattr(remediation, "_approved_current", check)
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("unverified worktree must not transition"))
    args = argparse.Namespace(engagement_key="project", remediation_command="development-handoff",
                              case_id="3", actor="owner")
    with pytest.raises(SystemExit, match="configured repository"):
        remediation.run_remediation(args, tmp_path)


@pytest.mark.parametrize(("status", "command"), [("pr_draft", "create-pr"), ("development", "development-handoff")])
def test_generic_transition_rejects_dedicated_handoff_states(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: str, command: str) -> None:
    from vigil_cli import remediation

    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("generic transition must not record a handoff state"))
    args = argparse.Namespace(engagement_key="project", remediation_command="transition", case_id="3", status=status, actor="owner", reason="Ready")

    with pytest.raises(SystemExit, match=command):
        remediation.run_remediation(args, tmp_path)


def test_red_test_evidence_requires_laravel_output_and_outcome(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {}))
    args = argparse.Namespace(engagement_key="project", remediation_command="evidence", case_id="1", kind="red-test", method="Laravel", command="php artisan test", observed="failed", proved="boundary exercised", artifact=None, revision="sha", outcome="failed_as_expected", environment="local")
    with pytest.raises(SystemExit, match="saved output artifact"):
        remediation.run_remediation(args, tmp_path)


def test_ordinary_evidence_sends_explicit_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {}))
    sent = []
    monkeypatch.setattr(remediation, "_api", lambda *_args: sent.append(_args[-1]) or {"id": 1})
    args = argparse.Namespace(engagement_key="project", remediation_command="evidence", case_id="1",
                              kind="baseline", method="HTTP", command="curl example.test",
                              observed="403", proved="boundary holds", artifact=None, revision="abc",
                              outcome=None, environment="development")
    remediation.run_remediation(args, tmp_path)
    assert sent[0]["environment"] == "development"


@pytest.mark.parametrize(("kind", "outcome"), [("red-test", "failed_as_expected"), ("green-test", "passed")])
@pytest.mark.parametrize("revision", [None, " "])
def test_typed_test_evidence_requires_revision(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, revision: str | None, kind: str, outcome: str) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    artifact = eng / "remediation/cases/1/tests/red.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("expected failure", encoding="utf-8")
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {}))
    monkeypatch.setattr(remediation, "_api", lambda *_args: pytest.fail("revisionless test evidence must not be recorded"))

    args = argparse.Namespace(engagement_key="project", remediation_command="evidence", case_id="1", kind=kind, method="Laravel", command="php artisan test", observed="failed", proved="boundary exercised", artifact=artifact, revision=revision, outcome=outcome, environment="local")
    with pytest.raises(SystemExit, match="--revision"):
        remediation.run_remediation(args, tmp_path)


def test_prepare_pr_retains_and_indexes_reviewed_body(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from vigil_cli import remediation

    eng = tmp_path / "eng"
    eng.mkdir()
    case = {
        "approval_current": True, "approvals": [{"review_digest": "d" * 64, "evidence_cutoff_id": 3}],
        "evidence": [{"id": i, "kind": kind, "method": "Laravel" if kind != "stagehand" else "stagehand", "observed": "ran", "proved": "boundary"} for i, kind in enumerate(("red-test", "green-test", "stagehand"), 1)],
        "worktree_revision": "sha", "verification_plan": "Open Manage and confirm the saved value",
        "release_plan": {"production_canary_decision": "not_required", "production_canary_rationale": "Local route coverage", "safe_procedure": "", "coralogix_monitoring": "Watch errors"},
    }
    monkeypatch.setattr(remediation, "_project", lambda *_: (eng, {"repository": str(tmp_path)}))
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_approved_current", lambda *_: eng)
    payloads: list[dict] = []
    monkeypatch.setattr(remediation, "_api", lambda *_args: payloads.append(_args[-1]) or {"id": 4})
    output = tmp_path / "pr.md"
    args = argparse.Namespace(engagement_key="project", remediation_command="prepare-pr", case_id="1", output=output, root_cause="Controller selected an unscoped record by ID", fix_summary="Load the record through the authorized tenant relation")
    remediation.run_remediation(args, tmp_path)
    assert output.is_file()
    assert (eng / payloads[0]["artifact_path"]).read_text(encoding="utf-8") == output.read_text(encoding="utf-8")
