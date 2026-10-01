import subprocess

import pytest

from vigil_cli import engagements, remediation


def jj(path, *args):
    return subprocess.run(
        ["jj", "--no-pager", "--color=never", "-R", str(path), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture(params=[False, True], ids=["standalone-jj", "colocated-jj"])
def repository(tmp_path, request):
    path = tmp_path / "repo"
    subprocess.run(
        [
            "jj",
            "git",
            "init",
            "--colocate" if request.param else "--no-colocate",
            str(path),
        ],
        check=True,
        capture_output=True,
    )
    jj(path, "config", "set", "--repo", "user.name", "Remediation Test")
    jj(path, "config", "set", "--repo", "user.email", "test@example.invalid")
    (path / "application.txt").write_text("baseline\n")
    jj(path, "describe", "-m", "Baseline")
    jj(path, "bookmark", "create", "main", "-r", "@")
    jj(path, "new", "-m", "Unrelated root work")
    return path


def test_jj_repository_validation_accepts_noncolocated_workspace_root(repository):
    assert engagements.remediation_repository(str(repository)) == repository


def test_jj_current_revision_is_content_commit_and_survives_empty_child(repository):
    expected = jj(repository, "log", "-r", "@-", "--no-graph", "-T", "commit_id")
    assert remediation._revision(repository) == expected
    jj(repository, "new", "-m", "Another empty child")
    assert remediation._revision(repository) == expected


def test_jj_workspace_registration_and_reviewed_bookmark_cleanliness(
    repository, tmp_path
):
    workspace = tmp_path / "case"
    jj(repository, "workspace", "add", "--name", "case", "-r", "main", str(workspace))
    jj(workspace, "bookmark", "create", "codex/remediation-case", "-r", "@")
    assert remediation._is_registered_worktree(repository, workspace)
    assert not remediation._worktree_status(workspace)
    before = remediation._revision(workspace)
    (workspace / "application.txt").write_text("fixed\n")
    assert remediation._revision(workspace) != before
    assert not remediation._worktree_status(workspace)
    jj(workspace, "describe", "-m", "Fix regression")
    jj(workspace, "bookmark", "move", "codex/remediation-case", "--to", "@")
    assert not remediation._worktree_status(workspace)
    reviewed = remediation._revision(workspace)
    jj(workspace, "new", "-m", "Empty child")
    assert remediation._revision(workspace) == reviewed
    assert not remediation._worktree_status(workspace)
    assert (
        remediation._require_case_worktree(
            {
                "worktree_path": str(workspace),
                "worktree_branch": "codex/remediation-case",
            },
            repository,
        )
        == workspace
    )
    jj(repository, "workspace", "forget", "case")
    assert not remediation._is_registered_worktree(repository, workspace)


def test_backend_jj_revision_review_diff_and_red_ancestry(repository, tmp_path):
    from app.services import remediation as service

    workspace = tmp_path / "backend-case"
    jj(
        repository,
        "workspace",
        "add",
        "--name",
        "backend-case",
        "-r",
        "main",
        str(workspace),
    )
    jj(workspace, "bookmark", "create", "codex/backend-case", "-r", "@")
    (workspace / "regression.txt").write_text("red regression\n")
    jj(workspace, "describe", "-m", "Failing regression")
    red = jj(workspace, "log", "-r", "@", "--no-graph", "-T", "commit_id")
    jj(workspace, "new", "-m", "Fix regression")
    (workspace / "application.txt").write_text("fixed\n")
    green = jj(workspace, "log", "-r", "@", "--no-graph", "-T", "commit_id")
    assert service._actual_revision(str(workspace)) == green
    assert service._registered_worktree(repository, workspace)
    assert service._worktree_clean(str(workspace))
    assert service._commit_ancestor(str(workspace), red, green)
    assert not service._commit_ancestor(str(workspace), green, red)
    assert service._evidence_revision(str(workspace), green) == green
    base, head, patch, truncated, total = service._review_patch(str(workspace))
    assert head == green
    assert base == jj(workspace, "log", "-r", "main", "--no-graph", "-T", "commit_id")
    assert b"+fixed" in patch and b"+red regression" in patch
    assert not truncated
    digest = service._worktree_digest(str(workspace))
    jj(workspace, "new", "-m", "Empty child")
    assert service._actual_revision(str(workspace)) == green
    assert service._worktree_digest(str(workspace)) == digest
    (workspace / "application.txt").write_text("unapproved\n")
    assert service._actual_revision(str(workspace)) != green
    assert service._worktree_digest(str(workspace)) != digest


def test_jj_workspace_creation_does_not_register_case_using_existing_bookmark(
    repository, tmp_path
):
    adapter = remediation._vcs()
    workspace = tmp_path / "duplicate-case"
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        adapter.create_workspace(repository, workspace, "main", "main")
    assert not workspace.exists()


def test_jj_publish_uses_only_reviewed_bookmark_and_exact_sha(repository, tmp_path):
    adapter = remediation._vcs()
    remote = tmp_path / "remote.git"
    subprocess.run(
        ["git", "init", "--bare", str(remote)], check=True, capture_output=True
    )
    jj(repository, "git", "remote", "add", "origin", str(remote))
    workspace = tmp_path / "publishing-case"
    adapter.create_workspace(repository, workspace, "codex/fix", "main")
    (workspace / "application.txt").write_text("reviewed fix\n")
    jj(workspace, "describe", "-m", "Reviewed fix")
    approved = adapter.revision(workspace)
    jj(workspace, "new", "-m", "Empty review child")
    adapter.push(workspace, "codex/fix", approved)
    pushed = subprocess.run(
        ["git", "--git-dir", str(remote), "rev-parse", "refs/heads/codex/fix"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert pushed == approved
    refs = subprocess.run(
        ["git", "--git-dir", str(remote), "for-each-ref", "--format=%(refname)"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert refs == ["refs/heads/codex/fix"]
    (workspace / "application.txt").write_text("unapproved\n")
    with pytest.raises(ValueError, match="changed after approval"):
        adapter.push(workspace, "codex/fix", approved)


def test_jj_revision_refuses_files_excluded_from_snapshot(repository):
    jj(repository, "config", "set", "--repo", "snapshot.max-new-file-size", "32")
    (repository / "unreviewed.txt").write_text("x" * 64)
    with pytest.raises(SystemExit, match="snapshot"):
        remediation._revision(repository)


def test_jj_workspace_creation_preserves_root_work_and_uses_jj(
    repository, tmp_path, monkeypatch
):
    adapter = remediation._vcs()
    notes = repository / "operator-notes.txt"
    notes.write_text("Unrelated operator work\n")
    root_revision = jj(repository, "log", "-r", "@", "--no-graph", "-T", "commit_id")
    commands = []
    run = adapter._run

    def record(args):
        commands.append(args)
        return run(args)

    monkeypatch.setattr(adapter, "_run", record)
    workspace = tmp_path / "preserved-case"
    adapter.create_workspace(repository, workspace, "codex/preserved", "main")
    assert adapter.registered(repository, workspace)
    (workspace / "nested").mkdir()
    assert adapter.root(workspace / "nested") == workspace
    assert adapter.is_jj(workspace / "nested")
    assert notes.read_text() == "Unrelated operator work\n"
    assert (
        jj(repository, "log", "-r", "@", "--no-graph", "-T", "commit_id")
        == root_revision
    )
    assert commands and all(command[0] == "jj" for command in commands)


def test_jj_worktree_conflicts_block_cleanliness(repository):
    base = jj(repository, "log", "-r", "main", "--no-graph", "-T", "commit_id")
    (repository / "application.txt").write_text("first side\n")
    jj(repository, "describe", "-m", "First side")
    first = jj(repository, "log", "-r", "@", "--no-graph", "-T", "commit_id")
    jj(repository, "new", base, "-m", "Second side")
    (repository / "application.txt").write_text("second side\n")
    second = jj(repository, "log", "-r", "@", "--no-graph", "-T", "commit_id")
    jj(repository, "new", first, second, "-m", "Conflicting merge")
    assert remediation._worktree_status(repository)
    with pytest.raises(SystemExit, match="uncommitted or untracked"):
        remediation._require_clean_worktree(repository)
    from app.services import remediation as service

    assert not service._worktree_clean(str(repository))


def test_jj_worktree_from_foreign_repository_is_not_registered(repository, tmp_path):
    foreign = tmp_path / "foreign"
    subprocess.run(
        ["jj", "git", "init", "--no-colocate", str(foreign)],
        check=True,
        capture_output=True,
    )
    assert not remediation._is_registered_worktree(repository, foreign)


@pytest.mark.parametrize(
    "origin",
    [
        "https://github.com/example/repo.git",
        "git@github.com:example/repo.git",
        "ssh://git@github.com/example/repo.git",
    ],
)
def test_jj_github_pr_list_routes_explicit_origin_without_git_marker(
    repository, tmp_path, monkeypatch, origin
):
    import json

    workspace = tmp_path / "gh-case"
    remediation._vcs().create_workspace(repository, workspace, "codex/gh-case", "main")
    assert not (workspace / ".git").exists()
    jj(repository, "git", "remote", "add", "origin", origin)
    monkeypatch.setenv("GH_REPO", "unrelated/wrong-repository")
    sha = remediation._revision(workspace)
    real_run = subprocess.run
    commands = []

    def github_run(command, **kwargs):
        if command[0] != "gh":
            return real_run(command, **kwargs)
        commands.append(command)
        if "--repo" not in command:
            return subprocess.CompletedProcess(
                command, 1, "", "fatal: not a git repository"
            )
        assert command[command.index("--repo") + 1] == "github.com/example/repo"
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                [
                    {
                        "url": "https://github.com/example/repo/pull/1",
                        "state": "OPEN",
                        "isDraft": True,
                        "headRefName": "codex/gh-case",
                        "baseRefName": "main",
                        "headRefOid": sha,
                        "body": "Reviewed body",
                    }
                ]
            ),
            "",
        )

    monkeypatch.setattr(subprocess, "run", github_run)
    assert (
        remediation._existing_draft_pr(workspace, "codex/gh-case", "Reviewed body")
        == "https://github.com/example/repo/pull/1"
    )
    assert len(commands) == 1


def test_jj_github_pr_creation_and_reconciliation_use_same_explicit_origin(
    repository, tmp_path, monkeypatch
):
    import argparse
    import json

    eng = tmp_path / "engagement"
    workspace = eng / "remediation/cases/1/worktree"
    workspace.parent.mkdir(parents=True)
    adapter = remediation._vcs()
    adapter.create_workspace(repository, workspace, "codex/gh-case", "main")
    assert not (workspace / ".git").exists()
    jj(repository, "git", "remote", "add", "origin", "git@github.com:example/repo.git")
    monkeypatch.setenv("GH_REPO", "unrelated/wrong-repository")
    sha = remediation._revision(workspace)
    digest = "a" * 64
    release = {
        "production_canary_decision": "not_required",
        "production_canary_rationale": "Covered by local regression",
        "safe_procedure": "",
        "coralogix_monitoring": "Watch authorization errors",
    }
    evidence = [
        {
            "id": index,
            "kind": kind,
            "method": "Laravel" if kind != "stagehand" else "stagehand",
            "observed": "observed",
            "proved": "proved",
        }
        for index, kind in enumerate(("red-test", "green-test", "stagehand"), 1)
    ]
    case = {
        "status": "approved",
        "approval_current": True,
        "approvals": [{"review_digest": digest, "evidence_cutoff_id": 3}],
        "evidence": evidence,
        "worktree_path": str(workspace),
        "worktree_branch": "codex/gh-case",
        "worktree_revision": sha,
        "release_plan": release,
        "verification_plan": "Open the page and verify authorized save",
        "title": "Fix",
    }
    cause, fix = (
        "Record lookup omits the tenant scope",
        "Use the authorized tenant relation",
    )
    (workspace.parent / "pr-content.json").write_text(
        json.dumps({"approval_digest": digest, "root_cause": cause, "fix_summary": fix})
    )
    body = tmp_path / "body.md"
    body.write_text(
        "\n".join(
            [
                digest,
                sha,
                "not_required",
                release["production_canary_rationale"],
                release["coralogix_monitoring"],
                cause,
                fix,
                case["verification_plan"],
                *remediation._required_reviewed_evidence_lines(case),
            ]
        )
    )
    monkeypatch.setattr(
        remediation, "_project", lambda *_: (eng, {"repository": str(repository)})
    )
    monkeypatch.setattr(remediation, "_case", lambda *_: case)
    monkeypatch.setattr(remediation, "_register_pr_body", lambda *_: body)
    monkeypatch.setattr(adapter, "push", lambda *_: None)
    monkeypatch.setattr(remediation, "_api", lambda *_: {"status": "pr_draft"})
    real_run = subprocess.run
    commands = []
    created = []

    def github_run(command, **kwargs):
        if command[0] != "gh":
            return real_run(command, **kwargs)
        commands.append(command)
        if "--repo" not in command:
            return subprocess.CompletedProcess(
                command, 1, "", "fatal: not a git repository"
            )
        assert command[command.index("--repo") + 1] == "github.com/example/repo"
        if command[:3] == ["gh", "pr", "create"]:
            created.append(True)
            return subprocess.CompletedProcess(
                command, 0, "https://github.com/example/repo/pull/1\n", ""
            )
        rows = (
            [
                {
                    "url": "https://github.com/example/repo/pull/1",
                    "state": "OPEN",
                    "isDraft": True,
                    "headRefName": "codex/gh-case",
                    "baseRefName": "main",
                    "headRefOid": sha,
                    "body": body.read_text(),
                }
            ]
            if created
            else []
        )
        return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")

    monkeypatch.setattr(subprocess, "run", github_run)
    args = argparse.Namespace(
        engagement_key="project",
        remediation_command="create-pr",
        case_id="1",
        body_file=body,
        actor="owner",
        template_mapped=True,
    )
    remediation.run_remediation(args, tmp_path)
    assert [command[:3] for command in commands] == [
        ["gh", "pr", "list"],
        ["gh", "pr", "create"],
        ["gh", "pr", "list"],
    ]
