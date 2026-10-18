from __future__ import annotations

from pathlib import Path
import importlib.util
import sys
import os
import subprocess

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "tools" / "check_public_commit_identity.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_public_commit_identity", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_repository_provides_portable_identity_hooks() -> None:
    assert (REPO_ROOT / ".githooks" / "pre-commit").is_file()
    assert (REPO_ROOT / ".githooks" / "pre-push").is_file()
    assert SCRIPT.is_file()


def test_identity_audit_requires_approved_author_and_committer() -> None:
    checker = _load_checker()
    records = [
        checker.CommitIdentity("a" * 40, "External Contributor", "contributor@example.com",
                               "External Contributor", "contributor@example.com"),
        checker.CommitIdentity("b" * 40, checker.APPROVED_NAME, "private@example.com",
                               checker.APPROVED_NAME, checker.APPROVED_EMAIL),
        checker.CommitIdentity("c" * 40, checker.APPROVED_NAME, checker.APPROVED_EMAIL,
                               checker.APPROVED_NAME, checker.APPROVED_EMAIL),
    ]

    errors = checker.identity_errors(records)

    assert len(errors) == 3
    assert all("must use" in error for error in errors)
    assert not any("c" * 40 in error for error in errors)


def test_pre_push_ranges_cover_new_updates_and_skip_deletions() -> None:
    checker = _load_checker()
    local = "1" * 40
    remote = "2" * 40
    deleted = "0" * 40

    revisions = checker.pre_push_revisions(
        [
            f"refs/heads/main {local} refs/heads/main {remote}\n",
            f"refs/heads/topic {local} refs/heads/topic {deleted}\n",
            f"(delete) {deleted} refs/heads/old {remote}\n",
        ]
    )

    assert revisions == [f"{remote}..{local}", local]


@pytest.mark.parametrize("colocated", [False, True])
def test_config_check_rejects_effective_identity_overrides(monkeypatch, tmp_path, colocated) -> None:
    checker = _load_checker()
    if colocated:
        (tmp_path / ".jj").mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(checker, "_local_config", lambda key: {
        "user.name": checker.APPROVED_NAME,
        "user.email": checker.APPROVED_EMAIL,
    }[key])
    monkeypatch.setattr(checker, "_run", lambda command: (
        "Other Maintainer <maintainer@example.com> 0 +0000"
        if command[:2] == ("git", "var") else "maintainer@example.com"
    ))

    errors = checker._check_local_config()

    assert any("effective Git author" in error for error in errors)
    assert any("effective Git committer" in error for error in errors)
    assert any("jj" in error for error in errors) == colocated


def test_fork_history_can_retain_contributor_attribution() -> None:
    checker = _load_checker()
    records = [checker.CommitIdentity("a" * 40, "External Contributor", "contributor@example.com",
                                      "External Contributor", "contributor@example.com")]
    assert checker.identity_errors(records, allow_contributors=True) == []


@pytest.mark.parametrize("role", ["author", "committer"])
@pytest.mark.parametrize("tagged", [False, True])
def test_installed_jj_guard_blocks_wrong_identity_pushes(tmp_path: Path, role: str, tagged: bool) -> None:
    checker = _load_checker()
    repo = tmp_path / "maintainer"
    remote = tmp_path / "remote.git"
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GIT_AUTHOR_", "GIT_COMMITTER_"))}
    env.update(JJ_CONFIG="/dev/null", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")

    def jj(*args: str, check: bool = True):
        return subprocess.run(["jj", *args], cwd=repo, env=env,
                              check=check, capture_output=True, text=True)

    subprocess.run(["jj", "git", "init", "--colocate", str(repo)], env=env,
                   check=True, capture_output=True, text=True)
    subprocess.run(["git", "init", "--bare", str(remote)], env=env,
                   check=True, capture_output=True, text=True)
    subprocess.run([sys.executable, str(SCRIPT), "--install"], cwd=repo, env=env,
                   check=True, capture_output=True, text=True)
    jj("git", "remote", "add", "probe", str(remote))
    jj("describe", "-m", "Synthetic identity guard check")
    jj("bookmark", "create", "probe")
    if role == "author":
        jj("metaedit", "--author", "External Contributor <contributor@example.com>")
    else:
        jj("--config", 'user.name="External Contributor"',
           "--config", 'user.email="contributor@example.com"',
           "describe", "-m", "Synthetic committer override")
    actual = jj("log", "-r", "@", "--no-graph", "-T",
                f'{role}.name() ++ " <" ++ {role}.email() ++ ">"')
    assert actual.stdout.strip() == "External Contributor <contributor@example.com>"
    if tagged:
        jj("tag", "set", "v99.0.0", "--revision", "probe")
    rejected = jj("git", "push", "--remote", "probe", "--bookmark", "probe", "--dry-run", check=False)
    assert rejected.returncode != 0, "jj must reject a non-maintainer identity before pushing"
    assert "private" in rejected.stderr.lower()
    jj("metaedit", "probe", "--ignore-immutable", "--force-rewrite",
       "--author", f"{checker.APPROVED_NAME} <{checker.APPROVED_EMAIL}>")
    approved = jj("git", "push", "--remote", "probe", "--bookmark", "probe", "--dry-run")
    assert approved.returncode == 0
