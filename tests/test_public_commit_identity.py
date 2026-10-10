from __future__ import annotations

from pathlib import Path
import importlib.util
import sys


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


def test_config_check_rejects_effective_identity_overrides(monkeypatch) -> None:
    checker = _load_checker()
    monkeypatch.chdir(REPO_ROOT)
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
    assert any("jj" in error for error in errors)


def test_fork_history_can_retain_contributor_attribution() -> None:
    checker = _load_checker()
    records = [checker.CommitIdentity("a" * 40, "External Contributor", "contributor@example.com",
                                      "External Contributor", "contributor@example.com")]
    assert checker.identity_errors(records, allow_contributors=True) == []
