from __future__ import annotations

from pathlib import Path
import hashlib
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


def test_identity_audit_rejects_private_identity_but_allows_contributors() -> None:
    checker = _load_checker()
    private_email = "private@example.com"
    checker._BANNED_EMAIL_DIGESTS = {hashlib.sha256(private_email.encode()).hexdigest()}
    records = [
        checker.CommitIdentity(
            "a" * 40,
            "External Contributor",
            "contributor@example.com",
            "External Contributor",
            "contributor@example.com",
        ),
        checker.CommitIdentity(
            "b" * 40,
            checker.APPROVED_NAME,
            private_email,
            checker.APPROVED_NAME,
            checker.APPROVED_EMAIL,
        ),
    ]

    errors = checker.identity_errors(records)

    assert len(errors) == 2
    assert "private author email" in errors[0]
    assert "must use" in errors[1]


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
