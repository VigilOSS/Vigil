"""One security-history vocabulary drives both ingest's Git grep and the history classifier."""
from __future__ import annotations

import os
import subprocess

import pytest

from assess.lib.security_history import SECURITY_HISTORY_GIT_GREP, classify_message
from assess.lib.trusted_exec import resolve_trusted_tool

_MESSAGES = (
    "Patch Security hole in uploads",
    "cve-2026-4242 backport",
    "Use-After-Free in the image parser",
    "Fix XSS VULNERABILITY in search",
    "fixes a vuln in the parser",
    "Buffer_Overflow when reading headers",
    "Update readme",
    "Refactor logging",
    "GHSA-2c4f-8x9q-m5h7 follow-up",
    "addresses CWE-79 in templates",
)


def test_ids_are_extracted_case_insensitively_and_normalized():
    classified = classify_message(
        "fix cve-2026-0001 and CVE-2026-0001; see ghsa-2C4F-8x9q-M5H7, cwe-22 and CWE-0079\n"
        "unrelated CVE-26-1 and XCWE-12"
    )

    assert classified["cve_ids"] == ["CVE-2026-0001"]
    assert classified["ghsa_ids"] == ["GHSA-2c4f-8x9q-m5h7"]
    assert classified["cwe_ids"] == ["CWE-22", "CWE-79"]
    assert classified["keyword_hits"] == ["cve"]
    assert classified["security_relevant"] is True


def test_an_advisory_id_alone_is_security_relevant():
    assert classify_message("Follow up on GHSA-2c4f-8x9q-m5h7")["security_relevant"] is True
    assert classify_message("Update readme")["security_relevant"] is False


def test_ingest_scans_history_with_the_shared_vocabulary():
    """Ingest's `git log --grep` is built from the same owner the classifier reads."""
    from assess.commands import code_ingest

    assert code_ingest.SECURITY_HISTORY_GIT_GREP is SECURITY_HISTORY_GIT_GREP


@pytest.fixture(scope="module")
def git_bin(tmp_path_factory) -> str:
    resolved = resolve_trusted_tool("git", source_root=tmp_path_factory.mktemp("no-source"))
    if not resolved:
        pytest.skip("trusted Git executable not available")
    return resolved


def test_classifier_keywords_agree_with_the_git_grep_ingest_runs(tmp_path, git_bin):
    repo = tmp_path / "acme-vocabulary"
    repo.mkdir()
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Acme Dev",
        "GIT_AUTHOR_EMAIL": "dev@acme.example",
        "GIT_COMMITTER_NAME": "Acme Dev",
        "GIT_COMMITTER_EMAIL": "dev@acme.example",
    }

    def git(*args: str) -> str:
        return subprocess.run(
            [git_bin, *args], cwd=repo, env=env, check=True, capture_output=True, text=True,
        ).stdout

    git("init", "-q", "-b", "main")
    by_commit: dict[str, str] = {}
    for message in _MESSAGES:
        git("commit", "-q", "--allow-empty", "-m", message)
        by_commit[git("rev-parse", "HEAD").strip()] = message

    grep = set(
        git("log", "--regexp-ignore-case", f"--grep={SECURITY_HISTORY_GIT_GREP}", "--format=%H").split()
    )

    assert grep == {
        commit for commit, message in by_commit.items() if classify_message(message)["keyword_hits"]
    }
