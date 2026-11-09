"""A classify pass that fails partway must say what it already committed.

`code/files/bulk-classify` takes one chunk of `DEFAULT_BULK_WRITE_SIZE` per
POST and the backend refuses an unchunked caller, so a whole-repository pass is
dozens of separately committed transactions. When chunk k fails, chunks 1..k-1
are durable: the operator needs the committed prefix and the failing chunk's
index range to know what to re-submit, and a language change carried by an
already-committed chunk still left a repo undispatchable — so its
`code-index build` / `code-index sync` repair command has to reach the operator
on the failure path too, not only after a pass that ran to completion.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_classify
from assess.lib.client import AssessError
from _fake_client import StubClient

_INVALIDATION = {
    "structural_index_invalidated_repo_ids": [42],
    "language_changes": [
        {
            "file_id": 7,
            "file_path": "a/b.cc",
            "previous_language": "cpp",
            "language": "python",
        }
    ],
}


class _ChunkClient(StubClient):
    """Commits every chunk until ``fail_on``, which fails like a backend 5xx."""

    def __init__(self, *, fail_on: int = 0, response: dict | None = None) -> None:
        self.fail_on = fail_on
        self.response = response or {}
        self.posts: list[dict] = []

    def post(self, _endpoint: str, payload: dict, **_options) -> dict:
        self.posts.append(payload)
        if len(self.posts) == self.fail_on:
            raise AssessError(
                "POST code/files/bulk-classify failed: HTTP 500: database is locked"
            )
        count = len(payload["classifications"])
        return {**self.response, "updated": count, "total": count}


def _classify(monkeypatch, tmp_path: Path, client: _ChunkClient, count: int) -> None:
    monkeypatch.setattr(code_classify, "AssessmentClient", lambda *_args: client)
    monkeypatch.setattr(
        code_classify,
        "load_config",
        lambda engagement_dir: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    path = tmp_path / "classifications.json"
    path.write_text(
        json.dumps(
            [
                {"file_id": file_id, "classification": "medium", "analysis_priority": 40}
                for file_id in range(1, count + 1)
            ]
        ),
        encoding="utf-8",
    )
    code_classify.run(
        SimpleNamespace(classifications_json=str(path), engagement_dir=str(tmp_path))
    )


def test_a_failed_chunk_reports_the_committed_prefix_and_the_repair_command(
    monkeypatch, tmp_path, capsys
):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    client = _ChunkClient(fail_on=2, response=_INVALIDATION)

    with pytest.raises(AssessError) as excinfo:
        _classify(monkeypatch, tmp_path, client, size + 2)

    # The failure itself still reaches the operator, with a non-zero exit.
    assert "bulk-classify failed" in str(excinfo.value)
    err = capsys.readouterr().err
    # How far the pass actually got.
    assert "1 of 2 chunk(s) committed" in err
    assert f"{size} row(s) classified" in err
    assert f"items {size}-{size + 1}" in err
    assert f"items 0-{size - 1}" in err
    assert "re-apply" in err
    # The invalidation a committed chunk reported, with its repair command.
    assert "invalidated the structural-index binding for repo(s): 42" in err
    assert "a/b.cc: cpp -> python" in err
    assert "code-index build" in err
    assert "code-index sync --repo-id 42" in err


def test_the_untried_remainder_of_a_failed_pass_is_named_as_unsent(
    monkeypatch, tmp_path, capsys
):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    client = _ChunkClient(fail_on=2)

    with pytest.raises(AssessError):
        _classify(monkeypatch, tmp_path, client, size * 2 + 3)

    err = capsys.readouterr().err
    assert "1 of 3 chunk(s) committed" in err
    assert f"items {size}-{size * 2 - 1}" in err
    assert "not sent" in err
    assert f"items {size * 2}-{size * 2 + 2}" in err
    # The run stops at the failing chunk rather than retrying past it.
    assert len(client.posts) == 2


def test_the_first_chunk_failing_reports_nothing_committed(
    monkeypatch, tmp_path, capsys
):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    client = _ChunkClient(fail_on=1)

    with pytest.raises(AssessError):
        _classify(monkeypatch, tmp_path, client, size + 2)

    err = capsys.readouterr().err
    assert "0 of 2 chunk(s) committed" in err
    assert "0 row(s) classified" in err
    assert f"items 0-{size - 1}" in err


def test_a_pass_that_commits_every_chunk_stays_silent_on_stderr(
    monkeypatch, tmp_path, capsys
):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    client = _ChunkClient()

    _classify(monkeypatch, tmp_path, client, size + 2)

    captured = capsys.readouterr()
    assert f"Total classified: {size + 2}" in captured.out
    assert captured.err == ""
