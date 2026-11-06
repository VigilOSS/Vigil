"""The two destructive lease-recovery verbs must be as precise as the reads.

* `reset-stale` was global while its own read-only preview
  (`list --stale-minutes N`) already took the full lane scope, so a deep-analysis
  lane could not reap its own window without reaping every other lane's.
* There was no non-verdict lease release at all: a lane holding a file another
  lane owns had to render `clean`, `skipped` or `needs-context`, each of which is
  a verdict the reviewer never reached. `release` returns the row to unleased
  `pending` and records why, without inventing a disposition.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


class _PostClient:
    """Records one POST and answers with a caller-supplied response."""

    response: dict = {}
    posts: list[tuple[str, dict]] = []

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, endpoint: str, payload: dict, **_kwargs):
        type(self).posts.append((endpoint, payload))
        return type(self).response


@pytest.fixture
def post_client(monkeypatch, tmp_path):
    _PostClient.posts = []
    _PostClient.response = {}
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PostClient)
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot
    )
    return _PostClient


# --- reset-stale lane scope -------------------------------------------------


def test_reset_stale_takes_the_same_lane_scope_as_its_preview(post_client, tmp_path):
    """The destructive verb must accept exactly what `list --stale-minutes` does."""
    options = code_dispatch._parse_reset_stale_options(
        [
            "--path-glob", "*.php",
            "--repo-id", "4",
            "--path-prefix", "src/billing",
            "--batch-theme", "deep analysis",
            "--path-prefix", "src/auth",
            "--queue-mode", "reanalysis",
        ]
    )
    post_client.response = {"reset": 2}

    code_dispatch._reset_stale(_config(tmp_path), 30, options)

    assert post_client.posts == [
        (
            "code/analysis-queue/reset-stale",
            {
                "minutes": 30,
                "repo_id": 4,
                "batch_theme": "deep analysis",
                "queue_mode": "reanalysis",
                "path_prefix": ["src/auth", "src/billing"],
                "path_glob": ["*.php"],
            },
        )
    ]


def test_reset_stale_path_scope_is_order_independent_like_list_and_fetch():
    typed = ["--path-glob", "*.py", "--path-prefix", "b", "--path-prefix", "a"]
    reordered = ["--path-prefix", "a", "--path-glob", "*.py", "--path-prefix", "b"]

    assert code_dispatch._parse_reset_stale_options(typed) == (
        code_dispatch._parse_reset_stale_options(reordered)
    )


def test_reset_stale_without_a_scope_stays_the_global_sweep(post_client, tmp_path):
    post_client.response = {"reset": 0}

    code_dispatch._reset_stale(_config(tmp_path), 10, {})

    assert post_client.posts == [
        ("code/analysis-queue/reset-stale", {"minutes": 10})
    ]


@pytest.mark.parametrize(
    "tokens",
    [
        ["--repo-id"],
        ["--repo-id", "0"],
        ["--repo-id", "x"],
        ["--batch-theme", " "],
        ["--unknown", "x"],
        ["--path-prefix"],
        ["--path-glob", ""],
        ["--batch-theme", "a", "--batch-theme", "b"],
        ["--stale-minutes", "5"],
    ],
)
def test_reset_stale_rejects_malformed_scope(tokens, capsys):
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._parse_reset_stale_options(tokens)

    assert excinfo.value.code == 1
    assert capsys.readouterr().err


def test_reset_stale_scope_is_reported_with_the_reaped_count(post_client, tmp_path, capsys):
    post_client.response = {"reset": 3}

    code_dispatch._reset_stale(
        _config(tmp_path), 20, {"repo_id": 9, "path_prefix": ["src/auth"]}
    )

    out = capsys.readouterr().out
    assert "Reset 3 stale item(s)" in out
    assert "repo_id=9" in out
    assert "path_prefix=src/auth" in out


# --- release ----------------------------------------------------------------


def test_release_is_a_registered_action_with_its_own_help() -> None:
    assert "release" in code_dispatch._ACTION_HELP
    help_text = code_dispatch._ACTION_HELP["release"]
    assert "--reason" in help_text
    assert "pending" in help_text


def test_release_returns_the_row_without_rendering_a_verdict(post_client, tmp_path, capsys):
    post_client.response = {
        "item_id": 41,
        "file_id": 7,
        "file_path": "app/Billing/RefundController.php",
        "reason": "owned by lane 2",
        "previous_agent_name": "hunter-a",
        "previous_lease_token": "lease-a",
        "previous_lease_activity_at": "2026-11-07T10:00:00Z",
        "discarded_result_count": 2,
    }

    code_dispatch._release(_config(tmp_path), "41", "hunter-a", "lease-a", "owned by lane 2")

    assert post_client.posts == [
        (
            "code/analysis-queue/release",
            {
                "item_id": 41,
                "agent_name": "hunter-a",
                "lease_token": "lease-a",
                "reason": "owned by lane 2",
            },
        )
    ]
    out = capsys.readouterr().out
    assert "Released queue item 41" in out
    assert "app/Billing/RefundController.php" in out
    assert "hunter-a / lease-a" in out
    assert "unleased pending" in out
    assert "discarded 2 receipt(s)" in out
    assert "earned no coverage credit" in out
    assert json.loads(out[out.index("{"):]) == post_client.response
    # The whole point of the verb: no disposition is claimed for the file.
    assert "disposition" not in out


def test_release_requires_a_reason(capsys):
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._parse_release_options([])

    assert excinfo.value.code == 1
    assert "--reason" in capsys.readouterr().err


def test_release_rejects_a_non_positive_item_id(post_client, tmp_path, capsys):
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._release(_config(tmp_path), "0", "hunter-a", "lease-a", "why")

    assert excinfo.value.code == 1
    assert "item-id must be one positive integer" in capsys.readouterr().err
    assert post_client.posts == []


def test_release_refuses_a_non_object_response(post_client, tmp_path, capsys):
    post_client.response = []  # type: ignore[assignment]

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._release(_config(tmp_path), "41", "hunter-a", "lease-a", "why")

    assert excinfo.value.code == 1
    assert "non-object" in capsys.readouterr().err


def test_release_does_not_add_a_disposition_to_the_done_vocabulary() -> None:
    assert "owned-elsewhere" not in code_dispatch._DONE_DISPOSITIONS
    assert code_dispatch._DONE_DISPOSITIONS == (
        "clean", "finding", "suspicious", "skipped"
    )
