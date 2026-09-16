"""A6: `code-dispatch list` recovers queue IDs after insertion output scrolls.

`fetch --ids-file` is the documented precise batching mechanism, but initial
queue outcomes cap at 200 rows and nothing listed the queue, so the IDs were
unrecoverable through the supported operator surface. The machine forms of this
verb must therefore be consumable as an ids file without scraping the table.
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


_PAGE = {
    "total": 3,
    "offset": 4,
    "count": 2,
    "has_more": True,
    "item_ids": [41, 42],
    "items": [
        {
            "id": 41,
            "file_id": 7,
            "file_path": "src/parser.py",
            "classification": "critical",
            "repo_id": 1,
            "status": "processing",
            "queue_mode": "initial",
            "priority": 100,
            "batch_theme": "parser-core",
            "agent_name": "hunter-a",
            "lease_token": "lease-a",
            "last_heartbeat_at": "2026-09-15T10:00:00Z",
        },
        {
            "id": 42,
            "file_id": 8,
            "file_path": "src/helpers.py",
            "classification": "low",
            "repo_id": 1,
            "status": "pending",
            "queue_mode": "trigger",
            "priority": 10,
            "batch_theme": "helpers",
            "agent_name": "",
            "lease_token": "",
            "last_heartbeat_at": None,
        },
    ],
}


class _FakeClient:
    requested: list[str] = []
    payload: dict = _PAGE

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).requested.append(endpoint)
        return type(self).payload


@pytest.fixture
def fake_client(monkeypatch):
    _FakeClient.requested = []
    _FakeClient.payload = _PAGE
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FakeClient)
    return _FakeClient


def test_list_is_a_registered_action() -> None:
    assert "list" in code_dispatch._ACTION_HELP


def test_list_sends_every_filter_in_one_canonical_query(fake_client, tmp_path, capsys):
    filters, output = code_dispatch._parse_list_filters(
        [
            "--queue-mode", "trigger",
            "--status", "pending",
            "--limit", "2",
            "--repo-id", "1",
            "--classification", "critical",
            "--batch-theme", "parser core",
            "--offset", "4",
        ]
    )
    code_dispatch._list(_config(tmp_path), filters, output)

    assert output == "table"
    assert fake_client.requested == [
        "code/analysis-queue?status=pending&repo_id=1&classification=critical"
        "&batch_theme=parser+core&queue_mode=trigger&limit=2&offset=4"
    ]
    out = capsys.readouterr().out
    assert "41" in out and "42" in out
    assert "src/parser.py" in out
    assert "hunter-a" in out
    assert "--offset 6" in out


def test_list_json_output_is_directly_usable_as_an_ids_file(
    fake_client, tmp_path, capsys
):
    code_dispatch._list(_config(tmp_path), {}, "json")

    payload = json.loads(capsys.readouterr().out)
    assert payload == _PAGE
    ids_file = tmp_path / "ids.json"
    ids_file.write_text(json.dumps(payload), encoding="utf-8")
    assert code_dispatch._ids_from_file(str(ids_file)) == [41, 42]


def test_list_ids_only_output_is_directly_usable_as_an_ids_file(
    fake_client, tmp_path, capsys
):
    code_dispatch._list(_config(tmp_path), {}, "ids")

    out = capsys.readouterr().out
    assert json.loads(out) == [41, 42]
    ids_file = tmp_path / "ids.json"
    ids_file.write_text(out, encoding="utf-8")
    assert code_dispatch._ids_from_file(str(ids_file)) == [41, 42]


@pytest.mark.parametrize(
    "tokens",
    [
        ["--status"],
        ["--unknown", "x"],
        ["--limit", "zero"],
        ["--limit", "0"],
        ["--repo-id", "-1"],
        ["--json", "--ids-only"],
        ["--status", "pending", "--status", "done"],
        ["stats"],
    ],
)
def test_list_rejects_malformed_filters(tokens, capsys):
    with pytest.raises(SystemExit) as exc:
        code_dispatch._parse_list_filters(tokens)

    assert exc.value.code == 1
    assert capsys.readouterr().err


def test_fetch_passes_queue_mode_filter_to_the_backend(monkeypatch, tmp_path, capsys):
    posted: dict[str, object] = {}

    class _FetchClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict[str, object]):
            posted["endpoint"] = endpoint
            posted["payload"] = payload
            return []

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FetchClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(
        _config(tmp_path),
        3,
        "trigger-hunter",
        code_dispatch._parse_fetch_filters(["--queue-mode", "trigger"]),
    )

    assert posted["payload"] == {
        "limit": 3,
        "agent_name": "trigger-hunter",
        "queue_mode": "trigger",
    }


def test_a_truncated_ids_page_says_so_on_stderr(fake_client, tmp_path, capsys):
    """An ids file that is silently short is the defect this verb exists to fix.

    `--ids-only` is meant to be redirected straight into a file and handed to
    `fetch --ids-file`. With nothing but the id array on stdout, a page that
    stopped at the limit produces a short claim set and no signal at all — the
    same lost-IDs failure as scraping truncated insertion output, one layer down.
    """
    code_dispatch._list(_config(tmp_path), {}, "ids")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [41, 42]
    assert "of 3 matching rows" in captured.err
    assert "--offset 6" in captured.err


def test_a_truncated_json_page_says_so_on_stderr(fake_client, tmp_path, capsys):
    code_dispatch._list(_config(tmp_path), {}, "json")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == _PAGE
    assert "matching rows" in captured.err


def test_a_complete_page_warns_about_nothing(fake_client, tmp_path, capsys):
    fake_client.payload = {**_PAGE, "has_more": False}
    code_dispatch._list(_config(tmp_path), {}, "ids")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [41, 42]
    assert captured.err == ""
