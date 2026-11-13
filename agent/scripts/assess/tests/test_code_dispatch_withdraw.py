"""`code-dispatch withdraw` posts the ids and reason, and fails on any refusal."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess.commands import code_dispatch


def _install(monkeypatch, tmp_path, response):
    posts: list[tuple[str, dict]] = []

    class FakeClient(StubClient):
        def post(self, endpoint: str, payload: dict):
            posts.append((endpoint, payload))
            return response

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)))
    return posts


def _run(*extra: str) -> None:
    code_dispatch.run(SimpleNamespace(action="withdraw", extra=list(extra), engagement_dir="/tmp/acme"))


_WITHDRAWN = {
    "queue_item_id": 41, "file_id": 7, "file_path": "static/js/app.example.js",
    "predecessor_queue_item_id": 12, "predecessor_status": "done",
    "predecessor_disposition": "clean", "file_analysis_status": "analyzed",
    "returned_trigger_ids": [301, 302],
}


def test_withdraw_posts_every_id_with_the_reason(monkeypatch, tmp_path, capsys):
    posts = _install(monkeypatch, tmp_path, {"withdrawn": [_WITHDRAWN], "refused": [], "total": 1})

    _run("41", "--reason", "requeued by mistake")

    assert posts == [("code/analysis-queue/withdraw", {
        "item_ids": [41], "reason": "requeued by mistake",
    })]
    out = capsys.readouterr().out
    assert "Withdrew 1 of 1" in out
    assert "static/js/app.example.js" in out and "301, 302" in out


def test_withdraw_reads_an_ids_file(monkeypatch, tmp_path):
    ids = tmp_path / "ids.json"
    ids.write_text(json.dumps({"item_ids": [43, 41, 42]}), encoding="utf-8")
    posts = _install(monkeypatch, tmp_path, {"withdrawn": [], "refused": [], "total": 3})

    _run("--ids-file", str(ids), "--reason", "Acme wave rolled back")

    assert posts[0][1]["item_ids"] == [41, 42, 43]


def test_a_refused_row_is_named_and_fails_the_command(monkeypatch, tmp_path, capsys):
    _install(monkeypatch, tmp_path, {
        "withdrawn": [_WITHDRAWN],
        "refused": [{"queue_item_id": 44, "file_path": "static/js/b.example.js",
                     "reason": "queue item 44 is processing under a lease held by cvh-1"}],
        "total": 2,
    })

    with pytest.raises(SystemExit) as exc:
        _run("41,44", "--reason", "Acme")

    assert exc.value.code == 1
    assert "queue item 44 is processing under a lease held by cvh-1" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [("41",), ("--reason", "x"), ("41", "--ids-file", "f", "--reason", "x")])
def test_withdraw_needs_one_id_source_and_a_reason(monkeypatch, tmp_path, argv):
    posts = _install(monkeypatch, tmp_path, {})

    with pytest.raises(SystemExit):
        _run(*argv)

    assert posts == []
