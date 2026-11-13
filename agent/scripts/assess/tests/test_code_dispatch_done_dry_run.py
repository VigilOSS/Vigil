"""`code-dispatch done --dry-run` asks the backend to run the close without writing.

A client-only preview could not see the checks that live in the backend (the
attempt's candidate receipts and the close they require, coverage
completeness), so a dry run that passed could still be refused by the
real close. The dry run sends the close with `dry_run: true`; the backend runs
every check and writes nothing, and its refusal is the dry run's refusal.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch
from assess.lib.client import AssessError

_COVERAGE = [{"family": "ssrf", "effort": 80}]


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _install(monkeypatch, response):
    posts: list[tuple[str, dict]] = []

    class _Client:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint, payload):
            posts.append((endpoint, payload))
            if isinstance(response, Exception):
                raise response
            return response

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)
    return posts


def _coverage(tmp_path: Path) -> str:
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_COVERAGE), encoding="utf-8")
    return str(path)


def test_dry_run_sends_the_close_with_dry_run_and_prints_the_preview(
    monkeypatch, tmp_path, capsys
):
    posts = _install(monkeypatch, {"dry_run": True, "updated": 0, "would_update": 1,
                                   "total": 1, "disposition": "finding"})

    code_dispatch._done(_config(tmp_path), "42", "HUNT-1", "lease-42", "finding",
                        _coverage(tmp_path), "", dry_run=True)

    [(endpoint, payload)] = posts
    assert endpoint == "code/analysis-queue/done"
    assert payload["dry_run"] is True
    out = capsys.readouterr().out
    assert '"would_update": 1' in out
    assert "nothing was written" in out


def test_a_backend_refusal_of_the_dry_run_exits_non_zero_with_its_detail(
    monkeypatch, tmp_path
):
    _install(monkeypatch, AssessError(
        "POST code/analysis-queue/done failed: HTTP 409 candidate-bearing analysis "
        "result requires queue disposition='finding'; cannot complete as 'suspicious'"))

    with pytest.raises(AssessError, match="requires queue disposition='finding'"):
        code_dispatch._done(_config(tmp_path), "42", "HUNT-1", "lease-42", "suspicious",
                            _coverage(tmp_path), "", dry_run=True)


def test_a_dry_run_with_shape_problems_is_refused_without_a_request(
    monkeypatch, tmp_path, capsys
):
    posts = _install(monkeypatch, {})

    with pytest.raises(SystemExit) as raised:
        code_dispatch._done(_config(tmp_path), "42", "HUNT-1", "lease-42", "clean",
                            _coverage(tmp_path), "", dry_run=True)

    assert raised.value.code == 1
    assert posts == []
    assert "WOULD BE REFUSED" in capsys.readouterr().out
