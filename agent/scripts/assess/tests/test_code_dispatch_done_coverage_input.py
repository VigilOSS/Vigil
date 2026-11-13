"""`code-dispatch done` takes its CWE coverage the ways a lane already has it.

The coverage argument was a file path holding a bare JSON array, and anything
else was refused: inline JSON (what a lane has in hand after counting its
families), `-` for a pipe, and the `{"cwe_coverage": [...]}` wrapper the
request payload itself uses. Each is the same array, so each is accepted; the
unwrap is named on stderr.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch

_COVERAGE = [{"family": "ssrf", "effort": 80}, {"family": "injection", "effort": 60}]


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)
    )


class _PreviewClient:
    """The backend's dry-run answer: every close check passed, nothing written."""

    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, _endpoint, _payload):
        return {"dry_run": True, "updated": 0, "would_update": 1, "total": 1}


@pytest.fixture(autouse=True)
def _backend_preview(monkeypatch):
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PreviewClient)


def _dry_run(tmp_path: Path, coverage_arg: str, capsys) -> tuple[dict, str]:
    code_dispatch._done(
        _config(tmp_path), "42", "HUNT-1", "lease-42", "finding", coverage_arg,
        "", dry_run=True,
    )
    captured = capsys.readouterr()
    rendered, _end = json.JSONDecoder().raw_decode(captured.out[captured.out.index("{"):])
    return rendered["payload"], captured.err


def test_done_accepts_a_coverage_file(tmp_path, capsys):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps(_COVERAGE), encoding="utf-8")

    payload, _err = _dry_run(tmp_path, str(path), capsys)

    assert payload["cwe_coverage"] == _COVERAGE


def test_done_accepts_inline_coverage_json(tmp_path, capsys):
    payload, _err = _dry_run(tmp_path, json.dumps(_COVERAGE), capsys)

    assert payload["cwe_coverage"] == _COVERAGE


def test_done_reads_coverage_from_stdin_for_a_dash(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_COVERAGE)))

    payload, _err = _dry_run(tmp_path, "-", capsys)

    assert payload["cwe_coverage"] == _COVERAGE


def test_done_unwraps_the_request_shaped_wrapper_and_says_so(tmp_path, capsys):
    path = tmp_path / "coverage.json"
    path.write_text(json.dumps({"cwe_coverage": _COVERAGE}), encoding="utf-8")

    payload, err = _dry_run(tmp_path, str(path), capsys)

    assert payload["cwe_coverage"] == _COVERAGE
    assert "cwe_coverage" in err


@pytest.mark.parametrize(
    "raw",
    [
        json.dumps({"cwe_coverage": _COVERAGE, "notes": "x"}),
        json.dumps({"family": "ssrf", "effort": 80}),
        "[{not json",
    ],
)
def test_done_still_refuses_what_is_not_a_coverage_array(tmp_path, capsys, raw):
    with pytest.raises(SystemExit) as exc:
        _dry_run(tmp_path, raw, capsys)

    assert exc.value.code == 1
    assert "CWE coverage" in capsys.readouterr().err


def test_done_names_a_missing_coverage_path(tmp_path, capsys):
    with pytest.raises(SystemExit):
        _dry_run(tmp_path, str(tmp_path / "absent.json"), capsys)

    assert "absent.json" in capsys.readouterr().err
