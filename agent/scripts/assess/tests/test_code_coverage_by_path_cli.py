"""CLI rendering for `vigil assess code-coverage --by-path`."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from assess.commands import code_coverage

_PAGE = {
    "repo_id": None,
    "depth": 2,
    "path_prefix": [],
    "total": 3,
    "offset": 0,
    "count": 2,
    "has_more": True,
    "directories": [
        {
            "repo_id": 4,
            "repo_key": "acme-api",
            "path": "src/billing",
            "files": 12,
            "loc": 3400,
            "by_classification": {
                "critical": {"count": 3, "analyzed": 1},
                "high": {"count": 5, "analyzed": 2},
                "low": {"count": 4, "analyzed": 0},
            },
            "uncovered_critical_high": 5,
            "by_status": {
                "analyzed": 3, "queued": 4, "in_progress": 1,
                "needs_context": 1, "classified": 3, "pending": 0,
            },
            "structural_debt": {"count": 2, "degraded": 1, "unsupported": 1, "truncated": 0},
            "accounted_skips": 2,
        },
        {
            "repo_id": 4,
            "repo_key": "acme-api",
            "path": ".",
            "files": 1,
            "loc": 20,
            "by_classification": {"unclassified": {"count": 1, "analyzed": 0}},
            "uncovered_critical_high": 0,
            "by_status": {
                "analyzed": 0, "queued": 0, "in_progress": 0,
                "needs_context": 0, "classified": 0, "pending": 1,
            },
            "structural_debt": {"count": 0, "degraded": 0, "unsupported": 0, "truncated": 0},
            "accounted_skips": 0,
        },
    ],
}


class _FakeClient:
    requested: list[str] = []

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).requested.append(endpoint)
        return _PAGE


@pytest.fixture
def fake_client(monkeypatch, tmp_path):
    _FakeClient.requested = []
    monkeypatch.setattr(code_coverage, "AssessmentClient", _FakeClient)
    monkeypatch.setattr(
        code_coverage,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)
        ),
    )
    return _FakeClient


def _parse(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engagement-dir", default=".")
    subparsers = parser.add_subparsers()
    code_coverage.register(subparsers)
    return parser.parse_args(["code-coverage", *argv])


def test_by_path_requests_one_canonical_query(fake_client, capsys):
    args = _parse(
        [
            "--by-path",
            "--path-prefix", "src/billing",
            "--depth", "3",
            "--repo-id", "4",
            "--path-prefix", "src/auth",
            "--limit", "2",
        ]
    )
    args.func(args)

    assert fake_client.requested == [
        "code/coverage/by-path?repo_id=4&depth=3"
        "&path_prefix=src%2Fauth&path_prefix=src%2Fbilling&limit=2"
    ]
    capsys.readouterr()


def test_by_path_renders_one_row_per_directory(fake_client, capsys):
    args = _parse(["--by-path"])
    args.func(args)

    assert fake_client.requested == ["code/coverage/by-path"]
    out = capsys.readouterr().out
    assert "2 of 3 directories" in out
    billing = next(line for line in out.splitlines() if line.rstrip().endswith("src/billing"))
    cells = billing.split()
    assert cells[:4] == ["5", "1/3", "2/5", "12"]
    assert "acme-api" in billing
    root = next(line for line in out.splitlines() if line.rstrip().endswith(" ."))
    assert root.split()[0] == "0"
    assert "--offset 2" in out


def test_by_path_json_emits_the_backend_page(fake_client, capsys):
    args = _parse(["--by-path", "--json"])
    args.func(args)

    assert json.loads(capsys.readouterr().out) == _PAGE


@pytest.mark.parametrize(
    "argv",
    [
        ["--depth", "3"],
        ["--path-prefix", "src"],
        ["--json"],
        ["--by-path", "--cwe-matrix"],
        ["--by-path", "--require-transition-ready", "hunt"],
    ],
)
def test_by_path_options_are_refused_outside_the_by_path_view(fake_client, argv, capsys):
    args = _parse(argv)
    with pytest.raises(SystemExit) as exc:
        args.func(args)

    assert exc.value.code == 2
    assert "--by-path" in capsys.readouterr().err
    assert fake_client.requested == []
