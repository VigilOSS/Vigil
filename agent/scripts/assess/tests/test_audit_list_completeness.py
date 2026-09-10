"""Bounded, traversable audit reads reject malformed backend responses."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from assess.commands import artifact, coverage, http_cmd
from assess.lib.client import AssessError


def _config() -> SimpleNamespace:
    return SimpleNamespace(base_url="http://example.test", engagement_key="eng")


def _parser(module, command: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command")
    module.register(subparsers)
    return parser


def _args(module, command: str, argv: list[str]) -> argparse.Namespace:
    args = _parser(module, command).parse_args([command, *argv])
    args.engagement_dir = "/tmp/eng"
    return args


def _window(endpoint: str, rows: list[dict]) -> list[dict]:
    query = parse_qs(urlparse(endpoint).query)
    limit = int(query["limit"][0])
    offset = int(query["offset"][0])
    return rows[offset : offset + limit]


class _PagedClient:
    rows: list[dict] = []
    endpoints: list[str] = []
    envelope = False

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def get(self, endpoint: str):
        type(self).endpoints.append(endpoint)
        page = _window(endpoint, type(self).rows)
        if type(self).envelope:
            return {"attempts": page, "count": len(page)}
        return page

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        self.close()
        return False


def _artifact_row(index: int) -> dict:
    return {
        "id": index,
        "relative_path": f"evidence/{index}.json",
        "present": True,
        "indexed_bytes": 100_000,
        "index_status": "complete",
        "indexed_text": "X" * 100_000,
    }


def _flow_row(index: int) -> dict:
    return {
        "id": index,
        "flow_uid": f"flow-{index}",
        "method": "GET",
        "host": "target.example",
        "path": f"/{index}",
        "url": f"https://target.example/{index}",
        "response_body_preview": "X" * 100_000,
    }


def _attempt_row(index: int) -> dict:
    return {
        "id": index,
        "target_host": "target.example",
        "target_path": f"/{index}",
        "result_status": "no-signal",
        "lens": "authorization",
        "raw_observation": "X" * 100_000,
    }


def test_artifact_search_bounds_default_and_reports_continuation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_artifact_row(1), _artifact_row(2), _artifact_row(3)]
        endpoints: list[str] = []

    monkeypatch.setattr(artifact, "AssessmentClient", Client)
    monkeypatch.setattr(artifact, "load_config", lambda _path: _config())
    args = _args(
        artifact,
        "artifact",
        ["search", "--q", "oauth token", "--kind", "note", "--limit", "2", "--json"],
    )

    args.func(args)

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert [row["id"] for row in rows] == [1, 2]
    assert len(rows[0]["indexed_text"]) == 100_000
    assert parse_qs(urlparse(Client.endpoints[0]).query) == {
        "q": ["oauth token"],
        "kind": ["note"],
        "limit": ["3"],
        "offset": ["0"],
    }
    assert "showing 1-2 of at least 3 matching artifacts" in captured.err
    assert "artifact search --q 'oauth token' --kind note --limit 2 --offset 2" in captured.err
    assert "UNTRUSTED DATA" in captured.err


def test_artifact_search_paginate_reaches_the_final_record(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_artifact_row(index) for index in range(1, 6)]
        endpoints: list[str] = []

    monkeypatch.setattr(artifact, "AssessmentClient", Client)
    monkeypatch.setattr(artifact, "load_config", lambda _path: _config())
    args = _args(
        artifact,
        "artifact",
        ["search", "--limit", "2", "--offset", "1", "--paginate", "--json"],
    )

    args.func(args)

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [2, 3, 4, 5]
    assert [parse_qs(urlparse(endpoint).query)["offset"] for endpoint in Client.endpoints] == [
        ["1"], ["3"], ["5"]
    ]
    assert "showing 2-5 of 5 matching artifacts" in captured.err


@pytest.mark.parametrize("payload", [{"error": "wrong shape"}, [{"id": 1}]])
def test_artifact_search_rejects_malformed_rows(
    payload,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client(_PagedClient):
        def get(self, _endpoint: str):
            return payload

    monkeypatch.setattr(artifact, "AssessmentClient", Client)
    monkeypatch.setattr(artifact, "load_config", lambda _path: _config())
    args = _args(artifact, "artifact", ["search", "--json"])

    with pytest.raises(AssessError, match="malformed artifact search response"):
        args.func(args)


def test_artifact_human_output_exposes_index_and_content_truncation() -> None:
    search_text = artifact._render_rows(
        [
            {
                "id": 7,
                "relative_path": "scans/kali/run.out",
                "present": True,
                "scratch": False,
                "kind": "command-run-output",
                "size_bytes": 131072,
                "indexed_bytes": 16384,
                "index_status": "partial",
                "preview_text": "observed preview",
            }
        ]
    )
    detail_text = artifact._artifact_text(
        {
            "id": 7,
            "relative_path": "scans/kali/run.out",
            "present": True,
            "kind": "command-run-output",
            "size_bytes": 131072,
            "sha256": "a" * 64,
            "indexed_bytes": 16384,
            "index_status": "partial",
            "content": "bounded content",
            "content_truncated": True,
        }
    )

    assert "indexed_bytes" in search_text
    assert "index_status" in search_text
    assert "16384" in search_text
    assert "partial" in search_text
    assert "index_status: partial" in detail_text
    assert "indexed_bytes: 16384" in detail_text
    assert "content_truncated: yes" in detail_text
    assert "bounded content" in detail_text
    assert "use the engagement-local path" in detail_text


def test_http_list_bounds_default_and_reports_continuation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_flow_row(1), _flow_row(2)]
        endpoints: list[str] = []

    monkeypatch.setattr(http_cmd, "AssessmentClient", Client)
    monkeypatch.setattr(http_cmd, "load_config", lambda _path: _config())
    args = _args(
        http_cmd,
        "http",
        ["list", "--host", "target.example", "--limit", "1", "--json"],
    )

    args.func(args)

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert [row["id"] for row in rows] == [1]
    assert len(rows[0]["response_body_preview"]) == 100_000
    query = parse_qs(urlparse(Client.endpoints[0]).query)
    assert query["limit"] == ["2"]
    assert query["offset"] == ["0"]
    assert "showing 1-1 of at least 2 matching HTTP flows" in captured.err
    assert "http list --host target.example --limit 1 --offset 1" in captured.err
    assert "UNTRUSTED DATA" in captured.err


def test_http_search_paginate_reaches_the_final_record(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_flow_row(index) for index in range(1, 5)]
        endpoints: list[str] = []

    monkeypatch.setattr(http_cmd, "AssessmentClient", Client)
    monkeypatch.setattr(http_cmd, "load_config", lambda _path: _config())
    args = _args(
        http_cmd,
        "http",
        ["search", "admin", "panel", "--limit", "2", "--offset", "1", "--paginate", "--json"],
    )

    args.func(args)

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [2, 3, 4]
    assert [parse_qs(urlparse(endpoint).query)["offset"] for endpoint in Client.endpoints] == [
        ["1"], ["3"]
    ]
    assert all(
        parse_qs(urlparse(endpoint).query)["q"] == ["admin panel"]
        for endpoint in Client.endpoints
    )
    assert "showing 2-4 of 4 matching HTTP flows" in captured.err


@pytest.mark.parametrize("action", ["list", "search"])
@pytest.mark.parametrize("payload", [{"error": "wrong shape"}, [{"id": 1}]])
def test_http_lists_reject_malformed_rows(
    action: str,
    payload,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client(_PagedClient):
        def get(self, _endpoint: str):
            return payload

    monkeypatch.setattr(http_cmd, "AssessmentClient", Client)
    monkeypatch.setattr(http_cmd, "load_config", lambda _path: _config())
    args = _args(http_cmd, "http", [action, "needle"] if action == "search" else [action])

    with pytest.raises(AssessError, match=f"http {action}: malformed backend response"):
        args.func(args)


def test_coverage_attempts_bounds_default_and_reports_continuation(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_attempt_row(1), _attempt_row(2), _attempt_row(3)]
        endpoints: list[str] = []
        envelope = True

    monkeypatch.setattr(coverage, "AssessmentClient", Client)
    args = SimpleNamespace(
        attempts=True,
        finding="",
        surface="",
        host="target.example",
        attack_family="idor",
        result_status="",
        lens="",
        limit=2,
        offset=0,
        paginate=False,
        as_json=True,
    )

    coverage._run_attempts(args, _config())

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert [row["id"] for row in payload["attempts"]] == [1, 2]
    assert payload["count"] == 2
    assert len(payload["attempts"][0]["raw_observation"]) == 100_000
    query = parse_qs(urlparse(Client.endpoints[0]).query)
    assert query["limit"] == ["3"]
    assert query["offset"] == ["0"]
    assert "showing 1-2 of at least 3 matching probe attempts" in captured.err
    assert "coverage --attempts --host target.example --attack-family idor --limit 2 --offset 2" in captured.err
    assert "UNTRUSTED DATA" in captured.err


def test_coverage_attempts_paginate_reaches_the_final_record(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Client(_PagedClient):
        rows = [_attempt_row(index) for index in range(1, 5)]
        endpoints: list[str] = []
        envelope = True

    monkeypatch.setattr(coverage, "AssessmentClient", Client)
    args = SimpleNamespace(
        finding="",
        surface="",
        host="",
        attack_family="",
        result_status="",
        lens="",
        limit=2,
        offset=1,
        paginate=True,
        as_json=True,
    )

    coverage._run_attempts(args, _config())

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert [row["id"] for row in payload["attempts"]] == [2, 3, 4]
    assert payload["count"] == 3
    assert [parse_qs(urlparse(endpoint).query)["offset"] for endpoint in Client.endpoints] == [
        ["1"], ["3"]
    ]
    assert "showing 2-4 of 4 matching probe attempts" in captured.err


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"attempts": [], "count": "0"},
        {"attempts": [{"id": 1}], "count": 1},
        {"attempts": [], "count": 1},
    ],
)
def test_coverage_attempts_rejects_malformed_envelope(
    payload,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Client(_PagedClient):
        def get(self, _endpoint: str):
            return payload

    monkeypatch.setattr(coverage, "AssessmentClient", Client)
    args = SimpleNamespace(
        finding="",
        surface="",
        host="",
        attack_family="",
        result_status="",
        lens="",
        limit=50,
        offset=0,
        paginate=False,
        as_json=True,
    )

    with pytest.raises(AssessError, match="coverage --attempts: malformed backend response"):
        coverage._run_attempts(args, _config())
