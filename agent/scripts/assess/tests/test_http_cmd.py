"""CLI tests for `vigil assess http` (list/show/search/export-har/import-har/policy).

Backend + runtime are stubbed (``load_config`` + a non-context-managed
``AssessmentClient`` closed in a ``finally``) matching the pattern used by the
other assess CLI suites (see test_block_technique.py). These pin: the
server-side filter flags map to the exact backend query-param names, `search`
routes its positional to the `q` filter, `export-har`/`import-har` round-trip a
HAR file, and `policy set` sends a partial update (only provided fields) with
correct --enabled/--no-enabled semantics.
"""
from __future__ import annotations

import argparse
import json
from urllib.parse import parse_qs, urlparse

import pytest

from assess.commands import http_cmd


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records get/post/put calls and serves canned responses."""

    def __init__(self, *, get_result=None) -> None:
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict]] = []
        self.puts: list[tuple[str, dict]] = []
        self._get_result = get_result if get_result is not None else []
        self.closed = False

    def get(self, endpoint: str):
        self.gets.append(endpoint)
        return self._get_result

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        entries = payload.get("log", {}).get("entries", [])
        return {
            "engagement_id": 1,
            "count": len(entries),
            "flows": [{"id": index + 1} for index, _entry in enumerate(entries)],
        }

    def put(self, endpoint: str, payload: dict) -> dict:
        self.puts.append((endpoint, payload))
        # Echo a merged policy back as the backend would.
        merged = {
            "enabled": False,
            "capture_request_bodies": False,
            "capture_response_bodies": False,
            "max_body_bytes": 102400,
            "content_type_allow": [],
            "content_type_deny": [],
            "retention": "until_engagement_deletion",
        }
        merged.update(payload)
        return merged

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _parser():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    http_cmd.register(sub)
    return parser


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    args = _parser().parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(http_cmd, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(http_cmd, "AssessmentClient", lambda *a, **k: fake)


def _query_of(endpoint: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(endpoint).query)


_FLOW_ROW = {
    "id": 7,
    "flow_uid": "abc123",
    "method": "POST",
    "scheme": "https",
    "host": "api.example.com",
    "port": 443,
    "url": "https://api.example.com/login",
    "path": "/login",
    "response_status": 200,
    "content_type_family": "json",
    "auth_context": "anonymous",
    "request_content_type": "application/json",
    "response_content_type": "application/json",
    "request_body_sha256": "deadbeef",
    "response_body_sha256": "cafef00d",
    "request_body_bytes": 42,
    "response_body_bytes": 128,
    "request_body_truncated": False,
    "response_body_truncated": True,
    "request_body_artifact_path": "traffic/mitmproxy/bodies/deadbeef.bin",
    "response_body_artifact_path": "traffic/mitmproxy/bodies/cafef00d.bin",
    "request_headers": {"Content-Type": "application/json"},
    "response_headers": {"Content-Type": "application/json"},
    "host_mismatch": False,
    "timing_ms": 55,
    "started_at": "2026-07-01T00:00:00Z",
}


def test_list_maps_filters_to_backend_query_param_names(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=[_FLOW_ROW])
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "http", "list",
            "--host", "api.example.com",
            "--method", "POST",
            "--status", "200",
            "--content-type", "json",
            "--auth-context", "anonymous",
            "--truncated",
            "--q", "login",
            "--limit", "10",
            "--offset", "5",
        ],
        str(tmp_path),
    )
    args.func(args)
    out = capsys.readouterr().out
    assert "api.example.com" in out
    assert "POST" in out

    assert len(fake.gets) == 1
    endpoint = fake.gets[0]
    assert endpoint.startswith("http-flows?")
    q = _query_of(endpoint)
    assert q["host"] == ["api.example.com"]
    assert q["method"] == ["POST"]
    assert q["response_status"] == ["200"]
    assert q["content_type_family"] == ["json"]
    assert q["auth_context"] == ["anonymous"]
    assert q["truncated"] == ["true"]
    assert q["q"] == ["login"]
    assert q["limit"] == ["11"]
    assert q["offset"] == ["5"]
    assert fake.closed is True


def test_list_no_filters_requests_bounded_lookahead(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=[])
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "list"], str(tmp_path))
    args.func(args)
    assert fake.gets == ["http-flows?limit=251&offset=0"]
    assert "no flows matched" in capsys.readouterr().out


def test_list_no_truncated_sends_false(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=[])
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "list", "--no-truncated"], str(tmp_path))
    args.func(args)
    q = _query_of(fake.gets[0])
    assert q["truncated"] == ["false"]


def test_list_json_emits_raw_rows(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=[_FLOW_ROW])
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "list", "--json"], str(tmp_path))
    args.func(args)
    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["flow_uid"] == "abc123"


def test_search_routes_positional_to_q(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=[_FLOW_ROW])
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "search", "admin", "panel", "--host", "api.example.com"], str(tmp_path))
    args.func(args)
    q = _query_of(fake.gets[0])
    assert q["q"] == ["admin panel"]
    assert q["host"] == ["api.example.com"]


def test_show_renders_metadata_and_json(tmp_path, monkeypatch, capsys):
    fake = _FakeClient(get_result=_FLOW_ROW)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "show", "abc123"], str(tmp_path))
    args.func(args)
    captured = capsys.readouterr()
    out = captured.out
    assert fake.gets == ["http-flows/abc123"]
    assert "flow_uid: abc123" in out
    assert "response body:" in out
    assert "cafef00d" in out  # response body sha256 preview
    assert "response headers:" in out  # header block label present
    assert "UNTRUSTED DATA" in captured.err

    fake2 = _FakeClient(get_result=_FLOW_ROW)
    _install(monkeypatch, tmp_path, fake2)
    args = _parse(["http", "show", "abc123", "--json"], str(tmp_path))
    args.func(args)
    captured = capsys.readouterr()
    row = json.loads(captured.out)
    assert row["id"] == 7
    assert "UNTRUSTED DATA" in captured.err


def test_export_har_writes_file_and_summary(tmp_path, monkeypatch, capsys):
    har = {"log": {"version": "1.2", "creator": {"name": "vigil"}, "entries": [{"a": 1}, {"b": 2}]}}
    fake = _FakeClient(get_result=har)
    _install(monkeypatch, tmp_path, fake)
    out_file = tmp_path / "sub" / "api.har"
    args = _parse(["http", "export-har", "--host", "api.example.com", "-o", str(out_file)], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    assert fake.gets[0].startswith("http-flows/export-har?")
    assert _query_of(fake.gets[0])["host"] == ["api.example.com"]
    assert out_file.is_file()
    written = json.loads(out_file.read_text())
    assert written["log"]["entries"] == [{"a": 1}, {"b": 2}]
    assert "Wrote 2 HAR entries" in out


def test_import_har_posts_log_wrapper(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    har_path = tmp_path / "in.har"
    har_path.write_text(json.dumps({"log": {"entries": [{"x": 1}]}}))
    args = _parse(["http", "import-har", str(har_path)], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    assert len(fake.posts) == 1
    endpoint, payload = fake.posts[0]
    assert endpoint == "http-flows/import-har"
    assert payload == {"log": {"entries": [{"x": 1}]}}
    assert "Imported 1 flow(s)" in out


def test_import_har_wraps_bare_log_object(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    har_path = tmp_path / "bare.har"
    har_path.write_text(json.dumps({"entries": [{"x": 1}]}))
    args = _parse(["http", "import-har", str(har_path)], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    _endpoint, payload = fake.posts[0]
    assert payload == {"log": {"entries": [{"x": 1}]}}


def test_policy_get_renders(tmp_path, monkeypatch, capsys):
    policy = {
        "enabled": False,
        "capture_request_bodies": False,
        "max_body_bytes": 102400,
        "retention": "until_engagement_deletion",
    }
    fake = _FakeClient(get_result=policy)
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "policy"], str(tmp_path))
    args.func(args)
    out = capsys.readouterr().out
    assert fake.gets == ["capture-policy"]
    assert "Capture Policy" in out
    assert "enabled: False" in out
    assert "retention: until_engagement_deletion" in out


def test_policy_set_partial_update_only_sends_provided_fields(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "http", "policy", "set",
            "--enabled",
            "--capture-request-bodies",
            "--max-body-bytes", "262144",
            "--content-type-allow", "application/json,text/html",
            "--content-type-allow", "application/xml",
        ],
        str(tmp_path),
    )
    args.func(args)
    capsys.readouterr()
    assert len(fake.puts) == 1
    endpoint, payload = fake.puts[0]
    assert endpoint == "capture-policy"
    assert payload["enabled"] is True
    assert payload["capture_request_bodies"] is True
    assert payload["max_body_bytes"] == 262144
    assert payload["content_type_allow"] == ["application/json", "text/html", "application/xml"]
    # Untouched fields are NOT sent (partial update).
    assert "capture_response_bodies" not in payload
    assert "content_type_deny" not in payload


def test_policy_set_no_enabled_sends_false(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "policy", "set", "--no-enabled"], str(tmp_path))
    args.func(args)
    capsys.readouterr()
    _endpoint, payload = fake.puts[0]
    assert payload == {"enabled": False}


def test_policy_set_empty_update_fails_closed(tmp_path, monkeypatch, capsys):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["http", "policy", "set"], str(tmp_path))
    with pytest.raises(SystemExit) as exc:
        args.func(args)
    assert exc.value.code == 1
    assert fake.puts == []
    assert "at least one field" in capsys.readouterr().err


def test_http_verb_documented_in_contract():
    """The http verb group has a contract entry so `vigil assess contract http`
    and the register()-time epilog resolve."""
    from assess.lib.contracts import get_contract

    contract = get_contract("http")
    assert contract is not None
    assert contract.name == "http"
    joined = " ".join(contract.preferred_invocations)
    for verb in ("http list", "http show", "http search", "http export-har", "http import-har", "http policy"):
        assert verb in joined
