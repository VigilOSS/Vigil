from __future__ import annotations

import json
from pathlib import Path


def write_engagement(engagements_dir: Path, key: str, *, hosts: list[str] | None = None) -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "created_at": "2026-06-01T00:00:00Z"}),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_hosts": hosts or ["example.com"],
                "out_of_scope": [],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    return engagement_dir


def _flow_payload(**overrides) -> dict:
    payload = {
        "flow_uid": "flow-0001",
        "method": "GET",
        "scheme": "https",
        "host": "api.example.com",
        "port": 443,
        "url": "https://api.example.com/v1/users?page=1",
        "path": "/v1/users",
        "response_status": 200,
        "request_content_type": "",
        "response_content_type": "application/json",
        "content_type_family": "json",
        "auth_context": "authenticated",
        "request_headers": {"Accept": "application/json"},
        "response_headers": {"Content-Type": "application/json"},
        "timing_ms": 42,
        "started_at": "2026-06-01T12:00:00Z",
    }
    payload.update(overrides)
    return payload


BASE = "/engagements/{key}/assessment/http-flows"


def test_ingest_never_422s_a_wellformed_flow(client, isolate_settings):
    key = "2026-06-01-000000-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    # Minimal well-formed flow (almost everything omitted) must still 201.
    resp = client.post(BASE.format(key=key), json={"flow_uid": "min-1", "method": "POST", "url": "https://api.example.com/x"})
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["flow_uid"] == "min-1"
    assert body["method"] == "POST"
    # Top-level array body / odd but well-formed payloads never blow up ingest.
    resp2 = client.post(BASE.format(key=key), json={"flow_uid": "min-2"})
    assert resp2.status_code == 201, resp2.text


def test_insert_is_idempotent_on_flow_uid(client, isolate_settings):
    key = "2026-06-01-000001-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    p = _flow_payload()
    r1 = client.post(BASE.format(key=key), json=p)
    r2 = client.post(BASE.format(key=key), json={**p, "response_status": 500})
    assert r1.status_code == 201 and r2.status_code == 201
    # INSERT OR IGNORE: the second post returns the first stored row unchanged.
    assert r2.json()["response_status"] == 200
    listed = client.get(BASE.format(key=key)).json()
    assert len(listed) == 1


def test_list_http_flows_server_side_filters(client, isolate_settings):
    key = "2026-06-01-000002-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    client.post(BASE.format(key=key), json=_flow_payload(flow_uid="f-get", method="GET", response_status=200, host="api.example.com", content_type_family="json", auth_context="authenticated"))
    client.post(BASE.format(key=key), json=_flow_payload(flow_uid="f-post", method="POST", response_status=500, host="www.example.com", content_type_family="html", auth_context="anonymous", url="https://www.example.com/login", path="/login"))
    client.post(BASE.format(key=key), json=_flow_payload(flow_uid="f-trunc", method="GET", response_status=200, response_body_truncated=True, url="https://api.example.com/big"))

    def uids(params):
        return {row["flow_uid"] for row in client.get(BASE.format(key=key), params=params).json()}

    assert uids({"method": "POST"}) == {"f-post"}
    assert uids({"response_status": 500}) == {"f-post"}
    assert uids({"host": "www.example.com"}) == {"f-post"}
    assert uids({"content_type_family": "html"}) == {"f-post"}
    assert uids({"auth_context": "anonymous"}) == {"f-post"}
    assert uids({"truncated": "true"}) == {"f-trunc"}
    assert uids({"q": "login"}) == {"f-post"}
    assert uids({"q": "example.com"}) == {"f-get", "f-post", "f-trunc"}
    # No filter returns all three.
    assert len(uids({})) == 3


def test_get_http_flow_detail_and_404(client, isolate_settings):
    key = "2026-06-01-000003-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    client.post(BASE.format(key=key), json=_flow_payload(flow_uid="detail-1"))
    got = client.get(BASE.format(key=key) + "/detail-1")
    assert got.status_code == 200
    assert got.json()["flow_uid"] == "detail-1"
    assert got.json()["request_headers"] == {"Accept": "application/json"}
    missing = client.get(BASE.format(key=key) + "/nope")
    assert missing.status_code == 404


def test_har_export_shape_and_body_inlining(client, isolate_settings):
    key = "2026-06-01-000004-flows"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    # Write a response body sidecar under the engagement root.
    body_rel = "traffic/mitmproxy/bodies/abc123.bin"
    body_path = root / body_rel
    body_path.parent.mkdir(parents=True, exist_ok=True)
    body_path.write_text('{"ok": true}', encoding="utf-8")

    client.post(
        BASE.format(key=key),
        json=_flow_payload(
            flow_uid="har-1",
            response_body_artifact_path=body_rel,
            response_body_bytes=12,
            response_body_sha256="deadbeef",
        ),
    )
    har = client.get(BASE.format(key=key) + "/export-har").json()
    assert har["log"]["version"] == "1.2"
    assert har["log"]["creator"]["name"] == "vigil"
    entries = har["log"]["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["request"]["method"] == "GET"
    assert entry["request"]["url"] == "https://api.example.com/v1/users?page=1"
    assert entry["response"]["status"] == 200
    # Body sidecar inlined into response content.
    assert entry["response"]["content"]["text"] == '{"ok": true}'
    # Vigil metadata rides on the custom field.
    assert entry["_vigil"]["flow_uid"] == "har-1"
    assert entry["_vigil"]["auth_context"] == "authenticated"
    assert entry["_vigil"]["response_body_sha256"] == "deadbeef"


def test_har_export_import_round_trip(client, isolate_settings):
    src = "2026-06-01-000005-src"
    dst = "2026-06-01-000006-dst"
    write_engagement(isolate_settings["engagements_dir"], src)
    write_engagement(isolate_settings["engagements_dir"], dst)
    client.post(BASE.format(key=src), json=_flow_payload(flow_uid="rt-1", host_mismatch=True, url_authority="api.example.com:443", sni="api.example.com"))
    har = client.get(BASE.format(key=src) + "/export-har").json()

    imported = client.post(BASE.format(key=dst) + "/import-har", json=har)
    assert imported.status_code == 201, imported.text
    assert imported.json()["count"] == 1

    round_tripped = client.get(BASE.format(key=dst) + "/rt-1").json()
    assert round_tripped["flow_uid"] == "rt-1"
    assert round_tripped["method"] == "GET"
    assert round_tripped["auth_context"] == "authenticated"
    assert round_tripped["content_type_family"] == "json"
    assert round_tripped["host"] == "api.example.com"
    assert round_tripped["scheme"] == "https"
    assert round_tripped["response_status"] == 200
    assert round_tripped["host_mismatch"] is True
    assert round_tripped["url_authority"] == "api.example.com:443"
    assert round_tripped["sni"] == "api.example.com"


def test_capture_policy_default_off_and_put(client, isolate_settings):
    key = "2026-06-01-000007-flows"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    policy_url = f"/engagements/{key}/assessment/capture-policy"

    default = client.get(policy_url)
    assert default.status_code == 200
    body = default.json()
    assert body["enabled"] is False
    assert body["capture_request_bodies"] is False
    assert body["capture_response_bodies"] is False
    assert body["max_body_bytes"] == 102400
    assert body["content_type_allow"] == []
    assert body["redaction_profile"] == "none"

    updated = client.put(
        policy_url,
        json={"enabled": True, "capture_response_bodies": True, "max_body_bytes": 4096, "content_type_deny": ["image/*"]},
    )
    assert updated.status_code == 200
    u = updated.json()
    assert u["enabled"] is True
    assert u["capture_response_bodies"] is True
    assert u["max_body_bytes"] == 4096
    assert u["content_type_deny"] == ["image/*"]
    # Partial update preserved an unspecified knob at its default.
    assert u["capture_request_bodies"] is False

    # Re-GET reflects persisted state.
    assert client.get(policy_url).json()["enabled"] is True
    # Filesystem mirror written next to scope.json for the addon's offline fallback.
    mirror = json.loads((root / "capture-policy.json").read_text(encoding="utf-8"))
    assert mirror["enabled"] is True
    assert mirror["max_body_bytes"] == 4096


def test_capture_policy_present_in_engagements_registry(client, isolate_settings):
    key = "2026-06-01-000008-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    # Default policy is present in the registry payload the proxy addon consumes.
    rows = client.get("/engagements", params={"status": "in_progress"}).json()
    row = next(r for r in rows if r["key"] == key)
    assert "capture_policy" in row
    assert row["capture_policy"]["enabled"] is False

    client.put(
        f"/engagements/{key}/assessment/capture-policy",
        json={"enabled": True, "capture_request_bodies": True},
    )
    rows2 = client.get("/engagements", params={"status": "in_progress"}).json()
    row2 = next(r for r in rows2 if r["key"] == key)
    assert row2["capture_policy"]["enabled"] is True
    assert row2["capture_policy"]["capture_request_bodies"] is True


def test_ingest_registers_body_artifacts(client, isolate_settings):
    key = "2026-06-01-000009-flows"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    body_rel = "traffic/mitmproxy/bodies/req1.bin"
    (root / body_rel).parent.mkdir(parents=True, exist_ok=True)
    (root / body_rel).write_text("payload-bytes", encoding="utf-8")
    index_rel = "traffic/mitmproxy/flows/index-1.jsonl"
    (root / index_rel).parent.mkdir(parents=True, exist_ok=True)
    (root / index_rel).write_text('{"flow_uid": "art-1"}\n', encoding="utf-8")

    client.post(
        BASE.format(key=key),
        json=_flow_payload(
            flow_uid="art-1",
            request_body_artifact_path=body_rel,
            index_artifact_path=index_rel,
        ),
    )
    arts = client.get(f"/engagements/{key}/assessment/artifacts/search", params={"q": "mitmproxy"}).json()
    kinds = {a["kind"] for a in arts}
    assert "http_flow_body" in kinds
    assert "http_flow_index" in kinds
