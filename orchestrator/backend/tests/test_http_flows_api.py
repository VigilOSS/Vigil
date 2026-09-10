from __future__ import annotations

import base64
import hashlib
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
    client.post(
        BASE.format(key=key),
        json=_flow_payload(
            flow_uid="detail-1",
            request_body_capture_status="write_failed",
            request_body_capture_error="simulated full disk",
            response_body_capture_status="not_requested",
        ),
    )
    got = client.get(BASE.format(key=key) + "/detail-1")
    assert got.status_code == 200
    assert got.json()["flow_uid"] == "detail-1"
    assert got.json()["request_headers"] == {"Accept": "application/json"}
    assert got.json()["request_body_capture_status"] == "write_failed"
    assert got.json()["request_body_capture_error"] == "simulated full disk"
    assert got.json()["response_body_capture_status"] == "not_requested"
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


def test_import_drops_stale_cross_engagement_request_variant_id(client, isolate_settings):
    # A HAR exported from ANOTHER engagement carries ``_vigil.request_variant_id``
    # — a source-DB id. If passed straight into the destination it hits the
    # request_variant_id FK (IntegrityError → 500) or mis-links to an unrelated
    # local variant sharing that id. Import must DISCARD it: the flow imports
    # successfully with request_variant_id = None, never a 500.
    key = "2026-06-01-000007-varid"
    write_engagement(isolate_settings["engagements_dir"], key)
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "vigil", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-06-01T12:00:00Z",
                    "time": 10,
                    "request": {"method": "GET", "url": "https://api.example.com/v1/x", "headers": []},
                    "response": {"status": 200, "headers": []},
                    # 999999 does not exist in the destination engagement's variants.
                    "_vigil": {"flow_uid": "foreign-var", "request_variant_id": 999999},
                }
            ],
        }
    }
    imported = client.post(BASE.format(key=key) + "/import-har", json=har)
    assert imported.status_code == 201, imported.text
    assert imported.json()["count"] == 1
    # Stale foreign variant id was discarded, not persisted (no FK violation).
    assert imported.json()["flows"][0]["request_variant_id"] is None
    detail = client.get(BASE.format(key=key) + "/foreign-var").json()
    assert detail["request_variant_id"] is None


def test_import_plain_har_persists_body_to_sidecar_and_re_exports(client, isolate_settings):
    # BUG 3 regression: a plain (non-Vigil) HAR carries inline body text but no
    # ``_vigil.*_body_artifact_path``. Import must persist that text to an
    # engagement-local sidecar and record the path — otherwise the positive byte
    # count points at a body that ``har_from_flows`` (re-inlines only from paths)
    # can never recover, and the body is lost on the next export/detail view.
    key = "2026-06-01-000010-plainhar"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    req_text = '{"user":"admin","pw":"s3cret"}'
    resp_text = '{"token":"abc123"}'
    plain_har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "some-browser", "version": "1.0"},
            "entries": [
                {
                    "startedDateTime": "2026-06-01T12:00:00Z",
                    "time": 5,
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.com/v1/login",
                        "headers": [],
                        "postData": {"mimeType": "application/json", "text": req_text},
                    },
                    "response": {
                        "status": 200,
                        "headers": [],
                        "content": {"mimeType": "application/json", "text": resp_text},
                    },
                    # NO _vigil object → plain (non-Vigil) HAR.
                }
            ],
        }
    }
    imported = client.post(BASE.format(key=key) + "/import-har", json=plain_har)
    assert imported.status_code == 201, imported.text
    flow = imported.json()["flows"][0]
    # Bytes counted AND a recoverable sidecar path recorded (the fix).
    assert flow["request_body_bytes"] == len(req_text.encode("utf-8"))
    assert flow["response_body_bytes"] == len(resp_text.encode("utf-8"))
    assert flow["request_body_artifact_path"]
    assert flow["response_body_artifact_path"]
    # sha recorded and the sidecar exists on disk under the engagement root.
    assert flow["response_body_sha256"] == hashlib.sha256(resp_text.encode()).hexdigest()
    assert (root / flow["response_body_artifact_path"]).is_file()
    # Re-export re-inlines the bodies from the sidecars (previously unrecoverable).
    har = client.get(BASE.format(key=key) + "/export-har").json()
    entry = har["log"]["entries"][0]
    assert entry["request"]["postData"]["text"] == req_text
    assert entry["response"]["content"]["text"] == resp_text


def test_export_base64_encodes_non_utf8_body(client, isolate_settings):
    # BUG 4 regression: a non-UTF-8 body sidecar (PDF/zip/octet-stream captured
    # with no content-type filter) must be base64-encoded with an ``encoding``
    # marker on HAR export — NOT silently mojibake'd via ``errors="replace"``.
    key = "2026-06-01-000011-binary"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    raw = bytes([0x89, 0x50, 0x4E, 0x47, 0xFF, 0xFE, 0x00, 0x01, 0x80])  # invalid UTF-8
    assert raw.decode("utf-8", errors="ignore") != raw.decode("latin-1")  # truly non-UTF-8
    sha = hashlib.sha256(raw).hexdigest()
    body_rel = f"traffic/mitmproxy/bodies/{sha}.bin"
    (root / body_rel).parent.mkdir(parents=True, exist_ok=True)
    (root / body_rel).write_bytes(raw)
    client.post(
        BASE.format(key=key),
        json=_flow_payload(
            flow_uid="bin-1",
            response_content_type="application/octet-stream",
            response_body_artifact_path=body_rel,
            response_body_bytes=len(raw),
            response_body_sha256=sha,
        ),
    )
    har = client.get(BASE.format(key=key) + "/export-har").json()
    content = har["log"]["entries"][0]["response"]["content"]
    assert content["encoding"] == "base64"
    assert base64.b64decode(content["text"]) == raw  # exact bytes, no corruption


def test_binary_body_round_trips_export_import_via_base64(client, isolate_settings):
    # BUG 3 + BUG 4 integration: export marks a non-UTF-8 body base64; a plain-HAR
    # re-import decodes that base64 back into a sidecar so the EXACT bytes survive
    # a full export→import round trip (rather than being lost or corrupted).
    src = "2026-06-01-000012-binsrc"
    dst = "2026-06-01-000013-bindst"
    sroot = write_engagement(isolate_settings["engagements_dir"], src)
    droot = write_engagement(isolate_settings["engagements_dir"], dst)
    raw = bytes(range(256))  # every byte value → decidedly non-UTF-8
    sha = hashlib.sha256(raw).hexdigest()
    body_rel = f"traffic/mitmproxy/bodies/{sha}.bin"
    (sroot / body_rel).parent.mkdir(parents=True, exist_ok=True)
    (sroot / body_rel).write_bytes(raw)
    client.post(
        BASE.format(key=src),
        json=_flow_payload(
            flow_uid="rt-bin",
            response_content_type="application/octet-stream",
            response_body_artifact_path=body_rel,
            response_body_bytes=len(raw),
            response_body_sha256=sha,
        ),
    )
    har = client.get(BASE.format(key=src) + "/export-har").json()
    content = har["log"]["entries"][0]["response"]["content"]
    assert content["encoding"] == "base64"
    # Strip _vigil so import treats it as a plain HAR and re-persists the body via
    # _har_body_raw (base64-aware) + the sidecar writer (the cross-engagement
    # sidecar-copy path for Vigil HARs is a separate concern).
    for entry in har["log"]["entries"]:
        entry.pop("_vigil", None)
    imported = client.post(BASE.format(key=dst) + "/import-har", json=har)
    assert imported.status_code == 201, imported.text
    flow = imported.json()["flows"][0]
    assert flow["response_body_artifact_path"]
    assert (droot / flow["response_body_artifact_path"]).read_bytes() == raw


def test_vigil_har_import_rehydrates_foreign_body_sidecars(client, isolate_settings):
    # A Vigil HAR exported from another engagement carries source-relative
    # ``_vigil.*_body_artifact_path`` values. Importing it into a destination
    # engagement must persist the inline HAR bodies under the destination root;
    # trusting the source path alone leaves a missing sidecar and loses the body
    # on the next detail/export read.
    src = "2026-06-01-000014-vigil-src"
    dst = "2026-06-01-000015-vigil-dst"
    sroot = write_engagement(isolate_settings["engagements_dir"], src)
    droot = write_engagement(isolate_settings["engagements_dir"], dst)
    request_raw = b'{"user":"admin"}'
    response_raw = b'{"ok":true}'
    request_sha = hashlib.sha256(request_raw).hexdigest()
    response_sha = hashlib.sha256(response_raw).hexdigest()
    request_rel = f"traffic/mitmproxy/bodies/{request_sha}.bin"
    response_rel = f"traffic/mitmproxy/bodies/{response_sha}.bin"
    (sroot / request_rel).parent.mkdir(parents=True, exist_ok=True)
    (sroot / request_rel).write_bytes(request_raw)
    (sroot / response_rel).write_bytes(response_raw)

    client.post(
        BASE.format(key=src),
        json=_flow_payload(
            flow_uid="foreign-vigil-body",
            method="POST",
            request_content_type="application/json",
            response_content_type="application/json",
            request_body_artifact_path=request_rel,
            request_body_bytes=len(request_raw),
            request_body_sha256=request_sha,
            response_body_artifact_path=response_rel,
            response_body_bytes=len(response_raw),
            response_body_sha256=response_sha,
        ),
    )
    har = client.get(BASE.format(key=src) + "/export-har").json()
    imported = client.post(BASE.format(key=dst) + "/import-har", json=har)
    assert imported.status_code == 201, imported.text

    flow = imported.json()["flows"][0]
    assert (droot / flow["request_body_artifact_path"]).read_bytes() == request_raw
    assert (droot / flow["response_body_artifact_path"]).read_bytes() == response_raw

    reexported = client.get(BASE.format(key=dst) + "/export-har").json()
    entry = reexported["log"]["entries"][0]
    assert entry["request"]["postData"]["text"] == request_raw.decode()
    assert entry["response"]["content"]["text"] == response_raw.decode()


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
    assert body["redaction_warning"] == ""
    assert body["retention"] == "until_engagement_deletion"

    unsupported = client.put(policy_url, json={"redaction_profile": "default"})
    assert unsupported.status_code == 422

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


def test_capture_policy_surfaces_unsupported_legacy_redaction_without_claiming_it(
    client, isolate_settings
):
    from app import db as db_module

    key = "2026-06-01-000007-legacy-redaction"
    write_engagement(isolate_settings["engagements_dir"], key)
    policy_url = f"/engagements/{key}/assessment/capture-policy"
    assert client.put(policy_url, json={"enabled": True}).status_code == 200
    engagement_id = client.get(f"/engagements/{key}").json()["id"]
    with db_module.get_connection() as connection:
        connection.execute(
            "UPDATE assessment_capture_policy SET redaction_profile = 'legacy-default' "
            "WHERE engagement_id = ?",
            (engagement_id,),
        )

    response = client.get(policy_url)

    assert response.status_code == 200
    assert response.json()["redaction_profile"] == "none"
    assert "legacy-default" in response.json()["redaction_warning"]


def test_http_flow_capture_status_additive_migration_preserves_legacy_rows(
    isolate_settings,
):
    import sqlite3

    from app import db as db_module

    db_module.init_db()
    db_module.close_thread_connection()
    path = db_module.database_path()
    with sqlite3.connect(path) as connection:
        connection.execute(
            "INSERT INTO engagements (id, key, target, status, engagement_root) "
            "VALUES (1, 'legacy-flow', 'https://example.com', 'active', '/tmp/legacy')"
        )
        connection.execute(
            "INSERT INTO assessment_http_flows "
            "(engagement_id, flow_uid, method, url, request_body_sha256, "
            "request_body_bytes, request_body_artifact_path) "
            "VALUES (1, 'legacy-1', 'POST', 'https://example.com/api', "
            "'abc123', 7, 'traffic/legacy.bin')"
        )
        for column in (
            "request_body_capture_status",
            "response_body_capture_status",
            "request_body_capture_error",
            "response_body_capture_error",
        ):
            connection.execute(f"ALTER TABLE assessment_http_flows DROP COLUMN {column}")

    db_module.init_db()

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT method, url, request_body_sha256, request_body_bytes, "
            "request_body_artifact_path, request_body_capture_status, "
            "response_body_capture_status, request_body_capture_error, "
            "response_body_capture_error FROM assessment_http_flows "
            "WHERE flow_uid = 'legacy-1'"
        ).fetchone()
    assert row == (
        "POST",
        "https://example.com/api",
        "abc123",
        7,
        "traffic/legacy.bin",
        "unknown",
        "unknown",
        "",
        "",
    )


def test_capture_policy_reports_filesystem_mirror_failure(
    client, isolate_settings, monkeypatch
) -> None:
    key = "2026-06-01-000007-mirror-failure"
    root = write_engagement(isolate_settings["engagements_dir"], key)
    policy_url = f"/engagements/{key}/assessment/capture-policy"
    original_write_text = Path.write_text

    def fail_capture_policy_write(path: Path, *args, **kwargs):
        if path.name == "capture-policy.json.tmp":
            raise OSError("simulated read-only engagement root")
        return original_write_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_capture_policy_write)
    response = client.put(policy_url, json={"enabled": True})

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["database_updated"] is True
    assert detail["filesystem_mirror_updated"] is False
    assert "simulated read-only engagement root" in detail["error"]
    # The authoritative DB write is retained and honestly reported, so retrying
    # the idempotent PUT can repair the mirror without losing the requested policy.
    assert client.get(policy_url).json()["enabled"] is True
    assert not (root / "capture-policy.json").exists()


def test_capture_policy_present_in_engagements_registry(client, isolate_settings):
    key = "2026-06-01-000008-flows"
    write_engagement(isolate_settings["engagements_dir"], key)
    # Default policy is present in the registry payload the proxy addon consumes.
    rows = client.get("/engagements", params={"status": "in_progress"}).json()
    row = next(r for r in rows if r["key"] == key)
    assert "capture_policy" in row
    assert row["capture_policy"]["enabled"] is False
    assert row["capture_policy"]["retention"] == "until_engagement_deletion"

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
