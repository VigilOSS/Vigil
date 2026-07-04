"""End-to-end tests for `vigil assess ingest-endpoints`.

These pin the content-type round-trip: a JSON endpoint line carrying a
`content_type` must (a) drive the typer at ingest (POST + application/json
floors to `type='api'`) AND (b) PERSIST that content_type onto the
`work_items` row, so a later `classify-work --retype` pass — which re-derives
`type` from the row's STORED content_type — reproduces the same `api` type
instead of flipping it back to `unknown`.

The bug this guards: `ingest-endpoints.run()` historically did not pass the
ingest-time `content_type` to `db_insert_work_item`, so the column stored `""`.
The first `--retype` over that corpus then fed the typer an empty content_type
and downgraded `api -> unknown` (a real, observed regression on proxy-captured
rows whose content_type was only known at ingest).

No FastAPI backend / runtime container: `load_config`, `auth_active_context`,
and the `AssessmentClient` are stubbed so the test exercises only the host-side
ingest path that builds and persists the work item.
"""
from __future__ import annotations

import argparse
import json

from assess.commands import classify_work
from assess.commands import ingest_endpoints
from assess.lib.db import (
    db_init,
    db_insert_out_of_scope_work_item,
    db_insert_work_item,
    db_query,
)


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Records observations and returns a synthetic request_variant id.

    `ingest-endpoints` POSTs a `request-observations` payload and uses the
    returned `request_variant.id` to key the work item; it also best-effort
    POSTs `coverage-items` for matched gf buckets. Both are accepted here so the
    ingest loop runs to completion without a live backend.
    """

    def __init__(self) -> None:
        self.observations: list[dict] = []
        self.posts: list[tuple[str, dict]] = []
        self._next_variant_id = 1000

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        if endpoint == "request-observations/bulk":
            records = []
            for observation in payload.get("items", []):
                self.observations.append(observation)
                self._next_variant_id += 1
                records.append({"request_variant": {"id": self._next_variant_id}})
            return {"count": len(records), "records": records}
        if endpoint == "coverage-items/bulk":
            return {"count": len(payload.get("items", [])), "records": []}
        if endpoint == "request-observations":
            self.observations.append(payload)
            self._next_variant_id += 1
            return {"request_variant": {"id": self._next_variant_id}}
        # coverage-items (and anything else) — return an empty ack.
        return {}

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _ingest_ns(db_path: str, input_file: str, engagement_dir: str) -> argparse.Namespace:
    """Build the parsed-args namespace `ingest_endpoints.run` expects."""
    return argparse.Namespace(
        db_path=db_path,
        source="recon",
        input_file=input_file,
        egress_blocked_hosts=None,
        engagement_dir=engagement_dir,
    )


def _retype_ns(db_path: str, **overrides) -> argparse.Namespace:
    base = dict(
        db_path=db_path,
        batch=500,
        reclassify_all=False,
        reclaim_skipped=False,
        only_unscored=False,
        retype=False,
        retype_all=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_ingest_endpoints_persists_content_type_and_survives_retype(
    tmp_path, monkeypatch, capsys
):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    # A POST endpoint whose JSON content_type is the ONLY signal that types it
    # as `api` (the path `/submit` carries no `/api/` marker or extension), so
    # this row is the precise case where a dropped content_type would mistype it.
    line = json.dumps(
        {
            "method": "POST",
            "url": "https://h.example/submit",
            "content_type": "application/json",
        }
    )
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(line + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    rows = db_query(
        str(db),
        "SELECT type, content_type FROM work_items WHERE url = ?",
        ("https://h.example/submit",),
    )
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    # (a) the content_type drove the typer at ingest -> api
    assert rows[0]["type"] == "api"
    # (b) the SAME content_type was persisted onto the row (the fix)
    assert rows[0]["content_type"] == "application/json"

    # Round-trip: a --retype-all pass re-derives `type` from the STORED
    # content_type. Because the content_type was persisted, classify_type sees
    # `application/json` on a POST and reproduces `api`. Without the fix the
    # stored content_type would be "" and the row would flip api -> unknown.
    classify_work.run(_retype_ns(str(db), retype=True, retype_all=True))
    capsys.readouterr()  # drain the retype summary

    after = db_query(
        str(db),
        "SELECT type, content_type FROM work_items WHERE url = ?",
        ("https://h.example/submit",),
    )
    assert after[0]["type"] == "api", (
        "retype flipped the type away from api — the ingest-time content_type "
        "was not persisted, so the typer saw an empty content_type"
    )
    assert after[0]["content_type"] == "application/json"


def test_ingest_endpoints_batches_request_observation_posts(
    tmp_path, monkeypatch, capsys
):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(
        "\n".join(
            [
                "https://h.example/one",
                "https://h.example/two",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    request_posts = [
        endpoint for endpoint, _payload in fake_client.posts
        if endpoint.startswith("request-observations")
    ]
    assert request_posts == ["request-observations/bulk"]

    rows = db_query(
        str(db),
        "SELECT request_variant_id, url FROM work_items ORDER BY url",
        (),
    )
    assert [row["url"] for row in rows] == [
        "https://h.example/one",
        "https://h.example/two",
    ]
    assert all(row["request_variant_id"] for row in rows)


def test_ingest_endpoints_preserves_json_liveness_metadata(
    tmp_path, monkeypatch, capsys
):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(
        json.dumps(
            {
                "method": "GET",
                "url": "https://h.example/",
                "response_status": 401,
                "type": "unknown",
                "source": "web-discovery",
                "live_status": "live",
                "signals": ["httpx-live"],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )

    ns = _ingest_ns(str(db), str(input_file), str(tmp_path))
    ns.source = "web-discovery"
    ingest_endpoints.run(ns)
    capsys.readouterr()  # drain the ingest summary

    assert fake_client.observations[0]["response_status"] == 401
    assert fake_client.observations[0]["observation_payload"] == {
        "source": "web-discovery",
        "signals": ["httpx-live"],
        "live_status": "live",
    }

    rows = db_query(
        str(db),
        "SELECT response_status, live_status, signals, priority_score, cluster_key "
        "FROM work_items WHERE url = ?",
        ("https://h.example/",),
    )
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    assert rows[0]["response_status"] == 401
    assert rows[0]["live_status"] == "live"
    assert json.loads(rows[0]["signals"]) == ["httpx-live"]
    assert rows[0]["cluster_key"] == "type:host_root"
    assert rows[0]["priority_score"] == 5


def test_gf_coverage_payloads_use_full_url_context_for_regex_buckets():
    payloads = ingest_endpoints._gf_coverage_item_payloads(
        request_variant_id=123,
        case_type="unknown",
        url="https://h.example/probe?x=http://169.254.169.254/latest/meta-data",
        url_path="/probe",
        query_params={"x": "http://169.254.169.254/latest/meta-data"},
        body_params={},
        path_params={},
        auth_context="anonymous",
    )

    assert {
        (payload["attack_family"], payload["notes"])
        for payload in payloads
    } == {("ssrf", "gf bucket 'cloud_metadata' matched at ingest")}


def test_gf_coverage_payloads_use_full_url_context_for_object_storage_hosts():
    payloads = ingest_endpoints._gf_coverage_item_payloads(
        request_variant_id=123,
        case_type="unknown",
        url="https://public-bucket.s3.amazonaws.com/reports/q1.pdf",
        url_path="/reports/q1.pdf",
        query_params={},
        body_params={},
        path_params={},
        auth_context="anonymous",
    )

    assert {
        (payload["attack_family"], payload["notes"])
        for payload in payloads
    } == {("info-disclosure", "gf bucket 'object-storage' matched at ingest")}


def test_gf_coverage_payloads_skip_redirect_url_suffix_as_weak_ssrf():
    payloads = ingest_endpoints._gf_coverage_item_payloads(
        request_variant_id=123,
        case_type="unknown",
        url="https://h.example/callback?return_url=https://login.example/sso",
        url_path="/callback",
        query_params={"return_url": "https://login.example/sso"},
        body_params={},
        path_params={},
        auth_context="anonymous",
    )

    assert "open-redirect" in {payload["attack_family"] for payload in payloads}
    assert "ssrf" not in {payload["attack_family"] for payload in payloads}
    assert all(
        "gf bucket 'ssrf' weak inner-token signal at ingest" != payload["notes"]
        for payload in payloads
    )


def _run_ingest_line(tmp_path, monkeypatch, capsys, line: str) -> None:
    """Run ingest-endpoints over a single JSONL `line` with the stubbed backend."""
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(line + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )
    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary
    return str(db)


def test_ingest_endpoints_carries_request_response_payloads_when_present(
    tmp_path, monkeypatch, capsys
):
    """P1-F: when a JSON producer emits headers/body/response_headers/
    response_snippet, ingest-endpoints threads them onto the work_item instead
    of dropping them at this second silent-truncation point. headers/
    response_headers arriving as dicts are JSON-serialized; body/response_snippet
    strings pass through."""
    line = json.dumps(
        {
            "method": "POST",
            "url": "https://h.example/api/orders",
            "content_type": "application/json",
            "headers": {"Content-Type": "application/json", "X-Req": "1"},
            "body": '{"qty": 2}',
            "response_headers": {"Content-Type": "application/json"},
            "response_snippet": '{"order_id": 42, "status": "created"}',
        }
    )
    db = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = db_query(
        str(db),
        "SELECT headers, body, response_headers, response_snippet "
        "FROM work_items WHERE url = ?",
        ("https://h.example/api/orders",),
    )
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    assert json.loads(rows[0]["headers"]) == {"Content-Type": "application/json", "X-Req": "1"}
    assert rows[0]["body"] == '{"qty": 2}'
    assert json.loads(rows[0]["response_headers"]) == {"Content-Type": "application/json"}
    assert rows[0]["response_snippet"] == '{"order_id": 42, "status": "created"}'


def test_ingest_endpoints_captures_header_schema_from_json_row(
    tmp_path, monkeypatch, capsys
):
    """A2.1: when a JSON/HAR row carries `headers`, the observation's
    header_schema is populated from the header NAMES (values discarded), with
    hop-by-hop / browser / already-captured noise dropped — so the depth ledger's
    CORS/proxy presence triggers fire on this slice instead of always seeing {}.
    """
    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    line = json.dumps(
        {
            "method": "GET",
            "url": "https://h.example/fetch",
            "headers": {
                "X-Forwarded-Host": "evil.example",  # attack-relevant → kept
                "X-Api-Key": "demo",                  # app-specific → kept
                "Host": "h.example",                  # target identity → dropped
                "User-Agent": "curl/8",               # browser noise → dropped
                "Cookie": "sid=abc",                  # own schema slot → dropped
                "Authorization": "Bearer x",          # auth_context → dropped
            },
        }
    )
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(line + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client)

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()

    assert len(fake_client.observations) == 1
    header_schema = fake_client.observations[0]["header_schema"]
    assert set(header_schema) == {"X-Forwarded-Host", "X-Api-Key"}
    assert all(v == "" for v in header_schema.values())  # names only, no values


def test_ingest_endpoints_bare_url_leaves_header_schema_empty(
    tmp_path, monkeypatch, capsys
):
    """A2.1: bare-URL sources carry no headers, so header_schema stays {} — a
    clean no-op, never a faked schema."""
    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text("https://h.example/plain\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client)

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()

    assert len(fake_client.observations) == 1
    assert fake_client.observations[0]["header_schema"] == {}


def test_ingest_endpoints_bare_url_leaves_payloads_empty(
    tmp_path, monkeypatch, capsys
):
    """P1-F regression: the passthrough is a clean no-op for the current
    bare-URL sources (katana/gau/recon) that carry no payloads — the fields
    default empty, unchanged from before the fix."""
    db = _run_ingest_line(tmp_path, monkeypatch, capsys, "https://h.example/plain")
    rows = db_query(
        str(db),
        "SELECT headers, body, response_headers, response_snippet "
        "FROM work_items WHERE url = ?",
        ("https://h.example/plain",),
    )
    assert len(rows) == 1
    assert (rows[0]["headers"] or "") == ""
    assert (rows[0]["body"] or "") == ""
    assert (rows[0]["response_headers"] or "") == ""
    assert (rows[0]["response_snippet"] or "") == ""


def test_ingest_explicit_unknown_type_falls_through_to_typer(
    tmp_path, monkeypatch, capsys
):
    # Fix 5 / Issues 5,D: an explicit `type=="unknown"` is NOT authoritative — it
    # falls through to classify_type(), which types `/v1/users` as `api` (the
    # bare-URL path shape). Without the guard the row would persist as `unknown`.
    line = json.dumps(
        {"method": "GET", "url": "https://h.example/v1/users", "type": "unknown"}
    )
    db = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = db_query(
        str(db),
        "SELECT type FROM work_items WHERE url = ?",
        ("https://h.example/v1/users",),
    )
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    assert rows[0]["type"] == "api", (
        "explicit type=='unknown' was treated as authoritative — it must fall "
        "through to classify_type()"
    )


def test_ingest_explicit_real_type_still_authoritative(
    tmp_path, monkeypatch, capsys
):
    # The guard ONLY bypasses the `unknown` sentinel — a real explicit type still
    # wins over classify_type (`/v1/users` would otherwise type `api`).
    line = json.dumps(
        {"method": "GET", "url": "https://h.example/v1/users", "type": "auth_entry"}
    )
    db = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = db_query(
        str(db),
        "SELECT type FROM work_items WHERE url = ?",
        ("https://h.example/v1/users",),
    )
    assert len(rows) == 1
    assert rows[0]["type"] == "auth_entry"


def test_ingest_endpoints_scope_filter_excludes_out_of_scope_hosts(
    tmp_path, monkeypatch, capsys
):
    """gau/wayback historical URLs routinely surface reachable-but-out-of-scope
    hosts (e.g. *.bank.acme.example subdomains the program excluded). ingest-endpoints
    must admit ONLY scope.json-allowlisted hosts and record the rest as skipped
    (terminal_reason out-of-scope), never POSTing a request-observation for them
    (so no service/surface is created for an out-of-scope host). Covers both the
    denylist carve-out and the no-allowlist-match case."""
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    # In scope: *.example.com (apex + every subdomain). Carve-out: bad.example.com.
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.com"], "out_of_scope": ["bad.example.com"]}),
        encoding="utf-8",
    )

    lines = "\n".join(
        [
            json.dumps({"method": "GET", "url": "https://good.example.com/api/v1/users"}),  # admitted
            json.dumps({"method": "GET", "url": "https://bad.example.com/b"}),              # denied carve-out
            json.dumps({"method": "GET", "url": "https://evil.other.org/c"}),               # no allowlist match
        ]
    )
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(lines + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    # In-scope host admitted as a real (pending) work item.
    good = db_query(
        str(db),
        "SELECT status FROM work_items WHERE url = ?",
        ("https://good.example.com/api/v1/users",),
    )
    assert len(good) == 1, "in-scope host was not admitted to the work buffer"
    assert good[0]["status"] == "pending"

    # Both out-of-scope hosts recorded as skipped with the structured reason —
    # the denylist carve-out AND the no-allowlist-match case.
    for oos_url in ("https://bad.example.com/b", "https://evil.other.org/c"):
        rows = db_query(
            str(db),
            "SELECT status, cluster_key, terminal_reason FROM work_items WHERE url = ?",
            (oos_url,),
        )
        assert len(rows) == 1, f"no work_items row recorded for out-of-scope {oos_url}"
        assert rows[0]["status"] == "skipped", f"{oos_url} was not skipped"
        assert rows[0]["cluster_key"] == "skipped:out-of-scope"
        assert (rows[0]["terminal_reason"] or "").startswith("skipped:out-of-scope")

    # The out-of-scope hosts never got a request-observation POST (so no service
    # or surface is created for them); only the admitted host did.
    observed_urls = {o.get("url") for o in fake_client.observations}
    assert observed_urls == {"https://good.example.com/api/v1/users"}


def test_ingest_endpoints_over_long_url_skipped_batch_survives(
    tmp_path, monkeypatch, capsys
):
    """I-12: a single pathologically long URL (>4096 chars) must be skipped and
    reported, never carried into the bulk request-observation POST where one
    over-long row can fail the WHOLE batch at the backend's length validation and
    silently drop every good row with it. The well-formed rows around it still
    ingest."""
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    over_long = "https://h.example/" + "a" * 5000
    assert len(over_long) > 4096
    lines = "\n".join(
        [
            "https://h.example/one",
            over_long,
            "https://h.example/two",
        ]
    )
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(lines + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake_client
    )

    ingest_endpoints.run(_ingest_ns(str(db), str(input_file), str(tmp_path)))
    captured = capsys.readouterr()

    # The two well-formed URLs ingested; the over-long one did not.
    rows = db_query(str(db), "SELECT url FROM work_items ORDER BY url", ())
    assert [row["url"] for row in rows] == [
        "https://h.example/one",
        "https://h.example/two",
    ]
    # The over-long URL never reached the backend payload, so it could not take
    # the batch down with it.
    observed_urls = {o.get("url") for o in fake_client.observations}
    assert observed_urls == {"https://h.example/one", "https://h.example/two"}
    # The drop is reported (per-line WARN + the summary breakdown), not silent.
    assert "over-long URL" in captured.err
    assert "1 over-long-URL" in captured.err


class _StableVariantClient:
    """Backend stub whose upsert returns the SAME request_variant id for a
    repeated (method, url).

    This mirrors the real backend: re-observing an already-admitted URL upserts
    to the same request_variant instead of minting a new one. That is the
    precondition for the duplicate-row bug — the CLI then derives the SAME
    queue_key on the richer second ingest, so a plain INSERT OR IGNORE would
    leave the first row's empty payloads in place.
    """

    def __init__(self) -> None:
        self.observations: list[dict] = []
        self.posts: list[tuple[str, dict]] = []
        self._ids: dict[tuple[str, str], int] = {}
        self._next = 1000

    def _variant_for(self, method, url) -> int:
        key = (method, url)
        if key not in self._ids:
            self._next += 1
            self._ids[key] = self._next
        return self._ids[key]

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        if endpoint == "request-observations/bulk":
            records = []
            for obs in payload.get("items", []):
                self.observations.append(obs)
                vid = self._variant_for(obs.get("method"), obs.get("url"))
                records.append({"request_variant": {"id": vid}})
            return {"count": len(records), "records": records}
        if endpoint == "coverage-items/bulk":
            return {"count": len(payload.get("items", [])), "records": []}
        if endpoint == "request-observations":
            self.observations.append(payload)
            vid = self._variant_for(payload.get("method"), payload.get("url"))
            return {"request_variant": {"id": vid}}
        return {}

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def test_ingest_richer_reingest_updates_existing_row_payloads(
    tmp_path, monkeypatch, capsys
):
    """A richer JSON/HAR ingest that re-visits a URL first admitted by a bare-URL
    source must LAND its payloads on the already-admitted row.

    The backend upsert returns the SAME request_variant id, so the CLI derives
    the SAME queue_key; before the fix, db_insert_work_item's INSERT OR IGNORE +
    classification-only update left the pre-existing empty headers/body/response
    untouched. Marking payload-carrying rows as curated routes them through the
    update-existing path so the payload is stored (and no duplicate row appears).
    """
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))
    url = "https://h.example/api/orders"

    fake = _StableVariantClient()
    monkeypatch.setattr(ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_endpoints, "AssessmentClient", lambda *a, **k: fake)

    # 1) Bare-URL source admits the URL first — no request/response payloads.
    bare = tmp_path / "bare.txt"
    bare.write_text(url + "\n", encoding="utf-8")
    ingest_endpoints.run(_ingest_ns(str(db), str(bare), str(tmp_path)))
    capsys.readouterr()

    before = db_query(
        str(db),
        "SELECT headers, body, response_headers, response_snippet FROM work_items WHERE url = ?",
        (url,),
    )
    assert len(before) == 1, "bare-URL ingest did not create the work item"
    assert (before[0]["headers"] or "") == ""
    assert (before[0]["body"] or "") == ""
    assert (before[0]["response_snippet"] or "") == ""

    # 2) Richer JSON ingest re-visits the SAME url carrying payloads.
    richer = tmp_path / "richer.jsonl"
    richer.write_text(
        json.dumps(
            {
                "method": "GET",
                "url": url,
                "content_type": "application/json",
                "headers": {"Content-Type": "application/json", "X-Req": "1"},
                "body": '{"qty": 2}',
                "response_headers": {"Content-Type": "application/json"},
                "response_snippet": '{"order_id": 42, "status": "created"}',
            }
        )
        + "\n",
        encoding="utf-8",
    )
    ingest_endpoints.run(_ingest_ns(str(db), str(richer), str(tmp_path)))
    capsys.readouterr()

    after = db_query(
        str(db),
        "SELECT headers, body, response_headers, response_snippet FROM work_items WHERE url = ?",
        (url,),
    )
    # Upsert, not a duplicate — still exactly one row for the URL.
    assert len(after) == 1
    # ...and the payloads the richer ingest carried now landed on it (before the
    # fix these stayed empty because the colliding queue_key hit INSERT OR IGNORE).
    assert (after[0]["headers"] or ""), (
        "richer re-ingest did not store request headers on the already-admitted row"
    )
    assert json.loads(after[0]["headers"]) == {"Content-Type": "application/json", "X-Req": "1"}
    assert after[0]["body"] == '{"qty": 2}'
    assert json.loads(after[0]["response_headers"]) == {"Content-Type": "application/json"}
    assert after[0]["response_snippet"] == '{"order_id": 42, "status": "created"}'


def test_out_of_scope_insert_retires_existing_pending_same_url(tmp_path):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    url = "https://bad.example.com/api/v1/users"
    db_insert_work_item(
        str(db),
        queue_key="variant:123:api",
        method="GET",
        url=url,
        url_path="/api/v1/users",
        query_params="{}",
        body_params="{}",
        path_params="{}",
        cookie_params="{}",
        case_type="api",
        source="recon",
        params_key_sig="",
        request_variant_id=123,
        auth_context="anonymous",
    )

    before = db_query(
        str(db),
        "SELECT status, terminal_reason FROM work_items WHERE queue_key = ?",
        ("variant:123:api",),
    )
    assert before == [{"status": "pending", "terminal_reason": None}]

    db_insert_out_of_scope_work_item(
        str(db),
        method="GET",
        url=url,
        url_path="/api/v1/users",
        query_params={},
        body_params={},
        path_params={},
        cookie_params={},
        case_type="api",
        source="recon",
        params_key_sig="",
        auth_context="anonymous",
        host="bad.example.com",
    )

    rows = db_query(
        str(db),
        "SELECT queue_key, status, cluster_key, terminal_reason "
        "FROM work_items WHERE url = ? ORDER BY id",
        (url,),
    )
    assert rows == [
        {
            "queue_key": "variant:123:api",
            "status": "skipped",
            "cluster_key": "skipped:out-of-scope",
            "terminal_reason": "skipped:out-of-scope | bad.example.com",
        }
    ]

    db_insert_work_item(
        str(db),
        queue_key="variant:123:api",
        method="GET",
        url=url,
        url_path="/api/v1/users",
        query_params="{}",
        body_params="{}",
        path_params="{}",
        cookie_params="{}",
        case_type="api",
        source="recon",
        params_key_sig="",
        request_variant_id=123,
        auth_context="anonymous",
    )

    readmitted = db_query(
        str(db),
        "SELECT status, cluster_key, terminal_reason FROM work_items WHERE queue_key = ?",
        ("variant:123:api",),
    )
    assert readmitted == [
        {
            "status": "pending",
            "cluster_key": "gf:api-versioning",
            "terminal_reason": None,
        }
    ]
