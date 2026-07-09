"""End-to-end tests for `vigil assess ingest-endpoints`.

These pin the content-type round-trip: a JSON endpoint line carrying a
`content_type` must (a) drive the typer at ingest (POST + application/json
floors to `type='api'`) AND (b) PERSIST that content_type onto the derived
work item, so a later `classify-work --retype` pass — which re-derives `type`
from the row's STORED content_type — reproduces the same `api` type instead of
flipping it back to `unknown`.

The per-engagement `work_items` table was folded into the orchestrator backend
(`assessment_work_items`, ADR 0013): `ingest-endpoints` now POSTs each in-scope
endpoint as a request-observation carrying a `work_item` derivation block, and
the backend derives the request-variant, coverage items, and the work-item row
in one transaction. Out-of-scope / egress-blocked URLs POST to `work-items/bulk`.

No FastAPI backend / runtime container: `load_config`, `auth_active_context`,
and `AssessmentClient` are stubbed with the stateful `FakeAssessmentClient`,
which derives work-item rows from the posted observations exactly as the backend
would — so the former `cases.db` row assertions are re-expressed against the
client's durable `rows` and captured POST payloads.
"""
from __future__ import annotations

import argparse
import json

from assess.commands import classify_work
from assess.commands import ingest_endpoints

from _fake_client import FakeAssessmentClient


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _ingest_ns(input_file: str, engagement_dir: str) -> argparse.Namespace:
    """Build the parsed-args namespace `ingest_endpoints.run` expects."""
    return argparse.Namespace(
        source="recon",
        input_file=input_file,
        egress_blocked_hosts=None,
        engagement_dir=engagement_dir,
    )


def _retype_ns(engagement_dir: str, **overrides) -> argparse.Namespace:
    base = dict(
        engagement_dir=engagement_dir,
        batch=500,
        reclassify_all=False,
        reclassify_stale=False,
        reclaim_skipped=False,
        only_unscored=False,
        retype=False,
        retype_all=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _install(monkeypatch, tmp_path, fake: FakeAssessmentClient) -> None:
    monkeypatch.setattr(
        ingest_endpoints, "load_config", lambda *a, **k: _Cfg(str(tmp_path))
    )
    monkeypatch.setattr(
        ingest_endpoints, "auth_active_context", lambda *a, **k: "anonymous"
    )
    monkeypatch.setattr(
        ingest_endpoints, "AssessmentClient", lambda *a, **k: fake
    )


def test_ingest_endpoints_persists_content_type_and_survives_retype(
    tmp_path, monkeypatch, capsys
):
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

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    rows = fake.row_for_url("https://h.example/submit")
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    # (a) the content_type drove the typer at ingest -> api
    assert rows[0]["type"] == "api"
    # (b) the SAME content_type was persisted onto the derived row (the fix)
    assert rows[0]["content_type"] == "application/json"

    # Round-trip: a --retype-all pass re-derives `type` from the STORED
    # content_type. Because the content_type was persisted, classify_type sees
    # `application/json` on a POST and reproduces `api`. Without the fix the
    # stored content_type would be "" and the row would flip api -> unknown.
    # classify-work reads/writes the SAME backend state, so point it at the same
    # fake client.
    monkeypatch.setattr(classify_work, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(classify_work, "AssessmentClient", lambda *a, **k: fake)
    classify_work.run(_retype_ns(str(tmp_path), retype=True, retype_all=True))
    capsys.readouterr()  # drain the retype summary

    after = fake.row_for_url("https://h.example/submit")
    assert after[0]["type"] == "api", (
        "retype flipped the type away from api — the ingest-time content_type "
        "was not persisted, so the typer saw an empty content_type"
    )
    assert after[0]["content_type"] == "application/json"


def test_ingest_endpoints_batches_request_observation_posts(
    tmp_path, monkeypatch, capsys
):
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

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    request_posts = [
        endpoint for endpoint, _payload in fake.posts
        if endpoint.startswith("request-observations")
    ]
    assert request_posts == ["request-observations/bulk"]

    rows = sorted(fake.rows, key=lambda row: row["url"])
    assert [row["url"] for row in rows] == [
        "https://h.example/one",
        "https://h.example/two",
    ]
    assert all(row["request_variant_id"] for row in rows)


def test_ingest_endpoints_preserves_json_liveness_metadata(
    tmp_path, monkeypatch, capsys
):
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

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    ns = _ingest_ns(str(input_file), str(tmp_path))
    ns.source = "web-discovery"
    ingest_endpoints.run(ns)
    capsys.readouterr()  # drain the ingest summary

    assert fake.observations[0]["response_status"] == 401
    assert fake.observations[0]["observation_payload"] == {
        "source": "web-discovery",
        "signals": ["httpx-live"],
        "live_status": "live",
    }

    rows = fake.row_for_url("https://h.example/")
    assert len(rows) == 1, "ingest-endpoints did not create the work item"
    assert rows[0]["response_status"] == 401
    assert rows[0]["live_status"] == "live"
    assert json.loads(rows[0]["signals"]) == ["httpx-live"]
    assert rows[0]["cluster_key"] == "type:host_root"
    assert rows[0]["priority_score"] == 5


def _coverage_candidates_for_line(tmp_path, monkeypatch, capsys, line: str) -> list[dict]:
    """Run ingest over a single JSONL `line` and return the coverage candidates
    the ingest attached to the (single) request-observation.

    The gf coverage bridge (matched-bucket → class-typed coverage candidate,
    incl. the weak-secondary-ssrf skip) now lives in the observation's
    `coverage_candidates` block the backend links to the request-variant, so the
    former `_gf_coverage_item_payloads` unit test is re-expressed as an assertion
    on that block after a real ingest.
    """
    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(line + "\n", encoding="utf-8")
    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    capsys.readouterr()
    assert len(fake.observations) == 1
    return list(fake.observations[0]["coverage_candidates"])


def test_gf_coverage_payloads_use_full_url_context_for_regex_buckets(
    tmp_path, monkeypatch, capsys
):
    payloads = _coverage_candidates_for_line(
        tmp_path, monkeypatch, capsys,
        "https://h.example/probe?x=http://169.254.169.254/latest/meta-data",
    )
    assert {
        (payload["attack_family"], payload["notes"])
        for payload in payloads
    } == {("ssrf", "gf bucket 'cloud_metadata' matched at ingest")}


def test_gf_coverage_payloads_use_full_url_context_for_object_storage_hosts(
    tmp_path, monkeypatch, capsys
):
    payloads = _coverage_candidates_for_line(
        tmp_path, monkeypatch, capsys,
        "https://public-bucket.s3.amazonaws.com/reports/q1.pdf",
    )
    assert {
        (payload["attack_family"], payload["notes"])
        for payload in payloads
    } == {("info-disclosure", "gf bucket 'object-storage' matched at ingest")}


def test_gf_coverage_payloads_skip_redirect_url_suffix_as_weak_ssrf(
    tmp_path, monkeypatch, capsys
):
    payloads = _coverage_candidates_for_line(
        tmp_path, monkeypatch, capsys,
        "https://h.example/callback?return_url=https://login.example/sso",
    )
    assert "open-redirect" in {payload["attack_family"] for payload in payloads}
    assert "ssrf" not in {payload["attack_family"] for payload in payloads}
    assert all(
        "gf bucket 'ssrf' weak inner-token signal at ingest" != payload["notes"]
        for payload in payloads
    )


def _run_ingest_line(tmp_path, monkeypatch, capsys, line: str) -> FakeAssessmentClient:
    """Run ingest-endpoints over a single JSONL `line` with the stubbed backend.

    Returns the fake client so the test can read back the derived work-item rows.
    """
    input_file = tmp_path / "endpoints.jsonl"
    input_file.write_text(line + "\n", encoding="utf-8")

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)
    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary
    return fake


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
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = fake.row_for_url("https://h.example/api/orders")
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
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, line)

    assert len(fake.observations) == 1
    header_schema = fake.observations[0]["header_schema"]
    assert set(header_schema) == {"X-Forwarded-Host", "X-Api-Key"}
    assert all(v == "" for v in header_schema.values())  # names only, no values


def test_ingest_endpoints_bare_url_leaves_header_schema_empty(
    tmp_path, monkeypatch, capsys
):
    """A2.1: bare-URL sources carry no headers, so header_schema stays {} — a
    clean no-op, never a faked schema."""
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, "https://h.example/plain")
    assert len(fake.observations) == 1
    assert fake.observations[0]["header_schema"] == {}


def test_ingest_endpoints_bare_url_leaves_payloads_empty(
    tmp_path, monkeypatch, capsys
):
    """P1-F regression: the passthrough is a clean no-op for the current
    bare-URL sources (katana/gau/recon) that carry no payloads — the fields
    default empty, unchanged from before the fix."""
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, "https://h.example/plain")
    rows = fake.row_for_url("https://h.example/plain")
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
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = fake.row_for_url("https://h.example/v1/users")
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
    fake = _run_ingest_line(tmp_path, monkeypatch, capsys, line)
    rows = fake.row_for_url("https://h.example/v1/users")
    assert len(rows) == 1
    assert rows[0]["type"] == "auth_entry"


def test_ingest_endpoints_scope_filter_excludes_out_of_scope_hosts(
    tmp_path, monkeypatch, capsys
):
    """gau/wayback historical URLs routinely surface reachable-but-out-of-scope
    hosts (e.g. *.acme-bank.example subdomains the program excluded). ingest-endpoints
    must admit ONLY scope.json-allowlisted hosts and record the rest as skipped
    (terminal_reason out-of-scope) via `work-items/bulk`, never POSTing a
    request-observation for them (so no service/surface is created for an
    out-of-scope host). Covers both the denylist carve-out and the
    no-allowlist-match case."""
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

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    # In-scope host admitted as a real (pending) work item.
    good = fake.row_for_url("https://good.example.com/api/v1/users")
    assert len(good) == 1, "in-scope host was not admitted to the work buffer"
    assert good[0]["status"] == "pending"

    # Both out-of-scope hosts recorded as skipped with the structured reason —
    # the denylist carve-out AND the no-allowlist-match case. These land as
    # `work-items/bulk` items, never as request-observations.
    for oos_url in ("https://bad.example.com/b", "https://evil.other.org/c"):
        rows = fake.row_for_url(oos_url)
        assert len(rows) == 1, f"no work_items row recorded for out-of-scope {oos_url}"
        assert rows[0]["status"] == "skipped", f"{oos_url} was not skipped"
        assert rows[0]["cluster_key"] == "skipped:out-of-scope"
        assert (rows[0]["terminal_reason"] or "").startswith("skipped:out-of-scope")

    # The out-of-scope hosts never got a request-observation POST (so no service
    # or surface is created for them); only the admitted host did.
    observed_urls = {o.get("url") for o in fake.observations}
    assert observed_urls == {"https://good.example.com/api/v1/users"}


def test_ingest_endpoints_over_long_url_skipped_batch_survives(
    tmp_path, monkeypatch, capsys
):
    """I-12: a single pathologically long URL (>4096 chars) must be skipped and
    reported, never carried into the bulk request-observation POST where one
    over-long row can fail the WHOLE batch at the backend's length validation and
    silently drop every good row with it. The well-formed rows around it still
    ingest."""
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

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    ingest_endpoints.run(_ingest_ns(str(input_file), str(tmp_path)))
    captured = capsys.readouterr()

    # The two well-formed URLs ingested; the over-long one did not.
    rows = sorted(fake.rows, key=lambda row: row["url"])
    assert [row["url"] for row in rows] == [
        "https://h.example/one",
        "https://h.example/two",
    ]
    # The over-long URL never reached the backend payload, so it could not take
    # the batch down with it.
    observed_urls = {o.get("url") for o in fake.observations}
    assert observed_urls == {"https://h.example/one", "https://h.example/two"}
    # The drop is reported (per-line WARN + the summary breakdown), not silent.
    assert "over-long URL" in captured.err
    assert "1 over-long-URL" in captured.err


def test_ingest_richer_reingest_updates_existing_row_payloads(
    tmp_path, monkeypatch, capsys
):
    """A richer JSON/HAR ingest that re-visits a URL first admitted by a bare-URL
    source must LAND its payloads on the already-admitted row.

    The backend upsert returns the SAME request_variant id for a repeated
    (method, url), so the derived queue_key collides and the row is UPDATED in
    place (not duplicated) — the fake mirrors that stable-variant upsert. The
    richer ingest's payloads must therefore overwrite the first ingest's empty
    headers/body/response, with still exactly one row for the URL.
    """
    url = "https://h.example/api/orders"

    fake = FakeAssessmentClient()
    _install(monkeypatch, tmp_path, fake)

    # 1) Bare-URL source admits the URL first — no request/response payloads.
    bare = tmp_path / "bare.txt"
    bare.write_text(url + "\n", encoding="utf-8")
    ingest_endpoints.run(_ingest_ns(str(bare), str(tmp_path)))
    capsys.readouterr()

    before = fake.row_for_url(url)
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
    ingest_endpoints.run(_ingest_ns(str(richer), str(tmp_path)))
    capsys.readouterr()

    after = fake.row_for_url(url)
    # Upsert, not a duplicate — still exactly one row for the URL.
    assert len(after) == 1
    # ...and the payloads the richer ingest carried now landed on the row.
    assert (after[0]["headers"] or ""), (
        "richer re-ingest did not store request headers on the already-admitted row"
    )
    assert json.loads(after[0]["headers"]) == {"Content-Type": "application/json", "X-Req": "1"}
    assert after[0]["body"] == '{"qty": 2}'
    assert json.loads(after[0]["response_headers"]) == {"Content-Type": "application/json"}
    assert after[0]["response_snippet"] == '{"order_id": 42, "status": "created"}'


# NOTE: the former `test_out_of_scope_insert_retires_existing_pending_same_url`
# exercised the local-SQLite `db_insert_work_item` / `db_insert_out_of_scope_work_item`
# retire-and-readmit mechanics (queue_key collision, cluster_key derivation). That
# entire code path moved server-side when `work_items` was folded into the
# backend `assessment_work_items` table; its behavior is now covered by the
# backend suite (orchestrator/backend/tests/test_work_buffer_backend.py), so the
# host-side test was removed rather than re-expressed against a fake.
