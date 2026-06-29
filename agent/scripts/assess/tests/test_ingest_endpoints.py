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
from assess.lib.db import db_init, db_query


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
    hosts (e.g. *.acme-bank.example subdomains the program excluded). ingest-endpoints
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
