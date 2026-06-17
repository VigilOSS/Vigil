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
        self._next_variant_id = 1000

    def post(self, endpoint: str, payload: dict) -> dict:
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
