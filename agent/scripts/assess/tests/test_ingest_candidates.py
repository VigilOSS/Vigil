"""Scope-filter tests for `vigil assess ingest-candidates` + the shared resolver.

ingest-candidates ingests curated, metadata-rich candidate JSONL. Each record
carries an arbitrary per-record URL, so — exactly like ingest-endpoints — a
curated row can carry a reachable-but-out-of-scope host (e.g. carried through
from a gau/wayback corpus the curating specialist read). The scope gate must
admit only scope.json-allowlisted hosts and record the rest skipped
(terminal_reason out-of-scope), never POSTing an observation for them.

The backend / runtime are stubbed (`load_config`, `auth_active_context`, and the
context-managed `AssessmentClient`) so the test exercises only the host-side
ingest + scope-gate path.
"""
from __future__ import annotations

import argparse
import json

from assess.commands import ingest_candidates
from assess.lib.db import db_init, db_query
from assess.lib.scope import ingest_scope_filter


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Context-managed fake (ingest-candidates uses `with AssessmentClient(...)`)."""

    def __init__(self) -> None:
        self.observations: list[dict] = []
        self._next_variant_id = 2000

    def post(self, endpoint: str, payload: dict) -> dict:
        if endpoint == "request-observations":
            self.observations.append(payload)
            self._next_variant_id += 1
            return {"request_variant": {"id": self._next_variant_id}}
        return {}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _ns(db_path: str, records_file: str, engagement_dir: str) -> argparse.Namespace:
    return argparse.Namespace(
        db_path=db_path,
        source="surface-collector-curated",
        records_file=records_file,
        engagement_dir=engagement_dir,
    )


def test_ingest_candidates_scope_filter_excludes_out_of_scope_hosts(
    tmp_path, monkeypatch, capsys
):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")  # db_init requires the file to already exist
    db_init(str(db))

    # In scope: *.example.com (apex + every subdomain). Carve-out: bad.example.com.
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.com"], "out_of_scope": ["bad.example.com"]}),
        encoding="utf-8",
    )

    records = "\n".join(
        [
            json.dumps({"method": "GET", "url": "https://good.example.com/api/v1/users"}),  # admitted
            json.dumps({"method": "GET", "url": "https://bad.example.com/b"}),              # denied carve-out
            json.dumps({"method": "GET", "url": "https://evil.other.org/c"}),               # no allowlist match
        ]
    )
    records_file = tmp_path / "candidates.jsonl"
    records_file.write_text(records + "\n", encoding="utf-8")

    fake_client = _FakeClient()
    monkeypatch.setattr(ingest_candidates, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_candidates, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_candidates, "AssessmentClient", lambda *a, **k: fake_client)

    ingest_candidates.run(_ns(str(db), str(records_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    good = db_query(
        str(db),
        "SELECT status FROM work_items WHERE url = ?",
        ("https://good.example.com/api/v1/users",),
    )
    assert len(good) == 1, "in-scope candidate was not admitted to the work buffer"
    assert good[0]["status"] == "pending"

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

    # Only the admitted host got a request-observation POST.
    observed_urls = {o.get("url") for o in fake_client.observations}
    assert observed_urls == {"https://good.example.com/api/v1/users"}


def test_ingest_scope_filter_active_and_fail_open(tmp_path):
    """The shared resolver: active with a real allowlist, fail-open (inactive)
    when scope.json is absent — the contract every ingest path depends on so an
    unloadable/empty scope never rejects an entire batch."""
    # No scope.json -> SystemExit inside load_scope -> inactive (admit all).
    allow, deny, active = ingest_scope_filter(str(tmp_path))
    assert active is False and allow == [] and deny == []

    # A real allowlist -> active, with entries the gate can match against.
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.com"], "out_of_scope": ["bad.example.com"]}),
        encoding="utf-8",
    )
    allow, deny, active = ingest_scope_filter(str(tmp_path))
    assert active is True
    assert allow and deny

    # An allowlist of only un-admittable entries still yields active=False is NOT
    # asserted here (bool(allow) is True for any parsed entry); the fail-open path
    # is specifically the no-scope / unloadable case above.
