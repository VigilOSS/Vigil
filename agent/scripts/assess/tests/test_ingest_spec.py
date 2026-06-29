"""Scope-filter tests for `vigil assess ingest-spec`.

A spec that declares an ABSOLUTE `servers`/`host` url has that url used as-is,
which bypasses the in-scope-only `_engagement_fallback_base` derivation. Without
a scope gate, a spec pointing at an out-of-scope host would ingest every
operation as probeable work. Because all operations in this implementation share
one base host, the gate is a single base-host check that refuses the whole spec
when the host is out of scope (and composes with the existing relative/empty-base
refusal). The backend/runtime are stubbed.
"""
from __future__ import annotations

import argparse
import json

from assess.commands import ingest_spec
from assess.lib.db import db_init, db_query


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    """Context-managed fake (ingest-spec uses `with AssessmentClient(...)`)."""

    def __init__(self) -> None:
        self.observations: list[dict] = []
        self._next_variant_id = 3000

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


def _spec_ns(db_path: str, spec_file: str, engagement_dir: str) -> argparse.Namespace:
    return argparse.Namespace(
        db_path=db_path,
        spec_file=spec_file,
        engagement_dir=engagement_dir,
    )


def _write_spec(tmp_path, server_url: str):
    spec = {
        "openapi": "3.0.0",
        "servers": [{"url": server_url}],
        "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(spec), encoding="utf-8")
    return spec_file


def _setup(tmp_path, monkeypatch, fake_client):
    db = tmp_path / "cases.db"
    db.write_bytes(b"")
    db_init(str(db))
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.com"]}), encoding="utf-8"
    )
    monkeypatch.setattr(ingest_spec, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_spec, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_spec, "AssessmentClient", lambda *a, **k: fake_client)
    return db


def test_ingest_spec_refuses_out_of_scope_base_host(tmp_path, monkeypatch, capsys):
    fake_client = _FakeClient()
    db = _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.out-of-scope.org")

    ingest_spec.run(_spec_ns(str(db), str(spec_file), str(tmp_path)))
    out = capsys.readouterr().out

    # Whole spec refused: 0 endpoints ingested, no observation POSTed (so no
    # service/surface created for the out-of-scope host), no work_items rows.
    assert "Ingested 0 endpoints" in out
    assert fake_client.observations == []
    total = db_query(str(db), "SELECT COUNT(*) AS n FROM work_items", ())
    assert total[0]["n"] == 0


def test_ingest_spec_admits_in_scope_base_host(tmp_path, monkeypatch, capsys):
    fake_client = _FakeClient()
    db = _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.example.com")

    ingest_spec.run(_spec_ns(str(db), str(spec_file), str(tmp_path)))
    capsys.readouterr()

    rows = db_query(
        str(db),
        "SELECT status FROM work_items WHERE url = ?",
        ("https://api.example.com/users",),
    )
    assert len(rows) == 1, "in-scope spec operation was not ingested"
    assert rows[0]["status"] == "pending"
    assert any("api.example.com" in (o.get("url") or "") for o in fake_client.observations)
