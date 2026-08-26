"""Readiness endpoint reports database connectivity and schema probes."""
from __future__ import annotations


import sqlite3
from contextlib import contextmanager


def test_readyz_returns_schema_readiness_flags(client) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["database_connected"] is True
    assert body["assessment_schema_ready"] is True
    assert body["code_analysis_schema_ready"] is True
    runtime = body["backend_runtime"]
    assert runtime["source_root"].endswith("/orchestrator/backend/app")
    assert runtime["process_started_at"].endswith("Z")
    assert isinstance(runtime["restart_required"], bool)
    assert isinstance(runtime["newer_source_files"], list)


def test_sqlite_lock_contention_is_a_retryable_503(client, monkeypatch) -> None:
    from app import main

    @contextmanager
    def locked_connection():
        raise sqlite3.OperationalError("database is locked")
        yield  # pragma: no cover

    monkeypatch.setattr(main, "get_connection", locked_connection)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert response.json()["detail"] == "database write contention; retry shortly"
