"""Readiness endpoint reports database connectivity and schema probes."""
from __future__ import annotations


def test_readyz_returns_schema_readiness_flags(client) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["database_connected"] is True
    assert body["assessment_schema_ready"] is True
    assert body["code_analysis_schema_ready"] is True
