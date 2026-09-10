"""Scope-filter tests for `vigil assess ingest spec`.

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

import pytest

from assess.commands import ingest_spec
from assess.lib.client import AssessError

from _fake_client import FakeAssessmentClient


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _spec_ns(spec_file: str, engagement_dir: str) -> argparse.Namespace:
    return argparse.Namespace(
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


def _setup(tmp_path, monkeypatch, fake_client, *, scope_enforcement=None):
    scope = {"hosts": ["*.example.com"]}
    if scope_enforcement is not None:
        scope["scope_enforcement"] = scope_enforcement
        scope["out_of_scope"] = ["api.out-of-scope.org"]
    (tmp_path / "scope.json").write_text(
        json.dumps(scope), encoding="utf-8"
    )
    monkeypatch.setattr(ingest_spec, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_spec, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_spec, "AssessmentClient", lambda *a, **k: fake_client)


def test_ingest_spec_refuses_out_of_scope_base_host(tmp_path, monkeypatch, capsys):
    fake_client = FakeAssessmentClient()
    _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.out-of-scope.org")

    ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))
    out = capsys.readouterr().out

    # Whole spec refused: 0 endpoints ingested, no observation POSTed (so no
    # service/surface created for the out-of-scope host), no work_items rows.
    assert "Ingested 0 endpoints" in out
    assert fake_client.observations == []
    assert fake_client.rows == []


def test_ingest_spec_admits_in_scope_base_host(tmp_path, monkeypatch, capsys):
    fake_client = FakeAssessmentClient()
    _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.example.com")

    ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))
    capsys.readouterr()

    rows = fake_client.row_for_url("https://api.example.com/users")
    assert len(rows) == 1, "in-scope spec operation was not ingested"
    assert rows[0]["status"] == "pending"
    assert any("api.example.com" in (o.get("url") or "") for o in fake_client.observations)


def test_individual_observation_response_requires_persisted_identities(
    tmp_path, monkeypatch, capsys
):
    fake_client = FakeAssessmentClient()
    _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.example.com")

    def individual_fallback(client, observations, **_kwargs):
        return [client.post("request-observations", item) for item in observations]

    monkeypatch.setattr(
        ingest_spec,
        "post_request_observations_bulk",
        individual_fallback,
    )
    original_post = fake_client.post

    def malformed_observation(endpoint, payload):
        if endpoint == "request-observations":
            original_post(endpoint, payload)
            return {"message": "accepted"}
        return original_post(endpoint, payload)

    fake_client.post = malformed_observation

    ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))

    captured = capsys.readouterr()
    assert "Ingested 0 endpoints" in captured.out
    assert "do not retry automatically" in captured.err


def test_malformed_bulk_success_receipt_is_not_retried_individually(
    tmp_path, monkeypatch
):
    class MalformedBulkClient(FakeAssessmentClient):
        def __init__(self) -> None:
            super().__init__()
            self.write_endpoints: list[str] = []

        def post(self, endpoint: str, payload: dict) -> dict:
            self.write_endpoints.append(endpoint)
            response = super().post(endpoint, payload)
            if endpoint == "request-observations/bulk":
                return {"count": 1, "records": [{"message": "accepted"}]}
            return response

    fake_client = MalformedBulkClient()
    _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.example.com")

    with pytest.raises(AssessError, match="write may have committed") as exc:
        ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))

    assert "do not retry automatically" in str(exc.value)
    assert fake_client.write_endpoints == ["request-observations/bulk"]


def test_explicit_bulk_payload_rejection_can_fall_back_individually(
    tmp_path, monkeypatch, capsys
):
    class PayloadRejectedBulkClient(FakeAssessmentClient):
        def __init__(self) -> None:
            super().__init__()
            self.write_endpoints: list[str] = []

        def post(self, endpoint: str, payload: dict) -> dict:
            self.write_endpoints.append(endpoint)
            if endpoint == "request-observations/bulk":
                raise AssessError("HTTP 422: bulk payload rejected before commit")
            return super().post(endpoint, payload)

    fake_client = PayloadRejectedBulkClient()
    _setup(tmp_path, monkeypatch, fake_client)
    spec_file = _write_spec(tmp_path, "https://api.example.com")

    ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))

    assert fake_client.write_endpoints == [
        "request-observations/bulk",
        "request-observations",
    ]
    assert "Ingested 1 endpoints" in capsys.readouterr().out


def test_ingest_spec_global_bypass_admits_outside_and_denied_base_host(
    tmp_path, monkeypatch, capsys
):
    fake_client = FakeAssessmentClient()
    _setup(tmp_path, monkeypatch, fake_client, scope_enforcement="bypass")
    spec_file = _write_spec(tmp_path, "https://api.out-of-scope.org")

    ingest_spec.run(_spec_ns(str(spec_file), str(tmp_path)))
    capsys.readouterr()

    rows = fake_client.row_for_url("https://api.out-of-scope.org/users")
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
