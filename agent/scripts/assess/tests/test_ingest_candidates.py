"""Scope-filter tests for `vigil assess ingest candidates` + the shared resolver.

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

import pytest

from assess.commands import ingest_candidates
from assess.lib.scope import ingest_scope_filter

from _fake_client import FakeAssessmentClient


class _Cfg:
    """Minimal stand-in for `assess.lib.config.Config`."""

    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _ns(records_file: str, engagement_dir: str) -> argparse.Namespace:
    return argparse.Namespace(
        source="surface-collector-curated",
        records_file=records_file,
        engagement_dir=engagement_dir,
    )


def test_ingest_candidates_rejects_noncanonical_observation_receipt(
    tmp_path, monkeypatch
) -> None:
    records_file = tmp_path / "candidates.jsonl"
    records_file.write_text(
        json.dumps({"method": "GET", "url": "https://target.example/one"}) + "\n",
        encoding="utf-8",
    )

    class InvalidReceiptClient(FakeAssessmentClient):
        def post(self, endpoint: str, payload: dict) -> dict:
            response = super().post(endpoint, payload)
            if endpoint == "request-observations/bulk":
                response["records"] = [{"request_variant": {"id": 1}}]
            return response

    fake = InvalidReceiptClient()
    monkeypatch.setattr(ingest_candidates, "load_config", lambda *_: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_candidates, "auth_active_context", lambda *_: "anonymous")
    monkeypatch.setattr(ingest_candidates, "AssessmentClient", lambda *_: fake)

    with pytest.raises(Exception, match="request observation.*may have committed") as exc:
        ingest_candidates.run(_ns(str(records_file), str(tmp_path)))

    assert "do not retry automatically" in str(exc.value)


def test_ingest_candidates_scope_filter_excludes_out_of_scope_hosts(
    tmp_path, monkeypatch, capsys
):
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

    fake_client = FakeAssessmentClient()
    monkeypatch.setattr(ingest_candidates, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_candidates, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_candidates, "AssessmentClient", lambda *a, **k: fake_client)

    ingest_candidates.run(_ns(str(records_file), str(tmp_path)))
    capsys.readouterr()  # drain the ingest summary

    good = fake_client.row_for_url("https://good.example.com/api/v1/users")
    assert len(good) == 1, "in-scope candidate was not admitted to the work buffer"
    assert good[0]["status"] == "pending"

    # Out-of-scope candidates land as `work-items/bulk` items (skipped), never as
    # request-observations.
    for oos_url in ("https://bad.example.com/b", "https://evil.other.org/c"):
        rows = fake_client.row_for_url(oos_url)
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


def test_ingest_scope_filter_global_bypass_disables_allow_and_deny_gate(tmp_path):
    (tmp_path / "scope.json").write_text(
        json.dumps(
            {
                "hosts": ["target.example"],
                "out_of_scope": ["blocked.example"],
                "scope_enforcement": "bypass",
            }
        ),
        encoding="utf-8",
    )

    allow, deny, active = ingest_scope_filter(str(tmp_path))

    assert active is False
    assert allow and deny


def test_ingest_candidates_global_bypass_admits_outside_and_denied_hosts(
    tmp_path, monkeypatch, capsys
):
    (tmp_path / "scope.json").write_text(
        json.dumps(
            {
                "hosts": ["target.example"],
                "out_of_scope": ["blocked.example"],
                "scope_enforcement": "bypass",
            }
        ),
        encoding="utf-8",
    )
    records_file = tmp_path / "candidates.jsonl"
    urls = ["https://outside.example/a", "https://blocked.example/b"]
    records_file.write_text(
        "\n".join(json.dumps({"method": "GET", "url": url}) for url in urls) + "\n",
        encoding="utf-8",
    )
    fake_client = FakeAssessmentClient()
    monkeypatch.setattr(ingest_candidates, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_candidates, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_candidates, "AssessmentClient", lambda *a, **k: fake_client)

    ingest_candidates.run(_ns(str(records_file), str(tmp_path)))
    capsys.readouterr()

    assert {row["url"] for row in fake_client.observations} == set(urls)
    assert all(fake_client.row_for_url(url)[0]["status"] == "pending" for url in urls)


def _single_record_setup(tmp_path, monkeypatch, record: dict) -> tuple[str, FakeAssessmentClient]:
    (tmp_path / "scope.json").write_text(
        json.dumps({"hosts": ["*.example.com"]}), encoding="utf-8"
    )
    records_file = tmp_path / "candidates.jsonl"
    records_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

    fake_client = FakeAssessmentClient()
    monkeypatch.setattr(ingest_candidates, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(ingest_candidates, "auth_active_context", lambda *a, **k: "anonymous")
    monkeypatch.setattr(ingest_candidates, "AssessmentClient", lambda *a, **k: fake_client)
    return str(records_file), fake_client


def test_ingest_candidates_headers_present_flow_into_observation_and_work_item(
    tmp_path, monkeypatch, capsys
):
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "headers": {"X-Api-Key": "demo-key"},
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert len(fake_client.observations) == 1
    assert fake_client.observations[0]["header_schema"] == {"X-Api-Key": "demo-key"}

    rows = fake_client.row_for_url("https://good.example.com/api/v1/users")
    assert len(rows) == 1
    assert json.loads(rows[0]["headers"]) == {"X-Api-Key": "demo-key"}


def test_ingest_candidates_headers_absent_behaves_as_before(tmp_path, monkeypatch, capsys):
    record = {"method": "GET", "url": "https://good.example.com/api/v1/users"}
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert fake_client.observations[0]["header_schema"] == {}

    rows = fake_client.row_for_url("https://good.example.com/api/v1/users")
    assert len(rows) == 1
    assert rows[0]["headers"] in (None, "", "{}")


def test_ingest_candidates_header_params_list_shape_does_not_drop_candidate(
    tmp_path, monkeypatch, capsys
):
    """`header_params` is conventionally a list[str] of header NAMES elsewhere
    in this codebase (arjun_enrich.py / ingest_arjun.py), not the dict-shaped
    header_schema the backend expects. A candidate record using that existing
    list convention must still ingest (coerced to a dict) instead of sending a
    non-dict header_schema that 422s and silently drops the whole candidate."""
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "header_params": ["X-Api-Key", "X-Trace-Id"],
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    # The observation still posted (not dropped) and header_schema is a dict.
    assert len(fake_client.observations) == 1
    assert fake_client.observations[0]["header_schema"] == {"X-Api-Key": "", "X-Trace-Id": ""}

    rows = fake_client.row_for_url("https://good.example.com/api/v1/users")
    assert len(rows) == 1, "candidate was silently dropped instead of ingesting with coerced headers"
    assert rows[0]["status"] == "pending"
    assert json.loads(rows[0]["headers"]) == {"X-Api-Key": "", "X-Trace-Id": ""}


def test_ingest_candidates_header_params_non_dict_non_list_falls_back_to_empty(
    tmp_path, monkeypatch, capsys
):
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "header_params": "not-a-collection",
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert len(fake_client.observations) == 1
    assert fake_client.observations[0]["header_schema"] == {}


def test_ingest_candidates_evidence_ref_present_passed_through(tmp_path, monkeypatch, capsys):
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "evidence_ref": "scans/katana.txt:42",
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert fake_client.observations[0]["evidence_ref"] == "scans/katana.txt:42"


def test_ingest_candidates_evidence_ref_absent_stays_empty(tmp_path, monkeypatch, capsys):
    record = {"method": "GET", "url": "https://good.example.com/api/v1/users"}
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert fake_client.observations[0]["evidence_ref"] == ""


def test_ingest_candidates_surface_refs_creates_links(tmp_path, monkeypatch, capsys):
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "evidence_ref": "scans/katana.txt:42",
        "surface_refs": [7, 9],
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    out = capsys.readouterr().out

    assert len(fake_client.links) == 2
    surface_ids = {link["surface_id"] for link in fake_client.links}
    assert surface_ids == {7, 9}
    # The links carry the request_variant_id the backend minted for the derived
    # work item (the durable cross-reference, not the ephemeral local row id).
    variant_id = fake_client.row_for_url("https://good.example.com/api/v1/users")[0]["request_variant_id"]
    for link in fake_client.links:
        assert link["evidence_ref"] == "scans/katana.txt:42"
        assert link["request_variant_id"] == variant_id
    assert "Created 2 surface link(s)" in out


def test_ingest_candidates_surface_refs_absent_creates_no_links(tmp_path, monkeypatch, capsys):
    record = {"method": "GET", "url": "https://good.example.com/api/v1/users"}
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    capsys.readouterr()

    assert fake_client.links == []


def test_ingest_candidates_failed_link_does_not_abort_ingestion(tmp_path, monkeypatch, capsys):
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "surface_refs": [7],
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    real_post = fake_client.post

    def _flaky_post(endpoint: str, payload: dict) -> dict:
        if endpoint == "surface-request-variant-links":
            raise RuntimeError("backend rejected the link")
        return real_post(endpoint, payload)

    monkeypatch.setattr(fake_client, "post", _flaky_post)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    out, err = capsys.readouterr()

    # The work_item itself still ingested successfully despite the link failure.
    rows = fake_client.row_for_url("https://good.example.com/api/v1/users")
    assert len(rows) == 1
    assert rows[0]["status"] == "pending"
    assert "Created 0 surface link(s)" in out
    assert "failed to link surface" in err


def test_ingest_candidates_surface_refs_dropped_with_warning_on_service_only_resolution(
    tmp_path, monkeypatch, capsys
):
    """A candidate that resolves to a service only (no request_variant_id) has
    nothing for a surface_refs link to attach to. It must be visibly skipped
    (warning + links_skipped count), not silently dropped."""
    record = {
        "method": "GET",
        "url": "https://good.example.com/api/v1/users",
        "surface_refs": [7],
    }
    records_file, fake_client = _single_record_setup(tmp_path, monkeypatch, record)

    def _service_only_post(endpoint: str, payload: dict) -> dict:
        if endpoint == "request-observations/bulk":
            records = [{"service": {"id": 42}} for _ in payload.get("items", [])]
            return {"count": len(records), "records": records}
        raise AssertionError(f"unexpected endpoint {endpoint}")

    monkeypatch.setattr(fake_client, "post", _service_only_post)

    ingest_candidates.run(_ns(records_file, str(tmp_path)))
    out, err = capsys.readouterr()

    assert fake_client.links == []
    assert "resolved to a service only" in err
    assert "dropping 1 surface_refs link(s)" in err
    assert "Created 0 surface link(s)" in out
    assert "skipped 1" in out
