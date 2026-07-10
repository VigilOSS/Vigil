"""record-finding clobber-guard + --update opt-in (I-21).

The backend dedup UPSERT matches a net-new record onto an existing finding by
the ``(defect_family + root_cause_key + auth_context + canonical_location)``
tuple (excluding ``merged``), NOT by slug. Before this guard, a net-new finding
that collided that tuple with an existing finding under a DIFFERENT slug
silently overwrote a load-bearing (``reported``/``active``) finding.

Decided behavior: REFUSE such a clobber unless the caller names that exact
existing slug — the ``--update <slug>`` CLI opt-in, or an explicit slug on the
raw POST. The guard is enforced at BOTH the CLI boundary (``record_finding.py``)
and the backend match (``state_manager/findings.py``) so a CLI bypass cannot
defeat the HTTP enforcement; this module covers both surfaces.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sqlite3
import sys
from pathlib import Path

# The assess CLI package lives under agent/scripts; put it on the path so the
# CLI-boundary half of the dual enforcement is testable from the backend suite
# (mirrors test_kali_cli.py).
_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))


ENGAGEMENT_KEY = "2026-06-30-120000-clobber"


# ──────────────────────────────────────────────────────────────────────────
# Backend HTTP enforcement (the authoritative, un-bypassable layer)
# ──────────────────────────────────────────────────────────────────────────


def _seed(client, isolate_settings) -> None:
    engagement_dir = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "Clobber Guard", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _base() -> str:
    return f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _finding(
    slug,
    *,
    workflow_status="active",
    verification_state="unreviewed",
    verification_disposition="none",
    defect_family="access-control",
    root_cause_key="missing-object-authz",
    auth_context="anonymous",
    canonical_location="https://app.example/api/users",
    summary="IDOR",
    title="IDOR in /api/users/{id} allows anon read of any user PII",
) -> dict:
    payload = {
        "title": title,
        "severity": "high",
        "workflow_status": workflow_status,
        "verification_state": verification_state,
        "verification_disposition": verification_disposition,
        "defect_family": defect_family,
        "root_cause_key": root_cause_key,
        "auth_context": auth_context,
        "canonical_location": canonical_location,
        "summary": summary,
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "Replayable request.", "impact": "PII disclosure."},
        "provenance": {"agent_name": "vulnerability-analyst"},
        "links": [],
    }
    if slug is not None:
        payload["slug"] = slug
    return payload


def test_net_new_collision_against_reported_is_refused(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="reported")
    ).status_code == 201

    # A net-new finding with a DIFFERENT slug but the SAME dedup tuple.
    resp = client.post(
        f"{_base()}/findings",
        json=_finding("VA-002", workflow_status="active", summary="rediscovered by a later pass"),
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "VA-001" in detail
    assert "--update VA-001" in detail

    # VA-001 is untouched and VA-002 was never created.
    rows = client.get(f"{_base()}/findings").json()
    assert {r["slug"] for r in rows} == {"VA-001"}
    assert next(r for r in rows if r["slug"] == "VA-001")["summary"] == "IDOR"


def test_net_new_collision_against_active_is_refused(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="active")
    ).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding("VA-002", workflow_status="active", summary="rediscovered"),
    )
    assert resp.status_code == 409, resp.text


def test_evidence_artifact_backfill_does_not_attach_to_concurrently_replaced_evidence(
    client, isolate_settings, monkeypatch
):
    _seed(client, isolate_settings)
    payload = _finding("VA-099")
    payload["evidence_ref"] = ""
    created = client.post(f"{_base()}/findings", json=payload)
    assert created.status_code == 201, created.text
    initial_version = created.json()["finding"]["row_version"]

    from app.services.state_manager import _common

    original_register = _common._register_artifact_reference
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    raced = False

    def register_then_replace(*args, **kwargs):
        nonlocal raced
        artifact_id = original_register(*args, **kwargs)
        if not raced:
            raced = True
            with sqlite3.connect(str(db_path)) as connection:
                connection.execute(
                    """
                    UPDATE assessment_findings
                    SET evidence_ref = 'evidence/newer-proof.txt',
                        evidence_artifact_id = NULL,
                        row_version = row_version + 1
                    WHERE slug = 'VA-099'
                    """
                )
                connection.commit()
        return artifact_id

    monkeypatch.setattr(_common, "_register_artifact_reference", register_then_replace)
    updated = client.patch(
        f"{_base()}/findings/VA-099",
        json={
            "evidence_ref": "evidence/stale-proof.txt",
            "expected_row_version": initial_version,
            "source_name": "vulnerability-analyst",
        },
    )
    assert updated.status_code == 200, updated.text
    finding = updated.json()["finding"]
    assert finding["evidence_ref"] == "evidence/newer-proof.txt"
    assert finding["evidence_artifact_id"] is None
    assert finding["row_version"] == initial_version + 2


def test_no_slug_collision_against_reported_is_refused(client, isolate_settings):
    # The CLI always allocates a slug, but a raw POST can omit it — the backend
    # must still refuse the silent clobber (the CLI-bypass backstop).
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="reported")
    ).status_code == 201

    resp = client.post(
        f"{_base()}/findings", json=_finding(None, summary="rediscovered, no slug")
    )
    assert resp.status_code == 409, resp.text


def test_explicit_slug_updates_reported_finding(client, isolate_settings):
    # Naming the exact existing slug == the --update opt-in: intentional modify.
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="reported")
    ).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding("VA-001", workflow_status="reported", summary="updated replayable proof"),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding"]["slug"] == "VA-001"
    assert resp.json()["finding"]["summary"] == "updated replayable proof"


def test_genuinely_new_tuple_records_normally(client, isolate_settings):
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="reported")
    ).status_code == 201

    # Distinct root cause + location => distinct tuple => its own finding.
    resp = client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-002",
            workflow_status="active",
            defect_family="rate-limiting",
            root_cause_key="missing-login-throttle",
            canonical_location="https://app.example/api/login",
            title="No rate limit on login",
            summary="Login has no throttle",
        ),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding"]["slug"] == "VA-002"
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-001", "VA-002"}


def test_collision_against_draft_upserts_not_refused(client, isolate_settings):
    # A draft finding is not load-bearing; the historical dedup upsert still
    # applies so checkpoints accrete onto it.
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="draft")
    ).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding("VA-002", workflow_status="draft", summary="folded into VA-001"),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding"]["slug"] == "VA-001"
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-001"}


def test_false_positive_rerecord_is_not_clobber_guarded(client, isolate_settings):
    # Regression: a suppressed (false_positive) finding stays semantically
    # sticky — a rediscovery folds onto it and is NOT refused (fp is outside the
    # reported/active guard set).
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-001",
            workflow_status="false_positive",
            verification_state="verified",
            verification_disposition="false_positive",
        ),
    ).status_code == 201

    resp = client.post(
        f"{_base()}/findings", json=_finding(None, summary="rediscovered, no slug")
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding"]["slug"] == "VA-001"
    assert resp.json()["finding"]["workflow_status"] == "false_positive"


# ──────────────────────────────────────────────────────────────────────────
# D4: killed (false_positive) re-mint guard — a BROADER (technique + endpoint)
# match than the exact dedup tuple, so a source-line vs runtime rediscovery of a
# DISPROVEN finding cannot silently resurrect at a different canonical_location.
# ──────────────────────────────────────────────────────────────────────────


def _killed_ssrf(slug, **over) -> dict:
    """A finding KILLED as false_positive at a runtime SSRF endpoint (with query)."""
    return _finding(
        slug,
        workflow_status="false_positive",
        verification_state="verified",
        verification_disposition="false_positive",
        defect_family="ssrf",
        root_cause_key="unvalidated-fetch",
        canonical_location="https://app.example/api/fetch?url=http://169.254.169.254",
        title="SSRF via fetch url param",
        summary="killed: egress firewalled, metadata unreachable",
        **over,
    )


def test_d4_remint_of_killed_at_shared_endpoint_is_refused(client, isolate_settings):
    # (a) A net-new record sharing the SAME technique + normalized endpoint with a
    # killed finding, but a DIFFERENT canonical_location/root_cause_key/title (so it
    # misses the exact dedup tuple), is refused with an actionable message.
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_killed_ssrf("VA-050")).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-051",
            workflow_status="active",
            defect_family="ssrf",
            root_cause_key="ssrf-source-line",
            canonical_location="https://app.example/api/fetch",  # same endpoint, no query
            title="SSRF reachable at fetch endpoint",
            summary="rediscovered from source analysis",
        ),
    )
    assert resp.status_code == 409, resp.text
    detail = resp.json()["detail"]
    assert "Refusing to re-mint" in detail
    assert "VA-050" in detail
    assert "reset-finding VA-050" in detail
    assert "--allow-remint" in detail
    # The killed finding is untouched and the re-mint was NOT created.
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-050"}


def test_d4_remint_allowed_with_override_flag(client, isolate_settings):
    # (b) --allow-remint / allow_remint=true forces an intentional distinct re-mint.
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_killed_ssrf("VA-050")).status_code == 201

    payload = _finding(
        "VA-051",
        workflow_status="active",
        defect_family="ssrf",
        root_cause_key="ssrf-source-line",
        canonical_location="https://app.example/api/fetch",
        title="SSRF reachable at fetch endpoint",
    )
    payload["allow_remint"] = True
    resp = client.post(f"{_base()}/findings", json=payload)
    assert resp.status_code == 201, resp.text
    assert resp.json()["finding"]["slug"] == "VA-051"
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-050", "VA-051"}


def test_d4_different_class_at_same_endpoint_is_not_refused(client, isolate_settings):
    # (c) Same endpoint, GENUINELY different vuln class (defect_family) => the
    # technique gate misses => not refused. A shared endpoint alone is not enough.
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_killed_ssrf("VA-050")).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-051",
            workflow_status="active",
            defect_family="reflected-xss",
            root_cause_key="unescaped-echo",
            canonical_location="https://app.example/api/fetch",
            title="Reflected XSS in fetch response",
        ),
    )
    assert resp.status_code == 201, resp.text
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-050", "VA-051"}


def test_d4_same_technique_different_endpoint_is_not_refused(client, isolate_settings):
    # Boundary: same technique but a genuinely different endpoint => no shared
    # signal => allowed (the guard is technique AND endpoint, not technique alone).
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_killed_ssrf("VA-050")).status_code == 201

    resp = client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-051",
            workflow_status="active",
            defect_family="ssrf",
            root_cause_key="ssrf-proxy",
            canonical_location="https://app.example/api/proxy",
            title="SSRF at proxy endpoint",
        ),
    )
    assert resp.status_code == 201, resp.text
    assert {r["slug"] for r in client.get(f"{_base()}/findings").json()} == {"VA-050", "VA-051"}


def test_d4_active_reported_clobber_guard_unchanged(client, isolate_settings):
    # (d) The D4 killed-guard is additive: the reported/active clobber guard on the
    # EXACT tuple still fires (and D4 does not double-refuse or change its message).
    _seed(client, isolate_settings)
    assert client.post(
        f"{_base()}/findings", json=_finding("VA-001", workflow_status="reported")
    ).status_code == 201
    resp = client.post(
        f"{_base()}/findings",
        json=_finding("VA-002", workflow_status="active", summary="rediscovered"),
    )
    assert resp.status_code == 409, resp.text
    assert "Refusing to clobber" in resp.json()["detail"]


def test_d4_reset_finding_reopens_killed(client, isolate_settings):
    # (e) reset-finding (PATCH reopen) still works on a killed finding, and after
    # reopening it is no longer false_positive so the D4 guard no longer keys on it.
    _seed(client, isolate_settings)
    assert client.post(f"{_base()}/findings", json=_killed_ssrf("VA-050")).status_code == 201

    resp = client.patch(
        f"{_base()}/findings/VA-050",
        json={"workflow_status": "draft", "reason_text": "retest disproved the kill"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["finding"]["workflow_status"] == "draft"

    # With VA-050 reopened (no longer false_positive), a fresh record at the same
    # endpoint + technique is not blocked by the killed-remint guard.
    resp2 = client.post(
        f"{_base()}/findings",
        json=_finding(
            "VA-051",
            workflow_status="active",
            defect_family="ssrf",
            root_cause_key="ssrf-source-line",
            canonical_location="https://app.example/api/fetch",
            title="SSRF reachable at fetch endpoint",
        ),
    )
    assert resp2.status_code == 201, resp2.text


# ──────────────────────────────────────────────────────────────────────────
# CLI boundary enforcement (record_finding.py)
# ──────────────────────────────────────────────────────────────────────────


def _record_finding():
    return importlib.import_module("assess.commands.record_finding")


def _existing(slug, **over) -> dict:
    row = {
        "slug": slug,
        "workflow_status": "reported",
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "auth_context": "anonymous",
        "canonical_location": "https://app.example/api/users",
    }
    row.update(over)
    return row


def _tuple_kwargs(candidate_slug="VA-002", **over) -> dict:
    kwargs = {
        "candidate_slug": candidate_slug,
        "defect_family": "access-control",
        "root_cause_key": "missing-object-authz",
        "auth_context": "anonymous",
        "canonical_location": "https://app.example/api/users",
    }
    kwargs.update(over)
    return kwargs


def test_cli_find_clobbered_detects_reported_tuple_collision():
    rf = _record_finding()
    hit = rf._find_clobbered_finding([_existing("VA-001")], **_tuple_kwargs())
    assert hit is not None and hit["slug"] == "VA-001"


def test_cli_find_clobbered_detects_active_tuple_collision():
    rf = _record_finding()
    hit = rf._find_clobbered_finding(
        [_existing("VA-001", workflow_status="active")], **_tuple_kwargs()
    )
    assert hit is not None and hit["slug"] == "VA-001"


def test_cli_find_clobbered_skips_draft_and_non_collisions():
    rf = _record_finding()
    # draft target is fair game for the historical upsert.
    assert rf._find_clobbered_finding(
        [_existing("VA-001", workflow_status="draft")], **_tuple_kwargs()
    ) is None
    # false_positive target stays semantically sticky, not a clobber.
    assert rf._find_clobbered_finding(
        [_existing("VA-001", workflow_status="false_positive")], **_tuple_kwargs()
    ) is None
    # Different canonical_location => no tuple collision.
    assert rf._find_clobbered_finding(
        [_existing("VA-001", canonical_location="https://app.example/api/orders")],
        **_tuple_kwargs(),
    ) is None
    # The candidate IS this slug (an explicit --update naming the row).
    assert rf._find_clobbered_finding(
        [_existing("VA-001")], **_tuple_kwargs(candidate_slug="VA-001")
    ) is None


def test_cli_find_clobbered_skips_when_root_cause_key_empty():
    # An empty root_cause_key cannot collide on the dedup tuple; the backend's
    # title-fallback tier remains the authoritative backstop.
    rf = _record_finding()
    assert rf._find_clobbered_finding(
        [_existing("VA-001", root_cause_key="")], **_tuple_kwargs(root_cause_key="")
    ) is None


def test_cli_register_adds_update_flag():
    rf = _record_finding()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    rf.register(sub)
    args = parser.parse_args(
        ["record-finding", "vulnerability-analyst", "finding.json", "--update", "VA-001"]
    )
    assert args.update_slug == "VA-001"
    # Optional: defaults to no update target.
    args_default = parser.parse_args(["record-finding", "vulnerability-analyst", "finding.json"])
    assert getattr(args_default, "update_slug", None) in (None, "")


def test_contract_documents_update_flag():
    from assess.lib import contracts

    text = contracts.render_contract("record-finding")
    assert "--update" in text


def _run_record_finding_with_flags(monkeypatch, tmp_path, *, allow_remint: bool) -> dict:
    """Drive record_finding.run against a stubbed client and return the POSTed body."""
    import contextlib
    import types

    rf = _record_finding()
    posted: dict = {}

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def __enter__(self) -> "FakeClient":
            return self

        def __exit__(self, *exc) -> bool:
            return False

        def close(self) -> None:
            pass

        def get(self, endpoint):
            return []  # no existing findings => no clobber

        def post(self, endpoint, payload):
            posted["endpoint"] = endpoint
            posted["payload"] = payload
            return {"finding": {"slug": payload.get("slug", "VA-100"), "title": "t"}}

        def post_event(self, body):
            posted["event"] = body

    cfg = types.SimpleNamespace(base_url="http://x", engagement_key="k", engagement_dir=str(tmp_path))
    monkeypatch.setattr(rf, "load_config", lambda *a, **k: cfg)
    monkeypatch.setattr(rf, "AssessmentClient", lambda *a, **k: FakeClient())
    monkeypatch.setattr(rf, "collect_validation_errors", lambda *a, **k: [])
    monkeypatch.setattr(rf, "file_lock", lambda *a, **k: contextlib.nullcontext())
    monkeypatch.setattr(rf, "finding_lock_path", lambda *a, **k: str(tmp_path / "lock"))

    finding_json = tmp_path / "finding.json"
    finding_json.write_text(
        json.dumps(
            {
                "slug": "VA-100",
                "title": "SSRF via fetch",
                "defect_family": "ssrf",
                "canonical_location": "https://app.example/api/fetch",
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        engagement_dir=str(tmp_path),
        agent_name="vulnerability-analyst",
        json_file=str(finding_json),
        allow_unindexed_evidence=True,
        update_slug="",
        allow_remint=allow_remint,
    )
    rf.run(args)
    return posted


def test_cli_allow_remint_injects_flag_into_post(monkeypatch, tmp_path):
    posted = _run_record_finding_with_flags(monkeypatch, tmp_path, allow_remint=True)
    assert posted["endpoint"] == "findings"
    assert posted["payload"].get("allow_remint") is True


def test_cli_allow_remint_absent_by_default(monkeypatch, tmp_path):
    posted = _run_record_finding_with_flags(monkeypatch, tmp_path, allow_remint=False)
    assert "allow_remint" not in posted["payload"]


def test_cli_register_adds_allow_remint_flag():
    rf = _record_finding()
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    rf.register(sub)
    for flag in ("--allow-remint", "--force"):
        args = parser.parse_args(["record-finding", "vulnerability-analyst", "finding.json", flag])
        assert args.allow_remint is True
    args_default = parser.parse_args(["record-finding", "vulnerability-analyst", "finding.json"])
    assert args_default.allow_remint is False
