from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from itertools import count
from pathlib import Path

import pytest

from app import db as db_module
from app.services import engagements as engagement_service
from app.services import events as events_service
from tests.proof_fixtures import completed_confirm_check, post_artifact_backed_source_observation


def legacy_finding_slug(suffix: str = "VA-001") -> str:
    return f"{'FINDING'}-{suffix}"


_proof_run_counter = count(1)


def _author_provenance(
    client, slug: str, *, key: str = "2026-03-30-120000-example"
) -> dict[str, str]:
    agent_id = f"FIXTURE-AUTHOR-{slug}"
    base = f"/engagements/{key}/assessment/dispatches"
    existing = client.get(f"{base}/{agent_id}")
    if existing.status_code == 404:
        response = client.post(
            base,
            json={
                "agent_id": agent_id,
                "agent_role": "fixture-finding-author",
                "task": f"Record {slug} for the API fixture.",
            },
        )
        assert response.status_code == 201, response.text
    else:
        assert existing.status_code == 200, existing.text
    return {"agent_id": agent_id}


def _proof_receipt(client, slug: str, *, key: str = "2026-03-30-120000-example") -> int:
    sequence = next(_proof_run_counter)
    agent_id = f"FIXTURE-VERIFY-{slug}-{sequence}"
    base = f"/engagements/{key}/assessment"
    dispatch = client.post(
        f"{base}/dispatches",
        json={
            "agent_id": agent_id,
            "agent_role": "fixture-independent-verifier",
            "task": f"Independently verify {slug} for the API fixture.",
        },
    )
    assert dispatch.status_code == 201, dispatch.text
    run = client.post(
        f"{base}/assessment-runs",
        json={
            "run_uuid": f"engagements-api-{slug}-{sequence}",
            "run_kind": "shared",
            "producer_dispatch_agent_id": agent_id,
        },
    )
    assert run.status_code == 201, run.text
    finding = client.get(f"{base}/findings/{slug}")
    if finding.status_code == 200:
        linked = client.post(
            f"{base}/findings/{slug}/links",
            json={
                "link_kind": "proof_run", "target_kind": "assessment_run",
                "target_id": run.json()["id"],
            },
        )
        assert linked.status_code == 200, linked.text
    receipt = post_artifact_backed_source_observation(
        client,
        f"{base}/proof-receipts",
        json={
            "run_id": run.json()["id"],
            "evidence_kind": "source_observation",
            "expected_result": "the finding claim survives an independent counter-check",
            "observed_result": "the independent review reproduced the recorded result",
        },
    )
    assert receipt.status_code == 201, receipt.text
    completed = client.patch(
        f"{base}/assessment-runs/{run.json()['id']}",
        json={"status": "completed"},
    )
    assert completed.status_code == 200, completed.text
    return int(receipt.json()["id"])


def _verify_with_fixture_proof(
    client,
    slug: str,
    payload: dict,
    *,
    key: str = "2026-03-30-120000-example",
):
    receipt_id = _proof_receipt(client, slug, key=key)
    request = {**payload, "proof_receipt_ids": [receipt_id]}
    if request["verification_status"] in {"confirmed", "downgraded"}:
        request["confirm_check"] = completed_confirm_check(receipt_id)
    if request["verification_status"] == "false_positive":
        request["counter_check"] = {
            "method": "independent source-path counter-check",
            "expected_result": "the claimed vulnerable path remains reachable",
            "observed_result": "the counter-check falsified the recorded claim",
            "falsified_claim": "the recorded vulnerable path is reachable",
            "completed": True,
            "proof_receipt_ids": [receipt_id],
        }
    return client.post(
        f"/engagements/{key}/assessment/findings/{slug}/verify",
        json=request,
    )


def _record_terminal_finding(client, payload: dict):
    slug = str(payload["slug"])
    terminal_status = str(payload["verification_status"])
    author_agent_id = f"FIXTURE-AUTHOR-{slug}-{next(_proof_run_counter)}"
    author = client.post(
        "/engagements/2026-03-30-120000-example/assessment/dispatches",
        json={
            "agent_id": author_agent_id,
            "agent_role": "fixture-finding-author",
            "task": f"Record {slug} for the API fixture.",
        },
    )
    assert author.status_code == 201, author.text
    create_payload = {
        **payload,
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "provenance": {
            **dict(payload.get("provenance") or {}),
            "agent_id": author_agent_id,
        },
    }
    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json=create_payload,
    )
    assert created.status_code == 201, created.text
    return _verify_with_fixture_proof(
        client,
        slug,
        {
            "verification_status": terminal_status,
            "reason_code": "fixture-independent-review",
            "reason_text": "Independent fixture review completed.",
            "source_name": "fixture-independent-verifier",
        },
    )


def write_engagement(engagements_dir: Path, key: str = "2026-03-30-120000-example") -> Path:
    engagement_dir = engagements_dir / key
    (engagement_dir / "sessions" / "session-a" / "proposals").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": key,
                "target": "https://example.com",
                "hostname": "example.com",
                "created_at": "2026-03-30T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "out_of_scope": [],
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_targets": ["VA-001"],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "log.md").write_text("# Engagement Log\n", encoding="utf-8")
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_targets": ["VA-001"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return engagement_dir


def test_list_engagements_discovers_filesystem_engagements(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["key"] == "2026-03-30-120000-example"
    assert payload[0]["current_phase"] == "exploit"
    assert payload[0]["session_count"] == 1


def test_both_engagement_exposes_independent_code_phase(client, isolate_settings):
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"],
        key="2026-08-04-120000-both",
    )
    scope_path = engagement_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope.update(
        {
            "engagement_type": "both",
            "current_phase": "hunt",
            "code_phase": "verify-variant",
            "status": "completed",
        }
    )
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    listed = client.get("/engagements")
    fetched = client.get("/engagements/2026-08-04-120000-both")

    assert listed.status_code == 200
    assert fetched.status_code == 200
    list_row = next(
        row for row in listed.json() if row["key"] == "2026-08-04-120000-both"
    )
    assert list_row["current_phase"] == "hunt"
    assert list_row["code_phase"] == "verify-variant"
    assert fetched.json()["code_phase"] == "verify-variant"
    assert fetched.json()["track_state"] == {
        "web": {"phase": "hunt", "complete": False},
        "code": {"phase": "verify-variant", "complete": False},
    }
    assert fetched.json()["aggregate_complete"] is False


def test_legacy_both_missing_code_phase_requires_repair_before_completion(client, isolate_settings):
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"], key="2026-09-29-120000-both-unrepaired"
    )
    scope_path = engagement_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope.update({"engagement_type": "both", "current_phase": "complete", "status": "completed"})
    scope.pop("code_phase", None)
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    response = client.get("/engagements/2026-09-29-120000-both-unrepaired")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "in_progress"
    assert body["aggregate_complete"] is False
    assert body["track_state"]["code"] == {
        "phase": "repair-required", "complete": False, "repair_required": True,
    }


def test_offensive_tracks_expose_independent_phases_without_both_type(
    client, isolate_settings
):
    """The durable track map, rather than a combined type label, owns phases."""
    engagement_dir = write_engagement(
        isolate_settings["engagements_dir"],
        key="2026-09-29-120000-offensive-tracks",
    )
    scope_path = engagement_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope.update(
        {
            "engagement_type": "offensive",
            "tracks": {
                "web": {"phase": "verify"},
                "code": {"phase": "hunt"},
            },
            "status": "in_progress",
        }
    )
    scope.pop("code_phase", None)
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    response = client.get("/engagements/2026-09-29-120000-offensive-tracks")

    assert response.status_code == 200
    assert response.json()["track_state"] == {
        "web": {"phase": "verify", "complete": False},
        "code": {"phase": "hunt", "complete": False},
    }
    assert response.json()["current_phase"] == "verify"
    assert response.json()["code_phase"] == "hunt"
    assert response.json()["status"] == "in_progress"


def test_list_engagements_surfaces_scope_hosts_for_proxy_router(client, isolate_settings):
    """The multi-engagement mitmproxy router fetches the active engagement set
    from this endpoint; scope_hosts must be present so the addon can route
    captured flows without a second round-trip to read scope.json.
    """
    engagements_dir = isolate_settings["engagements_dir"]
    engagement_dir = engagements_dir / "2026-04-01-100000-multi"
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": "2026-04-01-100000-multi",
                "target": "https://multi.example",
                "created_at": "2026-04-01T10:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "multi.example",
                "hosts": ["multi.example", "*.multi.example"],
                "scope": ["legacy.multi.example"],
                "status": "in_progress",
                "current_phase": "recon",
                "scope_priority": 5,
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    response = client.get("/engagements")
    assert response.status_code == 200
    row = next(item for item in response.json() if item["key"] == "2026-04-01-100000-multi")
    assert row["scope_hosts"] == ["multi.example", "*.multi.example", "legacy.multi.example"]
    assert row["scope_priority"] == 5


def test_list_engagements_surfaces_out_of_scope_for_proxy_router(client, isolate_settings):
    """The proxy router's PREFERRED registry source is this backend endpoint
    (filesystem scan is only a fallback), so the ``out_of_scope`` denylist must
    be serialized here — otherwise carve-outs are silently unenforced whenever
    the orchestrator is up. Deduped + lowercased, mirroring ``scope_hosts``.
    """
    engagements_dir = isolate_settings["engagements_dir"]
    engagement_dir = engagements_dir / "2026-04-01-110000-oos"
    (engagement_dir / "sessions").mkdir(parents=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": "2026-04-01-110000-oos",
                "target": "https://target.example",
                "created_at": "2026-04-01T11:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "target.example",
                "hosts": ["*.target.example"],
                "out_of_scope": ["Appointments.example.com", "*.mobile.example.com", "appointments.example.com"],
                "status": "in_progress",
                "current_phase": "recon",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    response = client.get("/engagements")
    assert response.status_code == 200
    row = next(item for item in response.json() if item["key"] == "2026-04-01-110000-oos")
    # Lowercased + deduped, order-preserving.
    assert row["out_of_scope"] == ["appointments.example.com", "*.mobile.example.com"]


def test_list_engagements_filters_by_status(client, isolate_settings):
    """The proxy registry asks for ?status=in_progress so completed engagements
    don't keep claiming traffic. The filter must apply to the same payload
    shape as the unfiltered list.
    """
    engagements_dir = isolate_settings["engagements_dir"]
    active_dir = engagements_dir / "2026-04-02-100000-active"
    completed_dir = engagements_dir / "2026-04-02-100100-completed"
    for path, status in ((active_dir, "in_progress"), (completed_dir, "completed")):
        (path / "sessions").mkdir(parents=True)
        (path / "engagement.json").write_text(
            json.dumps(
                {
                    "key": path.name,
                    "target": f"https://{path.name}.example",
                    "created_at": "2026-04-02T10:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (path / "scope.json").write_text(
            json.dumps(
                {
                    "hostname": f"{path.name}.example",
                    "hosts": [f"{path.name}.example"],
                    "status": status,
                }
            ),
            encoding="utf-8",
        )
        (path / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    all_keys = {row["key"] for row in client.get("/engagements").json()}
    assert active_dir.name in all_keys
    assert completed_dir.name in all_keys

    active_only = {row["key"] for row in client.get("/engagements?status=in_progress").json()}
    assert active_dir.name in active_only
    assert completed_dir.name not in active_only


def test_list_engagements_uses_single_db_connection_after_sync(client, isolate_settings, monkeypatch):
    """The proxy polls `/engagements?status=in_progress`; avoid an N+1 SQLite
    connection fan-out that forces each request to repeatedly parse the schema.
    """
    engagements_dir = isolate_settings["engagements_dir"]
    for index in range(4):
        write_engagement(engagements_dir, key=f"2026-04-02-100{index}00-active")

    assert client.get("/engagements?status=in_progress").status_code == 200

    original_get_connection = db_module.get_connection
    open_count = 0

    @contextmanager
    def counted_connection():
        nonlocal open_count
        open_count += 1
        with original_get_connection() as connection:
            yield connection

    monkeypatch.setattr(db_module, "get_connection", counted_connection)
    engagement_service.clear_list_engagements_cache()

    response = client.get("/engagements?status=in_progress")

    assert response.status_code == 200
    assert len(response.json()) == 4
    assert open_count == 1


def test_list_engagements_cache_hit_skips_signature_scan(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements?status=in_progress")
    assert response.status_code == 200
    assert len(response.json()) == 1

    def fail_signature_scan():
        raise AssertionError("cached registry poll should not stat engagement files")

    monkeypatch.setattr(engagement_service, "_engagements_signature", fail_signature_scan)

    cached_response = client.get("/engagements?status=in_progress")
    assert cached_response.status_code == 200
    assert len(cached_response.json()) == 1


def test_tombstoned_engagement_is_hidden_from_active_registry(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements?status=in_progress")
    assert response.status_code == 200
    assert [row["key"] for row in response.json()] == ["2026-03-30-120000-example"]

    engagement = db_module.get_engagement_by_key("2026-03-30-120000-example")
    assert engagement is not None
    engagement_service.mark_engagement_deleted(engagement)

    response = client.get("/engagements?status=in_progress")
    assert response.status_code == 200
    assert response.json() == []


def test_list_engagements_surfaces_and_filters_blue_customer_platform(client, isolate_settings):
    engagements_dir = isolate_settings["engagements_dir"]
    blue_dir = engagements_dir / "2026-05-20-120000-acme-gws"
    other_dir = engagements_dir / "2026-05-20-121000-other-example-aws"
    for path, customer, platforms in (
        (blue_dir, "acme", ["gws", "m365"]),
        (other_dir, "other-example", ["aws"]),
    ):
        (path / "sessions").mkdir(parents=True)
        (path / "engagement.json").write_text(
            json.dumps(
                {
                    "key": path.name,
                    "target": f"{customer}:{','.join(platforms)}",
                    "created_at": "2026-05-20T12:00:00Z",
                }
            ),
            encoding="utf-8",
        )
        (path / "scope.json").write_text(
            json.dumps(
                {
                    "engagement_type": "blue",
                    "customer": customer,
                    "platforms": platforms,
                    "tenant_reference_paths": [
                        f"agent/references/tenants/{customer}-{platforms[0]}.md"
                    ],
                    "status": "in_progress",
                    "current_phase": "intake",
                }
            ),
            encoding="utf-8",
        )
        (path / "sessions" / "index.json").write_text("[]", encoding="utf-8")

    rows = client.get("/engagements?engagement_type=blue&customer=acme").json()
    assert [row["key"] for row in rows] == [blue_dir.name]
    assert rows[0]["customer"] == "acme"
    assert rows[0]["platforms"] == ["gws", "m365"]
    assert rows[0]["tenant_reference_paths"] == ["agent/references/tenants/acme-gws.md"]

    platform_rows = client.get("/engagements?engagement_type=blue&platform=m365").json()
    assert [row["key"] for row in platform_rows] == [blue_dir.name]


def test_maybe_sync_engagements_skips_repeated_resync_without_filesystem_changes(isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])
    db_module.init_db()

    monkeypatch.setattr(engagement_service, "_last_sync_signature", None)
    call_count = 0
    original_sync = engagement_service.sync_engagements

    def counted_sync() -> None:
        nonlocal call_count
        call_count += 1
        original_sync()

    monkeypatch.setattr(engagement_service, "sync_engagements", counted_sync)

    engagement_service.maybe_sync_engagements()
    engagement_service.maybe_sync_engagements()

    assert call_count == 1

    write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120500-example")
    monkeypatch.setattr(engagement_service, "_last_sync_checked_at", 0.0)
    engagement_service.maybe_sync_engagements()

    assert call_count == 2


def test_maybe_sync_engagements_resyncs_when_assignment_json_changes(isolate_settings, monkeypatch):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    session_dir = engagement_dir / "sessions" / "session-a"
    assignment_path = session_dir / "assignment.json"
    assignment_path.write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_targets": ["VA-001"],
            }
        ),
        encoding="utf-8",
    )
    db_module.init_db()

    monkeypatch.setattr(engagement_service, "_last_sync_signature", None)
    call_count = 0
    original_sync = engagement_service.sync_engagements

    def counted_sync() -> None:
        nonlocal call_count
        call_count += 1
        original_sync()

    monkeypatch.setattr(engagement_service, "sync_engagements", counted_sync)

    engagement_service.maybe_sync_engagements()
    engagement_service.maybe_sync_engagements()

    assert call_count == 1

    assignment_path.write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_targets": ["VA-001", "VA-002"],
            }
        ),
        encoding="utf-8",
    )
    stat = assignment_path.stat()
    os.utime(assignment_path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000))

    monkeypatch.setattr(engagement_service, "_last_sync_checked_at", 0.0)
    engagement_service.maybe_sync_engagements()

    assert call_count == 2


def test_get_connection_requires_startup_initialized_database(isolate_settings, monkeypatch):
    monkeypatch.setattr(db_module, "_startup_database_fingerprint", None)

    with pytest.raises(RuntimeError, match="has not been initialized"):
        with db_module.get_connection():
            pass


def test_get_connection_rejects_database_file_replacement(isolate_settings, monkeypatch):
    db_module.init_db()
    original_path = db_module.database_path()
    fingerprint = db_module._startup_database_fingerprint
    assert fingerprint is not None

    replacement_path = isolate_settings["data_dir"] / "replacement.sqlite3"
    with sqlite3.connect(str(replacement_path)) as connection:
        connection.execute("CREATE TABLE replacement_marker (id INTEGER PRIMARY KEY)")

    original_path.unlink()
    replacement_path.replace(original_path)

    with pytest.raises(RuntimeError, match="database file changed after startup"):
        with db_module.get_connection():
            pass


def test_init_db_renames_legacy_assigned_findings_column(isolate_settings):
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute(
            """
            CREATE TABLE engagement_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                session_id TEXT NOT NULL,
                session_path TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                merge_state TEXT NOT NULL DEFAULT 'pending',
                assigned_findings_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                merged_at TEXT
            )
            """
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(engagement_sessions)").fetchall()}

    assert "assigned_targets_json" in columns
    assert "assigned_findings_json" not in columns


def test_init_db_migrates_legacy_finding_slug_references(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug()

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        finding_id = connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, ?, 'Legacy slug')
            """,
            (engagement_id, legacy),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO engagement_sessions (engagement_id, session_id, session_path, assigned_targets_json)
            VALUES (?, 'session-a', '/tmp/eng/sessions/session-a', ?)
            """,
            (engagement_id, json.dumps([legacy])),
        )
        connection.execute(
            """
            INSERT INTO assessment_finding_links (engagement_id, finding_id, link_kind, target_kind, target_ref)
            VALUES (?, ?, 'variant_of', 'finding', ?)
            """,
            (engagement_id, finding_id, legacy),
        )
        connection.execute(
            """
            INSERT INTO assessment_attack_chains (engagement_id, chain_key, title)
            VALUES (?, 'chain-a', 'Chain A')
            """,
            (engagement_id,),
        )
        chain_id = connection.execute("SELECT id FROM assessment_attack_chains WHERE chain_key = 'chain-a'").fetchone()[0]
        connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (engagement_id, chain_id, relation, entity_kind, entity_ref)
            VALUES (?, ?, 'step', 'finding', ?)
            """,
            (engagement_id, chain_id, legacy),
        )
        connection.execute(
            """
            INSERT INTO code_analysis_results (engagement_id, file_id, finding_slug)
            VALUES (?, 1, ?)
            """,
            (engagement_id, legacy),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        assert connection.execute("SELECT slug FROM assessment_findings").fetchone()[0] == "VA-001"
        assert json.loads(connection.execute("SELECT assigned_targets_json FROM engagement_sessions").fetchone()[0]) == ["VA-001"]
        assert connection.execute("SELECT target_ref FROM assessment_finding_links").fetchone()[0] == "VA-001"
        assert connection.execute("SELECT entity_ref FROM assessment_attack_chain_links").fetchone()[0] == "VA-001"
        assert connection.execute("SELECT finding_slug FROM code_analysis_results").fetchone()[0] == "VA-001"


def test_init_db_migrates_legacy_finding_slug_collision_without_startup_crash(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug()

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        legacy_id = connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, ?, 'Legacy slug')
            """,
            (engagement_id, legacy),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_findings (engagement_id, slug, title)
            VALUES (?, 'VA-001', 'Already migrated slug')
            """,
            (engagement_id,),
        )
        connection.execute(
            """
            INSERT INTO code_analysis_results (engagement_id, file_id, finding_slug)
            VALUES (?, 1, ?)
            """,
            (engagement_id, legacy),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        rows = connection.execute(
            "SELECT id, slug FROM assessment_findings ORDER BY id ASC"
        ).fetchall()
        migrated_legacy_slug = rows[0][1]
        assert migrated_legacy_slug.startswith("VA-001-legacy-")
        assert rows[1][1] == "VA-001"
        assert legacy not in {row[1] for row in rows}
        assert connection.execute(
            "SELECT finding_slug FROM code_analysis_results WHERE engagement_id = ?",
            (engagement_id,),
        ).fetchone()[0] == migrated_legacy_slug
        assert str(legacy_id) in migrated_legacy_slug


def test_init_db_migrates_legacy_finding_slugs_in_finding_json(isolate_settings):
    db_module.init_db()
    db_path = db_module.database_path()
    legacy = legacy_finding_slug("CH-001")

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            """
            INSERT INTO engagements (key, target, status, engagement_root)
            VALUES ('eng', 'https://example.com', 'in_progress', '/tmp/eng')
            """
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, details_json, provenance_json
            )
            VALUES (?, 'CV-001', 'Variant slug', ?, ?)
            """,
            (
                engagement_id,
                json.dumps({"variant_of": legacy, "related": [legacy]}),
                json.dumps(
                    {
                        "source_slug": legacy,
                        "review": {"target_slug": legacy},
                        "evidence": f"Same root cause as {legacy}.",
                    }
                ),
            ),
        )
        connection.commit()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        details_json, provenance_json = connection.execute(
            "SELECT details_json, provenance_json FROM assessment_findings"
        ).fetchone()
    assert json.loads(details_json) == {"variant_of": "CH-001", "related": ["CH-001"]}
    assert json.loads(provenance_json) == {
        "source_slug": "CH-001",
        "review": {"target_slug": "CH-001"},
        "evidence": "Same root cause as CH-001.",
    }


def test_engagement_artifacts_and_sessions_are_scoped_by_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    artifacts = client.get("/engagements/2026-03-30-120000-example/artifacts")
    assert artifacts.status_code == 200
    artifact_names = {artifact["name"] for artifact in artifacts.json() if artifact["exists"]}
    assert {"scope.json", "engagement.json"} <= artifact_names

    sessions = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert sessions.status_code == 200
    payload = sessions.json()
    assert payload[0]["session_id"] == "session-a"
    assert payload[0]["assigned_targets"] == ["VA-001"]


def test_engagement_sync_migrates_legacy_target_keys_on_disk(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    legacy = legacy_finding_slug()
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "example.com",
                "scope_mode": "host_only",
                "scope_hosts": ["example.com"],
                "scope": ["example.com"],
                "out_of_scope": [],
                "exploit_policy": "selected",
                "exploit_review_state": "approved",
                "approved_findings": [legacy],
                "status": "in_progress",
                "current_phase": "exploit",
            }
        ),
        encoding="utf-8",
    )
    session_dir = engagement_dir / "sessions" / "session-a"
    (engagement_dir / "sessions" / "index.json").write_text(
        json.dumps(
            [
                {
                    "session_id": "session-a",
                    "status": "active",
                    "merge_state": "pending",
                    "assigned_findings": [legacy],
                }
            ]
        ),
        encoding="utf-8",
    )
    (session_dir / "assignment.json").write_text(
        json.dumps(
            {
                "session_id": "session-a",
                "status": "active",
                "assigned_findings": [legacy],
            }
        ),
        encoding="utf-8",
    )

    first = client.get("/engagements")
    second = client.get("/engagements")

    assert first.status_code == 200
    assert second.status_code == 200
    scope_payload = json.loads((engagement_dir / "scope.json").read_text(encoding="utf-8"))
    index_payload = json.loads((engagement_dir / "sessions" / "index.json").read_text(encoding="utf-8"))
    assignment_payload = json.loads((session_dir / "assignment.json").read_text(encoding="utf-8"))
    assert scope_payload["approved_targets"] == ["VA-001"]
    assert "approved_findings" not in scope_payload
    assert index_payload[0]["assigned_targets"] == ["VA-001"]
    assert "assigned_findings" not in index_payload[0]
    assert assignment_payload["assigned_targets"] == ["VA-001"]
    assert "assigned_findings" not in assignment_payload


def test_engagement_sync_skips_invalid_engagement_json_without_aborting(client, isolate_settings, caplog):
    write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120000-valid")
    broken_dir = write_engagement(isolate_settings["engagements_dir"], key="2026-03-30-120500-broken")
    (broken_dir / "scope.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        response = client.get("/engagements")

    assert response.status_code == 200
    payload = response.json()
    assert [item["key"] for item in payload] == ["2026-03-30-120000-valid"]
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)


def test_invalid_session_artifacts_preserve_existing_engagement_state(client, isolate_settings, caplog):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    first = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert first.status_code == 200
    assert len(first.json()) == 1

    (engagement_dir / "sessions" / "index.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        sessions_response = client.get("/engagements/2026-03-30-120000-example/sessions")
        engagements_response = client.get("/engagements")

    assert sessions_response.status_code == 200
    assert len(sessions_response.json()) == 1
    assert engagements_response.status_code == 200
    assert [item["key"] for item in engagements_response.json()] == ["2026-03-30-120000-example"]
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)


def test_invalid_scope_preserves_existing_engagement_state(client, isolate_settings, caplog):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    first = client.get("/engagements")
    assert first.status_code == 200
    assert len(first.json()) == 1

    (engagement_dir / "scope.json").write_text("{not valid json", encoding="utf-8")

    with caplog.at_level("WARNING"):
        response = client.get("/engagements")

    assert response.status_code == 200
    payload = response.json()
    assert [item["key"] for item in payload] == ["2026-03-30-120000-example"]
    assert payload[0]["current_phase"] == "unknown"
    assert payload[0]["approved_targets"] == []
    assert any("Skipping invalid engagement artifacts" in message for message in caplog.messages)
    assert any("Using persisted engagement identity" in message for message in caplog.messages)


def test_engagement_event_and_assessment_routes_use_engagement_key(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_event = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "task.started",
            "phase": "exploit",
            "task_name": "exploit-developer",
            "agent_name": "exploit-developer",
            "summary": "Exploit task started",
        },
    )
    assert create_event.status_code == 201

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example.com/orders/7",
            "source_name": "source-analyzer",
            "rationale": "Observed direct object path",
            "evidence_ref": "activity_entries",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    invalid_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "web_application",
            "target_descriptor": "https://example.com/",
            "source_name": "source-analyzer",
            "status": "covered",
        },
    )
    assert invalid_surface.status_code == 422

    create_finding = _record_terminal_finding(
        client,
        {
            "slug": "VA-001",
            "title": "IDOR in orders",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Confirmed with adjacent object ids.",
            "source_name": "exploit-developer",
            "details": {
                "evidence": "GET /orders/7 returns order for user B when authenticated as user A",
                "impact": "cross-tenant access",
                "owasp_category": "A01:2021 Broken Access Control",
                "cwe_id": "CWE-639",
                "request_method": "GET",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                "cvss_score": 7.1,
                "remediation": "Enforce server-side ownership checks on order retrieval",
                "steps_to_reproduce": [
                    "Authenticate as user A",
                    "GET /orders/7 (belongs to user B)",
                    "Observe full order data returned"
                ]
            },
            "provenance": {"agent_name": "exploit-developer"},
            "links": [],
        },
    )
    assert create_finding.status_code == 200
    assert create_finding.json()["finding"]["slug"] == "VA-001"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    assert findings.json()[0]["slug"] == "VA-001"

    finding_detail = client.get("/engagements/2026-03-30-120000-example/assessment/findings/VA-001")
    assert finding_detail.status_code == 200
    assert finding_detail.json()["slug"] == "VA-001"
    assert finding_detail.json()["details"]["cwe_id"] == "CWE-639"

    missing_finding = client.get("/engagements/2026-03-30-120000-example/assessment/findings/VA-404")
    assert missing_finding.status_code == 404
    assert missing_finding.json()["detail"].startswith("finding not found: VA-404")

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 1
    # finding_severities mirrors finding_count's WHERE clause, so the single
    # live high finding is the entire rollup and it sums to finding_count.
    assert summary.json()["finding_severities"] == {"high": 1}
    assert sum(summary.json()["finding_severities"].values()) == summary.json()["finding_count"]
    assert summary.json()["exploit_candidate_count"] == 1
    assert summary.json()["coverage_blocker_count"] == 0
    assert summary.json()["report_blocker_count"] == 0

    exploit_candidates = client.get("/engagements/2026-03-30-120000-example/assessment/exploit-candidates")
    assert exploit_candidates.status_code == 200
    assert [row["slug"] for row in exploit_candidates.json()] == ["VA-001"]

    coverage_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-readiness")
    assert coverage_readiness.status_code == 200
    assert coverage_readiness.json()["ready"] is True
    assert coverage_readiness.json()["blocker_count"] == 0

    report_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/report-readiness")
    assert report_readiness.status_code == 200
    assert report_readiness.json()["ready"] is True, report_readiness.json()
    assert report_readiness.json()["blocker_count"] == 0

    final_report = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=final"
    )
    assert final_report.status_code == 200
    assert [row["slug"] for row in final_report.json()["standalone"]] == ["VA-001"]


def test_coverage_item_endpoint_records_class_typed_item(client, isolate_settings):
    """2b: POST /coverage-items wires the previously-dead record_coverage_item,
    minting a class-typed coverage_item (the gf-bucket bridge target)."""
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment"

    created = client.post(
        f"{base}/coverage-items",
        json={
            "attack_family": "idor",
            "auth_context": "anonymous",
            "input_slot": "endpoint",
            "status_value": "pending",
            "notes": "gf bucket 'idor' matched at ingest",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["attack_family"] == "idor"

    items = client.get(f"{base}/coverage-items")
    assert items.status_code == 200
    families = {row["attack_family"] for row in items.json()}
    assert "idor" in families


def test_coverage_item_bulk_endpoint_records_class_typed_items(client, isolate_settings):
    """Bulk coverage ingestion keeps the gf-bucket bridge from POSTing one
    coverage item per matched bucket under high-volume recon."""
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment"

    created = client.post(
        f"{base}/coverage-items/bulk",
        json={
            "items": [
                {
                    "attack_family": "idor",
                    "auth_context": "anonymous",
                    "input_slot": "endpoint",
                    "status_value": "pending",
                    "notes": "gf bucket 'idor' matched at ingest",
                },
                {
                    "attack_family": "ssrf",
                    "auth_context": "anonymous",
                    "input_slot": "endpoint",
                    "status_value": "pending",
                    "notes": "gf bucket 'ssrf' matched at ingest",
                },
            ]
        },
    )

    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["count"] == 2
    assert [row["attack_family"] for row in payload["records"]] == ["idor", "ssrf"]

    covered = client.post(
        f"{base}/coverage-items",
        json={
            "attack_family": "idor",
            "auth_context": "anonymous",
            "input_slot": "endpoint",
            "status_value": "covered",
            "notes": "operator already tested this family",
        },
    )
    assert covered.status_code == 201, covered.text

    repeated_pending = client.post(
        f"{base}/coverage-items/bulk",
        json={
            "items": [
                {
                    "attack_family": "idor",
                    "auth_context": "anonymous",
                    "input_slot": "endpoint",
                    "status_value": "pending",
                    "notes": "repeat gf ingest",
                },
            ]
        },
    )
    assert repeated_pending.status_code == 201, repeated_pending.text
    assert repeated_pending.json()["records"][0]["status"] == "covered"

    items = client.get(f"{base}/coverage-items")
    assert items.status_code == 200
    families = {row["attack_family"] for row in items.json()}
    assert {"idor", "ssrf"} <= families


def test_coverage_item_list_is_bounded_and_paginates(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment"
    created: list[dict] = []
    for idx in range(3):
        response = client.post(
            f"{base}/coverage-items",
            json={
                "attack_family": f"family-{idx}",
                "auth_context": "anonymous",
                "input_slot": "endpoint",
                "status_value": "pending",
                "notes": "pagination test",
            },
        )
        assert response.status_code == 201, response.text
        created.append(response.json())

    items = client.get(f"{base}/coverage-items?limit=2&offset=1")

    assert items.status_code == 200, items.text
    rows = items.json()
    assert len(rows) == 2
    assert [row["id"] for row in rows] == [created[1]["id"], created[0]["id"]]


def test_assessment_summary_is_cached_until_assessment_write(client, isolate_settings, monkeypatch):
    import importlib

    write_engagement(isolate_settings["engagements_dir"])
    summary_module = importlib.import_module("app.services.state_manager.assessment_summary")
    summary_module.clear_assessment_summary_cache()

    first = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert first.status_code == 200

    calls = 0
    original_report_readiness = summary_module.report_readiness

    def counted_report_readiness(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original_report_readiness(*args, **kwargs)

    monkeypatch.setattr(summary_module, "report_readiness", counted_report_readiness)

    second = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert second.status_code == 200
    assert calls == 0

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/coverage-items",
        json={
            "attack_family": "idor",
            "auth_context": "anonymous",
            "input_slot": "endpoint",
            "status_value": "pending",
            "notes": "invalidate summary cache",
        },
    )
    assert created.status_code == 201

    third = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert third.status_code == 200
    assert calls == 1


def test_assessment_summary_singleflights_concurrent_cache_miss(client, isolate_settings, monkeypatch):
    import concurrent.futures
    import importlib
    import threading
    import time

    write_engagement(isolate_settings["engagements_dir"])
    engagement = client.get("/engagements/2026-03-30-120000-example").json()
    summary_module = importlib.import_module("app.services.state_manager.assessment_summary")
    summary_module.clear_assessment_summary_cache()

    calls = 0
    calls_lock = threading.Lock()
    start = threading.Barrier(5)

    def fake_build_summary(engagement_id):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.05)
        return {"engagement_id": engagement_id}

    monkeypatch.setattr(summary_module, "_build_assessment_summary", fake_build_summary)

    def fetch_summary():
        start.wait()
        return summary_module.assessment_summary(engagement["id"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        results = list(executor.map(lambda _: fetch_summary(), range(5)))

    assert results == [{"engagement_id": engagement["id"]}] * 5
    assert calls == 1


def test_probe_run_endpoint_records_target_anchor(client, isolate_settings):
    """Probe runs accept and persist target_host/path/port, and two
    probes against DISTINCT hosts no longer collide on probe_key."""
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment"

    first = client.post(
        f"{base}/probe-runs",
        json={
            "attack_family": "idor",
            "tool_name": "sqlmap",
            "target_host": "a.example.com",
            "result_status": "tested",
        },
    )
    assert first.status_code == 201, first.text
    assert first.json()["target_host"] == "a.example.com"

    second = client.post(
        f"{base}/probe-runs",
        json={
            "attack_family": "idor",
            "tool_name": "sqlmap",
            "target_host": "b.example.com",
            "result_status": "tested",
        },
    )
    assert second.status_code == 201, second.text

    probes = client.get(f"{base}/probe-runs")
    assert probes.status_code == 200
    hosts = {row["target_host"] for row in probes.json()}
    assert {"a.example.com", "b.example.com"} <= hosts

    first_page = client.get(f"{base}/probe-runs?limit=1")
    assert first_page.status_code == 200
    assert len(first_page.json()) == 1
    second_page = client.get(f"{base}/probe-runs?limit=1&offset=1")
    assert second_page.status_code == 200
    assert len(second_page.json()) == 1
    assert first_page.json()[0]["id"] != second_page.json()[0]["id"]


def test_findings_endpoint_filters_and_paginates_server_side(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    payloads = [
        {
            "slug": "VA-101",
            "title": "OIDC static state replay",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "canonical_location": "https://example.com/login",
            "summary": "OIDC state can be replayed",
            "source_name": "vulnerability-analyst",
        },
        {
            "slug": "VA-102",
            "title": "Low severity cookie issue",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/cookie",
            "summary": "Cookie issue",
            "source_name": "recon-specialist",
        },
        {
            "slug": "VA-103",
            "title": "Another active OIDC issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "canonical_location": "https://example.com/callback",
            "summary": "OIDC callback issue",
            "source_name": "vulnerability-analyst",
        },
    ]
    for payload in payloads:
        if payload["verification_status"] == "confirmed":
            response = _record_terminal_finding(client, payload)
            assert response.status_code == 200, response.text
        else:
            response = client.post(
                "/engagements/2026-03-30-120000-example/assessment/findings",
                json={
                    **payload,
                    "provenance": _author_provenance(client, payload["slug"]),
                },
            )
            assert response.status_code == 201, response.text

    filtered = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        params={
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "source_name": "vulnerability-analyst",
            "search": "OIDC",
            "limit": 1,
            "offset": 1,
        },
    )
    assert filtered.status_code == 200, filtered.text
    rows = filtered.json()
    assert len(rows) == 1
    assert rows[0]["slug"] in {"VA-101", "VA-103"}
    assert rows[0]["severity"] == "high"
    assert rows[0]["workflow_status"] == "active"


def test_finding_create_rejects_malformed_slug_and_lookup_accepts_alias(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    malformed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA047",
            "title": "Malformed slug",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/malformed",
            "summary": "Malformed slug should be rejected at write time.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "VA047"),
        },
    )
    assert malformed.status_code == 400
    assert "did you mean VA-047" in malformed.json()["detail"]

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-047",
            "title": "Canonical slug",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/canonical",
            "summary": "Canonical slug should be stored.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "VA-047"),
        },
    )
    assert created.status_code == 201, created.text

    alias_lookup = client.get("/engagements/2026-03-30-120000-example/assessment/findings/VA047")
    assert alias_lookup.status_code == 200
    assert alias_lookup.json()["slug"] == "VA-047"


def test_finding_auto_slug_counts_canonical_ids_beyond_999(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    seeded = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-1000",
            "title": "Existing high-volume canonical slug",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/high-volume/1000",
            "summary": "Existing finding beyond the first 999 IDs.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "VA-1000"),
        },
    )
    assert seeded.status_code == 201, seeded.text

    allocated = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Next high-volume canonical slug",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/high-volume/1001",
            "summary": "Auto-allocation should not collide with VA-1000.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "VA-1001"),
        },
    )
    assert allocated.status_code == 201, allocated.text
    assert allocated.json()["finding"]["slug"] == "VA-1001"


def test_finding_auto_slug_falls_back_for_unknown_source_name(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Unknown source finding",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/unknown",
            "summary": "Clients that omit source_name still get a backend slug.",
            "evidence_ref": "findings.md",
            "provenance": _author_provenance(client, "unknown-source-finding"),
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["finding"]["slug"] == "unknown-source-finding-https-example-com-unknown"


def test_patch_finding_accepts_existing_database_legacy_slug(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])
    assert client.get("/engagements/2026-03-30-120000-example").status_code == 200
    db_path = db_module.database_path()

    with sqlite3.connect(str(db_path)) as connection:
        engagement_id = connection.execute(
            "SELECT id FROM engagements WHERE key = ?",
            ("2026-03-30-120000-example",),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO assessment_findings (
                engagement_id, slug, title, severity, status,
                verification_status, canonical_location,
                source_name, summary, evidence_ref
            ) VALUES (?, 'legacy-title-slug', 'Legacy row', 'medium', 'active',
                'unreviewed', 'https://example.com/legacy',
                'vulnerability-analyst', 'Before update', 'findings.md')
            """,
            (engagement_id,),
        )
        connection.commit()

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/legacy-title-slug",
        json={
            "summary": "Updated without forcing a new slug spelling.",
            "reason_code": "legacy_db_row",
            "reason_text": "Existing database row retained its pre-canonical slug.",
        },
    )

    assert patched.status_code == 200, patched.text
    assert patched.json()["finding"]["slug"] == "legacy-title-slug"
    assert patched.json()["finding"]["summary"] == "Updated without forcing a new slug spelling."


def test_events_synthesizes_legacy_log_artifact_timeline(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_start = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "artifact.updated",
            "phase": "recon",
            "task_name": "log.md",
            "agent_name": "recon-specialist",
            "summary": "Recon start",
        },
    )
    assert create_start.status_code == 201

    create_complete = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "artifact.updated",
            "phase": "recon",
            "task_name": "log.md",
            "agent_name": "recon-specialist",
            "summary": "Recon summary",
        },
    )
    assert create_complete.status_code == 201

    response = client.get("/engagements/2026-03-30-120000-example/events")

    assert response.status_code == 200, response.text
    event_types = [event["event_type"] for event in response.json()]
    assert "phase.started" in event_types
    assert "task.started" in event_types
    assert "task.completed" in event_types


def test_events_recent_limit_is_configurable(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    for index in range(4):
        response = client.post(
            "/engagements/2026-03-30-120000-example/events",
            json={
                "event_type": "task.updated",
                "phase": "recon",
                "task_name": f"task-{index}",
                "agent_name": "recon-specialist",
                "summary": f"Event {index}",
            },
        )
        assert response.status_code == 201

    response = client.get(
        "/engagements/2026-03-30-120000-example/events?limit=2"
    )

    assert response.status_code == 200, response.text
    assert [event["summary"] for event in response.json()] == ["Event 2", "Event 3"]


def test_events_summary_uses_targeted_latest_queries(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    create_phase = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "phase.started",
            "phase": "exploit",
            "task_name": "exploit",
            "agent_name": "operator",
            "summary": "Exploit phase started",
        },
    )
    assert create_phase.status_code == 201
    create_task = client.post(
        "/engagements/2026-03-30-120000-example/events",
        json={
            "event_type": "task.started",
            "phase": "exploit",
            "task_name": "exploit-developer",
            "agent_name": "exploit-developer",
            "summary": "Exploit task started",
        },
    )
    assert create_task.status_code == 201

    def fail_full_timeline(*_args, **_kwargs):
        raise AssertionError("summary must not build the full timeline")

    monkeypatch.setattr(db_module, "list_events_for_engagement", fail_full_timeline)
    monkeypatch.setattr(events_service, "_load_activity_signals", fail_full_timeline)

    response = client.get("/engagements/2026-03-30-120000-example/events/summary")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["latest_phase"]["phase"] == "exploit"
    assert payload["latest_task"]["task_name"] == "exploit-developer"


def test_final_report_mode_returns_conflict_when_readiness_fails(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "https://example.com/orders/7",
            "source_name": "source-analyzer",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    create_finding = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-009",
            "title": "Unreviewed IDOR in orders",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor-unreviewed",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/9",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Needs verification.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "GET /orders/9 returns order for user B when authenticated as user A",
                "impact": "cross-tenant access",
            },
            "provenance": {
                **_author_provenance(client, "VA-009"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert create_finding.status_code == 201

    report_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/report-readiness")
    assert report_readiness.status_code == 200
    assert report_readiness.json()["ready"] is False
    assert any(
        blocker["kind"] == "finding_verification_status" for blocker in report_readiness.json()["blockers"]
    )

    final_report = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=final"
    )
    assert final_report.status_code == 409
    assert final_report.json()["detail"]["ready"] is False
    assert any(
        blocker["kind"] == "finding_verification_status"
        for blocker in final_report.json()["detail"]["blockers"]
    )


def test_final_report_includes_verified_contained_blue_finding(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    scope_path = engagement_dir / "scope.json"
    scope = json.loads(scope_path.read_text(encoding="utf-8"))
    scope.update(
        {
            "engagement_type": "blue",
            "customer": "acme",
            "platforms": ["gws"],
            "tenant_reference_paths": ["agent/references/tenants/acme-workspace.md"],
            "current_phase": "report",
        }
    )
    scope_path.write_text(json.dumps(scope), encoding="utf-8")

    create_surface = client.post(
        "/engagements/2026-03-30-120000-example/assessment/surfaces",
        json={
            "surface_type": "object_reference",
            "target_descriptor": "acme:gws:user@acme.example",
            "source_name": "investigator",
            "status": "covered",
        },
    )
    assert create_surface.status_code == 201

    create_finding = _record_terminal_finding(
        client,
        {
            "slug": "IR-001",
            "title": "Compromised mailbox session contained",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "account-compromise",
            "root_cause_key": "gws-compromised-session",
            "auth_context": "tenant",
            "canonical_location": "acme:gws:user@acme.example",
            "summary": "Attacker held a valid mailbox session before revocation.",
            "evidence_ref": "ir/evidence/session.md",
            "notes": "Contained via session revoke.",
            "source_name": "investigator",
            "details": {
                "impact": "mailbox session access",
                "evidence": "Artifact 12 confirms login and Artifact 19 confirms revocation.",
                "mitre_techniques": ["T1078.004"],
            },
            "provenance": {"agent_name": "investigator"},
            "links": [],
        },
    )
    assert create_finding.status_code == 200

    evidence_path = engagement_dir / "ir" / "evidence" / "session.md"
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_text("session evidence\n", encoding="utf-8")
    register_artifact = client.post(
        "/engagements/2026-03-30-120000-example/assessment/artifacts",
        json={
            "path": "ir/evidence/session.md",
            "kind": "ir_evidence",
            "related_finding_slug": "IR-001",
        },
    )
    assert register_artifact.status_code == 201

    patch_finding = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/IR-001",
        json={
            "workflow_status": "contained",
            "source_name": "ir-lead",
            "reason_code": "containment_recorded",
            "reason_text": "blue contain recorded approved action",
        },
    )
    assert patch_finding.status_code == 200

    report_readiness = client.get("/engagements/2026-03-30-120000-example/assessment/report-readiness")
    assert report_readiness.status_code == 200
    assert report_readiness.json()["ready"] is True, report_readiness.json()

    final_report = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=final"
    )
    assert final_report.status_code == 200
    assert [row["slug"] for row in final_report.json()["standalone"]] == ["IR-001"]


def test_coverage_patch_covered_with_rationale_refreshes_service_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    service_coverage = next(item for item in coverage_items.json() if item["input_slot"] == "service")
    item_url = (
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{service_coverage['id']}"
    )

    rejected = client.patch(item_url, json={"status": "tested", "notes": "Validated service reachability"})
    assert rejected.status_code == 400
    assert "invalid coverage status" in rejected.text.lower()

    no_rationale = client.patch(item_url, json={"status": "covered", "notes": ""})
    assert no_rationale.status_code == 422
    assert "rationale" in no_rationale.text.lower()

    patch = client.patch(item_url, json={"status": "covered", "notes": "Validated service reachability"})
    assert patch.status_code == 200
    assert patch.json()["status"] == "covered"

    services = client.get("/engagements/2026-03-30-120000-example/assessment/services")
    assert services.status_code == 200
    assert services.json()[0]["coverage_status"] == "covered"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["service_coverage_gaps"] == []


def test_request_capture_lists_are_bounded_and_ordered(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    for index in range(4):
        ingest = client.post(
            "/engagements/2026-03-30-120000-example/assessment/request-observations",
            json={
                "url": f"https://example.com/path-{index}",
                "discovery_source": "proxy",
                "observation_payload": {"index": index},
            },
        )
        assert ingest.status_code == 201, ingest.text

    observations = client.get(
        "/engagements/2026-03-30-120000-example/assessment/request-observations?limit=2"
    )
    variants = client.get(
        "/engagements/2026-03-30-120000-example/assessment/request-variants?limit=2&offset=1"
    )

    assert observations.status_code == 200, observations.text
    observed_urls = [row["observed_url"] for row in observations.json()]
    assert observed_urls == ["https://example.com/path-3", "https://example.com/path-2"]
    assert variants.status_code == 200, variants.text
    variant_paths = [row["normalized_path"] for row in variants.json()]
    assert variant_paths == ["/path-2", "/path-1"]


def test_request_observation_bulk_endpoint_maps_rows_and_preserves_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment"

    bulk = client.post(
        f"{base}/request-observations/bulk",
        json={
            "items": [
                {
                    "url": "https://example.com/search?q=test",
                    "query_schema": {"q": {"type": "string"}},
                    "discovery_source": "recon",
                },
                {
                    "url": "https://example.com/api/users",
                    "discovery_source": "recon",
                },
            ]
        },
    )

    assert bulk.status_code == 201, bulk.text
    payload = bulk.json()
    assert payload["count"] == 2
    assert len(payload["records"]) == 2
    first, second = payload["records"]
    assert first["request_variant"]["canonical_url"] == "https://example.com/search?q=test"
    assert second["request_variant"]["canonical_url"] == "https://example.com/api/users"
    assert first["service"]["id"] == second["service"]["id"]
    assert first["request_observation"]["observed_url"] == "https://example.com/search?q=test"

    coverage_items = client.get(f"{base}/coverage-items")
    assert coverage_items.status_code == 200
    query_item = next(item for item in coverage_items.json() if item["input_slot"] == "query")
    patched = client.patch(
        f"{base}/coverage-items/{query_item['id']}",
        json={"status": "covered", "notes": "Operator validated this coverage item."},
    )
    assert patched.status_code == 200, patched.text

    repeat = client.post(
        f"{base}/request-observations/bulk",
        json={
            "items": [
                {
                    "url": "https://example.com/search?q=test",
                    "query_schema": {"q": {"type": "string"}},
                    "discovery_source": "recon",
                }
            ]
        },
    )
    assert repeat.status_code == 201, repeat.text

    refreshed_items = client.get(f"{base}/coverage-items")
    assert refreshed_items.status_code == 200
    refreshed_by_slot = {item["input_slot"]: item for item in refreshed_items.json()}
    assert refreshed_by_slot["query"]["status"] == "covered"


def test_summary_vendor_saas_decision_reads_dispatch_decisions(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://tenant.auth0.com/login",
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201, ingest.text

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200, summary.text
    pending = {
        row["host"]: row["vendor"]
        for row in summary.json()["vendor_saas_hosts_pending_decision"]
    }
    assert pending.get("tenant.auth0.com") == "auth0"

    decision = client.post(
        "/engagements/2026-03-30-120000-example/assessment/dispatch-decisions",
        json={
            "kind": "scope_decision",
            "payload": {
                "host": "tenant.auth0.com",
                "vendor": "auth0",
                "choice": "in_scope",
            },
            "surfaced_to_user": True,
        },
    )
    assert decision.status_code == 201, decision.text

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200, summary.text
    assert summary.json()["vendor_saas_hosts_pending_decision"] == []


def test_repeat_request_observation_preserves_stronger_coverage_status(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    first = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert first.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    payload = coverage_items.json()
    query_item = next(item for item in payload if item["input_slot"] == "query")
    service_item = next(item for item in payload if item["input_slot"] == "service")

    for item in (query_item, service_item):
        patch = client.patch(
            f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{item['id']}",
            json={"status": "covered", "notes": "Operator validated this coverage item."},
        )
        assert patch.status_code == 200
        assert patch.json()["status"] == "covered"

    second = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert second.status_code == 201

    refreshed_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert refreshed_items.status_code == 200
    refreshed_by_slot = {item["input_slot"]: item for item in refreshed_items.json()}
    assert refreshed_by_slot["query"]["status"] == "covered"
    assert refreshed_by_slot["service"]["status"] == "covered"

    services = client.get("/engagements/2026-03-30-120000-example/assessment/services")
    assert services.status_code == 200
    assert services.json()[0]["coverage_status"] == "covered"


def test_findings_verify_updates_existing_finding_and_records_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-001",
            "title": "IDOR in orders",
            "severity": "medium",
            "workflow_status": "draft",
            "verification_status": "unreviewed",
            "defect_family": "idor",
            "root_cause_key": "orders-idor",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/7",
            "summary": "Order data can be accessed cross-tenant.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential cross-tenant access",
            },
            "provenance": {
                **_author_provenance(client, "VA-001"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = _verify_with_fixture_proof(
        client,
        "VA-001",
        {
            "verification_status": "confirmed",
            "reason_code": "reproduced",
            "reason_text": "Adjacent object identifiers reliably return cross-tenant orders.",
            "notes": "Verified with adjacent object identifiers.",
            "source_name": "code-vuln-verifier",
            "evidence_ref": "findings.md",
            "artifact_ref": "findings.md",
            "details": {"impact": "Confirmed cross-tenant order read"},
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["slug"] == "VA-001"
    assert payload["finding"]["workflow_status"] == "draft"
    assert payload["finding"]["verification_status"] == "confirmed"
    assert payload["finding"]["severity"] == "medium"
    assert payload["transition"]["action"] == "verified_confirmed"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-001/transitions"
    )
    assert transitions.status_code == 200
    assert [item["action"] for item in transitions.json()] == ["verified_confirmed", "created"]

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    finding = next(item for item in findings.json() if item["slug"] == "VA-001")
    assert "Verified with adjacent object identifiers." in finding["notes"]
    assert finding["workflow_status"] == "draft"
    assert finding["verification_status"] == "confirmed"
    assert finding["details"]["impact"] == "Confirmed cross-tenant order read"
    assert finding["provenance"]["verified_by"] == "code-vuln-verifier"


def test_findings_verify_pending_runtime_proof_roundtrips_and_holds(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-050",
            "title": "Static state replay (runtime proof pending)",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "static-state-replay",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/login",
            "summary": "Static OIDC state appears replayable from code review.",
            "evidence_ref": "findings.md",
            "notes": "Static evidence captured.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "state param is not bound to a nonce in handler",
                "impact": "Potential account takeover pending runtime confirmation",
                "chain_required": True,
                "chain_rationale": "Only reaches takeover once a runtime pass proves the state is replayable against a live session.",
            },
            "provenance": {
                **_author_provenance(client, "VA-050"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-050/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static/code evidence accepted; runtime PoC still outstanding.",
            "notes": "Held pending exploit-developer runtime proof.",
            "source_name": "vulnerability-analyst",
            "evidence_ref": "findings.md",
            "artifact_ref": "findings.md",
            "details": {"impact": "Account takeover path pending runtime proof"},
            "provenance": {"verified_by": "vulnerability-analyst"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["slug"] == "VA-050"
    # The disposition must round-trip exactly (NOT silently degrade to none/disputed)
    # and the finding must be marked verified so it leaves the unreviewed queue.
    assert payload["finding"]["verification_status"] == "pending_runtime_proof"
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["severity"] == "high"
    assert payload["transition"]["action"] == "verified_pending_runtime_proof"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-050/transitions"
    )
    assert transitions.status_code == 200
    assert [item["action"] for item in transitions.json()] == [
        "verified_pending_runtime_proof",
        "created",
    ]

    # Re-read confirms the persisted disposition/state survive a fresh fetch.
    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    finding = next(item for item in findings.json() if item["slug"] == "VA-050")
    assert finding["verification_status"] == "pending_runtime_proof"


def test_pending_runtime_proof_is_sticky_against_bare_none_rerecord(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    base_payload = {
        "slug": "VA-051",
        "title": "Sticky pending disposition",
        "severity": "high",
        "defect_family": "auth-bypass",
        "root_cause_key": "sticky-pending",
        "auth_context": "anonymous",
        "canonical_location": "https://example.com/sticky",
        "summary": "Strong-but-unproven finding.",
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "code review", "impact": "pending runtime"},
        "provenance": {
            **_author_provenance(client, "VA-051"),
            "agent_name": "vulnerability-analyst",
        },
        "links": [],
    }
    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={**base_payload, "workflow_status": "active", "verification_status": "unreviewed"},
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-051/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static evidence accepted; runtime proof outstanding.",
            "source_name": "vulnerability-analyst",
        },
    )
    assert verified.status_code == 200
    assert verified.json()["finding"]["verification_status"] == "pending_runtime_proof"

    # A later record-finding pass that re-asserts the same semantic finding with a
    # bare none disposition must NOT clobber the held pending_runtime_proof.
    rerecorded = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            **base_payload,
            "summary": "Rediscovered by a later pass with no verification.",
            "workflow_status": "active",
            "verification_status": "unreviewed",
        },
    )
    assert rerecorded.status_code == 201
    assert rerecorded.json()["finding"]["verification_status"] == "pending_runtime_proof"


def test_pending_runtime_proof_yields_to_confirmed(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-052",
            "title": "Pending then confirmed",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "pending-then-confirmed",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/yields",
            "summary": "Held then proven.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "pending runtime"},
            "provenance": {
                **_author_provenance(client, "VA-052"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    pending = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-052/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static evidence accepted; runtime proof outstanding.",
            "source_name": "vulnerability-analyst",
        },
    )
    assert pending.status_code == 200
    assert pending.json()["finding"]["verification_status"] == "pending_runtime_proof"

    confirmed = _verify_with_fixture_proof(
        client,
        "VA-052",
        {
            "verification_status": "confirmed",
            "reason_code": "reproduced",
            "reason_text": "Runtime PoC reproduced the account takeover.",
            "source_name": "exploit-developer",
        },
    )
    assert confirmed.status_code == 200
    assert confirmed.json()["finding"]["verification_status"] == "confirmed"
    assert confirmed.json()["transition"]["action"] == "verified_confirmed"


@pytest.mark.parametrize("workflow_status", ["active", "draft"])
@pytest.mark.parametrize(
    "canonical_location",
    ["https://example.com/held", "file:src/acme/parser.py:7"],
)
def test_pending_runtime_proof_blocks_report_readiness_and_exploit_candidates(
    client, isolate_settings, workflow_status, canonical_location
):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-053",
            "title": "Held finding stays out of report and exploit queue",
            "severity": "high",
            "workflow_status": workflow_status,
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "held-excluded",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/held",
            "summary": "Strong-but-unproven, must not pass readiness.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "pending runtime"},
            "provenance": {
                **_author_provenance(client, "VA-053"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-053/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static evidence accepted; runtime proof outstanding.",
            "source_name": "vulnerability-analyst",
        },
    )
    assert verified.status_code == 200
    assert verified.json()["finding"]["verification_status"] == "pending_runtime_proof"
    if canonical_location.startswith("file:"):
        with db_module.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_findings SET canonical_location=? WHERE slug='VA-053'",
                (canonical_location,),
            )

    # Excluded from exploit candidates (disposition not in {confirmed, downgraded}).
    exploit_candidates = client.get(
        "/engagements/2026-03-30-120000-example/assessment/exploit-candidates"
    )
    assert exploit_candidates.status_code == 200
    assert all(row["slug"] != "VA-053" for row in exploit_candidates.json())

    # Produces a verification-disposition blocker in report-readiness (no
    # chain_required bypass: a held finding must NOT pass readiness silently).
    report_readiness = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-readiness"
    )
    assert report_readiness.status_code == 200
    body = report_readiness.json()
    assert body["ready"] is False, body
    disposition_blockers = [
        blocker
        for blocker in body["blockers"]
        if blocker.get("kind") == "finding_verification_status" and blocker.get("slug") == "VA-053"
    ]
    assert len(disposition_blockers) == 1, body["blockers"]
    assert "pending_runtime_proof" in disposition_blockers[0]["detail"]


def test_verification_narrative_artifact_registers_and_is_searchable(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-060",
            "title": "Finding with a persisted debate narrative",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "narrative-finding",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/narrative",
            "summary": "Has an Ideator-vs-Tracer debate doc.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "pending runtime"},
            "provenance": {
                **_author_provenance(client, "VA-060"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    notes_dir = engagement_dir / "notes"
    notes_dir.mkdir(parents=True, exist_ok=True)
    (notes_dir / "VA-060-debate.md").write_text(
        "# VA-060 Ideator-vs-Tracer debate\n\nClaim -> causal challenge -> evidence -> verdict.\n",
        encoding="utf-8",
    )

    registered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/artifacts",
        json={
            "path": "notes/VA-060-debate.md",
            "kind": "verification-narrative",
            "related_finding_slug": "VA-060",
            "producer_agent_role": "vulnerability-analyst",
        },
    )
    assert registered.status_code == 201, registered.text
    assert registered.json()["kind"] == "verification-narrative"
    assert registered.json()["related_finding_slug"] == "VA-060"

    by_finding_kind = client.get(
        "/engagements/2026-03-30-120000-example/assessment/artifacts/search",
        params={"finding": "VA-060", "kind": "verification-narrative"},
    )
    assert by_finding_kind.status_code == 200, by_finding_kind.text
    rows = by_finding_kind.json()
    assert any(row["relative_path"] == "notes/VA-060-debate.md" for row in rows)
    assert all(row["kind"] == "verification-narrative" for row in rows)


_ARTIFACTS_BULK_URL = "/engagements/2026-03-30-120000-example/assessment/artifacts/bulk"


def _write_artifact_files(engagement_dir: Path, *relative_paths: str) -> None:
    for relative in relative_paths:
        target = engagement_dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"# {relative}\n", encoding="utf-8")


def test_bulk_artifact_register_lands_every_valid_path(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    _write_artifact_files(engagement_dir, "notes/a.md", "notes/b.md", "tools/c.json")

    response = client.post(
        _ARTIFACTS_BULK_URL,
        json={
            "items": [
                {"path": "notes/a.md", "kind": "note"},
                {"path": "./notes/b.md", "kind": "note"},
                {"path": "tools/c.json", "kind": "tooling"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["requested"], body["registered"], body["failed"]) == (3, 3, 0)
    assert body["registered"] + body["failed"] == body["requested"]
    assert [outcome["index"] for outcome in body["outcomes"]] == [0, 1, 2]
    assert [outcome["path"] for outcome in body["outcomes"]] == [
        "notes/a.md",
        "./notes/b.md",
        "tools/c.json",
    ]
    assert [outcome["relative_path"] for outcome in body["outcomes"]] == [
        "notes/a.md",
        "notes/b.md",
        "tools/c.json",
    ]
    assert all(outcome["outcome"] == "registered" for outcome in body["outcomes"])
    assert all(outcome["detail"] == "" for outcome in body["outcomes"])
    assert [row["relative_path"] for row in body["artifacts"]] == [
        "notes/a.md",
        "notes/b.md",
        "tools/c.json",
    ]
    assert [outcome["artifact_id"] for outcome in body["outcomes"]] == [
        row["id"] for row in body["artifacts"]
    ]
    # The single-path row minus `indexed_text`: what landed, not an echo of the
    # bytes the caller submitted (~100 MB for a 500-path batch). Not ADR 0019
    # masking — `indexed_bytes`/`index_status` report the indexing and
    # `artifact get` returns the text verbatim.
    assert all(
        {"sha256", "preview_text", "indexed_bytes", "index_status", "kind"} <= set(row)
        for row in body["artifacts"]
    )
    assert all("indexed_text" not in row for row in body["artifacts"])

    listed = client.get(
        "/engagements/2026-03-30-120000-example/assessment/artifacts/search",
        params={"limit": 100},
    )
    assert listed.status_code == 200, listed.text
    assert {row["relative_path"] for row in listed.json()} >= {
        "notes/a.md",
        "notes/b.md",
        "tools/c.json",
    }


def test_bulk_artifact_register_reports_the_refused_path_and_keeps_the_rest(
    client, isolate_settings, tmp_path
):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    _write_artifact_files(engagement_dir, "notes/keep-one.md", "notes/keep-two.md")
    outside = tmp_path / "not-in-the-engagement.md"
    outside.write_text("someone else's file\n", encoding="utf-8")

    response = client.post(
        _ARTIFACTS_BULK_URL,
        json={
            "items": [
                {"path": "notes/keep-one.md", "kind": "note"},
                {"path": str(outside), "kind": "note"},
                {"path": "notes/keep-two.md", "kind": "note"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["requested"], body["registered"], body["failed"]) == (3, 2, 1)
    assert body["registered"] + body["failed"] == body["requested"]
    refused = body["outcomes"][1]
    assert refused["outcome"] == "failed"
    assert refused["path"] == str(outside)
    assert refused["relative_path"] is None
    assert refused["artifact_id"] is None
    assert refused["status_code"] == 400
    assert "inside the engagement directory" in refused["detail"]
    assert [row["relative_path"] for row in body["artifacts"]] == [
        "notes/keep-one.md",
        "notes/keep-two.md",
    ]

    listed = client.get(
        "/engagements/2026-03-30-120000-example/assessment/artifacts/search",
        params={"limit": 100},
    )
    assert {row["relative_path"] for row in listed.json()} == {
        "notes/keep-one.md",
        "notes/keep-two.md",
    }


def test_bulk_artifact_register_writes_the_same_activity_row_per_artifact(
    client, isolate_settings
):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    _write_artifact_files(engagement_dir, "notes/audited-one.md", "notes/audited-two.md")

    single = client.post(
        "/engagements/2026-03-30-120000-example/assessment/artifacts",
        json={"path": "notes/audited-one.md", "kind": "note", "producer_agent_role": "recon"},
    )
    assert single.status_code == 201, single.text

    bulk = client.post(
        _ARTIFACTS_BULK_URL,
        json={
            "items": [
                {"path": "notes/audited-two.md", "kind": "note", "producer_agent_role": "recon"}
            ]
        },
    )
    assert bulk.status_code == 201, bulk.text

    entries = client.get(
        "/engagements/2026-03-30-120000-example/activity-entries", params={"limit": 1000}
    )
    assert entries.status_code == 200, entries.text
    registrations = [
        entry for entry in entries.json()["items"] if entry["title"] == "artifact register"
    ]
    by_action = {entry["action"]: entry for entry in registrations}
    assert set(by_action) == {"notes/audited-one.md", "notes/audited-two.md"}
    single_row = by_action["notes/audited-one.md"]
    bulk_row = by_action["notes/audited-two.md"]
    # Activity-ledger parity: a bulk-registered artifact must be as findable as a
    # singly registered one, so the row differs only in the path it names.
    assert bulk_row["actor_kind"] == single_row["actor_kind"]
    assert bulk_row["actor_name"] == single_row["actor_name"] == "recon"
    assert bulk_row["result"] == single_row["result"] == "note"
    assert bulk_row["metadata"]["relative_path"] == "notes/audited-two.md"
    assert bulk_row["metadata"]["artifact_id"] == bulk.json()["artifacts"][0]["id"]



def test_bulk_artifact_register_rolls_back_only_the_refused_item(client, isolate_settings):
    """A refusal raised AFTER its own row was written must take only that row.

    The producer-attribution 409 fires after the upsert has already run, so
    without a per-item savepoint the refused path would keep the partial write
    (here: a rewritten ``kind``) that the caller was told did not happen.
    """
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    _write_artifact_files(engagement_dir, "notes/before.md", "notes/after.md")
    _proof_receipt(client, "VA-SAVEPOINT")
    proofs = client.get(
        "/engagements/2026-03-30-120000-example/assessment/artifacts/search",
        params={"kind": "proof", "limit": 10},
    )
    assert proofs.status_code == 200, proofs.text
    cited = proofs.json()[0]

    response = client.post(
        _ARTIFACTS_BULK_URL,
        json={
            "items": [
                {"path": "notes/before.md", "kind": "note"},
                {
                    "path": cited["relative_path"],
                    "kind": "rewritten-by-the-refused-item",
                    "producer_agent_id": "SOMEONE-ELSE",
                },
                {"path": "notes/after.md", "kind": "note"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["requested"], body["registered"], body["failed"]) == (3, 2, 1)
    refused = body["outcomes"][1]
    assert refused["outcome"] == "failed"
    assert refused["status_code"] == 409
    assert "immutable after proof registration" in refused["detail"]
    assert [row["relative_path"] for row in body["artifacts"]] == [
        "notes/before.md",
        "notes/after.md",
    ]

    unchanged = client.get(
        f"/engagements/2026-03-30-120000-example/assessment/artifacts/{cited['id']}"
    )
    assert unchanged.status_code == 200, unchanged.text
    assert unchanged.json()["kind"] == "proof"
    assert unchanged.json()["producer_agent_id"] == cited["producer_agent_id"]


def test_bulk_artifact_register_rejects_more_items_than_the_cap(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    response = client.post(
        _ARTIFACTS_BULK_URL,
        json={"items": [{"path": f"notes/over-{index}.md"} for index in range(501)]},
    )

    assert response.status_code == 422, response.text


def test_bulk_artifact_register_upserts_an_already_registered_path(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])
    _write_artifact_files(engagement_dir, "notes/again.md", "notes/fresh.md")

    first = client.post(
        "/engagements/2026-03-30-120000-example/assessment/artifacts",
        json={"path": "notes/again.md", "kind": "note"},
    )
    assert first.status_code == 201, first.text

    response = client.post(
        _ARTIFACTS_BULK_URL,
        json={
            "items": [
                {"path": "notes/again.md", "kind": "note"},
                {"path": "notes/fresh.md", "kind": "note"},
            ]
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert (body["requested"], body["registered"], body["failed"]) == (2, 2, 0)
    assert body["artifacts"][0]["id"] == first.json()["id"]

    listed = client.get(
        "/engagements/2026-03-30-120000-example/assessment/artifacts/search",
        params={"limit": 100},
    )
    paths = [row["relative_path"] for row in listed.json()]
    assert paths.count("notes/again.md") == 1


def test_findings_patch_can_revive_false_positive_and_lower_severity(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = _record_terminal_finding(
        client,
        {
            "slug": "CH-009",
            "title": "Parser length overflow",
            "severity": "high",
            "workflow_status": "false_positive",
            "verification_status": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "parser-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=91",
            "summary": "Suppressed after verifier review.",
            "evidence_ref": "tools/analysis-state/verifier.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "validate_length() enforces an 8KB upper bound before arithmetic.",
                "evidence": "validate_length() rejects oversized input.",
                "impact": "Potential overflow avoided by guard.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert created.status_code == 200, created.text

    revived = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-009",
        json={
            "workflow_status": "active",
            "severity": "low",
            "notes": "Operator reinstated after manual review.",
            "reason_code": "manual-override",
            "reason_text": "Manual review found the path is live with reduced impact.",
            "provenance": {"reviewed_by": "operator"},
        },
    )
    assert revived.status_code == 200
    assert revived.json()["finding"]["workflow_status"] == "active"
    assert revived.json()["finding"]["verification_status"] == "unreviewed"
    assert revived.json()["finding"]["severity"] == "low"
    assert revived.json()["transition"]["action"] == "verification_invalidated"


@pytest.mark.parametrize(
    ("destructive_patch", "expected_verification", "expected_action"),
    [
        ({
            "details": {"evidence": "Replacement proof set."},
            "details_mode": "merge",
        }, "confirmed", "claim_review_pending"),
        ({
            "details": {"impact": "Replacement removed the evidence narrative."},
            "details_mode": "replace",
        }, "unreviewed", "verification_invalidated"),
    ],
)
def test_findings_patch_append_evidence_preserves_terminal_verification(
    client, isolate_settings, destructive_patch, expected_verification, expected_action
):
    write_engagement(isolate_settings["engagements_dir"])
    created = _record_terminal_finding(
        client,
        {
            "slug": "VA-061",
            "title": "Confirmed parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/api/parse",
            "summary": "The parser trusts an attacker-controlled length.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"impact": "Memory corruption"},
            "provenance": {
                **_author_provenance(client, "CH-010"),
                "agent_name": "vulnerability-analyst",
            },
        },
    )
    assert created.status_code == 200, created.text
    original_receipts = created.json()["finding"]["proof_receipts"]
    assert original_receipts

    appended = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-061",
        json={
            "details": {"evidence": "Live replay reached the same copy."},
            "details_mode": "append",
            "source_name": "exploit-developer",
        },
    )

    assert appended.status_code == 200, appended.text
    finding = appended.json()["finding"]
    assert finding["verification_status"] == "confirmed"
    assert finding["verification_invalidated"] is False
    assert finding["details"]["evidence"] == "Live replay reached the same copy."
    assert finding["proof_receipts"] == original_receipts

    replaced = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-061",
        json={
            **destructive_patch,
            **(
                {"expected_row_version": finding["row_version"]}
                if destructive_patch["details_mode"] == "replace"
                else {}
            ),
            "source_name": "exploit-developer",
        },
    )
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["finding"]["verification_status"] == expected_verification
    assert replaced.json()["transition"]["action"] == expected_action


def test_findings_patch_rejects_direct_verification_bypass(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-010",
            "title": "Direct patch bypass",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "idor",
            "root_cause_key": "direct-patch-bypass",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/items/7",
            "summary": "Patch should not be able to persist verifier outcomes.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Initial request/response pair",
                "impact": "Potential unauthorized access",
            },
            "provenance": {
                **_author_provenance(client, "CH-010"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-010",
        json={
            "workflow_status": "false_positive",
            "reason_text": "Bypass verifier checks",
        },
    )
    assert patched.status_code == 400
    assert "must use POST /findings/{slug}/verify" in patched.json()["detail"]


def test_findings_patch_allows_explicit_workflow_rollback(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-011",
            "title": "Workflow rollback candidate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "idor",
            "root_cause_key": "workflow-rollback-candidate",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/items/rollback",
            "summary": "Active finding should be movable back to draft.",
            "evidence_ref": "findings.md",
            "notes": "Initial triage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Initial request/response pair"},
            "provenance": {
                **_author_provenance(client, "CH-011"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-011",
        json={
            "workflow_status": "draft",
            "reason_code": "needs-retriage",
            "reason_text": "Pushed back for additional review before reactivation.",
        },
    )
    assert patched.status_code == 200
    assert patched.json()["finding"]["workflow_status"] == "draft"


def test_findings_patch_rejects_records_merged_after_validation(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    created = _record_terminal_finding(
        client,
        {
            "slug": "CH-012",
            "title": "Patch/merge race candidate",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "patch-merge-race",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/orders/{id}",
            "summary": "Patch should fail if the finding is merged after validation.",
            "evidence_ref": "findings.md",
            "notes": "Created for stale patch race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "Object id is user-controlled", "impact": "Cross-tenant read"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert created.status_code == 200

    from app.services import state_manager

    original_create_finding = state_manager.create_finding
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(*args, **kwargs):
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                    SET status = 'merged',
                        merged_into_finding_id = id,
                        row_version = row_version + 1,
                        updated_at = '2099-01-01 00:00:00'
                WHERE slug = 'CH-012'
                """
            )
            connection.commit()
        return original_create_finding(*args, **kwargs)

    monkeypatch.setattr(state_manager.findings, "create_finding", race)

    patched = client.patch(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-012",
        json={"notes": "Late patch should not overwrite a merged finding."},
    )

    assert patched.status_code == 409
    assert "changed since it was loaded" in patched.json()["detail"]


def test_false_positive_findings_are_suppressed_but_semantically_sticky(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = _record_terminal_finding(
        client,
        {
            "slug": "CH-001",
            "title": "Header length overflow in parser",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=128",
            "summary": "Header length appears to overflow before allocation.",
            "evidence_ref": "tools/analysis-state/findings.json",
            "notes": "Initial hunter report.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "len * 4 appears attacker-controlled",
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert created.status_code == 200

    killed = _verify_with_fixture_proof(
        client,
        "CH-001",
        {
            "verification_status": "false_positive",
            "reason_code": "check-2-guard",
            "reason_text": "validate_header_length() bounds header length to 8192 bytes on all paths.",
            "artifact_ref": "tools/analysis-state/verifier.json",
            "source_name": "code-vuln-verifier",
            "notes": "Check 2 KILL: upstream guard bounds header length to 8192 bytes.",
            "details": {
                "kill_check": 2,
                "kill_reason": "upstream guard bounds header length to 8192 bytes.",
                "evidence": "validate_header_length() rejects oversized input before arithmetic."
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert killed.status_code == 200
    assert killed.json()["finding"]["workflow_status"] == "false_positive"
    assert killed.json()["finding"]["verification_status"] == "false_positive"
    assert killed.json()["transition"]["action"] == "verified_false_positive"

    summary = client.get("/engagements/2026-03-30-120000-example/assessment/summary")
    assert summary.status_code == 200
    assert summary.json()["finding_count"] == 0
    assert summary.json()["finding_workflow_statuses"]["false_positive"] == 1
    assert summary.json()["finding_verification_statuses"]["false_positive"] == 1
    # The false_positive CH-001 (high) is excluded from the severity rollup
    # exactly like finding_count, so the donut total stays at 0 (empty rollup)
    # rather than counting the suppressed high finding.
    assert summary.json()["finding_severities"] == {}
    assert sum(summary.json()["finding_severities"].values()) == summary.json()["finding_count"]
    assert summary.json()["top_findings"] == []

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert report_findings.json()["groups"] == []
    assert report_findings.json()["standalone"] == []

    rediscovered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Header length overflow in parser",
            "severity": "critical",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "integer-overflow",
            "root_cause_key": "header-length-overflow",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=128",
            "summary": "Rediscovery attempt from later analysis pass.",
            "evidence_ref": "tools/analysis-state/rediscovery.json",
            "notes": "Re-raised by later LLM pass.",
            "source_name": "code-vuln-hunter",
            "details": {
                "impact": "Potential heap corruption",
            },
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert rediscovered.status_code == 201
    assert rediscovered.json()["finding"]["slug"] == "CH-001"
    assert rediscovered.json()["finding"]["workflow_status"] == "false_positive"
    assert rediscovered.json()["finding"]["verification_status"] == "false_positive"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 1
    assert payload[0]["workflow_status"] == "false_positive"
    assert "Re-raised by later LLM pass." in payload[0]["notes"]
    assert payload[0]["details"]["kill_check"] == 2
    assert payload[0]["details"]["kill_reason"] == "upstream guard bounds header length to 8192 bytes."


def test_false_positive_title_fallback_does_not_suppress_distinct_finding(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    original = _record_terminal_finding(
        client,
        {
            "slug": "CH-020",
            "title": "Shared parser bug title",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_status": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "overflow-a",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=128",
            "summary": "Suppressed integer overflow hypothesis.",
            "evidence_ref": "tools/analysis-state/a.json",
            "notes": "Verifier killed the original hypothesis.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "size guard blocks the arithmetic path.",
                "evidence": "validate_length() blocks the original path.",
                "impact": "No live issue on this path.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert original.status_code == 200

    distinct = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Shared parser bug title",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "overflow-b",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=128",
            "summary": "Different defect family at the same location.",
            "evidence_ref": "tools/analysis-state/b.json",
            "notes": "Newly verified buffer overwrite path.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "memcpy() uses unchecked attacker length.",
                "impact": "Heap corruption",
            },
            "provenance": {
                **_author_provenance(client, "CH-020-DISTINCT"),
                "agent_name": "code-vuln-hunter",
            },
            "links": [],
        },
    )
    assert distinct.status_code == 201
    distinct_slug = distinct.json()["finding"]["slug"]
    distinct = _verify_with_fixture_proof(
        client,
        distinct_slug,
        {
            "verification_status": "confirmed",
            "reason_text": "Independent fixture review completed.",
            "source_name": "fixture-independent-verifier",
        },
    )
    assert distinct.status_code == 200, distinct.text
    assert distinct.json()["finding"]["slug"] != "CH-020"
    assert distinct.json()["finding"]["workflow_status"] == "active"
    assert distinct.json()["finding"]["verification_status"] == "confirmed"

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 2
    assert {item["workflow_status"] for item in payload} == {"false_positive", "active"}


def test_root_cause_free_false_positive_findings_stay_semantically_sticky(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    original = _record_terminal_finding(
        client,
        {
            "slug": "CH-025",
            "title": "Shared parser size bug",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_status": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=150",
            "summary": "Suppressed parser hypothesis without a root cause key.",
            "evidence_ref": "tools/analysis-state/original.json",
            "notes": "Verifier killed the original hypothesis.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 2,
                "kill_reason": "bounded before arithmetic.",
                "evidence": "size guard blocks the path.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert original.status_code == 200

    rediscovered = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "title": "Shared parser size bug",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "integer-overflow",
            "root_cause_key": "",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=150",
            "summary": "Rediscovered without a root cause key.",
            "evidence_ref": "tools/analysis-state/rediscovered.json",
            "notes": "Later analysis pass re-raised the same parser concern.",
            "source_name": "code-vuln-hunter",
            "details": {"impact": "Potential heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert rediscovered.status_code == 201
    assert rediscovered.json()["finding"]["slug"] == "CH-025"
    assert rediscovered.json()["finding"]["workflow_status"] == "false_positive"
    assert rediscovered.json()["finding"]["verification_status"] == "false_positive"


def test_coverage_items_expression_unique_index_blocks_nullable_duplicates(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={
            "url": "https://example.com/search?q=test",
            "query_schema": {"q": {"type": "string"}},
            "discovery_source": "recon",
        },
    )
    assert ingest.status_code == 201
    service_id = ingest.json()["service"]["id"]

    with db_module.get_connection() as connection:
        engagement_id = int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?",
                ("2026-03-30-120000-example",),
            ).fetchone()["id"]
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO assessment_coverage_items (
                    engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family, status, notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    None,
                    service_id,
                    "anonymous",
                    "service",
                    "service-validation",
                    "pending",
                    "duplicate logical coverage row",
                ),
            )


def test_merge_into_false_positive_target_is_rejected(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = _record_terminal_finding(
        client,
        {
            "slug": "CH-030",
            "title": "Live parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "live-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=211",
            "summary": "Live finding.",
            "evidence_ref": "tools/analysis-state/live.json",
            "notes": "Confirmed by hunter.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Unchecked copy", "impact": "Heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert source.status_code == 200

    target = _record_terminal_finding(
        client,
        {
            "slug": "CH-031",
            "title": "Suppressed parser issue",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_status": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-issue",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=333",
            "summary": "Suppressed by verifier.",
            "evidence_ref": "tools/analysis-state/suppressed.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 5,
                "kill_reason": "Build flag disables the path in production.",
                "evidence": "Code is behind a debug-only build flag.",
                "impact": "Not reachable in production.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert target.status_code == 200

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-030",
            "target_slug": "CH-031",
            "reason": "Attempted merge into suppressed target.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 400
    assert "false_positive target" in merge.json()["detail"]


def test_merge_false_positive_source_preserves_live_target(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = _record_terminal_finding(
        client,
        {
            "slug": "CH-032",
            "title": "Suppressed parser duplicate",
            "severity": "medium",
            "workflow_status": "false_positive",
            "verification_status": "false_positive",
            "defect_family": "integer-overflow",
            "root_cause_key": "suppressed-parser-duplicate",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=211",
            "summary": "Duplicate was previously suppressed by verifier.",
            "evidence_ref": "tools/analysis-state/suppressed-duplicate.json",
            "notes": "Killed during verification.",
            "source_name": "code-vuln-verifier",
            "details": {
                "kill_check": 5,
                "kill_reason": "Old triage considered the path dead.",
                "evidence": "Verifier marked the duplicate as unreachable.",
                "impact": "No separate issue remained.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
            "links": [],
        },
    )
    assert source.status_code == 200

    target = _record_terminal_finding(
        client,
        {
            "slug": "CH-033",
            "title": "Live parser issue",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "buffer-overflow",
            "root_cause_key": "live-parser-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=211",
            "summary": "Target finding is still live.",
            "evidence_ref": "tools/analysis-state/live-target.json",
            "notes": "Confirmed by hunter.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Unchecked copy", "impact": "Heap corruption"},
            "provenance": {"agent_name": "code-vuln-hunter"},
            "links": [],
        },
    )
    assert target.status_code == 200
    with db_module.get_connection() as connection:
        target_proof_receipts_before = [
            int(row["proof_receipt_id"])
            for row in connection.execute(
                """
                SELECT proof_receipt_id
                FROM assessment_finding_proof_receipts
                WHERE finding_id = (
                    SELECT id FROM assessment_findings WHERE slug = 'CH-033'
                ) AND relation = 'verification'
                ORDER BY proof_receipt_id
                """
            ).fetchall()
        ]
    assert len(target_proof_receipts_before) == 1

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-032",
            "target_slug": "CH-033",
            "reason": "Suppressed duplicate should merge into the live target without downgrading it.",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 200
    merge_payload = merge.json()
    assert merge_payload["target"]["workflow_status"] == "active"
    assert merge_payload["target"]["verification_status"] == "confirmed"
    assert merge_payload["target"]["severity"] == "high"
    assert merge_payload["target"]["summary"] == "Target finding is still live."
    assert merge_payload["target"]["evidence_ref"] == (
        "tools/analysis-state/live-target.json"
    )
    assert merge_payload["target"]["details"]["evidence"] == "Unchecked copy"
    assert merge_payload["target"]["details"]["impact"] == "Heap corruption"
    assert merge_payload["target"]["details"]["kill_check"] == 5
    assert merge_payload["target"]["details"]["kill_reason"] == (
        "Old triage considered the path dead."
    )
    assert merge_payload["source"]["workflow_status"] == "merged"
    assert merge_payload["source"]["verification_status"] == "false_positive"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-033/transitions"
    )
    assert transitions.status_code == 200, transitions.text
    merge_transition = transitions.json()[0]
    assert merge_transition["action"] == "operator_override"
    assert merge_transition["reason_code"] == "merge"
    merge_metadata = json.loads(merge_transition["metadata_json"])
    assert merge_metadata["verification_invalidated"] is False
    assert merge_metadata["replaced_dependencies"] == []

    with db_module.get_connection() as connection:
        target_proof_receipts_after = [
            int(row["proof_receipt_id"])
            for row in connection.execute(
                """
                SELECT proof_receipt_id
                FROM assessment_finding_proof_receipts
                WHERE finding_id = (
                    SELECT id FROM assessment_findings WHERE slug = 'CH-033'
                ) AND relation = 'verification'
                ORDER BY proof_receipt_id
                """
            ).fetchall()
        ]
        target_evidence_refs = {
            str(row["target_ref"])
            for row in connection.execute(
                """
                SELECT target_ref
                FROM assessment_finding_links
                WHERE finding_id = (
                    SELECT id FROM assessment_findings WHERE slug = 'CH-033'
                ) AND link_kind = 'evidence' AND retired_at IS NULL
                """
            ).fetchall()
        }
    assert target_proof_receipts_after == target_proof_receipts_before
    assert target_evidence_refs == {
        "tools/analysis-state/live-target.json",
        "tools/analysis-state/suppressed-duplicate.json",
    }

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    by_slug = {item["slug"]: item for item in findings.json()}
    assert by_slug["CH-033"]["workflow_status"] == "active"
    assert by_slug["CH-033"]["verification_status"] == "confirmed"
    assert by_slug["CH-032"]["workflow_status"] == "merged"
    assert by_slug["CH-032"]["verification_status"] == "false_positive"


def test_findings_verify_downgrade_records_previous_severity_transition(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-040",
            "title": "Privilege escalation via export endpoint",
            "severity": "critical",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "access-control",
            "root_cause_key": "export-privesc",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/export",
            "summary": "Privilege escalation path needs verification.",
            "evidence_ref": "tools/analysis-state/export.json",
            "notes": "Initial hunt output.",
            "source_name": "vulnerability-analyst",
            "details": {
                "evidence": "Role claim appears attacker-controlled.",
                "impact": "Potential admin export access.",
            },
            "provenance": {
                **_author_provenance(client, "CH-040"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    verified = _verify_with_fixture_proof(
        client,
        "CH-040",
        {
            "verification_status": "downgraded",
            "new_severity": "high",
            "reason_code": "limited-scope",
            "reason_text": "The export bug is real but constrained to project-scoped data.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-040.json",
            "evidence_ref": "tools/analysis-state/code-verification/CH-040.json",
            "notes": "Severity reduced after tracing authorization boundaries.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Project scoping check limits the blast radius.",
                "impact": "Unauthorized project export, not full admin compromise.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert verified.status_code == 200
    payload = verified.json()
    assert payload["finding"]["severity"] == "high"
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_status"] == "downgraded"
    assert payload["transition"]["action"] == "verified_downgraded"

    transitions = client.get(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-040/transitions"
    )
    assert transitions.status_code == 200
    latest = transitions.json()[0]
    assert latest["from_severity"] == "critical"
    assert latest["to_severity"] == "high"
    assert json.loads(latest["metadata_json"])["previous_severity"] == "critical"


def test_verify_downgrade_can_audit_an_already_lowered_severity(
    client, isolate_settings
):
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment/findings"
    created = client.post(
        base,
        json={
            "slug": "CH-140",
            "title": "Pre-lowered finding",
            "severity": "critical",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "access-control",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/prelowered",
                "summary": "Needs a recorded downgrade verdict.",
                "source_name": "vulnerability-analyst",
                "provenance": _author_provenance(client, "CH-140"),
        },
    )
    assert created.status_code == 201, created.text
    lowered = client.patch(
        f"{base}/CH-140",
        json={"severity": "high", "reason_text": "Pre-lowered by analyst."},
    )
    assert lowered.status_code == 200, lowered.text

    verified = _verify_with_fixture_proof(
        client,
        "CH-140",
        {
            "verification_status": "downgraded",
            "new_severity": "high",
            "reason_text": "Record the already-applied downgrade.",
            "source_name": "code-vuln-verifier",
        },
    )

    assert verified.status_code == 200, verified.text
    payload = verified.json()
    assert payload["finding"]["verification_status"] == "downgraded"
    assert payload["finding"]["severity"] == "high"
    assert json.loads(payload["transition"]["metadata_json"])["prelowered"] is True


def test_verify_downgrade_rejects_equal_severity_without_prior_lowering(
    client, isolate_settings
):
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment/findings"
    created = client.post(
        base,
        json={
            "slug": "CH-142",
            "title": "Never lowered",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "access-control",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/not-lowered",
            "summary": "An equal severity is not a downgrade.",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "CH-142"),
        },
    )
    assert created.status_code == 201, created.text

    verified = _verify_with_fixture_proof(
        client,
        "CH-142",
        {
            "verification_status": "downgraded",
            "new_severity": "high",
            "reason_text": "This must not manufacture a downgrade.",
            "source_name": "code-vuln-verifier",
        },
    )

    assert verified.status_code == 400
    assert "prior severity-lowering transition" in verified.json()["detail"]


def test_finding_update_source_name_is_actor_not_discovery_attribution(
    client, isolate_settings
):
    write_engagement(isolate_settings["engagements_dir"])
    base = "/engagements/2026-03-30-120000-example/assessment/findings"
    created = client.post(
        base,
        json={
            "slug": "CH-141",
            "title": "Attribution stays stable",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "metadata",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Discovery attribution is immutable on patch.",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(client, "CH-141"),
        },
    )
    assert created.status_code == 201, created.text

    updated = client.patch(
        f"{base}/CH-141",
        json={
            "summary": "Repaired by a later operator.",
            "source_name": "lifecycle-repair-agent",
            "reason_text": "Repair narrative only.",
        },
    )

    assert updated.status_code == 200, updated.text
    assert updated.json()["finding"]["source_name"] == "vulnerability-analyst"


def test_findings_verify_disputed_keeps_finding_live(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-041",
            "title": "Ambiguous parser state confusion",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "state-confusion",
            "root_cause_key": "parser-state-confusion",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/src/parser.c?line=411",
            "summary": "Verifier could not conclusively settle exploitability.",
            "evidence_ref": "tools/analysis-state/parser-state.json",
            "notes": "Needs further operator review.",
            "source_name": "code-vuln-hunter",
            "details": {
                "evidence": "State machine enters the suspicious branch with malformed input.",
                "impact": "Potential parse confusion with unclear reachability.",
            },
            "provenance": {
                **_author_provenance(client, "CH-041"),
                "agent_name": "code-vuln-hunter",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    disputed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/CH-041/verify",
        json={
            "verification_status": "disputed",
            "reason_code": "conflicting-evidence",
            "reason_text": "Reachability differs between the static trace and runtime evidence.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-041.json",
            "notes": "Escalated for operator review.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Static path exists, but runtime repro did not reach the sink.",
                "impact": "Exploitability remains disputed.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )
    assert disputed.status_code == 200
    payload = disputed.json()
    assert payload["finding"]["workflow_status"] == "active"
    assert payload["finding"]["verification_status"] == "disputed"
    assert payload["transition"]["action"] == "verification_disputed"

    report_findings = client.get("/engagements/2026-03-30-120000-example/assessment/report-findings")
    assert report_findings.status_code == 200
    assert all(item["slug"] != "CH-041" for item in report_findings.json()["standalone"])


def test_findings_verify_rejects_records_merged_after_validation(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    created = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "CH-042",
            "title": "Verify/merge race candidate",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "verify-merge-race",
            "auth_context": "user",
            "canonical_location": "https://example.com/api/export",
            "summary": "Verify should fail if the finding is merged after validation.",
            "evidence_ref": "findings.md",
            "notes": "Created for stale verify race coverage.",
            "source_name": "code-vuln-hunter",
            "details": {"evidence": "Export endpoint skips tenant check", "impact": "Cross-tenant export"},
            "provenance": {
                **_author_provenance(client, "CH-042"),
                "agent_name": "code-vuln-hunter",
            },
            "links": [],
        },
    )
    assert created.status_code == 201

    from app.services import state_manager

    original_patch_finding = state_manager.patch_finding
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"

    def race(*args, **kwargs):
        with sqlite3.connect(str(db_path)) as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                    SET status = 'merged',
                        merged_into_finding_id = id,
                        row_version = row_version + 1,
                        updated_at = '2099-01-01 00:00:00'
                WHERE slug = 'CH-042'
                """
            )
            connection.commit()
        return original_patch_finding(*args, **kwargs)

    monkeypatch.setattr(state_manager.findings, "patch_finding", race)

    verify = _verify_with_fixture_proof(
        client,
        "CH-042",
        {
            "verification_status": "confirmed",
            "reason_code": "validated",
            "reason_text": "Late verify should not overwrite a merged finding.",
            "artifact_ref": "tools/analysis-state/code-verification/CH-042.json",
            "evidence_ref": "tools/analysis-state/code-verification/CH-042.json",
            "notes": "Verification raced with a merge.",
            "source_name": "code-vuln-verifier",
            "details": {
                "evidence": "Tenant check is bypassable with crafted export ids.",
                "impact": "Cross-tenant export remains reachable.",
            },
            "provenance": {"verified_by": "code-vuln-verifier"},
        },
    )

    assert verify.status_code == 409
    assert "changed since it was loaded" in verify.json()["detail"]


def test_findings_verify_rejects_merged_records(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    source = _record_terminal_finding(
        client,
        {
            "slug": "CH-050",
            "title": "Merged source",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merged-source",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Source finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "source evidence", "impact": "source impact"},
            "provenance": {
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert source.status_code == 200

    target = _record_terminal_finding(
        client,
        {
            "slug": "CH-051",
            "title": "Merge target",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/target",
            "summary": "Target finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge test.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "target evidence", "impact": "target impact"},
            "provenance": {
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert target.status_code == 200

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-050",
            "target_slug": "CH-051",
            "reason": "Merged duplicate.",
            "source_name": "operator",
            "expected_source_row_version": source.json()["finding"]["row_version"],
            "expected_target_row_version": target.json()["finding"]["row_version"],
        },
    )
    assert merge.status_code == 200

    verify = _verify_with_fixture_proof(
        client,
        "CH-050",
        {
            "verification_status": "confirmed",
            "reason_text": "Should not revive merged finding.",
            "source_name": "code-vuln-verifier",
            "details": {"evidence": "n/a", "impact": "n/a"},
        },
    )
    assert verify.status_code == 400
    assert "merged findings cannot be re-verified" in verify.json()["detail"]


def test_merge_findings_rejects_target_changed_after_snapshot(client, isolate_settings, monkeypatch):
    write_engagement(isolate_settings["engagements_dir"])

    source = _record_terminal_finding(
        client,
        {
            "slug": "CH-052",
            "title": "First duplicate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-race-source",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/source",
            "summary": "Source finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "source evidence", "impact": "source impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert source.status_code == 200

    target = _record_terminal_finding(
        client,
        {
            "slug": "CH-053",
            "title": "Second duplicate",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "merge-race-target",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/target",
            "summary": "Target finding before merge.",
            "evidence_ref": "findings.md",
            "notes": "Created for merge race coverage.",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "target evidence", "impact": "target impact"},
            "provenance": {"agent_name": "vulnerability-analyst"},
            "links": [],
        },
    )
    assert target.status_code == 200

    from app.services import state_manager

    original_append_notes = state_manager._append_notes
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    injected = False

    def race(existing: str, incoming: str) -> str:
        nonlocal injected
        if not injected and incoming.startswith("Merged CH-052"):
            injected = True
            with sqlite3.connect(str(db_path)) as connection:
                connection.execute(
                    """
                    UPDATE assessment_findings
                        SET notes = notes || '\nConcurrent merge writer',
                            row_version = row_version + 1,
                            updated_at = '2099-01-01 00:00:00'
                    WHERE slug = 'CH-053'
                    """
                )
                connection.commit()
        return original_append_notes(existing, incoming)

    monkeypatch.setattr(state_manager._common, "_append_notes", race)

    merge = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/merge",
        json={
            "source_slug": "CH-052",
            "target_slug": "CH-053",
            "reason": "Stale merge should not overwrite a concurrently updated target.",
            "source_name": "operator",
        },
    )

    assert merge.status_code == 409
    assert "changed since it was loaded" in merge.json()["detail"]


def test_coverage_patch_rejects_unknown_status_values(client, isolate_settings):
    write_engagement(isolate_settings["engagements_dir"])

    ingest = client.post(
        "/engagements/2026-03-30-120000-example/assessment/request-observations",
        json={"url": "https://example.com/profile", "discovery_source": "recon"},
    )
    assert ingest.status_code == 201

    coverage_items = client.get("/engagements/2026-03-30-120000-example/assessment/coverage-items")
    assert coverage_items.status_code == 200
    coverage_item_id = coverage_items.json()[0]["id"]

    patch = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/coverage-items/{coverage_item_id}",
        json={"status": "complete-ish", "notes": "bad status"},
    )
    assert patch.status_code == 400
    assert "invalid coverage status" in patch.json()["detail"]


def test_incompatible_local_database_refuses_to_start_and_preserves_file(isolate_settings):
    """Auto-reset was removed: an incompatible DB must raise, never be unlinked.

    Silently deleting the orchestrator DB on a schema mismatch is unrecoverable
    data loss (findings, probe runs, command runs, code analysis). The
    orchestrator now refuses to start and tells the operator how to resolve.
    """
    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT)")
        connection.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                event_type TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE assessment_attack_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                chain_key TEXT NOT NULL
            )
            """
        )
        connection.commit()

    with pytest.raises(db_module.IncompatibleDatabaseError) as exc:
        db_module.init_db()
    message = str(exc.value)
    assert "Refusing to start" in message
    assert "delete engagement history" in message

    assert db_path.exists(), "incompatible DB must NOT be unlinked"
    with sqlite3.connect(str(db_path)) as connection:
        table_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "runs" in table_names, "legacy table must still be present after refuse"
        event_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(events)").fetchall()
        }
        assert "run_id" in event_columns, "legacy column must still be present after refuse"


def test_filesystem_engagement_removal_retains_db_row(client, isolate_settings):
    """Sync must NOT cascade-delete findings when an engagement directory
    vanishes. The old behavior silently wiped every finding/probe/command-run
    when the operator renamed, archived, or cleaned up an engagement dir.
    Deletion is now explicit — via ``DELETE /engagements/{key}`` — and this
    test exists to lock the additive-only sync contract in place.
    """
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements")
    assert response.status_code == 200
    assert len(response.json()) == 1

    for path in sorted(engagement_dir.rglob("*"), reverse=True):
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            path.rmdir()
    engagement_dir.rmdir()

    response = client.get("/engagements")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) == 1, "DB row must survive filesystem removal"
    assert rows[0]["key"] == "2026-03-30-120000-example"


def test_deleted_session_is_pruned_from_database(client, isolate_settings):
    engagement_dir = write_engagement(isolate_settings["engagements_dir"])

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert len(response.json()) == 1

    (engagement_dir / "sessions" / "index.json").write_text("[]\n", encoding="utf-8")

    response = client.get("/engagements/2026-03-30-120000-example/sessions")
    assert response.status_code == 200
    assert response.json() == []


def _all_report_finding_slugs(report_body: dict) -> set[str]:
    """Flatten a /report-findings group response into the set of slugs it exposes."""
    slugs: set[str] = set()
    for record in report_body.get("standalone", []):
        if record.get("slug"):
            slugs.add(record["slug"])
    for group in report_body.get("groups", []):
        root = group.get("root") or {}
        if root.get("slug"):
            slugs.add(root["slug"])
        for sibling in group.get("siblings", []):
            if sibling.get("slug"):
                slugs.add(sibling["slug"])
    return slugs


def test_pending_runtime_proof_absent_from_draft_report_findings(client, isolate_settings):
    # Regression: the draft report projection (mode=draft, the default, which feeds
    # `vigil engagement export --format markdown-tree`) used to filter only
    # `verification_status == "disputed"`. A pending_runtime_proof finding likewise
    # leaked into draft reports despite being a
    # non-durable HOLDING finding. Draft must now exclude it exactly like `final` does.
    write_engagement(isolate_settings["engagements_dir"])

    # A genuinely confirmed finding that MUST remain in the draft projection.
    confirmed = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-070",
            "title": "Confirmed durable finding",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "confirmed-durable",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/confirmed",
            "summary": "Proven and durable.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "account takeover"},
            "provenance": {
                **_author_provenance(client, "VA-070"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert confirmed.status_code == 201
    confirmed_verify = _verify_with_fixture_proof(
        client,
        "VA-070",
        {
            "verification_status": "confirmed",
            "reason_code": "runtime-proven",
            "reason_text": "Runtime PoC reproduced.",
            "source_name": "vulnerability-analyst",
            "evidence_ref": "findings.md",
        },
    )
    assert confirmed_verify.status_code == 200

    # A strong-but-unproven HOLDING finding that MUST be excluded from the report.
    held = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-071",
            "title": "Held finding pending runtime proof",
            "severity": "high",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "held-pending-runtime",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/held-report",
            "summary": "Strong static evidence, runtime proof outstanding.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "pending runtime"},
            "provenance": {
                **_author_provenance(client, "VA-071"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert held.status_code == 201
    held_verify = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-071/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static evidence accepted; runtime proof outstanding.",
            "source_name": "vulnerability-analyst",
            "evidence_ref": "findings.md",
        },
    )
    assert held_verify.status_code == 200
    assert held_verify.json()["finding"]["verification_status"] == "pending_runtime_proof"

    # Default mode is draft (the markdown-tree source).
    draft = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=draft"
    )
    assert draft.status_code == 200
    draft_slugs = _all_report_finding_slugs(draft.json())
    assert "VA-071" not in draft_slugs, draft.json()
    assert "VA-070" in draft_slugs, draft.json()
    # Exactly one durable finding survives the draft projection.
    assert draft.json()["finding_count"] == 1, draft.json()

    # The implicit default (no mode param) must match explicit draft.
    default = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings"
    )
    assert default.status_code == 200
    assert _all_report_finding_slugs(default.json()) == draft_slugs


def test_markdown_tree_draft_projection_excludes_pending_runtime_proof(client, isolate_settings):
    # The markdown-tree exporter joins each on-disk finding against the draft
    # report projection by slug (report_by_slug). A pending_runtime_proof finding
    # must be ABSENT from that projection so the exporter renders it with the
    # "not included in the current report projection" fallback rather than as a
    # durable report finding. This guards the exact data the CLI consumes.
    write_engagement(isolate_settings["engagements_dir"])

    held = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json={
            "slug": "VA-072",
            "title": "Held finding for markdown-tree projection",
            "severity": "critical",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "auth-bypass",
            "root_cause_key": "held-markdown-tree",
            "auth_context": "anonymous",
            "canonical_location": "https://example.com/held-tree",
            "summary": "Held; must fall back in markdown-tree.",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "details": {"evidence": "code review", "impact": "pending runtime"},
            "provenance": {
                **_author_provenance(client, "VA-072"),
                "agent_name": "vulnerability-analyst",
            },
            "links": [],
        },
    )
    assert held.status_code == 201
    held_verify = client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings/VA-072/verify",
        json={
            "verification_status": "pending_runtime_proof",
            "reason_code": "static-accepted",
            "reason_text": "Static evidence accepted; runtime proof outstanding.",
            "source_name": "vulnerability-analyst",
            "evidence_ref": "findings.md",
        },
    )
    assert held_verify.status_code == 200

    # The held finding still exists in the raw finding list the exporter iterates...
    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    assert findings.status_code == 200
    assert any(item["slug"] == "VA-072" for item in findings.json())

    # ...but is excluded from the draft report projection it joins against, so the
    # exporter's report_by_slug.get("VA-072") returns None -> fallback note path.
    draft = client.get(
        "/engagements/2026-03-30-120000-example/assessment/report-findings?mode=draft"
    )
    assert draft.status_code == 200
    assert "VA-072" not in _all_report_finding_slugs(draft.json()), draft.json()
    assert draft.json()["finding_count"] == 0, draft.json()


# ──────────────────────────────────────────────────────────────
# CR-31 — concurrent slug atomicity, details-replace, clear-disputed
# ──────────────────────────────────────────────────────────────


def _record_va_finding(
    client,
    *,
    location: str,
    summary: str,
    details: dict | None = None,
    author_key: str | None = None,
):
    """POST an auto-slugged VA finding (no explicit slug -> backend allocates)."""
    body = {
        "title": f"Auto-slug finding {location}",
        "severity": "medium",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        # Distinct canonical_location per call so _semantic_finding_match does
        # NOT dedup them onto one row — each must mint its own slug.
        "canonical_location": location,
        "summary": summary,
        "evidence_ref": "findings.md",
        "source_name": "vulnerability-analyst",
    }
    if details is not None:
        body["details"] = details
    body["provenance"] = _author_provenance(client, author_key or location)
    return client.post(
        "/engagements/2026-03-30-120000-example/assessment/findings",
        json=body,
    )


def test_concurrent_record_finding_allocates_distinct_sequential_slugs(client, isolate_settings):
    """CR-31(a): N parallel record-finding writes against one engagement must each
    receive a distinct sequential VA-### slug with zero UNIQUE-constraint 500s. The
    (engagement_id, slug) UNIQUE backstop + BEGIN IMMEDIATE serialization +
    insert-retry guarantee two lanes can never both land VA-012."""
    from concurrent.futures import ThreadPoolExecutor

    write_engagement(isolate_settings["engagements_dir"])
    # Force engagement-row discovery before the fan-out so the threads don't race
    # the first-touch creation.
    assert client.get("/engagements/2026-03-30-120000-example").status_code == 200

    n = 12

    def _post(i: int):
        return _record_va_finding(
            client,
            location=f"https://example.com/concurrent/{i}",
            summary=f"Concurrent lane {i}.",
        )

    with ThreadPoolExecutor(max_workers=n) as pool:
        responses = list(pool.map(_post, range(n)))

    statuses = [r.status_code for r in responses]
    assert all(s == 201 for s in statuses), (
        f"all concurrent records must succeed; got {statuses} "
        f"-> {[r.text for r in responses if r.status_code != 201]}"
    )
    slugs = sorted(r.json()["finding"]["slug"] for r in responses)
    # All distinct (no duplicate slug minted under the race).
    assert len(set(slugs)) == n, f"duplicate slug allocated under concurrency: {slugs}"
    # All canonical VA-### and contiguous 001..n (sequential allocation held).
    assert slugs == [f"VA-{i:03d}" for i in range(1, n + 1)], slugs


def test_patch_finding_details_replace_overwrites_stale_keys(client, isolate_settings):
    """CR-31(c): details_mode='replace' overwrites the whole details object so
    cross-contaminated/stale keys are removed; the default 'merge' accretes."""
    write_engagement(isolate_settings["engagements_dir"])

    created = _record_va_finding(
        client,
        location="https://example.com/details/replace",
        summary="Details replace target.",
        details={"attempts_summary": "leaked-from-other-lane", "impact": "original"},
    )
    assert created.status_code == 201, created.text
    slug = created.json()["finding"]["slug"]

    # Default merge: a new key accretes, prior keys survive.
    merged = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}",
        json={"details": {"entry_point": "by-merge"}},
    )
    assert merged.status_code == 200, merged.text

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    row = next(item for item in findings.json() if item["slug"] == slug)
    merged_details = row["details"]
    assert merged_details.get("attempts_summary") == "leaked-from-other-lane"
    assert merged_details.get("entry_point") == "by-merge"

    # Replace: only the supplied keys remain; attempts_summary is GONE (merge
    # could never delete it).
    replaced = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}",
        json={
            "details": {"sink": "rewritten"},
            "details_mode": "replace",
            "expected_row_version": 2,
        },
    )
    assert replaced.status_code == 200, replaced.text

    findings = client.get("/engagements/2026-03-30-120000-example/assessment/findings")
    row = next(item for item in findings.json() if item["slug"] == slug)
    replaced_details = row["details"]
    assert replaced_details == {"sink": "rewritten"}, replaced_details
    assert "attempts_summary" not in replaced_details
    assert "impact" not in replaced_details


def test_patch_finding_details_replace_without_details_rejected(client, isolate_settings):
    """CR-31(c): replace without a details payload would null the column -> 422
    (model validator) rather than silent data loss."""
    write_engagement(isolate_settings["engagements_dir"])

    created = _record_va_finding(
        client,
        location="https://example.com/details/guard",
        summary="Replace guard.",
        details={"impact": "me"},
    )
    assert created.status_code == 201, created.text
    slug = created.json()["finding"]["slug"]

    bad = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}",
        json={"details_mode": "replace", "notes": "no details supplied"},
    )
    assert bad.status_code == 422, bad.text


def _make_disputed(client, *, location: str, summary: str) -> str:
    created = _record_va_finding(
        client,
        location=location,
        summary=summary,
        author_key="DISPUTED",
    )
    assert created.status_code == 201, created.text
    slug = created.json()["finding"]["slug"]
    disputed = client.post(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}/verify",
        json={
            "verification_status": "disputed",
            "reason_code": "contested",
            "reason_text": "Two lanes disagree on whether this reproduces.",
            "source_name": "code-vuln-verifier",
        },
    )
    assert disputed.status_code == 200, disputed.text
    assert disputed.json()["finding"]["verification_status"] == "disputed"
    return slug


def test_verify_finding_confirmed_clears_disputed(client, isolate_settings):
    """CR-31(b): the verifier re-issuing verify-finding --disposition confirmed
    clears a prior disputed verdict (lands verified/confirmed)."""
    write_engagement(isolate_settings["engagements_dir"])
    slug = _make_disputed(
        client,
        location="https://example.com/disputed/verify",
        summary="Disputed then confirmed.",
    )

    confirmed = _verify_with_fixture_proof(
        client,
        slug,
        {
            "verification_status": "confirmed",
            "reason_code": "reproduced",
            "reason_text": "Re-ran the PoC; it reproduces deterministically.",
            "source_name": "code-vuln-verifier",
        },
    )
    assert confirmed.status_code == 200, confirmed.text
    finding = confirmed.json()["finding"]
    assert finding["verification_status"] == "confirmed"


def test_reset_finding_clears_disputed_to_unreviewed(client, isolate_settings):
    """CR-31(b): a specialist can re-queue a disputed finding via reset-finding
    (PATCH with a workflow reopen) -> verification returns to unreviewed/none
    without forcing a verdict, and a verification_recleared transition is recorded."""
    write_engagement(isolate_settings["engagements_dir"])
    slug = _make_disputed(
        client,
        location="https://example.com/disputed/reset",
        summary="Disputed then re-queued.",
    )

    # reset-finding sends a workflow_status reopen (default "draft") + reason.
    reset = client.patch(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}",
        json={
            "workflow_status": "draft",
            "reason_text": "Re-queue for a fresh verification pass.",
            "source_name": "vulnerability-analyst",
        },
    )
    assert reset.status_code == 200, reset.text
    finding = reset.json()["finding"]
    assert finding["verification_status"] == "unreviewed", finding

    transitions = client.get(
        f"/engagements/2026-03-30-120000-example/assessment/findings/{slug}/transitions"
    )
    assert transitions.status_code == 200
    actions = [item["action"] for item in transitions.json()]
    assert "verification_recleared" in actions, actions
def test_finding_row_version_increments_on_each_same_second_patch(client, isolate_settings):
    engagement_key = "2026-07-14-finding-row-version"
    write_engagement(isolate_settings["engagements_dir"], engagement_key)
    response = client.post(
        f"/engagements/{engagement_key}/assessment/findings",
        json={
            "slug": "VA-910",
            "title": "Versioned finding",
            "severity": "medium",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "canonical_location": "https://example.com/versioned",
            "summary": "initial",
            "evidence_ref": "findings.md",
            "source_name": "vulnerability-analyst",
            "provenance": _author_provenance(
                client, "VA-910", key=engagement_key
            ),
        },
    )
    assert response.status_code == 201, response.text
    created = response.json()["finding"]
    assert created["row_version"] == 1

    first = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/VA-910",
        json={"summary": "first mutation"},
    )
    second = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/VA-910",
        json={"summary": "second mutation"},
    )
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    assert first.json()["finding"]["row_version"] == 2
    assert second.json()["finding"]["row_version"] == 3

    stale = client.patch(
        f"/engagements/{engagement_key}/assessment/findings/VA-910",
        json={"summary": "stale mutation", "expected_row_version": 1},
    )
    assert stale.status_code == 409
    assert "changed since it was loaded" in stale.json()["detail"]
