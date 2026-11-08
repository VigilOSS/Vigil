"""Collection reads preserve point-read facts without per-finding evidence I/O."""
from __future__ import annotations

import importlib
import hashlib
import json
from pathlib import Path

from app import db
from app.services.state_manager import findings
from app.services.state_manager import proofs
from tests.test_finding_code_snapshot_provenance import _verification_receipt
from tests.test_report_readiness_evidence_basis import _engagement_id, _recorded

report_readiness = importlib.import_module("app.services.state_manager.report_readiness")


def _cloned_findings(client, isolate_settings, count=32, *, parked=False):
    _recorded(client, isolate_settings, "VA-501")
    with db.get_connection() as connection:
        row = dict(connection.execute("SELECT * FROM assessment_findings LIMIT 1").fetchone())
        if parked:
            connection.execute("UPDATE assessment_findings SET verification_status='pending_runtime_proof'")
            row["verification_status"] = "pending_runtime_proof"
        columns = [name for name in row if name != "id"]
        for index in range(1, count):
            row["slug"] = f"VA-{index + 600}"
            connection.execute(
                "INSERT INTO assessment_findings (" + ",".join(columns) + ") VALUES ("
                + ",".join("?" for _ in columns) + ")",
                [row[name] for name in columns],
            )
    return _engagement_id()


def test_finding_list_evidence_queries_are_bounded_by_the_read_not_row_count(client, isolate_settings):
    engagement_id = _cloned_findings(client, isolate_settings)
    with db.get_connection() as connection:
        queries = []
        connection.set_trace_callback(queries.append)
        try:
            rows = findings.list_findings(engagement_id, limit=32)
        finally:
            connection.set_trace_callback(None)
    assert len(rows) == 32
    assert len(queries) < 10, len(queries)
    for row in rows:
        point = findings.get_finding(engagement_id, row["slug"])
        for field in ("proof_receipts", "next_test", "reproduction_basis", "code_snapshot_status"):
            assert row[field] == point[field]


def test_parked_findings_read_current_plans_together(client, isolate_settings):
    engagement_id = _cloned_findings(client, isolate_settings, parked=True)
    with db.get_connection() as connection:
        queries = []
        connection.set_trace_callback(queries.append)
        try:
            rows = findings.list_findings(engagement_id, limit=32)
        finally:
            connection.set_trace_callback(None)
    assert all(row["next_test"] is None for row in rows)
    assert len(queries) < 10, len(queries)


def test_report_candidates_read_receipt_basis_in_one_collection(client, isolate_settings):
    engagement_id = _cloned_findings(client, isolate_settings)
    with db.get_connection() as connection:
        queries = []
        connection.set_trace_callback(queries.append)
        try:
            rows = report_readiness._report_candidate_records(engagement_id)
        finally:
            connection.set_trace_callback(None)
    assert len(rows) == 32
    assert len(queries) < 8, len(queries)


def test_shared_evidence_is_attested_once_per_read_but_again_on_next_read(
    client, isolate_settings, monkeypatch
):
    engagement_id = _cloned_findings(client, isolate_settings, count=1)
    receipt_id = _verification_receipt(client, "cvv-va-501", "VA-501")
    observed = []
    original = proofs.artifact_index.registered_snapshot_evidence_health

    def checked(*args, **kwargs):
        observed.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(proofs.artifact_index, "registered_snapshot_evidence_health", checked)
    with db.get_connection() as connection:
        raw = proofs._receipt_row(connection, engagement_id, receipt_id)
        records = proofs._serialize_receipts(connection, engagement_id, [raw, raw])
        assert all(row["evidence_health"] == "healthy" for row in records)
        assert len(observed) == 1
        root, relative = observed[0]
        (root / relative).write_text("Changed Acme evidence", encoding="utf-8")
        again = proofs._serialize_receipts(connection, engagement_id, [raw, raw])
        assert all(row["evidence_health"] == "stale" for row in again)
        assert len(observed) == 2


def test_collection_json_encoding_does_not_run_on_the_event_loop(
    client, isolate_settings, monkeypatch
):
    import asyncio

    from pydantic import TypeAdapter
    from tests.test_report_readiness_evidence_basis import BASE

    _cloned_findings(client, isolate_settings, count=3)
    encoded_on_event_loop = []
    original = TypeAdapter.dump_json

    def observed(adapter, value, *args, **kwargs):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            encoded_on_event_loop.append(False)
        else:
            encoded_on_event_loop.append(True)
        return original(adapter, value, *args, **kwargs)

    monkeypatch.setattr(TypeAdapter, "dump_json", observed)
    for path in ("findings?limit=3", "report-readiness"):
        response = client.get(f"{BASE}/{path}")
        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/json"
    assert encoded_on_event_loop
    assert not any(encoded_on_event_loop), encoded_on_event_loop


def _shared_proof_findings(client, isolate_settings, count=300):
    """A large ledger whose current decisions cite the same sizeable snapshot."""
    engagement_id = _cloned_findings(client, isolate_settings, count=count)
    receipt_id = _verification_receipt(client, "cvv-va-501", "VA-501")
    content = b"Acme source observation\n" * 90000
    digest = hashlib.sha256(content).hexdigest()
    with db.get_connection() as connection:
        artifact = connection.execute(
            "SELECT artifacts.*, engagements.engagement_root "
            "FROM assessment_artifacts AS artifacts "
            "JOIN engagements ON engagements.id=artifacts.engagement_id "
            "JOIN assessment_proof_receipts AS receipts ON receipts.artifact_id=artifacts.id "
            "WHERE receipts.id=?", (receipt_id,),
        ).fetchone()
        (Path(artifact["engagement_root"]) / artifact["relative_path"]).write_bytes(content)
        connection.execute(
            "UPDATE assessment_artifacts SET size_bytes=?, sha256=? WHERE id=?",
            (len(content), digest, artifact["id"]),
        )
        connection.execute(
            "UPDATE assessment_proof_receipts SET evidence_sha256=? WHERE id=?",
            (digest, receipt_id),
        )
        details = json.dumps({"evidence": [{"source": "file:src/parser.c:41",
                                            "observation": "Acme source observation"}] * 20})
        connection.execute("UPDATE assessment_findings SET details_json=?", (details,))
        for finding in connection.execute("SELECT id FROM assessment_findings").fetchall():
            transition = connection.execute(
                "INSERT INTO assessment_finding_transitions "
                "(engagement_id, finding_id, to_verification_status) VALUES (?, ?, 'unreviewed')",
                (engagement_id, finding["id"]),
            ).lastrowid
            connection.execute(
                "INSERT INTO assessment_finding_proof_receipts "
                "(engagement_id, finding_id, transition_id, proof_receipt_id) VALUES (?, ?, ?, ?)",
                (engagement_id, finding["id"], transition, receipt_id),
            )
    return engagement_id


def test_six_large_ledger_reads_leave_readiness_responsive_and_preserve_evidence(
    client, isolate_settings, monkeypatch
):
    import asyncio
    import threading

    import httpx
    from app.main import app
    from tests.test_report_readiness_evidence_basis import BASE

    _shared_proof_findings(client, isolate_settings)
    entered = threading.Event()
    release = threading.Event()
    original = proofs.artifact_index.registered_snapshot_evidence_health
    calls = []

    def attested(*args, **kwargs):
        calls.append(1)
        entered.set()
        assert release.wait(timeout=5), "The responsive event loop must release pending readers"
        return original(*args, **kwargs)

    monkeypatch.setattr(proofs.artifact_index, "registered_snapshot_evidence_health", attested)

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://acme.example") as reader:
            lanes = [asyncio.create_task(reader.get(f"{BASE}/findings?limit=300"))
                     for _ in range(6)]
            try:
                assert await asyncio.to_thread(entered.wait, 5)
                ready = await asyncio.wait_for(reader.get("/readyz"), timeout=2)
                assert ready.status_code == 200, ready.text
            finally:
                release.set()
            responses = await asyncio.wait_for(asyncio.gather(*lanes), timeout=10)
        for response in responses:
            assert response.status_code == 200, response.text
            rows = response.json()
            assert len(rows) == 300
            assert all(row["reproduction_basis"] == "source" for row in rows)
            assert all(row["proof_receipts"][0]["evidence_health"] == "healthy" for row in rows)
            assert all(len(row["details"]["evidence"]) == 20 for row in rows)

    asyncio.run(check())
    assert len(calls) == 6, "Each concurrent read must attest shared evidence for itself"


def test_mixed_ledger_reads_and_heartbeats_finish_with_a_stalled_browser(client, isolate_settings):
    import asyncio

    import httpx
    from app.main import app
    from app.ws import broadcaster
    from tests.test_code_queue_path_scope import _seed
    from tests.test_report_readiness_evidence_basis import BASE
    from tests.test_ws_delivery_isolation import Socket

    _shared_proof_findings(client, isolate_settings)
    queue_key = "2026-11-08-acme-mixed-lanes"
    queue_base, _, _ = _seed(client, isolate_settings, queue_key)
    claims = []
    for index in range(3):
        owner = f"acme-lane-{index}"
        response = client.post(f"{queue_base}/analysis-queue/fetch",
                               json={"limit": 1, "agent_name": owner})
        assert response.status_code == 200, response.text
        claim = response.json()[0]
        claims.append({"item_id": claim["id"], "agent_name": owner,
                       "lease_token": claim["lease_token"]})

    async def check():
        slow = Socket(blocked=True)
        await broadcaster.connect(queue_key, slow)
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="http://acme.example") as reader:
                async def hunt_read():
                    for _ in range(3):
                        response = await reader.get(f"{BASE}/findings?limit=300")
                        assert response.status_code == 200, response.text
                        assert len(response.json()) == 300

                async def heartbeat(claim):
                    for _ in range(10):
                        response = await reader.post(f"{queue_base}/analysis-queue/heartbeat",
                                                     json=claim)
                        assert response.status_code == 200, response.text
                        assert response.json()["item_id"] == claim["item_id"]

                lanes = [asyncio.create_task(hunt_read()) for _ in range(3)] + [
                    asyncio.create_task(heartbeat(claim)) for claim in claims
                ]
                try:
                    ready = await asyncio.wait_for(reader.get("/readyz"), timeout=2)
                    assert ready.status_code == 200, ready.text
                    await asyncio.wait_for(asyncio.gather(*lanes), timeout=10)
                finally:
                    for lane in lanes:
                        lane.cancel()
                    await asyncio.gather(*lanes, return_exceptions=True)
            assert not slow.sent
        finally:
            broadcaster.disconnect(queue_key, slow)

    asyncio.run(check())
