"""Backend work-buffer (assessment_work_items) — derivation, atomic claim, verbs.

Exercises ADR 0013: the former per-engagement cases.db work_items queue folded
into the backend ledger, with the work item derived server-side from a
request-observation in one transaction (no dual write) and the dispatch/claim
verbs served over HTTP.
"""
import json

from app import db as db_module
from app.services import state_manager
from app.services.state_manager import _common

ENGAGEMENT_KEY = "2026-07-08-000000-workbuf"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _seed(client, isolate_settings) -> None:
    eng = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "scope.json").write_text(
        json.dumps({"engagement_name": "WorkBuf", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def _observe(client, *, url, method="GET", case_type="api", **work_item):
    """POST a request-observation carrying a work_item derivation block."""
    wi = {"case_type": case_type, **work_item}
    return client.post(
        f"{BASE}/request-observations",
        json={
            "url": url,
            "method": method,
            "query_schema": {"q": "string"},
            "discovery_source": "test",
            "work_item": wi,
        },
    )


def test_observation_derives_one_work_item(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = _observe(
        client,
        url="https://app.example/api/users",
        case_type="api",
        priority_score=42,
        priority_reason="api endpoint",
        cluster_key="gf:trust_surface",
        classifier_version="v-test",
        source="ingest-endpoints",
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["work_item"] is not None
    wi = body["work_item"]
    assert wi["type"] == "api"
    assert wi["priority_score"] == 42
    assert wi["cluster_key"] == "gf:trust_surface"
    assert wi["status"] == "pending"
    assert wi["request_variant_id"] == body["request_variant"]["id"]
    assert wi["queue_key"] == f"variant:{body['request_variant']['id']}:api"
    assert wi["host"] == "app.example"

    rows = client.get(f"{BASE}/work-items?type=api").json()
    assert len(rows) == 1
    assert rows[0]["url"] == "https://app.example/api/users"


def test_reingest_dedupes_and_refreshes_snapshot(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/x", case_type="api", priority_score=1)
    # Re-ingest same variant → same queue_key → UPSERT, not a second row.
    _observe(
        client,
        url="https://app.example/api/x",
        case_type="api",
        priority_score=9,
        response_status=200,
        response_snippet="hello",
    )
    rows = client.get(f"{BASE}/work-items?type=api").json()
    assert len(rows) == 1
    # Non-manual row: classifier facts refreshed on re-ingest.
    assert rows[0]["priority_score"] == 9
    assert rows[0]["response_status"] == 200
    assert rows[0]["response_snippet"] == "hello"


def test_manual_rows_protected_on_reingest(client, isolate_settings):
    _seed(client, isolate_settings)
    body = _observe(client, url="https://app.example/api/keep", case_type="api", priority_score=5).json()
    wid = body["work_item"]["id"]
    assert client.post(f"{BASE}/work-items/mark-manual", json={"ids": [wid]}).json()["affected"] == 1
    # Re-ingest with a different score must NOT clobber the manual row's score.
    _observe(client, url="https://app.example/api/keep", case_type="api", priority_score=99)
    rows = client.get(f"{BASE}/work-items?type=api").json()
    assert rows[0]["priority_score"] == 5
    assert rows[0]["classifier_version"] == "manual"


def test_fetch_by_priority_claims_top_k_and_routes(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/a", case_type="api", priority_score=10,
             cluster_key="gf:trust_surface")
    _observe(client, url="https://app.example/api/b", case_type="api", priority_score=90,
             cluster_key="gf:trust_surface")
    _observe(client, url="https://app.example/app.js", case_type="javascript", priority_score=50)

    resp = client.post(f"{BASE}/work-items/fetch-by-priority", json={"limit": 1, "agent": "auto"})
    claimed = resp.json()["claimed"]
    assert len(claimed) == 1
    # Highest priority first, routed to the canonical specialist for its type.
    assert claimed[0]["url"] == "https://app.example/api/b"
    assert claimed[0]["assigned_agent"] == "vulnerability-analyst"
    assert claimed[0]["status"] == "processing"

    # A second fetch cannot re-claim the same row (atomic claim).
    again = client.post(f"{BASE}/work-items/fetch-by-priority", json={"limit": 5, "agent": "auto"}).json()["claimed"]
    claimed_urls = {c["url"] for c in again}
    assert "https://app.example/api/b" not in claimed_urls
    # Remaining routable rows get claimed and routed by type.
    by_url = {c["url"]: c for c in again}
    assert by_url["https://app.example/api/a"]["assigned_agent"] == "vulnerability-analyst"
    assert by_url["https://app.example/app.js"]["assigned_agent"] == "source-analyzer"


def test_app_unit_scoring_links_work_items_and_fetch_claims_coherent_unit(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    for i in range(8):
        _observe(
            client,
            url=f"https://app.example/shop/item{i}",
            case_type="api",
            priority_score=90 - i,
            cluster_key="gf:idor",
        )
    for i in range(5):
        _observe(
            client,
            url=f"https://app.example/assets/file{i}.js",
            case_type="javascript",
            priority_score=100,
        )
    engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    state_manager.score_application_units(int(engagement["id"]))

    rows = client.get(f"{BASE}/work-items?status=pending").json()
    assert all(row["application_unit_id"] is not None for row in rows)
    shop_unit = next(
        unit
        for unit in client.get(f"{BASE}/application-units").json()
        if unit["path_prefix"] == "/shop"
    )
    response = client.post(
        f"{BASE}/work-items/fetch-by-unit",
        json={"unit_id": shop_unit["id"], "agent": "auto", "limit": 3},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["unit"]["id"] == shop_unit["id"]
    assert body["effective_limit"] == 3
    assert len(body["claimed"]) == 3
    assert all(row["url_path"].startswith("/shop/") for row in body["claimed"])
    assert all(row["assigned_agent"] == "vulnerability-analyst" for row in body["claimed"])


def test_bare_ev_fetch_selects_highest_unsatisfied_unit_and_derives_limit(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    for i in range(14):
        _observe(
            client,
            url=f"https://app.example/api/order{i}",
            method="POST" if i == 0 else "GET",
            case_type="api",
            priority_score=20,
            cluster_key="gf:trust_surface",
        )
    for i in range(6):
        _observe(
            client,
            url=f"https://app.example/static/f{i}.css",
            case_type="stylesheet",
            priority_score=99,
        )
    engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    state_manager.score_application_units(int(engagement["id"]))

    response = client.post(
        f"{BASE}/work-items/fetch-by-unit",
        json={"agent": "auto", "path": "/api", "work_class": "api"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["selection"] == "highest-ev-unsatisfied"
    assert body["unit"]["path_prefix"] == "/api"
    assert body["effective_limit"] > 0
    assert body["effective_limit_source"] == "depth-tier-and-saturation"
    assert body["claimed"]
    assert all(row["type"] == "api" for row in body["claimed"])


def test_fetch_by_unit_path_treats_sql_wildcards_as_literal(client, isolate_settings):
    _seed(client, isolate_settings)
    for suffix in ("one", "two"):
        _observe(
            client,
            url=f"https://app.example/shop/{suffix}",
            case_type="api",
            priority_score=20,
        )
    engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    state_manager.score_application_units(int(engagement["id"]))

    response = client.post(
        f"{BASE}/work-items/fetch-by-unit",
        json={"agent": "auto", "path": "/shop%", "work_class": "api"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["claimed"] == []
    assert response.json()["error"] == "no-unsatisfied-unit"


def test_fetch_by_unit_serializes_selection_and_claim(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/one", case_type="api", priority_score=20)
    engagement = client.get(f"/engagements/{ENGAGEMENT_KEY}").json()
    state_manager.score_application_units(int(engagement["id"]))
    statements: list[str] = []
    with _common.get_connection() as connection:
        connection.set_trace_callback(statements.append)

    state_manager.fetch_work_items_by_unit(
        int(engagement["id"]),
        unit_id=None,
        path="",
        work_class="api",
        limit=1,
        agent="auto",
    )

    assert any(statement.strip().upper() == "BEGIN IMMEDIATE" for statement in statements)


def test_legacy_work_item_unit_column_migration_keeps_foreign_key(
    client, isolate_settings
):
    _seed(client, isolate_settings)
    with _common.get_connection() as connection:
        connection.execute("DROP TABLE assessment_work_items")
        connection.execute(
            """
            CREATE TABLE assessment_work_items (
                id INTEGER PRIMARY KEY,
                engagement_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                type TEXT NOT NULL DEFAULT 'unknown',
                priority_score INTEGER NOT NULL DEFAULT 0,
                cluster_key TEXT,
                consumed_at TEXT,
                host TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT ''
            )
            """
        )
        db_module._create_assessment_work_items_table(connection)
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(assessment_work_items)"
        ).fetchall()

    assert any(
        row["from"] == "application_unit_id"
        and row["table"] == "assessment_application_units"
        and row["on_delete"] == "SET NULL"
        for row in foreign_keys
    )


def test_fetch_by_type_and_done(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/one", case_type="api")
    _observe(client, url="https://app.example/api/two", case_type="api")
    claimed = client.post(f"{BASE}/work-items/fetch", json={"type": "api", "limit": 1, "agent": "vuln-1"}).json()["claimed"]
    assert len(claimed) == 1
    assert claimed[0]["assigned_agent"] == "vuln-1"
    done = client.post(f"{BASE}/work-items/done", json={"ids": [claimed[0]["id"]]}).json()
    assert done["affected"] == 1
    stats = client.get(f"{BASE}/work-items/stats?by=status").json()
    counts = {r["status"]: r["count"] for r in stats["status"]}
    assert counts.get("done") == 1
    assert counts.get("pending") == 1


def test_defer_cluster_and_reset_stale_and_retry(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/lo", case_type="api", cluster_key="gf:noise")
    _observe(client, url="https://app.example/api/lo2", case_type="api", cluster_key="gf:noise")
    deferred = client.post(f"{BASE}/work-items/defer-cluster",
                           json={"cluster_key": "gf:noise", "reason": "low-signal"}).json()
    assert deferred["affected"] == 2
    stats = client.get(f"{BASE}/work-items/stats?by=reason").json()
    assert any(r["terminal_reason"] == "low-signal" and r["count"] == 2 for r in stats["rows"])

    # error → retry-errors returns it to pending
    _observe(client, url="https://app.example/api/err", case_type="api")
    wid = client.get(f"{BASE}/work-items?type=api&status=pending").json()
    err_id = [r["id"] for r in wid if r["url"].endswith("/api/err")][0]
    client.post(f"{BASE}/work-items/error", json={"ids": [err_id]})
    retried = client.post(f"{BASE}/work-items/retry-errors", json={"max_retries": 3}).json()
    assert retried["affected"] == 1


def test_direct_bulk_out_of_scope_skip(client, isolate_settings):
    _seed(client, isolate_settings)
    resp = client.post(
        f"{BASE}/work-items/bulk",
        json={"items": [{
            "queue_key": "skipped:out-of-scope:evil.example:https://evil.example/x",
            "url": "https://evil.example/x",
            "url_path": "/x",
            "method": "GET",
            "type": "unknown",
            "source": "ingest-endpoints",
            "status": "skipped",
            "cluster_key": "skipped:out-of-scope",
            "terminal_reason": "skipped:out-of-scope | evil.example",
        }]},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["count"] == 1
    rows = client.get(f"{BASE}/work-items?status=skipped").json()
    assert len(rows) == 1
    assert rows[0]["host"] == "evil.example"


def test_apply_updates_force_writes_status_and_type(client, isolate_settings):
    """The classify-work update path force-writes status/type/queue_key by id,
    bypassing the ingest UPSERT's manual-protection and lifecycle preservation."""
    _seed(client, isolate_settings)
    body = _observe(client, url="https://app.example/api/z", case_type="unknown", priority_score=0).json()
    wid = body["work_item"]["id"]
    # Force a retype + status flip + rescore by id.
    resp = client.post(f"{BASE}/work-items/update", json={"updates": [{
        "id": wid,
        "type": "api",
        "status": "skipped",
        "priority_score": 77,
        "cluster_key": "gf:idor",
        "classifier_version": "v-reclass",
    }]})
    assert resp.status_code == 200, resp.text
    assert resp.json()["affected"] == 1
    row = client.get(f"{BASE}/work-items?status=skipped").json()[0]
    assert row["type"] == "api"
    assert row["priority_score"] == 77
    assert row["cluster_key"] == "gf:idor"
    assert row["classifier_version"] == "v-reclass"


def test_resume_brief_reflects_work_buffer(client, isolate_settings):
    _seed(client, isolate_settings)
    _observe(client, url="https://app.example/api/rb", case_type="api", cluster_key="gf:trust_surface")
    brief = client.get(f"{BASE}/resume-brief").json()
    wb = brief["work_buffer"]
    assert wb["pending_total"] >= 1
    assert "gf:trust_surface" in wb["by_bucket"]
