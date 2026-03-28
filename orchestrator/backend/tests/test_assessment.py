import http.server
import json
import os
import sqlite3
import socketserver
import subprocess
import threading
from pathlib import Path


def register_and_login(client, username: str) -> str:
    client.post("/auth/register", json={"username": username, "password": "secret-password"})
    login_response = client.post(
        "/auth/login",
        json={"username": username, "password": "secret-password"},
    )
    assert login_response.status_code == 200
    return login_response.json()["access_token"]


def create_project(client, token: str, name: str = "Alpha") -> dict:
    response = client.post(
        "/projects",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": name},
    )
    assert response.status_code == 201
    return response.json()


def create_run(client, token: str, project_id: int, target: str = "https://example.com") -> dict:
    response = client.post(
        f"/projects/{project_id}/runs",
        headers={"Authorization": f"Bearer {token}"},
        json={"target": target},
    )
    assert response.status_code == 201
    return response.json()


def test_assessment_summary_counts_structured_records(client):
    token = register_and_login(client, "alice")
    project = create_project(client, token)
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    target = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/targets",
        headers=headers,
        json={
            "identity": "example.com",
            "kind": "host",
            "host": "example.com",
            "hostname": "example.com",
            "notes": "seed target",
            "discovered_by": "recon-specialist",
        },
    )
    assert target.status_code == 201

    service = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/services",
        headers=headers,
        json={
            "endpoint": "example.com:443",
            "protocol": "tcp",
            "port": 443,
            "service": "https",
            "state": "discovered",
            "coverage_status": "pending",
            "target_identity": "example.com",
            "discovered_by": "recon-specialist",
        },
    )
    assert service.status_code == 201

    request_variant = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/request-variants",
        headers=headers,
        json={
            "url": "https://example.com/app?id=1",
            "method": "GET",
            "auth_context": "anonymous",
            "content_type_family": "html",
            "query_schema": {"id": "numeric"},
            "discovery_source": "katana",
            "response_status": 200,
            "observation_payload": {"source": "katana"},
        },
    )
    assert request_variant.status_code == 201
    request_variant_id = request_variant.json()["id"]

    coverage = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/coverage-items",
        headers=headers,
        json={
            "request_variant_id": request_variant_id,
            "auth_context": "anonymous",
            "input_slot": "query",
            "attack_family": "idor",
            "status": "pending",
        },
    )
    assert coverage.status_code == 201
    coverage_item_id = coverage.json()["id"]

    probe = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/probe-runs",
        headers=headers,
        json={
            "request_variant_id": request_variant_id,
            "coverage_item_id": coverage_item_id,
            "auth_context": "anonymous",
            "input_slot": "query",
            "attack_family": "idor",
            "payload_family": "numeric-enumeration",
            "payload_value": "2",
            "tool_name": "manual",
            "agent_name": "vulnerability-analyst",
            "result_status": "signal",
        },
    )
    assert probe.status_code == 201

    surface = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/surfaces",
        headers=headers,
        json={
            "surface_type": "web-app",
            "target_descriptor": "https://example.com/app",
            "source_name": "katana",
            "rationale": "discovered during crawl",
            "status": "discovered",
        },
    )
    assert surface.status_code == 201

    summary = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["target_count"] == 1
    assert payload["service_count"] == 1
    assert payload["request_variant_count"] == 1
    assert payload["request_observation_count"] == 1
    assert payload["coverage_count"] == 1
    assert payload["probe_count"] == 1
    assert payload["open_surface_count"] == 1
    assert payload["coverage_statuses"]["pending"] == 1

    surfaces = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/surfaces",
        headers=headers,
    )
    assert surfaces.status_code == 200
    assert surfaces.json()[0]["target_descriptor"] == "https://example.com/app"


def test_request_observation_ingest_keeps_host_auth_and_body_variants_distinct(client):
    token = register_and_login(client, "variant-user")
    project = create_project(client, token, "Variants")
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    observations = [
        {
            "url": "https://alpha.example/api/orders?id=1",
            "method": "GET",
            "auth_context": "anonymous",
            "content_type_family": "json",
            "query_schema": {"id": "numeric"},
            "body_schema": {},
            "path_schema": {},
            "cookie_schema": {},
            "header_schema": {},
            "discovery_source": "katana",
        },
        {
            "url": "https://beta.example/api/orders?id=1",
            "method": "GET",
            "auth_context": "anonymous",
            "content_type_family": "json",
            "query_schema": {"id": "numeric"},
            "body_schema": {},
            "path_schema": {},
            "cookie_schema": {},
            "header_schema": {},
            "discovery_source": "katana",
        },
        {
            "url": "https://alpha.example/api/orders?id=1",
            "method": "GET",
            "auth_context": "session:user",
            "content_type_family": "json",
            "query_schema": {"id": "numeric"},
            "body_schema": {},
            "path_schema": {},
            "cookie_schema": {"session": "opaque"},
            "header_schema": {},
            "discovery_source": "authenticated-collect",
        },
        {
            "url": "https://alpha.example/api/orders",
            "method": "POST",
            "auth_context": "session:user",
            "content_type_family": "json",
            "query_schema": {},
            "body_schema": {"order_id": "numeric"},
            "path_schema": {},
            "cookie_schema": {"session": "opaque"},
            "header_schema": {"content-type": "application/json"},
            "discovery_source": "authenticated-collect",
        },
        {
            "url": "https://alpha.example/api/orders",
            "method": "POST",
            "auth_context": "session:user",
            "content_type_family": "json",
            "query_schema": {},
            "body_schema": {"order_uuid": "uuid"},
            "path_schema": {},
            "cookie_schema": {"session": "opaque"},
            "header_schema": {"content-type": "application/json"},
            "discovery_source": "authenticated-collect",
        },
    ]

    variant_ids = set()
    for payload in observations:
        response = client.post(
            f"/projects/{project['id']}/runs/{run['id']}/assessment/request-observations",
            headers=headers,
            json=payload,
        )
        assert response.status_code == 201
        variant_ids.add(response.json()["request_variant"]["id"])

    assert len(variant_ids) == 5

    summary = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/summary",
        headers=headers,
    )
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["request_variant_count"] == 5
    assert payload["service_count"] == 2
    assert payload["coverage_count"] >= 7


def test_transient_work_buffer_keeps_host_and_auth_variants_distinct(tmp_path):
    repo_root = Path(__file__).resolve().parents[3]
    db_path = tmp_path / "cases.db"
    db_path.touch()

    schema = (repo_root / "agent" / "scripts" / "schema.sql").read_text(encoding="utf-8")
    with sqlite3.connect(db_path) as connection:
        connection.executescript(schema)

    class Handler(http.server.BaseHTTPRequestHandler):
        request_variant_id = 0
        service_id = 100

        def do_POST(self):
            payload = json.loads(
                self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8")
            )
            Handler.request_variant_id += 1
            Handler.service_id += 1
            response = {
                "request_variant": {
                    "id": Handler.request_variant_id,
                    "url": payload["url"],
                },
                "service": {
                    "id": Handler.service_id,
                    "endpoint": payload.get("target_identity") or "",
                },
            }
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))

        def log_message(self, format, *args):
            return

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        env = {
            **os.environ,
            "ORCHESTRATOR_BASE_URL": f"http://127.0.0.1:{server.server_address[1]}",
            "ORCHESTRATOR_TOKEN": "test-token",
            "ORCHESTRATOR_PROJECT_ID": "11",
            "ORCHESTRATOR_RUN_ID": "22",
        }

        subprocess.run(
            ["bash", str(repo_root / "agent" / "scripts" / "recon_ingest.sh"), str(db_path), "pytest"],
            input="GET https://alpha.example/app?id=1\nGET https://beta.example/app?id=1\n",
            text=True,
            check=True,
            cwd=repo_root,
            env=env,
        )
        server.shutdown()
        thread.join(timeout=1)

    subprocess.run(
        ["bash", str(repo_root / "agent" / "scripts" / "dispatcher.sh"), str(db_path), "requeue"],
        input='{"method":"GET","url":"https://alpha.example/app?id=1","type":"api","auth_context":"session:user"}\n',
        text=True,
        check=True,
        cwd=repo_root,
    )

    with sqlite3.connect(db_path) as connection:
        rows = connection.execute(
            "SELECT url, auth_context, queue_key FROM work_items ORDER BY id ASC"
        ).fetchall()

    assert len(rows) == 3
    assert {row[0] for row in rows} == {
        "https://alpha.example/app?id=1",
        "https://beta.example/app?id=1",
    }
    assert {row[1] for row in rows} == {"anonymous", "session:user"}
    assert len({row[2] for row in rows}) == 3


def test_repeating_same_probe_dedups_at_probe_level_only(client):
    token = register_and_login(client, "probe-user")
    project = create_project(client, token, "Probe")
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    request_variant = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/request-variants",
        headers=headers,
        json={
            "url": "https://example.com/export?id=1",
            "method": "GET",
            "auth_context": "anonymous",
            "content_type_family": "json",
            "query_schema": {"id": "numeric"},
            "discovery_source": "seed",
            "observation_payload": {"seed": True},
        },
    )
    request_variant_id = request_variant.json()["id"]

    coverage = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/coverage-items",
        headers=headers,
        json={
            "request_variant_id": request_variant_id,
            "auth_context": "anonymous",
            "input_slot": "query",
            "attack_family": "idor",
            "status": "pending",
        },
    )
    coverage_item_id = coverage.json()["id"]

    first = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/probe-runs",
        headers=headers,
        json={
            "request_variant_id": request_variant_id,
            "coverage_item_id": coverage_item_id,
            "auth_context": "anonymous",
            "input_slot": "query",
            "attack_family": "idor",
            "payload_family": "numeric-enumeration",
            "payload_value": "2",
            "tool_name": "manual",
            "agent_name": "vulnerability-analyst",
            "result_status": "signal",
        },
    )
    second = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/probe-runs",
        headers=headers,
        json={
            "request_variant_id": request_variant_id,
            "coverage_item_id": coverage_item_id,
            "auth_context": "anonymous",
            "input_slot": "query",
            "attack_family": "idor",
            "payload_family": "numeric-enumeration",
            "payload_value": "2",
            "tool_name": "manual",
            "agent_name": "vulnerability-analyst",
            "result_status": "exploited",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert second.json()["result_status"] == "exploited"

    summary = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/summary",
        headers=headers,
    ).json()
    assert summary["probe_count"] == 1
    assert summary["coverage_count"] == 1


def test_exploiting_existing_finding_updates_same_finding(client):
    token = register_and_login(client, "finding-user")
    project = create_project(client, token, "Findings")
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    base_payload = {
        "title": "Blind SQL injection in search",
        "severity": "high",
        "status": "confirmed",
        "defect_family": "sql-injection",
        "root_cause_key": "search-id-sqli",
        "auth_context": "anonymous",
        "canonical_location": "https://example.com/search?q",
        "summary": "Search endpoint accepts boolean-blind SQL injection",
        "evidence_ref": "findings.md",
        "notes": "Initial confirmation",
        "source_name": "vulnerability-analyst",
    }
    first = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
        json=base_payload,
    )
    assert first.status_code == 201

    second = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
        json={
            **base_payload,
            "status": "exploited",
            "notes": "Escalated to file read via UNION payload",
            "details": {"impact": "Arbitrary file read"},
        },
    )
    assert second.status_code == 201
    assert first.json()["finding"]["slug"] == second.json()["finding"]["slug"]
    assert second.json()["finding"]["status"] == "exploited"

    findings = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
    )
    assert findings.status_code == 200
    payload = findings.json()
    assert len(payload) == 1
    assert payload[0]["status"] == "exploited"


def test_similar_findings_on_distinct_endpoints_remain_separate(client):
    token = register_and_login(client, "graph-user")
    project = create_project(client, token, "DistinctFindings")
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    for location in ["https://example.com/api/users", "https://example.com/api/admin/users"]:
        response = client.post(
            f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
            headers=headers,
            json={
                "title": "IDOR on user lookup",
                "severity": "medium",
                "status": "confirmed",
                "defect_family": "idor",
                "root_cause_key": "user-lookup-idor",
                "auth_context": "session:user",
                "canonical_location": location,
                "summary": "User identifiers can be enumerated",
                "source_name": "vulnerability-analyst",
            },
        )
        assert response.status_code == 201

    findings = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
    ).json()
    assert len(findings) == 2


def test_manual_merge_promotes_target_and_rehomes_links(client):
    token = register_and_login(client, "merge-user")
    project = create_project(client, token, "MergeFindings")
    run = create_run(client, token, project["id"])
    headers = {"Authorization": f"Bearer {token}"}

    parent = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
        json={
            "slug": "FINDING-VA-001",
            "title": "Parent finding",
            "severity": "medium",
            "status": "confirmed",
            "defect_family": "idor",
            "root_cause_key": "orders-a",
            "auth_context": "anonymous",
            "canonical_location": "GET /orders?id=",
            "summary": "Parent summary",
            "evidence_ref": "parent.txt",
            "notes": "parent notes",
            "source_name": "vulnerability-analyst",
            "links": [
                {
                    "link_kind": "evidence",
                    "target_kind": "evidence_artifact",
                    "target_ref": "parent.txt",
                    "notes": "parent evidence",
                }
            ],
        },
    )
    child = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
        json={
            "slug": "FINDING-EX-002",
            "title": "Child finding",
            "severity": "critical",
            "status": "exploited",
            "defect_family": "idor",
            "root_cause_key": "orders-b",
            "auth_context": "anonymous",
            "canonical_location": "GET /admin/orders?id=",
            "summary": "Child summary",
            "evidence_ref": "child.txt",
            "notes": "child notes",
            "source_name": "exploit-developer",
            "links": [
                {
                    "link_kind": "evidence",
                    "target_kind": "evidence_artifact",
                    "target_ref": "child.txt",
                    "notes": "child evidence",
                }
            ],
        },
    )
    assert parent.status_code == 201
    assert child.status_code == 201

    merge = client.post(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings/merge",
        headers=headers,
        json={
            "source_slug": "FINDING-EX-002",
            "target_slug": "FINDING-VA-001",
            "reason": "same root cause after review",
            "source_name": "operator",
        },
    )
    assert merge.status_code == 200

    findings = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/findings",
        headers=headers,
    ).json()
    findings_by_slug = {row["slug"]: row for row in findings}
    assert findings_by_slug["FINDING-VA-001"]["severity"] == "critical"
    assert findings_by_slug["FINDING-VA-001"]["status"] == "exploited"
    assert findings_by_slug["FINDING-EX-002"]["status"] == "merged"

    links = client.get(
        f"/projects/{project['id']}/runs/{run['id']}/assessment/finding-links",
        headers=headers,
    ).json()
    assert any(link["finding_slug"] == "FINDING-VA-001" and link["target_ref"] == "child.txt" for link in links)
    assert not any(link["finding_slug"] == "FINDING-EX-002" and link["target_ref"] == "child.txt" for link in links)
    assert any(link["finding_slug"] == "FINDING-VA-001" and link["link_kind"] == "merged_from" for link in links)
