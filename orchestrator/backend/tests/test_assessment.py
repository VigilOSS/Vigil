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
