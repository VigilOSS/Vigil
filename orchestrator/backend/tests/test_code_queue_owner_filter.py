from test_code_queue_path_scope import _seed


def test_queue_owner_filter_applies_before_pagination_and_combines_with_status(client, isolate_settings):
    base, _file_ids, _item_ids = _seed(client, isolate_settings, "2026-11-08-owner-filter")
    claims = {}
    for agent in ("acme-hunter-a", "acme-hunter-b"):
        response = client.post(f"{base}/analysis-queue/fetch", json={"limit": 1, "agent_name": agent})
        assert response.status_code == 200, response.text
        claims[agent] = response.json()[0]["id"]

    response = client.get(f"{base}/analysis-queue", params={"agent_name": "acme-hunter-b", "limit": 1})
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["total"] == 1
    assert page["item_ids"] == [claims["acme-hunter-b"]]
    assert page["has_more"] is False
    assert client.get(f"{base}/analysis-queue", params={
        "agent_name": "acme-hunter-b", "status": "pending",
    }).json()["total"] == 0
    assert client.get(f"{base}/analysis-queue", params={
        "agent_name": "absent-acme-hunter",
    }).json()["total"] == 0
    assert client.get(f"{base}/analysis-queue").json()["total"] == 5
