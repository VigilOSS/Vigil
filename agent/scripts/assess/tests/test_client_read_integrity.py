"""Successful API reads must contain JSON, not an accidental frontend page."""
from __future__ import annotations

import http.client
import json
from unittest.mock import Mock

import pytest

from assess.lib.client import AssessError, AssessmentClient


@pytest.fixture(params=["assessment", "engagement"])
def api_read(request, monkeypatch):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    connection = Mock(spec=http.client.HTTPConnection)
    response = Mock(spec=http.client.HTTPResponse)
    connection.getresponse.return_value = response
    monkeypatch.setattr(client, "_get_conn", lambda _: connection)
    if request.param == "assessment":
        path = "/orchestrator/engagements/example/assessment/findings"

        def read():
            return client.get("findings")
    else:
        path = "/orchestrator/engagements/example/intel/notes?limit=5"

        def read():
            return client.get_engagement("intel/notes", "limit=5")
    return read, response, connection, path


@pytest.mark.parametrize(
    "body", ["<!doctype html><title>Vigil</title>", '{"items":', ""]
)
def test_successful_read_rejects_invalid_json_with_route_guidance(api_read, body):
    read, response, connection, path = api_read
    response.status = 200
    response.read.return_value = body.encode()

    with pytest.raises(AssessError, match="invalid JSON") as exc:
        read()

    message = str(exc.value)
    assert path in message
    assert "HTTP 200" in message
    assert "ORCHESTRATOR_BASE_URL" in message
    assert "http://localhost:8000/orchestrator" in message
    assert "frontend" in message
    connection.request.assert_called_once_with("GET", path, body=None, headers={})


@pytest.mark.parametrize("value", [{"items": [{"id": 1}]}, [1, 2], None, "text", False])
def test_successful_read_preserves_valid_json_value(api_read, value):
    read, response, connection, path = api_read
    response.status = 200
    response.read.return_value = json.dumps(value).encode()

    assert read() == value
    connection.request.assert_called_once_with("GET", path, body=None, headers={})


@pytest.mark.parametrize("status", [404, 409])
def test_http_error_is_not_reclassified_as_a_json_error(api_read, status):
    read, response, connection, path = api_read
    response.status = status
    response.read.return_value = b"route unavailable"

    with pytest.raises(AssessError) as exc:
        read()

    assert str(exc.value) == f"HTTP {status}:\nroute unavailable"
    connection.request.assert_called_once_with("GET", path, body=None, headers={})


@pytest.mark.parametrize(
    ("method_name", "endpoint"),
    [
        ("list_dispatches", "dispatches"),
        ("list_handoffs", "dispatch-handoffs"),
        ("list_decisions", "dispatch-decisions"),
    ],
)
def test_structured_list_helpers_reject_malformed_non_array_responses(
    monkeypatch, method_name, endpoint
):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    monkeypatch.setattr(client, "get", lambda _endpoint: {"detail": "wrong route"})

    with pytest.raises(AssessError, match=endpoint):
        getattr(client, method_name)()


@pytest.mark.parametrize(
    ("method_name", "endpoint"),
    [
        ("get_dispatch", "dispatches/agent-1"),
        ("get_handoff", "dispatch-handoffs/agent-1"),
    ],
)
def test_structured_point_helpers_reject_malformed_non_object_responses(
    monkeypatch, method_name, endpoint
):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    monkeypatch.setattr(client, "get", lambda _endpoint: ["wrong route"])

    with pytest.raises(AssessError, match=endpoint):
        getattr(client, method_name)("agent-1")


@pytest.fixture(
    params=[
        "assessment-post",
        "assessment-put",
        "assessment-patch",
        "assessment-delete",
        "engagement-post",
        "engagement-patch",
        "engagement-put",
    ]
)
def api_write(request, monkeypatch):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    connection = Mock(spec=http.client.HTTPConnection)
    response = Mock(spec=http.client.HTTPResponse)
    connection.getresponse.return_value = response
    monkeypatch.setattr(client, "_get_conn", lambda _: connection)

    payload = {"title": "preserve me"}
    if request.param == "assessment-post":
        method = "POST"
        path = "/orchestrator/engagements/example/assessment/findings"
        def write():
            return client.post("findings", payload)
    elif request.param == "assessment-put":
        method = "PUT"
        path = "/orchestrator/engagements/example/assessment/capture-policy"
        def write():
            return client.put("capture-policy", payload)
    elif request.param == "assessment-patch":
        method = "PATCH"
        path = "/orchestrator/engagements/example/assessment/findings/VA-001"
        def write():
            return client.patch("findings/VA-001", payload)
    elif request.param == "assessment-delete":
        method = "DELETE"
        path = "/orchestrator/engagements/example/assessment/findings/VA-001/root-cause"
        def write():
            return client.delete("findings/VA-001/root-cause")
    elif request.param == "engagement-post":
        method = "POST"
        path = "/orchestrator/engagements/example/intel/notes"
        def write():
            return client.post_engagement("intel/notes", payload)
    elif request.param == "engagement-patch":
        method = "PATCH"
        path = "/orchestrator/engagements/example/intel/notes/7"
        def write():
            return client.patch_engagement("intel/notes/7", payload)
    else:
        method = "PUT"
        path = "/orchestrator/engagements/example/credentials/user-a"
        def write():
            return client.put_engagement("credentials/user-a", payload)

    return write, response, connection, method, path, payload


@pytest.mark.parametrize(
    "body", ["<!doctype html><title>Vigil</title>", '{"id":', "not-json"]
)
def test_successful_write_rejects_unreadable_response_as_uncertain(api_write, body):
    write, response, connection, method, path, payload = api_write
    response.status = 200
    response.read.return_value = body.encode()

    with pytest.raises(AssessError, match="outcome is uncertain") as exc:
        write()

    message = str(exc.value)
    assert method in message
    assert path in message
    assert "HTTP 200" in message
    assert "do not retry automatically" in message
    expected_body = None if method == "DELETE" else json.dumps(payload).encode()
    expected_headers = {} if method == "DELETE" else {"Content-Type": "application/json"}
    connection.request.assert_called_once_with(
        method, path, body=expected_body, headers=expected_headers
    )


@pytest.mark.parametrize("value", [[], "created", 7, None, False])
def test_successful_write_requires_object_response(api_write, value):
    write, response, _connection, method, path, _payload = api_write
    response.status = 200
    response.read.return_value = json.dumps(value).encode()

    with pytest.raises(AssessError, match="expected a JSON object") as exc:
        write()

    message = str(exc.value)
    assert method in message
    assert path in message
    assert "outcome is uncertain" in message


def test_successful_write_rejects_empty_object_as_an_unknown_result_shape(api_write):
    write, response, _connection, method, path, _payload = api_write
    response.status = 200
    response.read.return_value = b"{}"

    with pytest.raises(AssessError, match="empty JSON object") as exc:
        write()

    message = str(exc.value)
    assert method in message
    assert path in message
    assert "outcome is uncertain" in message
    assert "do not retry automatically" in message


def test_ambiguous_write_failure_is_not_retried(api_write, monkeypatch):
    write, response, connection, method, path, _payload = api_write
    response.status = 503
    response.read.return_value = b'{"detail":"upstream outcome unknown"}'
    monkeypatch.setattr("assess.lib.client.time.sleep", lambda _seconds: None)

    with pytest.raises(AssessError, match="HTTP 503"):
        write()

    assert connection.request.call_count == 1, (
        f"{method} {path} may have committed before the 503 response; retrying "
        "can duplicate the durable mutation"
    )


def test_code_module_bulk_create_preserves_its_documented_array_response(monkeypatch):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    connection = Mock(spec=http.client.HTTPConnection)
    response = Mock(spec=http.client.HTTPResponse)
    response.status = 201
    rows = [{"id": 7, "module_key": "auth_login"}]
    response.read.return_value = json.dumps(rows).encode()
    connection.getresponse.return_value = response
    monkeypatch.setattr(client, "_get_conn", lambda _: connection)

    assert client.post("code/modules", {"repo_id": 1, "modules": [{}]}) == rows


def test_no_content_engagement_delete_remains_supported(monkeypatch):
    client = AssessmentClient("http://localhost:8000/orchestrator", "example")
    connection = Mock(spec=http.client.HTTPConnection)
    response = Mock(spec=http.client.HTTPResponse)
    response.status = 204
    response.read.return_value = b""
    connection.getresponse.return_value = response
    monkeypatch.setattr(client, "_get_conn", lambda _: connection)

    assert client.delete_engagement("credentials/user-a") is None
    connection.request.assert_called_once_with(
        "DELETE",
        "/orchestrator/engagements/example/credentials/user-a",
        body=None,
        headers={},
    )
