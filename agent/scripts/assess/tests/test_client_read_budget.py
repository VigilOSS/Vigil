"""A read the server is still computing is neither re-sent nor cut short.

A read timeout on a GET means the request arrived and the server is still
working on it. Re-sending it starts the same expensive computation again beside
the first, so a slow readiness read turned into several stacked ones. The
expensive aggregate reads (readiness, coverage) get a response budget sized to
the work they do instead of the default.
"""
from __future__ import annotations

import pytest

from assess.lib.client import (
    DEFAULT_READ_TIMEOUT_SECONDS,
    AGGREGATE_READ_TIMEOUT_SECONDS,
    AssessmentClient,
    AssessTransportError,
)
from test_client_stale_keepalive_retry import _client


def test_a_get_that_timed_out_reading_its_response_is_not_resent(monkeypatch):
    client, made = _client(
        monkeypatch, [("raise", TimeoutError()), ("respond", 200)], warm=False,
    )
    with pytest.raises(AssessTransportError) as raised:
        client._request_raw("GET", "/x", max_retries=3, read_timeout=7.5)
    assert len(made) == 1
    assert raised.value.request_sent
    # The server answered the connection and is still working: the message names
    # the budget that ran out, not a backend that is down.
    message = str(raised.value)
    assert "7.5 s response budget" in message
    assert "may still be working" in message
    assert "orchestrator start" not in message
    assert "Failed after" not in message


def test_a_write_that_timed_out_reading_its_response_reports_an_uncertain_outcome(monkeypatch):
    client, made = _client(monkeypatch, [("raise", TimeoutError())], warm=False)
    with pytest.raises(AssessTransportError) as raised:
        client._request_raw("POST", "/x", body=b"{}", max_retries=3)
    assert len(made) == 1
    message = str(raised.value)
    assert "response budget" in message
    assert "Write outcome uncertain" in message
    assert "orchestrator start" not in message


def test_a_get_whose_connection_failed_is_still_retried(monkeypatch):
    client, made = _client(
        monkeypatch, [("raise", ConnectionResetError()), ("respond", 200)], warm=False,
    )
    status, _body = client._request_raw("GET", "/x", max_retries=3)
    assert status == 200
    assert len(made) == 2


@pytest.mark.parametrize(
    "endpoint",
    [
        "report-readiness",
        "phase-readiness?phase=verify",
        "coverage-readiness/by-host",
        "coverage-readiness/by-family",
        "code/readiness?target_phase=verify-variant&include_debt_paths=true",
        "code/coverage",
        "code/coverage?repo_id=7",
        "coverage-readiness",
        "resume-brief",
        "resume-brief?since=2026-01-01T00%3A00%3A00Z",
        "application-units/terminal-block",
        "application-units/depth-ledger",
    ],
)
def test_aggregate_reads_get_the_wider_response_budget(monkeypatch, endpoint):
    budgets: list[float] = []

    def _request(self, method, path, **kwargs):
        budgets.append(kwargs.get("read_timeout", DEFAULT_READ_TIMEOUT_SECONDS))
        return 200, "{}"

    monkeypatch.setattr(AssessmentClient, "_request", _request)
    AssessmentClient("http://localhost:8000", "eng").get(endpoint)
    assert budgets == [AGGREGATE_READ_TIMEOUT_SECONDS]
    assert AGGREGATE_READ_TIMEOUT_SECONDS > DEFAULT_READ_TIMEOUT_SECONDS


@pytest.mark.parametrize("endpoint", ["findings/VA-001", "code/repos", "dispatches?status=in-progress"])
def test_ordinary_reads_keep_the_default_budget(monkeypatch, endpoint):
    budgets: list[float] = []

    def _request(self, method, path, **kwargs):
        budgets.append(kwargs.get("read_timeout", DEFAULT_READ_TIMEOUT_SECONDS))
        return 200, "{}"

    monkeypatch.setattr(AssessmentClient, "_request", _request)
    AssessmentClient("http://localhost:8000", "eng").get(endpoint)
    assert budgets == [DEFAULT_READ_TIMEOUT_SECONDS]
