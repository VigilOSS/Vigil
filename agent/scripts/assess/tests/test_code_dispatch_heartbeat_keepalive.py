"""`code-dispatch heartbeat --keepalive` renews one lease until the lease itself ends.

The stop condition is the backend's answer about this lease, never a file, so
two lanes can never stop each other's heartbeats. A refusal is classified from
the item's structured progress read: the item closed under this lease exits 0;
a lease that was reset, adopted or reclaimed exits 1.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from _fake_client import StubClient

from assess.commands import code_dispatch
from assess.lib.client import AssessError, AssessTransportError

_AGENT = "cvh-acme-1"
_TOKEN = "lease-acme-1"


def _install(monkeypatch, tmp_path, *, heartbeats, progress=None):
    """``heartbeats``: per call, a dict response or an exception to raise."""
    calls = {"heartbeat": 0, "progress": 0, "sleeps": []}
    outcomes = iter(heartbeats)

    class FakeClient(StubClient):
        def post(self, endpoint: str, payload: dict):
            assert endpoint == "code/analysis-queue/heartbeat"
            assert payload == {"item_id": 7, "agent_name": _AGENT, "lease_token": _TOKEN}
            calls["heartbeat"] += 1
            outcome = next(outcomes)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        def get(self, endpoint: str):
            assert endpoint == "code/analysis-queue/7/progress"
            calls["progress"] += 1
            return progress

    def fake_sleep(seconds):
        calls["sleeps"].append(seconds)

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch.time, "sleep", fake_sleep)
    monkeypatch.setattr(code_dispatch, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)))
    return calls


def _run(*extra: str) -> int:
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch.run(SimpleNamespace(
            action="heartbeat", extra=["7", _AGENT, _TOKEN, *extra], engagement_dir="/tmp/acme"))
    return excinfo.value.code


_ALIVE = {"item_id": 7, "last_heartbeat_at": "2026-11-14T10:00:00Z"}
_NOT_PROCESSING = AssessError(
    'HTTP 409:\n{"detail": "Cannot heartbeat queue item 7 unless it is processing; '
    'current status is done"}'
)


def test_keepalive_exits_zero_once_the_item_closes_under_this_lease(
    monkeypatch, tmp_path, capsys
):
    calls = _install(
        monkeypatch, tmp_path,
        heartbeats=[_ALIVE, _ALIVE, _NOT_PROCESSING],
        progress={"item_id": 7, "status": "done", "agent_name": _AGENT, "lease_token": _TOKEN},
    )

    assert _run("--keepalive") == 0

    assert calls["heartbeat"] == 3
    assert calls["sleeps"] == [240, 240]
    err = capsys.readouterr().err
    assert "closed under this lease" in err and "done" in err


def test_keepalive_exits_one_when_the_lease_moved(monkeypatch, tmp_path, capsys):
    refused = AssessError('HTTP 409:\n{"detail": "Cannot heartbeat: lease reset"}')
    calls = _install(
        monkeypatch, tmp_path,
        heartbeats=[_ALIVE, refused],
        progress={"item_id": 7, "status": "processing", "agent_name": "cvh-acme-2",
                  "lease_token": "lease-acme-2"},
    )

    assert _run("--keepalive", "--every", "30") == 1

    assert calls["sleeps"] == [30]
    err = capsys.readouterr().err
    assert "no longer holds" in err and "cvh-acme-2" in err


def test_keepalive_exits_one_when_the_item_cannot_be_read(monkeypatch, tmp_path, capsys):
    missing = AssessError('HTTP 404:\n{"detail": "Queue item not found"}')
    _install(monkeypatch, tmp_path, heartbeats=[missing])

    assert _run("--keepalive") == 1
    assert "Queue item not found" in capsys.readouterr().err


def test_keepalive_rides_out_a_transient_failure_but_not_three(monkeypatch, tmp_path, capsys):
    transient = AssessTransportError("connection refused", request_sent=False)
    calls = _install(
        monkeypatch, tmp_path,
        heartbeats=[transient, _ALIVE, transient, transient, transient],
    )

    assert _run("--keepalive") == 1

    assert calls["heartbeat"] == 5
    err = capsys.readouterr().err
    assert "3 consecutive" in err


def test_keepalive_stops_cleanly_on_interrupt(monkeypatch, tmp_path, capsys):
    calls = _install(monkeypatch, tmp_path, heartbeats=[_ALIVE])

    def interrupted(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(code_dispatch.time, "sleep", interrupted)

    assert _run("--keepalive") == 130
    assert calls["heartbeat"] == 1
    assert "lease stays held" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [("--keepalive", "--every", "29"), ("--keepalive", "--every", "600"),
     ("--keepalive", "--every", "x"), ("--every", "60"), ("--keepalive", "--keepalive")],
)
def test_keepalive_options_out_of_range_are_refused(monkeypatch, tmp_path, extra):
    calls = _install(monkeypatch, tmp_path, heartbeats=[])

    assert _run(*extra) == 1
    assert calls["heartbeat"] == 0


def test_a_single_heartbeat_keeps_its_one_shot_behaviour(monkeypatch, tmp_path, capsys):
    calls = _install(monkeypatch, tmp_path, heartbeats=[_ALIVE])

    code_dispatch.run(SimpleNamespace(
        action="heartbeat", extra=["7", _AGENT, _TOKEN], engagement_dir="/tmp/acme"))

    assert calls["heartbeat"] == 1 and calls["sleeps"] == []
    assert '"last_heartbeat_at"' in capsys.readouterr().out
