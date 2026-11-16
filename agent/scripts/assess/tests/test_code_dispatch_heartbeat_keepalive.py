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


def _fake_owner(pid):
    return code_dispatch._KeepaliveOwner(pid or 4242, 1.0, "acme-client")


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
            if endpoint == f"dispatches/{_AGENT}":
                return {"agent_id": _AGENT, "status": "in-progress"}
            assert endpoint == "code/analysis-queue/7/progress"
            calls["progress"] += 1
            return progress

    def fake_sleep(seconds):
        calls["sleeps"].append(seconds)

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch.time, "sleep", fake_sleep)
    monkeypatch.setattr(code_dispatch, "_owner_alive", lambda _owner: True)
    monkeypatch.setattr(code_dispatch, "_keepalive_owner", _fake_owner)
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


# One keepalive per lane: `--claims-file` renews every lease a fetch returned
# from one process, and each lease still stops only on the backend's answer
# about that lease.

_LEASES = {7: "lease-acme-7", 8: "lease-acme-8"}


def _claims_file(tmp_path, rows=None):
    path = tmp_path / "fetch.json"
    path.write_text(__import__("json").dumps(rows if rows is not None else [
        {"id": item_id, "queue_item_id": item_id, "agent_name": _AGENT,
         "lease_token": token, "scratch_dir": f"scratch/{item_id}"}
        for item_id, token in _LEASES.items()
    ]))
    return str(path)


def _install_lane(monkeypatch, tmp_path, *, heartbeats, progress, dispatch=None, owner=None):
    """``heartbeats``: item id -> per-call outcomes; ``progress``: item id -> row."""
    calls = {"heartbeat": [], "sleeps": [], "clients": 0}
    outcomes = {item_id: iter(values) for item_id, values in heartbeats.items()}

    class FakeClient(StubClient):
        def __init__(self, *args, **kwargs):
            calls["clients"] += 1
            super().__init__(*args, **kwargs)

        def post(self, endpoint: str, payload: dict):
            assert endpoint == "code/analysis-queue/heartbeat"
            item_id = payload["item_id"]
            assert payload == {
                "item_id": item_id, "agent_name": _AGENT, "lease_token": _LEASES[item_id],
            }
            calls["heartbeat"].append(item_id)
            outcome = next(outcomes[item_id])
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        def get(self, endpoint: str):
            if endpoint.startswith("dispatches/"):
                calls["dispatch_reads"] = calls.get("dispatch_reads", 0) + 1
                status = next(dispatch_status) if dispatch_status else "in-progress"
                return {"agent_id": endpoint.split("/", 1)[1], "status": status}
            item_id = int(endpoint.split("/")[2])
            return progress[item_id]

    dispatch_status = iter(dispatch) if dispatch is not None else None
    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(
        code_dispatch.time, "sleep", lambda seconds: calls["sleeps"].append(seconds)
    )
    alive = iter(owner) if owner is not None else None
    monkeypatch.setattr(
        code_dispatch, "_owner_alive", lambda _owner: next(alive) if alive else True
    )
    monkeypatch.setattr(code_dispatch, "_keepalive_owner", _fake_owner)
    monkeypatch.setattr(code_dispatch, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)))
    return calls


def _run_lane(*extra: str) -> int:
    with pytest.raises(SystemExit) as excinfo:
        code_dispatch.run(SimpleNamespace(
            action="heartbeat", extra=list(extra), engagement_dir="/tmp/acme"))
    return excinfo.value.code


def _closed(item_id: int) -> dict:
    return {"item_id": item_id, "status": "done", "agent_name": _AGENT,
            "lease_token": _LEASES[item_id]}


def _refused(item_id: int) -> AssessError:
    return AssessError(
        f'HTTP 409:\n{{"detail": "Cannot heartbeat queue item {item_id} unless it is '
        'processing; current status is done"}'
    )


def test_one_lane_keepalive_renews_every_lease_until_each_closes(
    monkeypatch, tmp_path, capsys
):
    calls = _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_ALIVE, _refused(7)], 8: [_ALIVE, _ALIVE, _refused(8)]},
        progress={7: _closed(7), 8: _closed(8)},
    )

    assert _run_lane("--keepalive", "--claims-file", _claims_file(tmp_path)) == 0

    assert calls["heartbeat"] == [7, 8, 7, 8, 8]
    assert calls["sleeps"] == [240, 240]
    err = capsys.readouterr().err
    assert "queue item 7 closed under this lease" in err
    assert "queue item 8 closed under this lease" in err


def test_one_lane_keepalive_exits_one_when_any_lease_moved(monkeypatch, tmp_path, capsys):
    moved = {"item_id": 8, "status": "processing", "agent_name": "cvh-acme-2",
             "lease_token": "lease-acme-2"}
    calls = _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_ALIVE, _ALIVE, _refused(7)], 8: [_refused(8)]},
        progress={7: _closed(7), 8: moved},
    )

    assert _run_lane(
        "--keepalive", "--every", "30", "--claims-file", _claims_file(tmp_path)
    ) == 1

    # The lost lease does not stop the lane's other heartbeats.
    assert calls["heartbeat"] == [7, 8, 7, 7]
    err = capsys.readouterr().err
    assert "no longer holds queue item 8" in err and "cvh-acme-2" in err
    assert "queue item 7 closed under this lease" in err


def test_a_claims_file_without_lease_identities_is_refused_before_any_heartbeat(
    monkeypatch, tmp_path, capsys
):
    calls = _install_lane(monkeypatch, tmp_path, heartbeats={}, progress={})
    path = _claims_file(tmp_path, rows=[
        {"id": 7, "agent_name": _AGENT},
        {"id": 8, "lease_token": "lease-acme-8"},
    ])

    assert _run_lane("--keepalive", "--claims-file", path) == 1

    assert calls["heartbeat"] == []
    err = capsys.readouterr().err
    assert "entry 1" in err and "lease_token" in err
    assert "entry 2" in err and "agent_name" in err


def test_a_claims_file_needs_keepalive_and_no_positional_lease(monkeypatch, tmp_path):
    calls = _install_lane(monkeypatch, tmp_path, heartbeats={}, progress={})
    path = _claims_file(tmp_path)

    assert _run_lane("--claims-file", path) == 1
    assert _run_lane("7", _AGENT, _TOKEN, "--keepalive", "--claims-file", path) == 1
    assert calls["heartbeat"] == []


# A keepalive ends with its owner: the process that started it, the dispatch the
# leases were fetched under, or its maximum lifetime. Each stop leaves the leases
# to go stale, so the operator's stale-lease recovery can reach them.


def test_lane_keepalive_names_what_it_watches(monkeypatch, tmp_path, capsys):
    _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_refused(7)], 8: [_refused(8)]},
        progress={7: _closed(7), 8: _closed(8)},
    )

    assert _run_lane(
        "--keepalive", "--owner-pid", "4242", "--claims-file", _claims_file(tmp_path)
    ) == 0

    err = capsys.readouterr().err
    assert "owner pid 4242" in err
    assert f"dispatch {_AGENT}" in err
    assert "at most" in err


def test_lane_keepalive_stops_when_its_owner_process_ends(monkeypatch, tmp_path, capsys):
    calls = _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_ALIVE], 8: [_ALIVE]},
        progress={},
        owner=[True, False],
    )

    assert _run_lane(
        "--keepalive", "--owner-pid", "4242", "--claims-file", _claims_file(tmp_path)
    ) == 1

    assert calls["heartbeat"] == [7, 8]
    err = capsys.readouterr().err
    assert "owner pid 4242" in err and "ended" in err
    assert "go stale" in err


def test_lane_keepalive_stops_when_its_dispatch_closes(monkeypatch, tmp_path, capsys):
    calls = _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_ALIVE], 8: [_ALIVE]},
        progress={},
        dispatch=["in-progress", "in-progress", "failed"],
    )

    assert _run_lane("--keepalive", "--claims-file", _claims_file(tmp_path)) == 1

    assert calls["heartbeat"] == [7, 8]
    err = capsys.readouterr().err
    assert f"dispatch {_AGENT} is failed" in err and "go stale" in err


def test_lane_keepalive_keeps_renewing_while_its_dispatch_is_in_progress(
    monkeypatch, tmp_path, capsys
):
    """The backend spells a live dispatch `in-progress`; that is the watch's go-on answer."""
    calls = _install_lane(
        monkeypatch, tmp_path,
        heartbeats={7: [_ALIVE, _refused(7)], 8: [_ALIVE, _ALIVE, _refused(8)]},
        progress={7: _closed(7), 8: _closed(8)},
        dispatch=["in-progress"] * 4,
    )

    assert _run_lane("--keepalive", "--claims-file", _claims_file(tmp_path)) == 0

    assert calls["heartbeat"] == [7, 8, 7, 8, 8]
    err = capsys.readouterr().err
    assert "stopping because" not in err
    assert f"dispatch {_AGENT} (in-progress) while it is in-progress" in err


def test_lane_keepalive_stops_at_its_maximum_lifetime(monkeypatch, tmp_path, capsys):
    calls = _install_lane(
        monkeypatch, tmp_path, heartbeats={7: [_ALIVE], 8: [_ALIVE]}, progress={},
    )
    clock = iter([0.0, 0.0, 700.0])
    monkeypatch.setattr(code_dispatch.time, "monotonic", lambda: next(clock))

    assert _run_lane(
        "--keepalive", "--max-lifetime", "600", "--claims-file", _claims_file(tmp_path)
    ) == 1

    assert calls["heartbeat"] == [7, 8]
    assert "maximum lifetime" in capsys.readouterr().err


@pytest.mark.parametrize(
    "extra",
    [("--keepalive", "--owner-pid", "0"), ("--keepalive", "--owner-pid", "x"),
     ("--keepalive", "--max-lifetime", "59"), ("--owner-pid", "4242")],
)
def test_keepalive_binding_options_are_validated(monkeypatch, tmp_path, extra):
    calls = _install(monkeypatch, tmp_path, heartbeats=[])

    assert _run(*extra) == 1
    assert calls["heartbeat"] == 0
