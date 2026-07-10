from __future__ import annotations

import json

import pytest

from assess.lib import host_processes
from assess.lib.client import AssessError


def test_register_process_requires_identity_and_writes_owned_record(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "start-77")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)

    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)

    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["run_uuid"] == "run-1"
    assert record["pid"] == 77
    assert record["pgid"] == 77
    assert record["process_identity"] == "start-77"

    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    with pytest.raises(AssessError, match="identity"):
        host_processes.register_process(tmp_path, run_uuid="run-2", pid=88)


def test_register_process_rejects_unowned_process_group(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "start-77")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 12)

    with pytest.raises(AssessError, match="process group"):
        host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)


def test_reaper_terminates_only_matching_owned_process(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "owned")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    terminated: list[tuple[int, int, str]] = []
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda pid, pgid, identity: terminated.append((pid, pgid, identity)) or True,
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert terminated == [(77, 77, "owned")]
    assert summary["reaped"] == 1
    assert not path.exists()


def test_reaper_does_not_signal_reused_pid(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "replacement")
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda *args: pytest.fail("reused PID must not be signalled"),
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["stale"] == 1
    assert not path.exists()


def test_reaper_retains_unverifiable_process_for_attention(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: True)

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["unverifiable"] == 1
    assert path.exists()


def test_reaper_removes_registry_when_pid_is_confirmed_absent(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: False)

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["stale"] == 1
    assert not path.exists()


def test_reaper_terminates_residual_owned_group_after_leader_exit(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    path = host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: False)
    monkeypatch.setattr(host_processes, "_group_exists", lambda pgid: True)
    terminated: list[tuple[int, int, str]] = []
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda pid, pgid, identity: terminated.append((pid, pgid, identity)) or True,
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert terminated == [(77, 77, "original")]
    assert summary["reaped"] == 1
    assert not path.exists()


def test_wait_for_owned_exit_waits_for_whole_group_not_only_leader(monkeypatch):
    states = iter([True, False])
    monkeypatch.setattr(host_processes, "_group_exists", lambda pgid: next(states))
    clock = iter([0.0, 0.1, 0.2])
    monkeypatch.setattr(host_processes.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(host_processes.time, "sleep", lambda _seconds: None)

    assert host_processes._wait_for_owned_exit(77, 77, "original", 1.0) is True


def test_owned_group_termination_kills_residual_children_after_leader_exit(monkeypatch):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: False)
    monkeypatch.setattr(host_processes, "_group_exists", lambda pgid: True)
    monkeypatch.setattr(host_processes, "_wait_for_owned_exit", lambda *args: False)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(
        host_processes.os,
        "killpg",
        lambda pgid, sig: signals.append((pgid, sig)),
    )

    assert host_processes._terminate_owned_group(77, 77, "original") is False
    assert signals == [
        (77, host_processes.signal.SIGTERM),
        (77, host_processes.signal.SIGKILL),
    ]


def test_owned_group_termination_rechecks_identity_and_pgid_before_each_signal(monkeypatch):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "owned")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    monkeypatch.setattr(host_processes, "_wait_for_owned_exit", lambda *args: False)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(
        host_processes.os,
        "killpg",
        lambda pgid, sig: signals.append((pgid, sig)),
    )

    assert host_processes._terminate_owned_group(77, 77, "owned") is False
    assert signals == [(77, host_processes.signal.SIGTERM), (77, host_processes.signal.SIGKILL)]
