from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from assess.lib import host_processes
from assess.lib.client import AssessError


def _ownership(pid: int = 4242) -> host_processes.ProcessOwnership:
    return host_processes.ProcessOwnership(
        pid=pid,
        pgid=pid,
        process_identity=f"proof-{pid}",
    )


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


def test_registry_rejects_symlinked_runtime_without_touching_target(tmp_path):
    engagement = tmp_path / "eng"
    engagement.mkdir()
    victim_parent = tmp_path / "victim-parent"
    victim_registry = victim_parent / "host-processes"
    victim_registry.mkdir(parents=True)
    victim = victim_registry / "run-parent.json"
    victim.write_bytes(b"KEEP-PARENT")
    (engagement / ".runtime").symlink_to(victim_parent, target_is_directory=True)

    with pytest.raises((AssessError, OSError)):
        host_processes.register_process_ownership(
            engagement,
            run_uuid="run-parent",
            ownership=_ownership(),
        )
    with pytest.raises((AssessError, OSError)):
        host_processes.unregister_process(engagement, run_uuid="run-parent")

    assert victim.read_bytes() == b"KEEP-PARENT"
    assert not (victim_registry / "run-parent.json.tmp").exists()
    assert (engagement / ".runtime").is_symlink()


def test_registry_rejects_symlinked_intermediate_engagement_ancestor(
    tmp_path,
):
    root = tmp_path / "root"
    engagement = root / "slot" / "eng"
    engagement.mkdir(parents=True)
    host_processes.register_process_ownership(
        engagement,
        run_uuid="run-ancestor",
        ownership=_ownership(),
    )
    (root / "slot").rename(root / "slot-pinned")
    victim_parent = tmp_path / "victim-parent"
    victim_registry = victim_parent / "eng" / ".runtime" / "host-processes"
    victim_registry.mkdir(parents=True)
    victim = victim_registry / "run-ancestor.json"
    victim.write_bytes(b"KEEP-ANCESTOR-TARGET")
    (root / "slot").symlink_to(victim_parent, target_is_directory=True)

    with pytest.raises((AssessError, OSError)):
        host_processes.unregister_process(
            engagement,
            run_uuid="run-ancestor",
        )

    assert victim.read_bytes() == b"KEEP-ANCESTOR-TARGET"
    assert (
        root
        / "slot-pinned"
        / "eng"
        / ".runtime"
        / "host-processes"
        / "run-ancestor.json"
    ).is_file()


def test_registry_ignores_preplanted_temp_symlink_and_publishes_regular_record(
    tmp_path,
):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    victim = tmp_path / "temp-target"
    victim.write_bytes(b"KEEP-TEMP-TARGET")
    planted = registry / "run-temp.json.tmp"
    planted.symlink_to(victim)

    final = host_processes.register_process_ownership(
        tmp_path,
        run_uuid="run-temp",
        ownership=_ownership(),
    )

    assert victim.read_bytes() == b"KEEP-TEMP-TARGET"
    assert planted.is_symlink()
    assert stat.S_ISREG(final.lstat().st_mode)
    assert not final.is_symlink()
    record = json.loads(final.read_text(encoding="utf-8"))
    assert record["run_uuid"] == "run-temp"
    assert record["pid"] == 4242


def test_registry_refuses_preexisting_final_symlink_without_touching_target(tmp_path):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    victim = tmp_path / "final-target"
    victim.write_bytes(b"KEEP-FINAL-TARGET")
    final = registry / "run-final.json"
    final.symlink_to(victim)

    with pytest.raises((AssessError, OSError)):
        host_processes.register_process_ownership(
            tmp_path,
            run_uuid="run-final",
            ownership=_ownership(),
        )

    assert victim.read_bytes() == b"KEEP-FINAL-TARGET"
    assert final.is_symlink()


def test_registry_rejects_symlinked_registry_directory(tmp_path):
    runtime = tmp_path / ".runtime"
    runtime.mkdir()
    victim_registry = tmp_path / "victim-registry"
    victim_registry.mkdir()
    victim = victim_registry / "run-dir.json"
    victim.write_bytes(b"KEEP-DIR-TARGET")
    (runtime / "host-processes").symlink_to(
        victim_registry, target_is_directory=True
    )

    with pytest.raises((AssessError, OSError)):
        host_processes.register_process_ownership(
            tmp_path,
            run_uuid="run-dir",
            ownership=_ownership(),
        )

    assert victim.read_bytes() == b"KEEP-DIR-TARGET"


def test_registry_publication_stays_on_pinned_directory_after_ancestor_swap(
    monkeypatch, tmp_path
):
    (tmp_path / ".runtime" / "host-processes").mkdir(parents=True)
    victim_parent = tmp_path / "victim-parent"
    (victim_parent / "host-processes").mkdir(parents=True)
    original_open = host_processes._open_registry_directory
    swapped = False

    def open_then_swap(*args, **kwargs):
        nonlocal swapped
        descriptor = original_open(*args, **kwargs)
        if not swapped:
            swapped = True
            (tmp_path / ".runtime").rename(tmp_path / ".runtime-pinned")
            (tmp_path / ".runtime").symlink_to(
                victim_parent, target_is_directory=True
            )
        return descriptor

    monkeypatch.setattr(host_processes, "_open_registry_directory", open_then_swap)

    host_processes.register_process_ownership(
        tmp_path,
        run_uuid="run-swap",
        ownership=_ownership(),
    )

    assert (tmp_path / ".runtime-pinned" / "host-processes" / "run-swap.json").is_file()
    assert not (victim_parent / "host-processes" / "run-swap.json").exists()


def test_unregister_removes_only_leaf_symlink_not_its_target(tmp_path):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    victim = tmp_path / "unlink-target"
    victim.write_bytes(b"KEEP-UNLINK-TARGET")
    leaf = registry / "run-unlink.json"
    leaf.symlink_to(victim)

    host_processes.unregister_process(tmp_path, run_uuid="run-unlink")

    assert victim.read_bytes() == b"KEEP-UNLINK-TARGET"
    assert not leaf.exists()
    assert not leaf.is_symlink()


def test_unregister_stays_on_pinned_directory_after_ancestor_swap(
    monkeypatch, tmp_path
):
    host_processes.register_process_ownership(
        tmp_path,
        run_uuid="run-unregister-swap",
        ownership=_ownership(),
    )
    victim_parent = tmp_path / "unregister-victim-parent"
    victim_registry = victim_parent / "host-processes"
    victim_registry.mkdir(parents=True)
    victim = victim_registry / "run-unregister-swap.json"
    victim.write_bytes(b"KEEP-UNREGISTER-SWAP")
    original_open = host_processes._open_registry_directory
    swapped = False

    def open_then_swap(*args, **kwargs):
        nonlocal swapped
        descriptor = original_open(*args, **kwargs)
        if not swapped:
            swapped = True
            (tmp_path / ".runtime").rename(tmp_path / ".runtime-pinned")
            (tmp_path / ".runtime").symlink_to(
                victim_parent, target_is_directory=True
            )
        return descriptor

    monkeypatch.setattr(host_processes, "_open_registry_directory", open_then_swap)

    host_processes.unregister_process(
        tmp_path, run_uuid="run-unregister-swap"
    )

    assert victim.read_bytes() == b"KEEP-UNREGISTER-SWAP"
    assert not (
        tmp_path
        / ".runtime-pinned"
        / "host-processes"
        / "run-unregister-swap.json"
    ).exists()


def test_reaper_never_traverses_symlinked_registry_ancestor(monkeypatch, tmp_path):
    victim_parent = tmp_path / "reap-victim-parent"
    victim_registry = victim_parent / "host-processes"
    victim_registry.mkdir(parents=True)
    victim = victim_registry / "run-reap.json"
    victim.write_text(
        json.dumps(
            {
                "run_uuid": "run-reap",
                "pid": 4242,
                "pgid": 4242,
                "process_identity": "proof-4242",
                "created_at_epoch": 1,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / ".runtime").symlink_to(victim_parent, target_is_directory=True)
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda *_args: pytest.fail("symlinked registry must never signal"),
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["unverifiable"] == 1
    assert victim.exists()


def test_reaper_rejects_symlinked_record_leaf(monkeypatch, tmp_path):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    target = tmp_path / "external-valid-record.json"
    target.write_text(
        json.dumps(
            {
                "run_uuid": "run-leaf",
                "pid": 4242,
                "pgid": 4242,
                "process_identity": "proof-4242",
                "created_at_epoch": 1,
            }
        ),
        encoding="utf-8",
    )
    (registry / "run-leaf.json").symlink_to(target)
    before = target.read_bytes()
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda *_args: pytest.fail("symlinked record must never signal"),
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["unverifiable"] == 1
    assert target.read_bytes() == before
    assert (registry / "run-leaf.json").is_symlink()


def test_reaper_never_unlinks_record_replacement_after_read(monkeypatch, tmp_path):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    record = host_processes.register_process(tmp_path, run_uuid="run-race", pid=77)
    victim = tmp_path / "replacement-target"
    victim.write_bytes(b"KEEP-REPLACEMENT-TARGET")
    original_read = host_processes._read_record

    def read_then_replace(directory_fd: int, name: str):
        loaded = original_read(directory_fd, name)
        record.unlink()
        record.symlink_to(victim)
        return loaded

    monkeypatch.setattr(host_processes, "_read_record", read_then_replace)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "replacement")

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["stale"] == 1
    assert summary["failed"] == 1
    assert victim.read_bytes() == b"KEEP-REPLACEMENT-TARGET"
    assert record.is_symlink()


def test_reaper_rejects_fifo_record_without_blocking(tmp_path):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    os.mkfifo(registry / "run-fifo.json", 0o600)
    script = "\n".join(
        (
            "import json",
            "import sys",
            "from assess.lib import host_processes",
            "result = host_processes.reap_registered_processes(",
            "    sys.argv[1], max_age_seconds=0, now_epoch=10**12",
            ")",
            "print(json.dumps(result))",
        )
    )

    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path)],
        cwd=Path(__file__).resolve().parents[2],
        check=True,
        capture_output=True,
        text=True,
        timeout=2,
    )

    assert json.loads(completed.stdout)["unverifiable"] == 1


@pytest.mark.parametrize(
    "run_uuid",
    ["", ".", "..", "../escape", "nested/run", "control\nchar"],
)
def test_registry_rejects_unsafe_run_uuid_before_filesystem_access(
    run_uuid, tmp_path
):
    with pytest.raises(AssessError, match="run_uuid"):
        host_processes.register_process_ownership(
            tmp_path,
            run_uuid=run_uuid,
            ownership=_ownership(),
        )
    with pytest.raises(AssessError, match="run_uuid"):
        host_processes.unregister_process(tmp_path, run_uuid=run_uuid)
    assert not (tmp_path / ".runtime").exists()


def test_reaper_rejects_malformed_records_without_signaling(monkeypatch, tmp_path):
    registry = tmp_path / ".runtime" / "host-processes"
    registry.mkdir(parents=True)
    records = [
        {"pid": True, "pgid": 1, "process_identity": "x", "created_at_epoch": 1},
        {"pid": 0, "pgid": 0, "process_identity": "x", "created_at_epoch": 1},
        {"pid": 7, "pgid": 8, "process_identity": "x", "created_at_epoch": 1},
        {"pid": 7, "pgid": 7, "process_identity": "x", "created_at_epoch": "bad"},
        {"pid": 7, "pgid": 7, "process_identity": False, "created_at_epoch": 1},
        {
            "pid": 10**100,
            "pgid": 10**100,
            "process_identity": "x",
            "created_at_epoch": 1,
        },
    ]
    for index, record in enumerate(records):
        run_uuid = f"malformed-{index}"
        record["run_uuid"] = run_uuid
        (registry / f"{run_uuid}.json").write_text(
            json.dumps(record), encoding="utf-8"
        )
    monkeypatch.setattr(
        host_processes,
        "_terminate_owned_group",
        lambda *_args: pytest.fail("malformed records must never signal"),
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["unverifiable"] == len(records)
    assert len(list(registry.glob("*.json"))) == len(records)


def test_registry_uses_private_modes_and_cleans_failed_publication(
    monkeypatch, tmp_path
):
    final = host_processes.register_process_ownership(
        tmp_path,
        run_uuid="run-modes",
        ownership=_ownership(),
    )
    assert stat.S_IMODE((tmp_path / ".runtime").stat().st_mode) == 0o700
    assert stat.S_IMODE(final.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(final.stat().st_mode) == 0o600

    monkeypatch.setattr(
        host_processes.os,
        "link",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("publish failed")),
    )
    with pytest.raises(OSError, match="publish failed"):
        host_processes.register_process_ownership(
            tmp_path,
            run_uuid="run-publish-fail",
            ownership=_ownership(4343),
        )
    assert not (final.parent / "run-publish-fail.json").exists()
    assert not list(final.parent.glob(".run-publish-fail.*.tmp"))


def test_registry_removes_published_record_when_durability_fails(
    monkeypatch, tmp_path
):
    registry = tmp_path / ".runtime" / "host-processes"
    final = registry / "run-fsync-fail.json"
    original_fsync = host_processes.os.fsync

    def fail_after_publication(descriptor: int) -> None:
        if final.exists():
            raise OSError("directory fsync failed")
        original_fsync(descriptor)

    monkeypatch.setattr(host_processes.os, "fsync", fail_after_publication)

    with pytest.raises(OSError, match="directory fsync failed"):
        host_processes.register_process_ownership(
            tmp_path,
            run_uuid="run-fsync-fail",
            ownership=_ownership(),
        )

    assert not final.exists()
    assert not list(registry.glob(".run-fsync-fail.*.tmp"))


def test_process_identity_uses_high_resolution_native_create_time(monkeypatch):
    monkeypatch.setattr(
        host_processes.Path,
        "read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no procfs")),
    )
    created_at = 1_786_000_001.123456

    class _Process:
        def __init__(self, pid: int) -> None:
            assert pid == 77

        def create_time(self) -> float:
            return created_at

    monkeypatch.setattr(host_processes.psutil, "Process", _Process)

    assert host_processes._process_identity(77) == f"psutil-create:{created_at.hex()}"


def test_process_identity_fails_closed_when_native_create_time_is_unavailable(
    monkeypatch,
):
    monkeypatch.setattr(
        host_processes.Path,
        "read_text",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("no procfs")),
    )
    monkeypatch.setattr(
        host_processes.psutil,
        "Process",
        lambda pid: (_ for _ in ()).throw(host_processes.psutil.AccessDenied(pid)),
    )

    assert host_processes._process_identity(77) is None


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


def test_reaper_reports_registry_cleanup_failure_without_aborting(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "original")
    monkeypatch.setattr(host_processes, "_process_group_id", lambda pid: 77)
    host_processes.register_process(tmp_path, run_uuid="run-1", pid=77)
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "replacement")
    monkeypatch.setattr(
        host_processes,
        "_unlink_matching_entry",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("cleanup failed")),
    )

    summary = host_processes.reap_registered_processes(
        tmp_path, max_age_seconds=0, now_epoch=10**12
    )

    assert summary["stale"] == 1
    assert summary["failed"] == 1


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


def test_owned_group_termination_refuses_unknown_residual_group_state(monkeypatch):
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: None)
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: False)
    monkeypatch.setattr(host_processes, "_group_exists", lambda pgid: None)
    monkeypatch.setattr(
        host_processes.os,
        "killpg",
        lambda *_args: pytest.fail("an unverifiable group must never be signalled"),
    )

    assert host_processes._terminate_owned_group(77, 77, "original") is False


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


def test_in_memory_ownership_refuses_reused_pid_without_signaling(monkeypatch):
    ownership = host_processes.ProcessOwnership(
        pid=77,
        pgid=77,
        process_identity="original",
    )
    monkeypatch.setattr(host_processes, "_process_identity", lambda pid: "replacement")
    monkeypatch.setattr(host_processes, "_pid_exists", lambda pid: True)
    monkeypatch.setattr(
        host_processes.os,
        "killpg",
        lambda *_args: pytest.fail("mismatched process identity must never be signalled"),
    )

    assert host_processes.terminate_owned_process(ownership) is False
