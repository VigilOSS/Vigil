"""sweep-orphans reconciles a lost row against the bind mount (I-138d / I-180).

A dead PID means the sweep lost the run's OUTCOME. It does not mean the run
produced nothing: the output streamed to a file this CLI opened and the bind
mount still holds it. The sweep used to PATCH ``{"status": "lost"}`` and nothing
else, so the backend left the pre-exec placeholders in place and a scan that
finished cleanly before its wrapper died reported ``stdout_bytes 0`` with the
whole measurement sitting on disk.

And a ``--destructive`` row finalized this way is not a bookkeeping problem: the
run never reached its trapped ``EXIT`` restore, so a live tenant may still be
holding whatever it granted or deleted. The reaper used to finalize it exactly
like a lost ``curl``.
"""
from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import kali_sweep_orphans as kso
from assess.lib.client import AssessError


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000",
        engagement_key=tmp_path.name,
        engagement_dir=str(tmp_path),
    )


class _FakeClient:
    def __init__(self, rows):
        self._rows = rows
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint):
        return self._rows if "offset=0" in endpoint else []

    def patch(self, endpoint, payload, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        return {
            "id": 1,
            "run_uuid": self._rows[0]["run_uuid"],
            "status": payload.get("status"),
        }

    def close(self):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _MalformedLaterPageClient:
    def __init__(self, prefix: str) -> None:
        self.prefix = prefix

    def get(self, endpoint: str):
        if endpoint.startswith(self.prefix) and "offset=0" in endpoint:
            return [{"id": index + 1} for index in range(1000)]
        return {"unexpected": "object page"}


def _stale_row(tmp_path: Path, *, run_uuid="a1b2c3", destructive=False, output=b""):
    kali_dir = tmp_path / "scans" / "kali"
    kali_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = kali_dir / f"{run_uuid}.out"
    stderr_path = kali_dir / f"{run_uuid}.err"
    stdout_path.write_bytes(output)
    stderr_path.write_bytes(b"")
    started = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(seconds=7200)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "id": 1,
        "status": "running",
        "created_at": started,
        "started_at": started,
        "run_uuid": run_uuid,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "destructive": destructive,
        "agent_name": "exploit-developer",
        "phase": "exploit",
        "argv": ["curl", "-X", "POST", "https://app.example.com/admin/grant"],
    }


def _sweep(monkeypatch, tmp_path, rows, *, dry_run=False):
    fake = _FakeClient(rows)
    monkeypatch.setattr(kso, "load_config", lambda _flag: _cfg(tmp_path))
    monkeypatch.setattr(kso, "AssessmentClient", lambda *a, **k: fake)
    # The pid file is gone, so the row is unambiguously lost.
    monkeypatch.setattr(
        kso,
        "_read_container_pid_result",
        lambda *a, **k: kso._PidReadResult(None, "pid-file-missing"),
    )
    kso.run(
        SimpleNamespace(
            scope="command-runs",
            engagement_dir=str(tmp_path),
            max_age_seconds=3600,
            container_name="vigil",
            dry_run=dry_run,
        )
    )
    return fake


def test_command_run_recovery_rejects_malformed_later_page() -> None:
    client = _MalformedLaterPageClient("command-runs?")

    with pytest.raises(AssessError, match="command-run recovery list"):
        kso._list_command_run_rows(client)


def test_job_recovery_rejects_malformed_later_page() -> None:
    client = _MalformedLaterPageClient("jobs?status=")

    with pytest.raises(AssessError, match="job recovery list"):
        kso._list_running_jobs(client)


def test_lost_row_carries_the_real_byte_count_and_digest(monkeypatch, tmp_path, capsys):
    payload_bytes = b"x" * 10240
    rows = [_stale_row(tmp_path, output=payload_bytes)]

    fake = _sweep(monkeypatch, tmp_path, rows)

    assert len(fake.patches) == 1
    _endpoint, body = fake.patches[0]
    assert body["status"] == "lost"
    assert body["stdout_bytes"] == 10240
    assert len(body["stdout_sha256"]) == 64
    assert body["stdout_preview"]
    # An empty stderr still reports its truth (0 bytes, no digest) so the
    # backend can write a real retention status instead of a placeholder.
    assert body["stderr_bytes"] == 0
    assert body["stderr_sha256"] == ""

    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])["summary"]
    assert summary["finalized"] == 1
    assert summary["output_recovered"] == 1


def test_lost_row_with_no_output_reports_zero_not_a_placeholder(
    monkeypatch, tmp_path, capsys
):
    fake = _sweep(monkeypatch, tmp_path, [_stale_row(tmp_path, output=b"")])

    _endpoint, body = fake.patches[0]
    assert body["stdout_bytes"] == 0
    assert body["stdout_sha256"] == ""
    assert "stdout_preview" not in body  # nothing to preview, so claim nothing

    summary = json.loads(capsys.readouterr().out.strip().splitlines()[-1])["summary"]
    assert summary["output_recovered"] == 0


def test_output_path_outside_the_engagement_is_not_read(monkeypatch, tmp_path):
    """``stdout_path`` is a value the row carries, not one we may trust."""
    outside = tmp_path.parent / "outside.out"
    outside.write_bytes(b"secret")
    row = _stale_row(tmp_path)
    row["stdout_path"] = str(outside)

    fake = _sweep(monkeypatch, tmp_path, [row])

    _endpoint, body = fake.patches[0]
    assert "stdout_bytes" not in body
    assert body["stderr_bytes"] == 0  # the in-engagement stderr still reconciles


def test_destructive_lost_row_raises_a_mutating_run_warning(
    monkeypatch, tmp_path, capsys
):
    fake = _sweep(monkeypatch, tmp_path, [_stale_row(tmp_path, destructive=True)])
    assert fake.patches

    captured = capsys.readouterr()
    assert "mutating_run_terminated_abnormally" in captured.err
    assert "trapped EXIT restore is UNVERIFIED" in captured.err
    assert "/admin/grant" in captured.err  # the argv is named, not just the id

    summary = json.loads(captured.out.strip().splitlines()[-1])["summary"]
    assert summary["mutating_terminated_abnormally"] == 1
    assert summary["mutating_terminated_abnormally_warnings"]


def test_read_only_lost_row_raises_no_mutating_warning(monkeypatch, tmp_path, capsys):
    _sweep(monkeypatch, tmp_path, [_stale_row(tmp_path, destructive=False)])
    captured = capsys.readouterr()
    assert "mutating_run_terminated_abnormally" not in captured.err
    summary = json.loads(captured.out.strip().splitlines()[-1])["summary"]
    assert summary["mutating_terminated_abnormally"] == 0


def test_dry_run_reports_recovery_and_the_mutating_warning_without_patching(
    monkeypatch, tmp_path, capsys
):
    fake = _sweep(
        monkeypatch,
        tmp_path,
        [_stale_row(tmp_path, destructive=True, output=b"y" * 64)],
        dry_run=True,
    )
    assert fake.patches == []

    captured = capsys.readouterr()
    assert "recovered_output_bytes=64" in captured.out
    assert "mutating_run_terminated_abnormally" in captured.err
    summary = json.loads(captured.out.strip().splitlines()[-1])["summary"]
    assert summary["output_recovered"] == 1
    assert summary["mutating_terminated_abnormally"] == 1


def test_terminal_rows_are_never_overwritten_with_lost(monkeypatch, tmp_path):
    row = _stale_row(tmp_path, output=b"done")
    row["status"] = "completed"

    fake = _sweep(monkeypatch, tmp_path, [row])

    assert fake.patches == []
