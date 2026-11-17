"""`vigil assess log` driven through the CLI entry point: engagement selection."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from _fake_client import StubClient

from assess import cli
from assess.commands import log_entry
from assess.lib import config


@pytest.fixture
def recorded(monkeypatch) -> list[tuple[str, str, dict]]:
    """Activity writes as (engagement key, endpoint, payload), with no backend."""
    writes: list[tuple[str, str, dict]] = []

    class _Recorder(StubClient):
        def __init__(self, _base_url: str, engagement_key: str) -> None:
            self.engagement_key = engagement_key

        def post_engagement(self, endpoint: str, payload: dict) -> dict:
            writes.append((self.engagement_key, endpoint, payload))
            return {**payload, "id": len(writes)}

        def post_event(self, _payload: dict) -> None:
            return None

    monkeypatch.setattr(log_entry, "AssessmentClient", _Recorder)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:9")
    monkeypatch.delenv("VIGIL_SESSION_ENGAGEMENT_DIR", raising=False)
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    return writes


def _engagement(root: Path, key: str) -> Path:
    engagement = root / key
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text('{"status": "in_progress"}', encoding="utf-8")
    return engagement


def _row(title: str, action: str, result: str) -> dict:
    return {"actor_kind": "hook", "actor_name": "hook-agent", "title": title, "action": action, "result": result}


@pytest.mark.parametrize("cwd_kind", ["outside_any_engagement", "inside_another_engagement"])
def test_log_records_into_the_engagement_the_root_flag_selects(
    monkeypatch, tmp_path: Path, recorded, cwd_kind: str
) -> None:
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    cwd = (
        tmp_path / "elsewhere" if cwd_kind == "outside_any_engagement"
        else _engagement(tmp_path, "2026-11-16-acme-other")
    )
    cwd.mkdir(exist_ok=True)
    monkeypatch.chdir(cwd)

    cli.main([
        "--engagement-dir", str(engagement), "log", "--actor-kind", "hook",
        "hook-agent", "Write", "file=engagements/acme/notes.md", "",
    ])

    assert recorded == [
        ("2026-11-16-acme-web", "activity-entries", _row("Write", "file=engagements/acme/notes.md", "")),
    ]


def test_log_keeps_the_engagement_positional(monkeypatch, tmp_path: Path, recorded) -> None:
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    monkeypatch.chdir(_engagement(tmp_path, "2026-11-16-acme-other"))

    cli.main(["log", "--actor-kind", "hook", str(engagement), "hook-agent", "Bash", "bash: id", "uid=1"])

    assert recorded == [("2026-11-16-acme-web", "activity-entries", _row("Bash", "bash: id", "uid=1"))]


def test_log_takes_option_shaped_values_after_the_separator(monkeypatch, tmp_path: Path, recorded) -> None:
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    monkeypatch.chdir(engagement)

    cli.main([
        "--engagement-dir", str(engagement), "log", "--actor-kind", "hook", "--",
        "hook-agent", "--engagement-dir", "-h", "-n",
    ])

    assert recorded == [("2026-11-16-acme-web", "activity-entries", _row("--engagement-dir", "-h", "-n"))]


def test_log_records_when_the_call_finished(monkeypatch, tmp_path: Path, recorded) -> None:
    """A queued logger names the call's finish time; the backend orders the row by it."""
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    monkeypatch.chdir(engagement)

    cli.main([
        "--engagement-dir", str(engagement), "log", "--actor-kind", "hook",
        "--occurred-at", "2026-11-16T10:00:00.123Z", "--", "hook-agent", "Bash", "bash: id", "uid=1",
    ])

    assert recorded == [("2026-11-16-acme-web", "activity-entries",
                         {**_row("Bash", "bash: id", "uid=1"), "occurred_at": "2026-11-16T10:00:00.123Z"})]


def _future(**delta: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


_NOT_AN_INSTANT = "not an ISO-8601 instant"


@pytest.mark.parametrize(("value", "reason"), [
    ("yesterday", _NOT_AN_INSTANT), ("2026-13-01T00:00:00Z", _NOT_AN_INSTANT),
    ("2026-13-45T25:61:61Z", _NOT_AN_INSTANT), ("", _NOT_AN_INSTANT), ("-x", _NOT_AN_INSTANT),
    ("2026-11-16T10:00:00", "has no UTC offset"),
    ("2999-01-01T00:00:00Z", "in the future"), pytest.param("future-hour", "in the future", id="an_hour_ahead"),
    # The backend refuses both: longer than its 64-character field, and outside the UTC calendar.
    pytest.param("2026-04-17T12:00:00." + "1" * 40 + "+00:00", "longer than 64 characters",
                 id="a_valid_instant_longer_than_the_backend_field"),
    ("0001-01-01T00:00:00+14:00", "outside the UTC calendar"),
])
def test_log_dates_the_row_itself_when_the_finish_time_is_unusable(
    monkeypatch, tmp_path: Path, recorded, value, reason, capsys
) -> None:
    """An unusable finish time still records the row, dated by the backend on arrival; stderr names why.

    A future instant would sort the row above every later one, so it is not forwarded either."""
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    monkeypatch.chdir(engagement)
    value = _future(hours=1) if value == "future-hour" else value

    cli.main(["--engagement-dir", str(engagement), "log", "--actor-kind", "hook",
              f"--occurred-at={value}", "--", "hook-agent", "Bash", "bash: id", "uid=1"])

    assert recorded == [("2026-11-16-acme-web", "activity-entries", _row("Bash", "bash: id", "uid=1"))]
    warning = capsys.readouterr().err
    assert "--occurred-at" in warning and reason in warning


def test_log_keeps_a_finish_time_with_any_utc_offset(monkeypatch, tmp_path: Path, recorded) -> None:
    engagement = _engagement(tmp_path, "2026-11-16-acme-web")
    monkeypatch.chdir(engagement)

    cli.main(["--engagement-dir", str(engagement), "log", "--actor-kind", "hook",
              "--occurred-at", "2026-11-16T15:30:00+05:30", "--", "hook-agent", "Bash", "bash: id", "uid=1"])

    assert recorded == [("2026-11-16-acme-web", "activity-entries",
                         {**_row("Bash", "bash: id", "uid=1"), "occurred_at": "2026-11-16T15:30:00+05:30"})]
