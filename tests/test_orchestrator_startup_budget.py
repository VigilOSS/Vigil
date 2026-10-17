"""Managed backend startup tolerates migrations but remains bounded and observable."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from vigil_cli import orchestrator


def fake_http_clock(monkeypatch, *, healthy_at=None):
    clock = {"now": 0.0, "attempts": 0}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

    def request(_url, **_kwargs):
        clock["attempts"] += 1
        if healthy_at is not None and clock["now"] >= healthy_at:
            return Response()
        raise OSError("database migration has not finished")

    def sleep(seconds):
        clock["now"] += seconds

    monkeypatch.setattr(orchestrator.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(orchestrator.time, "sleep", sleep)
    monkeypatch.setattr(orchestrator.urllib.request, "urlopen", request)
    return clock


def test_default_startup_allows_large_database_migration_and_reports_wait(monkeypatch, capsys):
    monkeypatch.delenv("VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS", raising=False)
    clock = fake_http_clock(monkeypatch, healthy_at=90.0)
    assert orchestrator._wait_for_health("127.0.0.1", 18000, process=SimpleNamespace(poll=lambda: None))
    assert clock["now"] >= 90.0
    assert "waiting" in capsys.readouterr().out


@pytest.mark.parametrize("endpoint", [orchestrator._wait_for_health, orchestrator._wait_for_readiness])
def test_configured_startup_timeout_still_bounds_unresponsive_child(monkeypatch, endpoint):
    monkeypatch.setenv("VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS", "2.5")
    clock = fake_http_clock(monkeypatch)
    assert endpoint("127.0.0.1", 18000, process=SimpleNamespace(poll=lambda: None)) is False
    assert clock["now"] == pytest.approx(2.5)


def test_exited_backend_does_not_consume_migration_budget(monkeypatch):
    monkeypatch.setenv("VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS", "600")
    clock = fake_http_clock(monkeypatch)
    assert orchestrator._wait_for_health("127.0.0.1", 18000, process=SimpleNamespace(poll=lambda: 1)) is False
    assert clock == {"now": 0.0, "attempts": 0}


@pytest.mark.parametrize("timeout", ["0", "-1", "nan", "inf", "later"])
def test_invalid_startup_budget_is_actionable(monkeypatch, timeout):
    monkeypatch.setenv("VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS", timeout)
    fake_http_clock(monkeypatch, healthy_at=0)
    with pytest.raises(SystemExit, match="VIGIL_ORCHESTRATOR_START_TIMEOUT_SECONDS"):
        orchestrator._wait_for_health("127.0.0.1", 18000)
