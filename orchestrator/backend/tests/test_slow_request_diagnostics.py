"""A stuck HTTP request leaves thread evidence without an external debugger."""
from concurrent.futures import ThreadPoolExecutor
import faulthandler
import threading

from fastapi.testclient import TestClient
from app import main
from app.request_diagnostics import RequestDiagnostics


def test_stalled_readiness_request_emits_one_all_thread_dump(isolate_settings, monkeypatch):
    monkeypatch.setenv("VIGIL_SLOW_REQUEST_SECONDS", "0.02")
    entered, release, dumped = threading.Event(), threading.Event(), threading.Event()
    observations = []
    original = main.database_readiness_flags
    def slow(connection):
        entered.set()
        assert release.wait(3)
        return original(connection)
    def capture(**kwargs):
        observations.append(kwargs)
        dumped.set()
    monkeypatch.setattr(main, "database_readiness_flags", slow)
    monkeypatch.setattr(faulthandler, "dump_traceback", capture)
    with TestClient(main.app) as client, ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(client.get, "/readyz")
        try:
            assert entered.wait(2)
            assert dumped.wait(1), "A stalled request must capture its thread stacks"
        finally:
            release.set()
        assert future.result(2).status_code == 200
    assert len(observations) == 1
    assert observations[0]["all_threads"] is True


def test_normal_request_keeps_its_response_without_a_dump(isolate_settings, monkeypatch):
    monkeypatch.setenv("VIGIL_SLOW_REQUEST_SECONDS", "3600")
    observations = []
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda **kwargs: observations.append(kwargs))
    with TestClient(main.app) as client:
        assert client.get("/readyz").json()["status"] == "ready"
    assert observations == []


def test_restarting_monitor_does_not_revive_its_stopped_worker(monkeypatch):
    monkeypatch.setenv("VIGIL_SLOW_REQUEST_SECONDS", "0.01")
    entered, release = threading.Event(), threading.Event()
    def capture(**kwargs):
        entered.set()
        assert release.wait(3)
    monkeypatch.setattr(faulthandler, "dump_traceback", capture)
    monitor = RequestDiagnostics()
    monitor.start()
    first = monitor._thread
    try:
        monitor.begin("GET", "/acme")
        assert entered.wait(1)
        monitor.stop()
        monitor.start()
        release.set()
        first.join(0.2)
        assert not first.is_alive(), "A stopped diagnostics worker must stay stopped"
    finally:
        release.set()
        monitor.stop()
        first.join(1)
