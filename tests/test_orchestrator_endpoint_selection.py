"""Backend lifecycle commands manage the workspace's own endpoint, and an
explicitly selected workspace never repoints the global default."""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from vigil_cli import engagements, main, orchestrator, paths, preflight, restart_manifest


def _write_receipt(workspace: Path, *, port: int, host: str = "127.0.0.1") -> None:
    directory = workspace / "state/runtime/pids"
    directory.mkdir(parents=True)
    (directory / "orchestrator.pid").write_text("4242\n")
    (directory / "orchestrator.json").write_text(json.dumps({
        "pid": 4242, "process_identity": "acme-birth", "workspace": str(workspace.resolve()),
        "host": host, "port": port, "process_group": 4242,
    }))


@pytest.fixture
def lifecycle(monkeypatch):
    calls: dict[str, list] = {"start": [], "stop": []}
    for module in (main, orchestrator):
        monkeypatch.setattr(module, "start_orchestrator", lambda options: calls["start"].append(options))
        monkeypatch.setattr(module, "stop_orchestrator",
                            lambda root, **kwargs: calls["stop"].append(kwargs))
    monkeypatch.setattr(orchestrator, "_port_in_use", lambda *a: False)
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    return calls


def test_restart_refuses_an_occupied_new_port_before_stopping(tmp_path, monkeypatch, lifecycle):
    _write_receipt(tmp_path, port=18030)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: "acme-birth")
    monkeypatch.setattr(orchestrator, "_port_in_use", lambda host, port: port == 18046)
    monkeypatch.setattr(orchestrator, "_port_listener_pid", lambda *a: None)
    with pytest.raises(SystemExit, match="18046 is already in use"):
        main.main(["--root", str(tmp_path), "orchestrator", "restart", "--port", "18046"])
    assert lifecycle["stop"] == [] and lifecycle["start"] == []


def test_restart_reuses_the_owned_backend_port(tmp_path, monkeypatch, lifecycle):
    _write_receipt(tmp_path, port=18030)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: "acme-birth")
    main.main(["--root", str(tmp_path), "orchestrator", "restart"])
    assert lifecycle["stop"] == [{"host": "127.0.0.1", "port": 18030}]
    assert [(options.host, options.port) for options in lifecycle["start"]] == [("127.0.0.1", 18030)]


def test_restart_ignores_a_receipt_whose_process_is_gone(tmp_path, monkeypatch, lifecycle):
    _write_receipt(tmp_path, port=18030)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: None)
    main.main(["--root", str(tmp_path), "orchestrator", "restart"])
    assert [(options.host, options.port) for options in lifecycle["start"]] == [("127.0.0.1", 18000)]


def test_explicit_port_overrides_start_and_restart(tmp_path, monkeypatch, lifecycle):
    _write_receipt(tmp_path, port=18030)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: "acme-birth")
    main.main(["--root", str(tmp_path), "orchestrator", "start", "--port", "18031"])
    main.main(["--root", str(tmp_path), "orchestrator", "restart", "--port", "18032"])
    assert [options.port for options in lifecycle["start"]] == [18031, 18032]
    # Restart stops the backend that is actually running, then binds the new port.
    assert lifecycle["stop"] == [{"host": "127.0.0.1", "port": 18030}]


def test_start_binds_the_workspace_configured_loopback_port(tmp_path, lifecycle):
    (tmp_path / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=http://127.0.0.1:18033\n")
    main.main(["--root", str(tmp_path), "orchestrator", "start"])
    assert [(options.host, options.port) for options in lifecycle["start"]] == [("127.0.0.1", 18033)]


def test_start_on_a_remote_client_url_keeps_the_local_default(tmp_path, lifecycle):
    (tmp_path / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=https://orchestrator.example.com\n")
    main.main(["--root", str(tmp_path), "orchestrator", "start"])
    assert [(options.host, options.port) for options in lifecycle["start"]] == [("127.0.0.1", 18000)]


def test_port_that_clients_do_not_resolve_is_reported(tmp_path, lifecycle, capsys):
    main.main(["--root", str(tmp_path), "orchestrator", "start", "--port", "18034"])
    err = capsys.readouterr().err
    assert "http://127.0.0.1:18000" in err
    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18034" in err
    assert str(tmp_path / ".orchestrator.env") in err


def test_open_uses_the_owned_backend_endpoint(tmp_path, monkeypatch, lifecycle):
    _write_receipt(tmp_path, port=18035)
    monkeypatch.setattr(orchestrator, "_process_identity", lambda pid: "acme-birth")
    opened = []
    monkeypatch.setattr(main.webbrowser, "open", opened.append)
    main.main(["--root", str(tmp_path), "orchestrator", "open"])
    assert opened == ["http://127.0.0.1:18035"]


def test_open_without_a_backend_uses_the_resolved_url(tmp_path, monkeypatch, lifecycle):
    (tmp_path / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=http://127.0.0.1:18036/\n")
    opened = []
    monkeypatch.setattr(main.webbrowser, "open", opened.append)
    main.main(["--root", str(tmp_path), "orchestrator", "open"])
    assert opened == ["http://127.0.0.1:18036"]


def test_session_start_recovers_a_managed_backend_on_its_configured_port(tmp_path, monkeypatch):
    url = "http://127.0.0.1:18037"
    monkeypatch.setattr(preflight, "resolve_orchestrator_base_url", lambda *a: url)
    monkeypatch.setattr(preflight, "orchestrator_status", lambda *a: "stopped")
    monkeypatch.setattr(engagements, "inspect_backend_ownership", lambda *a: engagements.BackendOwnership(
        engagements.BackendInstallRootStatus.UNREACHABLE, url))
    monkeypatch.setattr(engagements, "_verify_backend_install_root",
                        lambda *a: engagements.BackendInstallRootStatus.VERIFIED)
    monkeypatch.setattr(engagements, "_backend_request", lambda *a: (404, b"", "", False))
    started = []
    monkeypatch.setattr(orchestrator, "start_orchestrator", started.append)
    preflight._ensure_engagement_backend(tmp_path, tmp_path / "acme")
    assert [(options.host, options.port) for options in started] == [("127.0.0.1", 18037)]


@pytest.mark.parametrize(("url", "endpoint"), [
    ("http://127.0.0.1:18038", ("127.0.0.1", 18038)),
    ("http://localhost:18000/", ("127.0.0.1", 18000)),
    ("http://[::1]:18039", ("::1", 18039)),
    ("http://127.0.0.1", None),
    ("https://127.0.0.1:18000", None),
    ("http://192.0.2.10:18000", None),
    ("http://127.0.0.1:18000/api", None),
])
def test_managed_endpoint_is_any_literal_loopback_http_port(url, endpoint):
    assert preflight.managed_backend_endpoint(url) == endpoint


def test_stale_custom_port_backend_restarts_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "resolve_install_root", lambda: tmp_path)
    remedy = restart_manifest.backend_restart_remedy(tmp_path, "http://127.0.0.1:18040")
    assert "`vigil orchestrator restart`" in remedy


# --- workspace-own endpoint vs the global client default ---------------------

def _global_config(tmp_path: Path, monkeypatch, **values: str) -> None:
    config = tmp_path / "vigil-config.json"
    config.write_text(json.dumps(values))
    monkeypatch.setenv("VIGIL_CONFIG", str(config))
    monkeypatch.delenv("ORCHESTRATOR_BASE_URL", raising=False)
    monkeypatch.delenv("VIGIL_INSTALL_DIR", raising=False)
    monkeypatch.delenv("VIGIL_DIR", raising=False)


def test_selected_workspace_uses_its_own_endpoint_over_the_global_url(tmp_path, monkeypatch):
    default, other = tmp_path / "default", tmp_path / "other"
    for root in (default, other):
        root.mkdir()
        (root / ".orchestrator.env").write_text(f"ORCHESTRATOR_BASE_URL=http://127.0.0.1:{18041 if root == other else 18042}\n")
    _global_config(tmp_path, monkeypatch, **{"install.root": str(default),
                                             "orchestrator_base_url": "http://127.0.0.1:18043"})
    assert paths.resolve_orchestrator_base_url(other) == "http://127.0.0.1:18041"
    # The global URL still governs the default workspace it was configured for.
    assert paths.resolve_orchestrator_base_url(default) == "http://127.0.0.1:18043"
    # A selected workspace without its own setting still follows the global URL.
    (other / ".orchestrator.env").write_text("")
    assert paths.resolve_orchestrator_base_url(other) == "http://127.0.0.1:18043"


def test_status_for_a_selected_workspace_probes_its_own_endpoint(tmp_path, monkeypatch):
    default, other = tmp_path / "default", tmp_path / "other"
    default.mkdir()
    other.mkdir()
    (other / ".orchestrator.env").write_text("ORCHESTRATOR_BASE_URL=http://127.0.0.1:18044\n")
    _global_config(tmp_path, monkeypatch, **{"install.root": str(default),
                                             "orchestrator_base_url": "http://127.0.0.1:18045"})
    monkeypatch.setattr(orchestrator, "_port_in_use", lambda *a: False)
    payload = orchestrator.orchestrator_status_payload(other)
    assert (payload["host"], payload["port"]) == ("127.0.0.1", 18044)


# --- install never repoints an existing default -------------------------------

@pytest.fixture
def fake_install(monkeypatch, tmp_path):
    monkeypatch.setattr(paths, "DEFAULT_INSTALL_ROOT", tmp_path / "home-vigil")
    monkeypatch.setattr(main, "install_from_source", lambda options: SimpleNamespace(
        install_root=options.install_root, is_upgrade=False, image_built=False, source_root=None))
    monkeypatch.setattr(main, "_print_post_install", lambda *a, **k: None)
    monkeypatch.setattr(main, "resolve_source_root", lambda *a, **k: tmp_path / "application")


def _configured_root() -> str | None:
    from vigil_cli import config
    return config.get_config_value("install.root")


def test_explicit_install_root_keeps_the_existing_default(tmp_path, monkeypatch, fake_install, capsys):
    _global_config(tmp_path, monkeypatch, **{"install.root": str(tmp_path / "primary")})
    main.main(["install", str(tmp_path / "scratch")])
    main.main(["--root", str(tmp_path / "scratch-two"), "install"])
    assert _configured_root() == str(tmp_path / "primary")
    captured = capsys.readouterr()
    assert captured.out.splitlines() == [str(tmp_path / "scratch"), str(tmp_path / "scratch-two")]
    assert "--make-default" in captured.err
    assert str(tmp_path / "primary") in captured.err


def test_make_default_repoints_the_default(tmp_path, monkeypatch, fake_install):
    _global_config(tmp_path, monkeypatch, **{"install.root": str(tmp_path / "primary")})
    main.main(["install", str(tmp_path / "scratch"), "--make-default"])
    assert _configured_root() == str(tmp_path / "scratch")


def test_first_install_records_the_default(tmp_path, monkeypatch, fake_install):
    _global_config(tmp_path, monkeypatch)
    main.main(["install", str(tmp_path / "first")])
    assert _configured_root() == str(tmp_path / "first")


def test_an_unconfigured_existing_home_workspace_is_not_displaced(tmp_path, monkeypatch, fake_install):
    _global_config(tmp_path, monkeypatch)
    (tmp_path / "home-vigil" / "engagements" / "acme").mkdir(parents=True)
    (tmp_path / "home-vigil" / "workspace.json").write_text("{}")
    main.main(["install", str(tmp_path / "scratch")])
    assert _configured_root() is None


def test_dry_run_records_nothing(tmp_path, monkeypatch, fake_install):
    _global_config(tmp_path, monkeypatch)
    monkeypatch.setattr(main, "_print_install_dry_run", lambda *a, **k: None)
    main.main(["install", str(tmp_path / "first"), "--dry-run", "--make-default"])
    assert _configured_root() is None
