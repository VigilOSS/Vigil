from __future__ import annotations

import io

from vigil_cli import main, mitmproxy, orchestrator, runtime, status, term, up


class TTY(io.StringIO):
    def isatty(self) -> bool:
        return True


def _minimal_status() -> dict[str, object]:
    return {
        "install_root": "/vigil",
        "application": {"root": "/app", "version": "2.0.0"},
        "orchestrator": {"state": "running", "healthy": True, "readiness": {}},
        "runtime": {"state": "running", "mounts_ok": True, "resources": None},
        "mitmproxy": {"state": "stopped", "ca_volume": True},
        "oob": {"state": "stopped", "clients": [], "domain": "-"},
        "backup": {"latest": None},
        "database_write_check": {"status": "not_requested"},
        "legacy_both_missing_code_phase": [],
        "install_staleness": {"state": "current"},
    }


def test_heading_is_bold_only_for_a_terminal(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    assert term.heading("Vigil status", stream=TTY()) == "\x1b[1mVigil status\x1b[0m"
    assert term.heading("Vigil status", stream=io.StringIO()) == "Vigil status"


def test_status_uses_human_rows_on_a_terminal_and_keeps_plain_contract(monkeypatch, capsys) -> None:
    plain = _minimal_status()
    status.print_status(plain)
    assert "install\t/vigil" in capsys.readouterr().out

    stream = TTY()
    monkeypatch.setattr(status.sys, "stdout", stream)
    status.print_status(plain)
    rendered = stream.getvalue()
    assert "Vigil status" in rendered
    assert "✔ Orchestrator" in rendered
    assert "• Install" in rendered
    assert "\t" not in rendered


def test_doctor_uses_severity_rows_on_a_terminal_and_keeps_plain_contract(monkeypatch, capsys) -> None:
    checks = [
        status.Check("workspace", "OK", "ready"),
        status.Check("docker-daemon", "WARN", "not responding"),
        status.Check("uv", "MISSING", "required", required=True),
    ]
    status.print_doctor(checks)
    assert capsys.readouterr().out == (
        "OK\tworkspace\tready\n"
        "WARN\tdocker-daemon\tnot responding\n"
        "MISSING\tuv\trequired\n"
    )

    stream = TTY()
    monkeypatch.setattr(status.sys, "stdout", stream)
    status.print_doctor(checks)
    rendered = stream.getvalue()
    assert "Vigil doctor" in rendered
    assert "✔ workspace" in rendered
    assert "! docker-daemon" in rendered
    assert "✘ uv" in rendered
    assert "\t" not in rendered


def test_up_progress_uses_rows_only_for_a_terminal(monkeypatch, capsys) -> None:
    up._progress("Runtime", "running")
    assert capsys.readouterr().out == "  Runtime        running\n"

    stream = TTY()
    monkeypatch.setattr(up.sys, "stdout", stream)
    up._progress("Runtime", "running")
    assert "✔ Runtime" in stream.getvalue()


def test_runtime_resources_use_human_rows_on_a_terminal(monkeypatch) -> None:
    state = {
        "container": "vigil",
        "running": True,
        "configured": {"memory_gb": 2, "cpus": 1, "pids_limit": 512, "shm_size": "1g"},
        "egress": {"enabled": False},
        "live": {"memory_max": "2g", "cpu_max": "100000 100000", "pids_max": "512"},
    }
    monkeypatch.setattr(runtime, "runtime_resource_state", lambda *_args, **_kwargs: state)
    stream = TTY()
    monkeypatch.setattr(runtime.sys, "stdout", stream)
    runtime.vigil_runtime_resources()
    rendered = stream.getvalue()
    assert "Runtime resources" in rendered
    assert "✔ Container" in rendered
    assert "• Configured" in rendered
    assert "\t" not in rendered


def test_mitmproxy_status_uses_human_rows_on_a_terminal(monkeypatch) -> None:
    payload = {
        "state": "running",
        "container": "vigil-proxy",
        "port": 8080,
        "port_reachable": True,
        "image": "vigil-proxy:latest",
        "image_present": True,
        "cert_volume": "vigil-mitmproxy-ca",
        "cert_volume_present": True,
        "routes_loaded": 2,
    }
    stream = TTY()
    monkeypatch.setattr(main.sys, "stdout", stream)
    main._print_mitmproxy_status(payload)
    rendered = stream.getvalue()
    assert "mitmproxy status" in rendered
    assert "✔ mitmproxy" in rendered
    assert "• Routes" in rendered
    assert "\t" not in rendered


def test_mitmproxy_status_keeps_plain_records_when_redirected(capsys) -> None:
    main._print_mitmproxy_status({"state": "stopped", "container": "vigil-proxy"})
    assert capsys.readouterr().out.startswith("mitmproxy\tstopped\tcontainer=vigil-proxy\t")


def test_mitmproxy_lifecycle_records_are_human_only_on_a_terminal(monkeypatch, capsys) -> None:
    mitmproxy._emit("mitmproxy\tstarting\tcontainer=vigil-proxy\tport=8080")
    assert capsys.readouterr().out == "mitmproxy\tstarting\tcontainer=vigil-proxy\tport=8080\n"

    stream = TTY()
    monkeypatch.setattr(mitmproxy.sys, "stdout", stream)
    mitmproxy._emit("mitmproxy\trunning\tcontainer=vigil-proxy\tport=8080")
    assert "✔ mitmproxy" in stream.getvalue()
    assert "\t" not in stream.getvalue()


def test_engagement_mode_uses_human_rows_only_for_a_terminal(monkeypatch, capsys) -> None:
    state = {
        "mode": "code",
        "prompt": "/agent/code.md",
        "tracks": {
            "code": {
                "phase": "hunt",
                "prompt": "/agent/code.md",
                "start_command": "vigil engagement start acme --mode code",
            }
        },
        "source": None,
    }
    main._print_engagement_mode(state)
    assert capsys.readouterr().out.startswith("mode: code\nprompt: /agent/code.md\n")

    stream = TTY()
    monkeypatch.setattr(main.sys, "stdout", stream)
    main._print_engagement_mode(state)
    rendered = stream.getvalue()
    assert "Engagement mode" in rendered
    assert "• Mode" in rendered
    assert "\t" not in rendered


def test_engagement_summary_uses_human_rows_on_a_terminal(monkeypatch) -> None:
    stream = TTY()
    monkeypatch.setattr(main.sys, "stderr", stream)
    main._print_create_summary(
        "code",
        target=None,
        name="Acme",
        hosts=[],
        repos=["/src/acme"],
        artifacts=[],
        android_package=None,
    )
    rendered = stream.getvalue()
    assert "Engagement summary" in rendered
    assert "• Type" in rendered
    assert "• Repositories" in rendered
    assert "[vigil]" not in rendered


def test_orchestrator_worker_warning_uses_a_human_row_only_on_a_terminal(monkeypatch, capsys):
    monkeypatch.setenv(orchestrator.WORKERS_ENV, "many")
    options = orchestrator.OrchestratorOptions(install_root=orchestrator.Path("/vigil"))
    assert orchestrator._resolve_worker_count(options) == 1
    assert capsys.readouterr().out.startswith("orchestrator\twarn\t")

    stream = TTY()
    monkeypatch.setattr(orchestrator.sys, "stdout", stream)
    assert orchestrator._resolve_worker_count(options) == 1
    assert "! Orchestrator" in stream.getvalue()
    assert "\t" not in stream.getvalue()


def test_orchestrator_stop_uses_human_lifecycle_rows_on_a_terminal(tmp_path, monkeypatch):
    runtime_dir = tmp_path / "runtime"
    pid_file = runtime_dir / "pids" / "orchestrator.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("4242\n")
    monkeypatch.setattr(orchestrator, "resolve_runtime_state_dir", lambda _root: runtime_dir)
    monkeypatch.setattr(orchestrator, "_pid_alive", lambda _pid: True)
    monkeypatch.setattr(orchestrator, "_signal_process_group", lambda *_args: None)
    monkeypatch.setattr(orchestrator, "_wait_for_pid_exit", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(orchestrator, "_wait_for_port_release", lambda *_args, **_kwargs: True)
    stream = TTY()
    monkeypatch.setattr(orchestrator.sys, "stdout", stream)

    orchestrator.stop_orchestrator(tmp_path)

    rendered = stream.getvalue()
    assert "• Orchestrator" in rendered
    assert "✔ Orchestrator" in rendered
    assert "\t" not in rendered
