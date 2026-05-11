from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root / "src"))

from ai_threat_hunting_cli.engagements import CreateEngagementOptions, create_engagement


def _copy_agent_fixture(agent_root: Path, sandbox_root: Path, *, client: str) -> None:
    shutil.copytree(agent_root / "scripts", sandbox_root / "scripts")
    shutil.copytree(agent_root / "schemas", sandbox_root / "schemas")
    shutil.copytree(agent_root / "agents", sandbox_root / "agents")
    shutil.copytree(agent_root / "rules", sandbox_root / "rules")
    shutil.copytree(agent_root / "skills", sandbox_root / "skills")
    shutil.copytree(agent_root / "references", sandbox_root / "references")
    if client in {"codex", "both"}:
        shutil.copytree(agent_root / ".codex", sandbox_root / ".codex")
        shutil.copy2(agent_root / "AGENTS.md", sandbox_root / "AGENTS.md")
    if client in {"claude", "both"}:
        shutil.copytree(agent_root / ".claude", sandbox_root / ".claude")
        shutil.copy2(agent_root / "CLAUDE.md", sandbox_root / "CLAUDE.md")
    shutil.copy2(agent_root / "SKILL.md", sandbox_root / "SKILL.md")


def _isolate_orchestrator_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:9")


class _StubBackendHandler(BaseHTTPRequestHandler):
    """Tiny in-process backend that mimics /admin/install-root + /admin/sync-engagements
    so the install-root drift fail-fast logic in `aith engagement create` can be
    exercised without spinning up the real FastAPI app on a port."""

    install_root_value: str = ""
    sync_calls: list[str] = []

    def log_message(self, *args: object, **kwargs: object) -> None:  # noqa: D401
        return  # silence test-noise stderr

    def do_GET(self) -> None:  # noqa: N802 - stdlib API
        if self.path == "/admin/install-root":
            payload = json.dumps({
                "install_root": type(self).install_root_value,
                "engagements_root": type(self).install_root_value + "/agent/engagements",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self) -> None:  # noqa: N802 - stdlib API
        if self.path == "/admin/sync-engagements":
            type(self).sync_calls.append(self.path)
            payload = json.dumps({
                "synced": True,
                "install_root": type(self).install_root_value,
                "engagement_count": 0,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(404)
        self.end_headers()


@contextmanager
def _stub_backend_on_localhost(install_root_value: str):
    """Run a stub HTTP server that responds as the orchestrator would.

    Yields the base URL the CLI should hit. The handler stores the install
    root value the test wants to advertise, plus a list of POST paths
    received so tests can assert on the force-sync behavior.
    """
    handler = _StubBackendHandler
    handler.install_root_value = install_root_value
    handler.sync_calls = []
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[0], server.server_address[1]
        yield f"http://{host}:{port}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_aith_engagement_create_aborts_on_install_root_mismatch(tmp_path: Path, monkeypatch) -> None:
    """If the running orchestrator was started with a different install_root,
    `aith engagement create` must fail fast with the recovery instructions
    instead of leaving the operator to discover the mismatch on their first
    `aith assess kali` call. Data loss prevention — no audit data should be
    routed to a backend that cannot see the engagement."""
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "this-install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")

    other_install_root = str(tmp_path / "other-install")
    with _stub_backend_on_localhost(other_install_root) as (base_url, _handler):
        monkeypatch.setenv("ORCHESTRATOR_BASE_URL", base_url)
        with pytest.raises(SystemExit) as excinfo:
            create_engagement(
                CreateEngagementOptions(
                    install_root=install_root,
                    engagement_type="web",
                    target="https://app.example.com",
                )
            )
    message = str(excinfo.value)
    assert "the running orchestrator does not know about it" in message
    assert other_install_root in message
    assert "Recover by:" in message
    assert "orchestrator restart" in message


def test_aith_engagement_create_force_syncs_on_matching_install_root(tmp_path: Path, monkeypatch) -> None:
    """When the install roots match, `aith engagement create` POSTs
    /admin/sync-engagements so the running backend picks up the new directory
    immediately rather than waiting for the next implicit sync trigger."""
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "matching-install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")

    matching_install_root = str(install_root.resolve())
    with _stub_backend_on_localhost(matching_install_root) as (base_url, handler):
        monkeypatch.setenv("ORCHESTRATOR_BASE_URL", base_url)
        created = create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type="web",
                target="https://app.example.com",
            )
        )
        assert created.path.exists()
        assert "/admin/sync-engagements" in handler.sync_calls


def test_verify_backend_install_root_uses_https_connection_for_https_base_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """HTTPS orchestrator URLs must use TLS-capable http.client connections
    or drift detection silently skips both admin checks."""
    import http.client

    from ai_threat_hunting_cli import engagements as engagement_module

    install_root = tmp_path / "install"
    install_root.mkdir()
    eng_dir = install_root / "agent" / "engagements" / "eng-1"
    eng_dir.mkdir(parents=True)
    requests: list[tuple[str, str, int, str]] = []

    class _Response:
        def __init__(self, status_code: int, payload: dict[str, object] | None = None):
            self.status = status_code
            self._body = json.dumps(payload or {}).encode("utf-8")

        def read(self) -> bytes:
            return self._body

    class _HttpsConnection:
        def __init__(self, host: str, port: int, timeout: int):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.method = ""
            self.path = ""

        def request(self, method: str, path: str) -> None:
            self.method = method
            self.path = path
            requests.append((method, self.host, self.port, path))

        def getresponse(self) -> _Response:
            if self.method == "GET":
                return _Response(200, {"install_root": str(install_root.resolve())})
            return _Response(200, {"synced": True})

        def close(self) -> None:
            return None

    def fail_plain_http(*args, **kwargs):
        raise AssertionError("HTTPS base URLs must not use HTTPConnection")

    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "https://orchestrator.example.test:9443/prefix/")
    monkeypatch.setattr(http.client, "HTTPConnection", fail_plain_http)
    monkeypatch.setattr(http.client, "HTTPSConnection", _HttpsConnection)

    engagement_module._verify_backend_install_root(install_root, eng_dir)

    assert requests == [
        ("GET", "orchestrator.example.test", 9443, "/prefix/admin/install-root"),
        ("POST", "orchestrator.example.test", 9443, "/prefix/admin/sync-engagements"),
    ]


def test_verify_backend_install_root_force_syncs_when_install_root_endpoint_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Older backends can lack /admin/install-root but still expose the sync
    endpoint, so a 404 should only skip drift comparison, not immediate sync."""
    import http.client

    from ai_threat_hunting_cli import engagements as engagement_module

    install_root = tmp_path / "install"
    install_root.mkdir()
    eng_dir = install_root / "agent" / "engagements" / "eng-1"
    eng_dir.mkdir(parents=True)
    requests: list[tuple[str, str, int, str]] = []

    class _Response:
        def __init__(self, status_code: int, payload: dict[str, object] | None = None):
            self.status = status_code
            self._body = json.dumps(payload or {}).encode("utf-8")

        def read(self) -> bytes:
            return self._body

    class _HttpConnection:
        def __init__(self, host: str, port: int, timeout: int):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.method = ""
            self.path = ""

        def request(self, method: str, path: str) -> None:
            self.method = method
            self.path = path
            requests.append((method, self.host, self.port, path))

        def getresponse(self) -> _Response:
            if self.method == "GET":
                return _Response(404)
            return _Response(200, {"synced": True})

        def close(self) -> None:
            return None

    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://orchestrator.example.test:8080/prefix/")
    monkeypatch.setattr(http.client, "HTTPConnection", _HttpConnection)

    engagement_module._verify_backend_install_root(install_root, eng_dir)

    assert requests == [
        ("GET", "orchestrator.example.test", 8080, "/prefix/admin/install-root"),
        ("POST", "orchestrator.example.test", 8080, "/prefix/admin/sync-engagements"),
    ]
    assert "does not expose /admin/install-root" in capsys.readouterr().err


def test_aith_engagement_create_skips_drift_check_when_backend_unreachable(tmp_path: Path, monkeypatch) -> None:
    """Local-only / offline workflows must still succeed: when the backend is
    not running, `aith engagement create` should complete without raising."""
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "offline-install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")

    # Point at a port nothing is listening on. socket.create_connection should
    # raise ConnectionRefusedError (an OSError subclass) and the helper should
    # silently fall through.
    monkeypatch.setenv("ORCHESTRATOR_BASE_URL", "http://127.0.0.1:1")
    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )
    assert created.path.exists()
    assert (created.path / "scope.json").exists()


def test_aith_engagement_create_writes_explicit_web_scope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
            hosts=["app.example.com", "admin.example.com"],
            auth_mode="manual",
            exploit_policy="selected",
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((created.path / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert scope["hostname"] == "app.example.com"
    assert scope["hosts"] == ["app.example.com", "admin.example.com"]
    assert scope["exploit_policy"] == "selected"
    assert scope["exploit_review_state"] == "pending"
    assert scope["approved_targets"] == []
    assert auth["mode"] == "manual"
    assert auth["state"] == "missing"
    assert auth["use_for_requests"] is True
    assert manifest["key"] == created.key
    assert manifest["target"] == "https://app.example.com"
    assert (created.path / "sessions" / "index.json").exists()
    assert (created.path / "start_codex.sh").exists()
    assert (created.path / "start_claude.sh").exists()
    assert (created.path / ".codex" / "config.toml").exists()
    codex_agents = created.path / ".codex" / "agents"
    assert codex_agents.is_symlink()
    assert codex_agents.resolve() == (sandbox_root / ".codex" / "agents").resolve()
    assert (codex_agents / "vulnerability-analyst.toml").exists()
    assert (created.path / ".claude" / "settings.json").exists()
    claude_agents = created.path / ".claude" / "agents"
    assert claude_agents.is_symlink()
    assert claude_agents.resolve() == (sandbox_root / ".claude" / "agents").resolve()
    assert (claude_agents / "vulnerability-analyst.md").exists()


def test_aith_engagement_create_code_mode_with_local_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")
    fake_repo = tmp_path / "my-cool-project"
    fake_repo.mkdir()
    (fake_repo / "main.py").write_text("print('hello')\n", encoding="utf-8")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="code",
            name="my-cool-project",
            repos=[str(fake_repo)],
            exploit_policy="pause",
        )
    )

    scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
    auth = json.loads((created.path / "auth.json").read_text(encoding="utf-8"))
    manifest = json.loads((created.path / "engagement.json").read_text(encoding="utf-8"))

    assert scope["engagement_type"] == "code"
    assert scope["name"] == "my-cool-project"
    assert scope["repos"] == [{"path": str(fake_repo), "name": "my-cool-project"}]
    assert scope["hosts"] == []
    assert scope["current_phase"] == "ingest"
    assert scope["source_repos"] == []
    assert auth["mode"] == "none"
    assert auth["state"] == "none"
    assert manifest["name"] == "my-cool-project"
    assert manifest["target"] == "my-cool-project"
    assert (created.path / "source").is_dir()
    assert (created.path / "start_claude.sh").exists()
    assert not (created.path / "start_codex.sh").exists()


def test_aith_engagement_create_emits_scope_summary(tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch) -> None:
    """Bootstrap should print a one-line scope summary."""
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
            hosts=["app.example.com", "admin.example.com"],
        )
    )

    err = capsys.readouterr().err
    assert "[aith] scope: 2 entries" in err
    # All entries are bare hosts — no wildcard-only-no-apex warning.
    assert "wildcard-only entries lacking explicit apex" not in err


def test_aith_engagement_create_no_warning_under_wildcard_only_scope(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Wildcard scope admits the bare apex (HackerOne / Bugcrowd / VDP convention),
    so bootstrap emits no apex warning."""
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://example.test",
            hosts=["*.example.test"],
        )
    )

    err = capsys.readouterr().err
    assert "[aith] scope: 1 entries" in err
    assert "wildcard-only entries lacking explicit apex" not in err


def test_aith_engagement_create_no_warning_when_apex_listed_alongside_wildcard(
    tmp_path: Path, capsys, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No warning when both apex and wildcard are listed (operator-confirmed apex inclusion)."""
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://example.test",
            hosts=["example.test", "*.example.test"],
        )
    )

    err = capsys.readouterr().err
    assert "[aith] scope: 2 entries" in err
    assert "wildcard-only entries lacking explicit apex" not in err


def test_aith_start_codex_exports_engagement_environment(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="codex")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=https://override.example.test/\n",
        encoding="utf-8",
    )

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "codex").write_text(
        "#!/usr/bin/env bash\n"
        "printf 'ENGAGEMENT_DIR=%s\\n' \"${ENGAGEMENT_DIR:-}\"\n"
        "printf 'AI_THREAT_HUNTING_AGENT_ROOT=%s\\n' \"${AI_THREAT_HUNTING_AGENT_ROOT:-}\"\n"
        "printf 'ORCHESTRATOR_BASE_URL=%s\\n' \"${ORCHESTRATOR_BASE_URL:-}\"\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "codex", 0o755)

    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    env.pop("ORCHESTRATOR_BASE_URL", None)
    launch = subprocess.run(
        [str(created.path / "start_codex.sh")],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(created.path),
        env=env,
    )

    assert f"ENGAGEMENT_DIR={created.path}" in launch.stdout
    assert f"AI_THREAT_HUNTING_AGENT_ROOT={sandbox_root}" in launch.stdout
    assert "ORCHESTRATOR_BASE_URL=https://override.example.test" in launch.stdout


def test_aith_start_codex_keeps_engagement_env_over_install_env(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="codex")
    (install_root / ".env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:9/\n",
        encoding="utf-8",
    )

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )
    (created.path / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:19001/\n",
        encoding="utf-8",
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "codex").write_text(
        "#!/usr/bin/env bash\n"
        "printf 'ORCHESTRATOR_BASE_URL=%s\\n' \"${ORCHESTRATOR_BASE_URL:-}\"\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "codex", 0o755)

    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}
    env.pop("ORCHESTRATOR_BASE_URL", None)
    launch = subprocess.run(
        [str(created.path / "start_codex.sh")],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(created.path),
        env=env,
    )

    assert "ORCHESTRATOR_BASE_URL=http://127.0.0.1:19001" in launch.stdout


def test_aith_engagement_create_does_not_write_agent_name_to_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round 9: AGENT_NAME is NOT planted in the per-engagement env file.

    The default-to-"operator" fallback now lives in
    ``agent/scripts/assess/lib/kali.py:_resolve_agent_name`` so the operator's
    first ``aith assess kali`` call records ``operator`` without any env-file
    plumbing. Specialist dispatch wrappers still export AGENT_NAME=<role>
    explicitly when they launch a subagent.
    """
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    env_text = (created.path / ".orchestrator.env").read_text(encoding="utf-8")
    env_lines = [line.strip() for line in env_text.splitlines() if line.strip()]
    assert not any(line.startswith("AGENT_NAME=") for line in env_lines), (
        "Round 9 dropped AGENT_NAME from .orchestrator.env; the kali.py helper "
        "now defaults to 'operator' when neither the flag nor an env var is set."
    )


def test_aith_launchers_do_not_export_agent_name_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Round 9: start_*.sh launchers no longer source AGENT_NAME from env files.

    The default-to-"operator" behavior moved into kali.py; the launcher only
    handles ORCHESTRATOR_BASE_URL now. Specialist dispatch wrappers continue
    to override AGENT_NAME explicitly.
    """
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="both")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    for client in ("claude", "codex"):
        launcher = created.path / f"start_{client}.sh"
        script_text = launcher.read_text(encoding="utf-8")
        assert "AGENT_NAME" not in script_text, (
            f"Round 9: start_{client}.sh must NOT plant AGENT_NAME — the kali.py "
            f"default handles it. Specialist wrappers override it explicitly."
        )


def test_aith_launchers_respect_explicit_agent_name_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A parent-shell AGENT_NAME export still flows through to the LLM session.

    Specialist dispatch wrappers export AGENT_NAME=<role> before launching the
    LLM. Even though Round 9 dropped the launcher-side env-file plumbing, the
    parent-shell export still inherits naturally because we use ``exec`` in
    the launcher.
    """
    _isolate_orchestrator_url(monkeypatch)
    repo_root = Path(__file__).resolve().parents[3]
    install_root = tmp_path / "install"
    sandbox_root = install_root / "agent"
    sandbox_root.mkdir(parents=True)
    _copy_agent_fixture(repo_root / "agent", sandbox_root, client="claude")

    created = create_engagement(
        CreateEngagementOptions(
            install_root=install_root,
            engagement_type="web",
            target="https://app.example.com",
        )
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "claude").write_text(
        "#!/usr/bin/env bash\nprintf 'AGENT_NAME=%s\\n' \"${AGENT_NAME:-}\"\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "claude", 0o755)

    env_with_override = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "AGENT_NAME": "vulnerability-analyst",
    }
    launch = subprocess.run(
        [str(created.path / "start_claude.sh")],
        text=True,
        capture_output=True,
        check=True,
        cwd=str(created.path),
        env=env_with_override,
    )
    assert "AGENT_NAME=vulnerability-analyst" in launch.stdout
