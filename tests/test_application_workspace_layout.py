from __future__ import annotations

from pathlib import Path
import json
import tomllib

import pytest

from vigil_cli import paths


REPO_ROOT = Path(__file__).resolve().parents[1]
RELEASE_VERSION = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["version"]


def test_agent_assets_follow_imported_release_not_workspace(tmp_path, monkeypatch):
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    (tmp_path / "agent").mkdir()
    (tmp_path / "agent" / "AGENTS.md").write_text("obsolete copied source")
    assert paths.agent_root(tmp_path) == REPO_ROOT / "agent"


def test_explicit_application_override_does_not_change_workspace_data(tmp_path, monkeypatch):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    assert paths.agent_root(workspace) == application / "agent"
    assert paths.engagements_root(workspace) == workspace / "engagements"
    assert paths.resolve_orchestrator_data_dir(workspace) == workspace / "state"


def test_fresh_workspace_paths_do_not_include_application_trees(tmp_path):
    assert paths.engagements_root(tmp_path) == tmp_path / "engagements"
    assert paths.resolve_orchestrator_data_dir(tmp_path) == tmp_path / "state"


def test_existing_legacy_state_paths_remain_in_place(tmp_path):
    engagements = tmp_path / "agent" / "engagements"
    data = tmp_path / "orchestrator" / "backend" / "data"
    engagements.mkdir(parents=True)
    data.mkdir(parents=True)
    assert paths.engagements_root(tmp_path) == engagements
    assert paths.resolve_orchestrator_data_dir(tmp_path) == data


def test_source_compatibility_api_never_discovers_cwd_or_copied_workspace(tmp_path, monkeypatch):
    (tmp_path / "agent").mkdir()
    (tmp_path / "orchestrator").mkdir()
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    monkeypatch.setenv("VIGIL_DISABLE_SOURCE_SYNC", "1")
    monkeypatch.setattr(paths, "find_repo_root", lambda *_args: None)
    monkeypatch.chdir(tmp_path)
    assert paths.resolve_source_root(install_root=tmp_path) == REPO_ROOT


def test_invalid_explicit_application_override_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(tmp_path / "missing"))
    with pytest.raises(SystemExit, match="application"):
        paths.agent_root(tmp_path)


def test_initialize_fresh_workspace_creates_only_private_data(tmp_path):
    from vigil_cli.workspace import initialize_workspace

    root = tmp_path / "workspace"
    metadata = initialize_workspace(root, REPO_ROOT)
    assert metadata["schema_version"] == 1
    assert json.loads((root / "workspace.json").read_text()) == metadata
    assert {p.name for p in root.iterdir()} == {
        "workspace.json", ".env", "engagements", "state", "tenant-references", "logs", "cache",
    }
    assert paths.agent_root(root) == REPO_ROOT / "agent"


def test_adoption_registers_existing_state_without_copying_or_rewriting_data(tmp_path):
    from vigil_cli.workspace import initialize_workspace

    engagement = tmp_path / "agent" / "engagements" / "acme"
    data = tmp_path / "orchestrator" / "backend" / "data"
    engagement.mkdir(parents=True)
    data.mkdir(parents=True)
    (tmp_path / ".runtime-data" / "logs").mkdir(parents=True)
    (tmp_path / "agent" / "references" / "tenants").mkdir(parents=True)
    files = {
        engagement / "scope.json": json.dumps({"evidence": str(engagement / "evidence.txt")}),
        engagement / ".claude" / "settings.local.json": "custom client config\n",
        data / "orchestrator.db": "synthetic existing database",
        tmp_path / ".env": "ACME_PRIVATE_VALUE=retain-exact-bytes\n",
        tmp_path / "agent" / "custom.md": "operator-authored file",
    }
    for path, payload in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload)
    before = {path: path.read_bytes() for path in files}
    metadata = initialize_workspace(tmp_path, REPO_ROOT)
    assert all(path.read_bytes() == payload for path, payload in before.items())
    assert paths.engagements_root(tmp_path) == engagement.parent
    assert paths.resolve_orchestrator_data_dir(tmp_path) == data
    assert metadata["paths"]["logs"] == ".runtime-data/logs"
    assert not (tmp_path / "engagements").exists()
    assert not (tmp_path / "agent" / "AGENTS.md").exists()
    assert initialize_workspace(tmp_path, REPO_ROOT) == metadata


def test_workspace_metadata_symlink_is_rejected_without_touching_destination(tmp_path):
    from vigil_cli.workspace import initialize_workspace

    outside = tmp_path / "outside.json"
    outside.write_text("retained outside bytes")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "workspace.json").symlink_to(outside)
    with pytest.raises(OSError, match="symbolic link"):
        initialize_workspace(workspace, REPO_ROOT)
    assert outside.read_text() == "retained outside bytes"


def test_install_initializes_workspace_without_copying_application(tmp_path, monkeypatch):
    from vigil_cli.install import InstallOptions, install_from_source

    application = tmp_path / "application"
    root = tmp_path / "workspace"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    (application / "agent" / "release.txt").write_text("matched assets")
    result = install_from_source(InstallOptions(application, root, verify_docker_image=False))
    assert result.source_root == application
    assert (root / "workspace.json").is_file()
    assert not (root / "agent").exists()
    assert not (root / "orchestrator").exists()


def test_install_adopts_without_rewriting_live_client_entrypoints(tmp_path):
    from vigil_cli.install import InstallOptions, install_from_source

    application = tmp_path / "application"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    root = tmp_path / "workspace"
    engagement = root / "agent" / "engagements" / "acme"
    engagement.mkdir(parents=True)
    scope = '{"engagement_type":"offensive","tracks":{"web":{"phase":"recon"}}}'
    (engagement / "scope.json").write_text(scope)
    (engagement / "AGENTS.md").write_text("retained old release pointer")
    (engagement / "start_codex.sh").write_text("#!/bin/sh\n# custom launcher\n")
    result = install_from_source(InstallOptions(application, root, verify_docker_image=False))
    assert result.is_upgrade
    assert (engagement / "scope.json").read_text() == scope
    assert (engagement / "AGENTS.md").read_text() == "retained old release pointer"
    assert (engagement / "start_codex.sh").read_text() == "#!/bin/sh\n# custom launcher\n"


def test_workspace_staleness_compares_release_content_not_private_data(tmp_path, monkeypatch):
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.status import install_staleness

    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    (application / "agent" / "AGENTS.md").write_text("matched release")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    install_from_source(InstallOptions(application, workspace, verify_docker_image=False))
    assert install_staleness(workspace)["state"] == "current"
    (workspace / ".env").write_text("ACME_KEY=changed operator data\n")
    assert install_staleness(workspace)["state"] == "current"
    (application / "agent" / "AGENTS.md").write_text("new release bytes")
    assert install_staleness(workspace)["state"] == "stale"


def test_doctor_uses_release_assets_and_private_workspace_state(tmp_path, monkeypatch):
    from vigil_cli import status
    from vigil_cli.status import Check

    app = tmp_path / "application"
    workspace = tmp_path / "workspace"
    (app / "agent").mkdir(parents=True)
    (app / "orchestrator").mkdir()
    (workspace / "state").mkdir(parents=True)
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(app))
    monkeypatch.setattr(status, "_binary_check", lambda name: Check(name, "MISSING"))
    monkeypatch.setattr(status, "orchestrator_status", lambda *_args: "stopped")
    rows = {row.name: row for row in status.collect_doctor_checks(workspace)}
    assert rows["agent-dir"].status == "OK"
    assert rows["backend-data"].status == "OK"
    assert "npm" not in rows


def test_release_health_checks_work_without_git_or_node(tmp_path, monkeypatch):
    from vigil_cli import status
    monkeypatch.setattr(status, '_binary_check', lambda name: status.Check(name, 'MISSING'))
    rows = {row.name: row for row in status.collect_doctor_checks(tmp_path)}
    assert rows['application'].status == 'OK'
    assert rows['uv'].required is True


def test_automatic_initialization_is_current_without_legacy_install_stamp(tmp_path, monkeypatch):
    from vigil_cli.workspace import initialize_workspace
    from vigil_cli.status import install_staleness

    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(REPO_ROOT))
    initialize_workspace(tmp_path, REPO_ROOT)
    assert not (tmp_path / ".vigil-install-meta.json").exists()
    assert install_staleness(tmp_path)["state"] == "current"


def test_explicit_client_maintenance_refuses_live_old_release_before_rewrites(tmp_path, monkeypatch):
    from vigil_cli import client_sessions
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.application import application_provenance

    engagement = tmp_path / "workspace" / "engagements" / "acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}")
    (engagement / "AGENTS.md").write_text("retain old instructions")
    original = {**application_provenance(REPO_ROOT), "version": "1.0.0", "content_sha256": "a" * 64}
    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: ({
        "pid": 123, "engagement": str(engagement), "application": original,
    },))
    with pytest.raises(SystemExit, match="active client session"):
        install_from_source(InstallOptions(REPO_ROOT, engagement.parent.parent,
            refresh_physical_client_rosters=True, verify_docker_image=False))
    assert (engagement / "AGENTS.md").read_text() == "retain old instructions"


def test_status_exposes_application_identity_and_retained_session_restart(tmp_path, monkeypatch):
    from vigil_cli import status, client_sessions
    from vigil_cli.docker import DockerResult

    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(REPO_ROOT))
    monkeypatch.setattr(status, "_orchestrator_readyz_bundle", lambda _: {"healthy": False, "readiness": {"reachable": False}})
    monkeypatch.setattr(status, "orchestrator_status", lambda _: "stopped")
    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: ({
        "pid": 123, "engagement": str(tmp_path / "engagements/acme"), "client": "codex", "mode": "web",
        "application": {"root": str(tmp_path / "old"), "version": "1.0.0", "content_sha256": "a" * 64},
    },))
    result = status.collect_status(tmp_path, runner=lambda *_args, **_kwargs: DockerResult(1, "", ""))
    assert result["application"]["root"] == str(REPO_ROOT)
    assert result["client_sessions"]["state"] == "stale"
    assert "acme" in result["client_sessions"]["detail"]
    assert "vigil engagement start acme --client codex --mode web" in result["client_sessions"]["remedy"]


def test_explicit_maintenance_rechecks_release_binding_inside_bootstrap_lock(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from vigil_cli import client_sessions, install
    from vigil_cli.application import application_provenance

    workspace = tmp_path / "workspace"
    engagement = workspace / "engagements" / "acme"
    engagement.mkdir(parents=True)
    old = {**application_provenance(REPO_ROOT), "version": "1.0.0", "content_sha256": "a" * 64}
    locked = False
    writes = []

    @contextmanager
    def bootstrap(_workspace, _engagement):
        nonlocal locked
        locked = True
        try:
            yield
        finally:
            locked = False

    monkeypatch.setattr(client_sessions, "client_session_bootstrap", bootstrap)
    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: ({
        "pid": 123, "engagement": str(engagement), "application": old,
    },) if locked else ())
    monkeypatch.setattr(install, "repair_engagement_client_rosters", lambda *_args, **_kwargs: writes.append("repair"))
    with pytest.raises(SystemExit, match="active client session"):
        install.install_from_source(install.InstallOptions(REPO_ROOT, workspace,
            refresh_physical_client_rosters=True, verify_docker_image=False))
    assert not writes


def test_stale_workspace_notice_explains_matched_release_without_source_copy(capsys):
    from vigil_cli.status import _print_install_staleness_warning

    _print_install_staleness_warning({"state": "stale", "installed_sha": "a" * 40,
        "current_source_sha": "b" * 40, "behind_count": 1})
    message = capsys.readouterr().out
    assert "workspace" in message and "vigil install" in message
    assert "matched application" in message


def test_release_provenance_does_not_probe_git(tmp_path, monkeypatch):
    import subprocess
    from vigil_cli import status

    (tmp_path / "bundle.json").write_text("{}")
    probes = []
    def probe(argv, **kwargs):
        probes.append(argv)
        return subprocess.CompletedProcess(argv, 1, "", "")

    monkeypatch.setattr(status.subprocess, "run", probe)
    assert status.source_revision_sha(tmp_path) is None
    assert not probes


def test_direct_finding_renderer_bridge_uses_application_without_checkout_discovery():
    import subprocess
    import sys

    script = """
import sys
from vigil_cli import paths, engagements
paths.find_repo_root = lambda *args: None
sys.path[:] = [entry for entry in sys.path if not entry.endswith('/agent/scripts')]
for name in list(sys.modules):
    if name == 'assess' or name.startswith('assess.'):
        del sys.modules[name]
assert engagements._finding_render().string_list(['Acme']) == ['Acme']
"""
    import os

    result = subprocess.run([sys.executable, "-c", script], text=True, capture_output=True,
                            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src"), "VIGIL_APPLICATION_DIR": str(REPO_ROOT)})
    assert result.returncode == 0, result.stderr


def test_auth_dispatch_pins_explicit_workspace_for_external_engagements(tmp_path, monkeypatch, capsys):
    import json
    import os
    from vigil_cli import auth, main
    from vigil_cli.workspace import initialize_workspace

    workspace = tmp_path / "workspace"
    metadata = initialize_workspace(workspace, REPO_ROOT)
    engagement = tmp_path / "external" / "acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}")
    metadata["paths"]["engagements"] = str(engagement.parent)
    (workspace / "workspace.json").write_text(json.dumps(metadata))
    previous = str(tmp_path / "unrelated")
    monkeypatch.setenv("VIGIL_INSTALL_DIR", previous)
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setattr(auth, "status_line", lambda path, *_args, **_kwargs: str(auth._install_root(path)))
    main.main(["--root", str(workspace), "auth", "status", "acme"])
    assert capsys.readouterr().out.strip() == str(workspace)
    assert os.environ["VIGIL_INSTALL_DIR"] == previous


def test_doctor_reports_application_identity_and_old_client_restart(tmp_path, monkeypatch):
    from vigil_cli import status, client_sessions
    from vigil_cli.status import Check

    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(REPO_ROOT))
    monkeypatch.setattr(status, "_binary_check", lambda name: Check(name, "MISSING"))
    monkeypatch.setattr(status, "orchestrator_status", lambda *_args: "stopped")
    monkeypatch.setattr(client_sessions, "active_client_sessions", lambda _: ({
        "pid": 123, "engagement": str(tmp_path / "engagements/acme"), "client": "codex", "mode": "web",
        "application": {"root": str(tmp_path / "old"), "version": "1.0.0", "content_sha256": "a" * 64},
    },))
    rows = {row.name: row for row in status.collect_doctor_checks(tmp_path)}
    assert f"version={RELEASE_VERSION}" in rows["application"].detail
    assert rows["client-sessions"].status == "STALE"
    assert "vigil engagement start acme --client codex --mode web" in rows["client-sessions"].detail
