from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigil_cli import install_fs, workspace


@pytest.fixture
def absolute_workspace(tmp_path, monkeypatch, request):
    root = tmp_path / "private"
    root.mkdir()
    if request.param:
        for relative in ("agent/engagements", "orchestrator/backend/data", ".runtime-data/logs",
                         "agent/references/tenants"):
            (root / relative).mkdir(parents=True)
    paths = workspace._default_paths(root)
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    metadata = {"schema_version": 1, "paths": {name: str(path) for name, path in paths.items()}}
    (root / "workspace.json").write_text(json.dumps(metadata))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    for key in ("VIGIL_RUNTIME_DATA_DIR", "KALI_MCP_DATA_DIR", "VIGIL_DATA_DIR",
                "REDTEAM_ORCHESTRATOR_DATA_DIR"):
        monkeypatch.delenv(key, raising=False)
    return root, paths


@pytest.mark.parametrize("absolute_workspace", [False, True], indirect=True)
def test_pinned_relative_root_keeps_its_absolute_workspace_identity(absolute_workspace):
    root, paths = absolute_workspace
    original = (root / "workspace.json").read_bytes()
    boundary = install_fs.open_pinned_directory(root)
    assert boundary is not None
    with boundary, boundary.working_directory() as phase_root:
        assert phase_root == Path(".")
        assert workspace.workspace_path(phase_root, "runtime_state") == paths["runtime_state"]
        boundary.require_attached()
    assert (root / "workspace.json").read_bytes() == original


@pytest.mark.parametrize("absolute_workspace", [False, True], indirect=True)
def test_install_allocates_oob_for_same_absolute_workspace_under_pinned_root(
    absolute_workspace, tmp_path, monkeypatch,
):
    from vigil_cli.install import InstallOptions, install_from_source
    from vigil_cli.oob_relay import load_relay_route

    root, paths = absolute_workspace
    application = tmp_path / "application"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "callbacks.example.com")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    result = install_from_source(InstallOptions(application, root, verify_docker_image=False))
    assert result.install_root == root
    route = load_relay_route(root)
    assert route is not None
    assert route.legacy is False
    assert route.base_domain == "callbacks.example.com"
    assert route.metadata_path.parent == paths["runtime_state"] / "oob"
    assert route.metadata_path.is_file()
    assert (root / ".vigil-install-meta.json").is_file()
