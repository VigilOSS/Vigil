from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vigil_cli import install_fs, workspace


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("variable", ["VIGIL_DATA_DIR", "REDTEAM_ORCHESTRATOR_DATA_DIR"])
def test_first_adoption_preserves_external_database_after_override_is_removed(tmp_path, monkeypatch, variable):
    root = tmp_path / "workspace"
    database = tmp_path / "existing-data"
    database.mkdir()
    canary = database / "orchestrator.db"
    canary.write_bytes(b"synthetic existing operator database")
    monkeypatch.delenv("VIGIL_DATA_DIR", raising=False)
    monkeypatch.delenv("REDTEAM_ORCHESTRATOR_DATA_DIR", raising=False)
    monkeypatch.setenv(variable, str(database))

    metadata = workspace.initialize_workspace(root, REPO_ROOT)
    monkeypatch.delenv(variable)

    assert metadata["paths"]["data"] == str(database)
    assert workspace.workspace_path(root, "data") == database
    assert canary.read_bytes() == b"synthetic existing operator database"
    monkeypatch.setenv(variable, str(tmp_path / "transient-override"))
    assert workspace.initialize_workspace(root, REPO_ROOT)["paths"]["data"] == str(database)
    assert not (tmp_path / "transient-override").exists()


@pytest.mark.parametrize("operation", ["validate", "initialize"])
def test_replaced_metadata_is_rejected_instead_of_mixing_workspace_paths(tmp_path, monkeypatch, operation):
    root = tmp_path / "workspace"
    root.mkdir()
    initial = {"schema_version": 1, "paths": {name: str(path) for name, path in workspace._default_paths(root).items()}}
    changed = {"schema_version": 1, "paths": {**initial["paths"], "data": str(tmp_path / "different-data")}}
    path = root / workspace.WORKSPACE_FILENAME
    initial_bytes = json.dumps(initial)
    changed_bytes = json.dumps(changed)
    path.write_text(initial_bytes)
    loads = json.loads
    replaced = False

    def replace_after_read(payload, *args, **kwargs):
        nonlocal replaced
        parsed = loads(payload, *args, **kwargs)
        if parsed == initial and not replaced:
            replaced = True
            replacement = root / "next-workspace.json"
            replacement.write_text(changed_bytes)
            replacement.replace(path)
        return parsed

    monkeypatch.setattr(workspace.json, "loads", replace_after_read)
    with pytest.raises(OSError, match="changed|replaced"):
        if operation == "validate":
            workspace.validate_workspace(root)
        else:
            workspace.initialize_workspace(root, REPO_ROOT)
    assert path.read_text() == changed_bytes
    assert not (root / ".env").exists()
    assert not (tmp_path / "different-data").exists()


def test_concurrent_directory_creation_reopens_the_winning_regular_directory(tmp_path, monkeypatch):
    target = tmp_path / "new-cache"
    mkdir = os.mkdir
    raced = False

    def concurrent_mkdir(name, *args, **kwargs):
        nonlocal raced
        if name == target.name and kwargs.get("dir_fd") is not None and not raced:
            raced = True
            mkdir(name, *args, **kwargs)
        return mkdir(name, *args, **kwargs)

    monkeypatch.setattr(install_fs.os, "mkdir", concurrent_mkdir)
    pin = install_fs.open_pinned_directory(target, create=True)
    assert pin is not None
    with pin:
        pin.require_attached()
        assert target.is_dir()
    assert raced


def test_first_initialization_preserves_env_created_after_absence_check(tmp_path, monkeypatch):
    root = tmp_path / "workspace"
    root.mkdir()
    entry_stat = workspace.entry_stat
    env_checks = 0
    payload = b"ACME_PRIVATE_SETTING=keep-exact-bytes\n"

    def create_after_absence_check(directory_fd, name):
        nonlocal env_checks
        result = entry_stat(directory_fd, name)
        if name == ".env":
            env_checks += 1
            if env_checks == 2 and result is None:
                (root / ".env").write_bytes(payload)
        return result

    monkeypatch.setattr(workspace, "entry_stat", create_after_absence_check)
    workspace.initialize_workspace(root, REPO_ROOT)
    assert env_checks >= 2
    assert (root / ".env").read_bytes() == payload
