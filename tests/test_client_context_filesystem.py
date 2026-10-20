"""Managed client assets preserve collisions and reject unsafe reusable state."""
import os

import pytest

from vigil_cli import assessment_clients as clients


def test_matching_helper_without_execute_permission_is_reported(tmp_path):
    helper = tmp_path / "vigil"
    helper.write_bytes(b"helper\n")
    helper.chmod(0o600)
    with pytest.raises(SystemExit, match="mode|collision|executable"):
        clients._write_managed(helper, b"helper\n", executable=True)


def test_source_tree_root_symlink_is_not_followed(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "command.md").write_text("command\n")
    pointer = tmp_path / "pointer"
    pointer.symlink_to(actual, target_is_directory=True)
    with pytest.raises((SystemExit, OSError), match="symlink|symbolic|unsafe"):
        clients._source_files(pointer)


def test_concurrent_operator_collision_is_preserved(tmp_path, monkeypatch):
    target = tmp_path / "vigil"
    original = os.open
    injected = False

    def race(name, flags, *args, **kwargs):
        nonlocal injected
        if not injected and flags & os.O_CREAT and flags & os.O_WRONLY:
            injected = True
            target.write_bytes(b"operator")
        return original(name, flags, *args, **kwargs)

    monkeypatch.setattr(clients.os, "open", race)
    collision = None
    try:
        clients._write_managed(target, b"managed")
    except SystemExit as exc:
        collision = str(exc)
    assert collision is not None
    assert target.read_bytes() == b"operator"


def test_file_collision_does_not_overwrite_operator_content(tmp_path):
    target = tmp_path / "vigil"
    target.write_bytes(b"operator")
    with pytest.raises(SystemExit, match="collision"):
        clients._write_managed(target, b"managed")
    assert target.read_bytes() == b"operator"


@pytest.mark.parametrize("mode", [0o600, 0o644])
def test_native_marketplace_exact_content_reuse_preserves_native_mode(tmp_path, mode):
    target = tmp_path / "marketplace.json"
    target.write_bytes(b'{"name":"acme"}\n')
    target.chmod(mode)
    inode = target.stat().st_ino
    clients._write_managed(target, target.read_bytes(), native_marketplace=True)
    assert target.stat().st_mode & 0o7777 == mode
    assert target.stat().st_ino == inode


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o755, 0o1600])
def test_native_marketplace_rejects_writable_executable_and_special_modes(tmp_path, mode):
    target = tmp_path / "marketplace.json"
    target.write_bytes(b"Acme\n")
    target.chmod(mode)
    with pytest.raises(SystemExit, match="mode|collision"):
        clients._write_managed(target, b"Acme\n", native_marketplace=True)
    assert target.read_bytes() == b"Acme\n"
    assert target.stat().st_mode & 0o7777 == mode


def test_native_marketplace_rejects_changed_content_without_rewriting(tmp_path):
    target = tmp_path / "marketplace.json"
    target.write_bytes(b"operator content\n")
    target.chmod(0o644)
    with pytest.raises(SystemExit, match="collision"):
        clients._write_managed(target, b"managed content\n", native_marketplace=True)
    assert target.read_bytes() == b"operator content\n"
    assert target.stat().st_mode & 0o7777 == 0o644


def test_native_marketplace_rejects_symlink_without_touching_destination(tmp_path):
    destination = tmp_path / "operator.json"
    destination.write_bytes(b"Acme\n")
    destination.chmod(0o644)
    target = tmp_path / "marketplace.json"
    target.symlink_to(destination)
    with pytest.raises(SystemExit, match="collision"):
        clients._write_managed(target, b"Acme\n", native_marketplace=True)
    assert target.is_symlink()
    assert destination.read_bytes() == b"Acme\n"
    assert destination.stat().st_mode & 0o7777 == 0o644


def test_other_managed_json_keeps_private_mode_requirement(tmp_path):
    target = tmp_path / "marketplace.json"
    target.write_bytes(b"Acme\n")
    target.chmod(0o644)
    with pytest.raises(SystemExit, match="mode|collision"):
        clients._write_managed(target, b"Acme\n")


@pytest.mark.parametrize("executable,name", [(True, "marketplace.json"), (False, "hooks.json")])
def test_native_marketplace_allowance_requires_nonexecutable_marketplace(tmp_path, executable, name):
    with pytest.raises(ValueError, match="marketplace"):
        clients._write_managed(tmp_path / name, b"Acme\n", executable=executable, native_marketplace=True)
