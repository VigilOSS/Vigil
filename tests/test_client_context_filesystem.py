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
