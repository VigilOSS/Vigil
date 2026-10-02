import argparse
from pathlib import Path

import pytest

from vigil_cli import remediation


@pytest.mark.parametrize("linked_directory", [False, True])
def test_intake_refuses_symlink_destinations(tmp_path: Path, monkeypatch, linked_directory: bool) -> None:
    eng = tmp_path / "eng"
    destination = eng / "remediation/cases/1/source"
    external = tmp_path / "external"
    external.mkdir()
    original = external / "snapshot.json"
    original.write_text('{"report":"same"}')
    source = tmp_path / "issue.json"
    source.write_bytes(original.read_bytes())
    if linked_directory:
        destination.parent.mkdir(parents=True)
        destination.symlink_to(external, target_is_directory=True)
    else:
        destination.mkdir(parents=True)
        (destination / "snapshot.json").symlink_to(original)
    monkeypatch.setattr(remediation, "_api", lambda *_: {})
    before = original.stat().st_mtime_ns
    with pytest.raises(SystemExit, match="symlink"):
        remediation._register_intake_files(tmp_path, eng, "project", {"id": 1}, source, [])
    assert original.read_bytes() == source.read_bytes()
    assert original.stat().st_mtime_ns == before


@pytest.mark.parametrize("contents", [None, "{", "[]"])
def test_import_reports_invalid_snapshot_before_api_write(tmp_path: Path, monkeypatch, contents) -> None:
    source = tmp_path / "issue.json"
    if contents is not None:
        source.write_text(contents)
    monkeypatch.setattr(remediation, "_project", lambda *_: (tmp_path, {}))
    calls = []
    monkeypatch.setattr(remediation, "_api", lambda *args: calls.append(args))
    args = argparse.Namespace(engagement_key="project", remediation_command="import", finding_id=[], snapshot_file=source)
    with pytest.raises(SystemExit, match="snapshot"):
        remediation.run_remediation(args, tmp_path)
    assert calls == []
