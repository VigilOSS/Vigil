from pathlib import Path

import pytest

from vigil_cli import up


def test_up_stops_when_source_install_fails(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(up, "resolve_source_root", lambda *_args, **_kwargs: tmp_path)
    monkeypatch.setattr(up, "install_from_source", lambda *_args, **_kwargs: (_ for _ in ()).throw(SystemExit("install failed")))
    startup_calls: list[str] = []
    def unexpected_startup(*_args, **_kwargs) -> bool:
        startup_calls.append("runtime")
        raise AssertionError("startup continued after install failure")

    monkeypatch.setattr(up.docker, "container_running", unexpected_startup)

    with pytest.raises(SystemExit, match="install failed"):
        up.run_up(up.UpOptions(install_root=tmp_path, source_root=tmp_path))

    assert startup_calls == []
