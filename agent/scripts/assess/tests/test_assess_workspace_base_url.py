"""`vigil --root <workspace> assess` talks to that workspace's backend.

`assess.lib.config.resolve_base_url` mirrors `vigil_cli.paths.resolve_orchestrator_base_url`
on the assess side of the exec boundary. The global `orchestrator_base_url` setting
belongs to the global default workspace (`paths.global_default_install_root`); a
workspace selected with `--root` keeps its own install-root URL, so two workspaces
can run side by side on different ports.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from assess.lib import config
from vigil_cli import main as vigil_main
from vigil_cli import paths

_GLOBAL_URL = "http://127.0.0.1:18000"
_OWN_URL = "http://127.0.0.1:18033"


def _workspace(root: Path, *, env_name: str = ".orchestrator.env") -> Path:
    engagement = root / "engagements" / "acme"
    engagement.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}", encoding="utf-8")
    (root / env_name).write_text(f"ORCHESTRATOR_BASE_URL={_OWN_URL}/\n", encoding="utf-8")
    return engagement


def _write_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    config_path = tmp_path / "vigil-config.json"
    config_path.write_text(json.dumps(values), encoding="utf-8")
    monkeypatch.setenv("VIGIL_CONFIG", str(config_path))


def _assess_environment(monkeypatch: pytest.MonkeyPatch, install_root: Path) -> None:
    """Apply the environment `vigil --root <install_root> assess` execs with."""
    for key in ("ORCHESTRATOR_BASE_URL", "VIGIL_INSTALL_DIR", "VIGIL_DIR"):
        monkeypatch.delenv(key, raising=False)
    exported = vigil_main._assess_exec_environment(install_root, application_root=install_root)
    for key, value in exported.items():
        if os.environ.get(key) != value:
            monkeypatch.setenv(key, value)


@pytest.mark.parametrize("env_name", [".orchestrator.env", ".env"])
def test_root_workspace_reaches_its_own_backend_over_the_global_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, env_name: str
) -> None:
    default_root = tmp_path / "default"
    default_root.mkdir()
    other_root = tmp_path / "other"
    engagement = _workspace(other_root, env_name=env_name)
    _write_config(
        tmp_path, monkeypatch,
        **{"install.root": str(default_root), "orchestrator_base_url": f"{_GLOBAL_URL}/"},
    )
    _assess_environment(monkeypatch, other_root)

    resolved = config.resolve_base_url(str(engagement), str(other_root / "agent"))

    assert resolved == _OWN_URL
    assert resolved == paths.resolve_orchestrator_base_url(other_root, engagement)


def test_root_workspace_without_install_root_setting_keeps_its_own_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other_root = tmp_path / "other"
    engagement = _workspace(other_root)
    _write_config(tmp_path, monkeypatch, orchestrator_base_url=f"{_GLOBAL_URL}/")
    _assess_environment(monkeypatch, other_root)

    resolved = config.resolve_base_url(str(engagement), str(other_root / "agent"))

    assert resolved == _OWN_URL
    assert resolved == paths.resolve_orchestrator_base_url(other_root, engagement)


def test_global_default_workspace_keeps_the_global_url_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_root = tmp_path / "default"
    engagement = _workspace(default_root)
    _write_config(
        tmp_path, monkeypatch,
        **{"install.root": str(default_root), "orchestrator_base_url": f"{_GLOBAL_URL}/"},
    )
    _assess_environment(monkeypatch, default_root)

    resolved = config.resolve_base_url(str(engagement), str(default_root / "agent"))

    assert resolved == _GLOBAL_URL
    assert resolved == paths.resolve_orchestrator_base_url(default_root, engagement)


def test_engagement_env_still_outranks_the_workspace_url(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other_root = tmp_path / "other"
    engagement = _workspace(other_root)
    (engagement / ".orchestrator.env").write_text(
        "ORCHESTRATOR_BASE_URL=http://127.0.0.1:18044\n", encoding="utf-8"
    )
    _write_config(
        tmp_path, monkeypatch,
        **{"install.root": str(tmp_path / "default"), "orchestrator_base_url": _GLOBAL_URL},
    )
    _assess_environment(monkeypatch, other_root)

    resolved = config.resolve_base_url(str(engagement), str(other_root / "agent"))

    assert resolved == "http://127.0.0.1:18044"
    assert resolved == paths.resolve_orchestrator_base_url(other_root, engagement)
