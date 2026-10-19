from __future__ import annotations

import json
from types import SimpleNamespace
import sys

import pytest

from vigil_cli import auth


@pytest.mark.parametrize("layout", ["fresh", "adopted", "external"])
def test_auth_engagement_resolves_its_registered_private_workspace(tmp_path, monkeypatch, layout):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    engagements = workspace / ("agent/engagements" if layout == "adopted" else "engagements")
    if layout == "external":
        engagements = tmp_path / "retained-engagements"
        monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    else:
        monkeypatch.delenv("VIGIL_INSTALL_DIR", raising=False)
        monkeypatch.delenv("VIGIL_DIR", raising=False)
    engagement = engagements / "acme"
    engagement.mkdir(parents=True)
    (workspace / "workspace.json").write_text(json.dumps({
        "schema_version": 1, "paths": {"engagements": str(engagements), "data": "state", "runtime_state": "state/runtime", "logs": "logs", "cache": "cache", "tenant_references": "tenant-references"},
    }))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "missing-config.json"))
    assert auth._install_root(engagement) == workspace


def test_auth_liveness_classifier_comes_from_pinned_release_not_imported_or_workspace_code(tmp_path, monkeypatch):
    application = tmp_path / "application"
    workspace = tmp_path / "workspace"
    classifier = application / "agent/scripts/assess/lib/auth_liveness.py"
    classifier.parent.mkdir(parents=True)
    (application / "orchestrator").mkdir()
    classifier.write_text("def classify_liveness(*args):\n    return 'unknown', 'matched release classifier'\n")
    old = workspace / "agent/scripts/assess/lib/auth_liveness.py"
    old.parent.mkdir(parents=True)
    old.write_text("def classify_liveness(*args):\n    return 'unknown', 'obsolete workspace classifier'\n")
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setitem(sys.modules, "assess.lib.auth_liveness", SimpleNamespace(
        classify_liveness=lambda *_args: ("unknown", "unrelated imported classifier"),
    ))
    if hasattr(auth._load_liveness_classifier, "cache_clear"):
        auth._load_liveness_classifier.cache_clear()
    assert auth._classify_liveness(None, None, None) == ("unknown", "matched release classifier")
    assert not (classifier.parent / "__pycache__").exists()


def test_auth_script_fallback_uses_matched_application_not_workspace_copy(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    engagement = workspace / "engagements/acme"
    engagement.mkdir(parents=True)
    application = tmp_path / "application"
    (application / "agent").mkdir(parents=True)
    (application / "orchestrator").mkdir()
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(application))
    monkeypatch.setattr(auth.shutil, "which", lambda _: None)
    argv = auth._vigil_assess_argv(engagement, "default", "https://portal.example/profile")
    assert argv[0] == str(application / "agent/scripts/assess.py")
