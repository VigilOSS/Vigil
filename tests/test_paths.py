import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from vigil_cli import application, paths


def _application(root: Path) -> Path:
    (root / "agent").mkdir(parents=True)
    (root / "orchestrator").mkdir()
    return root


def _bundle(root: Path, *, version="1.1.0", prompt=b"Acme prompt\n") -> Path:
    _application(root)
    (root / "agent/AGENTS.md").write_bytes(prompt)
    files = {"agent/AGENTS.md": hashlib.sha256(prompt).hexdigest()}
    inventory = {"files": files, "executables": []}
    (root / "bundle.json").write_text(json.dumps({
        "schema_version": 1, "version": version, **inventory,
        "content_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
    }))
    return root


def test_source_resolution_uses_imported_checkout_instead_of_destination_or_cwd(tmp_path, monkeypatch):
    checkout = _application(tmp_path / "checkout")
    module = checkout / "src/vigil_cli/application.py"
    module.parent.mkdir(parents=True)
    module.write_text("# module location fixture\n")
    destination = _application(tmp_path / "legacy-workspace")
    cwd = _application(tmp_path / "unrelated-checkout")
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    monkeypatch.setattr(application, "__file__", str(module))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("source resolution must be offline"))
    assert paths.resolve_source_root(install_root=destination) == checkout


def test_explicit_application_override_wins_over_environment(tmp_path, monkeypatch):
    explicit = _application(tmp_path / "explicit")
    inherited = _application(tmp_path / "inherited")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(inherited))
    assert paths.resolve_source_root(explicit) == explicit
    assert paths.resolve_source_root() == inherited


def test_legacy_source_ref_and_repository_settings_cannot_select_old_assets(tmp_path, monkeypatch):
    current = _application(tmp_path / "current")
    old = _application(tmp_path / "source-v1.0.0")
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(current))
    monkeypatch.setenv("VIGIL_SOURCE_DIR", str(old))
    monkeypatch.setenv("VIGIL_SOURCE_REF", "v1.0.0")
    monkeypatch.setenv("VIGIL_SOURCE_REPO", "https://example.com/acme/vigil.git")
    monkeypatch.setattr(paths, "get_config_value", lambda *_a, **_kw: str(old))
    assert paths.resolve_source_root(install_root=old) == current


def test_invalid_bundle_does_not_publish_a_cache_and_retry_is_clean(tmp_path, monkeypatch):
    bundle = _bundle(tmp_path / "bundle")
    cache = tmp_path / "cache"
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(cache))
    (bundle / "agent/AGENTS.md").write_bytes(b"changed source\n")
    with pytest.raises(ValueError, match="content mismatch"):
        application.materialize_bundle(bundle)
    assert not cache.exists()
    (bundle / "agent/AGENTS.md").write_bytes(b"Acme prompt\n")
    release = application.materialize_bundle(bundle)
    assert (release / "agent/AGENTS.md").read_bytes() == b"Acme prompt\n"


def test_missing_application_never_fetches_a_source_checkout(tmp_path, monkeypatch):
    module = tmp_path / "missing/src/vigil_cli/application.py"
    module.parent.mkdir(parents=True)
    module.write_text("# missing application fixture\n")
    monkeypatch.delenv("VIGIL_APPLICATION_DIR", raising=False)
    monkeypatch.setattr(application, "__file__", str(module))
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("missing assets must not trigger a fetch"))
    with pytest.raises(SystemExit, match="matched Vigil application bundle"):
        paths.resolve_source_root()


def test_content_addressed_release_identity_binds_version_and_content(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    one = application.materialize_bundle(_bundle(tmp_path / "one"))
    another_version = application.materialize_bundle(_bundle(tmp_path / "version", version="1.2.0"))
    another_content = application.materialize_bundle(_bundle(tmp_path / "content", prompt=b"Second Acme prompt\n"))
    assert len({one, another_version, another_content}) == 3
    assert one.name.startswith("1.1.0-") and another_version.name.startswith("1.2.0-")
    assert (one / "agent/AGENTS.md").read_bytes() == b"Acme prompt\n"


def test_identical_release_content_reuses_retained_cache_without_network(tmp_path, monkeypatch):
    monkeypatch.setenv("VIGIL_APPLICATION_CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(subprocess, "run", lambda *_a, **_kw: pytest.fail("retained release must not fetch source"))
    first = application.materialize_bundle(_bundle(tmp_path / "first"))
    second = application.materialize_bundle(_bundle(tmp_path / "second"))
    assert first == second
    assert (first / "bin/vigil").stat().st_mode & 0o777 == 0o755
