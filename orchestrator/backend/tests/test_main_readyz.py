"""Readiness endpoint reports database connectivity and schema probes."""
from __future__ import annotations


import sqlite3
from contextlib import contextmanager
from pathlib import Path

import pytest


def test_readyz_returns_schema_readiness_flags(client) -> None:
    resp = client.get("/readyz")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "ready"
    assert body["database_connected"] is True
    assert body["assessment_schema_ready"] is True
    assert body["code_analysis_schema_ready"] is True
    runtime = body["backend_runtime"]
    assert runtime["source_root"].endswith("/orchestrator/backend/app")
    assert runtime["process_started_at"].endswith("Z")
    assert isinstance(runtime["restart_required"], bool)
    assert isinstance(runtime["changed_inputs"], list)


def test_sqlite_lock_contention_is_a_retryable_503(client, monkeypatch) -> None:
    from app import main

    @contextmanager
    def locked_connection():
        raise sqlite3.OperationalError("database is locked")
        yield  # pragma: no cover

    monkeypatch.setattr(main, "get_connection", locked_connection)

    response = client.get("/readyz")

    assert response.status_code == 503
    assert response.headers["retry-after"] == "1"
    assert response.json()["detail"] == "database write contention; retry shortly"


# --- Backend restart detection ------------------------------------------------
#
# `vigil install` rewrites every managed file unconditionally (install.py's
# `_sync_dir_fds` -> `copy_regular_file` -> `atomic_write_bytes` never compares
# content), so every install bumps the mtime of every backend `.py`. An mtime
# high-water mark therefore reports a restart is required after an install that
# changed nothing, and stays silent when a NEW DEPENDENCY lands — the one change
# that genuinely cannot work without a restart. Both are asserted against the
# real tree: nothing but a timestamp (or a byte the digest must see) moves.


def _backend_package_root():
    from app.config import BACKEND_ROOT

    return BACKEND_ROOT


def test_readyz_ignores_an_install_that_only_rewrites_mtimes(client) -> None:
    """A byte-identical backend file with a fresh mtime is NOT a restart."""
    import os

    target = _backend_package_root() / "app" / "config.py"
    before = target.stat()
    try:
        os.utime(target, None)  # content untouched; mtime is now newer than start
        runtime = client.get("/readyz").json()["backend_runtime"]
        assert runtime["restart_required"] is False, runtime.get("changed_inputs")
    finally:
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))


def test_readyz_flags_a_changed_dependency_manifest(client) -> None:
    """A new dependency in `pyproject.toml` needs a restart and must be seen."""
    target = _backend_package_root() / "pyproject.toml"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b'\n# a new dependency landed here\n')
        runtime = client.get("/readyz").json()["backend_runtime"]
        assert runtime["restart_required"] is True
        assert "pyproject.toml" in runtime["changed_inputs"]
    finally:
        target.write_bytes(original)


def test_readyz_flags_changed_backend_source_content(client) -> None:
    """A real content change under `app/` still reports a required restart."""
    target = _backend_package_root() / "app" / "config.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# changed\n")
        runtime = client.get("/readyz").json()["backend_runtime"]
        assert runtime["restart_required"] is True
        assert "app/config.py" in runtime["changed_inputs"]
    finally:
        target.write_bytes(original)


def test_readyz_exposes_both_startup_and_current_input_digests(client) -> None:
    runtime = client.get("/readyz").json()["backend_runtime"]
    assert len(runtime["startup_inputs_sha256"]) == 64
    assert len(runtime["current_inputs_sha256"]) == 64
    assert runtime["startup_inputs_sha256"] == runtime["current_inputs_sha256"]
    assert runtime["install_root"]


def test_a_cross_tree_module_loaded_at_startup_is_compared() -> None:
    """`agent/**` is not universally "just prompts".

    `taxonomy_bridge` imports `assess.lib.vuln_taxonomy` at module import time,
    so a file under `agent/` is genuinely running inside this process and a
    change to it needs a restart. Nothing declares that coupling; `sys.modules`
    is what makes it visible.
    """
    from app.main import _aligned_backend_inputs

    declared = frozenset({"app/db.py"})
    startup = {"app/db.py": "aaa", "agent/scripts/assess/lib/vuln_taxonomy.py": "bbb"}
    current = {"app/db.py": "aaa", "agent/scripts/assess/lib/vuln_taxonomy.py": "CHANGED"}

    before, after = _aligned_backend_inputs(startup, current, declared)
    changed = [label for label in before if before[label] != after[label]]

    assert changed == ["agent/scripts/assess/lib/vuln_taxonomy.py"]


def test_a_cross_tree_module_imported_after_startup_is_not_a_restart() -> None:
    """It was read from the current disk state, so it is current by construction."""
    from app.main import _aligned_backend_inputs

    declared = frozenset({"app/db.py"})
    startup = {"app/db.py": "aaa"}
    current = {"app/db.py": "aaa", "agent/scripts/assess/lib/vuln_taxonomy.py": "fresh"}

    before, after = _aligned_backend_inputs(startup, current, declared)

    assert before == after


def test_a_new_declared_file_is_a_restart() -> None:
    """Code the running process does not have yet."""
    from app.main import _aligned_backend_inputs

    declared = frozenset({"app/db.py", "app/brand_new.py"})
    startup = {"app/db.py": "aaa"}
    current = {"app/db.py": "aaa", "app/brand_new.py": "new"}

    before, after = _aligned_backend_inputs(startup, current, declared)
    changed = [label for label in before if before[label] != after[label]]

    assert changed == ["app/brand_new.py"]


def test_a_deleted_module_the_process_still_holds_is_a_restart() -> None:
    from app.main import _aligned_backend_inputs

    declared = frozenset({"app/db.py"})
    startup = {"app/db.py": "aaa", "app/removed.py": "gone-now"}
    current = {"app/db.py": "aaa"}

    before, after = _aligned_backend_inputs(startup, current, declared)
    changed = [label for label in before if before[label] != after[label]]

    assert changed == ["app/removed.py"]


def test_every_top_level_dependency_manifest_is_a_declared_input() -> None:
    """`_BACKEND_DEPENDENCY_MANIFESTS` is hand-maintained; this is its guard.

    A new manifest beside `pyproject.toml`/`uv.lock` (a `requirements.txt`, a
    second lock) would change what the process depends on while being invisible
    to the `app/**` walk — the exact false negative this detection exists to fix.
    """
    from app.main import _declared_backend_inputs

    declared = set(_declared_backend_inputs())
    present = {
        entry.name
        for entry in _backend_package_root().iterdir()
        if entry.is_file() and (entry.suffix in {".toml", ".lock"} or entry.name == "requirements.txt")
    }
    assert present <= declared, f"undeclared dependency manifest: {sorted(present - declared)}"


def test_cross_tree_detection_actually_finds_the_agent_tree_import() -> None:
    """The headline case, asserted against the real process rather than a helper.

    `services/state_manager/taxonomy_bridge` puts `agent/scripts` on `sys.path`
    and imports `assess.lib.vuln_taxonomy` at module-import time. That is the
    reason this detection is derived from `sys.modules` instead of a path table,
    and it is the example the module docstring and `AGENTS.md` both lead with —
    so it needs a test that fails if the derivation stops working, not one that
    exercises a pure helper around it.
    """
    from app import main as backend_main

    # Force the import the bridge performs, so the assertion does not depend on
    # which routers a previous test happened to pull in.
    from app.services.state_manager import taxonomy_bridge

    if not taxonomy_bridge.available():
        pytest.skip("agent tree not present (backend-only deployment)")

    cross_tree = backend_main._loaded_cross_tree_inputs()

    agent_labels = [label for label in cross_tree if label.startswith("agent/")]
    assert agent_labels, (
        "no agent/ file detected in sys.modules; the cross-tree derivation that "
        "`agent/**` is not only prompts has stopped working"
    )
    assert any("vuln_taxonomy" in label for label in agent_labels), agent_labels
    # Every entry must be a real digest of a real file, not a placeholder.
    for label in agent_labels:
        assert (backend_main._BACKEND_INSTALL_ROOT / label).is_file(), label
        assert len(cross_tree[label]) == 64, label


def test_cross_tree_digest_moves_when_the_agent_file_changes(tmp_path: Path) -> None:
    """A changed cross-tree file must change the digest, or the check is inert."""
    from app import main as backend_main

    baseline = {"agent/scripts/assess/lib/vuln_taxonomy.py": "a" * 64}
    changed = {"agent/scripts/assess/lib/vuln_taxonomy.py": "b" * 64}
    assert backend_main._inputs_sha256(baseline) != backend_main._inputs_sha256(changed)
