"""Readiness endpoint reports database connectivity and schema probes."""
from __future__ import annotations


import importlib
import os
import sqlite3
import sys
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


def test_alignment_compares_exactly_the_labels_its_caller_supplies() -> None:
    """`_aligned_backend_inputs` is pure alignment; the caller owns the set.

    A label in neither `startup` nor `declared` is not compared — which is the
    whole reason `_backend_runtime_snapshot` has to merge `_lazy_input_baseline`
    into the startup side. Reading this exclusion as "a post-startup import is
    current by construction" is what left lazily imported modules permanently
    uncompared; see `test_a_lazily_imported_module_is_baselined_at_the_bytes_it_was_loaded_from`
    for the behavior that now covers them.
    """
    from app.main import _aligned_backend_inputs

    declared = frozenset({"app/db.py"})
    startup = {"app/db.py": "aaa"}
    current = {"app/db.py": "aaa", "agent/scripts/assess/lib/vuln_taxonomy.py": "fresh"}

    before, after = _aligned_backend_inputs(startup, current, declared)

    assert before == after
    assert "agent/scripts/assess/lib/vuln_taxonomy.py" not in before


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


# --- modules first imported after startup -------------------------------------


def _import_recorded_module(tmp_path, monkeypatch, body: str, name: str):
    """Import a real module from under a fake install root, through the real machinery."""
    from app import main as main_module

    package = tmp_path / "agent" / "scripts"
    package.mkdir(parents=True, exist_ok=True)
    module_path = package / f"{name}.py"
    module_path.write_text(body, encoding="utf-8")
    monkeypatch.setattr(main_module, "_BACKEND_INSTALL_ROOT", tmp_path)
    monkeypatch.syspath_prepend(str(package))
    sys.modules.pop(name, None)
    importlib.import_module(name)
    return module_path, f"agent/scripts/{name}.py"


def test_a_lazily_imported_module_is_baselined_at_the_bytes_it_was_loaded_from(
    tmp_path, monkeypatch
) -> None:
    """The blind spot: a module that joins `sys.modules` after startup.

    It is in neither `_BACKEND_STARTUP_INPUTS` nor the declared set, so the
    alignment left it out of the comparison entirely — permanently. The process
    holds the bytes it loaded, a later install replaces them on disk, and the
    drift stays invisible for the life of the process. Being current at first
    load is not the same as being current forever.
    """
    from app import main as main_module

    path, label = _import_recorded_module(
        tmp_path, monkeypatch, "VALUE = 'loaded'\n", "vigil_lazy_probe_one"
    )
    loaded_digest = main_module._file_digest(path)
    assert main_module._lazy_input_baseline({label: loaded_digest}) == {label: loaded_digest}

    # An install now replaces the file. The process still runs the old code, so
    # the baseline must stay at what the import actually read.
    path.write_text("VALUE = 'replaced'\n", encoding="utf-8")
    current_digest = main_module._file_digest(path)
    assert current_digest != loaded_digest
    baseline = main_module._lazy_input_baseline({label: current_digest})
    assert baseline[label] == loaded_digest

    startup, current = main_module._aligned_backend_inputs(
        baseline, {label: current_digest}, frozenset()
    )
    assert startup[label] != current[label], "replaced bytes must read as a restart"


def test_a_byte_identical_rewrite_of_a_lazy_module_is_not_a_restart(
    tmp_path, monkeypatch
) -> None:
    """`vigil install` rewrites every managed file unconditionally.

    The rewrite bumps the mtime of a file whose content never changed, so any
    rule keyed on "was this written after the process started" reports a restart
    after every ordinary install — the exact false positive the rest of this
    module exists to eliminate. Content is the only thing that may decide it.
    """
    from app import main as main_module

    path, label = _import_recorded_module(
        tmp_path, monkeypatch, "VALUE = 'loaded'\n", "vigil_lazy_probe_two"
    )
    loaded_digest = main_module._file_digest(path)
    path.write_bytes(path.read_bytes())  # same bytes, new mtime
    os.utime(path, (main_module._BACKEND_PROCESS_STARTED_AT + 3600,) * 2)

    baseline = main_module._lazy_input_baseline({label: main_module._file_digest(path)})
    startup, current = main_module._aligned_backend_inputs(
        baseline, {label: main_module._file_digest(path)}, frozenset()
    )
    assert startup[label] == current[label] == loaded_digest


def test_a_module_the_recorder_never_saw_is_reported_but_never_gated_on() -> None:
    """Imported through a loader that bypasses PathFinder — provenance unknown.

    pytest's own assertion rewriter is that loader, and it is the only one that
    occurs in practice; a deployed backend has none. So such a label is surfaced
    for an operator, but manufacturing `restart_required` from it would put the
    always-wrong restart notice straight back.
    """
    from app import main as main_module

    label = "agent/scripts/never_recorded_by_the_finder.py"
    loaded = {label: "whatever-is-there-now"}

    assert main_module._lazy_input_baseline(loaded) == {}
    assert main_module._unvouched_lazy_inputs(loaded) == [label]

    startup, current = main_module._aligned_backend_inputs(
        main_module._lazy_input_baseline(loaded), loaded, frozenset()
    )
    assert startup == current, "an unvouched module must not read as drift"


def test_a_vouched_module_is_not_reported_as_unvouched(tmp_path, monkeypatch) -> None:
    from app import main as main_module

    path, label = _import_recorded_module(
        tmp_path, monkeypatch, "VALUE = 'loaded'\n", "vigil_lazy_probe_three"
    )
    loaded = {label: main_module._file_digest(path)}
    assert main_module._unvouched_lazy_inputs(loaded) == []


def test_a_startup_module_is_never_re_baselined() -> None:
    """Startup inputs already have an honest baseline; this must not touch them."""
    from app import main as main_module

    label = next(iter(main_module._BACKEND_STARTUP_INPUTS))
    assert main_module._lazy_input_baseline({label: "something-else"}) == {}


def test_the_import_recorder_sits_directly_ahead_of_pathfinder() -> None:
    """Builtin and frozen imports must still be resolved before it runs."""
    from importlib.machinery import PathFinder

    from app import main as main_module

    assert main_module._ImportDigestRecorder in sys.meta_path
    assert sys.meta_path.index(main_module._ImportDigestRecorder) == sys.meta_path.index(
        PathFinder
    ) - 1
    # Installing twice must not stack a second copy.
    main_module._install_import_digest_recorder()
    assert sys.meta_path.count(main_module._ImportDigestRecorder) == 1


def _add_loaded_cross_tree_label(monkeypatch, label: str, digest: str) -> None:
    """Add one label to what the process reports as loaded, keeping the rest.

    Replacing `_loaded_cross_tree_inputs` outright would drop every cross-tree
    module that IS in the startup snapshot, and each one would then read as
    `<absent>` — a restart for reasons the test never meant to create.
    """
    from app import main as main_module

    real = main_module._loaded_cross_tree_inputs
    monkeypatch.setattr(
        main_module, "_loaded_cross_tree_inputs", lambda: {**real(), label: digest}
    )


def test_readyz_reports_a_replaced_lazy_module_as_requiring_a_restart(
    client, tmp_path, monkeypatch
) -> None:
    """The wiring, not the helper: `/readyz` must actually consult the baseline.

    Every other test here calls `_lazy_input_baseline` directly, so dropping the
    merge in `_backend_runtime_snapshot` would leave them all green while the
    defect returned in full. This drives the real endpoint.
    """
    from app import main as main_module

    path, label = _import_recorded_module(
        tmp_path, monkeypatch, "VALUE = 'loaded'\n", "vigil_lazy_probe_four"
    )
    # Asserted as a delta, not an absolute: a developer checkout edited while the
    # test process runs legitimately has other changed inputs, and this test is
    # about whether THIS module reaches the comparison at all.
    before = client.get("/readyz").json()["backend_runtime"]
    assert label not in before["changed_inputs"]

    # An install replaces the file; the process still holds the old bytes.
    path.write_text("VALUE = 'replaced'\n", encoding="utf-8")
    _add_loaded_cross_tree_label(monkeypatch, label, main_module._file_digest(path))
    runtime = client.get("/readyz").json()["backend_runtime"]

    assert runtime["restart_required"] is True
    assert label in runtime["changed_inputs"]


def test_readyz_names_inputs_whose_provenance_it_could_not_establish(
    client, monkeypatch
) -> None:
    """The unvouched list must carry real labels, not merely be a list.

    It is reported and never gated on, so an assertion that only checks the key
    exists would pass just as well if the field were permanently empty.
    """
    label = "agent/scripts/imported_by_a_bypassing_loader.py"
    _add_loaded_cross_tree_label(monkeypatch, label, "on-disk-now")
    runtime = client.get("/readyz").json()["backend_runtime"]

    # pytest imports its own test modules through the assertion rewriter, which
    # bypasses PathFinder, so a test run legitimately carries more than one
    # unvouched label. What must hold is that ours is named and gates nothing.
    assert label in runtime["unestablished_inputs"]
    assert label not in runtime["changed_inputs"]


def test_the_recorder_does_not_skip_a_finder_installed_after_it(monkeypatch) -> None:
    """Resolution order must be exactly what it would be without the recorder.

    Calling `PathFinder` directly would silently bypass anything installed
    between the two, for every import in the process.
    """
    from app import main as main_module

    calls: list[str] = []

    class _Interposed:
        @staticmethod
        def find_spec(fullname, path=None, target=None):
            calls.append(fullname)
            return None

    index = sys.meta_path.index(main_module._ImportDigestRecorder)
    monkeypatch.setattr(
        sys,
        "meta_path",
        sys.meta_path[: index + 1] + [_Interposed] + sys.meta_path[index + 1 :],
    )
    sys.modules.pop("json.decoder", None)
    importlib.import_module("json.decoder")

    assert "json.decoder" in calls
