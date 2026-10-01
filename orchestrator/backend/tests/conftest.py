import os
import shutil
import sqlite3
import sys
import tempfile
from itertools import count
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

repo_root = Path(__file__).resolve().parents[3]
backend_root = repo_root / "orchestrator" / "backend"
sys.path.insert(0, str(backend_root))

# Disable the scheduled backup timer for the entire test run — the timer
# is a daemon thread that would otherwise fire against test-temp data dirs
# that get torn down between tests, producing log noise and interleaved
# sqlite3 handles across fixtures.
os.environ.setdefault("VIGIL_BACKUP_DISABLED", "1")

# E402: these imports must follow the sys.path.insert + VIGIL_BACKUP_DISABLED
# setup above — importing app.main triggers the backup timer, so the env var
# has to be set first. Reordering to the top would change runtime behavior.
from app.config import settings  # noqa: E402
from app import db as db_module  # noqa: E402
from app import main as main_module  # noqa: E402
from app.main import app  # noqa: E402
from app.services import engagements as engagement_service  # noqa: E402


def _chmod_quietly(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode, follow_symlinks=False)
    except (OSError, NotImplementedError):
        # A symlink on a platform without lchmod, or an entry that vanished
        # under us. Either way the subsequent unlink is what matters.
        pass


def _force_rmtree(path: Path) -> None:
    """Remove ``path`` even when it contains a sealed code snapshot.

    ``vigil assess code snapshot`` deliberately seals captured trees read-only
    — directories ``0555``, files ``0444`` — and
    ``test_code_snapshot_invariants.py`` asserts exactly those modes. Nothing
    inside a ``0555`` directory can be unlinked, so a plain
    ``shutil.rmtree(..., ignore_errors=True)`` over a fixture directory that
    holds a snapshot silently removes almost nothing and leaves the tree behind.

    First pass deletes everything removable — the common case, where there is
    no sealed content, finishes there and costs one walk. Anything left is
    sealed, so re-grant owner write on it and finish the job. ``chmod`` never
    follows symlinks: a test may have pointed one at a directory outside the
    tree, and rmtree only unlinks the link itself.
    """
    if not path.exists():
        return
    shutil.rmtree(path, ignore_errors=True)
    if not path.exists():
        return
    for dirpath, dirnames, filenames in os.walk(path, topdown=False):
        for name in filenames:
            _chmod_quietly(Path(dirpath) / name, 0o600)
        for name in dirnames:
            _chmod_quietly(Path(dirpath) / name, 0o700)
    _chmod_quietly(path, 0o700)
    shutil.rmtree(path)


_session_root: Path | None = None
_schema_root_fallback: list[Path] = []


@pytest.fixture(scope="session")
def test_root():
    global _session_root
    temp_root = Path(tempfile.mkdtemp(prefix="vigil-tests-"))
    _session_root = temp_root
    try:
        yield temp_root
    finally:
        _session_root = None
        for leftover in _schema_root_fallback:
            _force_rmtree(leftover)
        _schema_root_fallback.clear()
        _force_rmtree(temp_root)


_case_counter = count()
_pending_case_roots: list[Path] = []


def _reap_previous_case_roots() -> None:
    """Remove the per-test trees earlier tests finished with.

    Called from ``isolate_settings`` *setup*, not from its teardown. pytest
    finalizes in reverse setup order, and the autouse ``_isolate_vigil_config``
    pulls ``monkeypatch`` into the closure ahead of ``isolate_settings`` — so
    ``isolate_settings`` tears down *first*, while the test's monkeypatches are
    still installed. Several tests here patch ``os.open`` or ``os.unlink``
    globally to prove a no-follow read or that a cleanup path never unlinks a
    mutable name; a removal running at teardown goes straight through those
    patches. By the next test's setup they are gone.

    Best effort on purpose: anything a reap cannot remove stays under the
    session root and goes with it at session teardown, which is where a
    genuine removal failure is worth failing over. It can never reach another
    test — every test gets a directory nothing has written to before.
    """
    for path in _pending_case_roots:
        try:
            _force_rmtree(path)
        except OSError:
            pass
    _pending_case_roots.clear()


_real_init_db = db_module.init_db
_schema_template: Path | None = None


def _build_schema_template(destination: Path) -> None:
    """Run the real ``init_db`` once, into a throwaway data dir, and keep the file."""
    scratch = Path(tempfile.mkdtemp(prefix="vigil-schema-"))
    original_data_dir = settings.data_dir
    try:
        object.__setattr__(settings, "data_dir", scratch)
        db_module._startup_database_fingerprint = None
        _real_init_db()
        built = db_module.database_path()
        db_module.close_thread_connection()
        # Fold the write-ahead log back into the main file so a plain byte copy
        # is a complete database; only `built` is copied, not its -wal/-shm.
        with sqlite3.connect(str(built)) as checkpoint:
            checkpoint.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copyfile(built, destination)
    finally:
        db_module.close_thread_connection()
        db_module._startup_database_fingerprint = None
        object.__setattr__(settings, "data_dir", original_data_dir)
        _force_rmtree(scratch)


def _schema_template_path() -> Path:
    global _schema_template
    if _schema_template is None or not _schema_template.exists():
        root = _session_root
        if root is None:
            # Unreachable while every path into init_db runs under a test, but
            # a template built outside the session root still has to be removed
            # with it rather than left in the temp dir.
            root = Path(tempfile.mkdtemp(prefix="vigil-tests-schema-"))
            _schema_root_fallback.append(root)
        destination = root / "schema-template.sqlite3"
        _build_schema_template(destination)
        _schema_template = destination
    return _schema_template


def _init_db_from_template() -> None:
    """Stand in for ``init_db`` when there is no database to migrate yet.

    ``init_db`` replays the whole schema — 115 tables, 180 indexes, 22 triggers,
    6 FTS5 tables — and every test using the ``client`` fixture pays it against
    a brand-new data dir: ~70ms of CPU each, over a thousand times. The result
    is byte-identical every time, so build it once per session and copy the
    file (~0.9ms) instead.

    Only the create-from-nothing path is substituted. An existing database file
    goes to the real ``init_db``, which owns compatibility checks, the adjacent
    backups, and the schema migrations — the things the migration tests here are
    about. The two globals ``init_db`` publishes on its way out have to be set
    exactly as it sets them: ``_startup_database_fingerprint``, which every
    connection is verified against, and ``_connection_generation``, whose bump
    is what retires the cached per-thread connections pointing at the previous
    test's file.
    """
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    target = db_module.database_path()
    if target.exists():
        _real_init_db()
        return
    shutil.copyfile(_schema_template_path(), target)
    db_module._startup_database_fingerprint = db_module._database_fingerprint(target)
    db_module._connection_generation += 1


db_module.init_db = _init_db_from_template
# `app.main` imported `init_db` by name at module import, so its lifespan holds
# its own reference; rebind that too or the `client` fixture keeps the slow one.
main_module.init_db = _init_db_from_template


@pytest.fixture(autouse=True)
def isolate_settings(test_root):
    """Point ``settings`` at a directory tree nothing else has ever written to.

    Each test gets its own ``case-NNNNN`` root, created empty, rather than a
    shared set of directories wiped on the way in. A shared tree only stays
    isolated while every wipe succeeds, and a wipe here does not: sealed code
    snapshots are 0555 directories of 0444 files, nothing inside them can be
    unlinked, and the old ``shutil.rmtree(..., ignore_errors=True)`` swallowed
    that whole-tree failure — so a snapshot taken mid-run stayed visible to
    every test after it. A directory nothing has written to before cannot
    carry anything forward at all, and skipping the wipe is also the bulk of
    the time this fixture used to cost.
    """
    original_data_dir = settings.data_dir
    original_frontend_dist_dir = settings.frontend_dist_dir
    original_install_dir = settings.install_dir
    _reap_previous_case_roots()
    case_root = test_root / f"case-{next(_case_counter):05d}"
    data_dir = case_root / "orchestrator-data"
    frontend_dist_dir = case_root / "frontend-dist"
    install_dir = case_root / "install-root"
    engagements_dir = install_dir / "agent" / "engagements"

    data_dir.mkdir(parents=True)
    frontend_dist_dir.mkdir(parents=True)
    engagements_dir.mkdir(parents=True)

    object.__setattr__(settings, "data_dir", data_dir)
    object.__setattr__(settings, "frontend_dist_dir", frontend_dist_dir)
    object.__setattr__(settings, "install_dir", install_dir)
    original_db_fingerprint = db_module._startup_database_fingerprint
    original_sync_signature = engagement_service._last_sync_signature
    db_module._startup_database_fingerprint = None
    engagement_service._last_sync_signature = None

    try:
        yield {
            "data_dir": data_dir,
            "frontend_dist_dir": frontend_dist_dir,
            "install_dir": install_dir,
            "engagements_dir": engagements_dir,
        }
    finally:
        db_module.close_thread_connection()
        db_module._startup_database_fingerprint = original_db_fingerprint
        engagement_service._last_sync_signature = original_sync_signature
        object.__setattr__(settings, "data_dir", original_data_dir)
        object.__setattr__(settings, "frontend_dist_dir", original_frontend_dist_dir)
        object.__setattr__(settings, "install_dir", original_install_dir)
        _pending_case_roots.append(case_root)


@pytest.fixture
def client(isolate_settings):
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def _isolate_vigil_config(tmp_path, monkeypatch):
    """Redirect ``$VIGIL_CONFIG`` at a fresh per-test temp path so the persisted
    active-engagement pointer in the operator's ``~/.config/vigil/config.json``
    cannot leak into engagement resolution.

    Several CLI regressions here exercise the engagement resolver
    (``assess.lib.config`` / ``vigil_cli``), whose pointer tier reads
    ``active_engagement_dir`` from that file. On an operator's machine the
    pointer is a live engagement root, so without isolation it wins the resolver
    and those tests see the wrong engagement (or fail to raise). Pointing the
    config at an absent temp file makes the pointer tier read empty. Tests that
    manage ``$ENGAGEMENT_DIR`` or ``$VIGIL_CONFIG`` themselves via monkeypatch
    still override this cleanly (later setenv wins, LIFO teardown restores)."""
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "vigil-config.json"))


@pytest.fixture(autouse=True)
def _isolate_assess_import_cache():
    """CLI tests reload assess modules; backend imports must survive their teardown."""
    saved = {
        name: module for name, module in list(sys.modules.items())
        if name == "assess" or name.startswith("assess.")
    }
    yield
    for name in list(sys.modules):
        if name == "assess" or name.startswith("assess."):
            sys.modules.pop(name, None)
    sys.modules.update(saved)
