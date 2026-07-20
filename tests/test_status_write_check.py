from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def _minimal_status(write_check: dict[str, object]) -> dict[str, object]:
    return {
        "install_root": "/vigil",
        "install_exists": True,
        "engagement_count": 0,
        "orchestrator": {"state": "stopped", "healthy": False, "readiness": {}},
        "runtime": {"state": "stopped", "mounts_ok": None, "resources": None},
        "mitmproxy": {"state": "stopped", "ca_volume": False},
        "oob": {"state": "stopped", "clients": [], "domain": "-"},
        "backup": {"latest": None, "modified_at": None},
        "legacy_both_missing_code_phase": [],
        "install_staleness": {"state": "current"},
        "database_write_check": write_check,
    }


def _database_path(install_root: Path) -> Path:
    return install_root / "orchestrator" / "backend" / "data" / "orchestrator.sqlite3"


def _seed_database(install_root: Path) -> Path:
    path = _database_path(install_root)
    path.parent.mkdir(parents=True)
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE durable_state (value TEXT NOT NULL)")
        connection.execute("INSERT INTO durable_state VALUES ('kept')")
    return path


def test_database_write_check_rolls_back_probe_table_and_row(tmp_path: Path) -> None:
    from vigil_cli import status as status_module

    install_root = tmp_path / "install"
    path = _seed_database(install_root)

    result = status_module.database_write_check(install_root, timeout_seconds=0.05)

    assert result == {"status": "ok", "database": str(path), "detail": "write rolled back"}
    with sqlite3.connect(path) as connection:
        assert connection.execute("SELECT value FROM durable_state").fetchall() == [("kept",)]
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = '_vigil_status_write_probe'"
        ).fetchone() is None


def test_database_write_check_missing_database_does_not_create_it(tmp_path: Path) -> None:
    from vigil_cli import status as status_module

    install_root = tmp_path / "install"
    path = _database_path(install_root)

    result = status_module.database_write_check(install_root, timeout_seconds=0.01)

    assert result["status"] == "missing_or_unopenable"
    assert result["database"] == str(path)
    assert not path.exists()


def test_database_write_check_reports_busy_without_waiting_for_writer(tmp_path: Path) -> None:
    from vigil_cli import status as status_module

    install_root = tmp_path / "install"
    path = _seed_database(install_root)
    holder = sqlite3.connect(path)
    holder.execute("BEGIN IMMEDIATE")
    try:
        result = status_module.database_write_check(install_root, timeout_seconds=0.01)
    finally:
        holder.rollback()
        holder.close()

    assert result["status"] == "busy"


@pytest.mark.parametrize(
    ("sqlite_code", "expected_status"),
    [
        (sqlite3.SQLITE_READONLY, "read_only"),
        (sqlite3.SQLITE_NOTADB, "storage_error"),
    ],
)
def test_database_write_check_classifies_storage_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sqlite_code: int,
    expected_status: str,
) -> None:
    from vigil_cli import status as status_module

    error = sqlite3.OperationalError("synthetic sqlite failure")
    error.sqlite_errorcode = sqlite_code
    error.sqlite_errorname = "SYNTHETIC"

    def fail_connect(*_args: object, **_kwargs: object) -> None:
        raise error

    monkeypatch.setattr(status_module.sqlite3, "connect", fail_connect)

    result = status_module.database_write_check(tmp_path, timeout_seconds=0.01)

    assert result["status"] == expected_status
    assert result["detail"] == "synthetic sqlite failure"


def test_status_write_check_json_and_text_expose_probe_result(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli.status import print_status

    result = {"status": "ok", "database": "/vigil/db.sqlite3", "detail": "write rolled back"}
    payload = _minimal_status(result)

    print_status(payload, json_output=True)
    assert json.loads(capsys.readouterr().out)["database_write_check"] == result

    print_status(payload)
    assert "database-write\tok\twrite rolled back" in capsys.readouterr().out


def test_status_write_check_cli_requests_probe_and_fails_nonzero_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import main as main_module

    seen: list[bool] = []
    failure = {
        "status": "read_only",
        "database": "/vigil/db.sqlite3",
        "detail": "attempt to write a readonly database",
    }

    def fake_collect(_install_root: Path, *, runner: object, write_check: bool = False):
        seen.append(write_check)
        return _minimal_status(failure)

    monkeypatch.setattr(main_module, "collect_status", fake_collect)

    with pytest.raises(SystemExit) as exc_info:
        main_module.main(["--root", str(tmp_path), "status", "--write-check", "--json"])

    assert exc_info.value.code == 1
    assert seen == [True]
    assert json.loads(capsys.readouterr().out)["database_write_check"] == failure


def test_status_without_write_check_keeps_probe_not_requested(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from vigil_cli import main as main_module

    seen: list[bool] = []
    not_requested = {"status": "not_requested", "database": None, "detail": ""}

    def fake_collect(_install_root: Path, *, runner: object, write_check: bool = False):
        seen.append(write_check)
        return _minimal_status(not_requested)

    monkeypatch.setattr(main_module, "collect_status", fake_collect)

    main_module.main(["--root", str(tmp_path), "status", "--json"])

    assert seen == [False]
    assert json.loads(capsys.readouterr().out)["database_write_check"] == not_requested
