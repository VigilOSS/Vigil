"""Tests for `assess.py check-scope-coverage`.

The CLI reads scope.json, calls the backend for services/command-runs/summary,
and reads the local cases.db work_items table. We drive it in-process via a
monkeypatched ``AssessmentClient`` and a real SQLite cases.db so the tests
stay hermetic and don't spin up FastAPI. That mirrors the pattern used in
`test_agent_script_regressions.py::test_check_report_readiness_surfaces_backend_blockers`
so readers can locate prior art without searching.
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs

import pytest


# ---------------------------------------------------------------------------
# Module loader + shared helpers
# ---------------------------------------------------------------------------


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_db_module():
    return _load_script_module(
        "test_check_scope_coverage_db_module",
        "agent/scripts/assess/lib/db.py",
    )


def _load_module():
    return _load_script_module(
        "test_check_scope_coverage_module",
        "agent/scripts/assess/commands/check_scope_coverage.py",
    )


def _make_cases_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "cases.db"
    db_path.touch()
    db_module = _load_db_module()
    db_module.db_init(str(db_path))
    return db_path


def _insert_work_item(
    db_path: Path,
    *,
    queue_key: str,
    url: str,
    url_path: str,
    status: str = "pending",
    case_type: str = "api",
    terminal_reason: str | None = None,
) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """INSERT INTO work_items
            (queue_key, method, url, url_path, query_params, body_params,
             type, source, status, priority_score, cluster_key, terminal_reason)
            VALUES (?, 'GET', ?, ?, '{}', '{}', ?, 'test', ?, 0, NULL, ?)""",
            (queue_key, url, url_path, case_type, status, terminal_reason),
        )
        conn.commit()
    finally:
        conn.close()


def _write_scope(
    engagement_dir: Path,
    *,
    hosts: list[str],
    host_metadata: dict[str, dict[str, Any]] | None = None,
    deferred_hosts: list[str] | None = None,
) -> None:
    scope_path = engagement_dir / "scope.json"
    data: dict[str, Any] = {"hosts": hosts, "current_phase": "recon"}
    if host_metadata:
        data["host_metadata"] = host_metadata
    if deferred_hosts:
        data["deferred_hosts"] = deferred_hosts
    scope_path.write_text(json.dumps(data), encoding="utf-8")


class FakeClient:
    """In-process stand-in for AssessmentClient that serves fixture data."""

    def __init__(
        self,
        *,
        services: list[dict[str, Any]] | None = None,
        command_runs: list[dict[str, Any]] | dict[str, Any] | None = None,
        summary: dict[str, Any] | None = None,
        endpoint_handler=None,
    ) -> None:
        self._services = services or []
        self._command_runs = command_runs or []
        self._summary = summary or {}
        self._endpoint_handler = endpoint_handler
        self.calls: list[str] = []

    def get(self, endpoint: str) -> Any:
        self.calls.append(endpoint)
        if self._endpoint_handler is not None:
            handled = self._endpoint_handler(endpoint)
            if handled is not None:
                return handled
        if endpoint == "services":
            return self._services
        if endpoint.startswith("command-runs"):
            if isinstance(self._command_runs, dict):
                return self._command_runs[endpoint]
            return self._command_runs
        if endpoint == "summary":
            return self._summary
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    def close(self) -> None:
        return None


def _patch_client(monkeypatch, module, *, services=None, command_runs=None, summary=None, endpoint_handler=None) -> list[FakeClient]:
    fake_services = services or []
    fake_runs = command_runs or []
    fake_summary = summary or {}
    created: list[FakeClient] = []

    def _factory(base_url: str, engagement_key: str) -> FakeClient:
        client = FakeClient(
            services=fake_services,
            command_runs=fake_runs,
            summary=fake_summary,
            endpoint_handler=endpoint_handler,
        )
        created.append(client)
        return client

    monkeypatch.setattr(module, "AssessmentClient", _factory)
    return created


def _patch_config(monkeypatch, module, engagement_dir: Path, key: str = "eng") -> None:
    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir_flag: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement_dir),
            engagement_key=key,
            agent_root=str(engagement_dir.parent),
        ),
    )


def _run(
    monkeypatch,
    engagement_dir: Path,
    *,
    services=None,
    command_runs=None,
    summary=None,
    endpoint_handler=None,
    require_stage: str | None = None,
    as_json: bool = True,
    verbose: bool = False,
) -> FakeClient | None:
    module = _load_module()
    _patch_config(monkeypatch, module, engagement_dir)
    clients = _patch_client(
        monkeypatch,
        module,
        services=services,
        command_runs=command_runs,
        summary=summary,
        endpoint_handler=endpoint_handler,
    )
    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            require_stage=require_stage,
            as_json=as_json,
            verbose=verbose,
        )
    )
    return clients[0] if clients else None


# ---------------------------------------------------------------------------
# Required test cases from the plan
# ---------------------------------------------------------------------------


def test_apex_host_full_coverage(monkeypatch, tmp_path: Path, capsys) -> None:
    """Bare host with services, observations, and all work done → ready=true."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="v:1", url="https://target.example/api/one", url_path="/api/one", status="done")
    _insert_work_item(db, queue_key="v:2", url="https://target.example/api/two", url_path="/api/two", status="done")

    services = [
        {"endpoint": "target.example", "state": "up"},
        {"endpoint": "https://target.example/api", "state": "up"},
    ]
    runs = [
        # Surface-collection activity — katana ran against target.example
        {"command": "katana -u https://target.example -jc", "tool_bin": "katana", "tool_name": "katana"},
        # Nuclei reactive sweep
        {"command": "nuclei -u https://target.example", "tool_bin": "nuclei", "tool_name": "nuclei"},
    ]
    summary = {"request_observation_count": 1000, "service_count": 2}

    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary, require_stage="consumption")

    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["ready"] is True, report
    assert report["overall_gaps"] == []
    assert len(report["entries"]) == 1
    entry = report["entries"][0]
    assert entry["scope_entry"] == "target.example"
    assert entry["entry_kind"] == "bare_host"
    assert entry["enum_attempted"] is True
    assert entry["enum_tools"] == ["bare_host"]
    assert entry["collection_attempted"] is True
    assert "katana" in entry["collection_tools"]
    assert entry["live_hosts"] == 1
    assert entry["reactive_nuclei_runs"] == 1
    assert entry["work_queued"]["pending"] == 0
    assert entry["work_queued"]["done"] == 2
    assert entry["gaps"] == []


def test_nuclei_target_list_counts_as_reactive_coverage(monkeypatch, tmp_path: Path, capsys) -> None:
    """File-driven nuclei runs map back to scope entries via /engagements target lists."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)
    target_file = eng / "scans" / "nuclei_delta.txt"
    target_file.parent.mkdir()
    target_file.write_text("https://target.example/login\n", encoding="utf-8")

    services = [{"endpoint": "target.example", "state": "up"}]
    runs = [
        {
            "command": "nuclei -l /engagements/eng/scans/nuclei_delta.txt -jsonl",
            "tool_bin": "nuclei",
            "tool_name": "command",
        },
    ]

    _run(monkeypatch, eng, services=services, command_runs=runs)
    report = json.loads(capsys.readouterr().out)

    entry = report["entries"][0]
    assert entry["reactive_nuclei_runs"] == 1


def test_wildcard_zero_live_hosts(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard with enum attempted but zero live hosts is informational, not a gate failure."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    # Subfinder ran but nothing resolved (empty services list for wildcard).
    services: list[dict[str, Any]] = []
    runs = [
        {"command": "subfinder -d target.example -silent", "tool_bin": "subfinder", "tool_name": "subfinder"},
    ]
    summary = {"request_observation_count": 0, "service_count": 0}

    # --require-stage enum must pass because enum ATTEMPTED is the gate.
    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    assert report["overall_gaps"] == []
    entry = report["entries"][0]
    assert entry["entry_kind"] == "wildcard"
    assert entry["enum_attempted"] is True
    assert "subfinder" in entry["enum_tools"]
    assert entry["live_hosts"] == 0
    # Informational gap only.
    assert "no-live-hosts" in entry["gaps"]


def test_wildcard_partial_collection(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard with live hosts but only 2/5 subdomains crawled by katana.

    Collection is attempted (katana ran at all), so `--require-stage collection`
    passes. Verbose mode still surfaces the partial coverage — which live hosts
    got crawled vs which didn't — because downstream specialists need that
    detail even when the gate clears.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    services = [
        {"endpoint": "api.target.example", "state": "up"},
        {"endpoint": "admin.target.example", "state": "up"},
        {"endpoint": "dev.target.example", "state": "up"},
        {"endpoint": "stage.target.example", "state": "up"},
        {"endpoint": "www.target.example", "state": "up"},
    ]
    runs = [
        {"command": "subfinder -d target.example", "tool_bin": "subfinder", "tool_name": "subfinder"},
        {"command": "katana -u https://api.target.example", "tool_bin": "katana", "tool_name": "katana"},
        {"command": "gau admin.target.example", "tool_bin": "gau", "tool_name": "gau"},
    ]
    summary = {"request_observation_count": 300, "service_count": 5}

    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary, require_stage="collection")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    entry = report["entries"][0]
    assert entry["collection_attempted"] is True
    assert set(entry["collection_tools"]) >= {"katana", "gau"}
    assert entry["live_hosts"] == 5
    assert len(entry["live_host_samples"]) == 5


def test_host_explicitly_deferred(monkeypatch, tmp_path: Path, capsys) -> None:
    """An entry with `status=deferred` in scope metadata passes consumption gate.

    Also exercises the fallback path where every remaining pending item carries
    terminal_reason — that's an implicit deferral that should likewise satisfy
    the consumption gate without the explicit status=deferred tag.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["skip.target.example", "target.example"],
        deferred_hosts=["skip.target.example"],
    )
    db = _make_cases_db(eng)

    # skip.target.example has outstanding pending items but is deferred in scope.
    _insert_work_item(db, queue_key="s:1", url="https://skip.target.example/x", url_path="/x", status="pending")
    _insert_work_item(db, queue_key="s:2", url="https://skip.target.example/y", url_path="/y", status="pending")

    # target.example has pending items but each one carries a terminal_reason, which
    # is how classify-work marks "processed but not worth testing".
    _insert_work_item(
        db, queue_key="t:1", url="https://target.example/a", url_path="/a",
        status="pending", terminal_reason="inert_type",
    )
    _insert_work_item(
        db, queue_key="t:2", url="https://target.example/b", url_path="/b",
        status="pending", terminal_reason="inert_type",
    )

    services = [
        {"endpoint": "skip.target.example", "state": "up"},
        {"endpoint": "target.example", "state": "up"},
    ]
    runs = [
        # Enum + collection both attempted per-host so the earlier gates pass.
        {"command": "subfinder -d target.example", "tool_bin": "subfinder", "tool_name": "subfinder"},
        {"command": "katana -u https://target.example", "tool_bin": "katana", "tool_name": "katana"},
        {"command": "katana -u https://skip.target.example", "tool_bin": "katana", "tool_name": "katana"},
    ]
    summary = {"request_observation_count": 10, "service_count": 2}

    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    by_entry = {e["scope_entry"]: e for e in report["entries"]}
    assert by_entry["skip.target.example"]["status"] == "deferred"
    assert by_entry["skip.target.example"]["gaps"] == []
    # The implicit-terminal-reason path must also pass.
    assert by_entry["target.example"]["gaps"] == []


def test_out_of_scope_host_excluded(monkeypatch, tmp_path: Path, capsys) -> None:
    """Services/work-items for out-of-scope hosts must not inflate any entry's counts."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)

    # In-scope work
    _insert_work_item(db, queue_key="in:1", url="https://target.example/ok", url_path="/ok", status="done")
    # Out-of-scope: different apex. Should not be counted against target.example.
    _insert_work_item(db, queue_key="out:1", url="https://evil.example/zzz", url_path="/zzz", status="pending")
    _insert_work_item(db, queue_key="out:2", url="https://target.co.uk/zzz", url_path="/zzz", status="pending")

    services = [
        {"endpoint": "target.example", "state": "up"},
        {"endpoint": "evil.example", "state": "up"},  # out of scope
        {"endpoint": "sub.target.example", "state": "up"},  # NOT a wildcard scope -> should be excluded
    ]
    runs = [
        {"command": "katana -u https://target.example", "tool_bin": "katana", "tool_name": "katana"},
        # This run targets an out-of-scope host; the command string substring
        # check must not fire for target.example.
        {"command": "katana -u https://evil.example", "tool_bin": "katana", "tool_name": "katana"},
    ]
    summary = {"request_observation_count": 10, "service_count": 3}

    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary)
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["total_services"] == 1
    assert entry["live_hosts"] == 1
    assert entry["live_host_samples"] == ["target.example"]
    # Work counts: one done for target.example, nothing for evil.example/target.co.uk.
    assert entry["work_queued"]["done"] == 1
    assert entry["work_queued"]["pending"] == 0


def test_require_stage_enum_fails_when_missing(monkeypatch, tmp_path: Path, capsys) -> None:
    """A wildcard scope with no subfinder/puredns activity must fail the enum gate."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    services: list[dict[str, Any]] = []
    # Only an unrelated run; no enum tools fire for target.example.
    runs = [
        {"command": "nmap -sV 10.0.0.1", "tool_bin": "nmap", "tool_name": "nmap_scan"},
    ]
    summary = {"request_observation_count": 0, "service_count": 0}

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=services,
            command_runs=runs,
            summary=summary,
            require_stage="enum",
        )
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    assert any("no-enum" in msg for msg in report["overall_gaps"])


def test_require_stage_consumption_passes_when_all_done_or_skipped(monkeypatch, tmp_path: Path, capsys) -> None:
    """pending=0 with skipped items that carry terminal_reason → consumption gate passes."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)

    _insert_work_item(db, queue_key="d:1", url="https://target.example/a", url_path="/a", status="done")
    _insert_work_item(db, queue_key="d:2", url="https://target.example/b", url_path="/b", status="done")
    # classify-work marks inert images as skipped + terminal_reason="inert_type".
    _insert_work_item(
        db, queue_key="d:3", url="https://target.example/logo.png", url_path="/logo.png",
        status="skipped", case_type="image", terminal_reason="inert_type",
    )

    services = [{"endpoint": "target.example", "state": "up"}]
    runs = [
        {"command": "katana -u https://target.example", "tool_bin": "katana", "tool_name": "katana"},
    ]
    summary = {"request_observation_count": 42, "service_count": 1}

    _run(monkeypatch, eng, services=services, command_runs=runs, summary=summary, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    assert report["overall_gaps"] == []
    entry = report["entries"][0]
    assert entry["work_queued"]["pending"] == 0
    assert entry["work_queued"]["done"] == 2
    assert entry["work_queued"]["skipped"] == 1


def test_collection_gate_ignores_superdomain_substring_false_positive(monkeypatch, tmp_path: Path, capsys) -> None:
    """A different host containing the scope host as a substring must not count as collection."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "target.example", "state": "up"}]
    runs = [
        {"command": "katana -u https://target.example.evil.org", "tool_bin": "katana", "tool_name": "katana"},
        {"command": "gau https://nottarget.example", "tool_bin": "gau", "tool_name": "gau"},
    ]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, command_runs=runs, require_stage="collection")
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["collection_attempted"] is False
    assert entry["collection_tools"] == []
    assert "no-collection" in entry["gaps"]


def test_old_cases_db_schema_fails_closed_instead_of_claiming_readiness(monkeypatch, tmp_path: Path, capsys) -> None:
    """Legacy/malformed work buffer schemas must abort the audit instead of silently passing."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db_path = eng / "cases.db"
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("CREATE TABLE work_items (url TEXT NOT NULL, status TEXT NOT NULL)")
        conn.execute("INSERT INTO work_items (url, status) VALUES ('https://target.example/a', 'pending')")
        conn.commit()
    finally:
        conn.close()

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=[], command_runs=[], summary={})
    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unable to read work buffer" in captured.err
    assert "terminal_reason" in captured.err


def test_command_run_fetch_paginates_past_first_page(monkeypatch, tmp_path: Path, capsys) -> None:
    """Coverage must consider command runs beyond the first 1000 rows."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    first_page = [
        {"command": f"katana -u https://unrelated-{idx}.example", "tool_bin": "katana", "tool_name": "katana"}
        for idx in range(1000)
    ]
    second_page = [
        {"command": "katana -u https://target.example", "tool_bin": "katana", "tool_name": "katana"},
    ]

    def endpoint_handler(endpoint: str) -> Any:
        if not endpoint.startswith("command-runs?"):
            return None
        query = endpoint.split("?", 1)[1]
        params = parse_qs(query)
        offset = int(params["offset"][0])
        if offset == 0:
            return first_page
        if offset == 1000:
            return second_page
        raise AssertionError(f"Unexpected command-runs offset: {offset}")

    client = _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "target.example", "state": "up"}],
        summary={"request_observation_count": 1, "service_count": 1},
        endpoint_handler=endpoint_handler,
        require_stage="collection",
    )

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["collection_attempted"] is True
    assert "katana" in entry["collection_tools"]
    assert client is not None
    assert "command-runs?limit=1000&offset=1000" in client.calls


def test_deferred_url_metadata_normalizes_trailing_dot(monkeypatch, tmp_path: Path, capsys) -> None:
    """Deferred URL entries should normalize URL form and trailing dots before lookup."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["https://api.target.example./health"],
        deferred_hosts=["https://api.target.example./defer"],
    )
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="u:1", url="https://api.target.example/work", url_path="/work", status="pending")

    services = [{"endpoint": "https://api.target.example/health", "state": "up"}]
    runs = [{"command": "katana -u https://api.target.example", "tool_bin": "katana", "tool_name": "katana"}]

    _run(monkeypatch, eng, services=services, command_runs=runs, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "api.target.example"
    assert entry["status"] == "deferred"
    assert entry["gaps"] == []


def test_host_metadata_status_beats_deferred_hosts(monkeypatch, tmp_path: Path, capsys) -> None:
    """An explicit host_metadata status must not be overwritten by deferred_hosts fallback."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["target.example"],
        host_metadata={"target.example": {"status": "active"}},
        deferred_hosts=["target.example"],
    )
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="p:1", url="https://target.example/work", url_path="/work", status="pending")

    runs = [{"command": "katana -u https://target.example", "tool_bin": "katana", "tool_name": "katana"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            command_runs=runs,
            require_stage="consumption",
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["status"] == "active"
    assert "pending-work-remains" in entry["gaps"]


def test_wildcard_scope_normalizes_trailing_dot_for_metadata_and_matching(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard scope rows with trailing dots should still match services and metadata."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["*.target.example."],
        host_metadata={"*.target.example.": {"status": "active"}},
    )
    _make_cases_db(eng)

    services = [
        {"endpoint": "api.target.example", "state": "up"},
        {"endpoint": "www.target.example", "state": "up"},
    ]
    runs = [
        {"command": "subfinder -d target.example", "tool_bin": "subfinder", "tool_name": "subfinder"},
        {"command": "katana -u https://api.target.example", "tool_bin": "katana", "tool_name": "katana"},
    ]

    _run(monkeypatch, eng, services=services, command_runs=runs, require_stage="collection")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "target.example"
    assert entry["status"] == "active"
    assert entry["live_hosts"] == 2
    assert entry["collection_attempted"] is True
