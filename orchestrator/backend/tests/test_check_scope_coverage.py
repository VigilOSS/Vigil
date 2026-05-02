"""Tests for `aith assess check-scope-coverage`.

The CLI reads scope.json, calls the backend for services and surfaces, and
reads the local cases.db work_items table. We drive it in-process via a
monkeypatched ``AssessmentClient`` and a real SQLite cases.db so the tests
stay hermetic and don't spin up FastAPI. That mirrors the pattern used in
`test_agent_script_regressions.py::test_check_report_readiness_surfaces_backend_blockers`
so readers can locate prior art without searching.

The new implementation no longer parses command-run shell/argv. Coverage is
read directly from durable state — `GET /services`, `GET /surfaces`, and the
local cases.db `work_items` rollup. These tests exercise that contract and
will scream if the module ever tries to fetch `command-runs` or `summary`
again (``FakeClient.get`` raises on any endpoint other than the two allowed
ones).
"""
from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

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
    """In-process stand-in for AssessmentClient that serves fixture data.

    Only ``services`` and ``surfaces`` are valid endpoints. Anything else
    — including the removed ``command-runs`` and ``summary`` endpoints —
    raises ``AssertionError``. That is intentional: the new implementation
    must not call those endpoints, and a regression that re-adds the call
    should fail the test suite loudly rather than silently receive an
    empty list.

    ``list_decisions`` stands in for the assessment_dispatch_decisions table —
    vendor-SaaS scope decisions come from the backend.
    """

    def __init__(
        self,
        *,
        services: list[dict[str, Any]] | None = None,
        surfaces: list[dict[str, Any]] | None = None,
        decisions: list[dict[str, Any]] | None = None,
        endpoint_handler=None,
    ) -> None:
        self._services = services or []
        self._surfaces = surfaces or []
        self._decisions = decisions or []
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
        if endpoint == "surfaces":
            return self._surfaces
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    def list_decisions(self, **filters: Any) -> list[dict[str, Any]]:
        rows = list(self._decisions)
        kind = filters.get("kind")
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        return rows

    def close(self) -> None:
        return None


def _patch_client(
    monkeypatch,
    module,
    *,
    services=None,
    surfaces=None,
    decisions=None,
    endpoint_handler=None,
) -> list[FakeClient]:
    fake_services = services or []
    fake_surfaces = surfaces or []
    fake_decisions = decisions or []
    created: list[FakeClient] = []

    def _factory(base_url: str, engagement_key: str) -> FakeClient:
        client = FakeClient(
            services=fake_services,
            surfaces=fake_surfaces,
            decisions=fake_decisions,
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
    surfaces=None,
    decisions=None,
    endpoint_handler=None,
    require_stage: str | None = None,
    as_json: bool = True,
    verbose: bool = False,
    strict_vendor_saas: bool = False,
) -> FakeClient | None:
    module = _load_module()
    _patch_config(monkeypatch, module, engagement_dir)
    clients = _patch_client(
        monkeypatch,
        module,
        services=services,
        surfaces=surfaces,
        decisions=decisions,
        endpoint_handler=endpoint_handler,
    )
    module.run(
        SimpleNamespace(
            engagement_dir=str(engagement_dir),
            require_stage=require_stage,
            as_json=as_json,
            verbose=verbose,
            strict_vendor_saas=strict_vendor_saas,
        )
    )
    return clients[0] if clients else None


# ---------------------------------------------------------------------------
# Core coverage tests
# ---------------------------------------------------------------------------


def test_apex_host_full_coverage(monkeypatch, tmp_path: Path, capsys) -> None:
    """Bare host with services, a surface, and all work done → ready=true."""
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
    surfaces = [
        {"target_descriptor": "https://target.example/api/one"},
        {"target_descriptor": "https://target.example/api/two"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")

    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["ready"] is True, report
    assert report["overall_gaps"] == []
    assert len(report["entries"]) == 1
    entry = report["entries"][0]
    assert entry["scope_entry"] == "target.example"
    assert entry["entry_kind"] == "bare_host"
    assert entry["enum_attempted"] is True
    assert "bare_host" in entry["enum_evidence"]
    assert entry["collection_attempted"] is True
    assert "work_items" in entry["collection_evidence"]
    assert "surfaces" in entry["collection_evidence"]
    assert entry["live_hosts"] == 1
    assert entry["surfaces_count"] == 2
    assert entry["work_queued"]["pending"] == 0
    assert entry["work_queued"]["done"] == 2
    assert entry["gaps"] == []


def test_wildcard_zero_live_hosts(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard with enum attempted via a surface but zero live hosts is informational."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    # One surface recorded under a subdomain but the service list is empty —
    # nothing resolved to a live host.
    services: list[dict[str, Any]] = []
    surfaces = [{"target_descriptor": "https://beta.target.example/"}]

    # --require-stage enum must pass because enum evidence exists (the surface).
    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    assert report["overall_gaps"] == []
    entry = report["entries"][0]
    assert entry["entry_kind"] == "wildcard"
    assert entry["enum_attempted"] is True
    assert "surfaces" in entry["enum_evidence"]
    assert entry["live_hosts"] == 0
    # Informational gap only — the gate still passes.
    assert "no-live-hosts" in entry["gaps"]


def test_wildcard_partial_collection(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard with live hosts plus surfaces/work_items for a subset of subdomains.

    Collection is attempted (surfaces/work_items exist under the wildcard), so
    `--require-stage collection` passes.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    db = _make_cases_db(eng)
    # Work items under two of the five live subdomains.
    _insert_work_item(db, queue_key="w:1", url="https://api.target.example/v1", url_path="/v1", status="pending")
    _insert_work_item(db, queue_key="w:2", url="https://admin.target.example/login", url_path="/login", status="pending")

    services = [
        {"endpoint": "api.target.example", "state": "up"},
        {"endpoint": "admin.target.example", "state": "up"},
        {"endpoint": "dev.target.example", "state": "up"},
        {"endpoint": "stage.target.example", "state": "up"},
        {"endpoint": "www.target.example", "state": "up"},
    ]
    surfaces = [
        {"target_descriptor": "https://api.target.example/v1"},
        {"target_descriptor": "https://admin.target.example/login"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="collection")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    entry = report["entries"][0]
    assert entry["collection_attempted"] is True
    assert set(entry["collection_evidence"]) >= {"surfaces", "work_items"}
    assert entry["live_hosts"] == 5
    assert len(entry["live_host_samples"]) == 5
    assert entry["surfaces_count"] == 2


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
    surfaces = [
        {"target_descriptor": "https://target.example/a"},
        {"target_descriptor": "https://skip.target.example/x"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    by_entry = {e["scope_entry"]: e for e in report["entries"]}
    assert by_entry["skip.target.example"]["status"] == "deferred"
    assert by_entry["skip.target.example"]["gaps"] == []
    # The implicit-terminal-reason path must also pass.
    assert by_entry["target.example"]["gaps"] == []


def test_out_of_scope_host_excluded(monkeypatch, tmp_path: Path, capsys) -> None:
    """Services/surfaces/work-items for out-of-scope hosts must not inflate any entry's counts."""
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
    surfaces = [
        {"target_descriptor": "https://target.example/ok"},
        {"target_descriptor": "https://evil.example/zzz"},  # out of scope
        {"target_descriptor": "https://sub.target.example/"},  # out of scope vs bare-host entry
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces)
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["total_services"] == 1
    assert entry["live_hosts"] == 1
    assert entry["live_host_samples"] == ["target.example"]
    assert entry["surfaces_count"] == 1
    # Work counts: one done for target.example, nothing for evil.example/target.co.uk.
    assert entry["work_queued"]["done"] == 1
    assert entry["work_queued"]["pending"] == 0


def test_require_stage_enum_fails_when_missing(monkeypatch, tmp_path: Path, capsys) -> None:
    """A wildcard scope with no services, surfaces, or work items must fail the enum gate."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    # Nothing — no services, no surfaces, no work_items under *.target.example.
    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[],
            surfaces=[],
            require_stage="enum",
        )
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    entry = report["entries"][0]
    assert entry["enum_attempted"] is False
    assert entry["enum_evidence"] == []
    assert "no-enum" in entry["gaps"]
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
    surfaces = [{"target_descriptor": "https://target.example/a"}]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
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

    # Service keeps enum gate satisfied for target.example itself so the test is
    # specifically about collection evidence.
    services = [{"endpoint": "target.example", "state": "up"}]
    # Surfaces are all for unrelated hosts that merely contain the string
    # "target.example" — they must NOT count toward collection coverage.
    surfaces = [
        {"target_descriptor": "https://target.example.evil.org/"},
        {"target_descriptor": "https://nottarget.example/path"},
    ]

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=services,
            surfaces=surfaces,
            require_stage="collection",
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["collection_attempted"] is False
    assert entry["collection_evidence"] == []
    assert entry["surfaces_count"] == 0
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
        _run(monkeypatch, eng, services=[], surfaces=[])
    assert excinfo.value.code == 1

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unable to read work buffer" in captured.err
    assert "terminal_reason" in captured.err


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
    surfaces = [{"target_descriptor": "https://api.target.example/work"}]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "api.target.example"
    assert entry["status"] == "deferred"
    assert entry["gaps"] == []


def test_url_scope_entry_accepts_host_keyed_deferral(monkeypatch, tmp_path: Path, capsys) -> None:
    """URL scope rows should honor deferred metadata keyed by the normalized host string."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["https://api.target.example/v1"],
        deferred_hosts=["api.target.example"],
    )
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="u:2", url="https://api.target.example/work", url_path="/work", status="pending")

    services = [{"endpoint": "https://api.target.example/health", "state": "up"}]
    surfaces = [{"target_descriptor": "https://api.target.example/work"}]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "api.target.example"
    assert entry["status"] == "deferred"
    assert entry["gaps"] == []


def test_bare_scope_host_with_port_matches_host_keyed_services_and_work(monkeypatch, tmp_path: Path, capsys) -> None:
    """Bare scope rows with ports should normalize to the host for service/work matching."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["api.target.example:8443"])
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="hp:1", url="https://api.target.example/work", url_path="/work", status="pending")

    services = [{"endpoint": "https://api.target.example:8443/health", "state": "up"}]
    surfaces = [{"target_descriptor": "https://api.target.example:8443/work"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "api.target.example"
    assert entry["live_hosts"] == 1
    assert entry["work_queued"]["pending"] == 1
    assert "pending-work-remains" in entry["gaps"]


def test_scope_parser_accepts_bare_and_bracketed_ipv6_literals() -> None:
    """IPv6 literals in scope.json must participate in scope matching."""
    scope_module = _load_script_module(
        "test_scope_ipv6_module",
        "agent/scripts/assess/lib/scope.py",
    )

    assert scope_module.classify_scope_entry("2001:db8::1") == {
        "scope_entry": "2001:db8::1",
        "entry_kind": "bare_host",
        "host": "2001:db8::1",
    }
    assert scope_module.classify_scope_entry("[2001:db8::2]") == {
        "scope_entry": "[2001:db8::2]",
        "entry_kind": "bare_host",
        "host": "2001:db8::2",
    }
    assert scope_module.classify_scope_entry("https://[2001:db8::3]/health") == {
        "scope_entry": "https://[2001:db8::3]/health",
        "entry_kind": "url",
        "host": "2001:db8::3",
    }
    assert scope_module.host_from_token("https://[2001:db8::4]:8443/path") == "2001:db8::4"


def test_ipv6_scope_hosts_match_services_surfaces_and_work(monkeypatch, tmp_path: Path, capsys) -> None:
    """IPv6 scope rows should match backend services, surfaces, and queued work."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["2001:db8::1", "[2001:db8::2]"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db,
        queue_key="ip6:1",
        url="https://[2001:db8::1]/work",
        url_path="/work",
        status="done",
    )
    _insert_work_item(
        db,
        queue_key="ip6:2",
        url="https://[2001:db8::2]/work",
        url_path="/work",
        status="done",
    )

    services = [
        {"endpoint": "2001:db8::1:443", "state": "up"},
        {"endpoint": "[2001:db8::2]:8443", "state": "up"},
    ]
    surfaces = [
        {"target_descriptor": "https://[2001:db8::1]/work"},
        {"target_descriptor": "https://[2001:db8::2]:8443/work"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="collection")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report

    by_scope = {entry["scope_entry"]: entry for entry in report["entries"]}
    assert by_scope["2001:db8::1"]["host"] == "2001:db8::1"
    assert by_scope["2001:db8::1"]["live_hosts"] == 1
    assert by_scope["2001:db8::1"]["surfaces_count"] == 1
    assert by_scope["2001:db8::1"]["work_queued"]["done"] == 1
    assert by_scope["[2001:db8::2]"]["host"] == "2001:db8::2"
    assert by_scope["[2001:db8::2]"]["live_hosts"] == 1
    assert by_scope["[2001:db8::2]"]["surfaces_count"] == 1
    assert by_scope["[2001:db8::2]"]["work_queued"]["done"] == 1


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

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/work"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=services,
            surfaces=surfaces,
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
    surfaces = [
        {"target_descriptor": "https://api.target.example/"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="collection")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["host"] == "target.example"
    assert entry["status"] == "active"
    assert entry["live_hosts"] == 2
    assert entry["collection_attempted"] is True


def test_wildcard_and_bare_entries_keep_distinct_metadata_status(monkeypatch, tmp_path: Path, capsys) -> None:
    """Wildcard metadata must not leak onto a separate bare-host scope row for the same host."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["target.example", "*.target.example"],
        deferred_hosts=["*.target.example"],
    )
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="b:1", url="https://target.example/work", url_path="/work", status="pending")

    services = [
        {"endpoint": "target.example", "state": "up"},
        {"endpoint": "api.target.example", "state": "up"},
    ]
    surfaces = [
        {"target_descriptor": "https://target.example/work"},
        {"target_descriptor": "https://api.target.example/"},
    ]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    by_scope = {entry["scope_entry"]: entry for entry in report["entries"]}
    assert by_scope["target.example"]["status"] is None
    assert "pending-work-remains" in by_scope["target.example"]["gaps"]
    assert by_scope["*.target.example"]["status"] == "deferred"
    assert by_scope["*.target.example"]["gaps"] == []


# ---------------------------------------------------------------------------
# New tests for the surface/work_item-based enum and collection gates
# ---------------------------------------------------------------------------


def test_surface_under_wildcard_satisfies_enum_without_services(monkeypatch, tmp_path: Path, capsys) -> None:
    """A recorded surface under a wildcard satisfies the enum gate even with no live services."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    services: list[dict[str, Any]] = []
    surfaces = [{"target_descriptor": "https://api.target.example/login"}]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    entry = report["entries"][0]
    assert entry["enum_attempted"] is True
    assert entry["enum_evidence"] == ["surfaces"]
    assert entry["live_hosts"] == 0
    assert "no-live-hosts" in entry["gaps"]


def test_work_item_under_wildcard_satisfies_enum_without_services(monkeypatch, tmp_path: Path, capsys) -> None:
    """A work_item under a wildcard subdomain satisfies the enum gate even with no live services or surfaces."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(db, queue_key="we:1", url="https://api.target.example/x", url_path="/x", status="pending")

    services: list[dict[str, Any]] = []
    surfaces: list[dict[str, Any]] = []

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    entry = report["entries"][0]
    assert entry["enum_attempted"] is True
    assert entry["enum_evidence"] == ["work_items"]
    assert entry["live_hosts"] == 0
    assert "no-live-hosts" in entry["gaps"]


def test_collection_gate_fails_when_no_surfaces_or_work_items(monkeypatch, tmp_path: Path, capsys) -> None:
    """A bare host with a live service but no surfaces/work_items fails the collection gate."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces: list[dict[str, Any]] = []

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=services,
            surfaces=surfaces,
            require_stage="collection",
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["enum_attempted"] is True
    assert entry["collection_attempted"] is False
    assert entry["collection_evidence"] == []
    assert "no-collection" in entry["gaps"]


# ---------------------------------------------------------------------------
# Wildcard-apex semantics
# ---------------------------------------------------------------------------


def test_wildcard_admits_apex(monkeypatch, tmp_path: Path, capsys) -> None:
    """A wildcard scope entry covers the bare apex AND every subdomain
    (HackerOne / Bugcrowd / VDP convention)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.example.test"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="apex:1", url="https://example.test/", url_path="/", status="pending"
    )
    _insert_work_item(
        db,
        queue_key="sub:1",
        url="https://corp.example.test/api",
        url_path="/api",
        status="pending",
    )

    services = [
        {"endpoint": "example.test", "state": "up"},
        {"endpoint": "corp.example.test", "state": "up"},
    ]
    surfaces = [
        {"target_descriptor": "https://example.test/"},
        {"target_descriptor": "https://corp.example.test/api"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    entry = report["entries"][0]
    assert entry["entry_kind"] == "wildcard"
    assert entry["live_hosts"] == 2, entry
    assert entry["surfaces_count"] == 2
    assert entry["work_queued"]["pending"] == 2


def test_explicit_apex_plus_wildcard(monkeypatch, tmp_path: Path, capsys) -> None:
    """Listing the apex AND the wildcard covers both apex and subdomains.
    The wildcard entry already admits the apex; the explicit apex entry still
    matches and reports its own sample."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["example.test", "*.example.test"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="apex:1", url="https://example.test/", url_path="/", status="done"
    )
    _insert_work_item(
        db,
        queue_key="sub:1",
        url="https://vendor-saas.example.test/api",
        url_path="/api",
        status="done",
    )

    services = [
        {"endpoint": "example.test", "state": "up"},
        {"endpoint": "vendor-saas.example.test", "state": "up"},
    ]
    surfaces = [
        {"target_descriptor": "https://example.test/"},
        {"target_descriptor": "https://vendor-saas.example.test/api"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    by_scope = {entry["scope_entry"]: entry for entry in report["entries"]}
    assert by_scope["example.test"]["live_hosts"] == 1
    assert by_scope["example.test"]["live_host_samples"] == ["example.test"]
    assert by_scope["*.example.test"]["live_hosts"] == 2
    assert "vendor-saas.example.test" in by_scope["*.example.test"]["live_host_samples"]


def _patch_vendor_saas_suffix(monkeypatch, label: str, suffix: str) -> None:
    """Append a test-only suffix to the live vendor-SaaS suffix table."""
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    import importlib

    scope_mod = importlib.import_module("assess.lib.scope")
    monkeypatch.setattr(
        scope_mod,
        "_VENDOR_SAAS_SUFFIXES",
        list(scope_mod._VENDOR_SAAS_SUFFIXES) + [(label, suffix)],
    )


def test_vendor_saas_reports_pending_under_wildcard_expansion_by_default(monkeypatch, tmp_path: Path, capsys) -> None:
    """A vendor-SaaS host that surfaced under wildcard expansion (NOT an
    explicit literal in scope.json) blocks the gate until a scope_decision
    is recorded.

    ``host_is_vendor_saas`` matches CNAME / rDNS suffixes; the test
    monkeypatches the suffix table so the fixture host registers as vendor
    SaaS without putting a real vendor's domain in test fixtures.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    # Wildcard scope: the vendor-SaaS host appears under expansion, not as
    # an explicit literal — that is the genuinely ambiguous case the
    # checkpoint exists to resolve.
    _write_scope(eng, hosts=["*.example.test"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db,
        queue_key="vs:1",
        url="https://vendor-saas-platform.example.test/api/health",
        url_path="/api/health",
        status="done",
    )

    _patch_vendor_saas_suffix(monkeypatch, "vendor-saas-platform", ".example.test")

    services = [{"endpoint": "vendor-saas-platform.example.test", "state": "up"}]
    surfaces = [
        {"target_descriptor": "https://vendor-saas-platform.example.test/api/health"},
    ]

    # Without strict mode, an undecided vendor-SaaS discovery is reported for
    # operator visibility but does not fail the stage gate.
    _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
    )
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    pending = {row["host"]: row["vendor"] for row in report["vendor_saas_pending_decision"]}
    assert pending.get("vendor-saas-platform.example.test") == "vendor-saas-platform"
    assert report["strict_vendor_saas"] is False
    assert not any(
        "vendor-saas" in msg and "vendor-saas-platform.example.test" in msg
        for msg in report["overall_gaps"]
    )

    # Strict mode restores the phase gate when an engagement wants vendor-SaaS
    # ambiguity to block progress.
    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=services,
            surfaces=surfaces,
            require_stage="enum",
            strict_vendor_saas=True,
        )
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False, report
    assert report["strict_vendor_saas"] is True
    pending = {row["host"]: row["vendor"] for row in report["vendor_saas_pending_decision"]}
    assert pending.get("vendor-saas-platform.example.test") == "vendor-saas-platform"
    assert any(
        "vendor-saas" in msg and "vendor-saas-platform.example.test" in msg
        for msg in report["overall_gaps"]
    )

    # Recording a scope_decision in the backend clears the gate — the
    # decision lives in assessment_dispatch_decisions.
    decisions = [
        {
            "id": 1,
            "kind": "scope_decision",
            "payload": {
                "target": "vendor-saas-platform.example.test",
                "vendor": "vendor-saas-platform",
                "choice": "in_scope",
            },
            "surfaced_to_user": True,
            "resolved": False,
        }
    ]

    _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        decisions=decisions,
        require_stage="enum",
    )
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    assert report["vendor_saas_pending_decision"] == []


def test_vendor_saas_explicit_literal_in_scope_skips_gate(monkeypatch, tmp_path: Path, capsys) -> None:
    """A vendor-SaaS host authored as an explicit literal in scope.json is
    already the operator's in-scope decision, so the gate must not fire on
    it. The Vendor-SaaS scope checkpoint exists for the wildcard-expansion
    case where the operator did not author the host by hand; firing on a
    literal entry is theatre.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    # Explicit literal entry — the operator typed the host directly.
    _write_scope(eng, hosts=["vendor-saas-platform.example.test"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db,
        queue_key="vs:1",
        url="https://vendor-saas-platform.example.test/api/health",
        url_path="/api/health",
        status="done",
    )

    _patch_vendor_saas_suffix(monkeypatch, "vendor-saas-platform", ".example.test")

    services = [{"endpoint": "vendor-saas-platform.example.test", "state": "up"}]
    surfaces = [
        {"target_descriptor": "https://vendor-saas-platform.example.test/api/health"},
    ]

    # No scope_decision recorded — but the literal entry skips the gate.
    _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
    )
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True, report
    assert report["vendor_saas_pending_decision"] == []
