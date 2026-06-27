"""Tests for the per-scope-entry coverage gate (Wave 6d).

Originally ``vigil assess check-scope-coverage``; that standalone command was
folded into ``vigil assess check-phase-readiness --phase recon|collect|consume``
and its reusable logic moved into ``agent/scripts/assess/lib/coverage_checks.py``.
These tests now drive the consolidated command and the shared helper module,
preserving the per-scope-entry stage-gate assertions verbatim.

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
    cc = _load_script_module(
        "test_coverage_checks_module",
        "agent/scripts/assess/lib/coverage_checks.py",
    )
    module = _load_script_module(
        "test_check_phase_readiness_module",
        "agent/scripts/assess/commands/check_phase_readiness.py",
    )
    module.cc = cc
    from assess.lib.scope import classify_scope_entry, host_from_token
    module.classify_scope_entry = classify_scope_entry
    module.host_from_token = host_from_token
    for name in (
        "BUCKET_SKILLS",
        "_pending_buckets_for_host",
        "_consumption_satisfied",
        "_load_work_items_by_host",
        "_HINT_RECON_SPECIALIST",
        "_HINT_OSINT_ANALYST",
        "_OBJECTIVE_DISPATCH_HINTS",
    ):
        setattr(module, name, getattr(cc, name))
    return module


_STAGE_TO_PHASE = {"enum": "recon", "collection": "collect", "consumption": "consume"}


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
    query_params: str = "{}",
    cluster_key: str | None = None,
) -> None:
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(
            """INSERT INTO work_items
            (queue_key, method, url, url_path, query_params, body_params,
             type, source, status, priority_score, cluster_key, terminal_reason)
            VALUES (?, 'GET', ?, ?, ?, '{}', ?, 'test', ?, 0, ?, ?)""",
            (queue_key, url, url_path, query_params, case_type, status, cluster_key, terminal_reason),
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
    out_of_scope: list[str] | None = None,
) -> None:
    scope_path = engagement_dir / "scope.json"
    data: dict[str, Any] = {"hosts": hosts, "current_phase": "recon"}
    if host_metadata:
        data["host_metadata"] = host_metadata
    if deferred_hosts:
        data["deferred_hosts"] = deferred_hosts
    if out_of_scope:
        data["out_of_scope"] = out_of_scope
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
        dispatches: list[dict[str, Any]] | None = None,
        dispatches_error: bool = False,
        endpoint_handler=None,
        per_host_payload: dict[str, Any] | None = None,
    ) -> None:
        self._services = services or []
        self._surfaces = surfaces or []
        self._decisions = decisions or []
        self._dispatches = dispatches or []
        self._dispatches_error = dispatches_error
        self._endpoint_handler = endpoint_handler
        self._per_host_payload = per_host_payload
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
        if endpoint == "coverage-readiness/by-host":
            return getattr(self, "_per_host_payload", None) or {
                "objectives": [],
                "hosts": [],
                "engagement_signals": {},
            }
        if endpoint.startswith("phase-readiness"):
            return {
                "phase": endpoint.split("phase=", 1)[-1] if "phase=" in endpoint else "",
                "coverage": {"ready": True},
                "depth_ledger": {"skipped": True, "units": [], "summary": {}},
            }
        if endpoint == "application-units/depth-ledger":
            return {"skipped": True, "units": [], "summary": {}}
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    def get_engagement(self, endpoint: str, query: str = "") -> Any:
        self.calls.append(f"engagement:{endpoint}")
        return {
            "applicable": False,
            "engagement_type": "red",
            "open_high_cves": [],
            "open_leads": [],
            "exploited_unlinked_cves": [],
            "dangling_links": [],
        }

    def list_decisions(self, **filters: Any) -> list[dict[str, Any]]:
        rows = list(self._decisions)
        kind = filters.get("kind")
        if kind:
            rows = [r for r in rows if r.get("kind") == kind]
        limit = filters.get("limit")
        offset = int(filters.get("offset") or 0)
        if offset:
            rows = rows[offset:]
        if limit is not None:
            rows = rows[: int(limit)]
        return rows

    def list_all_decisions(self, **filters: Any) -> list[dict[str, Any]]:
        # Mirror the real client's paginating helper: return everything
        # matching `filters`, ignoring the per-page cap.
        scoped = {k: v for k, v in filters.items() if k not in ("limit", "offset")}
        return self.list_decisions(**scoped)

    def list_dispatches(self, **filters: Any) -> list[dict[str, Any]]:
        # Stands in for assessment_dispatch_decisions' dispatch rows — the same
        # method --auto-redispatch dedup reuses. `dispatches_error=True`
        # simulates a backend failure so the graceful-degrade path can be
        # exercised.
        #
        # Mirrors the real backend's exact-match `status` filter (aliased from
        # `status_value` in GET /dispatches) so the server-side
        # `status="in-progress"` dedup fetch is exercised faithfully: terminal
        # rows are filtered OUT here just as the backend would, proving the
        # active-only dedup contract end to end.
        self.calls.append("dispatches")
        if self._dispatches_error:
            from assess.lib.client import AssessError

            raise AssessError("HTTP 503:\nbackend down")
        rows = list(self._dispatches)
        role = filters.get("role")
        if role:
            rows = [r for r in rows if r.get("agent_role") == role or r.get("role") == role]
        status = filters.get("status")
        if status:
            rows = [r for r in rows if r.get("status") == status]
        return rows

    def close(self) -> None:
        return None

    def __enter__(self) -> "FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False


def _patch_client(
    monkeypatch,
    module,
    *,
    services=None,
    surfaces=None,
    decisions=None,
    dispatches=None,
    dispatches_error=False,
    endpoint_handler=None,
    per_host_payload=None,
) -> list[FakeClient]:
    fake_services = services or []
    fake_surfaces = surfaces or []
    fake_decisions = decisions or []
    fake_dispatches = dispatches or []
    created: list[FakeClient] = []

    def _factory(base_url: str, engagement_key: str) -> FakeClient:
        client = FakeClient(
            services=fake_services,
            surfaces=fake_surfaces,
            decisions=fake_decisions,
            dispatches=fake_dispatches,
            dispatches_error=dispatches_error,
            endpoint_handler=endpoint_handler,
            per_host_payload=per_host_payload,
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
    dispatches=None,
    dispatches_error=False,
    endpoint_handler=None,
    require_stage: str | None = None,
    as_json: bool = True,
    verbose: bool = False,
    strict_vendor_saas: bool = False,
    by_host: bool = False,
    include_discovered: bool = False,
    auto_redispatch: bool = False,
    max_recommendations: int = 10,
    per_host_payload=None,
    _module=None,
) -> FakeClient | None:
    module = _module if _module is not None else _load_module()
    _patch_config(monkeypatch, module, engagement_dir)
    clients = _patch_client(
        monkeypatch,
        module,
        services=services,
        surfaces=surfaces,
        decisions=decisions,
        dispatches=dispatches,
        dispatches_error=dispatches_error,
        endpoint_handler=endpoint_handler,
        per_host_payload=per_host_payload,
    )
    phase = _STAGE_TO_PHASE.get(require_stage or "", "verify")
    import contextlib
    import io

    buf = io.StringIO()
    rc = 0
    try:
        with contextlib.redirect_stdout(buf):
            module.run(
                SimpleNamespace(
                    engagement_dir=str(engagement_dir),
                    phase=phase,
                    as_json=as_json,
                    verbose=verbose,
                    strict_vendor_saas=strict_vendor_saas,
                    by_host=by_host,
                    include_discovered=include_discovered,
                    auto_redispatch=auto_redispatch,
                    max_recommendations=max_recommendations,
                    depth=False,
                    by_app_unit=False,
                    include_intel=False,
                    strict=False,
                    strict_deep=False,
                )
            )
    except SystemExit as exc:
        rc = int(exc.code or 0)
        _flatten_and_print(buf.getvalue(), as_json=as_json)
        raise SystemExit(rc)
    _flatten_and_print(buf.getvalue(), as_json=as_json)
    return clients[0] if clients else None


def _flatten_and_print(captured: str, *, as_json: bool) -> None:
    """Re-emit the consolidated command's output in the legacy top-level shape.

    The old check-scope-coverage --json emitted the per-scope-entry report at the
    top level (``entries`` / ``overall_gaps`` / ``ready`` / ``per_host_coverage``
    / ``redispatch`` / ``vendor_saas_pending_decision``). The consolidated command
    nests the scope report under ``scope_coverage``. Flatten it back so the
    existing assertions (which parse stdout JSON) keep working.
    """
    if not as_json:
        print(captured, end="")
        return
    try:
        projection = json.loads(captured)
    except (json.JSONDecodeError, ValueError):
        print(captured, end="")
        return
    scope = projection.get("scope_coverage") or {}
    flat = dict(scope)
    if "per_host_coverage" in projection:
        flat["per_host_coverage"] = projection["per_host_coverage"]
    if "per_host_warnings" in projection:
        flat["per_host_warnings"] = projection["per_host_warnings"]
    if "redispatch" in projection:
        flat["redispatch"] = projection["redispatch"]
    flat["ready"] = scope.get("ready", projection.get("ready", True))
    print(json.dumps(flat, ensure_ascii=False, indent=2))


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

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    assert entry["total_services"] == 1
    assert entry["live_hosts"] == 1
    assert entry["live_host_samples"] == ["target.example"]
    assert entry["surfaces_count"] == 1
    # Work counts: one done for target.example, nothing for evil.example/target.co.uk.
    assert entry["work_queued"]["done"] == 1
    assert entry["work_queued"]["pending"] == 0


def test_out_of_scope_carveout_not_counted_under_in_scope_wildcard(monkeypatch, tmp_path: Path, capsys) -> None:
    """A host that matches an in-scope wildcard but is listed in ``out_of_scope``
    must NOT count toward that wildcard's coverage — otherwise an OOS host
    inflates live/service/surface/work tallies and can help satisfy a stage gate.

    Regression for the QA-found gap: the coverage gate consulted only the
    in-scope allowlist (``entry_matches_host``), never the denylist.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(
        eng,
        hosts=["*.mobile.acme.example"],
        out_of_scope=["mobile.acme.example", "*.mobile.acme.example"],
    )
    db = _make_cases_db(eng)
    # Work items under one in-scope subdomain and one OOS carve-out.
    _insert_work_item(db, queue_key="w:1", url="https://mobile.acme.example/v1", url_path="/v1", status="pending")
    _insert_work_item(db, queue_key="w:2", url="https://mobile.acme.example/book", url_path="/book", status="pending")

    services = [
        {"endpoint": "mobile.acme.example", "state": "up"},          # in scope
        {"endpoint": "mobile.acme.example", "state": "up"}, # OOS exact carve-out
        {"endpoint": "mobile.acme.example", "state": "up"},     # OOS wildcard carve-out
    ]
    surfaces = [
        {"target_descriptor": "https://mobile.acme.example/v1"},
        {"target_descriptor": "https://mobile.acme.example/book"},
    ]

    _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="enum")
    report = json.loads(capsys.readouterr().out)
    entry = report["entries"][0]
    # Only mobile.acme.example counts; both carve-outs are excluded.
    assert entry["total_services"] == 1
    assert entry["live_hosts"] == 1
    assert entry["live_host_samples"] == ["mobile.acme.example"]
    assert entry["surfaces_count"] == 1
    # Work queue: only the in-scope subdomain's pending item is aggregated.
    assert entry["work_queued"]["pending"] == 1


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
        _run(monkeypatch, eng, services=[], surfaces=[], require_stage="enum")
    assert excinfo.value.code == 1

    captured = capsys.readouterr()
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
                "target": "https://vendor-saas-platform.example.test:8443/review",
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


# ---------------------------------------------------------------------------
# C40 — per-host outcome gates + coverage_deferral honoring
# ---------------------------------------------------------------------------


def _per_host_payload(
    *,
    hosts: list[dict[str, Any]],
    objectives: list[str] | None = None,
    engagement_signals: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "objectives": objectives
        or ["waf_tier", "service_inventory", "directory_fuzz", "tech_fingerprint", "osint"],
        "hosts": hosts,
        "engagement_signals": engagement_signals or {},
    }


def _outcome(*, met: bool, evidence: list[str] | None = None, deferred: bool = False) -> dict[str, Any]:
    return {
        "met": bool(met),
        "evidence": list(evidence or []),
        "deferred": bool(deferred),
    }


def test_by_host_renders_outcome_table_and_warns_on_unmet(monkeypatch, tmp_path: Path, capsys) -> None:
    """--by-host emits per-host outcome rows and per-host_warnings list (WARN-only)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["api.target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "api.target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://api.target.example/v1"}]

    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "api.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=False),
                    "service_inventory": _outcome(met=True, evidence=["services:1", "surfaces:1"]),
                    "directory_fuzz": _outcome(met=False),
                    "tech_fingerprint": _outcome(met=False),
                    "osint": _outcome(met=False),
                },
            },
        ],
    )

    client = _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
        by_host=True,
        per_host_payload=host_payload,
    )

    out = capsys.readouterr().out
    report = json.loads(out)
    # The scope-entry gate still passes — --by-host warns separately, never blocks.
    assert report["ready"] is True, report
    section = report["per_host_coverage"]
    assert section["objectives"] == [
        "waf_tier",
        "service_inventory",
        "directory_fuzz",
        "tech_fingerprint",
        "osint",
    ]
    by_host = {row["host"]: row for row in section["hosts"]}
    assert "api.target.example" in by_host
    row = by_host["api.target.example"]
    assert row["outcomes"]["service_inventory"]["met"] is True
    assert row["outcomes"]["waf_tier"]["met"] is False
    assert set(row["unmet_objectives"]) == {"waf_tier", "directory_fuzz", "tech_fingerprint", "osint"}

    warnings = report["per_host_warnings"]
    # One warning per unmet objective for the single host.
    assert len(warnings) == 4
    assert any("waf_tier" in w and "api.target.example" in w for w in warnings)
    assert any("coverage_deferral" in w for w in warnings)

    # The CLI must NOT have asked for command-runs — strict abstraction test.
    assert client is not None
    assert "command-runs" not in client.calls
    assert "summary" not in client.calls


def test_by_host_deferral_clears_warning(monkeypatch, tmp_path: Path, capsys) -> None:
    """A coverage_deferral for an objective marks it as deferred (not unmet) in the report."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["api.target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "api.target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://api.target.example/v1"}]

    # Backend payload reports waf_tier as deferred for this host.
    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "api.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=False, deferred=True),
                    "service_inventory": _outcome(met=True),
                    "directory_fuzz": _outcome(met=True),
                    "tech_fingerprint": _outcome(met=True),
                    "osint": _outcome(met=True),
                },
                "deferrals": [
                    {
                        "id": 7,
                        "kind": "coverage_deferral",
                        "payload": {
                            "host": "api.target.example",
                            "deferred_objectives": ["waf_tier"],
                            "reason": "vendor confirmed WAF tier in scope brief",
                        },
                        "created_at": "2026-05-17T12:00:00Z",
                    }
                ],
            },
        ],
    )

    _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
        by_host=True,
        per_host_payload=host_payload,
    )
    report = json.loads(capsys.readouterr().out)
    row = report["per_host_coverage"]["hosts"][0]
    assert row["outcomes"]["waf_tier"]["deferred"] is True
    assert row["unmet_objectives"] == []
    assert "waf_tier" in row["deferred_objectives"]
    # Empty warnings ↔ no actionable WARN-only lines.
    assert report["per_host_warnings"] == []


def test_by_host_does_not_query_command_runs_endpoint(monkeypatch, tmp_path: Path, capsys) -> None:
    """Contract assertion (C40): the CLI gate path NEVER hits assessment_command_runs.

    Captures every endpoint the CLI requests and asserts the safelist is exactly
    ``services``, ``surfaces``, and ``coverage-readiness/by-host``. If a regression
    re-adds a command-runs fetch the FakeClient will raise AssertionError; this
    test confirms that the new --by-host path stays inside the outcome-table
    contract too.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/"}]
    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=True, evidence=["Cloudflare"]),
                    "service_inventory": _outcome(met=True, evidence=["services:1"]),
                    "directory_fuzz": _outcome(met=True),
                    "tech_fingerprint": _outcome(met=True),
                    "osint": _outcome(met=True),
                },
            }
        ],
    )

    client = _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
        by_host=True,
        per_host_payload=host_payload,
    )
    capsys.readouterr()  # drain stdout

    assert client is not None
    allowed = {
        "services",
        "surfaces",
        "coverage-readiness/by-host",
        "phase-readiness?phase=recon",
        "engagement:intel/readiness",
    }
    assert set(client.calls) <= allowed, sorted(set(client.calls) - allowed)
    assert "command-runs" not in client.calls
    assert not any(call.startswith("command-runs") for call in client.calls)
    # Verify the per-host fetch happened.
    assert "coverage-readiness/by-host" in client.calls


def test_by_host_without_flag_skips_per_host_section(monkeypatch, tmp_path: Path, capsys) -> None:
    """Without --by-host the backend per-host endpoint must not be called.

    Preserves the prior CLI contract: the legacy gate path is unchanged when
    operators run the command without --by-host.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/"}]

    client = _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
    )
    capsys.readouterr()

    assert client is not None
    assert "coverage-readiness/by-host" not in client.calls
    # Report must NOT carry a per_host_coverage key when --by-host is not set.
    capsys.readouterr()  # already drained; redrain produces ""
    # Re-run to actually capture stdout via JSON path.
    _run(
        monkeypatch,
        eng,
        services=services,
        surfaces=surfaces,
        require_stage="enum",
    )
    report = json.loads(capsys.readouterr().out)
    assert "per_host_coverage" not in report
    assert "per_host_warnings" not in report


# ---------------------------------------------------------------------------
# FU3: hint-referenced specialist names must exist as agent role files.
# ---------------------------------------------------------------------------


def test_specialist_roster_names_in_hints_have_role_files_on_disk():
    """Every specialist name referenced by a C40 dispatch hint must be a
    real role file under `agent/agents/<name>.md`. Catches the class of
    drift where the C40 subagent wrote `osint-recon` (no such file) when
    the canonical name is `osint-analyst`. A rename of any role file will
    fail this test too — the hint must move with the rename."""
    module = _load_module()
    repo_root = Path(__file__).resolve().parents[3]
    referenced_names = {
        module._HINT_RECON_SPECIALIST,
        module._HINT_OSINT_ANALYST,
    }
    for name in referenced_names:
        role_file = repo_root / "agent" / "agents" / f"{name}.md"
        assert role_file.is_file(), (
            f"check_scope_coverage hint references specialist '{name}' but "
            f"{role_file} does not exist. Either fix the constant in "
            "check_scope_coverage.py or restore the role file."
        )


# ---------------------------------------------------------------------------
# FU1: discovered-host filtering / --include-discovered
# ---------------------------------------------------------------------------


def test_by_host_default_filters_wildcard_discovered_into_summary(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Hosts NOT authored in scope.json are folded into discovered_summary."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    # Scope.json: one literal host + one wildcard. The wildcard's expansions
    # should NOT show up in the matrix by default.
    _write_scope(eng, hosts=["api.target.example", "*.target.example"])
    _make_cases_db(eng)

    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "api.target.example",  # explicit literal — kept
                "outcomes": {
                    "waf_tier": _outcome(met=True, evidence=["intel:1"]),
                    "service_inventory": _outcome(met=True, evidence=["services:1"]),
                    "directory_fuzz": _outcome(met=True, evidence=["surfaces:1"]),
                    "tech_fingerprint": _outcome(met=True),
                    "osint": _outcome(met=True),
                },
            },
            {
                "host": "discovered-a.target.example",  # wildcard expansion — folded
                "outcomes": {
                    "waf_tier": _outcome(met=False),
                    "service_inventory": _outcome(met=False),
                    "directory_fuzz": _outcome(met=False),
                    "tech_fingerprint": _outcome(met=False),
                    "osint": _outcome(met=False),
                },
            },
            {
                "host": "discovered-b.target.example",  # wildcard expansion — folded
                "outcomes": {
                    "waf_tier": _outcome(met=False),
                    "service_inventory": _outcome(met=True),
                    "directory_fuzz": _outcome(met=False),
                    "tech_fingerprint": _outcome(met=False),
                    "osint": _outcome(met=True),
                },
            },
        ],
    )

    _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "api.target.example", "state": "up"}],
        surfaces=[{"target_descriptor": "https://api.target.example/v1"}],
        require_stage="enum",
        by_host=True,
        per_host_payload=host_payload,
    )

    report = json.loads(capsys.readouterr().out)
    section = report["per_host_coverage"]
    hosts = {row["host"]: row for row in section["hosts"]}

    # Literal stays.
    assert "api.target.example" in hosts
    # Discovered hosts are filtered out of `hosts[]`.
    assert "discovered-a.target.example" not in hosts
    assert "discovered-b.target.example" not in hosts

    # Summary present + correct.
    summary = section["discovered_summary"]
    assert summary["discovered_count"] == 2
    # Both discovered hosts have at least one unmet objective.
    assert summary["hosts_with_unmet_count"] == 2
    assert summary["hosts_with_deferral_count"] == 0
    # top_unmet_objectives: most-frequent unmet across discovered.
    top_objectives = {entry["objective"] for entry in summary["top_unmet_objectives"]}
    # waf_tier, directory_fuzz, tech_fingerprint all unmet on both discovered hosts.
    # service_inventory unmet on a but met on b → 1 instance.
    # osint unmet on a but met on b → 1 instance.
    assert "waf_tier" in top_objectives
    assert "directory_fuzz" in top_objectives
    assert "tech_fingerprint" in top_objectives


def test_by_host_include_discovered_keeps_full_matrix(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """--include-discovered restores wildcard-discovered hosts to the matrix."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["api.target.example", "*.target.example"])
    _make_cases_db(eng)

    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "api.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=True),
                    "service_inventory": _outcome(met=True),
                    "directory_fuzz": _outcome(met=True),
                    "tech_fingerprint": _outcome(met=True),
                    "osint": _outcome(met=True),
                },
            },
            {
                "host": "discovered.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=False),
                    "service_inventory": _outcome(met=False),
                    "directory_fuzz": _outcome(met=False),
                    "tech_fingerprint": _outcome(met=False),
                    "osint": _outcome(met=False),
                },
            },
        ],
    )

    _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "api.target.example", "state": "up"}],
        surfaces=[{"target_descriptor": "https://api.target.example/v1"}],
        require_stage="enum",
        by_host=True,
        include_discovered=True,
        per_host_payload=host_payload,
    )

    section = json.loads(capsys.readouterr().out)["per_host_coverage"]
    hosts = {row["host"] for row in section["hosts"]}
    assert hosts == {"api.target.example", "discovered.target.example"}
    # No summary when full matrix is rendered.
    assert "discovered_summary" not in section


def test_by_host_wildcard_only_scope_skips_filtering(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """When scope.json has no explicit literals (only wildcards), filtering is a no-op.

    Run without require_stage so the scope-entry gate doesn't sys.exit on
    the wildcard having no enum evidence — this test is exclusively about
    the FU1 filter behavior, not the enum-evidence audit.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])  # wildcard only — no literals
    _make_cases_db(eng)

    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "a.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=False),
                    "service_inventory": _outcome(met=False),
                    "directory_fuzz": _outcome(met=False),
                    "tech_fingerprint": _outcome(met=False),
                    "osint": _outcome(met=False),
                },
            },
        ],
    )

    _run(
        monkeypatch,
        eng,
        by_host=True,
        per_host_payload=host_payload,
    )

    section = json.loads(capsys.readouterr().out)["per_host_coverage"]
    hosts = {row["host"] for row in section["hosts"]}
    # With no literal anchor, the filter cannot run — full matrix is preserved.
    assert "a.target.example" in hosts
    assert "discovered_summary" not in section


def test_by_host_no_discovered_hosts_skips_summary(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """When every backend-signal host is a scope literal, no summary block."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["api.target.example", "edge.target.example"])
    _make_cases_db(eng)

    host_payload = _per_host_payload(
        hosts=[
            {
                "host": "api.target.example",
                "outcomes": {
                    "waf_tier": _outcome(met=True),
                    "service_inventory": _outcome(met=True),
                    "directory_fuzz": _outcome(met=True),
                    "tech_fingerprint": _outcome(met=True),
                    "osint": _outcome(met=True),
                },
            },
        ],
    )

    _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "api.target.example", "state": "up"}],
        surfaces=[{"target_descriptor": "https://api.target.example/v1"}],
        require_stage="enum",
        by_host=True,
        per_host_payload=host_payload,
    )

    section = json.loads(capsys.readouterr().out)["per_host_coverage"]
    # api.target.example is the only signal host AND it's a literal — summary
    # is suppressed because there are no discovered hosts to summarize.
    assert "discovered_summary" not in section


def test_specialist_roster_substituted_into_hints():
    """The hints must actually substitute the roster constants, not leave
    a stale literal in the string."""
    module = _load_module()
    hints = module._OBJECTIVE_DISPATCH_HINTS
    # `osint-recon` was the C40-introduced typo; assert it's gone everywhere.
    for objective, hint in hints.items():
        assert "osint-recon" not in hint, (
            f"objective={objective!r} still references 'osint-recon'; "
            "canonical name is 'osint-analyst'"
        )
    # `osint-analyst` should appear in the osint hint.
    assert "osint-analyst" in hints["osint"]
    # `recon-specialist` should appear in every non-osint hint.
    for objective in ("waf_tier", "service_inventory", "directory_fuzz", "tech_fingerprint"):
        assert "recon-specialist" in hints[objective], (
            f"objective={objective!r} missing recon-specialist reference"
        )


# ---------------------------------------------------------------------------
# Phase 5 — --auto-redispatch recommendations
# ---------------------------------------------------------------------------


def _redispatch(report: dict[str, Any]) -> dict[str, Any]:
    assert "redispatch" in report, report
    return report["redispatch"]


def _recs(report: dict[str, Any]) -> list[dict[str, Any]]:
    return _redispatch(report)["recommendations"]


def _rec_for_host(report: dict[str, Any], host: str) -> dict[str, Any]:
    matches = [r for r in _recs(report) if r["scope_host"] == host]
    assert matches, (host, _recs(report))
    return matches[0]


def test_auto_redispatch_enum_gap_recommends_recon(monkeypatch, tmp_path: Path, capsys) -> None:
    """An enum gap emits a recon-specialist recommendation: hypothesis-driven
    mode, fixed recon skills, and source-analyzer named as the parallel role."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[],
            surfaces=[],
            require_stage="enum",
            auto_redispatch=True,
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "enum"
    assert rec["role"] == "recon-specialist"
    assert rec["dispatch_mode"] == "hypothesis-driven"
    assert rec["confidence"] == "high"
    assert rec["skills"] == ["web-recon", "subdomain-enumeration"]
    assert rec["parallel_role"] == "source-analyzer"
    # The ready-to-run command line must encode the role/scope-host/mode/skills.
    assert "vigil assess agent start" in rec["command"]
    assert "--role recon-specialist" in rec["command"]
    assert "--scope-host target.example" in rec["command"]
    assert "--dispatch-mode hypothesis-driven" in rec["command"]
    assert "--skills web-recon,subdomain-enumeration" in rec["command"]
    # Task skeleton names the host + stage.
    assert "target.example" in rec["task_skeleton"]


def test_auto_redispatch_collection_gap_recommends_surface_collector(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A collection gap (live service, no surfaces/work) recommends the
    surface-collector with item-iterating mode and the collection skills."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    _make_cases_db(eng)

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[],
            require_stage="collection",
            auto_redispatch=True,
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "collection"
    assert rec["role"] == "surface-collector"
    assert rec["dispatch_mode"] == "item-iterating"
    assert rec["confidence"] == "high"
    assert rec["skills"] == ["surface-collection", "gau-triage"]
    assert rec["parallel_role"] is None
    assert "--role surface-collector" in rec["command"]
    assert "--dispatch-mode item-iterating" in rec["command"]


def test_auto_redispatch_consumption_dominant_idor(monkeypatch, tmp_path: Path, capsys) -> None:
    """A consumption gap whose dominant pending bucket is idor recommends the
    vulnerability-analyst + idor-testing(+split-brain-idor), correct scope-host,
    and item-iterating mode, at confidence=high."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    # Three untested pending IDOR-shaped items (the `user` param uniquely keys
    # the idor bucket; `id` would also hit the higher-weight sqli bucket).
    for i in range(3):
        _insert_work_item(
            db,
            queue_key=f"idor:{i}",
            url=f"https://target.example/api/profile/{i}",
            url_path="/api/profile",
            status="pending",
            query_params='{"user": "5"}',
        )

    # The audit fails the consumption gate -> SystemExit(1); the JSON report is
    # printed before the exit so we read it after catching.
    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
        )
    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "consumption"
    assert rec["role"] == "vulnerability-analyst"
    assert rec["dispatch_mode"] == "item-iterating"
    assert rec["confidence"] == "high"
    assert rec["dominant_bucket"] == "idor"
    assert rec["skills"] == ["idor-testing", "split-brain-idor"]
    assert rec["scope_host"] == "target.example"
    assert "--role vulnerability-analyst" in rec["command"]
    assert "--scope-host target.example" in rec["command"]
    assert "--skills idor-testing,split-brain-idor" in rec["command"]
    # Task skeleton names host + dominant cluster + pending count.
    assert "target.example" in rec["task_skeleton"]
    assert "idor" in rec["task_skeleton"]
    assert "3" in rec["task_skeleton"]


def test_auto_redispatch_consumption_dominant_idor_exit_code(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Companion to the idor test: the consumption gate still exits 1."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db,
        queue_key="idor:0",
        url="https://target.example/api/profile/0",
        url_path="/api/profile",
        status="pending",
        query_params='{"user": "5"}',
    )

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
        )
    assert excinfo.value.code == 1
    capsys.readouterr()


def test_auto_redispatch_ambiguous_pending_emits_low_confidence_shortlist(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Pending items split roughly evenly across >=3 mapped buckets yield a
    low-confidence ranked shortlist, not a single forced guess."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    # One item each in three distinct mapped buckets: idor (user), xss (name),
    # ssrf (url). No single dominant -> ambiguous.
    _insert_work_item(
        db, queue_key="a:1", url="https://target.example/p1", url_path="/p1",
        status="pending", query_params='{"user": "1"}',
    )
    _insert_work_item(
        db, queue_key="a:2", url="https://target.example/p2", url_path="/p2",
        status="pending", query_params='{"name": "x"}',
    )
    _insert_work_item(
        db, queue_key="a:3", url="https://target.example/p3", url_path="/p3",
        status="pending", query_params='{"url": "http://x"}',
    )

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/p1"}],
            require_stage="consumption",
            auto_redispatch=True,
        )

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "consumption"
    assert rec["confidence"] == "low"
    assert rec["dominant_bucket"] is None
    # Shortlist contains one skill per present mapped bucket, ranked.
    assert set(rec["skills"]) == {"idor-testing", "xss-testing", "ssrf-testing"}
    # Still a vulnerability-analyst dispatch; the operator picks per surface.
    assert rec["role"] == "vulnerability-analyst"


def test_auto_redispatch_generic_dominant_bucket_is_low_confidence(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """When the most common pending bucket is generic/ambiguous
    (interestingparams), the recommendation is a low-confidence shortlist even
    though a smaller mapped bucket exists."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    # Three interestingparams (token) + one idor (user). Generic bucket
    # dominates -> low confidence, shortlist of the mapped buckets present.
    for i in range(3):
        _insert_work_item(
            db, queue_key=f"ip:{i}", url=f"https://target.example/g{i}", url_path=f"/g{i}",
            status="pending", query_params='{"token": "x"}',
        )
    _insert_work_item(
        db, queue_key="id:1", url="https://target.example/h1", url_path="/h1",
        status="pending", query_params='{"user": "1"}',
    )

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/g0"}],
            require_stage="consumption",
            auto_redispatch=True,
        )

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["confidence"] == "low"
    assert rec["dominant_bucket"] is None
    # idor-testing is the only mapped bucket present, surfaced as a shortlist.
    assert "idor-testing" in rec["skills"]


def test_auto_redispatch_dedup_suppresses_when_prior_dispatch_exists(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A recommendation is suppressed when a prior dispatch already covers the
    same (role, scope_host)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="idor:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    # Prior dispatch: a vulnerability-analyst already in flight against the host.
    dispatches = [
        {
            "agent_id": "va-001",
            "agent_role": "vulnerability-analyst",
            "scope_host": "target.example",
            "status": "in-progress",
        }
    ]

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
            dispatches=dispatches,
        )

    report = json.loads(capsys.readouterr().out)
    block = _redispatch(report)
    # No live recommendation for target.example — it was suppressed.
    assert not any(r["scope_host"] == "target.example" for r in block["recommendations"])
    suppressed = block["suppressed"]
    assert len(suppressed) == 1
    assert suppressed[0]["scope_host"] == "target.example"
    assert suppressed[0]["role"] == "vulnerability-analyst"
    assert "va-001" in suppressed[0]["reason"]


@pytest.mark.parametrize("terminal_status", ["completed", "failed", "aborted", "blocked"])
def test_auto_redispatch_terminal_prior_dispatch_does_not_suppress_retry(
    monkeypatch, tmp_path: Path, capsys, terminal_status: str
) -> None:
    """A host whose ONLY prior dispatch already TERMINATED (completed/failed/
    aborted/blocked) and still fails the gate must STILL get a retry
    recommendation — terminal dispatches no longer suppress dedup.

    Regression for the Codex P2 bug where the dedup fetch pulled ALL dispatches
    (no status filter) and suppressed against terminal rows, permanently
    starving a host of the retry it needs. The fetch now constrains to
    in-progress server-side (the FakeClient mirrors the backend's exact-match
    `status` filter), so a terminal-only row is never returned and never
    suppresses.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="idor:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    # The only prior dispatch for this (role, host) already terminated.
    dispatches = [
        {
            "agent_id": "va-terminal",
            "agent_role": "vulnerability-analyst",
            "scope_host": "target.example",
            "status": terminal_status,
        }
    ]

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
            dispatches=dispatches,
        )

    report = json.loads(capsys.readouterr().out)
    block = _redispatch(report)
    # The retry IS recommended (not suppressed) because the prior dispatch is
    # terminal, not active.
    rec = _rec_for_host(report, "target.example")
    assert rec["role"] == "vulnerability-analyst"
    assert rec["stage"] == "consumption"
    assert block["suppressed"] == []


def test_auto_redispatch_active_prior_dispatch_without_agent_id_suppresses(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """The dedup index falls back to the `id` field when `agent_id` is absent.

    An ACTIVE (in-progress) prior dispatch row that carries only `id` (no
    `agent_id`) must still suppress the recommendation, and the suppression
    reason must surface that `id` value. Exercises the
    `row.get("agent_id") or row.get("id")` fallback in
    `_index_prior_dispatches`.
    """
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="idor:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    # In-flight dispatch keyed by `id` only (no `agent_id`).
    dispatches = [
        {
            "id": "dispatch-42",
            "agent_role": "vulnerability-analyst",
            "scope_host": "target.example",
            "status": "in-progress",
        }
    ]

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
            dispatches=dispatches,
        )

    report = json.loads(capsys.readouterr().out)
    block = _redispatch(report)
    assert not any(r["scope_host"] == "target.example" for r in block["recommendations"])
    suppressed = block["suppressed"]
    assert len(suppressed) == 1
    assert suppressed[0]["scope_host"] == "target.example"
    # The id-only fallback is reflected in the reason string.
    assert "dispatch-42" in suppressed[0]["reason"]


def test_auto_redispatch_dedup_degrades_gracefully_on_backend_error(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A backend failure fetching prior dispatches must NOT crash the audit:
    recommendations are emitted un-deduped with an explanatory note."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="idor:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
            dispatches_error=True,
        )

    report = json.loads(capsys.readouterr().out)
    block = _redispatch(report)
    # Recommendation still emitted (not deduped) ...
    assert any(r["scope_host"] == "target.example" for r in block["recommendations"])
    # ... with a note that dedup degraded.
    assert any("dedup degraded" in note for note in block["notes"])


def test_auto_redispatch_drops_non_resolving_skill(monkeypatch, tmp_path: Path, capsys) -> None:
    """A recommended skill with no SKILL.md on disk is dropped (never
    recommended) and the drop is noted in the output."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="idor:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    module = _load_module()
    # Point idor at a real skill + a bogus one; the bogus name must be dropped.
    monkeypatch.setattr(
        module.cc,
        "BUCKET_SKILLS",
        {**module.cc.BUCKET_SKILLS, "idor": ("idor-testing", "does-not-exist-skill")},
    )

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
            _module=module,
        )

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["skills"] == ["idor-testing"]
    assert "does-not-exist-skill" in rec["dropped_skills"]
    block = _redispatch(report)
    assert any("does-not-exist-skill" in note for note in block["notes"])


def test_auto_redispatch_no_op_without_require_stage(monkeypatch, tmp_path: Path, capsys) -> None:
    """--auto-redispatch on a phase with NO stage gate produces no recommendations.

    Wave 6d: the consolidated command always relays a --phase. On a stage-gated
    phase (recon/collect/consume) --auto-redispatch recommends against failing
    entries; on a phase with no stage gate (verify/exploit/report, exercised here
    via the None→verify mapping) there is no scope gate at all, so there is
    nothing to recommend — the redispatch section is simply absent. This
    preserves the old "no stage gate → nothing to recommend" intent."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="p:0", url="https://target.example/api/profile/0",
        url_path="/api/profile", status="pending", query_params='{"user": "5"}',
    )

    _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "target.example", "state": "up"}],
        surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
        auto_redispatch=True,
        require_stage=None,
    )
    report = json.loads(capsys.readouterr().out)
    assert "redispatch" not in report or report["redispatch"]["recommendations"] == []


def test_auto_redispatch_respects_max_recommendations(monkeypatch, tmp_path: Path, capsys) -> None:
    """--max-recommendations caps the surfaced list; overflow is noted."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    # Three independent wildcard entries, all with an enum gap (no evidence).
    # Wildcards (unlike bare hosts) do not satisfy the enum gate trivially.
    _write_scope(eng, hosts=["*.a.example.test", "*.b.example.test", "*.c.example.test"])
    _make_cases_db(eng)

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[],
            surfaces=[],
            require_stage="enum",
            auto_redispatch=True,
            max_recommendations=2,
        )

    report = json.loads(capsys.readouterr().out)
    block = _redispatch(report)
    assert len(block["recommendations"]) == 2
    assert block["overflow"] == 1
    assert any("more failing entr" in note for note in block["notes"])


def test_auto_redispatch_clean_entries_emit_no_recommendations(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A fully-covered scope with --auto-redispatch yields an empty
    recommendation list (no gaps -> nothing to recommend)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    _insert_work_item(
        db, queue_key="d:1", url="https://target.example/a", url_path="/a", status="done"
    )

    _run(
        monkeypatch,
        eng,
        services=[{"endpoint": "target.example", "state": "up"}],
        surfaces=[{"target_descriptor": "https://target.example/a"}],
        require_stage="consumption",
        auto_redispatch=True,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is True
    block = _redispatch(report)
    assert block["recommendations"] == []
    assert block["suppressed"] == []


def test_bucket_skills_mapping_resolves_on_disk():
    """Every skill named in classify_buckets.BUCKET_SKILLS must resolve to a
    real agent/skills/<name>/SKILL.md. Catches a typo'd or stale skill name in
    the (now taxonomy-derived) mapping before it reaches an operator.

    Strengthened (Wave 4): BUCKET_SKILLS is no longer a hand-maintained literal
    — it is derived from the canonical taxonomy + skill `vuln_class:`
    frontmatter at import time. So we also assert the derivation is not
    trivially empty (a broken skills-dir read or empty frontmatter would yield
    an empty dict that vacuously passes the on-disk check) and that it still
    covers the load-bearing gf-buckets."""
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    import importlib

    cb = importlib.import_module("assess.lib.classify_buckets")
    assert cb.BUCKET_SKILLS, (
        "BUCKET_SKILLS is empty — the taxonomy derivation read no skill "
        "vuln_class frontmatter (broken skills dir or missing frontmatter)."
    )
    assert {
        "idor", "sqli", "ssrf", "xss", "ssti", "lfi", "img_traversal",
        "rce", "redirect", "cors", "upload_fields",
    } <= set(cb.BUCKET_SKILLS), (
        "BUCKET_SKILLS dropped a legacy gf-bucket after derivation: "
        f"{sorted(cb.BUCKET_SKILLS)}"
    )

    repo_root = Path(__file__).resolve().parents[3]
    skills_dir = repo_root / "agent" / "skills"
    missing: list[str] = []
    for bucket, skills in cb.BUCKET_SKILLS.items():
        for skill in skills:
            if not (skills_dir / skill / "SKILL.md").is_file():
                missing.append(f"{bucket}->{skill}")
    assert not missing, f"BUCKET_SKILLS references skills with no SKILL.md: {missing}"


def test_auto_redispatch_human_output_is_recommendation_only(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """Human-readable output prints the ready-to-run command + task skeleton and
    is explicitly RECOMMENDATION-ONLY (never fires a dispatch)."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["*.target.example"])
    _make_cases_db(eng)

    with pytest.raises(SystemExit):
        _run(
            monkeypatch,
            eng,
            services=[],
            surfaces=[],
            require_stage="enum",
            auto_redispatch=True,
            as_json=False,
        )
    out = capsys.readouterr().out
    assert "RECOMMENDATION-ONLY" in out
    assert "vigil assess agent start --role recon-specialist" in out
    assert "--scope-host target.example" in out
    # The parallel-role note and the task skeleton are both present.
    assert "source-analyzer" in out
    assert "task:" in out


def test_auto_redispatch_consumption_high_volume_swaps_to_fuzzer(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A consumption gap with a high volume (>= 100) of untested pending items
    concentrated on ONE dominant mapped bucket is fuzzing-shaped: the base
    vulnerability-analyst is swapped for a fuzzer in variant-rotation mode at
    confidence=high, and the vuln-class skills stay attached."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    # 120 untested pending IDOR-shaped items under a single host (the `user`
    # param uniquely keys the idor bucket). 120 >= _FUZZER_VOLUME_THRESHOLD
    # (100), so the single-dominant-bucket pick swaps va -> fuzzer.
    for i in range(120):
        _insert_work_item(
            db,
            queue_key=f"idor:{i}",
            url=f"https://target.example/api/profile/{i}",
            url_path="/api/profile",
            status="pending",
            query_params='{"user": "5"}',
        )

    # The audit fails the consumption gate -> SystemExit(1); the JSON report is
    # printed before the exit so we read it after catching.
    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/api/profile"}],
            require_stage="consumption",
            auto_redispatch=True,
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "consumption"
    # High volume on one bucket -> fuzzer, not vulnerability-analyst.
    assert rec["role"] == "fuzzer"
    assert rec["dispatch_mode"] == "variant-rotation"
    assert rec["confidence"] == "high"
    assert rec["dominant_bucket"] == "idor"
    assert rec["pending_count"] == 120
    # The vuln-class skills for the dominant bucket are still attached.
    assert rec["skills"] == ["idor-testing", "split-brain-idor"]
    # The emitted command encodes the fuzzer role, variant-rotation, and skills.
    assert "--role fuzzer" in rec["command"]
    assert "--dispatch-mode variant-rotation" in rec["command"]
    assert "--skills idor-testing,split-brain-idor" in rec["command"]


def test_auto_redispatch_consumption_no_mapped_bucket_omits_skills(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """A consumption gap whose pending work has no mapped vuln-class bucket
    (only generic/unbucketed params, e.g. an interestingparams token) yields a
    vulnerability-analyst recommendation with EMPTY skills at confidence=low,
    and the emitted command omits --skills entirely."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)
    # A `token` param classifies as the generic `interestingparams` bucket,
    # which is intentionally NOT in BUCKET_SKILLS — so nothing maps to a
    # testing skill and the recommendation must not guess one.
    _insert_work_item(
        db,
        queue_key="ip:0",
        url="https://target.example/g0",
        url_path="/g0",
        status="pending",
        query_params='{"token": "x"}',
    )

    with pytest.raises(SystemExit) as excinfo:
        _run(
            monkeypatch,
            eng,
            services=[{"endpoint": "target.example", "state": "up"}],
            surfaces=[{"target_descriptor": "https://target.example/g0"}],
            require_stage="consumption",
            auto_redispatch=True,
        )
    assert excinfo.value.code == 1

    report = json.loads(capsys.readouterr().out)
    rec = _rec_for_host(report, "target.example")
    assert rec["stage"] == "consumption"
    assert rec["role"] == "vulnerability-analyst"
    assert rec["confidence"] == "low"
    assert rec["dominant_bucket"] is None
    # No bucketed pending maps to a vuln class -> empty skills (no guess).
    assert rec["skills"] == []
    # The command must omit --skills when there is nothing to recommend.
    assert "--skills" not in rec["command"]
    assert "--role vulnerability-analyst" in rec["command"]
    assert "--scope-host target.example" in rec["command"]




def test_consumption_not_satisfied_when_work_stuck_in_processing(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """S8 — a work item stuck in `processing` (claimed but never finalized) is
    NOT consumed: the consumption gate must NOT pass and must name it."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)

    _insert_work_item(db, queue_key="d:1", url="https://target.example/a", url_path="/a", status="done")
    _insert_work_item(
        db, queue_key="p:1", url="https://target.example/b", url_path="/b", status="processing"
    )

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/a"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    entry = report["entries"][0]
    assert entry["work_queued"]["processing"] == 1
    assert "work-stuck-processing-or-error" in entry["gaps"]
    assert "pending-work-remains" not in entry["gaps"]


def test_consumption_not_satisfied_when_work_in_error(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """S8 — an `error` row (a failed attempt) is not consumed work either."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    db = _make_cases_db(eng)

    _insert_work_item(db, queue_key="d:1", url="https://target.example/a", url_path="/a", status="done")
    _insert_work_item(
        db, queue_key="e:1", url="https://target.example/b", url_path="/b", status="error"
    )

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/a"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    entry = report["entries"][0]
    assert entry["work_queued"]["error"] == 1
    assert "work-stuck-processing-or-error" in entry["gaps"]


def test_advisory_bucket_tally_surfaces_stuck_processing_and_error(
    monkeypatch, tmp_path: Path
) -> None:
    """S8 — the advisory/EV-ranked bucket tally must ALSO see processing/error
    rows, not just pending; otherwise stuck work is hidden from the harness view
    even though the boolean flipped."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    db = _make_cases_db(eng)

    _insert_work_item(
        db, queue_key="p:1", url="https://target.example/u", url_path="/users/1",
        status="processing", cluster_key="gf:idor",
    )
    _insert_work_item(
        db, queue_key="e:1", url="https://target.example/v", url_path="/users/2",
        status="error", cluster_key="gf:idor",
    )

    module = _load_module()
    entry = module.classify_scope_entry("target.example")
    tally = module._pending_buckets_for_host(db, entry)
    assert tally.get("idor", 0) == 2


def test_consumption_not_satisfied_when_buffer_missing_but_surfaces_present(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """S9 — a missing cases.db (empty work map) with surfaces present must NOT
    silently pass consumption: the work to consume cannot be proven gone."""
    eng = tmp_path / "engagement"
    eng.mkdir()
    _write_scope(eng, hosts=["target.example"])
    assert not (eng / "cases.db").exists()

    services = [{"endpoint": "target.example", "state": "up"}]
    surfaces = [{"target_descriptor": "https://target.example/a"}]

    with pytest.raises(SystemExit) as excinfo:
        _run(monkeypatch, eng, services=services, surfaces=surfaces, require_stage="consumption")
    assert excinfo.value.code == 1
    report = json.loads(capsys.readouterr().out)
    assert report["ready"] is False
    entry = report["entries"][0]
    assert "work-buffer-missing" in entry["gaps"]
