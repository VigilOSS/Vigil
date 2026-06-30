"""CLI tests for the recon-pipeline stage-completion audit (item 2.1 / P-1).

Covers the CLI half of ``vigil assess check-phase-readiness``:

  * ``coverage_checks.render_stage_audit`` — renders the backend ``stage_audit``
    block and reports whether ≥1 stage gap is open.
  * ``check_phase_readiness.run`` --strict wiring — an open stage gap escalates
    to a non-zero exit ONLY under ``--strict`` (advisory/WARN otherwise), and
    that escalation is ADDITIVE to the pre-existing intel-closure ``--strict``
    behavior, never a replacement.

These mirror ``test_check_scope_coverage.py``: the CLI is driven in-process via
a monkeypatched ``AssessmentClient`` (serving the phase-readiness payload) and a
stubbed scope gate, so the test isolates the stage-audit contribution to the
exit code without standing up FastAPI or a real scope.json/cases.db.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any


# ---------------------------------------------------------------------------
# Module loaders (mirrors test_check_scope_coverage._load_script_module)
# ---------------------------------------------------------------------------


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_cc():
    return _load_script_module(
        "stage_audit_coverage_checks_module",
        "agent/scripts/assess/lib/coverage_checks.py",
    )


def _load_cli():
    cc = _load_cc()
    module = _load_script_module(
        "stage_audit_check_phase_readiness_module",
        "agent/scripts/assess/commands/check_phase_readiness.py",
    )
    module.cc = cc
    return module


# ---------------------------------------------------------------------------
# render_stage_audit — pure rendering + open-gap detection
# ---------------------------------------------------------------------------


def test_render_stage_audit_clean_reports_no_open_gaps():
    cc = _load_cc()
    audit = {
        "applicable": True,
        "phase": "recon",
        "expected_stages": ["subdomain_enum", "http_liveness", "crawl"],
        "satisfied_stages": ["subdomain_enum", "http_liveness", "crawl"],
        "gaps": [],
        "open_gap_count": 0,
    }
    has_open, lines = cc.render_stage_audit(audit)
    assert has_open is False
    assert any("ok" in line and "3 expected" in line for line in lines), lines


def test_render_stage_audit_reports_each_gap_and_open_flag():
    cc = _load_cc()
    audit = {
        "applicable": True,
        "phase": "recon",
        "expected_stages": ["crawl", "historical_urls"],
        "satisfied_stages": [],
        "gaps": [
            {
                "stage": "crawl",
                "label": "katana crawl",
                "disposition": "timed_out",
                "command_run_ids": [12],
                "action": "re-run-or-accept",
                "detail": "katana crawl timed out",
            },
            {
                "stage": "historical_urls",
                "label": "gau historical-URL mining",
                "disposition": "never_ran",
                "command_run_ids": [],
                "action": "re-run-or-accept",
                "detail": "gau never ran",
            },
        ],
        "open_gap_count": 2,
    }
    has_open, lines = cc.render_stage_audit(audit)
    assert has_open is True
    body = "\n".join(lines)
    assert "2 open stage gap(s)" in body
    assert "crawl" in body and "timed_out" in body and "#12" in body
    assert "historical_urls" in body and "never ran" in body


def test_render_stage_audit_not_applicable_renders_nothing():
    cc = _load_cc()
    has_open, lines = cc.render_stage_audit({"applicable": False, "gaps": []})
    assert has_open is False
    assert lines == []
    # A non-dict payload is also tolerated (defensive).
    assert cc.render_stage_audit(None) == (False, [])


# ---------------------------------------------------------------------------
# run() --strict wiring (advisory by default; strict escalates an open gap)
# ---------------------------------------------------------------------------


class _FakeClient:
    """Serves only the endpoints the recon path touches. The scope gate is
    stubbed out separately, so ``services``/``surfaces`` are never requested."""

    def __init__(self, *, stage_audit: dict[str, Any]) -> None:
        self._stage_audit = stage_audit
        self.calls: list[str] = []

    def get(self, endpoint: str) -> Any:
        self.calls.append(endpoint)
        if endpoint.startswith("phase-readiness"):
            return {
                "phase": "recon",
                "coverage": {"ready": True},
                "stage_audit": self._stage_audit,
                # Intel applicable=False → no open intel item, so the ONLY thing
                # that can drive a --strict non-zero exit here is the stage gap.
                "intel": {"applicable": False, "engagement_type": "red"},
            }
        raise AssertionError(f"Unexpected endpoint: {endpoint}")

    def get_engagement(self, *_a, **_k) -> Any:
        return {"applicable": False, "engagement_type": "red"}

    def close(self) -> None:
        return None

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False


def _run_recon(monkeypatch, *, stage_audit: dict[str, Any], strict: bool):
    """Drive ``run`` at the recon phase, returning (exit_code, projection).

    The per-scope-entry stage gate is stubbed to a passing empty report so the
    only exit-code contributor under test is the stage audit.
    """
    module = _load_cli()
    monkeypatch.setattr(
        module,
        "load_config",
        lambda _flag: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir="/tmp/eng-stage-audit",
            engagement_key="eng",
            agent_root="/tmp",
        ),
    )
    monkeypatch.setattr(
        module, "AssessmentClient", lambda base_url, engagement_key: _FakeClient(stage_audit=stage_audit)
    )
    # Stub the per-scope-entry gate: passing, empty, so it never drives exit.
    monkeypatch.setattr(
        module,
        "_run_scope_gate",
        lambda cfg, client, args, stage: (
            {"entries": [], "ready": True, "required_stage": stage, "overall_gaps": []},
            False,
        ),
    )

    args = SimpleNamespace(
        engagement_dir="/tmp/eng-stage-audit",
        phase="recon",
        as_json=True,
        verbose=False,
        strict_vendor_saas=False,
        by_host=False,
        include_discovered=False,
        auto_redispatch=False,
        max_recommendations=10,
        depth=False,
        by_app_unit=False,
        include_intel=False,
        strict=strict,
        strict_deep=False,
    )
    buf = io.StringIO()
    rc = 0
    try:
        with contextlib.redirect_stdout(buf):
            module.run(args)
    except SystemExit as exc:
        rc = int(exc.code or 0)
    projection = json.loads(buf.getvalue())
    return rc, projection


_GAP_AUDIT = {
    "applicable": True,
    "phase": "recon",
    "expected_stages": ["subdomain_enum", "http_liveness", "crawl", "historical_urls", "secret_mining"],
    "satisfied_stages": ["subdomain_enum", "http_liveness", "secret_mining"],
    "gaps": [
        {
            "stage": "crawl",
            "label": "katana crawl",
            "disposition": "timed_out",
            "command_run_ids": [12],
            "action": "re-run-or-accept",
            "detail": "katana crawl timed out",
        },
        {
            "stage": "historical_urls",
            "label": "gau historical-URL mining",
            "disposition": "never_ran",
            "command_run_ids": [],
            "action": "re-run-or-accept",
            "detail": "gau never ran",
        },
    ],
    "open_gap_count": 2,
}

_CLEAN_AUDIT = {
    "applicable": True,
    "phase": "recon",
    "expected_stages": ["subdomain_enum", "http_liveness", "crawl", "historical_urls", "secret_mining"],
    "satisfied_stages": ["subdomain_enum", "http_liveness", "crawl", "historical_urls", "secret_mining"],
    "gaps": [],
    "open_gap_count": 0,
}


def test_advisory_open_gap_does_not_change_exit_code(monkeypatch):
    """Without --strict an open stage gap is WARN-only: exit 0, gap reported."""
    rc, projection = _run_recon(monkeypatch, stage_audit=_GAP_AUDIT, strict=False)
    assert rc == 0
    assert projection["stage_audit_open_gaps"] is True
    assert projection["stage_audit"]["open_gap_count"] == 2
    assert projection["ready"] is True


def test_strict_open_gap_exits_nonzero(monkeypatch):
    """--strict escalates an open stage gap to a non-zero exit."""
    rc, projection = _run_recon(monkeypatch, stage_audit=_GAP_AUDIT, strict=True)
    assert rc == 1
    assert projection["stage_audit_open_gaps"] is True
    assert projection["ready"] is False


def test_strict_clean_audit_exits_zero(monkeypatch):
    """--strict with no open stage gap leaves the exit code clean."""
    rc, projection = _run_recon(monkeypatch, stage_audit=_CLEAN_AUDIT, strict=True)
    assert rc == 0
    assert projection["stage_audit_open_gaps"] is False
    assert projection["ready"] is True
