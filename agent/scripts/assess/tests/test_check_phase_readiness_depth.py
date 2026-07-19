"""Coverage-grain unbundle (ADR 0012) — check-phase-readiness depth legibility.

The depth harness must be LEGIBLE: `signal_classes_uncovered` is surfaced in the
DEFAULT (non-JSON) text (previously --json only), and `--phase report` PREVIEWS
the depth ledger + the would-block set so the terminal depth block is visible
BEFORE `transition-phase report` enforces it. Neither ever changes this advisory
command's exit code — the hard block is a transition-phase precondition.

These tests cover:
  * `_render_depth_ledger` surfaces signal_classes_uncovered; DECISIVE units read
    "will block at report unless covered or deferred"; non-decisive units read
    advisory — even when the unit is family-`depth_satisfied`.
  * `_render_terminal_block_preview` renders both class- and family-grain
    would-block units (and nothing for a skipped/web-only result).
  * `check-phase-readiness --phase report` renders the ledger + would-block
    preview and stays exit-0 (preview only).
"""
from __future__ import annotations

import json
from types import SimpleNamespace

from assess.commands import check_phase_readiness as cpr


# ---------------------------------------------------------------------------
# _render_depth_ledger — default text surfaces signal_classes_uncovered
# ---------------------------------------------------------------------------


def _ledger(units):
    return {
        "skipped": False,
        "summary": {"deep_required": len(units), "depth_satisfied": 1,
                    "depth_unsatisfied": 0},
        "units": units,
    }


_DECISIVE_SATISFIED_WITH_CLASS_GAP = {
    "unit": {"host": "api.example.com", "path_prefix": "/v2/orders",
             "depth_tier": "app-unit"},
    "depth_satisfied": True,          # family gate satisfied ...
    "decisive_surface": True,
    "confidence": "high",
    "ev_rank": 5,
    "missing_block": [],
    "missing_warn": [],
    "signal_classes_uncovered": ["sqli"],   # ... but a class is still uncovered
}


def test_render_depth_ledger_decisive_class_gap_reads_will_block():
    lines = cpr._render_depth_ledger(
        _ledger([_DECISIVE_SATISFIED_WITH_CLASS_GAP]), by_app_unit=False)
    text = "\n".join(lines)
    assert "per-class signal gaps" in text
    assert "api.example.com/v2/orders" in text
    assert "sqli" in text
    assert "will block at report unless covered or deferred" in text


def test_render_depth_ledger_non_decisive_class_gap_reads_advisory():
    non_decisive = {
        **_DECISIVE_SATISFIED_WITH_CLASS_GAP,
        "decisive_surface": False,
        "confidence": "low",
    }
    lines = cpr._render_depth_ledger(_ledger([non_decisive]), by_app_unit=False)
    text = "\n".join(lines)
    assert "sqli" in text
    assert "advisory; per-class gap" in text
    assert "will block at report" not in text


def test_render_depth_ledger_by_app_unit_also_surfaces_class_gap():
    lines = cpr._render_depth_ledger(
        _ledger([_DECISIVE_SATISFIED_WITH_CLASS_GAP]), by_app_unit=True)
    text = "\n".join(lines)
    assert "per-class signal gaps" in text
    assert "will block at report unless covered or deferred" in text


def test_render_depth_ledger_no_class_gap_omits_section():
    clean = {**_DECISIVE_SATISFIED_WITH_CLASS_GAP, "signal_classes_uncovered": []}
    lines = cpr._render_depth_ledger(_ledger([clean]), by_app_unit=False)
    assert "per-class signal gaps" not in "\n".join(lines)


# ---------------------------------------------------------------------------
# _render_terminal_block_preview — the would-block set as a preview
# ---------------------------------------------------------------------------


def _would_block(blocking, deferral_count=0):
    return {
        "skipped": False,
        "blocking": blocking,
        "warned_under_observed": [],
        "deferred": [],
        "deferral_count": deferral_count,
    }


def test_terminal_block_preview_renders_class_grain():
    result = _would_block([{
        "unit": {"host": "api.example.com", "path_prefix": "/v2/orders"},
        "block_grain": "class",
        "uncovered_classes": ["sqli", "idor"],
        "missing_block_families": [],
    }])
    text = "\n".join(cpr._render_terminal_block_preview(result))
    assert "WOULD BLOCK" in text
    assert "uncovered BLOCK_HIGH class(es): sqli, idor" in text
    assert "api.example.com/v2/orders" in text


def test_terminal_block_preview_renders_family_grain():
    result = _would_block([{
        "unit": {"host": "auth.example.com", "path_prefix": "/login"},
        "block_grain": "family",
        "missing_block_families": ["access-control", "auth"],
    }])
    text = "\n".join(cpr._render_terminal_block_preview(result))
    assert "untested/undeferred/untouched" in text
    assert "access-control" in text


def test_terminal_block_preview_empty_and_skipped():
    assert cpr._render_terminal_block_preview({"skipped": True}) == []
    text = "\n".join(cpr._render_terminal_block_preview(_would_block([], deferral_count=3)))
    assert "no app unit would block" in text
    assert "3 depth_deferral(s) recorded" in text


# ---------------------------------------------------------------------------
# check-phase-readiness --phase report — preview integration (exit-0)
# ---------------------------------------------------------------------------


def _setup_report_env(monkeypatch, tmp_path, *, backend, depth_ledger, terminal_block):
    engagement = tmp_path / "agent" / "engagements" / "eng-web"
    engagement.mkdir(parents=True, exist_ok=True)
    (engagement / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "exploit"}),
        encoding="utf-8")

    class _Client:
        def __init__(self, *_a, **_k) -> None:
            pass

        def get(self, path: str):
            if path == "phase-readiness?phase=report":
                return backend
            if path == "application-units/depth-ledger":
                return depth_ledger
            if path == "application-units/terminal-block":
                return terminal_block
            return []

        def get_engagement(self, path: str):
            return None

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            self.close()
            return False

    monkeypatch.setattr(cpr, "AssessmentClient", _Client)
    monkeypatch.setattr(
        cpr, "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_dir=str(engagement),
            engagement_key=engagement.name,
        ),
    )
    return engagement


def _report_args(engagement, **overrides):
    base = dict(
        engagement_dir=str(engagement),
        phase="report",
        as_json=False,
        strict=False,
        strict_deep=False,
        by_app_unit=False,
        depth=False,
        include_intel=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_phase_report_previews_ledger_and_would_block(monkeypatch, tmp_path, capsys):
    backend = {
        "report_readiness": {"ready": True, "blockers": [], "advisories": []},
        "intel": {},
    }
    eng = _setup_report_env(
        monkeypatch, tmp_path,
        backend=backend,
        depth_ledger=_ledger([_DECISIVE_SATISFIED_WITH_CLASS_GAP]),
        terminal_block=_would_block([{
            "unit": {"host": "api.example.com", "path_prefix": "/v2/orders"},
            "block_grain": "class",
            "uncovered_classes": ["sqli"],
            "missing_block_families": [],
        }]),
    )
    # report_readiness ready + no open intel -> the command exits 0. The depth
    # preview must NOT change that (preview only).
    cpr.run(_report_args(eng))
    out = capsys.readouterr().out
    assert "depth ledger:" in out
    assert "per-class signal gaps" in out
    assert "will block at report unless covered or deferred" in out
    assert "depth backstop preview:" in out
    assert "WOULD BLOCK" in out
    assert "sqli" in out


def test_phase_report_preview_is_exit_zero_json_carries_would_block(monkeypatch, tmp_path, capsys):
    backend = {
        "report_readiness": {"ready": True, "blockers": [], "advisories": []},
        "intel": {},
    }
    eng = _setup_report_env(
        monkeypatch, tmp_path,
        backend=backend,
        depth_ledger=_ledger([_DECISIVE_SATISFIED_WITH_CLASS_GAP]),
        terminal_block=_would_block([{
            "unit": {"host": "api.example.com", "path_prefix": "/v2/orders"},
            "block_grain": "class",
            "uncovered_classes": ["sqli"],
            "missing_block_families": [],
        }]),
    )
    # --json path: exits 0 (no raise), projection carries the depth ledger +
    # would-block set for the downstream contract.
    cpr.run(_report_args(eng, as_json=True))
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert payload["depth_ledger"]["units"][0]["signal_classes_uncovered"] == ["sqli"]
    assert payload["depth_would_block"]["blocking"][0]["block_grain"] == "class"
