"""Accessor coverage for the per-invocation rate cap + required-headers reads.

``vigil engagement create --rate-limit`` writes a ``rate_limit`` field (req/s, a
per-invocation / GLOBAL token-bucket ceiling that bounds per-host only as a side
effect) into scope.json; the recon pipeline's bulk web stages read it via
``scope.rate_limit`` / ``scope.rate_caps_for_dir``. Unset must return ``None`` so
behavior is exactly today's (per-tool defaults, no hard gate). A malformed value
is treated as unset rather than producing a zero/negative throttle. A scope.json
that EXISTS but cannot be parsed for the cap must warn loudly (fail-loud) rather
than silently un-throttle the pass.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from assess.lib import scope


@pytest.mark.parametrize(
    "value,expected",
    [
        ({}, None),
        ({"rate_limit": None}, None),
        ({"rate_limit": 5}, 5.0),
        ({"rate_limit": 3.5}, 3.5),
        ({"rate_limit": "5"}, 5.0),
        ({"rate_limit": 0}, None),
        ({"rate_limit": -1}, None),
        ({"rate_limit": "bogus"}, None),
        ({"rate_limit": True}, None),  # bool must not coerce to 1.0
    ],
)
def test_rate_limit_accessor(value, expected) -> None:
    assert scope.rate_limit(value) == expected


def test_required_headers_accessor_filters_non_strings() -> None:
    assert scope.required_headers({}) == {}
    assert scope.required_headers({"required_headers": "nope"}) == {}
    assert scope.required_headers(
        {"required_headers": {"X-Bug-Bounty": "h", "Empty": "", "Bad": 5, "  ": "x"}}
    ) == {"X-Bug-Bounty": "h", "Empty": ""}


def _write_scope(eng_dir: Path, **fields) -> None:
    eng_dir.mkdir(parents=True, exist_ok=True)
    payload = {"engagement_type": "web", "hosts": ["example.com"]}
    payload.update(fields)
    (eng_dir / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def test_rate_caps_for_dir_reads_both_knobs(tmp_path) -> None:
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, rate_limit=5, required_headers={"X-Bug-Bounty": "h"})
    rate, headers = scope.rate_caps_for_dir(str(eng_dir))
    assert rate == 5.0
    assert headers == {"X-Bug-Bounty": "h"}


def test_rate_caps_for_dir_defaults_when_unset(tmp_path) -> None:
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    assert scope.rate_caps_for_dir(str(eng_dir)) == (None, {})


def test_rate_caps_for_dir_missing_scope_degrades(tmp_path, capsys) -> None:
    # A MISSING scope (unconfigured engagement) is a quiet, valid state — no warning.
    assert scope.rate_caps_for_dir(str(tmp_path / "nope")) == (None, {})
    assert capsys.readouterr().err == ""


def test_rate_caps_for_dir_unparseable_scope_warns(tmp_path, capsys) -> None:
    # A scope.json that EXISTS but is unparseable must NOT silently un-throttle:
    # it degrades to (None, {}) but emits a loud stderr WARNING so a malformed
    # scope can't quietly drop a politeness/legal rate ceiling (fail-loud).
    eng_dir = tmp_path / "broken"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text("{not valid json", encoding="utf-8")
    assert scope.rate_caps_for_dir(str(eng_dir)) == (None, {})
    err = capsys.readouterr().err
    assert "WARNING" in err
    assert "scope.json" in err
    assert "NOT being enforced" in err


def test_rate_caps_for_dir_non_object_scope_warns(tmp_path, capsys) -> None:
    # A scope.json that parses but is not a JSON object also warns before degrading.
    eng_dir = tmp_path / "listy"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text('["not", "an", "object"]', encoding="utf-8")
    assert scope.rate_caps_for_dir(str(eng_dir)) == (None, {})
    assert "WARNING" in capsys.readouterr().err


def test_rate_caps_for_dir_present_but_invalid_rate_warns(tmp_path, capsys) -> None:
    # A valid scope.json whose rate_limit VALUE is garbage (non-numeric / non-positive)
    # must also warn rather than silently un-throttle — same fail-loud intent as a
    # malformed file. (Hand-edit-only: `engagement create` rejects <1 and writes valid.)
    eng_dir = tmp_path / "badval"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        '{"hosts": ["x.example"], "rate_limit": "fast"}', encoding="utf-8")
    rate, _ = scope.rate_caps_for_dir(str(eng_dir))
    assert rate is None
    err = capsys.readouterr().err
    assert "WARNING" in err and "rate_limit" in err and "not a positive number" in err


def test_rate_caps_for_dir_valid_rate_does_not_warn(tmp_path, capsys) -> None:
    # The normal path (a valid positive rate_limit) must never warn.
    eng_dir = tmp_path / "okval"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        '{"hosts": ["x.example"], "rate_limit": 5}', encoding="utf-8")
    rate, _ = scope.rate_caps_for_dir(str(eng_dir))
    assert rate == 5.0
    assert capsys.readouterr().err == ""
