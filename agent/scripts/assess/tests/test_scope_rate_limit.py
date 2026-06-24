"""Accessor coverage for the per-engagement rate cap + required-headers reads.

``vigil engagement create --rate-limit`` writes a ``rate_limit`` (req/s,
per-host) field into scope.json; recon stages (stage 2) read it via
``scope.rate_limit`` / ``scope.rate_caps_for_dir``. Unset must return ``None`` so
behavior is exactly today's (per-tool defaults, no hard gate). A malformed value
is treated as unset rather than producing a zero/negative throttle.
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


def test_rate_caps_for_dir_missing_scope_degrades(tmp_path) -> None:
    assert scope.rate_caps_for_dir(str(tmp_path / "nope")) == (None, {})
