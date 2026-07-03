"""Tests for the default-OFF dead-archive demotion (Fix 6, Issue H).

Covers the classify-context-and-surface 2026-06 Part 4 "Fix 6": when the opt-in
`demote_dead_archive` flag is set, a row that reaches the bucket-less `path:*`
fallback AND is dead `gau-archive` noise is parked at score 0 with the existing
`low-signal-cluster` skip tag (no new terminal vocabulary).

Pinned guarantees exercised here:
  (i)   the flag is default-OFF — a dead `gau-archive` fallback row is
        byte-identical to before unless the caller opts in;
  (ii)  with the flag ON the demotion predicate fires for source==gau-archive
        AND live_status null/dead/blackholed AND no gf bucket matched;
  (iii) the demotion NEVER touches a live row, a non-archive row, a
        bucket-matched row, or a type-floored row (precision-negatives).

The import + call convention mirrors `_classify_buckets()` in
`test_classify_precision.py` / `test_classify_context_scoring.py`, so these
exercise the real production `assess.lib.classify_buckets` module.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Import the real `assess.lib.classify_buckets` module (shared convention)."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


# ---------------------------------------------------------------------------
# (i) default-OFF — byte-identical unless the caller opts in
# ---------------------------------------------------------------------------
def test_flag_default_off_is_byte_identical():
    cb = _classify_buckets()
    base = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://www.example.com/old/page.html",
        source="gau-archive",
        live_status="dead",
    )
    explicit_off = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://www.example.com/old/page.html",
        source="gau-archive",
        live_status="dead",
        demote_dead_archive=False,
    )
    assert base == explicit_off
    assert base["terminal_reason"] is None
    assert base["cluster_key"].startswith("path:")


# ---------------------------------------------------------------------------
# (ii) flag ON — demotion fires for the dead-archive intersection
# ---------------------------------------------------------------------------
def test_demotes_dead_archive_null_live_status():
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://www.example.com/old/page.html",
        source="gau-archive",
        live_status=None,
        demote_dead_archive=True,
    )
    assert assignment["priority_score"] == 0
    assert assignment["priority_reason"] is None
    assert assignment["cluster_key"].startswith("path:")
    assert assignment["terminal_reason"].startswith("skipped:low-signal-cluster")
    assert cb.reason_tag_of(assignment["terminal_reason"]) == "low-signal-cluster"
    assert assignment["matched_buckets"] == []


def test_demotes_dead_archive_explicit_dead_and_blackholed():
    cb = _classify_buckets()
    for ls in ("dead", "blackholed", ""):
        assignment = cb.classify_from_fields(
            case_type="unknown",
            url_path="/old/page.html",
            url="https://www.example.com/old/page.html",
            source="gau-archive",
            live_status=ls,
            demote_dead_archive=True,
        )
        assert assignment["priority_score"] == 0, ls
        assert assignment["terminal_reason"].startswith("skipped:low-signal-cluster"), ls


def test_demotion_overrides_context_bonus_on_nonprod_host():
    """A dead archive row on a dev host would earn +15; demotion still parks it."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://dev.example.com/old/page.html",
        source="gau-archive",
        live_status="dead",
        demote_dead_archive=True,
    )
    assert assignment["priority_score"] == 0
    assert assignment["terminal_reason"].startswith("skipped:low-signal-cluster")


# ---------------------------------------------------------------------------
# (iii) precision-negatives — demotion must NOT fire
# ---------------------------------------------------------------------------
def test_live_archive_row_not_demoted():
    """A LIVE gau-archive row keeps its score (+5 live bonus) and no terminal."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://www.example.com/old/page.html",
        source="gau-archive",
        live_status="live",
        demote_dead_archive=True,
    )
    assert assignment["priority_score"] == 5
    assert assignment["terminal_reason"] is None


def test_non_archive_source_not_demoted():
    """A dead row from a non-archive source is left alone even with the flag on."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/old/page.html",
        url="https://www.example.com/old/page.html",
        source="katana",
        live_status="dead",
        demote_dead_archive=True,
    )
    assert assignment["terminal_reason"] is None


def test_bucket_matched_archive_row_not_demoted():
    """A dead gau-archive row that matched a gf bucket keeps its score/routing."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/users/avatar",
        query_params=json.dumps({"file": "x"}),
        url="https://www.example.com/api/users/avatar",
        source="gau-archive",
        live_status="dead",
        demote_dead_archive=True,
    )
    assert assignment["priority_reason"] == "gf:lfi+gf:upload_fields"
    assert assignment["priority_score"] == 40
    assert assignment["cluster_key"] == "gf:lfi"
    assert assignment["terminal_reason"] is None


def test_type_floored_archive_row_not_demoted():
    """A dead gau-archive row that hits a type floor keeps its floor cluster."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="api",
        url_path="/foo/bar",
        url="https://www.example.com/foo/bar",
        source="gau-archive",
        live_status="dead",
        demote_dead_archive=True,
    )
    assert assignment["cluster_key"] == "gf:api"
    assert assignment["terminal_reason"] is None
    assert assignment["priority_score"] > 0


# ---------------------------------------------------------------------------
# predicate helper unit checks
# ---------------------------------------------------------------------------
def test_is_dead_archive_noise_predicate():
    cb = _classify_buckets()
    assert cb._is_dead_archive_noise("gau-archive", None) is True
    assert cb._is_dead_archive_noise("gau-archive", "dead") is True
    assert cb._is_dead_archive_noise("GAU-ARCHIVE", "Blackholed") is True
    assert cb._is_dead_archive_noise("gau-archive", "live") is False
    assert cb._is_dead_archive_noise("gau-archive", "200") is False
    assert cb._is_dead_archive_noise("katana", None) is False
    assert cb._is_dead_archive_noise(None, None) is False
