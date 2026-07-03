"""Contract tests for the `dotnet_handler` gf bucket (Phase 0, Part 3 §A.1).

ASP.NET / WCF handler surfaces (`.axd`, `.ashx`, `.asmx`, `.svc`, `/_vti_bin/`,
`/trace.axd`, `/elmah.axd`) and the ViewState/EventValidation params
(`__viewstate`, `__eventvalidation`) score as `dotnet_handler` (weight 40 → class
`deserialization`). The module/fixture conventions mirror
``test_classify_buckets_storage_deser_debug.py`` (the ``_classify_buckets``
loader + ``classify_from_fields`` call shape).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Import the real ``assess.lib.classify_buckets`` module (same loader as the
    sibling bucket suites)."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(
    url_path: str,
    *,
    case_type: str = "unknown",
    query_params: dict | None = None,
    body_params: dict | None = None,
):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# Path-fragment positives
# ---------------------------------------------------------------------------


def test_dotnet_handler_axd_fragment() -> None:
    assignment = _classify("/trace.axd")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40
    assert "dotnet_handler" in assignment["matched_buckets"]


def test_dotnet_handler_ashx_fragment() -> None:
    assignment = _classify("/handlers/upload.ashx")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40
    assert "dotnet_handler" in assignment["matched_buckets"]


def test_dotnet_handler_asmx_fragment() -> None:
    assignment = _classify("/services/legacy.asmx")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40


def test_dotnet_handler_svc_fragment() -> None:
    assignment = _classify("/data.svc")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40


def test_dotnet_handler_vti_bin_fragment() -> None:
    assignment = _classify("/_vti_bin/owa/oab.xml")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40
    assert "dotnet_handler" in assignment["matched_buckets"]


def test_dotnet_handler_elmah_fragment() -> None:
    assignment = _classify("/elmah.axd")
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40


# ---------------------------------------------------------------------------
# Param-key positives
# ---------------------------------------------------------------------------


def test_dotnet_handler_eventvalidation_param() -> None:
    """`__eventvalidation` is unique to dotnet_handler (deserialization's key set
    has `__viewstate`/`viewstate` but NOT `__eventvalidation`), so it owns the
    cluster on its own."""
    assignment = _classify("/postback", body_params={"__EVENTVALIDATION": "abc"})
    assert assignment["cluster_key"] == "gf:dotnet_handler"
    assert assignment["priority_score"] == 40
    assert "dotnet_handler" in assignment["matched_buckets"]


def test_dotnet_handler_viewstate_cofires_deserialization_keeps_cluster() -> None:
    """`__VIEWSTATE` fires BOTH deserialization (declared first) and dotnet_handler.
    Deserialization keeps the cluster via the declaration-order tie-break at
    weight 40 (the pinned `__VIEWSTATE`→gf:deserialization behaviour), while
    dotnet_handler is additively recorded in the reason chain."""
    assignment = _classify("/render", query_params={"__VIEWSTATE": "AAEAAAD..."})
    assert assignment["cluster_key"] == "gf:deserialization"
    assert assignment["priority_score"] == 40
    assert "deserialization" in assignment["matched_buckets"]
    assert "dotnet_handler" in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# Precision negatives
# ---------------------------------------------------------------------------


def test_dotnet_handler_negative_trailing_boundary() -> None:
    """`.axd` requires a segment boundary AFTER it (fragment_in_path semantics);
    `/report.axdx` (next char `x`) MUST NOT match dotnet_handler."""
    assignment = _classify("/report.axdx")
    assert "dotnet_handler" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/report.axdx"
    assert assignment["priority_score"] == 0


def test_dotnet_handler_negative_ordinary_path() -> None:
    """An ordinary path with no handler extension / ViewState param MUST NOT match."""
    assignment = _classify("/static/app.css")
    assert "dotnet_handler" not in assignment["matched_buckets"]
