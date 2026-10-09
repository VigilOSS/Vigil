"""RED-phase contract tests for new classify_buckets behaviour.

Encodes the TEST-MATRIX rows from
``docs/research/classify-surface/IMPLEMENTATION-SPEC.md`` for four
bucket families:

* object-storage (§6.6 / matrix §12.6, rows B1-B6) — Domino + cloud discriminators,
  with the bare ``/files/`` and ``/static/files/`` NEGATIVE guards (override #2).
* deserialization (§6.7 / matrix §12.7, rows D1-D4) — Siteforce ``/sfsites/``
  path-prefix and ``__VIEWSTATE`` / ``viewState`` params, with ordinary ``.js``
  NEGATIVE (roster requirement).
* file-upload / upload_fields (§6.12 / matrix §12.13, rows U1-U4) — REST fragments
  and the three new keys, plus the EXACT-string regression pin for
  ``/api/users/avatar``.
* debug_logic extension (§6.13 / matrix §12.12, rows DL1-DL9) — the compound-only
  added fragments POSITIVE, plus the override #3 NEGATIVE guards (bare ``/health``,
  ``/info``, ``/version``, ``/metrics`` must NOT fire).

These describe TARGET behaviour and WILL fail against the current
``classify_buckets.py`` — that is the expected RED state. The module/fixture
conventions mirror ``orchestrator/backend/tests/test_work_buffer.py``
(``_classify_buckets`` loader + ``classify_from_fields`` call shape).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Import the real ``assess.lib.classify_buckets`` module.

    Mirrors the loader in ``test_work_buffer.py`` exactly so the two suites
    resolve the same module from the same ``agent/scripts`` path.
    """
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
    """Thin wrapper around ``classify_from_fields`` matching the
    ``test_work_buffer.py`` call convention (JSON-encoded param strings).

    Default ``case_type`` is the floor-less, non-inert ``unknown`` so these
    bucket-precision tests isolate bucket matching from the producer-``type``
    floor (the real ``api`` type floors to gf:api/20, which would make every
    bucket-less negative guard floor instead of falling through to path:*; the
    floor is covered by ``test_classify_type_floor.py``)."""
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# object-storage (matrix §12.6, rows B1-B6) — override #2
# ---------------------------------------------------------------------------


def test_object_storage_domino_nsf_fragment() -> None:
    """B1: ``.nsf`` Domino discriminator buckets as object-storage at 25."""
    assignment = _classify("/db.nsf/files")
    assert assignment["cluster_key"] == "gf:object-storage"
    assert assignment["priority_score"] == 25
    assert "object-storage" in assignment["matched_buckets"]


def test_object_storage_domino_file_with_numeric_id_idor_wins() -> None:
    """B2: ``$FILE`` + ``.nsf`` fire object-storage(25) but a numeric path id with
    context lifts the row to idor(35), which wins the cluster."""
    assignment = _classify("/foo.nsf/v/$FILE/123/doc.pdf")
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["priority_score"] == 35
    assert "object-storage" in assignment["matched_buckets"]
    assert "idor" in assignment["matched_buckets"]


def test_object_storage_cloud_s3_fragment() -> None:
    """B3: ``/s3/`` cloud fragment buckets as object-storage at 25."""
    assignment = _classify("/s3/bucket/key")
    assert assignment["cluster_key"] == "gf:object-storage"
    assert assignment["priority_score"] == 25


def test_object_storage_docscat_fragment() -> None:
    """B4: ``docscat`` Domino discriminator buckets as object-storage at 25."""
    assignment = _classify("/app/docscat/list")
    assert assignment["cluster_key"] == "gf:object-storage"
    assert assignment["priority_score"] == 25


def test_object_storage_negative_bare_files_pdf() -> None:
    """B5 NEGATIVE: a bare ``/files/*.pdf`` path MUST NOT match object-storage
    (override #2 forbids a bare ``/files/`` fragment); it has no id segment so it
    falls through to the path fallback at score 0."""
    assignment = _classify("/files/document.pdf")
    assert "object-storage" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/files/document.pdf"
    assert assignment["priority_score"] == 0


def test_object_storage_negative_static_files_logo() -> None:
    """B6 NEGATIVE: ``/static/files/logo.png`` MUST NOT match object-storage
    (override #2); it falls through to the path fallback at score 0."""
    assignment = _classify("/static/files/logo.png")
    assert "object-storage" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/static/files"
    assert assignment["priority_score"] == 0


# ---------------------------------------------------------------------------
# deserialization (matrix §12.7, rows D1-D4) — Siteforce path-prefix + ViewState
# ---------------------------------------------------------------------------


def test_deserialization_sfsites_path_prefix_overrides_js() -> None:
    """D1: the Siteforce ``/sfsites/`` loader-state path prefix buckets as
    deserialization(40) even though the URL ends ``.js``."""
    assignment = _classify("/sfsites/l/eyJtb2RlIjoxfQ/bootstrap.js")
    assert assignment["cluster_key"] == "gf:deserialization"
    assert assignment["priority_score"] == 40
    assert "deserialization" in assignment["matched_buckets"]


def test_deserialization_viewstate_query_param() -> None:
    """D2: a ``__VIEWSTATE`` query param buckets as deserialization(40)."""
    assignment = _classify("/render", query_params={"__VIEWSTATE": "AAEAAAD..."})
    assert assignment["cluster_key"] == "gf:deserialization"
    assert assignment["priority_score"] == 40
    assert "deserialization" in assignment["matched_buckets"]


def test_deserialization_negative_ordinary_js() -> None:
    """D3 NEGATIVE: an ordinary ``/static/app.js`` (no ``/sfsites/`` prefix, no
    deserial param) MUST NOT match deserialization; it stays low at the path
    fallback (roster requirement that ordinary ``.js`` stays low)."""
    assignment = _classify("/static/app.js")
    assert "deserialization" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/static/app.js"
    assert assignment["priority_score"] == 0


def test_deserialization_viewstate_body_param() -> None:
    """D4: a ``viewState`` body param buckets as deserialization(40)."""
    assignment = _classify("/save", body_params={"viewState": "rO0AB..."})
    assert assignment["cluster_key"] == "gf:deserialization"
    assert assignment["priority_score"] == 40
    assert "deserialization" in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# file-upload / upload_fields (matrix §12.13, rows U1-U4) — §6.12.1
# ---------------------------------------------------------------------------


def test_file_upload_avatar_exact_regression_pin() -> None:
    """U1 REGRESSION PIN (§10.2): the upload row ``/api/users/avatar`` with a
    ``file`` body param must cluster as ``gf:upload_fields`` at score 40 with the
    EXACT reason chain ``gf:lfi+gf:upload_fields`` (bucket token NOT renamed,
    weight kept at 30)."""
    assignment = _classify(
        "/api/users/avatar",
        case_type="upload",
        body_params={"file": "avatar.png"},
    )
    assert assignment["cluster_key"] == "gf:upload_fields"
    assert assignment["priority_score"] == 40
    assert assignment["priority_reason"] == "gf:lfi+gf:upload_fields"


def test_file_upload_rest_attachments_fragment_path_only() -> None:
    """U2: the new REST fragment ``/attachments`` fires upload_fields(30) with no
    param present."""
    assignment = _classify("/api/x/attachments")
    assert assignment["cluster_key"] == "gf:upload_fields"
    assert assignment["priority_score"] == 30
    assert "upload_fields" in assignment["matched_buckets"]


def test_file_upload_rest_file_upload_fragment() -> None:
    """U3: the new REST fragment ``/file-upload`` fires upload_fields(30)."""
    assignment = _classify("/file-upload")
    assert assignment["cluster_key"] == "gf:upload_fields"
    assert assignment["priority_score"] == 30


def test_file_upload_new_multipart_mime_type_keys() -> None:
    """U4: the new param keys ``multipart`` / ``mime_type`` fire upload_fields(30)."""
    assignment = _classify(
        "/submit",
        body_params={"multipart": "...", "mime_type": "image/png"},
    )
    assert assignment["cluster_key"] == "gf:upload_fields"
    assert assignment["priority_score"] == 30
    assert "upload_fields" in assignment["matched_buckets"]


# ---------------------------------------------------------------------------
# debug_logic extension (matrix §12.12, rows DL1-DL9) — override #3
# ---------------------------------------------------------------------------


def test_debug_logic_healthz_fragment() -> None:
    """DL1: the added ``/healthz`` fragment fires debug_logic(30)."""
    assignment = _classify("/healthz")
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30
    assert "debug_logic" in assignment["matched_buckets"]


def test_debug_logic_actuator_env_fragment() -> None:
    """DL2: the added ``/actuator/env`` fragment fires debug_logic(30)."""
    assignment = _classify("/actuator/env")
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30
    assert "debug_logic" in assignment["matched_buckets"]


def test_debug_logic_package_json_fragment() -> None:
    """DL3: the added ``/package.json`` fragment fires debug_logic(30)."""
    assignment = _classify("/package.json")
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30


def test_debug_logic_server_status_fragment() -> None:
    """DL4: the added ``/server-status`` fragment fires debug_logic(30)."""
    assignment = _classify("/server-status")
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30


def test_debug_logic_prometheus_fragment() -> None:
    """DL5: the added ``/prometheus`` fragment fires debug_logic(30)."""
    assignment = _classify("/prometheus")
    assert assignment["cluster_key"] == "gf:debug_logic"
    assert assignment["priority_score"] == 30


def test_debug_logic_negative_health_benefits_coverage() -> None:
    """DL6 NEGATIVE: bare ``/health`` is NOT a fragment and ``/healthz`` does not
    match ``/health-benefits``, so ``/health-benefits/coverage`` MUST score 0 and
    fall through to the path fallback (override #3)."""
    assignment = _classify("/health-benefits/coverage")
    assert "debug_logic" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/health-benefits/coverage"
    assert assignment["priority_score"] == 0


def test_debug_logic_negative_info_about() -> None:
    """DL7 NEGATIVE: bare ``/info`` is deliberately NOT added (override #3) →
    ``/info/about`` scores 0."""
    assignment = _classify("/info/about")
    assert "debug_logic" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/info/about"
    assert assignment["priority_score"] == 0


def test_debug_logic_negative_version_notes() -> None:
    """DL8 NEGATIVE: bare ``/version`` is deliberately NOT added (override #3) →
    ``/version/notes`` scores 0."""
    assignment = _classify("/version/notes")
    assert "debug_logic" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/version/notes"
    assert assignment["priority_score"] == 0


def test_debug_logic_negative_metrics_raw() -> None:
    """DL9 NEGATIVE: bare ``/metrics`` is deliberately NOT added (override #3) →
    ``/metrics/raw`` scores 0."""
    assignment = _classify("/metrics/raw")
    assert "debug_logic" not in assignment["matched_buckets"]
    assert assignment["cluster_key"] == "path:/metrics/raw"
    assert assignment["priority_score"] == 0
