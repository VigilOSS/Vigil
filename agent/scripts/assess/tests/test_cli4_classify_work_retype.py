"""CLI-4 — classify-work `--retype` pass (re-typing already-ingested rows).

`classify-work` historically re-applied only the *bucket* classification
(priority/cluster/terminal_reason) and consumed the stored `work_items.type`
verbatim. Any improvement to the *typer* (`assess.lib.classify.classify_type`)
was therefore inert on existing engagement corpora — there was no path to
re-derive `type` for rows already on disk.

These tests pin the MECHANISM of the new `--retype` pass against the CURRENT
`classify_type` behavior (they deliberately do NOT assert specific new typing
*outcomes*, which evolve as the typer is tuned):

- the pass is gated behind the explicit `--retype` flag (off by default);
- default scope is `type='unknown'` rows only — already-typed rows are never
  touched unless `--retype-all` is given;
- the row's STORED `content_type` (and request `body`) is read and passed to
  `classify_type` (the historical ingest bug fed it `""`);
- a row whose type CHANGES gets its `type` column rewritten AND its downstream
  bucket classification (priority_score / cluster_key) re-applied;
- a row newly typed into an INERT type gets `status='skipped'` like the insert
  path stamps it;
- the pass is idempotent (a second run changes nothing);
- non-`unknown` rows are untouched under the default scope.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import sqlite3
from pathlib import Path

from assess.commands import classify_work as cw
from assess.lib import classify as classify_mod
from assess.lib.db import db_init


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_db(tmp_path: Path) -> str:
    """Create an empty engagement DB with the real schema applied."""
    db_path = tmp_path / "cases.db"
    db_path.touch()
    db_init(str(db_path))
    return str(db_path)


def _insert_row(
    db_path: str,
    *,
    queue_key: str,
    method: str = "GET",
    url: str = "http://t.example/",
    url_path: str = "/",
    case_type: str = "unknown",
    content_type: str = "",
    body: str = "",
    status: str = "pending",
    priority_score: int = 0,
    priority_reason: str | None = None,
    cluster_key: str | None = None,
    terminal_reason: str | None = None,
    query_params: str = "{}",
    body_params: str = "{}",
    path_params: str = "{}",
) -> int:
    """Insert a work_items row with explicit control over every retype input.

    We write directly (not via `db_insert_work_item`) so each test can pin a
    precise pre-state — e.g. a row whose stored `content_type` was never fed to
    the typer, exactly the corpus condition `--retype` exists to repair.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO work_items (
                queue_key, method, url, url_path,
                query_params, body_params, path_params,
                content_type, body, type, source, status,
                priority_score, priority_reason, cluster_key, terminal_reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                queue_key, method, url, url_path,
                query_params, body_params, path_params,
                content_type, body, case_type, "test", status,
                priority_score, priority_reason, cluster_key, terminal_reason,
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _row(db_path: str, row_id: int) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        r = conn.execute("SELECT * FROM work_items WHERE id = ?", (row_id,)).fetchone()
        return dict(r) if r is not None else {}
    finally:
        conn.close()


def _args(db_path: str, **overrides) -> argparse.Namespace:
    """Build the parsed-args namespace `classify_work.run` expects.

    Mirrors the real parser defaults so a test only sets what it cares about.
    """
    base = dict(
        db_path=db_path,
        batch=500,
        reclassify_all=False,
        reclaim_skipped=False,
        only_unscored=False,
        retype=False,
        retype_all=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _run(args: argparse.Namespace) -> dict:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cw.run(args)
    return json.loads(out.getvalue())


# --------------------------------------------------------------------------- #
# Flag registration / gating
# --------------------------------------------------------------------------- #


def test_retype_flags_registered():
    """`--retype` and `--retype-all` are real parser flags, default False."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    cw.register(sub)
    ns = parser.parse_args(["classify-work", "db.sqlite"])
    assert ns.retype is False
    assert ns.retype_all is False
    ns2 = parser.parse_args(["classify-work", "db.sqlite", "--retype"])
    assert ns2.retype is True
    assert ns2.retype_all is False
    ns3 = parser.parse_args(["classify-work", "db.sqlite", "--retype-all"])
    assert ns3.retype_all is True


def test_retype_off_by_default_does_not_change_type(tmp_path, monkeypatch):
    """Without `--retype`, no row's `type` is ever rewritten — even if the
    typer would now return something different."""
    db_path = _make_db(tmp_path)
    rid = _insert_row(
        db_path, queue_key="k1", url_path="/style.css",
        content_type="text/css", case_type="unknown",
    )
    # Force the typer to a sentinel so any accidental call is detectable.
    monkeypatch.setattr(cw, "classify_type", lambda *a, **k: "SENTINEL")

    _run(_args(db_path))  # default classify-work, no --retype

    assert _row(db_path, rid)["type"] == "unknown"


# --------------------------------------------------------------------------- #
# Default scope: only type='unknown'
# --------------------------------------------------------------------------- #


def test_retype_default_scope_only_unknown(tmp_path):
    """Default `--retype` scope re-types ONLY `type='unknown'` rows; an
    already-typed row is left untouched."""
    db_path = _make_db(tmp_path)
    # An unknown row whose stored content_type re-types to `stylesheet`.
    unknown_id = _insert_row(
        db_path, queue_key="u", url_path="/asset", content_type="text/css",
        case_type="unknown",
    )
    # An already-typed `page` row that, if re-typed, would become `stylesheet`
    # too (css content-type) — but it must NOT be touched under default scope.
    typed_id = _insert_row(
        db_path, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )

    summary = _run(_args(db_path, retype=True))

    assert _row(db_path, unknown_id)["type"] == "stylesheet"
    assert _row(db_path, typed_id)["type"] == "page"  # untouched
    assert summary["retyped"] == 1


def test_retype_all_widens_scope_to_typed_rows(tmp_path):
    """`--retype-all` re-types already-typed rows too."""
    db_path = _make_db(tmp_path)
    typed_id = _insert_row(
        db_path, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )
    summary = _run(_args(db_path, retype=True, retype_all=True))
    assert _row(db_path, typed_id)["type"] == "stylesheet"
    assert summary["retyped"] == 1


# --------------------------------------------------------------------------- #
# Stored content_type / body are READ and PASSED to classify_type
# --------------------------------------------------------------------------- #


def test_retype_reads_stored_content_type_and_body(tmp_path, monkeypatch):
    """The row's stored `content_type` and `body` are read from the DB and
    passed positionally to `classify_type(method, url_path, content_type,
    body)` — the historical ingest bug fed the typer `""` for content_type."""
    db_path = _make_db(tmp_path)
    _insert_row(
        db_path, queue_key="k", method="POST", url_path="/submit",
        content_type="application/json", body='{"query":"{ me { id } }"}',
        case_type="unknown",
    )

    seen: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        seen["args"] = (method, url_path, content_type, body_snippet)
        # Return unknown so nothing downstream changes; we only assert inputs.
        return "unknown"

    monkeypatch.setattr(cw, "classify_type", spy)
    _run(_args(db_path, retype=True))

    assert seen["args"] == (
        "POST", "/submit", "application/json", '{"query":"{ me { id } }"}',
    )


def test_retype_passes_empty_string_when_content_type_null(tmp_path, monkeypatch):
    """When the stored content_type is NULL/empty, classify_type still receives
    a string (""), never None — path/extension typing still applies."""
    db_path = _make_db(tmp_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT INTO work_items (queue_key, method, url, url_path, type, source, "
            "content_type, body) VALUES (?,?,?,?,?,?,?,?)",
            ("k", "GET", "http://t/x.js", "/x.js", "unknown", "test", None, None),
        )
        conn.commit()
    finally:
        conn.close()

    seen: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        seen["ct"] = content_type
        seen["body"] = body_snippet
        return classify_mod.classify_type(method, url_path, content_type, body_snippet)

    monkeypatch.setattr(cw, "classify_type", spy)
    _run(_args(db_path, retype=True))

    assert seen["ct"] == ""
    assert seen["body"] == ""


# --------------------------------------------------------------------------- #
# Type change → downstream classification re-applied
# --------------------------------------------------------------------------- #


def test_retype_change_updates_type_and_reapplies_buckets(tmp_path):
    """A row whose type changes gets its `type` column rewritten AND its
    priority_score / cluster_key / priority_reason re-derived for the new
    type via the bucket classifier."""
    db_path = _make_db(tmp_path)
    # An unknown row on an API path. classify_type sees `/api/` and returns
    # `api`; the bucket classifier then floors it to gf:api (score 20).
    rid = _insert_row(
        db_path, queue_key="k", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
        priority_score=0, cluster_key=None, priority_reason=None,
    )

    _run(_args(db_path, retype=True))

    row = _row(db_path, rid)
    assert row["type"] == "api"
    # Downstream bucket re-applied: gf:api floor → score 20, cluster gf:api.
    assert row["priority_score"] == 20
    assert row["cluster_key"] == "gf:api"
    assert row["status"] == "pending"


def test_retype_newly_inert_row_is_skipped(tmp_path):
    """A row newly typed into an INERT type (e.g. image) gets status='skipped'
    and terminal_reason='inert_type', mirroring the insert path."""
    db_path = _make_db(tmp_path)
    rid = _insert_row(
        db_path, queue_key="k", url="http://t/logo", url_path="/logo",
        content_type="image/png", case_type="unknown", status="pending",
    )

    _run(_args(db_path, retype=True))

    row = _row(db_path, rid)
    assert row["type"] == "image"
    assert row["status"] == "skipped"
    assert row["terminal_reason"] == "inert_type"
    assert row["cluster_key"] == "type:image"


def test_retype_updates_queue_key_to_new_type(tmp_path):
    """queue_key embeds the type as its trailing ':'-delimited segment
    (`variant:<id>:<type>`). A retype that changes the type must rewrite
    queue_key too — otherwise a later re-ingest (which dedups on queue_key)
    computes the NEW `variant:<id>:api` key, misses the stale `:unknown` row,
    and inserts a DUPLICATE work item for the same request variant."""
    db_path = _make_db(tmp_path)
    rid = _insert_row(
        db_path, queue_key="variant:42:unknown", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
    )

    _run(_args(db_path, retype=True))

    row = _row(db_path, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == "variant:42:api"


def test_retype_inert_to_actionable_restores_pending(tmp_path):
    """An inert row auto-skipped at ingest (status='skipped',
    terminal_reason='inert_type') that `--retype-all` re-types to an actionable
    type must be RESTORED to status='pending' (terminal_reason cleared) — else
    `work-buffer fetch`, which only dispatches status='pending', would never
    pick it up despite the new actionable classification."""
    db_path = _make_db(tmp_path)
    # Mis-typed `image` + skipped at ingest, but its stored path + content_type
    # actually classify as `api`.
    rid = _insert_row(
        db_path, queue_key="variant:7:image", method="POST",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="image",
        status="skipped", terminal_reason="inert_type",
    )

    _run(_args(db_path, retype_all=True))

    row = _row(db_path, rid)
    assert row["type"] == "api"
    assert row["status"] == "pending"
    assert row["terminal_reason"] is None


def test_retype_no_change_leaves_row_alone(tmp_path):
    """When classify_type returns the SAME type, the row's downstream fields
    are not rewritten (a no-op type is not a change)."""
    db_path = _make_db(tmp_path)
    # An unknown row that re-types to unknown (no path/content-type signal):
    # `/about` hits no typer rule, so it stays `unknown` and nothing is
    # counted as retyped. (A bare `/` would re-type to `host_root` — a real
    # change — so it is deliberately NOT used here.)
    rid = _insert_row(
        db_path, queue_key="k", url_path="/about", content_type="",
        case_type="unknown", priority_score=0,
    )
    summary = _run(_args(db_path, retype=True))
    assert _row(db_path, rid)["type"] == "unknown"
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


def test_retype_is_idempotent(tmp_path):
    """Running `--retype` twice changes nothing the second time."""
    db_path = _make_db(tmp_path)
    rid = _insert_row(
        db_path, queue_key="k", url_path="/app.js", content_type="",
        case_type="unknown",
    )

    first = _run(_args(db_path, retype=True))
    snapshot = _row(db_path, rid)
    second = _run(_args(db_path, retype=True))

    assert first["retyped"] == 1
    assert second["retyped"] == 0
    assert _row(db_path, rid) == snapshot


def test_retype_all_idempotent_on_already_correct_rows(tmp_path):
    """`--retype-all` over rows already at their correct type retypes none."""
    db_path = _make_db(tmp_path)
    _insert_row(
        db_path, queue_key="k", url_path="/app.js", content_type="",
        case_type="javascript",
    )
    summary = _run(_args(db_path, retype=True, retype_all=True))
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Safety: rows are never deleted, summary reports old→new
# --------------------------------------------------------------------------- #


def test_retype_never_deletes_rows_and_reports_transitions(tmp_path):
    """No row is deleted; the summary records the old→new type transition map."""
    db_path = _make_db(tmp_path)
    _insert_row(db_path, queue_key="a", url_path="/a.css", content_type="text/css",
                case_type="unknown")
    _insert_row(db_path, queue_key="b", url_path="/b.png", content_type="image/png",
                case_type="unknown")

    summary = _run(_args(db_path, retype=True))

    conn = sqlite3.connect(db_path)
    try:
        count = conn.execute("SELECT COUNT(*) FROM work_items").fetchone()[0]
    finally:
        conn.close()
    assert count == 2  # nothing deleted
    assert summary["scanned"] == 2
    assert summary["retyped"] == 2
    # old→new transition tally is present and correct.
    assert summary["by_transition"]["unknown->stylesheet"] == 1
    assert summary["by_transition"]["unknown->image"] == 1
