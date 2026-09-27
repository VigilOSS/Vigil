"""CLI-4 — `work-buffer reclassify --retype` pass (re-typing already-ingested rows).

`classify-work` was folded into `work-buffer reclassify` (both operate on
`assessment_work_items`); the pass logic moved verbatim into
`assess.commands.dispatch.work_items._reclassify` / `_reclassify_retype`. It
historically re-applied only the *bucket* classification (priority/cluster/
terminal_reason) and consumed the stored work-item `type` verbatim; the `--retype`
pass re-derives `type` for already-ingested rows.

These tests pin the MECHANISM of the `--retype` pass against the CURRENT
`classify_type` behavior (they deliberately do NOT assert specific new typing
*outcomes*, which evolve as the typer is tuned):

- the pass is gated behind the explicit `--retype` flag (off by default);
- default scope is `type='unknown'` rows only — already-typed rows are never
  touched unless `--retype-all` is given;
- the row's STORED `content_type` (and request `body`) is read and passed to
  `classify_type`;
- a row whose type CHANGES gets its `type` rewritten AND its downstream bucket
  classification (priority_score / cluster_key) re-applied;
- a row newly typed into an INERT type gets `status='skipped'`;
- the pass is idempotent (a second run changes nothing);
- non-`unknown` rows are untouched under the default scope.

`_reclassify` reads rows via `client.get_all_pages("work-items")` and writes via
`client.post("work-items/update", {"updates":[...]})` (ADR 0013). The stateful
`FakeAssessmentClient` serves those rows and applies the updates in place; the
pass is invoked directly with the fake client (the CLI wrapper builds the client
and hands it to `dispatch.run`).
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json

from assess.commands import work_buffer as wb
from assess.commands.dispatch import work_items as wi
from assess.lib import classify as classify_mod

from _fake_client import FakeAssessmentClient


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _insert_row(
    fake: FakeAssessmentClient,
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
    row = fake.add_row(
        queue_key=queue_key,
        method=method,
        url=url,
        url_path=url_path,
        query_params=query_params,
        body_params=body_params,
        path_params=path_params,
        content_type=content_type,
        body=body,
        type=case_type,
        source="test",
        status=status,
        priority_score=priority_score,
        priority_reason=priority_reason,
        cluster_key=cluster_key,
        terminal_reason=terminal_reason,
    )
    return int(row["id"])


def _row(fake: FakeAssessmentClient, row_id: int) -> dict:
    row = fake.row_by_id(row_id)
    return dict(row) if row is not None else {}


def _args(**overrides) -> argparse.Namespace:
    """Build the parsed-args namespace `_reclassify` reads."""
    base = dict(
        engagement_dir="eng",
        batch=500,
        reclassify_all=False,
        reclassify_stale=False,
        reclaim_skipped=False,
        retype=False,
        retype_all=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _run(fake: FakeAssessmentClient, args: argparse.Namespace) -> dict:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        wi._reclassify(fake, args)
    return json.loads(out.getvalue())


# --------------------------------------------------------------------------- #
# Flag registration / gating (now on `work-buffer reclassify`)
# --------------------------------------------------------------------------- #


def test_reclassify_action_and_retype_flags_registered():
    """`reclassify` is a work-buffer action, and `--retype` / `--retype-all` are
    real flags on the work-buffer parser, default False."""
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    wb.register(sub)
    ns = parser.parse_args(["work-buffer", "reclassify"])
    assert ns.action == "reclassify"
    assert ns.retype is False
    assert ns.retype_all is False
    ns2 = parser.parse_args(["work-buffer", "reclassify", "--retype"])
    assert ns2.retype is True
    assert ns2.retype_all is False
    ns3 = parser.parse_args(["work-buffer", "reclassify", "--retype-all"])
    assert ns3.retype_all is True


def test_retype_off_by_default_does_not_change_type(tmp_path, monkeypatch):
    """Without `--retype`, no row's `type` is ever rewritten — even if the typer
    would now return something different."""
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="k1", url_path="/style.css",
        content_type="text/css", case_type="unknown",
    )
    # Force the typer to a sentinel so any accidental call is detectable.
    monkeypatch.setattr(classify_mod, "classify_type", lambda *a, **k: "SENTINEL")

    _run(fake, _args())  # default reclassify, no --retype

    assert _row(fake, rid)["type"] == "unknown"


# --------------------------------------------------------------------------- #
# Default scope: only type='unknown'
# --------------------------------------------------------------------------- #


def test_retype_default_scope_only_unknown(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    unknown_id = _insert_row(
        fake, queue_key="u", url_path="/asset", content_type="text/css",
        case_type="unknown",
    )
    typed_id = _insert_row(
        fake, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )

    summary = _run(fake, _args(retype=True))

    assert _row(fake, unknown_id)["type"] == "stylesheet"
    assert _row(fake, typed_id)["type"] == "page"  # untouched
    assert summary["retyped"] == 1


def test_retype_all_widens_scope_to_typed_rows(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    typed_id = _insert_row(
        fake, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )
    summary = _run(fake, _args(retype=True, retype_all=True))
    assert _row(fake, typed_id)["type"] == "stylesheet"
    assert summary["retyped"] == 1


# --------------------------------------------------------------------------- #
# Stored content_type / body are READ and PASSED to classify_type
# --------------------------------------------------------------------------- #


def test_retype_reads_stored_content_type_and_body(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    _insert_row(
        fake, queue_key="k", method="POST", url_path="/submit",
        content_type="application/json", body='{"query":"{ me { id } }"}',
        case_type="unknown",
    )

    seen: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        seen["args"] = (method, url_path, content_type, body_snippet)
        return "unknown"

    monkeypatch.setattr(classify_mod, "classify_type", spy)
    _run(fake, _args(retype=True))

    assert seen["args"] == (
        "POST", "/submit", "application/json", '{"query":"{ me { id } }"}',
    )


def test_retype_passes_empty_string_when_content_type_null(tmp_path, monkeypatch):
    """When the stored content_type is NULL/empty, classify_type still receives a
    string (""), never None."""
    fake = FakeAssessmentClient()
    fake.add_row(
        queue_key="k", method="GET", url="http://t/x.js", url_path="/x.js",
        type="unknown", source="test", content_type=None, body=None,
    )

    calls: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        calls["ct"] = content_type
        calls["body"] = body_snippet
        return "unknown"

    monkeypatch.setattr(classify_mod, "classify_type", spy)
    _run(fake, _args(retype=True))

    assert calls["ct"] == ""
    assert calls["body"] == ""


# --------------------------------------------------------------------------- #
# Type change → downstream classification re-applied
# --------------------------------------------------------------------------- #


def test_retype_change_updates_type_and_reapplies_buckets(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="k", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
        priority_score=0, cluster_key=None, priority_reason=None,
    )

    _run(fake, _args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["priority_score"] == 20
    assert row["cluster_key"] == "gf:api"
    assert row["status"] == "pending"


def test_retype_newly_inert_row_is_skipped(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="k", url="http://t/logo", url_path="/logo",
        content_type="image/png", case_type="unknown", status="pending",
    )

    _run(fake, _args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "image"
    assert row["status"] == "skipped"
    assert row["terminal_reason"] == "inert_type"
    assert row["cluster_key"] == "type:image"


def test_retype_updates_queue_key_to_new_type(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="variant:42:unknown", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
    )

    _run(fake, _args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == "variant:42:api"


def test_retype_inert_to_actionable_restores_pending(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="variant:7:image", method="POST",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="image",
        status="skipped", terminal_reason="inert_type",
    )

    _run(fake, _args(retype_all=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["status"] == "pending"
    assert row["terminal_reason"] is None


def test_retype_preserves_operator_deferred_skip(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="variant:8:page", method="GET",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="page",
        status="skipped", terminal_reason="skipped:operator | Review after access is granted",
    )

    _run(fake, _args(retype_all=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["status"] == "skipped"
    assert row["terminal_reason"] == "skipped:operator | Review after access is granted"


def test_retype_does_not_corrupt_arjun_queue_key(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    qk = "arjun:POST:https://h.example/api/users:deadbeefcafef00d"
    rid = _insert_row(
        fake, queue_key=qk, method="POST",
        url="https://h.example/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
    )

    _run(fake, _args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == qk  # unchanged — params_sig not a type


def test_retype_does_not_corrupt_deferred_queue_key(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    qk = "deferred:egress-blocked:h.example:https://h.example/api/x"
    rid = _insert_row(
        fake, queue_key=qk, method="GET",
        url="https://h.example/api/x", url_path="/api/x",
        content_type="application/json", case_type="unknown",
    )

    _run(fake, _args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == qk  # unchanged — trailing segment is a URL


def test_retype_preserves_non_skipped_status(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="variant:9:image", method="GET",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="image",
        status="deferred",
    )

    _run(fake, _args(retype_all=True))

    row = _row(fake, rid)
    assert row["type"] == "api"  # actionable, non-terminal
    assert row["status"] == "deferred"  # preserved, NOT flipped to pending


def test_retype_no_change_leaves_row_alone(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="k", url_path="/about", content_type="",
        case_type="unknown", priority_score=0,
    )
    summary = _run(fake, _args(retype=True))
    assert _row(fake, rid)["type"] == "unknown"
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


def test_retype_is_idempotent(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    rid = _insert_row(
        fake, queue_key="k", url_path="/app.js", content_type="",
        case_type="unknown",
    )

    first = _run(fake, _args(retype=True))
    snapshot = _row(fake, rid)
    second = _run(fake, _args(retype=True))

    assert first["retyped"] == 1
    assert second["retyped"] == 0
    assert _row(fake, rid) == snapshot


def test_retype_all_idempotent_on_already_correct_rows(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    _insert_row(
        fake, queue_key="k", url_path="/app.js", content_type="",
        case_type="javascript",
    )
    summary = _run(fake, _args(retype=True, retype_all=True))
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Safety: rows are never deleted, summary reports old→new
# --------------------------------------------------------------------------- #


def test_retype_never_deletes_rows_and_reports_transitions(tmp_path, monkeypatch):
    fake = FakeAssessmentClient()
    _insert_row(fake, queue_key="a", url_path="/a.css", content_type="text/css",
                case_type="unknown")
    _insert_row(fake, queue_key="b", url_path="/b.png", content_type="image/png",
                case_type="unknown")

    summary = _run(fake, _args(retype=True))

    assert len(fake.rows) == 2  # nothing deleted
    assert summary["scanned"] == 2
    assert summary["retyped"] == 2
    assert summary["by_transition"]["unknown->stylesheet"] == 1
    assert summary["by_transition"]["unknown->image"] == 1
