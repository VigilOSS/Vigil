"""CLI-4 — classify-work `--retype` pass (re-typing already-ingested rows).

`classify-work` historically re-applied only the *bucket* classification
(priority/cluster/terminal_reason) and consumed the stored work-item `type`
verbatim. Any improvement to the *typer* (`assess.lib.classify.classify_type`)
was therefore inert on existing engagement corpora — there was no path to
re-derive `type` for rows already ingested.

These tests pin the MECHANISM of the `--retype` pass against the CURRENT
`classify_type` behavior (they deliberately do NOT assert specific new typing
*outcomes*, which evolve as the typer is tuned):

- the pass is gated behind the explicit `--retype` flag (off by default);
- default scope is `type='unknown'` rows only — already-typed rows are never
  touched unless `--retype-all` is given;
- the row's STORED `content_type` (and request `body`) is read and passed to
  `classify_type` (the historical ingest bug fed it `""`);
- a row whose type CHANGES gets its `type` rewritten AND its downstream bucket
  classification (priority_score / cluster_key) re-applied;
- a row newly typed into an INERT type gets `status='skipped'` like the insert
  path stamps it;
- the pass is idempotent (a second run changes nothing);
- non-`unknown` rows are untouched under the default scope.

The `work_items` table now lives in the orchestrator backend
(`assessment_work_items`): `classify-work` reads rows via
`client.get_all_pages("work-items")` and writes via
`client.post("work-items/update", {"updates":[...]})`. The stateful
`FakeAssessmentClient` serves those rows and applies the updates in place, so
the former direct-SQLite pre-state seeding and re-reads are re-expressed against
the fake's `rows`.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json

from assess.commands import classify_work as cw
from assess.lib import classify as classify_mod

from _fake_client import FakeAssessmentClient


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


def _make_fake(monkeypatch) -> FakeAssessmentClient:
    """Build a fake backend and route classify-work's client at it."""
    fake = FakeAssessmentClient()
    monkeypatch.setattr(cw, "load_config", lambda *a, **k: _Cfg("eng"))
    monkeypatch.setattr(cw, "AssessmentClient", lambda *a, **k: fake)
    return fake


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
    """Seed a work-item row with explicit control over every retype input.

    Pins a precise pre-state — e.g. a row whose stored `content_type` was never
    fed to the typer, exactly the corpus condition `--retype` exists to repair.
    """
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
    """Build the parsed-args namespace `classify_work.run` expects.

    Mirrors the real parser defaults so a test only sets what it cares about.
    """
    base = dict(
        engagement_dir="eng",
        batch=500,
        reclassify_all=False,
        reclassify_stale=False,
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
    """`--retype` and `--retype-all` are real parser flags, default False.

    The `<cases.db>` positional was removed when the work buffer moved to the
    backend, so the parser takes no db path.
    """
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    cw.register(sub)
    ns = parser.parse_args(["classify-work"])
    assert ns.retype is False
    assert ns.retype_all is False
    ns2 = parser.parse_args(["classify-work", "--retype"])
    assert ns2.retype is True
    assert ns2.retype_all is False
    ns3 = parser.parse_args(["classify-work", "--retype-all"])
    assert ns3.retype_all is True


def test_retype_off_by_default_does_not_change_type(tmp_path, monkeypatch):
    """Without `--retype`, no row's `type` is ever rewritten — even if the
    typer would now return something different."""
    fake = _make_fake(monkeypatch)
    rid = _insert_row(
        fake, queue_key="k1", url_path="/style.css",
        content_type="text/css", case_type="unknown",
    )
    # Force the typer to a sentinel so any accidental call is detectable.
    monkeypatch.setattr(cw, "classify_type", lambda *a, **k: "SENTINEL")

    _run(_args())  # default classify-work, no --retype

    assert _row(fake, rid)["type"] == "unknown"


# --------------------------------------------------------------------------- #
# Default scope: only type='unknown'
# --------------------------------------------------------------------------- #


def test_retype_default_scope_only_unknown(tmp_path, monkeypatch):
    """Default `--retype` scope re-types ONLY `type='unknown'` rows; an
    already-typed row is left untouched."""
    fake = _make_fake(monkeypatch)
    # An unknown row whose stored content_type re-types to `stylesheet`.
    unknown_id = _insert_row(
        fake, queue_key="u", url_path="/asset", content_type="text/css",
        case_type="unknown",
    )
    # An already-typed `page` row that, if re-typed, would become `stylesheet`
    # too (css content-type) — but it must NOT be touched under default scope.
    typed_id = _insert_row(
        fake, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )

    summary = _run(_args(retype=True))

    assert _row(fake, unknown_id)["type"] == "stylesheet"
    assert _row(fake, typed_id)["type"] == "page"  # untouched
    assert summary["retyped"] == 1


def test_retype_all_widens_scope_to_typed_rows(tmp_path, monkeypatch):
    """`--retype-all` re-types already-typed rows too."""
    fake = _make_fake(monkeypatch)
    typed_id = _insert_row(
        fake, queue_key="t", url_path="/asset2", content_type="text/css",
        case_type="page",
    )
    summary = _run(_args(retype=True, retype_all=True))
    assert _row(fake, typed_id)["type"] == "stylesheet"
    assert summary["retyped"] == 1


# --------------------------------------------------------------------------- #
# Stored content_type / body are READ and PASSED to classify_type
# --------------------------------------------------------------------------- #


def test_retype_reads_stored_content_type_and_body(tmp_path, monkeypatch):
    """The row's stored `content_type` and `body` are read from backend state
    and passed positionally to `classify_type(method, url_path, content_type,
    body)` — the historical ingest bug fed the typer `""` for content_type."""
    fake = _make_fake(monkeypatch)
    _insert_row(
        fake, queue_key="k", method="POST", url_path="/submit",
        content_type="application/json", body='{"query":"{ me { id } }"}',
        case_type="unknown",
    )

    seen: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        seen["args"] = (method, url_path, content_type, body_snippet)
        # Return unknown so nothing downstream changes; we only assert inputs.
        return "unknown"

    monkeypatch.setattr(cw, "classify_type", spy)
    _run(_args(retype=True))

    assert seen["args"] == (
        "POST", "/submit", "application/json", '{"query":"{ me { id } }"}',
    )


def test_retype_passes_empty_string_when_content_type_null(tmp_path, monkeypatch):
    """When the stored content_type is NULL/empty, classify_type still receives
    a string (""), never None — path/extension typing still applies."""
    fake = _make_fake(monkeypatch)
    fake.add_row(
        queue_key="k", method="GET", url="http://t/x.js", url_path="/x.js",
        type="unknown", source="test", content_type=None, body=None,
    )

    seen: dict = {}

    def spy(method, url_path, content_type="", body_snippet=""):
        seen["ct"] = content_type
        seen["body"] = body_snippet
        return classify_mod.classify_type(method, url_path, content_type, body_snippet)

    monkeypatch.setattr(cw, "classify_type", spy)
    _run(_args(retype=True))

    assert seen["ct"] == ""
    assert seen["body"] == ""


# --------------------------------------------------------------------------- #
# Type change → downstream classification re-applied
# --------------------------------------------------------------------------- #


def test_retype_change_updates_type_and_reapplies_buckets(tmp_path, monkeypatch):
    """A row whose type changes gets its `type` rewritten AND its
    priority_score / cluster_key / priority_reason re-derived for the new
    type via the bucket classifier."""
    fake = _make_fake(monkeypatch)
    # An unknown row on an API path. classify_type sees `/api/` and returns
    # `api`; the bucket classifier then floors it to gf:api (score 20).
    rid = _insert_row(
        fake, queue_key="k", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
        priority_score=0, cluster_key=None, priority_reason=None,
    )

    _run(_args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    # Downstream bucket re-applied: gf:api floor → score 20, cluster gf:api.
    assert row["priority_score"] == 20
    assert row["cluster_key"] == "gf:api"
    assert row["status"] == "pending"


def test_retype_newly_inert_row_is_skipped(tmp_path, monkeypatch):
    """A row newly typed into an INERT type (e.g. image) gets status='skipped'
    and terminal_reason='inert_type', mirroring the insert path."""
    fake = _make_fake(monkeypatch)
    rid = _insert_row(
        fake, queue_key="k", url="http://t/logo", url_path="/logo",
        content_type="image/png", case_type="unknown", status="pending",
    )

    _run(_args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "image"
    assert row["status"] == "skipped"
    assert row["terminal_reason"] == "inert_type"
    assert row["cluster_key"] == "type:image"


def test_retype_updates_queue_key_to_new_type(tmp_path, monkeypatch):
    """queue_key embeds the type as its trailing ':'-delimited segment
    (`variant:<id>:<type>`). A retype that changes the type must rewrite
    queue_key too — otherwise a later re-ingest (which dedups on queue_key)
    computes the NEW `variant:<id>:api` key, misses the stale `:unknown` row,
    and inserts a DUPLICATE work item for the same request variant."""
    fake = _make_fake(monkeypatch)
    rid = _insert_row(
        fake, queue_key="variant:42:unknown", method="GET",
        url="http://t/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
    )

    _run(_args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == "variant:42:api"


def test_retype_inert_to_actionable_restores_pending(tmp_path, monkeypatch):
    """An inert row auto-skipped at ingest (status='skipped',
    terminal_reason='inert_type') that `--retype-all` re-types to an actionable
    type must be RESTORED to status='pending' (terminal_reason cleared) — else
    `work-buffer fetch`, which only dispatches status='pending', would never
    pick it up despite the new actionable classification."""
    fake = _make_fake(monkeypatch)
    # Mis-typed `image` + skipped at ingest, but its stored path + content_type
    # actually classify as `api`.
    rid = _insert_row(
        fake, queue_key="variant:7:image", method="POST",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="image",
        status="skipped", terminal_reason="inert_type",
    )

    _run(_args(retype_all=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["status"] == "pending"
    assert row["terminal_reason"] is None


def test_retype_does_not_corrupt_arjun_queue_key(tmp_path, monkeypatch):
    """`arjun:<method>:<url>:<params_sig>` keys (ingest_arjun) carry a params_sig
    in their trailing ':'-segment, NOT a type. An `unknown` arjun row on an
    `/api/...` path re-types to `api`, but its queue_key must be left EXACTLY as
    stored — blindly swapping the trailing segment would corrupt the params_sig
    (the historical bug rewrote `...:deadbeefcafef00d` → `...:api`)."""
    fake = _make_fake(monkeypatch)
    qk = "arjun:POST:https://h.example/api/users:deadbeefcafef00d"
    rid = _insert_row(
        fake, queue_key=qk, method="POST",
        url="https://h.example/api/users", url_path="/api/users",
        content_type="application/json", case_type="unknown",
    )

    _run(_args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == qk  # unchanged — params_sig not a type


def test_retype_does_not_corrupt_deferred_queue_key(tmp_path, monkeypatch):
    """`deferred:egress-blocked:<host>:<url>` keys (ingest_endpoints) carry a URL
    in their trailing ':'-segment, NOT a type. An `unknown` deferred row that
    re-types to `api` must keep its queue_key intact — the historical bug split
    on the URL's `https:` colon and corrupted the key."""
    fake = _make_fake(monkeypatch)
    qk = "deferred:egress-blocked:h.example:https://h.example/api/x"
    rid = _insert_row(
        fake, queue_key=qk, method="GET",
        url="https://h.example/api/x", url_path="/api/x",
        content_type="application/json", case_type="unknown",
    )

    _run(_args(retype=True))

    row = _row(fake, rid)
    assert row["type"] == "api"
    assert row["queue_key"] == qk  # unchanged — trailing segment is a URL


def test_retype_preserves_non_skipped_status(tmp_path, monkeypatch):
    """Under `--retype-all`, a row whose status is a NON-skipped terminal/active
    state (e.g. 'deferred', 'done', 'processing', 'error') must keep that status
    when it re-types to an actionable type. Only previously-`skipped` rows are
    restored to 'pending'; the historical bug's `ELSE 'pending'` resurrected
    deferred/done/processing/error rows."""
    fake = _make_fake(monkeypatch)
    rid = _insert_row(
        fake, queue_key="variant:9:image", method="GET",
        url="http://t/api/orders", url_path="/api/orders",
        content_type="application/json", case_type="image",
        status="deferred",
    )

    _run(_args(retype_all=True))

    row = _row(fake, rid)
    assert row["type"] == "api"  # actionable, non-terminal
    assert row["status"] == "deferred"  # preserved, NOT flipped to pending


def test_retype_no_change_leaves_row_alone(tmp_path, monkeypatch):
    """When classify_type returns the SAME type, the row's downstream fields
    are not rewritten (a no-op type is not a change)."""
    fake = _make_fake(monkeypatch)
    # An unknown row that re-types to unknown (no path/content-type signal):
    # `/about` hits no typer rule, so it stays `unknown` and nothing is
    # counted as retyped. (A bare `/` would re-type to `host_root` — a real
    # change — so it is deliberately NOT used here.)
    rid = _insert_row(
        fake, queue_key="k", url_path="/about", content_type="",
        case_type="unknown", priority_score=0,
    )
    summary = _run(_args(retype=True))
    assert _row(fake, rid)["type"] == "unknown"
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Idempotency
# --------------------------------------------------------------------------- #


def test_retype_is_idempotent(tmp_path, monkeypatch):
    """Running `--retype` twice changes nothing the second time."""
    fake = _make_fake(monkeypatch)
    rid = _insert_row(
        fake, queue_key="k", url_path="/app.js", content_type="",
        case_type="unknown",
    )

    first = _run(_args(retype=True))
    snapshot = _row(fake, rid)
    second = _run(_args(retype=True))

    assert first["retyped"] == 1
    assert second["retyped"] == 0
    assert _row(fake, rid) == snapshot


def test_retype_all_idempotent_on_already_correct_rows(tmp_path, monkeypatch):
    """`--retype-all` over rows already at their correct type retypes none."""
    fake = _make_fake(monkeypatch)
    _insert_row(
        fake, queue_key="k", url_path="/app.js", content_type="",
        case_type="javascript",
    )
    summary = _run(_args(retype=True, retype_all=True))
    assert summary["retyped"] == 0


# --------------------------------------------------------------------------- #
# Safety: rows are never deleted, summary reports old→new
# --------------------------------------------------------------------------- #


def test_retype_never_deletes_rows_and_reports_transitions(tmp_path, monkeypatch):
    """No row is deleted; the summary records the old→new type transition map."""
    fake = _make_fake(monkeypatch)
    _insert_row(fake, queue_key="a", url_path="/a.css", content_type="text/css",
                case_type="unknown")
    _insert_row(fake, queue_key="b", url_path="/b.png", content_type="image/png",
                case_type="unknown")

    summary = _run(_args(retype=True))

    assert len(fake.rows) == 2  # nothing deleted
    assert summary["scanned"] == 2
    assert summary["retyped"] == 2
    # old→new transition tally is present and correct.
    assert summary["by_transition"]["unknown->stylesheet"] == 1
    assert summary["by_transition"]["unknown->image"] == 1
