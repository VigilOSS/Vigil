"""Tests for the CLIENT-SIDE work-buffer classification pipeline.

ADR 0013 folded the per-engagement local ``cases.db`` ``work_items`` queue into
the backend ledger (``assessment_work_items``), served over HTTP. The
server-side derivation / atomic-claim / dispatch-verb mechanics (the former
``dispatch fetch-by-priority`` / ``defer-cluster`` / ``stats`` / ``list-clusters``
/ ``peek``, plus the ``work_items_per_host`` view, ``db_init`` migrations, and
the proxy ``_insert_case`` write) now live in
``tests/test_work_buffer_backend.py`` and are NOT duplicated here.

What remains here is the still-CLIENT-SIDE intent:

  * pure classification-bucket behaviour, exercised directly against
    ``assess.lib.classify_buckets.classify_from_fields`` / ``classify_type`` /
    the reason-tag + INERT_TYPES helpers (model: sibling ``test_classify_*.py``);
  * the ``classify-work`` command loop (default / ``--reclassify-stale`` /
    ``--reclassify-all`` / ``--reclaim-skipped`` predicates and the
    ``classifier_version`` stamp), driven through the real
    ``assess.commands.classify_work.run`` against a fake ``AssessmentClient``;
  * the ``ingest-endpoints`` gf-bucket → coverage-candidate bridge and its
    IP/localhost/IPv6 admission, driven the same way;
  * ``coverage_checks._load_work_items_by_host`` / ``_consumption_satisfied``
    over a client-backed work buffer.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_script_module(name: str, relative_path: str):
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    module_path = Path(__file__).resolve().parents[3] / relative_path
    spec = importlib.util.spec_from_file_location(name, module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_classify_module():
    """Return the folded-in reclassify implementation.

    ``classify-work`` was merged into ``work-buffer reclassify``; the pass logic
    lives in ``assess.commands.dispatch.work_items`` (``_reclassify`` /
    ``_reclassify_retype``). It is a package submodule (relative imports), so it
    is imported normally rather than loaded as a standalone file.
    """
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))
    from assess.commands.dispatch import work_items

    return work_items


def _load_proxy_addon_module():
    mitmproxy = ModuleType("mitmproxy")
    http = ModuleType("mitmproxy.http")
    http.HTTPFlow = object  # type: ignore[attr-defined]
    mitmproxy.http = http  # type: ignore[attr-defined]
    mitmproxy.ctx = SimpleNamespace(
        log=SimpleNamespace(
            info=lambda *_args, **_kwargs: None,
            warn=lambda *_args, **_kwargs: None,
            error=lambda *_args, **_kwargs: None,
        ),
        options=SimpleNamespace(engagements_root="", registry_poll_seconds=30),
    )
    sys.modules.setdefault("mitmproxy", mitmproxy)
    sys.modules.setdefault("mitmproxy.http", http)
    return _load_script_module(
        "test_proxy_addon_module",
        "agent/scripts/proxy_addon.py",
    )


# ---------------------------------------------------------------------------
# classify-work driver. The per-engagement local cases.db is gone (ADR 0013);
# classify-work now reads/writes the backend work buffer over HTTP. We drive the
# real `classify_work.run` against a fake AssessmentClient that serves seeded row
# dicts and captures the `work-items/update` payloads (applying them back onto
# its in-memory rows so re-runs observe the mutation, exactly like the backend).
# The server-side derivation/claim/verb mechanics live in
# tests/test_work_buffer_backend.py.
# ---------------------------------------------------------------------------
class _FakeClassifyClient:
    """Fake AssessmentClient for classify_work.run.

    Serves seeded work-item rows via ``get_all_pages`` and captures the
    ``work-items/update`` payloads, applying each update back onto the in-memory
    row (keyed by ``id``) so a subsequent ``get_all_pages`` reflects the write —
    the same force-write-by-id contract the backend implements (see
    tests/test_work_buffer_backend.py::test_apply_updates_force_writes_status_and_type).
    """

    def __init__(self, rows: list[dict]):
        self._rows: dict = {row["id"]: dict(row) for row in rows}
        self.updates: list[dict] = []        # cumulative across runs
        self.last_updates: list[dict] = []    # only the most recent run

    # Used as the monkeypatched ``AssessmentClient(base_url, key)`` constructor.
    def __call__(self, *_args, **_kwargs):
        return self

    def get_all_pages(self, endpoint: str) -> list[dict]:
        assert endpoint == "work-items"
        return [dict(row) for row in self._rows.values()]

    def post(self, endpoint: str, payload: dict) -> dict:
        assert endpoint == "work-items/update"
        ups = list(payload["updates"])
        self.last_updates = ups
        self.updates.extend(ups)
        for up in ups:
            row = self._rows.get(up["id"])
            if row is None:
                continue
            for key, value in up.items():
                if key == "id":
                    continue
                row[key] = value
        return {"affected": len(ups)}

    def row(self, row_id):
        return self._rows[row_id]

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def _wi(
    row_id,
    *,
    url_path: str,
    case_type: str = "unknown",
    status: str = "pending",
    query_params: dict | None = None,
    body_params: dict | None = None,
    path_params: dict | None = None,
    priority_score: int = 0,
    priority_reason: str | None = None,
    cluster_key: str | None = None,
    terminal_reason: str | None = None,
    classifier_version: str | None = None,
    url: str | None = None,
    source: str = "test",
    live_status: str | None = None,
) -> dict:
    """Build a backend work-item row dict carrying every field classify_work reads.

    Param columns are JSON text (the backend's storage shape) so
    `classify_row`'s `collect_keys` decodes them exactly as it does for a real row.
    """
    return {
        "id": row_id,
        "type": case_type,
        "url_path": url_path,
        "query_params": json.dumps(query_params or {}),
        "body_params": json.dumps(body_params or {}),
        "path_params": json.dumps(path_params or {}),
        "status": status,
        "priority_score": priority_score,
        "priority_reason": priority_reason,
        "cluster_key": cluster_key,
        "terminal_reason": terminal_reason,
        "classifier_version": classifier_version,
        "url": url or f"https://target.example{url_path}",
        "source": source,
        "live_status": live_status,
    }


def _classify_env(rows: list[dict]):
    """Return ``(module, fake)`` wired so the reclassify pass runs against a fake
    backend seeded with ``rows``. The ``work-buffer`` wrapper builds the client
    and hands it to the pass, so the fake is passed to ``_reclassify`` directly."""
    fake = _FakeClassifyClient(rows)
    module = _load_classify_module()
    return module, fake


def _run_classify(module, fake, capsys, *extra_args):
    """Invoke the real `work-buffer reclassify` pass once; return
    ``(updates, summary)`` — ``updates`` = the update dicts POSTed this run,
    ``summary`` = the printed JSON summary."""
    extras = list(extra_args)
    fake.last_updates = []
    module._reclassify(
        fake,
        SimpleNamespace(
            engagement_dir="/eng",
            batch=500,
            reclassify_all="--reclassify-all" in extras,
            reclassify_stale="--reclassify-stale" in extras,
            reclaim_skipped="--reclaim-skipped" in extras,
            retype=False,
            retype_all=False,
        ),
    )
    return fake.last_updates, json.loads(capsys.readouterr().out)


# Removed: local cases.db mechanics — db_init/ALTER schema migration,
# db_exec_returning, and db_connect. The work buffer is now the backend
# assessment_work_items ledger; see tests/test_work_buffer_backend.py.


def test_classify_work_assigns_ssrf_bucket() -> None:
    """An ssrf-shaped param (url=) buckets to gf:ssrf. Re-expressed against the
    client-side classifier `classify_from_fields` (classify-work applies exactly
    this per-row assignment; the update/summary mechanics are covered server-side
    in tests/test_work_buffer_backend.py)."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api",
        query_params=json.dumps({"url": "http://evil.example"}),
    )
    assert a["cluster_key"] == "gf:ssrf"
    assert a["priority_score"] >= 40
    assert a["priority_reason"] is not None and "gf:ssrf" in a["priority_reason"]
    assert a["terminal_reason"] is None


def test_upload_rows_prefer_upload_fields_over_generic_lfi() -> None:
    cb = _classify_buckets()
    a = cb.classify_from_fields(
        case_type="upload",
        url_path="/api/users/avatar",
        body_params=json.dumps({"file": "avatar.png"}),
    )
    assert a["cluster_key"] == "gf:upload_fields"
    assert a["priority_score"] == 40
    assert a["priority_reason"] == "gf:lfi+gf:upload_fields"


def test_classify_idor_path_embedded_numeric_id() -> None:
    """A numeric object id in the URL path (no query/body param) buckets as idor."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(case_type="unknown", url_path="/api/users/1024/profile")
    assert a["cluster_key"] == "gf:idor"
    assert a["priority_score"] == 35
    assert a["priority_reason"] is not None and "gf:idor" in a["priority_reason"]
    assert a["terminal_reason"] is None


def test_classify_idor_path_embedded_uuid() -> None:
    """A UUID object id in the URL path buckets as idor."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(
        case_type="unknown",
        url_path="/files/550e8400-e29b-41d4-a716-446655440000",
    )
    assert a["cluster_key"] == "gf:idor"
    assert a["priority_score"] == 35


def test_classify_idor_expanded_param_key_workspace() -> None:
    """A tenant/workspace scoping key (cross-tenant BOLA) buckets as idor."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(
        case_type="unknown",
        url_path="/api/list",
        query_params=json.dumps({"workspace_id": "acme"}),
    )
    assert a["cluster_key"] == "gf:idor"
    assert a["priority_score"] == 35
    assert a["priority_reason"] is not None and "gf:idor" in a["priority_reason"]


def test_classify_non_object_path_is_not_idor() -> None:
    """A static, id-free path stays in the path: fallback — no spurious idor."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(case_type="unknown", url_path="/about/company/history")
    assert a["cluster_key"] == "path:/about/company"
    assert a["priority_score"] == 0
    assert a["priority_reason"] is None


def test_classify_work_deterministic(capsys) -> None:
    module, fake = _classify_env([
        _wi("v:1", url_path="/account/profile", query_params={"id": "42", "url": "http://x"}),
        _wi("v:2", url_path="/admin/debug", query_params={"cmd": "id"}),
    ])

    _, first = _run_classify(module, fake, capsys)
    after_first = {rid: dict(fake.row(rid)) for rid in ("v:1", "v:2")}

    # Re-running with the safe default predicate must NOT touch already-scored
    # rows — otherwise an operator running it as a routine "refresh" would
    # silently overwrite manual triage.
    _, second = _run_classify(module, fake, capsys)
    after_second = {rid: dict(fake.row(rid)) for rid in ("v:1", "v:2")}

    assert after_first == after_second
    assert first["classified"] == 2
    # Default predicate is narrow: scored rows are skipped on re-run.
    assert second["classified"] == 0
    assert second["updated"] == 0

    # --reclassify-all re-applies the bucket table to every pending row (the
    # deliberate path for picking up _BUCKETS edits without resetting) and is
    # deterministic — it reproduces byte-identical assignments.
    _, third = _run_classify(module, fake, capsys, "--reclassify-all")
    after_third = {rid: dict(fake.row(rid)) for rid in ("v:1", "v:2")}
    assert third["classified"] == 2
    assert third["updated"] == 2
    assert after_third == after_first

    # Deprecated --only-unscored alias still behaves as a no-op when every row is
    # already scored (it now lives purely at the argparse layer — run() ignores
    # it — so a bare default pass is the faithful behavior).
    _, fourth = _run_classify(module, fake, capsys, "--only-unscored")
    assert fourth["classified"] == 0
    assert fourth["updated"] == 0


def test_classify_work_ignores_non_pending_consumable_rows(capsys) -> None:
    module, fake = _classify_env([
        _wi("done:rce", url_path="/api/run", status="done", query_params={"cmd": "id"}),
        _wi("pending:rce", url_path="/api/run", status="pending", query_params={"cmd": "id"}),
    ])

    _, summary = _run_classify(module, fake, capsys)

    done = fake.row("done:rce")
    pending = fake.row("pending:rce")
    assert (
        done["status"], done["cluster_key"], done["priority_score"], done["priority_reason"]
    ) == ("done", None, 0, None)
    assert (
        pending["status"], pending["cluster_key"], pending["priority_score"], pending["priority_reason"]
    ) == ("pending", "gf:rce", 50, "gf:rce")
    assert summary["classified"] == 1


def test_classify_work_inert_type_terminates(capsys) -> None:
    cb = _classify_buckets()
    # The client-side classifier terminates inert types: cluster type:<type>,
    # zero priority, terminal_reason 'inert_type'.
    a = cb.classify_from_fields(case_type="image", url_path="/static/logo.png")
    assert a["cluster_key"] == "type:image"
    assert a["priority_score"] == 0
    assert a["terminal_reason"] == "inert_type"
    assert "image" in cb.INERT_TYPES

    # classify-work's DEFAULT pass (no flags) turns that terminal_reason into a
    # status='skipped' write — a CLIENT-SIDE decision in classify_work.run
    # (terminal_reason non-None on a scored row → flip to skipped). Drive the
    # real run over a pending, never-scored inert row and assert the emitted
    # update carries the terminal fields + the skipped-status flip.
    module, fake = _classify_env([
        _wi("img:1", url_path="/static/logo.png", case_type="image", status="pending"),
    ])
    updates, _summary = _run_classify(module, fake, capsys)
    assert len(updates) == 1
    up = updates[0]
    assert up["id"] == "img:1"
    assert up["cluster_key"] == "type:image"
    assert up["priority_score"] == 0
    assert up["terminal_reason"] == "inert_type"
    assert up["status"] == "skipped"
    # And the row reflects the write.
    row = fake.row("img:1")
    assert row["status"] == "skipped"
    assert row["terminal_reason"] == "inert_type"
    assert row["cluster_key"] == "type:image"
    assert row["priority_score"] == 0


def test_classify_work_reclaim_skipped_unstrands_now_non_inert_rows(capsys) -> None:
    module, fake = _classify_env([
        _wi("map:1", url_path="/static/app.js.map", case_type="sourcemap",
            status="skipped", terminal_reason="inert_type", cluster_key="type:sourcemap"),
        _wi("img:1", url_path="/static/logo.png", case_type="image",
            status="skipped", terminal_reason="inert_type"),
    ])

    # Default predicate must NOT touch the stranded (now non-inert) sourcemap row.
    _run_classify(module, fake, capsys)
    assert fake.row("map:1")["status"] == "skipped", "default predicate must not touch the stranded row"

    _, summary = _run_classify(module, fake, capsys, "--reclaim-skipped")
    assert fake.row("map:1")["status"] == "pending"
    assert fake.row("map:1")["terminal_reason"] is None
    assert fake.row("img:1")["status"] == "skipped"
    assert fake.row("img:1")["terminal_reason"] == "inert_type"
    assert summary["reclaimed_to_pending"] == 1


def test_classify_type_marks_archive_extensions_inert() -> None:
    module = _load_classify_lib_module()

    assert module.classify_type("GET", "/backup.zip", "", "") == "archive"
    assert module.classify_type("GET", "/exports/site.tar.gz", "", "") == "archive"


def test_classify_type_marks_sourcemaps_before_generic_data_content_types() -> None:
    module = _load_classify_lib_module()

    assert (
        module.classify_type("GET", "/static/app.js.map", "application/json", "")
        == "sourcemap"
    )
    assert (
        module.classify_type("GET", "/static/app.css.map", "text/plain", "")
        == "sourcemap"
    )


def test_classify_type_bare_host_root() -> None:
    module = _load_classify_lib_module()

    # Bare scheme://host[/] with no path/query/content-type → host_root.
    assert module.classify_type("GET", "/", "", "") == "host_root"
    assert module.classify_type("GET", "", "", "") == "host_root"
    # A query gives param signal → not a bare host_root.
    assert module.classify_type("GET", "/?next=x", "", "") != "host_root"
    # A content-type means we know it's a rendered page, not a bare root.
    assert module.classify_type("GET", "/", "text/html", "") == "page"
    # Real paths are unaffected.
    assert module.classify_type("GET", "/api/users", "", "") == "api"


def test_classify_work_host_root_is_seed_not_skipped() -> None:
    cb = _classify_buckets()
    a = cb.classify_from_fields(case_type="host_root", url_path="/", query_params="{}")
    # Stable, greppable cluster; zero priority; NOT terminal (a Phase-2 crawl seed
    # must stay pending to be crawled — not silently dropped). host_root is not
    # inert, so classify-work keeps it pending.
    assert a["cluster_key"] == "type:host_root"
    assert a["priority_score"] == 0
    assert a["terminal_reason"] is None
    assert "host_root" not in cb.INERT_TYPES


def test_classify_work_path_fallback() -> None:
    cb = _classify_buckets()
    a = cb.classify_from_fields(
        case_type="unknown", url_path="/about/company/history", query_params="{}"
    )
    assert a["cluster_key"] == "path:/about/company"
    assert a["priority_score"] == 0
    assert a["priority_reason"] is None


# Removed: dispatch `fetch-by-priority` auto/agent routing (server-side now —
# tests/test_work_buffer_backend.py::test_fetch_by_priority_claims_top_k_and_routes),
# and the `db_insert_work_item` inline-classification insert (the backend derives
# the work item from a request-observation; see
# tests/test_work_buffer_backend.py::test_observation_derives_one_work_item). The
# unknown→gf:trust_surface bucketing is covered by test_classify_*.py.


# Removed: proxy `_insert_case` → cases.db inserts (shared-inline-classification
# and cached-connection reuse). The proxy no longer writes a local cases.db row;
# it POSTs a request-observation and the backend derives the work item (ADR
# 0013). See tests/test_work_buffer_backend.py::test_observation_derives_one_work_item.
# The proxy's request/response body-truncation policy is still covered directly
# by test_apply_body_policy_flags_truncation below.


def test_apply_body_policy_flags_truncation() -> None:
    """`_apply_body_policy` must surface truncation explicitly so cases.db
    rows never silently misrepresent a partial body as complete. The
    response_snippet path lives directly in `CaseCollector.response` and
    is exercised in the proxy_addon routing tests; this nails the
    request side.
    """
    module = _load_proxy_addon_module()
    collector = module.CaseCollector()
    big = b"x" * (module.BODY_TRUNCATE + 100)
    body, truncated = collector._apply_body_policy(big, "application/json")
    assert truncated is True
    assert body is not None and len(body) == module.BODY_TRUNCATE

    small = b'{"ok":true}'
    body, truncated = collector._apply_body_policy(small, "application/json")
    assert truncated is False
    assert body == small.decode()

    # Binary types and unsaveable content types return (None, False) so
    # the proxy doesn't accidentally label a "we never tried" body as
    # "truncated".
    body, truncated = collector._apply_body_policy(b"\x89PNG", "image/png")
    assert (body, truncated) == (None, False)
    body, truncated = collector._apply_body_policy(b"some bytes", "application/zip")
    assert (body, truncated) == (None, False)


# Removed: proxy `_insert_case` truncation-flag persistence into cases.db (the
# proxy no longer writes a local row — ADR 0013), and the dispatch
# `fetch-by-priority` (vuln-agent / known-agent routing, unroutable-agent
# rejection, skip-terminal) + `defer-cluster` (flip / reject-empty-reason) CLI
# verbs, all of which moved server-side. See
# tests/test_work_buffer_backend.py::{test_fetch_by_priority_claims_top_k_and_routes,
# test_defer_cluster_and_reset_stale_and_retry}.


def _classify_buckets():
    import sys as _sys
    from pathlib import Path as _Path
    scripts = _Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in _sys.path:
        _sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb
    return cb


def test_classify_matched_buckets_single(tmp_path: Path) -> None:
    """S14: classify_from_fields exposes a machine-readable matched_buckets list."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="api",
        url_path="/api/users/1024/profile",
    )
    assert assignment["cluster_key"] == "gf:idor"
    assert assignment["matched_buckets"] == ["idor"]


def test_classify_matched_buckets_multiple(tmp_path: Path) -> None:
    """S14: a URL matching TWO buckets surfaces BOTH in matched_buckets, not just
    the winner — this is what lets the 2b bridge mint two class-typed items."""
    cb = _classify_buckets()
    assignment = cb.classify_from_fields(
        case_type="api",
        url_path="/api/fetch",
        query_params=json.dumps({"id": "10", "url": "http://internal/"}),
    )
    matched = assignment["matched_buckets"]
    assert "idor" in matched
    assert "ssrf" in matched
    cb2 = _import_vuln_taxonomy()
    classes = {cb2.GF_BUCKET_TO_CLASS.get(b) for b in matched}
    assert "idor" in classes
    assert "ssrf" in classes


def _import_vuln_taxonomy():
    import sys as _sys
    from pathlib import Path as _Path
    scripts = _Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in _sys.path:
        _sys.path.insert(0, str(scripts))
    import assess.lib.vuln_taxonomy as vt
    return vt


def _run_ingest_bridge(monkeypatch, tmp_path, lines, *, variant_id=501):
    """Run ingest-endpoints over `lines` with a fake backend, capturing the
    class-typed gf coverage candidates the 2b bridge attaches to each
    request-observation.

    ADR 0013: coverage candidates now ride ON the observation
    (``coverage_candidates``) so the backend links each to the request-variant it
    derives in the same transaction — there is no longer a separate coverage-items
    POST (nor a client-side request_variant_id stamp)."""
    module = _load_script_module(
        "test_ingest_endpoints_bridge",
        "agent/scripts/assess/commands/ingest_endpoints.py",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda flag=None: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(tmp_path),
        ),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda _eng: "anonymous")

    coverage_posts: list[dict] = []

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        def post(self, endpoint, payload):
            if endpoint == "request-observations/bulk":
                records = []
                for item in payload.get("items", []):
                    coverage_posts.extend(item.get("coverage_candidates", []))
                    records.append({"request_variant": {"id": variant_id}, "service": {"id": 9}})
                return {"count": len(records), "records": records}
            if endpoint == "request-observations":
                coverage_posts.extend(payload.get("coverage_candidates", []))
                return {"request_variant": {"id": variant_id}, "service": {"id": 9}}
            return {}

        def close(self):
            pass

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    endpoints_file = tmp_path / "endpoints.txt"
    endpoints_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    module.run(SimpleNamespace(
        source="recon",
        input_file=str(endpoints_file),
        engagement_dir=str(tmp_path),
        egress_blocked_hosts=None,
    ))
    return coverage_posts


def test_ingest_bridges_single_gf_bucket_to_coverage_item(monkeypatch, tmp_path):
    """2b: an endpoint classifying to the idor bucket emits a class-typed
    coverage candidate with attack_family='idor' (additive to the generic
    baseline). The variant linkage is now server-side (the candidate rides on the
    observation, ADR 0013), so we assert on the emitted attack_family/shape rather
    than a client-side request_variant_id."""
    posts = _run_ingest_bridge(
        monkeypatch,
        tmp_path,
        ['{"url": "https://shop.example.com/api/users/1024/profile", "method": "GET"}'],
    )
    families = {p["attack_family"] for p in posts}
    assert "idor" in families
    idor_post = next(p for p in posts if p["attack_family"] == "idor")
    assert idor_post["input_slot"] == "endpoint"
    assert idor_post["status"] == "pending"


def test_ingest_bridges_two_buckets_to_two_coverage_items(monkeypatch, tmp_path):
    """2b/S14: a URL matching TWO gf buckets (idor + ssrf) yields TWO class-typed
    coverage candidates — not just the cluster winner."""
    posts = _run_ingest_bridge(
        monkeypatch,
        tmp_path,
        ['{"url": "https://shop.example.com/api/fetch", "method": "GET", '
         '"query_params": {"id": "10", "url": "http://internal/"}}'],
    )
    families = {p["attack_family"] for p in posts}
    assert "idor" in families
    assert "ssrf" in families


def test_reason_tag_helpers_round_trip():
    cb = _classify_buckets()
    assert cb.tagged_terminal_reason("blackholed", "akamai 403") == "skipped:blackholed | akamai 403"
    assert cb.tagged_terminal_reason("duplicate", "") == "skipped:duplicate"
    assert cb.tagged_terminal_reason("", "plain text") == "plain text"
    assert cb.reason_tag_of("skipped:blackholed | akamai 403") == "blackholed"
    assert cb.reason_tag_of("inert_type") == "inert_type"
    assert cb.reason_tag_of("") == ""
    assert cb.reason_tag_of("egress-blocked: some prose") == "untagged"  # legacy free-text


# Removed: dispatch/list-clusters CLI verbs that operated on the local cases.db
# and have MOVED server-side — defer-cluster reason-tag stamping, stats
# by=reason/host/cluster, list-clusters order/host-filter, peek, and defer-items
# (flip / reject-empty-reason). Covered by
# tests/test_work_buffer_backend.py::{test_defer_cluster_and_reset_stale_and_retry,
# test_fetch_by_type_and_done}. The reason-tag helper round-trip
# (tagged_terminal_reason / reason_tag_of) is still covered directly above by
# test_reason_tag_helpers_round_trip.


# ---------------------------------------------------------------------------
# 1D.2 — per-host URL budget regression coverage
# ---------------------------------------------------------------------------


def _load_classify_lib_module():
    return _load_script_module(
        "test_classify_lib_module",
        "agent/scripts/assess/lib/classify.py",
    )


def _load_ingest_module():
    return _load_script_module(
        "test_ingest_endpoints_module",
        "agent/scripts/assess/commands/ingest_endpoints.py",
    )


# Removed: the `_bulk_insert_for_host` seeder and the `work_items_per_host` VIEW
# tests (aggregate-across-statuses, explicit-port stripping, IPv6-literal). The
# view lived in the deleted per-engagement cases.db schema; per-host rollups are
# now computed by the backend and by `coverage_checks._load_work_items_by_host`
# over the backend ledger (see test_host_root_seed_does_not_block_consumption_gate
# and tests/test_work_buffer_backend.py).


def test_egress_script_logic_handles_dead_hosts_and_empty_input() -> None:
    """B4/B5/B9 regression: the egress reputation bash script

    - drops the ``|| echo 000`` fallback that caused curl-failure to print
      ``"000\\n000"`` and break the comparison;
    - guards against zero alive hosts so the percentage calculation does
      not divide by zero;
    - excludes 000-status hosts from the alive-sample total so dead hosts
      are not counted as blocked.

    We exercise the script in-process by feeding canned curl exit codes
    through a small bash translation of the same logic. This ensures the
    reference doc's script is shape-correct without needing to spawn the
    runtime container.
    """
    import subprocess

    # Faithful translation of the bash conditional in
    # web-recon/SKILL.md and cdn-ip-blocking.md. The harness substitutes
    # codes for the curl call.
    def run(codes: list[str]) -> tuple[int, str]:
        codes_str = " ".join(codes) if codes else ""
        script = f"""
set -e
codes="{codes_str}"
blocked=0; total=0
for code in $codes; do
  case "$code" in
    000) ;;
    403) blocked=$((blocked+1)); total=$((total+1)) ;;
    *)   total=$((total+1)) ;;
  esac
done
if [ "$total" -eq 0 ]; then
  echo "egress check skipped: no live hosts to sample"
  exit 0
fi
pct=$((blocked * 100 / total))
echo "egress_block_pct=$pct (blocked=$blocked alive=$total)"
"""
        proc = subprocess.run(
            ["bash", "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip()

    # All hosts dead — must skip cleanly, no division by zero.
    rc, out = run(["000", "000", "000"])
    assert rc == 0
    assert "egress check skipped" in out

    # Mixed dead/alive — dead excluded; only the 403 counts as blocked.
    rc, out = run(["000", "200", "403"])
    assert rc == 0
    assert "egress_block_pct=50 (blocked=1 alive=2)" in out

    # All 403 against alive hosts — 100% block rate.
    rc, out = run(["403", "403", "403"])
    assert rc == 0
    assert "egress_block_pct=100 (blocked=3 alive=3)" in out

    # Zero hosts (empty input) — must skip cleanly.
    rc, out = run([])
    assert rc == 0
    assert "egress check skipped" in out


# Removed: the client-side `dispatch._stamp_liveness` (stamped live_status onto
# claimed rows in the local cases.db — marks-claimed, best-effort-skip,
# negative-age clamp) and the `vigil assess work-buffer <cases.db> ...` CLI
# drivers (defer-cluster/stats reason-tag wiring, action-specific --help,
# defer-items reason-tag). Both operated on the deleted local cases.db; the verbs
# and liveness stamping now live server-side. See tests/test_work_buffer_backend.py.


def test_host_root_seed_does_not_block_consumption_gate():
    module = _load_script_module(
        "test_scope_cov_module", "agent/scripts/assess/lib/coverage_checks.py"
    )
    # `_load_work_items_by_host` now reads the backend work buffer over a client
    # (was: a local cases.db Path). Serve two rows — a host_root crawl seed and a
    # real api row — each carrying the stored `host` column the rollup groups on.
    rows = [
        {"host": "seed.example.com", "url_path": "/", "type": "host_root",
         "status": "pending", "terminal_reason": None, "cluster_key": "type:host_root"},
        {"host": "real.example.com", "url_path": "/api/x", "type": "api",
         "status": "pending", "terminal_reason": None, "cluster_key": "gf:api"},
    ]

    class _Client:
        def get_all_pages(self, endpoint):
            assert endpoint == "work-items"
            return rows

    by_host = module._load_work_items_by_host(_Client())
    seed = by_host.get("seed.example.com", {})
    real = by_host.get("real.example.com", {})
    assert seed.get("pending", 0) == 1
    assert seed.get("pending_without_terminal_reason", 0) == 0   # seed excluded
    assert real.get("pending_without_terminal_reason", 0) == 1
    assert module._consumption_satisfied(seed, "active") is True     # gate passes for seed-only host
    assert module._consumption_satisfied(real, "active") is False    # still fails for real uncovered work


def test_s13_nested_versioned_api_doc_paths_classify_as_api_spec() -> None:
    """S13: the API-doc classifier must match nested/versioned doc paths, not
    only top-level ones — a missed spec means its whole endpoint inventory is
    never ingested."""
    module = _load_classify_lib_module()
    nested = [
        "/api/swagger.json",
        "/v2/openapi.json",
        "/docs/openapi.json",
        "/docs/swagger.yaml",
        "/api/v1/api-docs",
    ]
    for path in nested:
        assert module.classify_type("GET", path, "", "") == "api-spec", path
    assert module.classify_type("GET", "/openapi.json", "", "") == "api-spec"
    assert module.classify_type("GET", "/swagger-ui.html", "", "") == "api-spec"
    assert module.classify_type("GET", "/myopenapi", "", "") != "api-spec"
    assert module.classify_type("GET", "/swaggerings/x", "", "") != "api-spec"


def test_s15_sourcemap_not_in_inert_set() -> None:
    """S15: sourcemap is no longer terminally inert. (The former db._SKIP_TYPES
    mirror check is gone with agent/scripts/assess/lib/db.py — INERT_TYPES is the
    single source of truth now.)"""
    cb = _classify_buckets()
    assert "sourcemap" not in cb.INERT_TYPES


def test_s15_sourcemap_classifies_to_secret_surface_not_inert() -> None:
    """S15: a sourcemap row classifies to a real, non-inert secret/JS surface
    that downstream analysis can act on (kept pending, no inert terminal_reason)."""
    cb = _classify_buckets()
    a = cb.classify_from_fields(case_type="sourcemap", url_path="/static/app.js.map")
    assert a["cluster_key"] == "gf:interestingext"
    assert a["priority_score"] > 0
    assert a["priority_reason"] == "gf:interestingext"
    assert a["terminal_reason"] is None
    # No inert terminal_reason + not in INERT_TYPES → classify-work keeps it pending.
    assert "sourcemap" not in cb.INERT_TYPES


def test_s20_admin_fragment_is_segment_anchored_not_substring() -> None:
    """S20: `/administration-guide` must NOT match the `/admin` risk fragment,
    while `/admin` and `/admin/...` still do."""
    cb = _classify_buckets()
    assert cb.fragment_in_path("/admin", "/administration-guide") is False
    assert cb.fragment_in_path("/admin", "/admin") is True
    assert cb.fragment_in_path("/admin", "/admin/users") is True
    assert cb.fragment_in_path("/admin", "/v1/admin?x=1") is True
    assert cb.fragment_in_path(".env", "/.environment") is False
    assert cb.fragment_in_path(".env", "/app/.env") is True
    assert cb.fragment_in_path(".config", "/app.configuration") is False
    assert cb.fragment_in_path("/proxy/", "/proxy/fetch") is True
    assert cb.fragment_in_path("/proxy/", "/proxyfoo") is False


def test_s20_administration_guide_does_not_bucket_as_debug_logic() -> None:
    """End-to-end S20: a `/administration-guide` doc page no longer falls into
    the `/admin` (debug_logic) bucket — it lands in the path fallback."""
    cb = _classify_buckets()
    guide = cb.classify_from_fields(
        case_type="unknown", url_path="/administration-guide/getting-started"
    )
    real = cb.classify_from_fields(case_type="unknown", url_path="/admin/users")
    assert not str(guide["cluster_key"]).startswith("gf:")
    assert real["cluster_key"] == "gf:debug_logic"


def test_s12_ingest_endpoints_admits_ip_localhost_ipv6_and_skips_malformed(
    monkeypatch, tmp_path: Path, capsys
) -> None:
    """S12: IP / localhost / bracketed-IPv6 endpoint lines now ingest (they used
    to pass through schemeless and fail the POST), template/fuzz lines WARN
    instead of dropping silently, and a genuinely malformed line is skipped with
    a WARN rather than failing the POST."""
    module = _load_ingest_module()
    engagement_dir = tmp_path / "engagement"
    engagement_dir.mkdir()
    (engagement_dir / "scope.json").write_text("{}", encoding="utf-8")

    input_file = tmp_path / "endpoints.txt"
    input_file.write_text(
        "\n".join(
            [
                "10.0.0.5/admin",
                "127.0.0.1:8080/api/login",
                "localhost/dashboard",
                "[::1]:8080/health",
                "https://app.example.com/x",
                "/relative/only",
                "GET FUZZ/path",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        module,
        "load_config",
        lambda engagement_dir=None: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng",
            engagement_dir=str(engagement_dir),
        ),
    )
    monkeypatch.setattr(module, "auth_active_context", lambda _eng_dir: "anonymous")

    posted_hosts: list[str] = []

    class FakeClient:
        def __init__(self, *a, **k) -> None:
            pass

        def post(self, endpoint, payload):
            if endpoint == "request-observations/bulk":
                records = []
                for item in payload.get("items", []):
                    posted_hosts.append(item.get("target_hostname"))
                    records.append({"request_variant": {"id": 100 + len(posted_hosts)}})
                return {"count": len(records), "records": records}
            posted_hosts.append(payload.get("target_hostname"))
            return {"request_variant": {"id": 100 + len(posted_hosts)}}

        def close(self) -> None:
            return None

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(module, "AssessmentClient", FakeClient)

    module.run(
        SimpleNamespace(
            source="recon",
            input_file=str(input_file),
            engagement_dir=str(engagement_dir),
            egress_blocked_hosts=None,
        )
    )

    captured = capsys.readouterr()
    assert "10.0.0.5" in posted_hosts
    assert "127.0.0.1" in posted_hosts
    assert "localhost" in posted_hosts
    assert "::1" in posted_hosts
    assert "app.example.com" in posted_hosts

    # Was: SELECT COUNT(*) FROM work_items == 5. The backend now derives the work
    # item from each observation (ADR 0013 — no local cases.db), so assert on the
    # number of observations the ingest POSTed. See tests/test_work_buffer_backend.py.
    assert len(posted_hosts) == 5

    assert "malformed endpoint line" in captured.err
    assert "template/fuzz-marker" in captured.err
    assert "Skipped" in captured.err


# --------------------------------------------------------------------------- #
# P1-D — reclassification staleness (classifier_version stamp + --reclassify-stale)
# --------------------------------------------------------------------------- #


def test_classifier_version_deterministic_across_pythonhashseed() -> None:
    """CRITICAL (review HIGH-1): CLASSIFIER_VERSION must be identical across
    processes with different PYTHONHASHSEED. If it were PYTHONHASHSEED-randomized
    (the `repr(frozenset)` / builtin-`hash()` trap), the ingest process and the
    `--reclassify-stale` process would compute different digests and EVERY row
    would look stale on every run. We compute it in two subprocesses under
    different seeds and assert equality (and that it is not accidentally empty).
    """
    import os
    import subprocess

    scripts_root = _scripts_root()
    snippet = "import assess.lib.classify_buckets as cb; print(cb.CLASSIFIER_VERSION)"

    def _compute(seed: str) -> str:
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = seed
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = (
            f"{scripts_root}{os.pathsep}{existing}" if existing else str(scripts_root)
        )
        out = subprocess.check_output(
            [sys.executable, "-c", snippet], env=env, text=True
        )
        return out.strip()

    v_a = _compute("0")
    v_b = _compute("1")
    v_c = _compute("987654321")
    assert v_a and len(v_a) == 12
    assert v_a == v_b == v_c, f"non-deterministic: {v_a!r} {v_b!r} {v_c!r}"


def test_classifier_version_inputs_cover_every_classification_constant() -> None:
    """Completeness guard (review MED): CLASSIFIER_VERSION must digest EVERY
    classification-affecting module-level constant, not just the four headline
    tables. If a taxonomy constant is missing from the input set, editing it does
    NOT bump the digest and `--reclassify-stale` silently misses the rows it
    changes. This pins the exact set so adding a new classification constant
    without wiring it into the digest fails here (and forces a `.pattern` string
    for any regex, since a bare Pattern is not JSON-serializable)."""
    import json

    import assess.lib.classify_buckets as cb

    inputs = cb._CLASSIFIER_VERSION_INPUTS

    # The digest input must stay JSON-serializable after canonicalization (a
    # stray compiled Pattern would crash `json.dumps` here).
    json.dumps(cb._canonicalize(inputs), sort_keys=True)

    # Every classification-affecting constant `classify_row`/`_context_bonus`/the
    # path predicates read is digested. Regexes are digested by `.pattern`.
    assert inputs["buckets"] is cb._BUCKETS
    assert inputs["regex_bucket_rules"] is cb._REGEX_BUCKET_RULES
    assert inputs["type_floor"] is cb._TYPE_FLOOR
    assert inputs["inert_types"] is cb.INERT_TYPES
    assert inputs["privileged_action_verbs"] is cb._PRIVILEGED_ACTION_VERBS
    assert inputs["full_url_regex_buckets"] is cb._FULL_URL_REGEX_BUCKETS
    assert inputs["auth_saml_fragments"] is cb._AUTH_SAML_FRAGMENTS
    assert inputs["upload_generic_shadows"] is cb._UPLOAD_GENERIC_SHADOWS
    assert inputs["placeholder_tokens"] is cb._PLACEHOLDER_TOKENS
    assert inputs["cluster_placeholders"] is cb._CLUSTER_PLACEHOLDERS
    assert inputs["uuid_re"] == cb._UUID_RE.pattern
    assert inputs["long_hex_re"] == cb._LONG_HEX_RE.pattern
    assert inputs["year_re"] == cb._YEAR_RE.pattern
    assert inputs["numeric_re"] == cb._NUMERIC_RE.pattern
    assert inputs["opaque_token_re"] == cb._OPAQUE_TOKEN_RE.pattern
    assert inputs["api_version_seg_re"] == cb._API_VERSION_SEG_RE.pattern
    assert inputs["weak_token_cap"] == cb.WEAK_TOKEN_CAP
    assert inputs["camel_boundary_re"] == cb._CAMEL_BOUNDARY_RE.pattern
    assert inputs["fragment_boundary"] == cb._FRAGMENT_BOUNDARY
    assert inputs["nonprod_host_label_re"] == cb._NONPROD_HOST_LABEL_RE.pattern
    assert inputs["nondefault_ports"] is cb._NONDEFAULT_PORTS
    assert inputs["live_status_tokens"] is cb._LIVE_STATUS_TOKENS
    assert inputs["gau_archive_source"] == cb._GAU_ARCHIVE_SOURCE
    assert inputs["dead_live_status_tokens"] is cb._DEAD_LIVE_STATUS_TOKENS
    assert inputs["logic_revision"] == cb._CLASSIFIER_LOGIC_REVISION


def test_classifier_version_tracks_logic_revision_and_tables() -> None:
    """A bump to `_CLASSIFIER_LOGIC_REVISION` (the escape hatch for pure-logic
    edits) OR to any digested taxonomy table must change CLASSIFIER_VERSION. We
    recompute the digest over a mutated copy of the inputs and assert it moves,
    proving both the logic-revision hatch and a representative context/demotion
    table actually feed the stamp."""
    import hashlib
    import json

    import assess.lib.classify_buckets as cb

    def _digest(inputs: dict) -> str:
        return hashlib.sha256(
            json.dumps(cb._canonicalize(inputs), sort_keys=True).encode("utf-8")
        ).hexdigest()[:12]

    base = dict(cb._CLASSIFIER_VERSION_INPUTS)
    assert _digest(base) == cb.CLASSIFIER_VERSION

    bumped_logic = dict(base)
    bumped_logic["logic_revision"] = base["logic_revision"] + 1
    assert _digest(bumped_logic) != cb.CLASSIFIER_VERSION

    # A representative previously-undigested table now moves the stamp too.
    changed_ports = dict(base)
    changed_ports["nondefault_ports"] = frozenset(base["nondefault_ports"] | {"9999"})
    assert _digest(changed_ports) != cb.CLASSIFIER_VERSION


# Removed: test_classifier_version_stamped_on_inline_insert — the
# db_insert_work_item inline stamp is gone (the backend stamps
# classifier_version when it derives the work item from an observation, ADR
# 0013). See tests/test_work_buffer_backend.py. The deterministic-digest
# contract for CLASSIFIER_VERSION is still covered above by the three
# test_classifier_version_* tests.


def test_classify_work_default_stamps_classifier_version(capsys) -> None:
    """The default classify-work pass stamps CLASSIFIER_VERSION on never-scored
    rows (and surfaces it + a from_version histogram in the JSON summary)."""
    cb = _classify_buckets()
    module, fake = _classify_env([
        _wi("v:1", url_path="/exec/run", query_params={"cmd": "id"}),
    ])
    _, summary = _run_classify(module, fake, capsys)
    assert summary["classifier_version"] == cb.CLASSIFIER_VERSION
    # The one never-scored row came from an unstamped (NULL) state.
    assert summary["from_version"] == {"none": 1}
    assert fake.row("v:1")["classifier_version"] == cb.CLASSIFIER_VERSION


def test_reclassify_stale_restamps_only_stale_rows(capsys) -> None:
    """--reclassify-stale restamps NULL + old-version rows (re-scoring them from
    the current bucket table) while leaving current-version and 'manual' rows
    untouched. --reclassify-all then proves it DOES touch the 'manual' row."""
    cb = _classify_buckets()
    current = cb.CLASSIFIER_VERSION
    manual = cb.MANUAL_CLASSIFIER_VERSION
    module, fake = _classify_env([
        # A: legacy NULL version, scored under an "old" bucket table.
        _wi("A:null", url_path="/exec/run", query_params={"cmd": "id"},
            priority_score=11, cluster_key="gf:oldbucket", classifier_version=None),
        # B: an explicit old (non-current) version.
        _wi("B:old", url_path="/exec/run", query_params={"cmd": "id"},
            priority_score=11, cluster_key="gf:oldbucket", classifier_version="oldversion01"),
        # C: already at the current version — must be left alone.
        _wi("C:current", url_path="/exec/run", query_params={"cmd": "id"},
            priority_score=50, cluster_key="gf:rce", classifier_version=current),
        # D: hand-tuned 'manual' row — protected from --reclassify-stale.
        _wi("D:manual", url_path="/exec/run", query_params={"cmd": "id"},
            priority_score=77, cluster_key="gf:custom-manual", classifier_version=manual),
    ])

    def _snap(rid):
        r = fake.row(rid)
        return (r["cluster_key"], r["priority_score"], r["classifier_version"])

    before = {rid: _snap(rid) for rid in ("A:null", "B:old", "C:current", "D:manual")}

    _, summary = _run_classify(module, fake, capsys, "--reclassify-stale")

    # A + B were stale → re-scored to the current bucket (gf:rce/50) and stamped.
    assert _snap("A:null") == ("gf:rce", 50, current)
    assert _snap("B:old") == ("gf:rce", 50, current)
    # C (current) and D (manual) are byte-identical to before.
    assert _snap("C:current") == before["C:current"]
    assert _snap("D:manual") == before["D:manual"]
    assert _snap("D:manual")[2] == manual

    # Only the two stale rows were touched.
    assert summary["updated"] == 2
    assert summary["classified"] == 2
    assert summary["from_version"] == {"none": 1, "oldversion01": 1}

    # --reclassify-all IS the nuclear option: it re-scores the 'manual' row too.
    _run_classify(module, fake, capsys, "--reclassify-all")
    assert _snap("D:manual") == ("gf:rce", 50, current)


def test_reclassify_stale_is_idempotent(capsys) -> None:
    """A second --reclassify-stale run reports 0 updates: after the first pass
    every touched row carries the current version, so nothing is stale."""
    module, fake = _classify_env([
        _wi("A:null", url_path="/exec/run", query_params={"cmd": "id"}, classifier_version=None),
        _wi("B:old", url_path="/proxy/x", query_params={"url": "http://evil"}, classifier_version="oldversion01"),
    ])

    _, first = _run_classify(module, fake, capsys, "--reclassify-stale")
    assert first["updated"] == 2

    _, second = _run_classify(module, fake, capsys, "--reclassify-stale")
    assert second["classified"] == 0
    assert second["updated"] == 0
    assert second["from_version"] == {}


# Removed: test_classifier_version_migration_adds_column_without_data_loss
# (db_init ALTER migration on the deleted local cases.db) and
# test_stats_by_classifier_version (`work-buffer stats --by classifier_version`
# CLI-over-cases.db — moved server-side). See tests/test_work_buffer_backend.py.


def test_mark_manual_protects_row_from_reclassify_stale(capsys) -> None:
    """A row stamped classifier_version='manual' (what `work-buffer mark-manual`
    writes, now a backend verb) survives a --reclassify-stale run untouched. We
    re-express the PROTECTION intent: the client-side reclassify predicate must
    skip a 'manual' row. (The mark-manual write itself is covered server-side —
    tests/test_work_buffer_backend.py::test_manual_rows_protected_on_reingest.)"""
    cb = _classify_buckets()
    module, fake = _classify_env([
        _wi("hand:1", url_path="/exec/run", query_params={"cmd": "id"},
            priority_score=90, cluster_key="gf:hand-tuned",
            classifier_version=cb.MANUAL_CLASSIFIER_VERSION),
    ])

    updates, summary = _run_classify(module, fake, capsys, "--reclassify-stale")

    # The hand-tuned 'manual' row is neither re-scored nor re-stamped.
    assert updates == []
    assert summary["classified"] == 0
    row = fake.row("hand:1")
    assert (row["priority_score"], row["cluster_key"], row["classifier_version"]) == (
        90, "gf:hand-tuned", cb.MANUAL_CLASSIFIER_VERSION,
    )
