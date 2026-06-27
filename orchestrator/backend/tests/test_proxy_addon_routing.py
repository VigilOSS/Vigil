"""Routing-layer tests for the multi-engagement mitmproxy addon.

The addon's job is to: (a) discover the set of active engagements, (b) pick the
right one per captured response, and (c) route auth.json writes, cases.db
inserts, and orchestrator POSTs to that engagement and nothing else.

Each test loads ``agent/scripts/proxy_addon.py`` with a stubbed ``mitmproxy``
module — no real proxy is started.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _load_proxy_addon_module():
    import importlib.util

    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))

    mitmproxy = ModuleType("mitmproxy")
    http = ModuleType("mitmproxy.http")
    http.HTTPFlow = object  # type: ignore[attr-defined]
    mitmproxy.http = http  # type: ignore[attr-defined]
    mitmproxy.ctx = SimpleNamespace(
        log=SimpleNamespace(
            info=lambda *_a, **_k: None,
            warn=lambda *_a, **_k: None,
            error=lambda *_a, **_k: None,
        ),
        options=SimpleNamespace(
            engagements_root="", engagement_dir="", registry_poll_seconds=30
        ),
    )
    sys.modules.setdefault("mitmproxy", mitmproxy)
    sys.modules.setdefault("mitmproxy.http", http)

    module_path = Path(__file__).resolve().parents[3] / "agent" / "scripts" / "proxy_addon.py"
    spec = importlib.util.spec_from_file_location("test_proxy_addon_module_routing", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _seed_engagement(
    engagements_root: Path,
    key: str,
    *,
    hosts: list[str],
    scope_priority: int = 0,
    out_of_scope: list[str] | None = None,
) -> Path:
    engagement_dir = engagements_root / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    scope: dict = {"hosts": hosts}
    if scope_priority:
        scope["scope_priority"] = scope_priority
    if out_of_scope:
        scope["out_of_scope"] = out_of_scope
    (engagement_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    return engagement_dir


# ---------------------------------------------------------------------------
# Filesystem registry + matching
# ---------------------------------------------------------------------------


def test_registry_scans_each_engagement_scope_json(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"])
    _seed_engagement(root, "eng-b", hosts=["b.example", "*.b.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert set(collector.registry) == {"eng-a", "eng-b"}
    assert collector.registry["eng-b"].scope_patterns == ["b.example", "*.b.example"]


def test_match_routes_to_disjoint_engagement_scopes(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"])
    _seed_engagement(root, "eng-b", hosts=["b.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    a = collector._match_engagement("a.example")
    b = collector._match_engagement("b.example")
    assert a is not None and a.key == "eng-a"
    assert b is not None and b.key == "eng-b"
    assert collector._match_engagement("c.example") is None


def test_match_drops_out_of_scope_carve_out_under_wildcard(tmp_path: Path) -> None:
    """An OOS host under an in-scope wildcard must not be captured/routed.

    ``*.acme-regional.example`` is in scope but ``appointments.acme-regional.example`` is an
    explicit out_of_scope carve-out — the denylist wins and the flow is dropped.
    """
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-acme-regional",
        hosts=["*.acme-regional.example"],
        out_of_scope=["appointments.acme-regional.example"],
    )

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector.registry["eng-acme-regional"].out_of_scope_patterns == [
        "appointments.acme-regional.example"
    ]

    chosen = collector._match_engagement("app.acme-regional.example")
    assert chosen is not None and chosen.key == "eng-acme-regional"
    # The carve-out is dropped even though the in-scope wildcard would match it.
    assert collector._match_engagement("appointments.acme-regional.example") is None


def test_match_prefers_literal_over_wildcard(tmp_path: Path) -> None:
    """When engagement A holds the wildcard ``*.example.com`` and B owns the
    literal ``admin.example.com``, a request to admin must route to B even
    though A's wildcard matches too.
    """
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-broad", hosts=["*.example.com"])
    _seed_engagement(root, "eng-focused", hosts=["admin.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    chosen = collector._match_engagement("admin.example.com")
    assert chosen is not None and chosen.key == "eng-focused"
    # Non-admin subdomain still routes to the wildcard owner.
    chosen = collector._match_engagement("api.example.com")
    assert chosen is not None and chosen.key == "eng-broad"


def test_match_prefers_narrower_wildcard(tmp_path: Path) -> None:
    """``*.admin.example.com`` is narrower than ``*.example.com`` and wins."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-broad", hosts=["*.example.com"])
    _seed_engagement(root, "eng-admin", hosts=["*.admin.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    chosen = collector._match_engagement("portal.admin.example.com")
    assert chosen is not None and chosen.key == "eng-admin"


def test_match_uses_scope_priority_for_ties(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-low", hosts=["host.example.com"], scope_priority=1)
    _seed_engagement(root, "eng-high", hosts=["host.example.com"], scope_priority=10)

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    chosen = collector._match_engagement("host.example.com")
    assert chosen is not None and chosen.key == "eng-high"


def test_no_match_returns_none(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector._match_engagement("nope.example") is None
    assert collector._match_engagement("") is None


# ---------------------------------------------------------------------------
# Hot reload behavior
# ---------------------------------------------------------------------------


def test_registry_picks_up_engagement_added_after_initial_load(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    assert set(collector.registry) == {"eng-a"}

    # Operator creates a new engagement after the proxy was already running.
    _seed_engagement(root, "eng-b", hosts=["b.example"])
    collector._reload_registry(force=True)
    assert set(collector.registry) == {"eng-a", "eng-b"}
    chosen = collector._match_engagement("b.example")
    assert chosen is not None and chosen.key == "eng-b"


def test_registry_drops_engagement_that_vanished(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"])
    _seed_engagement(root, "eng-b", hosts=["b.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    assert set(collector.registry) == {"eng-a", "eng-b"}

    # Engagement directory removed (archived, renamed, etc.).
    import shutil

    shutil.rmtree(root / "eng-b")
    collector._reload_registry(force=True)
    assert set(collector.registry) == {"eng-a"}


def test_routes_cache_is_written_after_reload(tmp_path: Path) -> None:
    """`vigil mitmproxy routes` reads this cache; reload must keep it fresh."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example"], scope_priority=3)

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    cache_path = root / module.ROUTES_CACHE
    assert cache_path.is_file()
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    rows = {row["key"]: row for row in payload["engagements"]}
    assert "eng-a" in rows
    assert rows["eng-a"]["scope_patterns"] == ["a.example"]
    assert rows["eng-a"]["scope_priority"] == 3


# ---------------------------------------------------------------------------
# Per-engagement auth.json writes
# ---------------------------------------------------------------------------


class _FakeHttpResponse:
    def __init__(self, status_code: int, headers: dict[str, str], body: bytes):
        self.status_code = status_code
        self.headers = _FakeHeaders(headers)
        self._body = body

    def get_content(self):
        return self._body


class _FakeHeaders:
    def __init__(self, items: dict[str, str]):
        # Headers are normalized lower-case keys to mimic mitmproxy.
        self._items = {k.lower(): v for k, v in items.items()}

    def get(self, key: str, default: str = "") -> str:
        return self._items.get(key.lower(), default)

    def get_all(self, key: str) -> list[str]:
        value = self._items.get(key.lower())
        return [value] if value else []


class _FakeRequest:
    def __init__(
        self,
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ):
        self.pretty_url = url
        self.method = method
        self.headers = _FakeHeaders(headers or {})
        self.cookies = cookies or {}

    def get_content(self):
        return b""


class _FakeFlow:
    def __init__(self, request: _FakeRequest, response: _FakeHttpResponse):
        self.request = request
        self.response = response


def _record_captures(collector):
    """Patch _post_credentials_capture to record (engagement_key, kwargs) calls.

    The cookie/header merge now lives server-side (see test_credentials_api.py);
    these addon tests verify the captured delta and engagement targeting only.
    """
    calls: list[tuple[str, dict]] = []
    collector._post_credentials_capture = (
        lambda entry, **kw: calls.append((entry.key, kw))
    )
    return calls


def test_capture_auth_posts_to_matched_engagement_only(tmp_path: Path) -> None:
    """Capture for engagement A must post only for A, with the right delta."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    _seed_engagement(root, "eng-b", hosts=["b.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)

    entry_a = collector._match_engagement("a.example.com")
    assert entry_a is not None

    request = _FakeRequest(
        url="https://a.example.com/login",
        method="POST",
        cookies={"session": "abc123"},
    )
    response = _FakeHttpResponse(
        status_code=200,
        headers={"set-cookie": "csrf=xyz; Path=/; HttpOnly"},
        body=b"{}",
    )
    collector._capture_auth(entry_a, _FakeFlow(request, response))

    assert len(calls) == 1
    key, kw = calls[0]
    assert key == "eng-a"
    assert kw["host"] == "a.example.com"
    assert kw["scope_host"] == "a.example.com"
    # Request cookies + Set-Cookie merged into the posted delta.
    assert kw["cookies"] == {"session": "abc123", "csrf": "xyz"}


def test_capture_auth_extracts_bearer_token_from_login_response(tmp_path: Path) -> None:
    """A login JSON response with a token yields an Authorization header + token
    in the posted capture delta."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")
    assert entry is not None

    request = _FakeRequest(url="https://a.example.com/login", method="POST")
    response = _FakeHttpResponse(
        status_code=200,
        headers={},
        body=b'{"access_token": "tok123"}',
    )
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["tokens"] == {"access_token": "tok123"}
    assert kw["headers"]["Authorization"] == "Bearer tok123"


def test_capture_auth_skips_post_when_nothing_captured(tmp_path: Path) -> None:
    """No cookies, no token -> no backend call."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")
    assert entry is not None

    request = _FakeRequest(url="https://a.example.com/page", method="GET")
    response = _FakeHttpResponse(status_code=200, headers={}, body=b"")
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert calls == []


# ---------------------------------------------------------------------------
# Backend registry fetch
# ---------------------------------------------------------------------------


def test_backend_registry_response_seeds_entries(tmp_path: Path, monkeypatch) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    (root / "eng-from-backend").mkdir(parents=True)

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"

    payload = [
        {
            "key": "eng-from-backend",
            "engagement_root": "/install/agent/engagements/eng-from-backend",
            "scope_hosts": ["api.example.com", "*.example.com"],
            "scope_priority": 7,
            "updated_at": "2026-05-18T10:00:00Z",
        }
    ]

    class _Response:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def read(self) -> bytes:
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *_exc) -> None:
            return None

    def fake_urlopen(request, timeout=5):
        assert request.full_url == "http://orchestrator.test/engagements?status=in_progress"
        return _Response(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    entries = collector._fetch_registry_from_backend()
    assert entries is not None
    assert len(entries) == 1
    entry = entries[0]
    assert entry.key == "eng-from-backend"
    # Backend paths are install-host paths; the addon resolves the container
    # path via engagements_root + key so the bind-mount stays portable.
    assert entry.root == root / "eng-from-backend"
    assert entry.scope_patterns == ["api.example.com", "*.example.com"]
    assert entry.scope_priority == 7


def test_backend_unreachable_falls_back_to_filesystem_scan(tmp_path: Path, monkeypatch) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-fs", hosts=["fs.example"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"

    def fake_urlopen(*_args, **_kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    collector._reload_registry(force=True)
    assert "eng-fs" in collector.registry


def test_filesystem_fallback_skips_non_in_progress_engagements(tmp_path: Path) -> None:
    """When the backend is unreachable, the filesystem scan must mirror the
    backend's `?status=in_progress` filter — archived/completed engagements
    re-entering routing would steal captures from active engagements with
    overlapping scope.
    """
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    active = _seed_engagement(root, "eng-active", hosts=["target.example"])
    archived = _seed_engagement(root, "eng-archived", hosts=["target.example"])
    # Tag scope.json status explicitly. Active stays default (treated as
    # in_progress); archived flips to "archived".
    active_scope = json.loads((active / "scope.json").read_text())
    active_scope["status"] = "in_progress"
    (active / "scope.json").write_text(json.dumps(active_scope), encoding="utf-8")
    archived_scope = json.loads((archived / "scope.json").read_text())
    archived_scope["status"] = "archived"
    (archived / "scope.json").write_text(json.dumps(archived_scope), encoding="utf-8")

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # Active routes; archived is filtered out.
    assert "eng-active" in collector.registry
    assert "eng-archived" not in collector.registry


def test_backend_registry_skips_rows_whose_root_is_missing(
    tmp_path: Path, monkeypatch
) -> None:
    """A stale backend row pointing at a directory that no longer exists must
    be skipped at registry-build time so `_open_db_for` never hits
    `FileNotFoundError` on `db_path.touch()` and crashes the flow hook.
    """
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    # Only one of the two engagements has an on-disk directory.
    _seed_engagement(root, "eng-present", hosts=["present.example"])

    class FakeResponse:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self) -> bytes:
            return self._body

    def fake_urlopen(*_args, **_kwargs):
        payload = [
            {
                "key": "eng-present",
                "scope_hosts": ["present.example"],
                "scope_priority": 0,
                "updated_at": "2026-05-19T12:00:00Z",
            },
            {
                "key": "eng-ghost",  # directory does not exist on disk
                "scope_hosts": ["ghost.example"],
                "scope_priority": 0,
                "updated_at": "2026-05-19T12:00:00Z",
            },
        ]
        return FakeResponse(json.dumps(payload).encode("utf-8"))

    monkeypatch.setattr(module, "urlopen", fake_urlopen)

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"
    collector._reload_registry(force=True)

    assert "eng-present" in collector.registry
    assert "eng-ghost" not in collector.registry


# ---------------------------------------------------------------------------
# DB insert: stale-connection detection and recovery
# ---------------------------------------------------------------------------


def _make_entry(module, engagements_root: Path, key: str):
    """Build a registry EngagementEntry with an initialized cases.db."""
    engagement_dir = engagements_root / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    return module.EngagementEntry(
        key=key,
        root=engagement_dir,
        scope_patterns=["x.example"],
        scope_priority=0,
    )


def _insert_one(module, collector, entry, *, queue_key: str) -> None:
    collector._insert_case(
        entry,
        queue_key=queue_key,
        request_variant_id=1,
        service_id=1,
        auth_context="unauthenticated",
        method="GET",
        url=f"https://x.example/{queue_key}",
        url_path=f"/{queue_key}",
        params={
            "query_params": "{}",
            "body_params": "{}",
            "path_params": "{}",
            "cookie_params": "{}",
        },
        headers="{}",
        body=None,
        content_type="text/html",
        content_length=0,
        request_body_truncated=False,
        response_status=200,
        response_headers="{}",
        response_size=0,
        response_snippet=None,
        response_truncated=False,
        case_type="page",
        params_key_sig="sig",
    )


def test_insert_case_persists_through_healthy_connection(tmp_path: Path) -> None:
    import sqlite3

    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir(parents=True, exist_ok=True)
    collector = module.CaseCollector()
    collector.engagements_root = root
    entry = _make_entry(module, root, "eng-a")

    _insert_one(module, collector, entry, queue_key="variant:1:page")
    healthy_conn = entry.db

    db_path = entry.root / "cases.db"
    rows = (
        sqlite3.connect(str(db_path))
        .execute("SELECT queue_key FROM work_items")
        .fetchall()
    )
    assert ("variant:1:page",) in rows
    # No spurious reconnect: the original cached connection is reused as-is.
    assert entry.db is healthy_conn
    assert entry.db is not None


def test_insert_case_recovers_from_connection_invisible_to_readers(
    tmp_path: Path,
) -> None:
    """Reproduce the production failure mode without mocking the probe.

    The cached connection is a *real* sqlite3.Connection whose commits succeed
    and whose own SELECTs see the row — but it is bound to a detached database
    file, so its writes never reach the canonical cases.db that independent
    readers (backend, CLI) open. This is the inode-replacement / external
    rebuild scenario from the incident.

    A read-back on the writing connection would see the detached row and wrongly
    report success; only the fresh-connection probe in _row_persisted detects
    that the write is invisible to other readers and triggers recovery.
    """
    import sqlite3

    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir(parents=True, exist_ok=True)
    collector = module.CaseCollector()
    collector.engagements_root = root
    entry = _make_entry(module, root, "eng-a")

    # Establish the canonical cases.db (schema initialized) that readers see.
    _insert_one(module, collector, entry, queue_key="variant:1:page")
    canonical = entry.root / "cases.db"
    assert canonical.exists()

    # Swap in a real connection bound to a detached DB with the same schema.
    detached = entry.root / "detached.db"
    detached.touch()
    module.db_init(str(detached))
    stale = sqlite3.connect(str(detached), check_same_thread=False)
    entry.db.close()
    entry.db = stale

    _insert_one(module, collector, entry, queue_key="variant:2:page")

    # Recovery happened: the stale connection was dropped and replaced.
    assert entry.db is not stale
    assert isinstance(entry.db, sqlite3.Connection)

    # The row landed in the canonical file where independent readers see it.
    canonical_rows = (
        sqlite3.connect(str(canonical))
        .execute(
            "SELECT queue_key FROM work_items WHERE queue_key = ?",
            ("variant:2:page",),
        )
        .fetchall()
    )
    assert canonical_rows == [("variant:2:page",)]

    # The stale connection genuinely committed (no error) — it just wrote to the
    # wrong file. This proves the failure was invisibility, not a write error,
    # so the same-connection read-back probe would have been fooled.
    orphan_rows = (
        sqlite3.connect(str(detached))
        .execute(
            "SELECT queue_key FROM work_items WHERE queue_key = ?",
            ("variant:2:page",),
        )
        .fetchall()
    )
    assert orphan_rows == [("variant:2:page",)]
