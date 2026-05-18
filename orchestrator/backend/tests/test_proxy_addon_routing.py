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
import threading
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
) -> Path:
    engagement_dir = engagements_root / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    scope = {"hosts": hosts}
    if scope_priority:
        scope["scope_priority"] = scope_priority
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
    """`aith mitmproxy routes` reads this cache; reload must keep it fresh."""
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


def test_capture_auth_writes_to_matched_engagement_only(tmp_path: Path) -> None:
    """Capture for engagement A must not touch engagement B's auth.json."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    _seed_engagement(root, "eng-b", hosts=["b.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

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

    auth_a = json.loads((root / "eng-a" / "auth.json").read_text(encoding="utf-8"))
    assert auth_a["cookies"] == {"session": "abc123", "csrf": "xyz"}
    assert auth_a["state"] == "available"
    # auth.json for eng-b never written.
    assert not (root / "eng-b" / "auth.json").exists()


def test_capture_auth_lock_serializes_same_engagement_writes(tmp_path: Path) -> None:
    """Concurrent flows on the same engagement must not tear the file."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry = collector._match_engagement("a.example.com")
    assert entry is not None

    def capture(idx: int) -> None:
        req = _FakeRequest(
            url="https://a.example.com/path",
            method="GET",
            cookies={f"k{idx}": f"v{idx}"},
        )
        resp = _FakeHttpResponse(status_code=200, headers={}, body=b"")
        collector._capture_auth(entry, _FakeFlow(req, resp))

    threads = [threading.Thread(target=capture, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    auth = json.loads((root / "eng-a" / "auth.json").read_text(encoding="utf-8"))
    # All eight cookies must have landed in the merged set — proves no torn writes.
    assert {f"k{i}" for i in range(8)} <= set(auth["cookies"])


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
