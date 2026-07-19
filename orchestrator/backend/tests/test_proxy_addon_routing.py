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
    http.Response = SimpleNamespace(  # type: ignore[attr-defined]
        make=lambda status, body, headers: _FakeHttpResponse(status, headers, body)
    )
    mitmproxy.http = http  # type: ignore[attr-defined]
    mitmproxy.ctx = SimpleNamespace(
        log=SimpleNamespace(
            info=lambda *_a, **_k: None,
            warn=lambda *_a, **_k: None,
            error=lambda *_a, **_k: None,
        ),
        options=SimpleNamespace(engagements_root="", registry_poll_seconds=30),
    )
    sys.modules["mitmproxy"] = mitmproxy
    sys.modules["mitmproxy.http"] = http

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
    required_headers: dict[str, str] | None = None,
    off_limits_paths: list[str] | None = None,
    scope_enforcement: str | None = None,
) -> Path:
    engagement_dir = engagements_root / key
    engagement_dir.mkdir(parents=True, exist_ok=True)
    scope: dict = {"hosts": hosts}
    if scope_priority:
        scope["scope_priority"] = scope_priority
    if out_of_scope:
        scope["out_of_scope"] = out_of_scope
    if required_headers is not None:
        scope["required_headers"] = required_headers
    if off_limits_paths is not None:
        scope["off_limits_paths"] = off_limits_paths
    if scope_enforcement is not None:
        scope["scope_enforcement"] = scope_enforcement
    (engagement_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    return engagement_dir


# ---------------------------------------------------------------------------
# Filesystem registry + matching
# ---------------------------------------------------------------------------


def test_load_exposes_only_shared_engagements_root_option() -> None:
    module = _load_proxy_addon_module()
    collector = module.CaseCollector()
    added: list[tuple] = []

    class Loader:
        def add_option(self, *args) -> None:
            added.append(args)

    collector.load(Loader())

    option_names = [args[0] for args in added]
    assert "engagements_root" in option_names
    assert "registry_poll_seconds" in option_names
    assert "engagement_dir" not in option_names


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


def test_out_of_scope_covers_defers_unresolved_cidr() -> None:
    module = _load_proxy_addon_module()
    patterns = ["10.0.0.0/8"]
    # No resolvable IP: the default is fail-closed; deferral skips the CIDR entry.
    assert module._out_of_scope_covers(patterns, "app.example.com", None) is True
    assert (
        module._out_of_scope_covers(
            patterns, "app.example.com", None, defer_unresolved_cidr=True
        )
        is False
    )
    # A resolved in-range IP still matches even when deferral is requested.
    assert (
        module._out_of_scope_covers(
            patterns, "app.example.com", "10.1.2.3", defer_unresolved_cidr=True
        )
        is True
    )


def test_request_time_defers_cidr_so_required_header_injects(tmp_path: Path) -> None:
    """A required-header engagement that ALSO carries a CIDR out_of_scope entry
    must still match (and inject its attribution header) on in-scope browser
    traffic at request time, when the upstream IP is not yet resolved."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-hdr",
        hosts=["*.example.com"],
        out_of_scope=["10.0.0.0/8"],
        required_headers={"X-Bug-Bounty": "researcher"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    host = "app.example.com"
    # Response path (IP unknown) fails closed on the unevaluable CIDR carve-out.
    assert collector._match_engagement(host, resolved_ip=None) is None
    # Request path defers that gate — the engagement matches and the header injects.
    chosen = collector._match_engagement(
        host, resolved_ip=None, defer_unresolved_cidr=True
    )
    assert chosen is not None and chosen.key == "eng-hdr"
    assert chosen.required_headers == {"X-Bug-Bounty": "researcher"}


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


def test_active_global_bypass_binds_unmatched_and_denied_hosts(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-bypass",
        hosts=["target.example"],
        out_of_scope=["blocked.example"],
        scope_enforcement="bypass",
    )
    (root / ".active").write_text("eng-bypass\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector.registry["eng-bypass"].scope_enforcement == "bypass"
    assert collector._match_engagement("outside.example").key == "eng-bypass"
    assert collector._match_engagement("blocked.example").key == "eng-bypass"


def test_active_global_bypass_never_steals_normal_hostname_owner(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-bypass",
        hosts=["target.example"],
        scope_enforcement="bypass",
    )
    _seed_engagement(root, "eng-owner", hosts=["owned.example"])
    (root / ".active").write_text("eng-bypass\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector._match_engagement("owned.example").key == "eng-owner"


def test_active_enforced_engagement_does_not_bind_unmatched_host(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-enforced", hosts=["target.example"])
    (root / ".active").write_text("eng-enforced\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector._match_engagement("outside.example") is None


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
    def __init__(
        self,
        status_code: int,
        headers: dict[str, str],
        body: bytes,
        timestamp_end: float | None = None,
    ):
        self.status_code = status_code
        self.headers = _FakeHeaders(headers)
        self._body = body
        self.timestamp_end = timestamp_end

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

    # Support ``dict(headers)`` the way mitmproxy's Headers does.
    def keys(self):
        return self._items.keys()

    def __getitem__(self, key: str) -> str:
        return self._items[key.lower()]

    # mitmproxy's real Headers matches/sets case-insensitively; the request hook
    # relies on ``name in headers`` and ``headers[name] = value`` behaving so.
    def __contains__(self, key: str) -> bool:
        return key.lower() in self._items

    def __setitem__(self, key: str, value: str) -> None:
        self._items[key.lower()] = value


class _FakeRequest:
    def __init__(
        self,
        *,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        body: bytes = b"",
        timestamp_start: float | None = None,
    ):
        self.pretty_url = url
        self.method = method
        self.headers = _FakeHeaders(headers or {})
        self.cookies = cookies or {}
        self._body = body
        self.timestamp_start = timestamp_start

    def get_content(self):
        return self._body


class _FakeConn:
    def __init__(self, ip_address=None, sni: str | None = None):
        self.ip_address = ip_address
        self.sni = sni


class _FakeFlow:
    def __init__(
        self,
        request: _FakeRequest,
        response: _FakeHttpResponse,
        *,
        server_conn: _FakeConn | None = None,
        client_conn: _FakeConn | None = None,
        flow_id: str = "",
    ):
        self.request = request
        self.response = response
        self.server_conn = server_conn
        self.client_conn = client_conn
        self.id = flow_id


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


# ---------------------------------------------------------------------------
# ROE required-header injection (the `request` hook)
#
# On a required-headers program (e.g. BugCrowd's mandated `X-Bug-Bounty`),
# un-attributed in-scope traffic is a ban-risk. The tool-exec path is covered by
# ADR 0010; the shared proxy is the chokepoint for browser/proxied traffic, so
# the `request` hook injects the marker there — gated by the same
# `_match_engagement` scope logic and non-destructive.
# ---------------------------------------------------------------------------


def _run_request_hook(
    collector,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    server_conn: "_FakeConn | None" = None,
) -> _FakeRequest:
    """Drive the addon's `request` hook for one outbound request and return the
    (possibly mutated) request so the caller can assert on its headers."""
    req = _FakeRequest(url=url, headers=headers or {})
    flow = _FakeFlow(req, None, server_conn=server_conn)  # response is None pre-connect
    collector.request(flow)
    return req


def test_request_hook_injects_required_header_on_in_scope_request(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    req = _run_request_hook(collector, "https://app.example.com/dashboard")
    assert req.headers.get("X-Bug-Bounty") == "vigiloss"


def test_request_hook_does_not_overwrite_client_supplied_header(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # Client already carries the marker (mixed case) — value must be preserved,
    # not clobbered or duplicated.
    req = _run_request_hook(
        collector, "https://app.example.com/x",
        headers={"x-bug-bounty": "operator-set"},
    )
    assert req.headers.get("X-Bug-Bounty") == "operator-set"
    assert list(dict(req.headers)) == ["x-bug-bounty"]  # exactly one, no duplicate


def test_request_hook_leaves_out_of_scope_host_untouched(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # A host no engagement claims must receive nothing.
    req = _run_request_hook(collector, "https://unrelated.test/x")
    assert "x-bug-bounty" not in req.headers


def test_request_hook_respects_out_of_scope_carve_out(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["*.example.com"],
        out_of_scope=["blocked.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # In-scope under the wildcard → injected.
    ok = _run_request_hook(collector, "https://ok.example.com/x")
    assert ok.headers.get("X-Bug-Bounty") == "vigiloss"

    # Covered by the out_of_scope carve-out → NOT injected (same gating as capture).
    blocked = _run_request_hook(collector, "https://blocked.example.com/x")
    assert "x-bug-bounty" not in blocked.headers


def test_request_hook_global_bypass_attributes_unmatched_and_denied_hosts(
    tmp_path: Path,
) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-bypass",
        hosts=["target.example"],
        out_of_scope=["blocked.example"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
        scope_enforcement="bypass",
    )
    (root / ".active").write_text("eng-bypass\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    for url in ("https://outside.example/x", "https://blocked.example/x"):
        req = _run_request_hook(collector, url)
        assert req.headers.get("X-Bug-Bounty") == "vigiloss"


def test_request_hook_noop_when_engagement_has_no_required_headers(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["app.example.com"])  # no required_headers
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    assert collector._any_required_headers() is False  # fast path short-circuits
    req = _run_request_hook(collector, "https://app.example.com/x")
    assert dict(req.headers) == {}


def test_request_hook_synthesizes_block_for_no_fire_url_without_upstream_send(
    tmp_path: Path,
) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-a",
        hosts=["app.example.com"],
        off_limits_paths=["/api/send-email"],
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    flow = _FakeFlow(
        _FakeRequest(url="https://app.example.com/api/send-email?to=real-user"),
        None,
    )

    collector.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 451
    assert flow.response.headers.get("X-Vigil-No-Fire") == "blocked"
    assert b"off_limits_paths" in flow.response.get_content()


def test_request_hook_global_bypass_still_blocks_no_fire_url(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-bypass",
        hosts=["target.example"],
        off_limits_paths=["/api/send-email"],
        scope_enforcement="bypass",
    )
    (root / ".active").write_text("eng-bypass\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    flow = _FakeFlow(
        _FakeRequest(url="https://outside.example/api/send-email"),
        None,
    )

    collector.request(flow)

    assert flow.response is not None
    assert flow.response.status_code == 451
    assert flow.response.headers.get("X-Vigil-No-Fire") == "blocked"


def test_request_hook_no_fire_is_host_scoped_for_absolute_patterns(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-a",
        hosts=["*.example.com"],
        off_limits_paths=["https://api.example.com/reset/*"],
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    flow = _FakeFlow(_FakeRequest(url="https://www.example.com/reset/alice"), None)

    collector.request(flow)

    assert flow.response is None


def test_request_hook_excessive_encoding_fails_closed_with_synthetic_response(
    tmp_path: Path,
) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-a",
        hosts=["app.example.com"],
        off_limits_paths=["/admin/delete"],
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    flow = _FakeFlow(
        _FakeRequest(url="https://app.example.com/admin%2525252Fdelete"),
        None,
    )

    collector.request(flow)

    assert flow.response.status_code == 451
    assert flow.response.headers.get("X-Vigil-No-Fire") == "blocked"


def test_filesystem_registry_parses_required_headers(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss", "X-Bad": 5, " ": "blank"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # Only str→str pairs survive (shared scope.required_headers coercion).
    assert collector.registry["eng-a"].required_headers == {"X-Bug-Bounty": "vigiloss"}


def test_backend_registry_reads_required_headers_from_scope_json(
    tmp_path: Path, monkeypatch
) -> None:
    """The backend /engagements payload does NOT serialize required_headers, so
    the backend registry path must read them from the on-disk scope.json. This is
    the load-bearing production path (backend up → this branch wins)."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    # scope.json on disk declares the marker; the backend row below omits it.
    _seed_engagement(
        root, "eng-from-backend", hosts=["api.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
        scope_enforcement="bypass",
    )

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"

    payload = [
        {
            "key": "eng-from-backend",
            "engagement_root": "/install/agent/engagements/eng-from-backend",
            "scope_hosts": ["api.example.com"],
            "scope_priority": 0,
            "updated_at": "2026-05-18T10:00:00Z",
            # NOTE: no "required_headers" key — mirrors the real backend response.
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

    monkeypatch.setattr(
        module, "urlopen",
        lambda *_a, **_k: _Response(json.dumps(payload).encode("utf-8")),
    )
    entries = collector._fetch_registry_from_backend()
    assert entries is not None and len(entries) == 1
    assert entries[0].required_headers == {"X-Bug-Bounty": "vigiloss"}
    assert entries[0].scope_enforcement == "bypass"


def test_reload_updates_required_headers_after_scope_edit(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "old-handle"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry_before = collector.registry["eng-a"]
    assert entry_before.required_headers == {"X-Bug-Bounty": "old-handle"}

    # Operator edits scope.json, then `vigil mitmproxy reload` re-scans.
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "new-handle"},
    )
    collector._reload_registry(force=True)

    # The existing entry object is reused (Change 5 merge branch) with the new value.
    assert collector.registry["eng-a"] is entry_before
    assert entry_before.required_headers == {"X-Bug-Bounty": "new-handle"}


def test_routes_cache_includes_required_headers(tmp_path: Path) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["app.example.com"],
        required_headers={"X-Bug-Bounty": "vigiloss"},
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    payload = json.loads((root / module.ROUTES_CACHE).read_text(encoding="utf-8"))
    rows = {row["key"]: row for row in payload["engagements"]}
    assert rows["eng-a"]["required_headers"] == {"X-Bug-Bounty": "vigiloss"}


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


def test_capture_auth_scope_host_is_captured_host_not_primary_scope(
    tmp_path: Path,
) -> None:
    """Multi-host engagement: scope_host must be the host actually captured, not
    the first scope pattern.

    Two unrelated hosts share one engagement. Capturing a session on the
    non-primary host (b.example.com) must scope the flat-cookie view to
    b.example.com — the legacy ``scope_patterns[0]`` primary would have scoped it
    to a.example.com, silently dropping b's session from every flat-view consumer
    (e.g. ``vigil auth export``). This is the I-22 multi-host regression guard.
    """
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-multi", hosts=["a.example.com", "b.example.com"])

    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)

    entry = collector._match_engagement("b.example.com")
    assert entry is not None
    # Premise guard: b.example.com is NOT the primary scope pattern, so the legacy
    # code would have mis-scoped the capture.
    assert entry.scope_patterns[0].lstrip("*.") != "b.example.com"

    request = _FakeRequest(
        url="https://b.example.com/login",
        method="POST",
        cookies={"session": "b-sess"},
    )
    response = _FakeHttpResponse(status_code=200, headers={}, body=b"{}")
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["host"] == "b.example.com"
    # The fix: scope_host is the actually-captured host, so b's session lands in
    # b's flat cookie view instead of being scoped to a.example.com and dropped.
    assert kw["scope_host"] == "b.example.com"


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
# Work items are now derived server-side from the request-observation POST —
# the proxy no longer opens SQLite (there is no _insert_case / cases.db write).
# The former healthy-connection and stale-connection-recovery tests were
# removed; see tests/test_work_buffer_backend.py for the server-side
# assessment_work_items derivation.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# _is_deletion_set_cookie unit tests (logout guard)
# ---------------------------------------------------------------------------


def test_is_deletion_set_cookie_f5_apm_deleted_value():
    """F5/APM CMS logout: value is the literal string 'deleted'."""
    module = _load_proxy_addon_module()
    # Canonical CMS logout pattern.
    assert module._is_deletion_set_cookie("MRHSession=deleted; path=/; Secure; HttpOnly") is True
    assert module._is_deletion_set_cookie("F5_ST=deleted; path=/") is True
    # Case-insensitive.
    assert module._is_deletion_set_cookie("MRHSession=DELETED; path=/") is True
    assert module._is_deletion_set_cookie("MRHSession=Deleted") is True


def test_is_deletion_set_cookie_empty_value():
    """Empty value is a deletion (Max-Age=0 stripped by some stacks before the value)."""
    module = _load_proxy_addon_module()
    assert module._is_deletion_set_cookie("MRHSession=; path=/") is True
    assert module._is_deletion_set_cookie("MRHSession=") is True


def test_is_deletion_set_cookie_max_age_zero():
    """Max-Age=0 is the RFC 6265 deletion mechanism."""
    module = _load_proxy_addon_module()
    assert module._is_deletion_set_cookie("sid=abc; Max-Age=0") is True
    assert module._is_deletion_set_cookie("sid=abc; max-age=0; path=/") is True
    assert module._is_deletion_set_cookie("sid=abc; Max-Age=-1") is True


def test_is_deletion_set_cookie_expires_in_past():
    """Expires with an epoch / far-past date is a deletion."""
    module = _load_proxy_addon_module()
    assert module._is_deletion_set_cookie(
        "sid=abc; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    ) is True
    assert module._is_deletion_set_cookie(
        "sid=abc; expires=Thu, 01 Jan 1970 00:00:01 GMT"
    ) is True


def test_is_deletion_set_cookie_live_cookie_not_deletion():
    """A normal session cookie must not be treated as a deletion."""
    module = _load_proxy_addon_module()
    assert module._is_deletion_set_cookie("MRHSession=abc123valid; path=/; Secure") is False
    assert module._is_deletion_set_cookie("sid=xyz; Max-Age=3600") is False
    # A far-future Expires is not a deletion (timegm >= now).
    assert module._is_deletion_set_cookie(
        "sid=abc; Expires=Thu, 01 Jan 2099 00:00:00 GMT"
    ) is False


def test_is_deletion_set_cookie_quoted_empty():
    """A quoted-empty logout cookie (MRHSession="") is a deletion sentinel."""
    module = _load_proxy_addon_module()
    assert module._is_deletion_set_cookie('MRHSession=""; path=/; Secure') is True
    assert module._is_deletion_set_cookie('sid=""') is True
    # A quoted LIVE value is not a deletion.
    assert module._is_deletion_set_cookie('sid="abc123"; path=/') is False


# ---------------------------------------------------------------------------
# P1 out-of-scope carve-out: URL-form + CIDR entries, fail-closed
# ---------------------------------------------------------------------------


def test_out_of_scope_covers_url_form_entry():
    module = _load_proxy_addon_module()
    # URL-form entry reduced to its bare host and matched.
    assert module._out_of_scope_covers(
        ["https://appointments.acme-regional.example/book"], "appointments.acme-regional.example"
    ) is True
    # A different host under the same apex is NOT covered by the URL-form host.
    assert module._out_of_scope_covers(
        ["https://appointments.acme-regional.example/book"], "app.acme-regional.example"
    ) is False


def test_out_of_scope_covers_cidr_against_resolved_ip():
    module = _load_proxy_addon_module()
    # In-range resolved IP → covered (drop).
    assert module._out_of_scope_covers(
        ["10.0.0.0/8"], "internal.example.com", "10.1.2.3"
    ) is True
    # Out-of-range resolved IP → not covered.
    assert module._out_of_scope_covers(
        ["10.0.0.0/8"], "public.example.com", "93.184.216.34"
    ) is False
    # An IP-literal hostname is honored even without a separate resolved_ip.
    assert module._out_of_scope_covers(["10.0.0.0/8"], "10.9.9.9") is True


def test_out_of_scope_cidr_without_ip_fails_closed():
    """A CIDR carve-out with no resolvable IP is uncertain — fail closed."""
    module = _load_proxy_addon_module()
    assert module._out_of_scope_covers(["10.0.0.0/8"], "internal.example.com") is True


def test_out_of_scope_slash_non_cidr_reduces_to_host_not_drop_all():
    """A slash-bearing entry that is NOT a valid CIDR (host/path or bare path) is
    reduced to its host and matched as a host pattern — it must NEVER drop every
    host in the engagement. Regression for the fail-closed-drops-everything bug
    (a single "example.com/admin" or CIDR typo killed the whole engagement's
    capture)."""
    module = _load_proxy_addon_module()
    # Host/path carve-out denylists ONLY its host...
    assert module._out_of_scope_covers(["example.com/admin"], "example.com") is True
    # ...and does NOT drop unrelated hosts (the bug dropped these too).
    assert module._out_of_scope_covers(["example.com/admin"], "shop.example.com") is False
    assert module._out_of_scope_covers(["example.com/admin"], "other.com") is False
    # A host-less path is host-blind → skipped, never a drop-all.
    assert module._out_of_scope_covers(["/api/internal"], "anything.example") is False
    # A CIDR typo ("not/a/cidr/or/url") reduces to host "not" → no match, no drop-all.
    assert module._out_of_scope_covers(["not/a/cidr/or/url"], "target.example") is False
    # Host-less/unparseable URL-form is host-blind → skipped, not a drop-all.
    assert module._out_of_scope_covers(["://"], "target.example") is False


def test_match_engagement_drops_cidr_out_of_scope_with_resolved_ip(tmp_path: Path):
    """A CIDR out_of_scope entry drops a host whose resolved IP is in-range,
    while an out-of-range host still routes."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a", hosts=["*.example.com"], out_of_scope=["10.0.0.0/8"]
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # Internal host resolving into 10/8 is dropped.
    assert (
        collector._match_engagement("internal.example.com", resolved_ip="10.5.6.7")
        is None
    )
    # Public host resolving outside 10/8 still routes.
    chosen = collector._match_engagement("api.example.com", resolved_ip="93.184.216.34")
    assert chosen is not None and chosen.key == "eng-a"


def test_match_engagement_path_carve_out_does_not_drop_whole_engagement(tmp_path: Path):
    """A host/path out_of_scope entry must denylist ONLY its host, never wipe out
    the whole engagement's capture. Regression for the catastrophic
    fail-closed-drops-everything bug."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root, "eng-a",
        hosts=["*.example.com", "*.other.com"],
        out_of_scope=["example.com/admin"],
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    # Unrelated in-scope hosts STILL route (the bug dropped all of these).
    assert collector._match_engagement("shop.example.com", resolved_ip="93.184.216.34").key == "eng-a"
    assert collector._match_engagement("api.other.com", resolved_ip="93.184.216.34").key == "eng-a"
    # Only the reduced carve-out host is dropped.
    assert collector._match_engagement("example.com", resolved_ip="93.184.216.34") is None


def test_capture_auth_skips_out_of_scope_host(tmp_path: Path):
    """_capture_auth must NEVER harvest credentials for a host an out_of_scope
    entry could cover (defense in depth, even if routing let it through)."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-a",
        hosts=["*.example.com"],
        out_of_scope=["https://secret.example.com"],
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector.registry["eng-a"]

    request = _FakeRequest(
        url="https://secret.example.com/login",
        method="POST",
        cookies={"session": "abc"},
    )
    response = _FakeHttpResponse(status_code=200, headers={}, body=b"{}")
    collector._capture_auth(entry, _FakeFlow(request, response))
    assert calls == []


# ---------------------------------------------------------------------------
# P1 bearer synthesis + nested tokens + request Authorization
# ---------------------------------------------------------------------------


def test_capture_auth_bearer_ignores_refresh_and_type_tokens(tmp_path: Path):
    """token_type=Bearer / refresh_token / csrf_token must NOT seed the bearer;
    the access_token wins by priority (not document order)."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")

    request = _FakeRequest(url="https://a.example.com/login", method="POST")
    response = _FakeHttpResponse(
        status_code=200,
        headers={},
        body=b'{"token_type": "Bearer", "refresh_token": "r-secret", '
        b'"csrf_token": "c-secret", "access_token": "a-secret"}',
    )
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["headers"]["Authorization"] == "Bearer a-secret"
    # All token-keyed fields are still accumulated in the tokens delta.
    assert kw["tokens"]["access_token"] == "a-secret"
    assert kw["tokens"]["refresh_token"] == "r-secret"


def test_capture_auth_extracts_nested_bearer_token(tmp_path: Path):
    """A bearer nested one level under the login response still enters the store."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")

    request = _FakeRequest(url="https://a.example.com/auth/login", method="POST")
    response = _FakeHttpResponse(
        status_code=200,
        headers={},
        body=b'{"data": {"access_token": "nested-tok"}}',
    )
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["tokens"]["access_token"] == "nested-tok"
    assert kw["headers"]["Authorization"] == "Bearer nested-tok"


def test_capture_auth_captures_request_authorization_header(tmp_path: Path):
    """A bearer-only session (Authorization on the request, no cookies, no login
    response) must still enter the credential store."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")

    request = _FakeRequest(
        url="https://a.example.com/api/me",
        method="GET",
        headers={"Authorization": "Bearer live-session-tok"},
    )
    response = _FakeHttpResponse(status_code=200, headers={}, body=b"{}")
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["headers"]["Authorization"] == "Bearer live-session-tok"


def test_capture_auth_stores_dequoted_set_cookie(tmp_path: Path):
    """A live quoted Set-Cookie value is stored dequoted (no double-quoting)."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    calls = _record_captures(collector)
    entry = collector._match_engagement("a.example.com")

    request = _FakeRequest(url="https://a.example.com/login", method="POST")
    response = _FakeHttpResponse(
        status_code=200,
        headers={"set-cookie": 'sid="quoted-val"; Path=/; HttpOnly'},
        body=b"{}",
    )
    collector._capture_auth(entry, _FakeFlow(request, response))

    assert len(calls) == 1
    _, kw = calls[0]
    assert kw["cookies"]["sid"] == "quoted-val"


# ---------------------------------------------------------------------------
# P2 content_type_family: html/xml before generic text/
# ---------------------------------------------------------------------------


def test_content_type_family_html_before_text():
    module = _load_proxy_addon_module()
    assert module._content_type_family("text/html; charset=utf-8") == "html"
    assert module._content_type_family("application/xml") == "xml"
    assert module._content_type_family("text/plain") == "text"
    assert module._content_type_family("application/json") == "json"
    assert module._content_type_family("application/javascript") == "javascript"
    assert module._content_type_family("") == "unknown"


# ---------------------------------------------------------------------------
# P1 body_schema: a top-level JSON array/scalar request body must not 422
# ---------------------------------------------------------------------------


def test_post_request_observation_coerces_non_dict_body_schema(tmp_path: Path, monkeypatch):
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"
    collector._reload_registry(force=True)
    entry = collector._match_engagement("a.example.com")

    sent: dict = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps({"request_variant": {"id": 42}}).encode("utf-8")

    def fake_urlopen(request, timeout=10):
        sent["payload"] = json.loads(request.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)

    result = collector._post_request_observation(
        entry=entry,
        url="https://a.example.com/api",
        method="POST",
        auth_context="anonymous",
        content_type="application/json",
        params={"body_params": "[1, 2, 3]"},  # top-level JSON array
        response_status=200,
        evidence_ref="proxy",
        observation_payload={},
    )
    assert result is not None
    # The array body was coerced to {} so the typed dict[str, Any] never 422s.
    assert sent["payload"]["body_schema"] == {}


# ---------------------------------------------------------------------------
# P1 request-body save gated on REQUEST content type (not response)
# ---------------------------------------------------------------------------


def test_request_body_saved_when_response_is_binary(tmp_path: Path):
    """A JSON request body answered by an image/png response must still be
    captured: the request-body save is gated on the REQUEST content type, not the
    response type, and the observation is still POSTed despite the binary
    response. The proxy no longer opens SQLite, so the captured request body/params
    ride in the request-observation POST's work_item block."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    posted: list[dict] = []
    collector._capture_auth = lambda *a, **k: None

    def _fake_post_observation(**kw):
        posted.append(kw)
        return {"request_variant": {"id": 1}, "service": {"id": 1}}

    collector._post_request_observation = _fake_post_observation

    request = _FakeRequest(
        url="https://a.example.com/upload",
        method="POST",
        headers={"content-type": "application/json"},
        body=b'{"k": "v"}',
    )
    response = _FakeHttpResponse(
        status_code=200,
        headers={"content-type": "image/png"},
        body=b"\x89PNG binary",
    )
    collector.response(_FakeFlow(request, response))

    # The observation was POSTed even though the RESPONSE body is binary ...
    assert len(posted) == 1
    kw = posted[0]
    # ... and the REQUEST body + parsed body_params were preserved (saved on the
    # request content type, not the image/png response type). The stored
    # request_content_type is the REQUEST type, consistent with the saved body.
    assert kw["body"] == '{"k": "v"}'
    assert kw["request_content_type"] == "application/json"
    assert json.loads(kw["params"]["body_params"]) == {"k": "v"}


def test_response_global_bypass_captures_unmatched_host_for_bound_engagement(
    tmp_path: Path,
) -> None:
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(
        root,
        "eng-bypass",
        hosts=["target.example"],
        out_of_scope=["blocked.example"],
        scope_enforcement="bypass",
    )
    (root / ".active").write_text("eng-bypass\n", encoding="utf-8")
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)

    auth_entries: list[str] = []
    observations: list[tuple[str, str]] = []
    full_flows: list[str] = []
    collector._capture_auth = lambda entry, *_a, **_k: auth_entries.append(entry.key)

    def _post_observation(*, entry, url, **_kwargs):
        observations.append((entry.key, url))
        return {"request_variant": {"id": 1}}

    collector._post_request_observation = _post_observation
    collector._maybe_capture_full_flow = (
        lambda entry, *_a, **_k: full_flows.append(entry.key)
    )
    request = _FakeRequest(
        url="https://blocked.example/api",
        headers={"content-type": "application/json"},
    )
    response = _FakeHttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=b'{"ok": true}',
    )

    collector.response(_FakeFlow(request, response))

    assert auth_entries == ["eng-bypass"]
    assert observations == [("eng-bypass", "https://blocked.example/api")]
    assert full_flows == ["eng-bypass"]


# ---------------------------------------------------------------------------
# Part B: full-flow capture (policy-gated sidecars + JSONL index + ingest POST)
# ---------------------------------------------------------------------------


def _enabled_policy(**overrides) -> dict:
    policy = {
        "enabled": True,
        "capture_request_bodies": True,
        "capture_response_bodies": True,
        "max_body_bytes": 100000,
        "content_type_allow": [],
        "content_type_deny": [],
        "redaction_profile": "none",
    }
    policy.update(overrides)
    return policy


def _capture_full_flow(collector, entry, flow, **kwargs):
    posted: list[dict] = []
    collector._post_http_flow = lambda e, record: posted.append(record)
    defaults = dict(
        hostname="a.example.com",
        path="/api",
        resolved_ip=None,
        request_variant_id=7,
        auth_context="authenticated",
        content_family="json",
        request_content_type="application/json",
        response_content_type="application/json",
        response_status=200,
        raw_req_body=b'{"req": 1}',
        resp_body=b'{"resp": 2}',
    )
    defaults.update(kwargs)
    collector._maybe_capture_full_flow(entry, flow, **defaults)
    return posted


def test_full_flow_capture_disabled_by_default(tmp_path: Path):
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry = collector.registry["eng-a"]
    # No capture-policy.json → policy disabled.
    assert entry.capture_policy["enabled"] is False

    request = _FakeRequest(url="https://a.example.com/api", method="POST", body=b'{"a":1}')
    response = _FakeHttpResponse(status_code=200, headers={}, body=b'{"b":2}')
    posted = _capture_full_flow(collector, entry, _FakeFlow(request, response))

    assert posted == []
    assert not (entry.root / "traffic").exists()


def test_full_flow_capture_writes_sidecars_index_and_posts(tmp_path: Path):
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry = collector.registry["eng-a"]
    entry.capture_policy = _enabled_policy()

    request = _FakeRequest(
        url="https://a.example.com/api",
        method="POST",
        headers={"content-type": "application/json", "host": "a.example.com"},
        body=b'{"req": 1}',
        timestamp_start=1_700_000_000.0,
    )
    response = _FakeHttpResponse(
        status_code=201,
        headers={"content-type": "application/json"},
        body=b'{"resp": 2}',
        timestamp_end=1_700_000_000.5,
    )
    flow = _FakeFlow(request, response, flow_id="flow-xyz")
    posted = _capture_full_flow(
        collector,
        entry,
        flow,
        response_status=201,
        raw_req_body=b'{"req": 1}',
        resp_body=b'{"resp": 2}',
    )

    assert len(posted) == 1
    rec = posted[0]
    assert rec["flow_uid"] == "flow-xyz"
    assert rec["request_variant_id"] == 7
    assert rec["host"] == "a.example.com"
    assert rec["timing_ms"] == 500
    assert rec["started_at"] == "2023-11-14T22:13:20Z"

    import hashlib

    req_sha = hashlib.sha256(b'{"req": 1}').hexdigest()
    resp_sha = hashlib.sha256(b'{"resp": 2}').hexdigest()
    assert rec["request_body_sha256"] == req_sha
    assert rec["response_body_sha256"] == resp_sha
    assert rec["request_body_artifact_path"] == f"traffic/mitmproxy/bodies/{req_sha}.bin"
    assert rec["response_body_artifact_path"] == f"traffic/mitmproxy/bodies/{resp_sha}.bin"
    assert rec["request_body_truncated"] is False

    # Sidecars written engagement-local with the exact bytes.
    assert (entry.root / rec["request_body_artifact_path"]).read_bytes() == b'{"req": 1}'
    assert (entry.root / rec["response_body_artifact_path"]).read_bytes() == b'{"resp": 2}'

    # JSONL index appended and referenced on the POST record.
    assert rec["index_artifact_path"].startswith("traffic/mitmproxy/flows/")
    index_file = entry.root / rec["index_artifact_path"]
    assert index_file.is_file()
    lines = index_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["flow_uid"] == "flow-xyz"


def test_full_flow_capture_truncates_and_honors_deny(tmp_path: Path):
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry = collector.registry["eng-a"]
    entry.capture_policy = _enabled_policy(
        max_body_bytes=4, content_type_deny=["image/"]
    )

    request = _FakeRequest(
        url="https://a.example.com/api",
        method="POST",
        headers={"content-type": "application/json", "host": "a.example.com"},
        body=b"0123456789",
    )
    # Response is image/png → denied, no response sidecar.
    response = _FakeHttpResponse(
        status_code=200, headers={"content-type": "image/png"}, body=b"PNGDATA"
    )
    posted = _capture_full_flow(
        collector,
        entry,
        _FakeFlow(request, response),
        request_content_type="application/json",
        response_content_type="image/png",
        raw_req_body=b"0123456789",
        resp_body=b"PNGDATA",
    )
    rec = posted[0]
    # Request body truncated to 4 bytes; truncation flagged honestly.
    assert rec["request_body_bytes"] == 4
    assert rec["request_body_truncated"] is True
    stored = entry.root / rec["request_body_artifact_path"]
    assert stored.read_bytes() == b"0123"
    # Denied response body → no sidecar, no sha.
    assert rec["response_body_artifact_path"] is None
    assert rec["response_body_sha256"] == ""


def test_full_flow_capture_records_host_mismatch(tmp_path: Path):
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    entry = collector.registry["eng-a"]
    entry.capture_policy = _enabled_policy(
        capture_request_bodies=False, capture_response_bodies=False
    )

    # Host header disagrees with the URL authority → host_mismatch telemetry.
    request = _FakeRequest(
        url="https://a.example.com/api",
        method="GET",
        headers={"host": "evil.example.com"},
    )
    response = _FakeHttpResponse(status_code=200, headers={}, body=b"")
    flow = _FakeFlow(
        request, response, client_conn=_FakeConn(sni="a.example.com")
    )
    posted = _capture_full_flow(
        collector,
        entry,
        flow,
        raw_req_body=b"",
        resp_body=b"",
    )
    rec = posted[0]
    assert rec["host_mismatch"] is True
    assert rec["host_header"] == "evil.example.com"
    assert rec["sni"] == "a.example.com"
    assert rec["url_authority"] == "a.example.com"


def test_capture_policy_read_from_filesystem_mirror(tmp_path: Path):
    """The addon reads the capture policy from the capture-policy.json mirror the
    backend writes next to scope.json (filesystem fallback)."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    root.mkdir()
    eng = _seed_engagement(root, "eng-a", hosts=["a.example.com"])
    (eng / "capture-policy.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "capture_request_bodies": True,
                "capture_response_bodies": False,
                "max_body_bytes": 2048,
                "content_type_allow": ["application/json"],
                "content_type_deny": [],
                "redaction_profile": "none",
            }
        ),
        encoding="utf-8",
    )
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector._reload_registry(force=True)
    policy = collector.registry["eng-a"].capture_policy
    assert policy["enabled"] is True
    assert policy["capture_request_bodies"] is True
    assert policy["capture_response_bodies"] is False
    assert policy["max_body_bytes"] == 2048
    assert policy["content_type_allow"] == ["application/json"]


def test_capture_policy_from_backend_registry_row(tmp_path: Path, monkeypatch):
    """The registry fetch carries capture_policy from the /engagements payload."""
    module = _load_proxy_addon_module()
    root = tmp_path / "engagements"
    (root / "eng-a").mkdir(parents=True)
    collector = module.CaseCollector()
    collector.engagements_root = root
    collector.orchestrator_base_url = "http://orchestrator.test"

    payload = [
        {
            "key": "eng-a",
            "scope_hosts": ["a.example.com"],
            "capture_policy": {"enabled": True, "max_body_bytes": 512},
        }
    ]

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self):
            return json.dumps(payload).encode("utf-8")

    monkeypatch.setattr(module, "urlopen", lambda *a, **k: _Resp())
    entries = collector._fetch_registry_from_backend()
    assert entries[0].capture_policy["enabled"] is True
    assert entries[0].capture_policy["max_body_bytes"] == 512


# ---------------------------------------------------------------------------
# Body-capture content-type filter: MIME wildcards (image/*) must match
# ---------------------------------------------------------------------------


def test_body_capture_deny_honors_mime_wildcard():
    """A ``content_type_deny`` of ``image/*`` (the exact value the capture-policy
    API stores) must exclude ``image/png`` — a substring-only check treated
    ``image/*`` as literal text and never matched, so binary responses were still
    captured when ``capture_response_bodies`` was on, bypassing the policy."""
    module = _load_proxy_addon_module()
    # Deny image/* -> image/png and a bare "image" are excluded; non-image passes.
    assert module._body_capture_allowed("image/png", [], ["image/*"]) is False
    assert module._body_capture_allowed("image/jpeg", [], ["image/*"]) is False
    assert module._body_capture_allowed("image", [], ["image/*"]) is False
    assert module._body_capture_allowed("application/json", [], ["image/*"]) is True


def test_body_capture_allow_honors_mime_wildcard_and_substring_still_works():
    module = _load_proxy_addon_module()
    # Allow-list wildcard: only text/* captured.
    assert module._body_capture_allowed("text/html; charset=utf-8", ["text/*"], []) is True
    assert module._body_capture_allowed("application/json", ["text/*"], []) is False
    # Historical substring entries keep working (no regression).
    assert module._body_capture_allowed("image/png", [], ["image/"]) is False
    assert module._body_capture_allowed("application/json", [], ["json"]) is False
