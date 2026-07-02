"""`vigil auth export` host-scoped cookie overlay (I-22, multi-host engagements).

`export_curl_args(host=...)` overlays the per-host `host_cookies` bucket on top of
the legacy flat `cookies` view, the same host-scoped lookup the proxy applies at
injection time. Without `--host`, only the flat view is rendered — which on a
multi-host engagement can be the wrong (or empty) session for the target host.

The per-host *selection* logic (`assess.lib.identity.host_cookies_for`) is covered
by `agent/scripts/assess/tests/test_identity_cookies.py`; these tests cover the CLI
wiring — that `--host` reaches the overlay and its absence leaves the flat view
untouched. The dynamic assess import is stubbed so the test is decoupled from the
install-root layout `export_curl_args` resolves at runtime.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vigil_cli import auth  # noqa: E402  (src must be on sys.path first)


def _material() -> dict[str, object]:
    return {
        "cookies": {"flat": "F"},
        "host_cookies": [
            {"host": "b.example.com", "cookies": {"bsess": "B"}},
        ],
        "headers": {"X-Api": "K"},
    }


def _stub_assess_identity(monkeypatch) -> None:
    """No-op the install-root path insert and inject a faithful stub of
    ``assess.lib.identity.host_cookies_for`` (returns a host's bucket)."""
    monkeypatch.setattr("vigil_cli.paths.add_assess_import_path", lambda _root: None)

    def host_cookies_for(material: dict, host: str) -> dict[str, str]:
        for bucket in material.get("host_cookies", []):
            if bucket.get("host") == host:
                return dict(bucket.get("cookies", {}))
        return {}

    identity_mod = types.ModuleType("assess.lib.identity")
    identity_mod.host_cookies_for = host_cookies_for  # type: ignore[attr-defined]
    lib_mod = types.ModuleType("assess.lib")
    assess_mod = types.ModuleType("assess")
    monkeypatch.setitem(sys.modules, "assess", assess_mod)
    monkeypatch.setitem(sys.modules, "assess.lib", lib_mod)
    monkeypatch.setitem(sys.modules, "assess.lib.identity", identity_mod)


def test_export_without_host_renders_only_flat_cookie_view(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _material())

    out = auth.export_curl_args(eng)

    assert "flat=F" in out
    assert "bsess=B" not in out  # per-host bucket NOT overlaid without --host
    assert "-H 'X-Api: K'" in out


def test_export_with_host_overlays_that_hosts_captured_session(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _material())
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="b.example.com")

    # b's captured session is overlaid on top of the flat view.
    assert "bsess=B" in out
    assert "flat=F" in out


def test_export_with_host_that_has_no_bucket_keeps_flat_view(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _material())
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="c.example.com")

    assert "flat=F" in out  # no bucket for c → flat view unchanged, no crash
    assert "bsess=B" not in out


# --------------------------------------------------------------------------- #
# CSRF double-submit export (mirror of assess.lib.kali) — the copy-paste path
# must render the same header the runtime injects. Method-gated, cookie-derived,
# opt-in, never clobbering an operator header.
# --------------------------------------------------------------------------- #

def _csrf_material_export() -> dict:
    return {
        "cookies": {"PORTAL-XSRF-TOKEN": "tok123", "SESSION": "s"},
        "csrf": {"cookie": "PORTAL-XSRF-TOKEN", "header": "PORTAL-X-CSRF-TOKEN"},
        "headers": {"X-Api": "K"},
    }


def test_csrf_export_arg_emitted_on_state_changing_method():
    mat = _csrf_material_export()
    assert auth._csrf_export_arg(mat, mat["cookies"], "POST") == "-H 'PORTAL-X-CSRF-TOKEN: tok123'"
    assert auth._csrf_export_arg(mat, mat["cookies"], "delete") == "-H 'PORTAL-X-CSRF-TOKEN: tok123'"


def test_csrf_export_arg_absent_on_safe_or_unset_method():
    mat = _csrf_material_export()
    assert auth._csrf_export_arg(mat, mat["cookies"], "GET") == ""
    assert auth._csrf_export_arg(mat, mat["cookies"], None) == ""
    assert auth._csrf_export_arg(mat, mat["cookies"], "") == ""


def test_csrf_export_arg_absent_when_named_cookie_missing():
    mat = _csrf_material_export()
    assert auth._csrf_export_arg(mat, {"SESSION": "s"}, "POST") == ""  # XSRF cookie absent


def test_csrf_export_arg_absent_when_no_mapping():
    mat = {"cookies": {"SESSION": "s"}}
    assert auth._csrf_export_arg(mat, mat["cookies"], "POST") == ""


def test_csrf_export_arg_not_emitted_when_operator_header_present():
    mat = _csrf_material_export()
    mat["headers"]["PORTAL-X-CSRF-TOKEN"] = "operator-set"  # already carried
    assert auth._csrf_export_arg(mat, mat["cookies"], "POST") == ""


def test_export_curl_args_includes_csrf_on_post_only(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _csrf_material_export())

    post = auth.export_curl_args(eng, method="POST")
    assert "-H 'PORTAL-X-CSRF-TOKEN: tok123'" in post
    get = auth.export_curl_args(eng, method="GET")
    assert "PORTAL-X-CSRF-TOKEN" not in get
    unset = auth.export_curl_args(eng)  # no method → matches a GET run
    assert "PORTAL-X-CSRF-TOKEN" not in unset


# --------------------------------------------------------------------------- #
# Liveness classifier + probe (mirror of assess auth-status). Network-free: the
# classifier is pure and operator-configured (material.liveness =
# {expect_status, authed_marker, dead_marker}); the probe is exercised with a
# fake HTTP connection. There is NO auto-detection of where auth lives.
# --------------------------------------------------------------------------- #

def test_classify_liveness_parity():
    cl = auth._classify_liveness
    # (2) no liveness signature configured -> unknown (names the shape to set).
    assert cl(200, "Sign out", None)[0] == "unknown"
    assert cl(200, "Sign out", {})[0] == "unknown"
    # (1) transport error (status None) wins even with a signature present.
    assert cl(None, None, {"authed_marker": "Sign out"})[0] == "unknown"
    # (3) dead_marker present in haystack -> dead.
    assert cl(200, "Please sign in", {"dead_marker": "sign in"})[0] == "dead"
    # (4) authed_marker absent -> dead.
    assert cl(200, "anonymous page", {"authed_marker": "Sign out"})[0] == "dead"
    # (5) expect_status mismatch -> dead (marker present, status wrong).
    assert cl(302, "Sign out", {"authed_marker": "Sign out", "expect_status": 200})[0] == "dead"
    # (6) all configured checks pass -> live.
    assert cl(200, "Welcome — Sign out", {"authed_marker": "Sign out", "expect_status": 200})[0] == "live"
    # marker-only configs each stand alone.
    assert cl(200, "Sign out", {"authed_marker": "Sign out"})[0] == "live"
    assert cl(200, "anon", {"authed_marker": "Sign out"})[0] == "dead"
    assert cl(200, "welcome home", {"dead_marker": "Log in"})[0] == "live"
    assert cl(200, "Log in to continue", {"dead_marker": "Log in"})[0] == "dead"
    assert cl(200, "anything", {"expect_status": 200})[0] == "live"
    assert cl(500, "anything", {"expect_status": 200})[0] == "dead"
    # markers are case-sensitive substrings; a bool expect_status is not a real int.
    assert cl(200, "sign out", {"authed_marker": "Sign out"})[0] == "dead"
    assert cl(200, "x", {"expect_status": True})[0] == "unknown"  # bool != int status config


class _FakeResp:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
        self.status = status
        self.reason = "OK"
        self._headers = headers
        self._body = body

    def getheaders(self) -> list[tuple[str, str]]:
        return self._headers

    def read(self) -> bytes:
        return self._body


class _FakeConn:
    """Records the single request and returns a canned response (redirects are
    NOT followed by ``probe_liveness``, so exactly one request must be issued)."""

    requests: list[dict] = []
    status = 200
    headers: list[tuple[str, str]] = []
    body: bytes = b""

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port

    def request(self, method, path, headers=None):
        _FakeConn.requests.append({"method": method, "path": path, "headers": headers})

    def getresponse(self):
        return _FakeResp(_FakeConn.status, _FakeConn.headers, _FakeConn.body)

    def close(self):
        pass


class _FailingConn:
    """Raises on the request — models a transport error (connection refused)."""

    def __init__(self, host, port, timeout=None):
        pass

    def request(self, method, path, headers=None):
        raise OSError("connection refused")

    def getresponse(self):  # pragma: no cover - request() raises first
        raise OSError("connection refused")

    def close(self):
        pass


def _install_fake_conn(monkeypatch, status, headers=None, body=b"") -> None:
    _FakeConn.requests = []
    _FakeConn.status = status
    _FakeConn.headers = headers or []
    _FakeConn.body = body
    monkeypatch.setattr(auth.http.client, "HTTPSConnection", _FakeConn)
    monkeypatch.setattr(auth.http.client, "HTTPConnection", _FakeConn)
    monkeypatch.setattr("vigil_cli.paths.add_assess_import_path", lambda _root: None)


def _identity_with_liveness(**liveness):
    return {"cookies": {"S": "1"}, "liveness": liveness}


def test_probe_liveness_live_on_authed_marker_and_status(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out", expect_status=200),
    )
    _install_fake_conn(monkeypatch, 200, body=b"<a href='/logout'>Sign out</a> Welcome")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "live"
    assert result["http_status"] == 200
    assert result["error"] is None
    # exactly one request; the identity cookie rode along; redirect not followed.
    assert len(_FakeConn.requests) == 1
    assert "S=1" in (_FakeConn.requests[0]["headers"].get("Cookie", ""))


def test_probe_liveness_dead_on_login_redirect_not_followed(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out", expect_status=200),
    )
    # 302 to a login page: the authed_marker is absent from the header+body haystack.
    _install_fake_conn(
        monkeypatch, 302,
        headers=[("Location", "https://portal.example.com/my.policy")], body=b"",
    )

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "dead"
    assert result["http_status"] == 302
    assert len(_FakeConn.requests) == 1  # 302 classified, never chased


def test_probe_liveness_dead_on_dead_marker_in_body(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(dead_marker="Please log in"),
    )
    _install_fake_conn(monkeypatch, 200, body=b"<h1>Please log in</h1>")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "dead"
    assert result["http_status"] == 200


def test_probe_liveness_dead_on_status_mismatch(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out", expect_status=200),
    )
    # authed_marker present but the status is wrong -> dead.
    _install_fake_conn(monkeypatch, 500, body=b"Sign out (but a 500)")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "dead"
    assert result["http_status"] == 500


def test_probe_liveness_unknown_without_liveness_signature(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    # No material.liveness configured -> classifier cannot decide -> unknown.
    monkeypatch.setattr(auth, "_active_material", lambda _d: {"cookies": {"S": "1"}})
    _install_fake_conn(monkeypatch, 200, body=b"anything at all")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "unknown"
    assert result["http_status"] == 200
    assert "no liveness signature" in result["reason"]


def test_probe_liveness_unknown_on_transport_error(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out"),
    )
    monkeypatch.setattr(auth.http.client, "HTTPSConnection", _FailingConn)
    monkeypatch.setattr(auth.http.client, "HTTPConnection", _FailingConn)
    monkeypatch.setattr("vigil_cli.paths.add_assess_import_path", lambda _root: None)

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "unknown"  # never a false verdict on transport error
    assert result["http_status"] is None
    assert result["error"]


def test_probe_liveness_rejects_non_http_url_without_network(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: {"cookies": {"S": "1"}})
    # No connection is installed; an invalid URL must be rejected before any network.
    result = auth.probe_liveness(eng, "ftp://portal.example.com/x")
    assert result["liveness"] == "unknown"
    assert result["http_status"] is None
    assert result["error"] and "invalid probe URL" in result["error"]
