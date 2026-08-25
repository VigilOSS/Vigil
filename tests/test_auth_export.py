"""`vigil auth export` host-scoped cookie selection (I-22, multi-host engagements).

`export_curl_args(host=...)` selects the per-host `host_cookies` bucket and uses it
ALONE, the same host-scoped lookup the proxy applies at injection time. The flat
`cookies` field is a UNION across every captured host, so it is used only as a
fallback for identities with NO per-host buckets — blending it in when a bucket
matches (or falling back to it when buckets exist but none match the target host)
would leak another host's session cookies (cross-host session bleed). Without
`--host`, only the flat view is rendered — which on a multi-host engagement can be
the wrong (or empty) session for the target host.

The per-host *selection* logic (`assess.lib.identity.host_cookies_for`) is covered
by `agent/scripts/assess/tests/test_identity_cookies.py`; these tests cover the CLI
wiring — that `--host` reaches the selection and honors the bucket-alone / gated-
fallback invariant (and that `_authed_request_headers`, backing `auth status
--probe`, does the same). The dynamic assess import is stubbed so the test is
decoupled from the install-root layout the CLI resolves at runtime.
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
    """No-op the install-root path insert and inject faithful stubs of
    ``assess.lib.identity.host_cookies_for`` (returns a host's bucket) and
    ``host_cookie_hosts`` (hosts with a non-empty captured bucket) — the pair the
    bucket-alone / gated-fallback invariant is built on."""
    monkeypatch.setattr("vigil_cli.paths.add_assess_import_path", lambda _root: None)

    def host_cookies_for(material: dict, host: str) -> dict[str, str]:
        for bucket in material.get("host_cookies", []):
            if bucket.get("host") == host:
                return dict(bucket.get("cookies", {}))
        return {}

    def host_cookie_hosts(material: dict) -> list[str]:
        return [
            b["host"]
            for b in material.get("host_cookies", [])
            if b.get("host") and b.get("cookies")
        ]

    identity_mod = types.ModuleType("assess.lib.identity")
    identity_mod.host_cookies_for = host_cookies_for  # type: ignore[attr-defined]
    identity_mod.host_cookie_hosts = host_cookie_hosts  # type: ignore[attr-defined]
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


def test_export_with_host_uses_that_hosts_bucket_alone(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _material())
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="b.example.com")

    # b's captured session is used ALONE — the flat union is NOT blended in
    # (blending would leak cookies unique to other hosts).
    assert "bsess=B" in out
    assert "flat=F" not in out


def test_export_with_host_that_has_no_bucket_omits_cookies(tmp_path, monkeypatch):
    # BUG 2 regression: buckets EXIST (for b) but none match the target host (c).
    # The flat ``cookies`` union must NOT be routed onto c — cookies are omitted
    # entirely rather than leaked cross-host.
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: _material())
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="c.example.com")

    assert "flat=F" not in out  # display-only union NOT routed onto unrelated host
    assert "bsess=B" not in out
    assert "-H 'Cookie:" not in out  # no Cookie header at all
    assert "-H 'X-Api: K'" in out  # non-cookie headers still exported


def test_export_with_no_buckets_falls_back_to_flat_view(tmp_path, monkeypatch):
    # Legacy/manual identity with NO per-host buckets: the flat view is the only
    # cookie view, so the gated fallback still renders it (backwards compatible).
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material", lambda _d: {"cookies": {"flat": "F"}, "headers": {}}
    )
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="anything.example.com")

    assert "flat=F" in out  # no buckets → flat fallback fires


def test_export_with_host_drops_other_hosts_union_cookies(tmp_path, monkeypatch):
    # BUG 2 regression (sharpest form): the flat ``cookies`` field is a UNION
    # across hosts a and b. Exporting for host a must carry ONLY a's cookie; b's
    # uniquely-named cookie must not survive from the union into the printed
    # ``-H 'Cookie: …'``.
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    material = {
        "cookies": {"asess": "A", "bsess": "B"},  # capture-time UNION across a + b
        "host_cookies": [
            {"host": "a.example.com", "cookies": {"asess": "A"}},
            {"host": "b.example.com", "cookies": {"bsess": "B"}},
        ],
        "headers": {},
    }
    monkeypatch.setattr(auth, "_active_material", lambda _d: material)
    _stub_assess_identity(monkeypatch)

    out = auth.export_curl_args(eng, host="a.example.com")

    assert "asess=A" in out
    assert "bsess=B" not in out  # b's cookie must NOT bleed onto a


# --------------------------------------------------------------------------- #
# `_authed_request_headers` (backs `vigil auth status --probe`) — the probe must
# host-scope cookies the same way export/injection do: the matching bucket ALONE,
# flat-union fallback ONLY when the identity has no buckets, omit on bucket-miss.
# --------------------------------------------------------------------------- #

def _multi_host_material() -> dict:
    return {
        "cookies": {"asess": "A", "bsess": "B"},  # capture-time UNION across a + b
        "host_cookies": [
            {"host": "a.example.com", "cookies": {"asess": "A"}},
            {"host": "b.example.com", "cookies": {"bsess": "B"}},
        ],
    }


def test_authed_probe_headers_use_matching_bucket_alone(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    _stub_assess_identity(monkeypatch)

    headers = auth._authed_request_headers(eng, _multi_host_material(), "a.example.com")

    assert "asess=A" in headers["Cookie"]
    assert "bsess=B" not in headers["Cookie"]  # b's cookie must not ride an a probe


def test_authed_probe_headers_omit_cookies_on_bucket_miss(tmp_path, monkeypatch):
    # BUG 1 regression: buckets EXIST (a, b) but none match the probed host (c).
    # The flat union must NOT be injected — no Cookie header at all.
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    _stub_assess_identity(monkeypatch)

    headers = auth._authed_request_headers(eng, _multi_host_material(), "c.example.com")

    assert "Cookie" not in headers  # cross-host union NOT leaked onto c


def test_authed_probe_headers_flat_fallback_without_buckets(tmp_path, monkeypatch):
    # Legacy/manual identity (no per-host buckets): flat view is the only cookie
    # source, so the gated fallback still injects it (backwards compatible).
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    _stub_assess_identity(monkeypatch)

    headers = auth._authed_request_headers(eng, {"cookies": {"S": "1"}}, "any.example.com")

    assert headers["Cookie"] == "S=1"


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
    # `dead` requires POSITIVE evidence of death. Everything that merely fails
    # to CONFIRM life is `unknown`, because a false `dead` retires a live
    # session and hard-blocks `kali --identity` until it is re-imported.

    # No signature configured -> unknown (the reason names the shape to set).
    assert cl(200, "Sign out", None)[0] == "unknown"
    assert cl(200, "Sign out", {})[0] == "unknown"
    # A bool is not a real int status config, so it configures nothing.
    assert cl(200, "x", {"expect_status": True})[0] == "unknown"
    # Transport error (status None) wins even with a signature present.
    assert cl(None, None, {"authed_marker": "Sign out"})[0] == "unknown"

    # POSITIVE evidence of death.
    assert cl(200, "Please sign in", {"dead_marker": "sign in"})[0] == "dead"
    assert cl(401, "nope", {"expect_status": 200})[0] == "dead"
    assert cl(
        302,
        "x\nLocation: https://h/login\n",
        {"authed_marker": "Sign out", "expect_status": 200},
    )[0] == "dead"

    # Absence of confirmation is NOT death.
    assert cl(200, "anonymous page", {"authed_marker": "Sign out"})[0] == "unknown"
    assert cl(500, "anything", {"expect_status": 200})[0] == "unknown"
    # A 3xx that is not a login bounce is a redirect, not an expiry.
    assert cl(
        302, "Sign out", {"authed_marker": "Sign out", "expect_status": 200}
    )[0] == "unknown"
    # Markers are case-sensitive substrings; a miss is inconclusive, not dead.
    assert cl(200, "sign out", {"authed_marker": "Sign out"})[0] == "unknown"

    # 403 is an AUTHORIZATION verdict, not an authentication challenge. A 403 on
    # another principal's object is the healthy IDOR/BOLA signal, so it must
    # never kill the identity doing the testing.
    assert cl(403, "forbidden", {"expect_status": 200})[0] == "unknown"

    # Confirmed life.
    assert cl(
        200, "Welcome - Sign out", {"authed_marker": "Sign out", "expect_status": 200}
    )[0] == "live"
    assert cl(200, "Sign out", {"authed_marker": "Sign out"})[0] == "live"
    assert cl(200, "welcome home", {"dead_marker": "Log in"})[0] == "live"
    assert cl(200, "Log in to continue", {"dead_marker": "Log in"})[0] == "dead"
    assert cl(200, "anything", {"expect_status": 200})[0] == "live"


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


def test_probe_liveness_unknown_on_unexplained_status_mismatch(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out", expect_status=200),
    )
    # A 500 is a server error, not an authentication challenge, and the
    # authed_marker is present. Retiring the session here would kill a live
    # identity over a transient upstream fault.
    _install_fake_conn(monkeypatch, 500, body=b"Sign out (but a 500)")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "unknown"
    assert result["http_status"] == 500


def test_probe_liveness_dead_on_auth_challenge_status(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth, "_active_material",
        lambda _d: _identity_with_liveness(authed_marker="Sign out", expect_status=200),
    )
    # A 401 says "you are not authenticated" verbatim -> positive proof of death.
    _install_fake_conn(monkeypatch, 401, body=b"unauthorized")

    result = auth.probe_liveness(eng, "https://portal.example.com/home")
    assert result["liveness"] == "dead"
    assert result["http_status"] == 401


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


def test_scoped_alias_transport_error_still_returns_resolved_identity(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(
        auth,
        "_api",
        lambda *_args, **_kwargs: {
            "identity_name": "cap-member-v2",
            "material": _identity_with_liveness(authed_marker="Sign out"),
        },
    )
    monkeypatch.setattr(auth.http.client, "HTTPSConnection", _FailingConn)
    monkeypatch.setattr(auth.http.client, "HTTPConnection", _FailingConn)

    result = auth.probe_liveness(
        eng,
        "https://portal.example.com/home",
        "member",
        scope_key="billing",
    )

    assert result["liveness"] == "unknown"
    assert result["identity_name"] == "cap-member-v2"


def test_missing_scoped_alias_is_not_probed_anonymously(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_api", lambda *_args, **_kwargs: {})

    def unexpected_connection(*_args, **_kwargs):
        raise AssertionError("missing alias must fail before network execution")

    monkeypatch.setattr(auth.http.client, "HTTPSConnection", unexpected_connection)

    result = auth.probe_liveness(
        eng,
        "https://portal.example.com/home",
        "member",
        scope_key="billing",
    )

    assert result["liveness"] == "unknown"
    assert result["identity_name"] is None
    assert "identity" in result["error"]


def test_probe_liveness_rejects_non_http_url_without_network(tmp_path, monkeypatch):
    eng = tmp_path / "agent" / "engagements" / "eng"
    eng.mkdir(parents=True)
    monkeypatch.setattr(auth, "_active_material", lambda _d: {"cookies": {"S": "1"}})
    # No connection is installed; an invalid URL must be rejected before any network.
    result = auth.probe_liveness(eng, "ftp://portal.example.com/x")
    assert result["liveness"] == "unknown"
    assert result["http_status"] is None
    assert result["error"] and "invalid probe URL" in result["error"]
