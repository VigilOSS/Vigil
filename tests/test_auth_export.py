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
