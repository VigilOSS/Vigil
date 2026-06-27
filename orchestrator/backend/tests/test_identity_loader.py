"""Tests for the named-identity adapter (depth-gate Wave 4 / identity).

Identities now live in the centralized credential store; ``identity.py`` is a
thin adapter over ``creds_client``. These tests cover:
  (a) the pure ``normalize_identities`` helper (dict-shape logic), and
  (b) the adapter's resolve/active/unknown semantics over a stubbed store.

The store itself (merge, persistence, multi-identity activation) is covered by
``test_credentials_api.py``.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib import creds_client, identity  # noqa: E402
from assess.lib.identity import DEFAULT_IDENTITY, normalize_identities  # noqa: E402


def _multi() -> dict:
    return {
        "identities": {
            "user_a": {"mode": "auth_json", "cookies": {"s": "a"}},
            "user_b": {"mode": "auth_json", "cookies": {"s": "b"}},
            "admin": {"mode": "auth_json", "headers": {"Authorization": "Bearer x"}},
        },
        "active_identity": "user_b",
    }


# -- normalize_identities (pure helper) -------------------------------------


def test_normalize_legacy_flat_to_default():
    loaded = normalize_identities(
        {"mode": "auth_json", "cookies": {"session": "abc"}, "headers": {}}
    )
    assert loaded["active_identity"] == DEFAULT_IDENTITY
    assert set(loaded["identities"]) == {DEFAULT_IDENTITY}
    assert loaded["identities"][DEFAULT_IDENTITY]["cookies"] == {"session": "abc"}


def test_normalize_multi_identity_active_selects():
    loaded = normalize_identities(_multi())
    assert set(loaded["identities"]) == {"user_a", "user_b", "admin"}
    assert loaded["active_identity"] == "user_b"


def test_normalize_active_falls_back_to_first_when_invalid():
    data = _multi()
    data["active_identity"] = "does-not-exist"
    assert normalize_identities(data)["active_identity"] == "user_a"


def test_normalize_drops_non_dict_entries():
    loaded = normalize_identities(
        {
            "identities": {"user_a": {"cookies": {}}, "bad": "not-a-dict"},
            "active_identity": "user_a",
        }
    )
    assert set(loaded["identities"]) == {"user_a"}


def test_normalize_empty():
    loaded = normalize_identities({})
    assert loaded["identities"] == {}
    assert loaded["active_identity"] == DEFAULT_IDENTITY


# -- adapter over the credential store (stubbed) ----------------------------


@pytest.fixture
def stub_store(monkeypatch):
    """Stub creds_client.load_identities — every identity.py read routes through
    it (load_identities / identity_names / resolve_identity)."""
    state = {"data": {"identities": {}, "active_identity": DEFAULT_IDENTITY}}
    monkeypatch.setattr(
        creds_client, "load_identities", lambda _eng, **_kw: state["data"]
    )
    return state


def test_load_identities_and_names(stub_store):
    stub_store["data"] = _multi()
    loaded = identity.load_identities("eng")
    assert set(loaded["identities"]) == {"user_a", "user_b", "admin"}
    assert loaded["active_identity"] == "user_b"
    assert sorted(identity.identity_names("eng")) == ["admin", "user_a", "user_b"]


def test_resolve_identity_active(stub_store):
    stub_store["data"] = _multi()
    name, material = identity.resolve_identity("eng", None)
    assert name == "user_b"
    assert material["cookies"] == {"s": "b"}


def test_resolve_identity_explicit(stub_store):
    stub_store["data"] = _multi()
    name, material = identity.resolve_identity("eng", "user_a")
    assert name == "user_a"
    assert material["cookies"] == {"s": "a"}


def test_resolve_identity_unknown_stamps_name_no_material(stub_store):
    stub_store["data"] = _multi()
    name, material = identity.resolve_identity("eng", "ghost")
    assert name == "ghost"
    assert material == {}


def test_resolve_identity_empty_store_returns_none(stub_store):
    # Empty store (no credentials / backend unreachable) -> legacy anonymous.
    name, material = identity.resolve_identity("eng", None)
    assert (name, material) == (None, {})
    assert identity.identity_names("eng") == []


# -- creds_client legacy auth.json warning (PR #40, real load path) ----------


class _Backend:
    def __init__(self, data):
        self._data = data

    def get_engagement(self, _kind):
        return self._data


def test_creds_client_warns_on_unimported_legacy_auth_json(tmp_path, monkeypatch, capsys):
    # After centralizing credentials to the backend, a pre-existing on-disk
    # auth.json is NOT auto-imported. An upgraded engagement that has auth.json but
    # zero backend rows must WARN (pointing at `vigil auth import`) instead of
    # silently resolving to anonymous and losing its identities.
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "auth.json").write_text('{"cookies": {"session": "abc"}}', encoding="utf-8")
    monkeypatch.setattr(
        creds_client, "_client",
        lambda _eng: _Backend({"identities": {}, "active_identity": DEFAULT_IDENTITY}),
    )
    creds_client._cache.clear()
    creds_client._warned.clear()

    data = creds_client.load_identities(str(eng), use_cache=False)
    assert data["identities"] == {}  # still fail-closed to anonymous
    err = capsys.readouterr().err
    assert "auth.json" in err and "vigil auth import" in err

    # Once-only: a second load does not re-warn.
    creds_client.load_identities(str(eng), use_cache=False)
    assert "auth.json" not in capsys.readouterr().err


def test_creds_client_no_warn_when_backend_has_identities(tmp_path, monkeypatch, capsys):
    # Backend already has identities -> the legacy file is irrelevant, no WARN.
    eng = tmp_path / "eng"
    eng.mkdir()
    (eng / "auth.json").write_text('{"cookies": {"session": "abc"}}', encoding="utf-8")
    monkeypatch.setattr(
        creds_client, "_client",
        lambda _eng: _Backend(
            {"identities": {"default": {"cookies": {"s": "x"}}}, "active_identity": DEFAULT_IDENTITY}
        ),
    )
    creds_client._cache.clear()
    creds_client._warned.clear()

    creds_client.load_identities(str(eng), use_cache=False)
    assert "auth.json" not in capsys.readouterr().err
