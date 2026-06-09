"""Tests for the named-identity auth.json loader (depth-gate Wave 4 / identity).

A legacy single-identity auth.json must still parse (normalized to ``default``);
a multi-identity file loads with active-identity selection; ``resolve_identity``
picks the requested / active identity and tolerates unknown names.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib.identity import (  # noqa: E402
    DEFAULT_IDENTITY,
    identity_names,
    load_identities,
    normalize_identities,
    resolve_identity,
)


def _write_auth(tmp_path: Path, data: dict) -> Path:
    (tmp_path / "auth.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def test_legacy_flat_auth_normalizes_to_default(tmp_path):
    eng = _write_auth(
        tmp_path,
        {"mode": "auth_json", "cookies": {"session": "abc"}, "headers": {}},
    )
    loaded = load_identities(eng)
    assert loaded["active_identity"] == DEFAULT_IDENTITY
    assert set(loaded["identities"]) == {DEFAULT_IDENTITY}
    assert loaded["identities"][DEFAULT_IDENTITY]["cookies"] == {"session": "abc"}
    assert identity_names(eng) == [DEFAULT_IDENTITY]


def test_resolve_identity_legacy_default_active(tmp_path):
    eng = _write_auth(tmp_path, {"mode": "auth_json", "cookies": {"s": "1"}})
    name, material = resolve_identity(eng, None)
    assert name == DEFAULT_IDENTITY
    assert material["cookies"] == {"s": "1"}


def _multi():
    return {
        "identities": {
            "user_a": {"mode": "auth_json", "cookies": {"s": "a"}},
            "user_b": {"mode": "auth_json", "cookies": {"s": "b"}},
            "admin": {"mode": "auth_json", "headers": {"Authorization": "Bearer x"}},
        },
        "active_identity": "user_b",
    }


def test_multi_identity_loads_and_active_selects(tmp_path):
    eng = _write_auth(tmp_path, _multi())
    loaded = load_identities(eng)
    assert set(loaded["identities"]) == {"user_a", "user_b", "admin"}
    assert loaded["active_identity"] == "user_b"
    assert sorted(identity_names(eng)) == ["admin", "user_a", "user_b"]


def test_resolve_identity_active(tmp_path):
    eng = _write_auth(tmp_path, _multi())
    name, material = resolve_identity(eng, None)
    assert name == "user_b"
    assert material["cookies"] == {"s": "b"}


def test_resolve_identity_explicit(tmp_path):
    eng = _write_auth(tmp_path, _multi())
    name, material = resolve_identity(eng, "user_a")
    assert name == "user_a"
    assert material["cookies"] == {"s": "a"}


def test_resolve_identity_unknown_stamps_name_no_material(tmp_path):
    eng = _write_auth(tmp_path, _multi())
    name, material = resolve_identity(eng, "ghost")
    assert name == "ghost"
    assert material == {}


def test_active_identity_falls_back_to_first_when_invalid(tmp_path):
    data = _multi()
    data["active_identity"] = "does-not-exist"
    loaded = normalize_identities(data)
    assert loaded["active_identity"] == "user_a"


def test_missing_auth_json_yields_empty(tmp_path):
    loaded = load_identities(tmp_path)
    assert loaded["identities"] == {}
    assert loaded["active_identity"] == DEFAULT_IDENTITY
    assert resolve_identity(tmp_path, None) == (None, {})


def test_invalid_json_yields_empty(tmp_path):
    (tmp_path / "auth.json").write_text("{not json", encoding="utf-8")
    loaded = load_identities(tmp_path)
    assert loaded["identities"] == {}


def test_multi_identity_drops_non_dict_entries(tmp_path):
    eng = _write_auth(
        tmp_path,
        {"identities": {"user_a": {"cookies": {}}, "bad": "not-a-dict"},
         "active_identity": "user_a"},
    )
    loaded = load_identities(eng)
    assert set(loaded["identities"]) == {"user_a"}
