"""Unit tests for `assess.lib.params.header_schema_from_headers`.

The helper is shared by the two dominant capture writers (`ingest_endpoints.py`
and `proxy_addon.py`) to reduce captured request headers to a stable
``{name: ""}`` header_schema. header_schema is PART of the request-variant dedup
hash and drives the depth ledger's CORS/proxy presence triggers, so its filter
set is load-bearing: it must keep attack-relevant/app-specific header NAMES and
drop hop-by-hop, browser-fingerprint, and already-captured-elsewhere noise that
would fork variants without adding coverage signal.
"""
from __future__ import annotations

from assess.lib.params import header_schema_from_headers


def test_keeps_attack_and_app_headers_drops_noise():
    schema = header_schema_from_headers(
        {
            "X-Forwarded-Host": "evil",   # attack-relevant → kept
            "X-Original-URL": "/admin",   # attack-relevant → kept
            "X-Api-Key": "demo",          # app-specific → kept
            "X-Csrf-Token": "t",          # app-specific → kept
            "Host": "h",                  # target identity → dropped
            "Connection": "keep-alive",   # hop-by-hop → dropped
            "Content-Length": "3",        # transport/body-size → dropped
            "Content-Type": "application/json",  # own schema slot → dropped
            "Cookie": "sid=1",            # own schema slot → dropped
            "Authorization": "Bearer x",  # auth_context → dropped
            "User-Agent": "curl",         # browser noise → dropped
            "Accept": "*/*",              # browser noise → dropped
            "Sec-Fetch-Mode": "cors",     # browser noise → dropped
            "Origin": "https://a",        # volatile browser noise → dropped
        }
    )
    assert set(schema) == {"X-Forwarded-Host", "X-Original-URL", "X-Api-Key", "X-Csrf-Token"}
    assert all(v == "" for v in schema.values())  # NAMES only, values discarded


def test_accepts_list_of_names():
    assert header_schema_from_headers(["X-Rewrite-URL", "Accept", "X-Custom"]) == {
        "X-Rewrite-URL": "",
        "X-Custom": "",
    }


def test_accepts_json_string_of_dict():
    assert header_schema_from_headers('{"X-Http-Method-Override": "DELETE", "Host": "h"}') == {
        "X-Http-Method-Override": ""
    }


def test_drops_http2_pseudo_headers():
    assert header_schema_from_headers({":method": "GET", ":authority": "h", "X-Real-IP": "1"}) == {
        "X-Real-IP": ""
    }


def test_case_insensitive_noise_match_and_dedup():
    # Noise match is case-insensitive; first-seen casing of a kept name survives.
    assert header_schema_from_headers({"USER-AGENT": "x", "x-forwarded-for": "1.2.3.4"}) == {
        "x-forwarded-for": ""
    }


def test_unparseable_and_empty_inputs_are_noops():
    assert header_schema_from_headers(None) == {}
    assert header_schema_from_headers("") == {}
    assert header_schema_from_headers("not json at all") == {}
    assert header_schema_from_headers(42) == {}
