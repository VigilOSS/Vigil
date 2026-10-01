"""Coverage for the `scope-explain` read-only oracle.

Two layers, mirroring `test_scope_rate_limit.py`:

* accessor tests over `scope.explain_target` — the aggregator that composes the
  existing scope primitives into one verdict struct. These pin the admission
  decision AND that the struct names *which* allow/deny entry drove it, across
  exact-host / wildcard / CIDR / carve-out / invalid-token / vendor-SaaS shapes.
* a per-command test that drives `scope_explain.run` end-to-end and asserts the
  `--json` output shape (stable key set) plus `--input-file` intake.

Fully host-side: the oracle never touches the backend or the network, so no
client stubbing is needed — only a scope.json on disk and the engagement-dir
flag.
"""
from __future__ import annotations

import argparse
import json

import pytest

from assess.commands import scope_explain
from assess.lib import scope


# Every verdict struct carries exactly this key set, always populated.
_VERDICT_KEYS = {
    "target",
    "host",
    "admitted",
    "reason",
    "allow_entry",
    "allow_entry_kind",
    "deny_entry",
    "deny_entry_kind",
    "required_headers",
    "rate_limit",
    "vendor_saas",
}


def _entries(hosts=None, out_of_scope=None, **fields):
    """Return (scope_dict, allow_entries, deny_entries) for a scope payload."""
    payload = {"hosts": list(hosts or [])}
    if out_of_scope is not None:
        payload["out_of_scope"] = list(out_of_scope)
    payload.update(fields)
    return payload, scope.scope_entries(payload), scope.out_of_scope_entries(payload)


# ---------------------------------------------------------------------------
# Aggregator (scope.explain_target) accessor coverage
# ---------------------------------------------------------------------------


def test_explain_target_exact_host_admitted() -> None:
    payload, allow, deny = _entries(hosts=["api.example.com"])
    result = scope.explain_target("api.example.com", allow, deny, payload)
    assert set(result) == _VERDICT_KEYS
    assert result["host"] == "api.example.com"
    assert result["admitted"] is True
    assert result["allow_entry"] == "api.example.com"
    assert result["allow_entry_kind"] == "bare_host"
    assert result["deny_entry"] is None
    assert "in scope" in result["reason"]


def test_explain_target_exact_host_no_sibling_match() -> None:
    # An exact-host allowlist must NOT admit a different host under it.
    payload, allow, deny = _entries(hosts=["api.example.com"])
    result = scope.explain_target("other.example.com", allow, deny, payload)
    assert result["admitted"] is False
    assert result["allow_entry"] is None
    assert "no allowlist entry" in result["reason"]


def test_explain_target_wildcard_matches_subdomain_and_apex() -> None:
    payload, allow, deny = _entries(hosts=["*.example.com"])
    sub = scope.explain_target("deep.sub.example.com", allow, deny, payload)
    assert sub["admitted"] is True
    assert sub["allow_entry"] == "*.example.com"
    assert sub["allow_entry_kind"] == "wildcard"
    # Wildcard also covers the bare apex (HackerOne / Bugcrowd / VDP convention).
    apex = scope.explain_target("example.com", allow, deny, payload)
    assert apex["admitted"] is True
    assert apex["allow_entry_kind"] == "wildcard"


def test_explain_target_cidr_admits_in_range_address() -> None:
    payload, allow, deny = _entries(hosts=["10.0.0.0/24"])
    inside = scope.explain_target("10.0.0.5", allow, deny, payload)
    assert inside["admitted"] is True
    assert inside["allow_entry"] == "10.0.0.0/24"
    assert inside["allow_entry_kind"] == "cidr"
    # An address outside the block is not admitted.
    outside = scope.explain_target("10.0.1.5", allow, deny, payload)
    assert outside["admitted"] is False
    assert outside["allow_entry"] is None


def test_explain_target_out_of_scope_carve_out_denied() -> None:
    # In-scope wildcard, but a denylist carve-out wins (denylist beats allowlist).
    payload, allow, deny = _entries(
        hosts=["*.example.com"], out_of_scope=["bad.example.com"]
    )
    result = scope.explain_target("bad.example.com", allow, deny, payload)
    assert result["admitted"] is False
    assert result["deny_entry"] == "bad.example.com"
    assert result["deny_entry_kind"] == "bare_host"
    # The allow entry still matched — the struct surfaces both sides of the call.
    assert result["allow_entry"] == "*.example.com"
    assert "denied by out-of-scope" in result["reason"]


def test_explain_target_invalid_token_reports_no_host() -> None:
    payload, allow, deny = _entries(hosts=["example.com"])
    result = scope.explain_target("%%%not-a-host", allow, deny, payload)
    assert set(result) == _VERDICT_KEYS
    assert result["host"] is None
    assert result["admitted"] is False
    assert result["allow_entry"] is None
    assert result["deny_entry"] is None
    assert "invalid token" in result["reason"]


def test_explain_target_vendor_saas_labelled() -> None:
    # A vendor-SaaS-fronted host is flagged even while admitted in scope.
    payload, allow, deny = _entries(hosts=["*.salesforce.com"])
    result = scope.explain_target("tenant.my.salesforce.com", allow, deny, payload)
    assert result["admitted"] is True
    assert result["vendor_saas"] == "salesforce"
    # A plain host carries no vendor label.
    plain, _allow, _deny = _entries(hosts=["example.com"])
    assert (
        scope.explain_target("example.com", _allow, _deny, plain)["vendor_saas"]
        is None
    )


def test_explain_target_surfaces_headers_and_rate_limit() -> None:
    payload, allow, deny = _entries(
        hosts=["example.com"],
        rate_limit=5,
        required_headers={"X-Bug-Bounty": "handle"},
    )
    result = scope.explain_target("example.com", allow, deny, payload)
    assert result["required_headers"] == {"X-Bug-Bounty": "handle"}
    assert result["rate_limit"] == 5.0


# ---------------------------------------------------------------------------
# Command wiring (scope_explain.run)
# ---------------------------------------------------------------------------


def _write_scope(tmp_path, **fields) -> str:
    payload = {"hosts": ["*.example.com"], "out_of_scope": ["bad.example.com"]}
    payload.update(fields)
    (tmp_path / "scope.json").write_text(json.dumps(payload), encoding="utf-8")
    return str(tmp_path)


def _ns(engagement_dir, targets=None, input_file=None, as_json=False):
    return argparse.Namespace(
        engagement_dir=engagement_dir,
        targets=list(targets or []),
        input_file=input_file,
        as_json=as_json,
    )


def test_scope_explain_json_shape_and_verdicts(tmp_path, capsys) -> None:
    eng = _write_scope(tmp_path, required_headers={"X-Bug-Bounty": "h"})
    scope_explain.run(
        _ns(
            eng,
            targets=["good.example.com", "bad.example.com", "%%%bad"],
            as_json=True,
        )
    )
    out = capsys.readouterr().out
    results = json.loads(out)
    assert isinstance(results, list) and len(results) == 3
    for result in results:
        assert set(result) == _VERDICT_KEYS

    good, bad, invalid = results
    assert good["target"] == "good.example.com"
    assert good["admitted"] is True
    assert good["allow_entry_kind"] == "wildcard"
    assert good["required_headers"] == {"X-Bug-Bounty": "h"}

    assert bad["admitted"] is False
    assert bad["deny_entry"] == "bad.example.com"

    assert invalid["host"] is None
    assert invalid["admitted"] is False


def test_scope_explain_reads_input_file(tmp_path, capsys) -> None:
    eng = _write_scope(tmp_path)
    listing = tmp_path / "targets.txt"
    listing.write_text(
        "# a comment line\nhttps://one.example.com/path\n\ntwo.example.com\n",
        encoding="utf-8",
    )
    scope_explain.run(_ns(eng, input_file=str(listing), as_json=True))
    results = json.loads(capsys.readouterr().out)
    # The comment and blank line are dropped; the two hosts remain (URL → host).
    assert [r["target"] for r in results] == [
        "https://one.example.com/path",
        "two.example.com",
    ]
    assert all(r["admitted"] for r in results)
    assert results[0]["host"] == "one.example.com"


def test_scope_explain_vendor_saas_warning_on_stderr(tmp_path, capsys) -> None:
    eng = _write_scope(tmp_path, hosts=["*.salesforce.com"], out_of_scope=[])
    scope_explain.run(_ns(eng, targets=["tenant.my.salesforce.com"]))
    err = capsys.readouterr().err
    assert "WARN" in err
    assert "salesforce" in err


def test_scope_explain_no_targets_exits_nonzero(tmp_path, capsys) -> None:
    eng = _write_scope(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        scope_explain.run(_ns(eng))
    assert excinfo.value.code == 2
    assert "no targets" in capsys.readouterr().err


@pytest.mark.parametrize("denied", [False, True])
def test_scope_filter_single_label_targets(tmp_path, monkeypatch, capsys, denied):
    from assess.commands import filter_scope

    eng = _write_scope(
        tmp_path, hosts=["intranet"], out_of_scope=["intranet"] if denied else []
    )
    listing = tmp_path / "targets.txt"
    targets = "intranet\nhttp://intranet/\nintranet:8080\n"
    listing.write_text(targets + "other\n", encoding="utf-8")
    monkeypatch.setattr(filter_scope, "_vendor_saas_decided_hosts", lambda _cfg: set())

    filter_scope.run(argparse.Namespace(
        engagement_dir=eng, input_file=str(listing), output=None,
    ))

    assert capsys.readouterr().out == ("" if denied else targets)
