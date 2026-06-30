"""Tests for program-mandated attribution-header injection in ``kali_exec``.

Bug-bounty programs (e.g. BugCrowd) require an attribution header — such as
``X-Bug-Bounty: <handle>`` — on every in-scope HTTP probe. ``kali.py`` injects
those headers at the single ``kali_exec`` chokepoint via a four-way classifier:

  * INJECTABLE (curl/httpx/nuclei/ffuf/sqlmap/katana) → append ``-H``.
  * FLAG-MAP (whatweb ``--header`` / nikto ``-Add-header`` / arjun ``--headers``)
    → HTTP-to-target tools whose header flag is NOT ``-H``; inject via the tool's
    own flag (Layer-1 I-3 extension; see ``_REQUIRED_HEADER_FLAG_SPECS``).
  * SKIP (gau/waybackurls/subfinder/amass/dnsx/nmap/naabu/masscan/puredns) →
    passive/archive/DNS/L3-L4, never reaches the in-scope target, so silently
    skip (no leak of the handle to web.archive.org / DNS APIs).
  * else (wafw00f/httprobe/unknown) → WARN (never block); cmd unchanged. wafw00f's
    ``-H``/``--headers`` reads a FILE not an inline string, and httprobe has no
    header flag at all, so neither can carry the marker inline — the Layer-2
    fail-closed backstop (ADR 0010) refuses an un-attributed in-scope run instead.

These tests cover the pure ``_apply_required_headers`` classifier and the
``_required_headers`` scope reader. The full ``kali_exec`` wiring (audit argv,
stderr warning) is exercised indirectly by ``test_kali_cli.py``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "agent" / "scripts"))

from assess.lib import kali  # noqa: E402


# -- _apply_required_headers (pure classifier) ------------------------------

_HEADERS = {"X-Bug-Bounty": "handle"}


@pytest.mark.parametrize("tool", ["curl", "httpx", "nuclei", "ffuf", "sqlmap", "katana", "dalfox"])
def test_injectable_tools_append_header_exact(tool):
    cmd = [tool, "https://target.example"]
    status = kali._apply_required_headers(cmd, tool, _HEADERS)
    assert status == "injected"
    # Exact formatting: -H followed by "Name: Value".
    assert cmd == [tool, "https://target.example", "-H", "X-Bug-Bounty: handle"]


# whatweb/nikto/arjun are HTTP-to-target tools whose attribution-header flag is
# NOT curl's ``-H`` (whatweb ``--header``, nikto ``-Add-header``, arjun
# ``--headers``), so Layer 1 (I-3) injects via the tool's own flag rather than
# warning. Exhaustive idempotency / arjun-single-block-merge coverage lives in the
# assess suite's test_required_headers_shell_inject.py; here we pin the four-way
# reclassification (was WARN) through kali.py's back-compat re-export.
@pytest.mark.parametrize(
    "tool, flag", [("whatweb", "--header"), ("nikto", "-Add-header"), ("arjun", "--headers")]
)
def test_flag_map_tools_inject_via_own_flag(tool, flag):
    cmd = [tool, "https://target.example"]
    status = kali._apply_required_headers(cmd, tool, _HEADERS)
    assert status == "injected"
    assert cmd == [tool, "https://target.example", flag, "X-Bug-Bounty: handle"]


@pytest.mark.parametrize(
    "tool",
    ["gau", "waybackurls", "subfinder", "amass", "dnsx", "nmap", "naabu", "masscan", "puredns", "tlsx"],
)
def test_skip_tools_unchanged(tool):
    cmd = [tool, "target.example"]
    original = list(cmd)
    status = kali._apply_required_headers(cmd, tool, _HEADERS)
    assert status == "skipped"
    assert cmd == original


# wafw00f (its ``-H``/``--headers`` reads a FILE, not an inline string), httprobe
# (sends HTTP to the target but has NO header flag) and any unknown tool must WARN:
# none can carry the marker inline, so Layer 1 leaves the cmd untouched and the
# Layer-2 backstop refuses the un-attributed in-scope run. (whatweb/nikto/arjun
# used to land here but now inject via their own flag — see the FLAG-MAP test.)
@pytest.mark.parametrize("tool", ["wafw00f", "httprobe", "some-unknown-tool"])
def test_non_injectable_http_tools_warn_unchanged(tool):
    cmd = [tool, "https://target.example"]
    original = list(cmd)
    status = kali._apply_required_headers(cmd, tool, _HEADERS)
    assert status == "warned"
    assert cmd == original


def test_empty_headers_is_noop():
    cmd = ["curl", "https://target.example"]
    original = list(cmd)
    assert kali._apply_required_headers(cmd, "curl", {}) == "noop"
    assert cmd == original


def test_classifier_is_case_insensitive_on_tool_name():
    cmd = ["CURL", "https://target.example"]
    status = kali._apply_required_headers(cmd, "CURL", _HEADERS)
    assert status == "injected"
    assert cmd[-2:] == ["-H", "X-Bug-Bounty: handle"]


def test_idempotent_when_header_already_present():
    cmd = ["curl", "-H", "X-Bug-Bounty: handle", "https://target.example"]
    original = list(cmd)
    status = kali._apply_required_headers(cmd, "curl", _HEADERS)
    assert status == "noop"
    assert cmd == original


def test_idempotent_case_insensitive_header_name():
    # Identity injected the same header with different casing / spacing.
    cmd = ["curl", "-H", "x-bug-bounty : handle", "https://target.example"]
    original = list(cmd)
    status = kali._apply_required_headers(cmd, "curl", _HEADERS)
    assert status == "noop"
    assert cmd == original


def test_partial_overlap_injects_only_missing():
    headers = {"X-Bug-Bounty": "handle", "X-Program": "acme"}
    cmd = ["curl", "-H", "X-Bug-Bounty: handle", "https://target.example"]
    status = kali._apply_required_headers(cmd, "curl", headers)
    assert status == "injected"
    # Only the missing header is appended; existing one is not duplicated.
    assert cmd.count("X-Bug-Bounty: handle") == 1
    assert cmd[-2:] == ["-H", "X-Program: acme"]


def test_multiple_headers_preserve_insertion_order():
    headers = {"X-Bug-Bounty": "handle", "X-Program": "acme", "X-Extra": "z"}
    cmd = ["nuclei", "-u", "https://target.example"]
    status = kali._apply_required_headers(cmd, "nuclei", headers)
    assert status == "injected"
    assert cmd[3:] == [
        "-H",
        "X-Bug-Bounty: handle",
        "-H",
        "X-Program: acme",
        "-H",
        "X-Extra: z",
    ]


# -- _required_headers (scope.json reader) ----------------------------------


def _write_scope(tmp_path: Path, payload) -> Path:
    scope = tmp_path / "scope.json"
    scope.write_text(json.dumps(payload), encoding="utf-8")
    return tmp_path


def test_required_headers_reads_pairs(tmp_path):
    eng = _write_scope(tmp_path, {"required_headers": {"X-Bug-Bounty": "handle"}})
    assert kali._required_headers(eng) == {"X-Bug-Bounty": "handle"}


def test_required_headers_missing_field(tmp_path):
    eng = _write_scope(tmp_path, {"engagement_type": "web"})
    assert kali._required_headers(eng) == {}


def test_required_headers_missing_scope(tmp_path):
    assert kali._required_headers(tmp_path) == {}


def test_required_headers_non_dict(tmp_path):
    eng = _write_scope(tmp_path, {"required_headers": ["X-Bug-Bounty"]})
    assert kali._required_headers(eng) == {}


def test_required_headers_drops_non_string_values(tmp_path):
    eng = _write_scope(
        tmp_path,
        {"required_headers": {"X-Bug-Bounty": "handle", "X-Num": 5, "": "blank", "X-Null": None}},
    )
    assert kali._required_headers(eng) == {"X-Bug-Bounty": "handle"}


def test_required_headers_malformed_json(tmp_path):
    scope = tmp_path / "scope.json"
    scope.write_text("{not valid json", encoding="utf-8")
    assert kali._required_headers(tmp_path) == {}
