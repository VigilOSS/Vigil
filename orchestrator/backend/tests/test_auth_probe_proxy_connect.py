"""A proxy's CONNECT reply must never be read as the origin's verdict.

Behind an HTTP egress proxy, `curl -i` on an https URL prints the tunnel's own
status line — `HTTP/1.1 200 Connection established` — before the origin's
response. The keepalive probe took the FIRST status line out of the blob, so a
revoked session answering 401 would have been classified LIVE and persisted as
such: a false-positive liveness verdict, the exact failure this subsystem was
hardened against.

Two layers close it: the probe argv passes `--suppress-connect-headers` so the
CONNECT block never enters the blob, and the parser skips tunnel/1xx preamble so
a blob that still carries one is read correctly anyway.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "src"))

from vigil_cli.auth import (  # noqa: E402
    _classify_probe,
    _parse_probe_blob,
    _vigil_assess_argv,
)
from vigil_cli import auth  # noqa: E402

# A real tunnelled `curl -i` blob: the proxy answers CONNECT, then the origin
# rejects the revoked session.
_PROXY_401 = (
    "HTTP/1.1 200 Connection established\r\n"
    "Proxy-Agent: corporate-egress/2.1\r\n"
    "\r\n"
    "HTTP/1.1 401 Unauthorized\r\n"
    "WWW-Authenticate: Bearer realm=\"app\"\r\n"
    "Content-Type: application/json\r\n"
    "\r\n"
    '{"error":"session expired"}'
)


def test_proxy_connect_status_is_not_read_as_the_origin_status():
    parsed = _parse_probe_blob(_PROXY_401, anchor_cookies=("MRHSession",))
    assert parsed["status"] == 401
    assert parsed["status_line"] == "HTTP/1.1 401"


def test_revoked_session_behind_a_proxy_classifies_dead_not_live():
    # 401 is positive evidence of death; reading the tunnel's 200 instead would
    # have reported a revoked session as healthy.
    verdict, _reason = _classify_probe(
        _parse_probe_blob(_PROXY_401, anchor_cookies=("MRHSession",)),
        _PROXY_401,
        {"expect_status": 200, "authed_marker": "Sign out"},
    )
    assert verdict == "dead"


def test_informational_preamble_is_skipped_too():
    raw = (
        "HTTP/1.1 100 Continue\r\n"
        "\r\n"
        "HTTP/1.1 401 Unauthorized\r\n"
        "\r\n"
        "denied"
    )
    assert _parse_probe_blob(raw, anchor_cookies=())["status"] == 401


def test_a_direct_response_is_still_read_from_its_own_status_line():
    raw = 'HTTP/2 200 \r\nContent-Type: text/html\r\n\r\n<p>Sign out</p>'
    assert _parse_probe_blob(raw, anchor_cookies=())["status"] == 200


def test_a_status_line_quoted_in_the_body_never_wins():
    # Last-match selection would pick the logged status out of the body; the
    # origin's own line is the first non-preamble match and stops the scan.
    raw = (
        "HTTP/1.1 200 Connection established\r\n\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<pre>last upstream reply was HTTP/1.1 503 Service Unavailable</pre>"
    )
    assert _parse_probe_blob(raw, anchor_cookies=())["status"] == 200


def test_escaped_envelope_blob_is_parsed_the_same_way():
    # The real input is the kali-exec JSON envelope, where the response newlines
    # arrive as literal \\r\\n escapes inside stdout_preview.
    raw = (
        '{"ok":true,"stdout_preview":"HTTP/1.1 200 Connection established'
        '\\r\\nProxy-Agent: egress\\r\\n\\r\\nHTTP/1.1 401 Unauthorized\\r\\n\\r\\n'
        '{\\"error\\":\\"session expired\\"}"}'
    )
    assert _parse_probe_blob(raw, anchor_cookies=())["status"] == 401


def test_blob_with_no_status_line_stays_unparsed():
    parsed = _parse_probe_blob(
        "__keepalive_probe_error__ kali exec timed out", anchor_cookies=()
    )
    assert parsed["status"] is None and parsed["status_line"] == "?"


@pytest.mark.parametrize("cli_on_path", [True, False])
def test_probe_argv_suppresses_the_connect_block(tmp_path, monkeypatch, cli_on_path):
    workspace = tmp_path / "workspace"
    engagement = workspace / "engagements" / "acme"
    engagement.mkdir(parents=True)
    monkeypatch.setenv("VIGIL_INSTALL_DIR", str(workspace))
    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "missing-config.json"))
    monkeypatch.setenv("VIGIL_APPLICATION_DIR", str(repo_root))
    monkeypatch.setattr(auth.shutil, "which", lambda _name: "/usr/local/bin/vigil" if cli_on_path else None)
    argv = _vigil_assess_argv(engagement, "cap-target", "https://app.example.com/me")
    assert argv[0] == ("/usr/local/bin/vigil" if cli_on_path else str(repo_root / "agent/scripts/assess.py"))
    assert "--suppress-connect-headers" in argv
    # It is a curl flag, so it must sit after the `--` argv separator.
    assert argv.index("--") < argv.index("--suppress-connect-headers")
