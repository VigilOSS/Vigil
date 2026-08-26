"""Regression coverage for three PR-43 review fixes in the host-side vigil_cli:

* auth keepalive: `<anchor>=deleted` teardown detection is case-insensitive.
* engagement export: the internal OPERATOR DETAILS section is stripped from PDFs.
* quickstart: printed next-commands are shell-quoted so they copy-paste safely.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo_root))
sys.path.insert(0, str(repo_root / "src"))

from vigil_cli.auth import _parse_probe_blob  # noqa: E402
from vigil_cli.engagements import _strip_operator_details  # noqa: E402
from vigil_cli.quickstart import _next_commands  # noqa: E402


# --------------------------------------------------------------------------- #
# auth.py — case-insensitive deletion-cookie teardown
# --------------------------------------------------------------------------- #
def test_probe_blob_detects_uppercase_deleted_teardown():
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: MRHSession=DELETED; path=/\r\n"
    assert _parse_probe_blob(raw, anchor_cookies=("MRHSession",))["deleted"] is True


def test_probe_blob_detects_mixedcase_deleted_teardown():
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: MRHSession=Deleted; path=/\r\n"
    assert _parse_probe_blob(raw, anchor_cookies=("MRHSession",))["deleted"] is True


def test_probe_blob_lowercase_deleted_still_detected():
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: MRHSession=deleted; path=/\r\n"
    assert _parse_probe_blob(raw, anchor_cookies=("MRHSession",))["deleted"] is True


def test_probe_blob_live_session_not_flagged_deleted():
    raw = "HTTP/1.1 200 OK\r\nSet-Cookie: MRHSession=live-token-abc; path=/\r\n"
    assert _parse_probe_blob(raw, anchor_cookies=("MRHSession",))["deleted"] is False


# --------------------------------------------------------------------------- #
# engagements.py — strip OPERATOR DETAILS before rendering a submission PDF
# --------------------------------------------------------------------------- #
def test_strip_operator_details_removes_reference_section():
    md = (
        "# XSS in search\n\nBody the triager reads.\n\n"
        "---\n\n"
        "## OPERATOR DETAILS — NOT FOR SUBMISSION (reference only — never paste anything below this line)\n\n"
        "**Hygiene warnings**: internal-host-name-leak\n\n"
        "poc_curl: curl https://internal.example\n"
    )
    out = _strip_operator_details(md)
    assert "Body the triager reads." in out
    assert "OPERATOR DETAILS" not in out
    assert "internal.example" not in out
    assert "Hygiene warnings" not in out
    # The trailing `---` divider that introduced the section is gone too.
    assert not out.rstrip().endswith("---")


def test_strip_operator_details_noop_without_section():
    md = "# Incident report\n\nAll findings resolved.\n"
    assert _strip_operator_details(md) == md


# --------------------------------------------------------------------------- #
# quickstart.py — shell-quote generated next-commands
# --------------------------------------------------------------------------- #
def test_next_commands_shell_quote_target_and_install_root():
    cmds = _next_commands(
        Path("/opt/vigil root"),
        "https://target.test/?a=1&b=2",
        "a.test, b.test",
    )
    create = next(c for c in cmds if c.startswith("vigil engagement create"))
    # The `&` and whitespace survive a round-trip through the shell as ONE token
    # each, instead of splitting/backgrounding the command.
    assert shlex.split(create) == [
        "vigil",
        "engagement",
        "create",
        "https://target.test/?a=1&b=2",
        "--hosts",
        "a.test, b.test",
    ]
    install = next(c for c in cmds if c.startswith("vigil install"))
    assert shlex.split(install) == ["vigil", "install", "/opt/vigil root"]
