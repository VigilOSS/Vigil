"""Target-anchor extraction — the one parse three runtime consumers depend on.

``kali_audit._extract_target_anchor`` decides three different things at once:

  * where the ``--resolve`` pin points the runtime's DNS (``kali_resolve``);
  * which host's cookies an ``--identity`` run may carry (``kali._apply_identity_material``);
  * which app unit an auto-emitted probe_run earns depth credit against (``kali._emit_probe_run``).

Its predecessor was a single loose scan — the first whitespace-delimited word in
argv starting with ``http://`` or containing a dot. That produced four separate
defects, all pinned here:

  * a ``bash -c`` body was invisible (the URL carried a leading quote), so every
    ``--identity`` run on the documented escape hatch refused with an empty
    request host;
  * an ``-H 'Origin: https://attacker'`` value outranked the real positional URL,
    letting attacker-controlled REQUEST CONTENT steer runtime networking;
  * a session cookie and a line of Python source parsed as multi-hundred-char
    "hostnames", which the backend refused on its 256-char cap — discarding the
    whole probe row and silently skipping the depth harness for that run.

The negative cases here are the point: an UNANCHORED probe is honest, a
mis-anchored one is not.
"""
from __future__ import annotations

import pytest

from assess.lib import kali_resolve
from assess.lib.kali_audit import _extract_target_anchor, _is_plausible_host


# --------------------------------------------------------------------------- #
# Shell wrappers are lexed, not whitespace-split.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        "curl -s 'https://api.example.com/v1/x'",
        'curl -s "https://api.example.com/v1/x"',
        "curl -s https://api.example.com/v1/x",
    ],
)
def test_shell_c_body_resolves_its_url_however_it_is_quoted(body):
    assert _extract_target_anchor("curl", ["bash", "-c", body]) == (
        "api.example.com",
        "/v1/x",
        None,
    )
    assert kali_resolve.target_host_port("curl", ["bash", "-c", body]) == (
        "api.example.com",
        443,
    )


def test_multi_command_shell_body_anchors_on_the_first_target():
    cmd = [
        "bash",
        "-c",
        "curl -s https://first.example.com/a; curl -s https://second.example.com/b",
    ]
    assert _extract_target_anchor("curl", cmd)[0] == "first.example.com"


def test_unlexable_shell_body_is_unanchored_and_does_not_raise():
    cmd = ["bash", "-c", "curl -s 'https://x.example.com"]
    assert _extract_target_anchor("curl", cmd) == ("", "", None)
    assert kali_resolve.target_host_port("curl", cmd) == ("", 0)


# --------------------------------------------------------------------------- #
# Option VALUES never steer the anchor (I-187L).
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "hazard",
    [
        ["-H", "Origin: https://attacker.example.com"],
        ["--header", "Referer: https://attacker.example.com/x"],
        ["--header=Origin: https://attacker.example.com"],
        ["-b", "sess=https://attacker.example.com"],
        ["--cookie", "sess=https://attacker.example.com"],
        ["-e", "https://attacker.example.com"],
        ["--referer", "https://attacker.example.com"],
        ["-x", "http://attacker.example.com:8080"],
        ["--proxy", "http://attacker.example.com:8080"],
        ["--data-raw", "next=https://attacker.example.com"],
        ["-d", "next=https://attacker.example.com"],
        ["-A", "curl/8 (https://attacker.example.com)"],
        ["-o", "https://attacker.example.com"],
        ["-u", "https://attacker.example.com"],
    ],
)
def test_option_values_never_outrank_the_positional_url(hazard):
    cmd = ["curl", "-sS", *hazard, "https://api.target.example.net:8443/v1/orders"]
    assert _extract_target_anchor("curl", cmd) == (
        "api.target.example.net",
        "/v1/orders",
        8443,
    )
    assert kali_resolve.target_host_port("curl", cmd) == (
        "api.target.example.net",
        8443,
    )


def test_header_only_argv_is_unanchored_rather_than_anchored_on_the_header():
    """No positional URL means no target. A hazard value is DROPPED, never
    demoted to a fallback candidate — falling back to ``Origin`` would leave the
    exact defect in place for the argv shape that triggered it."""
    cmd = ["curl", "-sS", "-H", "Origin: https://attacker.example.com"]
    assert _extract_target_anchor("curl", cmd) == ("", "", None)
    assert kali_resolve.target_host_port("curl", cmd) == ("", 0)


def test_shell_wrapped_header_value_is_skipped_too():
    cmd = [
        "bash",
        "-c",
        "curl -sS -H 'Origin: https://attacker.example.com' https://real.example.com/x",
    ]
    assert _extract_target_anchor("curl", cmd)[0] == "real.example.com"


def test_default_port_reads_the_target_scheme_not_a_proxy_url():
    """``-x http://proxy`` must not drag an HTTPS target's pin down to port 80."""
    cmd = ["curl", "-x", "http://proxy.example.com:8080", "https://api.example.com/v1"]
    assert kali_resolve.target_host_port("curl", cmd) == ("api.example.com", 443)


# --------------------------------------------------------------------------- #
# A scheme-less word must look like an address (I-138a / I-183).
# --------------------------------------------------------------------------- #


def test_inlined_session_token_never_becomes_a_hostname():
    cookie = "planner-session." + "A" * 300 + ".example"
    cmd = ["bash", "-c", f"curl -b {cookie} https://real.example.com/x"]
    host, _path, _port = _extract_target_anchor("curl", cmd)
    assert host == "real.example.com"
    assert len(host) <= 253


def test_python_source_yields_neither_a_host_nor_a_source_shaped_path():
    cmd = [
        "python3",
        "-c",
        "import requests;r=requests.get('https://api.example.com/v1/x',"
        "headers={'a':'b'});print(r.status_code)",
    ]
    assert _extract_target_anchor("python3", cmd) == ("", "", None)


@pytest.mark.parametrize(
    "word",
    ["README", "results.d", "output.tmp.q", "-notaflag"],
)
def test_dotted_words_that_are_not_addresses_do_not_anchor(word):
    assert _extract_target_anchor("curl", ["curl", word]) == ("", "", None)


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        (["curl", "example.com/api"], ("example.com", "/api", None)),
        (["curl", "http://localhost:8080/x"], ("localhost", "/x", 8080)),
        # A compose alias / internal single-label host is a real target here.
        (["curl", "http://target/x"], ("target", "/x", None)),
        (["curl", "target:8080/x"], ("target", "/x", 8080)),
        (["curl", "http://10.0.0.5/x"], ("10.0.0.5", "/x", None)),
        (["curl", "https://[2001:db8::1]:8443/path"], ("2001:db8::1", "/path", 8443)),
        (["curl", "https://xn--p1ai.xn--p1ai/x"], ("xn--p1ai.xn--p1ai", "/x", None)),
        (["curl", "https://user:pw@target.test/v1?id=1"], ("target.test", "/v1", None)),
    ],
)
def test_legitimate_target_shapes_still_anchor(cmd, expected):
    assert _extract_target_anchor("curl", cmd) == expected


# --------------------------------------------------------------------------- #
# The flag-driven per-tool branches are untouched.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("tool", "cmd", "expected"),
    [
        ("httpx", ["httpx", "-u", "https://www.example.com:8443/path"],
         ("www.example.com", "/path", 8443)),
        ("nuclei", ["nuclei", "-u", "http://api.target.test"], ("api.target.test", "", None)),
        ("nuclei", ["nuclei", "-l", "/engagements/x/hosts.txt"], ("", "", None)),
        ("ffuf", ["ffuf", "-u", "https://Admin.Example.test/FUZZ", "-w", "/tmp/w.txt"],
         ("admin.example.test", "/", None)),
        ("sqlmap", ["sqlmap", "-u", "https://user:pass@target.test/v1?id=1"],
         ("target.test", "/v1", None)),
        ("katana", ["katana", "--url", "https://k.example.com/"], ("k.example.com", "/", None)),
    ],
)
def test_flag_driven_tools_read_their_own_target_flag(tool, cmd, expected):
    assert _extract_target_anchor(tool, cmd) == expected


def test_flag_driven_tool_inside_a_shell_body_is_now_reachable():
    """``bash -c 'katana -u …'`` used to be unanchored: the flag scan ran over the
    shell's argv, where ``-u`` is not a token. Lexing the body fixes both."""
    cmd = ["bash", "-c", "katana -u https://k.example.com/ -jc"]
    assert _extract_target_anchor("katana", cmd)[0] == "k.example.com"


def test_ffuf_fuzz_marker_is_stripped_before_the_host_parse():
    cmd = ["ffuf", "-u", "https://FUZZ.example.test/", "-w", "/tmp/w.txt"]
    assert _extract_target_anchor("ffuf", cmd) == ("", "", None)


# --------------------------------------------------------------------------- #
# The shared hostname bound.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host", ["example.com", "target", "10.0.0.5", "2001:db8::1", "xn--p1ai.ru", "a.b.c.d.e"]
)
def test_plausible_hosts_are_accepted(host):
    assert _is_plausible_host(host)


@pytest.mark.parametrize(
    "host",
    [
        "",
        "A" * 254,
        "planner-session." + "A" * 300 + ".example",
        "has space.example.com",
        "under_score.example.com",
        "-leadinghyphen.example.com",
        "requests.get(x)",
    ],
)
def test_implausible_hosts_are_rejected(host):
    assert not _is_plausible_host(host)
