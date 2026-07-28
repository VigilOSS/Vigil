"""Best-effort required-header injection into ``sh -c``/``bash -c`` scripts.

A ``required_headers`` engagement may run a shell wrapper whose ``-c`` script
carries one or more curl/wget (or other ``-H``-capable) sub-commands. A naive
``-H`` append would land on the SHELL argv as a positional parameter and never
reach the inner tool, so ``_apply_required_headers`` parses the script text and
injects ``-H 'Name: Value'`` (``--header`` for wget) into each recognized
sub-command that lacks it.

Contract (W5):
  * BEST-EFFORT — when safe injection is not possible the function returns the
    existing ``"warned"``/``"skipped"`` status and NEVER raises or blocks. A
    missing attribution header is a reduced-reward, not a ban-risk; a hard block
    would stall a legitimate multi-curl probe mid-hunt.
  * IDEMPOTENT — a sub-command that already carries the header is left alone (no
    double-inject), even across two curls where only one already has it.
"""
from __future__ import annotations

import shlex

import pytest
from assess.lib import kali, kali_output

HDR = {"X-Bug-Bounty": "vigiloss"}


def _subcommands(script: str) -> list[list[str]]:
    """Split a script on top-level ``;``/``&&``/``||``/``|`` and shlex-parse each
    sub-command so a test can assert per-sub-command flags without depending on
    the exact quoting/spacing the injector produced."""
    out: list[list[str]] = []
    for raw in __import__("re").split(r"\s*(?:;|&&|\|\||\|)\s*", script):
        raw = raw.strip()
        if raw:
            out.append(shlex.split(raw))
    return out


def _has_header(tokens: list[str], name: str, value: str) -> bool:
    target = f"{name}: {value}".lower()
    for i, tok in enumerate(tokens):
        if tok in ("-H", "--header") and i + 1 < len(tokens):
            if tokens[i + 1].lower() == target:
                return True
    return False


# --------------------------------------------------------------------------- #
# Core scenarios required by the task
# --------------------------------------------------------------------------- #

def test_shell_two_curls_both_receive_header() -> None:
    cmd = ["sh", "-c", "curl http://a.example.com ; curl http://b.example.com"]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))

    assert status == "injected"
    assert cmd[:2] == ["sh", "-c"]
    subs = _subcommands(cmd[2])
    assert len(subs) == 2
    for tokens in subs:
        assert tokens[0] == "curl"
        assert _has_header(tokens, "X-Bug-Bounty", "vigiloss")


def test_shell_header_already_present_no_double_inject() -> None:
    # Single curl that already carries the header → idempotent no-op, untouched.
    script = "curl -H 'X-Bug-Bounty: vigiloss' http://a.example.com"
    cmd = ["sh", "-c", script]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))

    assert status == "noop"
    assert cmd[2] == script  # byte-for-byte unchanged
    assert cmd[2].count("X-Bug-Bounty") == 1


def test_shell_mixed_only_missing_curl_gets_header() -> None:
    # First curl already has it, second does not → only the second is injected.
    cmd = [
        "sh",
        "-c",
        "curl -H 'X-Bug-Bounty: vigiloss' http://a.example.com ; curl http://b.example.com",
    ]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))

    assert status == "injected"
    assert cmd[2].count("X-Bug-Bounty") == 2
    subs = _subcommands(cmd[2])
    assert len(subs) == 2
    for tokens in subs:
        # exactly one header on each, never duplicated
        assert sum(1 for t in tokens if t in ("-H", "--header")) == 1
        assert _has_header(tokens, "X-Bug-Bounty", "vigiloss")


def test_shell_non_curl_unknown_wrapper_warns_not_blocks() -> None:
    # A non-curl / non-injectable inner tool → warn-only status, argv untouched,
    # and crucially NO raise/block.
    cmd = ["sh", "-c", "whatweb https://example.com"]
    status = kali_output._apply_required_headers(cmd, "whatweb", dict(HDR))

    assert status == "warned"
    assert cmd == ["sh", "-c", "whatweb https://example.com"]


# --------------------------------------------------------------------------- #
# wget + other -H-capable tools + pipelines
# --------------------------------------------------------------------------- #

def test_shell_wget_gets_header_flag() -> None:
    cmd = ["sh", "-c", "wget http://a.example.com"]
    status = kali_output._apply_required_headers(cmd, "wget", dict(HDR))

    assert status == "injected"
    tokens = _subcommands(cmd[2])[0]
    assert tokens[0] == "wget"
    assert _has_header(tokens, "X-Bug-Bounty", "vigiloss")
    # wget's flag is --header, not -H
    assert "--header" in tokens


def test_shell_pipeline_injects_httpx_not_passive_gau() -> None:
    # gau is a skip-set passive harvester (handle must never leak to the public
    # archive); httpx is injectable. Only the httpx stage gets the header.
    cmd = ["sh", "-c", "gau example.com | httpx -silent"]
    status = kali_output._apply_required_headers(cmd, "httpx", dict(HDR))

    assert status == "injected"
    subs = _subcommands(cmd[2])
    gau_stage = next(s for s in subs if s and s[0] == "gau")
    httpx_stage = next(s for s in subs if s and s[0] == "httpx")
    assert "-H" not in gau_stage and "--header" not in gau_stage
    assert _has_header(httpx_stage, "X-Bug-Bounty", "vigiloss")


def test_bash_c_and_abs_path_variants() -> None:
    for head in ("bash", "/bin/sh", "/bin/bash"):
        cmd = [head, "-c", "curl http://a.example.com"]
        status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))
        assert status == "injected", head
        assert _has_header(_subcommands(cmd[2])[0], "X-Bug-Bounty", "vigiloss")


def test_shell_combined_c_flag_bundles_inject_header() -> None:
    # `bash -lc` / `sh -ec` / `-xc` bundle -c with other short flags; the wrapper
    # is still a command-string script, so the inner curl must get the header.
    # Previously only a STANDALONE -c was recognized, so `-lc` was treated as a
    # non-injectable invocation and the mandatory header was dropped.
    for head, flag in (("bash", "-lc"), ("sh", "-ec"), ("/bin/bash", "-xc")):
        cmd = [head, flag, "curl http://a.example.com ; curl http://b.example.com"]
        status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))
        assert status == "injected", (head, flag, status)
        assert cmd[:2] == [head, flag]
        subs = _subcommands(cmd[2])
        assert len(subs) == 2
        for tokens in subs:
            assert tokens[0] == "curl"
            assert _has_header(tokens, "X-Bug-Bounty", "vigiloss"), (head, flag, tokens)


def test_shell_control_flow_heads_inject_header() -> None:
    # A curl/wget head inside a control-flow construct (`if curl …; then …`,
    # `while curl …; do …`, `until curl …; do …`) must still be recognized and
    # injected. Previously only separators and do/then/else anchored a head, so the
    # curl right after `if`/`while`/`until` was missed and the script went out
    # header-less.
    for script in (
        "if curl http://a.example.com ; then echo ok ; fi",
        "while curl http://a.example.com ; do sleep 1 ; done",
        "until curl http://a.example.com ; do break ; done",
    ):
        cmd = ["bash", "-lc", script]
        status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))
        assert status == "injected", (script, status)
        seg = next(s for s in _subcommands(cmd[2]) if "curl" in s)
        assert _has_header(seg, "X-Bug-Bounty", "vigiloss"), (script, seg)


# --------------------------------------------------------------------------- #
# Idempotency edge: name present with a DIFFERENT value still counts as present
# --------------------------------------------------------------------------- #

def test_shell_existing_header_different_value_not_redundantly_injected() -> None:
    cmd = ["sh", "-c", "curl -H 'X-Bug-Bounty: someoneelse' http://a.example.com"]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))

    assert status == "noop"
    assert cmd[2].count("X-Bug-Bounty") == 1


# --------------------------------------------------------------------------- #
# Safety: unsafe-to-parse script never raises and never appends to the shell argv
# --------------------------------------------------------------------------- #

def test_shell_unbalanced_quotes_warns_without_raise_or_argv_append() -> None:
    # An unbalanced quote can't be safely lexed; the function must WARN (status),
    # leave the argv untouched, and NOT append -H onto the shell argv.
    script = "curl 'http://a.example.com"  # unterminated single quote
    cmd = ["sh", "-c", script]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))

    assert status in ("warned", "skipped")
    assert cmd == ["sh", "-c", script]  # nothing appended, script unchanged


def test_shell_passive_only_wrapper_is_silently_skipped() -> None:
    # A wrapper whose only sub-command is a skip-set passive tool stays silent
    # (skipped), never warns and never leaks the handle.
    cmd = ["sh", "-c", "gau example.com"]
    status = kali_output._apply_required_headers(cmd, "gau", dict(HDR))

    assert status == "skipped"
    assert cmd == ["sh", "-c", "gau example.com"]


def test_no_required_headers_is_noop() -> None:
    cmd = ["sh", "-c", "curl http://a.example.com"]
    assert kali_output._apply_required_headers(cmd, "curl", {}) == "noop"
    assert cmd == ["sh", "-c", "curl http://a.example.com"]


# --------------------------------------------------------------------------- #
# Regression: the plain (non-shell) argv path is unchanged
# --------------------------------------------------------------------------- #

def test_direct_curl_argv_still_injected() -> None:
    cmd = ["curl", "http://a.example.com"]
    status = kali_output._apply_required_headers(cmd, "curl", dict(HDR))
    assert status == "injected"
    assert cmd[-2:] == ["-H", "X-Bug-Bounty: vigiloss"]


def test_direct_non_injectable_still_warns() -> None:
    # wafw00f IS an HTTP-to-target tool but its ``-H``/``--headers`` flag reads a
    # FILE, not an inline ``Name: Value`` (verified: an inline value errors
    # "Headers file ... does not exist"), so it cannot carry the attribution
    # header on the argv — it warns without blocking execution.
    cmd = ["wafw00f", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "wafw00f", dict(HDR))
    assert status == "warned"
    assert cmd == ["wafw00f", "https://example.com"]


# --------------------------------------------------------------------------- #
# Layer 1 — per-tool header-flag injection for non-``-H`` HTTP-to-target tools
# (whatweb ``--header``, nikto ``-Add-header``, arjun ``--headers``). These are
# verified-real flags (nikto's ``-H`` is ``-Help``; the real flag is
# ``-Add-header``). wafw00f stays WARN — its flag takes a file, not a string.
# --------------------------------------------------------------------------- #

def test_direct_whatweb_injects_header_flag() -> None:
    cmd = ["whatweb", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "whatweb", dict(HDR))
    assert status == "injected"
    assert cmd[-2:] == ["--header", "X-Bug-Bounty: vigiloss"]


def test_direct_nikto_injects_add_header_flag() -> None:
    cmd = ["nikto", "-h", "example.com"]
    status = kali_output._apply_required_headers(cmd, "nikto", dict(HDR))
    assert status == "injected"
    assert cmd[-2:] == ["-Add-header", "X-Bug-Bounty: vigiloss"]


def test_direct_arjun_injects_headers_flag() -> None:
    cmd = ["arjun", "-u", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "arjun", dict(HDR))
    assert status == "injected"
    assert cmd[-2:] == ["--headers", "X-Bug-Bounty: vigiloss"]


def test_direct_arjun_multiple_headers_newline_joined_single_flag() -> None:
    # arjun's --headers is store-once and newline-separated, so multiple required
    # headers ride a SINGLE --headers value joined by newlines, never two flags
    # (a second --headers would clobber the first under argparse store).
    headers = {"X-Bug-Bounty": "vigiloss", "X-HackerOne": "h1user"}
    cmd = ["arjun", "-u", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "arjun", dict(headers))
    assert status == "injected"
    assert cmd.count("--headers") == 1
    flag_idx = cmd.index("--headers")
    assert cmd[flag_idx + 1] == "X-Bug-Bounty: vigiloss\nX-HackerOne: h1user"


def test_direct_whatweb_two_headers_two_flags() -> None:
    headers = {"X-Bug-Bounty": "vigiloss", "X-HackerOne": "h1user"}
    cmd = ["whatweb", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "whatweb", dict(headers))
    assert status == "injected"
    assert cmd.count("--header") == 2
    assert "X-Bug-Bounty: vigiloss" in cmd
    assert "X-HackerOne: h1user" in cmd


def test_direct_whatweb_existing_header_is_noop() -> None:
    # An operator-supplied --header (or -H alias) carrying the marker is honored —
    # no double-inject.
    cmd = ["whatweb", "--header", "X-Bug-Bounty: someoneelse", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "whatweb", dict(HDR))
    assert status == "noop"
    assert cmd.count("--header") == 1


def test_direct_whatweb_h_alias_existing_is_noop() -> None:
    cmd = ["whatweb", "-H", "X-Bug-Bounty: x", "https://example.com"]
    status = kali_output._apply_required_headers(cmd, "whatweb", dict(HDR))
    assert status == "noop"
    assert "--header" not in cmd


def test_direct_arjun_merges_into_existing_headers_block() -> None:
    # arjun already carries an auth --headers block (Authorization). The marker is
    # MERGED into that same value (newline-appended) rather than added as a second
    # --headers flag that would clobber the auth header under argparse store.
    cmd = ["arjun", "-u", "https://example.com", "--headers", "Authorization: Bearer t"]
    status = kali_output._apply_required_headers(cmd, "arjun", dict(HDR))
    assert status == "injected"
    assert cmd.count("--headers") == 1
    flag_idx = cmd.index("--headers")
    assert cmd[flag_idx + 1] == "Authorization: Bearer t\nX-Bug-Bounty: vigiloss"


def test_direct_arjun_existing_marker_in_block_is_noop() -> None:
    cmd = [
        "arjun", "-u", "https://example.com",
        "--headers", "Authorization: Bearer t\nX-Bug-Bounty: vigiloss",
    ]
    status = kali_output._apply_required_headers(cmd, "arjun", dict(HDR))
    assert status == "noop"
    assert cmd.count("--headers") == 1


def test_direct_skip_tool_still_skipped() -> None:
    cmd = ["gau", "example.com"]
    status = kali_output._apply_required_headers(cmd, "gau", dict(HDR))
    assert status == "skipped"
    assert cmd == ["gau", "example.com"]


def test_reexport_identity_unchanged() -> None:
    # kali re-exports the SAME classifier object so the container and host paths
    # never diverge.
    assert kali._apply_required_headers is kali_output._apply_required_headers


def test_apply_required_headers_never_raises_on_odd_inputs() -> None:
    # Best-effort contract: a grab-bag of awkward shell scripts must classify
    # without raising.
    samples = [
        ["sh", "-c", ""],
        ["sh", "-c", "   "],
        ["sh", "-c", ";;;"],
        ["bash", "-c", "for u in a b; do curl $u; done"],
        ["sh", "-c", "curl http://a 2>&1 | tee out.txt"],
        ["sh", "-c", "echo curl is here"],
        ["sh"],
        ["sh", "-c"],
    ]
    for cmd in samples:
        # Must not raise.
        kali_output._apply_required_headers(list(cmd), "curl", dict(HDR))


@pytest.mark.parametrize(
    ("tool", "cmd", "flag"),
    [
        ("whatweb", ["whatweb", "https://example.com"], "--header"),
        ("nikto", ["nikto", "-h", "https://example.com"], "-Add-header"),
        ("arjun", ["arjun", "-u", "https://example.com"], "--headers"),
        ("dalfox", ["dalfox", "url", "https://example.com"], "-H"),
    ],
)
def test_identity_headers_use_verified_typed_tool_flags(tool, cmd, flag) -> None:
    status = kali_output._apply_identity_headers(cmd, tool, {"Cookie": "sid=abc"})
    assert status == "injected"
    assert flag in cmd
    assert "Cookie: sid=abc" in cmd


def test_identity_and_required_headers_share_shell_transformer() -> None:
    cmd = ["sudo", "env", "X=1", "bash", "-lc", "curl https://example.com"]
    assert kali_output._apply_identity_headers(cmd, "curl", {"Cookie": "sid=abc"}) == "injected"
    assert "Cookie: sid=abc" in cmd[-1]


def test_required_attribution_header_wins_identity_conflict() -> None:
    cmd = ["curl", "https://example.com"]
    assert kali_output._apply_required_headers(cmd, "curl", {"X-Researcher": "required"}) == "injected"
    assert kali_output._apply_identity_headers(
        cmd, "curl", {"X-Researcher": "identity", "Cookie": "sid=abc"}
    ) == "injected"
    joined = " ".join(cmd)
    assert "X-Researcher: required" in joined
    assert "X-Researcher: identity" not in joined
    assert "Cookie: sid=abc" in joined
