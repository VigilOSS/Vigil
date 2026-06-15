"""CLI-1 — scoped did-you-mean parser errors for the kali audit enums.

Covers the canonical ``_validate_inputs`` AssessError path (technique / probe-
kind / phase), the ``ScopedErrorParser`` that re-renders argparse "invalid
choice" rejections without the multi-line usage dump, and the ``kali job start``
reconciliation that routes its ``--technique`` through the same scoped formatter.
"""
from __future__ import annotations

import contextlib
import io

import pytest

from assess.lib.client import AssessError
from assess.lib.kali_audit import _validate_inputs


def _expect_validate_error(**overrides) -> str:
    kwargs = dict(
        technique="RECON",
        intent="x",
        probe_kind="fingerprint",
        phase="recon",
        timeout=60,
        agent_name="operator",
    )
    kwargs.update(overrides)
    with pytest.raises(AssessError) as exc:
        _validate_inputs(**kwargs)
    return str(exc.value)


def _run_cli(argv: list[str]) -> tuple[int | None, str]:
    """Invoke assess.cli.main, capturing stderr and the SystemExit code."""
    from assess import cli

    err = io.StringIO()
    code: int | None = None
    with contextlib.redirect_stderr(err):
        try:
            cli.main(argv)
        except SystemExit as exc:  # argparse parse errors + cli.main AssessError handler
            code = exc.code
    return code, err.getvalue()


# --------------------------------------------------------------------------- #
# 1. technique reject leads with a suggestion / hint, no usage dump
# --------------------------------------------------------------------------- #


def test_technique_reject_leads_with_suggestion():
    msg = _expect_validate_error(technique="FINGERPRINT")
    # FINGERPRINT is the motivating bug: the natural word, the value of the
    # sibling --probe-kind. difflib may not rank RECON for the long word, so the
    # spec accepts EITHER a "Did you mean: RECON" OR the hint steering to RECON.
    assert ("Did you mean: RECON" in msg) or ("use RECON" in msg)
    assert "--technique is the vuln-class tag" in msg
    # No multi-line usage block in the AssessError text.
    assert "usage:" not in msg
    assert "\n" not in msg
    # The full allowed list is ALWAYS appended after the suggestion.
    assert "(allowed:" in msg and "RECON" in msg


def test_technique_reject_close_typo():
    msg = _expect_validate_error(technique="SQLINJECTION")
    assert "Did you mean:" in msg
    assert "SQLI" in msg
    assert "(allowed:" in msg


# --------------------------------------------------------------------------- #
# 3 + 4. probe-kind / phase typo close-match suggestions
# --------------------------------------------------------------------------- #


def test_probe_kind_reject_suggestion():
    msg = _expect_validate_error(probe_kind="fingerprnt")
    assert "Did you mean: fingerprint" in msg
    assert "(allowed:" in msg


def test_phase_reject_suggestion():
    msg = _expect_validate_error(phase="recon-pivt")
    assert "Did you mean:" in msg
    assert "recon-pivot" in msg
    assert "(allowed:" in msg


# --------------------------------------------------------------------------- #
# 5. ScopedErrorParser: parse-time enum miss -> single ERROR line, no usage
# --------------------------------------------------------------------------- #


def test_scoped_parser_no_usage_dump():
    # A parse-time --probe-kind enum miss on a typed verb routes through
    # ScopedErrorParser. Use a near-miss typo so a suggestion surfaces.
    code, err = _run_cli([
        "kali", "nmap-scan",
        "--technique", "RECON", "--intent", "x",
        "--probe-kind", "fingerprnt", "--phase", "recon",
        "--timeout", "60", "--", "nmap", "t",
    ])
    assert code == 2  # argparse parse-error exit code
    assert err.startswith("ERROR:")
    assert "Did you mean: fingerprint" in err
    assert "usage:" not in err
    # Exactly one ERROR line (no multi-line usage dump).
    assert err.strip().count("\n") == 0


def test_scoped_parser_phase_enum_no_usage_dump():
    code, err = _run_cli([
        "kali", "nmap-scan",
        "--technique", "RECON", "--intent", "x",
        "--probe-kind", "fingerprint", "--phase", "recon-pivt",
        "--timeout", "60", "--", "nmap", "t",
    ])
    assert code == 2
    assert err.startswith("ERROR:")
    assert "recon-pivot" in err
    assert "usage:" not in err


# --------------------------------------------------------------------------- #
# 6. kali job start --technique uses the SAME scoped error as the typed verbs
# --------------------------------------------------------------------------- #


def test_kali_job_technique_uses_scoped_error():
    # The technique check fires before any runtime/container interaction, so no
    # live container is needed. Exit 1 is the cli.main AssessError path.
    code, err = _run_cli([
        "kali", "job", "start",
        "--technique", "FINGERPRINT", "--intent", "x",
        "--probe-kind", "fingerprint", "--phase", "recon",
        "--", "nmap", "t",
    ])
    assert code == 1
    assert "--technique 'FINGERPRINT' is not valid." in err
    assert "--technique is the vuln-class tag" in err
    assert "usage:" not in err


def test_kali_job_probe_kind_uses_scoped_parser():
    # Reconciliation regression guard: probe-kind keeps choices= but routes
    # through ScopedErrorParser, so a parse-time miss is scoped, not a dump.
    code, err = _run_cli([
        "kali", "job", "start",
        "--technique", "RECON", "--intent", "x",
        "--probe-kind", "fingerprnt", "--phase", "recon",
        "--", "nmap", "t",
    ])
    assert code == 2
    assert err.startswith("ERROR:")
    assert "Did you mean: fingerprint" in err
    assert "usage:" not in err
