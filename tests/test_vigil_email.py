"""Unit tests for `vigil email` mailbox reading and code extraction.

These exercise the pure filtering/extraction helpers (no Mail.app, no network)
plus a CLI smoke that stubs the JXA reader, mirroring the contract-guard style
of ``test_vigil_cli.py``.
"""
from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def _msg(**kwargs):
    from vigil_cli.email import EmailMessage

    defaults = dict(
        sender="Acme Bank Security <security@acme-bank.example>",
        recipients=("researcher@example.com",),
        subject="Your verification code",
        body="Your Acme Bank verification code is 482915. It expires in 10 minutes.",
        received_at=datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC),
        account="researcher-example",
        mailbox="Inbox",
    )
    defaults.update(kwargs)
    return EmailMessage(**defaults)


def test_extract_token_default_otp_pattern():
    from vigil_cli.email import extract_token

    assert extract_token("Your code is 482915 now") == "482915"
    # Avoids a too-short or too-long run; 8 digits still match.
    assert extract_token("PIN: 12345678 end") == "12345678"
    assert extract_token("no code here") is None


def test_extract_token_custom_match_returns_capture_group():
    from vigil_cli.email import extract_token

    body = "Click https://acme-bank.example/verify?token=abc123 to confirm."
    link = extract_token(body, pattern=r"(https://\S+)")
    assert link == "https://acme-bank.example/verify?token=abc123"


def test_extract_token_invalid_regex_raises():
    from vigil_cli.email import EmailReadError, extract_token

    with pytest.raises(EmailReadError):
        extract_token("body", pattern="(")


def test_filter_messages_by_mailbox_and_domain_from():
    from vigil_cli.email import filter_messages

    base = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)
    on_target = _msg(received_at=base)
    wrong_mailbox = _msg(recipients=("someone@example.com",), received_at=base)
    wrong_sender = _msg(sender="noreply@other-bank.example", received_at=base)

    kept = filter_messages(
        [on_target, wrong_mailbox, wrong_sender],
        mailbox_address="researcher@example.com",
        from_filter="@acme-bank.example",
    )
    assert kept == [on_target]


def test_filter_messages_orders_newest_first_and_respects_since():
    from vigil_cli.email import filter_messages

    now = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)
    recent = _msg(received_at=now)
    older = _msg(received_at=now - timedelta(minutes=2))
    too_old = _msg(received_at=now - timedelta(minutes=10))

    kept = filter_messages(
        [older, recent, too_old],
        mailbox_address="researcher@example.com",
        since=now - timedelta(minutes=3),
    )
    assert kept == [recent, older]


def test_normalize_filter_bare_domain_is_suffix_scoped():
    from vigil_cli.email import _address_matches, _normalize_filter

    needle = _normalize_filter("acme-bank.example")
    assert needle == "@acme-bank.example"
    # A bare domain must not match a localpart that merely contains it.
    assert _address_matches(needle, ["alert@acme-bank.example"]) is True
    assert _address_matches(needle, ["acme-bank.example.attacker@evil.example"]) is False


def test_email_cli_json_extracts_code(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    captured_since = {}

    def fake_read(*, since, limit, timeout_seconds):
        captured_since["since"] = since
        return [_msg(received_at=datetime.now(UTC))]

    monkeypatch.setattr(email_module, "read_messages", fake_read)

    # JSON path prints and returns normally (no SystemExit).
    main(["email", "researcher@example.com", "--from", "@acme-bank.example", "--json"])

    out = capsys.readouterr().out
    import json as _json

    payload = _json.loads(out)
    assert payload["count"] == 1
    assert payload["messages"][0]["extracted"] == "482915"
    assert payload["messages"][0]["from"] == "Acme Bank Security <security@acme-bank.example>"


def test_email_cli_no_matches_exits_nonzero(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    monkeypatch.setattr(email_module, "read_messages", lambda **_: [])

    with pytest.raises(SystemExit) as exc:
        main(["email", "researcher@example.com"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "no messages" in err
