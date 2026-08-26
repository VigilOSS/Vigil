"""Focused regressions for Mail.app OTP coverage in ``vigil email``.

The tests fake the JXA boundary.  They never access Mail.app or contain live
mailbox data.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "src"))

from vigil_cli import email as email_module  # noqa: E402
from vigil_cli import main as main_module  # noqa: E402


NOW = datetime(2026, 8, 25, 16, 0, tzinfo=UTC)


def _message(
    *,
    mailbox: str,
    recipient: str,
    subject: str,
    message_id: str,
) -> dict[str, object]:
    return {
        "account": "Test Provider",
        "mailbox": mailbox,
        "message_id": message_id,
        "sender": "no-reply@example.test",
        "recipients": [recipient],
        "subject": subject,
        "body": "Your one-time code is 123456",
        "source": "",
        "received_at": NOW.isoformat(),
    }


def _coverage(*, complete: bool = True) -> dict[str, object]:
    return {
        "complete": complete,
        "candidate_limit": 2_000,
        "page_size": 200,
        "candidates_examined": 401,
        "candidates_collected": 3,
        "mailboxes": [
            {
                "account": "Test Provider",
                "mailbox": "All Mail",
                "examined": 401,
                "pages_scanned": 3,
                "complete": complete,
            }
        ],
        "truncated_mailboxes": [] if complete else ["Test Provider/All Mail"],
        "used_aggregate_inbox": False,
        "discovery_complete": True,
        "discovery_truncated": False,
    }


def test_read_and_filter_scans_archive_window_before_applying_final_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A matching archive message after page one survives unrelated candidates."""

    captured: dict[str, object] = {}

    def fake_run(script, args, *, timeout_seconds):
        captured["script"] = script
        captured["config"] = json.loads(args[0])
        captured["timeout"] = timeout_seconds
        return {
            "messages": [
                _message(
                    mailbox="Inbox",
                    recipient="someone-else@example.test",
                    subject="Unrelated first candidate",
                    message_id="unrelated-1",
                ),
                _message(
                    mailbox="Inbox",
                    recipient="another@example.test",
                    subject="Unrelated second candidate",
                    message_id="unrelated-2",
                ),
                _message(
                    mailbox="All Mail",
                    recipient="tester@example.test",
                    subject="Acme verification code",
                    message_id="archive-page-3",
                ),
            ],
            "coverage": _coverage(),
            "scan_errors": [],
        }

    monkeypatch.setattr(email_module, "_run_jxa_json", fake_run)

    scanned = email_module.read_messages(since=NOW, limit=1, timeout_seconds=12)
    matched = email_module.filter_messages(
        scanned,
        mailbox_address="tester@example.test",
        subject_filter="verification code",
        since=NOW,
    )

    assert [message.mailbox for message in matched] == ["All Mail"]
    assert len(matched) == 1
    assert matched.coverage.complete is True
    assert matched.coverage.mailboxes[0].pages_scanned == 3
    assert captured["timeout"] == 12
    assert captured["config"]["result_limit"] == 1
    assert captured["config"]["candidate_limit"] > 1
    assert captured["config"]["page_size"] == 200
    assert "all mail" in str(captured["script"]).lower()
    assert "important" in str(captured["script"]).lower()
    assert "receivedDate < since && source.newestFirst" not in str(captured["script"])


def test_filter_messages_deduplicates_inbox_and_all_mail_by_message_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate_id = "provider-stable-message-id"
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [
                _message(
                    mailbox="Inbox",
                    recipient="tester@example.test",
                    subject="Verification code",
                    message_id=duplicate_id,
                ),
                _message(
                    mailbox="All Mail",
                    recipient="tester@example.test",
                    subject="Verification code",
                    message_id=duplicate_id,
                ),
            ],
            "coverage": _coverage(),
            "scan_errors": [],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=10)
    matched = email_module.filter_messages(
        scanned,
        mailbox_address="tester@example.test",
        since=NOW,
    )

    assert len(matched) == 1
    assert matched[0].message_id == duplicate_id


def test_incomplete_scan_without_a_match_raises_coverage_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [],
            "coverage": _coverage(complete=False),
            "scan_errors": ["Test Provider/All Mail reached candidate window"],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)

    with pytest.raises(email_module.EmailReadError, match="incomplete Mail.app scan") as exc:
        email_module.filter_messages(
            scanned,
            mailbox_address="tester@example.test",
            since=NOW,
        )

    assert "All Mail" in str(exc.value)
    assert scanned.coverage.candidates_examined == 401


def test_complete_scan_without_a_match_is_authoritative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [],
            "coverage": _coverage(complete=True),
            "scan_errors": [],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)
    matched = email_module.filter_messages(
        scanned,
        mailbox_address="tester@example.test",
        since=NOW,
    )

    assert matched == []
    assert matched.coverage.complete is True


def test_unparseable_message_date_prevents_authoritative_no_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = _message(
        mailbox="All Mail",
        recipient="tester@example.test",
        subject="Verification code",
        message_id="bad-date",
    )
    malformed["received_at"] = None
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [malformed],
            "coverage": _coverage(complete=True),
            "scan_errors": [],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)

    with pytest.raises(email_module.EmailReadError, match="unreadable received_at"):
        email_module.filter_messages(
            scanned,
            mailbox_address="tester@example.test",
            since=NOW,
        )


def test_jxa_relevant_mailbox_message_access_failure_is_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = email_module._READ_MESSAGES_JXA
    assert "sourceFor(safe(() => mailbox.messages(), [])" not in script
    assert "message access failed" in script

    coverage = _coverage(complete=False)
    coverage["discovery_truncated"] = False
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [],
            "coverage": coverage,
            "scan_errors": ["Test Provider/All Mail message access failed"],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)

    with pytest.raises(email_module.EmailReadError, match="message access failed"):
        email_module.filter_messages(
            scanned,
            mailbox_address="tester@example.test",
            since=NOW,
        )


def test_jxa_discovery_caps_report_explicit_incomplete_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = email_module._READ_MESSAGES_JXA
    assert "discovery depth limit" in script
    assert "relevant mailbox source limit" in script

    coverage = _coverage(complete=False)
    coverage["discovery_complete"] = False
    coverage["discovery_truncated"] = True
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [],
            "coverage": coverage,
            "scan_errors": ["relevant mailbox source limit reached"],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)

    assert scanned.coverage.discovery_complete is False
    assert scanned.coverage.discovery_truncated is True
    with pytest.raises(email_module.EmailReadError, match="source limit"):
        email_module.filter_messages(
            scanned,
            mailbox_address="tester@example.test",
            since=NOW,
        )


def test_message_id_missing_fallback_keeps_distinct_otp_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _message(
        mailbox="Inbox",
        recipient="tester@example.test",
        subject="Verification code",
        message_id="",
    )
    second = dict(first)
    first["body"] = "Your one-time code is 123456"
    second["body"] = "Your one-time code is 654321"
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [first, second],
            "coverage": _coverage(),
            "scan_errors": [],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=10)
    matched = email_module.filter_messages(
        scanned,
        mailbox_address="tester@example.test",
        since=NOW,
    )

    assert [message.body for message in matched] == [first["body"], second["body"]]
    assert "subject, body, isoDate(received)" in email_module._READ_MESSAGES_JXA


def test_email_limit_help_describes_final_matching_result(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exc:
        main_module.main(["email", "--help"])

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "maximum matching messages to return" in help_text


def test_email_json_adds_scan_coverage_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    message = email_module.EmailMessage(
        sender="no-reply@example.test",
        recipients=("tester@example.test",),
        subject="Verification code",
        body="Your one-time code is 123456",
        received_at=NOW,
        account="Test Provider",
        mailbox="All Mail",
        message_id="json-diagnostic",
    )
    coverage = email_module._parse_scan_coverage(
        _coverage(),
        scan_errors=[],
        fallback_candidate_limit=2_000,
        fallback_page_size=200,
        message_count=1,
    )
    scan = email_module.EmailScan([message], result_limit=5, coverage=coverage)
    monkeypatch.setattr(email_module, "cutoff_for_window", lambda _minutes: NOW)
    monkeypatch.setattr(email_module, "read_messages", lambda **_kwargs: scan)

    main_module._email(
        SimpleNamespace(
            mailbox="tester@example.test",
            from_filter=None,
            subject_filter=None,
            within=5,
            match=None,
            extract=False,
            limit=5,
            timeout_seconds=10.0,
            wait_seconds=0.0,
            poll_seconds=1.0,
            links=False,
            json=True,
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["scan_coverage"] == {
        "complete": True,
        "candidate_limit": 2000,
        "page_size": 200,
        "candidates_examined": 401,
        "candidates_collected": 3,
        "mailboxes": [
            {
                "account": "Test Provider",
                "mailbox": "All Mail",
                "examined": 401,
                "pages_scanned": 3,
                "complete": True,
            }
        ],
        "truncated_mailboxes": [],
        "scan_errors": [],
        "used_aggregate_inbox": False,
        "discovery_complete": True,
        "discovery_truncated": False,
    }


def test_spam_only_match_is_found_because_spam_is_a_scanned_folder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OTP filtered to Spam must still be found.

    Gmail's All Mail excludes Spam and Trash by design, so before Spam/Junk were
    scanned a spam-filtered OTP produced a `complete: true` zero — an
    authoritative wrong answer, the exact class the coverage rewrite exists to
    kill.
    """
    script = email_module._READ_MESSAGES_JXA
    for folder in ("spam", "junk", "junk mail", "junk email", "archive"):
        assert f'"{folder}",' in script, folder
    # Matched through normalizedMailboxName (which turns "[Gmail]/Spam" into
    # "gmail spam") plus the trailing-segment rule, so provider-decorated names
    # resolve to the same set.
    assert 'normalized === candidate || normalized.endsWith(" " + candidate)' in script

    coverage = _coverage()
    coverage["mailboxes"] = [
        {
            "account": "Test Provider",
            "mailbox": "[Gmail]/Spam",
            "examined": 12,
            "pages_scanned": 1,
            "complete": True,
        }
    ]
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [
                _message(
                    mailbox="[Gmail]/Spam",
                    recipient="tester@example.test",
                    subject="Your verification code",
                    message_id="spam-otp-1",
                )
            ],
            "coverage": coverage,
            "scan_errors": [],
        },
    )

    scanned = email_module.read_messages(since=NOW, limit=5)
    matched = email_module.filter_messages(
        scanned,
        mailbox_address="tester@example.test",
        since=NOW,
    )

    assert [message.mailbox for message in matched] == ["[Gmail]/Spam"]
    assert email_module.extract_token(matched[0].body) == "123456"
    assert matched.coverage.mailboxes[0].mailbox == "[Gmail]/Spam"


def _email_args(**overrides: object) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "mailbox": "tester@example.test",
        "from_filter": None,
        "subject_filter": None,
        "within": 5,
        "match": None,
        "extract": False,
        "limit": 5,
        "timeout_seconds": 10.0,
        "wait_seconds": 0.0,
        "poll_seconds": 1.0,
        "links": False,
        "json": False,
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_email_json_incomplete_empty_scan_emits_json_not_a_plain_text_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A JSON caller must get JSON on the unauthoritative-empty path too.

    It previously exited 1 with a bare stderr string, so automation had to parse
    stderr to learn WHY the zero was untrustworthy.
    """
    monkeypatch.setattr(email_module, "cutoff_for_window", lambda _minutes: NOW)
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [],
            "coverage": _coverage(complete=False),
            "scan_errors": ["Test Provider/All Mail reached candidate window"],
        },
    )

    with pytest.raises(SystemExit) as exc:
        main_module._email(_email_args(json=True))

    assert exc.value.code == 1  # the scan is still unusable
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["count"] == 0
    assert payload["messages"] == []
    assert payload["scan_coverage"]["complete"] is False
    assert payload["scan_coverage"]["truncated_mailboxes"] == ["Test Provider/All Mail"]
    assert "incomplete Mail.app scan" in payload["error"]
    # The window is now shared with Spam/Junk/Archive, so the remedy has to be named.
    assert "raise --limit to widen the 2000-candidate window" in payload["error"]


def test_email_text_output_reports_which_folders_were_scanned(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Folder coverage must reach the plain-text operator too, on stderr only."""
    coverage = _coverage()
    coverage["mailboxes"] = [
        {
            "account": "Test Provider",
            "mailbox": "INBOX",
            "examined": 200,
            "pages_scanned": 1,
            "complete": True,
        },
        {
            "account": "Test Provider",
            "mailbox": "[Gmail]/Spam",
            "examined": 12,
            "pages_scanned": 1,
            "complete": True,
        },
    ]
    monkeypatch.setattr(email_module, "cutoff_for_window", lambda _minutes: NOW)
    monkeypatch.setattr(
        email_module,
        "_run_jxa_json",
        lambda *_args, **_kwargs: {
            "messages": [
                _message(
                    mailbox="[Gmail]/Spam",
                    recipient="tester@example.test",
                    subject="Your verification code",
                    message_id="spam-otp-2",
                )
            ],
            "coverage": coverage,
            "scan_errors": [],
        },
    )

    main_module._email(_email_args())

    captured = capsys.readouterr()
    assert "scanned 2 folder(s) [complete]" in captured.err
    assert "Test Provider/INBOX=200" in captured.err
    assert "Test Provider/[Gmail]/Spam=12" in captured.err
    # stdout stays parseable result lines only.
    assert captured.out.strip().endswith("Your verification code")
    assert "scanned" not in captured.out
