"""Unit tests for `vigil email` mailbox reading and code extraction.

These exercise the pure filtering/extraction helpers (no Mail.app, no network)
plus a CLI smoke that stubs the JXA reader, mirroring the contract-guard style
of ``test_vigil_cli.py``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


def _msg(**kwargs):
    from vigil_cli.email import EmailMessage

    defaults = dict(
        sender="Acme Bank Security <security@bank.acme.example>",
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

    body = "Click https://bank.acme.example/verify?token=abc123 to confirm."
    link = extract_token(body, pattern=r"(https://\S+)")
    assert link == "https://bank.acme.example/verify?token=abc123"


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
        from_filter="@bank.acme.example",
    )
    assert kept == [on_target]


def test_filter_messages_can_narrow_rewritten_relay_sender_by_subject():
    from vigil_cli.email import filter_messages

    acme = _msg(
        sender="Mail Forwarder <mail-forwarder@wearehackerone.com>",
        recipients=("researcher+pc1@example.com",),
        subject="Your Acme verification code",
    )
    unrelated = _msg(
        sender=acme.sender,
        recipients=acme.recipients,
        subject="Recruiting interview confirmation 482915",
    )

    kept = filter_messages(
        [acme, unrelated],
        mailbox_address="researcher+pc1@example.com",
        subject_filter="Acme",
    )

    assert kept == [acme]


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

    needle = _normalize_filter("bank.acme.example")
    assert needle == "@bank.acme.example"
    # A bare domain must not match a localpart that merely contains it.
    assert _address_matches(needle, ["alert@bank.acme.example"]) is True
    assert _address_matches(needle, ["bank.acme.example.attacker@evil.example"]) is False


def test_email_cli_json_extracts_code(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    captured_since = {}

    def fake_read(*, since, limit, timeout_seconds):
        captured_since["since"] = since
        return [_msg(received_at=datetime.now(UTC))]

    monkeypatch.setattr(email_module, "read_messages", fake_read)

    # JSON path prints and returns normally (no SystemExit).
    main(["email", "researcher@example.com", "--from", "@bank.acme.example", "--json"])

    out = capsys.readouterr().out
    import json as _json

    payload = _json.loads(out)
    assert payload["count"] == 1
    assert payload["messages"][0]["extracted"] == "482915"
    assert payload["messages"][0]["from"] == "Acme Bank Security <security@bank.acme.example>"


def test_email_cli_no_matches_exits_nonzero(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    monkeypatch.setattr(email_module, "read_messages", lambda **_: [])

    with pytest.raises(SystemExit) as exc:
        main(["email", "researcher@example.com"])
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "no messages" in err


def test_filter_messages_deduplicates_aggregate_and_account_views():
    from vigil_cli.email import filter_messages

    received = datetime(2026, 8, 24, 23, 41, 29, tzinfo=UTC)
    aggregate = _msg(
        sender="Acme <mail-forwarder@wearehackerone.com>",
        recipients=("researcher@example.com",),
        subject="Acme Groups People CSV Export Download Link.",
        body="Your CSV export is ready.",
        received_at=received,
        account="",
        mailbox="Inbox",
    )
    account_view = _msg(
        sender=aggregate.sender,
        recipients=aggregate.recipients,
        subject=aggregate.subject,
        body=aggregate.body,
        received_at=received,
        account="Parameno",
        mailbox="INBOX",
    )

    kept = filter_messages(
        [aggregate, account_view],
        mailbox_address="researcher@example.com",
    )

    assert kept == [aggregate]


def test_extract_links_decodes_hidden_html_href_from_raw_mime_source():
    from vigil_cli.email import extract_links

    raw_source = """\
From: Acme <mail-forwarder@wearehackerone.com>
To: researcher@example.com
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<p>Your export is ready.</p><a href=3D"https://groups.acme-portal.example/=
exports/owned-fixture.csv?token=3Dabc123">Download CSV</a>
"""
    message = _msg(
        body="Your export is ready. Download CSV",
        raw_source=raw_source,
    )

    assert extract_links(message) == [
        "https://groups.acme-portal.example/exports/owned-fixture.csv?token=abc123"
    ]


def test_email_cli_waits_for_delayed_message_without_moving_cutoff(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli import main as main_module
    from vigil_cli.main import main

    calls = []
    expected = _msg(received_at=datetime.now(UTC))

    def fake_read(*, since, limit, timeout_seconds):
        calls.append(since)
        return [] if len(calls) == 1 else [expected]

    monkeypatch.setattr(email_module, "read_messages", fake_read)
    monkeypatch.setattr(main_module.time, "sleep", lambda _: None)

    main(
        [
            "email",
            "researcher@example.com",
            "--wait-seconds",
            "5",
            "--poll-seconds",
            "0.01",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["poll_attempts"] == 2
    assert calls == [calls[0], calls[0]]


def test_email_cli_wait_retries_transient_mail_app_error(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli import main as main_module
    from vigil_cli.main import main

    attempts = 0

    def fake_read(**_):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise email_module.EmailReadError("osascript timed out")
        return [_msg(received_at=datetime.now(UTC))]

    monkeypatch.setattr(email_module, "read_messages", fake_read)
    monkeypatch.setattr(main_module.time, "sleep", lambda _: None)

    main(
        [
            "email",
            "researcher@example.com",
            "--wait-seconds",
            "5",
            "--poll-seconds",
            "0.01",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["poll_attempts"] == 2


def test_email_cli_links_reads_message_source_only_when_requested(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    captured = {}
    message = _msg(
        received_at=datetime.now(UTC),
        raw_source=(
            "Content-Type: text/html; charset=UTF-8\n\n"
            '<a href="https://example.test/download?id=1">Download</a>'
        ),
    )

    def fake_read(*, since, limit, timeout_seconds, include_source=False):
        captured["include_source"] = include_source
        return [message]

    monkeypatch.setattr(email_module, "read_messages", fake_read)

    main(["email", "researcher@example.com", "--links", "--json"])

    payload = json.loads(capsys.readouterr().out)
    assert captured["include_source"] is True
    assert payload["messages"][0]["links"] == [
        "https://example.test/download?id=1"
    ]


def test_email_cli_passes_subject_filter(monkeypatch, capsys):
    from vigil_cli import email as email_module
    from vigil_cli.main import main

    monkeypatch.setattr(
        email_module,
        "read_messages",
        lambda **_: [
            _msg(
                sender="Mail Forwarder <mail-forwarder@wearehackerone.com>",
                subject="Your Acme verification code",
                received_at=datetime.now(UTC),
            ),
            _msg(
                sender="Mail Forwarder <mail-forwarder@wearehackerone.com>",
                subject="Unrelated message",
                received_at=datetime.now(UTC),
            ),
        ],
    )

    main(
        [
            "email",
            "researcher@example.com",
            "--subject",
            "Acme",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["subject"] == "Acme"
    assert payload["count"] == 1


# ---------------------------------------------------------------------------
# JXA scan-direction regression coverage.
#
# The scan-direction bug lived in the `collectMessages` closure inside
# `_READ_MESSAGES_JXA`: it assumed each Mail.app mailbox's `messages()` array is
# ordered oldest-first and `break`-ed on the first message older than the
# `--within` cutoff, so newest-first mailboxes (e.g. the example IMAP INBOX)
# tripped the break immediately and silently dropped recent mail. The fix added
# per-mailbox direction detection, a `scanCap`, an early-exit only after the
# direction is confirmed, and a forced full-scan of the synthetic cross-account
# `Mail.inbox` aggregate (`forceFullScan: true`).
#
# The JXA normally runs only inside Mail.app via `osascript`, so it can't be
# invoked directly in CI. Instead of re-implementing the algorithm (which could
# silently drift from the shipped code), these tests execute the ACTUAL
# `_READ_MESSAGES_JXA` string under `node`, supplying a mocked Mail.app
# `Application` global so the real `run()` -> `collectMessages()` path drives our
# fixtures. This exercises the exact shipped algorithm, including the
# `Mail.inbox` -> `forceFullScan` and per-account "inbox" mailbox wiring.
#
# osascript's `Application`/`JavaScript for Automation` runtime is a superset of
# plain JS for the constructs `collectMessages` uses (const/let, arrow fns,
# for-of, Date/Math/JSON/Array), so running the same source under node is a
# faithful stand-in for the scan-direction logic. Not covered here: real
# Mail.app object semantics and osascript timeouts (mocked away), and the
# CLI/`read_messages` boundary (covered by the tests above).

_NOW = datetime(2026, 7, 2, 12, 0, 0, tzinfo=UTC)

requires_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is required to execute the JXA scan-direction algorithm",
)

# Node harness: install a mocked Mail.app `Application`, splice in the real
# shipped JXA, then invoke its `run()` entry point and emit the resulting
# payload plus a scan counter. `dateReceived` increments `scanCount` so tests
# can assert the scanCap bound. Placeholders are substituted (not f-string /
# %-formatted) so the JS braces stay literal.
_NODE_HARNESS_TEMPLATE = """\
let scanCount = 0;
function mkMsg(msValue) {
  return {
    dateReceived: function () { scanCount += 1; return new Date(msValue); },
    sender: function () { return ""; },
    subject: function () { return ""; },
    content: function () { return ""; },
    toRecipients: function () { return []; },
    ccRecipients: function () { return []; },
  };
}
const AGGREGATE = __AGGREGATE__.map(mkMsg);
const ACCOUNTS = __ACCOUNTS__.map(function (account) {
  return {
    name: function () { return account.name; },
    mailboxes: function () {
      return account.mailboxes.map(function (mailbox) {
        return {
          name: function () { return mailbox.name; },
          messages: function () { return mailbox.ms.map(mkMsg); },
        };
      });
    },
  };
});
const MOCK = {
  inbox: { messages: function () { return AGGREGATE; } },
  accounts: function () { return ACCOUNTS; },
};
globalThis.Application = function () { return MOCK; };

__JXA__

const out = run([JSON.stringify(__CFG__)]);
process.stdout.write(JSON.stringify({ payload: JSON.parse(out), scanCount: scanCount }));
"""


def _ms(minutes_ago: int) -> int:
    """Epoch-ms for a message received ``minutes_ago`` before the fixed _NOW."""
    return int((_NOW - timedelta(minutes=minutes_ago)).timestamp() * 1000)


def _minutes_ago(iso: str) -> int:
    """Round-trip a JXA `toISOString()` value back to whole minutes before _NOW."""
    text = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    return round((_NOW - datetime.fromisoformat(text)).total_seconds() / 60)


def _run_jxa_scan(
    *,
    aggregate_minutes: list[int] | None = None,
    accounts: list[dict] | None = None,
    since_minutes: int = 10,
    limit: int = 200,
):
    """Run the real `_READ_MESSAGES_JXA` under node against mocked mailboxes.

    ``aggregate_minutes`` populates the synthetic cross-account ``Mail.inbox``
    aggregate (always scanned with ``forceFullScan``); ``accounts`` is a list of
    ``{"name", "mailboxes": [{"name", "minutes": [...]}]}`` for per-account
    mailboxes (only those whose name contains "inbox" are scanned, mirroring
    the JXA filter). Message ages are expressed as whole minutes before _NOW.

    Returns ``(collected_minutes_ago, scan_count)`` where ``collected_minutes_ago``
    is the age (in minutes) of each collected message, in payload order.
    """
    from vigil_cli.email import _READ_MESSAGES_JXA

    node = shutil.which("node")
    assert node is not None  # guarded by @requires_node

    aggregate_ms = [_ms(m) for m in (aggregate_minutes or [])]
    accounts_ms = [
        {
            "name": account["name"],
            "mailboxes": [
                {"name": mb["name"], "ms": [_ms(m) for m in mb["minutes"]]}
                for mb in account["mailboxes"]
            ],
        }
        for account in (accounts or [])
    ]
    cfg = {"since": (_NOW - timedelta(minutes=since_minutes)).isoformat(), "limit": limit}

    script = (
        _NODE_HARNESS_TEMPLATE
        .replace("__AGGREGATE__", json.dumps(aggregate_ms))
        .replace("__ACCOUNTS__", json.dumps(accounts_ms))
        .replace("__JXA__", _READ_MESSAGES_JXA)
        .replace("__CFG__", json.dumps(cfg))
    )

    # `.cjs` forces CommonJS/non-strict regardless of any repo package.json,
    # matching how the plain-JS JXA source expects to be evaluated.
    with tempfile.NamedTemporaryFile("w", suffix=".cjs", delete=False) as handle:
        handle.write(script)
        path = handle.name
    try:
        proc = subprocess.run([node, path], text=True, capture_output=True)
    finally:
        os.unlink(path)

    if proc.returncode != 0:
        pytest.fail(
            f"node JXA harness failed ({proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )

    data = json.loads(proc.stdout)
    collected = [_minutes_ago(m["received_at"]) for m in data["payload"]["messages"]]
    return collected, data["scanCount"]


def _inbox_account(minutes: list[int]) -> list[dict]:
    return [{"name": "example", "mailboxes": [{"name": "INBOX", "minutes": minutes}]}]


@requires_node
def test_jxa_newest_first_mailbox_keeps_recent_mail():
    # The original bug: a newest-first mailbox (index 0 = newest) with recent
    # mail at the top followed by older mail. A fixed oldest-first scan breaks
    # immediately and drops the recent messages; the direction-detecting fix
    # must collect them.
    collected, _ = _run_jxa_scan(
        aggregate_minutes=[],
        accounts=_inbox_account([1, 2, 3, 40, 50]),
        since_minutes=10,
    )
    assert set(collected) == {1, 2, 3}
    # The messages beyond the --within cutoff are (correctly) excluded.
    assert 40 not in collected and 50 not in collected


@requires_node
def test_jxa_oldest_first_mailbox_early_exits_at_cutoff():
    # Oldest-first mailbox (index 0 = oldest). The 2-min message sits at index 1
    # (a deliberate order anomaly) so a correct early-exit never reaches it: the
    # scan starts at the newest end, collects the 1-min message, then breaks on
    # the 40-min message. If the early-exit regressed into a full scan the 2-min
    # message would leak in.
    collected, _ = _run_jxa_scan(
        aggregate_minutes=[],
        accounts=_inbox_account([50, 2, 45, 40, 1]),
        since_minutes=10,
    )
    assert collected == [1]
    assert 2 not in collected  # early-exit stopped before the anomalous message


@requires_node
def test_jxa_force_full_scan_aggregate_never_early_exits():
    # The synthetic Mail.inbox aggregate interleaves accounts, so ordering is not
    # monotonic. It is scanned with forceFullScan: an old message (40 min) sits
    # between two recent ones (1 and 2 min). A break-based scan would drop the
    # recent message after the old one; the full scan keeps both.
    collected, _ = _run_jxa_scan(aggregate_minutes=[1, 40, 2], accounts=[], since_minutes=10)
    assert set(collected) == {1, 2}
    assert 40 not in collected


@requires_node
def test_jxa_force_full_scan_is_load_bearing_vs_per_account():
    # Contrast: the SAME interleaved [1, 40, 2] ordering as a per-account mailbox
    # (no forceFullScan) is direction-detected as newest-first and breaks on the
    # 40-min message, dropping the trailing 2-min message. This proves the
    # aggregate's forceFullScan flag is what prevents the drop above.
    collected, _ = _run_jxa_scan(
        aggregate_minutes=[],
        accounts=_inbox_account([1, 40, 2]),
        since_minutes=10,
    )
    assert collected == [1]
    assert 2 not in collected


@requires_node
def test_jxa_scan_cap_bounds_the_scan():
    # scanCap = max(limit * 5, 500). With limit=100 the cap is 500. Feed 600
    # messages (a recent one at index 0, then 599 old ones): the full scan runs
    # from the tail, inspects exactly 500 messages (all old -> none collected),
    # and stops before reaching the recent message at index 0.
    collected, scan_count = _run_jxa_scan(
        aggregate_minutes=[1] + [60] * 599,
        accounts=[],
        since_minutes=10,
        limit=100,
    )
    assert scan_count == 500  # bounded by scanCap, not the full 600
    assert collected == []  # the index-0 recent message is past the cap


def test_jxa_scan_direction_wiring_present_in_source():
    # Cheap, node-free guard on the wiring the tests above depend on, so an
    # accidental edit to the JXA is caught even where node is unavailable.
    from vigil_cli.email import _READ_MESSAGES_JXA as jxa

    # The cross-account aggregate is scanned with forceFullScan...
    assert "Mail.inbox.messages()" in jxa
    assert "forceFullScan: true" in jxa
    # ...while per-account inbox mailboxes are scanned WITHOUT it (direction is
    # detected per mailbox).
    assert (
        "collectMessages(safe(() => mailbox.messages(), []), accountName, mailboxName, payload);"
        in jxa
    )
    # scanCap sizing is part of the fix's contract.
    assert "Math.max(limit * 5, 500)" in jxa
