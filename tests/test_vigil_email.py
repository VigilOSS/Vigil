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
        account="Acme",
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
# JXA scan-coverage regression suite.
#
# `_READ_MESSAGES_JXA` is the only place that decides which Mail.app messages a
# verification-code lookup can ever see, so a silent regression there is a
# missed OTP with no error to notice. Its contract has four load-bearing parts:
#
#   1. Folder discovery. Every account is walked (bounded by depth and source
#      count) and every mailbox whose name resolves to Inbox / All Mail /
#      Important / Spam / Junk / Archive becomes a scan source. Providers
#      routinely file an OTP as spam, and Gmail's All Mail excludes Spam by
#      design, so those folders are required coverage, not extras.
#   2. Direction. A provider's `messages()` array may be newest-first,
#      oldest-first, or (for the synthetic cross-account aggregate) neither.
#      The scan detects the orientation from the two endpoint dates and walks
#      from the newest end, so a tight candidate budget still reaches the
#      message that just arrived. There is deliberately NO early exit on the
#      `--within` cutoff: an out-of-order old message is skipped, never treated
#      as proof that the rest of the folder is older.
#   3. The candidate window. `candidate_limit` bounds total messages examined
#      across all folders, and folders are paged round-robin so one huge Inbox
#      cannot consume the budget before Spam or Archive is reached at all.
#   4. Honest coverage. When the window (or a discovery/access failure) stops
#      the scan short, the payload says so — `complete: false`, the folder
#      named in `truncated_mailboxes`, a `scan_errors` entry — so a zero-match
#      result is never reported as authoritative when it is not.
#
# The JXA normally runs only inside Mail.app via `osascript`, so it can't be
# invoked directly in CI. Instead of re-implementing the algorithm (which could
# silently drift from the shipped code), these tests execute the ACTUAL
# `_READ_MESSAGES_JXA` string under `node`, supplying a mocked Mail.app
# `Application` global so the real `run()` path drives our fixtures.
#
# osascript's `Application`/`JavaScript for Automation` runtime is a superset of
# plain JS for the constructs the scan uses (const/let, arrow fns, for-of, Set,
# Date/Math/JSON/Array), so running the same source under node is a faithful
# stand-in. Not covered here: real Mail.app object semantics and osascript
# timeouts (mocked away), and the `read_messages`/CLI boundary (covered by the
# tests above and by `orchestrator/backend/tests/test_vigil_cli_email.py`).

_NOW = datetime(2026, 7, 2, 12, 0, 0, tzinfo=UTC)

requires_node = pytest.mark.skipif(
    shutil.which("node") is None,
    reason="node is required to execute the JXA scan algorithm",
)

# Node harness: install a mocked Mail.app `Application`, splice in the real
# shipped JXA, then invoke its `run()` entry point and emit the resulting
# payload plus a raw message-touch counter. Placeholders are substituted (not
# f-string / %-formatted) so the JS braces stay literal.
_NODE_HARNESS_TEMPLATE = """\
let touchCount = 0;
function mkMsg(spec) {
  return {
    dateReceived: function () { touchCount += 1; return new Date(spec.ms); },
    messageId: function () { return spec.id; },
    sender: function () { return ""; },
    subject: function () { return ""; },
    content: function () { return ""; },
    source: function () { return ""; },
    toRecipients: function () { return []; },
    ccRecipients: function () { return []; },
  };
}
function mkMailbox(mailbox) {
  return {
    name: function () { return mailbox.name; },
    messages: function () { return mailbox.ms.map(mkMsg); },
    mailboxes: function () { return []; },
  };
}
const AGGREGATE = __AGGREGATE__.map(mkMsg);
const ACCOUNTS = __ACCOUNTS__.map(function (account) {
  return {
    name: function () { return account.name; },
    mailboxes: function () { return account.mailboxes.map(mkMailbox); },
  };
});
const MOCK = {
  inbox: { messages: function () { return AGGREGATE; } },
  accounts: function () { return ACCOUNTS; },
};
globalThis.Application = function () { return MOCK; };

__JXA__

const out = run([JSON.stringify(__CFG__)]);
process.stdout.write(JSON.stringify({ payload: JSON.parse(out), touchCount: touchCount }));
"""


def _ms(minutes_ago: int) -> int:
    """Epoch-ms for a message received ``minutes_ago`` before the fixed _NOW."""
    return int((_NOW - timedelta(minutes=minutes_ago)).timestamp() * 1000)


def _minutes_ago(iso: str) -> int:
    """Round-trip a JXA `toISOString()` value back to whole minutes before _NOW."""
    text = iso[:-1] + "+00:00" if iso.endswith("Z") else iso
    return round((_NOW - datetime.fromisoformat(text)).total_seconds() / 60)


def _specs(label: str, minutes: list[int], ids: list[str] | None = None) -> list[dict]:
    """Build message specs, defaulting each Message-ID to a unique synthetic one."""
    if ids is None:
        ids = [f"{label}-{index}@fixture.invalid" for index in range(len(minutes))]
    assert len(ids) == len(minutes)
    return [{"ms": _ms(m), "id": ident} for m, ident in zip(minutes, ids, strict=True)]


class _ScanResult:
    """Parsed JXA payload with the assertions these tests care about pre-derived."""

    def __init__(self, payload: dict, touch_count: int) -> None:
        self.payload = payload
        self.messages = payload["messages"]
        self.coverage = payload["coverage"]
        self.scan_errors = payload["scan_errors"]
        self.touch_count = touch_count
        self.minutes = [_minutes_ago(m["received_at"]) for m in self.messages]
        self.mailboxes = [m["mailbox"] for m in self.messages]

    @property
    def examined(self) -> int:
        return self.coverage["candidates_examined"]

    @property
    def complete(self) -> bool:
        return self.coverage["complete"]

    @property
    def truncated(self) -> list[str]:
        return self.coverage["truncated_mailboxes"]


def _run_jxa_scan(
    *,
    aggregate_minutes: list[int] | None = None,
    accounts: list[dict] | None = None,
    since_minutes: int = 10,
    limit: int = 200,
    candidate_limit: int | None = None,
    page_size: int = 200,
) -> _ScanResult:
    """Run the real `_READ_MESSAGES_JXA` under node against mocked mailboxes.

    ``aggregate_minutes`` populates the synthetic cross-account ``Mail.inbox``,
    which the scan uses ONLY as a fallback when no account folder is
    enumerable; ``accounts`` is a list of ``{"name", "mailboxes": [{"name",
    "minutes": [...], "ids": [...]}]}`` and only mailboxes whose name resolves
    to a relevant folder become scan sources. Message ages are whole minutes
    before _NOW; ``ids`` defaults to unique synthetic Message-IDs.
    """
    from vigil_cli.email import _READ_MESSAGES_JXA

    node = shutil.which("node")
    assert node is not None  # guarded by @requires_node

    aggregate_specs = _specs("aggregate", aggregate_minutes or [])
    accounts_specs = [
        {
            "name": account["name"],
            "mailboxes": [
                {
                    "name": mb["name"],
                    "ms": _specs(
                        f"{account['name']}-{mb['name']}",
                        mb["minutes"],
                        mb.get("ids"),
                    ),
                }
                for mb in account["mailboxes"]
            ],
        }
        for account in (accounts or [])
    ]
    cfg = {
        "since": (_NOW - timedelta(minutes=since_minutes)).isoformat(),
        "result_limit": limit,
        "page_size": page_size,
    }
    if candidate_limit is not None:
        cfg["candidate_limit"] = candidate_limit

    script = (
        _NODE_HARNESS_TEMPLATE
        .replace("__AGGREGATE__", json.dumps(aggregate_specs))
        .replace("__ACCOUNTS__", json.dumps(accounts_specs))
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
    return _ScanResult(data["payload"], data["touchCount"])


def _inbox_account(minutes: list[int], *, ids: list[str] | None = None) -> list[dict]:
    return [
        {
            "name": "example",
            "mailboxes": [{"name": "INBOX", "minutes": minutes, "ids": ids}],
        }
    ]


@requires_node
def test_jxa_newest_first_mailbox_keeps_recent_mail():
    # A newest-first mailbox (index 0 = newest) with recent mail at the top
    # followed by older mail. The original bug scanned oldest-first and broke on
    # the first message past the cutoff, dropping every recent message; the
    # direction-detecting scan must collect them.
    result = _run_jxa_scan(accounts=_inbox_account([1, 2, 3, 40, 50]), since_minutes=10)

    assert set(result.minutes) == {1, 2, 3}
    # Messages beyond the --within cutoff are (correctly) excluded, and having
    # walked the whole folder the scan can call the result authoritative.
    assert 40 not in result.minutes and 50 not in result.minutes
    assert result.complete is True
    assert result.truncated == []


@requires_node
def test_jxa_oldest_first_mailbox_walks_the_newest_end_first():
    # Oldest-first mailbox (index 0 = oldest, final index = newest). Direction
    # detection must walk from the NEWEST end, so a candidate window far smaller
    # than the folder still reaches the mail that just arrived. With a window of
    # two, an orientation-blind scan (or one that walked from index 0) would
    # spend the whole budget on 50/45-minute-old mail and report nothing.
    result = _run_jxa_scan(
        accounts=_inbox_account([50, 45, 40, 2, 1]),
        since_minutes=10,
        limit=2,
        candidate_limit=2,
    )

    assert result.minutes == [1, 2]
    assert result.examined == 2
    # ...and because the window stopped the scan short, the zero-beyond-this is
    # explicitly NOT authoritative.
    assert result.complete is False
    assert result.truncated == ["example/INBOX"]


@requires_node
def test_jxa_out_of_order_old_message_does_not_end_the_scan():
    # A provider array is not guaranteed monotonic: here a 40-minute-old message
    # sits between two recent ones. The endpoint dates make this look
    # newest-first, so a scan that treated the cutoff as an early exit would
    # stop at the 40-minute message and silently drop the trailing 2-minute one.
    # The shipped scan skips it and keeps walking the bounded window.
    result = _run_jxa_scan(accounts=_inbox_account([1, 40, 2]), since_minutes=10)

    assert sorted(result.minutes) == [1, 2]
    assert 40 not in result.minutes
    assert result.complete is True


@requires_node
def test_jxa_round_robin_paging_reaches_spam_before_the_window_closes():
    # Round-robin paging is what makes Spam/Junk/Archive real coverage rather
    # than nominal coverage. A 200-message Inbox of old mail plus a one-message
    # Spam folder holding the actual OTP: with a 10-candidate window, a scan
    # that drained folders sequentially would burn the entire budget inside the
    # Inbox and never touch Spam. One page per folder per round finds it.
    result = _run_jxa_scan(
        accounts=[
            {
                "name": "example",
                "mailboxes": [
                    {"name": "INBOX", "minutes": [60 + i for i in range(200)]},
                    {"name": "Spam", "minutes": [1]},
                ],
            }
        ],
        since_minutes=10,
        limit=10,
        candidate_limit=10,
        page_size=5,
    )

    assert result.minutes == [1]
    assert result.mailboxes == ["Spam"]
    # The Inbox is the folder that ran out of window, and it is named as such.
    assert result.complete is False
    assert result.truncated == ["example/INBOX"]
    scanned = {(m["mailbox"], m["complete"]) for m in result.coverage["mailboxes"]}
    assert ("Spam", True) in scanned


@requires_node
def test_jxa_candidate_limit_bounds_the_scan_and_is_reported_honestly():
    # The candidate window is the scan's only bound, so it has to be exact and
    # it has to be visible. 600 messages behind a 500-candidate window: the scan
    # examines exactly 500 and reports the folder as truncated.
    bounded = _run_jxa_scan(
        accounts=_inbox_account([1] + [60] * 599),
        since_minutes=10,
        candidate_limit=500,
    )

    assert bounded.examined == 500
    assert bounded.minutes == [1]  # the newest end is reached first
    assert bounded.complete is False
    assert bounded.truncated == ["example/INBOX"]
    assert any("candidate window" in err for err in bounded.scan_errors)
    # The harness counts every dateReceived() call; the only touches beyond the
    # examined window are the two endpoint probes used for direction detection.
    assert bounded.touch_count <= bounded.examined + 2

    # Widening the window is what changes the verdict — proving the bound, and
    # not some other early exit, is what stopped the scan above.
    widened = _run_jxa_scan(
        accounts=_inbox_account([1] + [60] * 599),
        since_minutes=10,
        candidate_limit=1_000,
    )

    assert widened.examined == 600
    assert widened.minutes == [1]
    assert widened.complete is True
    assert widened.truncated == []


@requires_node
def test_jxa_candidate_limit_never_undercuts_the_result_limit():
    # candidateLimit = max(resultLimit, candidate_limit): a caller asking for 5
    # results can never be served a 1-candidate scan.
    result = _run_jxa_scan(
        accounts=_inbox_account([1, 2, 3, 4, 5]),
        since_minutes=10,
        limit=5,
        candidate_limit=1,
    )

    assert result.coverage["candidate_limit"] == 5
    assert sorted(result.minutes) == [1, 2, 3, 4, 5]


@requires_node
def test_jxa_message_id_dedup_collapses_duplicate_folder_views():
    # Inbox and All Mail are separate scan sources that show the SAME message.
    # Message-ID dedup keeps it once, while both views still count against the
    # examined budget (the scan cannot know they are duplicates until it looks).
    result = _run_jxa_scan(
        accounts=[
            {
                "name": "example",
                "mailboxes": [
                    {"name": "INBOX", "minutes": [1], "ids": ["otp@fixture.invalid"]},
                    {"name": "All Mail", "minutes": [1], "ids": ["otp@fixture.invalid"]},
                ],
            }
        ],
        since_minutes=10,
    )

    assert result.minutes == [1]
    assert [m["message_id"] for m in result.messages] == ["otp@fixture.invalid"]
    assert result.examined == 2
    assert result.coverage["candidates_collected"] == 1
    assert result.complete is True


@requires_node
def test_jxa_aggregate_inbox_fallback_is_used_but_never_authoritative():
    # Some providers expose only the synthetic cross-account Mail.inbox through
    # JXA. It is still scanned (with unknown ordering, so both ends are walked),
    # but an empty or no-match result from it CANNOT be authoritative because
    # Archive/Important/Spam coverage was never available.
    result = _run_jxa_scan(aggregate_minutes=[1, 40, 2], accounts=[], since_minutes=10)

    assert sorted(result.minutes) == [1, 2]
    assert 40 not in result.minutes
    assert result.coverage["used_aggregate_inbox"] is True
    assert result.complete is False
    assert any("aggregate Inbox fallback" in err for err in result.scan_errors)


def test_read_messages_candidate_window_is_load_bearing(monkeypatch):
    # Node-free guard on the Python half of the bound: `read_messages` sizes the
    # candidate window from --limit and hands it to the JXA. The window must
    # always be at least the result limit, at least MIN_CANDIDATE_WINDOW, and
    # never above MAX_CANDIDATE_WINDOW.
    from vigil_cli import email as email_module

    seen: list[dict] = []

    def fake_run(_script, args, *, timeout_seconds):
        seen.append(json.loads(args[0]))
        return {"messages": [], "scan_errors": [], "coverage": {}}

    monkeypatch.setattr(email_module, "_run_jxa_json", fake_run)

    for limit in (1, 5, 200, 5_000):
        email_module.read_messages(since=_NOW, limit=limit)

    windows = [cfg["candidate_limit"] for cfg in seen]
    assert windows == [
        email_module.MIN_CANDIDATE_WINDOW,
        email_module.MIN_CANDIDATE_WINDOW,
        email_module.MIN_CANDIDATE_WINDOW,
        email_module.MAX_CANDIDATE_WINDOW,
    ]
    for cfg, limit in zip(seen, (1, 5, 200, 5_000), strict=True):
        assert cfg["result_limit"] == limit
        assert cfg["candidate_limit"] >= limit
        assert cfg["page_size"] == email_module.MAILBOX_PAGE_SIZE


def test_jxa_scan_wiring_present_in_source():
    # Cheap, node-free guard on the wiring the tests above depend on, so an
    # accidental edit to the JXA is caught even where node is unavailable.
    from vigil_cli.email import _READ_MESSAGES_JXA as jxa

    # The candidate window is the bound, and it can never undercut the result limit.
    assert "const candidateLimit = Math.max(resultLimit, Number(cfg.candidate_limit || 2000));" in jxa
    # Per-source direction detection, and a cutoff that skips rather than breaks.
    assert "source.newestFirst === true" in jxa
    assert "source.newestFirst === false" in jxa
    assert "if (receivedDate && receivedDate < since) {" in jxa
    # Spam/Junk/Archive are required coverage, not extras.
    for folder in ("all mail", "important", "spam", "junk", "archive"):
        assert f'"{folder}"' in jxa
    # The aggregate Inbox stays a flagged fallback, never a silent default.
    assert "used_aggregate_inbox = true" in jxa
