"""Read recent messages from a local Mail.app mailbox for verification-code retrieval.

This module drives macOS Mail.app through JXA / ``osascript`` — the same
mechanism ``email-utility`` uses to scan inbox replies. It does NOT
use SMTP/IMAP/an API: the mailbox being read must be configured as a Mail.app
account on this host (e.g. the ``researcher.example`` test mailbox used during
authenticated security testing). No credentials are stored by Vigil — Mail.app
owns the account auth.

The primary use is retrieving short-lived email-verification codes (6-8 digit
OTPs or verification links) sent to a test mailbox: ``vigil email`` filters by
recipient mailbox, sender, and recency, optionally extracts the matching token,
and can emit JSON so an automation can parse the code directly.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parseaddr


class EmailReadError(RuntimeError):
    """Raised when Mail.app automation fails or returns an unexpected payload."""


# Default extraction pattern: a 6-8 digit verification / OTP code. Used when
# --match is omitted but --extract is requested (or in JSON mode where the
# automation always wants a candidate code field).
DEFAULT_CODE_PATTERN = r"\b(\d{6,8})\b"

# Reads recent messages across the Inbox and every account's inbox-like
# mailboxes, filtered server-... no — filtered host-side after collection by
# received time and recipient address. Mirrors email-utility's
# _SCAN_REPLIES_JXA, extended to also surface the message's `to` recipients so
# we can scope to a specific test mailbox address.
_READ_MESSAGES_JXA = r"""
function run(argv) {
  const cfg = JSON.parse(argv[0] || "{}");
  const since = cfg.since ? new Date(String(cfg.since)) : new Date(0);
  const limit = Math.max(1, Number(cfg.limit || 200));

  function safe(fn, fallbackValue) {
    try {
      return fn();
    } catch (_err) {
      return fallbackValue;
    }
  }

  function isoDate(value) {
    if (!value) {
      return null;
    }
    try {
      return new Date(value).toISOString();
    } catch (_err) {
      return null;
    }
  }

  function recipientAddresses(message) {
    const out = [];
    const collections = [
      safe(() => message.toRecipients(), []),
      safe(() => message.ccRecipients(), []),
    ];
    for (const collection of collections) {
      if (!Array.isArray(collection)) {
        continue;
      }
      for (const recipient of collection) {
        const address = safe(() => recipient.address(), "");
        if (address) {
          out.push(String(address));
        }
      }
    }
    return out;
  }

  function collectMessages(messages, accountName, mailboxName, payload) {
    if (!Array.isArray(messages)) {
      return;
    }
    for (let i = messages.length - 1; i >= 0 && payload.messages.length < limit; i -= 1) {
      const message = messages[i];
      const received = safe(() => message.dateReceived(), null);
      const receivedDate = received ? new Date(received) : null;
      if (receivedDate && receivedDate < since) {
        // Inbox messages are roughly newest-last; once we cross the cutoff the
        // rest of this mailbox is older, so stop scanning it.
        break;
      }
      payload.messages.push({
        account: String(accountName || ""),
        mailbox: String(mailboxName || ""),
        sender: String(safe(() => message.sender(), "") || ""),
        recipients: recipientAddresses(message),
        subject: String(safe(() => message.subject(), "") || ""),
        body: String(safe(() => message.content(), "") || ""),
        received_at: isoDate(received),
      });
    }
  }

  const Mail = Application("Mail");
  const payload = { messages: [], scan_errors: [] };

  collectMessages(safe(() => Mail.inbox.messages(), []), "", "Inbox", payload);

  const accounts = safe(() => Mail.accounts(), []);
  for (const account of accounts) {
    if (payload.messages.length >= limit) {
      break;
    }
    const accountName = safe(() => account.name(), "");
    const mailboxes = safe(() => account.mailboxes(), []);
    for (const mailbox of mailboxes) {
      if (payload.messages.length >= limit) {
        break;
      }
      const mailboxName = String(safe(() => mailbox.name(), "") || "");
      if (!mailboxName || !mailboxName.toLowerCase().includes("inbox")) {
        continue;
      }
      collectMessages(safe(() => mailbox.messages(), []), accountName, mailboxName, payload);
    }
  }

  return JSON.stringify(payload);
}
"""


@dataclass(frozen=True, slots=True)
class EmailMessage:
    sender: str
    recipients: tuple[str, ...]
    subject: str
    body: str
    received_at: datetime
    account: str = ""
    mailbox: str = ""


def normalize_email(value: str) -> str:
    """Lower-case, strip, and unwrap a ``Name <addr>`` form to the bare address."""
    raw = str(value or "").strip()
    address = parseaddr(raw)[1] or raw
    return address.strip().lower()


def read_messages(
    *,
    since: datetime,
    limit: int = 200,
    timeout_seconds: float = 30.0,
) -> list[EmailMessage]:
    """Scan Mail.app inbox messages received at/after ``since``."""
    payload = {"since": since.isoformat(), "limit": limit}
    raw = _run_jxa_json(_READ_MESSAGES_JXA, [json.dumps(payload)], timeout_seconds=timeout_seconds)
    if not isinstance(raw, dict):
        raise EmailReadError(f"unexpected Mail.app read response: {raw!r}")
    messages_raw = raw.get("messages", [])
    if not isinstance(messages_raw, list):
        raise EmailReadError("unexpected Mail.app read message format")

    messages: list[EmailMessage] = []
    for item in messages_raw:
        if not isinstance(item, dict):
            continue
        received_at = _parse_datetime(item.get("received_at"))
        if received_at is None:
            continue
        recipients_raw = item.get("recipients", [])
        recipients = tuple(
            str(addr) for addr in recipients_raw if isinstance(recipients_raw, list) and addr
        )
        messages.append(
            EmailMessage(
                sender=str(item.get("sender", "") or ""),
                recipients=recipients,
                subject=str(item.get("subject", "") or ""),
                body=str(item.get("body", "") or ""),
                received_at=received_at,
                account=str(item.get("account", "") or ""),
                mailbox=str(item.get("mailbox", "") or ""),
            )
        )
    return messages


def filter_messages(
    messages: Sequence[EmailMessage],
    *,
    mailbox_address: str,
    from_filter: str | None = None,
    since: datetime | None = None,
) -> list[EmailMessage]:
    """Keep messages addressed to ``mailbox_address`` and matching the filters.

    ``mailbox_address`` and ``from_filter`` accept either a full address
    (``security@bank.acme.example``) or a bare domain (``@bank.acme.example`` / ``bank.acme.example``).
    Results are returned newest-first.
    """
    mailbox_norm = normalize_email(mailbox_address)
    from_norm = _normalize_filter(from_filter) if from_filter else None

    kept: list[EmailMessage] = []
    for message in messages:
        if since is not None and message.received_at < since:
            continue
        if mailbox_norm and not _address_matches(mailbox_norm, message.recipients):
            continue
        if from_norm and not _address_matches(from_norm, [message.sender]):
            continue
        kept.append(message)

    kept.sort(key=lambda m: m.received_at, reverse=True)
    return kept


def extract_token(body: str, *, pattern: str = DEFAULT_CODE_PATTERN) -> str | None:
    """Return the first capture group (or whole match) of ``pattern`` in ``body``.

    Used to pull a verification code or link out of a message body. Raises
    ``EmailReadError`` on an invalid regex so the operator gets a clear message
    instead of a traceback.
    """
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error as exc:
        raise EmailReadError(f"invalid --match regex {pattern!r}: {exc}") from exc
    match = compiled.search(body or "")
    if match is None:
        return None
    if match.groups():
        return match.group(1)
    return match.group(0)


def message_to_dict(message: EmailMessage, *, extracted: str | None = None) -> dict[str, object]:
    return {
        "received_at": message.received_at.isoformat(),
        "from": message.sender,
        "to": list(message.recipients),
        "subject": message.subject,
        "account": message.account,
        "mailbox": message.mailbox,
        "extracted": extracted,
        "body": message.body,
    }


def _normalize_filter(value: str) -> str:
    """Normalize a sender/recipient filter: a domain keeps its leading ``@``."""
    raw = str(value or "").strip().lower()
    if not raw:
        return raw
    if "@" not in raw:
        # Bare domain like "bank.acme.example" -> "@bank.acme.example" so it only matches the
        # domain part, never a localpart substring.
        return "@" + raw
    if raw.startswith("@"):
        return raw
    # Full address; unwrap any display-name form.
    return normalize_email(raw)


def _address_matches(needle: str, addresses: Sequence[str]) -> bool:
    """True if ``needle`` matches any of ``addresses``.

    A domain needle (starts with ``@``) matches by domain suffix; a full
    address matches exactly.
    """
    for raw in addresses:
        address = normalize_email(raw)
        if not address:
            continue
        if needle.startswith("@"):
            if address.endswith(needle):
                return True
        elif address == needle:
            return True
    return False


def _parse_datetime(value: object) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def cutoff_for_window(minutes: int, *, now: datetime | None = None) -> datetime:
    current = now or datetime.now(UTC)
    return current - timedelta(minutes=minutes)


def _run_jxa_json(
    script: str,
    args: Sequence[str],
    *,
    timeout_seconds: float | None = None,
) -> object:
    command = ["osascript", "-l", "JavaScript", "-"]
    command.extend(args)
    try:
        result = subprocess.run(
            command,
            input=script,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:  # osascript missing -> not macOS.
        raise EmailReadError(
            "osascript not found; `vigil email` requires macOS Mail.app automation"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise EmailReadError(f"osascript timed out after {timeout_seconds}s") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown osascript failure"
        raise EmailReadError(f"osascript failed: {detail}")

    stdout = result.stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise EmailReadError(f"failed to parse Mail.app JSON output: {exc}") from exc
