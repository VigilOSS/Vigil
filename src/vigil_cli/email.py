"""Read recent messages from a local Mail.app mailbox for verification-code retrieval.

This module drives macOS Mail.app through JXA / ``osascript`` — the same
mechanism ``email-utility`` uses to scan inbox replies. It does NOT
use SMTP/IMAP/an API: the mailbox being read must be configured as a Mail.app
account on this host (e.g. the ``researcher.example`` test mailbox used during
authenticated security testing). No credentials are stored by Vigil — Mail.app
owns the account auth.

The primary use is retrieving short-lived email-verification codes (6-8 digit
OTPs or verification links) sent to a test mailbox: ``vigil email`` filters by
recipient mailbox, sender or subject, and recency; can poll for delayed mail;
can decode links hidden in raw MIME; and emits JSON for automation.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser


class EmailReadError(RuntimeError):
    """Raised when Mail.app automation fails or returns an unexpected payload.

    ``coverage`` is populated when the failure IS a coverage verdict (an empty
    scan that cannot be called authoritative), so a caller can report the same
    folder-by-folder proof it would have reported on success instead of
    degrading to a bare message.

    ``kind`` discriminates a read that never returned (``"timeout"``) from every
    other failure, so the CLI can report *which* way the instrument failed
    instead of collapsing both into one error string.
    """

    def __init__(
        self,
        *args: object,
        coverage: EmailScanCoverage | None = None,
        kind: str = "error",
    ) -> None:
        super().__init__(*args)
        self.coverage = coverage
        self.kind = kind


# Default extraction pattern: a 6-8 digit verification / OTP code. Used when
# --match is omitted but --extract is requested (or in JSON mode where the
# automation always wants a candidate code field).
DEFAULT_CODE_PATTERN = r"\b(\d{6,8})\b"

# Mail.app does not offer a portable server-side recipient/sender/subject
# query across providers.  ``--limit`` is therefore the *matching result*
# limit, while collection walks this explicit, bounded candidate window before
# Python applies those filters.  The window is intentionally large enough to
# cover more than one ordinary Mail.app page without turning a verification
# lookup into an unbounded mailbox crawl.
MAILBOX_PAGE_SIZE = 200
MIN_CANDIDATE_WINDOW = 2_000
MAX_CANDIDATE_WINDOW = 10_000

# Wall-clock budget for the whole osascript read. The previous 30s was a guess,
# not a measured bound, and it fails asymmetrically: too short aborts a lane
# mid-flight with a hard error, too long merely waits. A multi-account Mail.app
# walking Inbox + Archive + Important + Spam routinely needs more than 30s.
# `--timeout-seconds` remains the override.
DEFAULT_READ_TIMEOUT_SECONDS = 90.0

# Reads recent messages across each account's Inbox plus provider archive,
# Important, and Spam/Junk folders, filtered host-side after collection.  The
# synthetic
# cross-account ``Mail.inbox`` is used only as a fallback because including it
# alongside account folders creates duplicate views and can consume the scan
# window before an archive-only OTP is reached.
_READ_MESSAGES_JXA = r"""
function run(argv) {
  const cfg = JSON.parse(argv[0] || "{}");
  const since = cfg.since ? new Date(String(cfg.since)) : new Date(0);
  const resultLimit = Math.max(1, Number(cfg.result_limit || cfg.limit || 200));
  const candidateLimit = Math.max(resultLimit, Number(cfg.candidate_limit || 2000));
  const pageSize = Math.max(1, Number(cfg.page_size || 200));
  const maxDiscoveryDepth = 4;
  const maxRelevantMailboxes = 64;
  const includeSource = Boolean(cfg.include_source);

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

  function normalizedMailboxName(value) {
    return String(value || "")
      .toLowerCase()
      .replace(/[\[\]_/.-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  // Folders a verification mail can legitimately land in.  Spam/Junk and
  // Archive are load-bearing, not optional: providers routinely file an OTP as
  // spam, and Gmail's All Mail excludes Spam and Trash by design — so without
  // them a filtered OTP is invisible to every other folder and the scan reports
  // an authoritative `complete: true` zero that is simply wrong.
  const relevantMailboxNames = [
    "inbox",
    "all mail",
    "important",
    "spam",
    "junk",
    "junk mail",
    "junk email",
    "archive",
  ];

  function isRelevantMailbox(name) {
    const normalized = normalizedMailboxName(name);
    return relevantMailboxNames.some(function (candidate) {
      return normalized === candidate || normalized.endsWith(" " + candidate);
    });
  }

  function sourceFor(messages, accountName, mailboxName, forceUnknownOrder) {
    if (!Array.isArray(messages)) {
      return null;
    }
    const total = messages.length;

    function dateAt(idx) {
      const value = safe(() => messages[idx].dateReceived(), null);
      return value ? new Date(value) : null;
    }

    let newestFirst = null;
    if (!forceUnknownOrder && total > 1) {
      const firstDate = dateAt(0);
      const lastDate = dateAt(total - 1);
      if (firstDate && lastDate && firstDate.getTime() !== lastDate.getTime()) {
        newestFirst = firstDate.getTime() > lastDate.getTime();
      }
    }
    return {
      messages: messages,
      accountName: String(accountName || ""),
      mailboxName: String(mailboxName || ""),
      total: total,
      newestFirst: newestFirst,
      low: 0,
      high: total - 1,
      takeLow: true,
      examined: 0,
      pagesScanned: 0,
      done: total === 0,
      complete: total === 0,
    };
  }

  function nextIndex(source) {
    if (source.low > source.high) {
      return null;
    }
    if (source.newestFirst === true) {
      const index = source.low;
      source.low += 1;
      return index;
    }
    if (source.newestFirst === false) {
      const index = source.high;
      source.high -= 1;
      return index;
    }
    // Unknown ordering: alternate the two ends page-by-page rather than
    // betting that either index zero or the final index is newest.
    let index;
    if (source.takeLow) {
      index = source.low;
      source.low += 1;
    } else {
      index = source.high;
      source.high -= 1;
    }
    source.takeLow = !source.takeLow;
    return index;
  }

  function stableMessageKey(message, received, recipients, sender, subject, body) {
    const messageId = String(safe(() => message.messageId(), "") || "").trim();
    if (messageId) {
      return { key: "id:" + messageId.toLowerCase(), messageId: messageId };
    }
    return {
      key: "fallback:" + [sender, recipients.slice().sort().join(","), subject, body, isoDate(received)].join("\u001f"),
      messageId: "",
    };
  }

  function scanPage(source, payload, seen) {
    let pageExamined = 0;
    while (!source.done && pageExamined < pageSize && payload.coverage.candidates_examined < candidateLimit) {
      const index = nextIndex(source);
      if (index === null) {
        source.done = true;
        source.complete = true;
        break;
      }
      const message = source.messages[index];
      const received = safe(() => message.dateReceived(), null);
      const receivedDate = received ? new Date(received) : null;
      source.examined += 1;
      pageExamined += 1;
      payload.coverage.candidates_examined += 1;

      if (receivedDate && receivedDate < since) {
        // Endpoint dates choose the likely newest edge, but they do not prove
        // the whole provider array is monotonic.  Keep walking the bounded
        // window; only exhausting the folder makes a no-match authoritative.
        continue;
      }

      const sender = String(safe(() => message.sender(), "") || "");
      const recipients = recipientAddresses(message);
      const subject = String(safe(() => message.subject(), "") || "");
      const body = String(safe(() => message.content(), "") || "");
      const stable = stableMessageKey(message, received, recipients, sender, subject, body);
      if (seen.has(stable.key)) {
        continue;
      }
      seen.add(stable.key);
      payload.messages.push({
        account: source.accountName,
        mailbox: source.mailboxName,
        message_id: stable.messageId,
        sender: sender,
        recipients: recipients,
        subject: subject,
        body: body,
        source: includeSource ? String(safe(() => message.source(), "") || "") : "",
        received_at: isoDate(received),
      });
      payload.coverage.candidates_collected += 1;
    }
    if (pageExamined > 0) {
      source.pagesScanned += 1;
    }
    if (source.low > source.high) {
      source.done = true;
      source.complete = true;
    }
  }

  const Mail = Application("Mail");
  const payload = {
    messages: [],
    scan_errors: [],
    coverage: {
      complete: true,
      result_limit: resultLimit,
      candidate_limit: candidateLimit,
      page_size: pageSize,
      candidates_examined: 0,
      candidates_collected: 0,
      mailboxes: [],
      truncated_mailboxes: [],
      used_aggregate_inbox: false,
      discovery_complete: true,
      discovery_truncated: false,
    },
  };
  const sources = [];
  const sourceNames = new Set();

  function recordScanError(message, discoveryTruncated) {
    payload.coverage.complete = false;
    if (discoveryTruncated) {
      payload.coverage.discovery_complete = false;
      payload.coverage.discovery_truncated = true;
    }
    if (!payload.scan_errors.includes(message)) {
      payload.scan_errors.push(message);
    }
  }

  function readMailboxMessages(mailbox, label) {
    try {
      const messages = mailbox.messages();
      if (!Array.isArray(messages)) {
        throw new Error("messages were not enumerable");
      }
      return messages;
    } catch (err) {
      recordScanError(label + " message access failed: " + String(err), false);
      return null;
    }
  }

  function readChildMailboxes(owner, label) {
    try {
      const mailboxes = owner.mailboxes();
      if (!Array.isArray(mailboxes)) {
        throw new Error("mailboxes were not enumerable");
      }
      return mailboxes;
    } catch (err) {
      recordScanError(label + " mailbox discovery failed: " + String(err), true);
      return [];
    }
  }

  function discoverMailboxes(account, accountName, mailboxes, parentName, depth) {
    if (!Array.isArray(mailboxes)) {
      recordScanError("mailbox discovery returned a non-enumerable collection", true);
      return;
    }
    if (mailboxes.length === 0) {
      return;
    }
    if (depth > maxDiscoveryDepth) {
      recordScanError(
        "discovery depth limit reached at " + (parentName || String(accountName || "account")),
        true
      );
      return;
    }
    if (sources.length >= maxRelevantMailboxes) {
      recordScanError("relevant mailbox source limit reached", true);
      return;
    }
    for (const mailbox of mailboxes) {
      if (sources.length >= maxRelevantMailboxes) {
        recordScanError("relevant mailbox source limit reached", true);
        break;
      }
      const ownName = String(safe(() => mailbox.name(), "") || "");
      if (!ownName) {
        continue;
      }
      const pathName = parentName ? parentName + "/" + ownName : ownName;
      const sourceName = String(accountName || "") + "/" + pathName;
      if (isRelevantMailbox(pathName) && !sourceNames.has(sourceName.toLowerCase())) {
        const messages = readMailboxMessages(mailbox, sourceName);
        const source = messages === null ? null : sourceFor(messages, accountName, pathName, false);
        if (source !== null) {
          sourceNames.add(sourceName.toLowerCase());
          sources.push(source);
        }
      }
      discoverMailboxes(
        account,
        accountName,
        readChildMailboxes(mailbox, sourceName),
        pathName,
        depth + 1
      );
    }
  }

  let accounts = [];
  try {
    accounts = Mail.accounts();
  } catch (err) {
    payload.coverage.complete = false;
    payload.scan_errors.push("Mail.app account enumeration failed: " + String(err));
  }
  if (!Array.isArray(accounts)) {
    accounts = [];
    payload.coverage.complete = false;
    payload.scan_errors.push("Mail.app returned no enumerable account list");
  }
  for (const account of accounts) {
    const accountName = safe(() => account.name(), "");
    discoverMailboxes(
      account,
      accountName,
      readChildMailboxes(account, String(accountName || "account")),
      "",
      0
    );
  }

  // Some Mail.app providers expose only the synthetic Inbox through JXA.  It
  // remains a useful fallback, but an empty result cannot be called
  // authoritative because archive/Important coverage was unavailable.
  if (sources.length === 0) {
    payload.coverage.complete = false;
    payload.coverage.used_aggregate_inbox = true;
    payload.scan_errors.push("provider Inbox/All Mail/Important/Spam/Archive folders were not enumerable; used aggregate Inbox fallback");
    const aggregateMessages = readMailboxMessages(Mail.inbox, "aggregate Inbox");
    const aggregate = aggregateMessages === null ? null : sourceFor(aggregateMessages, "", "Inbox", true);
    if (aggregate !== null) {
      sources.push(aggregate);
    }
  }

  // Round-robin one page per relevant folder.  A large Inbox therefore cannot
  // consume the global candidate budget before All Mail or Important gets a
  // first and subsequent page.
  const seen = new Set();
  let madeProgress = true;
  while (payload.coverage.candidates_examined < candidateLimit && madeProgress) {
    madeProgress = false;
    for (const source of sources) {
      if (source.done || payload.coverage.candidates_examined >= candidateLimit) {
        continue;
      }
      const before = source.examined;
      scanPage(source, payload, seen);
      if (source.examined > before) {
        madeProgress = true;
      }
    }
  }

  for (const source of sources) {
    if (!source.done) {
      source.complete = false;
      payload.coverage.complete = false;
      const label = (source.accountName ? source.accountName + "/" : "") + source.mailboxName;
      payload.coverage.truncated_mailboxes.push(label);
      payload.scan_errors.push(label + " reached candidate window before scan completion");
    }
    payload.coverage.mailboxes.push({
      account: source.accountName,
      mailbox: source.mailboxName,
      examined: source.examined,
      pages_scanned: source.pagesScanned,
      complete: source.complete,
    });
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
    raw_source: str = ""
    message_id: str = ""


@dataclass(frozen=True, slots=True)
class MailboxScanCoverage:
    """Bounded scan progress for one Mail.app folder."""

    account: str
    mailbox: str
    examined: int
    pages_scanned: int
    complete: bool


@dataclass(frozen=True, slots=True)
class EmailScanCoverage:
    """Coverage proof used to distinguish a real no-match from a partial scan."""

    complete: bool
    candidate_limit: int
    page_size: int
    candidates_examined: int
    candidates_collected: int
    mailboxes: tuple[MailboxScanCoverage, ...]
    truncated_mailboxes: tuple[str, ...] = ()
    scan_errors: tuple[str, ...] = ()
    used_aggregate_inbox: bool = False
    discovery_complete: bool = True
    discovery_truncated: bool = False

    def incomplete_summary(self) -> str:
        details = list(self.scan_errors)
        if not details and self.truncated_mailboxes:
            details.append(
                "candidate window reached in " + ", ".join(self.truncated_mailboxes)
            )
        if not details:
            details.append("Mail.app did not report complete folder coverage")
        if self.truncated_mailboxes:
            # Naming the lever matters more now that Spam/Junk/Archive share the
            # same global candidate window: without it the caller learns only that
            # the answer is untrustworthy, not how to get a trustworthy one.
            details.append(
                f"raise --limit to widen the {self.candidate_limit}-candidate window"
            )
        return "; ".join(details)


class EmailScan(list[EmailMessage]):
    """List-compatible message result with backward-compatible scan metadata."""

    def __init__(
        self,
        values: Sequence[EmailMessage] = (),
        *,
        result_limit: int | None = None,
        coverage: EmailScanCoverage | None = None,
    ) -> None:
        super().__init__(values)
        self.result_limit = result_limit
        self.coverage = coverage or EmailScanCoverage(
            complete=True,
            candidate_limit=0,
            page_size=0,
            candidates_examined=len(values),
            candidates_collected=len(values),
            mailboxes=(),
        )


def normalize_email(value: str) -> str:
    """Lower-case, strip, and unwrap a ``Name <addr>`` form to the bare address."""
    raw = str(value or "").strip()
    address = parseaddr(raw)[1] or raw
    return address.strip().lower()


def _coverage_int(value: object, fallback: int = 0) -> int:
    if not isinstance(value, (int, float, str)):
        return fallback
    try:
        return max(0, int(value))
    except (ValueError, OverflowError):
        return fallback


def _parse_scan_coverage(
    value: object,
    *,
    scan_errors: object,
    fallback_candidate_limit: int,
    fallback_page_size: int,
    message_count: int,
) -> EmailScanCoverage:
    raw = value if isinstance(value, Mapping) else {}
    errors = tuple(
        str(item)
        for item in (scan_errors if isinstance(scan_errors, list) else [])
        if item
    )
    mailboxes: list[MailboxScanCoverage] = []
    mailboxes_raw = raw.get("mailboxes", [])
    if isinstance(mailboxes_raw, list):
        for item in mailboxes_raw:
            if not isinstance(item, Mapping):
                continue
            mailboxes.append(
                MailboxScanCoverage(
                    account=str(item.get("account", "") or ""),
                    mailbox=str(item.get("mailbox", "") or ""),
                    examined=_coverage_int(item.get("examined")),
                    pages_scanned=_coverage_int(item.get("pages_scanned")),
                    complete=bool(item.get("complete", False)),
                )
            )
    truncated_raw = raw.get("truncated_mailboxes", [])
    truncated = tuple(
        str(item)
        for item in (truncated_raw if isinstance(truncated_raw, list) else [])
        if item
    )
    # A legacy/faked payload without the additive coverage object stays
    # compatible and is treated as complete unless it explicitly reported a
    # scan error.  The bundled JXA always supplies the richer coverage proof.
    reported_complete = bool(raw.get("complete", not errors))
    discovery_complete = bool(raw.get("discovery_complete", reported_complete))
    discovery_truncated = bool(raw.get("discovery_truncated", False))
    complete = reported_complete and discovery_complete and not discovery_truncated
    return EmailScanCoverage(
        complete=complete,
        candidate_limit=_coverage_int(
            raw.get("candidate_limit"), fallback_candidate_limit
        ),
        page_size=_coverage_int(raw.get("page_size"), fallback_page_size),
        candidates_examined=_coverage_int(
            raw.get("candidates_examined"), message_count
        ),
        candidates_collected=_coverage_int(
            raw.get("candidates_collected"), message_count
        ),
        mailboxes=tuple(mailboxes),
        truncated_mailboxes=truncated,
        scan_errors=errors,
        used_aggregate_inbox=bool(raw.get("used_aggregate_inbox", False)),
        discovery_complete=discovery_complete,
        discovery_truncated=discovery_truncated,
    )


def read_messages(
    *,
    since: datetime,
    limit: int = 200,
    timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
    include_source: bool = False,
) -> EmailScan:
    """Scan relevant Mail.app folders and return list-compatible messages.

    ``limit`` is applied to the final filtered results by :func:`filter_messages`,
    not to the raw candidates.  Coverage metadata remains available on the
    returned list as ``.coverage``.
    """
    candidate_limit = max(
        limit,
        min(max(limit * 10, MIN_CANDIDATE_WINDOW), MAX_CANDIDATE_WINDOW),
    )
    payload = {
        "since": since.isoformat(),
        "result_limit": limit,
        "candidate_limit": candidate_limit,
        "page_size": MAILBOX_PAGE_SIZE,
        "include_source": include_source,
    }
    raw = _run_jxa_json(_READ_MESSAGES_JXA, [json.dumps(payload)], timeout_seconds=timeout_seconds)
    if not isinstance(raw, dict):
        raise EmailReadError(f"unexpected Mail.app read response: {raw!r}")
    messages_raw = raw.get("messages", [])
    if not isinstance(messages_raw, list):
        raise EmailReadError("unexpected Mail.app read message format")

    messages: list[EmailMessage] = []
    parse_errors: list[str] = []
    for item in messages_raw:
        if not isinstance(item, dict):
            continue
        received_at = _parse_datetime(item.get("received_at"))
        if received_at is None:
            account = str(item.get("account", "") or "")
            mailbox = str(item.get("mailbox", "") or "")
            location = "/".join(part for part in (account, mailbox) if part) or "mailbox"
            parse_errors.append(f"{location} returned unreadable received_at")
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
                raw_source=str(item.get("source", "") or ""),
                message_id=str(item.get("message_id", "") or ""),
            )
        )
    coverage = _parse_scan_coverage(
        raw.get("coverage"),
        scan_errors=raw.get("scan_errors"),
        fallback_candidate_limit=candidate_limit,
        fallback_page_size=MAILBOX_PAGE_SIZE,
        message_count=len(messages),
    )
    if parse_errors:
        coverage = replace(
            coverage,
            complete=False,
            scan_errors=coverage.scan_errors + tuple(dict.fromkeys(parse_errors)),
        )
    return EmailScan(messages, result_limit=limit, coverage=coverage)


def filter_messages(
    messages: Sequence[EmailMessage],
    *,
    mailbox_address: str,
    from_filter: str | None = None,
    subject_filter: str | None = None,
    since: datetime | None = None,
) -> EmailScan:
    """Keep messages addressed to ``mailbox_address`` and matching the filters.

    ``mailbox_address`` and ``from_filter`` accept either a full address
    (``security@acme-bank.example``) or a bare domain (``@acme-bank.example`` / ``acme-bank.example``).
    Results are returned newest-first.
    """
    # Both filters go through the same normalizer: `mailbox_address` used to use
    # `normalize_email`, so the bare-domain form documented above silently
    # matched nothing while the identical `from_filter` form worked.
    mailbox_norm = _normalize_filter(mailbox_address)
    from_norm = _normalize_filter(from_filter) if from_filter else None
    subject_norm = str(subject_filter or "").strip().casefold()

    kept: list[EmailMessage] = []
    seen: set[tuple[object, ...]] = set()
    for message in messages:
        if since is not None and message.received_at < since:
            continue
        if mailbox_norm and not _address_matches(mailbox_norm, message.recipients):
            continue
        if from_norm and not _address_matches(from_norm, [message.sender]):
            continue
        if subject_norm and subject_norm not in message.subject.casefold():
            continue
        # Mail.app exposes the same message through both its synthetic
        # cross-account Inbox and the backing account's INBOX. Treat those as
        # one message while retaining the first view's account/mailbox fields.
        if message.message_id:
            duplicate_key: tuple[object, ...] = (
                "message_id",
                message.message_id.strip().casefold(),
            )
        else:
            duplicate_key = (
                "content",
                normalize_email(message.sender),
                tuple(sorted(normalize_email(value) for value in message.recipients)),
                message.subject,
                message.body,
                message.received_at,
            )
        if duplicate_key in seen:
            continue
        seen.add(duplicate_key)
        kept.append(message)

    kept.sort(key=lambda m: m.received_at, reverse=True)
    result_limit = getattr(messages, "result_limit", None)
    if isinstance(result_limit, int) and result_limit > 0:
        kept = kept[:result_limit]
    coverage = getattr(messages, "coverage", None)
    result = EmailScan(kept, result_limit=result_limit, coverage=coverage)
    if not result and not result.coverage.complete:
        raise EmailReadError(
            "incomplete Mail.app scan; no authoritative match: "
            + result.coverage.incomplete_summary(),
            coverage=result.coverage,
        )
    return result


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


class _LinkCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, _tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.links.append(value)


def extract_links(message: EmailMessage) -> list[str]:
    """Return unique HTTP(S) links from visible content and decoded MIME source.

    Mail.app's ``content`` property keeps link labels but commonly strips their
    href targets. When ``raw_source`` is available, parse and decode its MIME
    parts so quoted-printable HTML download and verification links are exposed.
    """
    texts = [message.body]
    if message.raw_source:
        try:
            parsed = Parser(policy=policy.default).parsestr(message.raw_source)
            for part in parsed.walk():
                if part.get_content_maintype() != "text":
                    continue
                try:
                    content = part.get_content()
                except (LookupError, UnicodeError):
                    content = part.get_payload(decode=False)
                if isinstance(content, str):
                    texts.append(content)
        except (TypeError, ValueError):
            texts.append(message.raw_source)

    found: list[str] = []
    seen: set[str] = set()
    url_pattern = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
    for text in texts:
        decoded = unescape(text or "")
        collector = _LinkCollector()
        try:
            collector.feed(decoded)
        except (TypeError, ValueError):
            pass
        candidates = collector.links + url_pattern.findall(decoded)
        for candidate in candidates:
            link = unescape(candidate).strip().rstrip(".,;]")
            if not link.lower().startswith(("http://", "https://")) or link in seen:
                continue
            seen.add(link)
            found.append(link)
    return found


def message_to_dict(
    message: EmailMessage,
    *,
    extracted: str | None = None,
    links: Sequence[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "received_at": message.received_at.isoformat(),
        "from": message.sender,
        "to": list(message.recipients),
        "subject": message.subject,
        "account": message.account,
        "mailbox": message.mailbox,
        "extracted": extracted,
        "body": message.body,
    }
    if links is not None:
        payload["links"] = list(links)
    return payload


def _normalize_filter(value: str) -> str:
    """Normalize a sender/recipient filter: a domain keeps its leading ``@``."""
    raw = str(value or "").strip().lower()
    if not raw:
        return raw
    if "@" not in raw:
        # Bare domain like "acme-bank.example" -> "@acme-bank.example" so it only matches the
        # domain part, never a localpart substring.
        return "@" + raw
    if raw.startswith("@"):
        return raw
    # Full address; unwrap any display-name form.
    return normalize_email(raw)


def _strip_subaddress(address: str) -> str:
    """``user+tag@host`` -> ``user@host`` (RFC 5233 subaddressing)."""
    local, at, domain = address.partition("@")
    if not at or "+" not in local:
        return address
    return f"{local.partition('+')[0]}@{domain}"


def _address_matches(needle: str, addresses: Sequence[str]) -> bool:
    """True if ``needle`` matches any of ``addresses``.

    A domain needle (starts with ``@``) matches by domain suffix. A full address
    matches exactly and — when the needle carries no ``+tag`` — also matches any
    plus-addressed alias of it, so ``tester@host`` finds mail sent to
    ``tester+lane2@host``. Test identities are provisioned through subaddressed
    mailboxes, so a literal-only compare made the DEFAULT path invisible.

    The reverse direction stays strict: a needle that names a tag matches only
    that tag, so one lane never reads a sibling lane's verification mail.
    """
    match_subaddressed = "+" not in needle
    for raw in addresses:
        address = normalize_email(raw)
        if not address:
            continue
        if needle.startswith("@"):
            if address.endswith(needle):
                return True
        elif address == needle:
            return True
        elif match_subaddressed and _strip_subaddress(address) == needle:
            return True
    return False


def subaddress_aliases(
    messages: Sequence[EmailMessage], mailbox_address: str
) -> list[str]:
    """Scanned recipient aliases that share ``mailbox_address``'s base address.

    A zero-result query against a tagged address (``tester+lane2@host``) reads
    identically to "no mail arrived at all" unless the sibling aliases the scan
    actually saw are named. Returns ``[]`` for a domain filter, an empty query,
    or when nothing related was scanned.
    """
    needle = _normalize_filter(mailbox_address)
    if not needle or needle.startswith("@"):
        return []
    base = _strip_subaddress(needle)
    found: set[str] = set()
    for message in messages:
        for raw in message.recipients:
            address = normalize_email(raw)
            if address and address != needle and _strip_subaddress(address) == base:
                found.add(address)
    return sorted(found)


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


# Duration flags. `--within` took a bare int while every sibling was explicitly
# unit-suffixed (`--timeout-seconds`, `--wait-seconds`, `--poll-seconds`), so
# `--within 10m` — the natural guess for a flag whose name carries no unit —
# died on argparse's "invalid int value". All four now accept the same forms;
# one flag understanding durations and three that don't is the next version of
# that bug.
_DURATION_UNIT_SECONDS = {"s": 1.0, "m": 60.0, "h": 3600.0}
_DURATION_UNIT_NAMES = {"s": "seconds", "m": "minutes", "h": "hours"}
_DURATION_PATTERN = re.compile(r"\A(\d+(?:\.\d+)?)\s*([smh]?)\Z", re.IGNORECASE)


def _duration_error(
    value: object, default_unit: str, qualifier: str
) -> argparse.ArgumentTypeError:
    return argparse.ArgumentTypeError(
        f"expected {qualifier}{_DURATION_UNIT_NAMES[default_unit]} (e.g. 30) or a "
        f"duration (90s, 30m, 2h); got {value!r}"
    )


def _parse_duration(value: str, *, default_unit: str) -> float:
    """Seconds for ``value``; an unsuffixed number is read as ``default_unit``."""
    match = _DURATION_PATTERN.match(str(value).strip())
    if match is None:
        raise _duration_error(value, default_unit, "")
    amount, suffix = match.groups()
    return float(amount) * _DURATION_UNIT_SECONDS[(suffix or default_unit).lower()]


def duration_minutes(value: str) -> int:
    """argparse ``type=`` for a minutes flag: ``30``, ``30m``, ``2h``, ``90s``.

    A bare number stays MINUTES so existing runbooks keep working. A sub-minute
    duration rounds up to a whole minute: the window may end up wider than
    asked, never narrower — a narrowed window silently misses the verification
    mail it was opened for.
    """
    seconds = _parse_duration(value, default_unit="m")
    if seconds <= 0:
        raise _duration_error(value, "m", "a positive number of ")
    return math.ceil(seconds / 60)


def duration_seconds(value: str) -> float:
    """argparse ``type=`` for a positive seconds flag: ``30``, ``90s``, ``2m``."""
    seconds = _parse_duration(value, default_unit="s")
    if seconds <= 0:
        raise _duration_error(value, "s", "a positive number of ")
    return seconds


def duration_seconds_or_zero(value: str) -> float:
    """argparse ``type=`` for a seconds flag where ``0`` disables the behaviour."""
    return _parse_duration(value, default_unit="s")


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
        raise EmailReadError(
            f"osascript timed out after {timeout_seconds}s", kind="timeout"
        ) from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown osascript failure"
        raise EmailReadError(f"osascript failed: {detail}")

    stdout = result.stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise EmailReadError(f"failed to parse Mail.app JSON output: {exc}") from exc
