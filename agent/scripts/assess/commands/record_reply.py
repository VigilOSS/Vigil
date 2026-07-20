"""vigil assess record-reply — durably append/update a reply on a submitted finding.

Persists ONE outgoing reply into the finding's ``details.replies`` append-only thread,
so a reply survives ``export reply --overwrite`` (unlike hand-editing the disposable
``reply-N.md``). The finding is the source of truth; ``export reply`` re-renders from
this durable entry.

WRITE PATH — read-modify-write (array-safe). The backend ``details`` merge is a shallow
``dict.update()`` (``_common.py _merge_object_text``): PATCHing ``{"replies": [only the
new one]}`` would REPLACE the whole array, dropping prior replies. So this verb FETCHES
the finding, parses the full ``details.replies`` array, appends (or updates the entry at
``--seq``) in place, then PATCHes back the ENTIRE array under ``details.replies``. The
shallow merge then swaps just the ``replies`` key, preserving every other ``details``
field (evidence / impact / cvss / …).

SUBMISSION-STATUS COUPLING IS EXPLICIT. This verb NEVER auto-writes ``submission_status``
(preserving the export submission invariant). ``--set-submission-status <s>`` is the one
opt-in that also PATCHes it — so ``needs_info → submitted`` after answering is one command
when the operator wants it, and silent otherwise.

"Sent" is operator-marked: ``--sent`` sets ``sent_status=sent`` + stamps ``sent_at``; it
is never inferred.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import SUBMISSION_STATUSES
from assess.lib.finding_render import details_object, nonempty

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
_DEFAULT_PLATFORM = "direct"


def _utcnow_iso() -> str:
    """Current UTC time as an ISO-8601 ``...Z`` stamp (patched in tests for determinism)."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record-reply",
        help=(
            "Durably append (or update at --seq) a reply on a finding's details.replies "
            "thread via read-modify-write. Pair with export reply to re-render. Never "
            "writes submission_status unless --set-submission-status is passed."
        ),
    )
    p.add_argument("slug", help="Finding slug the reply is on (e.g. VA-047)")
    p.add_argument(
        "--seq",
        dest="seq",
        type=int,
        default=None,
        help="Reply seq (default: next = max(seq)+1). Pass an existing seq to update it in place.",
    )
    p.add_argument(
        "--platform",
        choices=_PLATFORMS,
        default="",
        help="Reply channel: bugcrowd | hackerone | direct. Default on create: latest reply's platform, else 'direct'.",
    )
    p.add_argument(
        "--in-response-to",
        dest="in_response_to",
        default="",
        help="Verbatim triager ask this reply answers (required on create).",
    )
    p.add_argument(
        "--reply-to",
        dest="reply_to",
        type=int,
        default=None,
        help="Optional threading pointer: the prior reply seq this one answers.",
    )
    p.add_argument("--body", dest="body", default=None, help="Authored reply prose — exactly what we send.")
    p.add_argument(
        "--body-file",
        dest="body_file",
        default=None,
        help="Path to a file holding the reply body (relative paths resolve against the engagement dir).",
    )
    p.add_argument(
        "--new-evidence",
        dest="new_evidence",
        default="",
        help="Optional NEW proof authored for THIS reply (masked per submission-format.md PII rules).",
    )
    p.add_argument(
        "--new-evidence-ref",
        dest="new_evidence_ref",
        default="",
        help="Optional pointer to raw new-evidence (e.g. scans/<file>).",
    )
    p.add_argument(
        "--sent",
        action="store_true",
        help="Operator-mark this reply as sent: sets sent_status=sent and stamps sent_at.",
    )
    p.add_argument(
        "--set-submission-status",
        dest="set_submission_status",
        choices=SUBMISSION_STATUSES,
        default=None,
        help=(
            "OPT-IN: also PATCH the finding's submission_status (e.g. needs_info → submitted "
            "after answering). Omitted = submission_status is never touched."
        ),
    )
    p.add_argument(
        "--source-name",
        dest="source_name",
        default="report-writer",
        help="Author recorded on the reply entry (default: report-writer).",
    )
    p.add_argument("--reason", dest="reason_text", default="", help="Audit note for the finding PATCH.")
    p.set_defaults(func=run)


def _replies(finding: dict) -> list[dict]:
    raw = details_object(finding).get("replies")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _seq_of(entry: dict) -> int:
    value = entry.get("seq")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _resolve_body(args, engagement_dir: str) -> str | None:
    """The reply body from --body-file (preferred) or --body, or None when neither is set."""
    if args.body_file:
        path = Path(args.body_file)
        if not path.is_absolute():
            path = Path(engagement_dir) / path
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AssessError(f"record-reply: cannot read --body-file {args.body_file!r}: {exc}")
    return args.body


def _default_platform(replies: list[dict]) -> str:
    if replies:
        platform = nonempty(max(replies, key=_seq_of).get("platform"))
        if platform in _PLATFORMS:
            return platform
    return _DEFAULT_PLATFORM


def run(args) -> None:
    slug = args.slug

    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir
    body = _resolve_body(args, engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        finding = client.get(f"findings/{slug}")
        if not isinstance(finding, dict):
            raise AssessError(f"record-reply: unexpected response fetching finding {slug!r}")
        row_version = finding.get("row_version")
        if (
            not isinstance(row_version, int)
            or isinstance(row_version, bool)
            or row_version < 1
        ):
            raise AssessError(
                f"record-reply: finding {slug!r} did not return a positive row_version; "
                "refusing an unguarded reply write."
            )

        replies = _replies(finding)
        max_seq = max((_seq_of(entry) for entry in replies), default=0)
        seq_explicit = args.seq is not None
        seq = args.seq if seq_explicit else max_seq + 1

        index = next((i for i, entry in enumerate(replies) if _seq_of(entry) == seq), None)
        now = _utcnow_iso()

        if index is not None:
            # In-place UPDATE of an existing entry. Only legitimate when the operator
            # explicitly named the seq — an auto-derived seq that collides signals a
            # duplicate/corrupt array, not an update, so it is rejected rather than
            # silently overwriting a recorded reply.
            if not seq_explicit:
                raise AssessError(
                    f"record-reply: computed next seq {seq} already exists in details.replies for "
                    f"{slug!r}; pass an explicit --seq to update it in place, or fix the thread."
                )
            entry = dict(replies[index])
            if nonempty(args.platform):
                entry["platform"] = args.platform
            if nonempty(args.in_response_to):
                entry["in_response_to"] = args.in_response_to
            if args.reply_to is not None:
                entry["reply_to_seq"] = args.reply_to
            if body is not None:
                entry["body"] = body
            if nonempty(args.new_evidence):
                entry["new_evidence"] = args.new_evidence
            if nonempty(args.new_evidence_ref):
                entry["new_evidence_ref"] = args.new_evidence_ref
            if args.sent:
                entry["sent_status"] = "sent"
                if not nonempty(entry.get("sent_at")):
                    entry["sent_at"] = now
            replies[index] = entry
        else:
            # CREATE. A new reply must name the ask it answers and carry authored prose.
            missing: list[str] = []
            if not nonempty(args.in_response_to):
                missing.append("--in-response-to")
            if not nonempty(body):
                missing.append("--body/--body-file")
            if missing:
                raise AssessError(
                    f"record-reply: creating reply seq {seq} for {slug!r} requires "
                    f"{' and '.join(missing)}."
                )
            entry = {
                "seq": seq,
                "platform": nonempty(args.platform) or _default_platform(replies),
                "in_response_to": args.in_response_to,
                "reply_to_seq": args.reply_to,
                "body": body,
                "new_evidence": nonempty(args.new_evidence),
                "new_evidence_ref": nonempty(args.new_evidence_ref),
                "sent_status": "sent" if args.sent else "draft",
                "created_at": now,
                "sent_at": now if args.sent else None,
                "author": nonempty(args.source_name) or "report-writer",
            }
            replies.append(entry)

        # Read-modify-write: PATCH the FULL array so the shallow details merge swaps the
        # whole ``replies`` key (a partial array would drop prior replies). submission_status
        # is included ONLY on the explicit --set-submission-status opt-in.
        payload: dict = {
            "details": {"replies": replies},
            "expected_row_version": row_version,
        }
        if nonempty(args.reason_text):
            payload["reason_text"] = args.reason_text
        if args.set_submission_status is not None:
            payload["submission_status"] = args.set_submission_status

        result = client.patch(f"findings/{slug}", payload)

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(
        f"[record-reply] {'updated' if index is not None else 'appended'} reply seq {seq} "
        f"on {slug} ({len(replies)} in thread).",
        file=sys.stderr,
    )
