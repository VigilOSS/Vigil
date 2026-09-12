"""vigil assess record-reply — durably append/update a reply on a submitted finding.

Persists ONE outgoing reply into the finding's ``details.replies`` append-only thread,
so a draft survives ``export reply --overwrite`` (unlike hand-editing the disposable
``reply-N.md``). The finding is the editable authored source for drafts. At ``--sent``,
the backend selects that draft inside the write transaction, renders the external block,
and atomically binds the sent transition to those exact UTF-8 bytes, their length and
SHA-256, and server-owned renderer identity/version. Later sent exports download and
verify that record; they never rerender it.

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

"Sent" is operator-marked and never inferred. Sent rows and their byte records are
immutable; a correction appends a new sequence linked with ``--corrects``. Legacy sent
rows without byte evidence remain explicitly unavailable rather than reconstructed.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

from assess.lib.client import (
    AssessError,
    AssessmentClient,
    require_finding_write_response,
)
from assess.lib.config import load_config
from assess.lib.contracts import SUBMISSION_STATUSES
from assess.lib.finding_render import collect_internal_ids, hygiene_warnings, nonempty
from assess.lib.reply_render import render_outbound_reply_bytes
from assess.lib.reply_versions import reply_seq, reply_versions

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
            "thread via read-modify-write. --sent asks the backend to derive and "
            "atomically capture immutable exact outbound bytes. Never writes "
            "submission_status unless "
            "--set-submission-status is passed."
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
    p.add_argument(
        "--corrects",
        dest="corrects_seq",
        type=int,
        default=None,
        help=(
            "Append a new correction version linked to this sent reply seq. "
            "Sent reply bytes are never edited in place."
        ),
    )
    p.add_argument(
        "--body",
        dest="body",
        default=None,
        help="Authored reply prose used by the exact-byte renderer at send time.",
    )
    p.add_argument(
        "--body-file",
        dest="body_file",
        default=None,
        help="Path to a file holding the reply body (relative paths resolve against the engagement dir).",
    )
    # default=None (NOT "") — the same pattern --body uses, and for the same reason:
    # with a "" default the update path cannot distinguish "flag omitted" from
    # "operator asked for an empty value", so the field could be set once and never
    # unset. Passing the flag with an empty value CLEARS it.
    p.add_argument(
        "--new-evidence",
        dest="new_evidence",
        default=None,
        help=(
            "Optional NEW proof authored for THIS reply with exact captured values. "
            "Pass an empty value (--new-evidence '') to clear it."
        ),
    )
    p.add_argument(
        "--new-evidence-ref",
        dest="new_evidence_ref",
        default=None,
        help=(
            "Optional pointer to raw new-evidence (e.g. scans/<file>). Pass an empty "
            "value (--new-evidence-ref '') to clear a ref recorded earlier."
        ),
    )
    p.add_argument(
        "--sent",
        action="store_true",
        help=(
            "Operator-mark this reply sent; the backend derives and atomically "
            "preserves its exact renderer bytes, length, digest, and renderer identity/version."
        ),
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
        platform = nonempty(max(replies, key=reply_seq).get("platform"))
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

        replies = reply_versions(finding, operation="record-reply")
        max_seq = max((reply_seq(entry) for entry in replies), default=0)
        seq_explicit = args.seq is not None
        seq = args.seq if seq_explicit else max_seq + 1

        index = next(
            (i for i, entry in enumerate(replies) if reply_seq(entry) == seq),
            None,
        )
        original_entry: dict | None = None
        now = _utcnow_iso()

        if args.corrects_seq is not None:
            if seq_explicit:
                raise AssessError("record-reply: --corrects cannot be combined with --seq")
            corrected = next(
                (entry for entry in replies if reply_seq(entry) == args.corrects_seq),
                None,
            )
            if corrected is None or corrected.get("sent_status") != "sent":
                raise AssessError(
                    "record-reply: --corrects must name an existing sent reply"
                )

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
            original_entry = dict(replies[index])
            entry = dict(original_entry)
            content_change = any(
                (
                    nonempty(args.platform),
                    nonempty(args.in_response_to),
                    args.reply_to is not None,
                    body is not None,
                    args.new_evidence is not None,
                    args.new_evidence_ref is not None,
                )
            )
            if entry.get("sent_status") == "sent" and content_change:
                raise AssessError(
                    "record-reply: sent reply bytes are immutable; append a linked "
                    "correction with --corrects <seq>"
                )
            if nonempty(args.platform):
                entry["platform"] = args.platform
            if nonempty(args.in_response_to):
                entry["in_response_to"] = args.in_response_to
            if args.reply_to is not None:
                entry["reply_to_seq"] = args.reply_to
            if body is not None:
                entry["body"] = body
            # Presence-gated, not truthiness-gated: an empty value is a deliberate
            # CLEAR, not a no-op. The ref is stored stripped (it is a path, not
            # prose), so `--new-evidence-ref ''` and `--new-evidence-ref ' '` both
            # blank it and a copy-pasted path with stray whitespace still resolves.
            if args.new_evidence is not None:
                entry["new_evidence"] = args.new_evidence
            if args.new_evidence_ref is not None:
                entry["new_evidence_ref"] = nonempty(args.new_evidence_ref)
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
                # Every authored reply first lands as an editable draft. Only the
                # dedicated byte-capture endpoint performs the sent transition.
                "sent_status": "draft",
                "created_at": now,
                "sent_at": None,
                "author": nonempty(args.source_name) or "report-writer",
            }
            if args.corrects_seq is not None:
                entry["corrects_seq"] = args.corrects_seq
                entry["event_type"] = "correction"
            replies.append(entry)

        outbound_bytes: bytes | None = None
        if args.sent:
            if not nonempty(entry.get("body")):
                raise AssessError(
                    f"record-reply: cannot mark reply seq {seq} sent without a "
                    "nonempty authored body"
                )
            outbound_bytes = render_outbound_reply_bytes(entry)
            hygiene = hygiene_warnings(
                outbound_bytes.decode("utf-8"),
                slug,
                collect_internal_ids(finding, []),
                engagement_dir,
                separator_ordinal=1,
            )
            if hygiene:
                raise AssessError(
                    f"record-reply: cannot mark reply seq {seq} sent while hygiene "
                    f"warnings remain: {'; '.join(hygiene)}"
                )

        content_changed = original_entry is None or entry != original_entry
        # A send-only update deliberately skips the generic finding PATCH. That
        # route cannot create sent state because it cannot atomically bind bytes.
        if content_changed or not args.sent:
            payload: dict = {
                "details": {"replies": replies},
                "expected_row_version": row_version,
            }
            if nonempty(args.reason_text) and not args.sent:
                payload["reason_text"] = args.reason_text
            if args.set_submission_status is not None and not args.sent:
                payload["submission_status"] = args.set_submission_status
            result = require_finding_write_response(
                client.patch(f"findings/{slug}", payload),
                finding_slug=slug,
                operation="record reply",
            )
            finding = result["finding"]
            row_version = finding.get("row_version")
        else:
            result = {"finding": finding}

        if args.sent:
            if type(row_version) is not int or row_version < 1:
                raise AssessError(
                    "record-reply: draft write did not return a positive row_version; "
                    "the write may have committed, so inspect the finding and do not "
                    "retry automatically"
                )
            sent_result = require_finding_write_response(
                client.post(
                    f"submissions/{slug}/replies/{seq}/send",
                    {
                        "expected_row_version": row_version,
                        "actor": nonempty(args.source_name) or "report-writer",
                        "reason": (
                            nonempty(args.reason_text)
                            or "Reply finalized and marked sent with exact renderer bytes."
                        ),
                    },
                ),
                finding_slug=slug,
                operation="record sent reply bytes",
            )
            result = sent_result
            if args.set_submission_status is not None:
                sent_finding = sent_result["finding"]
                status_result = require_finding_write_response(
                    client.patch(
                        f"findings/{slug}",
                        {
                            "submission_status": args.set_submission_status,
                            "expected_row_version": sent_finding["row_version"],
                        },
                    ),
                    finding_slug=slug,
                    operation="update submission status after sent reply capture",
                )
                result = {
                    **sent_result,
                    "finding": status_result["finding"],
                }

    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(
        f"[record-reply] {'updated' if index is not None else 'appended'} reply seq {seq} "
        f"on {slug} ({len(replies)} in thread).",
        file=sys.stderr,
    )
