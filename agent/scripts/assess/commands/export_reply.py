"""vigil assess export-reply — render a reply to the program on a submitted finding.

Renders ONE outgoing reply (a Bugcrowd comment / HackerOne activity reply / direct
vendor follow-up) into a pasteable ``reply-<N>.md`` under
``$ENGAGEMENT_DIR/submissions/<slug>/replies/``. Mirrors the submission-first
architecture: the finding is the source of truth (its ``details.replies`` thread),
and the ``.md`` is a disposable render — a re-render loses nothing.

A reply is NOT a submission: there is no Title / VRT / CVSS / Summary. The layout is

    <reply body — leads with the new proof, answers the specific ask>   ← the ONLY
                                                                          pasteable block
    <optional NEW-evidence proof/attachment pointer>

    ---

    ## THREAD HISTORY — NOT FOR SUBMISSION (reference only — never paste below this line)
    **Answering (this reply):** <in_response_to, verbatim>
    **Prior replies (most recent first):** <inlined body for the latest ~3, older one-line>
    **Parent finding proof ...:** <the finding's structured proof + linked runs to author NEW
                                    evidence FROM (mask + weave; never paste raw)>
    **Hygiene warnings ...:** <FLAGGED internal-identifier leaks to strip before sending>

The single ``---`` is the never-paste line (the reply analog of export-submission's
second ``---``): everything below it is reference the operator never pastes.

INVARIANTS (mirrored from export-submission): this is a PURE render — it NEVER PATCHes
the finding and NEVER writes ``submission_status`` (the durable write path is the
dedicated ``record-reply`` verb). Internal identifiers (this finding's slug, engagement
UUIDs, absolute engagement paths, cases.db references) are FLAGGED non-destructively via
the shared hygiene gate, never rewritten, so the reply-format checklist / blind-triage
gate strips them deliberately before an external send.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.finding_render import (
    _fence_for,
    collect_internal_ids,
    detail_value,
    details_object,
    engagement_relative,
    hygiene_warnings,
    nonempty,
    poc_lines,
)
from assess.lib.outbound_redaction import redact_outbound_credentials
# ``export-reply`` reuses export-submission's finding-links → command-run resolution
# so the reply's THREAD HISTORY surfaces the same explicitly-linked reproducing runs
# the submission does (author NEW evidence from them). No cycle: export_submission does
# not import export_reply.
from assess.commands.export_submission import _linked_command_runs

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
# When the finding has no prior reply and no recorded submission platform, fall back
# here rather than hard-failing — a company-facing reply is the safe default.
_DEFAULT_PLATFORM = "direct"
# How many prior replies get their body inlined; older ones render one-line.
_INLINE_PRIOR_CAP = 3


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "reply",
        help=(
            "Render one reply-N.md (pasteable body + never-paste THREAD HISTORY) for a "
            "reply to the program on an already-submitted finding. Pure render: never "
            "PATCHes the finding. Use record-reply to persist the authored reply."
        ),
    )
    p.add_argument("slug", help="Finding slug the reply is on (e.g. VA-047)")
    p.add_argument(
        "--platform",
        choices=_PLATFORMS,
        default="",
        help=(
            "Reply channel: bugcrowd (comment) | hackerone (activity reply) | direct "
            "(reply email). Default: the latest reply's platform, else the finding's "
            "submission platform, else 'direct'."
        ),
    )
    p.add_argument(
        "--in-response-to",
        dest="in_response_to",
        default="",
        help="Verbatim triager ask this reply answers (required to scaffold a NEW reply).",
    )
    p.add_argument(
        "--reply-to",
        dest="reply_to",
        type=int,
        default=None,
        help="Optional threading pointer: the prior reply seq this one answers.",
    )
    p.add_argument(
        "--seq",
        dest="seq",
        type=int,
        default=None,
        help="Reply seq to render (default: next = max(seq)+1). Pass an existing seq to re-render it.",
    )
    p.add_argument(
        "--draft",
        action="store_true",
        help="Always write; mark an unauthored body with [NEEDS: reply body] instead of gating.",
    )
    p.add_argument(
        "--output",
        dest="output_dir",
        default="",
        help="Override the output directory (default: $ENGAGEMENT_DIR/submissions/<slug>/replies/).",
    )
    p.add_argument("--overwrite", action="store_true", help="Overwrite an existing reply-<N>.md.")
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit a machine-readable summary to stdout.")
    p.set_defaults(func=run)


def _replies(finding: dict) -> list[dict]:
    """The finding's ``details.replies`` thread as a list of entry dicts."""
    raw = details_object(finding).get("replies")
    if not isinstance(raw, list):
        return []
    return [entry for entry in raw if isinstance(entry, dict)]


def _seq_of(entry: dict) -> int:
    value = entry.get("seq")
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _resolve_platform(explicit: str, replies: list[dict], finding: dict) -> str:
    if explicit:
        return explicit
    if replies:
        latest = max(replies, key=_seq_of)
        platform = nonempty(latest.get("platform"))
        if platform in _PLATFORMS:
            return platform
    submission_platform = nonempty(detail_value(finding, "submission_platform", ""))
    if submission_platform in _PLATFORMS:
        return submission_platform
    return _DEFAULT_PLATFORM


def _prior_replies(replies: list[dict], current_seq: int) -> list[dict]:
    """Replies chronologically before ``current_seq``, most recent first."""
    prior = [entry for entry in replies if _seq_of(entry) < current_seq]
    return sorted(prior, key=_seq_of, reverse=True)


def _prior_reply_line(entry: dict) -> str:
    """The ``- Reply N (<stamp>) — answered "<ask>"`` header for one prior reply."""
    seq = _seq_of(entry)
    sent_status = nonempty(entry.get("sent_status")) or "draft"
    sent_at = nonempty(entry.get("sent_at"))
    stamp = f"sent {sent_at}" if sent_status == "sent" and sent_at else sent_status
    ask = nonempty(entry.get("in_response_to"))
    line = f"- Reply {seq} ({stamp})"
    if ask:
        line += f' — answered "{ask}"'
    return line


def _pasteable_lines(entry: dict, draft: bool) -> list[str]:
    """The copy-paste block: the reply body, then any NEW-evidence pointer."""
    lines: list[str] = []
    body = nonempty(entry.get("body"))
    lines += [body or "[NEEDS: reply body]", ""]

    new_evidence = nonempty(entry.get("new_evidence"))
    new_evidence_ref = nonempty(entry.get("new_evidence_ref"))
    if new_evidence or new_evidence_ref:
        lines += ["**New evidence:**", ""]
        if new_evidence:
            lines += [new_evidence, ""]
        if new_evidence_ref:
            lines += [f"**Attachment:** {new_evidence_ref}", ""]
    return lines


def _thread_history_lines(
    entry: dict,
    prior_entries: list[dict],
    finding: dict,
    linked_runs: list[dict],
    hygiene: list[str],
) -> list[str]:
    """The never-paste THREAD HISTORY below the single ``---``.

    Carries the ask this reply answers, the prior thread (latest ~3 with body, older
    one-line), the parent finding's structured proof + linked runs to author NEW
    evidence FROM (masked + woven, never pasted raw), and the FLAGGED hygiene warnings.
    """
    lines = [
        "---",
        "",
        "## THREAD HISTORY — NOT FOR SUBMISSION (reference only — never paste anything below this line)",
        "",
    ]

    in_response_to = nonempty(entry.get("in_response_to"))
    if in_response_to:
        lines += [f"**Answering (this reply):** {in_response_to}", ""]

    if prior_entries:
        lines += ["**Prior replies (most recent first):**", ""]
        for index, prior in enumerate(prior_entries):
            lines.append(_prior_reply_line(prior))
            if index < _INLINE_PRIOR_CAP:
                prior_body = nonempty(prior.get("body"))
                if prior_body:
                    lines.append(f"  {prior_body}")
        lines.append("")

    proof = poc_lines(finding)
    evidence_ref = nonempty(detail_value(finding, "evidence_ref", ""))
    if evidence_ref:
        proof += [f"- **Evidence reference:** {evidence_ref}", ""]
    lines += [
        "**Parent finding proof to author NEW evidence FROM (mask + weave; do NOT paste raw):**",
        "",
    ]
    lines += proof or ["(no structured proof recorded on the parent finding)", ""]

    if linked_runs:
        lines += ["**Linked command runs** (author NEW evidence from these):", ""]
        for row in linked_runs:
            command = nonempty(row.get("command"))
            if not command:
                continue
            intent = nonempty(row.get("intent"))
            rc = row.get("return_code")
            rc_str = "" if rc is None else f" (rc={rc})"
            header = f"- **Run{rc_str}**" + (f" — {intent}" if intent else "") + ":"
            fence = _fence_for(command)
            lines += [header, f"{fence}\n{command}\n{fence}", ""]

    if hygiene:
        lines += ["**Hygiene warnings** (strip every one before sending):", ""]
        lines += [f"- {warning}" for warning in hygiene]
        lines.append("")

    return lines


def _render_markdown(
    entry: dict,
    prior_entries: list[dict],
    finding: dict,
    linked_runs: list[dict],
    draft: bool,
    hygiene: list[str],
) -> str:
    lines = _pasteable_lines(entry, draft)
    lines += _thread_history_lines(entry, prior_entries, finding, linked_runs, hygiene)
    text = "\n".join(lines).rstrip()
    return text + "\n"


def _build_summary(
    slug: str,
    platform: str,
    seq: int,
    entry: dict,
    draft: bool,
    reply_rel: str,
    prior_entries: list[dict],
    artifact_registered: bool,
    hygiene: list[str],
) -> dict:
    return {
        "slug": slug,
        "platform": platform,
        "seq": seq,
        "mode": "draft" if draft else "final",
        "path": reply_rel,
        "in_response_to": nonempty(entry.get("in_response_to")),
        "reply_to_seq": entry.get("reply_to_seq"),
        "has_body": bool(nonempty(entry.get("body"))),
        "prior_replies": len(prior_entries),
        "artifact_registered": artifact_registered,
        "hygiene_warnings": hygiene,
    }


def run(args) -> None:
    slug = args.slug
    draft = bool(args.draft)

    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir

    if args.output_dir:
        out_dir = Path(args.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path(engagement_dir) / out_dir
    else:
        out_dir = Path(engagement_dir) / "submissions" / slug / "replies"

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        finding = client.get(f"findings/{slug}")
        if not isinstance(finding, dict):
            raise AssessError(f"export-reply: unexpected response fetching finding {slug!r}")
        finding = redact_outbound_credentials(finding)

        replies = _replies(finding)
        max_seq = max((_seq_of(entry) for entry in replies), default=0)
        seq = args.seq if args.seq is not None else max_seq + 1
        platform = _resolve_platform(nonempty(args.platform), replies, finding)

        existing = next((entry for entry in replies if _seq_of(entry) == seq), None)
        if existing is not None:
            # Re-render a recorded entry from its durable fields; flags only refine
            # the ask / threading, never the authored body. Platform is refined only
            # when --platform is explicit — a bare re-render keeps entry N's own
            # platform rather than adopting a later reply's.
            entry = dict(existing)
            if nonempty(args.platform):
                entry["platform"] = args.platform
            if nonempty(args.in_response_to):
                entry["in_response_to"] = args.in_response_to
            if args.reply_to is not None:
                entry["reply_to_seq"] = args.reply_to
        else:
            # Scaffold a NEW reply from flags (before record-reply persists it).
            if not nonempty(args.in_response_to):
                raise AssessError(
                    "export-reply: --in-response-to \"<triager ask>\" is required to scaffold a "
                    f"new reply (seq {seq}) — it names the question this reply answers."
                )
            entry = {
                "seq": seq,
                "platform": platform,
                "in_response_to": args.in_response_to,
                "reply_to_seq": args.reply_to,
                "body": "",
                "new_evidence": "",
                "new_evidence_ref": "",
                "sent_status": "draft",
            }

        # Final mode: refuse to render a reply that has not been authored yet (mirror
        # export-submission's completeness gate). Draft mode always writes, marking the
        # unauthored body with [NEEDS: reply body].
        missing: list[str] = []
        if not nonempty(entry.get("body")):
            missing.append("reply body")
        if not nonempty(entry.get("in_response_to")):
            missing.append("in-response-to (the ask this reply answers)")
        if not draft and missing:
            raise AssessError(
                f"export-reply: cannot render a FINAL reply (seq {seq}) for {slug!r} — "
                f"missing: {', '.join(missing)}. Author it with `record-reply` (or re-run "
                "with --draft to scaffold a work-in-progress with [NEEDS: ...] markers)."
            )

        reply_md = out_dir / f"reply-{seq}.md"
        if reply_md.exists() and not args.overwrite:
            raise AssessError(
                f"export-reply: {engagement_relative(reply_md, engagement_dir) or reply_md} "
                "already exists; pass --overwrite to replace it."
            )

        linked_runs = redact_outbound_credentials(
            _linked_command_runs(client, slug)
        )
        internal_ids = collect_internal_ids(finding, linked_runs)
        prior_entries = _prior_replies(replies, seq)
        reply_rel = engagement_relative(reply_md, engagement_dir)

        # FAITHFUL render — no content rewriting. Render once WITHOUT the hygiene
        # sub-block to scan the real content, then re-render with the resulting
        # warnings woven into THREAD HISTORY: the warning strings themselves quote the
        # leaked value (a UUID, a `cases.db` literal), so scanning a render that
        # already contains them would flag the advisory text as a fresh leak. Hygiene
        # scans only the PASTEABLE body — above the single `---` (separator_ordinal=1).
        scan_markdown = redact_outbound_credentials(
            _render_markdown(entry, prior_entries, finding, linked_runs, draft, [])
        )
        hygiene = hygiene_warnings(
            scan_markdown, slug, internal_ids, engagement_dir, separator_ordinal=1
        )
        markdown = redact_outbound_credentials(
            _render_markdown(
                entry,
                prior_entries,
                finding,
                linked_runs,
                draft,
                hygiene,
            )
        )

        out_dir.mkdir(parents=True, exist_ok=True)
        reply_md.write_text(markdown, encoding="utf-8")

        # Register the reply as a finding-linked artifact. NEVER include
        # submission_status: export-reply is a pure render and must never touch the
        # finding's submission state (that is record-reply's explicit opt-in only).
        artifact_registered = False
        if reply_rel is not None:
            try:
                client.post(
                    "artifacts",
                    {
                        "path": reply_rel,
                        "kind": "reply",
                        "media_type": "text/markdown",
                        "sensitive": False,
                        "producer_agent_id": None,
                        "producer_agent_role": None,
                        "producer_command_run_id": None,
                        "related_finding_slug": slug,
                    },
                )
                artifact_registered = True
            except AssessError as exc:
                print(f"WARN export-reply: artifact registration failed: {exc}", file=sys.stderr)
        else:
            print(
                "WARN export-reply: output is outside the engagement dir; "
                "skipping artifact registration.",
                file=sys.stderr,
            )

    for warning in hygiene:
        print(f"WARN export-reply: {warning}", file=sys.stderr)

    display_path = reply_rel or str(reply_md)
    if args.as_json:
        print(
            json.dumps(
                _build_summary(
                    slug, platform, seq, entry, draft, display_path,
                    prior_entries, artifact_registered, hygiene,
                ),
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        mode = "draft" if draft else "final"
        print(f"Wrote {mode} {platform} reply (seq {seq}) for {slug} to {display_path}")
        if missing:
            print("  NEEDS: " + ", ".join(missing))
