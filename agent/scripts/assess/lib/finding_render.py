"""Shared finding->markdown renderer.

Single source of truth for turning one persisted finding record into the
``## [slug] title`` markdown block used by both finding exporters:

  * ``vigil assess export findings`` — concatenates these blocks into a single
    ``findings.md`` report document (one section per finding, with the
    root-cause grouping context inline). See
    ``agent/scripts/assess/commands/export_findings.py``.
  * ``vigil engagement export --format markdown-tree`` — writes the same block
    as a per-finding ``draft.md`` in a git-diff-able tree (root-cause grouping
    is rendered separately into each finding's ``report.md`` instead, so the
    draft omits it). See
    ``src/vigil_cli/engagements.py:export_engagement_tree``.

Both callers share this module so the field selection, ordering, and PoC
formatting never drift between the report doc and the diffable tree. The only
behavioural knob is ``include_root_cause_group``; the trailing newline is left
to the caller (export findings strips and re-joins; the tree appends one).

This module lives under ``agent/scripts/assess/lib`` so the assess command
imports it directly; the ``src`` CLI package reaches it through the same
``add_assess_import_path`` bridge it already uses for ``assess.lib.client``
(see ``vigil_cli.paths``).
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Longest run of backticks anywhere in a string — used to pick a code fence
# that the content cannot prematurely close.
_BACKTICK_RUN = re.compile(r"`+")

# UUID shape — used only to confirm a collected internal id is genuinely a UUID
# before we FLAG (never rewrite) its presence in an outward-facing render. A
# target-application UUID in PoC proof (an IDOR/BOLA on a UUID-keyed resource)
# is never touched.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# Detects a reference to the internal cases.db work database (presence only).
_CASES_DB_RE = re.compile(r"cases\.db")


def nonempty(value: object) -> str:
    """``str(value)`` stripped of surrounding whitespace ("" for falsy input)."""
    return str(value or "").strip()


def step_lines(steps: object) -> list[str]:
    """Render ``steps_to_reproduce`` exactly as authored — no marker, no counter.

    The preferred shape is ONE authored string holding the whole reproduction
    block, numbered by the author; it renders through untouched. A list is also
    accepted, and each item renders as its own paragraph so distinct steps stay
    distinct without a marker being invented for them.

    Formatting belongs to the author because the rest of the submission depends on
    it: prose in Summary or Impact cross-references step numbers ("follow the
    location header from step 4"), and those references resolve only against
    numbers the author actually wrote. A renderer that supplied its own counter, or
    stripped one, would restate the reproduction in its own words — leaving the
    report-writer unable to tell its text from the tool's, and unable to trust the
    document it is about to file.
    """
    items = string_list(steps)
    if not items:
        return []
    body: list[str] = [items[0]]
    for item in items[1:]:
        body += ["", item]
    return body


def _fence_for(*parts: str) -> str:
    """Return a backtick fence guaranteed not to be closed by any of ``parts``.

    Markdown code fences must be longer than the longest backtick run inside the
    fenced content, otherwise PoC output / request bodies / response excerpts
    containing ``` (or longer runs) break out of the block. We scan every part
    and return a run one backtick longer than the maximum found (minimum 3)."""
    longest = 0
    for part in parts:
        for match in _BACKTICK_RUN.finditer(part or ""):
            longest = max(longest, len(match.group(0)))
    return "`" * max(3, longest + 1)


def details_object(finding: dict) -> dict:
    """Return the finding's structured details as a dict.

    The backend stores extended fields in a ``details_json`` text column; the
    serialized read payloads can carry it either as a JSON string or as an
    already-parsed object depending on the endpoint, so handle both.

    A parse failure is REPORTED, never silently swallowed. Returning a bare ``{}``
    makes every details-sourced section — steps, evidence, impact, remediation,
    CVSS, the structured proof — render as absent, which reads exactly like a
    finding nobody authored. A render that quietly drops half the report is worse
    than a loud one, so the reason goes to stderr where the caller's WARN lines
    already go.
    """
    details_json = finding.get("details_json")
    if isinstance(details_json, str):
        try:
            parsed = json.loads(details_json)
        except (json.JSONDecodeError, TypeError) as exc:
            print(
                f"WARN finding_render: finding {finding.get('slug') or '?'} has "
                f"unparseable details_json ({exc}); every details-sourced field "
                "will render as missing",
                file=sys.stderr,
            )
            return {}
        if not isinstance(parsed, dict):
            print(
                f"WARN finding_render: finding {finding.get('slug') or '?'} has a "
                f"details_json that is {type(parsed).__name__}, not an object; "
                "every details-sourced field will render as missing",
                file=sys.stderr,
            )
            return {}
        return parsed
    return details_json if isinstance(details_json, dict) else {}


def detail_value(finding: dict, key: str, default: Any = "") -> Any:
    """Prefer the top-level finding field, falling back to ``details_json``."""
    value = finding.get(key)
    if value not in (None, "", []):
        return value
    return details_object(finding).get(key, default)


def blocked_reason_summary(finding: dict) -> str:
    """One-line ``BLOCKED: <reason>`` marker for a blocked finding, or "".

    A finding is *blocked-for-provisioning* when its ``verification_disposition``
    is ``blocked``: the attempt could not even start because a precondition is
    missing (an account / line / device / credential / access), so the finding is
    held OUT of the report until unblocked. Its ``verification_state`` is
    ``verified`` and its ``workflow_status`` usually stays ``active`` — so a
    compact finding line that shows only ``workflow_status/verification_state``
    (resume-brief) renders it as a bare ``active/verified`` row with NO hint that
    it is blocked or why. This marker restores that signal from the required
    ``details.block_reason`` (guaranteed present by the verify/record invariant
    that blocked findings MUST carry a block_reason).

    Gated strictly on ``verification_disposition == 'blocked'`` — a ``block_reason``
    may legitimately sit on a non-blocked finding (e.g. a pending_runtime_proof
    hold), and labelling that "BLOCKED" would be wrong. Returns "" otherwise, so a
    normal finding never grows a marker. The reason is read via ``detail_value``
    so it resolves whether it is a top-level projected field (resume-brief) or
    nested in ``details_json`` (finding list' raw record).

    The compact marker intentionally omits richer prerequisite metadata; callers
    can fetch the finding detail when they need it.
    """
    disposition = str(finding.get("verification_disposition") or "").strip().lower()
    if disposition != "blocked":
        return ""
    reason = str(detail_value(finding, "block_reason", "") or "").strip()
    return f"BLOCKED: {reason}" if reason else "BLOCKED"


def string_list(values: object) -> list[str]:
    """Coerce an authored list-or-string field to a list of strings.

    A bare string becomes a ONE-ELEMENT list rather than an empty one. Authors
    routinely record a multi-item field as a single block of prose — a numbered
    reproduction, one string — and discarding that silently is the worst available
    outcome: the section vanishes from the render while the value sits plainly in
    the record, and ``export submission``'s final gate reports the field as missing
    for content the author can see they wrote. Backend ``_as_string_list``
    (``report_readiness.py``) coerces the same way, so readiness and export agree
    on what counts as authored.
    """
    if isinstance(values, str):
        text = values.strip()
        return [text] if text else []
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if value not in (None, "")]


def header_lines(headers: object) -> list[str]:
    if isinstance(headers, dict):
        return [f"{key}: {value}" for key, value in headers.items() if key not in (None, "") and value is not None]
    if isinstance(headers, str):
        return [headers] if headers else []
    if isinstance(headers, list):
        return [str(value) for value in headers if value not in (None, "")]
    return []


def _root_cause_lines(finding: dict) -> list[str]:
    """Render the root-cause grouping block (export findings only).

    ``export findings`` flattens grouping context onto each finding before
    rendering (root/sibling role + effect + note); the markdown-tree draft
    omits this because each finding's ``report.md`` renders grouping from the
    report projection instead.
    """
    lines: list[str] = []
    root_role = finding.get("root_cause_role")
    if root_role == "root":
        lines.append(f"- **Root Cause Group**: root ({finding.get('sibling_count', 0)} siblings)")
    elif root_role == "sibling":
        root_slug = finding.get("root_cause_slug", "")
        effect = finding.get("root_cause_effect", "eliminates_finding")
        effect_label = "fixing root eliminates this finding"
        if effect == "eliminates_attack_path":
            effect_label = "fixing root eliminates this attack path; residual finding remains"
        lines.append(f"- **Root Cause Group**: sibling of {root_slug} ({effect_label})")
        if finding.get("root_cause_note"):
            lines.append(f"- **Root Cause Note**: {finding['root_cause_note']}")
    return lines


def render_finding(finding: dict, *, include_root_cause_group: bool = False) -> str:
    """Render one finding to its markdown block (no trailing newline).

    ``include_root_cause_group`` adds the root/sibling grouping bullet(s) that
    ``export findings`` flattens onto the finding; leave it ``False`` for the
    per-finding ``draft.md`` in the markdown-tree export.

    The returned string is the stripped block; callers decide whether to append
    a trailing newline (export findings re-joins blocks; the tree adds one).
    """
    # An unset field renders as ``(unset)``, never as a plausible value. Printing
    # ``MEDIUM`` for a finding whose severity nobody set states a triage decision
    # the record does not contain, and the reader cannot tell it apart from a real
    # one.
    slug = str(finding.get("slug") or "")
    title = str(finding.get("title") or "(unset)")
    severity = str(finding.get("severity") or "(unset)").upper()
    workflow_status = finding.get("workflow_status") or "(unset)"
    verification_state = finding.get("verification_state") or "(unset)"
    verification_disposition = finding.get("verification_disposition") or "(unset)"
    source_name = finding.get("source_name") or finding.get("discovered_by") or "(unset)"
    defect_family = finding.get("defect_family") or ""
    location = finding.get("canonical_location") or ""
    auth_context = finding.get("auth_context") or ""
    evidence = finding.get("evidence_detail") or finding.get("evidence_ref") or ""
    # No ``impact ← summary`` fallback: showing Summary prose under an Impact
    # heading makes an unauthored impact statement look authored, and the reader
    # cannot tell which field they are reading. ``export submission`` already
    # refuses that substitution deliberately (``_evaluate``); the two renderers
    # agreeing matters more than filling the bullet.
    impact = finding.get("impact") or ""
    owasp_category = str(detail_value(finding, "owasp_category", "") or "")
    cwe_id = str(detail_value(finding, "cwe_id", "") or "")
    cvss_vector = str(detail_value(finding, "cvss_vector", "") or "")
    cvss_score = finding.get("cvss_score")
    if cvss_score is None:
        cvss_score = detail_value(finding, "cvss_score", None)
    remediation = finding.get("remediation") or str(detail_value(finding, "remediation", "") or "")
    if not impact:
        impact = str(detail_value(finding, "impact", "") or "")
    if not evidence:
        evidence = str(detail_value(finding, "evidence", "") or "")
    steps = string_list(detail_value(finding, "steps_to_reproduce", []))
    notes = (finding.get("notes") or "").strip()
    request_method = details_object(finding).get("request_method") or ""

    header = f"## [{slug}] {title}" if slug else f"## {title}"
    lines = [
        header,
        f"- **Discovered by**: {source_name}",
        f"- **Severity**: {severity}",
        f"- **Workflow**: {workflow_status}",
        f"- **Verification**: {verification_state} / {verification_disposition}",
    ]
    if defect_family:
        lines.append(f"- **Type**: {defect_family}")
    if owasp_category:
        lines.append(f"- **OWASP**: {owasp_category}")
    if cwe_id:
        lines.append(f"- **CWE**: {cwe_id}")
    if location:
        loc = f"{request_method} {location}" if request_method else location
        lines.append(f"- **Location**: {loc}")
    if auth_context:
        lines.append(f"- **Auth Context**: {auth_context}")
    if cvss_vector:
        score_str = f" ({cvss_score})" if cvss_score is not None else ""
        lines.append(f"- **CVSS**: {cvss_vector}{score_str}")
    if evidence:
        lines.append(f"- **Evidence**: {evidence}")
    if impact:
        lines.append(f"- **Impact**: {impact}")
    if remediation:
        lines.append(f"- **Remediation**: {remediation}")
    if finding.get("merged_into_slug"):
        lines.append(f"- **Merged Into**: {finding['merged_into_slug']}")
    if include_root_cause_group:
        lines.extend(_root_cause_lines(finding))

    entry_point = str(detail_value(finding, "entry_point", "") or "")
    sink = str(detail_value(finding, "sink", "") or "")
    references = string_list(detail_value(finding, "references", []))
    poc_code = str(detail_value(finding, "poc_code", "") or "")
    if entry_point:
        lines.append(f"- **Entry Point**: {entry_point}")
    if sink:
        lines.append(f"- **Sink**: {sink}")
    if references:
        lines.append(f"- **References**: {', '.join(references)}")

    if steps:
        lines.append("")
        lines.append("**Steps to Reproduce:**")
        lines.extend(step_lines(steps))
    if poc_code:
        lines.append("")
        lines.append("**PoC Code:**")
        fence = _fence_for(poc_code)
        lines.append(f"{fence}\n{poc_code}\n{fence}")
    poc_request = detail_value(finding, "poc_request")
    if isinstance(poc_request, dict):
        lines.append("")
        lines.append("**PoC Request:**")
        req_headers = header_lines(poc_request.get("headers"))
        req_body = str(poc_request.get("body") or "")
        # Fence over every fenced part (request line + headers + body) so a
        # backtick run anywhere in the request cannot close the block early.
        fence = _fence_for(
            f"{poc_request.get('method', '')} {poc_request.get('url', '')}",
            "\n".join(req_headers),
            req_body,
        )
        lines.append(f"{fence}\n{poc_request.get('method', '')} {poc_request.get('url', '')}")
        lines.extend(req_headers)
        if poc_request.get("body"):
            lines.append(f"\n{poc_request['body']}")
        lines.append(fence)
    poc_response = detail_value(finding, "poc_response")
    if isinstance(poc_response, dict):
        lines.append("")
        lines.append("**PoC Response:**")
        resp_headers = header_lines(poc_response.get("headers"))
        # Same either-key read as :func:`poc_lines`, so this renderer and the
        # submission/reply renderer never disagree about whether a finding has a
        # response body.
        resp_body = str(
            poc_response.get("body_excerpt") or poc_response.get("body") or ""
        )
        fence = _fence_for(
            f"HTTP {poc_response.get('status', '')}",
            "\n".join(resp_headers),
            resp_body,
        )
        lines.append(f"{fence}\nHTTP {poc_response.get('status', '')}")
        lines.extend(resp_headers)
        if resp_body:
            lines.append(f"\n{resp_body}")
        lines.append(fence)

    block = "\n".join(lines).rstrip()
    if notes:
        block = f"{block}\n\n{notes}"
    return block.strip()


# ---------------------------------------------------------------------------
# Shared submission / reply render + hygiene helpers
# ---------------------------------------------------------------------------
#
# Promoted from ``export_submission`` so both the submission renderer and the
# reply renderer (``export_reply``) share one source of truth for structured-proof
# formatting and the FLAG-not-strip internal-identifier hygiene gate. The
# submission renderer keeps its exact prior behaviour (``separator_ordinal``
# defaults to 2 — its OPERATOR DETAILS divider); the reply renderer passes 1
# (its single THREAD HISTORY divider).


def poc_lines(finding: dict) -> list[str]:
    """Render poc_code / poc_request / poc_response, reusing the shared fencing.

    Emits the ``**PoC Code:**`` / ``**PoC Request:**`` / ``**PoC Response:**``
    blocks a submission or reply surfaces as structured reference proof (never
    pasted raw — masked + woven into authored Evidence). Fences are chosen with
    :func:`_fence_for` so a backtick run inside any part cannot close the block
    early.
    """
    lines: list[str] = []
    poc_code = nonempty(detail_value(finding, "poc_code", ""))
    if poc_code:
        fence = _fence_for(poc_code)
        lines += ["**PoC Code:**", f"{fence}\n{poc_code}\n{fence}", ""]

    poc_request = detail_value(finding, "poc_request")
    if isinstance(poc_request, dict) and poc_request:
        req_headers = header_lines(poc_request.get("headers"))
        req_body = str(poc_request.get("body") or "")
        request_line = f"{poc_request.get('method', '')} {poc_request.get('url', '')}".strip()
        fence = _fence_for(request_line, "\n".join(req_headers), req_body)
        block = [f"{fence}\n{request_line}"]
        block += req_headers
        if poc_request.get("body"):
            block.append(f"\n{poc_request['body']}")
        block.append(fence)
        lines += ["**PoC Request:**", "\n".join(block), ""]

    poc_response = detail_value(finding, "poc_response")
    if isinstance(poc_response, dict) and poc_response:
        resp_headers = header_lines(poc_response.get("headers"))
        # Accept either key: recorders write ``body_excerpt``, but a hand-authored
        # or tool-captured response often carries plain ``body``. Reading only one
        # key drops the response body — the proof itself — from the render.
        resp_body = str(
            poc_response.get("body_excerpt") or poc_response.get("body") or ""
        )
        status_line = f"HTTP {poc_response.get('status', '')}".strip()
        fence = _fence_for(status_line, "\n".join(resp_headers), resp_body)
        block = [f"{fence}\n{status_line}"]
        block += resp_headers
        if resp_body:
            block.append(f"\n{resp_body}")
        block.append(fence)
        lines += ["**PoC Response:**", "\n".join(block), ""]
    return lines


def collect_internal_ids(finding: dict, linked_runs: list[dict]) -> list[str]:
    """UUID-shaped internal identifiers to FLAG (never rewrite) in the output.

    Only ids the backend assigns to its own records — this finding, its
    engagement, and the agents/rows behind any linked command runs. Never the
    target-application identifiers, so PoC proof is never mistaken for internal
    state. Integer ids (e.g. a command-run row's ``id``) collected here are
    harmless: :func:`hygiene_warnings` flags a value only when it is a full UUID.
    """
    ids: list[str] = []
    for key in ("id", "engagement_id", "merged_into_finding_id"):
        ids.append(nonempty(finding.get(key)))
    for row in linked_runs:
        for key in ("producer_agent_id", "agent_id", "engagement_id", "finding_id"):
            ids.append(nonempty(row.get(key)))
    seen: set[str] = set()
    unique: list[str] = []
    for value in ids:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def pasteable_body(text: str, *, separator_ordinal: int = 2) -> str:
    """The copy-paste body = everything ABOVE the ``separator_ordinal``-th ``---``.

    A submission emits two standalone ``---`` lines (header/body split, then the
    OPERATOR DETAILS divider): its pasteable body ends at the SECOND separator
    (``separator_ordinal=2``, the default). A reply emits a single ``---`` (its
    THREAD HISTORY divider): its pasteable body ends at the FIRST
    (``separator_ordinal=1``). Identifiers that LEGITIMATELY live in the
    never-paste reference below that divider (the finding slug, absolute
    engagement paths, internal-record UUIDs echoed by ``evidence_ref`` paths and
    linked runs) must be scanned only within this body, or the hygiene gate
    false-positives on every render. If the divider is somehow absent (defensive),
    fall back to the whole text so a real leak is never silently unflagged.
    """
    lines = text.split("\n")
    separators = 0
    for idx, line in enumerate(lines):
        if line == "---":
            separators += 1
            if separators == separator_ordinal:
                return "\n".join(lines[:idx])
    return text


def title_advisories(title: str) -> list[str]:
    """Prose-quality advice about a submission title. NEVER blocking.

    Kept apart from :func:`hygiene_warnings` because the two answer different
    questions and earn different authority. A leaked internal identifier is a fact
    about the document and rightly fails a final export closed. Title length is an
    editorial opinion: enforcing it as a refusal lets a 13-word title block
    publication of a finished, verified finding — the tool overruling the author on
    style. Surface it and let the report-writer decide.
    """
    advisories: list[str] = []
    title = nonempty(title)
    if title:
        word_count = len(title.split())
        if word_count > 12:
            advisories.append(
                f"submission title is {word_count} words (max 12) — tighten it to a concise, "
                "specific one-liner before external submission"
            )
    return advisories


def hygiene_warnings(
    text: str,
    slug: str,
    internal_ids: list[str],
    engagement_dir: str,
    *,
    separator_ordinal: int = 2,
) -> list[str]:
    """Non-destructively FLAG internal identifiers that leaked into the output.

    Returns warning strings; it NEVER mutates ``text``. The finding's content
    reaches the report-writer verbatim — a target-app UUID, filename, or path must
    survive — and these warnings let the report-writer (and the blind-triage gate)
    decide what to strip before an EXTERNAL submission or reply.

    Every entry here fails a FINAL export closed, so only a FACT about the document
    belongs in this list. Prose-quality opinions go to :func:`title_advisories`
    instead, where they are reported and never gated on.

    The slug / engagement-path / internal-UUID checks scan ONLY the PASTEABLE body
    (above the ``separator_ordinal``-th ``---``): those identifiers routinely and
    legitimately appear in the never-paste reference below it, so scanning the
    whole document would flag every render. ``cases.db`` is the exception — a target
    application never references the internal work database, so ANY mention
    (reference section included) is a genuine leak and is scanned whole-document.
    """
    warnings: list[str] = []
    body = pasteable_body(text, separator_ordinal=separator_ordinal)
    slug = nonempty(slug)
    if slug and slug in body:
        warnings.append(
            f"finding slug '{slug}' appears in the pasteable body — remove before external submission"
        )
    eng = nonempty(engagement_dir).rstrip("/")
    if eng and eng in body:
        warnings.append(
            f"absolute engagement path '{eng}' appears — make paths relative before external submission"
        )
    for value in internal_ids:
        if value and _UUID_RE.fullmatch(value) and value in body:
            warnings.append(
                f"internal identifier '{value}' appears — remove before external submission"
            )
    if _CASES_DB_RE.search(text):
        warnings.append(
            "reference to the internal cases.db work database appears — remove before external submission"
        )
    return warnings


def engagement_relative(path: Path, engagement_dir: str) -> str | None:
    """Engagement-relative form of ``path``, or None if it lies outside the tree."""
    try:
        rel = os.path.relpath(str(path), str(engagement_dir))
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel
