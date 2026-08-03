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
        # The audit rows behind those steps, named right under them. Ids only —
        # this renderer has no client to fetch argv with (``export submission``
        # does that) — but a reader can pull each run and diff the claimed step
        # against what ran, and their ABSENCE is itself the signal that nothing
        # can.
        repro_runs = string_list(detail_value(finding, "repro_runs", []))
        if repro_runs:
            lines.append("")
            lines.append(f"**Repro runs**: {', '.join(repro_runs)}")
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


# ---------------------------------------------------------------------------
# Prose advisories — length/shape opinions about the submission body
# ---------------------------------------------------------------------------
#
# Every number below mirrors a ceiling already written in
# ``agent/references/submission-format.md`` ("Section budgets"). Nothing here
# blocks; see :func:`prose_advisories` for why.

_SENTENCE_WORD_BUDGET = 25
_STEPS_SENTENCE_WORD_BUDGET = 20
_STEP_COUNT_BUDGET = 10
# Sizing the sentence quote in the length advisory (see :func:`_quote`).
_QUOTE_WORD_BUDGET = 8
_QUOTE_CHAR_BUDGET = 70
_EVIDENCE_BLOCK_LINE_BUDGET = 15
_REMEDIATION_ITEM_BUDGET = 3
# Sections whose ceiling is a sentence count, with the trailing clause each one
# uses to say what the over-budget sentences should be weighed against. The clause
# is carried in both numbers because the advisory names a range ("sentences 5-7")
# or a single position ("sentence 5") depending on how far past the ceiling the
# section ran, and an advisory that cannot conjugate reads like a template.
_SECTION_SENTENCE_BUDGETS = (
    (
        "Summary",
        4,
        (
            "carries a fact the reader needs before Steps",
            "carry a fact the reader needs before Steps",
        ),
    ),
    (
        "Attack Scenario",
        3,
        (
            "advances the scenario rather than restating Steps",
            "advance the scenario rather than restate Steps",
        ),
    ),
    (
        "Impact",
        2,
        (
            "names an impact the first two do not already carry",
            "name an impact the first two do not already carry",
        ),
    ),
)
_REMEDIATION_ITEM_CLAUSE = (
    "is a distinct fix or a restatement of the first three",
    "are distinct fixes or restatements of the first three",
)
_STEPS_SECTION = "Steps to Reproduce"

# A submission body section: exactly three hashes, at column 0. ``#### Step 2 —``
# (the per-step heading) and ``## OPERATOR DETAILS`` deliberately do not match.
_SECTION_HEADING_RE = re.compile(r"^###\s+(.+?)\s*$")
# Fence openers/closers of any length, so a 4-backtick fence chosen by
# :func:`_fence_for` is recognised as readily as a plain 3-backtick one.
_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_ANY_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")
_STEP_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s*Step\b", re.IGNORECASE)
_TABLE_ROW_RE = re.compile(r"^\s*\|")
_ORDERED_ITEM_RE = re.compile(r"^\s{0,3}\d+[.)]\s+")
_LIST_MARKER_RE = re.compile(r"^\s{0,3}(?:[-*+]|\d+[.)])\s+")
_HTTP_REQUEST_LINE_RE = re.compile(
    r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+"
    r"(\s+HTTP/\d(\.\d)?)?\s*$"
)
_HTTP_STATUS_LINE_RE = re.compile(r"^\s*HTTP/?[\d.]*\s+\d{3}\b")
_BOLD_LABEL_ONLY_RE = re.compile(r"^\s*\*{2}[^*]+\*{2}:?\s*$")
# The same bold label, but carrying a value: ``**Researcher:** A. Name — a@x.test``.
# ``_BOLD_LABEL_ONLY_RE`` is its empty-valued case.
_BOLD_LABEL_VALUE_RE = re.compile(r"^\s*\*{2}[^*]+\*{2}:?\s*(?P<value>.*?)\s*$")
# A terminator in PROSE position — followed by whitespace or end of line. The dots
# in ``priya.natarajan@research.example`` are followed by letters and do not match.
_SENTENCE_PUNCT_RE = re.compile(r"[.!?](\s|$)")
_STRUCTURAL_PUNCT_RE = re.compile(r"^\s*[\{\}\[\]\"]")
_BLOCKQUOTE_RE = re.compile(r"^\s{0,3}>\s?")
_INLINE_CODE_RE = re.compile(r"`+[^`]+`+")
_SENTENCE_BOUNDARY_RE = re.compile(r"[.!?]+[\"')\]]*\s+")
_WORDLIKE_RE = re.compile(r"[0-9A-Za-z]")
# Trailing tokens that end in a period WITHOUT ending a sentence. Missing a real
# boundary merges two sentences into one over-long "sentence" — the false
# positive this list exists to prevent.
_ABBREVIATIONS = frozenset(
    {
        "e.g", "eg", "i.e", "ie", "etc", "vs", "cf", "approx", "fig", "no",
        "resp", "al", "inc", "ltd", "co", "dr", "mr", "mrs", "ms", "st",
        "jr", "sr",
    }
)


def _is_sign_off_line(line: str) -> bool:
    """Is this line an attribution/sign-off footer rather than section content?

    Shape, never a word list: a bold label carrying a bare value with no
    sentence-ending punctuation in prose position. ``**Researcher:** A. Name —
    a@x.test``, ``**Reported by:** @handle``, ``**Contact:** security@x.test`` and a
    bare ``**Disclosure:**`` all qualify; ``**Fix:** Parameterize the query.`` does
    not, because a line with a real sentence in it is content whatever labels it.
    """
    match = _BOLD_LABEL_VALUE_RE.match(line)
    if not match:
        return False
    return not _SENTENCE_PUNCT_RE.search(match.group("value"))


def _strip_trailing_sign_off(lines: list[str]) -> list[str]:
    """Drop a trailing sign-off footer from the LAST section's lines.

    A submission's sign-off (``**Researcher:** …``) sits after the final ``###``
    heading, and with no heading to close that section it lands INSIDE it — so
    Remediation, the last section in the closed 6-section body, counts an
    attribution footer as one of its three items. That is a phantom item: it is not
    in the Structure template, nothing in the schema or the renderer produces it,
    and the cost is real. A hand-corrected exemplar was compressed to two fixes to
    leave room for a third that does not exist.

    Scoped to the document tail because that is the only place the defect exists:
    a footer anywhere else is closed by the next heading. Walks back over blank and
    footer-shaped lines and stops at the first line of real content, so a section
    that simply ENDS in a bold-labelled value loses only that value.

    A section made ENTIRELY of footer-shaped lines is content, not a footer, and is
    kept whole: a Remediation written as ``**Primary fix:** …`` / ``**Defense in
    depth:** …`` matches the shape on every line, and trimming it to nothing would
    silence every advisory about it — over-trimming that hides a real defect is a
    worse failure than the phantom item this function exists to remove.
    """
    end = len(lines)
    found = False
    while end:
        line = lines[end - 1].rstrip()
        if not line.strip():
            end -= 1
            continue
        if not _is_sign_off_line(line):
            break
        end -= 1
        found = True
    if not found or not any(line.strip() for line in lines[:end]):
        return lines
    return lines[:end]


def _submission_sections(body: str) -> list[tuple[str, list[str]]]:
    """``[(section title, lines)]`` for each ``### `` section of a submission body.

    Fence state is tracked while splitting so a ``### `` line that happens to sit
    inside a fenced request/response block is content, not a new section. Anything
    above the first ``### `` heading (the platform copy-paste header — Title / VRT /
    Severity / CVSS / Asset / Run / Pass if) is metadata rather than prose and is
    dropped here, which is why no length advice is ever aimed at it.

    The final section is closed by end-of-body rather than by the next heading, so
    it alone is trimmed of a trailing sign-off (:func:`_strip_trailing_sign_off`).
    """
    sections: list[tuple[str, list[str]]] = []
    fence = ""
    name = ""
    buf: list[str] = []
    for raw in body.split("\n"):
        line = raw.rstrip()
        if fence:
            if _FENCE_RE.match(line) and line.strip().startswith(fence):
                fence = ""
            if name:
                buf.append(raw)
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            fence = opening.group(1)
            if name:
                buf.append(raw)
            continue
        heading = _SECTION_HEADING_RE.match(line)
        if heading:
            if name:
                sections.append((name, buf))
            name = heading.group(1).strip()
            buf = []
            continue
        if name:
            buf.append(raw)
    if name:
        sections.append((name, _strip_trailing_sign_off(buf)))
    return sections


def _prose_blocks(lines: list[str], *, drop_ordered_items: bool = False) -> list[str]:
    """Paragraph-sized runs of PROSE from a section, structure removed first.

    Sentence segmentation over raw markdown is the failure mode that makes this
    class of linter useless: a splitter that reads a table row, a curl invocation,
    or a response dump as prose reports a 176-word "sentence" nobody wrote, and one
    bogus advisory costs the reader's trust in every other advisory the tool emits.
    So structure is removed BEFORE any splitting — fenced blocks, markdown tables,
    headings, unfenced HTTP request/status blocks and their header lines, JSON
    braces, and bold-only labels are dropped whole.

    Each dropped line also ENDS the current paragraph. Without that, the prose
    before a code block and the prose after it would join into one run and be
    measured as a single sentence. List items start their own paragraph for the
    same reason, and their marker is stripped so ``-`` never counts as a word.

    ``drop_ordered_items`` additionally removes ordered-list items (and their
    indented continuations). It exists for one caller: the Summary sentence COUNT,
    where an optional ``**Exploit flow**`` ordered list lives inside the authored
    ``summary`` string by convention. Counting those items as Summary prose would
    fire the Summary advisory on every finding that has a flow. Sentence LENGTH
    still measures them — a flow step is prose, and a long one is worth splitting.
    """
    blocks: list[str] = []
    current: list[str] = []
    fence = ""
    in_http_block = False
    skipping_item = False

    def flush() -> None:
        nonlocal current
        if current:
            text = " ".join(current).strip()
            if text:
                blocks.append(text)
            current = []

    for raw in lines:
        line = raw.rstrip()
        if fence:
            if _FENCE_RE.match(line) and line.strip().startswith(fence):
                fence = ""
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            flush()
            fence = opening.group(1)
            in_http_block = False
            skipping_item = False
            continue
        if not line.strip():
            flush()
            in_http_block = False
            skipping_item = False
            continue
        # An unfenced HTTP block runs from its request/status line to the next
        # blank line, so ``Cookie: session=…`` is consumed as part of the block
        # rather than by a generic ``word:`` rule that would also swallow prose.
        if in_http_block:
            continue
        if _ANY_HEADING_RE.match(line) or _TABLE_ROW_RE.match(line):
            flush()
            skipping_item = False
            continue
        if _HTTP_REQUEST_LINE_RE.match(line) or _HTTP_STATUS_LINE_RE.match(line):
            flush()
            in_http_block = True
            skipping_item = False
            continue
        if _STRUCTURAL_PUNCT_RE.match(line) or _BOLD_LABEL_ONLY_RE.match(line):
            flush()
            skipping_item = False
            continue
        # A ``**Label:** value`` line is its own item, exactly like a list entry:
        # ``**Primary fix:** …`` / ``**Defense in depth:** …`` is a real Remediation
        # shape, and joining those lines into one run would both invent a sentence
        # nobody wrote and collapse several items into one.
        if _BOLD_LABEL_VALUE_RE.match(line):
            flush()
            skipping_item = False
        if drop_ordered_items and _ORDERED_ITEM_RE.match(line):
            flush()
            skipping_item = True
            continue
        if skipping_item:
            if raw[:1].isspace():
                continue
            skipping_item = False
        if _LIST_MARKER_RE.match(line):
            flush()
            line = _LIST_MARKER_RE.sub("", line, count=1)
        else:
            line = _BLOCKQUOTE_RE.sub("", line)
        current.append(line.strip())
    flush()
    return blocks


def _fenced_blocks(lines: list[str]) -> list[list[str]]:
    """The inner lines of each fenced block in a section, in document order."""
    blocks: list[list[str]] = []
    current: list[str] | None = None
    fence = ""
    for raw in lines:
        line = raw.rstrip()
        if fence:
            if _FENCE_RE.match(line) and line.strip().startswith(fence):
                blocks.append(current or [])
                current = None
                fence = ""
            elif current is not None:
                current.append(line)
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            fence = opening.group(1)
            current = []
    if current:
        blocks.append(current)
    return blocks


def _sentences(block: str) -> list[str]:
    """Split one prose paragraph into sentences.

    A boundary is a terminator, optional closing quote/bracket, whitespace, and a
    next character that opens a sentence (upper case, digit, quote, bracket, or a
    backticked identifier). Anything else is left joined. The bias is deliberate:
    an over-split produces two SHORTER segments and merely under-reports, while an
    under-split invents a long sentence and fires a false advisory. The
    abbreviation guard exists for the same reason — "e.g." must not end a sentence.

    A segment carrying no word-like token (a stray rule, a lone marker) is not a
    sentence and is dropped, so it can never pad a section's sentence count.
    """
    text = block.strip()
    if not text:
        return []
    sentences: list[str] = []
    start = 0
    for match in _SENTENCE_BOUNDARY_RE.finditer(text):
        nxt = text[match.end() : match.end() + 1]
        if not nxt or not (nxt.isupper() or nxt.isdigit() or nxt in "([\"'`“‘"):
            continue
        trailing = re.search(r"([A-Za-z][A-Za-z.]*)\.$", text[: match.start() + 1])
        if trailing and trailing.group(1).rstrip(".").lower() in _ABBREVIATIONS:
            continue
        sentences.append(text[start : match.end()].strip())
        start = match.end()
    sentences.append(text[start:].strip())
    return [piece for piece in sentences if _word_count(piece)]


def _word_count(sentence: str) -> int:
    """Words in one sentence, with each inline-code span counted as ONE word.

    ``Run `curl -sk -H 'Cookie: session=x' https://host/a/b -o out.json` and read
    the body`` is a short instruction wrapped around one opaque token, not a
    twenty-word sentence. Counting the argv word by word would fire the length
    advisory on well-written steps, which is the FP class most likely to teach the
    report-writer to ignore advisories entirely.
    """
    text = _INLINE_CODE_RE.sub(" code ", sentence)
    text = text.replace("**", " ").replace("__", " ")
    return sum(1 for token in text.split() if _WORDLIKE_RE.search(token))


def _step_count(lines: list[str], steps: object) -> int:
    """How many steps the reproduction actually has.

    Read from the RENDERED section, not ``len(details.steps_to_reproduce)``: the
    preferred authored shape is one string holding the whole numbered block (see
    :func:`step_lines`), for which the list length is 1 however many steps it
    contains. ``#### Step N`` headings win over bare ``N.`` enumerators when both
    are present, so a numbered sub-list inside a labelled step is not a step. The
    authored list length is the floor for the multi-element case, where each item
    is a step and may carry no enumerator at all.
    """
    headings = 0
    ordered = 0
    fence = ""
    for raw in lines:
        line = raw.rstrip()
        if fence:
            if _FENCE_RE.match(line) and line.strip().startswith(fence):
                fence = ""
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            fence = opening.group(1)
            continue
        if _STEP_HEADING_RE.match(line):
            headings += 1
        elif _ORDERED_ITEM_RE.match(line):
            ordered += 1
    marked = headings or ordered
    authored = string_list(steps)
    return max(marked, len(authored) if len(authored) > 1 else 0)


def _list_item_count(lines: list[str]) -> int:
    """Top-level list items in a section (bullet or ordered), fences skipped.

    Remediation is budgeted in ITEMS, and an item is a list entry whether the
    author reached for ``-`` or ``1.``. Nested entries (4+ spaces of indent) are
    sub-points of an item, not items.
    """
    count = 0
    fence = ""
    for raw in lines:
        line = raw.rstrip()
        if fence:
            if _FENCE_RE.match(line) and line.strip().startswith(fence):
                fence = ""
            continue
        opening = _FENCE_RE.match(line)
        if opening:
            fence = opening.group(1)
            continue
        if _LIST_MARKER_RE.match(line):
            count += 1
    return count


def _tail_range(noun: str, budget: int, total: int, clause: tuple[str, str]) -> str:
    """``sentence 5 carries …`` / ``sentences 5-7 carry …`` — the over-budget part."""
    if total <= budget + 1:
        return f"{noun} {total} {clause[0]}"
    return f"{noun}s {budget + 1}-{total} {clause[1]}"


def _quote(sentence: str) -> str:
    """A short, embeddable excerpt naming the sentence a length advisory points at.

    Whitespace is collapsed first, so a sentence that wraps multiple source lines
    cannot inject a bare newline into the single OPERATOR DETAILS bullet the quote
    renders inside — that would break the fragment out of its ``- `` list item.
    Backticks and pipes are swapped out too, since either can make the excerpt read
    as a fence or a table cell it never was. Truncation is capped by BOTH words and
    characters: an inline-code span counts as ONE word to :func:`_word_count`, so an
    ``_QUOTE_WORD_BUDGET``-word quote can still run long in raw characters when one
    of those words is an opaque command line — the character cap is the backstop.
    """
    flat = " ".join(sentence.split()).replace("`", "'").replace("|", "/")
    words = flat.split(" ")
    quote = " ".join(words[:_QUOTE_WORD_BUDGET])
    truncated = len(words) > _QUOTE_WORD_BUDGET
    if len(quote) > _QUOTE_CHAR_BUDGET:
        quote = quote[:_QUOTE_CHAR_BUDGET].rstrip()
        truncated = True
    return f"{quote}…" if truncated else quote


def prose_advisories(
    text: str,
    *,
    steps: object = None,
    separator_ordinal: int = 2,
) -> list[str]:
    """Length/shape advice about a rendered submission body. NEVER blocking.

    Four measurements, each mirroring a ceiling ``submission-format.md`` already
    states in prose: sentence length (25 words, 20 inside Steps to Reproduce), step
    count (10), per-section sentence counts (Summary 4 / Attack Scenario 3 /
    Impact 2 / Remediation 3 items), and Evidence block length (15 lines per
    request/response pair).

    They live here with :func:`title_advisories`, and deliberately NOT in
    :func:`hygiene_warnings`, for the reason that docstring gives: a hygiene
    warning is a FACT about the document and fails a final export closed, while
    every number above is an editorial ceiling. A finished, verified finding whose
    Summary runs to five sentences is a publishable finding; refusing to render it
    would be the tool overruling the author on style, and would also make the
    ceilings unfalsifiable — the report-writer could no longer decide that this
    particular finding needs the extra sentence. So these are surfaced in
    ``submission-context.json``, on stderr, and under OPERATOR DETAILS, and the
    report-writer decides.

    Scanning is confined to the PASTEABLE body (above the ``separator_ordinal``-th
    ``---``, the same window :func:`hygiene_warnings` uses) so the never-paste
    OPERATOR DETAILS reference — which legitimately carries whole PoC requests,
    responses, and command transcripts — is never measured as submission prose.

    ``steps`` takes the authored ``details.steps_to_reproduce`` value; it is only a
    floor for the step count (see :func:`_step_count`).
    """
    body = pasteable_body(text, separator_ordinal=separator_ordinal)
    sections = _submission_sections(body)
    advisories: list[str] = []

    # 1. Sentence length. Steps are partitioned out rather than double-counted:
    #    a Steps sentence is measured against 20 and reported in the Steps
    #    advisory only, so no sentence appears in two advisories at once. The
    #    sentence text rides along so the message can quote the longest offender —
    #    the one it already names by word count — rather than just pointing at a
    #    section and leaving the author to hunt for it.
    over_general: list[tuple[int, str, str]] = []
    over_steps: list[tuple[int, str]] = []
    for name, lines in sections:
        in_steps = name == _STEPS_SECTION
        budget = _STEPS_SENTENCE_WORD_BUDGET if in_steps else _SENTENCE_WORD_BUDGET
        for block in _prose_blocks(lines):
            for sentence in _sentences(block):
                words = _word_count(sentence)
                if words <= budget:
                    continue
                if in_steps:
                    over_steps.append((words, sentence))
                else:
                    over_general.append((words, name, sentence))
    if over_general:
        count = len(over_general)
        longest, where, sentence = max(over_general, key=lambda item: item[0])
        verb = "sentence runs" if count == 1 else "sentences run"
        advisories.append(
            f"{count} {verb} over {_SENTENCE_WORD_BUDGET} words (longest {longest}, "
            f'in {where}: "{_quote(sentence)}"). Long sentences are the most common '
            "reason a triager re-reads a submission — consider splitting them."
        )
    if over_steps:
        count = len(over_steps)
        longest, sentence = max(over_steps, key=lambda item: item[0])
        verb = "sentence runs" if count == 1 else "sentences run"
        advisories.append(
            f"{count} {verb} over {_STEPS_SENTENCE_WORD_BUDGET} words in "
            f'{_STEPS_SECTION} (longest {longest}: "{_quote(sentence)}"). A step '
            "that has to be re-read is a step a triager can execute wrong — "
            "consider splitting them."
        )

    section_lines = {name: lines for name, lines in sections}

    # 2. Step count.
    step_total = _step_count(section_lines.get(_STEPS_SECTION, []), steps)
    if step_total > _STEP_COUNT_BUDGET:
        advisories.append(
            f"steps_to_reproduce has {step_total} steps (suggested ceiling "
            f"{_STEP_COUNT_BUDGET}). Worth a look: are any of these confirmations, "
            "alternates, or dead ends that don't gate a later step? Dropping a step "
            "re-triggers repro rehearsal."
        )

    # 3. Per-section sentence counts. Summary drops ordered-list items so the
    #    optional Exploit flow inside the authored summary is not counted as prose.
    for name, budget, clause in _SECTION_SENTENCE_BUDGETS:
        lines = section_lines.get(name)
        if lines is None:
            continue
        blocks = _prose_blocks(lines, drop_ordered_items=name == "Summary")
        total = sum(len(_sentences(block)) for block in blocks)
        if total > budget:
            advisories.append(
                f"{name} is {total} sentences (budget {budget}). The budget is a "
                "ceiling, not a target — consider whether "
                f"{_tail_range('sentence', budget, total, clause)}."
            )

    # 4. Remediation is budgeted in ITEMS: its list entries when it is a list, its
    #    sentences when it is prose (the shape both canonical examples use).
    remediation = section_lines.get("Remediation")
    if remediation is not None:
        items = _list_item_count(remediation)
        if not items:
            items = sum(len(_sentences(b)) for b in _prose_blocks(remediation))
        if items > _REMEDIATION_ITEM_BUDGET:
            advisories.append(
                f"Remediation is {items} items (budget {_REMEDIATION_ITEM_BUDGET}). "
                "The budget is a ceiling, not a target — consider whether "
                f"{_tail_range('item', _REMEDIATION_ITEM_BUDGET, items, _REMEDIATION_ITEM_CLAUSE)}."
            )

    # 5. Evidence block length. Blank lines are not counted: a 17-line block that
    #    is three well-spaced request/response pairs is inside the documented
    #    "5-15 lines per pair" budget, and firing on its whitespace would be the
    #    kind of false positive that teaches the reader to skip advisories.
    for index, block in enumerate(_fenced_blocks(section_lines.get("Evidence", [])), start=1):
        content = sum(1 for line in block if line.strip())
        if content > _EVIDENCE_BLOCK_LINE_BUDGET:
            advisories.append(
                f"Evidence block {index} is {content} lines of content (budget "
                f"{_EVIDENCE_BLOCK_LINE_BUDGET}). Consider truncating to the lines "
                "carrying the proof marker."
            )

    return advisories


# ---------------------------------------------------------------------------
# Reproduction-rehearsal advisory — decision-row state, not document text
# ---------------------------------------------------------------------------
#
# The one advisory here measures BACKEND STATE rather than the rendered prose, so
# it takes already-fetched rows instead of text. Everything else about it matches
# the family above: surfaced, never blocking.

# The decision kind stamped by the Phase-8 rehearsal (agent/phases/phase-8-report.md).
_REHEARSAL_KIND = "repro_rehearsal"
# The only verdict that clears the finding for drafting; `failed` routes it back to
# the specialist that recorded it.
_REHEARSAL_PASS_VERDICT = "followed"


def _run_id_set(values: object) -> set[int]:
    """Command-run ids from a declared list, accepting ints and digit strings.

    Deliberately lossy where ``export_submission._repro_runs`` is not: that
    function REPORTS every malformed entry because a bad id there is a claim about
    what was executed, while here an unparseable entry only means one id cannot
    participate in a set comparison. Silently dropping it makes the comparison
    narrower (fewer ids on both sides), never wider — so it can cost a signal,
    which is the safe direction, and cannot manufacture one.
    """
    if not isinstance(values, list):
        return set()
    ids: set[int] = set()
    for entry in values:
        if isinstance(entry, bool):
            continue
        if isinstance(entry, int):
            ids.add(entry)
        elif isinstance(entry, str) and entry.strip().isdigit():
            ids.add(int(entry.strip()))
    return ids


def _decision_recency(row: dict) -> tuple[str, int]:
    """Sort key picking the NEWEST decision row.

    ``created_at`` is written as a fixed-width ``%Y-%m-%dT%H:%M:%SZ`` UTC string,
    so a plain string compare orders it correctly without parsing. ``id`` breaks
    the tie, because that stamp has one-second resolution and two rehearsals of
    the same finding inside one second would otherwise order arbitrarily. The
    backend already returns these rows newest-first; sorting again is cheap
    insurance against picking the wrong row, which would make the advisory state
    something false about the finding.
    """
    raw_id = row.get("id")
    return (nonempty(row.get("created_at")), raw_id if type(raw_id) is int else 0)


def repro_rehearsal_advisories(
    decisions: object,
    slug: str,
    *,
    repro_run_ids: object = None,
) -> list[str]:
    """Advice about the reproduction rehearsal behind a finding. NEVER blocking.

    The rehearsal (``agent/phases/phase-8-report.md``) is the only check that
    EXECUTES ``details.steps_to_reproduce`` from a cold start; every other gate
    reads them. It is therefore the only thing that catches a step that removes
    state a later step needs — which is exactly what dropping a step during
    authoring can create, and why the plan re-triggers the rehearsal on a cut.

    Returns at most ONE advisory, from three mutually exclusive observations about
    the ``kind='repro_rehearsal'`` decision rows for ``slug`` (newest wins):

      1. no row at all — nobody has run this reproduction;
      2. the newest row's ``verdict`` is not ``followed`` — the recorded rehearsal
         did not reach the stated outcome;
      3. the newest row's ``runs_checked`` names a run ``details.repro_runs`` no
         longer declares — the reproduction changed after it was rehearsed.

    They are mutually exclusive because they have different fixes and naming two
    at once would point the report-writer at two of them.

    WHY THERE IS NO TIMESTAMP COMPARISON. The ideal check is "rehearsal stamp vs.
    the moment ``steps_to_reproduce`` last changed", and the backend cannot answer
    the second half: ``assessment_findings`` carries a whole-row ``updated_at`` /
    ``row_version`` and no per-field write record, and a finding transition row is
    written only when a LIFECYCLE field changes, so a details-only authoring write
    leaves no trace of its own. Comparing against ``updated_at`` would therefore
    fire whenever anything about the finding changed — and the report-writer's own
    write-back of Summary/Evidence/Impact happens between the rehearsal and the
    export on every finding, so that check would fire on every finding, always. A
    signal that is always on is worse than no signal: it teaches the reader to skip
    the advisory block, which costs the advisories that are true.

    Observation 3 is the sound part of that comparison, keyed on CONTENT instead of
    time. It fires in one direction only — a run the rehearsal checked that the
    finding no longer declares — which is the documented signature of a dropped
    step (the build rule removes the dropped step's id from ``repro_runs``). The
    other direction, ``repro_runs`` ids the rehearsal did not check, is NOT a
    signal: ``runs_checked`` records what the rehearsal diffed, not what it
    covered, so a partial check is normal and firing on it would be noise. The
    advisory states what it observed rather than asserting a step was dropped,
    because a corrected run id produces the same observation and deserves the same
    (cheap) answer: confirm the rehearsal still covers the current steps.

    ``repro_run_ids`` takes the finding's declared ``details.repro_runs``.
    Observation 3 is skipped when it is empty, because "no runs declared" already
    has its own advisory and a finding with none of them has nothing to compare.
    """
    rows = [
        row
        for row in (decisions if isinstance(decisions, list) else [])
        if isinstance(row, dict)
        # ``kind`` is re-checked here even though the caller filters it server-side:
        # ``blind_triage_verdict`` rows carry a ``finding_slug`` in the same payload
        # shape, so an unfiltered list handed to this function would otherwise read
        # a triage verdict as a rehearsal. The column is NOT NULL, so requiring it
        # cannot drop a real row.
        and nonempty(row.get("kind")) == _REHEARSAL_KIND
        and isinstance(row.get("payload"), dict)
        and nonempty(row["payload"].get("finding_slug")) == nonempty(slug)
    ]
    if not rows:
        return [
            "no repro_rehearsal decision is recorded for this finding — a rehearsal "
            "is what catches a step that removes state a later step needs, which "
            "reading the steps cannot. Run details.steps_to_reproduce from a cold "
            "start and stamp the outcome with `vigil assess agent decision --kind "
            "repro_rehearsal --payload-json '{\"finding_slug\":\"<slug>\","
            "\"verdict\":\"followed\",\"runs_checked\":[<run_id>, ...]}'` before "
            "publishing."
        ]

    latest = max(rows, key=_decision_recency)
    payload = latest["payload"]
    verdict = nonempty(payload.get("verdict"))
    if not verdict.lower().startswith(_REHEARSAL_PASS_VERDICT):
        # The observed value is quoted rather than translated: a verdict this
        # command does not recognise is not the same fact as `failed`, and naming
        # the wrong one sends the report-writer to fix something that is fine.
        return [
            "the most recent repro_rehearsal decision for this finding records "
            f"verdict {verdict or '(none)'!r}, not {_REHEARSAL_PASS_VERDICT!r} — "
            "only a followed rehearsal clears the reproduction. Route the finding "
            "back to the specialist that recorded it with the failing step, then "
            "re-rehearse and stamp the new verdict before publishing."
        ]

    declared = _run_id_set(repro_run_ids)
    checked = _run_id_set(payload.get("runs_checked"))
    dropped = sorted(checked - declared) if declared else []
    if dropped:
        noun = "run" if len(dropped) == 1 else "runs"
        names = ", ".join(str(run_id) for run_id in dropped)
        return [
            f"the most recent repro_rehearsal decision checked {noun} {names}, which "
            "details.repro_runs no longer declares — the reproduction has changed "
            "since it was rehearsed. If a step was dropped, re-run the rehearsal "
            "against the trimmed steps; if the ids were only corrected, confirm the "
            "recorded rehearsal still covers the current steps."
        ]

    return []


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
