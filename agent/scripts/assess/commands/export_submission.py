"""vigil assess export-submission — per-finding, platform-shaped submission writeup.

Renders ONE finding into a submission-ready ``submission.md`` (+ a machine-readable
``submission-context.json``) under ``$ENGAGEMENT_DIR/submissions/<slug>/``, shaped
for a bug-bounty platform (Bugcrowd / HackerOne) or a direct company disclosure.

This is the submission-first replacement for the retired red/code ``report.md``
path (docs/plans/submission-first-reporting-2026-07.md). Two modes:

  * ``--draft`` (the normal report-writer entrypoint) always writes, inserting
    ``[NEEDS: <field>]`` markers wherever a proof-critical field is missing.
  * final (default) applies the strict gate: it refuses to write and exits
    non-zero unless title, severity + CVSS vector, the platform taxonomy
    (Bugcrowd VRT / HackerOne weakness), an attacker-impact statement, and at
    least one concrete proof are all present.

BACKEND FINDING IS THE SOURCE OF TRUTH. The submission is rendered FROM the
finding's fields; the report-writer writes final content back to the finding
(``update-finding``), so a re-render at publish time is reproducible and loses no
hand edits, and PII masking is safe — the MASKED evidence is stored in the finding
and reaches the copy-paste body, while the raw tool output stays in ``scans/`` and
is never rendered here.

OUTPUT SHAPE — the real platform copy-paste layout, matching the scaffolds under
``agent/skills/report-generation/templates/{bugcrowd,hackerone,direct}.md`` (this
command references them by path; it does not read their bytes):

  * header field lines — ``**Title:**``, then ``**VRT:**`` (Bugcrowd) or
    ``**Weakness:**`` (HackerOne; ``direct`` drops both), then ``**Severity:**``
    and ``**CVSS:**``;
  * a ``---`` separator (so the operator selects the whole body in one paste);
  * the stable ``### `` sections — Summary, Steps to Reproduce, Evidence,
    (Attack Scenario), Impact, Remediation;
  * a second ``---`` and ONE "OPERATOR DETAILS — NOT FOR SUBMISSION" reference
    section. Everything below that second ``---`` is reference the operator never
    pastes — the report-writer authors the body sections (Evidence especially)
    FROM it. It carries, in order: the finding metadata (CWE / OWASP / location /
    auth context / references) to weave into the body; any internal-identifier
    hygiene warnings to strip; the structured proof (``poc_code`` /
    ``poc_request`` / ``poc_response`` / ``evidence_ref``) to mask and weave into
    Evidence; and the explicitly linked command runs to author Evidence from. The
    section is present in BOTH draft and final — it sits below the never-paste
    line, so keeping it in both avoids any draft/final structural divergence.

EVIDENCE IS AUTHORED, NOT SYNTHESIZED. The ``### Evidence`` section renders ONLY
the finding's authored ``details.evidence`` prose (``[NEEDS: evidence]`` in a draft
when absent; empty in final, since ``details.evidence`` is authored prose, not a
strict-gate field). The raw structured proof and the linked command runs are
deliberately NOT rendered into Evidence: a real submission carries hand-annotated,
PII-masked proof, so the tool surfaces them ONCE, as reference under the single
OPERATOR DETAILS section (mirrored by the ``linked_command_runs`` array in the
context JSON), for the report-writer to author Evidence FROM. Linked runs are
sourced ONLY from explicit ``finding-links`` (``target_kind="command_run"``) —
never a fuzzy command search (plan decision 4).

The generated ``submission.md`` is registered as a finding-linked artifact
(``kind="submission"``); the finding's ``submission_status`` is never written
(omitting the field preserves it).

The generator is FAITHFUL: it never rewrites the finding's content — a
target-application UUID, a filename, or a path reaches the report-writer
verbatim, because silently mangling them (a blanket UUID scrub redacting the very
identifier a PoC proves, a greedy ``cases.db`` regex clipping a real filename)
confuses the editor more than it protects. Instead it FLAGS internal identifiers
— this finding's slug, engagement / finding / agent UUIDs, absolute engagement
paths, and cases.db references — as non-destructive ``hygiene_warnings`` (in the
context JSON and on stderr), so the report-writer and the blind-triage gate strip
them deliberately before an EXTERNAL submission.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
# ``_fence_for`` and ``header_lines`` are the same PoC-formatting primitives the
# shared finding renderer uses (finding_render.py ~:205/:225); reusing them keeps
# submission PoC blocks byte-identical to export-findings rather than reimplementing.
from assess.lib.finding_render import _fence_for, detail_value, details_object, header_lines, string_list

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
_PLATFORM_LABEL = {"bugcrowd": "Bugcrowd", "hackerone": "HackerOne", "direct": "Direct disclosure"}

# UUID shape — used only to confirm a collected internal id is genuinely a UUID
# before we FLAG (never rewrite) its presence. A target-application UUID in PoC
# proof (e.g. an IDOR/BOLA on a UUID-keyed resource) is never touched.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# Detects a reference to the internal cases.db work database (presence only).
_CASES_DB_RE = re.compile(r"cases\.db")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "export-submission",
        help=(
            "Render one finding into a platform-shaped, submission-ready "
            "submission.md (+ context JSON). --draft always writes with "
            "[NEEDS: ...] markers; final mode gates on proof completeness."
        ),
    )
    p.add_argument("slug", help="Finding slug to render (e.g. VA-047)")
    p.add_argument(
        "--platform",
        required=True,
        choices=_PLATFORMS,
        help="Submission target: bugcrowd (VRT) | hackerone (weakness) | direct (company-facing)",
    )
    p.add_argument(
        "--draft",
        action="store_true",
        help="Always write; mark missing proof-critical fields with [NEEDS: ...] instead of gating.",
    )
    p.add_argument(
        "--output",
        dest="output_dir",
        default="",
        help="Override the output directory (default: $ENGAGEMENT_DIR/submissions/<slug>/).",
    )
    p.add_argument("--overwrite", action="store_true", help="Overwrite an existing submission.md.")
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit a machine-readable summary to stdout.")
    p.add_argument(
        "--vrt-category",
        dest="vrt_category",
        default="",
        help="Bugcrowd VRT category (else read from finding details.vrt_category).",
    )
    p.add_argument(
        "--weakness",
        dest="weakness",
        default="",
        help="HackerOne weakness (else read from finding details.weakness).",
    )
    p.set_defaults(func=run)


def _nonempty(value: object) -> str:
    return str(value or "").strip()


def _needs(value: object, field: str) -> str:
    """Return ``value`` or, when empty, the ``[NEEDS: field]`` draft marker.

    Final mode never reaches the renderer with an empty proof-critical field
    (the strict gate raises first), so the marker only ever surfaces in drafts.
    """
    text = _nonempty(value)
    return text or f"[NEEDS: {field}]"


def _poc_pair_present(finding: dict) -> bool:
    request = detail_value(finding, "poc_request")
    response = detail_value(finding, "poc_response")
    return bool(isinstance(request, dict) and request and isinstance(response, dict) and response)


def _evaluate(finding: dict, platform: str, vrt_category: str, weakness: str) -> dict:
    """Resolve the submission's proof-critical fields and the strict-gate misses.

    ``missing`` is the ordered list of proof-critical fields absent for this
    ``platform``; it drives both the final-mode gate (any entry => refuse) and
    the ``[NEEDS: ...]`` draft markers.
    """
    title = _nonempty(finding.get("title"))
    severity = _nonempty(finding.get("severity"))
    cvss_vector = _nonempty(detail_value(finding, "cvss_vector", ""))
    cvss_score = finding.get("cvss_score")
    if cvss_score is None:
        cvss_score = detail_value(finding, "cvss_score", None)
    # Attacker-impact statement: finding `impact` (top-level or details), else
    # `summary` — matching the templates' "Populated from: impact / summary".
    impact = _nonempty(detail_value(finding, "impact", "")) or _nonempty(finding.get("summary"))

    poc_pair = _poc_pair_present(finding)
    poc_code = _nonempty(detail_value(finding, "poc_code", ""))
    evidence_ref = _nonempty(detail_value(finding, "evidence_ref", ""))
    has_proof = poc_pair or bool(poc_code) or bool(evidence_ref)

    vrt = _nonempty(vrt_category) or _nonempty(detail_value(finding, "vrt_category", ""))
    weak = _nonempty(weakness) or _nonempty(detail_value(finding, "weakness", ""))

    missing: list[str] = []
    if not title:
        missing.append("title")
    if not severity:
        missing.append("severity")
    if not cvss_vector:
        missing.append("CVSS vector")
    if platform == "bugcrowd" and not vrt:
        missing.append("VRT category")
    elif platform == "hackerone" and not weak:
        missing.append("weakness")
    if not impact:
        missing.append("attacker-impact statement")
    if not has_proof:
        missing.append("proof (poc_request+poc_response, poc_code, or evidence_ref)")

    return {
        "title": title,
        "severity": severity,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "impact": impact,
        "vrt": vrt,
        "weakness": weak,
        "poc_pair": poc_pair,
        "poc_code": poc_code,
        "evidence_ref": evidence_ref,
        "has_proof": has_proof,
        "missing": missing,
    }


def _linked_command_runs(client, slug: str) -> list[dict]:
    """Linked command runs for ``slug`` from EXPLICIT finding-links only.

    Sources command runs strictly from ``finding-links`` rows whose
    ``target_kind == "command_run"`` for this finding, then fetches each linked
    run for its command string. There is deliberately NO fuzzy
    ``command-runs?q=`` search here (plan decision 4): the report-writer agent
    runs the targeted ``list-command-runs`` search itself and links the exact
    reproducing run; this command only surfaces what was explicitly linked.

    These runs are REFERENCE, not final Evidence — they are handed to the
    report-writer (context JSON ``linked_command_runs`` + the "Linked command runs"
    entry under the single OPERATOR DETAILS section) to author the Evidence section
    from, never auto-formatted into it.
    """
    try:
        links = client.get("finding-links")
    except AssessError as exc:
        print(f"WARN export-submission: could not load finding-links: {exc}", file=sys.stderr)
        return []
    if not isinstance(links, list):
        return []

    run_ids: list[int] = []
    seen: set[int] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        if _nonempty(link.get("finding_slug")) != slug:
            continue
        if _nonempty(link.get("target_kind")) != "command_run":
            continue
        target_id = link.get("target_id")
        run_id: int | None = None
        if isinstance(target_id, bool):
            continue
        if isinstance(target_id, int):
            run_id = target_id
        elif isinstance(target_id, str) and target_id.isdigit():
            run_id = int(target_id)
        if run_id is None or run_id in seen:
            continue
        seen.add(run_id)
        run_ids.append(run_id)

    runs: list[dict] = []
    for run_id in run_ids:
        try:
            row = client.get(f"command-runs/{run_id}")
        except AssessError as exc:
            print(f"WARN export-submission: command-run {run_id} unavailable: {exc}", file=sys.stderr)
            continue
        if isinstance(row, dict) and _nonempty(row.get("command")):
            runs.append(row)
    return runs


def _poc_lines(finding: dict) -> list[str]:
    """Render poc_code / poc_request / poc_response, reusing finding_render's fencing."""
    lines: list[str] = []
    poc_code = _nonempty(detail_value(finding, "poc_code", ""))
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
        resp_body = str(poc_response.get("body_excerpt") or "")
        status_line = f"HTTP {poc_response.get('status', '')}".strip()
        fence = _fence_for(status_line, "\n".join(resp_headers), resp_body)
        block = [f"{fence}\n{status_line}"]
        block += resp_headers
        if poc_response.get("body_excerpt"):
            block.append(f"\n{poc_response['body_excerpt']}")
        block.append(fence)
        lines += ["**PoC Response:**", "\n".join(block), ""]
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    """A stable ``### `` body section (copy-paste block)."""
    return [f"### {title}", "", *body, ""]


def _evidence_body(finding: dict, draft: bool) -> list[str]:
    """The Evidence section renders ONLY the finding's authored ``details.evidence``.

    The structured proof (``poc_*`` / ``evidence_ref``) and the linked command runs
    are deliberately NOT here — they live in the single OPERATOR DETAILS reference
    section below the second divider, which the report-writer masks and weaves into
    this authored prose. Draft mode marks an absent evidence body with
    ``[NEEDS: evidence]``; final mode leaves it empty, because ``details.evidence``
    is authored prose, not a strict-gate proof field (the gate presence-checks the
    structured proof instead).
    """
    evidence_text = _nonempty(detail_value(finding, "evidence", ""))
    if evidence_text:
        return [evidence_text]
    if draft:
        return ["[NEEDS: evidence]"]
    return []


def _metadata_reference_lines(finding: dict) -> list[str]:
    """Finding metadata that isn't a copy-paste header field, for OPERATOR DETAILS.

    CWE / OWASP / location / auth-context / references are kept out of the
    outward-facing header (which is Title / VRT-or-Weakness / Severity / CVSS
    only) so nothing is lost while the copy-paste block stays clean — the
    report-writer weaves these into the body prose where useful.
    """
    lines: list[str] = []
    cwe = _nonempty(detail_value(finding, "cwe_id", ""))
    if cwe:
        lines.append(f"- CWE: {cwe}")
    owasp = _nonempty(detail_value(finding, "owasp_category", ""))
    if owasp:
        lines.append(f"- OWASP: {owasp}")
    location = _nonempty(finding.get("canonical_location"))
    if location:
        method = _nonempty(details_object(finding).get("request_method"))
        # Some findings bake the method into canonical_location ("POST https://…");
        # only prepend request_method when it is not already the prefix (avoids
        # "POST POST https://…").
        if method and not location.upper().startswith(method.upper()):
            location = f"{method} {location}"
        lines.append(f"- Location: {location}")
    auth_context = _nonempty(finding.get("auth_context"))
    if auth_context:
        lines.append(f"- Auth context: {auth_context}")
    references = string_list(detail_value(finding, "references", []))
    if references:
        lines.append(f"- References: {', '.join(references)}")
    return lines


def _finding_record_lines(finding: dict) -> list[str]:
    """The rest of the finding record, surfaced under OPERATOR DETAILS so the
    report-writer edits with the full picture at hand — dedup/merge state, root
    cause, chain/propagation analysis, and verification. Everything is below the
    never-paste line, where more context beats less.
    """
    d = details_object(finding)
    out: list[str] = []

    # Dedup / merge / root cause — decisive when a finding is consolidated.
    dedup: list[str] = []
    merged = _nonempty(finding.get("merged_into_slug"))
    if merged:
        dedup.append(f"- Merged into: {merged} — this finding is consolidated; file the lead, not this one")
    for label, key in (("Root cause key", "root_cause_key"), ("Root cause note", "root_cause_note"), ("Defect family", "defect_family")):
        value = _nonempty(finding.get(key))
        if value:
            dedup.append(f"- {label}: {value}")
    if dedup:
        out += ["**Dedup / root cause:**", "", *dedup, ""]

    # Chain / propagation analysis.
    chain: list[str] = []
    for label, key in (("Chain required", "chain_required"), ("Chain rationale", "chain_rationale"), ("Propagation verdict", "propagation_verdict")):
        value = _nonempty(d.get(key))
        if value:
            chain.append(f"- {label}: {value}")
    if chain:
        out += ["**Chain / propagation:**", "", *chain, ""]

    # Verification provenance.
    ver: list[str] = []
    for label, key in (("Verification state", "verification_state"), ("Verification disposition", "verification_disposition")):
        value = _nonempty(finding.get(key))
        if value:
            ver.append(f"- {label}: {value}")
    discovered = _nonempty(d.get("discovered_by")) or _nonempty(finding.get("source_name"))
    if discovered:
        ver.append(f"- Discovered by: {discovered}")
    if ver:
        out += ["**Verification:**", "", *ver, ""]

    return out


def _notes_reference_lines(finding: dict) -> list[str]:
    """The finding's freeform ``notes`` (mechanism / reachability / caveats) as a
    reference block — the largest reference, so it sits last under OPERATOR DETAILS."""
    notes = _nonempty(finding.get("notes"))
    if not notes:
        return []
    return ["**Investigation notes** (working record — mine for detail, do not paste verbatim):", "", notes, ""]


def _operator_details_block(
    finding: dict,
    resolved: dict,
    linked_runs: list[dict],
    hygiene_warnings: list[str],
    draft: bool,
) -> list[str]:
    """The single OPERATOR DETAILS reference section below the second ``---``.

    ONE section consolidates everything the operator never pastes and the
    report-writer authors the body FROM: the finding metadata to weave in, any
    internal-identifier hygiene warnings to strip, the structured proof
    (``poc_*`` / ``evidence_ref``) to mask into Evidence, and the explicitly
    linked command runs to author Evidence from. It renders in BOTH draft and
    final (it sits below the never-paste line) so the structure never diverges
    between modes. The finding slug is deliberately never emitted here — it would
    otherwise self-trip the hygiene gate.
    """
    lines = [
        "---",
        "",
        "## OPERATOR DETAILS — NOT FOR SUBMISSION (reference only — never paste anything below this line)",
        "",
    ]

    meta = _metadata_reference_lines(finding)
    if meta:
        lines += ["**Finding metadata** (weave into the body as needed):", "", *meta, ""]

    # Dedup/root-cause, chain/propagation, and verification — the full record.
    lines += _finding_record_lines(finding)

    if hygiene_warnings:
        lines += ["**Hygiene warnings** (strip every one before an external submission):", ""]
        lines += [f"- {warning}" for warning in hygiene_warnings]
        lines.append("")

    proof_lines = _poc_lines(finding)
    if resolved["evidence_ref"]:
        proof_lines += [f"- **Evidence reference:** {resolved['evidence_ref']}", ""]
    lines += ["**Structured proof** (mask + weave into the Evidence section above; do NOT paste raw):", ""]
    if proof_lines:
        lines += proof_lines
    elif draft:
        lines += [
            "[NEEDS: proof — a reproducing request/response, PoC code, or evidence reference]",
            "",
        ]

    if linked_runs:
        lines += [
            "**Linked command runs** (author Evidence from these; run "
            "`vigil assess list-command-runs` to find more):",
            "",
        ]
        for row in linked_runs:
            command = _nonempty(row.get("command"))
            if not command:
                continue
            intent = _nonempty(row.get("intent"))
            rc = row.get("return_code")
            rc_str = "" if rc is None else f" (rc={rc})"
            header = f"- **Run{rc_str}**" + (f" — {intent}" if intent else "") + ":"
            fence = _fence_for(command)
            lines += [header, f"{fence}\n{command}\n{fence}", ""]

    # Freeform investigation notes go last — the largest reference block.
    lines += _notes_reference_lines(finding)

    return lines


def _render_markdown(
    finding: dict,
    resolved: dict,
    platform: str,
    linked_runs: list[dict],
    draft: bool,
    hygiene_warnings: list[str],
) -> str:
    # --- header field lines (the platform copy-paste layout) ----------------
    # The slug is NOT emitted in the body (submission-format.md "No internal
    # identifiers"); it lives in the directory name + context JSON.
    lines: list[str] = [f"**Title:** {_needs(resolved['title'], 'title')}", ""]

    if platform == "bugcrowd":
        lines += [f"**VRT:** {_needs(resolved['vrt'], 'VRT category')}", ""]
    elif platform == "hackerone":
        lines += [f"**Weakness:** {_needs(resolved['weakness'], 'weakness')}", ""]
    # direct: no platform-taxonomy line (VRT / weakness dropped).

    severity = resolved["severity"]
    lines += [f"**Severity:** {severity.upper() if severity else '[NEEDS: severity]'}", ""]

    cvss = _needs(resolved["cvss_vector"], "CVSS vector")
    if resolved["cvss_vector"] and resolved["cvss_score"] is not None:
        cvss = f"{cvss} ({resolved['cvss_score']})"
    lines += [f"**CVSS:** {cvss}", ""]

    lines += ["---", ""]

    # --- stable body sections (### headers) ---------------------------------
    summary = _nonempty(finding.get("summary"))
    lines += _section("Summary", [summary or "[NEEDS: summary]"])

    steps = string_list(detail_value(finding, "steps_to_reproduce", []))
    step_body = [f"{i}. {step}" for i, step in enumerate(steps, 1)] or ["[NEEDS: steps to reproduce]"]
    lines += _section("Steps to Reproduce", step_body)

    lines += _section("Evidence", _evidence_body(finding, draft))

    attack_scenario = _nonempty(detail_value(finding, "attack_scenario", ""))
    if attack_scenario:
        lines += _section("Attack Scenario", [attack_scenario])

    lines += _section("Impact", [_needs(resolved["impact"], "attacker-impact statement")])

    remediation = _nonempty(finding.get("remediation")) or _nonempty(detail_value(finding, "remediation", ""))
    lines += _section("Remediation", [remediation or "[NEEDS: remediation]"])

    # --- single OPERATOR DETAILS reference section below the second divider --
    # (never pasted; the report-writer authors the body sections FROM it).
    lines += _operator_details_block(finding, resolved, linked_runs, hygiene_warnings, draft)

    text = "\n".join(lines).rstrip()
    return text + "\n"


def _internal_ids(finding: dict, linked_runs: list[dict]) -> list[str]:
    """UUID-shaped internal identifiers to FLAG (never rewrite) in the output.

    Only ids the backend assigns to its own records — this finding, its
    engagement, and the agents/rows behind the linked command runs. Never the
    target-application identifiers, so PoC proof is never mistaken for internal
    state. Integer ids (e.g. a command-run row's ``id``) collected here are
    harmless: ``_hygiene_warnings`` flags a value only when it is a full UUID.
    """
    ids: list[str] = []
    for key in ("id", "engagement_id", "merged_into_finding_id"):
        ids.append(_nonempty(finding.get(key)))
    for row in linked_runs:
        for key in ("producer_agent_id", "agent_id", "engagement_id", "finding_id"):
            ids.append(_nonempty(row.get(key)))
    seen: set[str] = set()
    unique: list[str] = []
    for value in ids:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _hygiene_warnings(text: str, slug: str, internal_ids: list[str], engagement_dir: str) -> list[str]:
    """Non-destructively FLAG internal identifiers that leaked into the output.

    Returns advisory strings; it NEVER mutates ``text``. The finding's content
    reaches the report-writer verbatim — a target-app UUID, filename, or path must
    survive — and these warnings let the report-writer (and the blind-triage gate)
    decide what to strip before an EXTERNAL submission. Draft submissions are
    internal working artifacts, so leaving the identifiers in place is correct;
    only the outward-facing copy the operator pastes must be clean.
    """
    warnings: list[str] = []
    slug = _nonempty(slug)
    if slug and slug in text:
        warnings.append(
            f"finding slug '{slug}' appears in the body (heading) — remove before external submission"
        )
    eng = _nonempty(engagement_dir).rstrip("/")
    if eng and eng in text:
        warnings.append(
            f"absolute engagement path '{eng}' appears — make paths relative before external submission"
        )
    for value in internal_ids:
        if value and _UUID_RE.fullmatch(value) and value in text:
            warnings.append(
                f"internal identifier '{value}' appears — remove before external submission"
            )
    if _CASES_DB_RE.search(text):
        warnings.append(
            "reference to the internal cases.db work database appears — remove before external submission"
        )
    return warnings


def _engagement_relative(path: Path, engagement_dir: str) -> str | None:
    """Engagement-relative form of ``path``, or None if it lies outside the tree."""
    try:
        rel = os.path.relpath(str(path), str(engagement_dir))
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel


def _build_context(
    slug: str,
    platform: str,
    draft: bool,
    resolved: dict,
    linked_runs: list[dict],
    submission_rel: str,
    hygiene_warnings: list[str],
) -> dict:
    return {
        "slug": slug,
        "platform": platform,
        "mode": "draft" if draft else "final",
        "submission_path": submission_rel,
        "missing": resolved["missing"],
        "proof": {
            "poc_request_and_response": resolved["poc_pair"],
            "poc_code": bool(resolved["poc_code"]),
            "evidence_ref": bool(resolved["evidence_ref"]),
            "has_proof": resolved["has_proof"],
        },
        "taxonomy": {"vrt_category": resolved["vrt"], "weakness": resolved["weakness"]},
        # Clean REFERENCE for the report-writer to author Evidence from — surfaced
        # under OPERATOR DETAILS, never auto-rendered into the Evidence section.
        "linked_command_runs": [
            {
                "id": row.get("id"),
                "intent": _nonempty(row.get("intent")),
                "command": _nonempty(row.get("command")),
                "return_code": row.get("return_code"),
            }
            for row in linked_runs
        ],
        # Advisory only — the report-writer strips these before external submission.
        "hygiene_warnings": hygiene_warnings,
    }


def run(args) -> None:
    slug = args.slug
    platform = args.platform
    draft = bool(args.draft)

    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir

    if args.output_dir:
        out_dir = Path(args.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path(engagement_dir) / out_dir
    else:
        out_dir = Path(engagement_dir) / "submissions" / slug
    submission_md = out_dir / "submission.md"
    context_json = out_dir / "submission-context.json"

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        finding = client.get(f"findings/{slug}")
        if not isinstance(finding, dict):
            raise AssessError(f"export-submission: unexpected response fetching finding {slug!r}")

        linked_runs = _linked_command_runs(client, slug)
        internal_ids = _internal_ids(finding, linked_runs)
        resolved = _evaluate(finding, platform, args.vrt_category, args.weakness)

        # Final mode: refuse to write an incomplete submission (plan decision 3).
        # Raised BEFORE any file write or artifact POST — a gated finding leaves
        # no partial artifacts behind.
        if not draft and resolved["missing"]:
            raise AssessError(
                f"export-submission: cannot render a FINAL {platform} submission for "
                f"{slug!r} — missing proof-critical fields: {', '.join(resolved['missing'])}. "
                "Complete the finding or re-run with --draft to write a work-in-progress "
                "with [NEEDS: ...] markers."
            )

        # Overwrite guard — checked before writing so a stale submission is never
        # silently replaced.
        if submission_md.exists() and not args.overwrite:
            raise AssessError(
                f"export-submission: {_engagement_relative(submission_md, engagement_dir) or submission_md} "
                "already exists; pass --overwrite to replace it."
            )

        submission_rel = _engagement_relative(submission_md, engagement_dir)

        # FAITHFUL render — no content rewriting. Internal identifiers are flagged
        # (not stripped) so the report-writer removes them deliberately. Render
        # once WITHOUT the hygiene-warnings sub-block to scan the real content, then
        # re-render with the resulting warnings woven into OPERATOR DETAILS — the
        # warning strings themselves quote the leaked value (a UUID, a `cases.db`
        # literal), so scanning a render that already contains them would flag the
        # advisory text as if it were a fresh leak.
        scan_markdown = _render_markdown(finding, resolved, platform, linked_runs, draft, [])
        hygiene_warnings = _hygiene_warnings(scan_markdown, slug, internal_ids, engagement_dir)
        markdown = _render_markdown(finding, resolved, platform, linked_runs, draft, hygiene_warnings)
        context = _build_context(
            slug, platform, draft, resolved, linked_runs, submission_rel or str(submission_md), hygiene_warnings
        )
        context_text = json.dumps(context, indent=2, ensure_ascii=False)

        out_dir.mkdir(parents=True, exist_ok=True)
        submission_md.write_text(markdown, encoding="utf-8")
        context_json.write_text(context_text + "\n", encoding="utf-8")

        # Register the submission as a finding-linked artifact. NEVER include
        # submission_status: create lands 'none', and omitting the field on any
        # later upsert preserves whatever the operator set by hand.
        artifact_registered = False
        if submission_rel is not None:
            try:
                client.post(
                    "artifacts",
                    {
                        "path": submission_rel,
                        "kind": "submission",
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
                print(f"WARN export-submission: artifact registration failed: {exc}", file=sys.stderr)
        else:
            print(
                "WARN export-submission: output is outside the engagement dir; "
                "skipping artifact registration.",
                file=sys.stderr,
            )

    # Internal-identifier hygiene is advisory, never fatal: it is the report-writer's
    # job to strip these before the operator submits externally.
    for warning in hygiene_warnings:
        print(f"WARN export-submission: {warning}", file=sys.stderr)

    display_path = submission_rel or str(submission_md)
    if args.as_json:
        summary = {
            "slug": slug,
            "platform": platform,
            "mode": "draft" if draft else "final",
            "path": display_path,
            "missing": resolved["missing"],
            "has_proof": resolved["has_proof"],
            "linked_command_runs": len(linked_runs),
            "artifact_registered": artifact_registered,
            "hygiene_warnings": hygiene_warnings,
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        mode = "draft" if draft else "final"
        print(f"Wrote {mode} {platform} submission for {slug} to {display_path}")
        if resolved["missing"]:
            print("  NEEDS: " + ", ".join(resolved["missing"]))
