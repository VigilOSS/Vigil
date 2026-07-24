"""vigil assess export submission — per-finding, platform-shaped submission writeup.

Renders ONE finding into a submission-ready ``submission.md`` (+ a machine-readable
``submission-context.json``) under ``$ENGAGEMENT_DIR/submissions/<slug>/``, shaped
for a bug-bounty platform (Bugcrowd / HackerOne) or a direct company disclosure.

This is the submission-first replacement for the retired red/code ``report.md``
path. Two modes:

  * ``--draft`` (the normal report-writer entrypoint) always writes, inserting
    ``[NEEDS: <field>]`` markers wherever a proof-critical field is missing.
  * final (default) applies the strict gate: it refuses to write and exits
    non-zero unless the finding is a verified confirmed/downgraded report
    candidate with every outward-facing body section authored, complete platform
    fields, a contained indexed/present evidence artifact, no target readiness
    blockers, and no hygiene warnings.

BACKEND FINDING IS THE SOURCE OF TRUTH. The submission is rendered FROM the
finding's fields; the report-writer writes final content back to the finding
(``finding update``), so a re-render at publish time is reproducible and loses no
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
when absent; final export rejects the finding until it is authored). The raw
structured proof and the linked command runs are
deliberately NOT rendered into Evidence: a real submission carries hand-annotated
proof (genuine third-party PII partial-masked, self-owned/synthetic data in full),
so the tool surfaces them ONCE, as reference under the single
OPERATOR DETAILS section (mirrored by the ``linked_command_runs`` array in the
context JSON), for the report-writer to author Evidence FROM. Linked runs are
sourced ONLY from explicit ``finding-links`` (``target_kind="command_run"``) —
never a fuzzy command search.

The generated ``submission.md`` is registered as a finding-linked artifact
(``kind="submission"``); the finding's ``submission_status`` is never written
(omitting the field preserves it).

The generator is FAITHFUL: it preserves authored content while normalizing a
valid evidence pointer to engagement-relative form. A target-application UUID or
filename reaches the report-writer verbatim; blanket scrubbing would corrupt
proof. It FLAGS internal identifiers
— this finding's slug, engagement / finding / agent UUIDs, absolute engagement
paths, and cases.db references — in draft context/stderr, and final mode blocks
until the source content is clean.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from urllib.parse import urlencode, urlparse

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
# ``_fence_for`` is the same PoC-formatting primitive the shared finding renderer
# uses (finding_render.py); reusing it keeps submission PoC blocks byte-identical
# to export-findings rather than reimplementing. The
# hygiene gate (``collect_internal_ids`` / ``hygiene_warnings`` / ``pasteable_body``)
# and the structured-proof / path helpers (``poc_lines`` / ``engagement_relative``)
# now live there too so ``export_reply`` shares one source of truth (aliased to the
# prior private names to keep this module's call sites unchanged).
from assess.lib.finding_render import (
    _fence_for,
    collect_internal_ids as _internal_ids,
    detail_value,
    details_object,
    engagement_relative as _engagement_relative,
    hygiene_warnings as _hygiene_warnings,
    poc_lines as _poc_lines,
    string_list,
    strip_step_enumerator,
)
from assess.lib.outbound_redaction import redact_outbound_credentials
from assess.lib.scope import rate_caps_for_dir

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
_PLATFORM_LABEL = {"bugcrowd": "Bugcrowd", "hackerone": "HackerOne", "direct": "Direct disclosure"}
_REPORTABLE_STATUSES = {
    "active",
    "blocked",
    "exploited",
    "contained",
    "eradicated",
    "recovered",
    "reported",
}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "submission",
        help=(
            "Render one finding into a platform-shaped, submission-ready "
            "submission.md (+ context JSON). --draft always writes with "
            "[NEEDS: ...] diagnostics; final mode gates on durable evidence, "
            "verified lifecycle, readiness, and hygiene."
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


def _normalize_evidence_path(evidence_ref: str, engagement_dir: str, engagement_key: str) -> tuple[str, str]:
    """Return an engagement-relative evidence path and a diagnostic reason.

    Evidence references may be stored as engagement-relative paths, absolute
    host paths inside the engagement, or Kali's ``/engagements/<key>/`` mount
    form. URLs and paths that escape the engagement are content references, not
    durable local evidence.
    """
    value = _nonempty(evidence_ref)
    if not value:
        return "", "finding has no evidence_ref"
    parsed = urlparse(value)
    if parsed.scheme and parsed.scheme != "file":
        return "", "evidence_ref is a URL, not an engagement artifact"

    mount_prefix = f"/engagements/{engagement_key}/"
    if value.startswith(mount_prefix):
        value = value.removeprefix(mount_prefix)
    elif value.startswith("/engagements/"):
        return "", "evidence_ref points at a different engagement mount"

    root = Path(engagement_dir).expanduser().resolve()
    raw = Path(value).expanduser()
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve(strict=False)
    try:
        relative = resolved.relative_to(root)
    except ValueError:
        return "", "evidence_ref is outside the engagement directory"
    if relative == Path("."):
        return "", "evidence_ref names the engagement directory, not an artifact"
    return relative.as_posix(), ""


def _durable_evidence(
    client,
    finding: dict,
    engagement_dir: str,
    engagement_key: str,
) -> dict:
    raw_ref = _nonempty(detail_value(finding, "evidence_ref", ""))
    relative_path, reason = _normalize_evidence_path(raw_ref, engagement_dir, engagement_key)
    lookup_error = ""
    artifact: dict | None = None
    raw_artifact_id = finding.get("evidence_artifact_id")
    evidence_artifact_id = (
        raw_artifact_id
        if type(raw_artifact_id) is int and raw_artifact_id > 0
        else None
    )
    if relative_path and raw_artifact_id is not None:
        if evidence_artifact_id is None:
            lookup_error = "finding has an invalid evidence_artifact_id"
        else:
            try:
                response = client.get(f"artifacts/{evidence_artifact_id}")
            except AssessError as exc:
                lookup_error = f"linked evidence artifact unavailable: {exc}"
            else:
                if not isinstance(response, dict):
                    lookup_error = "linked evidence artifact returned an unexpected response"
                elif _nonempty(response.get("relative_path")) != relative_path:
                    lookup_error = (
                        f"evidence_artifact_id {evidence_artifact_id} points to "
                        f"{_nonempty(response.get('relative_path'))!r}, not {relative_path!r}"
                    )
                else:
                    artifact = response
    elif relative_path:
        page_size = 1000
        offset = 0
        seen_pages: set[tuple[tuple[object, object], ...]] = set()
        while True:
            try:
                query = urlencode(
                    {
                        "q": relative_path,
                        "finding": _nonempty(finding.get("slug")),
                        "limit": page_size,
                        "offset": offset,
                    }
                )
                response = client.get(f"artifacts/search?{query}")
            except AssessError as exc:
                lookup_error = f"artifact index unavailable: {exc}"
                break
            if not isinstance(response, list):
                lookup_error = "artifact index returned an unexpected response"
                break
            page = [item for item in response if isinstance(item, dict)]
            artifact = next(
                (
                    row
                    for row in page
                    if _nonempty(row.get("relative_path")) == relative_path
                ),
                None,
            )
            if artifact is not None or len(response) < page_size:
                break
            fingerprint = tuple(
                (row.get("id"), row.get("relative_path")) for row in page
            )
            if fingerprint in seen_pages:
                lookup_error = "artifact index pagination did not advance"
                break
            seen_pages.add(fingerprint)
            offset += len(response)

    indexed = artifact is not None
    indexed_present = bool(artifact and artifact.get("present"))
    live_present = bool(
        relative_path
        and (Path(engagement_dir).expanduser().resolve() / relative_path).is_file()
    )
    related_slug = _nonempty(artifact.get("related_finding_slug")) if artifact else ""
    linked = bool(
        artifact
        and (
            str(artifact.get("id")) == str(evidence_artifact_id)
            if evidence_artifact_id is not None
            else related_slug == _nonempty(finding.get("slug"))
        )
    )
    if not reason and lookup_error:
        reason = lookup_error
    elif not reason and not indexed:
        reason = f"evidence artifact {relative_path!r} is not indexed"
    elif not reason and not linked:
        reason = f"evidence artifact {relative_path!r} is not linked to this finding"
    elif not reason and not indexed_present:
        reason = f"evidence artifact {relative_path!r} is indexed as missing"
    elif not reason and not live_present:
        reason = f"evidence artifact {relative_path!r} is no longer present on disk"
    return {
        "raw_ref": raw_ref,
        "path": relative_path,
        "indexed": indexed,
        "linked": linked,
        "index_present": indexed_present,
        "live_present": live_present,
        "present": bool(indexed_present and live_present),
        "has_durable_proof": bool(
            relative_path and indexed and linked and indexed_present and live_present
        ),
        "reason": reason,
    }


def _target_readiness_blockers(client, slug: str) -> tuple[list[dict], str]:
    try:
        readiness = client.get("report-readiness")
    except AssessError as exc:
        return [], f"report-readiness unavailable: {exc}"
    if not isinstance(readiness, dict):
        return [], "report-readiness returned an unexpected response"
    blockers = readiness.get("blockers", [])
    if not isinstance(blockers, list):
        return [], "report-readiness blockers have an unexpected shape"
    target: list[dict] = []
    for blocker in blockers:
        if not isinstance(blocker, dict):
            continue
        slugs = blocker.get("slugs", [])
        matches_many = isinstance(slugs, list) and slug in {str(item) for item in slugs}
        if str(blocker.get("slug") or blocker.get("finding_slug") or "") == slug or matches_many:
            target.append(blocker)
    return target, ""


def _evaluate(
    finding: dict,
    platform: str,
    vrt_category: str,
    weakness: str,
    durable_evidence: dict,
) -> dict:
    """Resolve the submission's proof-critical fields and the strict-gate misses.

    ``missing`` is the ordered list of proof-critical fields absent for this
    ``platform``; it drives both the final-mode gate (any entry => refuse) and
    the ``[NEEDS: ...]`` draft markers.
    """
    title = _nonempty(finding.get("title"))
    severity = _nonempty(finding.get("severity"))
    summary = _nonempty(finding.get("summary"))
    steps = string_list(detail_value(finding, "steps_to_reproduce", []))
    evidence = _nonempty(detail_value(finding, "evidence", ""))
    remediation = _nonempty(finding.get("remediation")) or _nonempty(
        detail_value(finding, "remediation", "")
    )
    cvss_vector = _nonempty(detail_value(finding, "cvss_vector", ""))
    cvss_score = finding.get("cvss_score")
    if cvss_score is None:
        cvss_score = detail_value(finding, "cvss_score", None)
    # Summary and Impact are independently authored outward-facing sections.
    # Reusing Summary here can make a final package appear complete while
    # duplicating the same prose under both headings.
    impact = _nonempty(detail_value(finding, "impact", ""))

    poc_pair = _poc_pair_present(finding)
    poc_code = _nonempty(detail_value(finding, "poc_code", ""))
    raw_evidence_ref = _nonempty(detail_value(finding, "evidence_ref", ""))
    evidence_ref = durable_evidence["path"] or raw_evidence_ref
    has_content_proof = poc_pair or bool(poc_code)

    vrt = _nonempty(vrt_category) or _nonempty(detail_value(finding, "vrt_category", ""))
    weak = (
        _nonempty(weakness)
        or _nonempty(detail_value(finding, "weakness", ""))
        or _nonempty(detail_value(finding, "cwe_id", ""))
    )

    missing: list[str] = []
    if not title:
        missing.append("title")
    if not severity:
        missing.append("severity")
    if not summary:
        missing.append("summary")
    if not steps:
        missing.append("steps to reproduce")
    if not evidence:
        missing.append("evidence")
    if not remediation:
        missing.append("remediation")
    if not cvss_vector:
        missing.append("CVSS vector")
    if platform == "bugcrowd" and not vrt:
        missing.append("VRT category")
    elif platform == "hackerone" and not weak:
        missing.append("weakness")
    if not impact:
        missing.append("attacker-impact statement")
    if not durable_evidence["has_durable_proof"]:
        missing.append("indexed, present evidence artifact")

    workflow_status = _nonempty(finding.get("workflow_status")).lower()
    verification_state = _nonempty(finding.get("verification_state")).lower()
    verification_disposition = _nonempty(finding.get("verification_disposition")).lower()
    if workflow_status not in _REPORTABLE_STATUSES:
        missing.append(f"workflow_status report candidate (got {workflow_status or 'unset'!r})")
    if verification_state != "verified":
        missing.append(f"verification_state=verified (got {verification_state or 'unset'!r})")
    if verification_disposition not in {"confirmed", "downgraded"}:
        missing.append(
            "verification_disposition=confirmed|downgraded "
            f"(got {verification_disposition or 'unset'!r})"
        )

    return {
        "title": title,
        "severity": severity,
        "summary": summary,
        "steps": steps,
        "evidence": evidence,
        "remediation": remediation,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "impact": impact,
        "vrt": vrt,
        "weakness": weak,
        "poc_pair": poc_pair,
        "poc_code": poc_code,
        "evidence_ref": evidence_ref,
        "has_content_proof": has_content_proof,
        "has_durable_proof": durable_evidence["has_durable_proof"],
        "durable_evidence": durable_evidence,
        "missing": missing,
    }


def _linked_command_runs(client, slug: str) -> list[dict]:
    """Linked command runs for ``slug`` from EXPLICIT finding-links only.

    Sources command runs strictly from ``finding-links`` rows whose
    ``target_kind == "command_run"`` for this finding, then fetches each linked
    run for its command string. There is deliberately NO fuzzy
    ``command-runs?q=`` search here: the report-writer agent
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
        print(f"WARN export submission: could not load finding-links: {exc}", file=sys.stderr)
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
            print(f"WARN export submission: command-run {run_id} unavailable: {exc}", file=sys.stderr)
            continue
        if isinstance(row, dict) and _nonempty(row.get("command")):
            runs.append(row)
    return runs


def _section(title: str, body: list[str]) -> list[str]:
    """A stable ``### `` body section (copy-paste block)."""
    return [f"### {title}", "", *body, ""]


def _evidence_body(evidence_text: str, draft: bool) -> list[str]:
    """The Evidence section renders ONLY the finding's authored ``details.evidence``.

    The structured proof (``poc_*`` / ``evidence_ref``) and the linked command runs
    are deliberately NOT here — they live in the single OPERATOR DETAILS reference
    section below the second divider, which the report-writer masks and weaves into
    this authored prose. Draft mode marks an absent evidence body with
    ``[NEEDS: evidence]``; final mode leaves it empty, because ``details.evidence``
    is authored prose; the final export gate requires it, while the separate
    durable-proof gate requires a current indexed artifact.
    """
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
            "[NEEDS: proof content — a reproducing request/response or PoC code]",
            "",
        ]
    if draft and not resolved["has_durable_proof"]:
        lines += [
            "[NEEDS: indexed, present evidence artifact inside this engagement]",
            "",
        ]

    if linked_runs:
        lines += [
            "**Linked command runs** (author Evidence from these; run "
            "`vigil assess command-run list` to find more):",
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


def _asset_location(finding: dict) -> str:
    """The finding's affected location, method-prefixed (deduping a baked-in verb).

    Mirrors ``_metadata_reference_lines`` so the A2 operational-header ``Asset``
    line renders the same location string the OPERATOR DETAILS ``Location`` line
    does, and never produces "POST POST https://…" when ``canonical_location``
    already carries the verb.
    """
    location = _nonempty(finding.get("canonical_location"))
    if not location:
        return ""
    method = _nonempty(details_object(finding).get("request_method"))
    if method and not location.upper().startswith(method.upper()):
        location = f"{method} {location}"
    return location


def _poc_ref(finding: dict) -> str:
    """A pointer to the finding's PoC for the A2 ``POC`` line.

    Prefers a staged evidence file (``evidence_ref``); falls back to the captured
    request line, then a marker that inline ``poc_code`` exists. Returns "" when
    the finding carries no proof pointer at all (the line is then omitted).
    """
    ref = _nonempty(detail_value(finding, "evidence_ref", ""))
    if ref:
        return ref
    poc_request = detail_value(finding, "poc_request")
    if isinstance(poc_request, dict) and poc_request:
        request_line = f"{poc_request.get('method', '')} {poc_request.get('url', '')}".strip()
        if request_line:
            return request_line
    if _nonempty(detail_value(finding, "poc_code", "")):
        return "inline PoC code (see Evidence / OPERATOR DETAILS)"
    return ""


def _operational_header_lines(finding: dict, required_headers: dict[str, str]) -> list[str]:
    """The A2 operational overlay — Asset / POC / Run / Pass if / Deconfliction.

    Emitted in the copy-paste header block FROM finding fields so a re-render or
    ``--overwrite`` reconstructs the operator's operational overlay instead of
    wiping it. Every line is omitted when its backing field is empty, so a finding
    with none of these produces nothing (the prior header shape is unchanged).

    Sources: Asset ← ``canonical_location`` (method-prefixed); POC ← the proof
    pointer (``evidence_ref`` / request line / inline poc_code); Run ←
    ``details.run``; Pass if ← ``details.pass_if``; Deconfliction ← the
    engagement's program-attribution ``required_headers`` (scope.json), so the
    triager/blue-team can attribute the traffic.
    """
    lines: list[str] = []
    asset = _asset_location(finding)
    if asset:
        lines.append(f"**Asset:** {asset}")
    poc = _poc_ref(finding)
    if poc:
        lines.append(f"**POC:** {poc}")
    run = _nonempty(detail_value(finding, "run", ""))
    if run:
        lines.append(f"**Run:** {run}")
    pass_if = _nonempty(detail_value(finding, "pass_if", ""))
    if pass_if:
        lines.append(f"**Pass if:** {pass_if}")
    deconfliction = "; ".join(
        f"{name}: {value}" for name, value in required_headers.items()
    )
    if deconfliction:
        lines.append(f"**Deconfliction:** {deconfliction}")
    if lines:
        lines.append("")
    return lines


def _render_markdown(
    finding: dict,
    resolved: dict,
    platform: str,
    linked_runs: list[dict],
    draft: bool,
    hygiene_warnings: list[str],
    required_headers: dict[str, str],
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

    # --- A2 operational overlay (rendered FROM finding fields) --------------
    # Placed in the copy-paste header, above the first ``---``, so it survives
    # ``--overwrite``. Omitted entirely when the finding carries none of its
    # backing fields.
    lines += _operational_header_lines(finding, required_headers)

    lines += ["---", ""]

    # --- stable body sections (### headers) ---------------------------------
    lines += _section("Summary", [resolved["summary"] or "[NEEDS: summary]"])

    step_body = [
        f"{i}. {strip_step_enumerator(step)}"
        for i, step in enumerate(resolved["steps"], 1)
    ] or ["[NEEDS: steps to reproduce]"]
    lines += _section("Steps to Reproduce", step_body)

    lines += _section("Evidence", _evidence_body(resolved["evidence"], draft))

    attack_scenario = _nonempty(detail_value(finding, "attack_scenario", ""))
    if attack_scenario:
        lines += _section("Attack Scenario", [attack_scenario])

    lines += _section("Impact", [_needs(resolved["impact"], "attacker-impact statement")])

    lines += _section("Remediation", [resolved["remediation"] or "[NEEDS: remediation]"])

    # --- single OPERATOR DETAILS reference section below the second divider --
    # (never pasted; the report-writer authors the body sections FROM it).
    lines += _operator_details_block(finding, resolved, linked_runs, hygiene_warnings, draft)

    text = "\n".join(lines).rstrip()
    return text + "\n"


def _build_context(
    slug: str,
    platform: str,
    draft: bool,
    resolved: dict,
    linked_runs: list[dict],
    submission_rel: str,
    hygiene_warnings: list[str],
    readiness_blockers: list[dict],
    readiness_error: str,
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
            "has_content_proof": resolved["has_content_proof"],
            "evidence_ref": resolved["evidence_ref"],
            "evidence_path": resolved["durable_evidence"]["path"],
            "evidence_indexed": resolved["durable_evidence"]["indexed"],
            "evidence_linked": resolved["durable_evidence"]["linked"],
            "evidence_index_present": resolved["durable_evidence"]["index_present"],
            "evidence_live_present": resolved["durable_evidence"]["live_present"],
            "evidence_present": resolved["durable_evidence"]["present"],
            "has_durable_proof": resolved["has_durable_proof"],
            "durable_evidence_diagnostic": resolved["durable_evidence"]["reason"],
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
        "hygiene_warnings": hygiene_warnings,
        "readiness_blockers": readiness_blockers,
        "readiness_error": readiness_error,
    }


def _restore_output(path: Path, previous: bytes | None) -> None:
    """Undo a final-mode file write after artifact registration fails."""
    if previous is None:
        path.unlink(missing_ok=True)
    else:
        path.write_bytes(previous)


def _restore_outputs(
    outputs: tuple[tuple[Path, bytes | None], ...],
) -> list[str]:
    errors: list[str] = []
    for path, previous in outputs:
        try:
            _restore_output(path, previous)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    return errors


def _rollback_message(errors: list[str]) -> str:
    if errors:
        return f"output rollback failed: {'; '.join(errors)}"
    return "output files were restored"


def run(args) -> None:
    slug = args.slug
    platform = args.platform
    draft = bool(args.draft)

    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir
    # A2 Deconfliction source: the engagement's program-attribution headers from
    # scope.json. Read defensively (``rate_caps_for_dir`` degrades a missing
    # scope.json to ``{}`` without raising), so a submission renders whether or not
    # the engagement configured attribution headers.
    _, required_headers = rate_caps_for_dir(engagement_dir)

    if args.output_dir:
        out_dir = Path(args.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path(engagement_dir) / out_dir
    else:
        out_dir = Path(engagement_dir) / "submissions" / slug
    submission_md = out_dir / "submission.md"
    context_json = out_dir / "submission-context.json"
    submission_rel = _engagement_relative(submission_md.resolve(strict=False), engagement_dir)
    if not draft and submission_rel is None:
        raise AssessError(
            "export submission: final output must be inside the engagement directory "
            "so it can be registered as a durable artifact"
        )

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        finding = client.get(f"findings/{slug}")
        if not isinstance(finding, dict):
            raise AssessError(f"export submission: unexpected response fetching finding {slug!r}")

        linked_runs = _linked_command_runs(client, slug)
        internal_ids = _internal_ids(finding, linked_runs)
        durable_evidence = _durable_evidence(
            client,
            finding,
            engagement_dir,
            cfg.engagement_key,
        )
        readiness_blockers, readiness_error = _target_readiness_blockers(client, slug)
        resolved = _evaluate(
            finding,
            platform,
            args.vrt_category,
            args.weakness,
            durable_evidence,
        )
        render_finding = redact_outbound_credentials(dict(finding))
        resolved = redact_outbound_credentials(resolved)
        linked_runs = redact_outbound_credentials(linked_runs)
        render_finding["evidence_ref"] = resolved["evidence_ref"]

        # Final mode refuses to write an incomplete submission.
        # Raised BEFORE any file write or artifact POST — a gated finding leaves
        # no partial artifacts behind.
        if not draft and (resolved["missing"] or readiness_blockers or readiness_error):
            blockers = [
                f"{item.get('kind', 'readiness')}: {item.get('detail', '')}".rstrip(": ")
                for item in readiness_blockers
            ]
            diagnostics = [*resolved["missing"], *blockers]
            if readiness_error:
                diagnostics.append(readiness_error)
            raise AssessError(
                f"export submission: cannot render a FINAL {platform} submission for "
                f"{slug!r} — missing proof-critical fields or readiness requirements: "
                f"{'; '.join(diagnostics)}. "
                "Complete the finding or re-run with --draft to write a work-in-progress "
                "with [NEEDS: ...] markers."
            )

        # FAITHFUL render — no content rewriting. Internal identifiers are flagged
        # (not stripped) so the report-writer removes them deliberately. Render
        # once WITHOUT the hygiene-warnings sub-block to scan the real content, then
        # re-render with the resulting warnings woven into OPERATOR DETAILS — the
        # warning strings themselves quote the leaked value (a UUID, a `cases.db`
        # literal), so scanning a render that already contains them would flag the
        # advisory text as if it were a fresh leak.
        scan_markdown = redact_outbound_credentials(
            _render_markdown(
                render_finding,
                resolved,
                platform,
                linked_runs,
                draft,
                [],
                required_headers,
            )
        )
        hygiene_warnings = _hygiene_warnings(
            scan_markdown, slug, internal_ids, engagement_dir, resolved["title"]
        )
        if not draft and hygiene_warnings:
            raise AssessError(
                f"export submission: cannot render a FINAL {platform} submission for {slug!r} "
                f"while hygiene warnings remain: {'; '.join(hygiene_warnings)}. "
                "Fix the finding content or use --draft for a diagnostic render."
            )

        # Check only after all final-mode gates so a blocked render never leaves
        # a partial output or obscures its actionable diagnostics.
        if submission_md.exists() and not args.overwrite:
            raise AssessError(
                f"export submission: {submission_rel or submission_md} "
                "already exists; pass --overwrite to replace it."
            )

        markdown = redact_outbound_credentials(
            _render_markdown(
                render_finding,
                resolved,
                platform,
                linked_runs,
                draft,
                hygiene_warnings,
                required_headers,
            )
        )
        context = redact_outbound_credentials(
            _build_context(
                slug,
                platform,
                draft,
                resolved,
                linked_runs,
                submission_rel or str(submission_md),
                hygiene_warnings,
                readiness_blockers,
                readiness_error,
            )
        )
        context_text = json.dumps(context, indent=2, ensure_ascii=False)

        previous_submission = submission_md.read_bytes() if submission_md.exists() else None
        previous_context = context_json.read_bytes() if context_json.exists() else None
        prior_outputs = (
            (submission_md, previous_submission),
            (context_json, previous_context),
        )
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
            submission_md.write_text(markdown, encoding="utf-8")
            context_json.write_text(context_text + "\n", encoding="utf-8")
        except OSError as exc:
            if not draft:
                rollback_errors = _restore_outputs(prior_outputs)
                raise AssessError(
                    "export submission: final output write failed; "
                    f"{_rollback_message(rollback_errors)}: {exc}"
                ) from exc
            raise

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
                if not draft:
                    rollback_errors = _restore_outputs(prior_outputs)
                    raise AssessError(
                        "export submission: final artifact registration failed; "
                        f"{_rollback_message(rollback_errors)}: {exc}"
                    ) from exc
                print(f"WARN export submission: artifact registration failed: {exc}", file=sys.stderr)
        else:
            print(
                "WARN export submission: output is outside the engagement dir; "
                "skipping artifact registration.",
                file=sys.stderr,
            )

    # Drafts surface unresolved hygiene/readiness work; finals have already
    # failed closed above and therefore reach this point clean.
    for warning in hygiene_warnings:
        print(f"WARN export submission: {warning}", file=sys.stderr)
    for blocker in readiness_blockers:
        print(
            "WARN export submission: target readiness blocker: "
            f"{blocker.get('kind', 'readiness')}: {blocker.get('detail', '')}",
            file=sys.stderr,
        )
    if readiness_error:
        print(f"WARN export submission: {readiness_error}", file=sys.stderr)

    display_path = submission_rel or str(submission_md)
    if args.as_json:
        summary = {
            "slug": slug,
            "platform": platform,
            "mode": "draft" if draft else "final",
            "path": display_path,
            "missing": resolved["missing"],
            "has_content_proof": resolved["has_content_proof"],
            "has_durable_proof": resolved["has_durable_proof"],
            "linked_command_runs": len(linked_runs),
            "artifact_registered": artifact_registered,
            "hygiene_warnings": hygiene_warnings,
            "readiness_blockers": readiness_blockers,
            "readiness_error": readiness_error,
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        mode = "draft" if draft else "final"
        print(f"Wrote {mode} {platform} submission for {slug} to {display_path}")
        if resolved["missing"]:
            print("  NEEDS: " + ", ".join(resolved["missing"]))
