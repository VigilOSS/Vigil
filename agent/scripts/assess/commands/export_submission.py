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
(``finding update``), so a re-render at publish time reproduces the authored
content exactly. Content typed only into ``submission.md`` is NOT durable — the
next render replaces the file. Credentials, tokens, PII, and other captured
evidence remain verbatim in the durable finding and the operator-visible render.

NOTHING IS REWRITTEN ON THE WAY OUT. This command assembles and presents; it
never edits authored text. A transformation pass cannot tell the operator's own
session cookie from a credential the target disclosed, and either may be needed
to reproduce the proof. Every later render therefore reproduces the exact values
stored in the finding.

The same rule governs everything else here. Steps render VERBATIM as list items —
no imposed ``N.`` counter, and nothing strips an enumerator the author wrote, so
``2024. Renewal year field accepts a past date`` survives as written. The bullet
is container formatting, like the code fences: it keeps each step on its own line
when the markdown is pasted into a platform form. What code MAY still do is FLAG
(``hygiene_warnings`` — leaks, and they fail a final export closed), ADVISE
(``advisories`` — prose opinions that never block), and REFUSE outright (the
final gate, which writes nothing). Adding a marker, an advisory, or a refusal
leaves the operator's words intact; rewriting them does not.

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
    ``poc_request`` / ``poc_response`` / ``evidence_ref``) to weave into
    Evidence; and the explicitly linked command runs to author Evidence from. The
    section is present in BOTH draft and final — it sits below the never-paste
    line, so keeping it in both avoids any draft/final structural divergence.

EVIDENCE IS AUTHORED, NOT SYNTHESIZED. The ``### Evidence`` section renders ONLY
the finding's authored ``details.evidence`` prose (``[NEEDS: evidence]`` in a draft
when absent; final export rejects the finding until it is authored). The raw
structured proof and the linked command runs are
deliberately NOT rendered into Evidence: a real submission carries hand-annotated
proof (including exact credentials, tokens, PII, and synthetic data),
so the tool surfaces them ONCE, as reference under the single
OPERATOR DETAILS section (mirrored by the ``linked_command_runs`` array in the
context JSON), for the report-writer to author Evidence FROM. Linked runs are
sourced ONLY from explicit, non-retired ``finding-links``
(``target_kind="command_run"``) — never a fuzzy command search.

THE REPRODUCTION IS TRANSCRIBED, NOT INFERRED. ``details.repro_runs`` names the
command runs that actually produced ``details.steps_to_reproduce``, in step order,
and this command fetches each row and renders its REAL argv under OPERATOR DETAILS.
That is the difference between a reproduction and a plausible narrative: a reader
can diff every claimed step against the audit row behind it. The runs are a
separate block from the linked-evidence runs above because they answer a different
question — "what proves the finding" versus "what reproduces it" — and a finding
routinely has one without the other. Nothing here GATES: authored steps with no
``repro_runs`` behind them, and declared ids that do not resolve, are both reported
as (non-blocking) ``advisories``. A run fetch can fail for reasons that say nothing
about the finding — a transient backend error resolves to the same signal as a
fabricated id — so refusing on it would let infrastructure block the publish of a
correct, verified finding. The unresolved ids are named in the render, on stderr,
and in the context JSON (``repro_runs_unresolved``); the report-writer decides.

THE REHEARSAL IS ADVISED ON HERE, not at the phase transition. The Phase-8
reproduction rehearsal — an agent that EXECUTES the steps from a cold start — is
the only check that can catch a step whose removal takes state a later step needs,
which is the defect a trim can introduce; this command reads its ``repro_rehearsal``
decision rows and advises when none is recorded, when the newest one did not follow,
or when it checked a run ``details.repro_runs`` no longer declares. Export is the
right place because the trim happens HERE, while the report-writer is reading, and
a rehearsal re-dispatched at engagement close is the same work at its most
expensive. It never blocks, and an unreachable backend degrades to a stderr WARN
with no advisory (see ``_repro_rehearsal_decisions``).

The generated ``submission.md`` is registered as a finding-linked artifact
(``kind="submission"``); final mode then asks the backend to stage, verify and
publish an immutable numbered version. ``--attachment-id`` selects registered,
hash-valid artifacts for a deterministic ZIP; the default is no attachments and
the numbered version is exactly the Markdown bytes. ``--recover`` reconciles
interrupted local exports without rendering a new workspace. The finding's
``submission_status`` is never written (omitting the field preserves it).

The generator is FAITHFUL: it preserves authored content while normalizing a
valid evidence pointer to engagement-relative form. A target-application UUID or
filename reaches the report-writer verbatim; blanket scrubbing would corrupt
proof. It FLAGS internal identifiers
— this finding's slug, engagement / finding / agent UUIDs, absolute engagement
paths, and cases.db references — in draft context/stderr, and final mode blocks
until the source content is clean.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import urlencode, urlparse

from assess.lib.client import (
    AssessError,
    AssessmentClient,
    require_artifact_write_response,
    require_write_result,
)
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
    prose_advisories,
    repro_rehearsal_advisories,
    step_lines,
    string_list,
    title_advisories,
)
from assess.lib.scope import rate_caps_for_dir

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
# The decision kind the Phase-8 reproduction rehearsal stamps
# (``agent/phases/phase-8-report.md``), read here to ADVISE — never to gate.
_REHEARSAL_DECISION_KIND = "repro_rehearsal"
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
    p.add_argument(
        "slug",
        nargs="?",
        help="Finding slug to render (e.g. VA-047); omit only with --recover.",
    )
    p.add_argument(
        "--platform",
        choices=_PLATFORMS,
        help=(
            "Submission target: bugcrowd (VRT) | hackerone (weakness) | "
            "direct (company-facing); required unless --recover is used."
        ),
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
        "--recover",
        action="store_true",
        help="Verify and reconcile interrupted immutable exports; render no new workspace.",
    )
    p.add_argument(
        "--attachment-id",
        dest="attachment_ids",
        action="append",
        type=int,
        default=[],
        help=(
            "Include one already-registered artifact in the immutable final ZIP. "
            "Repeat for multiple attachments; the default is none."
        ),
    )
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
    verification_status = _nonempty(finding.get("verification_status")).lower()
    if workflow_status not in _REPORTABLE_STATUSES:
        missing.append(f"workflow_status report candidate (got {workflow_status or 'unset'!r})")
    if verification_status not in {"confirmed", "downgraded"}:
        missing.append(
            "verification_status=confirmed|downgraded "
            f"(got {verification_status or 'unset'!r})"
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

    Sources command runs strictly from LIVE ``finding-links`` rows whose
    ``target_kind == "command_run"`` for this finding, then fetches each linked
    run for its command string. Rows carrying a ``retired_at`` are skipped — the
    listing deliberately returns retired history, and only the export path can
    tell "was linked once" from "is evidence now". There is deliberately NO fuzzy
    ``command-runs?q=`` search here: the report-writer agent
    runs the targeted ``command-run list`` search itself and links the exact
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
        if _nonempty(link.get("retired_at")):
            # RETIRED links are history, not evidence. ``finding-links`` returns
            # every row on purpose (the retired ones stay inspectable), so the
            # export path is where a link the operator explicitly invalidated has
            # to be dropped — otherwise a retired run comes back as current proof
            # in OPERATOR DETAILS and in every reply thread built from it, steering
            # the report writer at material that was deliberately withdrawn.
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
        if isinstance(row, dict):
            runs.append(row)
    return runs


def _repro_runs(client, finding: dict) -> tuple[list[dict], list[str]]:
    """The command runs the finding DECLARES as its reproduction, in step order.

    Sourced from ``details.repro_runs`` — an ordered array of command-run ids the
    recording agent wrote while running the reproduction. Kept separate from
    :func:`_linked_command_runs` (explicit ``finding-links``) because the two make
    different claims: a linked run is evidence the finding is real, a repro run is
    the audit row behind one authored step. A finding commonly has one and not the
    other, and collapsing them would let evidence links masquerade as a verified
    reproduction.

    Returns ``(rows, unresolved)``. ``unresolved`` names every declared entry that
    is malformed or fetches no run — a claim about what was executed that the audit
    log does not support. The caller ADVISES on it rather than refusing: this
    function cannot tell a fabricated id from a run row that is momentarily
    unreachable, and treating the second as the first would let a backend hiccup
    block the publish of a finished finding.

    BOTH lists stay in the author's declared order, deduped. Parsing and fetching
    happen in ONE pass for exactly that reason: splitting them would group every
    malformed entry ahead of every failed fetch, and a reader lining the unresolved
    ids up against the steps they belong to would be reading the wrong step.
    """
    declared = detail_value(finding, "repro_runs", [])
    if not isinstance(declared, list):
        # A non-list here is a schema violation that ``finding record`` /
        # ``finding update`` already reject; treat it as an unusable claim rather
        # than silently rendering nothing.
        return [], [f"{declared!r} (details.repro_runs must be an array of run ids)"]

    runs: list[dict] = []
    unresolved: list[str] = []
    seen: set[int] = set()
    for entry in declared:
        run_id: int | None = None
        if isinstance(entry, bool):
            run_id = None
        elif isinstance(entry, int):
            run_id = entry
        elif isinstance(entry, str) and entry.strip().isdigit():
            run_id = int(entry.strip())
        if run_id is None:
            unresolved.append(f"{entry!r} (not a command-run id)")
            continue
        if run_id in seen:
            continue
        seen.add(run_id)
        try:
            row = client.get(f"command-runs/{run_id}")
        except AssessError as exc:
            # Carry the backend's own reason rather than asserting "no such run":
            # a 404 and a transient failure are different problems, and naming the
            # wrong one sends the report-writer to edit a finding that is correct.
            unresolved.append(f"{run_id} (does not resolve: {exc})")
            continue
        if isinstance(row, dict):
            runs.append(row)
        else:
            unresolved.append(f"{run_id} (unexpected response shape)")
    return runs, unresolved


def _repro_rehearsal_decisions(client) -> tuple[list[dict], str]:
    """The engagement's ``kind='repro_rehearsal'`` decision rows, or a reason.

    ONE filtered read — the same shape ``transition_phase._blind_triage_blockers``
    uses for ``blind_triage_verdict``: the kind is filtered SERVER-side and the
    page size is the endpoint's maximum, so a long engagement cannot push an older
    rehearsal behind the default ``limit=100``. Per-slug filtering is left to
    :func:`repro_rehearsal_advisories` because the endpoint has no slug parameter
    (the finding slug lives inside the row's JSON payload).

    The cost is deliberately kept to one round trip because export runs REPEATEDLY
    — it is the report-writer's author -> write-back -> re-render loop, not a
    once-per-finding command — and it is skipped entirely for a finding with no
    authored steps (see the call site), where there is no reproduction to rehearse.

    FAILS SOFT, returning ``([], reason)``. An unreachable backend says nothing
    about whether the rehearsal happened, and the two outcomes it would otherwise
    collapse into one another — "no rehearsal on record" and "could not ask" — have
    opposite fixes. The caller reports the reason and emits NO advisory, so a
    backend hiccup can neither block an export nor assert something false about the
    finding.
    """
    try:
        rows = client.get(f"dispatch-decisions?kind={_REHEARSAL_DECISION_KIND}&limit=1000")
    except AssessError as exc:
        return [], f"repro-rehearsal decisions unavailable: {exc}"
    if not isinstance(rows, list):
        return [], "dispatch-decisions returned an unexpected response"
    return [row for row in rows if isinstance(row, dict)], ""


def _section(title: str, body: list[str]) -> list[str]:
    """A stable ``### `` body section (copy-paste block)."""
    return [f"### {title}", "", *body, ""]


def _evidence_body(evidence_text: str, draft: bool) -> list[str]:
    """The Evidence section renders ONLY the finding's authored ``details.evidence``.

    The structured proof (``poc_*`` / ``evidence_ref``) and the linked command runs
    are deliberately NOT here — they live in the single OPERATOR DETAILS reference
    section below the second divider, which the report-writer preserves and weaves into
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


def _method_prefixed_location(finding: dict) -> str:
    """``canonical_location``, prefixed with ``request_method`` when it is missing.

    ONE implementation shared by the OPERATOR DETAILS ``Location`` line and the A2
    operational-header ``Asset`` line, so the two can never disagree about the same
    finding.

    Some findings bake the verb into ``canonical_location`` ("POST https://…"), so
    prepending unconditionally would produce "POST POST https://…". The dedup
    compares the location's FIRST WHITESPACE-DELIMITED TOKEN to the method rather
    than testing ``startswith``: a location like "POSTMAN collection endpoint /x"
    starts with the string "POST" without starting with the verb, so a prefix test
    would drop the real method from the render.
    """
    location = _nonempty(finding.get("canonical_location"))
    if not location:
        return ""
    method = _nonempty(details_object(finding).get("request_method"))
    if not method:
        return location
    first_token = location.split(maxsplit=1)[0]
    if first_token.upper() == method.upper():
        return location
    return f"{method} {location}"


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
    location = _method_prefixed_location(finding)
    if location:
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
    for label, key in (("Verification status", "verification_status"),):
        value = _nonempty(finding.get(key))
        if value:
            ver.append(f"- {label}: {value}")
    discovered = _nonempty(d.get("discovered_by")) or _nonempty(finding.get("source_name"))
    if discovered:
        ver.append(f"- Discovered by: {discovered}")
    if ver:
        out += ["**Verification:**", "", *ver, ""]

    audit = finding.get("verification_audit")
    if isinstance(audit, dict):
        counter_checks = audit.get("counter_checks")
        severity_variances = audit.get("severity_variances")
        audit_lines: list[str] = []
        decision_receipt_ids = audit.get("proof_receipt_ids")
        if isinstance(decision_receipt_ids, list) and decision_receipt_ids:
            audit_lines.append(
                "- Decision proof receipts: "
                + ", ".join(
                    str(receipt_id) for receipt_id in decision_receipt_ids
                )
            )
        if isinstance(counter_checks, list):
            for record in counter_checks:
                if not isinstance(record, dict):
                    continue
                completed = "yes" if record.get("completed") is True else "no"
                audit_lines += [
                    (
                        f"- Counter-check #{record.get('id', '?')} "
                        f"(transition {record.get('transition_id', '?')}; "
                        f"verifier dispatch {record.get('verifier_dispatch_id', '?')}; "
                        f"completed: {completed})"
                    ),
                    f"  - Method: {_nonempty(record.get('method'))}",
                    f"  - Expected result: {_nonempty(record.get('expected_result'))}",
                    f"  - Observed result: {_nonempty(record.get('observed_result'))}",
                    f"  - Falsified claim: {_nonempty(record.get('falsified_claim'))}",
                ]
                receipt_ids = record.get("proof_receipt_ids")
                if isinstance(receipt_ids, list):
                    audit_lines.append(
                        "  - Proof receipts: "
                        + ", ".join(str(receipt_id) for receipt_id in receipt_ids)
                    )
        if isinstance(severity_variances, list):
            for record in severity_variances:
                if not isinstance(record, dict):
                    continue
                audit_lines += [
                    (
                        f"- Severity variance #{record.get('id', '?')} "
                        f"(transition {record.get('transition_id', '?')}; "
                        f"actor: {_nonempty(record.get('actor'))})"
                    ),
                    (
                        f"  - Band: {_nonempty(record.get('normal_band'))} → "
                        f"{_nonempty(record.get('chosen_severity'))}"
                    ),
                    f"  - Reason: {_nonempty(record.get('reason'))}",
                    f"  - Proof receipt: {record.get('proof_receipt_id', '?')}",
                ]
        if audit_lines:
            if audit.get("truncated") is True:
                audit_lines.append(
                    "- Audit summary truncated; use `vigil assess finding history "
                    "<slug> --paginate` for the complete transition-bound record."
                )
            out += [
                "**Structured verification audit** (internal decision evidence — never paste):",
                "",
                *audit_lines,
                "",
            ]

    corrections = d.get("correction_history")
    if isinstance(corrections, str):
        correction_lines = [corrections] if corrections.strip() else []
    elif isinstance(corrections, list):
        correction_lines = [
            item if isinstance(item, str) else json.dumps(item, ensure_ascii=False)
            for item in corrections
        ]
    else:
        correction_lines = []
    if correction_lines:
        out += [
            "**Correction history** (internal audit trail — never paste):",
            "",
            *(f"- {item}" for item in correction_lines),
            "",
        ]

    return out


def _notes_reference_lines(finding: dict) -> list[str]:
    """The finding's freeform ``notes`` (mechanism / reachability / caveats) as a
    reference block — the largest reference, so it sits last under OPERATOR DETAILS."""
    notes = _nonempty(finding.get("notes"))
    if not notes:
        return []
    return ["**Investigation notes** (working record — mine for detail, do not paste verbatim):", "", notes, ""]


def _command_run_lines(rows: list[dict], header_label: str) -> list[str]:
    """One ``- **<label>**`` bullet per run, with the row's real command fenced.

    Shared by the linked-evidence and reproduction blocks so the two render
    identically — the same audit row must not look like two different things
    depending on which claim cited it.
    """
    lines: list[str] = []
    for row in rows:
        command = _nonempty(row.get("command"))
        intent = _nonempty(row.get("intent"))
        rc = row.get("return_code")
        rc_str = "" if rc is None else f" (rc={rc})"
        header = f"- **{header_label}{rc_str}**" + (f" — {intent}" if intent else "") + ":"
        if not command:
            # The operator cited this run deliberately, so it is listed even with
            # no command string: dropping the row hides a citation they made,
            # while naming it as empty tells them the citation needs fixing.
            lines += [f"{header} (no command recorded on this run)", ""]
            continue
        fence = _fence_for(command)
        lines += [header, f"{fence}\n{command}\n{fence}", ""]
    return lines


def _operator_details_block(
    finding: dict,
    resolved: dict,
    linked_runs: list[dict],
    repro_runs: list[dict],
    repro_unresolved: list[str],
    hygiene_warnings: list[str],
    advisories: list[str],
    draft: bool,
) -> list[str]:
    """The single OPERATOR DETAILS reference section below the second ``---``.

    ONE section consolidates everything the operator never pastes and the
    report-writer authors the body FROM: the finding metadata to weave in, any
    internal-identifier hygiene warnings to strip, prose advisories to weigh, the
    structured proof (``poc_*`` / ``evidence_ref``) to preserve in Evidence, and the
    explicitly linked command runs to author Evidence from. It renders in BOTH
    draft and final (it sits below the never-paste line) so the structure never
    diverges between modes. The finding slug is deliberately never emitted here —
    it would otherwise self-trip the hygiene gate.

    Warnings and advisories are separate sub-blocks because they carry different
    authority: a hygiene warning is a fact that fails a final export closed, while
    an advisory is an opinion the report-writer may overrule.
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

    if advisories:
        lines += ["**Advisories** (non-blocking — your call):", ""]
        lines += [f"- {advisory}" for advisory in advisories]
        lines.append("")

    proof_lines = _poc_lines(finding)
    if resolved["evidence_ref"]:
        proof_lines += [f"- **Evidence reference:** {resolved['evidence_ref']}", ""]
    # Show what the operator actually wrote when the path was normalized, so the
    # authored value is not invisible in both output files.
    raw_ref = _nonempty(resolved["durable_evidence"].get("raw_ref"))
    if raw_ref and raw_ref != resolved["evidence_ref"]:
        proof_lines += [f"- **Evidence reference (as authored):** {raw_ref}", ""]
    lines += [
        "**Structured proof** (weave exact values into the Evidence section above):",
        "",
    ]
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
        lines += _command_run_lines(linked_runs, "Run")

    # The reproduction's own audit trail, in the author's declared step order. It
    # is the check on Steps to Reproduce: transcribe the argv below rather than
    # paraphrasing the step, and a step with no run under it was never executed.
    if repro_runs or repro_unresolved:
        lines += [
            "**Reproduction runs** (`details.repro_runs`, in step order — the argv "
            "that actually produced Steps to Reproduce; transcribe from these, do "
            "not paraphrase):",
            "",
        ]
        lines += _command_run_lines(repro_runs, "Step run")
        # Named here, where the missing argv would have been, rather than only in
        # the advisories block — the report-writer is reading this section to
        # transcribe a step, and needs to see that one of them has nothing under it.
        for entry in repro_unresolved:
            lines += [
                f"- **Unresolved** — `details.repro_runs` cites {entry}. No audit "
                "row stands behind the step attributed to it; correct the id at the "
                "finding rather than writing that step from the prose.",
                "",
            ]
    elif resolved["steps"] and draft:
        lines += [
            "[NEEDS: details.repro_runs — the command-run ids behind these steps "
            "(`vigil assess command-run list --q \"<url/param/payload>\"`), so the "
            "reproduction can be diffed against what was actually executed]",
            "",
        ]

    # Freeform investigation notes go last — the largest reference block.
    lines += _notes_reference_lines(finding)

    return lines


def _operational_header_lines(finding: dict, required_headers: dict[str, str]) -> list[str]:
    """The operational overlay — Asset / Run / Pass if / Deconfliction.

    Emitted in the copy-paste header block FROM finding fields so a re-render or
    ``--overwrite`` reconstructs the operator's operational overlay instead of
    wiping it. Every line is omitted when its backing field is empty, so a finding
    with none of these produces nothing.

    EVERY LINE HERE IS EITHER AUTHORED OR PROGRAM-REQUIRED. Above the paste
    boundary nothing may be composed by this command: whatever appears here gets
    sent to a triager, so a value the author did not write is one the report-writer
    has to notice and delete on every render. Asset ← ``canonical_location``
    verbatim (put the verb in that field when it matters); Run ← ``details.run``;
    Pass if ← ``details.pass_if``; Deconfliction ← the engagement's
    program-attribution ``required_headers`` (scope.json), which the
    triager/blue-team needs to attribute the traffic.

    There is deliberately no ``POC:`` line. A proof pointer synthesized from
    ``evidence_ref`` names an internal engagement artifact (``scans/…``) that means
    nothing to a triager and leaks the engagement's layout into the paste block.
    The pointer belongs under OPERATOR DETAILS, which already carries it, and the
    file the triager receives is the one the operator attaches in the platform form.
    """
    lines: list[str] = []
    asset = _nonempty(finding.get("canonical_location"))
    if asset:
        lines.append(f"**Asset:** {asset}")
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
    repro_runs: list[dict],
    repro_unresolved: list[str],
    draft: bool,
    hygiene_warnings: list[str],
    required_headers: dict[str, str],
    advisories: list[str],
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

    step_body = step_lines(resolved["steps"]) or ["[NEEDS: steps to reproduce]"]
    lines += _section("Steps to Reproduce", step_body)

    lines += _section("Evidence", _evidence_body(resolved["evidence"], draft))

    attack_scenario = _nonempty(detail_value(finding, "attack_scenario", ""))
    if attack_scenario:
        lines += _section("Attack Scenario", [attack_scenario])

    lines += _section("Impact", [_needs(resolved["impact"], "attacker-impact statement")])

    lines += _section("Remediation", [resolved["remediation"] or "[NEEDS: remediation]"])

    # --- single OPERATOR DETAILS reference section below the second divider --
    # (never pasted; the report-writer authors the body sections FROM it).
    lines += _operator_details_block(
        finding,
        resolved,
        linked_runs,
        repro_runs,
        repro_unresolved,
        hygiene_warnings,
        advisories,
        draft,
    )

    text = "\n".join(lines).rstrip()
    return text + "\n"


def _build_context(
    slug: str,
    platform: str,
    draft: bool,
    resolved: dict,
    linked_runs: list[dict],
    repro_runs: list[dict],
    repro_unresolved: list[str],
    submission_rel: str,
    hygiene_warnings: list[str],
    readiness_blockers: list[dict],
    readiness_error: str,
    advisories: list[str],
    verification_audit: dict[str, object],
    finding: dict[str, object],
    submission_sha256: str,
) -> dict:
    return {
        "slug": slug,
        "platform": platform,
        "mode": "draft" if draft else "final",
        "submission_path": submission_rel,
        "submission_sha256": submission_sha256,
        "source_finding": {
            "id": finding.get("id"),
            "row_version": finding.get("row_version"),
            "updated_at": finding.get("updated_at"),
            "workflow_status": finding.get("workflow_status"),
            "verification_status": finding.get("verification_status"),
        },
        "missing": resolved["missing"],
        "proof": {
            "poc_request_and_response": resolved["poc_pair"],
            "poc_code": bool(resolved["poc_code"]),
            "has_content_proof": resolved["has_content_proof"],
            "evidence_ref": resolved["evidence_ref"],
            # The authored value, before path normalization — so the JSON shows
            # what the operator wrote as well as what the render used.
            "evidence_ref_raw": resolved["durable_evidence"]["raw_ref"],
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
        # Each run row passes through WHOLE: this JSON exists to hand the LLM
        # everything the backend knows about the run it is writing Evidence from,
        # so any projection here would decide for it which fields are proof.
        "linked_command_runs": list(linked_runs),
        # The audit trail behind Steps to Reproduce, in the author's declared step
        # order, whole rows for the same reason as above. ``repro_runs_unresolved``
        # names declared ids that fetched nothing — a claimed step with no run
        # behind it. Reported, never gated on (see ``_repro_runs``).
        "repro_runs": list(repro_runs),
        "repro_runs_unresolved": list(repro_unresolved),
        "hygiene_warnings": hygiene_warnings,
        "advisories": advisories,
        "readiness_blockers": readiness_blockers,
        "readiness_error": readiness_error,
        "verification_audit": verification_audit,
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


_DEFINITE_ARTIFACT_REJECTION_PREFIXES = (
    "HTTP 400",
    "HTTP 401",
    "HTTP 403",
    "HTTP 404",
    "HTTP 405",
    "HTTP 409",
    "HTTP 413",
    "HTTP 422",
    "HTTP 429",
)


def _artifact_failure_is_definite(exc: AssessError) -> bool:
    """True only when the server explicitly refused the artifact before commit."""

    return str(exc).lstrip().startswith(_DEFINITE_ARTIFACT_REJECTION_PREFIXES)


def run(args) -> None:
    slug = args.slug
    platform = args.platform
    draft = bool(args.draft)
    attachment_ids = list(args.attachment_ids)
    if args.recover:
        incompatible = bool(
            slug
            or platform
            or draft
            or args.output_dir
            or args.overwrite
            or attachment_ids
            or args.vrt_category
            or args.weakness
        )
        if incompatible:
            raise AssessError(
                "export submission: --recover is a standalone mode; do not pass a "
                "slug, platform, render, or attachment option"
            )
        cfg = load_config(args.engagement_dir)
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            recovery = client.post(
                "submissions/recover", {"actor_surface": "vigil-assess"}
            )
            if not isinstance(recovery, dict):
                raise AssessError(
                    "recover submission exports: backend returned an invalid recovery "
                    "receipt; inspect the Submissions tab before retrying"
                )
            recovered_ids = list(recovery.get("recovered_version_ids", []))
            failed_versions = list(recovery.get("failed_versions", []))
            orphaned_paths = list(recovery.get("orphaned_staging_paths", []))
            page = recovery
            seen_cursors: set[tuple[int, str]] = set()
            fetched_pages = 1
            while True:
                failed_page = page.get("failed_versions_page")
                orphan_page = page.get("orphaned_staging_page")
                if failed_page is None and orphan_page is None:
                    break
                if not isinstance(failed_page, dict) or not isinstance(orphan_page, dict):
                    raise AssessError(
                        "recover submission exports: backend returned invalid recovery "
                        "page metadata; inspect the Submissions tab before retrying"
                    )
                failed_has_more = failed_page.get("has_more") is True
                orphan_has_more = orphan_page.get("has_more") is True
                if not failed_has_more and not orphan_has_more:
                    break
                failed_offset = (
                    failed_page.get("next_offset")
                    if failed_has_more
                    else int(failed_page.get("offset", 0))
                    + int(failed_page.get("returned", 0))
                )
                current_orphans = page.get("orphaned_staging_paths", [])
                orphan_after = (
                    orphan_page.get("next_after")
                    if orphan_has_more
                    else (current_orphans[-1] if current_orphans else "")
                )
                if not isinstance(failed_offset, int) or failed_offset < 0:
                    raise AssessError(
                        "recover submission exports: backend returned an invalid failed-version cursor"
                    )
                if not isinstance(orphan_after, str):
                    raise AssessError(
                        "recover submission exports: backend returned an invalid orphan cursor"
                    )
                cursor = (failed_offset, orphan_after)
                if cursor in seen_cursors:
                    raise AssessError(
                        "recover submission exports: backend recovery pagination made no progress"
                    )
                seen_cursors.add(cursor)
                page = client.post(
                    "submissions/recover",
                    {
                        "actor_surface": "vigil-assess",
                        "failed_version_offset": failed_offset,
                        "orphan_after": orphan_after,
                    },
                )
                if not isinstance(page, dict):
                    raise AssessError(
                        "recover submission exports: backend returned an invalid recovery "
                        "receipt; inspect the Submissions tab before retrying"
                    )
                recovered_ids.extend(page.get("recovered_version_ids", []))
                failed_versions.extend(page.get("failed_versions", []))
                orphaned_paths.extend(page.get("orphaned_staging_paths", []))
                fetched_pages += 1
            if fetched_pages > 1:
                failed_page = dict(recovery["failed_versions_page"])
                failed_page.update(
                    offset=0,
                    returned=len(failed_versions),
                    has_more=False,
                    next_offset=None,
                )
                orphan_page = dict(recovery["orphaned_staging_page"])
                orphan_page.update(
                    returned=len(dict.fromkeys(orphaned_paths)),
                    has_more=False,
                    next_after=None,
                )
                recovery = {
                    **recovery,
                    "recovered_version_ids": list(dict.fromkeys(recovered_ids)),
                    "failed_version_ids": [
                        item.get("id")
                        for item in failed_versions
                        if isinstance(item, dict)
                    ],
                    "failed_versions": failed_versions,
                    "failed_versions_page": failed_page,
                    "orphaned_staging_paths": list(dict.fromkeys(orphaned_paths)),
                    "orphaned_staging_page": orphan_page,
                    "diagnostic_pages_fetched": fetched_pages,
                }
        if not isinstance(recovery, dict) or any(
            not isinstance(recovery.get(key), list)
            for key in (
                "recovered_version_ids",
                "failed_version_ids",
                "failed_versions",
                "orphaned_staging_paths",
            )
        ):
            raise AssessError(
                "recover submission exports: backend returned an invalid recovery "
                "receipt; inspect the Submissions tab before retrying"
            )
        failed_versions = recovery["failed_versions"]
        if any(
            not isinstance(item, dict)
            or not isinstance(item.get("id"), int)
            or not isinstance(item.get("finding_slug"), str)
            or not isinstance(item.get("version_number"), int)
            or not isinstance(item.get("failure_reason"), str)
            or not isinstance(item.get("staging_relative_path"), str)
            or not isinstance(item.get("relative_path"), str)
            for item in failed_versions
        ) or sorted(recovery["failed_version_ids"]) != sorted(
            item["id"] for item in failed_versions
        ):
            raise AssessError(
                "recover submission exports: backend omitted actionable failure "
                "details; inspect the Submissions tab before retrying"
            )
        if args.as_json:
            print(json.dumps(recovery, indent=2, ensure_ascii=False))
        else:
            print(
                "Submission export recovery: "
                f"{len(recovery['recovered_version_ids'])} recovered, "
                f"{len(recovery['failed_version_ids'])} failed, "
                f"{len(recovery['orphaned_staging_paths'])} orphaned staging files"
            )
            for failure in failed_versions:
                print(
                    f"  FAILED {failure['finding_slug']} "
                    f"version {failure['version_number']} "
                    f"(id={failure['id']}): {failure['failure_reason']}"
                )
                print(f"    staging: {failure['staging_relative_path']}")
                print(f"    destination: {failure['relative_path']}")
            for orphaned_path in recovery["orphaned_staging_paths"]:
                print(f"  ORPHAN staging: {orphaned_path}")
        return
    if not slug or not platform:
        raise AssessError(
            "export submission: slug and --platform are required unless --recover is used"
        )
    if draft and attachment_ids:
        raise AssessError(
            "export submission: --attachment-id applies only to immutable final exports"
        )
    if any(artifact_id < 1 for artifact_id in attachment_ids):
        raise AssessError("export submission: --attachment-id values must be positive integers")
    if len(attachment_ids) != len(set(attachment_ids)):
        raise AssessError("export submission: --attachment-id values must be unique")

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
    context_rel = _engagement_relative(context_json.resolve(strict=False), engagement_dir)
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
        repro_runs, repro_unresolved = _repro_runs(client, finding)
        # Repro-run rows carry the same class of backend-assigned UUIDs as linked
        # runs, so they feed the same hygiene scan — a run id that leaked into the
        # pasteable body must be flagged regardless of which claim cited the run.
        internal_ids = _internal_ids(finding, [*linked_runs, *repro_runs])
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
        render_finding = dict(finding)
        render_finding["evidence_ref"] = resolved["evidence_ref"]

        # Final mode refuses to write an incomplete submission.
        # Raised BEFORE any file write or artifact POST — a gated finding leaves
        # no partial artifacts behind. Repro-run state is deliberately NOT part of
        # this gate: see ``_repro_runs`` — an unreachable run row and a fabricated
        # id are indistinguishable here, so both are advised on below.
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
        # literal), so scanning a render that already contains them would flag that
        # warning text as if it were a fresh leak.
        scan_markdown = _render_markdown(
            render_finding,
            resolved,
            platform,
            linked_runs,
            repro_runs,
            repro_unresolved,
            draft,
            [],
            required_headers,
            [],
        )
        hygiene_warnings = _hygiene_warnings(
            scan_markdown, slug, internal_ids, engagement_dir
        )
        # Prose advisories are surfaced, never gated on: only leaks fail closed.
        advisories = title_advisories(resolved["title"])
        # Length/shape advice about the body, measured on the SAME scan render the
        # hygiene gate reads (no warnings or advisories woven in yet, so nothing
        # measures the tool's own text) and confined to the pasteable body, so the
        # never-paste OPERATOR DETAILS proof is never counted as submission prose.
        advisories += prose_advisories(scan_markdown, steps=resolved["steps"])
        # Both repro-run conditions advise. Refusing on either would gate a publish
        # on something that is not a fact about the document: an absent repro_runs
        # is every finding recorded before the field existed, and an unresolved id
        # can be a backend hiccup as easily as an invented run.
        for entry in repro_unresolved:
            advisories.append(
                f"details.repro_runs cites {entry} — no audit row stands behind the "
                "step attributed to it. Confirm the id with `vigil assess command-run "
                "list` and correct it at the finding; do not write that step from the "
                "prose."
            )
        # Authored steps with nothing behind them: the steps may well be right, but
        # nobody can tell them apart from a reconstruction, and that ambiguity is
        # what burns a triage round. Suppressed when ids WERE declared and failed —
        # there the actionable message is "fix these ids", not "add some".
        if resolved["steps"] and not repro_runs and not repro_unresolved:
            advisories.append(
                "steps_to_reproduce is authored but details.repro_runs is empty — no "
                "command run stands behind these steps, so the reproduction cannot be "
                "diffed against what was actually executed. Find the runs with "
                '`vigil assess command-run list --q "<url/param/payload>"` and record '
                "their ids in step order."
            )
        # The rehearsal state behind those steps. Export is where this lands rather
        # than the phase transition because export is where the trim that invalidates
        # a rehearsal actually happens and where the report-writer is reading, so the
        # signal arrives while it is still cheap to act on — at engagement close,
        # re-dispatching a rehearsal is at its most expensive. It ADVISES for the
        # same reason the repro-run checks above do: a missing rehearsal is a fact
        # about process, not about the document, and refusing on it would let the
        # tool hold a finished, verified finding hostage to a decision row.
        if resolved["steps"]:
            rehearsal_decisions, rehearsal_error = _repro_rehearsal_decisions(client)
            if rehearsal_error:
                # Reported where the other reference-fetch failures go, and NOT as
                # an advisory: "could not ask" is not "no rehearsal on record".
                print(
                    f"WARN export submission: {rehearsal_error}; the repro-rehearsal "
                    "advisory is not evaluated for this render",
                    file=sys.stderr,
                )
            else:
                advisories += repro_rehearsal_advisories(
                    rehearsal_decisions,
                    slug,
                    repro_run_ids=detail_value(finding, "repro_runs", []),
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

        markdown = _render_markdown(
            render_finding,
            resolved,
            platform,
            linked_runs,
            repro_runs,
            repro_unresolved,
            draft,
            hygiene_warnings,
            required_headers,
            advisories,
        )
        submission_sha256 = hashlib.sha256(markdown.encode("utf-8")).hexdigest()
        context = _build_context(
            slug,
            platform,
            draft,
            resolved,
            linked_runs,
            repro_runs,
            repro_unresolved,
            submission_rel or str(submission_md),
            hygiene_warnings,
            readiness_blockers,
            readiness_error,
            advisories,
            (
                finding["verification_audit"]
                if isinstance(finding.get("verification_audit"), dict)
                else {}
            ),
            finding,
            submission_sha256,
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
        version: dict | None = None
        if submission_rel is not None:
            try:
                require_artifact_write_response(
                    client.post(
                        "artifacts",
                        {
                            "path": submission_rel,
                            "kind": "submission",
                            "media_type": "text/markdown",
                            "producer_agent_id": None,
                            "producer_agent_role": None,
                            "producer_command_run_id": None,
                            "related_finding_slug": slug,
                        },
                    ),
                    artifact_path=submission_rel,
                    operation="register submission artifact",
                )
                artifact_registered = True
            except AssessError as exc:
                if not draft:
                    if not _artifact_failure_is_definite(exc):
                        raise AssessError(
                            "export submission: final artifact registration failed with an "
                            "uncertain outcome; the rendered final files were preserved exactly "
                            f"at {submission_md} and {context_json} for reconciliation. Inspect "
                            "`vigil assess artifact search --json` and do not retry automatically: "
                            f"{exc}"
                        ) from exc
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

        if not draft:
            if not artifact_registered or context_rel is None:
                raise AssessError(
                    "export submission: final workspace was not durably registered; "
                    "no immutable version was created"
                )
            version = require_write_result(
                client.post(
                    f"submissions/{slug}/exports",
                    {
                        "platform": platform,
                        "submission_path": submission_rel,
                        "context_path": context_rel,
                        "attachment_ids": attachment_ids,
                        "actor_surface": "vigil-assess",
                    },
                ),
                operation="export immutable submission version",
                expected={"status": "complete"},
                positive_ids=("id", "version_number"),
            )
            if (
                not isinstance(version.get("relative_path"), str)
                or not str(version["relative_path"]).strip()
                or not isinstance(version.get("sha256"), str)
                or len(str(version["sha256"])) != 64
            ):
                raise AssessError(
                    "export immutable submission version: backend did not return "
                    "the package path and digest; the write may have committed, so "
                    "inspect the Submissions tab and do not retry automatically"
                )

    # Drafts surface unresolved hygiene/readiness work; finals have already
    # failed closed above and therefore reach this point clean.
    for warning in hygiene_warnings:
        print(f"WARN export submission: {warning}", file=sys.stderr)
    # ADVISORY, not WARN: a final export never fails on these, so the prefix
    # should not read like something that did.
    for advisory in advisories:
        print(f"ADVISORY export submission: {advisory}", file=sys.stderr)
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
            "repro_runs": len(repro_runs),
            "repro_runs_unresolved": repro_unresolved,
            "artifact_registered": artifact_registered,
            "hygiene_warnings": hygiene_warnings,
            "advisories": advisories,
            "readiness_blockers": readiness_blockers,
            "readiness_error": readiness_error,
            "version": version,
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        mode = "draft" if draft else "final"
        print(f"Wrote {mode} {platform} submission for {slug} to {display_path}")
        if version is not None:
            print(
                f"  Immutable version {version['version_number']}: "
                f"{version['relative_path']} ({version['sha256']})"
            )
        if resolved["missing"]:
            print("  NEEDS: " + ", ".join(resolved["missing"]))
