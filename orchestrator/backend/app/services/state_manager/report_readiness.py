from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ...finding_merge import strict_finding_id
from ..artifact_index import _normalize_relative_path
from ..events import _engagement_or_404
from ..engagement_tracks import has_track
from . import _common
from ._common import (
    FINDING_NOTES_MAX_LENGTH,
    ROOT_CAUSE_LINK_KIND,
    SEVERITY_RANK,
    _json_object,
    _serialize_finding_record,
)
from .coverage import coverage_readiness, web_uncovered_high_route_hosts
from .cvss import CvssVectorError, base_score
from .findings import (
    _claim_review_status,
    code_snapshot_attestation_status,
    finding_code_snapshot_status,
    is_file_finding,
    load_code_repo_snapshot_states,
)
from .finding_snapshots import (
    closest_snapshot_path,
    code_snapshot_binding,
    snapshot_location_problem,
)
from .links import _root_cause_link_metadata
from .proofs import (
    TERMINAL_VERIFICATION_STATUSES,
    operator_authority_stamp,
    proof_evidence_health_issues_for_finding,
    proof_receipts_for_findings,
)
from .repro_currentness import reproduction_basis_for_receipts

_MARKDOWN_PATH_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.-])"
    r"((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:md|markdown))"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

# The free-text ``details`` keys whose own schema descriptions TEACH the
# ``<path>:<line>`` convention — ``details.sink``'s description is literally
# ``"memcpy(buf, scheme, schemelen) at lib/urlapi.c:342"`` — so authors write
# citations here, and nothing read them. Every STRUCTURED citation a finding
# carries already resolves against the generation its binding seals; these did
# not, so a finding could cite a line that does not exist and survive until a
# verifier opened it.
_CITED_CODE_DETAIL_KEYS = (
    "entry_point",
    "sink",
    "taint_path",
    "guards_evaluated",
    "evidence",
    "remediation",
)

# A path-shaped token followed by a cited line (or line range). The lookbehind
# and lookahead keep the match off the inside of a longer token, so a URL
# authority (``https://host:8443/x``), a dotted version (``CVSS:3.1/AV:N``), a
# clock time (``12:30:05``) and an ISO timestamp never match; a cited line is
# REQUIRED, because a bare file name in prose is a reference, not a claim about
# where something lives.
_DETAIL_CODE_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.-])"
    r"(?P<path>[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
    r":(?P<line>[0-9]{1,7})(?:-(?P<end>[0-9]{1,7}))?"
    r"(?![A-Za-z0-9_/-])"
)
_PATH_EXTENSION_RE = re.compile(r"\.[A-Za-z][A-Za-z0-9_+]{0,8}$")


def _gated(item: dict[str, Any], severity: str) -> dict[str, Any]:
    """Stamp one readiness item with the gating class that produced it.

    The payload separates ``blockers`` from ``advisories``, but the ITEM — kind
    plus detail — is what gets copied into a handoff or grepped out of a log,
    and it arrives at its reader with the split long gone. Two near-homonyms
    make that costly: ``missing_cited_markdown_artifact`` never gates while
    ``finding_evidence_missing_artifact`` always does, and both describe a cited
    artifact that is absent. Stamping here, at the one point both buckets pass
    through, means a new append cannot forget it. ``block`` refuses the final
    report; ``advisory`` never does. Mirrors the ``severity`` key
    ``transition-phase`` already stamps on its own precondition items.
    """

    return {**item, "severity": severity}


def _is_path_shaped(path: str) -> bool:
    """A token that claims to name a file, not a word, a version or a time."""

    if ".." in path or path.endswith("/"):
        return False
    return "/" in path or bool(_PATH_EXTENSION_RE.search(path))


def _cited_code_locations(value: Any) -> Iterable[tuple[str, int, int | None]]:
    """Yield each ``<path>:<line>[-<end>]`` citation in one details value.

    ``taint_path`` is declared as a string OR an array of strings, so a list is
    walked element by element rather than skipped.
    """

    if isinstance(value, (list, tuple)):
        for item in value:
            yield from _cited_code_locations(item)
        return
    if not isinstance(value, str):
        return
    for match in _DETAIL_CODE_REFERENCE_RE.finditer(value):
        line = int(match.group("line"))
        if line < 1:
            continue
        path = match.group("path")
        if not _is_path_shaped(path):
            continue
        end = match.group("end")
        yield path, line, int(end) if end is not None else None


def _outside_snapshot_paths(
    connection, engagement_id: int, repo_id: int
) -> set[str]:
    """Paths this engagement already declared outside the repository's snapshot.

    A cross-file trigger target the snapshot genuinely cannot hold (a binary, a
    dependency outside the checkout, a file in another repository) is recorded
    with no file id. Prose naming such a target is not a defective citation.
    """

    return {
        str(row["target_file_path"])
        for row in connection.execute(
            """
            SELECT DISTINCT target_file_path
            FROM code_analysis_triggers
            WHERE engagement_id = ? AND repo_id = ? AND target_file_id IS NULL
              AND target_file_path != ''
            """,
            (engagement_id, repo_id),
        ).fetchall()
    }


def _details_citation_blockers(
    connection, engagement_id: int, candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Resolve each reportable finding's free-text code citations.

    Refusing the WRITE would be the wrong instrument: a remediation legitimately
    names a vendor file, a build output, or a libc call the sealed tree never
    held, and a hunter must be able to say so. So this is a report-time gate,
    and it fires only where the sealed generation can be shown to CONTRADICT the
    citation:

    * the cited path is a file in the generation and the cited line lies past
      its end — the citation names bytes that do not exist; or
    * the cited path is not in the generation while the generation holds a file
      of the same NAME under another directory — the wrong directory, not an
      external reference.

    Everything else stays silent: a path with no admitted namesake (vendor
    prose), a path already declared ``outside_snapshot``, a citation with no
    directory component (a file name alone omits the location rather than
    claiming a wrong one), and any finding with no sealed binding to resolve
    against. Symbol names are deliberately NOT refused: ``details.sink``'s own
    taught examples name ``memcpy`` and ``sqlite3_exec``, which the sealed tree
    does not define, so absence from the structural index is no defect.
    """

    blockers: list[dict[str, Any]] = []
    rosters: dict[tuple[int, int], bool] = {}
    outside_by_repo: dict[int, set[str]] = {}
    for row in candidates:
        binding = code_snapshot_binding(row)
        if binding is None:
            continue
        repo_id = binding["repo_id"]
        generation = binding["repo_generation"]
        roster_key = (repo_id, generation)
        if roster_key not in rosters:
            rosters[roster_key] = (
                connection.execute(
                    """
                    SELECT 1 FROM code_source_generation_files
                    WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
                    LIMIT 1
                    """,
                    (engagement_id, repo_id, generation),
                ).fetchone()
                is not None
            )
        if not rosters[roster_key]:
            # An empty roster cannot answer any citation; the unattested and
            # stale-snapshot blockers own that failure.
            continue
        if repo_id not in outside_by_repo:
            outside_by_repo[repo_id] = _outside_snapshot_paths(
                connection, engagement_id, repo_id
            )
        details = _json_object(row.get("details"))
        slug = str(row.get("slug", ""))
        seen: set[tuple[str, str, int, int | None]] = set()
        for key in _CITED_CODE_DETAIL_KEYS:
            for path, line, end_line in _cited_code_locations(details.get(key)):
                if (key, path, line, end_line) in seen:
                    continue
                seen.add((key, path, line, end_line))
                if path in outside_by_repo[repo_id]:
                    continue
                file_row, problem = snapshot_location_problem(
                    connection, engagement_id, repo_id, generation, path, line,
                    end_line=end_line,
                )
                if not problem:
                    continue
                closest = (
                    path
                    if file_row is not None
                    else closest_snapshot_path(
                        connection, engagement_id, repo_id, generation, path
                    )
                )
                if file_row is None and (
                    "/" not in path
                    or closest is None
                    or closest.rsplit("/", 1)[-1] != path.rsplit("/", 1)[-1]
                ):
                    continue
                blockers.append(
                    {
                        "kind": "finding_details_citation_unresolved",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail_key": key,
                        "path": path,
                        "line": line,
                        "closest_admitted_path": closest,
                        "detail": (
                            f"finding {slug} cites {path}:{line} in details.{key}, "
                            f"but {problem}. The sealed generation is what a "
                            "verifier opens, so correct the citation to the "
                            f"admitted location ({closest}) with "
                            f"`vigil assess finding update {slug} --details-inline "
                            f"'{{\"{key}\": \"...\"}}'`, or re-review the finding "
                            "against the current source if the code moved."
                        ),
                    }
                )
    return blockers


def _source_bound_evidence(record: dict[str, Any], snapshot_status: str) -> bool:
    """True when the finding's evidence IS the sealed source it cites.

    A source-derived code finding's ``canonical_location`` names a file and a
    line inside the generation its binding seals, and its proof receipts are
    source observations over those exact bytes — there is no separate engagement
    artifact to write, index, or repoint. The ``finding_repro_runs_missing``
    advisory already exempts this shape for the same reason, and ``finding
    record`` carries the matching warning-side exemption, so both ends read one
    predicate: ``file:`` form AND a binding that is current for the repository.
    A stale or unbound file finding does NOT qualify — it cites bytes nothing
    seals, so its citation is not evidence.
    """

    return (
        is_file_finding(str(record.get("canonical_location", "") or ""))
        and snapshot_status == "current"
    )


def _is_durable_markdown_path(path: str) -> bool:
    lower_path = path.lower()
    return lower_path.endswith((".md", ".markdown")) and (
        lower_path.startswith("notes/") or "/" not in lower_path
    )


def _cited_markdown_exists(engagement_root: Path, cited_path: str) -> bool:
    """Return true only for a real citation contained by the engagement."""
    root = engagement_root.resolve()
    candidate = (root / cited_path).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return candidate.is_file()



def _normalize_report_evidence_ref(root: Path, evidence_ref: str) -> str:
    mount = f"/engagements/{root.name}/"
    if evidence_ref.startswith(mount):
        evidence_ref = evidence_ref[len(mount):]
    try:
        return _normalize_relative_path(root, evidence_ref)
    except HTTPException:
        return evidence_ref


_REPORT_ARTIFACT_COLUMNS = (
    "id",
    "relative_path",
    "present",
    "scratch",
    "producer_agent_id",
    "producer_command_run_id",
    "related_finding_slug",
    "related_chain_key",
    "related_surface_id",
    "related_request_variant_id",
)


def _artifact_rows_by_id(
    connection,
    engagement_id: int,
    artifact_ids: Iterable[int],
    *,
    include_text: bool,
) -> dict[int, dict[str, Any]]:
    """Load the named artifacts of one engagement by id, in id order.

    ``indexed_text`` is the file's full extracted text; only the markdown
    citation scan reads it.
    """
    ids = sorted({int(artifact_id) for artifact_id in artifact_ids})
    if not ids:
        return {}
    columns = ", ".join(
        f"artifacts.{column}"
        for column in (*_REPORT_ARTIFACT_COLUMNS, *(("indexed_text",) if include_text else ()))
    )
    # CROSS JOIN pins the requested ids as the outer loop so each artifact is a
    # rowid seek; left to itself the planner prefers walking the engagement.
    rows = connection.execute(
        f"SELECT {columns} FROM json_each(?) AS wanted "
        "CROSS JOIN assessment_artifacts AS artifacts ON artifacts.id = wanted.value "
        "WHERE artifacts.engagement_id = ? "
        "ORDER BY artifacts.id",
        (json.dumps(ids), engagement_id),
    ).fetchall()
    return {int(row["id"]): dict(row) for row in rows}


def _report_candidate_records(
    engagement_id: int,
    *,
    current_receipts: dict[int, list[dict[str, Any]]] | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status NOT IN ('merged', 'false_positive')
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()
        receipts = proof_receipts_for_findings(
            connection, engagement.id, [int(row["id"]) for row in rows]
        )
        if current_receipts is not None:
            current_receipts.update(receipts)
        records = []
        for row in rows:
            record = _serialize_finding_record(row)
            record["claim_review_pending"] = _claim_review_status(
                connection, engagement.id, row,
            )["claim_review_pending"]
            record["reproduction_basis"] = reproduction_basis_for_receipts(
                str(record.get("canonical_location") or ""), receipts[int(row["id"])]
            )
            records.append(record)
    # A ``blocked`` verification status (blocked-for-provisioning, hunting.md)
    # is NOT a report candidate: the primitive was never reached, so it is neither
    # gradeable at impact-if-true nor report-durable — it "stays OUT of the report".
    # Excluding it here removes it from BOTH report projections
    # (``_report_finding_records`` draft AND final) and from every report_readiness
    # gate (this is the shared source), so a blocked finding never appears in the
    # report AND never blocks finalizing it. A later real proof supersedes the
    # block and explicitly re-admits the finding.
    return [
        record
        for record in records
        if record.get("verification_status") != "blocked"
    ]


def _finding_merge_integrity_blockers(engagement_id: int) -> list[dict[str, Any]]:
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, engagement_id, slug, status, merged_into_finding_id
            FROM assessment_findings
            WHERE engagement_id = ?
            ORDER BY id
            """,
            (engagement_id,),
        ).fetchall()
        by_id = {int(row["id"]): dict(row) for row in rows}
        referenced_ids = {
            target_id
            for row in rows
            if (target_id := strict_finding_id(row["merged_into_finding_id"]))
            is not None
            and target_id not in by_id
        }
        if referenced_ids:
            placeholders = ",".join("?" for _ in referenced_ids)
            referenced_rows = connection.execute(
                f"""
                SELECT id, engagement_id, '' AS slug, status, merged_into_finding_id
                FROM assessment_findings
                WHERE id IN ({placeholders})
                """,
                tuple(sorted(referenced_ids)),
            ).fetchall()
            by_id.update({int(row["id"]): dict(row) for row in referenced_rows})
    blockers: list[dict[str, Any]] = []

    for source in rows:
        source_id = int(source["id"])
        slug = str(source["slug"] or "")
        workflow_status = str(source["status"] or "")
        pointer = source["merged_into_finding_id"]
        if workflow_status == "merged" and pointer is None:
            blockers.append(
                {
                    "kind": "finding_merge_integrity",
                    "slug": slug,
                    "detail": f"merged finding {slug} has no merge target",
                }
            )
            continue
        if workflow_status != "merged" and pointer is not None:
            blockers.append(
                {
                    "kind": "finding_merge_integrity",
                    "slug": slug,
                    "detail": f"non-merged finding {slug} carries a merge target pointer",
                }
            )
            continue
        if pointer is None:
            continue

        seen = {source_id}
        path = [slug]
        target_id = strict_finding_id(pointer)
        if target_id is None:
            blockers.append(
                {
                    "kind": "finding_merge_integrity",
                    "slug": slug,
                    "detail": f"merge target pointer {pointer!r} is not a valid finding id",
                }
            )
            continue
        depth = 0
        detail = ""
        while True:
            target = by_id.get(target_id)
            if target is None:
                detail = f"merge target id {target_id} does not exist"
                break
            if int(target["engagement_id"]) != engagement_id:
                detail = "merge target belongs to another engagement"
                break
            target_slug = str(target["slug"] or target_id)
            path.append(target_slug)
            depth += 1
            if target_id == source_id and depth == 1:
                detail = f"finding {slug} is merged into itself"
                break
            if target_id in seen:
                detail = f"merge cycle detected: {' -> '.join(path)}"
                break
            seen.add(target_id)
            next_pointer = target["merged_into_finding_id"]
            target_status = str(target["status"] or "")
            if target_status != "merged":
                if next_pointer is not None:
                    detail = (
                        f"merge path enters non-merged finding {target_slug} "
                        "that carries a merge target pointer"
                    )
                elif depth > 1:
                    detail = f"merge depth {depth} exceeds one hop: {' -> '.join(path)}"
                break
            if next_pointer is None:
                detail = f"merge path ends at merged finding {target_slug} with no merge target"
                break
            target_id = strict_finding_id(next_pointer)
            if target_id is None:
                detail = (
                    f"merged finding {target_slug} has merge target pointer "
                    f"{next_pointer!r}, which is not a valid finding id"
                )
                break

        if detail:
            blockers.append(
                {
                    "kind": "finding_merge_integrity",
                    "slug": slug,
                    "detail": detail,
                }
            )
    return blockers

def report_readiness(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    root = Path(engagement.engagement_root)
    is_blue = has_track(root, "blue")
    is_web = has_track(root, "web")
    engagement_root = Path(engagement.engagement_root).expanduser().resolve()
    coverage = coverage_readiness(engagement_id)
    blockers: list[dict[str, Any]] = []
    advisories: list[dict[str, Any]] = []
    blockers.extend(_finding_merge_integrity_blockers(engagement_id))
    if not coverage["ready"]:
        blockers.append(
            {
                "kind": "coverage",
                "detail": "Coverage blockers remain",
                "blocker_count": coverage["blocker_count"],
            }
        )

    reportable_statuses = {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
    current_receipts: dict[int, list[dict[str, Any]]] = {}
    candidate_records = _report_candidate_records(
        engagement_id, current_receipts=current_receipts
    )
    # Runtime proof is durable debt regardless of whether the finding has been
    # promoted into a reportable workflow state.  The candidate projection
    # deliberately excludes drafts, so gate it before that projection rather
    # than allowing a draft URL finding to leave final readiness green.
    for row in candidate_records:
        if row.get("verification_status") == "pending_runtime_proof":
            blockers.append(
                {
                    "kind": "finding_verification_status",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": "verification_status=pending_runtime_proof",
                }
            )
    candidates = [
        row
        for row in candidate_records
        if row.get("workflow_status") in reportable_statuses
    ]

    # Classified once per candidate and read by three gates: the stale/unbound
    # blockers below, the draft disposition item, and the source-bound evidence
    # exemption, which is only paid for by a CURRENT binding.
    snapshot_statuses: dict[str, str] = {}
    with _common.get_connection() as connection:
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        for row in candidate_records:
            snapshot_status = finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            snapshot_statuses[str(row.get("slug", ""))] = snapshot_status
            if row.get("workflow_status") not in reportable_statuses:
                continue
            # Legacy rows predate attestation and remain readable. A new
            # attestation that names no audited source is a final-report defect.
            attestation_status = code_snapshot_attestation_status(row)
            if attestation_status in {"copied", "unattested"}:
                blockers.append(
                    {
                        "kind": "finding_code_snapshot_unattested",
                        "slug": row.get("slug", ""),
                        "title": row.get("title", ""),
                        "attestation_status": attestation_status,
                        "detail": (
                            "reportable code finding's provenance.code_snapshot is "
                            f"{attestation_status}: no audited dispatch or command run "
                            "stands behind it"
                            + (
                                ", and its attestation names a different finding"
                                if attestation_status == "copied"
                                else ""
                            )
                            + ". Re-verify it from the dispatch that reviewed the "
                            "source so the binding attests something."
                        ),
                    }
                )
            if snapshot_status not in {"stale", "unbound"}:
                continue
            blockers.append(
                {
                    "kind": "finding_code_snapshot",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "snapshot_status": snapshot_status,
                    "detail": (
                        "reportable finding is not bound to the current verified "
                        f"repository snapshot: {snapshot_status}; re-review it and "
                        "use finding verify with current provenance.code_snapshot"
                    ),
                }
            )
        blockers.extend(
            _details_citation_blockers(connection, engagement.id, candidates)
        )

    # Import lazily: code_analysis imports the finding snapshot helpers from this
    # package, so a module-level import would create a package initialization
    # cycle. The code-analysis service remains the owner of receipt currency and
    # candidate-file selection; report readiness only renders its obligations.
    from .. import code_analysis as code_analysis_service

    for obligation in code_analysis_service.unresolved_suspicious_analysis_obligations(
        engagement.id
    ):
        suspicious_count = int(obligation["suspicious_count"])
        blockers.append(
            {
                "kind": "unresolved_suspicious_analysis",
                "repo_id": int(obligation["repo_id"]),
                "suspicious_count": suspicious_count,
                "detail": (
                    f"repository has {suspicious_count} current suspicious "
                    "code-analysis attempt(s); promote each to a finding or "
                    "complete a clean terminal reanalysis"
                ),
            }
        )

    for obligation in code_analysis_service.report_durable_finding_variant_receipt_obligations(
        engagement.id
    ):
        finding_slugs = list(obligation["finding_slugs"])
        variant_parent_finding_slugs = list(
            obligation["variant_parent_finding_slugs"]
        )
        missing_file_ids = list(obligation["missing_file_ids"])
        missing_file_paths = list(obligation["missing_file_paths"])
        path_sample = ", ".join(missing_file_paths[:5])
        if len(missing_file_paths) > 5:
            path_sample += f", and {len(missing_file_paths) - 5} more"
        blockers.append(
            {
                "kind": "finding_variant_receipts_incomplete",
                "repo_id": int(obligation["repo_id"]),
                "slugs": finding_slugs,
                "variant_parent_finding_slugs": variant_parent_finding_slugs,
                "missing_file_count": len(missing_file_ids),
                "missing_file_ids": missing_file_ids,
                "missing_file_paths": missing_file_paths,
                # ``slugs`` names the report-durable findings that create the
                # debt; the freezable dispatch scope is the wider Phase 2 set.
                "detail": (
                    f"{len(finding_slugs)} report-durable current code finding(s) "
                    "have no complete current "
                    f"variant-scan receipt for {len(missing_file_ids)} "
                    f"admitted current repository file(s): {path_sample}. "
                    + code_analysis_service.variant_dispatch_scope_instruction(
                        int(obligation["repo_id"]), variant_parent_finding_slugs
                    )
                ),
            }
        )

    from .. import code_fuzz_completion

    for fuzz_state in code_fuzz_completion.fuzz_states(engagement.id):
        if not fuzz_state["applicability_ready"]:
            blockers.append(
                {
                    "kind": "fuzz_decision_missing",
                    "repo_id": int(fuzz_state["repo_id"]),
                    "detail": (
                        "repository has no evidence-backed current-source fuzz "
                        "applicability decision; record required targets or a "
                        "not-required rationale"
                    ),
                }
            )
            continue
        if fuzz_state["completion_ready"]:
            continue
        blockers.append(
            {
                "kind": "fuzz_campaign_incomplete",
                "repo_id": int(fuzz_state["repo_id"]),
                "pending_target_ids": list(fuzz_state["pending_target_ids"]),
                "pending_finding_slugs": list(
                    fuzz_state["pending_finding_slugs"]
                ),
                "detail": (
                    "required current-source fuzzing lacks covering terminal "
                    "campaign receipts for "
                    f"{len(fuzz_state['pending_target_ids'])} target(s) and "
                    f"{len(fuzz_state['pending_finding_slugs'])} confirmed "
                    "memory-safety finding(s)"
                ),
            }
        )

    for row in candidate_records:
        if row.get("workflow_status") != "draft":
            continue
        slug = str(row.get("slug", ""))
        snapshot_status = snapshot_statuses.get(slug, "not_applicable")
        destination = (
            blockers
            if is_file_finding(str(row.get("canonical_location", "") or ""))
            else advisories
        )
        destination.append(
            {
                "kind": "draft_finding_needs_disposition",
                "slug": slug,
                "title": row.get("title", ""),
                "snapshot_status": snapshot_status,
                "detail": (
                    f"finding {slug} is parked in workflow_status='draft' and will NOT appear in "
                    f"the report or export. Disposition it: promote to active with "
                    f"`vigil assess finding update {slug} --status active` so it reports, "
                    f"or verify it false positive with `vigil assess finding verify {slug} "
                    f"--status false_positive --reason \"...\" --proof-receipt-id <id> "
                    f"--counter-check-file <path>` after completing the structured "
                    f"independent counter-check."
                    + (
                        " The code finding is not bound to the current verified source; "
                        "re-review and rebind it before promotion."
                        if snapshot_status in {"stale", "unbound"}
                        else ""
                    )
                ),
            }
        )
    candidate_slugs = {str(row.get("slug", "")) for row in candidates if row.get("slug")}
    with _common.get_connection() as connection:
        root_link_rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
              AND links.retired_at IS NULL
            """,
            (engagement_id, ROOT_CAUSE_LINK_KIND),
        ).fetchall()
        severity_variance_rows = connection.execute(
            """
            SELECT variances.finding_id, variances.normal_band,
                   variances.chosen_severity, variances.actor,
                   variances.reason, variances.proof_receipt_id
            FROM assessment_finding_severity_variances AS variances
            JOIN assessment_findings AS findings
              ON findings.id = variances.finding_id
            WHERE variances.engagement_id = ?
              AND variances.transition_id = (
                  SELECT MAX(proof_links.transition_id)
                  FROM assessment_finding_proof_receipts AS proof_links
                  JOIN assessment_finding_transitions AS transitions
                    ON transitions.id = proof_links.transition_id
                  WHERE proof_links.engagement_id = variances.engagement_id
                    AND proof_links.finding_id = variances.finding_id
                    AND transitions.to_verification_status =
                        findings.verification_status
              )
            """,
            (engagement_id,),
        ).fetchall()
    root_link_by_slug = {
        str(row["finding_slug"]): str(row["target_ref"])
        for row in root_link_rows
        if str(row["finding_slug"]) in candidate_slugs
    }
    current_severity_variance_by_finding = {
        int(row["finding_id"]): dict(row) for row in severity_variance_rows
    }

    for row in candidates:
        if row.get("verification_status") == "pending_runtime_proof":
            continue
        if row.get("verification_status") not in {"confirmed", "downgraded"}:
            blockers.append(
                {
                    "kind": "finding_verification_status",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_status={row.get('verification_status', 'unknown')}",
                }
            )
        elif row.get("claim_review_pending"):
            blockers.append(
                {
                    "kind": "finding_claim_review_pending",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": "verified claim wording changed; record a current independent claim_equivalence review or re-verify the finding",
                }
            )

    # A terminal verdict reached on the operator's OWN out-of-snapshot evidence
    # cites no proof receipt, so every receipt-shaped check below passes it in
    # silence and the verdict reads exactly like a dispatch-verified one. ADR
    # 0019 lets the operator weaken a gate over their own engagement; what it
    # does not permit is doing so invisibly, so readiness names the finding and
    # the intel row the waiver rests on. ADVISORY, never a blocker: the waiver
    # is legitimate, and gating it would take back the authority ADR 0019
    # grants. Read across every non-merged finding, not just the reportable
    # candidates, because an operator-authority ``false_positive`` leaves the
    # report entirely and is the most consequential waiver of the three.
    with _common.get_connection() as connection:
        authority_rows = connection.execute(
            """
            SELECT slug, title, verification_status, provenance_json
            FROM assessment_findings
            WHERE engagement_id = ?
              AND verification_status IN ({placeholders})
              AND merged_into_finding_id IS NULL
            ORDER BY id ASC
            """.format(
                placeholders=", ".join("?" for _ in TERMINAL_VERIFICATION_STATUSES)
            ),
            (engagement_id, *sorted(TERMINAL_VERIFICATION_STATUSES)),
        ).fetchall()
    for row in authority_rows:
        stamp = operator_authority_stamp(row["provenance_json"])
        if stamp is None:
            continue
        slug = str(row["slug"] or "")
        verification_status = str(row["verification_status"] or "")
        intel_id = stamp.get("intel_id")
        raw_type = stamp.get("intel_type")
        intel_type = raw_type if isinstance(raw_type, str) and raw_type else None
        # `intel get` takes the type as a required positional, and the ten intel
        # tables allocate ids independently, so the type is half the citation.
        # The verification resolves it and the stamp carries it; a stamp that
        # names no table gets the type-independent listing rather than a guess,
        # because a command naming the wrong table opens an unrelated row and
        # presents it as the evidence behind a terminal verdict — the exact
        # misreading this item exists to prevent.
        citation = f"intel {intel_type} {intel_id}" if intel_type else f"intel {intel_id}"
        read_clause = (
            f"`vigil assess intel get {intel_type} {intel_id}`"
            if intel_type
            else (
                "`vigil assess intel list` — this stamp records no intel type, and "
                f"the intel tables number independently, so find id {intel_id} "
                "among the types it counts"
            )
        )
        advisories.append(
            {
                "kind": "finding_operator_authority_verdict",
                "slug": slug,
                "title": str(row["title"] or ""),
                "verification_status": verification_status,
                "intel_id": intel_id,
                "intel_type": intel_type,
                "authority_kind": stamp.get("kind"),
                "detail": (
                    f"finding {slug} is verification_status='{verification_status}' on "
                    f"the operator's own out-of-snapshot evidence ({citation}), "
                    "not on a dispatch-verified proof receipt. Advisory, not a report "
                    f"blocker: {stamp.get('reason') or 'no reason recorded'}. Read the "
                    f"evidence with {read_clause}, and "
                    "describe the verdict as operator-attested wherever the report "
                    "states how it was reached."
                ),
            }
        )

    with _common.get_connection() as connection:
        for row in candidates:
            if row.get("verification_status") not in {"confirmed", "downgraded"}:
                continue
            for issue in proof_evidence_health_issues_for_finding(
                connection, engagement.id, int(row["id"]),
                current_receipts=current_receipts[int(row["id"])],
            ):
                evidence_health = str(issue["evidence_health"])
                dependent_raw_id = issue.get("dependent_raw_receipt_id")
                blockers.append(
                    {
                        "kind": f"finding_proof_evidence_{evidence_health}",
                        "slug": row.get("slug", ""),
                        "title": row.get("title", ""),
                        **issue,
                        "detail": (
                            f"finding depends on proof receipt "
                            f"{issue['proof_receipt_id']} whose "
                            + (
                                f"raw receipt {dependent_raw_id} evidence"
                                if dependent_raw_id is not None
                                else "evidence"
                            )
                            + f" is {evidence_health}; capture fresh evidence and "
                            "record a new verification decision without rewriting "
                            "the historical receipt"
                        ),
                    }
                )

    for row in candidates:
        if row.get("verification_status") not in {"confirmed", "downgraded"}:
            continue
        slug = row.get("slug", "")
        title = row.get("title", "")
        details = _json_object(row.get("details"))
        missing_fields: list[str] = []
        if is_blue:
            mitre = details.get("mitre_techniques")
            if not isinstance(mitre, list) or not mitre:
                missing_fields.append("mitre_techniques")
        else:
            if details.get("cvss_score") is None:
                missing_fields.append("cvss_score")
            if not details.get("cvss_vector"):
                missing_fields.append("cvss_vector")
            if not details.get("steps_to_reproduce"):
                missing_fields.append("steps_to_reproduce")
            if not details.get("remediation"):
                missing_fields.append("remediation")
        if not details.get("impact"):
            missing_fields.append("impact")
        if not details.get("evidence"):
            missing_fields.append("evidence")
        if missing_fields:
            blockers.append(
                {
                    "kind": "finding_field_quality",
                    "slug": slug,
                    "title": title,
                    "detail": f"missing structured fields: {', '.join(missing_fields)}",
                }
            )
        # Reproduction steps with no audit row behind them. ADVISORY, not a
        # blocker: the empty-``steps_to_reproduce`` blocker above already stops a
        # finding that carries no reproduction at all, while this one says the
        # steps cannot be told apart from a reconstruction — real, but not worth
        # gating every finding recorded before ``repro_runs`` existed. It fires
        # only where there is something to back up, and never for a source-derived
        # code finding, whose steps are backed by its source proof receipts.
        if (
            not is_blue
            and details.get("steps_to_reproduce")
            and not details.get("repro_runs")
            and row.get("reproduction_basis") != "source"
        ):
            advisories.append(
                {
                    "kind": "finding_repro_runs_missing",
                    "slug": slug,
                    "title": title,
                    "detail": (
                        "advisory, not a report blocker: "
                        f"finding {slug} has authored steps_to_reproduce but no "
                        "details.repro_runs, so no command run stands behind the steps and "
                        "nobody can diff them against what was actually executed. Find the "
                        'runs with `vigil assess command-run list --q "<url/param/payload>"` '
                        f"and record their ids in step order: `vigil assess finding update {slug} "
                        "--details-inline '{\"repro_runs\": [<run_id>, ...]}'`."
                    ),
                }
            )
        cvss_score = details.get("cvss_score")
        cvss_vector = details.get("cvss_vector")
        severity = str(row.get("severity", "")).lower()
        if not is_blue and cvss_vector:
            try:
                computed_score = base_score(str(cvss_vector))
            except CvssVectorError as exc:
                blockers.append(
                    {
                        "kind": "cvss_vector_invalid",
                        "slug": slug,
                        "title": title,
                        "detail": f"cvss_vector is invalid: {exc}",
                    }
                )
            else:
                try:
                    stored_score = float(cvss_score)
                except (TypeError, ValueError):
                    stored_score = None
                if (
                    stored_score is not None
                    and abs(stored_score - computed_score) >= 0.05
                ):
                    blockers.append(
                        {
                            "kind": "cvss_vector_score_mismatch",
                            "slug": slug,
                            "title": title,
                            "detail": (
                                f"cvss_score={stored_score} but cvss_vector "
                                f"computes to {computed_score}"
                            ),
                        }
                    )
        if not is_blue and cvss_score is not None and severity:
            try:
                score = float(cvss_score)
            except (TypeError, ValueError):
                score = -1
            expected = (
                "critical" if score >= 9.0
                else "high" if score >= 7.0
                else "medium" if score >= 4.0
                else "low" if score >= 0.1
                else "info"
            )
            if score >= 0 and severity != expected:
                # The band and CVSS score are independent scales, but old prose
                # cannot stand in for an approval. Only the attributed variance
                # attached to the current verification transition settles this
                # disagreement; arithmetic errors above remain blockers.
                variance = current_severity_variance_by_finding.get(int(row["id"]))
                approved = bool(
                    variance
                    and str(variance["normal_band"]) == expected
                    and str(variance["chosen_severity"]) == severity
                )
                authority = (
                    operator_authority_stamp(row.get("provenance"))
                    if str(row.get("verification_status")) in TERMINAL_VERIFICATION_STATUSES
                    else None
                )
                detail = (
                    f"severity={severity} but cvss_score={score} expects {expected}"
                )
                if approved or authority:
                    attribution = (
                        f"operator authority: {authority.get('reason') or 'no reason recorded'}"
                        if authority
                        else f"structured variance approved by {variance['actor']}: {variance['reason']}"
                    )
                    advisories.append(
                        {
                            "kind": "severity_cvss_band_divergence",
                            "slug": slug,
                            "title": title,
                            "detail": (
                                f"{detail}; {attribution}"
                            ),
                        }
                    )
                else:
                    blockers.append(
                        {
                            "kind": "severity_cvss_mismatch",
                            "slug": slug,
                            "title": title,
                            "detail": (
                                f"{detail}. Correct whichever is wrong, or record an "
                                "attributed variance on a fresh verification with "
                                f"`vigil assess finding verify {slug} ... "
                                "--severity-variance-file <path>`."
                            ),
                        }
                    )

    for slug, root_slug in sorted(root_link_by_slug.items()):
        if root_slug not in candidate_slugs:
            blockers.append(
                {
                    "kind": "root_cause_root_not_reportable",
                    "slug": slug,
                    "detail": f"root_cause_slug={root_slug} is not reportable",
                }
            )

    duplicate_groups: dict[tuple[str, str], list[str]] = {}
    root_cause_groups: dict[str, list[str]] = {}
    for row in candidates:
        slug = str(row.get("slug", ""))
        root_cause_key = str(row.get("root_cause_key", "") or "").strip()
        if root_cause_key:
            root_cause_groups.setdefault(root_cause_key, []).append(slug)
        location = str(row.get("canonical_location", "") or "").strip()
        defect_family = str(row.get("defect_family", "") or "").strip()
        if location and defect_family:
            duplicate_groups.setdefault((location, defect_family), []).append(slug)

    for root_cause_key, slugs in root_cause_groups.items():
        if len(slugs) > 1:
            grouped_roots = {
                root_link_by_slug.get(slug, slug)
                for slug in slugs
            }
            if len(grouped_roots) == 1:
                continue
            blockers.append(
                {
                    "kind": "duplicate_root_cause",
                    "slugs": sorted(slugs),
                    "detail": f"root_cause_key={root_cause_key}",
                }
            )
    for (location, defect_family), slugs in duplicate_groups.items():
        if len(slugs) > 1:
            blockers.append(
                {
                    "kind": "duplicate_location_family",
                    "slugs": sorted(slugs),
                    "detail": f"{defect_family} @ {location}",
                }
            )

    with _common.get_connection() as connection:
        # Artifact rows carry each file's full extracted text, so reading every
        # row of a long engagement materializes gigabytes. Enumerate paths from
        # the covering (engagement_id, relative_path) index and load rows only
        # for what this gate inspects: durable markdown notes (with their text)
        # and the evidence the reportable candidates cite (without it).
        artifact_ids_by_path = {
            str(row["relative_path"]): int(row["id"])
            for row in connection.execute(
                "SELECT id, relative_path FROM assessment_artifacts WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        evidence_artifact_ids = {
            int(row["evidence_artifact_id"])
            for row in candidates
            if row.get("evidence_artifact_id") is not None
        }
        for row in candidates:
            evidence_ref = str(row.get("evidence_ref", "") or "").strip()
            if not evidence_ref:
                continue
            try:
                indexed_path = _normalize_report_evidence_ref(engagement_root, evidence_ref)
            except (OSError, RuntimeError, ValueError):
                # Prefetch only: the candidate loop below normalizes again and
                # fails exactly where it always has.
                continue
            if indexed_path in artifact_ids_by_path:
                evidence_artifact_ids.add(artifact_ids_by_path[indexed_path])
        markdown_artifacts = _artifact_rows_by_id(
            connection,
            engagement_id,
            [
                artifact_id
                for path, artifact_id in artifact_ids_by_path.items()
                if _is_durable_markdown_path(path)
            ],
            include_text=True,
        )
        artifact_rows_by_id = {
            **_artifact_rows_by_id(
                connection, engagement_id, evidence_artifact_ids, include_text=False
            ),
            **markdown_artifacts,
        }
        missing_citations: dict[str, set[str]] = {}
        for artifact in markdown_artifacts.values():
            artifact_path = str(artifact["relative_path"])
            if not bool(artifact.get("present")):
                continue
            if bool(artifact.get("scratch")):
                # Operator explicitly marked this as scratch — outside the
                # report-readiness contract by design.
                continue
            linked = any(
                artifact.get(field)
                for field in (
                    "related_finding_slug",
                    "related_chain_key",
                    "related_surface_id",
                    "related_request_variant_id",
                    "producer_agent_id",
                    "producer_command_run_id",
                )
            )
            if not linked:
                advisories.append(
                    {
                        "kind": "unlinked_markdown_note",
                        "artifact_id": artifact.get("id"),
                        "path": artifact_path,
                        "detail": (
                            f"markdown note '{artifact_path}' is indexed but not linked to a finding, chain, "
                            "surface, request_variant, command_run, or producing agent. Fix with one of: "
                            f"`vigil assess artifact register {artifact_path} --finding <slug>` to link, or "
                            f"`vigil assess artifact mark-scratch {artifact_path}` to dismiss as scratch."
                        ),
                    }
                )
            for cited_path in _MARKDOWN_PATH_REFERENCE_RE.findall(
                str(artifact.get("indexed_text") or "")
            ):
                if cited_path == artifact_path or _cited_markdown_exists(
                    engagement_root, cited_path
                ):
                    continue
                missing_citations.setdefault(cited_path, set()).add(artifact_path)
        for cited_path, citing_paths in sorted(missing_citations.items()):
            advisories.append(
                {
                    "kind": "missing_cited_markdown_artifact",
                    "path": cited_path,
                    "cited_by": sorted(citing_paths),
                    "detail": (
                        f"markdown artifact '{cited_path}' is cited by durable engagement state "
                        f"but is absent on disk. Restore it or correct the citations before treating "
                        "the referenced backlog or evidence as empty."
                    ),
                }
            )
        for row in candidates:
            slug = str(row.get("slug", ""))
            evidence_ref = str(row.get("evidence_ref", "") or "").strip()
            evidence_artifact_id = row.get("evidence_artifact_id")
            linked_evidence_artifact = None
            # A source-derived code finding's evidence IS the sealed source its
            # location cites, so there is no artifact to index and nothing a
            # repoint could aim at. The two obligations below are exempt; the
            # indexed-but-absent and mismatch blockers still apply, because a
            # finding that DOES name an engagement artifact must name a real one.
            source_bound = _source_bound_evidence(
                row, snapshot_statuses.get(slug, "not_applicable")
            )

            if evidence_artifact_id is not None:
                linked_evidence_artifact = artifact_rows_by_id.get(int(evidence_artifact_id))
                if linked_evidence_artifact is not None and not bool(linked_evidence_artifact.get("present")):
                    blockers.append(
                        {
                            "kind": "finding_evidence_missing_artifact",
                            "slug": slug,
                            "title": row.get("title", ""),
                            # Wording matters here: this fires against real
                            # evidence directories and captures. "Restore the
                            # file" reads as an instruction to recreate or
                            # overwrite it, which would destroy the evidence the
                            # finding rests on. Say VERIFY first, and never
                            # imply re-authoring.
                            "detail": (
                                f"finding {slug} evidence artifact id={evidence_artifact_id} "
                                f"({linked_evidence_artifact.get('relative_path', '')!r}) is indexed but the "
                                f"index last saw nothing at that path. VERIFY the path first — do NOT recreate "
                                f"or overwrite anything there. If the evidence IS present, re-index it with "
                                f"`vigil assess artifact register {linked_evidence_artifact.get('relative_path', '')} --finding {slug}` "
                                f"(a directory of captured evidence is valid). If it genuinely moved, repoint "
                                f"the finding via "
                                f"`vigil assess finding update {slug} --evidence-ref <relative-path>`."
                            ),
                        }
                    )
                    continue

            if not evidence_ref and source_bound:
                continue
            if not evidence_ref:
                blockers.append(
                    {
                        "kind": "finding_missing_evidence_ref",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"active/reportable finding {slug} has no evidence_ref. "
                            f"Fix with `vigil assess finding update {slug} --evidence-ref <relative-path>` "
                            "after writing the evidence artifact to disk."
                        ),
                    }
                )
                continue
            indexed_evidence_ref = _normalize_report_evidence_ref(engagement_root, evidence_ref)
            indexed_artifact_id = artifact_ids_by_path.get(indexed_evidence_ref)
            artifact = (
                artifact_rows_by_id.get(indexed_artifact_id)
                if indexed_artifact_id is not None
                else None
            )
            if artifact is None and source_bound:
                continue
            if artifact is None:
                blockers.append(
                    {
                        "kind": "finding_evidence_unindexed",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} is not in the artifact index. "
                            f"Fix with `vigil assess artifact register {indexed_evidence_ref} --finding {slug}`."
                        ),
                    }
                )
            elif not bool(artifact.get("present")):
                blockers.append(
                    {
                        "kind": "finding_evidence_missing_artifact",
                        "slug": slug,
                        "title": row.get("title", ""),
                        # See the wording note on the sibling blocker above:
                        # never phrase this as "restore the file", which invites
                        # overwriting live evidence.
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} is indexed but the index "
                            f"last saw nothing at that path. VERIFY the path first — do NOT recreate or "
                            f"overwrite anything there. If the evidence IS present, re-index it with "
                            f"`vigil assess artifact register {indexed_evidence_ref} --finding {slug}` "
                            f"(a directory of captured evidence is valid). If it genuinely moved, repoint "
                            f"the finding via "
                            f"`vigil assess finding update {slug} --evidence-ref <relative-path>`."
                        ),
                    }
                )
            elif (
                linked_evidence_artifact is not None
                and int(linked_evidence_artifact.get("id") or 0) != int(artifact.get("id") or 0)
            ):
                blockers.append(
                    {
                        "kind": "finding_evidence_artifact_mismatch",
                        "slug": slug,
                        "title": row.get("title", ""),
                        "detail": (
                            f"finding {slug} evidence_ref={evidence_ref!r} resolves to artifact "
                            f"id={artifact.get('id')}, but evidence_artifact_id points to "
                            f"id={evidence_artifact_id} ({linked_evidence_artifact.get('relative_path', '')!r}). "
                            f"Refresh the finding link with "
                            f"`vigil assess finding update {slug} --evidence-ref {indexed_evidence_ref}`."
                        ),
                    }
                )

        # Only STEP links represent the ordered attack path and must each resolve
        # to a reportable finding slug. The schema legitimately permits
        # evidence/access/credential links (relation != 'step'); those attach
        # supporting context, not path steps, so they must NOT be flagged as
        # unlinked finding-steps.
        chain_links = connection.execute(
            """
            SELECT chains.chain_key, links.entity_kind, links.entity_ref
            FROM assessment_attack_chain_links AS links
            JOIN assessment_attack_chains AS chains ON chains.id = links.chain_id
            WHERE links.engagement_id = ?
              AND links.relation = 'step'
            """,
            (engagement_id,),
        ).fetchall()
        for link in chain_links:
            if str(link["entity_kind"]) != "finding":
                blockers.append(
                    {
                        "kind": "chain_step_not_finding_linked",
                        "chain_key": link["chain_key"],
                        "detail": f"chain step entity_kind={link['entity_kind']} must link to a finding slug",
                    }
                )
                continue
            entity_ref = str(link["entity_ref"] or "")
            if not entity_ref or entity_ref not in candidate_slugs:
                blockers.append(
                    {
                        "kind": "chain_step_missing_finding",
                        "chain_key": link["chain_key"],
                        "detail": f"finding step {entity_ref or '<empty>'} is not reportable",
                    }
                )

        handoff_rows = connection.execute(
            """
            SELECT agent_id, finding_slugs_json
            FROM assessment_dispatch_handoffs
            WHERE engagement_id = ? AND finding_slugs_json IS NOT NULL
            """,
            (engagement_id,),
        ).fetchall()
        known_slugs = {
            str(row["slug"])
            for row in connection.execute(
                "SELECT slug FROM assessment_findings WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        for handoff in handoff_rows:
            try:
                handoff_slugs = json.loads(handoff["finding_slugs_json"] or "[]")
            except json.JSONDecodeError:
                handoff_slugs = []
            if not isinstance(handoff_slugs, list):
                continue
            missing = [str(slug) for slug in handoff_slugs if str(slug) not in known_slugs]
            if missing:
                blockers.append(
                    {
                        "kind": "handoff_unknown_finding",
                        "agent_id": handoff["agent_id"],
                        "slugs": missing,
                        "detail": "handoff references finding slugs not present in backend",
                    }
                )

        stale_ready = connection.execute(
            """
            SELECT dispatches.agent_id, dispatches.agent_role, handoffs.handoff_status
            FROM assessment_dispatches AS dispatches
            JOIN assessment_dispatch_handoffs AS handoffs
              ON handoffs.engagement_id = dispatches.engagement_id
             AND handoffs.agent_id = dispatches.agent_id
            WHERE dispatches.engagement_id = ?
              AND dispatches.status = 'in-progress'
              AND handoffs.handoff_status IN ('ready', 'blocked')
            """,
            (engagement_id,),
        ).fetchall()
        for row in stale_ready:
            advisories.append(
                {
                    "kind": "stale_dispatch_ready_handoff",
                    "agent_id": row["agent_id"],
                    "detail": (
                        f"{row['agent_role']} dispatch {row['agent_id']} has a "
                        f"{row['handoff_status']!r} handoff but is still in-progress. "
                        f"Close with `vigil assess agent close {row['agent_id']}` "
                        "or bulk-close ready/blocked stales with "
                        "`vigil assess agent reconcile-stale`."
                    ),
                }
            )

    # W3 — WEB coverage/grading gate (BLOCK-WITH-OVERRIDE, web/both only). These
    # do NOT fire on code or blue engagements. Both are non-bypassable at the
    # POST /report-export mode=final edge (report_export inherits this readiness)
    # and at the transition report/complete precondition; --force is the global
    # escape.
    if is_web:
        # (1) uncovered_high_route_hosts — an in-scope real-app host (recorded
        # routes, or an API/auth/GraphQL surface) with NO recorded verdict and
        # no active coverage_completeness_deferral naming it.
        for row in web_uncovered_high_route_hosts(engagement_id):
            host = str(row.get("host", ""))
            blockers.append(
                {
                    "kind": "uncovered_high_route_hosts",
                    "host": host,
                    "route_count": int(row.get("route_count", 0)),
                    "detail": (
                        f"in-scope real-app host {host} ({row.get('real_app_reason', '')}) "
                        f"has no recorded VERDICT — a finding (or an evidence-backed-negative "
                        f"false_positive finding) on the host. Record a verdict, or accept the "
                        f"gap with `vigil assess agent decision --kind coverage_completeness_deferral "
                        f"--payload-json '{{\"host\": \"{host}\", \"reason\": \"...\"}}' "
                        f"--surfaced-to-user`."
                    ),
                }
            )

        # (2) unreviewed_findings — any critical/high/medium finding still
        # verification_status='unreviewed' (ANY auth_context), status not in
        # (merged, false_positive). The existing finding_verification_status
        # blocker only catches reportable-status candidates; this also catches
        # draft / non-reportable findings that have never been graded.
        with _common.get_connection() as connection:
            unreviewed_rows = connection.execute(
                """
                SELECT slug, title, severity, auth_context
                FROM assessment_findings
                WHERE engagement_id = ?
                  AND lower(severity) IN ('critical', 'high', 'medium')
                  AND verification_status = 'unreviewed'
                  AND status NOT IN ('merged', 'false_positive')
                  AND merged_into_finding_id IS NULL
                ORDER BY id DESC
                """,
                (engagement_id,),
            ).fetchall()
        for row in unreviewed_rows:
            slug = str(row["slug"] or "")
            blockers.append(
                {
                    "kind": "unreviewed_findings",
                    "slug": slug,
                    "title": str(row["title"] or ""),
                    # ``severity`` on a readiness item names its gating class, so
                    # the finding's own band travels under its own key.
                    "finding_severity": str(row["severity"] or ""),
                    "auth_context": str(row["auth_context"] or ""),
                    "detail": (
                        f"finding {slug} (severity={row['severity']}) is verification_status="
                        f"'unreviewed' and must be graded before the final report. Grade it with "
                        f"`vigil assess finding verify {slug} --status confirmed|downgraded|disputed "
                        f"--reason ...` (records a verification verdict)."
                    ),
                }
            )

    # ── Submission-axis integrity, and the two backlogs nothing surfaced ──
    #
    # ``submission_status`` is orthogonal to ``workflow_status`` and no readiness
    # gate reads it, which is precisely why a withdrawn-but-still-reported finding
    # kept looking filable. Blocking on the CONTRADICTION is the honest fix: a
    # withdrawal that silently re-banded the finding would move an axis the
    # operator did not ask to move.
    with _common.get_connection() as connection:
        submission_rows = connection.execute(
            """
            SELECT slug, title, status, submission_status, submission_ref,
                   verification_status, details_json, notes
            FROM assessment_findings
            WHERE engagement_id = ?
              AND merged_into_finding_id IS NULL
            ORDER BY id ASC
            """,
            (engagement_id,),
        ).fetchall()
    for row in submission_rows:
        slug = str(row["slug"] or "")
        title = str(row["title"] or "")
        submission_status = str(row["submission_status"] or "none")
        if submission_status == "withdrawn" and str(row["status"] or "") == "reported":
            blockers.append(
                {
                    "kind": "finding_withdrawn_but_reported",
                    "slug": slug,
                    "title": title,
                    "detail": (
                        f"finding {slug} was withdrawn from the program but is still "
                        "workflow_status='reported', so the report still claims it. "
                        f"Move the workflow axis too: `vigil assess finding update {slug} "
                        "--status draft --reason 'withdrawn from program'`."
                    ),
                }
            )
        if submission_status != "none" and not str(row["submission_ref"] or "").strip():
            advisories.append(
                {
                    "kind": "finding_submission_ref_missing",
                    "slug": slug,
                    "title": title,
                    "detail": (
                        f"finding {slug} carries submission_status='{submission_status}' "
                        "with no submission_ref, so it cannot be joined back to the "
                        f"external report. Backfill it: `vigil assess finding update {slug} "
                        "--submission-ref <program-id> --submission-platform <platform>`."
                    ),
                }
            )
        row_details = _json_object(row["details_json"])
        if len(str(row["notes"] or "")) > FINDING_NOTES_MAX_LENGTH:
            advisories.append(
                {
                    "kind": "finding_notes_over_cap",
                    "slug": slug,
                    "title": title,
                    "detail": (
                        f"finding {slug} notes are {len(str(row['notes'] or ''))} characters, "
                        f"past the {FINDING_NOTES_MAX_LENGTH}-character append cap, so the "
                        "next checkpoint append will be refused. Rewrite them down to "
                        f"a summary with `vigil assess finding update {slug} "
                        "--notes-replace --notes '<summary>' --expected-row-version <n>` "
                        "— the prior text is kept on the transition ledger."
                    ),
                }
            )
        # A kill that names a settling test nobody ran is a real backlog item, and
        # ``false_positive`` findings are dropped from every report projection, so
        # without this it vanishes entirely. ADVISORY, never a blocker: the kill
        # itself is legitimate; what is missing is the follow-up.
        if str(row["verification_status"] or "") == "false_positive":
            followup = row_details.get("required_followup")
            if isinstance(followup, list) and any(
                isinstance(item, str) and item.strip() for item in followup
            ):
                blocked_items = ", ".join(
                    str(item).strip()
                    for item in followup
                    if isinstance(item, str) and item.strip()
                )
                advisories.append(
                    {
                        "kind": "killed_finding_settling_test_outstanding",
                        "slug": slug,
                        "title": title,
                        "detail": (
                            f"killed finding {slug} names a settling test that was never "
                            f"run: {blocked_items}. If the experiment could not start, "
                            "`--status blocked` keeps it visible instead."
                        ),
                    }
                )

    # A reportable finding with no root_cause_key has no mechanical duplicate
    # signal at all — the estate's only collision surface is that string.
    for row in candidates:
        if not str(row.get("root_cause_key", "") or "").strip():
            advisories.append(
                {
                    "kind": "finding_root_cause_key_missing",
                    "slug": str(row.get("slug", "")),
                    "title": str(row.get("title", "")),
                    "detail": (
                        "reportable finding carries no root_cause_key, so duplicate "
                        "detection has nothing to key on for it"
                    ),
                }
            )

    return {
        "ready": len(blockers) == 0,
        "blocker_count": len(blockers),
        "blockers": [_gated(item, "block") for item in blockers],
        "advisories": [_gated(item, "advisory") for item in advisories],
        "advisory_count": len(advisories),
        "coverage": coverage,
    }

def _as_string_list(value: Any) -> list[str]:
    """Coerce a details field that *should* be a string list into one.

    Agents occasionally record ``steps_to_reproduce`` as a single string (a
    numbered multi-step block) instead of a list. Downstream report renderers
    iterate it with ``.forEach`` / ``.join``; a raw string would crash them, so
    normalize here: a list keeps its (stringified, non-empty) items, a non-empty
    string becomes a one-element list (content preserved), anything else is ``[]``.
    """
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    if isinstance(value, str) and value.strip():
        return [value]
    return []


def _report_record(record: dict[str, Any], report_id: str) -> dict[str, Any]:
    item = dict(record)
    details = _json_object(item.get("details"))
    item["report_id"] = report_id
    # The waiver behind the verdict, projected to the top level beside
    # ``verification_status`` because that field alone cannot tell a
    # dispatch-verified `downgraded` from one the operator reached on their own
    # out-of-snapshot evidence. ADR 0019 lets the operator weaken a gate over
    # their own engagement; delivering the result as indistinguishable from
    # proof is the laundering that permission does not extend to. The WHOLE
    # stamp travels — ``intel_id`` and ``reason`` are what make the verdict
    # legible — and ``None`` is the ordinary case.
    item["operator_authority"] = operator_authority_stamp(item.get("provenance"))
    item["cvss_vector"] = details.get("cvss_vector", "")
    item["cvss_score"] = details.get("cvss_score")
    item["remediation"] = details.get("remediation", "")
    item["steps_to_reproduce"] = _as_string_list(details.get("steps_to_reproduce"))
    # The command-run ids behind those steps, projected alongside them so a report
    # renderer can show what backs each reproduction without re-parsing details.
    item["repro_runs"] = _as_string_list(details.get("repro_runs"))
    item["cwe_id"] = details.get("cwe_id", "")
    item["owasp_category"] = details.get("owasp_category", "")
    item["impact"] = details.get("impact", item.get("summary", ""))
    item["evidence_detail"] = details.get("evidence", "")
    item["entry_point"] = details.get("entry_point", "")
    item["sink"] = details.get("sink", "")
    item["poc_code"] = details.get("poc_code", "")
    raw_req = details.get("poc_request")
    item["poc_request"] = raw_req if isinstance(raw_req, dict) else None
    raw_resp = details.get("poc_response")
    item["poc_response"] = raw_resp if isinstance(raw_resp, dict) else None
    raw_refs = details.get("references", [])
    item["references"] = raw_refs if isinstance(raw_refs, list) else []
    return item

def _report_finding_records(engagement_id: int, *, mode: str = "draft") -> list[dict[str, Any]]:
    rows = _report_candidate_records(engagement_id)
    if mode == "draft":
        # Both report projections contain only verification-reportable statuses.
        # There is no chain_required bypass — a held finding is never
        # report-durable. Also drop
        # ``workflow_status == "draft"`` findings: readiness blocks them until
        # triage closes, while both report projections intentionally omit unresolved
        # work so a renderer cannot mistake it for report-durable content.
        rows = [
            row
            for row in rows
            if row.get("verification_status") in {"confirmed", "downgraded"}
            and row.get("workflow_status") != "draft"
        ]
    elif mode == "final":
        rows = [
            row
            for row in rows
            if row.get("workflow_status") in {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
            and row.get("verification_status") in {"confirmed", "downgraded"}
        ]
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"unsupported report mode: {mode}")

    rows.sort(
        key=lambda row: (
            {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }.get(str(row.get("severity", "")), 5),
            {
                "exploited": 0,
                "contained": 1,
                "eradicated": 2,
                "recovered": 3,
                "active": 4,
                "reported": 5,
                "blocked": 6,
                "draft": 7,
            }.get(str(row.get("workflow_status", "")), 5),
            -int(row.get("id", 0)),
        )
    )
    return [_report_record(row, f"{idx:03d}") for idx, row in enumerate(rows, start=1)]

def list_report_findings(engagement_id: int, *, mode: str = "draft") -> list[dict[str, Any]]:
    """Return findings formatted for report generation.

    Excludes merged and false-positive findings, orders by severity (critical
    first), and extracts structured fields from the ``details`` object so
    the report-writer has them at the top level without manual JSON parsing:
    CVSS, remediation, steps_to_reproduce, repro_runs, CWE, OWASP, impact,
    evidence, entry_point, sink, poc_code, poc_request, poc_response, and
    references.
    """
    return _report_finding_records(engagement_id, mode=mode)

def list_report_finding_groups(engagement_id: int, *, mode: str = "draft") -> dict[str, Any]:
    records = _report_finding_records(engagement_id, mode=mode)
    by_slug = {str(record.get("slug", "")): record for record in records if record.get("slug")}
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, findings.slug AS finding_slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
              AND links.retired_at IS NULL
            """,
            (engagement_id, ROOT_CAUSE_LINK_KIND),
        ).fetchall()
    groups: dict[str, dict[str, Any]] = {}
    linked_siblings: set[str] = set()
    for row in rows:
        link = dict(row)
        sibling_slug = str(link.get("finding_slug", "") or "")
        root_slug = str(link.get("target_ref", "") or "")
        sibling = by_slug.get(sibling_slug)
        root = by_slug.get(root_slug)
        if sibling is None or root is None:
            continue
        sibling_record = dict(sibling)
        sibling_record.update(_root_cause_link_metadata(link))
        group = groups.setdefault(
            root_slug,
            {
                "root": root,
                "siblings": [],
                "sibling_count": 0,
                "residual_path_count": 0,
                "highest_severity": root.get("severity", "info"),
            },
        )
        group["siblings"].append(sibling_record)
        linked_siblings.add(sibling_slug)

    for group in groups.values():
        siblings = group["siblings"]
        siblings.sort(
            key=lambda item: (
                item.get("sibling_order") if item.get("sibling_order") is not None else 999999,
                -SEVERITY_RANK.get(str(item.get("severity", "info")), 0),
                str(item.get("slug", "")),
            )
        )
        group["sibling_count"] = len(siblings)
        group["residual_path_count"] = sum(
            1 for item in siblings if item.get("root_cause_effect") == "eliminates_attack_path"
        )
        severities = [str(group["root"].get("severity", "info"))] + [str(item.get("severity", "info")) for item in siblings]
        group["highest_severity"] = max(severities, key=lambda sev: SEVERITY_RANK.get(sev, 0))

    groups_list = sorted(
        groups.values(),
        key=lambda group: (
            -SEVERITY_RANK.get(str(group.get("highest_severity", "info")), 0),
            str(group["root"].get("report_id", "")),
        ),
    )
    grouped_roots = {str(group["root"].get("slug", "")) for group in groups_list}
    standalone = [
        record for record in records
        if str(record.get("slug", "")) not in linked_siblings
        and str(record.get("slug", "")) not in grouped_roots
    ]
    return {
        "mode": mode,
        "groups": groups_list,
        "standalone": standalone,
        "group_count": len(groups_list),
        "standalone_count": len(standalone),
        "finding_count": len(records),
    }
