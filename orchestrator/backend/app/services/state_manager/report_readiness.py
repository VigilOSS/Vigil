from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ...finding_merge import strict_finding_id
from ..artifact_index import _normalize_relative_path
from ..events import _engagement_or_404
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
    code_snapshot_attestation_status,
    finding_code_snapshot_status,
    is_file_finding,
    load_code_repo_snapshot_states,
)
from .links import _root_cause_link_metadata
from .proofs import proof_evidence_health_issues_for_finding

_MARKDOWN_PATH_REFERENCE_RE = re.compile(
    r"(?<![A-Za-z0-9_:/.-])"
    r"((?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:md|markdown))"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
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
    try:
        return _normalize_relative_path(root, evidence_ref)
    except HTTPException:
        return evidence_ref

def _report_candidate_records(engagement_id: int) -> list[dict[str, Any]]:
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
        for record in (_serialize_finding_record(row) for row in rows)
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
    engagement_type = str(getattr(engagement, "engagement_type", "") or "").lower()
    is_blue = engagement_type == "blue"
    # WEB-ONLY guard for the W3 coverage/grading blockers below. Mirrors the
    # ``_is_web_engagement`` convention used by app-unit scoring / the depth
    # ledger: anything that is NOT a code or blue track is web-eligible
    # (``web`` / ``both`` / legacy ``red`` / unset). Code and blue engagements
    # never get the route-coverage or finding-grading blockers.
    is_web = engagement_type not in ("code", "blue")
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
    candidate_records = _report_candidate_records(engagement_id)
    candidates = [
        row
        for row in candidate_records
        if row.get("workflow_status") in reportable_statuses
    ]

    draft_snapshot_statuses: dict[str, str] = {}
    with _common.get_connection() as connection:
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        for row in candidate_records:
            snapshot_status = finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            if row.get("workflow_status") == "draft":
                draft_snapshot_statuses[str(row.get("slug", ""))] = snapshot_status
            if row.get("workflow_status") not in reportable_statuses:
                continue
            # ADVISORY, never a blocker: the gate's verdict is unchanged, and a
            # legacy row that predates the attestation is not a violation. What
            # this surfaces is a binding that nothing corroborates — asserted
            # outside any audited dispatch or run, or carried over from another
            # finding — which the gate alone cannot tell from a genuine one.
            attestation_status = code_snapshot_attestation_status(row)
            if attestation_status in {"copied", "unattested"}:
                advisories.append(
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
                "missing_file_count": len(missing_file_ids),
                "missing_file_ids": missing_file_ids,
                "missing_file_paths": missing_file_paths,
                "detail": (
                    "report-durable current code finding(s) "
                    f"{', '.join(finding_slugs)} have no complete current "
                    f"variant-scan receipt for {len(missing_file_ids)} "
                    f"admitted current repository file(s): {path_sample}"
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
        snapshot_status = draft_snapshot_statuses.get(slug, "not_applicable")
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
        if row.get("verification_status") not in {"confirmed", "downgraded"}:
            blockers.append(
                {
                    "kind": "finding_verification_status",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_status={row.get('verification_status', 'unknown')}",
                }
            )

    with _common.get_connection() as connection:
        for row in candidates:
            if row.get("verification_status") not in {"confirmed", "downgraded"}:
                continue
            for issue in proof_evidence_health_issues_for_finding(
                connection, engagement.id, int(row["id"])
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
        # only where there is something to back up.
        if not is_blue and details.get("steps_to_reproduce") and not details.get("repro_runs"):
            advisories.append(
                {
                    "kind": "finding_repro_runs_missing",
                    "slug": slug,
                    "title": title,
                    "detail": (
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
                detail = (
                    f"severity={severity} but cvss_score={score} expects {expected}"
                )
                if approved:
                    advisories.append(
                        {
                            "kind": "severity_cvss_band_divergence",
                            "slug": slug,
                            "title": title,
                            "detail": (
                                f"{detail}; structured variance approved by "
                                f"{variance['actor']}: {variance['reason']}"
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
        artifact_rows = {
            str(row["relative_path"]): dict(row)
            for row in connection.execute(
                "SELECT * FROM assessment_artifacts WHERE engagement_id = ?",
                (engagement_id,),
            ).fetchall()
        }
        missing_citations: dict[str, set[str]] = {}
        for artifact_path, artifact in artifact_rows.items():
            if not _is_durable_markdown_path(artifact_path):
                continue
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
        artifact_rows_by_id = {int(a["id"]): a for a in artifact_rows.values() if a.get("id")}
        for row in candidates:
            slug = str(row.get("slug", ""))
            evidence_ref = str(row.get("evidence_ref", "") or "").strip()
            evidence_artifact_id = row.get("evidence_artifact_id")
            linked_evidence_artifact = None

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
            artifact = artifact_rows.get(indexed_evidence_ref)
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
                    "severity": str(row["severity"] or ""),
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
        "blockers": blockers,
        "advisories": advisories,
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
