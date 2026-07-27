from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from fastapi import HTTPException, status

from ..events import _engagement_or_404
from ..artifact_index import _normalize_relative_path
from ...finding_merge import strict_finding_id

from . import _common
from ._common import ROOT_CAUSE_LINK_KIND, SEVERITY_RANK, _json_object, _serialize_finding_record
from .links import _root_cause_link_metadata
from .coverage import coverage_readiness, web_uncovered_high_route_hosts
from .cvss import CvssVectorError, base_score


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
    # A ``blocked`` verification disposition (blocked-for-provisioning, hunting.md)
    # is NOT a report candidate: the primitive was never reached, so it is neither
    # gradeable at impact-if-true nor report-durable — it "stays OUT of the report".
    # Excluding it here removes it from BOTH report projections
    # (``_report_finding_records`` draft AND final) and from every report_readiness
    # gate (this is the shared source), so a blocked finding never appears in the
    # report AND never blocks finalizing it. A later real proof supersedes the
    # block (rank: blocked < downgraded/confirmed) and re-admits the finding.
    return [
        record
        for record in (_serialize_finding_record(row) for row in rows)
        if record.get("verification_disposition") != "blocked"
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

    for row in candidate_records:
        if row.get("workflow_status") != "draft":
            continue
        slug = str(row.get("slug", ""))
        advisories.append(
            {
                "kind": "draft_finding_needs_disposition",
                "slug": slug,
                "title": row.get("title", ""),
                "detail": (
                    f"finding {slug} is parked in workflow_status='draft' and will NOT appear in "
                    f"the report or export. Disposition it: promote to active with "
                    f"`vigil assess finding update {slug} --workflow-status active` so it reports, "
                    f"or verify it false positive with `vigil assess finding verify {slug} "
                    f"--disposition false_positive --reason \"...\" --kill-reason \"...\" "
                    f"--kill-check <index>` after documenting the failed check."
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
    root_link_by_slug = {
        str(row["finding_slug"]): str(row["target_ref"])
        for row in root_link_rows
        if str(row["finding_slug"]) in candidate_slugs
    }

    for row in candidates:
        if row.get("verification_state") != "verified":
            blockers.append(
                {
                    "kind": "finding_verification_state",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_state={row.get('verification_state', 'unknown')}",
                }
            )
            continue
        if row.get("verification_disposition") not in {"confirmed", "downgraded"}:
            blockers.append(
                {
                    "kind": "finding_verification_disposition",
                    "slug": row.get("slug", ""),
                    "title": row.get("title", ""),
                    "detail": f"verification_disposition={row.get('verification_disposition', 'unknown')}",
                }
            )

    for row in candidates:
        if row.get("verification_state") != "verified":
            continue
        if row.get("verification_disposition") not in {"confirmed", "downgraded"}:
            continue
        slug = row.get("slug", "")
        title = row.get("title", "")
        details = _json_object(row.get("details_json", "{}"))
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
                blockers.append(
                    {
                        "kind": "severity_cvss_mismatch",
                        "slug": slug,
                        "title": title,
                        "detail": f"severity={severity} but cvss_score={score} expects {expected}",
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
        # verification_state='unreviewed' (ANY auth_context), status not in
        # (merged, false_positive). The existing finding_verification_state
        # blocker only catches reportable-status candidates; this also catches
        # draft / non-reportable findings that have never been graded.
        with _common.get_connection() as connection:
            unreviewed_rows = connection.execute(
                """
                SELECT slug, title, severity, auth_context
                FROM assessment_findings
                WHERE engagement_id = ?
                  AND lower(severity) IN ('critical', 'high', 'medium')
                  AND verification_state = 'unreviewed'
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
                        f"finding {slug} (severity={row['severity']}) is verification_state="
                        f"'unreviewed' and must be graded before the final report. Grade it with "
                        f"`vigil assess finding verify {slug} --disposition confirmed|downgraded|disputed "
                        f"--reason-text ...` (records a verification verdict)."
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
    details = _json_object(item.get("details_json", "{}"))
    item["report_id"] = report_id
    item["cvss_vector"] = details.get("cvss_vector", "")
    item["cvss_score"] = details.get("cvss_score")
    item["remediation"] = details.get("remediation", "")
    item["steps_to_reproduce"] = _as_string_list(details.get("steps_to_reproduce"))
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
        # Exclude disputed findings, and exclude the sticky holding disposition
        # ``pending_runtime_proof`` (strong-but-unproven). The latter carries
        # ``verification_state == "verified"`` so the disputed filter alone would
        # leak it into draft reports; mirror how ``final`` mode keeps only
        # {confirmed, downgraded} dispositions. There is no chain_required bypass
        # in ``final`` — a held finding is never report-durable. Also drop
        # ``workflow_status == "draft"`` findings: ``report_readiness()`` never
        # gates them (draft is not a reportable status) and ``final`` mode already
        # excludes them, so they must not leak into the draft projection either.
        rows = [
            row
            for row in rows
            if row.get("verification_state") != "disputed"
            and row.get("verification_disposition") != "pending_runtime_proof"
            and row.get("workflow_status") != "draft"
        ]
    elif mode == "final":
        rows = [
            row
            for row in rows
            if row.get("workflow_status") in {"active", "blocked", "exploited", "contained", "eradicated", "recovered", "reported"}
            and row.get("verification_state") == "verified"
            and row.get("verification_disposition") in {"confirmed", "downgraded"}
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
    first), and extracts structured fields from the ``details_json`` blob so
    the report-writer has them at the top level without manual JSON parsing:
    CVSS, remediation, steps_to_reproduce, CWE, OWASP, impact, evidence,
    entry_point, sink, poc_code, poc_request, poc_response, and references.
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
