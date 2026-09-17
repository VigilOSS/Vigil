from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ..db import get_connection
from .artifact_index import _normalize_relative_path, _open_registered_artifact
from .code_security_policy import NATIVE_MEMORY_SAFETY_DEFECT_FAMILIES
from .events import _engagement_or_404
from .state_manager.findings import (
    _code_snapshot_binding,
    finding_code_snapshot_status,
    load_code_repo_snapshot_states,
)


FUZZ_DISPATCH_ROLE = "code-fuzz-engineer"
MEMORY_SAFETY_DEFECT_FAMILIES = NATIVE_MEMORY_SAFETY_DEFECT_FAMILIES
FUZZ_DECISIONS = frozenset({"required", "not_required"})
FUZZ_CAMPAIGN_OUTCOMES = frozenset(
    {
        "completed_no_crash",
        "completed_crashes_triaged",
        "build_failed",
        "campaign_failed",
    }
)
COVERING_FUZZ_CAMPAIGN_OUTCOMES = frozenset(
    {"completed_no_crash", "completed_crashes_triaged"}
)
MAX_FUZZ_TARGETS = 128
MAX_FUZZ_FINDINGS = 1000
MAX_FUZZ_EVIDENCE_BYTES = 256 * 1024
DEFAULT_FUZZ_HISTORY_PAGE = 50
MAX_FUZZ_HISTORY_PAGE = 100


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_list(value: Any) -> list[str]:
    try:
        parsed = json.loads(str(value or "[]"))
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _canonical_identifiers(
    values: list[str], *, field: str, maximum: int
) -> list[str]:
    if len(values) > maximum or values != sorted(set(values)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be sorted, unique, and contain at most {maximum} entries",
        )
    if any(
        not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        for value in values
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} entries must be canonical strings up to 256 characters",
        )
    return values


def _require_canonical_text(value: str, *, field: str, maximum: int) -> str:
    if (
        not value
        or len(value) > maximum
        or value != value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be a canonical nonempty string up to {maximum} characters",
        )
    return value


def _repo_row(connection, engagement_id: int, repo_id: int) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT * FROM code_repos
        WHERE id = ? AND engagement_id = ?
          AND active_generation > 0
          AND source_snapshot_quality = 'verified'
        """,
        (repo_id, engagement_id),
    ).fetchone()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="published verified code repository not found",
        )
    return dict(row)


def _require_current_identity(
    repo: dict[str, Any],
    *,
    repo_generation: int,
    source_manifest_digest: str,
    label: str,
) -> None:
    if int(repo["active_generation"]) != repo_generation:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{label} repository generation is stale",
        )
    if str(repo["source_manifest_digest"] or "") != source_manifest_digest:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{label} source manifest digest is stale",
        )


def _evidence_identity(engagement_root: str, evidence_ref: str) -> tuple[str, str]:
    root = Path(engagement_root).resolve()
    relative = _normalize_relative_path(root, evidence_ref)
    descriptor = _open_registered_artifact(root, relative)
    if descriptor is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="fuzz evidence_ref must name an existing engagement-owned regular file",
        )
    digest = hashlib.sha256()
    total = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="fuzz evidence_ref must name an existing engagement-owned regular file",
            )
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, MAX_FUZZ_EVIDENCE_BYTES + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FUZZ_EVIDENCE_BYTES:
                raise HTTPException(
                    status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                    detail=(
                        "fuzz evidence file exceeds the bounded receipt limit of "
                        f"{MAX_FUZZ_EVIDENCE_BYTES} bytes"
                    ),
                )
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return relative, digest.hexdigest()


def _current_memory_finding_slugs(
    connection,
    engagement_id: int,
    repo_id: int,
    *,
    repo_states: dict[int, dict[str, Any]] | None = None,
) -> list[str]:
    if repo_states is None:
        repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    family_placeholders = ", ".join(
        "?" for _ in MEMORY_SAFETY_DEFECT_FAMILIES
    )
    rows = connection.execute(
        f"""
        SELECT slug, provenance_json, canonical_location
        FROM assessment_findings
        WHERE engagement_id = ?
          AND status NOT IN ('false_positive', 'merged')
          AND verification_status != 'false_positive'
          AND merged_into_finding_id IS NULL
          AND LOWER(TRIM(defect_family)) IN ({family_placeholders})
          AND CASE WHEN json_valid(provenance_json) THEN CAST(json_extract(
              provenance_json, '$.code_snapshot.repo_id'
          ) AS INTEGER) END = ?
        ORDER BY slug
        LIMIT ?
        """,
        (
            engagement_id,
            *sorted(MEMORY_SAFETY_DEFECT_FAMILIES),
            repo_id,
            MAX_FUZZ_FINDINGS + 1,
        ),
    ).fetchall()
    if len(rows) > MAX_FUZZ_FINDINGS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "current native memory-safety finding obligations exceed the "
                f"bounded fuzz gate limit of {MAX_FUZZ_FINDINGS}; deduplicate or "
                "merge findings before completion"
            ),
        )
    current: list[str] = []
    for row in rows:
        try:
            provenance = json.loads(str(row["provenance_json"] or "{}"))
        except json.JSONDecodeError:
            provenance = {}
        binding = _code_snapshot_binding(
            provenance if isinstance(provenance, dict) else {}, strict=False
        )
        if (
            binding is not None
            and binding["repo_id"] == repo_id
            and finding_code_snapshot_status(
                connection,
                engagement_id,
                row,
                repo_states=repo_states,
            )
            == "current"
        ):
            current.append(str(row["slug"]))
    return current


def _decision_fingerprint(
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    decision: str,
    target_ids: list[str],
    evidence_ref: str,
    evidence_sha256: str,
    rationale: str,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema": "code-fuzz-decision/v1",
                "repo_id": repo_id,
                "repo_generation": repo_generation,
                "source_manifest_digest": source_manifest_digest,
                "decision": decision,
                "target_ids": target_ids,
                "evidence_ref": evidence_ref,
                "evidence_sha256": evidence_sha256,
                "rationale": rationale,
            }
        ).encode("utf-8")
    ).hexdigest()


def _decision_is_current(
    engagement_root: str,
    repo: dict[str, Any],
    row: dict[str, Any],
) -> bool:
    if (
        int(row["repo_generation"]) != int(repo["active_generation"])
        or str(row["source_manifest_digest"] or "")
        != str(repo["source_manifest_digest"] or "")
    ):
        return False
    target_ids = _json_list(row["target_ids_json"])
    expected = _decision_fingerprint(
        repo_id=int(row["repo_id"]),
        repo_generation=int(row["repo_generation"]),
        source_manifest_digest=str(row["source_manifest_digest"]),
        decision=str(row["decision"]),
        target_ids=target_ids,
        evidence_ref=str(row["evidence_ref"]),
        evidence_sha256=str(row["evidence_sha256"]),
        rationale=str(row["rationale"]),
    )
    if expected != str(row["decision_fingerprint"]):
        return False
    try:
        evidence_ref, evidence_sha256 = _evidence_identity(
            engagement_root, str(row["evidence_ref"])
        )
    except HTTPException:
        return False
    return (
        evidence_ref == str(row["evidence_ref"])
        and evidence_sha256 == str(row["evidence_sha256"])
    )


def record_fuzz_decision(
    engagement_id: int,
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    decision: str,
    target_ids: list[str],
    evidence_ref: str,
    rationale: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    target_ids = _canonical_identifiers(
        target_ids, field="target_ids", maximum=MAX_FUZZ_TARGETS
    )
    _require_canonical_text(rationale, field="rationale", maximum=20000)
    _require_canonical_text(evidence_ref, field="evidence_ref", maximum=4096)
    if decision not in FUZZ_DECISIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="fuzz decision must be required or not_required",
        )
    if decision == "not_required" and target_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="not_required fuzz decisions cannot declare target_ids",
        )
    evidence_ref, evidence_sha256 = _evidence_identity(
        engagement.engagement_root, evidence_ref
    )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _repo_row(connection, engagement.id, repo_id)
        _require_current_identity(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="fuzz decision",
        )
        forced_findings = _current_memory_finding_slugs(
            connection, engagement.id, repo_id
        )
        if decision == "not_required" and forced_findings:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "fuzzing cannot be marked not_required while a current non-killed "
                    "native memory-safety finding exists: "
                    + ", ".join(forced_findings)
                ),
            )
        if decision == "required" and not target_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "required fuzz decisions must declare at least one target_id"
                ),
            )
        fingerprint = _decision_fingerprint(
            repo_id=repo_id,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            decision=decision,
            target_ids=target_ids,
            evidence_ref=evidence_ref,
            evidence_sha256=evidence_sha256,
            rationale=rationale,
        )

        candidate_row = connection.execute(
            """
            SELECT * FROM code_fuzz_decisions
            WHERE engagement_id = ? AND repo_id = ?
              AND repo_generation = ? AND source_manifest_digest = ?
            ORDER BY id DESC LIMIT 1
            """,
            (
                engagement.id,
                repo_id,
                repo_generation,
                source_manifest_digest,
            ),
        ).fetchone()
        if candidate_row is not None:
            candidate = dict(candidate_row)
            if not _decision_is_current(
                engagement.engagement_root, repo, candidate
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "the newest fuzz decision is invalid; repair its evidence or "
                        "advance the sealed source generation before recording another"
                    ),
                )
            policy_invalid_waiver = (
                bool(forced_findings)
                and str(candidate["decision"]) == "not_required"
            )
            if (
                not policy_invalid_waiver
                and str(candidate["decision_fingerprint"]) == fingerprint
            ):
                payload = candidate
                payload["target_ids"] = _json_list(
                    payload.pop("target_ids_json")
                )
                payload["current"] = True
                payload["created"] = False
                return payload
            if not policy_invalid_waiver:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "a different current fuzz decision already exists for this "
                        "repository generation and source digest; advance the sealed "
                        "source generation before changing applicability or target scope"
                    ),
                )
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO code_fuzz_decisions (
                engagement_id, repo_id, repo_generation, source_manifest_digest,
                decision, target_ids_json, evidence_ref, evidence_sha256,
                rationale, decision_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                repo_id,
                repo_generation,
                source_manifest_digest,
                decision,
                _canonical_json(target_ids),
                evidence_ref,
                evidence_sha256,
                rationale,
                fingerprint,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "the fuzz decision fingerprint exists only in superseded history; "
                    "advance the sealed source generation instead of reviving it"
                ),
            )
        row = connection.execute(
            """
            SELECT * FROM code_fuzz_decisions
            WHERE engagement_id = ? AND decision_fingerprint = ?
            """,
            (engagement.id, fingerprint),
        ).fetchone()
        assert row is not None
        payload = dict(row)
        if not _decision_is_current(engagement.engagement_root, repo, payload):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "fuzz decision evidence changed while the decision was being recorded"
                ),
            )
    payload["target_ids"] = _json_list(payload.pop("target_ids_json"))
    payload["current"] = True
    payload["created"] = True
    return payload


def _campaign_fingerprint(
    *,
    dispatch_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    target_id: str,
    covered_finding_slugs: list[str],
    engine: str,
    sanitizers: list[str],
    run_budget_seconds: int,
    executions: int,
    outcome: str,
    crash_count: int,
    triage_summary: str,
    evidence_ref: str,
    evidence_sha256: str,
    rationale: str,
) -> str:
    return hashlib.sha256(
        _canonical_json(
            {
                "schema": "code-fuzz-campaign-receipt/v1",
                "dispatch_id": dispatch_id,
                "repo_id": repo_id,
                "repo_generation": repo_generation,
                "source_manifest_digest": source_manifest_digest,
                "target_id": target_id,
                "covered_finding_slugs": covered_finding_slugs,
                "engine": engine,
                "sanitizers": sanitizers,
                "run_budget_seconds": run_budget_seconds,
                "executions": executions,
                "outcome": outcome,
                "crash_count": crash_count,
                "triage_summary": triage_summary,
                "evidence_ref": evidence_ref,
                "evidence_sha256": evidence_sha256,
                "rationale": rationale,
            }
        ).encode("utf-8")
    ).hexdigest()


def _campaign_receipt_is_current(
    connection,
    engagement_root: str,
    repo: dict[str, Any],
    row: dict[str, Any],
    *,
    dispatch: dict[str, Any] | None = None,
) -> bool:
    if dispatch is None:
        raw_dispatch = connection.execute(
            """
            SELECT agent_id, agent_role, status FROM assessment_dispatches
            WHERE engagement_id = ? AND id = ?
            """,
            (int(row["engagement_id"]), int(row["dispatch_id"])),
        ).fetchone()
        dispatch = dict(raw_dispatch) if raw_dispatch is not None else None
    if (
        dispatch is None
        or str(dispatch.get("agent_role") or "") != FUZZ_DISPATCH_ROLE
        or str(dispatch.get("agent_id") or "") != str(row["dispatch_agent_id"] or "")
        or str(dispatch.get("status") or "") not in {"in-progress", "completed"}
        or int(row["repo_generation"]) != int(repo["active_generation"])
        or str(row["source_manifest_digest"] or "")
        != str(repo["source_manifest_digest"] or "")
    ):
        return False
    covered = _json_list(row["covered_finding_slugs_json"])
    sanitizers = _json_list(row["sanitizers_json"])
    expected = _campaign_fingerprint(
        dispatch_id=int(row["dispatch_id"]),
        repo_id=int(row["repo_id"]),
        repo_generation=int(row["repo_generation"]),
        source_manifest_digest=str(row["source_manifest_digest"]),
        target_id=str(row["target_id"]),
        covered_finding_slugs=covered,
        engine=str(row["engine"]),
        sanitizers=sanitizers,
        run_budget_seconds=int(row["run_budget_seconds"]),
        executions=int(row["executions"]),
        outcome=str(row["outcome"]),
        crash_count=int(row["crash_count"]),
        triage_summary=str(row["triage_summary"]),
        evidence_ref=str(row["evidence_ref"]),
        evidence_sha256=str(row["evidence_sha256"]),
        rationale=str(row["rationale"]),
    )
    if expected != str(row["receipt_fingerprint"]):
        return False
    try:
        evidence_ref, evidence_sha256 = _evidence_identity(
            engagement_root, str(row["evidence_ref"])
        )
    except HTTPException:
        return False
    return (
        evidence_ref == str(row["evidence_ref"])
        and evidence_sha256 == str(row["evidence_sha256"])
    )


def record_fuzz_campaign_receipt(
    engagement_id: int,
    *,
    dispatch_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    target_id: str,
    covered_finding_slugs: list[str],
    engine: str,
    sanitizers: list[str],
    run_budget_seconds: int,
    executions: int,
    outcome: str,
    crash_count: int,
    triage_summary: str,
    evidence_ref: str,
    rationale: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    _canonical_identifiers([target_id], field="target_id", maximum=1)
    _require_canonical_text(engine, field="engine", maximum=128)
    _require_canonical_text(
        triage_summary, field="triage_summary", maximum=20000
    )
    _require_canonical_text(evidence_ref, field="evidence_ref", maximum=4096)
    _require_canonical_text(rationale, field="rationale", maximum=20000)
    covered_finding_slugs = _canonical_identifiers(
        covered_finding_slugs,
        field="covered_finding_slugs",
        maximum=MAX_FUZZ_FINDINGS,
    )
    sanitizers = _canonical_identifiers(
        sanitizers, field="sanitizers", maximum=32
    )
    if outcome not in FUZZ_CAMPAIGN_OUTCOMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="unknown fuzz campaign outcome",
        )
    if outcome == "completed_no_crash" and crash_count != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="completed_no_crash receipts must report crash_count=0",
        )
    if outcome == "completed_crashes_triaged" and crash_count < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="completed_crashes_triaged receipts must report at least one crash",
        )
    if outcome in COVERING_FUZZ_CAMPAIGN_OUTCOMES and executions < 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="completed fuzz campaign receipts require at least one execution",
        )
    evidence_ref, evidence_sha256 = _evidence_identity(
        engagement.engagement_root, evidence_ref
    )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        dispatch = connection.execute(
            """
            SELECT * FROM assessment_dispatches
            WHERE engagement_id = ? AND id = ?
            """,
            (engagement.id, dispatch_id),
        ).fetchone()
        if (
            dispatch is None
            or str(dispatch["agent_role"] or "") != FUZZ_DISPATCH_ROLE
            or str(dispatch["status"] or "") not in {"in-progress", "completed"}
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "fuzz campaign receipt requires an active/completed dispatch in "
                    f"this engagement with role={FUZZ_DISPATCH_ROLE}"
                ),
            )
        repo = _repo_row(connection, engagement.id, repo_id)
        _require_current_identity(
            repo,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            label="fuzz campaign receipt",
        )
        state = _fuzz_state_with_connection(
            connection, engagement, repo
        )
        if state["decision"] != "required":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="fuzz campaign receipt requires a current required applicability decision",
            )
        if target_id not in set(state["required_target_ids"]):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="fuzz campaign target_id is outside the current decision target scope",
            )
        required_findings = set(state["required_finding_slugs"])
        if not set(covered_finding_slugs).issubset(required_findings):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="covered_finding_slugs must be current required memory-safety findings",
            )
        fingerprint = _campaign_fingerprint(
            dispatch_id=dispatch_id,
            repo_id=repo_id,
            repo_generation=repo_generation,
            source_manifest_digest=source_manifest_digest,
            target_id=target_id,
            covered_finding_slugs=covered_finding_slugs,
            engine=engine,
            sanitizers=sanitizers,
            run_budget_seconds=run_budget_seconds,
            executions=executions,
            outcome=outcome,
            crash_count=crash_count,
            triage_summary=triage_summary,
            evidence_ref=evidence_ref,
            evidence_sha256=evidence_sha256,
            rationale=rationale,
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO code_fuzz_campaign_receipts (
                engagement_id, dispatch_id, dispatch_agent_id, repo_id,
                repo_generation, source_manifest_digest, target_id,
                covered_finding_slugs_json, engine, sanitizers_json,
                run_budget_seconds, executions, outcome, crash_count,
                triage_summary, evidence_ref, evidence_sha256, rationale,
                receipt_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                dispatch_id,
                str(dispatch["agent_id"]),
                repo_id,
                repo_generation,
                source_manifest_digest,
                target_id,
                _canonical_json(covered_finding_slugs),
                engine,
                _canonical_json(sanitizers),
                run_budget_seconds,
                executions,
                outcome,
                crash_count,
                triage_summary,
                evidence_ref,
                evidence_sha256,
                rationale,
                fingerprint,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM code_fuzz_campaign_receipts
            WHERE engagement_id = ? AND receipt_fingerprint = ?
            """,
            (engagement.id, fingerprint),
        ).fetchone()
        assert row is not None
        payload = dict(row)
        current = _campaign_receipt_is_current(
            connection, engagement.engagement_root, repo, payload
        )
    payload["covered_finding_slugs"] = _json_list(
        payload.pop("covered_finding_slugs_json")
    )
    payload["sanitizers"] = _json_list(payload.pop("sanitizers_json"))
    payload["covering"] = (
        current and payload["outcome"] in COVERING_FUZZ_CAMPAIGN_OUTCOMES
    )
    payload["current"] = current
    return payload


def _fuzz_state_with_connection(connection, engagement, repo: dict[str, Any]) -> dict[str, Any]:
    repo_id = int(repo["id"])
    forced_findings = _current_memory_finding_slugs(
        connection, engagement.id, repo_id
    )
    decision_row = connection.execute(
        """
        SELECT * FROM code_fuzz_decisions
        WHERE engagement_id = ? AND repo_id = ?
          AND repo_generation = ? AND source_manifest_digest = ?
        ORDER BY id DESC LIMIT 1
        """,
        (
            engagement.id,
            repo_id,
            int(repo["active_generation"]),
            str(repo["source_manifest_digest"]),
        ),
    ).fetchone()
    recorded = dict(decision_row) if decision_row is not None else None
    if recorded is not None and not _decision_is_current(
        engagement.engagement_root, repo, recorded
    ):
        recorded = None
    recorded_targets = (
        _json_list(recorded["target_ids_json"]) if recorded is not None else []
    )
    if forced_findings and recorded is not None and recorded["decision"] != "required":
        recorded = None
        recorded_targets = []
    if recorded is not None:
        decision = str(recorded["decision"])
        source = "recorded"
        required_targets = recorded_targets if decision == "required" else []
    else:
        decision = None
        source = "none"
        required_targets = []

    rows: list[Any] = []
    if required_targets:
        target_values = ", ".join("(?)" for _ in required_targets)
        rows = connection.execute(
            f"""
            WITH required_targets(target_id) AS (VALUES {target_values}),
            newest_receipts(receipt_id) AS (
                SELECT (
                    SELECT candidate.id
                    FROM code_fuzz_campaign_receipts AS candidate
                    WHERE candidate.engagement_id = ?
                      AND candidate.repo_id = ?
                      AND candidate.repo_generation = ?
                      AND candidate.source_manifest_digest = ?
                      AND candidate.target_id = required_targets.target_id
                      AND candidate.outcome IN (
                          'completed_no_crash', 'completed_crashes_triaged'
                      )
                    ORDER BY candidate.id DESC
                    LIMIT 1
                )
                FROM required_targets
            )
            SELECT receipts.*,
                   dispatches.agent_id AS authority_agent_id,
                   dispatches.agent_role AS authority_agent_role,
                   dispatches.status AS authority_status
            FROM newest_receipts
            JOIN code_fuzz_campaign_receipts AS receipts
              ON receipts.id = newest_receipts.receipt_id
            LEFT JOIN assessment_dispatches AS dispatches
              ON dispatches.engagement_id = receipts.engagement_id
             AND dispatches.id = receipts.dispatch_id
            ORDER BY receipts.target_id
            """,
            (
                *required_targets,
                engagement.id,
                repo_id,
                int(repo["active_generation"]),
                str(repo["source_manifest_digest"]),
            ),
        ).fetchall()
    covered_targets: set[str] = set()
    covered_findings: set[str] = set()
    current_receipt_ids: list[int] = []
    for raw_row in rows:
        row = dict(raw_row)
        dispatch = {
            "agent_id": row.pop("authority_agent_id"),
            "agent_role": row.pop("authority_agent_role"),
            "status": row.pop("authority_status"),
        }
        if not _campaign_receipt_is_current(
            connection,
            engagement.engagement_root,
            repo,
            row,
            dispatch=dispatch,
        ):
            continue
        current_receipt_ids.append(int(row["id"]))
        covered_targets.add(str(row["target_id"]))
        covered_findings.update(_json_list(row["covered_finding_slugs_json"]))
    pending_targets = sorted(set(required_targets) - covered_targets)
    pending_findings = sorted(set(forced_findings) - covered_findings)
    completion_ready = decision == "not_required" or (
        decision == "required" and not pending_targets and not pending_findings
    )
    return {
        "repo_id": repo_id,
        "repo_generation": int(repo["active_generation"]),
        "source_manifest_digest": str(repo["source_manifest_digest"]),
        "decision": decision,
        "forced_decision": "required" if forced_findings else None,
        "source": source,
        "decision_id": int(recorded["id"]) if recorded is not None else None,
        "required_target_ids": required_targets,
        "required_finding_slugs": forced_findings,
        "pending_target_ids": pending_targets,
        "pending_finding_slugs": pending_findings,
        "current_campaign_receipt_ids": current_receipt_ids,
        "applicability_ready": decision is not None,
        "completion_ready": completion_ready,
    }


def get_fuzz_state(engagement_id: int, repo_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        repo = _repo_row(connection, engagement.id, repo_id)
        return _fuzz_state_with_connection(connection, engagement, repo)


def fuzz_states(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        repos = connection.execute(
            # `repo_role = 'analysis'` belongs HERE, not at the two consumers:
            # `code/readiness?target_phase=fuzz` and `GET /report-readiness` both
            # read this list, and a predicate copied into each would be two
            # places to forget. A `reference` repository is indexed and citable
            # but carries no review obligation, and "decide whether to fuzz it"
            # is an obligation over a codebase nobody is reviewing.
            """
            SELECT * FROM code_repos
            WHERE engagement_id = ? AND active_generation > 0
              AND source_snapshot_quality = 'verified'
              AND repo_role = 'analysis'
            ORDER BY id
            """,
            (engagement.id,),
        ).fetchall()
        return [
            _fuzz_state_with_connection(connection, engagement, dict(repo))
            for repo in repos
        ]


def list_fuzz_decisions(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    include_stale: bool = False,
    limit: int = DEFAULT_FUZZ_HISTORY_PAGE,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        parameters: list[Any] = [engagement.id]
        where = "WHERE engagement_id = ?"
        if repo_id is not None:
            where += " AND repo_id = ?"
            parameters.append(repo_id)
        parameters.extend((limit, offset))
        rows = connection.execute(
            f"SELECT * FROM code_fuzz_decisions {where} "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(parameters),
        ).fetchall()
        repo_ids = sorted({int(row["repo_id"]) for row in rows})
        repos: dict[int, dict[str, Any]] = {}
        if repo_ids:
            repo_placeholders = ", ".join("?" for _ in repo_ids)
            repos = {
                int(row["id"]): dict(row)
                for row in connection.execute(
                    f"SELECT * FROM code_repos WHERE engagement_id = ? "
                    f"AND id IN ({repo_placeholders})",
                    (engagement.id, *repo_ids),
                ).fetchall()
            }
        selected: dict[int, dict[str, Any]] = {}
        if repos:
            identity_values = ", ".join("(?, ?, ?)" for _ in repos)
            identity_parameters: list[Any] = []
            for selected_repo_id, selected_repo in sorted(repos.items()):
                identity_parameters.extend(
                    (
                        selected_repo_id,
                        int(selected_repo["active_generation"]),
                        str(selected_repo["source_manifest_digest"] or ""),
                    )
                )
            identity_parameters.append(engagement.id)
            selected = {
                int(row["repo_id"]): dict(row)
                for row in connection.execute(
                    f"""
                    WITH identities(
                        repo_id, repo_generation, source_manifest_digest
                    ) AS (VALUES {identity_values}),
                    selected_ids(repo_id, decision_id) AS (
                        SELECT identities.repo_id, (
                            SELECT candidate.id
                            FROM code_fuzz_decisions AS candidate
                            WHERE candidate.engagement_id = ?
                              AND candidate.repo_id = identities.repo_id
                              AND candidate.repo_generation = identities.repo_generation
                              AND candidate.source_manifest_digest = identities.source_manifest_digest
                            ORDER BY candidate.id DESC
                            LIMIT 1
                        )
                        FROM identities
                    )
                    SELECT selected_ids.repo_id, decisions.id, decisions.decision
                    FROM selected_ids
                    LEFT JOIN code_fuzz_decisions AS decisions
                      ON decisions.id = selected_ids.decision_id
                    """,
                    tuple(identity_parameters),
                ).fetchall()
                if row["id"] is not None
            }
        invalid_not_required: set[int] = set()
        repo_states: dict[int, dict[str, Any]] | None = None
        for selected_repo_id, selected_row in selected.items():
            if str(selected_row["decision"]) != "not_required":
                continue
            if repo_states is None:
                repo_states = load_code_repo_snapshot_states(
                    connection, engagement.id
                )
            if _current_memory_finding_slugs(
                connection,
                engagement.id,
                selected_repo_id,
                repo_states=repo_states,
            ):
                invalid_not_required.add(selected_repo_id)
        payloads: list[dict[str, Any]] = []
        for raw_row in rows:
            payload = dict(raw_row)
            payload_repo_id = int(payload["repo_id"])
            repo = repos.get(payload_repo_id)
            selected_row = selected.get(payload_repo_id)
            current = (
                repo is not None
                and selected_row is not None
                and int(selected_row["id"]) == int(payload["id"])
                and payload_repo_id not in invalid_not_required
                and _decision_is_current(
                    engagement.engagement_root, repo, payload
                )
            )
            if not include_stale and not current:
                continue
            payload["target_ids"] = _json_list(
                payload.pop("target_ids_json")
            )
            payload["current"] = current
            payloads.append(payload)
        return payloads


def list_fuzz_campaign_receipts(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    include_stale: bool = False,
    limit: int = DEFAULT_FUZZ_HISTORY_PAGE,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        parameters: list[Any] = [engagement.id]
        where = "WHERE engagement_id = ?"
        if repo_id is not None:
            where += " AND repo_id = ?"
            parameters.append(repo_id)
        parameters.extend((limit, offset))
        rows = connection.execute(
            f"SELECT * FROM code_fuzz_campaign_receipts {where} "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(parameters),
        ).fetchall()
        repo_ids = sorted({int(row["repo_id"]) for row in rows})
        repos: dict[int, dict[str, Any]] = {}
        if repo_ids:
            repo_placeholders = ", ".join("?" for _ in repo_ids)
            repos = {
                int(row["id"]): dict(row)
                for row in connection.execute(
                    f"SELECT * FROM code_repos WHERE engagement_id = ? "
                    f"AND id IN ({repo_placeholders})",
                    (engagement.id, *repo_ids),
                ).fetchall()
            }
        dispatch_ids = sorted({int(row["dispatch_id"]) for row in rows})
        dispatches: dict[int, dict[str, Any]] = {}
        if dispatch_ids:
            placeholders = ", ".join("?" for _ in dispatch_ids)
            dispatches = {
                int(row["id"]): dict(row)
                for row in connection.execute(
                    f"SELECT id, agent_id, agent_role, status "
                    f"FROM assessment_dispatches WHERE engagement_id = ? "
                    f"AND id IN ({placeholders})",
                    (engagement.id, *dispatch_ids),
                ).fetchall()
            }
        payloads: list[dict[str, Any]] = []
        for raw_row in rows:
            payload = dict(raw_row)
            repo = repos.get(int(payload["repo_id"]))
            current = repo is not None and _campaign_receipt_is_current(
                connection,
                engagement.engagement_root,
                repo,
                payload,
                dispatch=dispatches.get(int(payload["dispatch_id"]), {}),
            )
            if not include_stale and not current:
                continue
            payload["covered_finding_slugs"] = _json_list(
                payload.pop("covered_finding_slugs_json")
            )
            payload["sanitizers"] = _json_list(payload.pop("sanitizers_json"))
            payload["covering"] = (
                current
                and payload["outcome"] in COVERING_FUZZ_CAMPAIGN_OUTCOMES
            )
            payload["current"] = current
            payloads.append(payload)
        return payloads
