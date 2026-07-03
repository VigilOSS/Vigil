from __future__ import annotations

import enum
import hashlib
import json
import re
from difflib import get_close_matches
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from fastapi import HTTPException, status

# Re-exported for the package seam: sibling modules reach these as
# ``_common.get_connection()`` and ``_common._engagement_or_404``, and the
# package __init__ re-exports them again. The redundant ``as`` aliases mark the
# imports as intentional re-exports so they are not pruned as unused.
from ...db import get_connection as get_connection
from ..events import _engagement_or_404 as _engagement_or_404
from ..search import (
    canonical_finding_alias,
    is_canonical_finding_slug,
)



SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

class WorkflowStatus(enum.StrEnum):
    """Finding workflow status. ``StrEnum`` so members serialize/compare as their
    bare lowercase string (DB TEXT columns, JSON, f-strings) with no leak of the
    ``WorkflowStatus.`` prefix."""

    DRAFT = "draft"
    ACTIVE = "active"
    BLOCKED = "blocked"
    EXPLOITED = "exploited"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    FALSE_POSITIVE = "false_positive"
    MERGED = "merged"
    REPORTED = "reported"


class SubmissionStatus(enum.StrEnum):
    """External bug-bounty / program submission state for a finding.

    Canonical single source of truth for the submission vocabulary. ORTHOGONAL
    to ``WorkflowStatus`` (which tracks whether the finding is in report.md): a
    finding can be ``workflow_status=reported`` AND ``submission_status=accepted``
    independently, and neither axis derives from or mutates the other. The CLI
    (``agent/scripts``) cannot import this package, so ``SUBMISSION_STATUSES`` is
    mirrored in ``assess.lib.contracts``; ``test_submission_status`` pins the two
    in sync (the ``dispatch_mode`` precedent). ``StrEnum`` so members serialize /
    compare as their bare lowercase string (DB TEXT, JSON, f-strings)."""

    NONE = "none"
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    NEEDS_INFO = "needs_info"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class VerificationState(enum.StrEnum):
    """Finding verification review state."""

    UNREVIEWED = "unreviewed"
    VERIFIED = "verified"
    DISPUTED = "disputed"


class VerificationDisposition(enum.StrEnum):
    """Finding verification disposition outcome."""

    NONE = "none"
    PENDING_RUNTIME_PROOF = "pending_runtime_proof"
    BLOCKED = "blocked"
    CONFIRMED = "confirmed"
    DOWNGRADED = "downgraded"
    FALSE_POSITIVE = "false_positive"


# Derived membership sets (frozenset of enum members, NOT aliases of the class).
# Keeps the ``x not in WORKFLOW_STATUSES`` guards working and avoids the 3.11
# ``str in EnumClass`` edge. Members compare/hash equal to their str value, so
# ``"draft" in WORKFLOW_STATUSES`` stays True.
WORKFLOW_STATUSES = frozenset(WorkflowStatus)

# Submission-status vocabulary as a derived membership set (mirrors the
# WORKFLOW_STATUSES pattern). ``none`` is the default for a finding that has not
# been submitted externally.
SUBMISSION_STATUSES = frozenset(SubmissionStatus)

WORKFLOW_STATUS_RANK = {
    WorkflowStatus.DRAFT: 0,
    WorkflowStatus.ACTIVE: 1,
    WorkflowStatus.BLOCKED: 2,
    WorkflowStatus.EXPLOITED: 3,
    # Blue IR response phases sit between exploited and reported. They are
    # monotonically increasing (contained < eradicated < recovered) so the
    # standard "incoming must not regress" guard blocks an accidental rollback
    # (e.g., eradicated → contained) without an operator reset.
    WorkflowStatus.CONTAINED: 4,
    WorkflowStatus.ERADICATED: 5,
    WorkflowStatus.RECOVERED: 6,
    WorkflowStatus.REPORTED: 7,
    WorkflowStatus.FALSE_POSITIVE: -2,
    WorkflowStatus.MERGED: -1,
}

VERIFICATION_STATES = frozenset(VerificationState)

VERIFICATION_STATE_RANK = {
    VerificationState.UNREVIEWED: 0,
    VerificationState.DISPUTED: 1,
    VerificationState.VERIFIED: 2,
}

VERIFICATION_DISPOSITIONS = frozenset(VerificationDisposition)

VERIFICATION_DISPOSITION_RANK = {
    VerificationDisposition.NONE: 0,
    # "Strong but not yet runtime-proven": sticky vs none (0 >= 1 is False so a
    # later bare none cannot clobber it) but yields to downgraded/confirmed,
    # which rank higher. false_positive is handled by explicit early-returns in
    # _coalesce_verification_disposition, so its -1 only matters for confidence
    # ordering in _finding_confidence_tuple.
    VerificationDisposition.PENDING_RUNTIME_PROOF: 1,
    # "Blocked-for-provisioning" (hunting.md): the exploit attempt could not even
    # start because a precondition is missing (no test account / line / device /
    # credential / access). Sticky vs 'none' (rank 1 >= 0, so a later bare none in
    # _coalesce_verification_disposition cannot clobber it), but yields to
    # downgraded (2) / confirmed (3) so a later real proof supersedes the block,
    # and false_positive is handled by the explicit early-returns in the coalesce.
    # Shares rank 1 with pending_runtime_proof: both are non-report holding states
    # that a real verdict outranks; the tie only affects confidence ordering in
    # _finding_confidence_tuple, where they are equivalently weak-but-reviewed.
    VerificationDisposition.BLOCKED: 1,
    VerificationDisposition.DOWNGRADED: 2,
    VerificationDisposition.CONFIRMED: 3,
    VerificationDisposition.FALSE_POSITIVE: -1,
}

class DispatchStatus(enum.StrEnum):
    """Specialist-dispatch lifecycle status (``assessment_dispatches.status``).

    ``in-progress`` is the single non-terminal state; the rest are terminal.
    ``StrEnum`` so members compare/serialize as their bare value."""

    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    BLOCKED = "blocked"


class CommandRunStatus(enum.StrEnum):
    """``assessment_command_runs.status`` lifecycle.

    ``queued``/``running`` are mutable pre-terminal states; a finalize PATCH may
    only land ``running`` or a terminal state (never back to ``queued``)."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    KILLED = "killed"
    LOST = "lost"


class JobStatus(enum.StrEnum):
    """``assessment_jobs.status`` lifecycle. Mirrors CommandRunStatus except jobs
    carry ``stop_failed`` (kill attempt failed) and never ``timed_out``."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    KILLED = "killed"
    LOST = "lost"
    STOP_FAILED = "stop_failed"


# Derived membership sets (frozenset of enum members). Members compare/hash equal
# to their str value, so ``"completed" in TERMINAL_DISPATCH_STATUSES`` stays True
# and these remain the single source of truth for the consuming modules.
DISPATCH_STATUSES = frozenset(DispatchStatus)
TERMINAL_DISPATCH_STATUSES = DISPATCH_STATUSES - {DispatchStatus.IN_PROGRESS}

COMMAND_RUN_STATUSES = frozenset(CommandRunStatus)
COMMAND_RUN_MUTABLE_STATUSES = frozenset({CommandRunStatus.QUEUED, CommandRunStatus.RUNNING})
COMMAND_RUN_TERMINAL_STATUSES = COMMAND_RUN_STATUSES - COMMAND_RUN_MUTABLE_STATUSES
# A finalize PATCH accepts the terminal states plus a ``running`` refresh, but not
# ``queued`` (a row cannot be finalized back to queued).
COMMAND_RUN_FINALIZE_ALLOWED_STATUSES = COMMAND_RUN_TERMINAL_STATUSES | {CommandRunStatus.RUNNING}

JOB_STATUSES = frozenset(JobStatus)
JOB_PRE_TERMINAL_STATUSES = frozenset({JobStatus.QUEUED, JobStatus.RUNNING})
JOB_TERMINAL_STATUSES = JOB_STATUSES - JOB_PRE_TERMINAL_STATUSES

class LeadStatus(enum.StrEnum):
    """Disposition lifecycle for an intel note that is a tracked *lead* (an
    actionable hypothesis/thread). A note with no ``lead_status`` (NULL) is a
    plain reference note, not a lead. ``StrEnum`` so members serialize as their
    bare value."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    RULED_OUT = "ruled_out"


LEAD_STATUSES = frozenset(LeadStatus)
# Terminal/closed = a lead that no longer needs work. Worklist = the rest.
LEAD_TERMINAL_STATUSES = frozenset({LeadStatus.RESOLVED, LeadStatus.RULED_OUT})
LEAD_OPEN_STATUSES = LEAD_STATUSES - LEAD_TERMINAL_STATUSES

ROOT_CAUSE_LINK_KIND = "root_cause"

ROOT_CAUSE_EFFECTS = {"eliminates_finding", "eliminates_attack_path"}

SLUG_RE = re.compile(r"[^a-z0-9]+")

def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))

def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}

def _merge_object_text(existing: str, incoming: dict[str, Any] | None) -> str:
    current = _json_object(existing)
    if incoming:
        current.update({key: value for key, value in incoming.items() if value not in (None, "", [], {})})
    return _json_text(current)

def _append_notes(existing: str, incoming: str) -> str:
    if not incoming:
        return existing
    if not existing:
        return incoming
    if incoming in existing.splitlines():
        return existing
    return f"{existing}\n{incoming}"

def _normalize_severity(value: str) -> str:
    severity = (value or "info").strip().lower()
    return severity if severity in SEVERITY_RANK else "info"

def _stronger_severity(existing: str, incoming: str) -> str:
    existing_normalized = _normalize_severity(existing)
    incoming_normalized = _normalize_severity(incoming)
    if SEVERITY_RANK[incoming_normalized] > SEVERITY_RANK[existing_normalized]:
        return incoming_normalized
    return existing_normalized

def _normalize_workflow_status(value: str) -> WorkflowStatus:
    status_value = (value or "draft").strip().lower()
    if status_value not in WORKFLOW_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid workflow status: {value}")
    return WorkflowStatus(status_value)

def _normalize_submission_status(value: str | None) -> SubmissionStatus:
    """Normalize/validate a submission status. ``None``/empty defaults to ``none``;
    anything outside the canonical set is a 400 (the persistence-layer enforcement
    seam, independent of the HTTP-model validator in ``assessment.py``)."""
    submission_value = (value or "none").strip().lower()
    if submission_value not in SUBMISSION_STATUSES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid submission status: {value}")
    return SubmissionStatus(submission_value)

def _normalize_verification_state(value: str) -> VerificationState:
    state_value = (value or "unreviewed").strip().lower()
    if state_value not in VERIFICATION_STATES:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid verification state: {value}")
    return VerificationState(state_value)

def _normalize_verification_disposition(value: str) -> VerificationDisposition:
    disposition_value = (value or "none").strip().lower()
    if disposition_value not in VERIFICATION_DISPOSITIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid verification disposition: {value}")
    return VerificationDisposition(disposition_value)

def _legacy_verification_defaults(workflow_status: str) -> tuple[VerificationState, VerificationDisposition]:
    normalized_workflow = _normalize_workflow_status(workflow_status)
    if normalized_workflow == "false_positive":
        return (VerificationState.VERIFIED, VerificationDisposition.FALSE_POSITIVE)
    if normalized_workflow in {"blocked", "exploited", "reported"}:
        return (VerificationState.VERIFIED, VerificationDisposition.CONFIRMED)
    if normalized_workflow == "active":
        return (VerificationState.UNREVIEWED, VerificationDisposition.NONE)
    return (VerificationState.UNREVIEWED, VerificationDisposition.NONE)

def _row_workflow_status(row: dict[str, Any] | Any) -> WorkflowStatus:
    if isinstance(row, dict):
        return _normalize_workflow_status(str(row.get("status", "draft")))
    return _normalize_workflow_status(str(row["status"]))

def _row_verification_state(row: dict[str, Any] | Any) -> VerificationState:
    if isinstance(row, dict):
        value = str(row.get("verification_state", "") or "")
        if value:
            return _normalize_verification_state(value)
        return _legacy_verification_defaults(_row_workflow_status(row))[0]
    value = str(row["verification_state"]) if "verification_state" in row.keys() else ""
    if value:
        return _normalize_verification_state(value)
    return _legacy_verification_defaults(_row_workflow_status(row))[0]

def _row_verification_disposition(row: dict[str, Any] | Any) -> VerificationDisposition:
    if isinstance(row, dict):
        value = str(row.get("verification_disposition", "") or "")
        if value:
            return _normalize_verification_disposition(value)
        return _legacy_verification_defaults(_row_workflow_status(row))[1]
    value = str(row["verification_disposition"]) if "verification_disposition" in row.keys() else ""
    if value:
        return _normalize_verification_disposition(value)
    return _legacy_verification_defaults(_row_workflow_status(row))[1]

def _is_suppressed_workflow_status(workflow_status: str) -> bool:
    return _normalize_workflow_status(workflow_status) in {"merged", "false_positive"}

def _serialize_finding_record(row: dict[str, Any] | Any) -> dict[str, Any]:
    record = dict(row)
    # Read-path serialization must not crash on invalid DB values.
    # Validation belongs on write paths; here we pass through raw data
    # so the frontend can still display the finding.
    try:
        record["workflow_status"] = _row_workflow_status(record)
    except HTTPException:
        record["workflow_status"] = str(record.get("status", "draft")).strip().lower()
    try:
        record["verification_state"] = _row_verification_state(record)
    except HTTPException:
        record["verification_state"] = str(record.get("verification_state", "unreviewed") or "unreviewed").strip().lower()
    try:
        record["verification_disposition"] = _row_verification_disposition(record)
    except HTTPException:
        record["verification_disposition"] = str(record.get("verification_disposition", "none") or "none").strip().lower()
    # submission_status is a separate axis from workflow_status; surface it on
    # every read projection, defaulting to 'none' when absent (legacy rows /
    # synthetic dicts). Read path must not crash on an invalid DB value.
    try:
        record["submission_status"] = _normalize_submission_status(record.get("submission_status"))
    except HTTPException:
        record["submission_status"] = str(record.get("submission_status", "none") or "none").strip().lower()
    record.pop("status", None)
    return record

def _finding_confidence_tuple(row: dict[str, Any] | Any) -> tuple[int, int, int, int, int]:
    if isinstance(row, dict):
        severity_value = row.get("severity", "info")
        evidence_ref = row.get("evidence_ref", "")
    else:
        severity_value = row["severity"]
        evidence_ref = row["evidence_ref"]
    return (
        WORKFLOW_STATUS_RANK[_row_workflow_status(row)],
        VERIFICATION_STATE_RANK[_row_verification_state(row)],
        VERIFICATION_DISPOSITION_RANK[_row_verification_disposition(row)],
        SEVERITY_RANK[_normalize_severity(str(severity_value))],
        1 if evidence_ref else 0,
    )

def _slugify(value: str) -> str:
    normalized = SLUG_RE.sub("-", value.strip().lower()).strip("-")
    return normalized or "finding"

def _parse_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="request url must be absolute")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    normalized_path = parsed.path or "/"
    return parsed.scheme, parsed.hostname, port, normalized_path

def _hash_json(value: Any) -> str:
    return hashlib.sha256(_json_text(value).encode("utf-8")).hexdigest()

def _scalar_row(connection, query: str, params: tuple[Any, ...]) -> int:
    row = connection.execute(query, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0

def _fetch_all(connection, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, params).fetchall()]

def _require_canonical_finding_slug(slug: str | None, *, field: str = "finding_slug") -> str:
    value = str(slug or "").strip()
    if not is_canonical_finding_slug(value):
        alias = canonical_finding_alias(value)
        suggestion = f"; did you mean {alias}?" if alias and alias != value else ""
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field} must be canonical <PREFIX>-<at least 3 digits> (example VA-047){suggestion}",
        )
    return value

def _require_canonical_finding_slugs(slugs: list[str] | None, *, field: str = "finding_slugs") -> list[str] | None:
    if slugs is None:
        return None
    return [_require_canonical_finding_slug(str(slug), field=field) for slug in slugs]

def _finding_not_found(connection, engagement_id: int, slug: str) -> HTTPException:
    rows = connection.execute(
        "SELECT slug FROM assessment_findings WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchall()
    candidates = [str(row["slug"]) for row in rows]
    close = get_close_matches(slug, candidates, n=3, cutoff=0.55)
    detail = f"finding not found: {slug}"
    if close:
        detail += "; close matches: " + ", ".join(close)
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

def _resolve_existing_finding_slug(
    connection,
    engagement_id: int,
    slug: str | None,
    *,
    field: str = "finding_slug",
) -> str:
    value = str(slug or "").strip()
    lookup = canonical_finding_alias(value) or value
    if lookup:
        row = connection.execute(
            "SELECT slug FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, lookup),
        ).fetchone()
        if row is not None:
            return str(row["slug"])
    if canonical_finding_alias(value):
        raise _finding_not_found(connection, engagement_id, lookup)
    _require_canonical_finding_slug(value, field=field)
    raise _finding_not_found(connection, engagement_id, value)

def _register_artifact_reference(engagement_id: int, path: str, **metadata: Any) -> int | None:
    """Register an artifact reference and return the artifact id (or None)."""
    if not path:
        return None
    from ..artifact_index import register_reference_if_local

    result = register_reference_if_local(engagement_id, path=path, **metadata)
    if result and result.get("id"):
        return int(result["id"])
    return None

def _remove_written_command_run_artifacts(*artifact_refs: str) -> None:
    for artifact_ref in artifact_refs:
        if not artifact_ref:
            continue
        try:
            Path(artifact_ref).unlink(missing_ok=True)
        except OSError:
            pass

def _utcnow_iso_dispatch() -> str:
    import datetime as _dt
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
