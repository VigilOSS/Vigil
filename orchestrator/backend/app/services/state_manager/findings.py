from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import urlsplit
from fastapi import HTTPException, status

from ..events import _engagement_or_404
from ..search import (
    canonical_finding_alias,
    is_canonical_finding_slug,
)

from . import _common
from ._common import ROOT_CAUSE_LINK_KIND, SEVERITY_RANK, VERIFICATION_DISPOSITION_RANK, VERIFICATION_STATE_RANK, WORKFLOW_STATUS_RANK, VerificationDisposition, VerificationState, WorkflowStatus, _finding_confidence_tuple, _finding_not_found, _json_object, _json_text, _merge_object_text, _normalize_severity, _normalize_submission_status, _normalize_verification_disposition, _normalize_verification_state, _normalize_workflow_status, _require_canonical_finding_slug, _resolve_existing_finding_slug, _row_verification_disposition, _row_verification_state, _row_workflow_status, _serialize_finding_record, _slugify, _stronger_severity
from .links import _is_root_cause_link, _upsert_finding_link



_FINDING_PREFIX_BY_SOURCE = {
    "exploit-developer": "EX",
    "vulnerability-analyst": "VA",
    "source-analyzer": "SA",
    "recon-specialist": "RE",
    "fuzzer": "FZ",
    "osint-analyst": "OS",
    "code-architect": "CA",
    "code-vuln-hunter": "CH",
    "code-variant-hunter": "CV",
    "code-vuln-verifier": "VF",
    "surface-collector": "SC",
    "code-fuzz-engineer": "CF",
    "operator": "OP",
    "operator-review": "OR",
}

def _coalesce_workflow_status(existing: str, incoming: str, *, explicit_workflow_override: bool = False) -> WorkflowStatus:
    existing_normalized = _normalize_workflow_status(existing)
    incoming_normalized = _normalize_workflow_status(incoming)
    if existing_normalized == "merged":
        return existing_normalized
    if explicit_workflow_override:
        return incoming_normalized
    if incoming_normalized == "merged":
        return incoming_normalized
    if incoming_normalized == "false_positive":
        return incoming_normalized
    if existing_normalized == "false_positive" and not explicit_workflow_override:
        # Keep prior verifier suppression sticky for semantic rediscovery so the same
        # location/family does not silently resurrect as a new live finding.
        return existing_normalized
    return (
        incoming_normalized
        if WORKFLOW_STATUS_RANK[incoming_normalized] >= WORKFLOW_STATUS_RANK[existing_normalized]
        else existing_normalized
    )

def _coalesce_verification_state(existing: str, incoming: str, *, explicit_override: bool = False) -> VerificationState:
    existing_normalized = _normalize_verification_state(existing)
    incoming_normalized = _normalize_verification_state(incoming)
    if explicit_override:
        return incoming_normalized
    return (
        incoming_normalized
        if VERIFICATION_STATE_RANK[incoming_normalized] >= VERIFICATION_STATE_RANK[existing_normalized]
        else existing_normalized
    )

def _coalesce_verification_disposition(existing: str, incoming: str, *, explicit_override: bool = False) -> VerificationDisposition:
    existing_normalized = _normalize_verification_disposition(existing)
    incoming_normalized = _normalize_verification_disposition(incoming)
    if incoming_normalized == "false_positive":
        return incoming_normalized
    if existing_normalized == "false_positive" and not explicit_override:
        return existing_normalized
    if explicit_override:
        return incoming_normalized
    return (
        incoming_normalized
        if VERIFICATION_DISPOSITION_RANK[incoming_normalized] >= VERIFICATION_DISPOSITION_RANK[existing_normalized]
        else existing_normalized
    )

def _raise_stale_finding_conflict() -> None:
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="finding changed since it was loaded; refetch and retry",
    )


# I-21 (clobber guard): the dedup UPSERT in ``_semantic_finding_match`` matches a
# net-new record onto an existing finding by the
# ``(defect_family + root_cause_key + auth_context + canonical_location)`` tuple
# (excluding ``merged``), NOT by slug. When that match lands on a load-bearing
# finding (already ``reported`` or ``active``) under a DIFFERENT slug, a silent
# overwrite destroys a reported finding. Refuse unless the caller named that
# exact existing slug — the ``--update <slug>`` CLI opt-in, or an explicit slug
# on the raw POST. ``draft`` (still being shaped) and ``false_positive`` /
# ``merged`` (intentionally sticky) stay outside the guard so the historical
# dedup upsert behavior is preserved for them. Mirrored CLI-side in
# ``record_finding.py`` so a CLI bypass cannot defeat this HTTP enforcement.
_CLOBBER_GUARDED_WORKFLOW_STATUSES: frozenset[WorkflowStatus] = frozenset(
    {WorkflowStatus.ACTIVE, WorkflowStatus.REPORTED}
)


def _raise_finding_clobber_conflict(
    existing: dict[str, Any],
    *,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
) -> None:
    existing_slug = str(existing.get("slug", ""))
    existing_status = _row_workflow_status(existing)
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"Refusing to clobber {existing_status} finding '{existing_slug}': this record's "
            f"dedup tuple (defect_family={defect_family!r}, root_cause_key={root_cause_key!r}, "
            f"auth_context={auth_context!r}, canonical_location={canonical_location!r}) matches "
            f"it under a different slug, and merging would silently overwrite a {existing_status} "
            f"finding. If this is a distinct sibling on the same root cause, give it a DISTINCT "
            f"root_cause_key/defect_family and attach it with "
            f"`vigil assess link-finding <new-slug> --root-cause {existing_slug}`; to "
            f"intentionally modify '{existing_slug}', re-record with --update {existing_slug} "
            f"(or POST with slug={existing_slug!r})."
        ),
    )


# D4 (kill re-mint guard): a KILLED (``false_positive``) finding is deliberately
# OUTSIDE the reported/active clobber-guard set above, and the sticky-FP coalesce
# (``_coalesce_workflow_status``) only fires on the EXACT dedup tuple. So two
# agents that express the SAME underlying defect at DIFFERENT canonical_locations
# — a source-line ``file:x:42`` vs a runtime endpoint URL — miss the tuple, and
# one silently RE-MINTS a finding the other already DISPROVED, with no flag.
# Guard it with a BROADER match than the exact tuple: same ``defect_family``
# (technique) AND a shared endpoint/canonical-location signal. Refuse-with-
# override — the operator either reopens the real prior kill with ``reset-finding``
# (the earlier kill was wrong), or forces an intentional distinct re-mint with
# ``--allow-remint`` / ``--force`` (a genuinely new finding that only coincidentally
# shares the endpoint + technique). ``merged`` stays out (it is a different concept
# — a duplicate folded elsewhere, reachable via its canonical target).
def _canonical_location_endpoint(location: str) -> str:
    """Normalize a canonical_location to a comparable endpoint signal.

    URL locations collapse to ``netloc + path`` (query/fragment/trailing-slash
    stripped) so ``/api/fetch?url=…`` and ``/api/fetch`` share a signal; ``file:``
    locations collapse to the file path (a trailing ``:line[:col]`` stripped) so two
    source findings in the same file share a signal; anything else compares by its
    stripped/lower-cased self. Empty in → empty out (an empty signal never matches).
    """
    text = (location or "").strip().lower()
    if not text:
        return ""
    if text.startswith(("http://", "https://")):
        parts = urlsplit(text)
        path = parts.path.rstrip("/")
        combined = f"{parts.netloc}{path}"
        return combined or text
    if text.startswith("file:"):
        segments = text[len("file:"):].split(":")
        while len(segments) > 1 and segments[-1].isdigit():
            segments.pop()
        return "file:" + ":".join(segments)
    return text


def _find_killed_remint_collision(
    connection,
    engagement_id: int,
    *,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
) -> dict[str, Any] | None:
    """Return a KILLED finding this net-new record would silently re-mint, or None.

    Broader than the exact dedup tuple: matches an existing ``false_positive``
    finding that shares the same (non-empty) ``defect_family`` AND either the exact
    tuple OR a shared endpoint/canonical-location signal. Same ``defect_family`` is
    REQUIRED so a genuinely-different vuln class at the same endpoint is NOT caught.
    """
    family = (defect_family or "").strip()
    if not family:
        # No technique to key on; the exact-tuple sticky-FP upsert (handled by the
        # normal ``_semantic_finding_match`` path) is the only backstop here.
        return None
    new_endpoint = _canonical_location_endpoint(canonical_location)
    rows = connection.execute(
        """
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ?
          AND status = 'false_positive'
        ORDER BY id ASC
        """,
        (engagement_id,),
    ).fetchall()
    for row in rows:
        existing = dict(row)
        if str(existing.get("defect_family") or "").strip() != family:
            continue
        exact_tuple = (
            str(existing.get("root_cause_key") or "") == (root_cause_key or "")
            and str(existing.get("auth_context") or "") == (auth_context or "")
            and str(existing.get("canonical_location") or "") == (canonical_location or "")
        )
        if exact_tuple:
            return existing
        existing_endpoint = _canonical_location_endpoint(
            str(existing.get("canonical_location") or "")
        )
        if new_endpoint and existing_endpoint and new_endpoint == existing_endpoint:
            return existing
    return None


def _raise_killed_remint_conflict(
    killed: dict[str, Any],
    *,
    defect_family: str,
    canonical_location: str,
) -> None:
    killed_slug = str(killed.get("slug", ""))
    killed_location = str(killed.get("canonical_location", ""))
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"Refusing to re-mint disproven finding '{killed_slug}': it was killed "
            f"(false_positive) for defect_family={defect_family!r} at canonical_location "
            f"{killed_location!r}, and this net-new record targets the SAME technique + "
            f"endpoint at {canonical_location!r} under a different location/slug — minting it "
            f"would silently resurrect a disproven finding as a fresh duplicate. If the earlier "
            f"kill was WRONG and this should re-open, run "
            f"`vigil assess reset-finding {killed_slug} --reason \"...\"`. If this is a genuinely "
            f"NEW finding that only coincidentally shares the endpoint + technique, re-record "
            f"with --allow-remint (a.k.a. --force) to override."
        ),
    )


# CR-31 (slug atomicity): the (engagement_id, slug) UNIQUE index in db.py is the
# hard DB-level backstop against two concurrent record-finding lanes minting the
# same auto-assigned slug (e.g. both VA-012). ``BEGIN IMMEDIATE`` serializes the
# MAX-scan + INSERT so the second lane normally sees the first's committed slug,
# but we still treat the constraint as authoritative: an auto-generated slug that
# collides is retried (recomputed against the now-larger MAX), never surfaced as
# an unhandled IntegrityError / HTTP 500. The retry cap bounds the loop so a
# genuinely stuck writer fails loudly instead of spinning.
_SLUG_INSERT_MAX_ATTEMPTS = 8


def _is_slug_unique_violation(exc: sqlite3.IntegrityError) -> bool:
    message = str(exc).lower()
    return "unique" in message and "slug" in message

def _finding_state_snapshot(row: dict[str, Any] | Any) -> dict[str, str]:
    if isinstance(row, dict):
        severity_value = row.get("severity", "info")
    else:
        severity_value = row["severity"]
    return {
        "workflow_status": _row_workflow_status(row),
        "verification_state": _row_verification_state(row),
        "verification_disposition": _row_verification_disposition(row),
        "severity": _normalize_severity(str(severity_value)),
    }

def _finding_state_changed(before: dict[str, str] | None, after: dict[str, str]) -> bool:
    if before is None:
        return True
    return any(before[key] != after[key] for key in after)

def _infer_transition_action(before: dict[str, str] | None, after: dict[str, str]) -> str:
    if before is None:
        return "created"
    if after["workflow_status"] == "merged" and before["workflow_status"] != "merged":
        return "workflow_merged"
    if after["workflow_status"] == "reported" and before["workflow_status"] != "reported":
        return "workflow_reported"
    if after["workflow_status"] == "blocked" and before["workflow_status"] != "blocked":
        return "workflow_blocked"
    if (
        after["verification_state"] == "verified"
        and after["verification_disposition"] == "false_positive"
        and (
            before["verification_disposition"] != "false_positive"
            or before["workflow_status"] != "false_positive"
        )
    ):
        return "verified_false_positive"
    if (
        before["workflow_status"] == "false_positive"
        or before["verification_disposition"] == "false_positive"
    ) and (
        after["workflow_status"] != "false_positive"
        and after["verification_disposition"] != "false_positive"
    ):
        return "operator_override"
    if after["verification_state"] == "disputed" and before["verification_state"] != "disputed":
        return "verification_disputed"
    if after["verification_disposition"] == "downgraded" and before["verification_disposition"] != "downgraded":
        return "verified_downgraded"
    if (
        after["verification_state"] == "verified"
        and after["verification_disposition"] == "confirmed"
        and (
            before["verification_state"] != "verified"
            or before["verification_disposition"] != "confirmed"
        )
    ):
        return "verified_confirmed"
    if (
        after["verification_disposition"] == "pending_runtime_proof"
        and before["verification_disposition"] != "pending_runtime_proof"
    ):
        return "verified_pending_runtime_proof"
    return "operator_override"

def _default_transition_reason(action: str, after: dict[str, str]) -> str:
    if action == "created":
        return "Finding created."
    if action == "verified_confirmed":
        return "Verification confirmed the finding."
    if action == "verified_pending_runtime_proof":
        return "Verification accepted static evidence; runtime proof outstanding."
    if action == "verified_downgraded":
        return "Verification downgraded the finding severity."
    if action == "verified_false_positive":
        return "Verification marked the finding as a false positive."
    if action == "verified_blocked":
        return "Verification recorded the finding as blocked-for-provisioning; held out of the report."
    if action == "verification_disputed":
        return "Verification disputed the current finding assessment."
    if action == "workflow_reported":
        return "Finding included in report output."
    if action == "workflow_merged":
        return "Finding merged into another canonical record."
    if action == "workflow_blocked":
        return "Finding workflow moved to blocked."
    return f"Finding state updated to {after['workflow_status']}."

def _record_finding_transition(
    connection,
    *,
    engagement_id: int,
    finding_id: int,
    actor: str,
    action: str,
    before: dict[str, str] | None,
    after: dict[str, str],
    reason_code: str,
    reason_text: str,
    artifact_ref: str,
    metadata: dict[str, Any] | None,
) -> dict[str, Any]:
    cursor = connection.execute(
        """
        INSERT INTO assessment_finding_transitions (
            engagement_id, finding_id, actor, action,
            from_workflow_status, to_workflow_status,
            from_verification_state, to_verification_state,
            from_verification_disposition, to_verification_disposition,
            from_severity, to_severity,
            reason_code, reason_text, artifact_ref, metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            finding_id,
            actor,
            action,
            None if before is None else before["workflow_status"],
            after["workflow_status"],
            None if before is None else before["verification_state"],
            after["verification_state"],
            None if before is None else before["verification_disposition"],
            after["verification_disposition"],
            None if before is None else before["severity"],
            after["severity"],
            reason_code,
            reason_text,
            artifact_ref,
            _json_text(metadata),
        ),
    )
    row = connection.execute("SELECT * FROM assessment_finding_transitions WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)

def _finding_slug(
    connection,
    engagement_id: int,
    slug: str | None,
    title: str,
    canonical_location: str,
    source_name: str,
) -> str:
    if slug:
        _require_canonical_finding_slug(slug, field="slug")
        return slug
    prefix = _FINDING_PREFIX_BY_SOURCE.get(str(source_name or "").strip())
    if not prefix:
        base = _slugify(f"{title}-{canonical_location}")
        candidate = base
        suffix = 2
        while connection.execute(
            "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, candidate),
        ).fetchone():
            candidate = f"{base}-{suffix}"
            suffix += 1
        return candidate
    rows = connection.execute(
        "SELECT slug FROM assessment_findings WHERE engagement_id = ? AND slug LIKE ?",
        (engagement_id, f"{prefix}-%"),
    ).fetchall()
    max_id = 0
    for row in rows:
        row_slug = str(row["slug"] or "")
        if is_canonical_finding_slug(row_slug) and row_slug.startswith(f"{prefix}-"):
            max_id = max(max_id, int(row_slug.rsplit("-", 1)[1]))
    return f"{prefix}-{max_id + 1:03d}"

def _ensure_finding_slugs_exist(connection, engagement_id: int, slugs: list[str] | None) -> None:
    if not slugs:
        return
    for slug in slugs:
        if not connection.execute(
            "SELECT 1 FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, slug),
        ).fetchone():
            raise _finding_not_found(connection, engagement_id, slug)

def _semantic_finding_match(
    connection,
    engagement_id: int,
    *,
    slug: str | None,
    defect_family: str,
    root_cause_key: str,
    canonical_location: str,
    auth_context: str,
    title: str,
) -> dict[str, Any] | None:
    if slug:
        row = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement_id, slug),
        ).fetchone()
        if row is not None:
            return dict(row)
    if defect_family and root_cause_key:
        row = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status != 'merged'
              AND defect_family = ?
              AND root_cause_key = ?
              AND auth_context = ?
              AND canonical_location = ?
            ORDER BY id ASC
            LIMIT 1
            """,
            (engagement_id, defect_family, root_cause_key, auth_context, canonical_location),
        ).fetchone()
        if row is not None:
            return dict(row)
    row = connection.execute(
        (
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
              AND status != 'merged'
              AND title = ?
              AND canonical_location = ?
              AND auth_context = ?
            """
            + (" AND defect_family = ?" if defect_family else "")
            + """
            ORDER BY CASE WHEN status = 'false_positive' THEN 0 ELSE 1 END, id ASC
            LIMIT 1
            """
        ),
        (
            (engagement_id, title, canonical_location, auth_context, defect_family)
            if defect_family
            else (engagement_id, title, canonical_location, auth_context)
        ),
    ).fetchone()
    return dict(row) if row is not None else None

def create_finding(
    engagement_id: int,
    *,
    slug: str | None,
    title: str,
    severity: str,
    workflow_status: str,
    verification_state: str,
    verification_disposition: str,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
    summary: str,
    evidence_ref: str,
    notes: str,
    source_name: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    evidence_type: str | None = None,
    submission_status: str | None = None,
    request_variant_id: int | None,
    service_id: int | None,
    surface_id: int | None,
    links: list[dict[str, Any]] | None,
    explicit_workflow_override: bool = False,
    explicit_submission_override: bool = False,
    explicit_verification_state_override: bool = False,
    explicit_verification_disposition_override: bool = False,
    explicit_severity_override: bool = False,
    allow_existing_noncanonical_slug: bool = False,
    allow_remint: bool = False,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    expected_row_version: int | None = None,
    notes_mode: str = "append",
    details_mode: str = "merge",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if slug:
        slug = str(slug).strip()
        if not allow_existing_noncanonical_slug:
            slug = _require_canonical_finding_slug(slug, field="slug")
    incoming_workflow_status = _normalize_workflow_status(workflow_status)
    incoming_verification_state = _normalize_verification_state(verification_state)
    incoming_verification_disposition = _normalize_verification_disposition(verification_disposition)
    incoming_severity = _normalize_severity(severity)
    # submission_status is its own axis: validate + default to 'none' on a true
    # INSERT. On an UPDATE (upsert match), only overwrite when the caller
    # explicitly set it — otherwise preserve the stored value so a re-record /
    # an unrelated workflow patch never clobbers external submission tracking.
    incoming_submission_status = _normalize_submission_status(submission_status)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = _semantic_finding_match(
            connection,
            engagement.id,
            slug=slug,
            defect_family=defect_family,
            root_cause_key=root_cause_key,
            canonical_location=canonical_location,
            auth_context=auth_context,
            title=title,
        )
        if existing is not None:
            # I-21: the operator "named" this exact finding only when the
            # incoming slug resolves to it (matched by slug in
            # ``_semantic_finding_match``'s first tier). A tuple/title dedup
            # match onto a DIFFERENT (or unnamed) slug is the silent-clobber
            # path — refuse it for load-bearing reported/active findings.
            named_existing_slug = bool(slug) and str(existing["slug"]) == slug
            if (
                not named_existing_slug
                and _row_workflow_status(existing) in _CLOBBER_GUARDED_WORKFLOW_STATUSES
            ):
                _raise_finding_clobber_conflict(
                    existing,
                    defect_family=defect_family,
                    root_cause_key=root_cause_key,
                    auth_context=auth_context,
                    canonical_location=canonical_location,
                )
        # D4: a true net-new INSERT (no slug/tuple/title match resolved ``existing``)
        # that nonetheless re-mints an already-DISPROVEN (false_positive) finding
        # under the broader technique+endpoint match is refused unless forced. Only
        # fires when ``existing is None`` — an exact-tuple upsert onto a sticky-FP,
        # an ``--update`` by slug, and a live active/reported dedup match all resolve
        # ``existing`` and are handled by the paths above, so this never disturbs the
        # existing sticky-FP coalesce or the reported/active clobber guard.
        if existing is None and not allow_remint:
            killed = _find_killed_remint_collision(
                connection,
                engagement.id,
                defect_family=defect_family,
                root_cause_key=root_cause_key,
                auth_context=auth_context,
                canonical_location=canonical_location,
            )
            if killed is not None:
                _raise_killed_remint_conflict(
                    killed,
                    defect_family=defect_family,
                    canonical_location=canonical_location,
                )
        # A ``blocked`` disposition REQUIRES a ``block_reason`` on the create/record
        # path too — not only via /verify. Without this guard, POST /findings with
        # verification_disposition='blocked' and no block_reason would 201 and then
        # be silently excluded from the report (report-readiness drops 'blocked'),
        # producing a reasonless, invisible finding. Mirror verify_finding's invariant
        # (the reason may arrive in this record's details OR already be on the finding).
        if incoming_verification_disposition == "blocked":
            _validate_blocked_verification_details(
                incoming_details=details or {},
                existing_details=(
                    _json_object(existing["details_json"]) if existing is not None else {}
                ),
            )
        before_state = _finding_state_snapshot(existing) if existing is not None else None
        if existing is None:
            # CR-31: allocate the slug + INSERT under the (engagement_id, slug)
            # UNIQUE backstop. An auto-assigned slug that loses a race recomputes
            # against the now-committed MAX and retries; a caller-supplied slug
            # that collides is a genuine duplicate → 409 (never a silent clobber
            # or an unhandled 500). ``slug`` truthy here means caller-supplied.
            caller_supplied_slug = bool(slug)
            cursor = None
            for attempt in range(_SLUG_INSERT_MAX_ATTEMPTS):
                resolved_slug = _finding_slug(connection, engagement.id, slug, title, canonical_location, source_name)
                try:
                    cursor = connection.execute(
                        """
                        INSERT INTO assessment_findings (
                            engagement_id, slug, title, severity, status, verification_state, verification_disposition, defect_family, root_cause_key, auth_context,
                            canonical_location, source_name, summary, evidence_ref, notes, details_json, provenance_json, evidence_type, submission_status
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            engagement.id,
                            resolved_slug,
                            title,
                            incoming_severity,
                            incoming_workflow_status,
                            incoming_verification_state,
                            incoming_verification_disposition,
                            defect_family,
                            root_cause_key,
                            auth_context,
                            canonical_location,
                            source_name,
                            summary,
                            evidence_ref,
                            notes,
                            _json_text(details),
                            _json_text(provenance),
                            evidence_type,
                            incoming_submission_status,
                        ),
                    )
                    break
                except sqlite3.IntegrityError as exc:
                    if not _is_slug_unique_violation(exc):
                        raise
                    if caller_supplied_slug:
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail=f"finding slug '{resolved_slug}' already exists for this engagement",
                        ) from exc
                    if attempt == _SLUG_INSERT_MAX_ATTEMPTS - 1:
                        # Should be unreachable under BEGIN IMMEDIATE serialization;
                        # surface loudly rather than spin or return a bad slug.
                        raise HTTPException(
                            status_code=status.HTTP_409_CONFLICT,
                            detail="could not allocate a unique finding slug; retry the record",
                        ) from exc
                    # Auto-assigned slug raced a concurrent insert; recompute.
                    continue
            assert cursor is not None
            row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (cursor.lastrowid,)).fetchone()
        else:
            if expected_row_version is not None and int(existing["row_version"]) != expected_row_version:
                _raise_stale_finding_conflict()
            existing_workflow = _row_workflow_status(existing)
            existing_verification_state = _row_verification_state(existing)
            existing_verification_disposition = _row_verification_disposition(existing)
            connection.execute(
                """
                UPDATE assessment_findings
                SET title = ?,
                    severity = ?,
                    status = ?,
                    verification_state = ?,
                    verification_disposition = ?,
                    defect_family = COALESCE(NULLIF(?, ''), defect_family),
                    root_cause_key = COALESCE(NULLIF(?, ''), root_cause_key),
                    auth_context = COALESCE(NULLIF(?, ''), auth_context),
                    canonical_location = COALESCE(NULLIF(?, ''), canonical_location),
                    source_name = COALESCE(NULLIF(?, ''), source_name),
                    summary = CASE WHEN ? = '' THEN summary ELSE ? END,
                    evidence_ref = COALESCE(NULLIF(?, ''), evidence_ref),
                    notes = ?,
                    details_json = ?,
                    provenance_json = ?,
                    evidence_type = COALESCE(?, evidence_type),
                    submission_status = COALESCE(?, submission_status),
                    last_seen_at = CURRENT_TIMESTAMP,
                    row_version = row_version + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND (? IS NULL OR row_version = ?)
                """,
                (
                    title,
                    incoming_severity if explicit_severity_override else _stronger_severity(existing["severity"], incoming_severity),
                    _coalesce_workflow_status(
                        existing_workflow,
                        incoming_workflow_status,
                        explicit_workflow_override=explicit_workflow_override,
                    ),
                    _coalesce_verification_state(
                        existing_verification_state,
                        incoming_verification_state,
                        explicit_override=explicit_verification_state_override,
                    ),
                    _coalesce_verification_disposition(
                        existing_verification_disposition,
                        incoming_verification_disposition,
                        explicit_override=explicit_verification_disposition_override,
                    ),
                    defect_family,
                    root_cause_key,
                    auth_context,
                    canonical_location,
                    source_name,
                    summary,
                    summary,
                    evidence_ref,
                    # Default appends (record-finding/verify-finding checkpoints);
                    # notes_mode="replace" overwrites so stale text can be scrubbed.
                    notes if notes_mode == "replace" else _common._append_notes(existing["notes"], notes),
                    # CR-31: details default-merge (so checkpoints accrete keys);
                    # details_mode="replace" overwrites the whole object so
                    # cross-contaminated/stale detail keys can be fully removed,
                    # not just shadowed (merge cannot delete keys). The CLI/API
                    # require details to be present when replace is requested, so
                    # this won't silently null an unspecified payload.
                    _json_text(details) if details_mode == "replace" else _merge_object_text(existing["details_json"], details),
                    _merge_object_text(existing["provenance_json"], provenance),
                    evidence_type,
                    # None => COALESCE preserves the stored submission_status; a
                    # value => an explicit operator override of the submission axis.
                    incoming_submission_status if explicit_submission_override else None,
                    existing["id"],
                    expected_row_version,
                    expected_row_version,
                ),
            )
            if connection.execute("SELECT changes()").fetchone()[0] != 1:
                _raise_stale_finding_conflict()
            row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (existing["id"],)).fetchone()
        assert row is not None
        finding = dict(row)
        after_state = _finding_state_snapshot(finding)
        derived_links = list(links or [])
        if request_variant_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "request_variant", "target_id": request_variant_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if service_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "service", "target_id": service_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if surface_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "surface", "target_id": surface_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if evidence_ref:
            derived_links.append({"link_kind": "evidence", "target_kind": "evidence_artifact", "target_id": None, "target_ref": evidence_ref, "notes": "", "provenance": provenance or {}})
        finding_links = [
            _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=finding["id"],
                link_kind=str(item.get("link_kind", "related")),
                target_kind=str(item.get("target_kind", "unknown")),
                target_id=item.get("target_id"),
                target_ref=str(item.get("target_ref", "")),
                notes=str(item.get("notes", "")),
                provenance=item.get("provenance"),
            )
            for item in derived_links
        ]
        transition = None
        if _finding_state_changed(before_state, after_state):
            action = transition_action or _infer_transition_action(before_state, after_state)
            actor = source_name or str((provenance or {}).get("agent_name", "") or (provenance or {}).get("verified_by", "") or (provenance or {}).get("reviewed_by", ""))
            transition = _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(finding["id"]),
                actor=actor,
                action=action,
                before=before_state,
                after=after_state,
                reason_code=transition_reason_code,
                reason_text=transition_reason_text or notes or _default_transition_reason(action, after_state),
                artifact_ref=transition_artifact_ref or evidence_ref,
                metadata=transition_metadata,
            )
    if evidence_ref:
        # NOTE (atomicity): this runs in a separate transaction from the finding
        # INSERT/UPDATE above, and intentionally so. ``_register_artifact_reference``
        # opens its OWN ``get_connection()`` to write the artifact-index row, and
        # the database is WAL (single writer); the nested connection inherits
        # sqlite3's default 5 s busy-timeout, so calling it inside the still-open
        # ``BEGIN IMMEDIATE`` finding transaction would block ~5 s and then hit
        # "database is locked". So the index write cannot be folded into the
        # finding transaction. The ``evidence_artifact_id`` back-fill below could in
        # principle ride the finding transaction, but only by registering the
        # artifact first; the registration is the uncloseable separate writer, and
        # the report-readiness ``finding_evidence_unindexed`` gate keys on the
        # presence of that index row (controlled by the registration), not on
        # ``evidence_artifact_id``. A crash after registration but before this
        # back-fill leaves ``evidence_artifact_id`` NULL but the artifact indexed,
        # which does NOT raise a false ``finding_evidence_unindexed`` and self-heals
        # on the next record/verify write. Keeping the back-fill separate here.
        artifact_id = _common._register_artifact_reference(
            engagement.id,
            evidence_ref,
            kind="evidence",
            producer_agent_role=source_name or None,
            related_finding_slug=str(finding["slug"]),
        )
        with _common.get_connection() as connection:
            connection.execute(
                """
                UPDATE assessment_findings
                SET evidence_artifact_id = ?
                WHERE id = ? AND row_version = ? AND evidence_ref = ?
                """,
                (
                    artifact_id,
                    int(finding["id"]),
                    int(finding["row_version"]),
                    str(finding["evidence_ref"]),
                ),
            )
            finding = connection.execute(
                "SELECT * FROM assessment_findings WHERE id = ?",
                (int(finding["id"]),),
            ).fetchone()
    for link in finding_links:
        if str(link.get("target_kind") or "") in {"evidence_artifact", "artifact"} and link.get("target_ref"):
            _common._register_artifact_reference(
                engagement.id,
                str(link.get("target_ref") or ""),
                kind="evidence",
                producer_agent_role=source_name or None,
                related_finding_slug=str(finding["slug"]),
            )
    return {
        "finding": _serialize_finding_record(finding),
        "links": finding_links,
        "transition": transition,
    }

def update_finding(
    engagement_id: int,
    *,
    slug: str,
    title: str,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_state: str | None = None,
    verification_disposition: str | None = None,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
    summary: str,
    evidence_ref: str,
    notes: str,
    source_name: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    evidence_type: str | None = None,
    submission_status: str | None = None,
) -> dict[str, Any]:
    # severity / workflow_status / verification_state / verification_disposition
    # are partial-update fields: ``None`` means "preserve the existing value".
    # Passing a value sets the matching ``explicit_*_override`` flag so the caller
    # can deliberately overwrite; ``None`` leaves the override False, and
    # ``create_finding`` then coalesces the (default) incoming value against the
    # semantically-matched existing row via ``_coalesce_*`` / ``_stronger_severity``
    # — i.e. the existing stronger/sticky value is preserved. The defaults below
    # therefore only take effect when there is NO existing finding to match (a true
    # create). Previously these were required ``str`` with no default, so the
    # ``is not None`` guards were always True and every call hard-overwrote the
    # lifecycle columns — silently downgrading confirmed/reported findings.
    result = create_finding(
        engagement_id,
        slug=slug,
        title=title,
        severity=severity if severity is not None else "info",
        workflow_status=workflow_status if workflow_status is not None else "draft",
        verification_state=verification_state if verification_state is not None else "unreviewed",
        verification_disposition=verification_disposition if verification_disposition is not None else "none",
        defect_family=defect_family,
        root_cause_key=root_cause_key,
        auth_context=auth_context,
        canonical_location=canonical_location,
        summary=summary,
        evidence_ref=evidence_ref,
        notes=notes,
        source_name=source_name,
        details=details,
        provenance=provenance,
        evidence_type=evidence_type,
        submission_status=submission_status,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_submission_override=submission_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
        allow_existing_noncanonical_slug=True,
    )
    return result["finding"]

def patch_finding(
    engagement_id: int,
    *,
    slug: str,
    title: str | None = None,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_state: str | None = None,
    verification_disposition: str | None = None,
    defect_family: str | None = None,
    root_cause_key: str | None = None,
    auth_context: str | None = None,
    canonical_location: str | None = None,
    summary: str | None = None,
    evidence_ref: str | None = None,
    notes: str | None = None,
    source_name: str | None = None,
    details: dict[str, Any] | None = None,
    provenance: dict[str, Any] | None = None,
    evidence_type: str | None = None,
    submission_status: str | None = None,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    allow_verification_mutation: bool = False,
    expected_row_version: int | None = None,
    notes_mode: str = "append",
    details_mode: str = "merge",
) -> dict[str, Any]:
    if notes_mode == "replace" and notes is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="notes_mode='replace' requires notes",
        )
    if details_mode == "replace" and details is None:
        # Replace overwrites the whole details object; without an explicit
        # details payload it would silently null the column. Reject (mirrors the
        # notes_mode='replace' guard).
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details_mode='replace' requires details",
        )

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()

    existing_workflow = _row_workflow_status(existing)
    existing_verification = _row_verification_state(existing)
    current_row_version = int(existing["row_version"])

    if not allow_verification_mutation:
        if verification_state is not None or verification_disposition is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="verification lifecycle changes must use POST /findings/{slug}/verify",
            )
        if workflow_status in {"false_positive", "merged"}:
            detail = (
                "false_positive workflow changes must use POST /findings/{slug}/verify"
                if workflow_status == "false_positive"
                else "merged workflow changes must use POST /findings/merge"
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
        if existing_workflow == "merged" and workflow_status is not None and workflow_status != "merged":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="merged findings cannot be reopened via patch",
            )
        if existing_workflow == "false_positive" and workflow_status is not None and workflow_status != "false_positive":
            verification_state = "unreviewed"
            verification_disposition = "none"
        elif existing_verification == "disputed" and workflow_status is not None:
            # CR-31 (clear-disputed): a `disputed` verdict previously could only
            # be cleared by the verifier re-issuing verify-finding (which lands
            # `verified`, not a re-queue). Let a specialist reopen via reset-finding
            # return it to `unreviewed`/`none` — re-queues for verification without
            # forcing a verdict. Only on an explicit workflow reopen, and only out
            # of `disputed` (does not touch verified/false_positive verdicts).
            verification_state = "unreviewed"
            verification_disposition = "none"
            if transition_action is None:
                transition_action = "verification_recleared"

    return create_finding(
        engagement.id,
        slug=slug,
        title=title if title is not None else str(existing["title"]),
        severity=severity if severity is not None else str(existing["severity"]),
        workflow_status=workflow_status if workflow_status is not None else _row_workflow_status(existing),
        verification_state=verification_state if verification_state is not None else _row_verification_state(existing),
        verification_disposition=verification_disposition if verification_disposition is not None else _row_verification_disposition(existing),
        defect_family=defect_family or "",
        root_cause_key=root_cause_key or "",
        auth_context=auth_context or "",
        canonical_location=canonical_location or "",
        summary="" if summary is None else summary,
        evidence_ref=evidence_ref or "",
        notes="" if notes is None else notes,
        source_name=source_name or "",
        details=details,
        provenance=provenance,
        evidence_type=evidence_type,
        submission_status=submission_status,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_submission_override=submission_status is not None,
        explicit_verification_state_override=verification_state is not None,
        explicit_verification_disposition_override=verification_disposition is not None,
        explicit_severity_override=severity is not None,
        allow_existing_noncanonical_slug=True,
        transition_action=transition_action,
        transition_reason_code=transition_reason_code,
        transition_reason_text=transition_reason_text,
        transition_artifact_ref=transition_artifact_ref,
        transition_metadata=transition_metadata,
        expected_row_version=(
            current_row_version if expected_row_version is None else expected_row_version
        ),
        notes_mode=notes_mode,
        details_mode=details_mode,
    )

# Documented (not hard-enforced) vocabulary for what a blocked finding is
# waiting on. hunting.md: unblock_requirements.kind names the class of the
# missing precondition; a light type check only — an unknown kind is NOT a 400
# (mirrors the free-text/forward-compatible posture of probe result_status).
_UNBLOCK_REQUIREMENT_KINDS = frozenset({"account", "line", "device", "credential", "access"})


def _validate_unblock_requirements(value: Any) -> None:
    """Light shape check for ``details.unblock_requirements`` on a blocked finding.

    Optional. When present it must be an object; ``kind`` (if present) must be a
    string, but its VALUE is not enum-enforced so a new kind does not require a
    backend redeploy. ``description`` / ``requested_from`` are advisory free-text.
    """
    if value is None:
        return
    if not isinstance(value, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details.unblock_requirements must be an object",
        )
    kind = value.get("kind")
    if kind is not None and not isinstance(kind, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details.unblock_requirements.kind must be a string",
        )


def _validate_blocked_verification_details(
    *,
    incoming_details: dict[str, Any],
    existing_details: dict[str, Any],
) -> None:
    """A ``blocked`` verification disposition REQUIRES a ``block_reason``.

    Mirrors the intel precedent (``intel._validate_cve_attempted_blocked``): the
    reason (why the exploit attempt could not even start) may arrive in this
    verify's ``details`` OR already exist on the finding, but it must be present
    (non-empty, <=500 chars) after the verify applies. This is a genuine
    validation invariant — a hard 400 — not an advisory heuristic.
    """
    block_reason = incoming_details.get("block_reason")
    if not (isinstance(block_reason, str) and block_reason.strip()):
        block_reason = existing_details.get("block_reason")
    if not isinstance(block_reason, str) or not block_reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details.block_reason is required when disposition='blocked'",
        )
    if len(block_reason) > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="details.block_reason exceeds 500 characters",
        )
    _validate_unblock_requirements(
        incoming_details.get("unblock_requirements", existing_details.get("unblock_requirements"))
    )


def verify_finding(
    engagement_id: int,
    *,
    slug: str,
    disposition: str,
    reason_code: str,
    reason_text: str,
    source_name: str,
    evidence_ref: str,
    notes: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    artifact_ref: str,
    new_severity: str | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if disposition == "disputed":
        normalized_disposition = "none"
    else:
        normalized_disposition = _normalize_verification_disposition(disposition)
    if normalized_disposition == "none" and disposition != "disputed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="verification disposition cannot be none")

    with _common.get_connection() as connection:
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()

    expected_row_version = int(existing["row_version"])
    existing_workflow = _row_workflow_status(existing)
    if existing_workflow == "merged":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="merged findings cannot be re-verified")
    target_workflow = existing_workflow if existing_workflow not in {"false_positive", "merged"} else "active"
    target_verification_state = "verified"
    target_severity = str(existing["severity"])
    transition_action = "verified_confirmed"
    transition_metadata: dict[str, Any] = {}
    details_payload = dict(details or {})

    if normalized_disposition == "downgraded":
        if not new_severity:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="downgraded verification requires new_severity")
        normalized_new_severity = _normalize_severity(new_severity)
        if SEVERITY_RANK[normalized_new_severity] >= SEVERITY_RANK[_normalize_severity(str(existing["severity"]))]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="new_severity must be lower than the current severity")
        target_severity = normalized_new_severity
        transition_action = "verified_downgraded"
        transition_metadata["previous_severity"] = _normalize_severity(str(existing["severity"]))
    elif normalized_disposition == "false_positive":
        if not details_payload.get("kill_reason") or details_payload.get("kill_check") is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="false_positive verification requires details.kill_reason and details.kill_check",
            )
        target_workflow = "false_positive"
        transition_action = "verified_false_positive"
    elif normalized_disposition == "blocked":
        # Blocked-for-provisioning (hunting.md): the attempt could not even start
        # (missing account/line/device/credential/access). Requires a
        # block_reason (present in this verify OR already on the finding). Marked
        # verified so it leaves the unreviewed DoD queue, but report-readiness /
        # the report projection exclude it on disposition ('blocked' is neither
        # confirmed nor downgraded), keeping it OUT of the report until unblocked.
        _validate_blocked_verification_details(
            incoming_details=details_payload,
            existing_details=_json_object(existing["details_json"]),
        )
        target_verification_state = "verified"
        transition_action = "verified_blocked"
    elif normalized_disposition == "confirmed":
        transition_action = "verified_confirmed"
    elif normalized_disposition == "pending_runtime_proof":
        # Analyst accepted the static/code evidence; only runtime proof is
        # outstanding. Mark verified so it leaves the unreviewed DoD queue while
        # report-readiness still excludes it on disposition (pending != confirmed
        # /downgraded), keeping it in the holding area until proven.
        target_verification_state = "verified"
        transition_action = "verified_pending_runtime_proof"
    else:
        target_verification_state = "disputed"
        normalized_disposition = "none"
        transition_action = "verification_disputed"

    result = patch_finding(
        engagement.id,
        slug=slug,
        severity=target_severity,
        workflow_status=target_workflow,
        verification_state=target_verification_state,
        verification_disposition=normalized_disposition,
        evidence_ref=evidence_ref or None,
        notes=notes,
        source_name=source_name or None,
        details=details_payload,
        provenance=provenance,
        transition_action=transition_action,
        transition_reason_code=reason_code,
        transition_reason_text=reason_text,
        transition_artifact_ref=artifact_ref or evidence_ref,
        transition_metadata=transition_metadata or None,
        allow_verification_mutation=True,
        expected_row_version=expected_row_version,
    )
    if artifact_ref:
        _common._register_artifact_reference(
            engagement.id,
            artifact_ref,
            kind="verification-artifact",
            producer_agent_role=source_name or None,
            related_finding_slug=slug,
        )
    return result

def merge_findings(
    engagement_id: int,
    *,
    source_slug: str,
    target_slug: str,
    reason: str,
    source_name: str,
    expected_source_row_version: int | None = None,
    expected_target_row_version: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        source = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, source_slug),
        ).fetchone()
        target = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, target_slug),
        ).fetchone()
        if source is None or target is None:
            missing = source_slug if source is None else target_slug
            raise _finding_not_found(connection, engagement.id, missing)
        if (
            expected_source_row_version is not None
            and int(source["row_version"]) != expected_source_row_version
        ) or (
            expected_target_row_version is not None
            and int(target["row_version"]) != expected_target_row_version
        ):
            _raise_stale_finding_conflict()
        if source["id"] == target["id"]:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="cannot merge a finding into itself")
        if _row_workflow_status(target) == "false_positive" and _row_workflow_status(source) != "false_positive":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot merge a live finding into a false_positive target",
            )
        source_children = connection.execute(
            """
            SELECT findings.slug
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS findings ON findings.id = links.finding_id
            WHERE links.engagement_id = ?
              AND links.link_kind = ?
              AND links.target_kind = 'finding'
              AND links.target_ref = ?
              AND findings.status != 'merged'
            """,
            (engagement.id, ROOT_CAUSE_LINK_KIND, source_slug),
        ).fetchall()
        if source_children:
            child_slugs = ", ".join(str(row["slug"]) for row in source_children)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cannot merge root cause {source_slug} while siblings remain linked: {child_slugs}",
            )
        source_root_link = connection.execute(
            """
            SELECT target_ref
            FROM assessment_finding_links
            WHERE engagement_id = ?
              AND finding_id = ?
              AND link_kind = ?
              AND target_kind = 'finding'
            LIMIT 1
            """,
            (engagement.id, int(source["id"]), ROOT_CAUSE_LINK_KIND),
        ).fetchone()
        if source_root_link is not None and str(source_root_link["target_ref"]) != target_slug:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"cannot merge sibling {source_slug} into {target_slug}; "
                    f"clear or relink its root cause first"
                ),
            )
        source_confidence = _finding_confidence_tuple(source)
        target_confidence = _finding_confidence_tuple(target)
        source_row_version = int(source["row_version"])
        target_row_version = int(target["row_version"])
        source_stronger = source_confidence > target_confidence
        source_workflow = _row_workflow_status(source)
        target_workflow = _row_workflow_status(target)
        source_verification_state = _row_verification_state(source)
        target_verification_state = _row_verification_state(target)
        source_verification_disposition = _row_verification_disposition(source)
        target_verification_disposition = _row_verification_disposition(target)
        source_before = _finding_state_snapshot(source)
        target_before = _finding_state_snapshot(target)
        merged_notes = _common._append_notes(
            _common._append_notes(target["notes"], f"Merged {source_slug}: {reason}"),
            source["notes"],
        )
        merged_details = _merge_object_text(target["details_json"], _json_object(source["details_json"]))
        merged_provenance_payload = _json_object(target["provenance_json"])
        merged_provenance_payload.update(_json_object(source["provenance_json"]))
        merged_provenance_payload["merge"] = {
            "source_slug": source_slug,
            "target_slug": target_slug,
            "reason": reason,
            "source_name": source_name,
        }
        source_links = connection.execute(
            "SELECT * FROM assessment_finding_links WHERE engagement_id = ? AND finding_id = ?",
            (engagement.id, source["id"]),
        ).fetchall()
        source_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'merged',
                verification_state = 'unreviewed',
                verification_disposition = 'none',
                merged_into_finding_id = ?,
                notes = ?,
                row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (target["id"], _common._append_notes(source["notes"], reason), source["id"], source_row_version),
        )
        if source_cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        target_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET severity = ?,
                status = ?,
                verification_state = ?,
                verification_disposition = ?,
                source_name = CASE
                    WHEN ? = '' THEN source_name
                    WHEN ? = 1 THEN ?
                    ELSE source_name
                END,
                summary = CASE
                    WHEN summary = '' THEN ?
                    WHEN ? = 1 AND ? != '' THEN ?
                    ELSE summary
                END,
                evidence_ref = CASE
                    WHEN evidence_ref = '' THEN ?
                    WHEN ? = 1 AND ? != '' THEN ?
                    ELSE evidence_ref
                END,
                notes = ?,
                details_json = ?,
                provenance_json = ?,
                row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP,
                last_seen_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (
                _stronger_severity(target["severity"], source["severity"]),
                (
                    target_workflow
                    if source_workflow == "false_positive" and target_workflow != "false_positive"
                    else _coalesce_workflow_status(target_workflow, source_workflow)
                ),
                (
                    target_verification_state
                    if source_workflow == "false_positive" and target_workflow != "false_positive"
                    else _coalesce_verification_state(target_verification_state, source_verification_state)
                ),
                (
                    target_verification_disposition
                    if source_verification_disposition == "false_positive"
                    and target_verification_disposition != "false_positive"
                    else _coalesce_verification_disposition(
                        target_verification_disposition,
                        source_verification_disposition,
                    )
                ),
                source["source_name"],
                1 if source_stronger else 0,
                source["source_name"],
                source["summary"],
                1 if source_stronger else 0,
                source["summary"],
                source["summary"],
                source["evidence_ref"],
                1 if source_stronger else 0,
                source["evidence_ref"],
                source["evidence_ref"],
                merged_notes,
                merged_details,
                _json_text(merged_provenance_payload),
                target["id"],
                target_row_version,
            ),
        )
        if target_cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        for row in source_links:
            if _is_root_cause_link(row):
                continue
            _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=target["id"],
                link_kind=row["link_kind"],
                target_kind=row["target_kind"],
                target_id=row["target_id"],
                target_ref=row["target_ref"],
                notes=row["notes"],
                provenance=_json_object(row["provenance_json"]),
            )
        connection.execute(
            "DELETE FROM assessment_finding_links WHERE engagement_id = ? AND finding_id = ?",
            (engagement.id, source["id"]),
        )
        link = _upsert_finding_link(
            connection,
            engagement.id,
            finding_id=target["id"],
            link_kind="merged_from",
            target_kind="finding",
            target_id=source["id"],
            target_ref=source_slug,
            notes=reason,
            provenance={"source_name": source_name},
        )
        source_row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (source["id"],)).fetchone()
        target_row = connection.execute("SELECT * FROM assessment_findings WHERE id = ?", (target["id"],)).fetchone()
        assert source_row is not None and target_row is not None
        source_after = _finding_state_snapshot(source_row)
        target_after = _finding_state_snapshot(target_row)
        if _finding_state_changed(source_before, source_after):
            _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(source["id"]),
                actor=source_name,
                action="workflow_merged",
                before=source_before,
                after=source_after,
                reason_code="merge",
                reason_text=reason,
                artifact_ref="",
                metadata={"target_slug": target_slug},
            )
        if _finding_state_changed(target_before, target_after):
            _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(target["id"]),
                actor=source_name,
                action="operator_override",
                before=target_before,
                after=target_after,
                reason_code="merge",
                reason_text=f"Merged {source_slug} into {target_slug}: {reason}",
                artifact_ref="",
                metadata={"source_slug": source_slug},
            )
    return {
        "source": _serialize_finding_record(source_row),
        "target": _serialize_finding_record(target_row),
        "link": link,
    }

def list_findings(
    engagement_id: int,
    *,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_state: str | None = None,
    verification_disposition: str | None = None,
    auth_context: str | None = None,
    source_name: str | None = None,
    slug: str | None = None,
    search: str | None = None,
    holding: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    where = ["findings.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if severity:
        where.append("LOWER(findings.severity) = LOWER(?)")
        params.append(severity)
    if workflow_status:
        where.append("LOWER(findings.status) = LOWER(?)")
        params.append(workflow_status)
    if verification_state:
        where.append("LOWER(findings.verification_state) = LOWER(?)")
        params.append(verification_state)
    if verification_disposition:
        where.append("LOWER(findings.verification_disposition) = LOWER(?)")
        params.append(verification_disposition)
    if auth_context:
        # Server-side drill-down for the coverage ledger: an operator pivots
        # from a host's verdict into "the authenticated findings on this host"
        # without pulling every finding to the client.
        where.append("LOWER(findings.auth_context) = LOWER(?)")
        params.append(auth_context)
    if source_name:
        where.append("LOWER(findings.source_name) = LOWER(?)")
        params.append(source_name)
    if slug:
        where.append("LOWER(findings.slug) = LOWER(?)")
        params.append(slug)
    if search:
        escaped = _escape_like(search.lower())
        needle = f"%{escaped}%"
        where.append(
            "("
            "LOWER(findings.slug) LIKE ? ESCAPE '\\' OR "
            "LOWER(findings.title) LIKE ? ESCAPE '\\' OR "
            "LOWER(findings.summary) LIKE ? ESCAPE '\\' OR "
            "LOWER(findings.canonical_location) LIKE ? ESCAPE '\\' OR "
            "LOWER(findings.source_name) LIKE ? ESCAPE '\\'"
            ")"
        )
        params.extend([needle, needle, needle, needle, needle])
    if holding:
        where.append(
            "("
            "LOWER(findings.evidence_type) = 'theoretical' OR "
            "LOWER(findings.verification_disposition) = 'pending_runtime_proof'"
            ")"
        )
    limit_sql = ""
    if limit is not None:
        limit_sql = " LIMIT ? OFFSET ?"
        params.extend([int(limit), int(offset)])
    with _common.get_connection() as connection:
        rows = connection.execute(
            f"""
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE {' AND '.join(where)}
            ORDER BY
                CASE findings.status
                    WHEN 'exploited' THEN 0
                    WHEN 'active' THEN 1
                    WHEN 'blocked' THEN 2
                    WHEN 'reported' THEN 3
                    WHEN 'draft' THEN 4
                    WHEN 'false_positive' THEN 5
                    WHEN 'merged' THEN 6
                    ELSE 7
                END,
                CASE findings.verification_state
                    WHEN 'verified' THEN 0
                    WHEN 'disputed' THEN 1
                    ELSE 2
                END,
                findings.updated_at DESC,
                findings.id DESC
            {limit_sql}
            """,
            tuple(params),
        ).fetchall()
    return [_serialize_finding_record(row) for row in rows]


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def get_finding(engagement_id: int, slug: str) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    slug = canonical_finding_alias(slug) or slug
    with _common.get_connection() as connection:
        row = connection.execute(
            """
            SELECT findings.*, merged.slug AS merged_into_slug
            FROM assessment_findings AS findings
            LEFT JOIN assessment_findings AS merged ON merged.id = findings.merged_into_finding_id
            WHERE findings.engagement_id = ? AND findings.slug = ?
            """,
            (engagement.id, slug),
        ).fetchone()
        if row is None:
            raise _finding_not_found(connection, engagement.id, slug)
    return _serialize_finding_record(row)

def list_exploit_candidates(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_findings
            WHERE engagement_id = ?
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()

    candidates: list[dict[str, Any]] = []
    for row in rows:
        record = _serialize_finding_record(row)
        workflow_status = record.get("workflow_status", "draft")
        if workflow_status in {"merged", "false_positive", "reported", "exploited"}:
            continue
        if record.get("verification_state") != "verified":
            continue
        if record.get("verification_disposition") not in {"confirmed", "downgraded"}:
            continue
        details = _json_object(record.get("details_json", "{}"))
        severity = _normalize_severity(str(record.get("severity", "info")))
        chain_required = details.get("chain_required") is True
        if SEVERITY_RANK[severity] < SEVERITY_RANK["medium"] and not chain_required:
            continue
        if chain_required and SEVERITY_RANK[severity] < SEVERITY_RANK["medium"]:
            candidate_reason = "verified_chain_required"
        else:
            candidate_reason = f"verified_{severity}"
        record["candidate_reason"] = candidate_reason
        record["chain_required"] = chain_required
        candidates.append(record)

    return sorted(
        candidates,
        key=lambda row: (
            {
                "verified_critical": 0,
                "verified_high": 1,
                "verified_medium": 2,
                "verified_chain_required": 3,
            }.get(str(row.get("candidate_reason", "")), 99),
            str(row.get("slug", "")),
        ),
    )

def list_finding_transitions(engagement_id: int, *, slug: str) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    slug = canonical_finding_alias(slug) or slug
    with _common.get_connection() as connection:
        finding = connection.execute(
            "SELECT id FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if finding is None:
            raise _finding_not_found(connection, engagement.id, slug)
        rows = connection.execute(
            """
            SELECT *
            FROM assessment_finding_transitions
            WHERE engagement_id = ? AND finding_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            (engagement.id, int(finding["id"])),
        ).fetchall()
    return [dict(row) for row in rows]
