from __future__ import annotations

import sqlite3
from collections.abc import Collection
from typing import Any
from urllib.parse import urlsplit

from fastapi import HTTPException, status

from ..code_security_policy import NATIVE_MEMORY_SAFETY_DEFECT_FAMILIES
from ..events import _engagement_or_404
from ..search import (
    canonical_finding_alias,
    is_canonical_finding_slug,
)
from . import _common, run_accounting
from ._common import (
    DUPLICATE_LINK_KIND,
    FINDING_NOTES_MAX_LENGTH,
    ROOT_CAUSE_LINK_KIND,
    SEVERITY_RANK,
    VERIFICATION_STATUSES,
    WORKFLOW_STATUS_RANK,
    WORKFLOW_STATUSES,
    SubmissionStatus,
    VerificationStatus,
    WorkflowStatus,
    _finding_confidence_tuple,
    _finding_not_found,
    _json_object,
    _json_text,
    _merge_object_text,
    _normalize_severity,
    _normalize_submission_status,
    _normalize_verification_status,
    _normalize_workflow_status,
    _require_canonical_finding_slug,
    _resolve_existing_finding_slug,
    _row_verification_status,
    _row_workflow_status,
    _serialize_finding_record,
    _slugify,
    _stronger_severity,
)
from .cvss import CvssVectorError, base_score
from .finding_details import (
    validate_finding_details,
    validate_stored_reply_sequence_identity,
)
from .links import (
    _active_finding_link,
    _invalidate_relationship_verification,
    _is_root_cause_link,
    _relationship_change,
    _upsert_finding_link,
)
from .proofs import (
    TERMINAL_VERIFICATION_STATUSES,
    proof_receipts_for_finding,
    record_finding_verification_evidence,
    verification_audit_by_transition,
    verification_audit_for_finding,
)

CODE_SNAPSHOT_PROVENANCE_KEY = "code_snapshot"
# Names the binding an audited relocation out of ``file:`` reserved rather than
# deleted — it is the record of which bytes were reviewed while the finding was a
# file finding.
SUPERSEDED_CODE_SNAPSHOT_PROVENANCE_KEY = "superseded_code_snapshot"
# WHO asserted the binding, and under which audited work. The gate proves the
# snapshot identity is well-formed and current for the repo; it cannot prove that
# THIS verifier read THESE bytes for THIS finding, so a binding copied verbatim
# from another finding satisfies it while attesting nothing — a laundered binding
# that is indistinguishable from a genuine one, which is strictly worse for the
# sealed-evidence guarantee than an honest refusal. This sibling block is stamped
# SERVER-SIDE on every write that asserts a binding, from identities the backend
# resolves itself, so the two cases stop looking alike.
CODE_SNAPSHOT_ATTESTATION_PROVENANCE_KEY = "code_snapshot_attestation"
_CODE_SNAPSHOT_WRITE_MODES = frozenset({"record", "patch", "verify"})
_VERIFICATION_MATERIAL_DETAIL_KEYS = frozenset(
    {
        "cwe_id",
        "cvss_score",
        "cvss_vector",
        "evidence",
        "exploitability",
        "impact",
        "proof",
    }
)


def is_file_finding(canonical_location: str) -> bool:
    return str(canonical_location or "").strip().startswith("file:")


def _code_snapshot_binding(
    provenance: dict[str, Any] | None,
    *,
    strict: bool,
) -> dict[str, Any] | None:
    payload = provenance or {}
    if CODE_SNAPSHOT_PROVENANCE_KEY not in payload:
        return None
    binding = payload.get(CODE_SNAPSHOT_PROVENANCE_KEY)
    valid = (
        isinstance(binding, dict)
        and type(binding.get("repo_id")) is int
        and binding["repo_id"] >= 1
        and type(binding.get("repo_generation")) is int
        and binding["repo_generation"] >= 1
        and isinstance(binding.get("source_manifest_digest"), str)
        and len(binding["source_manifest_digest"]) == 64
        and all(
            character in "0123456789abcdef"
            for character in binding["source_manifest_digest"]
        )
    )
    if not valid:
        if strict:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "provenance.code_snapshot requires positive integer repo_id and "
                    "repo_generation plus a lowercase SHA-256 source_manifest_digest"
                ),
            )
        return None
    return {
        "repo_id": int(binding["repo_id"]),
        "repo_generation": int(binding["repo_generation"]),
        "source_manifest_digest": str(binding["source_manifest_digest"]),
    }


def _resolve_dispatch_id(
    connection: sqlite3.Connection,
    engagement_id: int,
    agent_id: Any,
) -> int | None:
    """Resolve a claimed ``agent_id`` to a real dispatch row in this engagement.

    Resolved, never taken on trust: an id that names no dispatch yields ``None``,
    which is exactly the signal that the binding arrived outside audited work.
    """

    if not isinstance(agent_id, str) or not agent_id.strip():
        return None
    row = connection.execute(
        """
        SELECT id
        FROM assessment_dispatches
        WHERE engagement_id = ? AND agent_id = ?
        """,
        (engagement_id, agent_id.strip()),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _resolve_command_run_id(
    connection: sqlite3.Connection,
    engagement_id: int,
    command_run_id: Any,
) -> int | None:
    """Resolve a claimed command-run id to a real audited run in this engagement."""

    if type(command_run_id) is not int or command_run_id < 1:
        return None
    row = connection.execute(
        """
        SELECT id
        FROM assessment_command_runs
        WHERE id = ? AND engagement_id = ?
        """,
        (command_run_id, engagement_id),
    ).fetchone()
    return int(row["id"]) if row is not None else None


def _code_snapshot_attestation(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    incoming_provenance: dict[str, Any] | None,
    stored_provenance: dict[str, Any],
    finding_slug: str,
    source_name: str,
    write_mode: str,
) -> dict[str, Any]:
    """Build the attestation for a write that asserts a code-snapshot binding.

    Two things make a copied binding visible:

    * ``dispatch_id`` / ``command_run_id`` are RESOLVED against real rows rather
      than believed. A binding asserted outside any audited dispatch or run
      resolves to ``None`` on both and reads as unattested — which is the honest
      description of a claim with nothing behind it.
    * An incoming attestation naming a DIFFERENT finding is preserved as
      ``copied_from_finding_slug`` instead of being silently overwritten. Copying
      another finding's provenance is precisely the reported workaround, and it
      carries this block along with the binding it was meant to justify.
    """

    incoming = incoming_provenance or {}
    prior = incoming.get(CODE_SNAPSHOT_ATTESTATION_PROVENANCE_KEY)
    if not isinstance(prior, dict):
        prior = stored_provenance.get(CODE_SNAPSHOT_ATTESTATION_PROVENANCE_KEY)
    attestation: dict[str, Any] = {
        "finding_slug": finding_slug,
        "recorded_by": str(source_name or ""),
        "write_mode": write_mode,
        "agent_id": str(incoming.get("agent_id") or ""),
        "dispatch_id": _resolve_dispatch_id(
            connection, engagement_id, incoming.get("agent_id")
        ),
        "command_run_id": _resolve_command_run_id(
            connection, engagement_id, incoming.get("command_run_id")
        ),
        "at": _common._utcnow_iso_dispatch(),
    }
    if isinstance(prior, dict):
        prior_slug = str(prior.get("finding_slug") or "")
        if prior_slug and prior_slug != finding_slug:
            attestation["copied_from_finding_slug"] = prior_slug
    return attestation


def code_snapshot_attestation_status(
    finding: dict[str, Any] | sqlite3.Row,
) -> str:
    """How much the stored binding's attestation is worth.

    ``legacy`` is deliberately NOT a violation: rows written before the
    attestation existed carry no stamp and must stay readable and writable.
    """

    record = dict(finding)
    provenance = _finding_provenance(record)
    if CODE_SNAPSHOT_PROVENANCE_KEY not in provenance:
        return "not_applicable"
    attestation = provenance.get(CODE_SNAPSHOT_ATTESTATION_PROVENANCE_KEY)
    if not isinstance(attestation, dict):
        return "legacy"
    if attestation.get("copied_from_finding_slug"):
        return "copied"
    if attestation.get("dispatch_id") is None and attestation.get("command_run_id") is None:
        return "unattested"
    return "attested"


def _finding_provenance(record: dict[str, Any]) -> dict[str, Any]:
    provenance = record.get("provenance")
    if isinstance(provenance, dict):
        return provenance
    return _json_object(record.get("provenance_json", "{}"))


def _require_record_author_dispatch(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    existing: dict[str, Any] | sqlite3.Row | None,
    provenance: dict[str, Any] | None,
) -> str:
    """Return the immutable, engagement-local author for a record write."""

    incoming_author = (provenance or {}).get("agent_id")
    incoming_author = (
        incoming_author.strip() if isinstance(incoming_author, str) else ""
    )
    if existing is None:
        if not incoming_author:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "new findings require provenance.agent_id naming the authoring "
                    "dispatch; pass finding record --agent-id <Runtime Identity agent_id>"
                ),
            )
        if _resolve_dispatch_id(connection, engagement_id, incoming_author) is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"provenance.agent_id '{incoming_author}' does not resolve to a "
                    "dispatch in this engagement"
                ),
            )
        return incoming_author

    stored_value = _finding_provenance(dict(existing)).get("agent_id")
    stored_author = stored_value.strip() if isinstance(stored_value, str) else ""
    if not stored_author:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "this historical finding has no provenance.agent_id; repair it once "
                "with `vigil assess finding bind-author` before re-recording it"
            ),
        )
    if _resolve_dispatch_id(connection, engagement_id, stored_author) is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"stored provenance.agent_id '{stored_author}' does not resolve to a "
                "dispatch in this engagement; repair it once with "
                "`vigil assess finding bind-author` before re-recording it"
            ),
        )
    return stored_author


def _provenance_update_preserving_author(
    existing_provenance_json: Any,
    incoming: dict[str, Any] | None,
    *,
    reject_rebind: bool,
) -> dict[str, Any]:
    """Return mutable provenance without rebinding the finding's author."""

    payload = dict(incoming or {})
    incoming_author = str(payload.get("agent_id") or "").strip()
    stored_author = str(
        _json_object(existing_provenance_json).get("agent_id") or ""
    ).strip()
    if reject_rebind and incoming_author and incoming_author != stored_author:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="finding provenance.agent_id is immutable after creation",
        )
    payload.pop("agent_id", None)
    return payload


def load_code_repo_snapshot_states(
    connection: sqlite3.Connection,
    engagement_id: int,
) -> dict[int, dict[str, Any]]:
    """Load all repository identities once for batch finding classification."""

    return {
        int(row["id"]): dict(row)
        for row in connection.execute(
            """
            SELECT id, active_generation, source_manifest_digest,
                   source_snapshot_quality
            FROM code_repos
            WHERE engagement_id = ?
            """,
            (engagement_id,),
        ).fetchall()
    }


def finding_code_snapshot_status(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding: dict[str, Any] | sqlite3.Row,
    *,
    repo_states: dict[int, dict[str, Any]] | None = None,
) -> str:
    """Classify file-like or explicitly bound findings against verified source."""

    record = dict(finding)
    provenance = _finding_provenance(record)
    if CODE_SNAPSHOT_PROVENANCE_KEY not in provenance:
        return (
            "unbound"
            if is_file_finding(str(record.get("canonical_location", "")))
            else "not_applicable"
        )
    binding = _code_snapshot_binding(provenance, strict=False)
    if binding is None:
        return "stale"
    repo = (
        repo_states.get(binding["repo_id"])
        if repo_states is not None
        else connection.execute(
            """
            SELECT active_generation, source_manifest_digest, source_snapshot_quality
            FROM code_repos
            WHERE id = ? AND engagement_id = ?
            """,
            (binding["repo_id"], engagement_id),
        ).fetchone()
    )
    if repo is None:
        return "stale"
    if str(repo["source_snapshot_quality"]) != "verified":
        return "stale"
    if int(repo["active_generation"]) != binding["repo_generation"]:
        return "stale"
    if str(repo["source_manifest_digest"]) != binding["source_manifest_digest"]:
        return "stale"
    return "current"


def finding_has_current_code_snapshot(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding: dict[str, Any] | sqlite3.Row,
) -> bool:
    return finding_code_snapshot_status(connection, engagement_id, finding) == "current"


def _serialize_finding_with_code_snapshot_status(
    connection: sqlite3.Connection,
    engagement_id: int,
    finding: dict[str, Any] | sqlite3.Row,
    *,
    repo_states: dict[int, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    record = _serialize_finding_record(finding)
    validate_stored_reply_sequence_identity(
        record["details"], finding_slug=str(record.get("slug") or "")
    )
    record["code_snapshot_status"] = finding_code_snapshot_status(
        connection, engagement_id, record, repo_states=repo_states
    )
    # Beside the binding's currency, how much that binding is WORTH: the gate can
    # only prove the snapshot identity is current for the repo, never that this
    # verifier read these bytes for this finding.
    record["code_snapshot_attestation_status"] = code_snapshot_attestation_status(
        record
    )
    record["proof_receipts"] = proof_receipts_for_finding(
        connection, engagement_id, int(record["id"])
    )
    return record


def _require_current_code_snapshot(
    connection: sqlite3.Connection,
    engagement_id: int,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    binding = _code_snapshot_binding(provenance, strict=True)
    if binding is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "file findings require provenance.code_snapshot bound to the "
                "current verified repository snapshot"
            ),
        )
    repo = connection.execute(
        """
        SELECT active_generation, source_manifest_digest, source_snapshot_quality
        FROM code_repos
        WHERE id = ? AND engagement_id = ?
        """,
        (binding["repo_id"], engagement_id),
    ).fetchone()
    if repo is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="code snapshot repository is not part of this engagement",
        )
    if str(repo["source_snapshot_quality"]) != "verified":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="code snapshot repository is not a verified source snapshot",
        )
    if int(repo["active_generation"]) != binding["repo_generation"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="code snapshot repository generation is stale; refetch and re-review",
        )
    if str(repo["source_manifest_digest"]) != binding["source_manifest_digest"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="code snapshot source manifest digest is stale; refetch and re-review",
        )
    return binding



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

def _coalesce_verification_status(
    existing: str,
    incoming: str,
    *,
    explicit_override: bool = False,
) -> VerificationStatus:
    existing_normalized = _normalize_verification_status(existing)
    incoming_normalized = _normalize_verification_status(incoming)
    if explicit_override:
        return incoming_normalized
    return existing_normalized

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
            f"`vigil assess finding link <new-slug> --root-cause {existing_slug}`; to "
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
# override — the operator either reopens the real prior kill with ``finding update``
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


ORIGINAL_CANONICAL_LOCATION_PROVENANCE_KEY = "original_canonical_location"


def _normalize_file_location(
    connection: sqlite3.Connection,
    engagement_id: int,
    location: str,
    *,
    repo_id: int | None = None,
) -> str:
    """Re-emit a ``file:`` location repo-relative.

    ``canonical_location`` is the primary dedup key, and it was stored as
    author-supplied free text: ``file:<origin-root>/pkg/x.rb:12`` and
    ``file:pkg/x.rb:12`` describe one line of one file and collided in NOTHING —
    not the dedup tuple, not the title tier, not the killed-remint guard. The repo
    root is knowable at write time, so the normalisation was always available and
    simply never applied.

    Two properties keep it from misrouting, which matters because normalisation
    changes the dedup key:

    * The candidate prefix is a contiguous SUFFIX of a real repo root's path
      segments (longest first), so it strips the origin root the author echoed,
      not an arbitrary leading directory.
    * A one-segment candidate — the repo's own directory name — is accepted ONLY
      when the backend's file inventory corroborates it: the stripped form must
      name a known ``code_files`` path and the authored form must not. Without
      that, a repository whose directory happens to be called ``src`` would eat
      the ``src/`` of every correctly-authored path in it.

    Deliberately scoped to ``file:`` locations. URL locations keep their query
    strings, which the exact-tuple dedup tier depends on.
    """

    text = str(location or "").strip()
    if not text.startswith("file:"):
        return text
    body = text[len("file:"):].lstrip("/")
    while body.startswith("./"):
        body = body[2:]
    if not body:
        return text
    rows = connection.execute(
        """
        SELECT id, repo_path, source_origin_path
        FROM code_repos
        WHERE engagement_id = ?
        """,
        (engagement_id,),
    ).fetchall()
    candidates: list[tuple[int, str]] = []
    for row in rows:
        if repo_id is not None and int(row["id"]) != repo_id:
            continue
        for raw_root in (row["repo_path"], row["source_origin_path"]):
            segments = [part for part in str(raw_root or "").split("/") if part]
            for depth in range(len(segments), 0, -1):
                prefix = "/".join(segments[-depth:]) + "/"
                if body.startswith(prefix) and len(body) > len(prefix):
                    candidates.append((depth, prefix))
                    break
    if not candidates:
        return f"file:{body}"
    depth, prefix = max(candidates)
    stripped = body[len(prefix):]
    if depth == 1 and not _stripped_path_is_the_known_one(
        connection, engagement_id, body, stripped, repo_id=repo_id
    ):
        return f"file:{body}"
    return f"file:{stripped}"


def _file_path_only(location_body: str) -> str:
    """Drop a trailing ``:line[:col]`` so the body can be matched against a path."""

    segments = location_body.split(":")
    while len(segments) > 1 and segments[-1].isdigit():
        segments.pop()
    return ":".join(segments)


def _stripped_path_is_the_known_one(
    connection: sqlite3.Connection,
    engagement_id: int,
    body: str,
    stripped: str,
    *,
    repo_id: int | None,
) -> bool:
    """Does the ingested file inventory agree that ``stripped`` is the real path?"""

    params: list[Any] = [engagement_id, _file_path_only(body), _file_path_only(stripped)]
    repo_clause = ""
    if repo_id is not None:
        repo_clause = " AND repo_id = ?"
        params.append(int(repo_id))
    row = connection.execute(
        f"""
        SELECT
            SUM(CASE WHEN file_path = ? THEN 1 ELSE 0 END) AS authored,
            SUM(CASE WHEN file_path = ? THEN 1 ELSE 0 END) AS stripped
        FROM code_files
        WHERE engagement_id = ?{repo_clause}
        """,
        (params[1], params[2], params[0], *params[3:]),
    ).fetchone()
    if row is None:
        return False
    return int(row["stripped"] or 0) > 0 and int(row["authored"] or 0) == 0


def _duplicate_advisories(
    connection: sqlite3.Connection,
    engagement_id: int,
    *,
    finding_id: int,
    canonical_location: str,
    root_cause_key: str,
    details: dict[str, Any],
) -> list[dict[str, Any]]:
    """Siblings that were already FILED and this record probably duplicates.

    Advisory, never a refusal: a legitimate variant shares an endpoint with its
    root by definition, and the exact-tuple clobber guard already owns the refusal
    semantics. What was missing is any signal at all — ``root_cause_key`` is
    author-invented free text with no collision surface, so a rediscovery of an
    already-submitted defect landed silently beside it.
    """

    entry_point = str(details.get("entry_point", "") or "").strip()
    parameter = str(details.get("parameter", "") or "").strip()
    root_key = str(root_cause_key or "").strip()
    location = str(canonical_location or "").strip()
    rows = connection.execute(
        """
        SELECT slug, title, submission_status, submission_ref, canonical_location,
               root_cause_key, details_json
        FROM assessment_findings
        WHERE engagement_id = ?
          AND id != ?
          AND submission_status != 'none'
        ORDER BY id ASC
        """,
        (engagement_id, finding_id),
    ).fetchall()
    advisories: list[dict[str, Any]] = []
    for row in rows:
        sibling_details = _json_object(row["details_json"])
        reasons: list[str] = []
        if location and str(row["canonical_location"] or "").strip() == location:
            reasons.append("canonical_location")
        if root_key and str(row["root_cause_key"] or "").strip() == root_key:
            reasons.append("root_cause_key")
        if (
            entry_point
            and parameter
            and str(sibling_details.get("entry_point", "") or "").strip() == entry_point
            and str(sibling_details.get("parameter", "") or "").strip() == parameter
        ):
            reasons.append("entry_point+parameter")
        if not reasons:
            continue
        sibling_slug = str(row["slug"])
        advisories.append(
            {
                "slug": sibling_slug,
                "title": str(row["title"] or ""),
                "submission_status": str(row["submission_status"] or ""),
                "submission_ref": str(row["submission_ref"] or ""),
                "matched_on": reasons,
                "detail": (
                    f"{sibling_slug} is already submission_status="
                    f"'{row['submission_status']}' and matches on "
                    f"{', '.join(reasons)}. If this is the same defect, link it: "
                    f"`vigil assess finding link <slug> --link-kind {DUPLICATE_LINK_KIND} "
                    f"--target-kind finding --target-ref {sibling_slug}`."
                ),
            }
        )
    return advisories


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
            f"kill was WRONG and this should re-open, run `vigil assess finding update "
            f"{killed_slug} --status draft --reason \"...\"`. If this is a genuinely "
            f"NEW finding that only coincidentally shares the endpoint + technique, re-record "
            f"with --allow-remint (a.k.a. --force) to override."
        ),
    )


# CR-31 (slug atomicity): the (engagement_id, slug) UNIQUE index in db.py is the
# hard DB-level backstop against two concurrent finding record lanes minting the
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
        "verification_status": _row_verification_status(row),
        "severity": _normalize_severity(str(severity_value)),
    }

def _finding_state_changed(before: dict[str, str] | None, after: dict[str, str]) -> bool:
    if before is None:
        return True
    return any(before[key] != after[key] for key in after)


_NOTES_HISTORY_STATUS_KEY = "notes_history_status"
_NOTES_HISTORY_STATUSES = frozenset(
    {"recorded", "unchanged", "initial", "historical_gap"}
)


def _finding_content_snapshot(row: dict[str, Any] | Any) -> dict[str, str]:
    """The mutable CONTENT axes the lifecycle snapshot does not cover.

    A details / notes / canonical-location write moves none of the four lifecycle
    axes, so before this existed a details patch wrote no transition row at all
    and a clobbered key's prior value survived nowhere. Kept SEPARATE from
    ``_finding_state_snapshot`` so the lifecycle transition vocabulary and
    ``_infer_transition_action``'s inference stay exactly as they were.
    """

    if isinstance(row, dict):
        get = row.get
    else:
        def get(key: str, default: str = "") -> Any:
            return row[key] if key in row.keys() else default

    return {
        "canonical_location": str(get("canonical_location", "") or ""),
        "details_json": str(get("details_json", "{}") or "{}"),
        "notes": str(get("notes", "") or ""),
        # A rebind moves ONLY this. Without it in the snapshot, the one write
        # whose purpose is to change the source binding emitted no ledger row.
        "provenance_json": str(get("provenance_json", "{}") or "{}"),
    }

def _resolved_details(
    existing_details_json: str,
    details: dict[str, Any] | None,
    details_mode: str,
) -> str:
    """Apply the requested details mode to the stored column."""

    if details_mode == "replace":
        return _json_text(details)
    if details_mode == "append":
        return _common._append_object_text(existing_details_json, details, path="details")
    return _merge_object_text(existing_details_json, details)


def _verification_material_details_changed(
    existing_details_json: str,
    details: dict[str, Any] | None,
    details_mode: str,
) -> bool:
    if details is None or details_mode == "append":
        return False
    before = _json_object(existing_details_json)
    after = _json_object(
        _resolved_details(existing_details_json, details, details_mode)
    )
    return any(
        (key in before) != (key in after) or before.get(key) != after.get(key)
        for key in _VERIFICATION_MATERIAL_DETAIL_KEYS
    )


def _merge_replaces_verification_material_details(
    existing_details_json: str,
    merged_details: dict[str, Any],
) -> bool:
    """Report only changed or removed dependencies, never additive detail."""

    existing = _json_object(existing_details_json)
    return any(
        key in existing
        and (key not in merged_details or existing[key] != merged_details[key])
        for key in _VERIFICATION_MATERIAL_DETAIL_KEYS
    )


def _resolved_notes(
    existing_notes: str,
    incoming: str,
    notes_mode: str,
    *,
    slug: str,
) -> str:
    """Apply the requested notes mode, bounded where the field actually grows."""

    if notes_mode == "replace":
        return incoming
    if notes_mode == "rotate":
        # The prior text is preserved verbatim on the transition row this write
        # emits (``notes_before_json``), so the pointer is a real address rather
        # than a euphemism for a delete. This is the exit for a row whose notes
        # already exceed the append cap: it is the only mode that can shrink the
        # column without discarding what was there.
        pointer = (
            f"[notes rotated {_common._utcnow_iso_dispatch()}; the prior "
            f"{len(existing_notes)} characters are on this finding's transition "
            f"ledger \u2014 read them with `vigil assess finding history {slug}`]"
        )
        return _common._append_notes(
            pointer, incoming, max_length=FINDING_NOTES_MAX_LENGTH
        )
    return _common._append_notes(
        existing_notes, incoming, max_length=FINDING_NOTES_MAX_LENGTH
    )


def _validate_sent_reply_immutability(
    existing_details: dict[str, Any], effective_details: dict[str, Any]
) -> None:
    """Keep externally sent reply records immutable; corrections append."""
    before = existing_details.get("replies")
    after = effective_details.get("replies")
    before_rows = before if isinstance(before, list) else []
    after_rows = after if isinstance(after, list) else []
    after_by_seq = {
        row.get("seq"): row
        for row in after_rows
        if isinstance(row, dict) and type(row.get("seq")) is int
    }
    sent_by_seq = {
        row.get("seq"): row
        for row in before_rows
        if isinstance(row, dict)
        and type(row.get("seq")) is int
        and row.get("sent_status") == "sent"
    }
    for seq, sent in sent_by_seq.items():
        if after_by_seq.get(seq) != sent:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"sent reply seq {seq} is immutable; append a correction "
                    "version that references it"
                ),
            )
    for row in after_rows:
        if not isinstance(row, dict) or "corrects_seq" not in row:
            continue
        if (
            row.get("event_type") != "correction"
            or row.get("corrects_seq") not in sent_by_seq
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="a correction must reference an existing sent reply",
            )


def _infer_transition_action(before: dict[str, str] | None, after: dict[str, str]) -> str:
    if before is None:
        return "created"
    if after["workflow_status"] == "merged" and before["workflow_status"] != "merged":
        return "workflow_merged"
    if after["workflow_status"] == "reported" and before["workflow_status"] != "reported":
        return "workflow_reported"
    if after["workflow_status"] == "blocked" and before["workflow_status"] != "blocked":
        return "workflow_blocked"
    if after["verification_status"] == "false_positive" and (
        before["verification_status"] != "false_positive"
        or before["workflow_status"] != "false_positive"
    ):
        return "verified_false_positive"
    if (
        before["workflow_status"] == "false_positive"
        or before["verification_status"] == "false_positive"
    ) and (
        after["workflow_status"] != "false_positive"
        and after["verification_status"] != "false_positive"
    ):
        return "operator_override"
    if after["verification_status"] == "disputed" and before["verification_status"] != "disputed":
        return "verification_disputed"
    if after["verification_status"] == "downgraded" and before["verification_status"] != "downgraded":
        return "verified_downgraded"
    if after["verification_status"] == "confirmed" and before["verification_status"] != "confirmed":
        return "verified_confirmed"
    if (
        after["verification_status"] == "pending_runtime_proof"
        and before["verification_status"] != "pending_runtime_proof"
    ):
        return "verified_pending_runtime_proof"
    if after["verification_status"] == "blocked" and before["verification_status"] != "blocked":
        return "verified_blocked"
    if (
        after["verification_status"] == "unreviewed"
        and before["verification_status"] != "unreviewed"
    ):
        return "verification_invalidated"
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
    if action == "verification_invalidated":
        return "A material finding change invalidated the prior verification."
    if action == "workflow_reported":
        return "Finding included in report output."
    if action == "workflow_merged":
        return "Finding merged into another canonical record."
    if action == "workflow_blocked":
        return "Finding workflow moved to blocked."
    if action == "details_patched":
        return "Finding details/notes rewritten; prior content preserved on this transition."
    if action == "location_relocated":
        return "Finding canonical location relocated under review."
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
    before_content: dict[str, str] | None = None,
    after_content: dict[str, str] | None = None,
) -> dict[str, Any]:
    # Content history is recorded ONLY on the axes this write actually moved.
    # Notes are the exception to prefix-based compaction: every edit keeps the
    # complete before/after values, because a later rotation or rewrite may make
    # either side the only recoverable copy. Unchanged notes stay represented by
    # a small status marker rather than duplicating the finding on every
    # lifecycle transition.
    location_before = location_after = None
    details_before = details_after = None
    notes_before = notes_after = None
    notes_history_status = "historical_gap"
    if before_content is not None and after_content is not None:
        if before_content["canonical_location"] != after_content["canonical_location"]:
            location_before = before_content["canonical_location"]
            location_after = after_content["canonical_location"]
        if before_content["details_json"] != after_content["details_json"]:
            details_before = before_content["details_json"]
            details_after = after_content["details_json"]
        if before_content["notes"] != after_content["notes"]:
            notes_before = before_content["notes"]
            notes_after = after_content["notes"]
            notes_history_status = "recorded"
        else:
            notes_history_status = "unchanged"
    elif before_content is None and after_content is not None:
        notes_history_status = "initial"
    metadata_payload = dict(metadata or {})
    metadata_payload[_NOTES_HISTORY_STATUS_KEY] = notes_history_status
    cursor = connection.execute(
        """
        INSERT INTO assessment_finding_transitions (
            engagement_id, finding_id, actor, action,
            from_workflow_status, to_workflow_status,
            from_verification_status, to_verification_status,
            from_severity, to_severity,
            from_canonical_location, to_canonical_location,
            details_before_json, details_after_json,
            notes_before_json, notes_after_json,
            reason_code, reason_text, artifact_ref, metadata_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            finding_id,
            actor,
            action,
            None if before is None else before["workflow_status"],
            after["workflow_status"],
            None if before is None else before["verification_status"],
            after["verification_status"],
            None if before is None else before["severity"],
            after["severity"],
            location_before,
            location_after,
            details_before,
            details_after,
            notes_before,
            notes_after,
            reason_code,
            reason_text,
            artifact_ref,
            _json_text(metadata_payload),
        ),
    )
    row = connection.execute("SELECT * FROM assessment_finding_transitions WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)


def _invalidate_terminal_verification_for_relationship(
    connection,
    *,
    engagement_id: int,
    finding: dict[str, Any] | Any,
    actor: str,
    relationship_change: dict[str, Any] | None,
    record_transition: bool = True,
) -> tuple[dict[str, Any], bool]:
    """Invalidate a terminal verdict when its reviewed relationship graph moves."""
    finding_record = dict(finding)
    if (
        relationship_change is None
        or _row_verification_status(finding_record)
        not in TERMINAL_VERIFICATION_STATUSES
    ):
        return finding_record, False

    before_state = _finding_state_snapshot(finding_record)
    before_content = _finding_content_snapshot(finding_record)
    cursor = connection.execute(
        """
        UPDATE assessment_findings
        SET verification_status = 'unreviewed',
            row_version = row_version + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ? AND row_version = ?
        """,
        (
            engagement_id,
            int(finding_record["id"]),
            int(finding_record["row_version"]),
        ),
    )
    if cursor.rowcount != 1:
        _raise_stale_finding_conflict()
    updated = connection.execute(
        "SELECT * FROM assessment_findings WHERE id = ?",
        (int(finding_record["id"]),),
    ).fetchone()
    assert updated is not None
    updated_record = dict(updated)
    if record_transition:
        after_state = _finding_state_snapshot(updated_record)
        _record_finding_transition(
            connection,
            engagement_id=engagement_id,
            finding_id=int(updated_record["id"]),
            actor=actor or "operator",
            action="verification_invalidated",
            before=before_state,
            after=after_state,
            reason_code="relationship_changed",
            reason_text=(
                "A material finding relationship changed after terminal verification."
            ),
            artifact_ref="",
            metadata={
                "material_change": True,
                "relationship_change": relationship_change,
            },
            before_content=before_content,
            after_content=_finding_content_snapshot(updated_record),
        )
    return updated_record, True

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


# CVSS is a PAIR: the vector is the derivation and the score is its result. When
# they disagree, every downstream consumer that reads only one of them (severity
# banding, the submission export, the report render) states something the other
# half contradicts.
_CVSS_KEYS = ("cvss_score", "cvss_vector")
# CVSS scores are published to one decimal; anything closer than half a step is
# float noise, not an authoring error. Same threshold the readiness backstop uses.
_CVSS_SCORE_TOLERANCE = 0.05


def _cvss_pair_disagreement(details: dict[str, Any]) -> tuple[str, str] | None:
    """Describe how ``details``' CVSS pair contradicts itself, or ``None``.

    Returns ``(kind, message)`` where ``kind`` is ``vector_invalid``,
    ``score_not_numeric``, or ``score_mismatch``. Kept separate from the
    write-time gate so the same judgement can be REPORTED instead of enforced
    where refusing costs more than the contradiction — see ``merge_findings``.
    """
    vector = details.get("cvss_vector")
    if vector is None:
        return None
    try:
        computed = base_score(str(vector))
    except CvssVectorError as exc:
        return (
            "vector_invalid",
            f"details.cvss_vector '{vector}' is not a valid CVSS v3.1 base "
            f"vector: {exc}",
        )
    score = details.get("cvss_score")
    if score is None:
        return None
    try:
        stored = float(score)
    except (TypeError, ValueError):
        return (
            "score_not_numeric",
            f"details.cvss_score must be a number, got {score!r}",
        )
    if abs(stored - computed) >= _CVSS_SCORE_TOLERANCE:
        return (
            "score_mismatch",
            f"details.cvss_score={stored} disagrees with details.cvss_vector "
            f"'{vector}', which computes to {computed}; correct whichever of "
            "the two is wrong",
        )
    return None


def _validate_cvss_pair(
    authored_details: dict[str, Any], effective_details: dict[str, Any]
) -> None:
    """Reject a ``cvss_score`` that contradicts its own ``cvss_vector``, on write.

    ``authored_details`` is what this write actually CONTRIBUTES (the caller
    applies the same empty-value filter the merge write does, so a key whose
    value never lands is not authored); ``effective_details`` is the pair as it
    will be stored. The gate fires only when the write authors one of the two
    keys and judges the EFFECTIVE MERGED pair — so a patch supplying just a
    score is scored against the stored vector. Deliberately not "recompute and
    overwrite": a silent correction hides the authoring error that produced it.

    A write authoring neither key is never blocked, so a row that already holds
    a legacy mismatch stays editable — otherwise the mismatch would trap the
    very patch that fixes it. The ``cvss_vector_score_mismatch`` /
    ``cvss_vector_invalid`` report-readiness blockers remain the backstop for
    those pre-existing rows.
    """
    if not any(key in authored_details for key in _CVSS_KEYS):
        return
    problem = _cvss_pair_disagreement(effective_details)
    if problem is None:
        return
    kind, message = problem
    if kind == "vector_invalid" and "cvss_vector" not in authored_details:
        # The STORED vector was already broken; readiness owns it. Blocking here
        # would strand every later edit to the finding.
        return
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)


_CHAIN_KEYS = ("chain_required", "chain_rationale")


def _validate_chain_rationale_pair(
    authored_details: dict[str, Any], effective_details: dict[str, Any]
) -> None:
    """Reject ``chain_required=true`` with no ``chain_rationale`` behind it.

    ``chain_required`` is what parks a finding as meaningful only inside a
    chain: it keeps the finding out of the report and hands an exploit-developer
    pass the follow-up. Without the rationale, the park says nothing about WHICH
    chain step it enables, and the gap only surfaces at report time as a finding
    nobody can act on — so hold the two together where they are written, the way
    ``_validate_cvss_pair`` holds the CVSS pair together.

    Same scoping as that gate: it fires only when the write AUTHORS one of the
    two keys, and judges the EFFECTIVE MERGED pair — so a patch supplying just
    the flag is scored against the stored rationale, and a legacy row that
    already holds an unexplained flag stays editable by any write that does not
    touch the pair.
    """
    if not any(key in authored_details for key in _CHAIN_KEYS):
        return
    if effective_details.get("chain_required") is not True:
        return
    if str(effective_details.get("chain_rationale") or "").strip():
        return
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            "details.chain_required=true requires details.chain_rationale: name "
            "the chain step this finding enables and why its standalone impact "
            "is insufficient. Clear the flag, or supply the rationale in the "
            "same write."
        ),
    )


def create_finding(
    engagement_id: int,
    *,
    slug: str | None,
    title: str,
    severity: str,
    workflow_status: str,
    verification_status: str,
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
    submission_platform: str | None = None,
    submission_ref: str | None = None,
    submission_url: str | None = None,
    request_variant_id: int | None,
    service_id: int | None,
    surface_id: int | None,
    links: list[dict[str, Any]] | None,
    explicit_workflow_override: bool = False,
    explicit_submission_override: bool = False,
    explicit_verification_override: bool = False,
    explicit_severity_override: bool = False,
    allow_existing_noncanonical_slug: bool = False,
    allow_remint: bool = False,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    transition_actor: str = "",
    expected_row_version: int | None = None,
    notes_mode: str = "append",
    details_mode: str = "merge",
    code_snapshot_write_mode: str = "record",
    verification_proof_receipt_ids: list[int] | None = None,
    verification_counter_check: dict[str, Any] | None = None,
    verification_severity_variance: dict[str, Any] | None = None,
    verification_normal_severity_band: str | None = None,
    run_candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    canonical_location = str(canonical_location).strip()
    if code_snapshot_write_mode not in _CODE_SNAPSHOT_WRITE_MODES:
        raise ValueError(f"unknown code snapshot write mode: {code_snapshot_write_mode}")
    if slug:
        slug = str(slug).strip()
        if not allow_existing_noncanonical_slug:
            slug = _require_canonical_finding_slug(slug, field="slug")
    incoming_workflow_status = _normalize_workflow_status(workflow_status)
    incoming_verification_status = _normalize_verification_status(verification_status)
    incoming_severity = _normalize_severity(severity)
    # submission_status is its own axis: validate + default to 'none' on a true
    # INSERT. On an UPDATE (upsert match), only overwrite when the caller
    # explicitly set it — otherwise preserve the stored value so a re-record /
    # an unrelated workflow patch never clobbers external submission tracking.
    incoming_submission_status = _normalize_submission_status(submission_status)
    promoted_run_candidate: dict[str, Any] | None = None
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        incoming_binding = _code_snapshot_binding(provenance, strict=True)
        # Normalise BEFORE anything reads the location — the dedup match, the
        # category guards, and the re-mint guard all key on it, so normalising
        # afterwards would leave each of them comparing a different string.
        authored_canonical_location = canonical_location
        canonical_location = _normalize_file_location(
            connection,
            engagement.id,
            canonical_location,
            repo_id=(incoming_binding or {}).get("repo_id"),
        )
        if canonical_location != authored_canonical_location:
            # Keep what the author wrote; the audit trail should not be rewritten
            # by a normalisation the author never saw.
            provenance = {
                **(provenance or {}),
                ORIGINAL_CANONICAL_LOCATION_PROVENANCE_KEY: authored_canonical_location,
            }
        if code_snapshot_write_mode == "patch" and incoming_binding is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "provenance.code_snapshot is reserved and cannot be changed "
                    "by a generic finding patch"
                ),
            )
        if (
            is_file_finding(canonical_location)
            and code_snapshot_write_mode in {"record", "verify"}
        ) or incoming_binding is not None:
            incoming_binding = _require_current_code_snapshot(
                connection, engagement.id, provenance
            )
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
        if code_snapshot_write_mode == "record":
            record_author = _require_record_author_dispatch(
                connection,
                engagement.id,
                existing=existing,
                provenance=provenance,
            )
            if existing is None:
                provenance = {**(provenance or {}), "agent_id": record_author}
        provenance_for_storage = dict(provenance or {})
        if existing is not None:
            # ``provenance.agent_id`` names the finding's original author for
            # verifier-independence checks. A later write may carry its own
            # agent_id (notably a code-snapshot verifier attestation), but that
            # cannot retroactively become the finding author. Verify still
            # receives the unsanitized payload for its nested attestation below.
            provenance_for_storage = _provenance_update_preserving_author(
                existing["provenance_json"],
                provenance,
                reject_rebind=code_snapshot_write_mode != "verify",
            )
            existing_family = str(existing["defect_family"] or "").strip().lower()
            requested_family = str(defect_family or "").strip().lower()
            if (
                code_snapshot_write_mode in {"record", "patch"}
                and requested_family
                and requested_family != existing_family
                and existing_family in NATIVE_MEMORY_SAFETY_DEFECT_FAMILIES
                and _row_verification_status(existing) == "confirmed"
            ):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "ordinary finding mutation cannot relabel a verified/confirmed "
                        "memory-safety defect_family; preserve the confirmed record "
                        "until the verification lifecycle kills or merges it, then "
                        "record the corrected distinct finding"
                    ),
                )
            if code_snapshot_write_mode == "record" and is_file_finding(
                canonical_location
            ) != is_file_finding(str(existing["canonical_location"])):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "finding re-record cannot change canonical-location category "
                        "between file and non-file; disposition the stored finding and "
                        "record a separately reviewed destination finding"
                    ),
                )
            existing_binding = _code_snapshot_binding(
                _json_object(existing["provenance_json"]), strict=False
            )
            if (
                code_snapshot_write_mode == "record"
                and existing_binding != incoming_binding
                and (existing_binding is not None or incoming_binding is not None)
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "finding code snapshot binding differs from the stored binding; "
                        "re-review and use finding verify to rebind it"
                    ),
                )
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
        # A ``blocked`` status REQUIRES a ``block_reason`` on the create/record
        # path too — not only via /verify. Without this guard, POST /findings with
        # verification_status='blocked' and no block_reason would 201 and then
        # be silently excluded from the report (report-readiness drops 'blocked'),
        # producing a reasonless, invisible finding. Mirror verify_finding's invariant
        # (the reason may arrive in this record's details OR already be on the finding).
        if incoming_verification_status == "blocked":
            _validate_blocked_verification_details(
                incoming_details=details or {},
                existing_details=(
                    _json_object(existing["details_json"]) if existing is not None else {}
                ),
            )
        # Every finding write — record, `finding update` (patch_finding), and the
        # verify checkpoint — funnels through here, so this is the one layer that
        # can hold cvss_score and cvss_vector to each other at write time. What
        # the write AUTHORS has to be computed the same way the write itself
        # stores it, or a value that never lands would let pre-existing data
        # reject a patch that never touched the pair.
        if existing is None or details_mode == "replace":
            # Both store the payload verbatim (`_json_text(details)`).
            authored_details = dict(details or {})
            effective_details = authored_details
        elif details_mode == "append":
            # Append accretes, so every incoming key is authored (nothing is
            # dropped as an empty no-op the way merge drops it).
            authored_details = dict(details or {})
            effective_details = _json_object(
                _common._append_object_text(
                    existing["details_json"], details, path="details"
                )
            )
        else:
            # Merge mode drops empty incoming values, so an empty CVSS key is a
            # no-op, not an authoring act.
            authored_details = {
                key: value
                for key, value in (details or {}).items()
                if value not in (None, "", [], {})
            }
            effective_details = _json_object(
                _merge_object_text(existing["details_json"], details)
            )
        # The details allow-list moved SERVER-side here so no CLI can be a hole in
        # it again: `finding verify` skipped the client-side validator entirely,
        # which is how the adjudication keys and an out-of-range kill_check got
        # onto records that `finding update` then refused to maintain. Scoped to
        # the keys this write AUTHORS, and permissive for keys already stored, so
        # closing the door cannot strand what came through it.
        existing_details = (
            _json_object(existing["details_json"]) if existing is not None else {}
        )
        validate_finding_details(
            authored_details,
            already_stored_keys=frozenset(existing_details),
            existing_details=existing_details,
            effective_details=effective_details,
        )
        if (
            existing is not None
            and existing_details.get("replies") != effective_details.get("replies")
        ):
            _validate_sent_reply_immutability(
                existing_details, effective_details
            )
        _validate_submission_identity(
            incoming_status=incoming_submission_status,
            explicit_override=explicit_submission_override,
            existing=existing,
            submission_ref=submission_ref,
            authored_details=authored_details,
            effective_details=effective_details,
        )
        _validate_cvss_pair(authored_details, effective_details)
        _validate_chain_rationale_pair(authored_details, effective_details)
        before_state = _finding_state_snapshot(existing) if existing is not None else None
        before_content = (
            _finding_content_snapshot(existing) if existing is not None else None
        )
        # Verify is the ONLY path that can rebind a stale file finding, so it is
        # the one write whose caller needs the transition rather than the endpoint:
        # a rebind that silently changed nothing is otherwise indistinguishable
        # from one that worked. Captured before the UPDATE, surfaced on the write
        # envelope, and recorded in the ledger.
        code_snapshot_status_before: str | None = None
        if code_snapshot_write_mode == "verify" and existing is not None:
            code_snapshot_status_before = finding_code_snapshot_status(
                connection, engagement.id, existing
            )
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
                            engagement_id, slug, title, severity, status, verification_status, defect_family, root_cause_key, auth_context,
                            canonical_location, source_name, summary, evidence_ref, notes, details_json, provenance_json, evidence_type, submission_status,
                            submission_platform, submission_ref, submission_url
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            engagement.id,
                            resolved_slug,
                            title,
                            incoming_severity,
                            incoming_workflow_status,
                            incoming_verification_status,
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
                            submission_platform or "",
                            submission_ref or "",
                            submission_url or "",
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
            existing_verification_status = _row_verification_status(existing)
            connection.execute(
                """
                UPDATE assessment_findings
                SET title = ?,
                    severity = ?,
                    status = ?,
                    verification_status = ?,
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
                    submission_platform = COALESCE(?, submission_platform),
                    submission_ref = COALESCE(?, submission_ref),
                    submission_url = COALESCE(?, submission_url),
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
                    _coalesce_verification_status(
                        existing_verification_status,
                        incoming_verification_status,
                        explicit_override=explicit_verification_override,
                    ),
                    defect_family,
                    root_cause_key,
                    auth_context,
                    canonical_location,
                    source_name,
                    summary,
                    summary,
                    evidence_ref,
                    # Default appends (finding record/finding verify checkpoints);
                    # "replace" overwrites so stale text can be scrubbed, "rotate"
                    # banks the accumulated text on the transition ledger.
                    _resolved_notes(
                        str(existing["notes"] or ""),
                        notes,
                        notes_mode,
                        slug=str(existing["slug"]),
                    ),
                    # CR-31: details default-merge (so checkpoints accrete keys);
                    # details_mode="replace" overwrites the whole object so
                    # cross-contaminated/stale detail keys can be fully removed,
                    # not just shadowed (merge cannot delete keys). The CLI/API
                    # require details to be present when replace is requested, so
                    # this won't silently null an unspecified payload.
                    _resolved_details(existing["details_json"], details, details_mode),
                    _merge_object_text(
                        existing["provenance_json"], provenance_for_storage
                    ),
                    evidence_type,
                    # None => COALESCE preserves the stored submission_status; a
                    # value => an explicit operator override of the submission axis.
                    incoming_submission_status if explicit_submission_override else None,
                    # None => COALESCE preserves; the identity fields are only
                    # rewritten when the caller actually supplies them.
                    submission_platform,
                    submission_ref,
                    submission_url,
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
        # Stamped AFTER the row lands because the attestation names the finding it
        # justifies, and an auto-allocated slug is not known until the INSERT
        # returns. Only writes that actually asserted a binding are stamped, so a
        # patch that never touched provenance leaves a legacy row exactly as it
        # found it.
        if incoming_binding is not None:
            stored_provenance = _json_object(finding["provenance_json"])
            stored_provenance[CODE_SNAPSHOT_ATTESTATION_PROVENANCE_KEY] = (
                _code_snapshot_attestation(
                    connection,
                    engagement.id,
                    incoming_provenance=provenance,
                    stored_provenance=(
                        _json_object(existing["provenance_json"])
                        if existing is not None
                        else {}
                    ),
                    finding_slug=str(finding["slug"]),
                    source_name=source_name or transition_actor,
                    write_mode=code_snapshot_write_mode,
                )
            )
            connection.execute(
                "UPDATE assessment_findings SET provenance_json = ? WHERE id = ?",
                (_json_text(stored_provenance), int(finding["id"])),
            )
            finding["provenance_json"] = _json_text(stored_provenance)
        code_snapshot_status = finding_code_snapshot_status(
            connection, engagement.id, finding
        )
        if code_snapshot_status_before is not None:
            transition_metadata = {
                **(transition_metadata or {}),
                "code_snapshot_status_before": code_snapshot_status_before,
                "code_snapshot_status_after": code_snapshot_status,
            }
        verification_evidence_requested = any(
            (
                verification_proof_receipt_ids,
                verification_counter_check is not None,
                verification_severity_variance is not None,
            )
        )
        duplicate_advisories = _duplicate_advisories(
            connection,
            engagement.id,
            finding_id=int(finding["id"]),
            canonical_location=str(finding["canonical_location"] or ""),
            root_cause_key=str(finding["root_cause_key"] or ""),
            details=_json_object(finding["details_json"]),
        )
        derived_links = list(links or [])
        if request_variant_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "request_variant", "target_id": request_variant_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if service_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "service", "target_id": service_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if surface_id is not None:
            derived_links.append({"link_kind": "related", "target_kind": "surface", "target_id": surface_id, "target_ref": "", "notes": "", "provenance": provenance or {}})
        if evidence_ref:
            derived_links.append({
                "link_kind": "evidence",
                "target_kind": "evidence_artifact",
                "target_id": None,
                "target_ref": evidence_ref,
                "notes": "",
                "provenance": provenance or {},
                # ``evidence_ref`` is already part of the finding mutation
                # contract. Treating its automatically mirrored index link as a
                # second relationship mutation would invalidate a terminal
                # verdict during the verification write that establishes it,
                # and would defeat sticky false-positive rediscovery. An
                # explicitly authored evidence link still uses the relationship
                # invalidation lifecycle.
                "implicit_evidence_ref": True,
            })
        finding_links: list[dict[str, Any]] = []
        relationship_changes: list[dict[str, Any]] = []
        for item in derived_links:
            link_kind = str(item.get("link_kind", "related"))
            target_kind = str(item.get("target_kind", "unknown"))
            target_id = item.get("target_id")
            target_ref = str(item.get("target_ref", ""))
            if target_kind == "finding" and target_ref:
                target_ref = _resolve_existing_finding_slug(
                    connection,
                    engagement.id,
                    target_ref,
                    field="target_ref",
                )
            before_link = _active_finding_link(
                connection,
                engagement.id,
                finding_id=int(finding["id"]),
                link_kind=link_kind,
                target_kind=target_kind,
                target_id=target_id,
                target_ref=target_ref,
            )
            link = _upsert_finding_link(
                connection,
                engagement.id,
                finding_id=int(finding["id"]),
                link_kind=link_kind,
                target_kind=target_kind,
                target_id=target_id,
                target_ref=target_ref,
                notes=str(item.get("notes", "")),
                provenance=item.get("provenance"),
            )
            finding_links.append(link)
            change = _relationship_change(
                operation="created",
                before=before_link,
                after=link,
            )
            if change is not None and not item.get("implicit_evidence_ref"):
                relationship_changes.append(change)
        if existing is not None and relationship_changes:
            relationship_change = (
                relationship_changes[0]
                if len(relationship_changes) == 1
                else {"operation": "recorded", "changes": relationship_changes}
            )
            finding, relationship_invalidated = _invalidate_relationship_verification(
                connection,
                engagement_id=engagement.id,
                finding=finding,
                actor=transition_actor or source_name or "operator",
                relationship_change=relationship_change,
                record_transition=False,
            )
            if relationship_invalidated:
                transition_action = "verification_invalidated"
                transition_reason_code = "relationship_changed"
                transition_reason_text = (
                    "A material finding relationship changed after terminal verification."
                )
                transition_metadata = {
                    **(transition_metadata or {}),
                    "material_change": True,
                    "relationship_change": relationship_change,
                }
        after_state = _finding_state_snapshot(finding)
        after_content = _finding_content_snapshot(finding)
        terminal_verification_asserted = (
            after_state["verification_status"] in TERMINAL_VERIFICATION_STATUSES
            and (
                before_state is None
                or before_state["verification_status"]
                != after_state["verification_status"]
            )
        )
        if terminal_verification_asserted and not verification_evidence_requested:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "terminal verification must use the verification endpoint with "
                    "independent proof_receipt_ids"
                ),
            )
        transition = None
        lifecycle_changed = _finding_state_changed(before_state, after_state)
        # A pure details / notes / location rewrite moves no lifecycle axis, so
        # without this branch it wrote NO ledger row and the clobbered value was
        # unrecoverable. The row is what makes `finding history` able to answer
        # "what did this key say before".
        content_changed = (
            before_content is not None
            and after_content is not None
            and before_content != after_content
        )
        if lifecycle_changed or content_changed or verification_evidence_requested:
            action = transition_action or (
                _infer_transition_action(before_state, after_state)
                if lifecycle_changed
                else "details_patched"
            )
            actor = transition_actor or source_name or str(
                (provenance or {}).get("agent_name", "")
                or (provenance or {}).get("verified_by", "")
                or (provenance or {}).get("reviewed_by", "")
            )
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
                before_content=before_content,
                after_content=after_content,
            )
        verification_evidence = {
            "proof_receipts": [],
            "counter_check": None,
            "severity_variance": None,
        }
        if verification_evidence_requested:
            assert transition is not None
            verification_evidence = record_finding_verification_evidence(
                connection,
                engagement_id=engagement.id,
                finding=finding,
                transition_id=int(transition["id"]),
                verification_status=after_state["verification_status"],
                proof_receipt_ids=list(verification_proof_receipt_ids or []),
                counter_check=verification_counter_check,
                severity_variance=verification_severity_variance,
                normal_severity_band=verification_normal_severity_band,
            )
        else:
            verification_evidence["proof_receipts"] = proof_receipts_for_finding(
                connection, engagement.id, int(finding["id"])
            )
        if run_candidate is not None:
            promoted_run_candidate = run_accounting.promote_run_candidate_with_connection(
                connection,
                engagement_id=engagement.id,
                run_id=int(run_candidate["run_id"]),
                candidate_id=int(run_candidate["candidate_id"]),
                finding_slug=str(finding["slug"]),
                reason=str(run_candidate["reason"]),
                proof_receipt_ids=list(run_candidate["proof_receipt_ids"]),
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
    # The write envelope carries the snapshot standing too — it used to be on 2 of
    # 9 finding projections, which is what made a rebind unreadable at the one verb
    # whose purpose is to move it. Reuses the status computed inside the
    # transaction; the optional evidence-artifact back-fill above cannot change it.
    record = _serialize_finding_record(finding)
    record["code_snapshot_status"] = code_snapshot_status
    record["code_snapshot_attestation_status"] = code_snapshot_attestation_status(
        record
    )
    record["proof_receipts"] = verification_evidence["proof_receipts"]
    if code_snapshot_status_before is not None:
        record["code_snapshot_status_before"] = code_snapshot_status_before
    return {
        "finding": record,
        "links": finding_links,
        "transition": transition,
        # Always present so a caller can read it unconditionally; empty on a clean
        # record. A backstop for the CLI-side preflight, so a raw POST is warned too.
        "duplicate_advisories": duplicate_advisories,
        "run_candidate": promoted_run_candidate,
        **verification_evidence,
    }

def update_finding(
    engagement_id: int,
    *,
    slug: str,
    title: str,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_status: str | None = None,
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
    # Severity / workflow_status / verification_status
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
        verification_status=verification_status if verification_status is not None else "unreviewed",
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
        explicit_verification_override=verification_status is not None,
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
    verification_status: str | None = None,
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
    submission_platform: str | None = None,
    submission_ref: str | None = None,
    submission_url: str | None = None,
    transition_action: str | None = None,
    transition_reason_code: str = "",
    transition_reason_text: str = "",
    transition_artifact_ref: str = "",
    transition_metadata: dict[str, Any] | None = None,
    allow_verification_mutation: bool = False,
    expected_row_version: int | None = None,
    notes_mode: str = "append",
    details_mode: str = "merge",
    verification_proof_receipt_ids: list[int] | None = None,
    verification_counter_check: dict[str, Any] | None = None,
    verification_severity_variance: dict[str, Any] | None = None,
    verification_normal_severity_band: str | None = None,
) -> dict[str, Any]:
    if canonical_location is not None:
        canonical_location = str(canonical_location).strip()
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
    if (
        notes_mode in {"replace", "rotate"} or details_mode == "replace"
    ) and (type(expected_row_version) is not int or expected_row_version < 1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="replacement modes require a positive expected_row_version",
        )

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()

    existing_workflow = _row_workflow_status(existing)
    existing_verification = _row_verification_status(existing)
    current_row_version = int(existing["row_version"])

    if canonical_location is not None and is_file_finding(
        canonical_location
    ) != is_file_finding(str(existing["canonical_location"])):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "generic finding patch cannot change canonical-location category "
                "between file and non-file; re-record and review the finding through "
                "the destination workflow"
            ),
        )

    if not allow_verification_mutation:
        if verification_status is not None:
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
            verification_status = "unreviewed"
        elif existing_verification == "disputed" and workflow_status is not None:
            # CR-31 (clear-disputed): a `disputed` verdict previously could only
            # be cleared by the verifier re-issuing finding verify (which lands
            # `verified`, not a re-queue). Let a specialist reopen via finding update
            # return it to `unreviewed` — re-queues for verification without
            # forcing a verdict. Only on an explicit workflow reopen, and only out
            # of `disputed` (does not touch verified/false_positive verdicts).
            verification_status = "unreviewed"
            if transition_action is None:
                transition_action = "verification_recleared"

        material_change = any(
            (
                severity is not None and _normalize_severity(severity) != str(existing["severity"]),
                defect_family is not None and defect_family != str(existing["defect_family"]),
                root_cause_key is not None and root_cause_key != str(existing["root_cause_key"]),
                auth_context is not None and auth_context != str(existing["auth_context"]),
                canonical_location is not None
                and canonical_location != str(existing["canonical_location"]),
                summary is not None and summary != str(existing["summary"]),
                evidence_ref is not None and evidence_ref != str(existing["evidence_ref"]),
                _verification_material_details_changed(
                    str(existing["details_json"]), details, details_mode
                ),
            )
        )
        verification_invalidated = (
            material_change and existing_verification != "unreviewed"
        )
        if verification_invalidated:
            verification_status = "unreviewed"
            transition_action = "verification_invalidated"
            transition_metadata = {
                **(transition_metadata or {}),
                "material_change": True,
            }
    else:
        verification_invalidated = False

    result = create_finding(
        engagement.id,
        slug=slug,
        title=title if title is not None else str(existing["title"]),
        severity=severity if severity is not None else str(existing["severity"]),
        workflow_status=workflow_status if workflow_status is not None else _row_workflow_status(existing),
        verification_status=verification_status if verification_status is not None else _row_verification_status(existing),
        defect_family=defect_family or "",
        root_cause_key=root_cause_key or "",
        auth_context=auth_context or "",
        canonical_location=(
            str(existing["canonical_location"])
            if canonical_location is None
            else canonical_location
        ),
        summary="" if summary is None else summary,
        evidence_ref=evidence_ref or "",
        notes="" if notes is None else notes,
        # Discovery attribution is immutable on patch. ``source_name`` names
        # the mutation actor and is retained in transition audit when state changes.
        source_name="",
        details=details,
        provenance=provenance,
        evidence_type=evidence_type,
        submission_status=submission_status,
        submission_platform=submission_platform,
        submission_ref=submission_ref,
        submission_url=submission_url,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=None,
        explicit_workflow_override=workflow_status is not None,
        explicit_submission_override=submission_status is not None,
        explicit_verification_override=verification_status is not None,
        explicit_severity_override=severity is not None,
        allow_existing_noncanonical_slug=True,
        transition_action=transition_action,
        transition_reason_code=transition_reason_code,
        transition_reason_text=transition_reason_text,
        transition_artifact_ref=transition_artifact_ref,
        transition_metadata=transition_metadata,
        transition_actor=source_name,
        expected_row_version=(
            current_row_version if expected_row_version is None else expected_row_version
        ),
        notes_mode=notes_mode,
        details_mode=details_mode,
        code_snapshot_write_mode=(
            "verify" if allow_verification_mutation else "patch"
        ),
        verification_proof_receipt_ids=verification_proof_receipt_ids,
        verification_counter_check=verification_counter_check,
        verification_severity_variance=verification_severity_variance,
        verification_normal_severity_band=verification_normal_severity_band,
    )
    result["finding"]["verification_invalidated"] = verification_invalidated
    return result

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


_UNTESTABILITY_MARKERS: tuple[str, ...] = (
    "could not",
    "couldn't",
    "no second organization",
    "no test account",
    "unable to provision",
    "not testable",
    "untestable",
    "fixture unbuildable",
    "no identity",
    "lacked",
    "unavailable",
)


def _validate_kill_names_a_settling_test(
    *,
    incoming_details: dict[str, Any],
    existing_details: dict[str, Any],
) -> None:
    """Keep unrun experiments out of the false-positive terminal state."""

    kill_reason = incoming_details.get("kill_reason")
    if not (isinstance(kill_reason, str) and kill_reason.strip()):
        kill_reason = existing_details.get("kill_reason")
    if not isinstance(kill_reason, str) or not any(
        marker in kill_reason.lower() for marker in _UNTESTABILITY_MARKERS
    ):
        return

    followup = incoming_details.get("required_followup")
    if followup is None:
        followup = existing_details.get("required_followup")
    if isinstance(followup, list) and any(
        isinstance(item, str) and item.strip() for item in followup
    ):
        return

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=(
            "this kill_reason says the experiment could not be run, which is "
            "`blocked`, not `false_positive`. Either re-verify with "
            "`--status blocked --details-inline '{\"block_reason\": \"...\"}'`, "
            "or name the test that would settle it in "
            "details.required_followup (a non-empty list of strings)."
        ),
    )


def _validate_submission_identity(
    *,
    incoming_status: str,
    explicit_override: bool,
    existing: Any,
    submission_ref: str | None,
    authored_details: dict[str, Any],
    effective_details: dict[str, Any],
) -> None:
    """A non-``none`` submission status must name the report it refers to.

    Enforced on a NEW TRANSITION only — the write that actually moves the axis —
    never on every patch. A hard requirement on any patch would freeze exactly the
    legacy rows that need backfilling: they already carry a status with no ref, so
    an unrelated workflow patch would become unwritable.

    ``withdrawn`` additionally requires a reason. It is the one status that
    asserts a RESEARCHER action rather than a program decision, so the record has
    to say why; mirrors ``block_reason`` in accepting a reason already stored.
    """

    stored_status = (
        _normalize_submission_status(existing["submission_status"])
        if existing is not None
        else SubmissionStatus.NONE
    )
    # On a true INSERT the incoming value always lands; on an upsert it lands only
    # when the caller explicitly set the axis (otherwise COALESCE preserves the
    # stored one). Compute what this write actually RESULTS in, so a net-new
    # finding recorded straight into 'submitted' is gated exactly like a patch.
    resulting_status = (
        incoming_status if (existing is None or explicit_override) else stored_status
    )
    if resulting_status == SubmissionStatus.NONE or resulting_status == stored_status:
        return
    resolved_ref = submission_ref
    if not (isinstance(resolved_ref, str) and resolved_ref.strip()):
        resolved_ref = (
            str(existing["submission_ref"] or "") if existing is not None else ""
        )
    if not resolved_ref.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"submission_ref is required when moving submission_status to "
                f"'{resulting_status}'; a submission state with no referent cannot "
                "be joined back to the report it describes"
            ),
        )
    if resulting_status != SubmissionStatus.WITHDRAWN:
        return
    reason = authored_details.get("withdrawal_reason") or effective_details.get(
        "withdrawal_reason"
    )
    if not (isinstance(reason, str) and reason.strip()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "details.withdrawal_reason is required when submission_status is "
                "'withdrawn'"
            ),
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
    verification_status: str,
    reason_code: str,
    reason_text: str,
    source_name: str,
    evidence_ref: str,
    notes: str,
    details: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
    artifact_ref: str,
    new_severity: str | None = None,
    proof_receipt_ids: list[int] | None = None,
    counter_check: dict[str, Any] | None = None,
    severity_variance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    normalized_verification_status = _normalize_verification_status(verification_status)
    if normalized_verification_status == "unreviewed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="verification endpoint cannot set status to unreviewed",
        )
    if new_severity and normalized_verification_status != "downgraded":
        # ``new_severity`` is only ever consumed by the downgraded branch. Any
        # other disposition silently dropped it, so a verifier who believed they
        # had re-banded the finding got a 200 and the OLD severity. Verification
        # is not the severity-editing verb; ``patch_finding`` owns that axis.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"new_severity applies only to verification_status='downgraded' (got "
                f"'{verification_status}'); change the band with "
                f"`vigil assess finding update {slug} --severity {new_severity}`"
            ),
        )

    with _common.get_connection() as connection:
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        severity_transitions = connection.execute(
            """
            SELECT from_severity, to_severity
            FROM assessment_finding_transitions
            WHERE engagement_id = ? AND finding_id = ?
            ORDER BY id DESC
            """,
            (engagement.id, int(existing["id"])),
        ).fetchall()

    expected_row_version = int(existing["row_version"])
    existing_workflow = _row_workflow_status(existing)
    if existing_workflow == "merged":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="merged findings cannot be re-verified")
    target_workflow = existing_workflow if existing_workflow not in {"false_positive", "merged"} else "active"
    target_severity = str(existing["severity"])
    transition_action = "verified_confirmed"
    transition_metadata: dict[str, Any] = {}
    details_payload = dict(details or {})

    if normalized_verification_status == "downgraded":
        if not new_severity:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="downgraded verification requires new_severity")
        normalized_new_severity = _normalize_severity(new_severity)
        current_severity = _normalize_severity(str(existing["severity"]))
        if SEVERITY_RANK[normalized_new_severity] > SEVERITY_RANK[current_severity]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="new_severity cannot be higher than the current severity",
            )
        prior_higher_severity = next(
            (
                _normalize_severity(str(row["from_severity"]))
                for row in severity_transitions
                if row["from_severity"]
                and _normalize_severity(str(row["to_severity"])) == current_severity
                and SEVERITY_RANK[_normalize_severity(str(row["from_severity"]))]
                > SEVERITY_RANK[current_severity]
            ),
            None,
        )
        if (
            normalized_new_severity == current_severity
            and prior_higher_severity is None
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "new_severity must be lower than the current severity unless "
                    "a prior severity-lowering transition proves it was pre-lowered"
                ),
            )
        target_severity = normalized_new_severity
        transition_action = "verified_downgraded"
        transition_metadata["previous_severity"] = (
            prior_higher_severity or current_severity
        )
        if normalized_new_severity == current_severity:
            transition_metadata["prelowered"] = True
    elif normalized_verification_status == "false_positive":
        existing_details = _json_object(existing["details_json"])
        kill_reason = details_payload.get(
            "kill_reason", existing_details.get("kill_reason")
        )
        kill_check = details_payload.get(
            "kill_check", existing_details.get("kill_check")
        )
        if not kill_reason or kill_check is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "false_positive verification requires "
                    "details.kill_reason and details.kill_check"
                ),
            )
        _validate_kill_names_a_settling_test(
            incoming_details=details_payload,
            existing_details=existing_details,
        )
        target_workflow = "false_positive"
        transition_action = "verified_false_positive"
    elif normalized_verification_status == "blocked":
        # Blocked-for-provisioning (hunting.md): the attempt could not even start
        # (missing account/line/device/credential/access). Requires a
        # block_reason (present in this verify OR already on the finding). Marked
        # reviewed so it leaves the unreviewed DoD queue, but report-readiness /
        # the report projection exclude it ('blocked' is neither
        # confirmed nor downgraded), keeping it OUT of the report until unblocked.
        _validate_blocked_verification_details(
            incoming_details=details_payload,
            existing_details=_json_object(existing["details_json"]),
        )
        transition_action = "verified_blocked"
    elif normalized_verification_status == "confirmed":
        transition_action = "verified_confirmed"
    elif normalized_verification_status == "pending_runtime_proof":
        # Analyst accepted the static/code evidence; only runtime proof is
        # outstanding. Mark verified so it leaves the unreviewed DoD queue while
        # report-readiness still excludes it on disposition (pending != confirmed
        # /downgraded), keeping it in the holding area until proven.
        transition_action = "verified_pending_runtime_proof"
    else:
        transition_action = "verification_disputed"

    effective_details = _json_object(
        _resolved_details(existing["details_json"], details_payload, "merge")
    )
    cvss_score = effective_details.get("cvss_score")
    normal_severity_band = None
    if isinstance(cvss_score, int | float) and not isinstance(cvss_score, bool):
        score_value = float(cvss_score)
        if score_value == 0:
            normal_severity_band = "info"
        elif score_value < 4:
            normal_severity_band = "low"
        elif score_value < 7:
            normal_severity_band = "medium"
        elif score_value < 9:
            normal_severity_band = "high"
        else:
            normal_severity_band = "critical"

    result = patch_finding(
        engagement.id,
        slug=slug,
        severity=target_severity,
        workflow_status=target_workflow,
        verification_status=normalized_verification_status,
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
        verification_proof_receipt_ids=list(proof_receipt_ids or []),
        verification_counter_check=counter_check,
        verification_severity_variance=severity_variance,
        verification_normal_severity_band=normal_severity_band,
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

def relocate_finding(
    engagement_id: int,
    *,
    slug: str,
    canonical_location: str,
    reason_text: str,
    source_name: str,
    expected_row_version: int,
    provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Move a finding across the file/non-file canonical-location boundary.

    The generic patch keeps refusing that crossing, and must: it exists so a
    non-file finding cannot acquire ``file:`` semantics — and with them the
    snapshot gate — through a metadata patch nobody reviewed. But the legitimate
    inverse is real: a static hypothesis whose runtime proof relocates the defect
    server-side. So the absolute becomes a REVIEWED, AUDITED transition on its own
    route rather than a hole in the generic one.
    """

    engagement = _engagement_or_404(engagement_id)
    canonical_location = str(canonical_location).strip()
    if not canonical_location:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="relocation requires a non-empty canonical_location",
        )
    if not str(reason_text).strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="relocation requires a reason_text",
        )
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if int(existing["row_version"]) != expected_row_version:
            _raise_stale_finding_conflict()
        incoming_provenance = _provenance_update_preserving_author(
            existing["provenance_json"], provenance, reject_rebind=True
        )
        merged_provenance = _json_object(existing["provenance_json"])
        stored_binding = _code_snapshot_binding(merged_provenance, strict=False)
        from_location = str(existing["canonical_location"] or "")
        canonical_location = _normalize_file_location(
            connection,
            engagement.id,
            canonical_location,
            repo_id=(
                _code_snapshot_binding(incoming_provenance, strict=False)
                or stored_binding
                or {}
            ).get("repo_id"),
        )
        if canonical_location == from_location:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="relocation must change the canonical_location",
            )
        if is_file_finding(canonical_location):
            # Moving INTO file: must satisfy the same binding requirement as a
            # record, or the route is a back door around the snapshot gate.
            binding_source = (
                incoming_provenance
                if CODE_SNAPSHOT_PROVENANCE_KEY in incoming_provenance
                else merged_provenance
            )
            _require_current_code_snapshot(connection, engagement.id, binding_source)
            merged_provenance.update(incoming_provenance)
        else:
            merged_provenance.update(incoming_provenance)
            if not is_file_finding(canonical_location) and stored_binding is not None:
                # Reserve the binding rather than delete it: it is the record of
                # which bytes were reviewed while the finding was a file finding.
                merged_provenance.pop(CODE_SNAPSHOT_PROVENANCE_KEY, None)
                merged_provenance[SUPERSEDED_CODE_SNAPSHOT_PROVENANCE_KEY] = {
                    "slug": slug,
                    CODE_SNAPSHOT_PROVENANCE_KEY: stored_binding,
                    "reason": str(reason_text).strip(),
                    "at": _common._utcnow_iso_dispatch(),
                }
        merged_provenance[ORIGINAL_CANONICAL_LOCATION_PROVENANCE_KEY] = from_location
        before_state = _finding_state_snapshot(existing)
        before_content = _finding_content_snapshot(existing)
        verification_invalidated = before_state["verification_status"] != "unreviewed"
        cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET canonical_location = ?,
                provenance_json = ?,
                verification_status = CASE
                    WHEN ? = 1 THEN 'unreviewed'
                    ELSE verification_status
                END,
                row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (
                canonical_location,
                _json_text(merged_provenance),
                1 if verification_invalidated else 0,
                int(existing["id"]),
                expected_row_version,
            ),
        )
        if cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        row = connection.execute(
            "SELECT * FROM assessment_findings WHERE id = ?", (int(existing["id"]),)
        ).fetchone()
        assert row is not None
        transition = _record_finding_transition(
            connection,
            engagement_id=engagement.id,
            finding_id=int(row["id"]),
            actor=source_name,
            action="location_relocated",
            before=before_state,
            after=_finding_state_snapshot(row),
            reason_code="relocation",
            reason_text=str(reason_text).strip(),
            artifact_ref="",
            metadata={
                "from": from_location,
                "to": canonical_location,
                "material_change": True,
                "verification_invalidated": verification_invalidated,
            },
            before_content=before_content,
            after_content=_finding_content_snapshot(row),
        )
        record = _serialize_finding_with_code_snapshot_status(
            connection, engagement.id, row
        )
    return {"finding": record, "transition": transition}


def repair_finding_author(
    engagement_id: int,
    *,
    slug: str,
    agent_id: str,
    actor: str,
    reason: str,
    expected_row_version: int,
) -> dict[str, Any]:
    """Repair missing or unresolvable legacy author provenance exactly once."""

    engagement = _engagement_or_404(engagement_id)
    agent_id = str(agent_id).strip()
    actor = str(actor).strip()
    reason = str(reason).strip()
    if not actor:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="author repair actor must contain non-whitespace text",
        )
    if not reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="author repair reason must contain non-whitespace text",
        )
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        slug = _resolve_existing_finding_slug(connection, engagement.id, slug)
        existing = connection.execute(
            "SELECT * FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if int(existing["row_version"]) != expected_row_version:
            _raise_stale_finding_conflict()
        provenance = _json_object(existing["provenance_json"])
        stored_author = str(provenance.get("agent_id") or "").strip()
        stored_dispatch = (
            _resolve_dispatch_id(connection, engagement.id, stored_author)
            if stored_author
            else None
        )
        if stored_dispatch is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"finding already has immutable provenance.agent_id {stored_author!r}; "
                    "author repair cannot rewrite it"
                ),
            )
        dispatch = connection.execute(
            """
            SELECT id, agent_id, agent_role
            FROM assessment_dispatches
            WHERE engagement_id = ? AND agent_id = ?
            """,
            (engagement.id, agent_id),
        ).fetchone()
        if dispatch is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"author repair agent_id {agent_id!r} does not resolve to a dispatch "
                    "in this engagement"
                ),
            )
        before_state = _finding_state_snapshot(existing)
        before_content = _finding_content_snapshot(existing)
        provenance["agent_id"] = agent_id
        cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET provenance_json = ?, row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (_json_text(provenance), int(existing["id"]), expected_row_version),
        )
        if cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        row = connection.execute(
            "SELECT * FROM assessment_findings WHERE id = ?", (int(existing["id"]),)
        ).fetchone()
        assert row is not None
        transition = _record_finding_transition(
            connection,
            engagement_id=engagement.id,
            finding_id=int(row["id"]),
            actor=actor,
            action="author_provenance_repaired",
            before=before_state,
            after=_finding_state_snapshot(row),
            reason_code="missing_author_repair",
            reason_text=reason,
            artifact_ref="",
            metadata={
                "old_agent_id": stored_author or None,
                "new_agent_id": agent_id,
                "repair_kind": (
                    "unresolvable_author" if stored_author else "missing_author"
                ),
                "dispatch_id": int(dispatch["id"]),
                "dispatch_role": str(dispatch["agent_role"] or ""),
            },
            before_content=before_content,
            after_content=_finding_content_snapshot(row),
        )
        record = _serialize_finding_with_code_snapshot_status(
            connection, engagement.id, row
        )
    return {"finding": record, "transition": transition}


def _merge_details_precedence(winner: dict[str, Any], loser: dict[str, Any]) -> str:
    """Merge two ``details_json`` payloads so the WINNING side survives on key
    conflict while still inheriting keys the winner lacks from the loser.

    ``merge_findings`` keeps the stronger finding's severity
    (``_stronger_severity``) and its summary/evidence (``source_stronger``).
    The canonical (kept) finding's CVSS/impact live as flat ``details_json``
    keys (``cvss_score``/``cvss_vector``/``impact``), so its details MUST follow
    the same side that won — otherwise a weaker duplicate overwrites the
    canonical's CVSS/impact and trips the severity↔CVSS readiness gate. Seed
    from the losing side (fill gaps), then overlay the winning side's non-empty
    values (win conflicts). Empties are dropped with the same filter shared
    ``_merge_object_text`` uses, so a blank winner value never clobbers a real
    loser value.
    """
    def _non_empty(payload: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in payload.items() if value not in (None, "", [], {})}

    merged = _non_empty(loser)
    merged.update(_non_empty(winner))
    return _json_text(merged)


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
        if int(source["engagement_id"]) != engagement.id or int(target["engagement_id"]) != engagement.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="cannot merge findings from different engagements",
            )
        if _row_workflow_status(source) == "merged":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"source finding {source_slug} is already merged",
            )
        if _row_workflow_status(target) == "merged":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"target finding {target_slug} is already merged",
            )
        if source["merged_into_finding_id"] is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"source finding {source_slug} has a merge target but is not marked merged",
            )
        if target["merged_into_finding_id"] is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"target finding {target_slug} has a merge target but is not marked merged",
            )
        source_provenance = _json_object(source["provenance_json"])
        target_provenance = _json_object(target["provenance_json"])
        source_binding = _code_snapshot_binding(source_provenance, strict=False)
        target_binding = _code_snapshot_binding(target_provenance, strict=False)
        source_is_file = is_file_finding(str(source["canonical_location"]))
        target_is_file = is_file_finding(str(target["canonical_location"]))
        cross_track_merge = source_is_file != target_is_file
        canonical_location = str(target["canonical_location"])
        if cross_track_merge:
            file_row = source if source_is_file else target
            file_binding = source_binding if source_is_file else target_binding
            live_provenance = target_provenance if source_is_file else source_provenance
            live_binding = target_binding if source_is_file else source_binding
            if file_binding is None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "cannot merge a file and live finding without a structured "
                        "code snapshot identity on the file finding"
                    ),
                )
            if (
                CODE_SNAPSHOT_PROVENANCE_KEY in live_provenance
                and live_binding != file_binding
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="cannot merge findings bound to different code snapshots",
                )
            canonical_location = str(file_row["canonical_location"])
        else:
            either_has_binding = (
                CODE_SNAPSHOT_PROVENANCE_KEY in source_provenance
                or CODE_SNAPSHOT_PROVENANCE_KEY in target_provenance
            )
            if either_has_binding and (
                source_binding is None
                or target_binding is None
                or source_binding != target_binding
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="cannot merge findings bound to different code snapshots",
                )
        merged_children = connection.execute(
            """
            SELECT slug
            FROM assessment_findings
            WHERE engagement_id = ? AND merged_into_finding_id = ?
            ORDER BY slug
            """,
            (engagement.id, source["id"]),
        ).fetchall()
        if merged_children:
            child_slugs = ", ".join(str(row["slug"]) for row in merged_children)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"cannot merge source finding {source_slug}; it represents merged findings "
                    f"{child_slugs} and moving it would create a merge chain"
                ),
            )
        foreign_child = connection.execute(
            """
            SELECT 1
            FROM assessment_findings
            WHERE engagement_id != ? AND merged_into_finding_id = ?
            LIMIT 1
            """,
            (engagement.id, source["id"]),
        ).fetchone()
        if foreign_child is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"cannot merge source finding {source_slug}; a finding from another "
                    "engagement references it"
                ),
            )
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
              AND links.retired_at IS NULL
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
              AND retired_at IS NULL
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
        source_before = _finding_state_snapshot(source)
        target_before = _finding_state_snapshot(target)
        source_before_content = _finding_content_snapshot(source)
        target_before_content = _finding_content_snapshot(target)
        merged_notes = _common._append_notes(
            _common._append_notes(target["notes"], f"Merged {source_slug}: {reason}"),
            source["notes"],
        )
        source_details = _json_object(source["details_json"])
        target_details = _json_object(target["details_json"])
        # The explicitly selected target is the canonical record. Source
        # details fill missing keys but never overwrite canonical narrative.
        merged_details_obj = _json_object(
            _merge_details_precedence(target_details, source_details)
        )
        # CVSS-bearing keys are the exception: they must follow the SEVERITY winner
        # (kept below via `_stronger_severity`), NOT the confidence winner. Otherwise
        # a more-progressed but lower-severity duplicate leaves a higher-severity
        # canonical carrying the duplicate's weaker CVSS and trips the severity↔CVSS
        # readiness gate.
        severity_winner_details = (
            source_details
            if (
                _stronger_severity(target["severity"], source["severity"]) == source["severity"]
                and source["severity"] != target["severity"]
            )
            else target_details
        )
        # The pair moves ATOMICALLY. Filling only the half the winner lacks from
        # the loser manufactures a score that its own vector never produced — a
        # mismatch neither input finding had. Once the winner declares either
        # half, its absences win too.
        if any(
            severity_winner_details.get(key) not in (None, "", [], {})
            for key in _CVSS_KEYS
        ):
            for _cvss_key in _CVSS_KEYS:
                _cvss_value = severity_winner_details.get(_cvss_key)
                if _cvss_value not in (None, "", [], {}):
                    merged_details_obj[_cvss_key] = _cvss_value
                else:
                    merged_details_obj.pop(_cvss_key, None)
        # A pair that still disagrees arrived WHOLE on one of the two inputs —
        # the atomic move above means merge can never assemble a mismatch that
        # neither side had. So refusing here would dead-end a correct duplicate
        # consolidation over a data defect this caller did not author, and the
        # two duplicates would stay separate in the report. Merge instead, and
        # say so: `cvss_vector_score_mismatch` / `cvss_vector_invalid` in
        # report-readiness still block the report until the pair is repaired.
        merge_warnings: list[str] = []
        cvss_problem = _cvss_pair_disagreement(merged_details_obj)
        if cvss_problem is not None:
            merge_warnings.append(
                f"merge completed, but {target_slug} carries a contradictory CVSS "
                f"pair inherited from one of the two findings: {cvss_problem[1]}. "
                f"Repair it with `vigil assess finding update {target_slug} "
                "--details-inline '{\"cvss_score\": <n>, \"cvss_vector\": \"<v>\"}'` "
                "— the report is blocked until the pair agrees."
            )
        merged_details = _json_text(merged_details_obj)
        merged_provenance_payload = _json_object(target["provenance_json"])
        merged_provenance_payload.update(
            _provenance_update_preserving_author(
                target["provenance_json"],
                _json_object(source["provenance_json"]),
                reject_rebind=False,
            )
        )
        merged_provenance_payload["merge"] = {
            "source_slug": source_slug,
            "target_slug": target_slug,
            "reason": reason,
            "source_name": source_name,
        }
        merged_severity = _stronger_severity(
            str(target["severity"]), str(source["severity"])
        )
        merged_workflow = (
            target_workflow
            if source_workflow == "false_positive"
            and target_workflow != "false_positive"
            else _coalesce_workflow_status(target_workflow, source_workflow)
        )
        merged_source_name = str(target["source_name"])
        if str(source["source_name"]):
            if source_stronger:
                merged_source_name = str(source["source_name"])
        merged_summary = str(target["summary"])
        if not merged_summary or (source_stronger and str(source["summary"])):
            merged_summary = str(source["summary"])
        merged_evidence_ref = str(target["evidence_ref"])
        if not merged_evidence_ref or (
            source_stronger and str(source["evidence_ref"])
        ):
            merged_evidence_ref = str(source["evidence_ref"])

        # A merge may add an independent evidence link without changing the
        # claim a verifier adjudicated. Keep a terminal verdict in that case.
        # If the canonical merge replaces any material input to that verdict,
        # force another review and make the exact invalidating axes auditable.
        replaced_verification_dependencies: list[str] = []
        if merged_severity != str(target["severity"]):
            replaced_verification_dependencies.append("severity")
        if merged_workflow != target_workflow:
            replaced_verification_dependencies.append("workflow_status")
        if canonical_location != str(target["canonical_location"]):
            replaced_verification_dependencies.append("canonical_location")
        if merged_source_name != str(target["source_name"]):
            replaced_verification_dependencies.append("source_name")
        if merged_summary != str(target["summary"]):
            replaced_verification_dependencies.append("summary")
        if (
            str(target["evidence_ref"])
            and merged_evidence_ref != str(target["evidence_ref"])
        ):
            replaced_verification_dependencies.append("evidence_ref")
        if _merge_replaces_verification_material_details(
            str(target["details_json"]), merged_details_obj
        ):
            replaced_verification_dependencies.append("details")
        if any(
            key != "merge"
            and key in merged_provenance_payload
            and merged_provenance_payload[key] != value
            for key, value in target_provenance.items()
        ):
            replaced_verification_dependencies.append("provenance")
        verification_invalidated = bool(replaced_verification_dependencies) and (
            _row_verification_status(target) in TERMINAL_VERIFICATION_STATUSES
        )
        merged_verification_status = (
            "unreviewed"
            if verification_invalidated
            else _row_verification_status(target)
        )
        source_links = connection.execute(
            "SELECT * FROM assessment_finding_links "
            "WHERE engagement_id = ? AND finding_id = ? AND retired_at IS NULL",
            (engagement.id, source["id"]),
        ).fetchall()
        source_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET status = 'merged',
                merged_into_finding_id = ?,
                notes = ?,
                row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (
                target["id"],
                _common._append_notes(source["notes"], reason),
                source["id"],
                source_row_version,
            ),
        )
        if source_cursor.rowcount != 1:
            _raise_stale_finding_conflict()
        target_cursor = connection.execute(
            """
            UPDATE assessment_findings
            SET severity = ?,
                status = ?,
                verification_status = ?,
                canonical_location = ?,
                source_name = ?,
                summary = ?,
                evidence_ref = ?,
                notes = ?,
                details_json = ?,
                provenance_json = ?,
                row_version = row_version + 1,
                updated_at = CURRENT_TIMESTAMP,
                last_seen_at = CURRENT_TIMESTAMP
            WHERE id = ? AND row_version = ?
            """,
            (
                merged_severity,
                merged_workflow,
                merged_verification_status,
                canonical_location,
                merged_source_name,
                merged_summary,
                merged_evidence_ref,
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
            """
            UPDATE assessment_finding_links
            SET retired_at = COALESCE(retired_at, CURRENT_TIMESTAMP),
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND finding_id = ?
            """,
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
        source_after_content = _finding_content_snapshot(source_row)
        target_after_content = _finding_content_snapshot(target_row)
        source_record = _serialize_finding_with_code_snapshot_status(
            connection, engagement.id, source_row
        )
        target_record = _serialize_finding_with_code_snapshot_status(
            connection, engagement.id, target_row
        )
        if (
            _finding_state_changed(source_before, source_after)
            or source_before_content != source_after_content
        ):
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
                before_content=source_before_content,
                after_content=source_after_content,
            )
        if (
            _finding_state_changed(target_before, target_after)
            or target_before_content != target_after_content
        ):
            _record_finding_transition(
                connection,
                engagement_id=engagement.id,
                finding_id=int(target["id"]),
                actor=source_name,
                action=(
                    "verification_invalidated"
                    if verification_invalidated
                    else "operator_override"
                ),
                before=target_before,
                after=target_after,
                reason_code=(
                    "merge_replaced_verification_dependency"
                    if verification_invalidated
                    else "merge"
                ),
                reason_text=(
                    f"Merged {source_slug} into {target_slug} and invalidated "
                    "verification because the merge replaced: "
                    f"{', '.join(replaced_verification_dependencies)}. {reason}"
                    if verification_invalidated
                    else f"Merged {source_slug} into {target_slug}: {reason}"
                ),
                artifact_ref="",
                metadata={
                    "source_slug": source_slug,
                    "verification_invalidated": verification_invalidated,
                    "replaced_dependencies": replaced_verification_dependencies,
                },
                before_content=target_before_content,
                after_content=target_after_content,
            )
    return {
        "source": source_record,
        "target": target_record,
        "link": link,
        # Always present so a consumer can read it unconditionally; non-empty
        # only when the merge carried a pre-existing defect into the canonical.
        "warnings": merge_warnings,
    }

def _validated_enum_filter(
    field: str, value: str | None, allowed: Collection[Any]
) -> str | None:
    """Reject a filter value that names nothing in its enum.

    A SQL equality filter on an unknown value is indistinguishable from a genuine
    empty result: `--verification-status verified` (the retired two-axis spelling)
    returned `[]` and exit 0, which an agent reads as "no confirmed findings to
    exploit" while confirmed findings sit in the table. Fail the query instead, and
    name the vocabulary so the caller can correct itself in one step.
    """
    if value is None:
        return None
    normalized = value.strip().lower()
    if not normalized:
        return None
    if normalized not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"invalid {field} filter {value!r}; allowed: "
                + ", ".join(sorted(str(item) for item in allowed))
            ),
        )
    return normalized

def list_findings(
    engagement_id: int,
    *,
    severity: str | None = None,
    workflow_status: str | None = None,
    verification_status: str | None = None,
    auth_context: str | None = None,
    source_name: str | None = None,
    slug: str | None = None,
    search: str | None = None,
    holding: bool = False,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    severity = _validated_enum_filter("severity", severity, SEVERITY_RANK)
    workflow_status = _validated_enum_filter(
        "workflow_status", workflow_status, WORKFLOW_STATUSES
    )
    verification_status = _validated_enum_filter(
        "verification_status", verification_status, VERIFICATION_STATUSES
    )
    where = ["findings.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if severity:
        where.append("LOWER(findings.severity) = ?")
        params.append(severity)
    if workflow_status:
        where.append("LOWER(findings.status) = ?")
        params.append(workflow_status)
    if verification_status:
        where.append("LOWER(findings.verification_status) = ?")
        params.append(verification_status)
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
            "LOWER(findings.verification_status) IN ('pending_runtime_proof', 'blocked')"
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
                CASE findings.verification_status
                    WHEN 'confirmed' THEN 0
                    WHEN 'downgraded' THEN 1
                    WHEN 'disputed' THEN 2
                    WHEN 'pending_runtime_proof' THEN 3
                    WHEN 'blocked' THEN 4
                    ELSE 5
                END,
                findings.updated_at DESC,
                findings.id DESC
            {limit_sql}
            """,
            tuple(params),
        ).fetchall()
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        return [
            _serialize_finding_with_code_snapshot_status(
                connection, engagement.id, row, repo_states=repo_states
            )
            for row in rows
        ]


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
        record = _serialize_finding_with_code_snapshot_status(
            connection, engagement.id, row
        )
        record["verification_audit"] = verification_audit_for_finding(
            connection, engagement.id, int(row["id"])
        )
        return record

def list_exploit_candidates(engagement_id: int) -> list[dict[str, Any]]:
    """Findings an exploit dispatch may be authorized against.

    Track-agnostic by design: a confirmed ``file:`` finding is as exploitable as
    a confirmed URL one, and ADR 0023 keeps both on a single canonical claim.
    What is excluded is ``pending_runtime_proof`` — proof owed is not proof, so a
    parked finding cannot enter the approval gate. Its complement is read
    separately by ``vigil assess exploit review``; widening this predicate would
    collapse the two into one queue and let an unproven claim be approved.
    See: ``tests/test_engagements_api.py`` —
    ``test_pending_runtime_proof_blocks_report_readiness_and_exploit_candidates``.
    """
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
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        records = [
            _serialize_finding_with_code_snapshot_status(
                connection, engagement.id, row, repo_states=repo_states
            )
            for row in rows
        ]

    candidates: list[dict[str, Any]] = []
    for record in records:
        workflow_status = record.get("workflow_status", "draft")
        if workflow_status in {"merged", "false_positive", "reported", "exploited"}:
            continue
        if record.get("verification_status") not in {"confirmed", "downgraded"}:
            continue
        details = _json_object(record.get("details"))
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

def list_finding_transitions(
    engagement_id: int,
    *,
    slug: str,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    slug = canonical_finding_alias(slug) or slug
    with _common.get_connection() as connection:
        finding = connection.execute(
            "SELECT id FROM assessment_findings WHERE engagement_id = ? AND slug = ?",
            (engagement.id, slug),
        ).fetchone()
        if finding is None:
            raise _finding_not_found(connection, engagement.id, slug)
        sql = """
            SELECT *
            FROM assessment_finding_transitions
            WHERE engagement_id = ? AND finding_id = ?
            ORDER BY created_at DESC, id DESC
            """
        params: list[Any] = [engagement.id, int(finding["id"])]
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend((int(limit), int(offset)))
        rows = connection.execute(sql, tuple(params)).fetchall()
        audit_by_transition = verification_audit_by_transition(
            connection,
            engagement.id,
            int(finding["id"]),
            [int(row["id"]) for row in rows],
        )
    records: list[dict[str, Any]] = []
    for row in rows:
        record = dict(row)
        metadata = _json_object(record.get("metadata_json"))
        notes_history_status = metadata.get(_NOTES_HISTORY_STATUS_KEY)
        if notes_history_status not in _NOTES_HISTORY_STATUSES:
            # Content columns were added after the transition ledger already
            # contained rows. A populated side proves that transition captured
            # note history; two NULLs on an unmarked row mean the old writer did
            # not say whether notes changed. Expose that gap instead of
            # reinterpreting missing history as "unchanged".
            notes_history_status = (
                "recorded"
                if record.get("notes_before_json") is not None
                or record.get("notes_after_json") is not None
                else "historical_gap"
            )
        record[_NOTES_HISTORY_STATUS_KEY] = notes_history_status
        record["verification_audit"] = audit_by_transition[int(row["id"])]
        records.append(record)
    return records
