"""Code-snapshot bindings and finding author provenance.

Finding writes and merge orchestration live in :mod:`findings`; this module owns
the sealed source identity attached to a finding and the server-resolved
provenance that makes that identity auditable.
"""

from __future__ import annotations

import difflib
import re
import sqlite3
from typing import Any

from fastapi import HTTPException, status

from . import _common
from ._common import _json_object, _serialize_finding_record, is_file_finding
from .finding_details import validate_stored_reply_sequence_identity
from .finding_next_tests import current_next_test, current_next_tests
from .proofs import proof_receipts_for_finding, proof_receipts_for_findings
from .repro_currentness import reproduction_basis_for_receipts

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
CODE_SNAPSHOT_WRITE_MODES = frozenset({"record", "patch", "verify"})
_CODE_SNAPSHOT_WRITE_MODES = CODE_SNAPSHOT_WRITE_MODES


_LINE_SEGMENT = re.compile(r"([0-9]+)(?:-([0-9]+))?")


def parse_file_location(canonical_location: str) -> tuple[str, int | None, int | None]:
    """Split ``file:<path>[:<line>[-<end>]][:<column>]`` into path and lines.

    ``:null`` is the documented form for a decompiled file without line mapping
    and cites no line. A trailing column is ignored.
    """

    body = str(canonical_location or "").strip()[len("file:"):]
    segments = body.split(":")
    if len(segments) > 1 and segments[-1] == "null":
        return ":".join(segments[:-1]), None, None
    if (
        len(segments) > 2
        and _LINE_SEGMENT.fullmatch(segments[-2])
        and re.fullmatch(r"[0-9]+", segments[-1])
    ):
        segments.pop()
    if len(segments) > 1:
        match = _LINE_SEGMENT.fullmatch(segments[-1])
        if match:
            end = int(match[2]) if match[2] is not None else None
            return ":".join(segments[:-1]), int(match[1]), end
    return body, None, None


def closest_snapshot_path(
    connection: sqlite3.Connection,
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    path: str,
    *,
    roster_cache: dict[tuple[int, int], list[str]] | None = None,
    closest_cache: dict[tuple[int, int, str], str | None] | None = None,
) -> str | None:
    """The generation's file nearest ``path``: same basename first, then spelling."""

    key = (repo_id, repo_generation, path)
    if closest_cache is not None and key in closest_cache:
        return closest_cache[key]
    roster_key = (repo_id, repo_generation)
    paths = roster_cache.get(roster_key) if roster_cache is not None else None
    if paths is None:
        paths = [
            str(row["file_path"])
            for row in connection.execute(
                """
                SELECT file_path FROM code_source_generation_files
                WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
                """,
                (engagement_id, repo_id, repo_generation),
            ).fetchall()
        ]
        if roster_cache is not None:
            roster_cache[roster_key] = paths
    basename = path.rsplit("/", 1)[-1]
    same_name = [candidate for candidate in paths if candidate.rsplit("/", 1)[-1] == basename]
    closest = difflib.get_close_matches(
        path, same_name or paths, n=1, cutoff=0 if same_name else 0.6
    )
    result = closest[0] if closest else None
    if closest_cache is not None:
        closest_cache[key] = result
    return result


def snapshot_location_problem(
    connection: sqlite3.Connection,
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    path: str,
    line: int | None = None,
    *,
    end_line: int | None = None,
    roster_cache: dict[tuple[int, int], list[str]] | None = None,
    closest_cache: dict[tuple[int, int, str], str | None] | None = None,
) -> tuple[dict[str, Any] | None, str]:
    """Look ``path`` (and its lines) up in one sealed generation's file roster.

    Returns ``(file_row, "")`` when the citation resolves, else ``(row_or_None,
    reason)``. Callers that refuse use :func:`resolve_snapshot_location`.
    """

    row = connection.execute(
        """
        SELECT file_id AS id, file_path, file_hash, language, loc
        FROM code_source_generation_files
        WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
          AND file_path = ?
        """,
        (engagement_id, repo_id, repo_generation, path),
    ).fetchone()
    if row is None:
        roster = connection.execute(
            """
            SELECT 1 FROM code_source_generation_files
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
            LIMIT 1
            """,
            (engagement_id, repo_id, repo_generation),
        ).fetchone()
        if roster is None:
            return None, (
                f"generation {repo_generation} of repository {repo_id} has no files "
                "in its sealed roster, so nothing in it can be cited; re-ingest the "
                "repository so its current generation records the files it holds"
            )
        reason = f"'{path}' is not a file in generation {repo_generation} of repository {repo_id}"
        closest = closest_snapshot_path(
            connection, engagement_id, repo_id, repo_generation, path,
            roster_cache=roster_cache, closest_cache=closest_cache,
        )
        if closest is not None:
            reason += f"; closest admitted path: {closest!r}"
        return None, reason
    file_row = dict(row)
    loc = int(file_row["loc"] or 0)
    for number in (line, end_line):
        if number is not None and not 1 <= number <= loc:
            return file_row, f"line {number} is outside {path} ({loc} lines)"
    return file_row, ""


def resolve_snapshot_location(
    connection: sqlite3.Connection,
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    path: str,
    line: int | None,
    *,
    end_line: int | None = None,
) -> dict[str, Any]:
    """Return the sealed file row a citation names, or refuse it with 400.

    The one check that a cited path is a file in the generation, and each cited
    line lies inside it, for finding locations, lead bindings and cross-file
    triggers alike.
    """

    file_row, problem = snapshot_location_problem(
        connection, engagement_id, repo_id, repo_generation, path, line,
        end_line=end_line,
    )
    if problem:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)
    assert file_row is not None
    return file_row


def require_cited_file_location(
    connection: sqlite3.Connection,
    engagement_id: int,
    binding: dict[str, Any],
    canonical_location: str,
) -> dict[str, Any]:
    """Resolve a ``file:`` finding location in the generation its binding seals."""

    path, line, end_line = parse_file_location(canonical_location)
    if end_line is not None and line is not None and end_line < line:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"line range {line}-{end_line} in {canonical_location!r} runs backwards",
        )
    return resolve_snapshot_location(
        connection,
        engagement_id,
        int(binding["repo_id"]),
        int(binding["repo_generation"]),
        path,
        line,
        end_line=end_line,
    )


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


def code_snapshot_binding(
    finding: dict[str, Any] | sqlite3.Row,
) -> dict[str, Any] | None:
    """The sealed generation a finding's stored provenance binds, or ``None``.

    The read-path counterpart to :func:`_require_current_code_snapshot`: a
    malformed or absent binding yields ``None`` instead of refusing, so a
    projection can ask which generation a finding's citations belong to without
    deciding whether the finding is writable.
    """

    return _code_snapshot_binding(_finding_provenance(dict(finding)), strict=False)


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
    current_receipts: list[dict[str, Any]] | None = None,
    current_plans: dict[int, dict[str, Any]] | None = None,
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
    record["proof_receipts"] = (
        proof_receipts_for_finding(connection, engagement_id, int(record["id"]))
        if current_receipts is None else current_receipts
    )
    record["reproduction_basis"] = reproduction_basis_for_receipts(
        str(record.get("canonical_location") or ""), record["proof_receipts"]
    )
    record["next_test"] = (
        current_next_test(
            connection, engagement_id, int(record["id"]), str(record["verification_status"]),
            workflow_status=str(record["workflow_status"]),
        ) if current_plans is None else current_plans.get(int(record["id"]))
    )
    return record


def _serialize_findings_with_code_snapshot_status(
    connection: sqlite3.Connection,
    engagement_id: int,
    findings: list[sqlite3.Row],
) -> list[dict[str, Any]]:
    """Keep collection and point projections identical while sharing request work."""
    if not findings:
        return []
    records = [dict(row) for row in findings]
    repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    receipts = proof_receipts_for_findings(
        connection, engagement_id, [int(row["id"]) for row in records]
    )
    plans = current_next_tests(connection, engagement_id, records)
    return [
        _serialize_finding_with_code_snapshot_status(
            connection, engagement_id, row, repo_states=repo_states,
            current_receipts=receipts[int(row["id"])], current_plans=plans,
        )
        for row in records
    ]


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
