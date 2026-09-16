from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from ..code_snapshot import (
    SOURCE_MANIFEST_VERSION,
    SnapshotAttestationError,
    VerifiedSnapshotAttestation,
    attest_verified_snapshot,
    source_manifest_digest,
)
from ..db import get_connection
from . import code_fuzz_completion
from .artifact_index import _normalize_relative_path
from .events import _engagement_or_404
from .state_manager.findings import (
    CODE_SNAPSHOT_PROVENANCE_KEY,
    finding_code_snapshot_status,
    is_file_finding,
    load_code_repo_snapshot_states,
)
from .state_manager import run_accounting
from .variant_scopes import (
    MAX_VARIANT_PARENT_FINDINGS,
    VARIANT_DISPATCH_ROLE as _VARIANT_DISPATCH_ROLE,
    variant_parent_finding_set_digest as _variant_parent_finding_set_digest,
)

STRUCTURAL_INPUT_IDENTITY_SCHEMA = "structural-input-identity/v1"
STRUCTURAL_INDEX_SCHEMA = "structural-index/v6"
STRUCTURAL_CALLABLE_IDENTITY_SCHEMA = "structural-callable/v1"
VARIANT_INPUT_IDENTITY_SCHEMA = "variant-input-identity/v1"
MAX_VARIANT_RECEIPT_PAGE = 500
DEFAULT_VARIANT_RECEIPT_PAGE = 100
_REPORTABLE_FINDING_STATUSES = frozenset(
    {
        "active",
        "blocked",
        "exploited",
        "contained",
        "eradicated",
        "recovered",
        "reported",
    }
)
_CANONICAL_STRUCTURAL_LANGUAGES = frozenset(
    {
        "",
        "c",
        "c++",
        "cpp",
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
        "java",
        "kotlin",
        "ruby",
        "php",
        "swift",
        "objectivec",
        "shell",
        "lua",
        "sql",
        "html",
        "css",
        "xml",
        "json",
        "yaml",
        "toml",
        "markdown",
        "text",
        "rst",
        "makefile",
        "cmake",
        "dockerfile",
    }
)
_STRUCTURAL_LANGUAGE_ALIASES = {"c++": "cpp"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_text(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True, separators=(",", ":"))


def _json_list_text(value: Any) -> str:
    return json.dumps(value if value is not None else [], sort_keys=True, separators=(",", ":"))


def _scalar_row(connection, query: str, params: tuple[Any, ...]) -> int:
    row = connection.execute(query, params).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def _fetch_all(connection, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(query, params).fetchall()]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_structural_language(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="structural index language must be a canonical unpadded string",
        )
    normalized = _STRUCTURAL_LANGUAGE_ALIASES.get(value, value)
    if normalized not in _CANONICAL_STRUCTURAL_LANGUAGES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"unsupported structural index language: {value!r}",
        )
    return normalized


def structural_input_identity_digest(
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest_value: str,
    files: list[dict[str, Any]],
) -> str:
    payload = {
        "schema": STRUCTURAL_INPUT_IDENTITY_SCHEMA,
        "repo_id": int(repo_id),
        "repo_generation": int(repo_generation),
        "source_manifest_digest": str(source_manifest_digest_value),
        "files": sorted(
            (
                {
                    "file_path": str(file_row["file_path"]),
                    "source_sha256": str(
                        file_row.get("source_sha256", file_row.get("file_hash", ""))
                    ),
                    "language": canonical_structural_language(
                        file_row.get("indexed_language", file_row.get("language", ""))
                    ),
                }
                for file_row in files
            ),
            key=lambda row: row["file_path"],
        ),
    }
    return hashlib.sha256(_json_text(payload).encode("utf-8")).hexdigest()


def _structural_callable_key(
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    file_id: int,
    file_sha256: str,
    name: str,
    qualified_name: str,
    start_line: int,
    end_line: int,
) -> str:
    return hashlib.sha256(
        _json_text(
            {
                "schema": STRUCTURAL_CALLABLE_IDENTITY_SCHEMA,
                "repo_id": repo_id,
                "repo_generation": repo_generation,
                "source_manifest_digest": source_manifest_digest,
                "file_id": file_id,
                "file_sha256": file_sha256,
                "name": name,
                "qualified_name": qualified_name,
                "start_line": start_line,
                "end_line": end_line,
            }
        ).encode("utf-8")
    ).hexdigest()


def _canonical_structural_callables(
    item: dict[str, Any],
    file_row: dict[str, Any],
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
) -> list[dict[str, Any]]:
    callables = item.get("callables", [])
    if not isinstance(callables, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="structural callables must be a list",
        )
    if len(callables) > int(item["total_functions"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="structural callables cannot exceed total_functions",
        )
    canonical: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for raw in callables:
        if not isinstance(raw, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="each structural callable must be an object",
            )
        _reject_unknown_fields(
            raw,
            {"name", "qualified_name", "start_line", "end_line"},
            entity_name="structural callable",
        )
        name = raw.get("name")
        qualified_name = raw.get("qualified_name")
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or not isinstance(qualified_name, str)
            or not qualified_name
            or qualified_name != qualified_name.strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural callable names must be non-empty unpadded strings",
            )
        start_line = raw.get("start_line")
        end_line = raw.get("end_line")
        if (
            type(start_line) is not int
            or type(end_line) is not int
            or start_line < 1
            or end_line < start_line
            or end_line > int(file_row["loc"])
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "structural callable source span must fall within the sealed file "
                    f"for file_id={file_row['id']}"
                ),
            )
        identity = (qualified_name, start_line, end_line)
        if identity in seen:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural callable identities must be unique within a file",
            )
        seen.add(identity)
        canonical.append(
            {
                "engagement_id": int(file_row["engagement_id"]),
                "repo_id": repo_id,
                "repo_generation": repo_generation,
                "source_manifest_digest": source_manifest_digest,
                "file_id": int(file_row["id"]),
                "file_path": str(file_row["file_path"]),
                "file_sha256": str(file_row["file_hash"]),
                "name": name,
                "qualified_name": qualified_name,
                "start_line": start_line,
                "end_line": end_line,
                "callable_key": _structural_callable_key(
                    repo_id=repo_id,
                    repo_generation=repo_generation,
                    source_manifest_digest=source_manifest_digest,
                    file_id=int(file_row["id"]),
                    file_sha256=str(file_row["file_hash"]),
                    name=name,
                    qualified_name=qualified_name,
                    start_line=start_line,
                    end_line=end_line,
                ),
            }
        )
    return canonical


def _bind_legacy_analysis_results(
    connection,
    *,
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
) -> None:
    legacy_rows = connection.execute(
        """
        SELECT results.id, results.file_id, results.function_name
        FROM code_analysis_results AS results
        JOIN code_files AS files
          ON files.id = results.file_id
         AND files.engagement_id = results.engagement_id
        WHERE results.engagement_id = ? AND files.repo_id = ?
          AND results.repo_generation = ?
          AND results.receipt_binding_status = 'legacy_unbound'
          AND trim(results.function_name) != ''
        """,
        (engagement_id, repo_id, repo_generation),
    ).fetchall()
    for legacy in legacy_rows:
        matches = connection.execute(
            """
            SELECT callables.*, files.file_path
            FROM code_structural_callables AS callables
            JOIN code_files AS files
              ON files.id = callables.file_id
             AND files.engagement_id = callables.engagement_id
            WHERE callables.engagement_id = ? AND callables.repo_id = ?
              AND callables.repo_generation = ? AND callables.file_id = ?
              AND (callables.name = ? OR callables.qualified_name = ?)
            ORDER BY callables.id
            """,
            (
                engagement_id,
                repo_id,
                repo_generation,
                int(legacy["file_id"]),
                str(legacy["function_name"]),
                str(legacy["function_name"]),
            ),
        ).fetchall()
        if len(matches) != 1:
            connection.execute(
                """
                UPDATE code_analysis_results
                SET receipt_binding_status = ?
                WHERE id = ? AND receipt_binding_status = 'legacy_unbound'
                """,
                (
                    "legacy_ambiguous" if matches else "legacy_missing",
                    int(legacy["id"]),
                ),
            )
            continue
        matched = matches[0]
        callable_ref = {
            "callable_key": str(matched["callable_key"]),
            "file_id": int(matched["file_id"]),
            "file_path": str(matched["file_path"]),
            "name": str(matched["name"]),
            "qualified_name": str(matched["qualified_name"]),
            "start_line": int(matched["start_line"]),
            "end_line": int(matched["end_line"]),
        }
        connection.execute(
            """
            UPDATE code_analysis_results
            SET callable_refs_json = ?, receipt_binding_status = 'legacy_bound'
            WHERE id = ? AND receipt_binding_status = 'legacy_unbound'
            """,
            (_json_list_text([callable_ref]), int(legacy["id"])),
        )
        connection.execute(
            """
            INSERT OR IGNORE INTO code_analysis_result_callables (
                result_id, callable_id, file_id, ordinal
            ) VALUES (?, ?, ?, 0)
            """,
            (int(legacy["id"]), int(matched["id"]), int(matched["file_id"])),
        )


def _normalized_variant_language(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    return _STRUCTURAL_LANGUAGE_ALIASES.get(normalized, normalized)


def _normalize_variant_evidence_ref(engagement_root: str, evidence_ref: str) -> str:
    if evidence_ref != evidence_ref.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check evidence_ref must not contain surrounding whitespace",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in evidence_ref):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check evidence_ref must not contain control characters",
        )
    raw_path = Path(evidence_ref)
    if raw_path.is_absolute() or evidence_ref.startswith("~") or ".." in raw_path.parts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check evidence_ref must be an engagement-relative artifact path",
        )
    return _normalize_relative_path(Path(engagement_root).resolve(), evidence_ref)


def variant_input_identity_digest(
    *,
    repo: dict[str, Any],
    file_row: Any,
    parent_finding_slugs: list[str],
) -> str:
    payload = {
        "schema": VARIANT_INPUT_IDENTITY_SCHEMA,
        "repo_id": int(repo["id"]),
        "repo_generation": int(repo.get("active_generation", 0) or 0),
        "source_manifest_digest": str(repo.get("source_manifest_digest", "") or ""),
        "file": {
            "file_id": int(file_row["id"]),
            "file_path": str(file_row.get("file_path", "") or ""),
            "file_sha256": str(file_row.get("file_hash", "") or ""),
            "language": _normalized_variant_language(file_row.get("language", "")),
            "classification": str(file_row.get("classification", "") or "")
            .strip()
            .lower(),
            "role": str(file_row.get("role", "") or "").strip(),
            "slot_types": sorted(
                set(_json_decode(file_row.get("slot_types_json"), []))
            ),
        },
        "parent_finding_set_digest": _variant_parent_finding_set_digest(
            parent_finding_slugs
        ),
    }
    return hashlib.sha256(_json_text(payload).encode("utf-8")).hexdigest()


def _json_decode(value: Any, default: Any) -> Any:
    if isinstance(value, str) and value:
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return default
    return default


def _finding_snapshot_repo_id(finding: Any) -> int | None:
    provenance = _json_decode(dict(finding).get("provenance_json"), {})
    binding = provenance.get(CODE_SNAPSHOT_PROVENANCE_KEY)
    if not isinstance(binding, dict) or type(binding.get("repo_id")) is not int:
        return None
    return int(binding["repo_id"])


def _require_current_reportable_root_file_finding(
    connection,
    engagement_id: int,
    file_row: dict[str, Any],
    finding_slug: Any,
) -> None:
    slug = str(finding_slug or "")
    if not slug or slug != slug.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "disposition='finding' requires a non-empty canonical finding_slug"
            ),
        )
    finding_row = connection.execute(
        """
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ? AND slug = ?
        """,
        (engagement_id, slug),
    ).fetchone()
    if finding_row is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="finding_slug references an unknown finding in this engagement",
        )
    finding = dict(finding_row)
    if str(finding.get("status", "")) not in _REPORTABLE_FINDING_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="finding_slug must reference a reportable finding",
        )
    if not is_file_finding(str(finding.get("canonical_location", ""))):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="finding_slug must reference a file finding",
        )
    if _finding_snapshot_repo_id(finding) != int(file_row["repo_id"]):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "finding_slug must reference a file finding from the same repository"
            ),
        )
    if finding_code_snapshot_status(connection, engagement_id, finding) != "current":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "finding_slug must reference a finding bound to the current verified "
                "repository source generation"
            ),
        )
    variant_link = connection.execute(
        """
        SELECT 1
        FROM assessment_finding_links
        WHERE engagement_id = ? AND finding_id = ?
          AND link_kind = 'variant_of' AND retired_at IS NULL
        LIMIT 1
        """,
        (engagement_id, int(finding["id"])),
    ).fetchone()
    if variant_link is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="finding_slug must reference a root file finding, not a variant finding",
        )


def _reject_unknown_fields(payload: dict[str, Any], allowed_fields: set[str], *, entity_name: str) -> None:
    unknown_fields = sorted(key for key in payload if key not in allowed_fields)
    if unknown_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{entity_name} does not accept fields: {', '.join(unknown_fields)}",
        )


def _coerce_int(value: Any, *, field_name: str) -> int:
    if isinstance(value, bool):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer",
        )
    if isinstance(value, float):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer",
        )
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer",
        ) from exc


def _coerce_non_negative_int(value: Any, *, field_name: str) -> int:
    coerced = _coerce_int(value, field_name=field_name)
    if coerced < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be >= 0",
        )
    return coerced


def _require_strict_positive_id(value: Any, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a positive integer",
        )
    return value


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _merge_cwe_entry(existing: dict[str, Any], entry: dict[str, Any]) -> None:
    """Merge one CWE coverage entry using the same max/sum rules everywhere."""
    if _is_cwe_entry_not_applicable(entry):
        if _is_cwe_entry_not_applicable(existing):
            existing["not_applicable"] = True
            existing["disposition"] = entry.get("disposition", "not_applicable")
            if entry.get("notes"):
                existing["notes"] = entry.get("notes")
        return

    existing.pop("not_applicable", None)
    if _is_cwe_entry_not_applicable(existing):
        existing.pop("disposition", None)
    if entry.get("disposition"):
        existing["disposition"] = entry.get("disposition")

    if _coerce_float(entry.get("effort", 0)) > _coerce_float(existing.get("effort", 0)):
        existing["effort"] = entry.get("effort", 0)

    existing_chains = _safe_int(existing.get("entry_chains_traced", 0))
    new_chains = _safe_int(entry.get("entry_chains_traced", 0))
    existing["entry_chains_traced"] = existing_chains + new_chains

    for merge_key in ("functions_analyzed", "total_entry_chains"):
        new_val = _safe_int(entry.get(merge_key, 0))
        old_val = _safe_int(existing.get(merge_key, 0))
        if new_val > old_val:
            existing[merge_key] = new_val

    new_notes = entry.get("notes", "")
    if new_notes:
        existing["notes"] = new_notes


def _is_cwe_entry_not_applicable(entry: dict[str, Any]) -> bool:
    if entry.get("not_applicable") is True:
        return True
    disposition = str(entry.get("disposition", entry.get("status", ""))).strip().lower()
    return disposition in {"not_applicable", "not-applicable", "n/a", "na"}


def _merge_file_effort_entry(
    file_efforts: dict[int, dict[str, float]],
    file_not_applicable: dict[int, set[str]],
    file_id: int,
    entry: dict[str, Any],
) -> None:
    family = entry.get("family", "")
    if not family:
        return
    if _is_cwe_entry_not_applicable(entry):
        if family not in file_efforts[file_id]:
            file_not_applicable[file_id].add(family)
        return
    file_not_applicable[file_id].discard(family)
    effort = _coerce_float(entry.get("effort", 0))
    if family not in file_efforts[file_id] or effort > file_efforts[file_id][family]:
        file_efforts[file_id][family] = effort


def _merge_cwe_coverage_entries(
    cwe_by_file: dict[int, dict[str, dict[str, Any]]],
    file_id: int,
    entries: list[dict[str, Any]],
) -> None:
    if file_id not in cwe_by_file:
        cwe_by_file[file_id] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        family = entry.get("family", "")
        if not family:
            continue
        existing = cwe_by_file[file_id].get(family)
        if existing is None:
            cwe_by_file[file_id][family] = dict(entry)
        else:
            _merge_cwe_entry(existing, entry)


def _hydrate_code_repo(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["lsp_config"] = _json_decode(payload.get("lsp_config_json"), {})
    payload["git_churn"] = _json_decode(payload.get("git_churn_json"), {})
    payload["threat_model"] = _json_decode(payload.get("threat_model_json"), {})
    payload["structural_degraded_file_paths"] = _json_decode(
        payload.get("structural_degraded_file_paths_json"), []
    )
    payload["structural_artifact_truncated_file_paths"] = _json_decode(
        payload.get("structural_artifact_truncated_file_paths_json"), []
    )
    payload["structural_analysis_status_counts"] = _json_decode(
        payload.get("structural_analysis_status_counts_json"), {}
    )
    if payload.get("worktree_dirty") is not None:
        payload["worktree_dirty"] = bool(payload["worktree_dirty"])
    return payload


def _hydrate_code_file(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["slot_types"] = _json_decode(payload.get("slot_types_json"), [])
    payload["structural_unavailable_dimensions"] = _json_decode(
        payload.get("structural_unavailable_dimensions_json"), []
    )
    payload["structural_truncated_dimensions"] = _json_decode(
        payload.get("structural_truncated_dimensions_json"), []
    )
    payload["structural_signal_counts"] = _json_decode(
        payload.get("structural_signal_counts_json"), {}
    )
    payload["structural_artifact_truncated"] = bool(
        payload.get("structural_artifact_truncated")
    )
    return payload


def _hydrate_code_analysis_result(row: Any) -> dict[str, Any]:
    payload = dict(row)
    payload["supersedes"] = payload.pop("supersedes_result_id", None)
    payload["audit_metadata"] = _json_decode(payload.get("audit_metadata_json"), {})
    payload["cwe_coverage"] = _json_decode(payload.get("cwe_coverage_json"), [])
    payload["cross_file_triggers"] = _json_decode(payload.get("cross_file_triggers_json"), [])
    payload["callable_refs"] = _json_decode(payload.get("callable_refs_json"), [])
    payload["reviewed_spans"] = _json_decode(payload.get("reviewed_spans_json"), [])
    return payload


def _normalize_analysis_receipt_anchors(
    connection,
    *,
    engagement_id: int,
    queue_row: dict[str, Any],
    queue_file: dict[str, Any],
    receipt_kind: str,
    callable_refs: Any,
    reviewed_spans: Any,
) -> tuple[list[dict[str, Any]], list[int], list[dict[str, Any]], str]:
    if receipt_kind not in {"file", "call_chain"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="receipt_kind must be file or call_chain",
        )
    if not isinstance(callable_refs, list) or not isinstance(reviewed_spans, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="callable_refs and reviewed_spans must be lists",
        )
    if not callable_refs and not reviewed_spans:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="analysis result requires callable_refs or reviewed_spans",
        )
    all_file_ids: set[int] = set()
    for anchor in [*callable_refs, *reviewed_spans]:
        if not isinstance(anchor, dict) or type(anchor.get("file_id")) is not int:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="every source receipt anchor requires an exact integer file_id",
            )
        all_file_ids.add(int(anchor["file_id"]))
    file_rows = _get_file_rows(connection, engagement_id, all_file_ids)
    repo_id = int(queue_file["repo_id"])
    if any(int(row["repo_id"]) != repo_id for row in file_rows.values()):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="grouped source receipt cannot cross repository snapshots",
        )
    if receipt_kind == "file" and all_file_ids != {int(queue_file["id"])}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="file receipt anchors must all belong to the claimed queue file",
        )
    if int(queue_file["id"]) not in all_file_ids:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="grouped source receipt must include the claimed queue file",
        )

    canonical_refs: list[dict[str, Any]] = []
    callable_ids: list[int] = []
    seen_callable_ids: set[int] = set()
    for raw in callable_refs:
        _reject_unknown_fields(
            raw,
            {"file_id", "name", "qualified_name", "start_line", "end_line"},
            entity_name="structural callable reference",
        )
        file_id = int(raw["file_id"])
        row = connection.execute(
            """
            SELECT callables.*, files.file_path
            FROM code_structural_callables AS callables
            JOIN code_files AS files
              ON files.id = callables.file_id
             AND files.engagement_id = callables.engagement_id
            WHERE callables.engagement_id = ? AND callables.repo_id = ?
              AND callables.repo_generation = ?
              AND callables.source_manifest_digest = ?
              AND callables.file_id = ? AND callables.file_sha256 = ?
              AND callables.name = ? AND callables.qualified_name = ?
              AND callables.start_line = ? AND callables.end_line = ?
            """,
            (
                engagement_id,
                repo_id,
                int(queue_row["repo_generation"]),
                str(
                    connection.execute(
                        "SELECT source_manifest_digest FROM code_repos WHERE id = ?",
                        (repo_id,),
                    ).fetchone()[0]
                ),
                file_id,
                str(file_rows[file_id]["file_hash"]),
                raw.get("name"),
                raw.get("qualified_name"),
                raw.get("start_line"),
                raw.get("end_line"),
            ),
        ).fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="structural callable reference does not match the current structural index",
            )
        callable_id = int(row["id"])
        if callable_id in seen_callable_ids:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural callable references must be unique within a receipt",
            )
        seen_callable_ids.add(callable_id)
        callable_ids.append(callable_id)
        canonical_refs.append(
            {
                "callable_key": str(row["callable_key"]),
                "file_id": file_id,
                "file_path": str(row["file_path"]),
                "name": str(row["name"]),
                "qualified_name": str(row["qualified_name"]),
                "start_line": int(row["start_line"]),
                "end_line": int(row["end_line"]),
            }
        )

    if reviewed_spans:
        callable_publication = connection.execute(
            """
            SELECT 1
            FROM code_structural_callable_publications
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
            """,
            (engagement_id, repo_id, int(queue_row["repo_generation"])),
        ).fetchone()
        if callable_publication is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "reviewed spans require a sealed callable registry publication "
                    "before they can prove non-callable source coverage"
                ),
            )
    canonical_spans: list[dict[str, Any]] = []
    seen_spans: set[tuple[int, int, int, str]] = set()
    for raw in reviewed_spans:
        _reject_unknown_fields(
            raw,
            {"file_id", "start_line", "end_line", "label"},
            entity_name="reviewed span",
        )
        file_id = int(raw["file_id"])
        start_line = raw.get("start_line")
        end_line = raw.get("end_line")
        label = str(raw.get("label") or "")
        if (
            type(start_line) is not int
            or type(end_line) is not int
            or start_line < 1
            or end_line < start_line
            or end_line > int(file_rows[file_id]["loc"])
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reviewed span must fall within the sealed file",
            )
        function_dimension_incomplete = (
            str(file_rows[file_id].get("structural_analysis_status") or "")
            == "unsupported"
            or "functions"
            in {
                *_json_decode(
                    file_rows[file_id].get("structural_unavailable_dimensions_json"),
                    [],
                ),
                *_json_decode(
                    file_rows[file_id].get("structural_truncated_dimensions_json"),
                    [],
                ),
            }
        )
        if function_dimension_incomplete and (
            start_line != 1 or end_line != int(file_rows[file_id]["loc"])
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "reviewed spans require whole-file coverage while the structural "
                    "function registry is incomplete"
                ),
            )
        identity = (file_id, start_line, end_line, label)
        if identity in seen_spans:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="reviewed spans must be unique within a receipt",
            )
        overlapped_callable_ids = {
            int(row["id"])
            for row in connection.execute(
                """
                SELECT id
                FROM code_structural_callables
                WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
                  AND file_id = ? AND start_line <= ? AND end_line >= ?
                """,
                (
                    engagement_id,
                    repo_id,
                    int(queue_row["repo_generation"]),
                    file_id,
                    end_line,
                    start_line,
                ),
            ).fetchall()
        }
        missing_callable_refs = overlapped_callable_ids - seen_callable_ids
        if missing_callable_refs:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "reviewed span overlaps a registered structural callable; "
                    "submit every overlapped callable as an exact callable_ref"
                ),
            )
        seen_spans.add(identity)
        canonical_spans.append(
            {
                "file_id": file_id,
                "file_path": str(file_rows[file_id]["file_path"]),
                "start_line": start_line,
                "end_line": end_line,
                "label": label,
            }
        )
    binding_status = "structural" if canonical_refs else "source_span"
    return canonical_refs, callable_ids, canonical_spans, binding_status


def _analysis_result_row(connection, result_id: int) -> Any:
    return connection.execute(
        """
        SELECT
            results.*,
            findings.status AS finding_workflow_status,
            findings.verification_status AS finding_verification_status,
            (
                SELECT replacement.id
                FROM code_analysis_results AS replacement
                WHERE replacement.supersedes_result_id = results.id
            ) AS replaced_by_result_id
        FROM code_analysis_results AS results
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = results.engagement_id
         AND findings.slug = results.finding_slug
        WHERE results.id = ?
        """,
        (result_id,),
    ).fetchone()


def _get_repo_row_raw(connection, engagement_id: int, repo_id: int) -> dict[str, Any]:
    row = connection.execute(
        "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
        (engagement_id, repo_id),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return dict(row)


def _get_published_repo_row(connection, engagement_id: int, repo_id: int) -> dict[str, Any]:
    row = _get_repo_row_raw(connection, engagement_id, repo_id)
    if int(row.get("active_generation", 0)) == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return row


def _get_repo_rows(connection, engagement_id: int, repo_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not repo_ids:
        return {}
    placeholders = ",".join("?" for _ in repo_ids)
    rows = connection.execute(
        f"""
        SELECT * FROM code_repos
        WHERE engagement_id = ? AND active_generation > 0
          AND id IN ({placeholders})
        """,
        (engagement_id, *sorted(repo_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(repo_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return found


def _get_file_rows(connection, engagement_id: int, file_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not file_ids:
        return {}
    placeholders = ",".join("?" for _ in file_ids)
    rows = connection.execute(
        f"""
        SELECT files.*
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE files.engagement_id = ? AND files.retired_at IS NULL
          AND files.id IN ({placeholders})
        """,
        (engagement_id, *sorted(file_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(file_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
    return found


def _get_queue_rows(connection, engagement_id: int, item_ids: set[int]) -> dict[int, dict[str, Any]]:
    if not item_ids:
        return {}
    placeholders = ",".join("?" for _ in item_ids)
    rows = connection.execute(
        f"""
        SELECT queue.*
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE queue.engagement_id = ? AND queue.id IN ({placeholders})
        """,
        (engagement_id, *sorted(item_ids)),
    ).fetchall()
    found = {int(row["id"]): dict(row) for row in rows}
    if len(found) != len(item_ids):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Queue item not found")
    return found


_QUEUE_ACTIVE_STATUSES = frozenset({"pending", "processing"})


def _canonical_queue_attempt_state(
    current_rows: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str | None]:
    """Return latest/active rows and quarantine malformed active history.

    Callers supply one file's current-generation attempts ordered by ascending
    queue id. A single active row is valid only when it is also the latest
    attempt; otherwise fetch cannot claim it and no writer may mutate or bind
    to it.
    """
    if not current_rows:
        return None, None, None
    latest = current_rows[-1]
    active_rows = [
        row
        for row in current_rows
        if str(row.get("status", "")) in _QUEUE_ACTIVE_STATUSES
    ]
    if len(active_rows) > 1:
        return latest, None, "multiple-active"
    active = active_rows[0] if active_rows else None
    if active is not None and int(active["id"]) != int(latest["id"]):
        return latest, active, "superseded-active"
    return latest, active, None


def _require_queue_status(
    queue_rows: dict[int, dict[str, Any]],
    *,
    expected_status: str,
    action: str,
) -> None:
    invalid = {
        item_id: str(row.get("status", ""))
        for item_id, row in queue_rows.items()
        if str(row.get("status", "")) != expected_status
    }
    if not invalid:
        return
    if len(invalid) == 1:
        item_id, row_status = next(iter(invalid.items()))
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot {action} queue item {item_id} unless it is "
                f"{expected_status}; current status is {row_status or 'unknown'}"
            ),
        )
    details = ", ".join(
        f"{item_id}={row_status or 'unknown'}"
        for item_id, row_status in sorted(invalid.items())
    )
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Cannot {action} queue items unless they are {expected_status}: {details}",
    )


def _require_queue_lease(
    queue_rows: dict[int, dict[str, Any]], *, agent_name: str, lease_token: str, action: str
) -> None:
    invalid = [
        item_id
        for item_id, row in queue_rows.items()
        if str(row.get("assigned_agent", "")) != agent_name
        or str(row.get("lease_token", "")) != lease_token
    ]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot {action}: queue lease is no longer owned by {agent_name}",
        )


def _require_queue_generation(
    connection, engagement_id: int, queue_rows: dict[int, dict[str, Any]], *, action: str
) -> None:
    """Lock and reject writes outside the one canonical current attempt."""
    if not queue_rows:
        return
    if not getattr(connection, "in_transaction", False):
        connection.execute("BEGIN IMMEDIATE")
    placeholders = ",".join("?" for _ in queue_rows)
    current_rows = connection.execute(
        f"""
        SELECT queue.id, repos.active_generation
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE queue.engagement_id = ? AND queue.id IN ({placeholders})
        """,
        (engagement_id, *sorted(queue_rows)),
    ).fetchall()
    current_generations = {
        int(row["id"]): int(row["active_generation"] or 0) for row in current_rows
    }
    stale = [
        item_id
        for item_id, row in queue_rows.items()
        if int(row.get("repo_generation", 0) or 0) != current_generations.get(item_id, 0)
    ]
    if stale:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot {action}: repository generation changed for queue items "
                f"{', '.join(str(item_id) for item_id in sorted(stale))}; refetch and retry"
            ),
        )

    invalid: list[int] = []
    state_cache: dict[tuple[int, int], tuple[dict[str, Any] | None, str | None]] = {}
    for item_id, queue_row in queue_rows.items():
        file_id = int(queue_row["file_id"])
        repo_generation = int(queue_row["repo_generation"])
        state_key = (file_id, repo_generation)
        if state_key not in state_cache:
            attempts = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT *
                    FROM code_analysis_queue
                    WHERE engagement_id = ? AND file_id = ? AND repo_generation = ?
                    ORDER BY id ASC
                    """,
                    (engagement_id, file_id, repo_generation),
                ).fetchall()
            ]
            latest, _, issue = _canonical_queue_attempt_state(attempts)
            state_cache[state_key] = (latest, issue)
        latest, issue = state_cache[state_key]
        if (
            issue is not None
            or latest is None
            or int(latest["id"]) != item_id
        ):
            invalid.append(item_id)
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Cannot {action}: queue items {', '.join(str(item_id) for item_id in sorted(invalid))} "
                "are not the sole canonical latest attempts; reconcile queue history first"
            ),
        )


def _sync_file_analysis_status(connection, engagement_id: int, file_id: int) -> None:
    queue_row = connection.execute(
        """
        WITH current_attempts AS (
            SELECT queue.status,
                   ROW_NUMBER() OVER (ORDER BY queue.id DESC) AS attempt_rank,
                   SUM(CASE WHEN queue.status IN ('pending', 'processing')
                            THEN 1 ELSE 0 END) OVER () AS active_count
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ? AND queue.file_id = ?
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
        )
        SELECT status, active_count
        FROM current_attempts
        WHERE attempt_rank = 1
        """,
        (engagement_id, file_id),
    ).fetchone()
    queue_counts = {} if queue_row is None else {str(queue_row["status"]): 1}
    latest_is_active = (
        queue_row is not None
        and str(queue_row["status"]) in _QUEUE_ACTIVE_STATUSES
    )
    invalid_active_history = (
        queue_row is not None
        and int(queue_row["active_count"] or 0) > (1 if latest_is_active else 0)
    )
    pending_queue = queue_counts.get("pending", 0)
    processing_queue = queue_counts.get("processing", 0)
    done_queue = queue_counts.get("done", 0)
    error_queue = queue_counts.get("error", 0)
    queue_needs_context = queue_counts.get("needs_context", 0)

    direct_result_counts = connection.execute(
        f"""
        SELECT results.disposition, COUNT(*) AS total
        FROM code_analysis_results AS results
        JOIN code_analysis_queue AS result_queue
          ON result_queue.id = results.queue_item_id
        JOIN code_files AS files
          ON files.id = results.file_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE results.engagement_id = ? AND results.file_id = ?
          AND ({_current_result_receipt_sql(
              "results", "result_queue", "files", "repos", allow_processing=True
          )})
        GROUP BY results.disposition
        """,
        (engagement_id, file_id),
    ).fetchall()
    direct_counts = {str(row["disposition"]): int(row["total"]) for row in direct_result_counts}
    direct_total = sum(direct_counts.values())
    direct_needs_context = direct_counts.get("needs_context", 0)

    # File-direct mode: a direct analysis record without queue state is still
    # durable analysis. Queue state takes precedence when work is active.
    if invalid_active_history:
        next_status = "in_progress"
    elif not queue_counts:
        if direct_needs_context > 0:
            next_status = "needs_context"
        elif direct_total > 0:
            next_status = "analyzed"
        else:
            return
    elif queue_needs_context > 0:
        next_status = "needs_context"
    elif pending_queue == 0 and processing_queue == 0 and done_queue > 0:
        next_status = "analyzed"
    elif processing_queue > 0 or error_queue > 0:
        next_status = "in_progress"
    elif pending_queue > 0:
        next_status = "queued"
    elif direct_needs_context > 0:
        next_status = "needs_context"
    elif direct_total > 0:
        next_status = "analyzed"
    else:
        next_status = "classified"

    connection.execute(
        """
        UPDATE code_files
        SET analysis_status = ?, updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (next_status, engagement_id, file_id),
    )
    module_row = connection.execute(
        "SELECT module_id FROM code_files WHERE engagement_id = ? AND id = ?",
        (engagement_id, file_id),
    ).fetchone()
    module_id = None if module_row is None else module_row["module_id"]
    if module_id is not None:
        _sync_module_rollup(connection, engagement_id, int(module_id))


def _derive_module_analysis_status(status_counts: dict[str, int]) -> str:
    if not status_counts:
        return "pending"
    analyzed_total = status_counts.get("analyzed", 0) + status_counts.get("done", 0)
    total_files = sum(status_counts.values())
    if status_counts.get("needs_context", 0) > 0:
        return "needs_context"
    if total_files > 0 and analyzed_total == total_files:
        return "analyzed"
    if status_counts.get("in_progress", 0) > 0 or analyzed_total > 0:
        return "in_progress"
    if status_counts.get("queued", 0) > 0:
        return "queued"
    if status_counts.get("classified", 0) > 0:
        return "classified"
    return "pending"


def _sync_module_rollup(connection, engagement_id: int, module_id: int) -> None:
    status_rows = connection.execute(
        """
        SELECT analysis_status, COUNT(*) AS total
        FROM code_files
        WHERE engagement_id = ? AND module_id = ? AND retired_at IS NULL
        GROUP BY analysis_status
        """,
        (engagement_id, module_id),
    ).fetchall()
    status_counts = {str(row["analysis_status"]): int(row["total"]) for row in status_rows}
    file_count = sum(status_counts.values())
    critical_file_count = _scalar_row(
        connection,
        """
        SELECT COUNT(*)
        FROM code_files
        WHERE engagement_id = ? AND module_id = ? AND classification = 'critical'
          AND retired_at IS NULL
        """,
        (engagement_id, module_id),
    )
    connection.execute(
        """
        UPDATE code_modules
        SET file_count = ?,
            critical_file_count = ?,
            analysis_status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (
            file_count,
            critical_file_count,
            _derive_module_analysis_status(status_counts),
            engagement_id,
            module_id,
        ),
    )


_TRIGGER_STATUS_PENDING = "pending"
_TRIGGER_STATUS_QUEUED = "queued"
_TRIGGER_STATUS_RESOLVED = "resolved"
_TRIGGER_STATUS_EXTERNAL_CONTEXT = "external_context_unavailable"
_TRIGGER_STATUS_SOURCE_EQUIVALENT = "source_equivalent_analyzed"
_TRIGGER_STATUS_NOT_APPLICABLE = "not_applicable"


def _valid_nonempty_json_array_sql(expression: str) -> str:
    return (
        f"CASE WHEN json_valid({expression}) "
        f"THEN json_type({expression}) = 'array' "
        f"AND json_array_length({expression}) > 0 "
        f"AND NOT EXISTS ("
        f"SELECT 1 FROM json_each({expression}) AS coverage_entry "
        f"WHERE CASE WHEN coverage_entry.type != 'object' THEN 1 "
        f"ELSE CASE WHEN json_type(coverage_entry.value, '$.family') = 'text' "
        f"AND trim(json_extract(coverage_entry.value, '$.family')) != '' "
        f"THEN 0 ELSE 1 END END = 1"
        f") ELSE 0 END"
    )


def _valid_current_root_finding_result_sql(
    queue_alias: str,
    result_alias: str,
) -> str:
    reportable_statuses = ", ".join(
        f"'{status_value}'"
        for status_value in sorted(_REPORTABLE_FINDING_STATUSES)
    )
    return f"""
        trim({result_alias}.finding_slug) != ''
        AND EXISTS (
            SELECT 1
            FROM assessment_findings AS linked_finding
            JOIN code_files AS reviewed_file
              ON reviewed_file.engagement_id = {queue_alias}.engagement_id
             AND reviewed_file.id = {queue_alias}.file_id
            JOIN code_repos AS reviewed_repo
              ON reviewed_repo.engagement_id = reviewed_file.engagement_id
             AND reviewed_repo.id = reviewed_file.repo_id
             AND reviewed_repo.active_generation > 0
             AND reviewed_repo.source_snapshot_quality = 'verified'
            WHERE linked_finding.engagement_id = {result_alias}.engagement_id
              AND linked_finding.slug = {result_alias}.finding_slug
              AND linked_finding.status IN ({reportable_statuses})
              AND substr(ltrim(linked_finding.canonical_location), 1, 5) = 'file:'
              AND NOT EXISTS (
                  SELECT 1
                  FROM assessment_finding_links AS variant_link
                  WHERE variant_link.engagement_id = linked_finding.engagement_id
                    AND variant_link.finding_id = linked_finding.id
                    AND variant_link.link_kind = 'variant_of'
                    AND variant_link.retired_at IS NULL
              )
              AND CASE WHEN json_valid(linked_finding.provenance_json) THEN (
                  json_type(
                      linked_finding.provenance_json,
                      '$.code_snapshot.repo_id'
                  ) = 'integer'
                  AND json_extract(
                      linked_finding.provenance_json,
                      '$.code_snapshot.repo_id'
                  ) = reviewed_file.repo_id
                  AND json_type(
                      linked_finding.provenance_json,
                      '$.code_snapshot.repo_generation'
                  ) = 'integer'
                  AND json_extract(
                      linked_finding.provenance_json,
                      '$.code_snapshot.repo_generation'
                  ) = reviewed_repo.active_generation
                  AND json_type(
                      linked_finding.provenance_json,
                      '$.code_snapshot.source_manifest_digest'
                  ) = 'text'
                  AND json_extract(
                      linked_finding.provenance_json,
                      '$.code_snapshot.source_manifest_digest'
                  ) = reviewed_repo.source_manifest_digest
              ) ELSE 0 END
        )
    """


def _valid_claimed_terminal_attempt_sql(queue_alias: str) -> str:
    return f"""
        trim({queue_alias}.assigned_agent) != ''
        AND trim({queue_alias}.lease_token) != ''
        AND {queue_alias}.consumed_at IS NOT NULL
        AND trim({queue_alias}.consumed_at) != ''
        AND {queue_alias}.completed_at IS NOT NULL
        AND trim({queue_alias}.completed_at) != ''
    """


def _valid_claimed_result_receipt_sql(
    queue_alias: str,
    result_alias: str,
) -> str:
    return f"""
        trim({result_alias}.agent_name) != ''
        AND {result_alias}.agent_name = {queue_alias}.assigned_agent
        AND trim({result_alias}.lease_token) != ''
        AND {result_alias}.lease_token = {queue_alias}.lease_token
        AND trim({result_alias}.result_fingerprint) != ''
        AND {result_alias}.receipt_binding_status NOT IN (
            'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
        )
    """


def _result_not_replaced_sql(result_alias: str) -> str:
    return f"""
        NOT EXISTS (
            SELECT 1
            FROM code_analysis_results AS replacement_result
            WHERE replacement_result.supersedes_result_id = {result_alias}.id
        )
    """


def _successful_terminal_review_row_sql(
    queue_alias: str,
    *,
    include_superseded_results: bool = False,
) -> str:
    valid_coverage = _valid_nonempty_json_array_sql(
        f"{queue_alias}.cwe_coverage_json"
    )
    def result_is_current(result_alias: str) -> str:
        if include_superseded_results:
            return "1 = 1"
        return (
            f"{result_alias}.superseded_at IS NULL "
            f"AND ({_result_not_replaced_sql(result_alias)})"
        )

    return f"""
        {queue_alias}.status = 'done'
        AND {queue_alias}.disposition IN ('clean', 'finding', 'suspicious')
        AND ({_valid_claimed_terminal_attempt_sql(queue_alias)})
        AND ({valid_coverage})
        AND (
            (
                {queue_alias}.disposition = 'clean'
                AND trim({queue_alias}.analysis_notes) != ''
                AND NOT EXISTS (
                    SELECT 1
                    FROM code_analysis_results AS contradictory_result
                    WHERE contradictory_result.engagement_id = {queue_alias}.engagement_id
                      AND contradictory_result.queue_item_id = {queue_alias}.id
                      AND contradictory_result.file_id = {queue_alias}.file_id
                      AND contradictory_result.lease_token = {queue_alias}.lease_token
                      AND contradictory_result.repo_generation = {queue_alias}.repo_generation
                      AND contradictory_result.disposition IN ('finding', 'suspicious')
                      AND ({result_is_current("contradictory_result")})
                      AND ({_valid_claimed_result_receipt_sql(
                          queue_alias, "contradictory_result"
                      )})
                )
            )
            OR (
                {queue_alias}.disposition IN ('finding', 'suspicious')
                AND EXISTS (
                    SELECT 1
                    FROM code_analysis_results AS completed_result
                    WHERE completed_result.engagement_id = {queue_alias}.engagement_id
                      AND completed_result.queue_item_id = {queue_alias}.id
                      AND completed_result.file_id = {queue_alias}.file_id
                      AND completed_result.lease_token = {queue_alias}.lease_token
                      AND completed_result.repo_generation = {queue_alias}.repo_generation
                      AND completed_result.disposition = {queue_alias}.disposition
                      AND ({result_is_current("completed_result")})
                      AND ({_valid_claimed_result_receipt_sql(
                          queue_alias, "completed_result"
                      )})
                      AND (
                          trim(completed_result.evidence) != ''
                          OR trim(completed_result.evidence_ref) != ''
                      )
                      AND (
                          {queue_alias}.disposition = 'suspicious'
                          OR (
                              {queue_alias}.disposition = 'finding'
                              AND ({_valid_current_root_finding_result_sql(
                                  queue_alias, "completed_result"
                              )})
                          )
                      )
                )
                AND NOT EXISTS (
                    SELECT 1
                    FROM code_analysis_results AS contradictory_result
                    WHERE contradictory_result.engagement_id = {queue_alias}.engagement_id
                      AND contradictory_result.queue_item_id = {queue_alias}.id
                      AND contradictory_result.file_id = {queue_alias}.file_id
                      AND contradictory_result.lease_token = {queue_alias}.lease_token
                      AND contradictory_result.repo_generation = {queue_alias}.repo_generation
                      AND contradictory_result.disposition IN ('finding', 'suspicious')
                      AND contradictory_result.disposition != {queue_alias}.disposition
                      AND ({result_is_current("contradictory_result")})
                      AND ({_valid_claimed_result_receipt_sql(
                          queue_alias, "contradictory_result"
                      )})
                )
            )
        )
        AND (
            NOT EXISTS (
                SELECT 1 FROM code_files AS receipt_required_file
                WHERE receipt_required_file.engagement_id = {queue_alias}.engagement_id
                  AND receipt_required_file.id = {queue_alias}.file_id
                  AND receipt_required_file.classification IN ('critical', 'high')
            )
            OR EXISTS (
                SELECT 1
                FROM code_analysis_results AS source_receipt
                WHERE source_receipt.engagement_id = {queue_alias}.engagement_id
                  AND source_receipt.queue_item_id = {queue_alias}.id
                  AND source_receipt.file_id = {queue_alias}.file_id
                  AND source_receipt.lease_token = {queue_alias}.lease_token
                  AND source_receipt.repo_generation = {queue_alias}.repo_generation
                  AND source_receipt.disposition = {queue_alias}.disposition
                  AND ({result_is_current("source_receipt")})
                  AND ({_valid_claimed_result_receipt_sql(
                      queue_alias, "source_receipt"
                  )})
                  AND (
                      EXISTS (
                          SELECT 1
                          FROM code_analysis_result_callables AS source_link
                          WHERE source_link.result_id = source_receipt.id
                            AND source_link.file_id = {queue_alias}.file_id
                      )
                      OR EXISTS (
                          SELECT 1 FROM json_each(source_receipt.reviewed_spans_json) AS source_span
                          WHERE CAST(json_extract(source_span.value, '$.file_id') AS INTEGER)
                                = {queue_alias}.file_id
                      )
                  )
            )
        )
    """


def _latest_current_queue_attempt_sql(queue_alias: str, repos_alias: str) -> str:
    return f"""
        {queue_alias}.id = (
            SELECT MAX(latest_attempt.id)
            FROM code_analysis_queue AS latest_attempt
            WHERE latest_attempt.engagement_id = {queue_alias}.engagement_id
              AND latest_attempt.file_id = {queue_alias}.file_id
              AND latest_attempt.repo_generation = {repos_alias}.active_generation
              AND latest_attempt.source_superseded_at IS NULL
        )
    """


def _no_superseded_active_attempt_sql(queue_alias: str, repos_alias: str) -> str:
    return f"""
        NOT EXISTS (
            SELECT 1
            FROM code_analysis_queue AS superseded_active
            WHERE superseded_active.engagement_id = {queue_alias}.engagement_id
              AND superseded_active.file_id = {queue_alias}.file_id
              AND superseded_active.repo_generation = {repos_alias}.active_generation
              AND superseded_active.source_superseded_at IS NULL
              AND superseded_active.status IN ('pending', 'processing')
              AND superseded_active.id != {queue_alias}.id
        )
    """


def _invalid_active_history_exists_sql(files_alias: str) -> str:
    return f"""
        EXISTS (
            SELECT 1
            FROM code_analysis_queue AS superseded_active
            JOIN code_repos AS active_repo
              ON active_repo.id = {files_alias}.repo_id
             AND active_repo.engagement_id = {files_alias}.engagement_id
            WHERE superseded_active.engagement_id = {files_alias}.engagement_id
              AND superseded_active.file_id = {files_alias}.id
              AND superseded_active.repo_generation = active_repo.active_generation
              AND superseded_active.source_superseded_at IS NULL
              AND superseded_active.status IN ('pending', 'processing')
              AND superseded_active.id != (
                  SELECT MAX(latest_attempt.id)
                  FROM code_analysis_queue AS latest_attempt
                  WHERE latest_attempt.engagement_id = {files_alias}.engagement_id
                    AND latest_attempt.file_id = {files_alias}.id
                    AND latest_attempt.repo_generation = active_repo.active_generation
                    AND latest_attempt.source_superseded_at IS NULL
              )
        )
    """


def _current_result_receipt_sql(
    result_alias: str,
    queue_alias: str,
    files_alias: str,
    repos_alias: str,
    *,
    allow_processing: bool,
) -> str:
    if allow_processing:
        status_clause = (
            f"({queue_alias}.status = 'processing' OR "
            f"({queue_alias}.status = 'done' "
            f"AND {queue_alias}.disposition = {result_alias}.disposition))"
        )
    else:
        status_clause = (
            f"{queue_alias}.status = 'done' "
            f"AND {queue_alias}.disposition = {result_alias}.disposition"
        )
    return f"""
        {result_alias}.superseded_at IS NULL
        AND {result_alias}.source_superseded_at IS NULL
        AND ({_result_not_replaced_sql(result_alias)})
        AND {result_alias}.receipt_binding_status NOT IN (
            'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
        )
        AND {result_alias}.engagement_id = {queue_alias}.engagement_id
        AND {result_alias}.queue_item_id = {queue_alias}.id
        AND {result_alias}.file_id = {queue_alias}.file_id
        AND {result_alias}.lease_token = {queue_alias}.lease_token
        AND {result_alias}.repo_generation = {queue_alias}.repo_generation
        AND {queue_alias}.source_superseded_at IS NULL
        AND {queue_alias}.file_id = {files_alias}.id
        AND {queue_alias}.engagement_id = {files_alias}.engagement_id
        AND {files_alias}.repo_id = {repos_alias}.id
        AND {files_alias}.engagement_id = {repos_alias}.engagement_id
        AND {repos_alias}.active_generation > 0
        AND {result_alias}.repo_generation = {repos_alias}.active_generation
        AND ({_latest_current_queue_attempt_sql(queue_alias, repos_alias)})
        AND ({_no_superseded_active_attempt_sql(queue_alias, repos_alias)})
        AND ({status_clause})
    """


def _current_terminal_review_exists_sql(*, allow_accounted_skip: bool) -> str:
    accounted_skip = """
        OR (
            completed_review.disposition = 'skipped'
            AND trim(completed_review.skip_reason) != ''
        )
    """ if allow_accounted_skip else ""
    successful_review = _successful_terminal_review_row_sql("completed_review")
    return f"""
        EXISTS (
            SELECT 1
            FROM code_analysis_queue AS completed_review
            JOIN code_repos AS completed_review_repo
              ON completed_review_repo.id = files.repo_id
             AND completed_review_repo.engagement_id = files.engagement_id
            WHERE completed_review.engagement_id = files.engagement_id
              AND completed_review.file_id = files.id
              AND completed_review.status = 'done'
              AND completed_review.repo_generation = completed_review_repo.active_generation
              AND completed_review.source_superseded_at IS NULL
              AND ({_latest_current_queue_attempt_sql(
                  "completed_review", "completed_review_repo"
              )})
              AND ({_no_superseded_active_attempt_sql(
                  "completed_review", "completed_review_repo"
              )})
              AND ({_valid_claimed_terminal_attempt_sql("completed_review")})
              AND (
                  ({successful_review})
                  {accounted_skip}
              )
        )
    """


# Semantic review is intentionally stricter than all-file accounting: a
# structured skip explains exclusion, but cannot prove a high-risk or degraded
# file received source review.
_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL = _current_terminal_review_exists_sql(
    allow_accounted_skip=False
)
_CURRENT_ACCOUNTED_FILE_EXISTS_SQL = _current_terminal_review_exists_sql(
    allow_accounted_skip=True
)


def _current_suspicious_analysis_counts(
    connection,
    engagement_id: int,
) -> dict[int, int]:
    semantic_review = _successful_terminal_review_row_sql(
        "semantic_attempt",
        include_superseded_results=True,
    )
    rows = connection.execute(
        f"""
        WITH semantic_attempts AS (
            SELECT files.repo_id,
                   semantic_attempt.file_id,
                   semantic_attempt.disposition,
                   ROW_NUMBER() OVER (
                       PARTITION BY semantic_attempt.file_id
                       ORDER BY semantic_attempt.id DESC
                   ) AS semantic_rank
            FROM code_analysis_queue AS semantic_attempt
            JOIN code_files AS files
              ON files.id = semantic_attempt.file_id
             AND files.engagement_id = semantic_attempt.engagement_id
            JOIN code_repos AS semantic_repo
              ON semantic_repo.id = files.repo_id
             AND semantic_repo.engagement_id = files.engagement_id
             AND semantic_repo.active_generation > 0
            WHERE semantic_attempt.engagement_id = ?
              AND semantic_attempt.repo_generation = semantic_repo.active_generation
              AND semantic_attempt.source_superseded_at IS NULL
              AND ({semantic_review})
        )
        SELECT repo_id, COUNT(*) AS suspicious_count
        FROM semantic_attempts
        WHERE semantic_rank = 1 AND disposition = 'suspicious'
        GROUP BY repo_id
        ORDER BY repo_id
        """,
        (engagement_id,),
    ).fetchall()
    return {
        int(row["repo_id"]): int(row["suspicious_count"])
        for row in rows
    }


_TERMINAL_TRIGGER_RESOLUTION_STATUSES = frozenset(
    {
        _TRIGGER_STATUS_EXTERNAL_CONTEXT,
        _TRIGGER_STATUS_SOURCE_EQUIVALENT,
        _TRIGGER_STATUS_NOT_APPLICABLE,
    }
)
_TRIGGER_STATUSES = frozenset(
    {
        _TRIGGER_STATUS_PENDING,
        _TRIGGER_STATUS_QUEUED,
        _TRIGGER_STATUS_RESOLVED,
        *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
    }
)


def _has_current_successful_review(connection, engagement_id: int, file_id: int) -> bool:
    row = connection.execute(
        f"""
        SELECT 1
        FROM code_files AS files
        WHERE files.engagement_id = ? AND files.id = ?
          AND files.retired_at IS NULL
          AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL})
        """,
        (engagement_id, file_id),
    ).fetchone()
    return row is not None


def _trigger_status_for_file(connection, engagement_id: int, file_id: int) -> str:
    trigger_rows = connection.execute(
        f"""
        SELECT triggers.status, COUNT(*) AS total
        FROM code_analysis_triggers AS triggers
        JOIN code_repos AS repos
          ON repos.id = triggers.repo_id
         AND repos.engagement_id = triggers.engagement_id
         AND repos.active_generation > 0
        WHERE triggers.engagement_id = ? AND triggers.target_file_id = ?
          AND triggers.repo_generation = repos.active_generation
          AND triggers.source_superseded_at IS NULL
          AND triggers.status NOT IN ({','.join('?' for _ in _TERMINAL_TRIGGER_RESOLUTION_STATUSES)})
        GROUP BY triggers.status
        """,
        (
            engagement_id,
            file_id,
            *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
        ),
    ).fetchall()
    trigger_counts = {str(row["status"]): int(row["total"]) for row in trigger_rows}
    if trigger_counts.get(_TRIGGER_STATUS_PENDING, 0) > 0:
        return _TRIGGER_STATUS_PENDING
    if trigger_counts.get(_TRIGGER_STATUS_QUEUED, 0) > 0:
        return _TRIGGER_STATUS_QUEUED
    if trigger_counts.get(_TRIGGER_STATUS_RESOLVED, 0) > 0:
        return _TRIGGER_STATUS_RESOLVED

    queue_row = connection.execute(
        """
        WITH current_attempts AS (
            SELECT queue.status,
                   ROW_NUMBER() OVER (ORDER BY queue.id DESC) AS attempt_rank,
                   SUM(CASE WHEN queue.status IN ('pending', 'processing')
                            THEN 1 ELSE 0 END) OVER () AS active_count
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ? AND queue.file_id = ?
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
        )
        SELECT status, active_count
        FROM current_attempts
        WHERE attempt_rank = 1
        """,
        (engagement_id, file_id),
    ).fetchone()
    if queue_row is not None:
        latest_status = str(queue_row["status"])
        latest_is_active = latest_status in _QUEUE_ACTIVE_STATUSES
        if int(queue_row["active_count"] or 0) > (1 if latest_is_active else 0):
            return _TRIGGER_STATUS_QUEUED
    else:
        latest_status = ""
    if latest_status in {"pending", "processing", "needs_context"}:
        return _TRIGGER_STATUS_QUEUED
    if _has_current_successful_review(connection, engagement_id, file_id):
        return _TRIGGER_STATUS_RESOLVED
    return _TRIGGER_STATUS_PENDING


def _bound_trigger_status(
    connection,
    engagement_id: int,
    trigger_id: int,
    file_id: int,
    queue_item_id: int | None,
) -> tuple[str, bool]:
    if queue_item_id is None:
        return _TRIGGER_STATUS_PENDING, False
    successful_review = _successful_terminal_review_row_sql("queue")
    row = connection.execute(
        f"""
        SELECT queue.status, queue.cross_file_triggers_json,
               CASE WHEN ({successful_review}) THEN 1 ELSE 0 END AS successful_review
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE queue.engagement_id = ? AND queue.id = ? AND queue.file_id = ?
          AND queue.repo_generation = repos.active_generation
          AND queue.source_superseded_at IS NULL
          AND ({_latest_current_queue_attempt_sql("queue", "repos")})
          AND ({_no_superseded_active_attempt_sql("queue", "repos")})
        """,
        (engagement_id, queue_item_id, file_id),
    ).fetchone()
    if row is None:
        return _TRIGGER_STATUS_PENDING, True
    queue_triggers = _json_decode(row["cross_file_triggers_json"], [])
    if not any(
        isinstance(entry, dict)
        and type(entry.get("trigger_id")) is int
        and int(entry["trigger_id"]) == trigger_id
        and entry.get("source") == "code_analysis_trigger"
        for entry in queue_triggers
    ):
        return _TRIGGER_STATUS_PENDING, True
    if str(row["status"]) in {"pending", "processing", "needs_context"}:
        return _TRIGGER_STATUS_QUEUED, False
    if bool(row["successful_review"]):
        return _TRIGGER_STATUS_RESOLVED, False
    return _TRIGGER_STATUS_PENDING, False


def _sync_trigger_status_for_file(connection, engagement_id: int, file_id: int) -> None:
    file_row = _get_file_rows(connection, engagement_id, {file_id})[file_id]
    terminal_placeholders = ",".join("?" for _ in _TERMINAL_TRIGGER_RESOLUTION_STATUSES)
    trigger_rows = connection.execute(
        f"""
        SELECT id, resolved_queue_item_id
        FROM code_analysis_triggers
        WHERE engagement_id = ?
          AND source_superseded_at IS NULL
          AND repo_generation = (
              SELECT active_generation
              FROM code_repos
              WHERE id = code_analysis_triggers.repo_id
                AND engagement_id = code_analysis_triggers.engagement_id
                AND active_generation > 0
          )
          AND status NOT IN ({terminal_placeholders})
          AND (
              target_file_id = ?
              OR (
                  target_file_id IS NULL
                  AND target_file_path = ?
                  AND source_file_id IN (
                      SELECT id
                      FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
              )
          )
        """,
        (
            engagement_id,
            *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
            file_id,
            str(file_row["file_path"]),
            engagement_id,
            int(file_row["repo_id"]),
        ),
    ).fetchall()
    for trigger_row in trigger_rows:
        next_status, clear_invalid_binding = _bound_trigger_status(
            connection,
            engagement_id,
            int(trigger_row["id"]),
            file_id,
            int(trigger_row["resolved_queue_item_id"])
            if trigger_row["resolved_queue_item_id"] is not None
            else None,
        )
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET target_file_id = ?, status = ?,
                resolved_queue_item_id = CASE
                    WHEN ? THEN NULL ELSE resolved_queue_item_id END,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (
                file_id,
                next_status,
                1 if clear_invalid_binding else 0,
                engagement_id,
                int(trigger_row["id"]),
            ),
        )


# =========================================================================
# Repository Management
# =========================================================================

def start_code_repo_refresh(engagement_id: int, repo: dict[str, Any]) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if repo.get("source_snapshot_quality") == "verified":
        required_identity = {
            "source_origin_path": repo.get("source_origin_path"),
            "snapshot_manifest_path": repo.get("snapshot_manifest_path"),
            "snapshot_digest": repo.get("snapshot_digest"),
        }
        missing = sorted(key for key, value in required_identity.items() if not value)
        if repo.get("source_kind") not in {"git", "directory"}:
            missing.append("source_kind")
        if repo.get("source_kind") == "git" and repo.get("worktree_dirty") is None:
            missing.append("worktree_dirty")
        if missing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "verified source snapshot is missing identity fields: "
                    + ", ".join(sorted(set(missing)))
                ),
            )
        snapshot_digest = str(repo["snapshot_digest"])
        if len(snapshot_digest) != 64 or any(
            char not in "0123456789abcdef" for char in snapshot_digest
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="snapshot_digest must be a lowercase SHA-256 digest",
            )
    refresh_token = str(uuid.uuid4())
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND repo_key = ?",
            (engagement.id, repo["repo_key"]),
        ).fetchone()
        if row is None:
            cursor = connection.execute(
                """
                INSERT INTO code_repos (
                    engagement_id, repo_key, name, language, repo_path,
                    commit_hash, branch, pending_refresh_token, pending_refresh_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id, repo["repo_key"], repo["name"], repo.get("language", ""),
                    repo["repo_path"], repo.get("commit_hash", ""), repo.get("branch", ""),
                    refresh_token, _json_text(repo),
                ),
            )
            repo_id = int(cursor.lastrowid)
        else:
            repo_id = int(row["id"])
            old_token = str(row["pending_refresh_token"] or "")
            if old_token:
                connection.execute(
                    "DELETE FROM code_ingest_staging WHERE repo_id = ? AND refresh_token = ?",
                    (repo_id, old_token),
                )
            connection.execute(
                """
                UPDATE code_repos
                SET pending_refresh_token = ?, pending_refresh_json = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (refresh_token, _json_text(repo), engagement.id, repo_id),
            )
    return {"repo_id": repo_id, "refresh_token": refresh_token}


def _normalized_file_manifest_record(record: Any) -> dict[str, Any]:
    record = dict(record)
    return {
        "file_hash": str(record.get("file_hash", "") or ""),
        "language": str(record.get("language", "") or ""),
        "loc": int(record.get("loc", 0) or 0),
        "header_snippet": str(record.get("header_snippet", "") or ""),
        "git_churn_score": int(record.get("git_churn_score", 0) or 0),
        "has_past_cve_fix": bool(record.get("has_past_cve_fix")),
    }


def preview_code_repo_refresh(
    engagement_id: int, *, repo_key: str, files: list[dict[str, Any]]
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    incoming = {str(row["file_path"]): row for row in files}
    with get_connection() as connection:
        repo = connection.execute(
            "SELECT id FROM code_repos WHERE engagement_id = ? AND repo_key = ?",
            (engagement.id, repo_key),
        ).fetchone()
        if repo is None:
            return {"added": sorted(incoming), "changed": [], "renamed": [], "removed": [], "unchanged": []}
        rows = connection.execute(
            """
            SELECT file_path, file_hash, language, loc, header_snippet,
                   git_churn_score, has_past_cve_fix
            FROM code_files WHERE engagement_id = ? AND repo_id = ?
              AND retired_at IS NULL
            """,
            (engagement.id, int(repo["id"])),
        ).fetchall()
    existing = {str(row["file_path"]): _normalized_file_manifest_record(row) for row in rows}
    normalized_incoming = {
        path: _normalized_file_manifest_record(record) for path, record in incoming.items()
    }
    changed = sorted(
        path for path in set(existing) & set(incoming)
        if existing[path] != normalized_incoming[path]
    )
    unchanged = sorted((set(existing) & set(incoming)) - set(changed))
    removed = set(existing) - set(incoming)
    added = set(incoming) - set(existing)
    removed_by_hash: dict[str, list[str]] = {}
    added_by_hash: dict[str, list[str]] = {}
    for path in removed:
        removed_by_hash.setdefault(str(existing[path]["file_hash"]), []).append(path)
    for path in added:
        added_by_hash.setdefault(str(normalized_incoming[path]["file_hash"]), []).append(path)
    renamed: list[dict[str, str]] = []
    for file_hash, old_paths in removed_by_hash.items():
        new_paths = added_by_hash.get(file_hash, [])
        if file_hash and len(old_paths) == 1 and len(new_paths) == 1:
            renamed.append({"from": old_paths[0], "to": new_paths[0], "file_hash": file_hash})
            removed.discard(old_paths[0])
            added.discard(new_paths[0])
    return {
        "added": sorted(added), "changed": changed,
        "renamed": sorted(renamed, key=lambda row: (row["from"], row["to"])),
        "removed": sorted(removed), "unchanged": unchanged,
    }


def stage_code_repo_refresh_files(
    engagement_id: int, repo_id: int, *, refresh_token: str, files: list[dict[str, Any]]
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_repo_row_raw(connection, engagement.id, repo_id)
        if str(repo.get("pending_refresh_token", "")) != refresh_token:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="repo refresh token is stale")
        for file_record in files:
            connection.execute(
                """
                INSERT INTO code_ingest_staging (
                    engagement_id, repo_id, refresh_token, file_path, file_json
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(repo_id, refresh_token, file_path)
                DO UPDATE SET file_json = excluded.file_json
                """,
                (engagement.id, repo_id, refresh_token, file_record["file_path"], _json_text(file_record)),
            )
    return {"staged": len(files)}


def _invalidate_file_analysis(connection, engagement_id: int, file_id: int) -> None:
    """Reset current file state without erasing generation-bound audit history."""
    connection.execute(
        """
        UPDATE code_analysis_results
        SET superseded_at = COALESCE(superseded_at, ?)
        WHERE engagement_id = ? AND file_id = ?
        """,
        (_now_iso(), engagement_id, file_id),
    )
    connection.execute(
        """
        UPDATE code_files
        SET classification = 'unclassified', role = '', slot_types_json = '[]',
            analysis_priority = 0, analysis_status = 'pending', analysis_depth = 'none',
            skip_reason = '', variant_check_status = 'pending', module_id = NULL,
            notes = '', total_functions = 0, total_entry_points = 0,
            total_sinks = 0, total_exports = 0,
            structural_analysis_status = 'pending', structural_analysis_mode = '',
            structural_degradation_reason = '', structural_source_size = 0,
            structural_bytes_scanned = 0,
            structural_unavailable_dimensions_json = '[]',
            structural_artifact_truncated = 0,
            structural_truncated_dimensions_json = '[]',
            structural_signal_counts_json = '{}'
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, file_id),
    )


def _invalidate_repo_structural_index(connection, engagement_id: int, repo_id: int) -> None:
    """Discard parser- and language-dependent facts for an entire repository."""
    connection.execute(
        """
        UPDATE code_files
        SET total_functions = 0, total_entry_points = 0, total_sinks = 0,
            total_exports = 0, structural_analysis_status = 'pending',
            structural_analysis_mode = '', structural_degradation_reason = '',
            structural_source_size = 0, structural_bytes_scanned = 0,
            structural_unavailable_dimensions_json = '[]',
            structural_artifact_truncated = 0,
            structural_truncated_dimensions_json = '[]',
            structural_signal_counts_json = '{}', updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND repo_id = ?
        """,
        (engagement_id, repo_id),
    )
    connection.execute(
        """
        UPDATE code_repos
        SET structural_index_schema = '', structural_index_generation = NULL,
            structural_index_manifest_path = '',
            structural_degraded_files = 0,
            structural_degraded_file_paths_json = '[]',
            structural_artifact_truncated_files = 0,
            structural_artifact_truncated_file_paths_json = '[]',
            structural_analysis_status_counts_json = '{}', lsp_config_json = '{}',
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, repo_id),
    )


_METADATA_REFRESH_REVIEW_THEME = "metadata-refresh-review"
_METADATA_REFRESH_REVIEW_MODE = "metadata-refresh"
_SOURCE_GENERATION_REPLACED_REASON = "source_generation_replaced"


def _record_source_generation(
    connection,
    *,
    engagement_id: int,
    repo_id: int,
    previous_generation: int,
    repo_generation: int,
    metadata: dict[str, Any],
    source_manifest_version: str,
    source_manifest_digest_value: str,
    source_review_identity_digest: str,
    staged_paths: set[str],
) -> None:
    promoted_at = _now_iso()
    if previous_generation > 0:
        connection.execute(
            """
            UPDATE code_source_generations
            SET source_superseded_at = ?,
                source_supersession_reason = ?,
                replacement_repo_generation = ?
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
              AND source_superseded_at IS NULL
            """,
            (
                promoted_at,
                _SOURCE_GENERATION_REPLACED_REASON,
                repo_generation,
                engagement_id,
                repo_id,
                previous_generation,
            ),
        )
        for table_name in ("code_analysis_queue", "code_analysis_results"):
            connection.execute(
                f"""
                UPDATE {table_name}
                SET source_superseded_at = ?,
                    source_supersession_reason = ?,
                    replacement_repo_generation = ?
                WHERE engagement_id = ? AND repo_generation = ?
                  AND file_id IN (
                      SELECT id FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
                  AND source_superseded_at IS NULL
                """,
                (
                    promoted_at,
                    _SOURCE_GENERATION_REPLACED_REASON,
                    repo_generation,
                    engagement_id,
                    previous_generation,
                    engagement_id,
                    repo_id,
                ),
            )
        connection.execute(
            """
            UPDATE code_analysis_results
            SET superseded_at = COALESCE(superseded_at, ?)
            WHERE engagement_id = ? AND repo_generation = ?
              AND file_id IN (
                  SELECT id FROM code_files
                  WHERE engagement_id = ? AND repo_id = ?
              )
            """,
            (
                promoted_at,
                engagement_id,
                previous_generation,
                engagement_id,
                repo_id,
            ),
        )
        connection.execute(
            """
            UPDATE code_analysis_triggers
            SET source_superseded_at = ?,
                source_supersession_reason = ?,
                replacement_repo_generation = ?
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
              AND source_superseded_at IS NULL
            """,
            (
                promoted_at,
                _SOURCE_GENERATION_REPLACED_REASON,
                repo_generation,
                engagement_id,
                repo_id,
                previous_generation,
            ),
        )

    connection.execute(
        """
        INSERT INTO code_source_generations (
            engagement_id, repo_id, repo_generation,
            source_manifest_version, source_manifest_digest,
            source_review_identity_digest, snapshot_manifest_path,
            snapshot_digest, source_snapshot_quality, repo_path,
            source_origin_path, source_kind, commit_hash, branch,
            worktree_dirty, promoted_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            repo_id,
            repo_generation,
            source_manifest_version,
            source_manifest_digest_value,
            source_review_identity_digest,
            str(metadata.get("snapshot_manifest_path") or ""),
            str(metadata.get("snapshot_digest") or ""),
            str(metadata.get("source_snapshot_quality") or "legacy-unverified"),
            str(metadata.get("repo_path") or ""),
            str(metadata.get("source_origin_path") or metadata.get("repo_path") or ""),
            str(metadata.get("source_kind") or "legacy"),
            str(metadata.get("commit_hash") or ""),
            str(metadata.get("branch") or ""),
            (
                1
                if metadata.get("worktree_dirty") is True
                else 0
                if metadata.get("worktree_dirty") is False
                else None
            ),
            promoted_at,
        ),
    )
    if not staged_paths:
        return
    placeholders = ",".join("?" for _ in staged_paths)
    file_rows = connection.execute(
        f"""
        SELECT id, file_path, file_hash, language, loc, header_snippet,
               git_churn_score, has_past_cve_fix
        FROM code_files
        WHERE engagement_id = ? AND repo_id = ?
          AND retired_at IS NULL
          AND file_path IN ({placeholders})
        ORDER BY file_path
        """,
        (engagement_id, repo_id, *sorted(staged_paths)),
    ).fetchall()
    if len(file_rows) != len(staged_paths):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="source generation file identity changed before promotion",
        )
    connection.executemany(
        """
        INSERT INTO code_source_generation_files (
            engagement_id, repo_id, repo_generation, file_id, file_path,
            file_hash, language, loc, header_snippet, git_churn_score,
            has_past_cve_fix
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                engagement_id,
                repo_id,
                repo_generation,
                int(row["id"]),
                str(row["file_path"]),
                str(row["file_hash"]),
                str(row["language"]),
                int(row["loc"]),
                str(row["header_snippet"]),
                int(row["git_churn_score"]),
                int(row["has_past_cve_fix"]),
            )
            for row in file_rows
        ],
    )


def _has_current_file_analysis_activity(
    connection,
    engagement_id: int,
    file_id: int,
) -> bool:
    row = connection.execute(
        """
        SELECT 1
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE queue.engagement_id = ? AND queue.file_id = ?
          AND queue.repo_generation = repos.active_generation
          AND queue.source_superseded_at IS NULL
        LIMIT 1
        """,
        (engagement_id, file_id),
    ).fetchone()
    return row is not None


def _reopen_file_metadata_review(
    connection,
    engagement_id: int,
    file_row: dict[str, Any],
    *,
    invalidate_architecture: bool,
) -> None:
    """Retire stale conclusions while preserving them as non-covering history."""
    file_id = int(file_row["id"])
    prior_priority = int(file_row.get("analysis_priority", 0) or 0)
    if prior_priority <= 0:
        row = connection.execute(
            "SELECT MAX(priority) AS priority FROM code_analysis_queue WHERE engagement_id = ? AND file_id = ?",
            (engagement_id, file_id),
        ).fetchone()
        prior_priority = int(row["priority"] or 50) if row is not None else 50
    review_priority = max(0, min(100, prior_priority))
    superseded_at = _now_iso()
    connection.execute(
        """
        UPDATE code_analysis_results
        SET superseded_at = ?
        WHERE engagement_id = ? AND file_id = ? AND superseded_at IS NULL
        """,
        (superseded_at, engagement_id, file_id),
    )
    connection.execute(
        "DELETE FROM code_analysis_triggers WHERE engagement_id = ? AND source_file_id = ?",
        (engagement_id, file_id),
    )
    connection.execute(
        """
        UPDATE code_analysis_triggers
        SET status = CASE
                WHEN status IN (?, ?, ?) THEN status ELSE 'pending' END,
            resolved_queue_item_id = NULL,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ?
          AND (
              target_file_id = ?
              OR (
                  target_file_id IS NULL
                  AND target_file_path = ?
                  AND source_file_id IN (
                      SELECT id FROM code_files
                      WHERE engagement_id = ? AND repo_id = ?
                  )
              )
          )
        """,
        (
            *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
            engagement_id,
            file_id,
            str(file_row["file_path"]),
            engagement_id,
            int(file_row["repo_id"]),
        ),
    )
    connection.execute(
        """
        UPDATE code_analysis_queue
        SET status = 'done', disposition = 'superseded',
            cwe_coverage_json = '[]', cross_file_triggers_json = '[]',
            guidance_hypotheses_json = '[]', completed_at = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND file_id = ?
        """,
        (superseded_at, engagement_id, file_id),
    )
    architecture_fields = (
        "role = '', slot_types_json = '[]', module_id = NULL," if invalidate_architecture else ""
    )
    connection.execute(
        f"""
        UPDATE code_files
        SET classification = 'unclassified', {architecture_fields}
            analysis_priority = 0, analysis_status = 'pending',
            updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, file_id),
    )
    connection.execute(
        """
        INSERT INTO code_analysis_queue (
            engagement_id, file_id, priority, status, batch_theme,
            slot_types_json, guidance_hypotheses_json, repo_generation, queue_mode
        )
        SELECT ?, ?, ?, 'pending', ?, '[]', '[]', active_generation, ?
        FROM code_repos
        WHERE engagement_id = ? AND id = ?
        """,
        (
            engagement_id,
            file_id,
            review_priority,
            _METADATA_REFRESH_REVIEW_THEME,
            _METADATA_REFRESH_REVIEW_MODE,
            engagement_id,
            int(file_row["repo_id"]),
        ),
    )
    _sync_trigger_status_for_file(connection, engagement_id, file_id)


def _sync_metadata_review_queue_identity(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    priority: int | None = None,
) -> None:
    priority_assignment = "priority = ?," if priority is not None else ""
    params: list[Any] = []
    if priority is not None:
        params.append(priority)
    params.extend(
        [
            engagement_id,
            file_id,
            engagement_id,
            file_id,
            _METADATA_REFRESH_REVIEW_MODE,
        ]
    )
    connection.execute(
        f"""
        UPDATE code_analysis_queue
        SET {priority_assignment}
            slot_types_json = COALESCE((
                SELECT slot_types_json
                FROM code_files
                WHERE engagement_id = ? AND id = ?
            ), '[]'),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = (
            SELECT MAX(id)
            FROM code_analysis_queue
            WHERE engagement_id = ? AND file_id = ?
              AND queue_mode = ? AND status = 'pending'
        )
        """,
        tuple(params),
    )


def commit_code_repo_refresh(
    engagement_id: int, repo_id: int, *, refresh_token: str, manifest_complete: bool
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    inserted = changed = renamed = retired_count = unchanged = 0
    attestation: VerifiedSnapshotAttestation | None = None
    try:
        # Hash and validate the sealed tree before taking SQLite's global write
        # reservation. The returned proof keeps pinned engagement/snapshot/source
        # descriptors live; the write transaction below rechecks the token,
        # staged inventory, and every filesystem identity before it can commit.
        with get_connection() as connection:
            claimed_repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(claimed_repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            claimed_metadata = _json_decode(
                claimed_repo.get("pending_refresh_json"), {}
            )
        requested_quality = str(
            claimed_metadata.get(
                "source_snapshot_quality",
                claimed_repo.get("source_snapshot_quality", "legacy-unverified"),
            )
            or "legacy-unverified"
        )
        if requested_quality == "verified":
            attestation = attest_verified_snapshot(
                engagement_root=engagement.engagement_root,
                metadata={**claimed_repo, **claimed_metadata},
            )

        # First reconcile the staged inventory against the live attestation
        # without a writer reservation. A second exact read under BEGIN
        # IMMEDIATE below is the CAS that authorizes promotion.
        with get_connection() as connection:
            repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            staged_rows = connection.execute(
                """
                SELECT file_path, file_json FROM code_ingest_staging
                WHERE engagement_id = ? AND repo_id = ? AND refresh_token = ?
                ORDER BY file_path
                """,
                (engagement.id, repo_id, refresh_token),
            ).fetchall()
            if not manifest_complete:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="repo refresh manifest is incomplete",
                )
            staged = {
                str(row["file_path"]): _json_decode(row["file_json"], {})
                for row in staged_rows
            }
            metadata = _json_decode(repo.get("pending_refresh_json"), {})
            if metadata != claimed_metadata:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh metadata changed during snapshot attestation",
                )
            # Persisted quality is derived from backend proof, never copied from
            # the caller's assertion. Legacy/unverified refreshes remain supported
            # but continue to fail the later source-integrity readiness gate.
            metadata = dict(metadata)
            metadata["source_snapshot_quality"] = (
                "verified" if attestation is not None else "legacy-unverified"
            )
            if attestation is not None:
                attestation.assert_staged_inventory(staged, metadata)

        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            repo = _get_repo_row_raw(connection, engagement.id, repo_id)
            if str(repo.get("pending_refresh_token", "")) != refresh_token:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh token is stale",
                )
            live_metadata = _json_decode(repo.get("pending_refresh_json"), {})
            if live_metadata != claimed_metadata:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh metadata changed during snapshot attestation",
                )
            live_rows = connection.execute(
                """
                SELECT file_path, file_json FROM code_ingest_staging
                WHERE engagement_id = ? AND repo_id = ? AND refresh_token = ?
                ORDER BY file_path
                """,
                (engagement.id, repo_id, refresh_token),
            ).fetchall()
            live_staged = {
                str(row["file_path"]): _json_decode(row["file_json"], {})
                for row in live_rows
            }
            if live_staged != staged:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="repo refresh staged inventory changed during snapshot attestation",
                )
            metadata = dict(live_metadata)
            metadata["source_snapshot_quality"] = (
                "verified" if attestation is not None else "legacy-unverified"
            )
            staged = live_staged
            if attestation is not None:
                attestation.assert_staged_inventory(staged, metadata)
            manifest_version = str(
                metadata.get(
                    "source_manifest_version",
                    repo.get("source_manifest_version", SOURCE_MANIFEST_VERSION),
                )
                or SOURCE_MANIFEST_VERSION
            )
            manifest_digest = source_manifest_digest(staged.values(), version=manifest_version)
            current_generation = int(repo.get("active_generation", 0) or 0)
            incoming_snapshot_digest = str(
                metadata.get("snapshot_digest", repo.get("snapshot_digest", "")) or ""
            )
            incoming_snapshot_quality = str(
                metadata.get(
                    "source_snapshot_quality",
                    repo.get("source_snapshot_quality", "legacy-unverified"),
                )
                or "legacy-unverified"
            )
            incoming_review_identity_digest = (
                attestation.review_identity_digest
                if attestation is not None
                else incoming_snapshot_digest
            )
            stored_review_identity_digest = str(
                repo.get("source_review_identity_digest") or ""
            )
            stored_snapshot_digest = str(repo.get("snapshot_digest") or "")
            stored_snapshot_quality = str(
                repo.get("source_snapshot_quality") or "legacy-unverified"
            )
            # The review-identity column was introduced additively and is empty on
            # upgraded rows. Seed it without reopening work only when a verified
            # refresh proves the exact previously stored snapshot. If the full
            # snapshot digest differs, legacy state cannot distinguish a benign
            # provenance change from an exclusion-boundary change, so advance the
            # generation conservatively.
            seeds_legacy_review_identity = (
                not stored_review_identity_digest
                and current_generation > 0
                and attestation is not None
                and incoming_snapshot_quality == "verified"
                and stored_snapshot_quality == "verified"
                and bool(incoming_snapshot_digest)
                and incoming_snapshot_digest == stored_snapshot_digest
                and manifest_digest
                == str(repo.get("source_manifest_digest", "") or "")
            )
            source_review_identity_changed = (
                incoming_review_identity_digest != stored_review_identity_digest
                and not seeds_legacy_review_identity
            )
            snapshot_trust_boundary_changed = (
                incoming_snapshot_quality != stored_snapshot_quality
            )
            generation_changed = (
                current_generation == 0
                or manifest_digest != str(repo.get("source_manifest_digest", "") or "")
                or source_review_identity_changed
                or snapshot_trust_boundary_changed
            )
            repo_generation = current_generation + 1 if generation_changed else current_generation
            all_existing_rows = connection.execute(
                "SELECT * FROM code_files WHERE engagement_id = ? AND repo_id = ?",
                (engagement.id, repo_id),
            ).fetchall()
            all_existing = {
                str(row["file_path"]): dict(row) for row in all_existing_rows
            }
            existing_rows = [row for row in all_existing_rows if row["retired_at"] is None]
            existing = {str(row["file_path"]): dict(row) for row in existing_rows}
            retired_paths = set(all_existing) - set(existing)

            missing_paths = set(existing) - set(staged)
            new_paths = set(staged) - set(existing)
            missing_by_hash: dict[str, list[str]] = {}
            new_by_hash: dict[str, list[str]] = {}
            for path in missing_paths:
                missing_by_hash.setdefault(str(existing[path].get("file_hash", "")), []).append(path)
            for path in new_paths:
                new_by_hash.setdefault(str(staged[path].get("file_hash", "")), []).append(path)
            renamed_old: set[str] = set()
            renamed_new: set[str] = set()
            for file_hash, old_paths in missing_by_hash.items():
                new_matches = new_by_hash.get(file_hash, [])
                if not file_hash or len(old_paths) != 1 or len(new_matches) != 1:
                    continue
                old_path, new_path = old_paths[0], new_matches[0]
                if new_path in retired_paths:
                    continue
                record = staged[new_path]
                file_id = int(existing[old_path]["id"])
                _invalidate_file_analysis(connection, engagement.id, file_id)
                connection.execute(
                    """
                    UPDATE code_files SET file_path = ?, language = ?, loc = ?, file_hash = ?,
                        header_snippet = ?, git_churn_score = ?, has_past_cve_fix = ?,
                        retired_at = NULL, retirement_reason = NULL,
                        replacement_repo_generation = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ?
                    """,
                    (
                        new_path, record.get("language", ""), record.get("loc", 0), file_hash,
                        record.get("header_snippet", ""), record.get("git_churn_score", 0),
                        1 if record.get("has_past_cve_fix") else 0, engagement.id, file_id,
                    ),
                )
                renamed_old.add(old_path)
                renamed_new.add(new_path)
                renamed += 1

            for path, record in staged.items():
                if path in renamed_new:
                    continue
                current = existing.get(path)
                if current is None:
                    retired = all_existing.get(path)
                    if retired is None:
                        connection.execute(
                            """
                            INSERT INTO code_files (
                                engagement_id, repo_id, file_path, language, loc, file_hash,
                                header_snippet, git_churn_score, has_past_cve_fix
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                engagement.id, repo_id, path, record.get("language", ""),
                                record.get("loc", 0), record.get("file_hash", ""),
                                record.get("header_snippet", ""),
                                record.get("git_churn_score", 0),
                                1 if record.get("has_past_cve_fix") else 0,
                            ),
                        )
                    else:
                        _invalidate_file_analysis(
                            connection, engagement.id, int(retired["id"])
                        )
                        connection.execute(
                            """
                            UPDATE code_files
                            SET language = ?, loc = ?, file_hash = ?, header_snippet = ?,
                                git_churn_score = ?, has_past_cve_fix = ?,
                                retired_at = NULL, retirement_reason = NULL,
                                replacement_repo_generation = NULL,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE engagement_id = ? AND id = ?
                            """,
                            (
                                record.get("language", ""), record.get("loc", 0),
                                record.get("file_hash", ""),
                                record.get("header_snippet", ""),
                                record.get("git_churn_score", 0),
                                1 if record.get("has_past_cve_fix") else 0,
                                engagement.id, retired["id"],
                            ),
                        )
                    inserted += 1
                    continue
                content_changed = str(current.get("file_hash", "")) != str(record.get("file_hash", ""))
                language_changed = str(current.get("language", "")) != str(record.get("language", ""))
                loc_changed = int(current.get("loc", 0) or 0) != int(record.get("loc", 0) or 0)
                header_changed = str(current.get("header_snippet", "")) != str(record.get("header_snippet", ""))
                risk_metadata_changed = (
                    int(current.get("git_churn_score", 0) or 0)
                    != int(record.get("git_churn_score", 0) or 0)
                    or bool(current.get("has_past_cve_fix"))
                    != bool(record.get("has_past_cve_fix"))
                )
                if content_changed or language_changed or loc_changed:
                    _invalidate_file_analysis(connection, engagement.id, int(current["id"]))
                    connection.execute(
                        """
                        UPDATE code_files SET language = ?, loc = ?, file_hash = ?, header_snippet = ?,
                            git_churn_score = ?, has_past_cve_fix = ?,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (
                            record.get("language", ""), record.get("loc", 0), record.get("file_hash", ""),
                            record.get("header_snippet", ""), record.get("git_churn_score", 0),
                            1 if record.get("has_past_cve_fix") else 0, engagement.id, current["id"],
                        ),
                    )
                    changed += 1
                elif header_changed or risk_metadata_changed:
                    _reopen_file_metadata_review(
                        connection,
                        engagement.id,
                        current,
                        invalidate_architecture=header_changed,
                    )
                    connection.execute(
                        """
                        UPDATE code_files SET language = ?, loc = ?, header_snippet = ?,
                            git_churn_score = ?, has_past_cve_fix = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (
                            record.get("language", ""), record.get("loc", 0), record.get("header_snippet", ""),
                            record.get("git_churn_score", 0), 1 if record.get("has_past_cve_fix") else 0,
                            engagement.id, current["id"],
                        ),
                    )
                    changed += 1
                else:
                    connection.execute(
                        """
                        UPDATE code_files SET language = ?, loc = ?, header_snippet = ?,
                            git_churn_score = ?, has_past_cve_fix = ?, updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (
                            record.get("language", ""), record.get("loc", 0), record.get("header_snippet", ""),
                            record.get("git_churn_score", 0), 1 if record.get("has_past_cve_fix") else 0,
                            engagement.id, current["id"],
                        ),
                    )
                    unchanged += 1

            for path in missing_paths - renamed_old:
                file_id = int(existing[path]["id"])
                prior_module_id = existing[path].get("module_id")
                _invalidate_file_analysis(connection, engagement.id, file_id)
                connection.execute(
                    """
                    UPDATE code_files
                    SET retired_at = ?, retirement_reason = ?,
                        replacement_repo_generation = ?, module_id = NULL,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ?
                    """,
                    (
                        _now_iso(),
                        _SOURCE_GENERATION_REPLACED_REASON,
                        repo_generation,
                        engagement.id,
                        file_id,
                    ),
                )
                if prior_module_id is not None:
                    _sync_module_rollup(
                        connection, engagement.id, int(prior_module_id)
                    )
                retired_count += 1

            if generation_changed:
                connection.execute(
                    """
                    UPDATE code_files
                    SET analysis_status = CASE
                            WHEN classification = 'unclassified' THEN 'pending'
                            ELSE 'classified'
                        END,
                        variant_check_status = 'pending',
                        structural_analysis_status = 'pending', structural_analysis_mode = '',
                        structural_degradation_reason = '', structural_source_size = 0,
                        structural_bytes_scanned = 0,
                        structural_unavailable_dimensions_json = '[]',
                        structural_artifact_truncated = 0,
                        structural_truncated_dimensions_json = '[]',
                        structural_signal_counts_json = '{}'
                    WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
                    """,
                    (engagement.id, repo_id),
                )
                _record_source_generation(
                    connection,
                    engagement_id=engagement.id,
                    repo_id=repo_id,
                    previous_generation=current_generation,
                    repo_generation=repo_generation,
                    metadata=metadata,
                    source_manifest_version=manifest_version,
                    source_manifest_digest_value=manifest_digest,
                    source_review_identity_digest=incoming_review_identity_digest,
                    staged_paths=set(staged),
                )

            connection.execute(
                """
                UPDATE code_repos SET name = ?, language = ?, repo_path = ?, total_files = ?,
                    analyzable_files = ?, total_loc = ?, commit_hash = ?, branch = ?,
                    git_churn_json = ?, active_generation = ?, source_origin_path = ?,
                    source_kind = ?, snapshot_manifest_path = ?, snapshot_digest = ?,
                    source_review_identity_digest = ?, source_manifest_version = ?,
                    source_manifest_digest = ?,
                    source_snapshot_quality = ?, worktree_dirty = ?,
                    structural_index_schema = ?, structural_index_generation = ?,
                    structural_index_manifest_path = ?,
                    structural_degraded_files = ?, structural_degraded_file_paths_json = ?,
                    structural_artifact_truncated_files = ?,
                    structural_artifact_truncated_file_paths_json = ?,
                    structural_analysis_status_counts_json = ?,
                    lsp_config_json = ?,
                    pending_refresh_token = '', pending_refresh_json = '{}',
                    analysis_status = 'ingested', updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND pending_refresh_token = ?
                """,
                (
                    metadata.get("name", repo["name"]), metadata.get("language", ""),
                    metadata.get("repo_path", repo["repo_path"]), metadata.get("total_files", len(staged)),
                    metadata.get("analyzable_files", len(staged)), metadata.get("total_loc", 0),
                    metadata.get("commit_hash", ""), metadata.get("branch", ""),
                    _json_text(metadata.get("git_churn")), repo_generation,
                    metadata.get("source_origin_path", repo.get("source_origin_path") or metadata.get("repo_path", repo["repo_path"])),
                    metadata.get("source_kind", repo.get("source_kind", "legacy")),
                    metadata.get("snapshot_manifest_path", repo.get("snapshot_manifest_path", "")),
                    metadata.get("snapshot_digest", repo.get("snapshot_digest", "")),
                    incoming_review_identity_digest, manifest_version, manifest_digest,
                    metadata.get("source_snapshot_quality", repo.get("source_snapshot_quality", "legacy-unverified")),
                    (
                        1 if metadata.get("worktree_dirty") is True else 0
                        if metadata.get("worktree_dirty") is False else None
                        if "worktree_dirty" in metadata else repo.get("worktree_dirty")
                    ),
                    "" if generation_changed else repo.get("structural_index_schema", ""),
                    None if generation_changed else repo.get("structural_index_generation"),
                    "" if generation_changed else repo.get("structural_index_manifest_path", ""),
                    0 if generation_changed else repo.get("structural_degraded_files", 0),
                    "[]"
                    if generation_changed
                    else repo.get("structural_degraded_file_paths_json", "[]"),
                    0 if generation_changed else repo.get("structural_artifact_truncated_files", 0),
                    "[]"
                    if generation_changed
                    else repo.get("structural_artifact_truncated_file_paths_json", "[]"),
                    "{}"
                    if generation_changed
                    else repo.get("structural_analysis_status_counts_json", "{}"),
                    "{}" if generation_changed else repo.get("lsp_config_json", "{}"),
                    engagement.id, repo_id, refresh_token,
                ),
            )
            connection.execute(
                "DELETE FROM code_ingest_staging WHERE repo_id = ? AND refresh_token = ?",
                (repo_id, refresh_token),
            )
            for module_row in connection.execute(
                "SELECT id FROM code_modules WHERE engagement_id = ? AND repo_id = ?", (engagement.id, repo_id)
            ).fetchall():
                _sync_module_rollup(connection, engagement.id, int(module_row["id"]))
            if attestation is not None:
                attestation.verify_unchanged()
            connection.commit()
    except SnapshotAttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"verified snapshot attestation failed: {exc}",
        ) from exc
    finally:
        if attestation is not None:
            attestation.close()
    return {
        "repo_id": repo_id, "inserted": inserted, "changed": changed, "renamed": renamed,
        "retired": retired_count, "unchanged": unchanged,
        "repo_generation": repo_generation,
        "source_manifest_version": manifest_version,
        "source_manifest_digest": manifest_digest,
        "generation_changed": generation_changed,
    }


def list_code_repos(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT * FROM code_repos
            WHERE engagement_id = ?
              AND active_generation > 0
            ORDER BY updated_at DESC, id DESC
            """,
            (engagement.id,),
        ).fetchall()
        return [_hydrate_code_repo(row) for row in rows]


def get_code_repo(engagement_id: int, repo_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = _get_published_repo_row(connection, engagement.id, repo_id)
    return _hydrate_code_repo(row)


_CODE_REPO_ALLOWED_FIELDS = frozenset({
    "name", "language", "analysis_status",
})


def update_code_repo(
    engagement_id: int,
    repo_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_repo(engagement_id, repo_id)
    _reject_unknown_fields(kwargs, _CODE_REPO_ALLOWED_FIELDS, entity_name="repo patch")

    set_clauses = []
    params: list[Any] = []
    for key, value in kwargs.items():
        if key not in _CODE_REPO_ALLOWED_FIELDS:
            continue
        set_clauses.append(f"{key} = ?")
        params.append(value)

    if not set_clauses:
        return get_code_repo(engagement_id, repo_id)

    set_clauses.append("updated_at = CURRENT_TIMESTAMP")
    params.extend([engagement.id, repo_id])

    with get_connection() as connection:
        _get_published_repo_row(connection, engagement.id, repo_id)
        connection.execute(
            f"UPDATE code_repos SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return _hydrate_code_repo(row)


def publish_code_repo_lsp_config(
    engagement_id: int,
    repo_id: int,
    *,
    repo_generation: int,
    source_manifest_digest: str,
    lsp_config: dict[str, Any],
) -> dict[str, Any]:
    """Publish derived tooling state only for the source generation it indexed."""

    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        if int(repo.get("active_generation", 0) or 0) != repo_generation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LSP repository generation is stale",
            )
        if str(repo.get("source_manifest_digest", "") or "") != source_manifest_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LSP source manifest digest is stale",
            )
        cursor = connection.execute(
            """
            UPDATE code_repos
            SET lsp_config_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
              AND active_generation = ? AND source_manifest_digest = ?
            """,
            (
                _json_text(lsp_config),
                engagement.id,
                repo_id,
                repo_generation,
                source_manifest_digest,
            ),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="LSP source generation changed before publication",
            )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return _hydrate_code_repo(row)


# =========================================================================
# File Management
# =========================================================================


def list_code_files(
    engagement_id: int,
    *,
    repo_id: int | None = None,
    module_id: int | None = None,
    classification: str | None = None,
    analysis_status: str | None = None,
    search: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    include_header_snippet: bool = False,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    clauses = [
        "files.engagement_id = ?",
        "files.retired_at IS NULL",
        "repos.active_generation > 0",
    ]
    params: list[Any] = [engagement.id]
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(repo_id)
    if module_id is not None:
        clauses.append("files.module_id = ?")
        params.append(module_id)
    if classification is not None:
        clauses.append("files.classification = ?")
        params.append(classification)
    if analysis_status is not None:
        clauses.append("files.analysis_status = ?")
        params.append(analysis_status)
    if search is not None:
        clauses.append("files.file_path LIKE ? ESCAPE '\\'")
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params.append(f"%{escaped}%")
    from_where = f"""
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id AND repos.engagement_id = files.engagement_id
        WHERE {' AND '.join(clauses)}
    """
    query = f"""
        SELECT files.*
        {from_where}
        ORDER BY files.analysis_priority DESC, files.id ASC
    """
    if limit is not None:
        query += f" LIMIT {int(limit)}"
        if offset > 0:
            query += f" OFFSET {int(offset)}"
    with get_connection() as connection:
        total = int(
            connection.execute(
                f"SELECT COUNT(*) {from_where}", tuple(params)
            ).fetchone()[0]
        )
        rows = connection.execute(query, tuple(params)).fetchall()
        file_ids = [int(row["id"]) for row in rows]
        queue_rows_by_file: dict[int, list[dict[str, Any]]] = {
            file_id: [] for file_id in file_ids
        }
        active_generation_by_file: dict[int, int] = {}
        if file_ids:
            placeholders = ",".join("?" for _ in file_ids)
            queue_rows = connection.execute(
                f"""
                SELECT queue.*, repos.active_generation
                FROM code_analysis_queue AS queue
                JOIN code_files AS files
                  ON files.id = queue.file_id
                 AND files.engagement_id = queue.engagement_id
                JOIN code_repos AS repos
                  ON repos.id = files.repo_id
                 AND repos.engagement_id = files.engagement_id
                WHERE queue.engagement_id = ?
                  AND queue.file_id IN ({placeholders})
                ORDER BY queue.id DESC
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for queue_row in queue_rows:
                file_id = int(queue_row["file_id"])
                queue_rows_by_file[file_id].append(dict(queue_row))
                active_generation_by_file[file_id] = int(
                    queue_row["active_generation"]
                )
        parent_finding_cache: dict[int, list[str]] = {}
        records: list[dict[str, Any]] = []
        for row in rows:
            file_row = dict(row)
            payload = _hydrate_code_file(file_row)
            if not include_header_snippet:
                payload.pop("header_snippet", None)
            file_id = int(file_row["id"])
            attempts = queue_rows_by_file.get(file_id, [])
            active_generation = active_generation_by_file.get(file_id)
            current = next(
                (
                    attempt
                    for attempt in attempts
                    if int(attempt["repo_generation"]) == active_generation
                ),
                None,
            )
            current_attempt = None
            if current is not None:
                current_attempt = {
                    "id": int(current["id"]),
                    "status": str(current["status"]),
                    "priority": int(current["priority"]),
                    "queue_mode": str(current.get("queue_mode") or "initial"),
                    "batch_theme": str(current.get("batch_theme") or ""),
                    "repo_generation": int(current["repo_generation"]),
                    "agent_name": str(current.get("assigned_agent") or ""),
                    "lease_token": str(current.get("lease_token") or ""),
                }
            payload["queue"] = {
                "state": (
                    "current"
                    if current_attempt is not None
                    else ("historical_only" if attempts else "none")
                ),
                "current_attempt": current_attempt,
                "historical_attempts": len(attempts) - (1 if current else 0),
            }
            payload["variant_check_status"] = _current_variant_check_status(
                connection,
                engagement.id,
                file_row,
                parent_finding_cache=parent_finding_cache,
            )
            records.append(payload)
        return {
            "total": total,
            "offset": offset,
            "count": len(records),
            "has_more": offset + len(records) < total,
            "items": records,
        }


def get_code_file(engagement_id: int, file_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = _get_file_rows(connection, engagement.id, {file_id})[file_id]
        payload = _hydrate_code_file(row)
        payload["variant_check_status"] = _current_variant_check_status(
            connection,
            engagement.id,
            row,
        )
        return payload


CLASSIFICATION_PRIORITY_BANDS = {
    "critical": (80, 100),
    "high": (50, 79),
    "medium": (20, 49),
    "low": (5, 19),
    "skip": (0, 0),
}
_VALID_CLASSIFICATIONS = frozenset(CLASSIFICATION_PRIORITY_BANDS)
_VALID_SLOT_TYPES = frozenset({
    "NETWORK-INPUT",
    "URL-COMPONENT",
    "CMD-ARGUMENT",
    "FILE-CONTENT",
    "ENV-VARIABLE",
    "CALLBACK-DATA",
    "PROTOCOL-FIELD",
    "SERIALIZED-DATA",
    "EXEC-POLICY",
})


def _require_strict_priority(value: Any, *, field_name: str) -> int:
    if type(value) is not int:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be an integer",
        )
    if not 0 <= value <= 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be between 0 and 100",
        )
    return value


def _require_classification_priority(
    classification: str,
    value: Any,
    *,
    field_name: str,
) -> int:
    priority = _require_strict_priority(value, field_name=field_name)
    minimum, maximum = CLASSIFICATION_PRIORITY_BANDS[classification]
    if not minimum <= priority <= maximum:
        expected = str(minimum) if minimum == maximum else f"between {minimum} and {maximum}"
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{field_name} must be {expected} when classification is "
                f"{classification}"
            ),
        )
    return priority


def _synchronize_pending_queue_priority(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    current_priority: int,
    new_priority: int,
) -> None:
    if current_priority == new_priority:
        return
    current_rows = [
        dict(row)
        for row in connection.execute(
        """
        SELECT queue.id, queue.status, queue.assigned_agent, queue.lease_token
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
        WHERE queue.engagement_id = ? AND queue.file_id = ?
          AND queue.repo_generation = repos.active_generation
          AND queue.source_superseded_at IS NULL
        ORDER BY queue.id
        """,
        (engagement_id, file_id),
        ).fetchall()
    ]
    _, active_row, active_issue = _canonical_queue_attempt_state(current_rows)
    if active_issue is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"file {file_id} has {active_issue} queue history; reconcile it before "
                "changing analysis_priority"
            ),
        )
    if active_row is None:
        return
    row = active_row
    queue_status = str(row["status"])
    is_leased = bool(str(row["assigned_agent"] or "") or str(row["lease_token"] or ""))
    if queue_status == "processing" or is_leased:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"file {file_id} has live or inconsistently leased queue work; "
                "finish or recover it before changing analysis_priority"
            ),
        )
    cursor = connection.execute(
        """
        UPDATE code_analysis_queue
        SET priority = ?, updated_at = CURRENT_TIMESTAMP
        WHERE engagement_id = ? AND id = ? AND status = 'pending'
          AND assigned_agent = '' AND lease_token = ''
        """,
        (new_priority, engagement_id, int(row["id"])),
    )
    if cursor.rowcount != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="pending queue work changed while analysis_priority was being updated",
        )


def _normalize_slot_types(value: Any, *, field_name: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a list of slot type strings",
        )

    normalized: list[str] = []
    seen: set[str] = set()
    invalid: list[str] = []
    for raw_slot in value:
        if not isinstance(raw_slot, str):
            invalid.append(repr(raw_slot))
            continue
        slot = raw_slot.strip()
        if slot not in _VALID_SLOT_TYPES:
            invalid.append(slot or "<empty>")
            continue
        if slot not in seen:
            normalized.append(slot)
            seen.add(slot)

    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"{field_name} contains invalid values: {', '.join(invalid)}. "
                f"Allowed values: {', '.join(sorted(_VALID_SLOT_TYPES))}"
            ),
        )
    return normalized


def _require_slot_types_for_classification(classification: str, slot_types: list[str], *, field_name: str) -> None:
    if classification in {"critical", "high"} and not slot_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} is required for {classification} classifications",
        )


def _normalize_guidance_hypotheses(value: Any, *, field_name: str) -> list[str]:
    if value in (None, ""):
        return []
    if not isinstance(value, list):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must be a list of strings",
        )
    normalized: list[str] = []
    for idx, raw_value in enumerate(value):
        if not isinstance(raw_value, str):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"{field_name}[{idx}] must be a string",
            )
        normalized.append(raw_value)
    return normalized


def bulk_classify_code_files(
    engagement_id: int,
    classifications: list[dict[str, Any]],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    submitted_file_ids = [
        _require_strict_positive_id(
            item.get("file_id"),
            field_name=f"classifications[{idx}].file_id",
        )
        for idx, item in enumerate(classifications)
    ]
    if len(submitted_file_ids) != len(set(submitted_file_ids)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="classification request contains duplicate file IDs",
        )
    updated = 0
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_rows = _get_file_rows(
            connection,
            engagement.id,
            set(submitted_file_ids),
        )
        affected_module_ids: set[int] = set()
        structurally_invalidated_repo_ids: set[int] = set()
        for idx, c in enumerate(classifications):
            file_id = submitted_file_ids[idx]
            classification = str(c.get("classification", "")).strip()
            if classification not in _VALID_CLASSIFICATIONS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"classifications[{idx}].classification must be one of: "
                        f"{', '.join(sorted(_VALID_CLASSIFICATIONS))}"
                    ),
                )
            slot_types = _normalize_slot_types(
                c.get("slot_types"),
                field_name=f"classifications[{idx}].slot_types",
            )
            _require_slot_types_for_classification(
                classification,
                slot_types,
                field_name=f"classifications[{idx}].slot_types",
            )
            role = str(c.get("role", "")).strip()
            current_file = file_rows[file_id]
            language = c.get("language")
            normalized_language = (
                str(current_file.get("language", ""))
                if language is None
                else str(language).strip()
            )
            priority = _require_classification_priority(
                classification,
                c.get("analysis_priority"),
                field_name=f"classifications[{idx}].analysis_priority",
            )
            language_changed = normalized_language != str(current_file.get("language", ""))
            review_identity_changed = (
                classification != str(current_file.get("classification", ""))
                or role != str(current_file.get("role", ""))
                or slot_types != _json_decode(current_file.get("slot_types_json"), [])
                or language_changed
            )
            review_reopened = review_identity_changed and _has_current_file_analysis_activity(
                connection,
                engagement.id,
                file_id,
            )
            _synchronize_pending_queue_priority(
                connection,
                engagement.id,
                file_id,
                current_priority=int(current_file.get("analysis_priority", 0) or 0),
                new_priority=priority,
            )
            if language_changed:
                structurally_invalidated_repo_ids.add(int(current_file["repo_id"]))
            if review_reopened:
                if current_file.get("module_id") is not None:
                    affected_module_ids.add(int(current_file["module_id"]))
                _reopen_file_metadata_review(
                    connection,
                    engagement.id,
                    current_file,
                    invalidate_architecture=False,
                )
            cursor = connection.execute(
                """
                UPDATE code_files
                SET classification = ?,
                    role = ?,
                    slot_types_json = ?,
                    language = ?,
                    analysis_priority = ?,
                    analysis_status = 'classified',
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ?
                """,
                (
                    classification,
                    role,
                    _json_list_text(slot_types),
                    normalized_language,
                    priority,
                    engagement.id,
                    file_id,
                ),
            )
            if cursor.rowcount > 0:
                updated += 1
                if review_identity_changed:
                    connection.execute(
                        """
                        UPDATE code_files
                        SET variant_check_status = 'pending', updated_at = CURRENT_TIMESTAMP
                        WHERE engagement_id = ? AND id = ?
                        """,
                        (engagement.id, file_id),
                    )
                if review_reopened:
                    _sync_metadata_review_queue_identity(
                        connection,
                        engagement.id,
                        file_id,
                        priority=priority,
                    )
                    _sync_file_analysis_status(
                        connection,
                        engagement.id,
                        file_id,
                    )
                module_row = connection.execute(
                    "SELECT module_id FROM code_files WHERE engagement_id = ? AND id = ?",
                    (engagement.id, file_id),
                ).fetchone()
                if module_row is not None and module_row["module_id"] is not None:
                    affected_module_ids.add(int(module_row["module_id"]))
        for repo_id in structurally_invalidated_repo_ids:
            _invalidate_repo_structural_index(connection, engagement.id, repo_id)
        for module_id in affected_module_ids:
            _sync_module_rollup(connection, engagement.id, module_id)
    return {"updated": updated, "total": len(classifications)}


_CODE_FILE_ALLOWED_FIELDS = frozenset({
    "classification", "role", "analysis_priority",
    "analysis_depth", "module_id",
    "notes", "slot_types_json", "language",
})


def update_code_file(
    engagement_id: int,
    file_id: int,
    **kwargs: Any,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not kwargs:
        return get_code_file(engagement_id, file_id)
    _reject_unknown_fields(kwargs, _CODE_FILE_ALLOWED_FIELDS, entity_name="file patch")

    set_clauses = []
    params: list[Any] = []
    json_list_fields = {"slot_types_json"}
    json_object_fields: set[str] = set()

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_row = _get_file_rows(connection, engagement.id, {file_id})[file_id]

        normalized_kwargs = dict(kwargs)
        if "language" in normalized_kwargs:
            normalized_kwargs["language"] = str(normalized_kwargs["language"]).strip()
        if "role" in normalized_kwargs:
            normalized_kwargs["role"] = str(normalized_kwargs["role"]).strip()
        language_changed = (
            "language" in normalized_kwargs
            and normalized_kwargs["language"] != str(file_row.get("language", ""))
        )
        if "module_id" in normalized_kwargs:
            raw_module_id = normalized_kwargs["module_id"]
            if raw_module_id in ("", None):
                normalized_kwargs["module_id"] = None
            else:
                module_id = _coerce_int(raw_module_id, field_name="module_id")
                module_row = connection.execute(
                    """
                    SELECT id
                    FROM code_modules
                    WHERE engagement_id = ? AND id = ? AND repo_id = ?
                    """,
                    (engagement.id, module_id, int(file_row["repo_id"])),
                ).fetchone()
                if module_row is None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="module_id must reference a module in the same repo",
                    )
                normalized_kwargs["module_id"] = module_id

        if "classification" in normalized_kwargs:
            classification = str(normalized_kwargs["classification"]).strip()
            if classification not in _VALID_CLASSIFICATIONS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "classification must be one of: "
                        + ", ".join(sorted(_VALID_CLASSIFICATIONS))
                    ),
                )
            normalized_kwargs["classification"] = classification

        if "analysis_priority" in normalized_kwargs:
            normalized_kwargs["analysis_priority"] = _require_strict_priority(
                normalized_kwargs["analysis_priority"],
                field_name="analysis_priority",
            )

        if "slot_types_json" in normalized_kwargs:
            normalized_kwargs["slot_types_json"] = _normalize_slot_types(
                normalized_kwargs["slot_types_json"],
                field_name="slot_types_json",
            )

        effective_classification = str(
            normalized_kwargs.get("classification", file_row["classification"] or "")
        ).strip()
        effective_priority = normalized_kwargs.get(
            "analysis_priority",
            int(file_row.get("analysis_priority", 0) or 0),
        )
        if effective_classification in _VALID_CLASSIFICATIONS:
            effective_priority = _require_classification_priority(
                effective_classification,
                effective_priority,
                field_name="analysis_priority",
            )
        elif "classification" in normalized_kwargs or "analysis_priority" in normalized_kwargs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="classification and analysis_priority must form a valid classified pair",
            )
        effective_slot_types = (
            normalized_kwargs["slot_types_json"]
            if "slot_types_json" in normalized_kwargs
            else _json_decode(file_row["slot_types_json"], [])
        )
        _require_slot_types_for_classification(
            effective_classification,
            effective_slot_types,
            field_name="slot_types_json",
        )
        review_identity_changed = (
            (
                "classification" in normalized_kwargs
                and normalized_kwargs["classification"]
                != str(file_row.get("classification", ""))
            )
            or (
                "role" in normalized_kwargs
                and normalized_kwargs["role"] != str(file_row.get("role", ""))
            )
            or (
                "slot_types_json" in normalized_kwargs
                and normalized_kwargs["slot_types_json"]
                != _json_decode(file_row.get("slot_types_json"), [])
            )
            or language_changed
        )
        review_reopened = review_identity_changed and _has_current_file_analysis_activity(
            connection,
            engagement.id,
            file_id,
        )
        _synchronize_pending_queue_priority(
            connection,
            engagement.id,
            file_id,
            current_priority=int(file_row.get("analysis_priority", 0) or 0),
            new_priority=int(effective_priority),
        )

        # Reopening first retires the old semantic receipt and resets derived
        # review state. Restore the complete effective identity so a partial
        # PATCH cannot accidentally erase a high-risk file's valid slots.
        if review_reopened:
            normalized_kwargs["classification"] = effective_classification
            normalized_kwargs["analysis_priority"] = int(effective_priority)

        for key, value in normalized_kwargs.items():
            if key not in _CODE_FILE_ALLOWED_FIELDS:
                continue  # already caught by _reject_unknown_fields above; dead branch
            if key in json_list_fields:
                set_clauses.append(f"{key} = ?")
                params.append(_json_list_text(value))
            elif key in json_object_fields:
                set_clauses.append(f"{key} = ?")
                params.append(_json_text(value))
            else:
                set_clauses.append(f"{key} = ?")
                params.append(value)

        if review_identity_changed:
            set_clauses.append("variant_check_status = 'pending'")

        if not set_clauses:
            return get_code_file(engagement_id, file_id)

        set_clauses.append("updated_at = CURRENT_TIMESTAMP")
        params.extend([engagement.id, file_id])

        previous_module_id = file_row["module_id"]
        if review_reopened:
            _reopen_file_metadata_review(
                connection,
                engagement.id,
                file_row,
                invalidate_architecture=False,
            )
        connection.execute(
            f"UPDATE code_files SET {', '.join(set_clauses)} WHERE engagement_id = ? AND id = ?",
            tuple(params),
        )
        if language_changed:
            _invalidate_repo_structural_index(
                connection,
                engagement.id,
                int(file_row["repo_id"]),
            )
        if review_reopened:
            _sync_metadata_review_queue_identity(
                connection,
                engagement.id,
                file_id,
                priority=int(normalized_kwargs["analysis_priority"]),
            )
            _sync_file_analysis_status(connection, engagement.id, file_id)
        module_ids_to_sync: set[int] = set()
        if previous_module_id is not None:
            module_ids_to_sync.add(int(previous_module_id))
        row = connection.execute(
            "SELECT * FROM code_files WHERE engagement_id = ? AND id = ?",
            (engagement.id, file_id),
        ).fetchone()
        if row is not None and row["module_id"] is not None:
            module_ids_to_sync.add(int(row["module_id"]))
        for module_id in module_ids_to_sync:
            _sync_module_rollup(connection, engagement.id, module_id)
        payload = _hydrate_code_file(row)
        payload["variant_check_status"] = _current_variant_check_status(
            connection,
            engagement.id,
            dict(row),
        )
    return payload


def bulk_update_structural_metadata(
    engagement_id: int,
    *,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    structural_index_schema: str,
    structural_input_digest: str,
    structural_index_manifest_path: str,
    degraded_files: int,
    degraded_file_paths: list[str],
    artifact_truncated_files: int,
    artifact_truncated_file_paths: list[str],
    analysis_status_counts: dict[str, int],
    updates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Publish one complete structural index against an exact source snapshot."""
    engagement = _engagement_or_404(engagement_id)
    if structural_index_schema != STRUCTURAL_INDEX_SCHEMA:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "structural index schema is stale; "
                f"expected {STRUCTURAL_INDEX_SCHEMA}"
            ),
        )
    structural_fields = {
        "total_functions",
        "total_entry_points",
        "total_sinks",
        "total_exports",
        "structural_analysis_status",
        "structural_analysis_mode",
        "structural_degradation_reason",
        "structural_source_size",
        "structural_bytes_scanned",
        "structural_unavailable_dimensions",
        "structural_artifact_truncated",
        "structural_truncated_dimensions",
        "structural_signal_counts",
        "callables",
    }

    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        if int(repo.get("active_generation", 0) or 0) != repo_generation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="structural index repository generation is stale",
            )
        if str(repo.get("source_manifest_digest", "") or "") != source_manifest_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="structural index source manifest digest is stale",
            )

        submitted_ids = [int(item["file_id"]) for item in updates]
        if len(submitted_ids) != len(set(submitted_ids)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index contains duplicate file IDs",
            )
        current_rows = connection.execute(
            """
            SELECT * FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
            ORDER BY id
            """,
            (engagement.id, repo_id),
        ).fetchall()
        current_by_id = {int(row["id"]): dict(row) for row in current_rows}
        if set(submitted_ids) != set(current_by_id):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index must cover every file in the current repository snapshot",
            )

        for item in updates:
            _reject_unknown_fields(
                item,
                structural_fields | {"file_id", "source_sha256", "indexed_language"},
                entity_name="bulk structural metadata update",
            )
            file_id = int(item["file_id"])
            if str(current_by_id[file_id].get("file_hash", "") or "") != str(item["source_sha256"]):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"structural index source hash is stale for file_id={file_id}",
                )
            expected_language = canonical_structural_language(
                current_by_id[file_id].get("language", "")
            )
            indexed_language = canonical_structural_language(item["indexed_language"])
            if indexed_language != str(item["indexed_language"]):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "indexed_language must already be canonical for "
                        f"file_id={file_id}; expected {indexed_language!r}"
                    ),
                )
            if indexed_language != expected_language:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"structural index language is stale for file_id={file_id}",
                )

        expected_input_digest = structural_input_identity_digest(
            repo_id=repo_id,
            repo_generation=repo_generation,
            source_manifest_digest_value=source_manifest_digest,
            files=list(current_by_id.values()),
        )
        if structural_input_digest != expected_input_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="structural index input identity is stale",
            )

        callable_registry_flags = ["callables" in item for item in updates]
        if any(callable_registry_flags) and not all(callable_registry_flags):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural callable registry publication must cover every file",
            )
        publishes_callable_registry = all(callable_registry_flags)

        canonical_callables = [
            callable_record
            for item in updates
            for callable_record in _canonical_structural_callables(
                item,
                current_by_id[int(item["file_id"])],
                repo_id=repo_id,
                repo_generation=repo_generation,
                source_manifest_digest=source_manifest_digest,
            )
        ]
        submitted_callable_keys = {
            str(callable_record["callable_key"])
            for callable_record in canonical_callables
        }
        existing_callable_keys = {
            str(row["callable_key"])
            for row in connection.execute(
                """
                SELECT callable_key
                FROM code_structural_callables
                WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
                """,
                (engagement.id, repo_id, repo_generation),
            ).fetchall()
        }
        callable_registry_published = connection.execute(
            """
            SELECT 1
            FROM code_structural_callable_publications
            WHERE engagement_id = ? AND repo_id = ? AND repo_generation = ?
            """,
            (engagement.id, repo_id, repo_generation),
        ).fetchone() is not None
        if callable_registry_published and not publishes_callable_registry:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "structural callable registry is already sealed; every replay "
                    "must publish the exact complete registry"
                ),
            )
        if (
            callable_registry_published
            and existing_callable_keys != submitted_callable_keys
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "structural callable registry is already sealed for this repository "
                    "generation"
                ),
            )

        canonical_status_counts = {"complete": 0, "degraded": 0, "unsupported": 0}
        canonical_degraded_paths: list[str] = []
        canonical_truncated_paths: list[str] = []
        for item in updates:
            file_id = int(item["file_id"])
            structural_status = str(item["structural_analysis_status"])
            canonical_status_counts[structural_status] += 1
            file_path = str(current_by_id[file_id]["file_path"])
            if structural_status == "degraded":
                canonical_degraded_paths.append(file_path)
            if bool(item["structural_artifact_truncated"]):
                canonical_truncated_paths.append(file_path)
        canonical_degraded_paths.sort()
        canonical_truncated_paths.sort()
        if (
            degraded_files != len(canonical_degraded_paths)
            or degraded_file_paths != canonical_degraded_paths
            or artifact_truncated_files != len(canonical_truncated_paths)
            or artifact_truncated_file_paths != canonical_truncated_paths
            or analysis_status_counts != canonical_status_counts
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="structural index aggregate debt metadata does not match per-file updates",
            )

        for item in updates:
            connection.execute(
                """
                UPDATE code_files
                SET total_functions = ?, total_entry_points = ?, total_sinks = ?,
                    total_exports = ?, structural_analysis_status = ?,
                    structural_analysis_mode = ?, structural_degradation_reason = ?,
                    structural_source_size = ?, structural_bytes_scanned = ?,
                    structural_unavailable_dimensions_json = ?,
                    structural_artifact_truncated = ?,
                    structural_truncated_dimensions_json = ?,
                    structural_signal_counts_json = ?, updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND repo_id = ? AND id = ?
                """,
                (
                    int(item["total_functions"]),
                    int(item["total_entry_points"]),
                    int(item["total_sinks"]),
                    int(item["total_exports"]),
                    str(item["structural_analysis_status"]),
                    str(item["structural_analysis_mode"]),
                    str(item.get("structural_degradation_reason") or ""),
                    int(item["structural_source_size"]),
                    int(item["structural_bytes_scanned"]),
                    _json_list_text(item["structural_unavailable_dimensions"]),
                    1 if item["structural_artifact_truncated"] else 0,
                    _json_list_text(item["structural_truncated_dimensions"]),
                    _json_text(item["structural_signal_counts"]),
                    engagement.id,
                    repo_id,
                    int(item["file_id"]),
                ),
            )
        for callable_record in canonical_callables:
            connection.execute(
                """
                INSERT INTO code_structural_callables (
                    engagement_id, repo_id, repo_generation,
                    source_manifest_digest, file_id, file_sha256,
                    callable_key, name, qualified_name, start_line, end_line
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, repo_generation, callable_key)
                DO NOTHING
                """,
                (
                    callable_record["engagement_id"],
                    callable_record["repo_id"],
                    callable_record["repo_generation"],
                    callable_record["source_manifest_digest"],
                    callable_record["file_id"],
                    callable_record["file_sha256"],
                    callable_record["callable_key"],
                    callable_record["name"],
                    callable_record["qualified_name"],
                    callable_record["start_line"],
                    callable_record["end_line"],
                ),
            )
        if publishes_callable_registry:
            connection.execute(
                """
                INSERT INTO code_structural_callable_publications (
                    engagement_id, repo_id, repo_generation, source_manifest_digest
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, repo_generation) DO NOTHING
                """,
                (engagement.id, repo_id, repo_generation, source_manifest_digest),
            )
            _bind_legacy_analysis_results(
                connection,
                engagement_id=engagement.id,
                repo_id=repo_id,
                repo_generation=repo_generation,
            )
        connection.execute(
            """
            UPDATE code_repos
            SET structural_index_schema = ?, structural_index_generation = ?,
                structural_index_manifest_path = ?,
                structural_degraded_files = ?, structural_degraded_file_paths_json = ?,
                structural_artifact_truncated_files = ?,
                structural_artifact_truncated_file_paths_json = ?,
                structural_analysis_status_counts_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (
                structural_index_schema,
                repo_generation,
                structural_index_manifest_path,
                degraded_files,
                _json_list_text(degraded_file_paths),
                artifact_truncated_files,
                _json_list_text(artifact_truncated_file_paths),
                _json_text(analysis_status_counts),
                engagement.id,
                repo_id,
            ),
        )

    return {
        "repo_id": repo_id,
        "repo_generation": repo_generation,
        "source_manifest_digest": source_manifest_digest,
        "structural_index_schema": structural_index_schema,
        "structural_input_digest": structural_input_digest,
        "structural_index_manifest_path": structural_index_manifest_path,
        "degraded_files": degraded_files,
        "degraded_file_paths": degraded_file_paths,
        "artifact_truncated_files": artifact_truncated_files,
        "artifact_truncated_file_paths": artifact_truncated_file_paths,
        "analysis_status_counts": analysis_status_counts,
        "registered_callables": len(canonical_callables),
        "callable_registry_published": publishes_callable_registry,
        "updated": len(updates),
    }


# =========================================================================
# Module Management
# =========================================================================

def bulk_create_code_modules(
    engagement_id: int,
    repo_id: int,
    modules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    created: list[int] = []
    with get_connection() as connection:
        _get_published_repo_row(connection, engagement.id, repo_id)
        repo_files = connection.execute(
            """
            SELECT id, file_path
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND retired_at IS NULL
            """,
            (engagement.id, repo_id),
        ).fetchall()
        file_by_path = {str(row["file_path"]): int(row["id"]) for row in repo_files}
        repo_file_ids = {int(row["id"]) for row in repo_files}

        for m in modules:
            connection.execute(
                """
                INSERT INTO code_modules (
                    engagement_id, repo_id, module_key, name, description, trust_boundary
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(engagement_id, repo_id, module_key) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    trust_boundary = excluded.trust_boundary,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    engagement.id,
                    repo_id,
                    m["module_key"],
                    m["name"],
                    m.get("description", ""),
                    m.get("trust_boundary", ""),
                ),
            )
            row = connection.execute(
                "SELECT * FROM code_modules WHERE engagement_id = ? AND repo_id = ? AND module_key = ?",
                (engagement.id, repo_id, m["module_key"]),
            ).fetchone()
            assert row is not None
            module_id = int(row["id"])
            created.append(module_id)

            selected_ids: set[int] = set()
            for file_id in m.get("file_ids", []):
                selected_ids.add(int(file_id))
            for file_path in m.get("files", []):
                if file_path not in file_by_path:
                    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")
                selected_ids.add(file_by_path[file_path])
            if not selected_ids.issubset(repo_file_ids):
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code file not found")

            if selected_ids:
                keep_placeholders = ",".join("?" for _ in selected_ids)
                connection.execute(
                    f"""
                    UPDATE code_files
                    SET module_id = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND module_id = ? AND id NOT IN ({keep_placeholders})
                    """,
                    (engagement.id, module_id, *sorted(selected_ids)),
                )
                assign_placeholders = ",".join("?" for _ in selected_ids)
                connection.execute(
                    f"""
                    UPDATE code_files
                    SET module_id = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND repo_id = ? AND id IN ({assign_placeholders})
                    """,
                    (module_id, engagement.id, repo_id, *sorted(selected_ids)),
                )
            else:
                connection.execute(
                    """
                    UPDATE code_files
                    SET module_id = NULL, updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND module_id = ?
                    """,
                    (engagement.id, module_id),
                )

        repo_module_ids = [
            int(row["id"])
            for row in connection.execute(
                "SELECT id FROM code_modules WHERE engagement_id = ? AND repo_id = ?",
                (engagement.id, repo_id),
            ).fetchall()
        ]
        for module_id in repo_module_ids:
            _sync_module_rollup(connection, engagement.id, module_id)

        rows = []
        for module_id in created:
            row = connection.execute(
                "SELECT * FROM code_modules WHERE engagement_id = ? AND id = ?",
                (engagement.id, module_id),
            ).fetchone()
            assert row is not None
            rows.append(dict(row))
    return rows


def list_code_modules(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)
            repo_clause = " AND modules.repo_id = ?"
            params: tuple[Any, ...] = (engagement.id, repo_id)
        else:
            repo_clause = ""
            params = (engagement.id,)
        query = f"""
            SELECT modules.*
            FROM code_modules AS modules
            JOIN code_repos AS repos
              ON repos.id = modules.repo_id
             AND repos.engagement_id = modules.engagement_id
             AND repos.active_generation > 0
            WHERE modules.engagement_id = ?{repo_clause}
            ORDER BY modules.id ASC
        """
        module_rows = connection.execute(query, params).fetchall()
        for row in module_rows:
            _sync_module_rollup(connection, engagement.id, int(row["id"]))
        return _fetch_all(connection, query, params)


# =========================================================================
# Analysis Queue
# =========================================================================

_QUEUE_BLOCKED_TERMINAL_STATUSES = frozenset({"error", "needs_context"})
_QUEUE_STATUSES = frozenset(
    {"pending", "processing", "done", "error", "needs_context"}
)
_QUEUE_MODES = frozenset(
    {"initial", "reanalysis", "trigger", _METADATA_REFRESH_REVIEW_MODE}
)


def _queue_item_matches(row: dict[str, Any], item: dict[str, Any]) -> bool:
    return (
        int(row["priority"]) == int(item["priority"])
        and str(row["batch_theme"]) == str(item["batch_theme"])
        and _json_decode(row.get("slot_types_json"), []) == item["slot_types"]
        and _json_decode(row.get("guidance_hypotheses_json"), [])
        == item["guidance_hypotheses"]
        and _json_decode(row.get("cross_file_triggers_json"), [])
        == item["cross_file_triggers"]
    )


def _queue_outcome(
    *,
    file_id: int,
    queue_item_id: int | None,
    outcome: str,
    status_value: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "file_id": file_id,
        "queue_item_id": queue_item_id,
        "outcome": outcome,
        "status": status_value,
        "detail": detail,
    }


def bulk_create_queue_items(
    engagement_id: int,
    items: list[dict[str, Any]],
    *,
    mode: str = "initial",
    reason: str = "",
) -> dict[str, Any]:
    """Create canonical initial work or an explicit terminal-to-pending reanalysis.

    ``BEGIN IMMEDIATE`` makes the read/decide/write sequence the concurrency
    boundary. Initial retries can refresh only an unleased pending initial row;
    they never alter a processing lease or any completed/error/context evidence.
    Reanalysis is a separate, reasoned attempt chained to the latest completed
    row, so depth is auditable instead of emerging from duplicate inserts.
    """
    engagement = _engagement_or_404(engagement_id)
    normalized_mode = str(mode).strip().lower()
    normalized_reason = str(reason).strip()
    if normalized_mode not in {"initial", "reanalysis"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="queue mode must be initial or reanalysis",
        )
    if normalized_mode == "reanalysis" and not normalized_reason:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reason is required when mode=reanalysis",
        )

    submitted_file_ids = [
        _require_strict_positive_id(
            item.get("file_id"),
            field_name=f"items[{idx}].file_id",
        )
        for idx, item in enumerate(items)
    ]
    if len(submitted_file_ids) != len(set(submitted_file_ids)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="queue request contains duplicate file IDs",
        )
    submitted_priorities: list[int] = []
    for item in items:
        if "priority" not in item:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="every queue item requires an integer priority",
            )
        priority = _require_strict_priority(
            item["priority"],
            field_name="queue priority",
        )
        submitted_priorities.append(priority)

    counts = {
        "inserted": 0,
        "updated": 0,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
    }
    outcomes: list[dict[str, Any]] = []
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        file_rows = _get_file_rows(connection, engagement.id, set(submitted_file_ids))
        repo_rows = _get_repo_rows(
            connection,
            engagement.id,
            {int(file_row["repo_id"]) for file_row in file_rows.values()},
        )
        for file_id, priority in zip(
            submitted_file_ids, submitted_priorities, strict=True
        ):
            expected_priority = int(file_rows[file_id]["analysis_priority"])
            if priority != expected_priority:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"queue priority for file {file_id} must equal current "
                        f"analysis_priority {expected_priority} (received {priority})"
                    ),
                )

        for idx, (item, priority) in enumerate(
            zip(items, submitted_priorities, strict=True)
        ):
            file_id = submitted_file_ids[idx]
            repo_generation = int(
                repo_rows[int(file_rows[file_id]["repo_id"])]["active_generation"]
            )
            normalized_item = {
                "priority": priority,
                "batch_theme": str(item.get("batch_theme", "")),
                "slot_types": _normalize_slot_types(
                    item.get("slot_types"), field_name="slot_types"
                ),
                "guidance_hypotheses": _normalize_guidance_hypotheses(
                    item.get("guidance_hypotheses"),
                    field_name="guidance_hypotheses",
                ),
                "cross_file_triggers": list(item.get("cross_file_triggers") or []),
            }
            current_rows = [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT * FROM code_analysis_queue
                    WHERE engagement_id = ? AND file_id = ? AND repo_generation = ?
                    ORDER BY id ASC
                    """,
                    (engagement.id, file_id, repo_generation),
                ).fetchall()
            ]
            latest, active, active_issue = _canonical_queue_attempt_state(current_rows)
            if active_issue is not None:
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        queue_item_id=(
                            None if active is None else int(active["id"])
                        ),
                        outcome="conflict",
                        status_value=active_issue,
                        detail=(
                            f"{active_issue} queue history requires operator reconciliation"
                        ),
                    )
                )
                continue

            requested_predecessor = item.get("supersedes")
            expected_predecessor = None
            if normalized_mode == "reanalysis":
                if requested_predecessor is None:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=(
                            f"reanalysis for file {file_id} requires supersedes with "
                            "the exact predecessor queue row ID"
                        ),
                    )
                if active is not None and str(active.get("queue_mode")) == "reanalysis":
                    expected_predecessor = active.get("reanalysis_of_queue_item_id")
                elif latest is not None:
                    expected_predecessor = latest.get("id")
                if (
                    expected_predecessor is not None
                    and int(requested_predecessor) != int(expected_predecessor)
                ):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            f"reanalysis supersedes={requested_predecessor} does not match "
                            f"the current predecessor queue row {expected_predecessor} "
                            f"for file {file_id}"
                        ),
                    )

            if active is not None:
                active_status = str(active["status"])
                active_mode = str(active.get("queue_mode") or "initial")
                if active_mode == "initial" and (
                    str(active.get("batch_theme") or "") == "cross-file-trigger"
                    or _json_decode(active.get("cross_file_triggers_json"), [])
                ):
                    active_mode = "trigger"
                same_payload = _queue_item_matches(active, normalized_item)
                same_attempt = active_mode == normalized_mode and (
                    normalized_mode == "initial"
                    or str(active.get("reanalysis_reason") or "") == normalized_reason
                )
                pending_is_unleased = not str(
                    active.get("assigned_agent") or ""
                ) and not str(active.get("lease_token") or "")
                if active_status == "pending" and same_attempt:
                    if same_payload and pending_is_unleased:
                        counts["already_active"] += 1
                        outcomes.append(
                            _queue_outcome(
                                file_id=file_id,
                                queue_item_id=int(active["id"]),
                                outcome="already_active",
                                status_value=active_status,
                                detail=f"identical pending {normalized_mode} queue item already exists",
                            )
                        )
                        continue
                    if normalized_mode == "initial" and pending_is_unleased:
                        cursor = connection.execute(
                            """
                            UPDATE code_analysis_queue
                            SET priority = ?, batch_theme = ?, slot_types_json = ?,
                                guidance_hypotheses_json = ?,
                                cross_file_triggers_json = ?,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE engagement_id = ? AND id = ? AND status = 'pending'
                              AND queue_mode = 'initial'
                              AND assigned_agent = '' AND lease_token = ''
                            """,
                            (
                                priority,
                                normalized_item["batch_theme"],
                                _json_list_text(normalized_item["slot_types"]),
                                _json_list_text(normalized_item["guidance_hypotheses"]),
                                _json_list_text(normalized_item["cross_file_triggers"]),
                                engagement.id,
                                int(active["id"]),
                            ),
                        )
                        if cursor.rowcount != 1:
                            raise HTTPException(
                                status_code=status.HTTP_409_CONFLICT,
                                detail="pending queue item changed during retry",
                            )
                        counts["updated"] += 1
                        outcomes.append(
                            _queue_outcome(
                                file_id=file_id,
                                queue_item_id=int(active["id"]),
                                outcome="updated",
                                status_value="pending",
                                detail="updated pending initial queue item",
                            )
                        )
                        _sync_file_analysis_status(connection, engagement.id, file_id)
                        _sync_trigger_status_for_file(connection, engagement.id, file_id)
                        continue

                if active_status == "processing" and same_attempt and same_payload:
                    counts["already_active"] += 1
                    outcomes.append(
                        _queue_outcome(
                            file_id=file_id,
                            queue_item_id=int(active["id"]),
                            outcome="already_active",
                            status_value=active_status,
                            detail="identical live lease already owns this queue item",
                        )
                    )
                    continue

                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        queue_item_id=int(active["id"]),
                        outcome="conflict",
                        status_value=active_status,
                        detail="active queue item differs; live work was not mutated",
                    )
                )
                continue

            if normalized_mode == "initial" and latest is not None:
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        queue_item_id=int(latest["id"]),
                        outcome="conflict",
                        status_value=str(latest["status"]),
                        detail="current-generation evidence exists; use explicit reanalysis",
                    )
                )
                continue

            if normalized_mode == "reanalysis" and (
                latest is None or str(latest["status"]) != "done"
            ):
                latest_status = "missing" if latest is None else str(latest["status"])
                detail = "reanalysis requires a completed predecessor"
                if latest_status in _QUEUE_BLOCKED_TERMINAL_STATUSES:
                    detail = f"{latest_status} item must use its dedicated retry workflow"
                counts["conflicts"] += 1
                outcomes.append(
                    _queue_outcome(
                        file_id=file_id,
                        queue_item_id=None if latest is None else int(latest["id"]),
                        outcome="conflict",
                        status_value=latest_status,
                        detail=detail,
                    )
                )
                continue

            predecessor_id = (
                None
                if normalized_mode == "initial"
                else int(requested_predecessor)
            )
            cursor = connection.execute(
                """
                INSERT INTO code_analysis_queue (
                    engagement_id, file_id, priority,
                    batch_theme, slot_types_json, guidance_hypotheses_json,
                    cross_file_triggers_json, repo_generation, queue_mode,
                    reanalysis_reason, reanalysis_of_queue_item_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    file_id,
                    priority,
                    normalized_item["batch_theme"],
                    _json_list_text(normalized_item["slot_types"]),
                    _json_list_text(normalized_item["guidance_hypotheses"]),
                    _json_list_text(normalized_item["cross_file_triggers"]),
                    repo_generation,
                    normalized_mode,
                    normalized_reason if normalized_mode == "reanalysis" else "",
                    predecessor_id,
                ),
            )
            outcome_name = "reanalysis" if normalized_mode == "reanalysis" else "inserted"
            counts[outcome_name] += 1
            outcomes.append(
                _queue_outcome(
                    file_id=file_id,
                    queue_item_id=int(cursor.lastrowid),
                    outcome=outcome_name,
                    status_value="pending",
                    detail=(
                        "created explicit reanalysis queue item"
                        if normalized_mode == "reanalysis"
                        else "created initial queue item"
                    ),
                )
            )
            _sync_file_analysis_status(connection, engagement.id, file_id)
            _sync_trigger_status_for_file(connection, engagement.id, file_id)

        return {
            "mode": normalized_mode,
            **counts,
            "total": len(items),
            "outcomes": outcomes,
        }


def queue_stats(engagement_id: int) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        rows = connection.execute(
            """
            WITH ranked AS (
                SELECT queue.status, queue.assigned_agent, queue.lease_token,
                       ROW_NUMBER() OVER (
                           PARTITION BY queue.file_id
                           ORDER BY queue.id DESC
                       ) AS attempt_rank,
                       SUM(CASE WHEN queue.status IN ('pending', 'processing')
                                THEN 1 ELSE 0 END) OVER (
                           PARTITION BY queue.file_id
                       ) AS active_count
                FROM code_analysis_queue AS queue
                JOIN code_files AS files
                  ON files.id = queue.file_id
                 AND files.engagement_id = queue.engagement_id
                JOIN code_repos AS repos
                  ON repos.id = files.repo_id
                 AND repos.engagement_id = files.engagement_id
                 AND repos.active_generation > 0
                WHERE queue.engagement_id = ?
                  AND queue.repo_generation = repos.active_generation
                  AND queue.source_superseded_at IS NULL
            )
            SELECT status, assigned_agent, lease_token, attempt_rank, active_count
            FROM ranked
            """,
            (engagement.id,),
        ).fetchall()
        historical_total = _scalar_row(
            connection,
            """
            SELECT COUNT(*)
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ? AND repos.active_generation > 0
            """,
            (engagement.id,),
        )
    counts: dict[str, int] = {}
    current_attempt_total = 0
    invalid_active_identity = 0
    invalid_active_history = 0
    for row in rows:
        if int(row["attempt_rank"]) == 1:
            current_attempt_total += 1
            status_value = str(row["status"])
            latest_is_active = status_value in _QUEUE_ACTIVE_STATUSES
            if int(row["active_count"] or 0) > (1 if latest_is_active else 0):
                invalid_active_history += 1
                continue
            assigned_agent = str(row["assigned_agent"] or "")
            lease_token = str(row["lease_token"] or "")
            invalid_identity = (
                status_value == "pending" and bool(assigned_agent or lease_token)
            ) or (
                status_value == "processing"
                and not bool(assigned_agent and lease_token)
            )
            if invalid_identity:
                invalid_active_identity += 1
                continue
            counts[status_value] = counts.get(status_value, 0) + 1
    actionable_total = sum(counts.values())
    return {
        "pending": counts.get("pending", 0),
        "processing": counts.get("processing", 0),
        "done": counts.get("done", 0),
        "error": counts.get("error", 0),
        "needs_context": counts.get("needs_context", 0),
        "total": actionable_total,
        "historical_total": historical_total,
        "superseded_history": historical_total - current_attempt_total,
        "invalid_active_identity": invalid_active_identity,
        "invalid_active_history": invalid_active_history,
    }


def _hydrate_queue_listing_row(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "file_id": int(row["file_id"]),
        "file_path": str(row["file_path"]),
        "classification": str(row["classification"] or ""),
        "analysis_priority": int(row["analysis_priority"]),
        "repo_id": int(row["repo_id"]),
        "repo_key": str(row["repo_key"]),
        "status": str(row["status"]),
        "queue_mode": str(row["queue_mode"] or "initial"),
        "priority": int(row["priority"]),
        "batch_theme": str(row["batch_theme"] or ""),
        "slot_types": _json_decode(row["slot_types_json"], []),
        "guidance_hypotheses": _json_decode(row["guidance_hypotheses_json"], []),
        "cross_file_triggers": _json_decode(row["cross_file_triggers_json"], []),
        "agent_name": str(row["assigned_agent"] or ""),
        "lease_token": str(row["lease_token"] or ""),
        "repo_generation": int(row["repo_generation"]),
        "disposition": str(row["disposition"] or ""),
        "skip_reason": str(row["skip_reason"] or ""),
        "reanalysis_of_queue_item_id": row["reanalysis_of_queue_item_id"],
        "consumed_at": row["consumed_at"],
        "last_heartbeat_at": row["last_heartbeat_at"],
        "completed_at": row["completed_at"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_queue_items(
    engagement_id: int,
    *,
    status_filter: str | None = None,
    repo_id: int | None = None,
    classification: str | None = None,
    batch_theme: str | None = None,
    queue_mode: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> dict[str, Any]:
    """Page the current-generation queue so its row IDs stay recoverable.

    Every current-generation, non-source-superseded attempt is listed, including
    an older active row that overlaps the latest one. `fetch` refuses to claim
    those and `stats` reports them only as an `invalid_active_history` count, so
    a listing that dropped them would hide the exact IDs an operator needs to
    reconcile the history. Ordering matches the claim order `fetch` applies, so a
    page fed back through `--ids-file` is claimed in the order it was shown.
    """
    engagement = _engagement_or_404(engagement_id)
    if status_filter is not None and status_filter not in _QUEUE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid queue status: {status_filter}",
        )
    if queue_mode is not None and queue_mode not in _QUEUE_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid queue mode: {queue_mode}",
        )
    if classification is not None and classification not in _VALID_CLASSIFICATIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid classification: {classification}",
        )
    clauses = [
        "queue.engagement_id = ?",
        "files.retired_at IS NULL",
        "queue.repo_generation = repos.active_generation",
        "queue.source_superseded_at IS NULL",
    ]
    params: list[Any] = [engagement.id]
    if status_filter is not None:
        clauses.append("queue.status = ?")
        params.append(status_filter)
    if repo_id is not None:
        clauses.append("files.repo_id = ?")
        params.append(_coerce_int(repo_id, field_name="repo_id"))
    if classification is not None:
        clauses.append("files.classification = ?")
        params.append(classification)
    if batch_theme is not None:
        clauses.append("queue.batch_theme = ?")
        params.append(batch_theme)
    if queue_mode is not None:
        clauses.append("queue.queue_mode = ?")
        params.append(queue_mode)
    from_where = f"""
        FROM code_analysis_queue AS queue
        JOIN code_files AS files
          ON files.id = queue.file_id
         AND files.engagement_id = queue.engagement_id
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE {' AND '.join(clauses)}
    """
    query = f"""
        SELECT queue.*, files.file_path, files.classification,
               files.analysis_priority, files.repo_id, repos.repo_key
        {from_where}
        ORDER BY queue.priority DESC, queue.id ASC
    """
    if offset > 0:
        # SQLite has no bare OFFSET, so an unbounded listing still needs a
        # LIMIT to skip rows at all. Dropping the offset instead would return
        # page one while `has_more` described a page the caller never got.
        query += f" LIMIT {int(limit) if limit is not None else -1} OFFSET {int(offset)}"
    elif limit is not None:
        query += f" LIMIT {int(limit)}"
    with get_connection() as connection:
        total = _scalar_row(connection, f"SELECT COUNT(*) {from_where}", tuple(params))
        rows = connection.execute(query, tuple(params)).fetchall()
    items = [_hydrate_queue_listing_row(row) for row in rows]
    return {
        "total": total,
        "offset": offset,
        "count": len(items),
        "has_more": offset + len(items) < total,
        # The exact shape `code-dispatch fetch --ids-file` consumes, so a page
        # of this response is itself a valid ids file.
        "item_ids": [item["id"] for item in items],
        "items": items,
    }


def fetch_queue_items(
    engagement_id: int,
    limit: int,
    agent_name: str,
    *,
    repo_id: int | None = None,
    classification: str | None = None,
    batch_theme: str | None = None,
    queue_mode: str | None = None,
    item_ids: list[int] | None = None,
) -> list[dict[str, Any]]:
    """Atomically claim pending queue items for an agent.

    Uses UPDATE ... WHERE id IN (SELECT ... LIMIT) to prevent two concurrent
    callers from claiming the same rows.
    """
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    filter_clauses: list[str] = []
    filter_params: list[Any] = []
    if repo_id is not None:
        filter_clauses.append("files.repo_id = ?")
        filter_params.append(repo_id)
    if classification is not None:
        filter_clauses.append("files.classification = ?")
        filter_params.append(classification)
    if batch_theme is not None:
        filter_clauses.append("queue.batch_theme = ?")
        filter_params.append(batch_theme)
    if queue_mode is not None:
        if queue_mode not in _QUEUE_MODES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid queue mode: {queue_mode}",
            )
        filter_clauses.append("queue.queue_mode = ?")
        filter_params.append(queue_mode)
    if item_ids is not None:
        normalized_ids = sorted(set(item_ids))
        placeholders = ",".join("?" for _ in normalized_ids)
        filter_clauses.append(f"queue.id IN ({placeholders})")
        filter_params.extend(normalized_ids)
    filter_sql = "" if not filter_clauses else " AND " + " AND ".join(filter_clauses)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        selected = connection.execute(
            f"""
            SELECT queue.id, queue.repo_generation
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE queue.engagement_id = ? AND queue.status = 'pending'
              AND queue.assigned_agent = '' AND queue.lease_token = ''
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND ({_latest_current_queue_attempt_sql("queue", "repos")})
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              {filter_sql}
            ORDER BY queue.priority DESC, queue.id ASC
            LIMIT ?
            """,
            (engagement.id, *filter_params, limit),
        ).fetchall()
        claimed_ids: list[int] = []
        for selected_row in selected:
            item_id = int(selected_row["id"])
            repo_generation = int(selected_row["repo_generation"])
            lease_token = str(uuid.uuid4())
            cursor = connection.execute(
                """
                UPDATE code_analysis_queue
                SET status = 'processing', assigned_agent = ?, lease_token = ?,
                    consumed_at = ?, last_heartbeat_at = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND status = 'pending'
                  AND assigned_agent = '' AND lease_token = ''
                  AND repo_generation = ?
                """,
                (
                    agent_name,
                    lease_token,
                    now,
                    now,
                    engagement.id,
                    item_id,
                    repo_generation,
                ),
            )
            if cursor.rowcount == 1:
                claimed_ids.append(item_id)
        if not claimed_ids:
            return []
        placeholders = ",".join("?" for _ in claimed_ids)
        rows = connection.execute(
            f"""
            SELECT * FROM code_analysis_queue
            WHERE engagement_id = ? AND id IN ({placeholders})
            ORDER BY priority DESC, id ASC
            """,
            (engagement.id, *claimed_ids),
        ).fetchall()

        file_rows = _get_file_rows(connection, engagement.id, {int(row["file_id"]) for row in rows})
        repo_rows = _get_repo_rows(connection, engagement.id, {int(file_rows[int(row["file_id"])]["repo_id"]) for row in rows})

        for file_id in {int(row["file_id"]) for row in rows}:
            _sync_file_analysis_status(connection, engagement.id, file_id)
        payload: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["agent_name"] = str(item.pop("assigned_agent", ""))
            item["batch_theme"] = item.get("batch_theme", "")
            item["slot_types"] = _json_decode(item.get("slot_types_json"), [])
            item["guidance_hypotheses"] = _json_decode(item.get("guidance_hypotheses_json"), [])
            item["cross_file_triggers"] = _json_decode(item.get("cross_file_triggers_json"), [])
            item["file"] = _hydrate_code_file(file_rows[int(row["file_id"])])
            item["repo"] = _hydrate_code_repo(repo_rows[int(file_rows[int(row["file_id"])]["repo_id"])])
            item["applicable_vuln_classes"] = _applicable_families_for_file(
                item["file"].get("slot_types", []),
                language=str(item["file"].get("language", "")),
                role=str(item["file"].get("role", "")),
            )
            payload.append(item)
    return payload


def _normalize_cwe_coverage(cwe_coverage: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if not isinstance(cwe_coverage, list) or not cwe_coverage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="cwe_coverage is required when completing a queue item",
        )
    normalized: list[dict[str, Any]] = []
    seen_families: set[str] = set()
    for idx, entry in enumerate(cwe_coverage):
        if not isinstance(entry, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cwe_coverage entry {idx} must be an object",
            )
        family = str(entry.get("family", "")).strip()
        if not family:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cwe_coverage entry {idx} is missing family",
            )
        if family in seen_families:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Duplicate cwe_coverage family '{family}'",
            )
        seen_families.add(family)
        normalized_entry = dict(entry)
        normalized_entry["family"] = family
        normalized.append(normalized_entry)
    return normalized


def _validate_completion_coverage(file_row: dict[str, Any], cwe_coverage: list[dict[str, Any]]) -> None:
    classification = str(file_row.get("classification", ""))
    slot_types = _json_decode(file_row.get("slot_types_json"), [])
    language = str(file_row.get("language", ""))
    role = str(file_row.get("role", ""))

    if classification in {"critical", "high"} and not slot_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot complete {classification} file {file_row['file_path']} without slot_types; "
                "classification metadata is incomplete"
            ),
        )

    applicable = _applicable_families_for_file(slot_types, language=language, role=role)
    if classification in {"critical", "high"} and not applicable:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot complete {classification} file {file_row['file_path']} without "
                "applicable vulnerability families"
            ),
        )

    provided = {str(entry.get("family", "")) for entry in cwe_coverage}
    missing = [family for family in applicable if family not in provided]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Missing cwe_coverage families for {file_row['file_path']}: "
                + ", ".join(missing)
            ),
        )


def _compute_coverage_integrity(
    connection,
    engagement_id: int,
    queue_item_id: int,
    file_id: int,
    total_functions: int,
    cwe_coverage: list[dict[str, Any]],
) -> dict[str, Any]:
    """Derive source coverage from current grouped receipts and structural bindings."""
    receipt_counts = connection.execute(
        """
        SELECT
            COUNT(*) AS current_receipt_rows,
            COALESCE(SUM(
                CASE WHEN trim(evidence) != '' OR trim(evidence_ref) != '' THEN 1 ELSE 0 END
            ), 0) AS evidenced_receipt_rows
        FROM code_analysis_results
        WHERE engagement_id = ? AND queue_item_id = ? AND file_id = ?
          AND superseded_at IS NULL
          AND receipt_binding_status NOT IN (
              'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
          )
          AND NOT EXISTS (
              SELECT 1 FROM code_analysis_results AS replacement
              WHERE replacement.supersedes_result_id = code_analysis_results.id
          )
        """,
        (engagement_id, queue_item_id, file_id),
    ).fetchone()
    current_receipt_rows = int(receipt_counts["current_receipt_rows"] or 0)
    evidenced_receipt_rows = int(receipt_counts["evidenced_receipt_rows"] or 0)

    distinct_structural_callables = connection.execute(
        """
        SELECT COUNT(DISTINCT links.callable_id)
        FROM code_analysis_results AS results
        JOIN code_analysis_result_callables AS links
          ON links.result_id = results.id AND links.file_id = ?
        WHERE results.engagement_id = ? AND results.queue_item_id = ?
          AND results.file_id = ? AND results.superseded_at IS NULL
          AND results.receipt_binding_status NOT IN (
              'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
          )
          AND NOT EXISTS (
              SELECT 1 FROM code_analysis_results AS replacement
              WHERE replacement.supersedes_result_id = results.id
          )
        """,
        (file_id, engagement_id, queue_item_id, file_id),
    ).fetchone()[0] or 0

    analyzed_entries = [
        e for e in cwe_coverage if not _is_cwe_entry_not_applicable(e)
    ]
    max_claimed_functions = max(
        (_safe_int(e.get("functions_analyzed", 0)) for e in analyzed_entries),
        default=0,
    )
    max_effort = max(
        (_coerce_float(e.get("effort", 0)) for e in analyzed_entries),
        default=0.0,
    )

    authoritative_blockers: list[str] = []
    advisories: list[str] = []

    if current_receipt_rows == 0 and max_claimed_functions > 0:
        authoritative_blockers.append(
            f"functions_analyzed={max_claimed_functions} claimed but 0 analysis-result rows recorded"
        )

    if distinct_structural_callables > 0 and max_claimed_functions > 0:
        ratio = distinct_structural_callables / max_claimed_functions
        if ratio < 0.3:
            advisories.append(
                f"functions_analyzed={max_claimed_functions} claimed but only "
                f"{distinct_structural_callables} structurally bound callables recorded "
                f"(ratio={ratio:.2f})"
            )

    if total_functions > 0 and max_claimed_functions > total_functions:
        advisories.append(
            f"functions_analyzed={max_claimed_functions} exceeds file total_functions={total_functions}"
        )

    if total_functions > 0 and max_effort >= 60 and current_receipt_rows == 0:
        authoritative_blockers.append(
            f"effort={max_effort:.0f} claimed for file with {total_functions} functions "
            f"but 0 analysis-result rows"
        )

    return {
        "current_receipt_rows": current_receipt_rows,
        "evidenced_receipt_rows": evidenced_receipt_rows,
        "distinct_structural_callables_reviewed": distinct_structural_callables,
        "callable_coverage_pct": round(
            min(100.0, distinct_structural_callables / total_functions * 100.0), 1
        ) if total_functions > 0 else 0.0,
        "max_claimed_functions_analyzed": max_claimed_functions,
        "total_functions_on_file": total_functions,
        "max_effort": max_effort,
        "authoritative_blockers": authoritative_blockers,
        "advisories": advisories,
        "warnings": [*authoritative_blockers, *advisories],
        "plausible": not authoritative_blockers,
    }


def _normalize_cross_file_triggers(
    cross_file_triggers: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    if not cross_file_triggers:
        return []
    normalized_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for idx, trigger in enumerate(cross_file_triggers):
        if not isinstance(trigger, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} must be an object",
            )
        file_path = str(trigger.get("file_path", "")).strip()
        vuln_class = str(trigger.get("vuln_class", "")).strip()
        reason = str(trigger.get("reason", "")).strip()
        if not file_path:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing file_path",
            )
        if not vuln_class:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing vuln_class",
            )
        if not reason:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"cross_file_triggers entry {idx} is missing reason",
            )
        normalized = dict(trigger)
        normalized["file_path"] = file_path
        normalized["vuln_class"] = vuln_class
        normalized["reason"] = reason
        normalized_by_key[(file_path, vuln_class, reason)] = normalized
    return list(normalized_by_key.values())


def _record_cross_file_triggers(
    connection,
    engagement_id: int,
    *,
    source_queue_item_id: int | None,
    source_file_id: int,
    cross_file_triggers: list[dict[str, Any]],
) -> None:
    if not cross_file_triggers:
        return
    source_file_row = _get_file_rows(connection, engagement_id, {source_file_id})[source_file_id]
    source_repo_id = int(source_file_row["repo_id"])
    source_repo = _get_published_repo_row(connection, engagement_id, source_repo_id)
    source_repo_generation = int(source_repo["active_generation"])
    source_manifest_digest_value = str(source_repo["source_manifest_digest"])
    for trigger in cross_file_triggers:
        target_file_path = str(trigger["file_path"])
        vuln_class = str(trigger["vuln_class"])
        reason = str(trigger["reason"])
        target_row = connection.execute(
            """
            SELECT id
            FROM code_files
            WHERE engagement_id = ? AND repo_id = ? AND file_path = ?
              AND retired_at IS NULL
            """,
            (engagement_id, source_repo_id, target_file_path),
        ).fetchone()
        target_file_id = int(target_row["id"]) if target_row is not None else None
        # A trigger is a new review obligation. An older review of the target
        # cannot satisfy a hypothesis that did not exist when that review ran.
        trigger_status = _TRIGGER_STATUS_PENDING

        if target_file_id is not None:
            existing = connection.execute(
                """
                SELECT id, status, resolution_note
                FROM code_analysis_triggers
                WHERE engagement_id = ? AND target_file_id = ? AND vuln_class = ?
                  AND reason = ? AND source_file_id IS ? AND source_queue_item_id IS ?
                  AND repo_id = ? AND repo_generation = ?
                """,
                (
                    engagement_id,
                    target_file_id,
                    vuln_class,
                    reason,
                    source_file_id,
                    source_queue_item_id,
                    source_repo_id,
                    source_repo_generation,
                ),
            ).fetchone()
        else:
            existing = connection.execute(
                """
                SELECT id, status, resolution_note
                FROM code_analysis_triggers
                WHERE engagement_id = ? AND source_file_id = ? AND target_file_id IS NULL
                  AND target_file_path = ? AND vuln_class = ?
                  AND reason = ? AND source_queue_item_id IS ?
                  AND repo_id = ? AND repo_generation = ?
                """,
                (
                    engagement_id,
                    source_file_id,
                    target_file_path,
                    vuln_class,
                    reason,
                    source_queue_item_id,
                    source_repo_id,
                    source_repo_generation,
                ),
            ).fetchone()

        resolution_note = ""

        if existing is None:
            connection.execute(
                """
                INSERT INTO code_analysis_triggers (
                    engagement_id, source_queue_item_id, source_file_id, target_file_id,
                    target_file_path, vuln_class, reason, status, resolution_note,
                    repo_id, repo_generation, source_manifest_digest
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement_id,
                    source_queue_item_id,
                    source_file_id,
                    target_file_id,
                    target_file_path,
                    vuln_class,
                    reason,
                    trigger_status,
                    resolution_note,
                    source_repo_id,
                    source_repo_generation,
                    source_manifest_digest_value,
                ),
            )
            continue

        existing_status = str(existing["status"])
        resolved_status = (
            existing_status
            if existing_status in _TERMINAL_TRIGGER_RESOLUTION_STATUSES
            else trigger_status
        )
        resolved_note = (
            str(existing["resolution_note"] or "")
            if existing_status in _TERMINAL_TRIGGER_RESOLUTION_STATUSES
            else resolution_note
        )
        connection.execute(
            f"""
            UPDATE code_analysis_triggers
            SET source_queue_item_id = ?,
                source_file_id = ?,
                target_file_id = ?,
                target_file_path = ?,
                vuln_class = ?,
                reason = ?,
                status = ?,
                resolved_queue_item_id = CASE
                    WHEN status IN ({','.join('?' for _ in _TERMINAL_TRIGGER_RESOLUTION_STATUSES)})
                    THEN resolved_queue_item_id ELSE NULL END,
                resolution_note = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (
                source_queue_item_id,
                source_file_id,
                target_file_id,
                target_file_path,
                vuln_class,
                reason,
                resolved_status,
                *_TERMINAL_TRIGGER_RESOLUTION_STATUSES,
                resolved_note,
                engagement_id,
                int(existing["id"]),
            ),
        )


_VALID_DISPOSITIONS = frozenset({"finding", "suspicious", "clean", "skipped"})
_VALID_ANALYSIS_RESULT_DISPOSITIONS = frozenset({"finding", "suspicious", "clean", "needs_context", "skipped"})


def complete_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    disposition: str,
    notes: str = "",
    cwe_coverage: list[dict[str, Any]] | None = None,
    skip_reason: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    if len(item_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="complete_queue_items accepts exactly one queue item per call",
        )
    if disposition not in _VALID_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid disposition '{disposition}'. Must be one of: {', '.join(sorted(_VALID_DISPOSITIONS))}",
        )
    # C50: when disposition='skipped', a skip_reason is mandatory so the
    # coverage report can attribute the skip (test-fixture, generated-code,
    # minified, out-of-scope-language). For other dispositions the field
    # stays empty and the existing notes blob carries any free-text context.
    if disposition == "skipped" and not (skip_reason or "").strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "skip_reason is required when disposition='skipped'. "
                "Standard reasons: test-fixture, generated-code, minified, "
                "out-of-scope-language, vendored-dependency."
            ),
        )
    if disposition == "clean" and not notes.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="notes are required when disposition='clean'",
        )
    now = _now_iso()
    # Skipped items had no CWE analysis run; empty cwe_coverage is the
    # natural payload. Skip both the required-non-empty check and the
    # per-CWE shape normalization.
    if disposition == "skipped":
        normalized_cwe_coverage: list[dict[str, Any]] = []
    else:
        normalized_cwe_coverage = _normalize_cwe_coverage(cwe_coverage)
    cwe_coverage_text = _json_list_text(normalized_cwe_coverage)
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="processing", action="complete")
        _require_queue_lease(queue_rows, agent_name=agent_name, lease_token=lease_token, action="complete")
        _require_queue_generation(connection, engagement.id, queue_rows, action="complete")
        queue_row = next(iter(queue_rows.values()))
        file_row = _get_file_rows(connection, engagement.id, {int(queue_row["file_id"])})[
            int(queue_row["file_id"])
        ]
        candidate_rows = connection.execute(
            """
            SELECT DISTINCT disposition
            FROM code_analysis_results
            WHERE engagement_id = ? AND queue_item_id = ? AND file_id = ?
              AND lease_token = ? AND disposition IN ('finding', 'suspicious')
              AND superseded_at IS NULL
              AND NOT EXISTS (
                  SELECT 1 FROM code_analysis_results AS replacement
                  WHERE replacement.supersedes_result_id = code_analysis_results.id
              )
            ORDER BY disposition
            """,
            (
                engagement.id,
                int(queue_row["id"]),
                int(queue_row["file_id"]),
                lease_token,
            ),
        ).fetchall()
        candidate_dispositions = [str(row["disposition"]) for row in candidate_rows]
        if len(candidate_dispositions) > 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "conflicting candidate-bearing analysis result dispositions "
                    f"exist for this lease: {', '.join(candidate_dispositions)}"
                ),
            )
        if candidate_dispositions and disposition != candidate_dispositions[0]:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "candidate-bearing analysis result requires queue disposition="
                    f"'{candidate_dispositions[0]}'; cannot complete as '{disposition}'"
                ),
            )
        if disposition == "finding":
            finding_results = connection.execute(
                """
                SELECT finding_slug
                FROM code_analysis_results
                WHERE engagement_id = ? AND queue_item_id = ? AND file_id = ?
                  AND lease_token = ? AND disposition = 'finding'
                  AND superseded_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM code_analysis_results AS replacement
                      WHERE replacement.supersedes_result_id = code_analysis_results.id
                  )
                ORDER BY id
                """,
                (
                    engagement.id,
                    int(queue_row["id"]),
                    int(queue_row["file_id"]),
                    lease_token,
                ),
            ).fetchall()
            for finding_result in finding_results:
                _require_current_reportable_root_file_finding(
                    connection,
                    engagement.id,
                    file_row,
                    finding_result["finding_slug"],
                )
        if disposition in {"finding", "suspicious"}:
            evidenced_result = connection.execute(
                """
                SELECT id
                FROM code_analysis_results
                WHERE engagement_id = ? AND queue_item_id = ? AND file_id = ?
                  AND lease_token = ? AND disposition = ? AND superseded_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM code_analysis_results AS replacement
                      WHERE replacement.supersedes_result_id = code_analysis_results.id
                  )
                  AND (trim(evidence) != '' OR trim(evidence_ref) != '')
                LIMIT 1
                """,
                (
                    engagement.id,
                    int(queue_row["id"]),
                    int(queue_row["file_id"]),
                    lease_token,
                    disposition,
                ),
            ).fetchone()
            if evidenced_result is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"disposition='{disposition}' requires a current analysis result "
                        "with evidence or evidence_ref"
                    ),
                )
        if (
            str(file_row.get("classification") or "") in {"critical", "high"}
            and disposition != "skipped"
        ):
            source_receipt = connection.execute(
                """
                SELECT results.id
                FROM code_analysis_results AS results
                WHERE results.engagement_id = ? AND results.queue_item_id = ?
                  AND results.file_id = ? AND results.lease_token = ?
                  AND results.repo_generation = ? AND results.disposition = ?
                  AND results.superseded_at IS NULL
                  AND results.receipt_binding_status NOT IN (
                      'legacy_ambiguous', 'legacy_missing', 'legacy_unbound'
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM code_analysis_results AS replacement
                      WHERE replacement.supersedes_result_id = results.id
                  )
                  AND (
                      EXISTS (
                          SELECT 1 FROM code_analysis_result_callables AS links
                          WHERE links.result_id = results.id AND links.file_id = ?
                      )
                      OR EXISTS (
                          SELECT 1 FROM json_each(results.reviewed_spans_json) AS span
                          WHERE CAST(json_extract(span.value, '$.file_id') AS INTEGER) = ?
                      )
                  )
                LIMIT 1
                """,
                (
                    engagement.id,
                    int(queue_row["id"]),
                    int(queue_row["file_id"]),
                    lease_token,
                    int(queue_row["repo_generation"]),
                    disposition,
                    int(queue_row["file_id"]),
                    int(queue_row["file_id"]),
                ),
            ).fetchone()
            if source_receipt is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "critical/high review requires a current source-level receipt "
                        "with a matching disposition, bound to this file and lease"
                    ),
                )
        # Skipped items bypass the cwe-coverage completeness check — by
        # definition the analyst did not analyze the file. Other dispositions
        # still enforce the existing coverage rule.
        if disposition != "skipped":
            _validate_completion_coverage(file_row, normalized_cwe_coverage)
        next_status = "done"
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = ?,
                disposition = ?,
                analysis_notes = ?,
                skip_reason = ?,
                cwe_coverage_json = ?,
                completed_at = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (next_status, disposition, notes, skip_reason, cwe_coverage_text, now, engagement.id,
             agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before completion; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        total_functions = _safe_int(file_row.get("total_functions", 0))
        integrity = _compute_coverage_integrity(
            connection,
            engagement.id,
            item_ids[0],
            int(queue_row["file_id"]),
            total_functions,
            normalized_cwe_coverage,
        )
        return {
            "updated": cursor.rowcount,
            "total": len(item_ids),
            "coverage_integrity": integrity,
        }


def error_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    notes: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="processing", action="mark as error")
        _require_queue_lease(queue_rows, agent_name=agent_name, lease_token=lease_token, action="mark as error")
        _require_queue_generation(connection, engagement.id, queue_rows, action="mark as error")
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'error',
                analysis_notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (notes, engagement.id, agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before error transition; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def needs_context_queue_items(
    engagement_id: int,
    item_ids: list[int],
    agent_name: str,
    lease_token: str,
    expansion_request: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"updated": 0, "total": 0}
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="processing", action="mark as needs_context")
        _require_queue_lease(
            queue_rows, agent_name=agent_name, lease_token=lease_token, action="mark as needs_context"
        )
        _require_queue_generation(
            connection, engagement.id, queue_rows, action="mark as needs_context"
        )
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'needs_context',
                expansion_request_json = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ? AND id IN ({placeholders})
            """,
            (_json_text(expansion_request), engagement.id, agent_name, lease_token, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before needs_context transition; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"updated": cursor.rowcount, "total": len(item_ids)}


def reset_stale_queue_items(
    engagement_id: int,
    minutes: int,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        # Serialize stale selection with heartbeat writers. The per-row CAS
        # below is defense in depth for connections whose transaction mode is
        # changed by an embedding caller.
        connection.execute("BEGIN IMMEDIATE")
        stale_rows = connection.execute(
            f"""
            SELECT queue.id, queue.file_id, queue.lease_token,
                   COALESCE(queue.last_heartbeat_at, queue.consumed_at, '') AS lease_activity_at
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE queue.engagement_id = ?
              AND queue.status = 'processing'
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND ({_latest_current_queue_attempt_sql("queue", "repos")})
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              AND (COALESCE(queue.last_heartbeat_at, queue.consumed_at) IS NULL
                   OR datetime(COALESCE(queue.last_heartbeat_at, queue.consumed_at))
                      < datetime('now', ? || ' minutes'))
            """,
            (engagement.id, f"-{minutes}"),
        ).fetchall()
        reset_count = 0
        for row in stale_rows:
            cursor = connection.execute(
                """
                UPDATE code_analysis_queue
                SET status = 'pending', assigned_agent = '', lease_token = '',
                    consumed_at = NULL, last_heartbeat_at = NULL,
                    priority = CASE
                        WHEN queue_mode = ? THEN priority
                        ELSE COALESCE((
                            SELECT files.analysis_priority
                            FROM code_files AS files
                            WHERE files.engagement_id = code_analysis_queue.engagement_id
                              AND files.id = code_analysis_queue.file_id
                        ), priority)
                    END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE engagement_id = ? AND id = ? AND status = 'processing'
                  AND lease_token = ?
                  AND COALESCE(last_heartbeat_at, consumed_at, '') = ?
                """,
                (
                    _METADATA_REFRESH_REVIEW_MODE,
                    engagement.id,
                    int(row["id"]),
                    str(row["lease_token"] or ""),
                    str(row["lease_activity_at"] or ""),
                ),
            )
            if cursor.rowcount != 1:
                continue
            reset_count += 1
            connection.execute(
                """
                UPDATE code_analysis_results SET superseded_at = ?
                WHERE queue_item_id = ? AND lease_token = ? AND superseded_at IS NULL
                """,
                (_now_iso(), int(row["id"]), str(row["lease_token"] or "")),
            )
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"reset": reset_count}


def heartbeat_queue_item(
    engagement_id: int, *, item_id: int, agent_name: str, lease_token: str
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    now = _now_iso()
    with get_connection() as connection:
        queue_rows = _get_queue_rows(connection, engagement.id, {item_id})
        _require_queue_generation(connection, engagement.id, queue_rows, action="heartbeat")
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET last_heartbeat_at = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
            """,
            (now, engagement.id, item_id, agent_name, lease_token),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot heartbeat: queue lease is no longer owned by this agent",
            )
    return {"item_id": item_id, "last_heartbeat_at": now}


def retry_error_queue_items(
    engagement_id: int,
    item_ids: list[int],
    reason: str = "",
) -> dict[str, Any]:
    """C5.1: recover queue items stuck at status='error' back to 'pending'.

    `reset_stale_queue_items` only recovers abandoned 'processing' rows on a
    time window; an 'error' row has no recovery path at all today — a stuck
    error item is a permanently un-analyzed source file (silent coverage
    loss). Id-scoped like `error_queue_items` (not time-windowed): every id
    must currently be 'error' via `_require_queue_status`, so a caller cannot
    silently no-op on the wrong status. `reason` is appended to the existing
    `analysis_notes` as an audit breadcrumb rather than overwriting prior
    notes from the failed run.
    """
    engagement = _engagement_or_404(engagement_id)
    if not item_ids:
        return {"retried": 0, "total": 0, "item_ids": []}
    # Dedupe (preserving order) so `retry-error 5,5` does not fail its own
    # rowcount==len(item_ids) check — `id IN (5,5)` updates one row while len is 2.
    item_ids = list(dict.fromkeys(item_ids))
    reason_text = (reason or "").strip()
    note_suffix = f"\n[retried: {reason_text}]" if reason_text else "\n[retried]"
    placeholders = ",".join("?" for _ in item_ids)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="error", action="retry")
        _require_queue_generation(connection, engagement.id, queue_rows, action="retry")
        for row in queue_rows.values():
            connection.execute(
                """
                UPDATE code_analysis_results SET superseded_at = ?
                WHERE queue_item_id = ? AND lease_token = ? AND superseded_at IS NULL
                """,
                (_now_iso(), int(row["id"]), str(row.get("lease_token", ""))),
            )
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'pending',
                assigned_agent = '',
                lease_token = '',
                consumed_at = NULL,
                last_heartbeat_at = NULL,
                priority = CASE
                    WHEN queue_mode = ? THEN priority
                    ELSE COALESCE((
                        SELECT files.analysis_priority
                        FROM code_files AS files
                        WHERE files.engagement_id = code_analysis_queue.engagement_id
                          AND files.id = code_analysis_queue.file_id
                    ), priority)
                END,
                analysis_notes = analysis_notes || ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'error' AND id IN ({placeholders})
            """,
            (_METADATA_REFRESH_REVIEW_MODE, note_suffix, engagement.id, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before retry; refetch and retry",
            )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
        return {"retried": cursor.rowcount, "total": len(item_ids), "item_ids": sorted(item_ids)}


def retry_needs_context_queue_items(
    engagement_id: int, item_ids: list[int], reason: str
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    item_ids = list(dict.fromkeys(item_ids))
    placeholders = ",".join("?" for _ in item_ids)
    note_suffix = f"\n[context supplied: {reason.strip()}]"
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        queue_rows = _get_queue_rows(connection, engagement.id, set(item_ids))
        _require_queue_status(queue_rows, expected_status="needs_context", action="retry")
        _require_queue_generation(connection, engagement.id, queue_rows, action="retry")
        cursor = connection.execute(
            f"""
            UPDATE code_analysis_queue
            SET status = 'pending', assigned_agent = '', lease_token = '',
                consumed_at = NULL, last_heartbeat_at = NULL,
                priority = CASE
                    WHEN queue_mode = ? THEN priority
                    ELSE COALESCE((
                        SELECT files.analysis_priority
                        FROM code_files AS files
                        WHERE files.engagement_id = code_analysis_queue.engagement_id
                          AND files.id = code_analysis_queue.file_id
                    ), priority)
                END,
                analysis_notes = analysis_notes || ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = 'needs_context' AND id IN ({placeholders})
            """,
            (_METADATA_REFRESH_REVIEW_MODE, note_suffix, engagement.id, *item_ids),
        )
        if cursor.rowcount != len(item_ids):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue items changed state before needs-context retry; refetch and retry",
            )
        connection.execute(
            f"""
            UPDATE code_analysis_results SET superseded_at = ?
            WHERE engagement_id = ? AND superseded_at IS NULL
              AND queue_item_id IN ({placeholders})
            """,
            (_now_iso(), engagement.id, *item_ids),
        )
        for row in queue_rows.values():
            _sync_file_analysis_status(connection, engagement.id, int(row["file_id"]))
            _sync_trigger_status_for_file(connection, engagement.id, int(row["file_id"]))
    return {"retried": len(item_ids), "total": len(item_ids), "item_ids": sorted(item_ids)}


# =========================================================================
# Analysis Results
# =========================================================================

def _require_promoted_run_candidate_for_finding_result(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    file_row: dict[str, Any],
    finding_slug: str | None,
) -> sqlite3.Row:
    repository = connection.execute(
        """
        SELECT repo_key, active_generation, source_manifest_digest
        FROM code_repos WHERE engagement_id = ? AND id = ?
        """,
        (engagement_id, int(file_row["repo_id"])),
    ).fetchone()
    assert repository is not None
    rows = connection.execute(
        """
        SELECT candidates.id, runs.source_generations_json,
               sources.target_key, sources.path, sources.content_sha256
        FROM assessment_run_candidates AS candidates
        JOIN assessment_runs AS runs ON runs.id = candidates.run_id
        JOIN assessment_run_sources AS sources ON sources.id = candidates.source_id
        WHERE candidates.engagement_id = ?
          AND candidates.state = 'promoted'
          AND candidates.finding_slug = ?
          AND runs.run_kind = 'code' AND runs.run_purpose = 'scan'
          AND runs.status IN ('queued', 'running')
          AND sources.path = ? AND sources.content_sha256 = ?
          AND sources.target_key = ?
        ORDER BY candidates.id
        """,
        (
            engagement_id,
            str(finding_slug or ""),
            str(file_row["file_path"]),
            str(file_row["file_hash"]),
            str(repository["repo_key"]),
        ),
    ).fetchall()
    exact_ids: list[int] = []
    for row in rows:
        generation_matches = [
            generation
            for generation in json.loads(str(row["source_generations_json"] or "[]"))
            if isinstance(generation, dict)
            and str(generation.get("target_key") or "")
            == str(repository["repo_key"])
        ]
        if len(generation_matches) != 1:
            continue
        generation = generation_matches[0]
        if (
            int(generation.get("generation", -1))
            == int(repository["active_generation"])
            and str(generation.get("manifest_digest") or "")
            == str(repository["source_manifest_digest"])
        ):
            exact_ids.append(int(row["id"]))
    if len(exact_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "finding analysis in an active code scan requires exactly one "
                "promoted candidate bound to the current file and repository generation"
            ),
        )
    candidate = connection.execute(
        "SELECT * FROM assessment_run_candidates WHERE id = ?",
        (exact_ids[0],),
    ).fetchone()
    assert candidate is not None
    return candidate

def create_analysis_result(
    engagement_id: int,
    result: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if "function_name" in result:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "function_name is historical read/filter data and is not accepted "
                "for new grouped source receipts"
            ),
        )
    disposition = str(result.get("disposition", "")).strip()
    if disposition not in _VALID_ANALYSIS_RESULT_DISPOSITIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Invalid disposition '{disposition}'. Must be one of: "
                f"{', '.join(sorted(_VALID_ANALYSIS_RESULT_DISPOSITIONS))}"
            ),
        )
    assessment_run_id = result.get("assessment_run_id")
    assessment_source_id = result.get("assessment_source_id")
    if (assessment_run_id is None) != (assessment_source_id is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "assessment_run_id and assessment_source_id must be supplied together"
            ),
        )
    if assessment_run_id is not None and disposition != "suspicious":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="run candidate binding is only valid for suspicious analysis results",
        )
    with get_connection() as connection:
        queue_item_id = result.get("queue_item_id")
        if queue_item_id is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="queue_item_id is required; analysis results must be tied to a claimed queue item",
            )
        queue_row = _get_queue_rows(connection, engagement.id, {int(queue_item_id)})[
            int(queue_item_id)
        ]
        queue_file_id = int(queue_row["file_id"])
        payload_file_id = result.get("file_id")
        if payload_file_id is not None and int(payload_file_id) != queue_file_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Analysis result file_id does not match the queue item",
            )
        file_row = _get_file_rows(connection, engagement.id, {queue_file_id})[queue_file_id]
        normalized_cross_file_triggers = _normalize_cross_file_triggers(result.get("cross_file_triggers"))
        agent_name = str(result.get("agent_name", ""))
        lease_token = str(result.get("lease_token", ""))

        _require_queue_status(
            {int(queue_item_id): queue_row},
            expected_status="processing",
            action="record analysis results for",
        )
        _require_queue_lease(
            {int(queue_item_id): queue_row},
            agent_name=agent_name,
            lease_token=lease_token,
            action="record analysis results",
        )
        _require_queue_generation(
            connection,
            engagement.id,
            {int(queue_item_id): queue_row},
            action="record analysis results",
        )
        receipt_kind = str(result.get("receipt_kind") or "file")
        has_source_anchors = bool(
            result.get("callable_refs") or result.get("reviewed_spans")
        )
        if disposition == "skipped" and not has_source_anchors:
            canonical_callable_refs: list[dict[str, Any]] = []
            callable_ids: list[int] = []
            canonical_reviewed_spans: list[dict[str, Any]] = []
            receipt_binding_status = "skipped_unbound"
        else:
            (
                canonical_callable_refs,
                callable_ids,
                canonical_reviewed_spans,
                receipt_binding_status,
            ) = _normalize_analysis_receipt_anchors(
                connection,
                engagement_id=engagement.id,
                queue_row=queue_row,
                queue_file=file_row,
                receipt_kind=receipt_kind,
                callable_refs=result.get("callable_refs", []),
                reviewed_spans=result.get("reviewed_spans", []),
            )
        active_scan = connection.execute(
            """
            SELECT id FROM assessment_runs
            WHERE engagement_id = ? AND run_kind = 'code'
              AND run_purpose = 'scan' AND status IN ('queued', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (engagement.id,),
        ).fetchone()
        if (
            disposition == "suspicious"
            and active_scan is not None
            and assessment_run_id is None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "suspicious analysis in an active code scan requires exact "
                    "assessment_run_id and assessment_source_id candidate binding"
                ),
            )
        finding_run_candidate = None
        if disposition == "finding":
            _require_current_reportable_root_file_finding(
                connection,
                engagement.id,
                file_row,
                result.get("finding_slug"),
            )
            if active_scan is not None:
                finding_run_candidate = (
                    _require_promoted_run_candidate_for_finding_result(
                        connection,
                        engagement_id=engagement.id,
                        file_row=file_row,
                        finding_slug=result.get("finding_slug"),
                    )
                )
        fingerprint_payload = {
            key: value
            for key, value in result.items()
            if key not in {"audit_metadata"}
        }
        fingerprint_payload["file_id"] = int(file_row["id"])
        fingerprint_payload["cross_file_triggers"] = normalized_cross_file_triggers
        fingerprint_payload["receipt_kind"] = receipt_kind
        fingerprint_payload["callable_refs"] = canonical_callable_refs
        fingerprint_payload["reviewed_spans"] = canonical_reviewed_spans
        result_fingerprint = hashlib.sha256(
            _json_text(fingerprint_payload).encode("utf-8")
        ).hexdigest()
        run_candidate_context: dict[str, Any] | None = None
        run_candidate_identity = ""
        if assessment_run_id is not None:
            repo = connection.execute(
                """
                SELECT repo_key, active_generation, source_manifest_digest
                FROM code_repos WHERE engagement_id = ? AND id = ?
                """,
                (engagement.id, int(file_row["repo_id"])),
            ).fetchone()
            assert repo is not None
            if canonical_callable_refs:
                primary_anchor = next(
                    (
                        ref
                        for ref in canonical_callable_refs
                        if int(ref["file_id"]) == int(file_row["id"])
                    ),
                    canonical_callable_refs[0],
                )
                source_anchor = (
                    f"{primary_anchor['file_path']}:{primary_anchor['start_line']}-"
                    f"{primary_anchor['end_line']}:{primary_anchor['qualified_name']}"
                )
            elif canonical_reviewed_spans:
                primary_span = next(
                    (
                        span
                        for span in canonical_reviewed_spans
                        if int(span["file_id"]) == int(file_row["id"])
                    ),
                    canonical_reviewed_spans[0],
                )
                source_anchor = (
                    f"{primary_span['file_path']}:{primary_span['start_line']}-"
                    f"{primary_span['end_line']}"
                )
            else:
                source_anchor = f"{file_row['file_path']}:(skipped)"
            # Keep exact queue/run/lease ids in the result provenance, but not in
            # the identity used to compare the same candidate across later scans.
            candidate_fingerprint_payload = {
                key: value
                for key, value in result.items()
                if key
                not in {
                    "audit_metadata",
                    "queue_item_id",
                    "file_id",
                    "agent_name",
                    "lease_token",
                    "assessment_run_id",
                    "assessment_source_id",
                }
            }
            candidate_fingerprint_payload["cross_file_triggers"] = (
                normalized_cross_file_triggers
            )
            candidate_fingerprint_payload["receipt_kind"] = receipt_kind
            candidate_fingerprint_payload["callable_refs"] = canonical_callable_refs
            candidate_fingerprint_payload["reviewed_spans"] = canonical_reviewed_spans
            result_identity_fingerprint = hashlib.sha256(
                _json_text(candidate_fingerprint_payload).encode("utf-8")
            ).hexdigest()
            run_candidate_context = {
                "engagement_id": engagement.id,
                "run_id": int(assessment_run_id),
                "source_id": int(assessment_source_id),
                "result_identity_fingerprint": result_identity_fingerprint,
                "dispatch_agent_id": agent_name,
                "target_key": str(repo["repo_key"]),
                "source_path": str(file_row["file_path"]),
                "source_sha256": str(file_row["file_hash"]),
                "repo_generation": int(repo["active_generation"]),
                "source_manifest_digest": str(repo["source_manifest_digest"]),
                "source_anchor": source_anchor,
                "vulnerability_family": str(
                    result.get("cwe_id") or result.get("slot_type") or "unclassified"
                ),
                "hypothesis": str(
                    result.get("hypothesis") or "suspicious analysis result"
                ),
            }
            run_candidate_identity = run_accounting._analysis_result_candidate_identity(
                target_key=str(run_candidate_context["target_key"]),
                source_path=str(run_candidate_context["source_path"]),
                source_sha256=str(run_candidate_context["source_sha256"]),
                source_anchor=str(run_candidate_context["source_anchor"]),
                result_identity_fingerprint=result_identity_fingerprint,
            )
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET updated_at = updated_at
            WHERE engagement_id = ? AND id = ? AND file_id = ? AND status = 'processing'
              AND assigned_agent = ? AND lease_token = ?
            """,
            (engagement.id, int(queue_item_id), int(file_row["id"]), agent_name, lease_token),
        )
        if cursor.rowcount != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="queue item changed state before recording analysis result; refetch and retry",
            )

        existing_result = connection.execute(
            """
            SELECT id FROM code_analysis_results
            WHERE engagement_id = ? AND queue_item_id = ? AND lease_token = ?
              AND result_fingerprint = ?
            """,
            (engagement.id, int(queue_item_id), lease_token, result_fingerprint),
        ).fetchone()
        if existing_result is not None:
            row = _analysis_result_row(connection, int(existing_result["id"]))
            assert row is not None
            hydrated = _hydrate_code_analysis_result(row)
            if assessment_run_id is not None:
                candidate = connection.execute(
                    """
                    SELECT * FROM assessment_run_candidates
                    WHERE engagement_id = ? AND run_id = ? AND originating_result_id = ?
                    """,
                    (engagement.id, int(assessment_run_id), int(row["id"])),
                ).fetchone()
                if candidate is None:
                    candidate = connection.execute(
                        """
                        SELECT * FROM assessment_run_candidates
                        WHERE engagement_id = ? AND run_id = ? AND identity_key = ?
                        """,
                        (engagement.id, int(assessment_run_id), run_candidate_identity),
                    ).fetchone()
                if candidate is None:
                    raise HTTPException(
                        status_code=409,
                        detail="analysis result retry is missing its atomic run candidate",
                    )
                hydrated["run_candidate"] = run_accounting._serialize_candidate(
                    candidate
                )
            elif finding_run_candidate is not None:
                hydrated["run_candidate"] = run_accounting._serialize_candidate(
                    finding_run_candidate
                )
            return hydrated

        supersedes = result.get("supersedes")
        if supersedes is not None:
            superseded_result = connection.execute(
                """
                SELECT original.*,
                       replacement.id AS replaced_by_result_id
                FROM code_analysis_results AS original
                LEFT JOIN code_analysis_results AS replacement
                  ON replacement.supersedes_result_id = original.id
                WHERE original.engagement_id = ? AND original.id = ?
                """,
                (engagement.id, int(supersedes)),
            ).fetchone()
            if superseded_result is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="supersedes analysis result was not found in this engagement",
                )
            if superseded_result["replaced_by_result_id"] is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result is already replaced",
                )
            if superseded_result["superseded_at"] is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result is not current for this source generation",
                )
            expected_identity = (
                int(queue_item_id),
                int(file_row["id"]),
                lease_token,
                int(queue_row.get("repo_generation", 0) or 0),
                receipt_kind,
                _json_list_text(canonical_callable_refs),
                _json_list_text(canonical_reviewed_spans),
            )
            actual_identity = (
                int(superseded_result["queue_item_id"]),
                int(superseded_result["file_id"]),
                str(superseded_result["lease_token"]),
                int(superseded_result["repo_generation"]),
                str(superseded_result["receipt_kind"]),
                str(superseded_result["callable_refs_json"]),
                str(superseded_result["reviewed_spans_json"]),
            )
            if actual_identity != expected_identity:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        "supersedes must identify a current result with the same "
                        "queue item, lease token, file, source anchors, and repository generation"
                    ),
                )

        try:
            cursor = connection.execute(
                """
            INSERT INTO code_analysis_results (
                engagement_id, queue_item_id, file_id,
                agent_name, receipt_kind, callable_refs_json, reviewed_spans_json,
                receipt_binding_status, hypothesis, evidence, evidence_ref,
                disposition, confidence, finding_slug, cwe_id,
                slot_type, notes, audit_metadata_json,
                cwe_coverage_json, cross_file_triggers_json,
                lease_token, repo_generation, result_fingerprint,
                supersedes_result_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    engagement.id,
                    queue_item_id,
                    int(file_row["id"]),
                    agent_name,
                    receipt_kind,
                    _json_list_text(canonical_callable_refs),
                    _json_list_text(canonical_reviewed_spans),
                    receipt_binding_status,
                    result.get("hypothesis", ""),
                    result.get("evidence", ""),
                    result.get("evidence_ref", ""),
                    disposition,
                    result.get("confidence", "medium"),
                    result.get("finding_slug", ""),
                    result.get("cwe_id", ""),
                    result.get("slot_type", ""),
                    result.get("notes", ""),
                    _json_text(result.get("audit_metadata")),
                    _json_list_text(result.get("cwe_coverage")),
                    _json_list_text(normalized_cross_file_triggers),
                    lease_token,
                    int(queue_row.get("repo_generation", 0) or 0),
                    result_fingerprint,
                    supersedes,
                ),
            )
        except sqlite3.IntegrityError as exc:
            if supersedes is not None:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="supersedes analysis result was concurrently replaced",
                ) from exc
            raise
        for ordinal, callable_id in enumerate(callable_ids):
            connection.execute(
                """
                INSERT INTO code_analysis_result_callables (
                    result_id, callable_id, file_id, ordinal
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    int(cursor.lastrowid),
                    callable_id,
                    int(canonical_callable_refs[ordinal]["file_id"]),
                    ordinal,
                ),
            )
        row = _analysis_result_row(connection, int(cursor.lastrowid))
        assert row is not None
        run_candidate = None
        if assessment_run_id is not None:
            assert run_candidate_context is not None
            run_candidate = run_accounting.record_analysis_result_candidate_with_connection(
                connection,
                result_id=int(row["id"]),
                **run_candidate_context,
            )
        _record_cross_file_triggers(
            connection,
            engagement.id,
            source_queue_item_id=int(queue_item_id),
            source_file_id=int(file_row["id"]),
            cross_file_triggers=normalized_cross_file_triggers,
        )
        _sync_file_analysis_status(connection, engagement.id, int(file_row["id"]))
        hydrated = _hydrate_code_analysis_result(row)
        if run_candidate is not None:
            hydrated["run_candidate"] = run_candidate
        elif finding_run_candidate is not None:
            hydrated["run_candidate"] = run_accounting._serialize_candidate(
                finding_run_candidate
            )
        return hydrated


def list_analysis_results(
    engagement_id: int,
    *,
    file_id: int | None = None,
    queue_item_id: int | None = None,
    lease_token: str | None = None,
    function_name: str | None = None,
    disposition: str | None = None,
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    clauses = ["results.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if file_id is not None:
        clauses.append("results.file_id = ?")
        params.append(file_id)
    if queue_item_id is not None:
        clauses.append("results.queue_item_id = ?")
        params.append(queue_item_id)
    if lease_token is not None:
        clauses.append("results.lease_token = ?")
        params.append(lease_token)
    if function_name is not None:
        clauses.append("results.function_name = ?")
        params.append(function_name)
    if disposition is not None:
        clauses.append("results.disposition = ?")
        params.append(disposition)
    if not include_superseded:
        clauses.append(
            "(" + _current_result_receipt_sql(
                "results",
                "result_queue",
                "files",
                "repos",
                allow_processing=True,
            ) + ")"
        )
    queue_join = "LEFT JOIN" if include_superseded else "JOIN"
    generation_file_join = ""
    file_path_projection = "files.file_path"
    if include_superseded:
        generation_file_join = """
        LEFT JOIN code_source_generation_files AS generation_files
          ON generation_files.engagement_id = results.engagement_id
         AND generation_files.repo_id = files.repo_id
         AND generation_files.repo_generation = results.repo_generation
         AND generation_files.file_id = results.file_id
        """
        file_path_projection = "COALESCE(generation_files.file_path, files.file_path)"
    query = f"""
        SELECT
            results.*,
            findings.status AS finding_workflow_status,
            findings.verification_status AS finding_verification_status,
            {file_path_projection} AS file_path,
            (
                SELECT replacement.id
                FROM code_analysis_results AS replacement
                WHERE replacement.supersedes_result_id = results.id
            ) AS replaced_by_result_id
        FROM code_analysis_results AS results
        LEFT JOIN assessment_findings AS findings
          ON findings.engagement_id = results.engagement_id
         AND findings.slug = results.finding_slug
        {queue_join} code_analysis_queue AS result_queue
          ON result_queue.id = results.queue_item_id
         AND result_queue.engagement_id = results.engagement_id
        JOIN code_files AS files
          ON files.id = results.file_id
         AND files.engagement_id = results.engagement_id
        {generation_file_join}
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE {' AND '.join(clauses)}
        ORDER BY results.id DESC
    """
    with get_connection() as connection:
        return [_hydrate_code_analysis_result(row) for row in connection.execute(query, tuple(params)).fetchall()]


# =========================================================================
# Variant-check receipts
# =========================================================================


def _current_variant_parent_rows_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
    *,
    report_durable_only: bool,
) -> dict[int, list[Any]]:
    reportable_statuses = sorted(_REPORTABLE_FINDING_STATUSES)
    status_placeholders = ",".join("?" for _ in reportable_statuses)
    lifecycle_clause = (
        "AND findings.verification_status IN ('confirmed', 'downgraded')"
        if report_durable_only
        else (
            "AND COALESCE(findings.verification_status, 'unreviewed') "
            "NOT IN ('blocked', 'false_positive')"
        )
    )
    rows = connection.execute(
        f"""
        SELECT findings.*
        FROM assessment_findings AS findings
        WHERE findings.engagement_id = ?
          AND findings.status IN ({status_placeholders})
          {lifecycle_clause}
          AND NOT EXISTS (
              SELECT 1
              FROM assessment_finding_links AS links
              WHERE links.engagement_id = findings.engagement_id
                AND links.finding_id = findings.id
                AND links.link_kind = 'variant_of'
                AND links.retired_at IS NULL
          )
        ORDER BY findings.slug
        """,
        (engagement_id, *reportable_statuses),
    ).fetchall()
    repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    eligible: dict[int, list[Any]] = {repo_id: [] for repo_id in repo_ids}
    for row in rows:
        repo_id = _finding_snapshot_repo_id(row)
        if (
            not is_file_finding(str(row["canonical_location"] or ""))
            or repo_id not in repo_ids
            or finding_code_snapshot_status(
                connection,
                engagement_id,
                row,
                repo_states=repo_states,
            )
            != "current"
        ):
            continue
        assert repo_id is not None
        eligible[repo_id].append(row)
    return eligible


def _current_phase2_variant_parent_slugs_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
) -> dict[int, list[str]]:
    return {
        repo_id: [str(row["slug"]) for row in rows]
        for repo_id, rows in _current_variant_parent_rows_by_repo(
            connection,
            engagement_id,
            repo_ids,
            report_durable_only=False,
        ).items()
    }


def _current_report_durable_variant_parent_slugs_by_repo(
    connection,
    engagement_id: int,
    repo_ids: set[int],
) -> dict[int, list[str]]:
    return {
        repo_id: [str(row["slug"]) for row in rows]
        for repo_id, rows in _current_variant_parent_rows_by_repo(
            connection,
            engagement_id,
            repo_ids,
            report_durable_only=True,
        ).items()
    }


def _current_phase2_variant_parent_slugs(
    connection,
    engagement_id: int,
    repo_id: int,
) -> list[str]:
    return _current_phase2_variant_parent_slugs_by_repo(
        connection,
        engagement_id,
        {repo_id},
    )[repo_id]


def validate_variant_dispatch_parent_scope(
    connection,
    engagement_id: int,
    parent_finding_slugs: list[str],
) -> None:
    """Require receipt authority to freeze one repository's exact Phase 2 roots."""
    placeholders = ",".join("?" for _ in parent_finding_slugs)
    rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ? AND slug IN ({placeholders})
        """,
        (engagement_id, *parent_finding_slugs),
    ).fetchall()
    repo_ids = {_finding_snapshot_repo_id(row) for row in rows}
    if None in repo_ids or len(repo_ids) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "code-variant-hunter finding_slugs must equal the exact current "
                "Phase 2 root set for one repository"
            ),
        )
    repo_id = next(iter(repo_ids))
    assert repo_id is not None
    expected = _current_phase2_variant_parent_slugs(
        connection,
        engagement_id,
        repo_id,
    )
    if parent_finding_slugs != expected:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "code-variant-hunter finding_slugs must equal the exact current "
                "Phase 2 root set for one repository; expected "
                f"{expected}"
            ),
        )


@dataclass(frozen=True, slots=True)
class _VariantReceiptProjection:
    repos: dict[int, dict[str, Any]]
    files: dict[int, dict[str, Any]]
    latest_receipts: dict[int, dict[str, Any]]
    dispatch_scopes: dict[int, dict[str, Any]]
    parent_slugs: dict[int, list[str]]


_LATEST_CURRENT_VARIANT_RECEIPTS_SQL = """
    SELECT receipts.*,
           scopes.dispatch_id AS projection_scope_dispatch_id,
           scopes.parent_finding_slugs_json AS projection_scope_slugs_json,
           scopes.parent_finding_set_digest AS projection_scope_digest
    FROM code_files AS current_files
    JOIN code_repos AS current_repos
      ON current_repos.id = current_files.repo_id
     AND current_repos.engagement_id = current_files.engagement_id
     AND current_repos.active_generation > 0
    JOIN code_variant_check_receipts AS receipts
      ON receipts.id = (
          SELECT candidate.id
          FROM code_variant_check_receipts AS candidate
          WHERE candidate.engagement_id = ?
            AND candidate.current_file_id = current_files.id
          ORDER BY candidate.id DESC
          LIMIT 1
      )
    LEFT JOIN assessment_dispatches AS dispatches
      ON dispatches.id = receipts.dispatch_id
     AND dispatches.engagement_id = receipts.engagement_id
     AND dispatches.agent_role = ?
    LEFT JOIN code_variant_dispatch_scopes AS scopes
      ON scopes.dispatch_id = dispatches.id
     AND scopes.engagement_id = dispatches.engagement_id
    WHERE current_files.engagement_id = ?
      AND current_files.retired_at IS NULL
    ORDER BY current_files.id
"""


def _load_variant_receipt_projection(
    connection,
    engagement_id: int,
    *,
    repo_rows: list[dict[str, Any]],
    file_rows: list[dict[str, Any]],
    parent_slugs: dict[int, list[str]],
) -> _VariantReceiptProjection:
    latest_receipts: dict[int, dict[str, Any]] = {}
    dispatch_scopes: dict[int, dict[str, Any]] = {}
    for raw_row in connection.execute(
        _LATEST_CURRENT_VARIANT_RECEIPTS_SQL,
        (engagement_id, _VARIANT_DISPATCH_ROLE, engagement_id),
    ).fetchall():
        row = dict(raw_row)
        scope_dispatch_id = row.pop("projection_scope_dispatch_id")
        scope_slugs_json = row.pop("projection_scope_slugs_json")
        scope_digest = row.pop("projection_scope_digest")
        latest_receipts[int(row["current_file_id"])] = row
        if scope_dispatch_id is not None:
            dispatch_scopes[int(scope_dispatch_id)] = {
                "dispatch_id": int(scope_dispatch_id),
                "parent_finding_slugs_json": scope_slugs_json,
                "parent_finding_set_digest": scope_digest,
            }
    return _VariantReceiptProjection(
        repos={int(row["id"]): dict(row) for row in repo_rows},
        files={int(row["id"]): dict(row) for row in file_rows},
        latest_receipts=latest_receipts,
        dispatch_scopes=dispatch_scopes,
        parent_slugs=parent_slugs,
    )


def _validate_dispatch_variant_parent_slugs(
    connection,
    engagement_id: int,
    repo_id: int,
    parent_finding_slugs: list[str],
) -> None:
    if not parent_finding_slugs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check requires a non-empty parent finding scope",
        )
    placeholders = ",".join("?" for _ in parent_finding_slugs)
    rows = connection.execute(
        f"""
        SELECT *
        FROM assessment_findings
        WHERE engagement_id = ? AND slug IN ({placeholders})
        """,
        (engagement_id, *parent_finding_slugs),
    ).fetchall()
    if len(rows) != len(parent_finding_slugs):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="variant check dispatch references an unknown parent finding",
        )
    repo_states = load_code_repo_snapshot_states(connection, engagement_id)
    if any(
        not is_file_finding(str(row["canonical_location"] or ""))
        or _finding_snapshot_repo_id(row) != repo_id
        or finding_code_snapshot_status(
            connection,
            engagement_id,
            row,
            repo_states=repo_states,
        )
        != "current"
        for row in rows
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "variant check dispatch parent findings must be code findings bound "
                "to the current repository snapshot"
            ),
        )


def _variant_receipt_context(
    connection,
    engagement_id: int,
    file_id: int,
    *,
    parent_finding_slugs: list[str],
) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    file_row = _get_file_rows(connection, engagement_id, {file_id})[file_id]
    repo = _get_published_repo_row(connection, engagement_id, int(file_row["repo_id"]))
    finding_set_digest = _variant_parent_finding_set_digest(parent_finding_slugs)
    input_digest = variant_input_identity_digest(
        repo=repo,
        file_row=file_row,
        parent_finding_slugs=parent_finding_slugs,
    )
    return repo, file_row, finding_set_digest, input_digest


def _hydrate_variant_check_receipt(row: Any, *, current: bool) -> dict[str, Any]:
    payload = dict(row)
    payload["slot_types"] = _json_decode(payload.pop("slot_types_json", "[]"), [])
    payload["parent_finding_slugs"] = _json_decode(
        payload.pop("parent_finding_slugs_json", "[]"), []
    )
    payload["current"] = current
    return payload


def _variant_receipt_fingerprint(
    *,
    dispatch_id: int,
    current_file_id: int,
    variant_input_digest: str,
    status_value: str,
    evidence_ref: str,
    rationale: str,
) -> str:
    identity = {
        "dispatch_id": dispatch_id,
        "current_file_id": current_file_id,
        "variant_input_digest": variant_input_digest,
        "status": status_value,
        "evidence_ref": evidence_ref,
        "rationale": rationale,
    }
    return hashlib.sha256(_json_text(identity).encode("utf-8")).hexdigest()


def _variant_receipt_is_current(
    connection,
    engagement_id: int,
    receipt: Any,
    *,
    parent_finding_cache: dict[int, list[str]] | None = None,
    projection: _VariantReceiptProjection | None = None,
) -> bool:
    row = dict(receipt)
    file_id = row.get("current_file_id")
    if file_id is None:
        return False
    covered_parent_slugs = _json_decode(
        row.get("parent_finding_slugs_json"), []
    )
    dispatch_scope = (
        projection.dispatch_scopes.get(int(row["dispatch_id"]))
        if projection is not None
        else connection.execute(
            """
            SELECT scopes.parent_finding_slugs_json, scopes.parent_finding_set_digest
            FROM code_variant_dispatch_scopes AS scopes
            JOIN assessment_dispatches AS dispatches
              ON dispatches.id = scopes.dispatch_id
             AND dispatches.engagement_id = scopes.engagement_id
            WHERE scopes.engagement_id = ? AND scopes.dispatch_id = ?
              AND dispatches.agent_role = ?
            """,
            (engagement_id, int(row["dispatch_id"]), _VARIANT_DISPATCH_ROLE),
        ).fetchone()
    )
    if dispatch_scope is None:
        return False
    scope_parent_slugs = _json_decode(
        dispatch_scope["parent_finding_slugs_json"], []
    )
    if (
        scope_parent_slugs != covered_parent_slugs
        or str(dispatch_scope["parent_finding_set_digest"] or "")
        != _variant_parent_finding_set_digest(scope_parent_slugs)
    ):
        return False
    latest_id = (
        int(projection.latest_receipts.get(int(file_id), {}).get("id", 0) or 0)
        if projection is not None
        else int(
            (
                connection.execute(
                    """
                    SELECT MAX(id)
                    FROM code_variant_check_receipts
                    WHERE engagement_id = ? AND repo_id = ? AND current_file_id = ?
                    """,
                    (engagement_id, int(row["repo_id"]), int(file_id)),
                ).fetchone()
                or (0,)
            )[0]
            or 0
        )
    )
    if latest_id != int(row["id"]):
        return False
    file_row = (
        projection.files.get(int(file_id))
        if projection is not None
        else connection.execute(
            """
            SELECT files.*
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE files.engagement_id = ? AND files.id = ?
              AND files.retired_at IS NULL
            """,
            (engagement_id, int(file_id)),
        ).fetchone()
    )
    if file_row is None or int(file_row["repo_id"]) != int(row["repo_id"]):
        return False
    repo = (
        projection.repos.get(int(row["repo_id"]))
        if projection is not None
        else _get_published_repo_row(connection, engagement_id, int(row["repo_id"]))
    )
    if repo is None:
        return False
    cache = parent_finding_cache if parent_finding_cache is not None else {}
    current_parent_slugs = (
        projection.parent_slugs.get(int(row["repo_id"]))
        if projection is not None
        else cache.get(int(row["repo_id"]))
    )
    if current_parent_slugs is None:
        current_parent_slugs = _current_phase2_variant_parent_slugs(
            connection,
            engagement_id,
            int(row["repo_id"]),
        )
        cache[int(row["repo_id"])] = current_parent_slugs
    current_slots = sorted(set(_json_decode(file_row["slot_types_json"], [])))
    receipt_slots = sorted(set(_json_decode(row.get("slot_types_json"), [])))
    expected_input_digest = variant_input_identity_digest(
        repo=dict(repo),
        file_row=dict(file_row),
        parent_finding_slugs=covered_parent_slugs,
    )
    expected_fingerprint = _variant_receipt_fingerprint(
        dispatch_id=int(row["dispatch_id"]),
        current_file_id=int(file_id),
        variant_input_digest=str(row.get("variant_input_digest", "")),
        status_value=str(row.get("status", "")),
        evidence_ref=str(row.get("evidence_ref", "")),
        rationale=str(row.get("rationale", "")),
    )
    return (
        str(row.get("status", "")) == "completed"
        and int(row.get("repo_generation", 0) or 0)
        == int(repo.get("active_generation", 0) or 0)
        and str(row.get("source_manifest_digest", "") or "")
        == str(repo.get("source_manifest_digest", "") or "")
        and str(row.get("file_path", "") or "")
        == str(file_row["file_path"] or "")
        and str(row.get("file_sha256", "") or "")
        == str(file_row["file_hash"] or "")
        and str(row.get("language", "") or "")
        == _normalized_variant_language(file_row["language"])
        and str(row.get("classification", "") or "")
        == str(file_row["classification"] or "").strip().lower()
        and str(row.get("role", "") or "") == str(file_row["role"] or "").strip()
        and receipt_slots == current_slots
        and set(current_parent_slugs).issubset(set(covered_parent_slugs))
        and str(row.get("parent_finding_set_digest", ""))
        == _variant_parent_finding_set_digest(covered_parent_slugs)
        and str(row.get("variant_input_digest", "")) == expected_input_digest
        and str(row.get("receipt_fingerprint", "")) == expected_fingerprint
    )


def _current_variant_check_status(
    connection,
    engagement_id: int,
    file_row: dict[str, Any],
    *,
    parent_finding_cache: dict[int, list[str]] | None = None,
    require_done_projection: bool = True,
    projection: _VariantReceiptProjection | None = None,
) -> str:
    if require_done_projection and str(file_row.get("variant_check_status", "")) != "done":
        return "pending"
    receipt = (
        projection.latest_receipts.get(int(file_row["id"]))
        if projection is not None
        else connection.execute(
            """
            SELECT *
            FROM code_variant_check_receipts
            WHERE engagement_id = ? AND repo_id = ? AND current_file_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (engagement_id, int(file_row["repo_id"]), int(file_row["id"])),
        ).fetchone()
    )
    if receipt is None:
        return "pending"
    return "done" if _variant_receipt_is_current(
        connection,
        engagement_id,
        receipt,
        parent_finding_cache=parent_finding_cache,
        projection=projection,
    ) else "pending"


def record_variant_check_receipt(
    engagement_id: int,
    *,
    dispatch_id: int,
    file_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    file_sha256: str,
    parent_finding_slugs: list[str],
    status_value: str,
    evidence_ref: str,
    rationale: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    if not parent_finding_slugs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="variant check requires a non-empty parent_finding_slugs scope",
        )
    if (
        len(parent_finding_slugs) > MAX_VARIANT_PARENT_FINDINGS
        or parent_finding_slugs != sorted(set(parent_finding_slugs))
        or any(
            not isinstance(slug, str)
            or not slug
            or slug != slug.strip()
            or len(slug) > 256
            for slug in parent_finding_slugs
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "variant check parent_finding_slugs must be canonical, sorted, unique, "
                f"and contain at most {MAX_VARIANT_PARENT_FINDINGS} entries"
            ),
        )
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        dispatch = connection.execute(
            """
            SELECT dispatches.*, scopes.parent_finding_slugs_json AS scope_slugs_json,
                   scopes.parent_finding_set_digest AS scope_finding_set_digest
            FROM assessment_dispatches AS dispatches
            LEFT JOIN code_variant_dispatch_scopes AS scopes
              ON scopes.dispatch_id = dispatches.id
             AND scopes.engagement_id = dispatches.engagement_id
            WHERE dispatches.engagement_id = ? AND dispatches.id = ?
            """,
            (engagement.id, dispatch_id),
        ).fetchone()
        if (
            dispatch is None
            or str(dispatch["agent_role"] or "") != _VARIANT_DISPATCH_ROLE
            or str(dispatch["status"] or "") not in {"in-progress", "completed"}
            or dispatch["scope_slugs_json"] is None
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "variant check receipt requires a dispatch in this engagement "
                    f"with role={_VARIANT_DISPATCH_ROLE}, active/completed status, "
                    "and an immutable start-time scope"
                ),
            )
        dispatch_parent_slugs = sorted(
            set(_json_decode(dispatch["scope_slugs_json"], []))
        )
        if str(dispatch["scope_finding_set_digest"] or "") != (
            _variant_parent_finding_set_digest(dispatch_parent_slugs)
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check dispatch scope failed its integrity digest",
            )
        if parent_finding_slugs != dispatch_parent_slugs:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "variant check parent_finding_slugs must exactly match the canonical "
                    "immutable start-time scope of the code-variant-hunter dispatch"
                ),
            )
        repo, file_row, finding_set_digest, input_digest = _variant_receipt_context(
            connection,
            engagement.id,
            file_id,
            parent_finding_slugs=parent_finding_slugs,
        )
        if int(repo["id"]) != repo_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check repository binding is stale",
            )
        if int(repo.get("active_generation", 0) or 0) != repo_generation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check repository generation is stale",
            )
        if str(repo.get("source_manifest_digest", "") or "") != source_manifest_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check source manifest digest is stale",
            )
        if str(file_row.get("file_hash", "") or "") != file_sha256:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="variant check file hash is stale",
            )
        _validate_dispatch_variant_parent_slugs(
            connection,
            engagement.id,
            repo_id,
            parent_finding_slugs,
        )
        if status_value != "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="variant check status must be completed",
            )
        normalized_evidence_ref = _normalize_variant_evidence_ref(
            engagement.engagement_root,
            evidence_ref,
        )
        normalized_rationale = rationale.strip()
        if not normalized_evidence_ref or not normalized_rationale:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="variant check evidence_ref and rationale must contain non-whitespace text",
            )
        fingerprint = _variant_receipt_fingerprint(
            dispatch_id=dispatch_id,
            current_file_id=file_id,
            variant_input_digest=input_digest,
            status_value=status_value,
            evidence_ref=normalized_evidence_ref,
            rationale=normalized_rationale,
        )
        connection.execute(
            """
            INSERT INTO code_variant_check_receipts (
                engagement_id, dispatch_id, dispatch_agent_id, dispatch_agent_role,
                current_file_id, repo_id,
                repo_generation, source_manifest_digest, file_path, file_sha256,
                language, classification, role, slot_types_json,
                parent_finding_slugs_json, parent_finding_set_digest,
                variant_input_digest, status, evidence_ref, rationale,
                receipt_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, receipt_fingerprint) DO NOTHING
            """,
            (
                engagement.id,
                dispatch_id,
                str(dispatch["agent_id"] or ""),
                str(dispatch["agent_role"] or ""),
                file_id,
                repo_id,
                repo_generation,
                source_manifest_digest,
                str(file_row["file_path"]),
                file_sha256,
                _normalized_variant_language(file_row.get("language", "")),
                str(file_row.get("classification", "") or "").strip().lower(),
                str(file_row.get("role", "") or "").strip(),
                _json_list_text(sorted(set(_json_decode(file_row.get("slot_types_json"), [])))),
                _json_list_text(parent_finding_slugs),
                finding_set_digest,
                input_digest,
                status_value,
                normalized_evidence_ref,
                normalized_rationale,
                fingerprint,
            ),
        )
        row = connection.execute(
            """
            SELECT * FROM code_variant_check_receipts
            WHERE engagement_id = ? AND receipt_fingerprint = ?
            """,
            (engagement.id, fingerprint),
        ).fetchone()
        assert row is not None
        returned_receipt_current = _variant_receipt_is_current(
            connection,
            engagement.id,
            row,
        )
        current_status = _current_variant_check_status(
            connection,
            engagement.id,
            file_row,
            require_done_projection=False,
        )
        connection.execute(
            """
            UPDATE code_files
            SET variant_check_status = ?, updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (current_status, engagement.id, file_id),
        )
        return _hydrate_variant_check_receipt(
            row,
            current=returned_receipt_current,
        )


def list_variant_check_receipts(
    engagement_id: int,
    *,
    file_id: int | None = None,
    repo_id: int | None = None,
    include_stale: bool = False,
    limit: int = DEFAULT_VARIANT_RECEIPT_PAGE,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if not 1 <= limit <= MAX_VARIANT_RECEIPT_PAGE or offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"variant receipt limit must be 1..{MAX_VARIANT_RECEIPT_PAGE} "
                "and offset must be nonnegative"
            ),
        )
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if file_id is not None:
        clauses.append("current_file_id = ?")
        params.append(file_id)
    if repo_id is not None:
        clauses.append("repo_id = ?")
        params.append(repo_id)
    with get_connection() as connection:
        query = f"""
            SELECT * FROM code_variant_check_receipts
            WHERE {' AND '.join(clauses)}
            ORDER BY id DESC
        """
        parent_finding_cache: dict[int, list[str]] = {}
        if include_stale:
            rows = connection.execute(
                query + " LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            return [
                _hydrate_variant_check_receipt(
                    row,
                    current=_variant_receipt_is_current(
                        connection,
                        engagement.id,
                        row,
                        parent_finding_cache=parent_finding_cache,
                    ),
                )
                for row in rows
            ]

        records: list[dict[str, Any]] = []
        current_seen = 0
        cursor = connection.execute(query, tuple(params))
        while len(records) < limit:
            rows = cursor.fetchmany(MAX_VARIANT_RECEIPT_PAGE)
            if not rows:
                break
            for row in rows:
                if not _variant_receipt_is_current(
                    connection,
                    engagement.id,
                    row,
                    parent_finding_cache=parent_finding_cache,
                ):
                    continue
                if current_seen < offset:
                    current_seen += 1
                    continue
                records.append(_hydrate_variant_check_receipt(row, current=True))
                if len(records) == limit:
                    break
        return records


def unresolved_suspicious_analysis_obligations(
    engagement_id: int,
) -> list[dict[str, int]]:
    """Return current-generation canonical suspicious attempt counts by repo."""
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        counts = _current_suspicious_analysis_counts(connection, engagement.id)
    return [
        {"repo_id": repo_id, "suspicious_count": suspicious_count}
        for repo_id, suspicious_count in sorted(counts.items())
    ]


def report_durable_finding_variant_receipt_obligations(
    engagement_id: int,
) -> list[dict[str, Any]]:
    """Return current variant-receipt gaps for report-durable code root findings.

    The receipt table is authoritative for completed per-file variant work, but
    Vigil does not yet own an immutable candidate ledger. Until it does, fail
    closed over every admitted file in the current repository inventory instead
    of letting a scheduling classification or an intel/prose artifact exclude a
    possible variant carrier.
    """
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        repo_rows = [
            dict(row)
            for row in connection.execute(
                """
                SELECT * FROM code_repos
                WHERE engagement_id = ? AND active_generation > 0
                ORDER BY id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        repo_ids = {int(row["id"]) for row in repo_rows}
        report_durable_by_repo = _current_report_durable_variant_parent_slugs_by_repo(
            connection,
            engagement.id,
            repo_ids,
        )
        if not any(report_durable_by_repo.values()):
            return []
        currency_parent_slugs_by_repo = (
            _current_phase2_variant_parent_slugs_by_repo(
                connection,
                engagement.id,
                repo_ids,
            )
        )
        inventory_files = [
            dict(row)
            for row in connection.execute(
                """
                SELECT files.*
                FROM code_files AS files
                JOIN code_repos AS repos
                  ON repos.id = files.repo_id
                 AND repos.engagement_id = files.engagement_id
                 AND repos.active_generation > 0
                WHERE files.engagement_id = ?
                  AND files.retired_at IS NULL
                ORDER BY files.repo_id, files.file_path, files.id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        files_by_repo: dict[int, list[dict[str, Any]]] = {}
        for file_row in inventory_files:
            files_by_repo.setdefault(int(file_row["repo_id"]), []).append(file_row)
        projection = _load_variant_receipt_projection(
            connection,
            engagement.id,
            repo_rows=repo_rows,
            file_rows=inventory_files,
            parent_slugs=currency_parent_slugs_by_repo,
        )
        obligations: list[dict[str, Any]] = []
        for repo_id, finding_slugs in sorted(report_durable_by_repo.items()):
            if not finding_slugs:
                continue
            repo_inventory = files_by_repo.get(repo_id, [])
            missing_files = [
                file_row
                for file_row in repo_inventory
                if _current_variant_check_status(
                    connection,
                    engagement.id,
                    file_row,
                    projection=projection,
                )
                != "done"
            ]
            if not missing_files:
                continue
            obligations.append(
                {
                    "repo_id": repo_id,
                    "finding_slugs": sorted(finding_slugs),
                    "missing_file_ids": [int(row["id"]) for row in missing_files],
                    "missing_file_paths": [
                        str(row["file_path"]) for row in missing_files
                    ],
                }
            )
        return obligations


# =========================================================================
# Threat Model
# =========================================================================

def record_threat_model(
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    threat_model: dict[str, Any],
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        repo = _get_published_repo_row(connection, engagement.id, repo_id)
        if int(repo.get("active_generation", 0) or 0) != repo_generation:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="threat model repository generation is stale",
            )
        if str(repo.get("source_manifest_digest", "") or "") != source_manifest_digest:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="threat model source manifest digest is stale",
            )
        connection.execute(
            """
            UPDATE code_repos
            SET threat_model_json = ?, threat_model_generation = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ?
            """,
            (_json_text(threat_model), repo_generation, engagement.id, repo_id),
        )
        row = connection.execute(
            "SELECT * FROM code_repos WHERE engagement_id = ? AND id = ?",
            (engagement.id, repo_id),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Code repo not found")
    return _hydrate_code_repo(row)


def get_threat_model(
    engagement_id: int,
    repo_id: int,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with get_connection() as connection:
        row = _get_published_repo_row(connection, engagement.id, repo_id)
    threat_model = _json_decode(row.get("threat_model_json"), {})
    threat_generation = row.get("threat_model_generation")
    active_generation = int(row.get("active_generation", 0) or 0)
    return {
        "repo_id": repo_id,
        "repo_generation": int(threat_generation) if threat_generation is not None else None,
        "active_generation": active_generation,
        "source_manifest_digest": str(row.get("source_manifest_digest", "") or ""),
        "current": threat_generation is not None and int(threat_generation) == active_generation,
        "threat_model": threat_model,
    }


# =========================================================================
# Coverage
# =========================================================================

def code_coverage_summary(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)

    repo_clause = (
        " AND repo_id IN (SELECT id FROM code_repos WHERE active_generation > 0)"
        " AND retired_at IS NULL"
    )
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = " AND repo_id = ? AND retired_at IS NULL"
        repo_params = (repo_id,)

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)

        # -- Total files --
        total_files = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ?{repo_clause}",
            (engagement.id, *repo_params),
        )

        # -- By classification --
        classification_rows = connection.execute(
            f"""
            SELECT files.classification,
                   COUNT(*) AS total,
                   SUM(CASE WHEN ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) THEN 1 ELSE 0 END) AS analyzed
            FROM code_files AS files
            WHERE files.engagement_id = ?{repo_clause}
            GROUP BY files.classification
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        by_classification: dict[str, dict[str, int]] = {}
        for row in classification_rows:
            by_classification[row["classification"]] = {
                "count": int(row["total"]),
                "analyzed": int(row["analyzed"]),
            }

        # -- By analysis status --
        status_rows = connection.execute(
            f"""
            SELECT current_analysis_status AS analysis_status, COUNT(*) AS total
            FROM (
                SELECT files.id,
                       CASE
                           WHEN ({_invalid_active_history_exists_sql("files")})
                           THEN 'in_progress'
                           WHEN EXISTS (
                               SELECT 1
                               FROM code_analysis_queue AS current_queue
                               JOIN code_repos AS current_queue_repo
                                 ON current_queue_repo.id = files.repo_id
                                AND current_queue_repo.engagement_id = files.engagement_id
                               WHERE current_queue.engagement_id = files.engagement_id
                                 AND current_queue.file_id = files.id
                                 AND current_queue.repo_generation = current_queue_repo.active_generation
                                 AND current_queue.source_superseded_at IS NULL
                                 AND ({_latest_current_queue_attempt_sql(
                                     "current_queue", "current_queue_repo"
                                 )})
                                 AND current_queue.status = 'needs_context'
                           ) THEN 'needs_context'
                           WHEN EXISTS (
                               SELECT 1
                               FROM code_analysis_queue AS current_queue
                               JOIN code_repos AS current_queue_repo
                                 ON current_queue_repo.id = files.repo_id
                                AND current_queue_repo.engagement_id = files.engagement_id
                               WHERE current_queue.engagement_id = files.engagement_id
                                 AND current_queue.file_id = files.id
                                 AND current_queue.repo_generation = current_queue_repo.active_generation
                                 AND current_queue.source_superseded_at IS NULL
                                 AND ({_latest_current_queue_attempt_sql(
                                     "current_queue", "current_queue_repo"
                                 )})
                                 AND current_queue.status IN ('processing', 'error')
                           ) THEN 'in_progress'
                           WHEN EXISTS (
                               SELECT 1
                               FROM code_analysis_queue AS current_queue
                               JOIN code_repos AS current_queue_repo
                                 ON current_queue_repo.id = files.repo_id
                                AND current_queue_repo.engagement_id = files.engagement_id
                               WHERE current_queue.engagement_id = files.engagement_id
                                 AND current_queue.file_id = files.id
                                 AND current_queue.repo_generation = current_queue_repo.active_generation
                                 AND current_queue.source_superseded_at IS NULL
                                 AND ({_latest_current_queue_attempt_sql(
                                     "current_queue", "current_queue_repo"
                                 )})
                                 AND current_queue.status = 'pending'
                           ) THEN 'queued'
                           WHEN ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) THEN 'analyzed'
                           WHEN files.classification != 'unclassified' THEN 'classified'
                           ELSE 'pending'
                       END AS current_analysis_status
                FROM code_files AS files
                WHERE files.engagement_id = ?{repo_clause}
            ) AS current_files
            GROUP BY current_analysis_status
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        by_status: dict[str, int] = {}
        for row in status_rows:
            by_status[row["analysis_status"]] = int(row["total"])

        # -- Findings summary (from assessment_findings where canonical_location starts with 'file:') --
        finding_rows = connection.execute(
            """
            SELECT f.*
            FROM assessment_findings AS f
            WHERE f.engagement_id = ?
              AND f.status NOT IN ('merged', 'false_positive')
            """,
            (engagement.id,),
        ).fetchall()
        repo_states = load_code_repo_snapshot_states(connection, engagement.id)
        current_findings = [
            row
            for row in finding_rows
            if is_file_finding(str(row["canonical_location"] or ""))
            and finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            == "current"
            and (repo_id is None or _finding_snapshot_repo_id(row) == repo_id)
        ]
        total_code_findings = len(current_findings)
        by_severity: dict[str, int] = {}
        for row in current_findings:
            severity = str(row["severity"])
            by_severity[severity] = by_severity.get(severity, 0) + 1

        variant_rows = connection.execute(
            """
            SELECT f.*
            FROM assessment_finding_links AS links
            JOIN assessment_findings AS f
              ON f.id = links.finding_id
             AND f.engagement_id = links.engagement_id
            WHERE f.engagement_id = ?
              AND links.link_kind = 'variant_of'
              AND f.status NOT IN ('merged', 'false_positive')
            """,
            (engagement.id,),
        ).fetchall()
        variant_count = sum(
            is_file_finding(str(row["canonical_location"] or ""))
            and finding_code_snapshot_status(
                connection,
                engagement.id,
                row,
                repo_states=repo_states,
            )
            == "current"
            and (repo_id is None or _finding_snapshot_repo_id(row) == repo_id)
            for row in variant_rows
        )

        # -- Confidence metrics --
        critical_total = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'critical'{repo_clause}",
            (engagement.id, *repo_params),
        )
        critical_analyzed = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*) FROM code_files AS files
            WHERE files.engagement_id = ? AND files.classification = 'critical'
              AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}){repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        high_total = _scalar_row(
            connection,
            f"SELECT COUNT(*) FROM code_files WHERE engagement_id = ? AND classification = 'high'{repo_clause}",
            (engagement.id, *repo_params),
        )
        high_analyzed = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*) FROM code_files AS files
            WHERE files.engagement_id = ? AND files.classification = 'high'
              AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}){repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        overall_loc_analyzed = _scalar_row(
            connection,
            f"""
            SELECT COALESCE(SUM(files.loc), 0) FROM code_files AS files
            WHERE files.engagement_id = ?
              AND ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}){repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        queue_repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
        unresolved_needs_context = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ? AND queue.status = 'needs_context'
              AND repos.active_generation > 0
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND ({_latest_current_queue_attempt_sql("queue", "repos")})
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        direct_needs_context = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_analysis_results AS results
            JOIN code_analysis_queue AS result_queue
              ON result_queue.id = results.queue_item_id
            JOIN code_files AS files
              ON files.id = results.file_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE results.engagement_id = ? AND results.disposition = 'needs_context'
              AND ({_current_result_receipt_sql(
                  "results", "result_queue", "files", "repos", allow_processing=True
              )})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        unresolved_needs_context += direct_needs_context
        unresolved_active_queue = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ?
              AND queue.status IN ('pending', 'processing')
              AND repos.active_generation > 0
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND ({_latest_current_queue_attempt_sql("queue", "repos")})
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        invalid_active_history = _scalar_row(
            connection,
            f"""
            SELECT COUNT(*)
            FROM code_files AS files
            WHERE files.engagement_id = ?
              AND ({_invalid_active_history_exists_sql("files")})
              {queue_repo_clause}
            """,
            (engagement.id, *repo_params),
        )
        trigger_rows = connection.execute(
            (
                """
                SELECT t.status, COUNT(*) AS total
                FROM code_analysis_triggers AS t
                JOIN code_files AS sf
                  ON sf.id = t.source_file_id
                 AND sf.engagement_id = t.engagement_id
                JOIN code_repos AS repos
                  ON repos.id = sf.repo_id
                 AND repos.engagement_id = sf.engagement_id
                 AND repos.active_generation > 0
                WHERE t.engagement_id = ?
                  AND t.repo_generation = repos.active_generation
                  AND t.source_superseded_at IS NULL
                GROUP BY t.status
                """
                if repo_id is None
                else """
                SELECT t.status, COUNT(*) AS total
                FROM code_analysis_triggers t
                JOIN code_files sf
                  ON sf.id = t.source_file_id
                 AND sf.engagement_id = t.engagement_id
                JOIN code_repos repos
                  ON repos.id = sf.repo_id
                 AND repos.engagement_id = sf.engagement_id
                 AND repos.active_generation > 0
                WHERE t.engagement_id = ? AND sf.repo_id = ?
                  AND t.repo_generation = repos.active_generation
                  AND t.source_superseded_at IS NULL
                GROUP BY t.status
                """
            ),
            (engagement.id,) if repo_id is None else (engagement.id, repo_id),
        ).fetchall()
        trigger_counts: dict[str, int] = {}
        for row in trigger_rows:
            trigger_counts[str(row["status"])] = int(row["total"])
        skip_repo_clause = "" if repo_id is None else " AND files.repo_id = ?"
        skip_reason_rows = connection.execute(
            f"""
            SELECT queue.skip_reason, COUNT(DISTINCT queue.file_id) AS total
            FROM code_analysis_queue AS queue
            JOIN code_files AS files
              ON files.id = queue.file_id
             AND files.engagement_id = queue.engagement_id
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
            WHERE queue.engagement_id = ?
              AND queue.status = 'done'
              AND queue.disposition = 'skipped'
              AND trim(queue.skip_reason) != ''
              AND repos.active_generation > 0
              AND queue.repo_generation = repos.active_generation
              AND queue.source_superseded_at IS NULL
              AND queue.id = (
                  SELECT MAX(latest_queue.id)
                  FROM code_analysis_queue AS latest_queue
                  WHERE latest_queue.engagement_id = queue.engagement_id
                    AND latest_queue.file_id = queue.file_id
                    AND latest_queue.repo_generation = repos.active_generation
                    AND latest_queue.source_superseded_at IS NULL
              )
              AND ({_no_superseded_active_attempt_sql("queue", "repos")})
              {skip_repo_clause}
            GROUP BY queue.skip_reason
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        skip_reasons: dict[str, int] = {}
        for row in skip_reason_rows:
            skip_reasons[row["skip_reason"]] = int(row["total"])

    critical_coverage = (critical_analyzed / critical_total * 100.0) if critical_total > 0 else 0.0
    high_coverage = (high_analyzed / high_total * 100.0) if high_total > 0 else 0.0

    # -- Coverage gate --
    gate_reasons: list[str] = []
    if critical_total > 0 and critical_analyzed < critical_total:
        gate_reasons.append(
            f"Critical files not fully analyzed: {critical_analyzed}/{critical_total}"
        )
    if high_total > 0 and high_analyzed < high_total:
        gate_reasons.append(
            f"High files not fully analyzed: {high_analyzed}/{high_total}"
        )
    if unresolved_needs_context > 0:
        gate_reasons.append(
            f"Unresolved needs-context items: {unresolved_needs_context}"
        )
    if unresolved_active_queue > 0:
        gate_reasons.append(
            f"Queue items still pending or processing: {unresolved_active_queue}"
        )
    if invalid_active_history > 0:
        gate_reasons.append(
            f"Files with superseded active queue attempts: {invalid_active_history}"
        )
    if trigger_counts.get(_TRIGGER_STATUS_PENDING, 0) > 0:
        gate_reasons.append(
            f"Unprocessed cross-file triggers: {trigger_counts[_TRIGGER_STATUS_PENDING]}"
        )

    # -- Effort-threshold gate (blocking for critical/high files) --
    effort_warnings: list[str] = []
    # W3b structural-verification accumulators (populated alongside the effort
    # gate so the uncovered-high-risk-file sub-gate reuses the same merge pass).
    file_applicable: dict[int, list[str]] = {}
    uncovered_high_risk_files: list[dict[str, Any]] = []
    with get_connection() as connection:
        successful_queue_review = _successful_terminal_review_row_sql("q")
        effort_file_rows = connection.execute(
            f"""
            SELECT files.id AS file_id, files.file_path, files.classification,
                   files.analysis_status, files.slot_types_json, files.language, files.role,
                   ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL}) AS review_completed,
                   q.cwe_coverage_json
            FROM code_files AS files
            JOIN code_repos AS effort_repos
              ON effort_repos.id = files.repo_id
             AND effort_repos.engagement_id = files.engagement_id
             AND effort_repos.active_generation > 0
            LEFT JOIN code_analysis_queue AS q
              ON q.file_id = files.id
             AND q.engagement_id = files.engagement_id
             AND q.status = 'done'
             AND q.disposition IN ('clean', 'finding', 'suspicious')
             AND q.repo_generation = effort_repos.active_generation
             AND ({_latest_current_queue_attempt_sql("q", "effort_repos")})
             AND ({_no_superseded_active_attempt_sql("q", "effort_repos")})
             AND ({successful_queue_review})
            WHERE files.engagement_id = ?
              AND files.classification IN ('critical', 'high'){repo_clause}
            """,
            (engagement.id, *repo_params),
        ).fetchall()
        # Accumulate max effort per family per file
        file_efforts: dict[int, dict[str, float]] = {}
        file_not_applicable: dict[int, set[str]] = {}
        file_meta: dict[int, dict[str, Any]] = {}
        for erow in effort_file_rows:
            fid = int(erow["file_id"])
            if fid not in file_meta:
                file_meta[fid] = {
                    "file_path": erow["file_path"],
                    "classification": erow["classification"],
                    "analysis_status": erow["analysis_status"] or "",
                    "review_completed": bool(erow["review_completed"]),
                    "has_coverage_record": False,
                    "slot_types": _json_decode(erow["slot_types_json"], []),
                    "language": erow["language"] or "",
                    "role": erow["role"] or "",
                }
            if erow["cwe_coverage_json"] is not None:
                file_meta[fid]["has_coverage_record"] = True
            cwe_cov = _json_decode(erow["cwe_coverage_json"], [])
            if fid not in file_efforts:
                file_efforts[fid] = {}
            if fid not in file_not_applicable:
                file_not_applicable[fid] = set()
            for entry in cwe_cov:
                _merge_file_effort_entry(file_efforts, file_not_applicable, fid, entry)

        if file_meta:
            placeholders = ",".join("?" for _ in file_meta)
            current_result_receipt = _current_result_receipt_sql(
                "results",
                "result_queue",
                "result_files",
                "result_repos",
                allow_processing=False,
            )
            direct_rows = connection.execute(
                f"""
                SELECT results.file_id, results.cwe_coverage_json
                FROM code_analysis_results AS results
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND results.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                """,
                (engagement.id, *file_meta.keys()),
            ).fetchall()
            for drow in direct_rows:
                fid = int(drow["file_id"])
                file_meta[fid]["has_coverage_record"] = True
                cwe_cov = _json_decode(drow["cwe_coverage_json"], [])
                if fid not in file_efforts:
                    file_efforts[fid] = {}
                if fid not in file_not_applicable:
                    file_not_applicable[fid] = set()
                for entry in cwe_cov:
                    _merge_file_effort_entry(file_efforts, file_not_applicable, fid, entry)

        for fid, meta in file_meta.items():
            threshold = 70 if meta["classification"] == "critical" else 50
            slot_types = meta["slot_types"]
            if not slot_types:
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "missing slot_types"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            applicable = _applicable_families_for_file(
                slot_types,
                language=meta.get("language", ""),
                role=meta.get("role", ""),
            )
            if not applicable:
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "no applicable vulnerability families"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            # Remember the applicable family set for the W3b structural sub-gate
            # (only files with a real applicable surface are candidates).
            file_applicable[fid] = applicable

            efforts = file_efforts.get(fid, {})
            not_applicable = file_not_applicable.get(fid, set())
            if not efforts:
                if applicable and all(family in not_applicable for family in applicable):
                    continue
                if not meta["review_completed"] and not meta["has_coverage_record"]:
                    continue
                msg = (
                    f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                    "analyzed but missing CWE coverage data"
                )
                gate_reasons.append(msg)
                effort_warnings.append(msg)
                continue

            for family in applicable:
                if family in not_applicable:
                    continue
                if efforts.get(family, 0) < threshold:
                    msg = (
                        f"{meta['classification'].capitalize()} file {meta['file_path']}: "
                        f"family '{family}' effort {efforts.get(family, 0):.0f} < {threshold}"
                    )
                    gate_reasons.append(msg)
                    effort_warnings.append(msg)
                    break  # One reason per file is enough

    gate_passed = len(gate_reasons) == 0

    # -- Coverage integrity cross-reference (advisory, not blocking) --
    integrity_warnings: list[dict[str, Any]] = []
    if file_meta:
        with get_connection() as connection:
            file_id_list = list(file_meta.keys())
            placeholders = ",".join("?" for _ in file_id_list)
            current_result_receipt = _current_result_receipt_sql(
                "results",
                "result_queue",
                "result_files",
                "result_repos",
                allow_processing=False,
            )
            result_count_rows = connection.execute(
                f"""
                SELECT results.file_id,
                       COUNT(DISTINCT results.id) AS receipt_count
                FROM code_analysis_results AS results
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND results.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                GROUP BY results.file_id
                """,
                (engagement.id, *file_id_list),
            ).fetchall()
            result_counts = {
                int(r["file_id"]): {
                    "receipt_count": int(r["receipt_count"]),
                    "distinct_structural_callables": 0,
                }
                for r in result_count_rows
            }
            callable_count_rows = connection.execute(
                f"""
                SELECT links.file_id,
                       COUNT(DISTINCT links.callable_id)
                           AS distinct_structural_callables
                FROM code_analysis_results AS results
                JOIN code_analysis_result_callables AS links
                  ON links.result_id = results.id
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND links.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                GROUP BY links.file_id
                """,
                (engagement.id, *file_id_list),
            ).fetchall()
            for row in callable_count_rows:
                fid = int(row["file_id"])
                result_counts.setdefault(
                    fid,
                    {"receipt_count": 0, "distinct_structural_callables": 0},
                )["distinct_structural_callables"] = int(
                    row["distinct_structural_callables"]
                )
            file_func_rows = connection.execute(
                f"""
                SELECT id, total_functions FROM code_files
                WHERE engagement_id = ? AND id IN ({placeholders})
                """,
                (engagement.id, *file_id_list),
            ).fetchall()
            file_total_functions = {
                int(r["id"]): _safe_int(r["total_functions"]) for r in file_func_rows
            }

            for fid, meta in file_meta.items():
                if not meta["has_coverage_record"]:
                    continue
                actual = result_counts.get(
                    fid,
                    {"receipt_count": 0, "distinct_structural_callables": 0},
                )
                total_funcs = file_total_functions.get(fid, 0)
                file_warnings: list[str] = []
                if actual["receipt_count"] == 0 and meta["has_coverage_record"]:
                    efforts = file_efforts.get(fid, {})
                    max_effort = max(efforts.values(), default=0.0)
                    if max_effort >= 60 and total_funcs > 0:
                        file_warnings.append(
                            f"effort={max_effort:.0f} with 0 source-review receipts"
                        )
                if file_warnings:
                    integrity_warnings.append({
                        "file_id": fid,
                        "file_path": meta["file_path"],
                        "classification": meta["classification"],
                        "total_functions": total_funcs,
                        "current_receipt_rows": actual["receipt_count"],
                        "distinct_structural_callables_reviewed": actual[
                            "distinct_structural_callables"
                        ],
                        "warnings": file_warnings,
                    })

            # -- W3b: uncovered high-risk files (callable-receipt structural
            # verification). A critical/high file that is terminal
            # (analyzed/done) and whose structural index found functions, but
            # which shows ZERO structurally bound callable coverage, has no linked finding, and no
            # accepted-gap resolution (all applicable families marked
            # not_applicable), is a coverage hole the effort gate alone misses
            # — the broad-18 near-miss where high files were closed with
            # functions_analyzed=0. Surfaced separately from gate.passed so the
            # phase gate can block on it while the effort dimension stays WARN.
            finding_loc_rows = connection.execute(
                """
                SELECT *
                FROM assessment_findings
                WHERE engagement_id = ?
                  AND status NOT IN ('merged', 'false_positive')
                """,
                (engagement.id,),
            ).fetchall()
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            finding_locations = [
                str(row["canonical_location"] or "").strip()
                for row in finding_loc_rows
                if is_file_finding(str(row["canonical_location"] or ""))
                and finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                == "current"
            ]
            for fid, meta in file_meta.items():
                if meta["classification"] not in ("critical", "high"):
                    continue
                # Only terminal files: unfinished files are the (a) critical/high
                # coverage sub-gate's job, not this structural one.
                if not meta["review_completed"]:
                    continue
                total_funcs = file_total_functions.get(fid, 0)
                if total_funcs <= 0:
                    continue  # no structural index to verify against
                applicable = file_applicable.get(fid, [])
                if not applicable:
                    continue
                not_applicable = file_not_applicable.get(fid, set())
                if all(family in not_applicable for family in applicable):
                    continue  # accepted gap: every applicable family is not_applicable
                actual = result_counts.get(fid, {"distinct_structural_callables": 0})
                callables_reviewed = int(
                    actual.get("distinct_structural_callables", 0)
                )
                if callables_reviewed > 0:
                    continue  # structurally attributable callable review was recorded
                file_path = str(meta["file_path"])
                prefix = f"file:{file_path}"
                if any(loc == prefix or loc.startswith(prefix + ":") for loc in finding_locations):
                    continue  # a finding is linked to this file
                uncovered_high_risk_files.append({
                    "file_id": fid,
                    "file_path": file_path,
                    "classification": meta["classification"],
                    "total_functions": total_funcs,
                })

    return {
        "total_files": total_files,
        "by_classification": by_classification,
        "by_status": by_status,
        "findings_summary": {
            "total_code_findings": total_code_findings,
            "by_severity": by_severity,
            "variant_count": variant_count,
        },
        "confidence": {
            "critical_coverage_pct": round(critical_coverage, 1),
            "high_coverage_pct": round(high_coverage, 1),
            "overall_loc_analyzed": overall_loc_analyzed,
            "unresolved_needs_context": unresolved_needs_context,
            "active_queue_items": unresolved_active_queue,
            "invalid_active_history": invalid_active_history,
            "unprocessed_triggers": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "skip_reasons": skip_reasons,
        },
        "trigger_summary": {
            "pending": trigger_counts.get(_TRIGGER_STATUS_PENDING, 0),
            "queued": trigger_counts.get(_TRIGGER_STATUS_QUEUED, 0),
            "resolved": trigger_counts.get(_TRIGGER_STATUS_RESOLVED, 0),
            "external_context_unavailable": trigger_counts.get(_TRIGGER_STATUS_EXTERNAL_CONTEXT, 0),
            "source_equivalent_analyzed": trigger_counts.get(_TRIGGER_STATUS_SOURCE_EQUIVALENT, 0),
            "not_applicable": trigger_counts.get(_TRIGGER_STATUS_NOT_APPLICABLE, 0),
        },
        "gate": {
            "passed": gate_passed,
            "reasons": gate_reasons,
            "effort_warnings": effort_warnings,
            "coverage_integrity": integrity_warnings,
            "uncovered_high_risk_files": uncovered_high_risk_files,
        },
    }


_CODE_READINESS_PHASES = (
    "classify-map",
    "hunt",
    "verify-variant",
    "fuzz",
    "complete",
)


def _readiness_blocker(
    code: str,
    message: str,
    *,
    repo_id: int | None = None,
    overrideable: bool = False,
) -> dict[str, Any]:
    blocker: dict[str, Any] = {
        "code": code,
        "message": message,
        "overrideable": overrideable,
    }
    if repo_id is not None:
        blocker["repo_id"] = repo_id
    return blocker


def code_readiness(engagement_id: int, *, target_phase: str) -> dict[str, Any]:
    """Project durable code-analysis state into explicit phase-transition blockers."""
    engagement = _engagement_or_404(engagement_id)
    if target_phase not in _CODE_READINESS_PHASES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported code-analysis target phase: {target_phase}",
        )

    blockers: list[dict[str, Any]] = []
    structural_quality_warnings: list[str] = []
    with get_connection() as connection:
        repos = [
            dict(row)
            for row in connection.execute(
                """
                SELECT * FROM code_repos
                WHERE engagement_id = ? AND active_generation > 0
                ORDER BY id
                """,
                (engagement.id,),
            ).fetchall()
        ]
        active_repo_ids = {int(repo["id"]) for repo in repos}
        suspicious_counts = _current_suspicious_analysis_counts(
            connection, engagement.id
        )
        unresolved_draft_counts: dict[int, int] = {}
        stale_draft_counts: dict[int, int] = {}
        unbound_draft_count = 0
        if target_phase in {"fuzz", "complete"}:
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            draft_rows = connection.execute(
                """
                SELECT *
                FROM assessment_findings
                WHERE engagement_id = ? AND status = 'draft'
                  AND COALESCE(verification_status, '') != 'blocked'
                ORDER BY slug
                """,
                (engagement.id,),
            ).fetchall()
            for row in draft_rows:
                repo_id = _finding_snapshot_repo_id(row)
                if not is_file_finding(str(row["canonical_location"] or "")):
                    continue
                snapshot_status = finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                if (
                    repo_id is None
                    or repo_id not in active_repo_ids
                    or snapshot_status == "unbound"
                ):
                    unbound_draft_count += 1
                    continue
                unresolved_draft_counts[repo_id] = (
                    unresolved_draft_counts.get(repo_id, 0) + 1
                )
                if snapshot_status == "stale":
                    stale_draft_counts[repo_id] = (
                        stale_draft_counts.get(repo_id, 0) + 1
                    )
        if unbound_draft_count:
            blockers.append(
                _readiness_blocker(
                    "unbound_draft_code_findings_unresolved",
                    (
                        f"Engagement has {unbound_draft_count} draft code finding(s) "
                        "without a resolvable repository binding; re-review and rebind, "
                        "then promote, merge, or kill each draft."
                    ),
                )
            )
        variant_inventory_by_repo: dict[int, list[dict[str, Any]]] = {}
        variant_parent_slugs_by_repo: dict[int, list[str]] = {}
        variant_unready_parent_slugs_by_repo: dict[int, list[str]] = {}
        variant_projection: _VariantReceiptProjection | None = None
        if target_phase in {"fuzz", "complete"} and active_repo_ids:
            phase2_parent_rows_by_repo = _current_variant_parent_rows_by_repo(
                connection,
                engagement.id,
                active_repo_ids,
                report_durable_only=False,
            )
            variant_parent_slugs_by_repo = {
                repo_id: [str(row["slug"]) for row in rows]
                for repo_id, rows in phase2_parent_rows_by_repo.items()
            }
            variant_unready_parent_slugs_by_repo = {
                repo_id: [
                    str(row["slug"])
                    for row in rows
                    if str(row["verification_status"] or "")
                    not in {"confirmed", "downgraded", "pending_runtime_proof"}
                ]
                for repo_id, rows in phase2_parent_rows_by_repo.items()
            }
            if any(variant_parent_slugs_by_repo.values()):
                variant_inventory_files = [
                    dict(row)
                    for row in connection.execute(
                        """
                        SELECT files.*
                        FROM code_files AS files
                        JOIN code_repos AS repos
                          ON repos.id = files.repo_id
                         AND repos.engagement_id = files.engagement_id
                         AND repos.active_generation > 0
                        WHERE files.engagement_id = ?
                          AND files.retired_at IS NULL
                        ORDER BY files.repo_id, files.id
                        """,
                        (engagement.id,),
                    ).fetchall()
                ]
                for file_row in variant_inventory_files:
                    variant_inventory_by_repo.setdefault(
                        int(file_row["repo_id"]), []
                    ).append(file_row)
                variant_projection = _load_variant_receipt_projection(
                    connection,
                    engagement.id,
                    repo_rows=repos,
                    file_rows=variant_inventory_files,
                    parent_slugs=variant_parent_slugs_by_repo,
                )
        if not repos:
            blockers.append(
                _readiness_blocker(
                    "no_repositories",
                    "No committed repository snapshot is available for code analysis.",
                )
            )

        for repo in repos:
            repo_id = int(repo["id"])
            active_generation = int(repo.get("active_generation", 0) or 0)
            structural_debt_rows: list[Any] = []
            if str(repo.get("source_snapshot_quality", "")) != "verified":
                blockers.append(
                    _readiness_blocker(
                        "source_snapshot_unverified",
                        "Repository source identity is legacy-unverified and must be re-ingested.",
                        repo_id=repo_id,
                    )
                )
            if (
                str(repo.get("source_manifest_version", "") or "") != SOURCE_MANIFEST_VERSION
                or len(str(repo.get("source_manifest_digest", "") or "")) != 64
            ):
                blockers.append(
                    _readiness_blocker(
                        "source_manifest_missing",
                        "Repository source manifest identity is missing or unsupported.",
                        repo_id=repo_id,
                    )
                )
            structural_generation = repo.get("structural_index_generation")
            structural_index_current = not (
                structural_generation is None
                or int(structural_generation) != active_generation
                or str(repo.get("structural_index_schema", "") or "")
                != STRUCTURAL_INDEX_SCHEMA
                or not str(repo.get("structural_index_manifest_path", "") or "")
            )
            if not structural_index_current:
                blockers.append(
                    _readiness_blocker(
                        "structural_index_stale",
                        "Structural index is not bound to the current repository snapshot.",
                        repo_id=repo_id,
                    )
                )
            else:
                incomplete_structural_metadata = _scalar_row(
                    connection,
                    """
                    SELECT COUNT(*)
                    FROM code_files
                    WHERE engagement_id = ? AND repo_id = ?
                      AND retired_at IS NULL
                      AND structural_analysis_status NOT IN (
                        'complete', 'degraded', 'unsupported'
                      )
                    """,
                    (engagement.id, repo_id),
                )
                if incomplete_structural_metadata:
                    blockers.append(
                        _readiness_blocker(
                            "structural_index_metadata_incomplete",
                            (
                                f"Structural index metadata is missing for "
                                f"{incomplete_structural_metadata} admitted source file(s); "
                                "rebuild and sync the current structural index."
                            ),
                            repo_id=repo_id,
                        )
                    )
                else:
                    structural_debt_rows = connection.execute(
                        f"""
                        SELECT files.file_path, files.structural_analysis_status,
                               files.structural_artifact_truncated
                        FROM code_files AS files
                        WHERE files.engagement_id = ? AND files.repo_id = ?
                          AND files.retired_at IS NULL
                          AND (
                            files.structural_analysis_status IN ('degraded', 'unsupported')
                            OR files.structural_artifact_truncated = 1
                          )
                          AND NOT ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL})
                        ORDER BY files.file_path
                        """,
                        (engagement.id, repo_id),
                    ).fetchall()
                    if structural_debt_rows and target_phase in {"classify-map", "hunt"}:
                        degraded_count = sum(
                            str(row["structural_analysis_status"]) == "degraded"
                            for row in structural_debt_rows
                        )
                        unsupported_count = sum(
                            str(row["structural_analysis_status"]) == "unsupported"
                            for row in structural_debt_rows
                        )
                        truncated_count = sum(
                            bool(row["structural_artifact_truncated"])
                            for row in structural_debt_rows
                        )
                        structural_quality_warnings.append(
                            f"Repository {repo_id} structural coverage debt: "
                            f"{len(structural_debt_rows)} unreviewed admitted file(s) "
                            f"({degraded_count} degraded, {unsupported_count} unsupported, "
                            f"{truncated_count} truncated); direct sealed-source specialist "
                            "review is required before Verify + Variant."
                        )

            if target_phase == "classify-map":
                continue

            threat_generation = repo.get("threat_model_generation")
            if threat_generation is None or int(threat_generation) != active_generation:
                blockers.append(
                    _readiness_blocker(
                        "threat_model_stale",
                        "Threat model is not bound to the current repository snapshot.",
                        repo_id=repo_id,
                    )
                )
            unclassified = _scalar_row(
                connection,
                """
                SELECT COUNT(*) FROM code_files
                WHERE engagement_id = ? AND repo_id = ? AND classification = 'unclassified'
                  AND retired_at IS NULL
                """,
                (engagement.id, repo_id),
            )
            if unclassified:
                blockers.append(
                    _readiness_blocker(
                        "files_unclassified",
                        f"Repository has {unclassified} unclassified source file(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )

            if target_phase == "hunt":
                # A5: the durable queue is what Phase 2 claims work from, so an
                # admitted file with no current-generation row can never be
                # dispatched and never reaches accounting. The on-disk queue
                # artifact is planning input and proves nothing about this.
                unqueued_files = _scalar_row(
                    connection,
                    """
                    SELECT COUNT(*)
                    FROM code_files AS files
                    WHERE files.engagement_id = ? AND files.repo_id = ?
                      AND files.retired_at IS NULL
                      AND NOT EXISTS (
                        SELECT 1
                        FROM code_analysis_queue AS queue
                        WHERE queue.engagement_id = files.engagement_id
                          AND queue.file_id = files.id
                          AND queue.repo_generation = ?
                          AND queue.source_superseded_at IS NULL
                      )
                    """,
                    (engagement.id, repo_id, active_generation),
                )
                if unqueued_files:
                    blockers.append(
                        _readiness_blocker(
                            "admitted_files_unqueued",
                            (
                                f"Repository has {unqueued_files} admitted file(s) with no "
                                "current-generation analysis queue row; every admitted file "
                                "needs one before hunting, including skip-tier files."
                            ),
                            repo_id=repo_id,
                            overrideable=True,
                        )
                    )
                continue

            unaccounted_files = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND NOT ({_CURRENT_ACCOUNTED_FILE_EXISTS_SQL})
                """,
                (engagement.id, repo_id),
            )
            if unaccounted_files:
                blockers.append(
                    _readiness_blocker(
                        "admitted_files_unaccounted",
                        (
                            f"Repository has {unaccounted_files} admitted file(s) without a "
                            "current terminal review or evidence-based structured skip."
                        ),
                        repo_id=repo_id,
                    )
                )

            if structural_debt_rows:
                debt_paths = [str(row["file_path"]) for row in structural_debt_rows]
                sample = ", ".join(debt_paths[:5])
                if len(debt_paths) > 5:
                    sample += f", and {len(debt_paths) - 5} more"
                blockers.append(
                    _readiness_blocker(
                        "structural_analysis_debt_unreviewed",
                        (
                            f"Repository has {len(debt_paths)} admitted source file(s) with "
                            "degraded, unsupported, or truncated structural analysis and no "
                            f"durable specialist/manual review: {sample}."
                        ),
                        repo_id=repo_id,
                    )
                )

            incomplete_high_risk = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*) FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND files.classification IN ('critical', 'high')
                  AND NOT ({_CURRENT_SUCCESSFUL_REVIEW_EXISTS_SQL})
                """,
                (engagement.id, repo_id),
            )
            if incomplete_high_risk:
                blockers.append(
                    _readiness_blocker(
                        "critical_high_incomplete",
                        f"Repository has {incomplete_high_risk} incomplete critical/high file(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            active_queue = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_analysis_queue AS queue
                JOIN code_files AS files
                  ON files.id = queue.file_id
                 AND files.engagement_id = queue.engagement_id
                JOIN code_repos AS queue_repos
                  ON queue_repos.id = files.repo_id
                 AND queue_repos.engagement_id = files.engagement_id
                WHERE queue.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND queue.status IN ('pending', 'processing', 'error')
                  AND queue.repo_generation = queue_repos.active_generation
                  AND queue.source_superseded_at IS NULL
                  AND ({_latest_current_queue_attempt_sql("queue", "queue_repos")})
                  AND ({_no_superseded_active_attempt_sql("queue", "queue_repos")})
                """,
                (engagement.id, repo_id),
            )
            invalid_active_history = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_files AS files
                WHERE files.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND ({_invalid_active_history_exists_sql("files")})
                """,
                (engagement.id, repo_id),
            )
            active_queue += invalid_active_history
            if active_queue:
                blockers.append(
                    _readiness_blocker(
                        "analysis_queue_active",
                        f"Repository has {active_queue} active or errored analysis queue item(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            needs_context = _scalar_row(
                connection,
                f"""
                SELECT COUNT(*)
                FROM code_analysis_queue AS queue
                JOIN code_files AS files
                  ON files.id = queue.file_id
                 AND files.engagement_id = queue.engagement_id
                JOIN code_repos AS queue_repos
                  ON queue_repos.id = files.repo_id
                 AND queue_repos.engagement_id = files.engagement_id
                WHERE queue.engagement_id = ? AND files.repo_id = ?
                  AND files.retired_at IS NULL
                  AND queue.status = 'needs_context'
                  AND queue.repo_generation = queue_repos.active_generation
                  AND queue.source_superseded_at IS NULL
                  AND ({_latest_current_queue_attempt_sql("queue", "queue_repos")})
                  AND ({_no_superseded_active_attempt_sql("queue", "queue_repos")})
                """,
                (engagement.id, repo_id),
            )
            if needs_context:
                blockers.append(
                    _readiness_blocker(
                        "needs_context_unresolved",
                        f"Repository has {needs_context} unresolved needs-context item(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )
            if target_phase in {"verify-variant", "fuzz", "complete"}:
                unresolved_suspicious = suspicious_counts.get(repo_id, 0)
                if unresolved_suspicious:
                    blockers.append(
                        _readiness_blocker(
                            "unresolved_suspicious_analysis",
                            (
                                f"Repository has {unresolved_suspicious} current "
                                "suspicious analysis attempt(s) requiring a finding "
                                "or clean terminal reanalysis."
                            ),
                            repo_id=repo_id,
                        )
                    )
            pending_triggers = _scalar_row(
                connection,
                """
                SELECT COUNT(*)
                FROM code_analysis_triggers AS triggers
                JOIN code_files AS files ON files.id = triggers.source_file_id
                JOIN code_repos AS repos
                  ON repos.id = triggers.repo_id
                 AND repos.engagement_id = triggers.engagement_id
                 AND repos.active_generation > 0
                WHERE triggers.engagement_id = ? AND files.repo_id = ?
                  AND triggers.status = 'pending'
                  AND triggers.repo_generation = repos.active_generation
                  AND triggers.source_superseded_at IS NULL
                """,
                (engagement.id, repo_id),
            )
            if pending_triggers:
                blockers.append(
                    _readiness_blocker(
                        "pending_triggers",
                        f"Repository has {pending_triggers} unprocessed cross-file trigger(s).",
                        repo_id=repo_id,
                        overrideable=True,
                    )
                )

            if target_phase in {"fuzz", "complete"}:
                unresolved_draft_count = unresolved_draft_counts.get(repo_id, 0)
                if unresolved_draft_count:
                    stale_draft_count = stale_draft_counts.get(repo_id, 0)
                    stale_detail = (
                        f"; {stale_draft_count} have stale snapshot bindings"
                        if stale_draft_count
                        else ""
                    )
                    blockers.append(
                        _readiness_blocker(
                            "draft_code_findings_unresolved",
                            (
                                f"Repository has {unresolved_draft_count} unresolved draft "
                                f"code finding(s){stale_detail}; re-review and rebind when "
                                "needed, then promote, merge, or kill each "
                                "draft before leaving verification."
                            ),
                            repo_id=repo_id,
                        )
                    )

                parent_finding_slugs = variant_parent_slugs_by_repo.get(repo_id, [])
                if parent_finding_slugs:
                    unready_parent_slugs = (
                        variant_unready_parent_slugs_by_repo.get(repo_id, [])
                    )
                    if unready_parent_slugs:
                        blockers.append(
                            _readiness_blocker(
                                "variant_parent_verification_incomplete",
                                (
                                    f"Repository has {len(unready_parent_slugs)} current "
                                    "Phase 2 root finding(s) without a verified "
                                    "confirmed, downgraded, or pending-runtime-proof "
                                    "disposition; finish evidence triage before entering fuzz."
                                ),
                                repo_id=repo_id,
                            )
                        )
                    incomplete_variants = sum(
                        _current_variant_check_status(
                            connection,
                            engagement.id,
                            file_row,
                            projection=variant_projection,
                        )
                        != "done"
                        for file_row in variant_inventory_by_repo.get(repo_id, [])
                    )
                    if incomplete_variants:
                        blockers.append(
                            _readiness_blocker(
                                "variant_checks_incomplete",
                                (
                                    f"Repository has {incomplete_variants} incomplete "
                                    "admitted-file variant check(s)."
                                ),
                                repo_id=repo_id,
                                overrideable=True,
                            )
                        )

    coverage = code_coverage_summary(engagement.id)
    coverage_gate = coverage.get("gate", {})
    uncovered = coverage_gate.get("uncovered_high_risk_files", [])
    if target_phase in {"verify-variant", "fuzz", "complete"} and uncovered:
        blockers.append(
            _readiness_blocker(
                "structural_coverage_unresolved",
                f"Structural coverage found {len(uncovered)} uncovered critical/high file(s).",
                overrideable=True,
            )
        )

    if target_phase == "complete":
        with get_connection() as connection:
            finding_rows = connection.execute(
                """
                SELECT * FROM assessment_findings
                WHERE engagement_id = ?
                  AND status IN (
                      'active', 'blocked', 'exploited', 'contained',
                      'eradicated', 'recovered', 'reported'
                  )
                  AND verification_status != 'blocked'
                """,
                (engagement.id,),
            ).fetchall()
            repo_states = load_code_repo_snapshot_states(connection, engagement.id)
            finding_snapshot_statuses = []
            for row in finding_rows:
                snapshot_status = finding_code_snapshot_status(
                    connection,
                    engagement.id,
                    row,
                    repo_states=repo_states,
                )
                if snapshot_status != "not_applicable":
                    finding_snapshot_statuses.append((row, snapshot_status))
            stale_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status != "current"
            ]
            unverified_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status == "current"
                and str(row["verification_status"] or "")
                not in {"confirmed", "downgraded", "false_positive"}
            ]
            blind_triage_findings = [
                row
                for row, snapshot_status in finding_snapshot_statuses
                if snapshot_status == "current"
                and str(row["verification_status"] or "")
                not in {"confirmed", "downgraded"}
            ]
        if stale_findings:
            blockers.append(
                _readiness_blocker(
                    "finding_snapshot_stale",
                    f"{len(stale_findings)} reportable code finding(s) are not bound to the current verified source snapshot.",
                )
            )
        if unverified_findings:
            blockers.append(
                _readiness_blocker(
                    "findings_unverified",
                    f"{len(unverified_findings)} current code finding(s) have not completed verification triage.",
                    overrideable=True,
                )
            )
        if blind_triage_findings:
            blockers.append(
                _readiness_blocker(
                    "findings_blind_triage_incomplete",
                    f"{len(blind_triage_findings)} current code finding(s) lack a report-durable triage disposition.",
                    overrideable=True,
                )
            )

    fuzz_completion: dict[str, Any] | None = None
    if target_phase in {"fuzz", "complete"}:
        fuzz_states = code_fuzz_completion.fuzz_states(engagement.id)
        pending_targets = sorted(
            {
                target_id
                for state in fuzz_states
                for target_id in state["pending_target_ids"]
            }
        )
        pending_findings = sorted(
            {
                slug
                for state in fuzz_states
                for slug in state["pending_finding_slugs"]
            }
        )
        fuzz_completion = {
            "repos": fuzz_states,
            "pending_target_ids": pending_targets,
            "pending_finding_slugs": pending_findings,
            "applicability_ready": all(
                state["applicability_ready"] for state in fuzz_states
            ),
            "completion_ready": all(
                state["completion_ready"] for state in fuzz_states
            ),
        }
        for state in fuzz_states:
            if not state["applicability_ready"]:
                blockers.append(
                    _readiness_blocker(
                        "fuzz_decision_missing",
                        (
                            "Repository has no agent-attested, evidence-hashed current-source fuzz "
                            "applicability decision; record required targets or a "
                            "not-required rationale before entering Phase 4."
                        ),
                        repo_id=int(state["repo_id"]),
                    )
                )
            if target_phase == "complete" and not state["completion_ready"]:
                blockers.append(
                    _readiness_blocker(
                        "fuzz_campaign_incomplete",
                        (
                            "Repository has incomplete generation-bound fuzz obligations: "
                            f"{len(state['pending_target_ids'])} target(s), "
                            f"{len(state['pending_finding_slugs'])} current native memory-safety "
                            "finding(s). Record covering terminal campaign receipts."
                        ),
                        repo_id=int(state["repo_id"]),
                    )
                )

    warnings = list(structural_quality_warnings)
    warnings.extend(str(warning) for warning in coverage_gate.get("effort_warnings", []))
    for item in coverage_gate.get("coverage_integrity", []):
        if not isinstance(item, dict):
            continue
        for warning in item.get("warnings", []):
            warnings.append(f"{item.get('file_path', 'unknown file')}: {warning}")
    warnings = list(dict.fromkeys(warnings))
    payload = {
        "track": "code",
        "target_phase": target_phase,
        "transition_ready": not blockers,
        "blockers": blockers,
        "quality_gate": {"passed": not warnings, "warnings": warnings},
    }
    if fuzz_completion is not None:
        payload["fuzz_completion"] = fuzz_completion
    return payload


# =========================================================================
# Slot-to-vuln-class mapping
# =========================================================================

SLOT_VULN_CLASSES: dict[str, dict[str, list[str]]] = {
    "NETWORK-INPUT": {
        "all": ["algorithmic-dos", "error-handling"],
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "ssrf", "open-redirect", "path-traversal"],
    },
    "PROTOCOL-FIELD": {
        "all": ["algorithmic-dos", "error-handling"],
        "native": ["buffer-overflow", "integer-overflow", "format-string"],
        "managed": ["web-app-injection", "web-app-auth", "race-condition"],
    },
    "URL-COMPONENT": {
        "all": [
            "injection", "auth-bypass", "ssrf", "open-redirect", "web-app-auth",
            "algorithmic-dos", "error-handling",
        ]
    },
    "FILE-CONTENT": {"all": ["injection", "buffer-overflow", "type-confusion", "path-traversal", "xxe", "file-upload"]},
    "CMD-ARGUMENT": {"all": ["injection", "format-string", "path-traversal"]},
    "CALLBACK-DATA": {"all": ["use-after-free", "race-condition", "type-confusion", "deserialization"]},
    "ENV-VARIABLE": {"all": ["injection", "path-traversal"]},
    "SERIALIZED-DATA": {
        "native": ["buffer-overflow", "integer-overflow", "type-confusion", "deserialization"],
        "managed": ["deserialization"],
    },
    "EXEC-POLICY": {"all": ["injection", "auth-bypass", "crypto-misuse", "error-handling"]},
}


NATIVE_LANGUAGES = frozenset({"c", "c++", "cpp"})
STRUCTURALLY_ANALYZED_LANGUAGES = frozenset(
    {
        "c",
        "c++",
        "cpp",
        "python",
        "javascript",
        "typescript",
        "go",
        "java",
        "ruby",
        "php",
        "shell",
        "lua",
        "html",
        "css",
        "dockerfile",
    }
)

ROLE_CONTEXT_VULN_CLASSES: tuple[tuple[tuple[str, ...], dict[str, list[str]]], ...] = (
    (("crypto", "cipher", "tls", "ssl", "digest", "hmac", "jwt", "x509"), {"all": ["crypto-misuse"]}),
    (("auth", "oauth", "session", "login", "signin", "permission", "rbac", "acl", "sso"), {"all": ["auth-bypass", "web-app-auth"]}),
    (("error", "exception", "fallback", "retry", "recovery"), {"all": ["error-handling"], "native": ["null-dereference"]}),
    (("allocator", "allocation", "memory", "arena", "pool"), {"native": ["uninitialized-memory"], "all": ["algorithmic-dos"]}),
    (("parser", "decoder", "deserializer", "deserialize", "serializer", "serialization", "codec", "marshal", "unmarshal", "regex", "regexp"), {"all": ["algorithmic-dos"]}),
    (("graphql", "resolver", "serializer", "orm", "resource", "controller", "view"), {"managed": ["web-app-data-exposure"]}),
    (("llm", "prompt", "rag", "mcp", "embedding"), {"all": ["ai-ml-security"]}),
)


def _apply_grouped_families(
    families: set[str],
    mapping: dict[str, list[str]],
    *,
    is_native: bool,
    lang_known: bool,
) -> None:
    for group, group_families in mapping.items():
        if group == "all":
            families.update(group_families)
        elif group == "native" and (is_native or not lang_known):
            families.update(group_families)
        elif group == "managed" and (not is_native or not lang_known):
            families.update(group_families)


def _applicable_families_for_file(
    slot_types: list[str],
    *,
    language: str = "",
    role: str = "",
) -> list[str]:
    """Compute canonical applicable vulnerability classes for a classified file."""
    lang_lower = language.lower().strip()
    is_native = lang_lower in NATIVE_LANGUAGES
    lang_known = bool(lang_lower)
    role_lower = role.lower().strip()

    families: set[str] = (
        {"algorithmic-dos", "error-handling"}
        if lang_lower in STRUCTURALLY_ANALYZED_LANGUAGES
        else set()
    )
    for slot in slot_types:
        _apply_grouped_families(
            families,
            SLOT_VULN_CLASSES.get(slot, {}),
            is_native=is_native,
            lang_known=lang_known,
        )

    for keywords, mapping in ROLE_CONTEXT_VULN_CLASSES:
        if any(keyword in role_lower for keyword in keywords):
            _apply_grouped_families(
                families,
                mapping,
                is_native=is_native,
                lang_known=lang_known,
            )

    return sorted(families)


def _applicable_families_for_slots(slot_types: list[str], language: str = "") -> list[str]:
    """Backward-compatible slot-only family computation."""
    return _applicable_families_for_file(slot_types, language=language)


# =========================================================================
# Requeue triggered files
# =========================================================================

def _merge_unique_values(existing: list[Any], additions: list[Any]) -> list[Any]:
    merged = list(existing)
    signatures = {json.dumps(value, sort_keys=True, default=str) for value in merged}
    for value in additions:
        signature = json.dumps(value, sort_keys=True, default=str)
        if signature not in signatures:
            merged.append(value)
            signatures.add(signature)
    return merged


def _contains_all_values(existing: list[Any], requested: list[Any]) -> bool:
    existing_signatures = {
        json.dumps(value, sort_keys=True, default=str) for value in existing
    }
    return all(
        json.dumps(value, sort_keys=True, default=str) in existing_signatures
        for value in requested
    )


class _TriggerTargetBlocked(Exception):
    """One trigger target cannot be written; every other target still commits."""


def _requeue_selector(item: dict[str, Any], index: int) -> dict[str, Any]:
    """Reduce one requeue input to exactly one target selector.

    Ambiguity is the defect this rejects. An input naming two targets used to
    resolve to whichever branch was tested first, and an input naming none was
    dropped in silence while still counting toward the reported total.
    """
    selector: dict[str, Any] = {}
    if item.get("file_id") is not None:
        selector["file_id"] = _require_strict_positive_id(
            item["file_id"], field_name=f"items[{index}].file_id"
        )
    if item.get("trigger_id") is not None:
        selector["trigger_id"] = _require_strict_positive_id(
            item["trigger_id"], field_name=f"items[{index}].trigger_id"
        )
    file_path = str(item.get("file_path", "")).strip()
    if file_path:
        selector["file_path"] = file_path
    if len(selector) != 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"items[{index}] needs exactly one selector — file_id, trigger_id, "
                f"or file_path — but named {len(selector)}"
            ),
        )
    if item.get("repo_id") is not None:
        if "file_path" not in selector:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    f"items[{index}].repo_id only disambiguates a file_path selector"
                ),
            )
        selector["repo_id"] = _require_strict_positive_id(
            item["repo_id"], field_name=f"items[{index}].repo_id"
        )
    return selector


_REQUEUE_TARGET_COLUMNS = """
    files.id, files.file_path, files.classification,
    files.analysis_priority, repos.active_generation
"""


def _requeue_target_by_file_id(connection, engagement_id: int, file_id: int) -> Any:
    return connection.execute(
        f"""
        SELECT {_REQUEUE_TARGET_COLUMNS}
        FROM code_files AS files
        JOIN code_repos AS repos
          ON repos.id = files.repo_id
         AND repos.engagement_id = files.engagement_id
         AND repos.active_generation > 0
        WHERE files.engagement_id = ? AND files.id = ?
          AND files.retired_at IS NULL
        """,
        (engagement_id, file_id),
    ).fetchone()


def _resolve_requeue_target(
    connection, engagement_id: int, selector: dict[str, Any]
) -> tuple[Any, str, str]:
    """Resolve one selector to its current target file row.

    Returns ``(row, outcome, label)``; ``row`` is None unless ``outcome`` is
    ``resolved``. The label is what the not_found/ambiguous summaries name.
    """
    if "file_id" in selector:
        file_id = int(selector["file_id"])
        row = _requeue_target_by_file_id(connection, engagement_id, file_id)
        return (row, "resolved", "") if row is not None else (None, "not_found", str(file_id))

    if "trigger_id" in selector:
        trigger_id = int(selector["trigger_id"])
        label = f"trigger:{trigger_id}"
        trigger = connection.execute(
            """
            SELECT triggers.target_file_id, triggers.target_file_path,
                   source_files.repo_id AS source_repo_id
            FROM code_analysis_triggers AS triggers
            JOIN code_files AS source_files
              ON source_files.id = triggers.source_file_id
             AND source_files.engagement_id = triggers.engagement_id
            JOIN code_repos AS source_repos
              ON source_repos.id = source_files.repo_id
             AND source_repos.engagement_id = source_files.engagement_id
             AND source_repos.active_generation > 0
            WHERE triggers.engagement_id = ? AND triggers.id = ?
              AND triggers.repo_generation = source_repos.active_generation
              AND triggers.source_superseded_at IS NULL
            """,
            (engagement_id, trigger_id),
        ).fetchone()
        if trigger is None:
            return None, "not_found", label
        if trigger["target_file_id"] is not None:
            row = _requeue_target_by_file_id(
                connection, engagement_id, int(trigger["target_file_id"])
            )
            return (row, "resolved", "") if row is not None else (None, "not_found", label)
        # An unbound trigger names its target by path inside the source repo,
        # which is the same repository the requeue insert must land in.
        selector = {
            "file_path": str(trigger["target_file_path"]),
            "repo_id": int(trigger["source_repo_id"]),
        }
        row, outcome, _label = _resolve_requeue_target(
            connection, engagement_id, selector
        )
        return row, outcome, label

    file_path = str(selector["file_path"])
    repo_id = selector.get("repo_id")
    rows = connection.execute(
        (
            f"""
            SELECT {_REQUEUE_TARGET_COLUMNS}
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE files.engagement_id = ? AND files.file_path = ?
              AND files.retired_at IS NULL
            """
            if repo_id is None
            else f"""
            SELECT {_REQUEUE_TARGET_COLUMNS}
            FROM code_files AS files
            JOIN code_repos AS repos
              ON repos.id = files.repo_id
             AND repos.engagement_id = files.engagement_id
             AND repos.active_generation > 0
            WHERE files.engagement_id = ? AND files.repo_id = ?
              AND files.file_path = ?
              AND files.retired_at IS NULL
            """
        ),
        (engagement_id, file_path)
        if repo_id is None
        else (engagement_id, int(repo_id), file_path),
    ).fetchall()
    if not rows:
        return None, "not_found", file_path
    if len(rows) > 1:
        return None, "ambiguous", file_path
    return rows[0], "resolved", ""


def _requeue_trigger_payload(
    item: dict[str, Any], *, file_path: str
) -> dict[str, Any] | None:
    """Project one input's free-text trigger context into a queue-row entry."""
    reason = item.get("reason", "")
    trigger_ctx = item.get("trigger_context")
    if not reason and not trigger_ctx:
        return None
    payload: dict[str, Any] = {"file_path": file_path, "source": "cross_file_trigger"}
    if reason:
        payload["reason"] = str(reason)
    if isinstance(trigger_ctx, dict):
        reserved_context_keys = {
            "file_path",
            "reason",
            "source",
            "trigger_id",
            "source_file_id",
            "source_file_path",
            "source_queue_item_id",
        }
        payload.update(
            {
                key: value
                for key, value in trigger_ctx.items()
                if key not in reserved_context_keys
            }
        )
    return {
        key: value for key, value in payload.items() if value not in (None, "", [], {})
    }


def _apply_requeue_target(
    connection,
    engagement_id: int,
    file_id: int,
    target: dict[str, Any],
) -> tuple[str, int | None, str, bool]:
    """Write one aggregated target. Returns (outcome, queue_item_id, detail, reopened).

    Raises :class:`_TriggerTargetBlocked` when durable state refuses the write,
    so the caller can roll back this target alone.
    """
    if target["blocked_reason"] is not None:
        raise _TriggerTargetBlocked(target["blocked_reason"])

    pending_trigger_rows = connection.execute(
        """
        SELECT triggers.id, triggers.source_queue_item_id,
               triggers.source_file_id, source_files.file_path AS source_file_path,
               triggers.target_file_path, triggers.vuln_class, triggers.reason
        FROM code_analysis_triggers AS triggers
        JOIN code_files AS source_files
          ON source_files.id = triggers.source_file_id
         AND source_files.engagement_id = triggers.engagement_id
        JOIN code_repos AS source_repos
          ON source_repos.id = triggers.repo_id
         AND source_repos.engagement_id = triggers.engagement_id
         AND source_repos.active_generation > 0
        JOIN code_files AS target_files
          ON target_files.id = ?
         AND target_files.engagement_id = triggers.engagement_id
        WHERE triggers.engagement_id = ? AND triggers.status = ?
          AND triggers.repo_generation = source_repos.active_generation
          AND triggers.source_superseded_at IS NULL
          AND (
              triggers.target_file_id = target_files.id
              OR (
                  triggers.target_file_id IS NULL
                  AND triggers.target_file_path = target_files.file_path
                  AND source_files.repo_id = target_files.repo_id
              )
          )
        ORDER BY triggers.id
        """,
        (file_id, engagement_id, _TRIGGER_STATUS_PENDING),
    ).fetchall()
    bucket_triggers = target["cross_file_triggers"]
    existing_trigger_ids = {
        int(entry["trigger_id"])
        for entry in bucket_triggers
        if isinstance(entry, dict) and entry.get("trigger_id") is not None
    }
    for trigger_row in pending_trigger_rows:
        trigger_id = int(trigger_row["id"])
        if trigger_id in existing_trigger_ids:
            continue
        trigger_payload = {
            "trigger_id": trigger_id,
            "file_path": str(trigger_row["target_file_path"]),
            "source": "code_analysis_trigger",
            "source_file_id": int(trigger_row["source_file_id"]),
            "source_file_path": str(trigger_row["source_file_path"]),
            "vuln_class": str(trigger_row["vuln_class"]),
            "reason": str(trigger_row["reason"]),
        }
        if trigger_row["source_queue_item_id"] is not None:
            trigger_payload["source_queue_item_id"] = int(
                trigger_row["source_queue_item_id"]
            )
        bucket_triggers.append(trigger_payload)
        existing_trigger_ids.add(trigger_id)

    current_rows = [
        dict(queue_row)
        for queue_row in connection.execute(
            """
            SELECT *
            FROM code_analysis_queue
            WHERE engagement_id = ? AND file_id = ? AND repo_generation = ?
            ORDER BY id
            """,
            (engagement_id, file_id, int(target["repo_generation"])),
        ).fetchall()
    ]
    latest, active, active_issue = _canonical_queue_attempt_state(current_rows)
    if active_issue is not None:
        raise _TriggerTargetBlocked(
            f"{active_issue} queue history requires operator reconciliation"
        )

    # A15b: a requeue is added depth on the file's existing lane, not a move to
    # a synthetic one. Provenance rides in queue_mode='trigger' instead.
    batch_theme = target["batch_theme"]
    if batch_theme is None:
        inherited = active if active is not None else latest
        batch_theme = str((inherited or {}).get("batch_theme") or "")

    if active is not None:
        active_status = str(active["status"])
        existing_slots = _json_decode(active.get("slot_types_json"), [])
        existing_guidance = _json_decode(active.get("guidance_hypotheses_json"), [])
        existing_triggers = _json_decode(active.get("cross_file_triggers_json"), [])
        requested_is_present = (
            int(active["priority"]) == int(target["priority"])
            and _contains_all_values(existing_slots, target["slot_types"])
            and _contains_all_values(existing_guidance, target["guidance_hypotheses"])
            and _contains_all_values(existing_triggers, target["cross_file_triggers"])
        )
        if active_status == "processing":
            if not requested_is_present:
                raise _TriggerTargetBlocked(
                    "file is processing; new trigger context cannot be merged into a "
                    "live lease"
                )
            result = (
                "already_queued",
                int(active["id"]),
                "live lease already carries this context",
                False,
            )
            return _finish_requeue_target(
                connection, engagement_id, file_id, pending_trigger_rows, result
            )
        if str(active.get("assigned_agent") or "") or str(
            active.get("lease_token") or ""
        ):
            raise _TriggerTargetBlocked(
                "pending queue attempt has an inconsistent lease identity"
            )
        if str(active.get("queue_mode") or "initial") == "reanalysis":
            raise _TriggerTargetBlocked(
                "pending explicit reanalysis owns this file; close that attempt "
                "before merging trigger context"
            )
        cursor = connection.execute(
            """
            UPDATE code_analysis_queue
            SET priority = ?, batch_theme = ?, slot_types_json = ?,
                guidance_hypotheses_json = ?, cross_file_triggers_json = ?,
                queue_mode = 'trigger', updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND id = ? AND status = 'pending'
              AND assigned_agent = '' AND lease_token = ''
            """,
            (
                int(target["priority"]),
                batch_theme,
                _json_list_text(_merge_unique_values(existing_slots, target["slot_types"])),
                _json_list_text(
                    _merge_unique_values(existing_guidance, target["guidance_hypotheses"])
                ),
                _json_list_text(
                    _merge_unique_values(existing_triggers, target["cross_file_triggers"])
                ),
                engagement_id,
                int(active["id"]),
            ),
        )
        if cursor.rowcount != 1:
            raise _TriggerTargetBlocked("pending queue item changed during trigger merge")
        return _finish_requeue_target(
            connection,
            engagement_id,
            file_id,
            pending_trigger_rows,
            (
                "already_queued",
                int(active["id"]),
                "merged into the pending attempt",
                False,
            ),
        )

    latest_contains_request = (
        latest is not None
        and int(latest["priority"]) == int(target["priority"])
        and _contains_all_values(
            _json_decode(latest.get("slot_types_json"), []), target["slot_types"]
        )
        and _contains_all_values(
            _json_decode(latest.get("guidance_hypotheses_json"), []),
            target["guidance_hypotheses"],
        )
        and _contains_all_values(
            _json_decode(latest.get("cross_file_triggers_json"), []),
            target["cross_file_triggers"],
        )
    )
    if (
        latest is not None
        and str(latest["status"]) == "done"
        and latest_contains_request
        and _has_current_successful_review(connection, engagement_id, file_id)
    ):
        # A completed review that already carries this context is not reopened,
        # so its pending triggers stay pending for an explicit disposition.
        _sync_trigger_status_for_file(connection, engagement_id, file_id)
        return (
            "already_completed",
            int(latest["id"]),
            "current review already covers this context",
            False,
        )

    cursor = connection.execute(
        """
        INSERT INTO code_analysis_queue (
            engagement_id, file_id, priority,
            batch_theme, slot_types_json, guidance_hypotheses_json,
            cross_file_triggers_json, repo_generation, queue_mode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'trigger')
        """,
        (
            engagement_id,
            file_id,
            int(target["priority"]),
            batch_theme,
            _json_list_text(target["slot_types"]),
            _json_list_text(target["guidance_hypotheses"]),
            _json_list_text(target["cross_file_triggers"]),
            int(target["repo_generation"]),
        ),
    )
    reopened = latest is not None
    detail = (
        "reopened a terminal file with a new trigger attempt"
        if reopened
        else "created the first trigger attempt"
    )
    return _finish_requeue_target(
        connection,
        engagement_id,
        file_id,
        pending_trigger_rows,
        ("inserted", int(cursor.lastrowid), detail, reopened),
    )


def _finish_requeue_target(
    connection,
    engagement_id: int,
    file_id: int,
    pending_trigger_rows: list[Any],
    result: tuple[str, int, str, bool],
) -> tuple[str, int, str, bool]:
    """Bind the target's pending triggers to the written row and resync rollups."""
    _outcome, queue_item_id, _detail, _reopened = result
    pending_trigger_ids = [int(row["id"]) for row in pending_trigger_rows]
    if pending_trigger_ids:
        placeholders = ",".join("?" for _ in pending_trigger_ids)
        connection.execute(
            f"""
            UPDATE code_analysis_triggers
            SET target_file_id = ?, resolved_queue_item_id = ?,
                status = ?, resolution_note = '',
                updated_at = CURRENT_TIMESTAMP
            WHERE engagement_id = ? AND status = ?
              AND id IN ({placeholders})
            """,
            (
                file_id,
                queue_item_id,
                _TRIGGER_STATUS_QUEUED,
                engagement_id,
                _TRIGGER_STATUS_PENDING,
                *pending_trigger_ids,
            ),
        )
    _sync_file_analysis_status(connection, engagement_id, file_id)
    _sync_trigger_status_for_file(connection, engagement_id, file_id)
    return result


def requeue_triggered_files(
    engagement_id: int,
    items: list[dict[str, Any]],
) -> dict[str, Any]:
    """Turn cross-file triggers into linked current analysis attempts.

    Every input names exactly one target — ``file_id``, ``trigger_id``, or
    ``file_path`` (with ``repo_id`` to disambiguate) — and receives exactly one
    outcome. Inputs aggregate per target file, so ``input_trigger_count`` and
    ``target_count`` are reported separately and the target buckets (inserted,
    already_queued, already_completed, blocked) sum to ``target_count`` exactly.
    Each target is written inside its own savepoint: a blocked target is
    reported with its reason instead of discarding every other target's work.
    """
    engagement = _engagement_or_404(engagement_id)
    selectors = [_requeue_selector(item, index) for index, item in enumerate(items)]
    counts = {
        "inserted": 0,
        "already_queued": 0,
        "already_completed": 0,
        "blocked": 0,
    }
    reopened_terminal_files = 0
    not_found: list[str] = []
    ambiguous: list[str] = []
    input_file_ids: list[int | None] = []
    input_outcomes: list[str] = []
    target_outcomes: list[dict[str, Any]] = []
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        aggregated: dict[int, dict[str, Any]] = {}
        for item, selector in zip(items, selectors, strict=True):
            row, outcome, label = _resolve_requeue_target(
                connection, engagement.id, selector
            )
            if row is None:
                (not_found if outcome == "not_found" else ambiguous).append(label)
                input_file_ids.append(None)
                input_outcomes.append(outcome)
                continue
            file_id = int(row["id"])
            input_file_ids.append(file_id)
            input_outcomes.append("")
            target = aggregated.setdefault(
                file_id,
                {
                    "priority": int(row["analysis_priority"]),
                    "repo_generation": int(row["active_generation"]),
                    "file_path": str(row["file_path"]),
                    "batch_theme": None,
                    "slot_types": [],
                    "guidance_hypotheses": [],
                    "cross_file_triggers": [],
                    "blocked_reason": None,
                },
            )
            classification = str(row["classification"] or "").strip()
            if classification not in _VALID_CLASSIFICATIONS:
                target["blocked_reason"] = (
                    "target file must be classified before requeue"
                )
            supplied_priority = item.get("priority")
            if supplied_priority is not None:
                supplied_priority = _require_strict_priority(
                    supplied_priority, field_name="trigger priority"
                )
                if supplied_priority != target["priority"]:
                    target["blocked_reason"] = (
                        f"trigger priority must equal the current analysis_priority "
                        f"{target['priority']} (received {supplied_priority})"
                    )
            batch_theme = str(item.get("batch_theme", "")).strip()
            if batch_theme:
                target["batch_theme"] = batch_theme
            target["slot_types"] = _merge_unique_values(
                target["slot_types"],
                _normalize_slot_types(item.get("slot_types"), field_name="slot_types"),
            )
            target["guidance_hypotheses"] = _merge_unique_values(
                target["guidance_hypotheses"],
                _normalize_guidance_hypotheses(
                    item.get("guidance_hypotheses"),
                    field_name="guidance_hypotheses",
                ),
            )
            trigger_payload = _requeue_trigger_payload(
                item, file_path=target["file_path"]
            )
            if trigger_payload is not None:
                target["cross_file_triggers"] = _merge_unique_values(
                    target["cross_file_triggers"], [trigger_payload]
                )

        for file_id, target in aggregated.items():
            connection.execute("SAVEPOINT requeue_target")
            try:
                outcome, queue_item_id, detail, reopened = _apply_requeue_target(
                    connection, engagement.id, file_id, target
                )
            except _TriggerTargetBlocked as blocked:
                connection.execute("ROLLBACK TO requeue_target")
                connection.execute("RELEASE requeue_target")
                counts["blocked"] += 1
                target_outcomes.append(
                    {
                        "file_id": file_id,
                        "file_path": target["file_path"],
                        "queue_item_id": None,
                        "outcome": "blocked",
                        "detail": str(blocked),
                    }
                )
                continue
            connection.execute("RELEASE requeue_target")
            counts[outcome] += 1
            reopened_terminal_files += 1 if reopened else 0
            target_outcomes.append(
                {
                    "file_id": file_id,
                    "file_path": target["file_path"],
                    "queue_item_id": queue_item_id,
                    "outcome": outcome,
                    "detail": detail,
                }
            )

    outcome_by_file = {row["file_id"]: row["outcome"] for row in target_outcomes}
    inputs = [
        {
            "index": index,
            "selector": selector,
            "file_id": file_id,
            "outcome": outcome or outcome_by_file[file_id],
        }
        for index, (selector, file_id, outcome) in enumerate(
            zip(selectors, input_file_ids, input_outcomes, strict=True)
        )
    ]
    return {
        "input_trigger_count": len(items),
        "target_count": len(aggregated),
        **counts,
        "reopened_terminal_files": reopened_terminal_files,
        "not_found": not_found,
        "ambiguous": ambiguous,
        "outcomes": target_outcomes,
        "inputs": inputs,
    }


def list_code_triggers(
    engagement_id: int,
    *,
    status_filter: str | None = None,
    repo_id: int | None = None,
    include_superseded: bool = False,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    if status_filter and status_filter not in _TRIGGER_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid trigger status: {status_filter}",
        )
    clauses = ["t.engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if not include_superseded:
        clauses.extend(
            [
                "t.repo_generation = repos.active_generation",
                "t.source_superseded_at IS NULL",
            ]
        )
    if status_filter:
        clauses.append("t.status = ?")
        params.append(status_filter)
    if repo_id is not None:
        _coerce_int(repo_id, field_name="repo_id")
        clauses.append("sf.repo_id = ?")
        params.append(repo_id)

    source_file_path = "sf.file_path"
    resolved_target_file_path = "tf.file_path"
    generation_file_joins = ""
    if include_superseded:
        source_file_path = "COALESCE(source_generation_file.file_path, sf.file_path)"
        resolved_target_file_path = (
            "COALESCE(target_generation_file.file_path, tf.file_path, t.target_file_path)"
        )
        generation_file_joins = """
            LEFT JOIN code_source_generation_files AS source_generation_file
              ON source_generation_file.engagement_id = t.engagement_id
             AND source_generation_file.repo_id = t.repo_id
             AND source_generation_file.repo_generation = t.repo_generation
             AND source_generation_file.file_id = t.source_file_id
            LEFT JOIN code_source_generation_files AS target_generation_file
              ON target_generation_file.engagement_id = t.engagement_id
             AND target_generation_file.repo_id = t.repo_id
             AND target_generation_file.repo_generation = t.repo_generation
             AND target_generation_file.file_id = t.target_file_id
        """

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, int(repo_id))
        rows = connection.execute(
            f"""
            SELECT
                t.*,
                {source_file_path} AS source_file_path,
                {resolved_target_file_path} AS resolved_target_file_path
            FROM code_analysis_triggers AS t
            JOIN code_files AS sf
              ON sf.id = t.source_file_id
             AND sf.engagement_id = t.engagement_id
            JOIN code_repos AS repos
              ON repos.id = sf.repo_id
             AND repos.engagement_id = sf.engagement_id
             AND repos.active_generation > 0
            LEFT JOIN code_files AS tf
              ON tf.id = t.target_file_id
             AND tf.engagement_id = t.engagement_id
            {generation_file_joins}
            WHERE {' AND '.join(clauses)}
            ORDER BY
                CASE t.status
                    WHEN 'pending' THEN 0
                    WHEN 'queued' THEN 1
                    WHEN 'resolved' THEN 2
                    ELSE 3
                END,
                t.updated_at DESC,
                t.id DESC
            """,
            tuple(params),
        ).fetchall()
    return [dict(row) for row in rows]


def resolve_code_triggers(
    engagement_id: int,
    *,
    items: list[dict[str, Any]],
    resolution_status: str,
    resolution_note: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    normalized_status = resolution_status.strip()
    if normalized_status not in _TERMINAL_TRIGGER_RESOLUTION_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "resolution_status must be one of: "
                + ", ".join(sorted(_TERMINAL_TRIGGER_RESOLUTION_STATUSES))
            ),
        )
    note = resolution_note.strip()
    if not note:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="resolution_note is required",
        )

    resolved = 0
    not_resolved: list[str] = []
    with get_connection() as connection:
        for idx, item in enumerate(items):
            trigger_id = item.get("trigger_id", item.get("id"))
            if trigger_id is not None:
                validated_id = _coerce_int(trigger_id, field_name="trigger_id")
                cursor = connection.execute(
                    """
                    UPDATE code_analysis_triggers
                    SET status = ?,
                        resolution_note = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE engagement_id = ? AND id = ? AND status = ?
                      AND source_superseded_at IS NULL
                      AND repo_generation = (
                          SELECT active_generation
                          FROM code_repos
                          WHERE id = code_analysis_triggers.repo_id
                            AND engagement_id = code_analysis_triggers.engagement_id
                            AND active_generation > 0
                      )
                      AND source_file_id IN (
                          SELECT files.id
                          FROM code_files AS files
                          JOIN code_repos AS repos
                            ON repos.id = files.repo_id
                           AND repos.engagement_id = files.engagement_id
                           AND repos.active_generation > 0
                          WHERE files.engagement_id = ?
                      )
                    """,
                    (
                        normalized_status,
                        note,
                        engagement.id,
                        validated_id,
                        _TRIGGER_STATUS_PENDING,
                        engagement.id,
                    ),
                )
                if cursor.rowcount == 0:
                    not_resolved.append(str(validated_id))
                else:
                    resolved += cursor.rowcount
                continue

            file_path = str(item.get("file_path", item.get("target_file_path", ""))).strip()
            if not file_path:
                not_resolved.append(f"item[{idx}]")
                continue
            vuln_class = str(item.get("vuln_class", "")).strip()
            repo_id = item.get("repo_id")

            clauses = [
                "engagement_id = ?",
                "target_file_path = ?",
                "status = ?",
                "source_superseded_at IS NULL",
                "repo_generation = ("
                "SELECT active_generation FROM code_repos "
                "WHERE id = code_analysis_triggers.repo_id "
                "AND engagement_id = code_analysis_triggers.engagement_id "
                "AND active_generation > 0)",
                "source_file_id IN ("
                "SELECT files.id FROM code_files AS files "
                "JOIN code_repos AS repos ON repos.id = files.repo_id "
                "AND repos.engagement_id = files.engagement_id "
                "AND repos.active_generation > 0 "
                "WHERE files.engagement_id = ?)",
            ]
            params: list[Any] = [
                engagement.id,
                file_path,
                _TRIGGER_STATUS_PENDING,
                engagement.id,
            ]
            if vuln_class:
                clauses.append("vuln_class = ?")
                params.append(vuln_class)
            if repo_id is not None:
                validated_repo_id = _coerce_int(repo_id, field_name="repo_id")
                clauses.append(
                    "source_file_id IN ("
                    "SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ?"
                    ")"
                )
                params.extend([engagement.id, validated_repo_id])

            cursor = connection.execute(
                f"""
                UPDATE code_analysis_triggers
                SET status = ?,
                    resolution_note = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE {' AND '.join(clauses)}
                """,
                (normalized_status, note, *params),
            )
            if cursor.rowcount == 0:
                label = f"{file_path}:{vuln_class}" if vuln_class else file_path
                not_resolved.append(label)
            else:
                resolved += cursor.rowcount

    return {
        "resolved": resolved,
        "items_requested": len(items),
        "total": len(items),
        "not_resolved": not_resolved,
        "resolution_status": normalized_status,
    }


# =========================================================================
# CWE Coverage Detail
# =========================================================================

def code_coverage_cwe_detail(
    engagement_id: int,
    *,
    repo_id: int | None = None,
) -> dict[str, Any]:
    """Return per-file coverage with accumulated CWE coverage from queue done
    records, plus applicable_families computed from file slot_types."""
    engagement = _engagement_or_404(engagement_id)

    repo_clause = """
      AND f.repo_id IN (SELECT id FROM code_repos WHERE active_generation > 0)
      AND f.retired_at IS NULL
    """
    repo_params: tuple[Any, ...] = ()
    if repo_id is not None:
        repo_clause = " AND f.repo_id = ? AND f.retired_at IS NULL"
        repo_params = (repo_id,)

    with get_connection() as connection:
        if repo_id is not None:
            _get_published_repo_row(connection, engagement.id, repo_id)
        # Fetch critical/high files with their slot_types
        file_rows = connection.execute(
            f"""
            SELECT f.id AS file_id, f.file_path, f.classification, f.slot_types_json,
                   f.analysis_status, f.loc, f.language, f.role,
                   f.total_functions, f.total_entry_points, f.total_sinks, f.total_exports
            FROM code_files f
            WHERE f.engagement_id = ? AND f.classification IN ('critical', 'high'){repo_clause}
            ORDER BY f.analysis_priority DESC, f.id ASC
            """,
            (engagement.id, *repo_params),
        ).fetchall()

        # Fetch all done queue items for these files to accumulate cwe_coverage
        file_ids = [int(r["file_id"]) for r in file_rows]
        cwe_by_file: dict[int, dict[str, dict[str, Any]]] = {}  # file_id -> family -> merged entry
        result_effort_by_file: dict[int, dict[str, int]] = {}
        if file_ids:
            placeholders = ",".join("?" for _ in file_ids)
            successful_queue_review = _successful_terminal_review_row_sql("queue")
            queue_done_rows = connection.execute(
                f"""
                SELECT queue.file_id, queue.cwe_coverage_json
                FROM code_analysis_queue AS queue
                JOIN code_files AS queue_files
                  ON queue_files.id = queue.file_id
                 AND queue_files.engagement_id = queue.engagement_id
                JOIN code_repos AS queue_repos
                  ON queue_repos.id = queue_files.repo_id
                 AND queue_repos.engagement_id = queue_files.engagement_id
                WHERE queue.engagement_id = ?
                  AND queue.file_id IN ({placeholders})
                  AND queue.repo_generation = queue_repos.active_generation
                  AND queue.source_superseded_at IS NULL
                  AND ({_latest_current_queue_attempt_sql("queue", "queue_repos")})
                  AND ({_no_superseded_active_attempt_sql("queue", "queue_repos")})
                  AND ({successful_queue_review})
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for qr in queue_done_rows:
                fid = int(qr["file_id"])
                cwe_cov = _json_decode(qr["cwe_coverage_json"], [])
                _merge_cwe_coverage_entries(cwe_by_file, fid, cwe_cov)

            current_result_receipt = _current_result_receipt_sql(
                "results",
                "result_queue",
                "result_files",
                "result_repos",
                allow_processing=True,
            )
            direct_rows = connection.execute(
                f"""
                SELECT results.file_id, results.cwe_coverage_json
                FROM code_analysis_results AS results
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND results.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for dr in direct_rows:
                fid = int(dr["file_id"])
                cwe_cov = _json_decode(dr["cwe_coverage_json"], [])
                _merge_cwe_coverage_entries(cwe_by_file, fid, cwe_cov)

            effort_rows = connection.execute(
                f"""
                SELECT results.file_id,
                       COUNT(DISTINCT results.id) AS current_receipt_rows,
                       COUNT(DISTINCT
                           CASE WHEN trim(results.evidence) != '' OR trim(results.evidence_ref) != ''
                                THEN results.id END
                       ) AS evidenced_receipt_rows
                FROM code_analysis_results AS results
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND results.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                GROUP BY results.file_id
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            result_effort_by_file = {
                int(row["file_id"]): {
                    "current_receipt_rows": int(row["current_receipt_rows"] or 0),
                    "evidenced_receipt_rows": int(row["evidenced_receipt_rows"] or 0),
                    "distinct_structural_callables_reviewed": 0,
                }
                for row in effort_rows
            }
            callable_effort_rows = connection.execute(
                f"""
                SELECT links.file_id,
                       COUNT(DISTINCT links.callable_id)
                           AS distinct_structural_callables_reviewed
                FROM code_analysis_results AS results
                JOIN code_analysis_result_callables AS links
                  ON links.result_id = results.id
                JOIN code_analysis_queue AS result_queue
                  ON result_queue.id = results.queue_item_id
                JOIN code_files AS result_files
                  ON result_files.id = results.file_id
                JOIN code_repos AS result_repos
                  ON result_repos.id = result_files.repo_id
                WHERE results.engagement_id = ?
                  AND links.file_id IN ({placeholders})
                  AND ({current_result_receipt})
                GROUP BY links.file_id
                """,
                (engagement.id, *file_ids),
            ).fetchall()
            for row in callable_effort_rows:
                fid = int(row["file_id"])
                result_effort_by_file.setdefault(
                    fid,
                    {
                        "current_receipt_rows": 0,
                        "evidenced_receipt_rows": 0,
                        "distinct_structural_callables_reviewed": 0,
                    },
                )["distinct_structural_callables_reviewed"] = int(
                    row["distinct_structural_callables_reviewed"] or 0
                )

        files_detail: list[dict[str, Any]] = []
        for fr in file_rows:
            fid = int(fr["file_id"])
            slot_types = _json_decode(fr["slot_types_json"], [])
            applicable = _applicable_families_for_file(
                slot_types,
                language=fr["language"] or "",
                role=fr["role"] or "",
            )
            merged_entries = list(cwe_by_file.get(fid, {}).values())
            total_functions = int(fr["total_functions"] or 0)
            result_effort = result_effort_by_file.get(
                fid,
                {
                    "current_receipt_rows": 0,
                    "evidenced_receipt_rows": 0,
                    "distinct_structural_callables_reviewed": 0,
                },
            )
            distinct_callables = int(
                result_effort["distinct_structural_callables_reviewed"]
            )
            callable_coverage_pct = (
                min(100.0, distinct_callables / total_functions * 100.0)
                if total_functions > 0
                else 0.0
            )
            files_detail.append({
                "file_id": fid,
                "file_path": fr["file_path"],
                "classification": fr["classification"],
                "analysis_status": fr["analysis_status"],
                "loc": int(fr["loc"]),
                "total_functions": total_functions,
                "total_entry_points": int(fr["total_entry_points"] or 0),
                "total_sinks": int(fr["total_sinks"] or 0),
                "total_exports": int(fr["total_exports"] or 0),
                "slot_types": slot_types,
                "applicable_families": applicable,
                "cwe_coverage": merged_entries,
                "analysis_effort": {
                    **result_effort,
                    "total_functions": total_functions,
                    "callable_coverage_pct": round(callable_coverage_pct, 1),
                },
            })

        # Also include the standard coverage summary fields
        summary = code_coverage_summary(engagement_id, repo_id=repo_id)

    return {
        "files": files_detail,
        "total_files": summary["total_files"],
        "by_classification": summary["by_classification"],
        "by_status": summary["by_status"],
        "gate": summary["gate"],
    }
