from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import HTTPException, status

from .artifact_index import _normalize_relative_path
from .state_manager.findings import (
    CODE_SNAPSHOT_PROVENANCE_KEY,
    finding_code_snapshot_status,
    is_file_finding,
)
from .state_manager._common import LEAD_OPEN_STATUSES
from .variant_scopes import (
    variant_parent_finding_set_digest as _variant_parent_finding_set_digest,
)

STRUCTURAL_INPUT_IDENTITY_SCHEMA = "structural-input-identity/v1"
STRUCTURAL_INDEX_SCHEMA = "structural-index/v7"
STRUCTURAL_CALLABLE_IDENTITY_SCHEMA = "structural-callable/v1"
# Dimensions the exact parser can only read inside a callable. When the index
# declares one of them unavailable, the sink and call-site detectors returned
# nothing over source they did not fully read, so the file owes the same
# coverage proof as one with no function registry at all. A cross-tree mirror:
# the single source of truth is `FUNCTION_SCOPED_DIMENSIONS` in
# `agent/scripts/assess/lib/treesitter_index.py`, produced there by
# `_unscanned_scope_dimensions`, and the backend mirrors the agent tree rather
# than importing from it (CODE-MAP.md). Keep the two lists identical.
FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS = frozenset(
    {"call_sites", "dataflow", "security_sinks"}
)
VARIANT_INPUT_IDENTITY_SCHEMA = "variant-input-identity/v1"
MAX_VARIANT_RECEIPT_PAGE = 500
DEFAULT_VARIANT_RECEIPT_PAGE = 100
# Adoption preserves a queue attempt across owners, and every preserved owner is
# walked by the readiness and coverage queries. A row abandoned this often is not
# making progress worth preserving, so the chain is bounded rather than endless.
MAX_ADOPTED_LEASE_CHAIN = 50
# Per-item progress renders a capped receipt list beside the true total.
MAX_PROGRESS_RECEIPTS = 200
# Open-lease worklists follow the capped-list + absolute-count pattern.
MAX_OPEN_LEASE_ROWS = 25

# B8: the repository role is the obligation axis, orthogonal to snapshot
# identity and generation. An `analysis` repository is the reviewed subject —
# every admitted file owes a queue row, a terminal accounting receipt, variant
# coverage and phase readiness. A `reference` repository is host or framework
# source loaded purely so a specialist can resolve a symbol and cite it: it
# stays sealed, indexed, searchable and citable with the same structured source
# identity, and simply never creates work. Reviewing a plugin must not silently
# buy coverage over the framework it plugs into.
ANALYSIS_REPO_ROLE = "analysis"
REFERENCE_REPO_ROLE = "reference"
CODE_REPO_ROLES: tuple[str, ...] = (ANALYSIS_REPO_ROLE, REFERENCE_REPO_ROLE)
# B2: plain-string projection of the canonical lead-disposition StrEnum set for
# SQL binding. The vocabulary itself stays owned by ``state_manager._common``;
# this is a rendering of it, never a second list.
_LEAD_OPEN_STATUS_VALUES: tuple[str, ...] = tuple(
    sorted(str(value) for value in LEAD_OPEN_STATUSES)
)
_LEAD_OPEN_STATUS_PLACEHOLDERS = ",".join("?" for _ in _LEAD_OPEN_STATUS_VALUES)
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
# Mirrors `agent/scripts/assess/lib/code_languages.py:CANONICAL_CODE_LANGUAGES`,
# plus spelling aliases the agent never emits (`c++`). It must be a SUPERSET of
# what ingest can detect: `canonical_structural_language` runs over every file in
# a repository from `structural_input_identity_digest`, so one file in a language
# missing here 400s `code-index sync` for the whole repository. Guarded by
# `orchestrator/backend/tests/test_structural_language_drift.py`.
_CANONICAL_STRUCTURAL_LANGUAGES = frozenset(
    {
        "",
        "blade",
        "c",
        "c++",
        "cpp",
        "freemarker",
        "powershell",
        "python",
        "javascript",
        "typescript",
        "go",
        "rust",
        "java",
        "kotlin",
        "ruby",
        "php",
        "csharp",
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
        unavailable_dimensions = set(
            _json_decode(
                file_rows[file_id].get("structural_unavailable_dimensions_json"), []
            )
        )
        if (
            str(file_rows[file_id].get("structural_analysis_status") or "")
            == "unsupported"
            or "functions"
            in {
                *unavailable_dimensions,
                *_json_decode(
                    file_rows[file_id].get("structural_truncated_dimensions_json"),
                    [],
                ),
            }
        ):
            incomplete_reason = "function registry is incomplete"
        elif unavailable_dimensions & FUNCTION_SCOPED_STRUCTURAL_DIMENSIONS:
            # A partial span has nothing to be read against here: the index
            # never scanned a line of this file for callables or sinks.
            incomplete_reason = "index scanned no function scope"
        else:
            incomplete_reason = ""
        if incomplete_reason and (
            start_line != 1 or end_line != int(file_rows[file_id]["loc"])
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "reviewed spans require whole-file coverage while the structural "
                    f"{incomplete_reason}"
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


def _lease_activity_sql(queue_alias: str) -> str:
    """The one expression that says when a lease last proved it was alive.

    `reset-stale`, the queue listing's heartbeat age and `--stale-minutes`
    filter, and lease adoption all measure abandonment from here, so the same
    window always means the same thing across them. (The two recovery verbs
    then apply their own canonical-attempt guards on top.) `consumed_at` is the
    fallback because a lease claimed but not yet heartbeated has proven life
    once.
    """
    return f"COALESCE({queue_alias}.last_heartbeat_at, {queue_alias}.consumed_at)"


def _lease_activity_age_seconds_sql(queue_alias: str) -> str:
    """Age of that proof of life in whole seconds, on the database clock.

    The comparison has to use the same clock the stored timestamps came from —
    a caller's wall clock would drift against the SQLite `datetime('now')` that
    `reset-stale` selects with. NULL for a row that never held a lease.
    """
    return (
        "CAST(ROUND((julianday('now') - julianday("
        f"{_lease_activity_sql(queue_alias)})) * 86400.0) AS INTEGER)"
    )


def _attempt_owned_result_sql(
    queue_alias: str,
    result_alias: str,
    *,
    match_author: bool,
) -> str:
    """True when a result row belongs to an owner of this queue attempt.

    Ordinarily that owner is the row's current lease. Adoption transfers a
    still-open attempt to a replacement agent *without* discarding the receipts
    the dead lease already wrote, so every adopted lease stays an owner of this
    attempt's receipts — otherwise preserving them would be pointless, since
    coverage, readiness and closeout all match receipts to the queue lease.
    `adopted_leases_json` is '[]' on every row that was never adopted, which
    makes the second branch inert there.

    `match_author` additionally requires the receipt's `agent_name` to be the
    agent that held the matched lease. Callers that already demanded an
    attributable author pass True; callers that only ever matched the lease
    token pass False, so neither gains a requirement it did not have.
    """
    author_clause = (
        f"\n                AND {result_alias}.agent_name = {queue_alias}.assigned_agent"
        if match_author
        else ""
    )
    adopted_author_clause = (
        "\n                      AND json_extract(adopted_lease.value, '$.agent_name')"
        f"\n                          = {result_alias}.agent_name"
        if match_author
        else ""
    )
    return f"""
        (
            (
                {result_alias}.lease_token = {queue_alias}.lease_token{author_clause}
            )
            OR (
                json_valid({queue_alias}.adopted_leases_json)
                AND EXISTS (
                    SELECT 1
                    FROM json_each({queue_alias}.adopted_leases_json) AS adopted_lease
                    WHERE json_extract(adopted_lease.value, '$.lease_token')
                          = {result_alias}.lease_token{adopted_author_clause}
                )
            )
        )
    """


def _current_attempt_result_count_sql(queue_alias: str) -> str:
    """Count the receipts this attempt currently carries.

    Exactly the rows `reset-stale` would supersede, so the number answers the
    question that decides between recovering an abandoned lease and discarding
    it: how much durable work is stranded in this row.
    """
    return f"""
        SELECT COUNT(*)
        FROM code_analysis_results AS attempt_result
        WHERE attempt_result.engagement_id = {queue_alias}.engagement_id
          AND attempt_result.queue_item_id = {queue_alias}.id
          AND attempt_result.superseded_at IS NULL
          AND ({_result_not_replaced_sql("attempt_result")})
    """


def _attempt_lease_tokens(queue_row: dict[str, Any]) -> list[str]:
    """The lease tokens whose receipts belong to this attempt, current first.

    The Python-side counterpart of :func:`_attempt_owned_result_sql`, for the
    closeout queries that bind an explicit token list. A row that was never
    adopted yields exactly its own token, so those checks are unchanged for it.
    """
    tokens = [str(queue_row.get("lease_token") or "")]
    for entry in _json_decode(queue_row.get("adopted_leases_json"), []):
        if not isinstance(entry, dict):
            continue
        token = str(entry.get("lease_token") or "")
        if token and token not in tokens:
            tokens.append(token)
    return tokens


def _valid_claimed_result_receipt_sql(
    queue_alias: str,
    result_alias: str,
) -> str:
    return f"""
        trim({result_alias}.agent_name) != ''
        AND trim({result_alias}.lease_token) != ''
        AND ({_attempt_owned_result_sql(
            queue_alias, result_alias, match_author=True
        )})
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
        AND EXISTS (
                SELECT 1
                FROM code_analysis_results AS source_receipt
                WHERE source_receipt.engagement_id = {queue_alias}.engagement_id
                  AND source_receipt.queue_item_id = {queue_alias}.id
                  AND source_receipt.file_id = {queue_alias}.file_id
                  AND source_receipt.repo_generation = {queue_alias}.repo_generation
                  AND source_receipt.disposition = {queue_alias}.disposition
                  AND ({result_is_current("source_receipt")})
                  AND ({_valid_claimed_result_receipt_sql(
                      queue_alias, "source_receipt"
                  )})
                  AND (
                      (source_receipt.receipt_binding_status = 'empty_file'
                       AND EXISTS (
                           SELECT 1 FROM code_files AS empty_source
                           WHERE empty_source.id = {queue_alias}.file_id
                             AND empty_source.engagement_id = {queue_alias}.engagement_id
                             AND empty_source.loc = 0
                             AND empty_source.file_hash = '{hashlib.sha256(b'').hexdigest()}'
                       ))
                      OR
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
        AND ({_attempt_owned_result_sql(
            queue_alias, result_alias, match_author=False
        )})
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


def _analysis_repo_sql(repos_alias: str) -> str:
    """Restrict an already-joined ``code_repos`` alias to obligation-owning repos."""
    return f"{repos_alias}.repo_role = '{ANALYSIS_REPO_ROLE}'"


def _analysis_repo_files_sql(files_alias: str) -> str:
    """Restrict a ``code_files`` alias to files that carry review obligations.

    For queries that never join ``code_repos`` and would otherwise have to grow
    one just to read the role.
    """
    return (
        f"{files_alias}.repo_id IN ("
        "SELECT id FROM code_repos"
        f" WHERE engagement_id = {files_alias}.engagement_id"
        f" AND {_analysis_repo_sql('code_repos')})"
    )


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
             AND {_analysis_repo_sql("semantic_repo")}
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


# ``code_analysis`` remains the service's public import surface.  Include the
# private helpers as well because its existing workflows resolve them as module
# globals, while callers and tests retain their established import paths.
__all__ = [name for name in globals() if not name.startswith("__")]
