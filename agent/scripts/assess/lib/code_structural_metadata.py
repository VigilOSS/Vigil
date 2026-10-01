"""Shared artifact validity for structural builds and metadata publication."""
from __future__ import annotations

from typing import Any

from assess.lib.treesitter_index import (
    STREAMING_FALLBACK_BASELINE_UNAVAILABLE,
    UNSCANNED_SCOPE_DEGRADATION_REASON,
)

STRUCTURAL_DIMENSIONS = {
    "call_sites",
    "classes",
    "dataflow",
    "entry_points",
    "exports",
    "functions",
    "imports",
    "security_sinks",
    "security_sources",
}
SIGNAL_DIMENSIONS = (
    "entry_points",
    "imports",
    "security_sinks",
    "security_sources",
)
STRUCTURAL_RECORD_FIELDS = (
    "functions",
    "entry_points",
    "security_sinks",
    "security_sources",
    "call_sites",
    "imports",
    "import_targets",
    "exports",
    "classes",
)
UNAVAILABLE_RECORD_FIELDS = {
    "functions": ("functions",),
    "entry_points": ("entry_points",),
    "security_sinks": ("security_sinks",),
    "security_sources": ("security_sources",),
    "call_sites": ("call_sites",),
    "imports": ("imports", "import_targets"),
    "exports": ("exports",),
    "classes": ("classes",),
}


def validated_structural_metadata(
    indexed: dict[str, Any],
    *,
    rel_path: str,
    source_size: int,
) -> dict[str, Any]:
    status = indexed.get("analysis_status")
    mode = indexed.get("analysis_mode")
    reason = indexed.get("degradation_reason")
    available = indexed.get("structural_index_available")
    unavailable = indexed.get("unavailable_dimensions")
    truncated = indexed.get("artifact_truncated")
    truncated_dimensions = indexed.get("truncated_dimensions")
    counts = indexed.get("signal_counts")
    if status not in {"complete", "degraded", "unsupported"}:
        raise ValueError(f"structural analysis status is invalid for {rel_path}")
    if mode not in {"tree_sitter", "lightweight_regex", "streaming_security_fallback", "none"}:
        raise ValueError(f"structural analysis mode is invalid for {rel_path}")
    if indexed.get("source_size") != source_size or indexed.get("bytes_scanned") != source_size:
        raise ValueError(f"structural scan byte accounting differs for {rel_path}")
    if not isinstance(available, bool) or not isinstance(truncated, bool):
        raise ValueError(f"structural availability/truncation is invalid for {rel_path}")
    if not isinstance(unavailable, list) or unavailable != sorted(set(unavailable)):
        raise ValueError(f"structural unavailable dimensions are invalid for {rel_path}")
    if not isinstance(truncated_dimensions, list) or truncated_dimensions != sorted(
        set(truncated_dimensions)
    ):
        raise ValueError(f"structural truncated dimensions are invalid for {rel_path}")
    if not set(unavailable).issubset(STRUCTURAL_DIMENSIONS) or not set(
        truncated_dimensions
    ).issubset(STRUCTURAL_DIMENSIONS):
        raise ValueError(f"structural dimensions are unsupported for {rel_path}")
    if truncated != bool(truncated_dimensions) or (truncated and status != "degraded"):
        raise ValueError(f"structural truncation debt is inconsistent for {rel_path}")
    if status == "complete" and (
        not available
        or mode not in {"tree_sitter", "lightweight_regex"}
        or reason
        or unavailable
        or truncated
    ):
        raise ValueError(f"complete structural analysis is inconsistent for {rel_path}")
    if status == "unsupported" and (
        available
        or mode != "none"
        or reason != "unsupported_language"
        or not unavailable
    ):
        raise ValueError(f"unsupported structural analysis is inconsistent for {rel_path}")
    if status == "degraded":
        if mode == "streaming_security_fallback":
            if (
                available
                or not reason
                or not STREAMING_FALLBACK_BASELINE_UNAVAILABLE.issubset(unavailable)
            ):
                raise ValueError(f"streaming fallback debt is incomplete for {rel_path}")
        elif not (
            mode in {"tree_sitter", "lightweight_regex"}
            and available
            and (truncated or unavailable)
            and reason
            == (
                "artifact_signal_limit"
                if truncated
                else UNSCANNED_SCOPE_DEGRADATION_REASON
            )
        ):
            raise ValueError(f"bounded parser debt is inconsistent for {rel_path}")
    if not isinstance(counts, dict) or set(counts) != set(SIGNAL_DIMENSIONS) or any(
        not isinstance(counts.get(dimension), int) or int(counts[dimension]) < 0
        for dimension in SIGNAL_DIMENSIONS
    ):
        raise ValueError(f"structural signal counts are invalid for {rel_path}")
    for field in STRUCTURAL_RECORD_FIELDS:
        if not isinstance(indexed.get(field), list):
            raise ValueError(f"structural {field} records are invalid for {rel_path}")
    if not isinstance(indexed.get("total_functions"), int) or int(
        indexed["total_functions"]
    ) < 0:
        raise ValueError(f"structural function total is invalid for {rel_path}")
    if not isinstance(indexed.get("total_exports"), int) or int(indexed["total_exports"]) < 0:
        raise ValueError(f"structural export total is invalid for {rel_path}")
    if status == "unsupported" and (
        int(indexed["total_functions"]) != 0
        or int(indexed["total_exports"]) != 0
        or any(int(counts[dimension]) for dimension in SIGNAL_DIMENSIONS)
        or any(indexed[field] for field in STRUCTURAL_RECORD_FIELDS)
    ):
        raise ValueError(f"unsupported structural analysis contains signals for {rel_path}")
    retained_counts = {
        "entry_points": len(indexed["entry_points"]),
        "imports": max(len(indexed["imports"]), len(indexed["import_targets"])),
        "security_sinks": len(indexed["security_sinks"]),
        "security_sources": len(indexed["security_sources"]),
    }
    if any(int(counts[dimension]) < retained_counts[dimension] for dimension in SIGNAL_DIMENSIONS):
        raise ValueError(f"structural signal totals undercount retained records for {rel_path}")
    if int(indexed["total_exports"]) < len(indexed["exports"]):
        raise ValueError(f"structural export total undercounts retained records for {rel_path}")
    if (
        "functions" not in {*unavailable, *truncated_dimensions}
        and int(indexed["total_functions"]) != len(indexed["functions"])
    ):
        raise ValueError(
            f"structural function total must match retained callables for {rel_path}"
        )
    # The backend refuses this shape too, but it refuses one `updates` list per
    # repository and names no file, so a single artifact like this takes the
    # whole sync down with an opaque 400. With no callable, the exact parser
    # handed no line to the function-scoped detectors; any other signal proves
    # the file still had source to scan, so `complete` claims a measurement
    # that cannot have happened. No signal at all stays legal -- a blank or
    # comment-only file really does measure empty.
    if (
        status == "complete"
        and mode == "tree_sitter"
        and int(indexed["total_functions"]) == 0
        and (
            int(indexed["total_exports"])
            or any(int(counts[dimension]) for dimension in SIGNAL_DIMENSIONS)
        )
    ):
        raise ValueError(
            "complete structural analysis has no callable scope to have measured "
            f"the source it clearly scanned for {rel_path}"
        )
    unavailable_signals = set(unavailable).intersection(SIGNAL_DIMENSIONS)
    if (
        any(int(counts[dimension]) for dimension in unavailable_signals)
        or ("functions" in unavailable and int(indexed["total_functions"]) != 0)
        or ("exports" in unavailable and int(indexed["total_exports"]) != 0)
        or any(
            any(indexed[field] for field in fields)
            for dimension, fields in UNAVAILABLE_RECORD_FIELDS.items()
            if dimension in unavailable
        )
    ):
        raise ValueError(f"unavailable structural dimension contains signals for {rel_path}")
    if reason is not None and (not isinstance(reason, str) or len(reason) > 128):
        raise ValueError(f"structural degradation reason is invalid for {rel_path}")
    return {
        "structural_analysis_status": status,
        "structural_analysis_mode": mode,
        "structural_degradation_reason": reason,
        "structural_source_size": source_size,
        "structural_bytes_scanned": int(indexed["bytes_scanned"]),
        "structural_unavailable_dimensions": unavailable,
        "structural_artifact_truncated": truncated,
        "structural_truncated_dimensions": truncated_dimensions,
        "structural_signal_counts": counts,
    }


def validated_callable_records(indexed: dict[str, Any], *, rel_path: str) -> list[dict[str, Any]]:
    callable_records: list[dict[str, Any]] = []
    callable_identities: set[tuple[str, int, int]] = set()
    for callable_record in indexed.get("functions", []):
        if not isinstance(callable_record, dict):
            raise ValueError(
                f"structural callable is invalid for {rel_path}"
            )
        source_span = callable_record.get("source_span")
        span = source_span if isinstance(source_span, dict) else callable_record
        name = callable_record.get("name")
        qualified_name = callable_record.get("qualified_name")
        start_line = span.get("start_line", span.get("line_start"))
        end_line = span.get("end_line", span.get("line_end"))
        if (
            not isinstance(name, str)
            or not name
            or name != name.strip()
            or not isinstance(qualified_name, str)
            or not qualified_name
            or qualified_name != qualified_name.strip()
            or type(start_line) is not int
            or type(end_line) is not int
            or start_line < 1
            or end_line < start_line
            or end_line > int(indexed.get("total_lines") or 0)
        ):
            raise ValueError(
                f"structural callable identity is invalid for {rel_path}"
            )
        identity = (qualified_name, start_line, end_line)
        if identity in callable_identities:
            raise ValueError(
                f"structural callable identity is duplicated for {rel_path}"
            )
        callable_identities.add(identity)
        callable_records.append(
            {
                "name": name,
                "qualified_name": qualified_name,
                "start_line": start_line,
                "end_line": end_line,
            }
        )
    return callable_records
