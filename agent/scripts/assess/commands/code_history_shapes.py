"""vigil assess code-history check-shapes — admit only cited, semantic bug shapes.

`tools/analysis-state/cve-bug-shapes.jsonl` seeds the Phase 2 variant swarm one
physical line per shape. A shape is admissible when it describes the bug and
its guard in words and cites the `code-history diff` receipt and patch for the
exact vulnerable (first parent) and fixed revisions it names. An identifier or
a commit subject alone is not a shape. A cited diff the budget truncated is
reported, never hidden. The check reads files only; it neither runs Git nor
calls the backend.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from assess.lib.code_history import (
    HISTORY_ARTIFACT_DIR,
    MIN_DESCRIPTIVE_WORDS,
    RECEIPT_SCHEMA,
    SHAPE_CHECK_SCHEMA,
    descriptive_word_count,
    full_object_id,
    repo_relative_path,
)
from assess.lib.code_snapshot import MAX_JSON_ARTIFACT_BYTES, read_bounded_regular_file
from assess.lib.config import resolve_engagement_dir
from assess.lib.render_containment import append_contained_value

_CWE = re.compile(r"^CWE-\d+$")
# Separators `str.splitlines()` honours besides LF. `agent start-swarm` slices
# the file with it, so a record carrying one would split into two work items.
_OTHER_LINE_SEPARATORS = re.compile("[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")
_RECEIPT_SUFFIX = ".receipt.json"
_DESCRIBED_FIELDS = ("bug_pattern", "guard_delta")


def register_check_shapes(subparsers) -> None:
    parser = subparsers.add_parser(
        "check-shapes",
        help="Validate cve-bug-shapes.jsonl against the code-history receipts and patches it cites",
    )
    parser.add_argument("shapes_path", metavar="jsonl", help="Path to cve-bug-shapes.jsonl")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Emit the check as JSON.")
    parser.set_defaults(func=run_check_shapes)


def _read_json_object(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(
            read_bounded_regular_file(path, max_bytes=MAX_JSON_ARTIFACT_BYTES, label="history receipt")
        )
    except (OSError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _sha256(path: Path, limit: int) -> str | None:
    try:
        return hashlib.sha256(read_bounded_regular_file(path, max_bytes=limit, label="history patch")).hexdigest()
    except (OSError, ValueError):
        return None


class _Citations:
    """Resolve evidence references against one engagement's history artifacts."""

    def __init__(self, engagement: Path) -> None:
        self.engagement = engagement
        self.root = engagement.joinpath(*HISTORY_ARTIFACT_DIR)

    def resolve(self, ref: str) -> Path | None:
        """The history artifact *ref* names, or None when it names something else."""
        candidate = Path(ref)
        if not candidate.is_absolute():
            candidate = self.engagement / candidate
        resolved = candidate.resolve()
        return resolved if resolved.is_relative_to(self.root.resolve()) else None

    def relative(self, path: Path) -> str:
        return path.relative_to(self.engagement.resolve()).as_posix()


def _text_errors(shape: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for field in _DESCRIBED_FIELDS:
        value = shape.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{field} is required")
        elif descriptive_word_count(value) < MIN_DESCRIPTIVE_WORDS:
            errors.append(
                f"{field} is identifier-only: describe the code shape in at least "
                f"{MIN_DESCRIPTIVE_WORDS} words beyond advisory ids and hashes"
            )
    return errors


def _field_errors(shape: dict[str, Any]) -> tuple[list[str], dict[str, str | None]]:
    errors: list[str] = []
    if not isinstance(shape.get("shape_id"), str) or not shape["shape_id"].strip():
        errors.append("shape_id is required")
    if not isinstance(shape.get("cwe"), str) or not _CWE.match(shape["cwe"]):
        errors.append("cwe must be one CWE-<number> identifier")
    paths = shape.get("affected_paths")
    if not isinstance(paths, list) or not paths:
        errors.append("affected_paths must be a non-empty list")
    else:
        for path in paths:
            try:
                repo_relative_path(path if isinstance(path, str) else "")
            except ValueError as exc:
                errors.append(f"affected_paths: {exc}")
    revisions = {}
    for field in ("vulnerable_revision", "fixed_revision"):
        revisions[field] = full_object_id(shape.get(field) if isinstance(shape.get(field), str) else "")
        if revisions[field] is None:
            errors.append(f"{field} must be a full commit id from a code-history diff receipt")
    refs = shape.get("evidence_refs")
    if not isinstance(refs, list) or not refs or not all(isinstance(ref, str) and ref for ref in refs):
        errors.append("evidence_refs must list the code-history diff receipt and patch paths")
    return errors + _text_errors(shape), revisions


def _citation_errors(
    shape: dict[str, Any], revisions: dict[str, str | None], citations: _Citations,
) -> tuple[list[str], bool, list[str]]:
    refs = [ref for ref in shape.get("evidence_refs") or [] if isinstance(ref, str) and ref]
    errors: list[str] = []
    cited: dict[Path, str] = {}
    for ref in refs:
        path = citations.resolve(ref)
        if path is None:
            continue  # an advisory or other non-history reference; it is not checked here
        if not path.is_file():
            errors.append(f"cited history artifact does not exist: {ref}")
            continue
        cited[path] = ref
    receipts = []
    for path in cited:
        if not path.name.endswith(_RECEIPT_SUFFIX):
            continue
        receipt = _read_json_object(path)
        if receipt is None or receipt.get("schema") != RECEIPT_SCHEMA:
            errors.append(f"not a {RECEIPT_SCHEMA} receipt: {cited[path]}")
            continue
        if receipt.get("kind") == "diff":
            receipts.append((path, receipt))
    matching = [
        (path, receipt)
        for path, receipt in receipts
        if receipt.get("commit") == revisions["fixed_revision"]
    ]
    if not matching:
        errors.append(
            "no cited code-history diff receipt for fixed_revision; run "
            "`vigil assess code-history diff --commit <fixed_revision>` and cite its receipt and patch"
        )
        return errors, False, []
    truncated = False
    changed: set[str] = set()
    for path, receipt in matching:
        label = citations.relative(path)
        if receipt.get("diff_status") != "available":
            errors.append(
                f"{label}: diff_status {receipt.get('diff_status')!r} has no first-parent vulnerable revision"
            )
            continue
        if receipt.get("first_parent") != revisions["vulnerable_revision"]:
            errors.append(f"{label}: vulnerable_revision is not the fixed commit's first parent")
        output = receipt.get("output") or {}
        patch = citations.engagement / str(output.get("path") or "")
        if patch.resolve() not in cited:
            errors.append(f"{label}: cite its patch {output.get('path')} in evidence_refs")
        elif _sha256(patch, int(output.get("bytes") or 0) + 1) != output.get("sha256"):
            errors.append(f"{label}: patch {output.get('path')} does not match its receipt digest")
        truncation = receipt.get("truncation") or {}
        truncated = truncated or bool(truncation.get("files_truncated") or truncation.get("patch_truncated"))
        changed.update(str(entry["path"]) for entry in receipt.get("files") or [] if "path" in entry)
    unanchored = [path for path in shape.get("affected_paths") or [] if path not in changed]
    if unanchored:
        errors.append(f"affected_paths are not changed by the cited fix: {unanchored}")
    return errors, truncated, [citations.relative(path) for path, _receipt in matching]


def _check(data: bytes, citations: _Citations) -> dict[str, Any]:
    report: dict[str, Any] = {"schema": SHAPE_CHECK_SCHEMA, "errors": [], "lines": []}
    if not data:
        report["errors"].append("the file is empty; omit cve-bug-shapes.jsonl when no shape applies")
    elif not data.endswith(b"\n"):
        report["errors"].append("the last record must end with a newline")
    seen: set[str] = set()
    for number, raw in enumerate(data.split(b"\n")[:-1] if data.endswith(b"\n") else data.split(b"\n"), 1):
        entry: dict[str, Any] = {
            "line": number, "shape_id": None, "errors": [], "evidence_truncated": False, "receipts": [],
        }
        report["lines"].append(entry)
        try:
            text = raw.decode("utf-8")
            shape = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            entry["errors"].append("not one compact JSON object on this physical line")
            continue
        if _OTHER_LINE_SEPARATORS.search(text):
            entry["errors"].append("the record holds a line separator other than LF; write JSON with ASCII escapes")
        if not isinstance(shape, dict):
            entry["errors"].append("each line must be a JSON object")
            continue
        entry["shape_id"] = shape.get("shape_id") if isinstance(shape.get("shape_id"), str) else None
        if entry["shape_id"] in seen:
            entry["errors"].append(f"duplicate shape_id {entry['shape_id']!r}")
        seen.add(entry["shape_id"] or "")
        errors, revisions = _field_errors(shape)
        citation_errors, truncated, receipts = _citation_errors(shape, revisions, citations)
        entry["errors"].extend(errors + citation_errors)
        entry["evidence_truncated"] = truncated
        entry["receipts"] = receipts
    report["shape_count"] = len(report["lines"])
    report["valid"] = not report["errors"] and all(not line["errors"] for line in report["lines"])
    return report


def run_check_shapes(args) -> None:
    engagement = Path(resolve_engagement_dir(getattr(args, "engagement_dir", None))).resolve()
    path = Path(args.shapes_path)
    try:
        data = read_bounded_regular_file(path, max_bytes=MAX_JSON_ARTIFACT_BYTES, label="cve-bug-shapes.jsonl")
    except (OSError, ValueError) as exc:
        print(f"Cannot check bug shapes: {exc}", file=sys.stderr)
        sys.exit(1)
    report = {"path": str(path), **_check(data, _Citations(engagement))}
    if getattr(args, "as_json", False):
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
    else:
        print("\n".join(_lines(report)))
    if not report["valid"]:
        sys.exit(1)


def _lines(report: dict[str, Any]) -> list[str]:
    lines = [f"code-history check-shapes: {report['path']}"]
    lines.extend(f"ERROR {error}" for error in report["errors"])
    for entry in report["lines"]:
        state = "ok" if not entry["errors"] else f"{len(entry['errors'])} error(s)"
        append_contained_value(lines, f"line {entry['line']} ({state}) shape_id:", entry["shape_id"] or "(none)")
        for error in entry["errors"]:
            append_contained_value(lines, "  error:", error)
        if entry["evidence_truncated"]:
            lines.append("  TRUNCATED: a cited diff hit its budget; rerun code-history diff with a larger budget")
    invalid = sum(bool(entry["errors"]) for entry in report["lines"])
    if report["valid"]:
        lines.append(f"{report['shape_count']} shape(s) valid")
    else:
        lines.append(f"{invalid} of {report['shape_count']} shape(s) invalid")
    return lines
