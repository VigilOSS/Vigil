"""vigil assess code-record variant-check — persist a variant-scan receipt."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NoReturn

from assess.lib.client import AssessmentClient
from assess.lib.code_snapshot import MAX_JSON_ARTIFACT_BYTES, read_bounded_regular_file
from assess.lib.config import load_config
from assess.lib.contracts import MAX_VARIANT_PARENT_FINDINGS


_REQUIRED_FIELDS = frozenset(
    {
        "dispatch_id",
        "file_id",
        "repo_id",
        "repo_generation",
        "source_manifest_digest",
        "file_sha256",
        "parent_finding_slugs",
        "status",
        "evidence_ref",
        "rationale",
    }
)
_LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _DuplicateJSONField(ValueError):
    pass


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "variant-check",
        help="Record one completed, dispatch-bound per-file variant check",
    )
    p.add_argument(
        "receipt_json",
        help="Path to one receipt JSON object, or '-' to read it from stdin",
    )
    p.set_defaults(func=run)


def _fail(message: str) -> NoReturn:
    print(f"variant-check: {message}", file=sys.stderr)
    raise SystemExit(1)


def _read_stdin() -> bytes:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    raw = stream.read(MAX_JSON_ARTIFACT_BYTES + 1)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_JSON_ARTIFACT_BYTES:
        _fail(f"receipt input exceeds {MAX_JSON_ARTIFACT_BYTES} bytes")
    return raw


def _read_receipt(source: str) -> bytes:
    if source == "-":
        return _read_stdin()
    try:
        return read_bounded_regular_file(
            Path(source),
            max_bytes=MAX_JSON_ARTIFACT_BYTES,
            label="variant-check receipt input",
        )
    except (OSError, RuntimeError, ValueError) as exc:
        _fail(f"could not read receipt file: {exc}")


def _parse_receipt(raw: bytes) -> dict[str, object]:
    if not raw:
        _fail("receipt input is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        _fail(f"receipt input is not UTF-8: {exc}")
    def reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for key, value in pairs:
            if key in parsed:
                raise _DuplicateJSONField(key)
            parsed[key] = value
        return parsed

    try:
        payload = json.loads(text, object_pairs_hook=reject_duplicate_fields)
    except _DuplicateJSONField as exc:
        _fail(f"duplicate JSON field: {exc}")
    except json.JSONDecodeError as exc:
        _fail(f"receipt input is not valid JSON: {exc}")
    if not isinstance(payload, dict):
        _fail("receipt input must contain one JSON object")
    return payload


def _validate_positive_integer(payload: dict[str, object], field: str) -> None:
    value = payload[field]
    if isinstance(value, bool) or not isinstance(value, int):
        _fail(f"{field} must be an integer")
    if value < 1:
        _fail(f"{field} must be at least 1")


def _validate_bounded_string(
    payload: dict[str, object],
    field: str,
    *,
    maximum: int,
) -> None:
    value = payload[field]
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        _fail(f"{field} must be 1 to {maximum} characters")
    if value != value.strip():
        _fail(f"{field} must not have leading or trailing whitespace")


def _validate_payload(payload: dict[str, object]) -> None:
    keys = set(payload)
    missing = _REQUIRED_FIELDS - keys
    if missing:
        _fail(f"missing required fields: {', '.join(sorted(missing))}")
    unknown = keys - _REQUIRED_FIELDS
    if unknown:
        _fail(f"unknown fields: {', '.join(sorted(unknown))}")

    for field in ("dispatch_id", "file_id", "repo_id"):
        _validate_positive_integer(payload, field)
    _validate_positive_integer(payload, "repo_generation")

    for field in ("source_manifest_digest", "file_sha256"):
        value = payload[field]
        if not isinstance(value, str) or _LOWER_SHA256_RE.fullmatch(value) is None:
            _fail(f"{field} must be a lowercase SHA-256 digest")

    parent_slugs = payload["parent_finding_slugs"]
    if not isinstance(parent_slugs, list):
        _fail("parent_finding_slugs must be a JSON array")
    if len(parent_slugs) > MAX_VARIANT_PARENT_FINDINGS:
        _fail(
            "parent_finding_slugs must contain at most "
            f"{MAX_VARIANT_PARENT_FINDINGS} entries"
        )
    if any(not isinstance(slug, str) or not 1 <= len(slug) <= 256 for slug in parent_slugs):
        _fail("each parent_finding_slugs entry must be 1 to 256 characters")
    if any(slug != slug.strip() for slug in parent_slugs):
        _fail("parent_finding_slugs entries must not have leading or trailing whitespace")
    if any(
        any(ord(character) < 32 or ord(character) == 127 for character in slug)
        for slug in parent_slugs
    ):
        _fail("parent_finding_slugs entries must not contain control characters")
    if len(set(parent_slugs)) != len(parent_slugs):
        _fail("parent_finding_slugs must not contain duplicates")
    if parent_slugs != sorted(parent_slugs):
        _fail("parent_finding_slugs must be sorted")

    if payload["status"] != "completed":
        _fail("status must be 'completed'")
    _validate_bounded_string(payload, "evidence_ref", maximum=4096)
    _validate_bounded_string(payload, "rationale", maximum=20000)


def run(args) -> None:
    payload = _parse_receipt(_read_receipt(args.receipt_json))
    _validate_payload(payload)

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post("code/variant-checks", payload)
    if not isinstance(result, dict):
        _fail("backend response must be a JSON object")
    print(json.dumps(result, indent=2, sort_keys=True))
