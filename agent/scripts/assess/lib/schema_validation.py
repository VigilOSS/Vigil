"""Minimal JSON Schema validation for bundled assessment payload schemas."""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a payload does not satisfy the bundled schema."""


_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas"


def load_schema(schema_name: str) -> dict[str, Any]:
    schema_path = _SCHEMA_DIR / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def _suggest_close_match(unknown_field: str, allowed_fields: list[str]) -> str | None:
    """Return a "Did you mean: <c1>, <c2>, <c3>?" hint for an unknown field name.

    Surfaces up to three suggestions joined by ``, `` so a single high-score
    fluke like ``evidence`` -> ``evidence_ref`` doesn't drown out equally
    plausible alternatives such as ``evidence_text`` or ``evidence_paths``.
    The cutoff is loose enough (0.55) to catch typos that previously slipped
    past the 0.6 wall while staying tight enough that genuinely unrelated
    tokens (``fizzbuzz``) still produce no hint.
    """
    if not allowed_fields:
        return None
    matches = difflib.get_close_matches(unknown_field, allowed_fields, n=3, cutoff=0.55)
    if not matches:
        return None
    return ", ".join(matches)


def suggest_close_match(unknown_field: str, allowed_fields: list[str]) -> str | None:
    """Public alias of the difflib close-match suggester (CLI-1 reuse).

    Non-schema callers (e.g. the kali enum-rejection formatter) reuse the exact
    ``difflib.get_close_matches`` behaviour the schema validator uses for unknown
    payload fields, so the "Did you mean: ...?" hint text stays consistent across
    the whole CLI rather than each call site rolling its own fuzzy matcher.
    """
    return _suggest_close_match(unknown_field, allowed_fields)


def collect_validation_errors(payload: Any, schema: dict[str, Any], *, path: str = "payload") -> list[str]:
    errors: list[str] = []
    _validate_value(payload, schema, path, errors)
    return errors


def collect_patch_validation_errors(
    payload: Any, schema: dict[str, Any], *, path: str = "payload"
) -> list[str]:
    """Validate ``payload`` against ``schema`` while skipping ``required`` checks.

    Use this for partial-update payloads (supersede / update) where the backend
    enforces a per-type updatable-column whitelist and natural-key fields are
    intentionally absent. Property-level checks (type, enum, length, did-you-mean
    hints on unknown fields) still apply so typos surface client-side.
    """
    errors: list[str] = []
    if not isinstance(payload, dict):
        errors.append(f"{path} must be an object")
        return errors
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    additional_properties = schema.get("additionalProperties", True) if isinstance(schema, dict) else True
    allowed_keys = sorted(properties.keys()) if isinstance(properties, dict) else []
    if additional_properties is False:
        for key in payload:
            if key not in properties:
                suggestion = _suggest_close_match(key, allowed_keys)
                if suggestion:
                    errors.append(f"{path}.{key} is not allowed. Did you mean: {suggestion}?")
                else:
                    errors.append(f"{path}.{key} is not allowed")
    for key, child_value in payload.items():
        child_schema = properties.get(key) if isinstance(properties, dict) else None
        if isinstance(child_schema, dict):
            _validate_value(child_value, child_schema, f"{path}.{key}", errors)
    return errors


def validate_payload(payload: Any, schema: dict[str, Any], *, path: str = "payload") -> None:
    errors = collect_validation_errors(payload, schema, path=path)
    if errors:
        raise SchemaValidationError(errors[0])


def _schema_passes(value: Any, schema: dict[str, Any], path: str) -> bool:
    """Return True when ``value`` satisfies ``schema`` with no validation errors.

    Used to evaluate ``if`` conditions and ``const`` matches for the
    ``allOf``/``if``-``then``-``else`` support (L4-5). Per JSON Schema draft
    2020-12, a failing ``if`` is not itself an error — it only selects whether
    ``then`` or ``else`` applies — so this collects errors into a throwaway list
    rather than appending to the caller's.
    """
    probe: list[str] = []
    _validate_value(value, schema, path, probe)
    return not probe


def _validate_object_keywords(
    value: dict[str, Any], schema: dict[str, Any], path: str, errors: list[str]
) -> None:
    """Apply ``required``/``additionalProperties``/``properties`` to an object.

    Extracted so it can run both for an explicit ``type: object`` schema and for
    a typeless object subschema — e.g. intel-cve's ``then`` block (L4-5), which
    declares ``required``/``properties`` without a ``type`` keyword. Per JSON
    Schema, these keywords apply to any object instance regardless of ``type``.
    """
    required = schema.get("required", [])
    for key in required:
        if key not in value:
            errors.append(f"{path}.{key} is required")
    properties = schema.get("properties", {})
    additional_properties = schema.get("additionalProperties", True)
    if additional_properties is False:
        allowed_keys = sorted(properties.keys()) if isinstance(properties, dict) else []
        for key in value:
            if key not in properties:
                suggestion = _suggest_close_match(key, allowed_keys)
                if suggestion:
                    errors.append(
                        f"{path}.{key} is not allowed. Did you mean: {suggestion}?"
                    )
                else:
                    errors.append(f"{path}.{key} is not allowed")
    for key, child_value in value.items():
        child_schema = properties.get(key) if isinstance(properties, dict) else None
        if isinstance(child_schema, dict):
            _validate_value(child_value, child_schema, f"{path}.{key}", errors)


def _validate_value(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} must equal {schema['const']!r}")

    expected_type = schema.get("type")
    if isinstance(expected_type, list):
        if any(_matches_json_type(value, item) for item in expected_type):
            expected_type = next(
                (item for item in expected_type if _matches_json_type(value, item)),
                expected_type[0],
            )
        else:
            errors.append(f"{path} must be one of the allowed types: {expected_type}")
            return
    if expected_type == "object":
        if not isinstance(value, dict):
            errors.append(f"{path} must be an object")
            return
        _validate_object_keywords(value, schema, path, errors)
        _validate_applicators(value, schema, path, errors)
        return

    if expected_type == "array":
        if not isinstance(value, list):
            errors.append(f"{path} must be an array")
            return
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_value(item, item_schema, f"{path}[{index}]", errors)
        _validate_applicators(value, schema, path, errors)
        return

    if expected_type == "string":
        if not isinstance(value, str):
            errors.append(f"{path} must be a string")
            return
        min_length = schema.get("minLength")
        if min_length is not None and len(value) < int(min_length):
            errors.append(f"{path} must be at least {min_length} characters")
        max_length = schema.get("maxLength")
        if max_length is not None and len(value) > int(max_length):
            errors.append(f"{path} must be at most {max_length} characters")
    elif expected_type == "integer":
        if isinstance(value, bool) or not isinstance(value, int):
            errors.append(f"{path} must be an integer")
            return
    elif expected_type == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            errors.append(f"{path} must be a number")
            return
    elif expected_type == "boolean":
        if not isinstance(value, bool):
            errors.append(f"{path} must be a boolean")
            return

    # String assertion keywords apply to string instances even when a
    # subschema deliberately omits ``type`` (as conditional ``if`` branches
    # commonly do). Non-string instances ignore ``pattern`` per JSON Schema.
    if isinstance(value, str):
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.search(pattern, value) is None:
            errors.append(f"{path} must match pattern {pattern!r}")

    if (
        expected_type is None
        and isinstance(value, dict)
        and any(k in schema for k in ("required", "properties", "additionalProperties"))
    ):
        _validate_object_keywords(value, schema, path, errors)

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} must be one of {schema['enum']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if minimum is not None and value < minimum:
            errors.append(f"{path} must be >= {minimum}")
        maximum = schema.get("maximum")
        if maximum is not None and value > maximum:
            errors.append(f"{path} must be <= {maximum}")
        exclusive_minimum = schema.get("exclusiveMinimum")
        if exclusive_minimum is not None and value <= exclusive_minimum:
            errors.append(f"{path} must be > {exclusive_minimum}")
        exclusive_maximum = schema.get("exclusiveMaximum")
        if exclusive_maximum is not None and value >= exclusive_maximum:
            errors.append(f"{path} must be < {exclusive_maximum}")

    _validate_applicators(value, schema, path, errors)


def _validate_applicators(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
    """Apply ``allOf`` and ``if``/``then``/``else`` constraints (L4-5).

    ``allOf`` requires the value to satisfy every subschema. ``if``/``then``/
    ``else`` is conditional: when the value matches ``if`` (a condition test
    whose own failures are NOT reported), ``then`` must hold; otherwise ``else``
    must hold. Subschemas may themselves nest applicators, so each is validated
    through the full ``_validate_value`` path.
    """
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for sub_schema in all_of:
            if isinstance(sub_schema, dict):
                _validate_value(value, sub_schema, path, errors)

    if_schema = schema.get("if")
    if isinstance(if_schema, dict):
        if _schema_passes(value, if_schema, path):
            then_schema = schema.get("then")
            if isinstance(then_schema, dict):
                _validate_value(value, then_schema, path, errors)
        else:
            else_schema = schema.get("else")
            if isinstance(else_schema, dict):
                _validate_value(value, else_schema, path, errors)


def _matches_json_type(value: Any, expected_type: str) -> bool:
    if expected_type == "object":
        return isinstance(value, dict)
    if expected_type == "array":
        return isinstance(value, list)
    if expected_type == "string":
        return isinstance(value, str)
    if expected_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected_type == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected_type == "boolean":
        return isinstance(value, bool)
    if expected_type == "null":
        return value is None
    return False
