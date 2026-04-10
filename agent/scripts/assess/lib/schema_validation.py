"""Minimal JSON Schema validation for bundled assessment payload schemas."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when a payload does not satisfy the bundled schema."""


_SCHEMA_DIR = Path(__file__).resolve().parents[3] / "schemas"


def load_schema(schema_name: str) -> dict[str, Any]:
    schema_path = _SCHEMA_DIR / schema_name
    return json.loads(schema_path.read_text(encoding="utf-8"))


def collect_validation_errors(payload: Any, schema: dict[str, Any], *, path: str = "payload") -> list[str]:
    errors: list[str] = []
    _validate_value(payload, schema, path, errors)
    return errors


def validate_payload(payload: Any, schema: dict[str, Any], *, path: str = "payload") -> None:
    errors = collect_validation_errors(payload, schema, path=path)
    if errors:
        raise SchemaValidationError(errors[0])


def _validate_value(value: Any, schema: dict[str, Any], path: str, errors: list[str]) -> None:
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
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                errors.append(f"{path}.{key} is required")
        properties = schema.get("properties", {})
        additional_properties = schema.get("additionalProperties", True)
        if additional_properties is False:
            for key in value:
                if key not in properties:
                    errors.append(f"{path}.{key} is not allowed")
        for key, child_value in value.items():
            child_schema = properties.get(key)
            if isinstance(child_schema, dict):
                _validate_value(child_value, child_schema, f"{path}.{key}", errors)
        return

    if expected_type == "array":
        if not isinstance(value, list):
            errors.append(f"{path} must be an array")
            return
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                _validate_value(item, item_schema, f"{path}[{index}]", errors)
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

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} must be one of {schema['enum']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        minimum = schema.get("minimum")
        if minimum is not None and value < minimum:
            errors.append(f"{path} must be >= {minimum}")
        maximum = schema.get("maximum")
        if maximum is not None and value > maximum:
            errors.append(f"{path} must be <= {maximum}")


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
