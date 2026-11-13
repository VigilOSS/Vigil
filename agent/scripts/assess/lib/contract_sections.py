"""The contract sections a schema refusal prints for the fields it got wrong.

A refusal owes its author the errors, the did-you-mean, and the part of the
contract that fixes them, never the whole verb. This module maps the
validator's error strings to the dotted fields they are about; the sections
themselves come from ``contracts.render_field_sections``, the renderer behind
``vigil assess contract <verb> --field <name>``, so a refusal and the contract
cannot describe one field differently.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

from assess.lib.contracts import (
    _schema_content_node,
    compact_field_line,
    get_contract,
    render_field_sections,
)
from assess.lib.schema_validation import load_schema

_ERROR_PATH_RE = re.compile(r"^(?P<path>[A-Za-z_][\w.\[\]]*)\s")
_DID_YOU_MEAN_RE = re.compile(r"Did you mean:\s*(?P<hints>.+?)\?\s*$")
_IDENTIFIER_RE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_INDEX_RE = re.compile(r"\[\d*\]")


def _schema_for(contract_name: str) -> dict[str, Any]:
    contract = get_contract(contract_name)
    if contract is None or not contract.schema_name.endswith(".schema.json"):
        return {}
    return load_schema(contract.schema_name)


def _property(schema: dict[str, Any], path: str) -> dict[str, Any] | None:
    """The schema node ``path`` names, or None when the schema does not declare it."""
    node: dict[str, Any] = schema
    prop: dict[str, Any] | None = None
    for part in [part for part in path.split(".") if part]:
        properties = node.get("properties")
        prop = properties.get(part) if isinstance(properties, dict) else None
        if not isinstance(prop, dict):
            return None
        node = _schema_content_node(prop)
    return prop


def _section_fields(schema: dict[str, Any], path: str) -> list[str]:
    """The fields whose sections explain ``path``.

    An object field's own section is its whole subtree (``details`` declares ~90
    keys), which is the dump a refusal exists to avoid, so an object stands in
    for its required children; one with none is left to the trailing
    ``--field`` pointer.
    """
    prop = _property(schema, path)
    if prop is None:
        return []
    content = _schema_content_node(prop)
    if not isinstance(content.get("properties"), dict):
        return [path]
    required = content.get("required")
    return [f"{path}.{name}" for name in required] if isinstance(required, list) else []


def _refused_fields(
    contract_name: str, errors: Iterable[str], *, root: str = "payload"
) -> tuple[list[str], list[str]]:
    """The fields whose sections fix ``errors``, and the parents to list keys for.

    A refused unknown key has no section of its own, so its did-you-mean targets
    stand in for it (each tried relative to the key's parent, then from the
    top). One that no target resolves owes its author the keys the parent does
    allow, so that parent is returned in the second list. Every other error
    names its own field.
    """
    schema = _schema_for(contract_name)
    found: list[str] = []
    parents: list[str] = []

    def _add(candidate: str) -> bool:
        fields = _section_fields(schema, _INDEX_RE.sub("", candidate).strip("."))
        for field in fields:
            if field not in found:
                found.append(field)
        return bool(fields) or _property(schema, candidate) is not None

    for error in errors:
        match = _ERROR_PATH_RE.match(error)
        if not match or not match.group("path").startswith(root + "."):
            continue
        path = _INDEX_RE.sub("", match.group("path")[len(root) + 1:])
        if " is not allowed" not in error:
            _add(path)
            continue
        parent = path.rpartition(".")[0]
        hints = _DID_YOU_MEAN_RE.search(error)
        resolved = False
        for token in _IDENTIFIER_RE.findall(hints.group("hints")) if hints else ():
            # A hint into a nested object is spelled from the payload root
            # (`payload.details.evidence` for a top-level `evidence`).
            token = token.removeprefix(root + ".")
            if parent and _add(f"{parent}.{token}"):
                resolved = True
            elif _add(token):
                resolved = True
        if not resolved and parent and parent not in parents and _property(schema, parent) is not None:
            parents.append(parent)
    return found, parents


def offending_fields(
    contract_name: str, errors: Iterable[str], *, root: str = "payload"
) -> list[str]:
    """Dotted fields, in error order, whose contract sections fix ``errors``."""
    return _refused_fields(contract_name, errors, root=root)[0]


def refusal_sections(contract_name: str, errors: Iterable[str]) -> str:
    """The sections for the fields ``errors`` name, ending with the --field pointer.

    An unknown key no did-you-mean resolves is preceded by its parent's compact
    line, which lists every key the parent allows.
    """
    fields, parents = _refused_fields(contract_name, errors)
    sections = render_field_sections(contract_name, fields, strict=False)
    if not parents:
        return sections
    lines = ["Keys these objects allow (`*` = required):"]
    lines.extend(compact_field_line(contract_name, parent) for parent in parents)
    return "\n".join(lines) + "\n\n" + sections
