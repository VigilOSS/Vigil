"""Dynamic fixture and session identity records for engagement-owned PoCs.

Engagement scripts often need the id returned by the object they just created
(``organization``, ``person``, ``subscription``, ...). Hardcoding those values
makes a rotated test tenant silently target a deleted fixture. This manifest
lets a script record an id from the response it just observed and resolve it
later by a named session/fixture alias.

It is not a credential store: only identifiers and provenance are kept, and
session cookies/tokens stay in the credential store. Writes go through a
same-directory temporary file plus ``os.replace`` so a crashed PoC cannot
leave a partially-written manifest.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SCHEMA = "vigil-fixture-manifest/v1"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FIELD_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class FixtureIdentityError(ValueError):
    """Raised when a fixture manifest is malformed or internally ambiguous."""


def _clean_name(value: str, label: str) -> str:
    name = str(value or "").strip()
    if not _NAME_RE.fullmatch(name):
        raise FixtureIdentityError(
            f"{label} must match {_NAME_RE.pattern!r}, got {value!r}"
        )
    return name


def _clean_field(value: str) -> str:
    field = str(value or "").strip().lower()
    if not _FIELD_RE.fullmatch(field):
        raise FixtureIdentityError(f"fixture field is invalid: {value!r}")
    return field


def _clean_id(value: Any) -> str:
    if isinstance(value, (Mapping, list, tuple, set, frozenset)):
        raise FixtureIdentityError("fixture id must be a non-empty scalar")
    if isinstance(value, (bool, bytes, bytearray)) or value is None:
        raise FixtureIdentityError("fixture id must be a non-empty scalar")
    result = str(value).strip()
    # Reject shell/template placeholders. Binding one from a narrative is a
    # fabrication bug and is worse than making the PoC stop visibly.
    if not result or result.startswith("<") or "${" in result or "{" in result:
        raise FixtureIdentityError(f"fixture id is not concrete: {value!r}")
    if len(result) > 512:
        raise FixtureIdentityError("fixture id exceeds 512 characters")
    return result


def _field_for_key(key: str) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
    aliases = {
        "organizationid": "organization_id",
        "organizationref": "organization_id",
        "orgid": "organization_id",
        "personid": "person_id",
        "userid": "person_id",
        "memberid": "person_id",
        "subscriptionid": "subscription_id",
    }
    return aliases.get(normalized)


def _field_for_type(value: Any) -> str | None:
    normalized = re.sub(r"[^a-z0-9]", "", str(value or "").lower())
    return {
        "organization": "organization_id",
        "org": "organization_id",
        "person": "person_id",
        "user": "person_id",
        "member": "person_id",
        "subscription": "subscription_id",
    }.get(normalized)


def extract_fixture_ids(payload: Any) -> dict[str, str]:
    """Extract concrete, semantically named ids from a JSON response.

    Direct ``*_id`` fields and JSON:API ``{type, id}`` objects are supported.
    Bare ``id`` fields are ignored unless their containing object declares a
    recognized ``type``; this avoids accidentally treating an unrelated object
    id as an organization or person id.  Duplicate fields with different values
    are rejected rather than silently selecting one.
    """

    found: dict[str, str] = {}

    def add(field: str, value: Any) -> None:
        clean_field = _clean_field(field)
        clean_value = _clean_id(value)
        previous = found.get(clean_field)
        if previous is not None and previous != clean_value:
            raise FixtureIdentityError(
                f"response contains conflicting {clean_field}: {previous!r} vs {clean_value!r}"
            )
        found[clean_field] = clean_value

    def visit(node: Any) -> None:
        if isinstance(node, list):
            for item in node:
                visit(item)
            return
        if not isinstance(node, Mapping):
            return

        typed_field = _field_for_type(node.get("type"))
        if typed_field and "id" in node:
            add(typed_field, node["id"])
        for key, value in node.items():
            field = _field_for_key(str(key))
            if field:
                add(field, value)
        # JSON:API metadata commonly carries the tenant in meta.parent.
        parent = node.get("parent")
        if isinstance(parent, Mapping) and "id" in parent:
            parent_field = _field_for_type(parent.get("type"))
            if parent_field:
                add(parent_field, parent["id"])
        for value in node.values():
            visit(value)

    visit(payload)
    return found


class FixtureManifest:
    """Named, rotation-safe fixture observations.

    Each alias is normally a session or fixture owner (for example
    ``org3_admin`` or ``webhook_probe``).  A fresh alias can be used for every
    newly-created organization/subscription; an existing alias refuses a
    changed id unless ``replace=True`` is explicit.
    """

    def __init__(self, records: Mapping[str, Mapping[str, Any]] | None = None) -> None:
        self.records: dict[str, dict[str, Any]] = {}
        for name, values in (records or {}).items():
            if not isinstance(values, Mapping):
                raise FixtureIdentityError(f"fixture {name!r} must be an object")
            self.records[_clean_name(name, "fixture name")] = dict(values)
        for name, values in self.records.items():
            for field, value in values.items():
                if field in {"source", "observed_at"}:
                    continue
                _clean_field(field)
                _clean_id(value)

    @classmethod
    def load(cls, path: str | Path) -> "FixtureManifest":
        manifest_path = Path(path)
        try:
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (OSError, json.JSONDecodeError) as exc:
            raise FixtureIdentityError(f"cannot load fixture manifest {manifest_path}: {exc}") from exc
        if not isinstance(document, dict) or document.get("schema") != SCHEMA:
            raise FixtureIdentityError(f"unsupported fixture manifest schema in {manifest_path}")
        records = document.get("fixtures", {})
        if not isinstance(records, dict):
            raise FixtureIdentityError("fixture manifest fixtures must be an object")
        return cls(records)

    def record(
        self,
        name: str,
        field: str,
        value: Any,
        *,
        source: str = "",
        replace: bool = False,
    ) -> str:
        fixture_name = _clean_name(name, "fixture name")
        fixture_field = _clean_field(field)
        fixture_id = _clean_id(value)
        row = self.records.setdefault(fixture_name, {})
        previous = row.get(fixture_field)
        if previous is not None and str(previous) != fixture_id and not replace:
            raise FixtureIdentityError(
                f"fixture {fixture_name}.{fixture_field} already binds {previous!r}; "
                "use a new alias or replace=True after an explicit rotation"
            )
        row[fixture_field] = fixture_id
        if source:
            row["source"] = str(source)
        return fixture_id

    def observe(
        self,
        name: str,
        payload: Any,
        *,
        source: str = "",
        replace: bool = False,
    ) -> dict[str, str]:
        """Record all ids observed in one response and return the extracted ids."""

        values = extract_fixture_ids(payload)
        if not values:
            raise FixtureIdentityError(
                "response contained no recognized concrete fixture ids"
            )
        fixture_name = _clean_name(name, "fixture name")
        staged = {record_name: dict(row) for record_name, row in self.records.items()}
        row = staged.setdefault(fixture_name, {})
        for field, value in values.items():
            fixture_field = _clean_field(field)
            fixture_id = _clean_id(value)
            previous = row.get(fixture_field)
            if previous is not None and str(previous) != fixture_id and not replace:
                raise FixtureIdentityError(
                    f"fixture {fixture_name}.{fixture_field} already binds {previous!r}; "
                    "use a new alias or replace=True after an explicit rotation"
                )
            row[fixture_field] = fixture_id
        if source:
            row["source"] = str(source)
        self.records = staged
        return values

    def require(self, name: str, field: str) -> str:
        fixture_name = _clean_name(name, "fixture name")
        fixture_field = _clean_field(field)
        row = self.records.get(fixture_name)
        if not row or fixture_field not in row:
            raise FixtureIdentityError(f"fixture id is not recorded: {fixture_name}.{fixture_field}")
        return _clean_id(row[fixture_field])

    def save(self, path: str | Path) -> None:
        manifest_path = Path(path)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        document = {"schema": SCHEMA, "fixtures": self.records}
        fd, temporary = tempfile.mkstemp(
            prefix=f".{manifest_path.name}.", suffix=".tmp", dir=manifest_path.parent
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, manifest_path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise


def resolve_fixture_id(manifest: FixtureManifest, reference: str) -> str:
    """Resolve ``<fixture-name>.<field>`` without accepting placeholders."""

    fixture_name, separator, field = str(reference).rpartition(".")
    if not separator or not fixture_name or not field:
        raise FixtureIdentityError(
            f"fixture reference must be '<fixture-name>.<field>', got {reference!r}"
        )
    return manifest.require(fixture_name, field)
