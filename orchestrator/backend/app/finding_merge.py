"""Pure validation primitives for finding-merge state."""
from __future__ import annotations


def strict_finding_id(value: object) -> int | None:
    """Return a canonical positive SQLite finding id without coercion.

    SQLite's dynamic typing allows a corrupt legacy FK column to contain REAL,
    TEXT, or BLOB values. Coercing those with ``int()`` can silently redirect a
    merge edge (for example, ``1.5`` to finding id ``1``), so only the type a
    valid INTEGER foreign key actually reads back as is accepted.
    """
    if type(value) is int and value > 0:
        return value
    return None
