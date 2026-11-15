"""The trigger list's `supersession_reason` filter accepts every reason the backend writes.

`code_analysis.py` owns the reasons a superseded trigger row carries as its
`_*_REASON` constants; `GET code/triggers` mirrors them as a query Literal. A
reason the backend writes but the filter refuses would make those rows
unreachable by reason, and one the filter accepts but nothing writes would
advertise a selection that always comes back empty.
"""
from __future__ import annotations

import typing


def _literal_values(annotation: object) -> set[str]:
    values: set[str] = set()
    for arg in typing.get_args(annotation):
        if typing.get_origin(arg) is typing.Literal:
            values.update(typing.get_args(arg))
        else:
            values.update(_literal_values(arg))
    return values


def test_supersession_reason_filter_mirrors_the_written_reasons() -> None:
    from app.api.code_analysis import list_code_triggers
    from app.services import code_analysis

    written = {
        value
        for name, value in vars(code_analysis).items()
        if name.startswith("_") and name.endswith("_REASON") and isinstance(value, str)
    }
    annotation = typing.get_type_hints(list_code_triggers)["supersession_reason"]

    assert written
    assert _literal_values(annotation) == written
