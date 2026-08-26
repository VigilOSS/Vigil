"""``intel list`` renders superseded rows distinguishably.

The listing includes superseded rows on purpose — they are the audit trail of
what an intel record used to say. But an unmarked superseded row is
byte-identical to the live one, so an agent scanning the list re-opens closed
work against stale facts. Mark it in the RENDERER; the stored ``lead_status``
stays untouched, because rewriting a historical status to satisfy a display is
the record's destruction, not its fix.
"""
from __future__ import annotations

import json

from assess.commands import list_intel


def test_superseded_row_is_labelled_with_the_row_that_replaced_it() -> None:
    rendered = list_intel._format_row(
        {"id": 12, "component": "nginx 1.18", "source_name": "recon", "superseded_by_id": 31}
    )

    assert rendered.startswith("[SUPERSEDED -> 31] ")
    assert "component=nginx 1.18" in rendered


def test_live_row_is_unmarked() -> None:
    rendered = list_intel._format_row(
        {"id": 31, "component": "nginx 1.25", "source_name": "recon", "superseded_by_id": None}
    )

    assert not rendered.startswith("[SUPERSEDED")
    assert rendered == "31 | component=nginx 1.25 | source=recon"


def test_label_survives_the_json_fallback_for_an_unrecognised_shape() -> None:
    row = {"id": 5, "unexpected_key": "value", "superseded_by_id": 9}

    rendered = list_intel._format_row(row)

    assert rendered.startswith("[SUPERSEDED -> 9] ")
    assert json.loads(rendered[len("[SUPERSEDED -> 9] "):]) == row
