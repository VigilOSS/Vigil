"""Name what a finding write's envelope says the backend did on the caller's behalf.

Every ``finding record`` / ``update`` / ``verify`` response carries
``derived: [{field, value, derived_from, detail}]`` (values the service stored
because the write left them out and the rest of it states them) and
``advisories: [{kind, detail}]`` (what the service noticed without refusing).
A caller reading stderr would otherwise never learn that a value was filled in
for it, so each entry is printed there. ``quiet`` silences only the advisories:
a derived value is part of what was stored, so it is always named. A quiet write
still prints one line counting the advisories it left out and naming their kinds,
so the flag never hides that the backend noticed something.
"""
from __future__ import annotations

import sys


def print_write_envelope_notes(label: str, response: object, *, quiet: bool = False) -> None:
    """Print one stderr line per ``derived`` entry and per advisory in ``response``."""
    if not isinstance(response, dict):
        return
    for entry in response.get("derived") or []:
        if isinstance(entry, dict):
            print(f"{label}: derived {entry.get('field')} — {entry.get('detail')}", file=sys.stderr)
    advisories = [row for row in response.get("advisories") or [] if isinstance(row, dict)]
    if quiet:
        if advisories:
            kinds = ", ".join(dict.fromkeys(str(row.get("kind")) for row in advisories))
            print(
                f"{label}: {len(advisories)} advisory(ies) not printed under --quiet "
                f"({kinds}); a write without --quiet prints each one",
                file=sys.stderr,
            )
        return
    for advisory in advisories:
        print(
            f"{label}: advisory [{advisory.get('kind')}] {advisory.get('detail')}",
            file=sys.stderr,
        )
