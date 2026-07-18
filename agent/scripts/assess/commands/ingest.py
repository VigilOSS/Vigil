"""vigil assess ingest — fold recon output into assessment state.

One dispatcher over the former ``ingest-{endpoints,candidates,spec,arjun,httpx}``
verbs (each is now a ``vigil assess ingest <kind>`` subcommand). The leaf
modules keep their own ``run`` entry points, which the internal recon/gau/js
pipelines still call directly (not via the CLI string), so this registration
change is purely a top-level re-shelving.

Note: ``ingest httpx`` targets the backend host-liveness ledger, not the work
buffer — it is grouped here for discoverability but writes a different table.
"""
from __future__ import annotations

import sys

from assess.commands import (
    ingest_arjun,
    ingest_candidates,
    ingest_endpoints,
    ingest_httpx,
    ingest_spec,
)

_KIND_MODULES = (
    ingest_endpoints,
    ingest_candidates,
    ingest_spec,
    ingest_arjun,
    ingest_httpx,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest",
        help="Fold recon output into assessment state: endpoints | candidates | spec | arjun | httpx",
    )
    sub = p.add_subparsers(dest="ingest_kind")
    for mod in _KIND_MODULES:
        mod.register(sub)

    def _print_help(_args) -> None:
        p.print_help()
        sys.exit(1)

    p.set_defaults(func=_print_help)
