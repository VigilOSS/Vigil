"""vigil assess gau — cache-aware gau pipelines.

One dispatcher over the former ``gau-{endpoints,secrets,js-endpoints}`` verbs
(each is now a ``vigil assess gau <mode>`` subcommand). The three modes share a
gau corpus + cache-key namespace (``assess.lib.gau_pipeline``); the leaf modules
keep their own ``run`` entry points so the recon pipeline can still call them
directly.
"""
from __future__ import annotations

import sys

from assess.commands import gau_endpoints, gau_js_endpoints, gau_secrets

_MODE_MODULES = (gau_endpoints, gau_secrets, gau_js_endpoints)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "gau",
        help="Cache-aware gau pipelines: endpoints | secrets | js-endpoints",
    )
    sub = p.add_subparsers(dest="gau_mode")
    for mod in _MODE_MODULES:
        mod.register(sub)

    def _print_help(_args) -> None:
        p.print_help()
        sys.exit(1)

    p.set_defaults(func=_print_help)
