"""vigil assess scope — scope oracle + list filter.

One dispatcher over the former ``scope-explain`` and ``filter-scope`` verbs
(now ``vigil assess scope <explain|filter>``). Both are pure compositions over
``assess.lib.scope``; the leaf modules keep their own ``run`` entry points.
"""
from __future__ import annotations

import sys

from assess.commands import filter_scope, scope_explain

_ACTION_MODULES = (scope_explain, filter_scope)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "scope",
        help="Scope oracle + list filter: explain | filter",
    )
    sub = p.add_subparsers(dest="scope_action")
    for mod in _ACTION_MODULES:
        mod.register(sub)

    def _print_help(_args) -> None:
        p.print_help()
        sys.exit(1)

    p.set_defaults(func=_print_help)
