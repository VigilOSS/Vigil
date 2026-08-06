"""vigil assess code-record — persist code-analysis outputs.

One dispatcher over the former ``code-record-{analysis,modules,threat-model}``
and ``code-classify`` verbs (each is now a ``vigil assess code-record <kind>``
subcommand). The leaf modules keep their own ``run`` entry points.
"""
from __future__ import annotations

import sys

from assess.commands import (
    code_classify,
    code_record_analysis,
    code_record_fuzz_campaign,
    code_record_fuzz_decision,
    code_record_modules,
    code_record_threat_model,
    code_record_variant_check,
)

_KIND_MODULES = (
    code_record_analysis,
    code_record_modules,
    code_record_threat_model,
    code_classify,
    code_record_variant_check,
    code_record_fuzz_decision,
    code_record_fuzz_campaign,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-record",
        help=(
            "Persist code-analysis outputs: analysis | modules | threat-model | classify | "
            "variant-check | fuzz-decision | fuzz-campaign"
        ),
    )
    sub = p.add_subparsers(dest="code_record_kind")
    for mod in _KIND_MODULES:
        mod.register(sub)

    def _print_help(_args) -> None:
        p.print_help()
        sys.exit(1)

    p.set_defaults(func=_print_help)
