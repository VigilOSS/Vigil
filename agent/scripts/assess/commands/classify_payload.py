"""vigil assess classify-payload — deterministic value-type classifier + mutation oracle.

Classifies a single parameter value into a semantic type and (with
``--mutations``) generates semantically-aware attack variant sets keyed by
intent. Useful for specialist agents that need to probe a parameter without
needing an LLM to invent variants.

Output format:
  Without ``--mutations``: prints the classified type (e.g. ``sequential_id``).
  With ``--mutations``: prints intent → variant lists (human-readable or JSON).
  Add ``--json`` to any form for machine-readable output.
"""
from __future__ import annotations

import json
import sys


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "classify-payload",
        help="Classify a parameter value type and generate attack mutation variants",
    )
    p.add_argument("value", help="Parameter value to classify")
    p.add_argument(
        "--mutations",
        action="store_true",
        default=False,
        help="Also generate intent-keyed attack variants (neighbor, boundary, escalation, format, empty)",
    )
    p.add_argument(
        "--max-per-intent",
        dest="max_per_intent",
        type=int,
        default=5,
        help="Maximum variants per intent bucket (default: 5)",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        default=False,
        help="Emit JSON output (machine-readable)",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    from assess.lib.payload_mutation import classify_value, mutate

    value = args.value
    as_json = bool(getattr(args, "as_json", False))
    show_mutations = bool(getattr(args, "mutations", False))
    max_per_intent = max(1, int(getattr(args, "max_per_intent", 5)))

    if show_mutations:
        result = mutate(value, max_per_intent=max_per_intent)
        if as_json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(f"value: {result['value']!r}")
            print(f"type:  {result['type']}")
            for intent, variants in result["intents"].items():
                if variants:
                    print(f"\n{intent}:")
                    for v in variants:
                        print(f"  {v!r}")
                else:
                    print(f"\n{intent}: (none)")
    else:
        vtype = classify_value(value)
        if as_json:
            print(json.dumps({"value": value, "type": vtype}, ensure_ascii=False))
        else:
            print(vtype)

    sys.stdout.flush()
