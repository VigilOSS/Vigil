"""vigil assess record-probe — record a COVERING probe run (tested|signal).

The covering counterpart to ``record-attempt``. A specialist runs this to log a
probe that actually concluded something about a surface: ``tested`` (the class
was exercised to a real verdict) or ``signal`` (a positive indicator was seen).
A covering verdict is what advances the coverage map, so this verb **requires
``--evidence-ref``** — a covering probe with no evidence is exactly the
self-attested signal the doctrine forbids, and the non-covering
``record-attempt`` verb exists for the "touched but inconclusive" case.

This replaces the old raw ``vigil assess post probe-runs <json-file>`` for the
covering path (that raw form is now redirected here). It POSTs the same
``ProbeRunRecordRequest`` to the ``probe-runs`` route; the flag set and payload
assembly are shared with ``record-attempt`` via ``assess.lib.probe_args`` so the
two verbs cannot drift. Pass the canonical ``--request-variant-id`` /
``--service-id`` / ``--coverage-item-id`` from the fetched work-item so the probe
attaches to the exact request and coverage item it satisfies.
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib import probe_args
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


# Covering result_status vocabulary — the two statuses that count as coverage.
# The non-covering four (attempted|blocked|no-signal|error) belong to
# record-attempt, which is why this verb restricts to the covering pair.
_COVERING_STATUSES = ("tested", "signal")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record-probe",
        help="Record a covering probe run (tested|signal); --evidence-ref required.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("record-probe"),
    )
    p.add_argument(
        "--result-status",
        dest="result_status",
        required=True,
        choices=list(_COVERING_STATUSES),
        help="Covering outcome: tested (class exercised to a verdict) | signal (positive indicator).",
    )
    probe_args.add_common_probe_args(p, include_links=True)
    p.set_defaults(func=run)


def run(args) -> None:
    if not (args.evidence_ref or "").strip():
        print(
            "record-probe: --evidence-ref is required for a covering probe "
            "(tested/signal) — a covering verdict without evidence is not "
            "coverage. Use record-attempt for a touched-but-inconclusive probe.",
            file=sys.stderr,
        )
        sys.exit(1)

    attack_family = probe_args.normalize_attack_family(args.attack_family, "record-probe")
    payload = probe_args.build_probe_payload(
        args, attack_family=attack_family, result_status=args.result_status
    )

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if (args.finding or "").strip():
            payload["finding_id"] = probe_args.resolve_finding_id(client, args.finding, "record-probe")
        result = client.post("probe-runs", payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
