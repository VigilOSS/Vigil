"""vigil assess record-attempt — record a NON-covering probe attempt.

A specialist runs this to log a probe attempt whose ``result_status`` is
deliberately NON-covering — ``attempted`` (the probe fired but proved nothing),
``blocked`` (a wall stopped it: WAF, auth gate, egress firewall), ``no-signal``
(the target answered but nothing distinguished it), or ``error`` (the probe
itself failed). These four are the "a non-conclusive response is a lead, not a
verdict" statuses: they record that the target was TOUCHED under a given lens
without counting as coverage, so the resume brief surfaces them under Attempts
and the next dispatch does not silently re-run the same dead end.

Covering statuses (``tested`` / ``signal``) are recorded by ``record-probe``
(which requires evidence), not here — this verb intentionally restricts
``--result-status`` to the non-covering set so a covering verdict cannot be
recorded without evidence.

POSTs to the same ``probe-runs`` route the covering path uses. The ``--lens`` is
part of the probe key server-side, so the same target under a different lens is
a distinct attempt (not a dedup hit). Pass ``--finding <slug>`` to backfill the
attempt→finding link (COALESCE-backfilled on a re-run of the same probe). The
shared flag set and payload assembly live in ``assess.lib.probe_args`` so this
verb and ``record-probe`` cannot drift apart.
"""
from __future__ import annotations

import argparse
import json

from assess.lib import probe_args
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import add_contract_subparser, render_contract_epilog


# The non-covering result_status vocabulary. The backend's ProbeRunRecordRequest
# accepts these plus the covering `tested`/`signal`; this verb exposes only the
# non-covering four so a hand-recorded attempt can never masquerade as coverage.
_NONCOVERING_STATUSES = ("attempted", "blocked", "no-signal", "error")


def register(subparsers) -> None:
    p = add_contract_subparser(
        subparsers,
        "record-attempt",
        contract_name="record-attempt",
        help="Record a non-covering probe attempt (attempted|blocked|no-signal|error) under a lens.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("record-attempt"),
    )
    p.add_argument(
        "--result-status",
        dest="result_status",
        required=True,
        choices=list(_NONCOVERING_STATUSES),
        help="Non-covering outcome: attempted | blocked | no-signal | error.",
    )
    probe_args.add_common_probe_args(p, include_links=False)
    p.set_defaults(func=run)


def run(args) -> None:
    probe_args.enforce_required_inputs(args, "record-attempt")
    attack_family = probe_args.normalize_attack_family(args.attack_family, "record-attempt")
    payload = probe_args.build_probe_payload(
        args, attack_family=attack_family, result_status=args.result_status
    )

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if (args.finding or "").strip():
            payload["finding_id"] = probe_args.resolve_finding_id(client, args.finding, "record-attempt")
        result = client.post("probe-runs", payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
