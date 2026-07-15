"""vigil assess record-probe — record ANY probe outcome to the probe ledger.

The single probe-recording verb (it absorbed the former ``record-attempt``). It
POSTs one ``ProbeRunRecordRequest`` to the ``probe-runs`` route for every probe
result_status:

  * COVERING — ``tested`` (the class was exercised to a real verdict) or
    ``signal`` (a positive indicator was seen). These advance the coverage map,
    so a covering probe **requires ``--evidence-ref``** — a covering verdict with
    no evidence is exactly the self-attested signal the doctrine forbids.
  * NON-COVERING — ``attempted`` (the probe fired but proved nothing),
    ``blocked`` (a WAF/auth/egress wall stopped it), ``no-signal`` (nothing
    distinguished the response), ``error`` (the probe itself failed). These
    record that the target was TOUCHED under a ``--lens`` without counting as
    coverage, so the resume brief surfaces them under Attempts and the next
    dispatch does not re-run a dead end. Evidence is optional for these.

Default-on FK cascade (1b): a COVERING probe carrying ``--coverage-item-id``
drains the work-items FK-linked to that coverage item, and one carrying
``--request-variant-id`` advances the discovered surface(s) linked to that
variant to ``partially-covered`` — no extra verbs. ``--work-item-ids`` /
``--resolve-surface`` narrow those to explicit ids; ``--no-drain`` suppresses the
cascade. This replaces the old raw ``vigil assess post probe-runs <json-file>``
(now redirected here). The shared flag set + payload assembly live in
``assess.lib.probe_args``.
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib import probe_args
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import add_contract_subparser, render_contract_epilog


# The full probe result_status vocabulary. The covering pair requires evidence
# (enforced in run()); the non-covering four do not.
_ALL_STATUSES = ("tested", "signal", "attempted", "blocked", "no-signal", "error")
_COVERING_STATUSES = frozenset({"tested", "signal"})


def register(subparsers) -> None:
    p = add_contract_subparser(
        subparsers,
        "record-probe",
        contract_name="record-probe",
        help="Record a probe run (covering tested|signal — evidence required — or non-covering attempted|blocked|no-signal|error).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("record-probe"),
    )
    p.add_argument(
        "--result-status",
        dest="result_status",
        required=True,
        choices=list(_ALL_STATUSES),
        help=(
            "Probe outcome. Covering (advances coverage, requires --evidence-ref): "
            "tested | signal. Non-covering (touched-but-inconclusive lead): "
            "attempted | blocked | no-signal | error."
        ),
    )
    probe_args.add_common_probe_args(p)
    p.set_defaults(func=run)


def run(args) -> None:
    probe_args.enforce_required_inputs(args, "record-probe")
    covering = args.result_status in _COVERING_STATUSES
    if covering and not (args.evidence_ref or "").strip():
        print(
            "record-probe: --evidence-ref is required for a covering probe "
            f"(result_status={args.result_status}) — a covering verdict without "
            "evidence is not coverage. Record a touched-but-inconclusive probe as "
            "--result-status attempted|blocked|no-signal|error instead (evidence "
            "optional), or attach the evidence path.",
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
