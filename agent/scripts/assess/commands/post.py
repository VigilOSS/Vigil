"""vigil assess post — generic POST for low-frequency endpoints."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.contracts import raw_endpoint_error
from assess.lib.json_inputs import parse_json_argument


_RESPONSE_IDENTITIES: dict[str, tuple[str, ...]] = {
    "credentials": ("credential_key",),
    "credential-tests": ("credential_id", "target_ref", "outcome"),
    "access-records": ("access_key",),
    "blocked-techniques": ("technique_key",),
}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "post",
        help="POST /assessment/{endpoint} with a JSON file or inline JSON payload",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  vigil assess post credentials payload.json\n"
            "  vigil assess post blocked-techniques payload.json"
        ),
    )
    p.add_argument(
        "endpoint",
        help=(
            "credentials, credential-tests, access-records, or blocked-techniques "
            "(typed endpoints such as probe-runs are disabled here)"
        ),
    )
    p.add_argument("payload", nargs="?", help="Path to JSON payload file or inline JSON object/array")
    p.add_argument("--inline", dest="inline_payload", help="Raw JSON payload text")
    p.set_defaults(func=run)


def run(args) -> None:
    raw_payload = args.inline_payload if args.inline_payload is not None else args.payload
    if raw_payload is None:
        print("POST requires a JSON payload file or --inline JSON text", file=sys.stderr)
        sys.exit(1)
    try:
        payload, _ = parse_json_argument(
            raw_payload,
            inline=args.inline_payload is not None,
            description="JSON payload",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    error = raw_endpoint_error("POST", args.endpoint, payload)
    if error:
        print(error, file=sys.stderr)
        sys.exit(1)
    endpoint = args.endpoint.strip("/")
    identity_fields = _RESPONSE_IDENTITIES.get(endpoint)
    if identity_fields is None:
        print(
            f"Raw POST endpoint {args.endpoint!r} has no durable response contract; "
            "use its typed command instead",
            file=sys.stderr,
        )
        sys.exit(1)
    if not isinstance(payload, dict):
        print(f"POST {endpoint} payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post(endpoint, payload)
        require_write_result(
            result,
            operation=f"POST {endpoint}",
            expected={field: payload.get(field) for field in identity_fields},
            positive_ids=("id",),
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
