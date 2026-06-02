"""vigil assess kali asnmap — typed wrapper around asnmap (ASN → CIDR mapper)."""
from __future__ import annotations

import subprocess
import sys

from assess.lib.client import AssessError, default_runtime_container
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)

# asnmap's data path is gated behind a ProjectDiscovery Cloud (PDCP) API key.
# Without it the tool exits 0 with EMPTY output — indistinguishable from "this
# ASN genuinely announces no CIDRs" — which silently poisons the downstream
# cero TLS-SAN feed. We detect the missing key and fail loud instead.
_PDCP_FALLBACK_GUIDANCE = (
    "asnmap requires a ProjectDiscovery Cloud (PDCP) API key; without it it exits 0 with\n"
    "empty output (looks identical to 'this ASN announces no CIDRs').\n"
    "  Fix: set PDCP_API_KEY in the runtime (free key at cloud.projectdiscovery.io), e.g. add\n"
    "  it to <install>/.env and `vigil runtime start`. Or use a keyless ASN->CIDR path:\n"
    "    Team Cymru :  whois -h whois.cymru.com ' -v <ip>'\n"
    "    RADB       :  whois -h whois.radb.net '!gAS<asn-number>'\n"
    "    ARIN RDAP  :  curl https://rdap.arin.net/registry/ip/<ip>\n"
    "  Pass --allow-no-key to run asnmap anyway."
)


def _runtime_has_pdcp_key(container_name: str | None = None):
    """Probe the runtime for a PDCP API key.

    Returns True if PDCP_API_KEY (env) or a non-empty pdcp credentials file is
    present in the container, False if definitively absent, or None if the probe
    itself could not run (docker unreachable / container down) — in which case
    the caller should not block, only warn.
    """
    # Resolve at call time so VIGIL_RUNTIME_CONTAINER is honoured even if it was
    # set after import; default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    probe = (
        'test -n "$PDCP_API_KEY"'
        ' || test -s "${HOME:-/root}/.config/pdcp/credentials.yaml"'
        ' || test -s /root/.config/pdcp/credentials.yaml'
    )
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", probe],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    # Any other code (125 container-not-running, etc.) — probe inconclusive.
    return None


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "asnmap",
        help="Run asnmap inside the runtime container with audit recording (ASN → CIDR mapper).",
    )
    add_required_kali_flags(p)
    p.add_argument("-d", "--domain", dest="domain", default="", help="Single domain to resolve to ASN.")
    p.add_argument(
        "-l",
        "--input-list",
        dest="input_list",
        default="",
        help="File of domains/IPs (one per line).",
    )
    p.add_argument(
        "-asn",
        dest="asn",
        default="",
        help="ASN identifier passthrough (e.g. AS13335).",
    )
    p.add_argument(
        "-org",
        dest="org",
        default="",
        help="Organization name to resolve when apex ASN lookup fails.",
    )
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent (suppress info).")
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-o", "--output", dest="output", default="", help="-o output file.")
    p.add_argument(
        "--allow-no-key",
        dest="allow_no_key",
        action="store_true",
        help="Run asnmap even when no PDCP_API_KEY is detected in the runtime "
             "(asnmap usually returns empty output without it).",
    )
    add_passthrough_args_flag(p)
    p.set_defaults(func=run)


def run(args) -> None:
    if not args.domain and not args.input_list and not args.asn and not args.org:
        print("asnmap: pass -d <domain>, -l <list>, -asn <ASN>, or -org <name>", file=sys.stderr)
        raise AssessError("missing -d/--domain, -l/--input-list, -asn, or -org")

    if not getattr(args, "allow_no_key", False):
        has_key = _runtime_has_pdcp_key()
        if has_key is False:
            print("asnmap: PDCP_API_KEY is not configured in the runtime.", file=sys.stderr)
            print(_PDCP_FALLBACK_GUIDANCE, file=sys.stderr)
            raise AssessError("asnmap requires PDCP_API_KEY (or pass --allow-no-key)")
        if has_key is None:
            print(
                "asnmap: warning — could not verify PDCP_API_KEY in the runtime; "
                "if it is unset, asnmap will return empty output (see --allow-no-key).",
                file=sys.stderr,
            )

    cmd: list[str] = ["asnmap"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.input_list:
        cmd.extend(["-l", args.input_list])
    if args.asn:
        cmd.extend(["-asn", args.asn])
    if args.org:
        cmd.extend(["-org", args.org])
    if args.silent:
        cmd.append("-silent")
    if args.output_json:
        cmd.append("-json")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="asnmap", **kali_args_to_kwargs(args))
    emit_result(result)
