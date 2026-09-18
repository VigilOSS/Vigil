"""vigil assess kali tlsx — typed wrapper around tlsx inside the runtime.

Bulk TLS certificate harvester: opens TLS handshakes against hosts/IPs and
pulls SAN, CN, subject-org and issuer fields off the served cert. SAN/CN
expand the subdomain set with names that never appear in CT logs (private-CA
certs); issuer/org + JARM/JA3 fingerprints drive cert pivoting (find sibling
hosts sharing a cert or TLS stack). Complements `cero` (also scrapes SANs) —
tlsx adds structured per-field JSON output and the fingerprints.

tlsx speaks raw TLS, not HTTP, so it carries no attribution header and is in
the required-header SKIP set (see `kali_output._REQUIRED_HEADER_SKIP`) — same
posture as nmap. Read-only handshakes: leave `--destructive` off.
"""
from __future__ import annotations

import sys

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "tlsx",
        help="Run tlsx inside the runtime container with audit recording (TLS SAN/CN/issuer harvest).",
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("target", nargs="?", default="", help="Single host or IP (positional). Mutually usable with -l.")
    p.add_argument("-u", "-host", dest="target_opt", default="", help="Single host/IP (alias for the positional target).")
    p.add_argument("-l", "-list", dest="input_list", default="", help="File of newline-separated hosts/IPs/CIDRs.")
    p.add_argument("-p", "-port", dest="ports", default="", help="Port list to handshake (default tlsx: 443).")
    p.add_argument("-san", dest="san", action="store_true", help="Display certificate Subject Alternative Names.")
    p.add_argument("-cn", dest="cn", action="store_true", help="Display certificate Common Name.")
    p.add_argument("-so", dest="subject_org", action="store_true", help="Display the subject organization (-so).")
    p.add_argument("-cert", dest="cert", action="store_true", help="Display the full certificate (issuer/validity/etc.).")
    p.add_argument("-jarm", dest="jarm", action="store_true", help="Compute the JARM TLS-server fingerprint (cert pivoting).")
    p.add_argument("-ja3", dest="ja3", action="store_true", help="Compute the JA3 TLS fingerprint.")
    p.add_argument("-resp-only", dest="resp_only", action="store_true",
                   help="Emit ONLY the harvested values (clean name list for subdomain expansion).")
    p.add_argument("-c", dest="concurrency", default="", help="Concurrency (tlsx -c).")
    p.add_argument("-json", dest="json_out", action="store_true", help="Structured JSON output (per-field).")
    p.add_argument("-silent", dest="silent", action="store_true", help="Suppress the banner/info logging.")
    p.add_argument("-o", dest="output", default="", help="-o output file (engagement-relative).")
    p.set_defaults(func=run)


def run(args) -> None:
    target = (args.target or args.target_opt or "").strip()
    if not target and not args.input_list:
        print("tlsx: pass <host> / -u <host> or -l <list>", file=sys.stderr)
        raise AssessError("missing <host> or -l")

    cmd: list[str] = ["tlsx"]
    if target:
        cmd.extend(["-u", target])
    if args.input_list:
        cmd.extend(["-l", args.input_list])
    if args.ports:
        cmd.extend(["-p", str(args.ports)])

    # Default to the SAN+CN subdomain-harvest profile when the operator names
    # no field. Issuer/org and JARM/JA3 are opt-in for cert pivoting.
    field_flags: list[str] = []
    if args.san:
        field_flags.append("-san")
    if args.cn:
        field_flags.append("-cn")
    if args.subject_org:
        field_flags.append("-so")
    if args.cert:
        field_flags.append("-cert")
    if args.jarm:
        field_flags.append("-jarm")
    if args.ja3:
        field_flags.append("-ja3")
    default_profile = not field_flags
    if default_profile:
        field_flags = ["-san", "-cn"]
    cmd.extend(field_flags)

    # `-resp-only` yields a clean value list for subdomain expansion. Default
    # it on for the bare SAN/CN harvest, but not for JSON (already structured)
    # or full `-cert` dumps.
    resp_only = args.resp_only or (default_profile and not args.json_out)
    if resp_only and not args.json_out and not args.cert:
        cmd.append("-resp-only")

    if args.concurrency:
        cmd.extend(["-c", str(args.concurrency)])
    if args.json_out:
        cmd.append("-json")
    # Silent by default so the value list is clean; -json/-cert dumps stay
    # verbose only if the operator opts out via --extra-args.
    if args.silent or (not args.json_out):
        cmd.append("-silent")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(cmd, args)

    result = kali_exec(cmd, tool_name="tlsx", **kali_args_to_kwargs(args))
    emit_result(result)
