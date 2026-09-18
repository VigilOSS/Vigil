"""vigil assess kali dnsx — typed wrapper around dnsx inside the runtime."""
from __future__ import annotations

import argparse
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from assess.lib.client import AssessError
from assess.lib.kali import (
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
    kali_exec,
)


@dataclass(frozen=True)
class DnsxProfile:
    rate_limit: int
    threads: int
    retry: int
    timeout: int


DNSX_PROFILES: dict[str, DnsxProfile] = {
    "polite-cdn": DnsxProfile(rate_limit=100, threads=20, retry=3, timeout=5),
    "polite-residential": DnsxProfile(rate_limit=300, threads=50, retry=2, timeout=5),
    "bursty-ok": DnsxProfile(rate_limit=500, threads=100, retry=2, timeout=5),
    # Fail-fast profile for the big permutation/brute resolve pass (I-3): a huge
    # candidate set is dominated by dead names, so a single retry + short timeout
    # avoids paying polite-cdn's 3×/5s budget on every miss. Rate/threads match
    # the bursty-ok (documented Docker-safe) ceiling. In the typed `kali dnsx`
    # wrapper this trips the rate guard (it is not named bursty-ok), so a manual
    # high-rate run still requires --allow-unsafe-rate; dns-discovery's resolve
    # stage uses the profile directly for its automated permutation pass.
    "brute-resolve": DnsxProfile(rate_limit=500, threads=100, retry=1, timeout=2),
}

RESOLVER_PROFILES: dict[str, str] = {
    # DNS over TCP avoids the UDP-heavy Docker Desktop path that has crashed
    # laptop runtimes during web engagements.
    "public-tcp": "tcp:1.1.1.1,tcp:8.8.8.8",
    "public-doh": (
        "doh:https://cloudflare-dns.com/dns-query:post,"
        "doh:https://dns.google/dns-query:post"
    ),
    "system": "",
}

POLITE_MAX_RATE_LIMIT = DNSX_PROFILES["polite-residential"].rate_limit
POLITE_MAX_THREADS = DNSX_PROFILES["polite-residential"].threads
BURSTY_MAX_RATE_LIMIT = DNSX_PROFILES["bursty-ok"].rate_limit
BURSTY_MAX_THREADS = DNSX_PROFILES["bursty-ok"].threads
BULK_JSON_RESPONSE_LINE_LIMIT = 1000
GUARDED_EXTRA_ARG_FLAGS = {
    "-j",
    "-json",
    "-r",
    "-resolver",
    "-re",
    "-resp",
    "-rl",
    "-rate-limit",
    "-ro",
    "-resp-only",
    "-t",
    "-threads",
    "-timeout",
    "-w",
    "-wordlist",
}

def _norm_resolve_host(host: str) -> str:
    """Bare comparable host: lowercased, trailing dot stripped; '' for blanks/comments."""
    h = (host or "").strip().lower().rstrip(".")
    return "" if (not h or h.startswith("#")) else h


def resolution_failures(
    resolver_input: Iterable[str], resolved_output: Iterable[str]
) -> list[str]:
    """In-scope hosts that ENTERED a dnsx resolve but produced no A/AAAA record.

    dnsx runs ``-silent``, so a host whose name is known/observed (passive enum,
    Certificate Transparency, brute-validated) but yields no address — e.g. a
    CNAME pointing off-network, or a dangling CNAME (a subdomain-takeover lead)
    — is dropped from the ``-o`` output with no trace. Diffing the resolver
    INPUT host-set against the resolved OUTPUT host-set recovers that gap as a
    sorted, de-duplicated resolution-FAILURE signal instead of a silent drop
    (I-6 / I-006 class: could-not-resolve read as does-not-exist).

    Hosts are compared case-insensitively with a trailing dot stripped;
    blanks/comments are ignored.

    Not the unbounded-permutation-brute hazard guard (a separate code path):
    raw brute guesses never reach this resolve input — puredns validates them
    against its trusted resolvers first, so only observed/validated names are
    diffed here.
    """
    resolved = {h for h in map(_norm_resolve_host, resolved_output) if h}
    failures = {h for h in map(_norm_resolve_host, resolver_input) if h} - resolved
    return sorted(failures)


DNSX_DESCRIPTION = """Run dnsx with audit recording and Docker-safe defaults.

The wrapper is intentionally permissive for normal dnsx usage: common query,
record, filter, and output flags are typed below, and --extra-args remains
available for unmodeled dnsx flags. Only the flags that control Docker/network
load, brute force, resolver transport, or bulk response serialization are
guarded so the safety checks stay visible and auditable.
"""

DNSX_EPILOG = """Profiles:
  default polite-cdn          -> -rl 100 -t 20 -retry 3 -timeout 5
  --dnsx-profile polite-residential
                               -> -rl 300 -t 50 -retry 2 -timeout 5
  --dnsx-profile bursty-ok    -> -rl 500 -t 100 -retry 2 -timeout 5
  --dnsx-profile brute-resolve
                               -> -rl 500 -t 100 -retry 1 -timeout 2
                                  (fail-fast for huge permutation/brute sets;
                                   requires --allow-unsafe-rate in this wrapper)

Opt-in flags:
  --allow-bruteforce          required for -w wordlist active enumeration
  --allow-bulk-json           required for -json with -resp/-resp-only when
                               the -l list is unknown-size or above 1000 rows
  --allow-unsafe-rate         required above the bursty-ok -rl/-t ceiling

Use typed flags for guarded knobs:
  -r, -rl, -t, -retry, -timeout, -w, -resp/-resp-only, -json

Use typed or --extra-args for normal dnsx expansion:
  typed:       -aaaa -mx -txt -ns -soa -ptr -asn -cdn -rcode noerror -wd target.example
  extra args:  --extra-args='-trace -stats'
"""


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "dnsx",
        help="Run dnsx inside the runtime container with audit recording and Docker-safe defaults.",
        description=DNSX_DESCRIPTION,
        epilog=DNSX_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    add_required_kali_flags(p)
    add_passthrough_args_flag(p)
    p.add_argument("-d", dest="domain", default="", help="Single domain.")
    p.add_argument("-l", dest="target_list", default="", help="File of subdomains.")
    p.add_argument(
        "-w",
        dest="wordlist",
        default="",
        help="Wordlist for active enumeration; requires --allow-bruteforce.",
    )
    p.add_argument(
        "-r",
        dest="resolvers",
        default="",
        help="Resolver file or inline resolver list. Overrides --resolver-profile.",
    )
    p.add_argument(
        "-rl",
        dest="rate_limit",
        type=int,
        default=None,
        help="Rate limit per second. Defaults from --dnsx-profile; high values require an opt-in.",
    )
    p.add_argument(
        "-t",
        dest="threads",
        type=int,
        default=None,
        help="Worker threads. Defaults from --dnsx-profile; high values require an opt-in.",
    )
    p.add_argument(
        "-retry",
        dest="retry",
        type=int,
        default=None,
        help="Retry count. Defaults from --dnsx-profile.",
    )
    p.add_argument(
        "-timeout",
        dest="dns_timeout",
        type=int,
        default=None,
        help="Per-query timeout in seconds. Defaults from --dnsx-profile.",
    )
    p.add_argument(
        "--dnsx-profile",
        choices=tuple(DNSX_PROFILES),
        default="polite-cdn",
        help=(
            "Safe default/cap profile for -rl, -t, -retry, and -timeout. "
            "Default polite-cdn is the Docker-safe web-engagement profile."
        ),
    )
    p.add_argument(
        "--resolver-profile",
        choices=tuple(RESOLVER_PROFILES),
        default="public-tcp",
        help="Default resolver transport when -r is not passed. public-tcp avoids Docker UDP churn.",
    )
    p.add_argument(
        "--allow-unsafe-rate",
        action="store_true",
        help="Permit -rl/-t above -rl 500 / -t 100 after explicit operator review.",
    )
    p.add_argument(
        "--allow-bruteforce",
        action="store_true",
        help="Permit -w active DNS enumeration through dnsx after choosing a safe profile.",
    )
    p.add_argument(
        "--allow-bulk-json",
        action="store_true",
        help="Permit -json with -resp/-resp-only when list size is unknown or above the bulk guardrail.",
    )
    p.add_argument("-a", dest="a_records", action="store_true", help="-a A record probe.")
    p.add_argument("-aaaa", dest="aaaa_records", action="store_true", help="-aaaa AAAA record probe.")
    p.add_argument("-cname", dest="cname", action="store_true", help="-cname records.")
    p.add_argument("-mx", dest="mx", action="store_true", help="-mx records.")
    p.add_argument("-txt", dest="txt", action="store_true", help="-txt records.")
    p.add_argument("-ns", dest="ns", action="store_true", help="-ns records.")
    p.add_argument("-soa", dest="soa", action="store_true", help="-soa records.")
    p.add_argument("-ptr", dest="ptr", action="store_true", help="-ptr reverse DNS records.")
    p.add_argument("-asn", dest="asn", action="store_true", help="-asn host ASN information.")
    p.add_argument("-cdn", dest="cdn", action="store_true", help="-cdn CDN name.")
    p.add_argument("-rcode", dest="rcode", default="", help="-rcode filter, e.g. noerror,servfail,refused.")
    p.add_argument("-wd", dest="wildcard_domain", default="", help="-wd wildcard filtering domain.")
    response_group = p.add_mutually_exclusive_group()
    response_group.add_argument(
        "-resp",
        dest="resp",
        action="store_true",
        help="-resp full response.",
    )
    response_group.add_argument(
        "-resp-only",
        dest="resp_only",
        action="store_true",
        help="-resp-only.",
    )
    p.add_argument("-json", dest="output_json", action="store_true", help="-json output.")
    p.add_argument("-omit-raw", dest="omit_raw", action="store_true", help="-omit-raw omit raw DNS response from JSONL.")
    p.add_argument("-silent", dest="silent", action="store_true", help="-silent.")
    p.add_argument("-o", dest="output", default="", help="-o output file.")
    p.set_defaults(func=run)


def _positive_int(value: int | None, flag: str) -> None:
    if value is not None and value <= 0:
        raise AssessError(f"dnsx {flag} must be a positive integer")


def _resolved_tuning(args) -> tuple[int, int, int, int]:
    profile = DNSX_PROFILES[args.dnsx_profile]
    rate_limit = args.rate_limit if args.rate_limit is not None else profile.rate_limit
    threads = args.threads if args.threads is not None else profile.threads
    retry = args.retry if args.retry is not None else profile.retry
    dns_timeout = args.dns_timeout if args.dns_timeout is not None else profile.timeout

    _positive_int(rate_limit, "-rl")
    _positive_int(threads, "-t")
    _positive_int(retry, "-retry")
    _positive_int(dns_timeout, "-timeout")

    if not args.allow_unsafe_rate:
        if args.dnsx_profile != "bursty-ok" and (
            rate_limit > POLITE_MAX_RATE_LIMIT or threads > POLITE_MAX_THREADS
        ):
            raise AssessError(
                "dnsx rate/thread settings exceed the polite-residential ceiling "
                f"(-rl {POLITE_MAX_RATE_LIMIT}, -t {POLITE_MAX_THREADS}); use "
                "--dnsx-profile bursty-ok for the documented bursty profile or "
                "--allow-unsafe-rate for an explicit override"
            )
        if rate_limit > BURSTY_MAX_RATE_LIMIT or threads > BURSTY_MAX_THREADS:
            raise AssessError(
                "dnsx rate/thread settings exceed the bursty-ok ceiling "
                f"(-rl {BURSTY_MAX_RATE_LIMIT}, -t {BURSTY_MAX_THREADS}); pass "
                "--allow-unsafe-rate only after confirming the Docker host and target "
                "can absorb the DNS traffic"
            )

    return rate_limit, threads, retry, dns_timeout


def _local_line_count(path_value: str) -> int | None:
    path = Path(path_value).expanduser()
    if not path.is_file():
        return None
    count = 0
    with path.open("rb") as fh:
        for count, _line in enumerate(fh, start=1):
            if count > BULK_JSON_RESPONSE_LINE_LIMIT:
                break
    return count


def _extra_args_tokens(args) -> list[str]:
    extra = getattr(args, "extra_args", "") or ""
    if not extra:
        return []
    try:
        return shlex.split(extra)
    except ValueError as exc:
        raise AssessError(f"dnsx --extra-args: invalid shell quoting: {exc}") from exc


def _validate_extra_args(args) -> None:
    guarded_hits: list[str] = []
    for token in _extra_args_tokens(args):
        flag = token.split("=", 1)[0]
        if flag in GUARDED_EXTRA_ARG_FLAGS:
            guarded_hits.append(flag)
    if guarded_hits:
        joined = ", ".join(dict.fromkeys(guarded_hits))
        raise AssessError(
            "dnsx --extra-args cannot contain guarded dnsx flags "
            f"({joined}); pass them as typed wrapper flags so Docker-safe "
            "rate, brute-force, resolver, and bulk-response guardrails still run"
        )


def _validate_guards(args) -> None:
    _validate_extra_args(args)

    if args.wordlist and not args.allow_bruteforce:
        raise AssessError(
            "dnsx -w active enumeration is disabled by default because DNS "
            "bruteforce can saturate Docker networking; pass --allow-bruteforce "
            "after choosing an explicit safe profile"
        )

    if (
        args.output_json
        and (args.resp or args.resp_only)
        and args.target_list
        and not args.allow_bulk_json
    ):
        line_count = _local_line_count(args.target_list)
        if line_count is None:
            raise AssessError(
                "dnsx -json with -resp/-resp-only requires --allow-bulk-json "
                "when the target list size cannot be verified locally"
            )
        if line_count > BULK_JSON_RESPONSE_LINE_LIMIT:
            raise AssessError(
                "dnsx -json with -resp/-resp-only on bulk local lists serializes "
                "responses for misses as well as hits; keep the first pass lean or "
                "pass --allow-bulk-json for a deliberate survivor-enrichment run"
            )


def run(args) -> None:
    _validate_guards(args)
    rate_limit, threads, retry, dns_timeout = _resolved_tuning(args)

    cmd: list[str] = ["dnsx"]
    if args.domain:
        cmd.extend(["-d", args.domain])
    if args.target_list:
        cmd.extend(["-l", args.target_list])
    if args.wordlist:
        cmd.extend(["-w", args.wordlist])
    resolvers = args.resolvers or RESOLVER_PROFILES[args.resolver_profile]
    if resolvers:
        cmd.extend(["-r", resolvers])
    cmd.extend(["-rl", str(rate_limit)])
    cmd.extend(["-t", str(threads)])
    cmd.extend(["-retry", str(retry)])
    cmd.extend(["-timeout", str(dns_timeout)])
    if args.a_records:
        cmd.append("-a")
    if args.aaaa_records:
        cmd.append("-aaaa")
    if args.cname:
        cmd.append("-cname")
    if args.mx:
        cmd.append("-mx")
    if args.txt:
        cmd.append("-txt")
    if args.ns:
        cmd.append("-ns")
    if args.soa:
        cmd.append("-soa")
    if args.ptr:
        cmd.append("-ptr")
    if args.asn:
        cmd.append("-asn")
    if args.cdn:
        cmd.append("-cdn")
    if args.rcode:
        cmd.extend(["-rcode", args.rcode])
    if args.wildcard_domain:
        cmd.extend(["-wd", args.wildcard_domain])
    if args.resp:
        cmd.append("-resp")
    if args.resp_only:
        cmd.append("-resp-only")
    if args.output_json:
        cmd.append("-json")
    if args.omit_raw:
        cmd.append("-omit-raw")
    if args.silent:
        cmd.append("-silent")
    if args.output:
        cmd.extend(["-o", args.output])
    extend_cmd_with_extra_args(
        cmd,
        args,
        typed_short_flags={
            "-d",
            "-l",
            "-w",
            "-r",
            "-rl",
            "-t",
            "-retry",
            "-timeout",
            "-a",
            "-aaaa",
            "-cname",
            "-mx",
            "-txt",
            "-ns",
            "-soa",
            "-ptr",
            "-asn",
            "-cdn",
            "-rcode",
            "-wd",
            "-resp",
            "-resp-only",
            "-json",
            "-omit-raw",
            "-silent",
            "-o",
        },
    )

    result = kali_exec(cmd, tool_name="dnsx", **kali_args_to_kwargs(args))
    emit_result(result)
