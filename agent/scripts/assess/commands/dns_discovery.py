"""vigil assess dns-discovery — composable DNS-discovery pipeline.

Runs the DNS discovery methods and merges them into one de-noised, resolved set
so the LLM does not hand-roll the 30-file glue that caused the §7 coverage gap:

    subfinder (passive) + CT (crt.sh) [+ optional puredns brute]
        -> merge + de-noise (PTR/MAC/service-record filter)
        -> dnsx resolve -> resolved hosts

Safe defaults (passive-first, non-recursive subfinder, brute OFF, de-noised
output) but every knob stays a first-class flag (`--recursive`, `--brute`,
`--wordlist`, `--dnsx-profile`, …). Runs synchronously; each tool stage writes
its own audit row via kali_exec. Feed `resolved_hosts.txt` straight into
`vigil assess web-discovery`.
"""
from __future__ import annotations

import shlex
import sys
from pathlib import Path

from assess.commands.kali_dnsx import DNSX_PROFILES, RESOLVER_PROFILES
from assess.lib.config import load_config
from assess.lib.discovery import denoise_hosts
from assess.lib.kali import kali_exec

_DEFAULT_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "dns-discovery",
        help="Pipeline: subfinder + CT (+ optional brute) -> merge/de-noise -> dnsx resolve.",
    )
    p.add_argument("apexes", nargs="+", help="Apex domain(s) to enumerate")
    p.add_argument("--no-passive", dest="no_passive", action="store_true", help="Skip subfinder passive enum.")
    p.add_argument("--no-ct", dest="no_ct", action="store_true", help="Skip the Certificate Transparency (crt.sh) step.")
    p.add_argument("--recursive", action="store_true", help="Pass -recursive to subfinder (dedicated runtime only; saturates a shared daemon).")
    p.add_argument("--subfinder-threads", dest="subfinder_threads", default="20", help="subfinder -t (default 20)")
    p.add_argument("--brute", action="store_true", help="Run a puredns bruteforce pass (OFF by default; skip on wildcard-sink apexes).")
    p.add_argument("--wordlist", default=_DEFAULT_WORDLIST, help="puredns bruteforce wordlist (when --brute).")
    p.add_argument("--dns-rate", dest="dns_rate", default="1500", help="puredns --rate-limit (default 1500)")
    p.add_argument("--dnsx-profile", dest="dnsx_profile", default="polite-cdn", help="dnsx resolve profile (default polite-cdn)")
    p.add_argument("--resolver-profile", dest="resolver_profile", default="public-tcp", help="dnsx resolver profile (default public-tcp)")
    p.add_argument("--dnsx-extra-args", dest="dnsx_extra_args", default="", help="Extra dnsx args (shlex-split).")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800, help="Per-tool --timeout seconds (default 1800)")
    p.set_defaults(func=run)


def _paths(cfg, name: str) -> tuple[Path, str]:
    host = Path(cfg.engagement_dir) / "scans" / "dns-discovery" / name
    container = f"/engagements/{cfg.engagement_key}/scans/dns-discovery/{name}"
    return host, container


def _exec(args, cmd, intent, tool_name):
    res = kali_exec(
        cmd, technique="RECON", intent=intent, probe_kind="fingerprint", phase="recon",
        timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir, tool_name=tool_name,
    )
    if getattr(res, "return_code", 0) not in (0, None):
        print(f"dns-discovery: {tool_name} exited {res.return_code}; continuing with partial output.", file=sys.stderr)
    return res


def _crt_sh_script(apexes: list[str], out_container: str) -> str:
    # Per-apex crt.sh query WITH backoff (crt.sh rate-limits and returns empty
    # 4-byte bodies under load). certspotter is the documented fallback when
    # crt.sh stays empty (see subdomain-enumeration SKILL Phase 0b).
    apex_list = " ".join(shlex.quote(a) for a in apexes)
    return (
        f"for apex in {apex_list}; do "
        "for attempt in 1 2 3; do "
        'out=$(curl -s "https://crt.sh/?q=%25.${apex}&output=json"); '
        '[ "$(printf %s \"$out\" | wc -c)" -gt 8 ] && break; '
        "sleep $((attempt * 5)); "
        "done; "
        "printf %s \"$out\" | jq -r '.[].name_value' 2>/dev/null; "
        "done | sed 's/^\\*\\.//' | sort -u > " + shlex.quote(out_container)
    )


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    out_dir = Path(cfg.engagement_dir) / "scans" / "dns-discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    apexes = [a.strip() for a in args.apexes if a.strip()]

    produced: list[Path] = []

    # --- Stage 1: subfinder passive ---------------------------------------
    if not args.no_passive:
        apex_host, apex_container = _paths(cfg, "apexes.txt")
        apex_host.write_text("\n".join(apexes) + "\n", encoding="utf-8")
        passive_host, passive_container = _paths(cfg, "subs_passive.txt")
        cmd = ["subfinder", "-dL", apex_container, "-all", "-t", str(args.subfinder_threads),
               "-silent", "-o", passive_container]
        if args.recursive:
            cmd.append("-recursive")
        _exec(args, cmd, "dns-discovery: subfinder passive enum", "subfinder")
        produced.append(passive_host)

    # --- Stage 2: Certificate Transparency (crt.sh) -----------------------
    if not args.no_ct:
        ct_host, ct_container = _paths(cfg, "subs_ct.txt")
        _exec(args, ["sh", "-c", _crt_sh_script(apexes, ct_container)],
              "dns-discovery: certificate-transparency harvest (crt.sh)", "crt.sh")
        produced.append(ct_host)

    # --- Stage 3: puredns bruteforce (opt-in) -----------------------------
    if args.brute:
        for apex in apexes:
            brute_host, brute_container = _paths(cfg, f"subs_brute_{apex}.txt")
            cmd = ["puredns", "bruteforce", args.wordlist, apex,
                   "--rate-limit", str(args.dns_rate), "-w", brute_container, "-q"]
            _exec(args, cmd, f"dns-discovery: puredns bruteforce {apex}", "puredns")
            produced.append(brute_host)

    # --- Stage 4: merge + de-noise ----------------------------------------
    merged_lines: list[str] = []
    for path in produced:
        if path.is_file():
            merged_lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
    clean, dropped = denoise_hosts(merged_lines)
    if not clean:
        print("dns-discovery: no hosts discovered after de-noise.", file=sys.stderr)
        sys.exit(0)
    merged_host, merged_container = _paths(cfg, "subs_merged.txt")
    merged_host.write_text("\n".join(clean) + "\n", encoding="utf-8")
    print(f"dns-discovery: {len(clean)} unique hosts after merge+de-noise ({dropped} dropped as noise)", file=sys.stderr)

    # --- Stage 5: dnsx resolve --------------------------------------------
    # Reuse kali_dnsx's profile tables (single source of truth) but emit REAL
    # dnsx flags — the `--dnsx-profile`/`--resolver-profile` names are wrapper-only.
    resolved_host, resolved_container = _paths(cfg, "resolved_hosts.txt")
    profile = DNSX_PROFILES.get(args.dnsx_profile, DNSX_PROFILES["polite-cdn"])
    resolvers = RESOLVER_PROFILES.get(args.resolver_profile, RESOLVER_PROFILES["public-tcp"])
    dnsx_cmd = [
        "dnsx", "-l", merged_container, "-silent", "-o", resolved_container,
        "-rl", str(profile.rate_limit), "-t", str(profile.threads),
        "-retry", str(profile.retry), "-timeout", str(profile.timeout),
    ]
    if resolvers:
        dnsx_cmd.extend(["-r", resolvers])
    if args.dnsx_extra_args:
        dnsx_cmd.extend(shlex.split(args.dnsx_extra_args))
    _exec(args, dnsx_cmd, "dns-discovery: dnsx resolve merged set", "dnsx")

    print(f"dns-discovery: done. Resolved hosts -> {resolved_host}\n"
          f"  Next: vigil assess web-discovery {resolved_host}", file=sys.stderr)
