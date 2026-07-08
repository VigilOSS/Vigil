"""vigil assess dns-discovery — composable, convergent DNS-discovery pipeline.

Runs the DNS discovery methods and merges them into one de-noised, resolved set
so the LLM does not hand-roll the 30-file glue that caused the §7 coverage gap:

    subfinder (passive) + CT (crt.sh) [+ optional puredns brute]
        -> merge + de-noise (PTR/MAC/service-record filter)
        -> wildcard pre-strip (per-parent random-label probe)   [CR-17]
        -> dnsx resolve -> resolved hosts
        -> productive-parent recursion (re-brute parents)        [CR-20]
    ... wrapped in a convergence loop until two consecutive passes
        add zero net-new resolved hosts (or --max-passes).       [CR-6]

Safe defaults (passive-first, non-recursive subfinder, brute OFF, de-noised
output) but every knob stays a first-class flag (`--recursive`, `--brute`,
`--wordlist`, `--dnsx-profile`, …). Runs synchronously; each tool stage writes
its own audit row via kali_exec OR the audited host path (`host-exec`) — the
audit rows + ingest are IDENTICAL regardless of where the tool runs.

Runtime routing (CR-4): on macOS Docker Desktop the DNS-heavy stages
(subfinder/puredns/dnsx) auto-route to the audited HOST path so they do not
wedge the userspace-proxy VM (engagement I-001); on native Linux / remote
Docker they stay in the container (transparent no-op). Override with
`--runtime {auto,host,container}`.

Feed `resolved_hosts.txt` straight into `vigil assess web-discovery`. An
in-scope host that ENTERS the resolve but produces no A/AAAA (a CNAME pointing
off-network / a dangling CNAME — a subdomain-takeover lead) is NOT silently
dropped: it is logged and recorded to `resolution_failures.txt` as an explicit
resolution-FAILURE signal (I-6 / I-006: could-not-resolve read as nothing).
"""
from __future__ import annotations

import os
import random
import shlex
import string
import subprocess
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from assess.commands import host_exec
from assess.commands.kali_dnsx import DNSX_PROFILES, RESOLVER_PROFILES, resolution_failures
from assess.lib.config import load_config
from assess.lib.discovery import (
    cluster_productive_parents,
    denoise_hosts,
    wildcard_parent_candidates,
    wordlist_head,
)
from assess.lib.kali import kali_exec
from assess.lib.kali_output import _apply_required_headers, _required_headers
from assess.lib.locking import network_heavy_lock
from assess.lib import runtime_route

_DEFAULT_WORDLIST = "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt"

# The runtime image also bakes a HEAD-capped (500k) n0kovo_subdomains list
# (CT-derived, frequency-ordered) at this path. It is NOT the default — the
# SecLists top-1M list above stays the default — but it is the recommended brute
# list (CR-19): pass `--wordlist /usr/share/wordlists/n0kovo_subdomains_500k.txt`.
# Already pre-capped to 500k, so the --wordlist-head cap is a no-op on it.
_N0KOVO_WORDLIST = "/usr/share/wordlists/n0kovo_subdomains_500k.txt"

# I-3: dnsx resolve profiles. The default resolve profile is the patient,
# CDN-safe 'polite-cdn'. When --brute is active the merged candidate set is
# dominated by mostly-dead permutation labels, so the resolve pass auto-swaps to
# the fail-fast 'brute-resolve' profile (retry=1, timeout=2) to avoid paying
# polite-cdn's 3×/5s retry budget on every dead name — UNLESS the operator
# explicitly chose a non-default --dnsx-profile (their choice is always honored).
_DEFAULT_DNSX_PROFILE = "polite-cdn"
_BRUTE_RESOLVE_PROFILE = "brute-resolve"

# CR-19: default HEAD cap for the brute wordlist. CT-derived / frequency-ordered
# huge lists (n0kovo, 3M) keep real labels in the head and CT-hash/one-off junk
# in the tail; brute the head by default, opt into the tail with --deep-tail.
_DEFAULT_WORDLIST_HEAD = 500_000

# CR-17: how many random nonexistent labels to probe per parent, and the
# fraction that must resolve identically for the parent to count as a sink.
_WILDCARD_PROBE_LABELS = 3

# CR-23: per-engagement DNS query-budget defaults (WARN, not hard-block). A
# brute fans out wordlist_lines × apex_count queries (plus wildcard tests); the
# per-resolver qps is the planned total --rate-limit ÷ healthy-resolver count.
_DEFAULT_QUERY_BUDGET = 5_000_000          # total planned DNS queries per engagement
_DEFAULT_PER_RESOLVER_QPS = 1_500          # advisory ceiling on rate-limit ÷ resolvers

# CR-16/CR-21: output-stall watchdog. Kill a brute whose output file is frozen
# while the process still burns CPU, but scale the idle window to input size so
# a large warm-up (puredns preprocesses the whole input before massdns emits)
# is not falsely killed.
_STALL_BASE_SECONDS = 180
_STALL_PER_100K_LINES = 60                 # +60s of warm-up tolerance per 100k wordlist lines
_STALL_POLL_SECONDS = 15


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "dns-discovery",
        help="Convergent pipeline: subfinder + CT (+ brute/recursion) -> merge/de-noise -> dnsx resolve.",
    )
    p.add_argument("apexes", nargs="+", help="Apex domain(s) to enumerate")
    p.add_argument("--no-passive", dest="no_passive", action="store_true", help="Skip subfinder passive enum.")
    p.add_argument("--no-ct", dest="no_ct", action="store_true", help="Skip the Certificate Transparency (crt.sh) step.")
    p.add_argument("--recursive", action="store_true", help="Pass -recursive to subfinder (dedicated runtime only; saturates a shared daemon).")
    p.add_argument("--subfinder-threads", dest="subfinder_threads", default="20", help="subfinder -t (default 20)")
    p.add_argument("--subfinder-timeout", dest="subfinder_timeout", default="20",
                   help="subfinder -timeout: seconds to wait per source before timing out "
                        "(default 20; bounds one slow/unkeyed source stalling the -all batch, CR-7). "
                        "Pass '' / 0 to use subfinder's own default.")
    p.add_argument("--brute", action="store_true", help="Run a puredns bruteforce pass (OFF by default; skip on wildcard-sink apexes).")
    p.add_argument("--wordlist", default=_DEFAULT_WORDLIST,
                   help=("puredns bruteforce wordlist (when --brute). Defaults to the SecLists "
                         "top-1M list; the runtime image also bakes a HEAD-capped n0kovo list at "
                         f"{_N0KOVO_WORDLIST} (CT-derived, frequency-ordered) — pass that path here "
                         "for the recommended brute (CR-19)."))
    # CR-19 — wordlist HEAD cap (default ON) + deep-tail opt-out.
    p.add_argument("--wordlist-head", dest="wordlist_head", type=int, default=_DEFAULT_WORDLIST_HEAD,
                   help=f"Brute only the first N labels of a frequency-ordered list (default {_DEFAULT_WORDLIST_HEAD}; 0 disables).")
    p.add_argument("--deep-tail", dest="deep_tail", action="store_true",
                   help="Brute the FULL wordlist, ignoring --wordlist-head (CT/frequency-ordered tails are mostly junk).")
    p.add_argument("--dns-rate", dest="dns_rate", default="1500", help="puredns --rate-limit, TOTAL qps across the resolver pool (default 1500)")
    p.add_argument("--dnsx-profile", dest="dnsx_profile", default=_DEFAULT_DNSX_PROFILE,
                   help=f"dnsx resolve profile (default {_DEFAULT_DNSX_PROFILE}; a --brute pass "
                        f"auto-uses the fail-fast '{_BRUTE_RESOLVE_PROFILE}' profile unless overridden here).")
    p.add_argument("--resolver-profile", dest="resolver_profile", default="public-tcp", help="dnsx resolver profile (default public-tcp)")
    p.add_argument("--dnsx-extra-args", dest="dnsx_extra_args", default="", help="Extra dnsx args (shlex-split).")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800, help="Per-tool --timeout seconds (default 1800)")
    # CR-4 — runtime routing. SAFE DEFAULT: `auto` stays in-container (transparent
    # no-op) unless the operator opts into host routing via `--runtime host` or
    # VIGIL_RECON_RUNTIME=host|auto (auto = platform-select: host on macOS Docker
    # Desktop, container elsewhere). This keeps the isolated container path the
    # default and makes host routing a one-flag operator choice (locked posture).
    p.add_argument("--runtime", dest="runtime", choices=("auto", "host", "container"), default="auto",
                   help="Where DNS-heavy stages run. host = audited host path (avoids the macOS "
                        "Docker Desktop proxy wedge); container = isolated runtime (default); auto = "
                        "container unless VIGIL_RECON_RUNTIME opts into host/platform-select.")
    # CR-8/CR-18 — two-tier resolvers (premium-anycast brute, trusted-anycast validate); operator-overridable.
    p.add_argument("--resolvers", dest="resolvers", default="",
                   help="puredns -r brute-tier resolver list (default: shipped premium-anycast.txt).")
    p.add_argument("--resolvers-trusted", dest="resolvers_trusted", default="",
                   help="puredns --resolvers-trusted validation-tier list (default: shipped trusted-anycast.txt).")
    p.add_argument("--no-default-resolvers", dest="no_default_resolvers", action="store_true",
                   help="Do NOT inject the shipped premium/trusted resolver lists when -r/--resolvers-trusted are unset.")
    # CR-6 — convergence loop.
    p.add_argument("--max-passes", dest="max_passes", type=int, default=3,
                   help="Max discover->resolve passes in the convergence loop (default 3).")
    p.add_argument("--no-converge", dest="no_converge", action="store_true",
                   help="Run a single pass (disable the convergence loop).")
    # CR-20 — productive-parent recursion.
    p.add_argument("--no-parent-recursion", dest="no_parent_recursion", action="store_true",
                   help="Disable re-bruting productive 2nd-level parents (CR-20).")
    p.add_argument("--parent-min-children", dest="parent_min_children", type=int, default=5,
                   help="Min distinct children for a parent to be re-bruted (default 5).")
    # CR-17 — wildcard pre-strip.
    p.add_argument("--no-wildcard-strip", dest="no_wildcard_strip", action="store_true",
                   help="Disable per-parent wildcard probing + permutation pre-strip (CR-17).")
    # CR-21 — massdns progress visibility (drop the puredns -q that hides warm-up).
    p.add_argument("--quiet-brute", dest="quiet_brute", action="store_true",
                   help="Pass -q to puredns (hide massdns progress). Default OFF so warm-up/progress is visible (CR-21).")
    # CR-6 — opt-in heavy axes (NOT default-on).
    p.add_argument("--js-host-mining", dest="js_host_mining", action="store_true",
                   help="OPT-IN axis: mine in-scope hostnames from gau --subs URLs and feed them into the resolve loop (CR-6).")
    p.add_argument("--bbot", dest="bbot", action="store_true",
                   help="OPT-IN axis: bbot passive subdomain-enum mop-up, DNS-validated before merge (CR-6/CR-24).")
    # CR-23 — DNS query budget (WARN-only).
    p.add_argument("--query-budget", dest="query_budget", type=int, default=_DEFAULT_QUERY_BUDGET,
                   help=f"Per-engagement total planned DNS-query budget; WARN when a brute would exceed it (default {_DEFAULT_QUERY_BUDGET}).")
    p.add_argument("--per-resolver-qps", dest="per_resolver_qps", type=int, default=_DEFAULT_PER_RESOLVER_QPS,
                   help=f"Advisory per-resolver qps ceiling (total --rate-limit ÷ healthy resolvers); WARN when exceeded (default {_DEFAULT_PER_RESOLVER_QPS}).")
    p.set_defaults(func=run)


def _paths(cfg, name: str) -> tuple[Path, str]:
    host = Path(cfg.engagement_dir) / "scans" / "dns-discovery" / name
    container = f"/engagements/{cfg.engagement_key}/scans/dns-discovery/{name}"
    return host, container


def _warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# Execution: route a stage to the audited HOST path or the in-container path.
# Audit rows + ingest are IDENTICAL either way (CR-4).
# --------------------------------------------------------------------------- #


def _host_dispatch(cmd, *, intent, tool_name, technique, phase, timeout, engagement_dir):
    """Run *cmd* via the audited host path (`host-exec`), same audit fields as kali.

    Reuses host_exec.run() so the run lands in assessment_command_runs with
    route='host_exec'; host_exec.run() ends in sys.exit(rc), so we catch
    SystemExit and synthesize a result object with the same .return_code shape
    callers expect from kali_exec.

    Program-mandated attribution headers are applied here with the SAME
    injectable/skip classifier kali_exec uses (``_apply_required_headers``).
    Every dns-discovery host tool (dnsx/subfinder/puredns/...) is in the
    skip-set, so this is a silent no-op that correctly keeps the researcher
    handle off DNS/passive endpoints; the call is kept for parity with the
    web-discovery host path and to future-proof an HTTP tool ever routed here.
    """
    cmd = list(cmd)
    _req_headers = _required_headers(Path(engagement_dir)) if engagement_dir else {}
    if _req_headers:
        status = _apply_required_headers(cmd, tool_name, _req_headers)
        if status == "warned":
            names = ", ".join(_req_headers)
            _warn(
                f"program requires header(s) {names} but host-routed tool "
                f"'{tool_name}' has no known -H injection — this run will NOT "
                "carry the required header; inject it manually if it reaches the "
                "in-scope target."
            )
    ns = SimpleNamespace(
        command=list(cmd),
        tool=tool_name,
        intent=intent,
        technique=technique or "RECON",
        phase=phase or "recon",
        target_host="",
        agent_name=None,
        scope_host="",
        cwd=None,
        timeout=int(timeout),
        audit_source="header",
        from_json=None,
        allow_destructive=False,
        require_audit=False,
        engagement_dir=engagement_dir,
    )
    rc = 0
    try:
        host_exec.run(ns)
    except SystemExit as exc:  # host_exec.run always exits with the wrapped rc
        code = exc.code
        rc = code if isinstance(code, int) else (0 if code in (None, "") else 1)
    return SimpleNamespace(return_code=rc)


def _exec(args, cmd, intent, tool_name, *, route="container"):
    """Run a stage in-container (kali_exec) or on the host (host-exec), per *route*.

    The CR-16/CR-21 output-stall watchdog is applied separately by
    :func:`_brute_exec_with_stall` for the brute path; this helper is the plain
    stage runner used by every non-brute stage.
    """
    if route == "host":
        res = _host_dispatch(
            cmd, intent=intent, tool_name=tool_name, technique="RECON",
            phase="recon", timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir,
        )
    else:
        res = kali_exec(
            cmd, technique="RECON", intent=intent, probe_kind="fingerprint", phase="recon",
            timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir, tool_name=tool_name,
        )
    if getattr(res, "return_code", 0) not in (0, None):
        print(f"dns-discovery: {tool_name} exited {res.return_code}; continuing with partial output.", file=sys.stderr)
    return res


# --------------------------------------------------------------------------- #
# CR-16/CR-21 — output-stall watchdog around the (blocking) brute exec.
# --------------------------------------------------------------------------- #


def _descendant_pids(root_pid: int) -> set[int]:
    """Best-effort set of PIDs that descend from *root_pid* (children, grandchildren,
    …), via repeated ``pgrep -P``. Returns an empty set if ``pgrep`` is unavailable.

    Used to scope the stall-kill (I-009) to the process tree *this* dns-discovery
    invocation actually launched: the host brute runs as a child of this Python
    process (host_exec.run → subprocess.run(["puredns", …])) and puredns spawns
    massdns beneath it, so both are descendants here.
    """
    seen: set[int] = set()
    frontier = [root_pid]
    while frontier:
        parent = frontier.pop()
        try:
            res = subprocess.run(
                ["pgrep", "-P", str(parent)],
                capture_output=True, text=True, check=False, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            break
        for line in res.stdout.split():
            try:
                child = int(line)
            except ValueError:
                continue
            if child not in seen:
                seen.add(child)
                frontier.append(child)
    return seen


def _kill_brute_processes(route: str) -> None:
    """Best-effort kill of a frozen puredns/massdns process tree so the blocking
    brute exec returns.

    Host route → kill ONLY the massdns/puredns processes that descend from this
    dns-discovery process (the brute this stage launched), never a host-wide
    ``pkill -f`` that would also reap a concurrent engagement's brute or an
    unrelated operator job sharing the host. Container route → ``docker exec <c>
    pkill`` (the runtime container is Vigil's own single-tenant container)."""
    targets = ("massdns", "puredns")
    try:
        if route == "host":
            descendants = _descendant_pids(os.getpid())
            if not descendants:
                return
            for name in targets:
                try:
                    matched = subprocess.run(
                        ["pgrep", "-f", name],
                        capture_output=True, text=True, check=False, timeout=10,
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                for line in matched.stdout.split():
                    try:
                        pid = int(line)
                    except ValueError:
                        continue
                    if pid in descendants:
                        subprocess.run(["kill", "-9", str(pid)],
                                       capture_output=True, check=False, timeout=10)
        else:
            from assess.lib.client import default_runtime_container
            container = default_runtime_container()
            for name in targets:
                subprocess.run(["docker", "exec", container, "pkill", "-9", "-f", name],
                               capture_output=True, check=False, timeout=10)
    except (OSError, subprocess.SubprocessError):
        pass


def _brute_exec_with_stall(args, cmd, intent, tool_name, *, route, out_host: Path,
                           window_s: int) -> bool:
    """Run a brute stage under an output-stall watchdog (CR-16/I-009).

    A background thread polls *out_host* size+mtime; if it has not grown for
    *window_s* seconds while the blocking exec is still running, it kills the
    massdns/puredns tree (route-appropriate) so the exec returns, and surfaces a
    distinct STALL error. *window_s* is scaled to the wordlist size by the caller
    (CR-21) so a large warm-up is not falsely killed. Returns True when a stall
    was detected+killed. Never raises.
    """
    if window_s <= 0 or os.environ.get("VIGIL_KALI_NOOP"):
        # Watchdog disabled / test no-op: run the stage plainly.
        _exec(args, cmd, intent, tool_name, route=route)
        return False

    stalled = {"hit": False}
    done = threading.Event()

    def _watch() -> None:
        last_size = -1
        last_change = time.monotonic()
        while not done.wait(_STALL_POLL_SECONDS):
            try:
                size = out_host.stat().st_size if out_host.is_file() else 0
            except OSError:
                size = last_size
            now = time.monotonic()
            if size != last_size:
                last_size = size
                last_change = now
                continue
            if now - last_change >= window_s:
                stalled["hit"] = True
                _kill_brute_processes(route)
                _warn(
                    f"STALL: {tool_name} output frozen > {window_s}s while the process "
                    "burned on (dead-resolver hot-loop / I-009); killed the brute. "
                    "Validate the -r resolver list or use the shipped premium-anycast tier (CR-16)."
                )
                return

    watcher = threading.Thread(target=_watch, daemon=True)
    watcher.start()
    try:
        _exec(args, cmd, intent, tool_name, route=route)
    finally:
        done.set()
        watcher.join(timeout=2)
    return stalled["hit"]


# CR-4 routing policy (resolves the open "auto = host-by-default?" question per the
# locked posture: container path is a transparent NO-OP unless the operator opts
# into host routing). Precedence, highest first:
#   1. --runtime host|container          (explicit per-invocation operator choice)
#   2. VIGIL_RECON_RUNTIME=host|container (engagement/session override)
#   3. VIGIL_RECON_RUNTIME=auto           (platform auto-select: host on macOS
#                                          Docker Desktop, container elsewhere)
#   4. --runtime auto with no env         (SAFE DEFAULT: container — unchanged
#                                          behavior; operator opts into host)
# Foundations' resolve_runtime() still does the host-binary-present fallback +
# Docker-Desktop detection, so a host route with a missing binary degrades to
# container with a WARN (never a hard-fail).
_RECON_RUNTIME_ENV = "VIGIL_RECON_RUNTIME"


def _route_for(args, tool: str) -> str:
    requested = (getattr(args, "runtime", "auto") or "auto").strip().lower()
    if requested in ("host", "container"):
        return runtime_route.resolve_runtime(requested, tool=tool)
    # requested == auto: defer to the env opt-in; absent → container (safe no-op).
    env = os.environ.get(_RECON_RUNTIME_ENV, "").strip().lower()
    if env in ("host", "container", "auto"):
        return runtime_route.resolve_runtime(env, tool=tool)
    return "container"


# --------------------------------------------------------------------------- #
# Resolver-list resolution (CR-8/CR-18) — host path uses the shipped HOST file;
# container path stages the file under the engagement dir and uses /engagements.
# --------------------------------------------------------------------------- #


def _stage_resolver_list(cfg, src: Path, name: str, route: str) -> str:
    """Make a shipped resolver list visible to the tool and return the path it
    should receive. Host route → the host path as-is; container route → copy it
    under <engagement_dir>/wordlists/ and return the /engagements container path.
    """
    if route == "host":
        return str(src)
    dst_host = Path(cfg.engagement_dir) / "wordlists" / name
    try:
        dst_host.parent.mkdir(parents=True, exist_ok=True)
        dst_host.write_bytes(src.read_bytes())
    except OSError as exc:
        _warn(f"could not stage resolver list {name} ({exc}); falling back to puredns default discovery.")
        return ""
    return runtime_route.container_staged_path(cfg.engagement_key, name)


def _resolve_resolver_args(args, cfg, route: str) -> tuple[str, str]:
    """Return (brute_r_path, trusted_path) to pass to puredns, honoring overrides.

    Defaults to the shipped premium-anycast (brute -r) and trusted-anycast
    (--resolvers-trusted) lists unless the operator overrode them or passed
    --no-default-resolvers (CR-8/CR-18). Operator-supplied paths pass through
    unchanged (assumed already valid for the chosen route).
    """
    brute_r = (args.resolvers or "").strip()
    trusted = (args.resolvers_trusted or "").strip()
    if not brute_r and not args.no_default_resolvers:
        src = runtime_route.premium_anycast_path()
        if src.is_file():
            brute_r = _stage_resolver_list(cfg, src, src.name, route)
    if not trusted and not args.no_default_resolvers:
        src = runtime_route.trusted_anycast_path()
        if src.is_file():
            trusted = _stage_resolver_list(cfg, src, src.name, route)
    return brute_r, trusted


def _resolver_count_for_guard(args, cfg) -> int | None:
    """Distinct resolver-IP count for the CR-3 guard.

    Counts the resolver list actually passed to puredns ``-r``:
      * an explicit ``--resolvers <file>`` → count THAT file (the list really used);
      * otherwise the shipped premium-anycast default.

    Returns ``None`` to mean "uncapped / operator-managed" — i.e. when
    ``--no-default-resolvers`` is set AND no explicit ``-r`` is given, so puredns
    falls back to its OWN huge self-discovered resolver set and the real
    destination-IP fan-out is largest precisely here (defect #1). The caller turns
    a ``None`` into a one-line WARN instead of a (false) small count.
    """
    brute_r = (args.resolvers or "").strip()
    if not brute_r and args.no_default_resolvers:
        return None
    src = Path(brute_r) if brute_r else runtime_route.premium_anycast_path()
    try:
        if src.is_file():
            return runtime_route.count_distinct_resolver_ips(src)
    except OSError:
        pass
    return 0


# --------------------------------------------------------------------------- #
# crt.sh harvest (unchanged behavior; runs in-container — curl/jq are container tools)
# --------------------------------------------------------------------------- #


def _crt_sh_script(apexes: list[str], out_container: str) -> str:
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


# --------------------------------------------------------------------------- #
# CR-19 — materialize a HEAD-capped copy of a large frequency-ordered wordlist.
# --------------------------------------------------------------------------- #


def _wordlist_for_route(cfg, original: str, route: str) -> str:
    """Return the wordlist path the tool should receive for *route* when no HEAD
    cap was applied (defect #3).

    Host route → the path as-is. Container route → if *original* is a host file
    that lives OUTSIDE the engagement dir (so it won't exist in-container), stage
    a copy under ``<engagement_dir>/wordlists/`` (mirroring `_stage_resolver_list`)
    and return the /engagements container path; if it already lives under the
    engagement dir, translate it to its /engagements path; if it's a known
    in-container path (e.g. the default SecLists path, not host-visible) leave it
    untouched. Falls back to the original with a WARN if staging is not possible.
    """
    if route == "host":
        return original
    src = Path(original)
    eng_dir = Path(cfg.engagement_dir)
    try:
        is_under_eng = src.resolve().is_relative_to(eng_dir.resolve())
    except (OSError, ValueError):
        is_under_eng = False
    if is_under_eng:
        rel = src.resolve().relative_to(eng_dir.resolve())
        return f"/engagements/{cfg.engagement_key}/{rel.as_posix()}"
    if not src.is_file():
        # Not host-visible — assume it's a path valid inside the container (the
        # default SecLists wordlist lives in the image, not on the host).
        return original
    # Host wordlist outside the engagement dir: stage it so it exists in-container.
    name = "brute_wordlist_" + src.name
    dst_host = eng_dir / "wordlists" / name
    try:
        dst_host.parent.mkdir(parents=True, exist_ok=True)
        dst_host.write_bytes(src.read_bytes())
    except OSError as exc:
        _warn(
            f"could not stage host wordlist {original} into the engagement dir ({exc}); "
            "the host path may not resolve in-container — pass a container-visible "
            "wordlist or use --runtime host."
        )
        return original
    return runtime_route.container_staged_path(cfg.engagement_key, name)


def _capped_wordlist(args, cfg, route: str) -> str:
    """Return the wordlist path to brute with, applying the CR-19 HEAD cap.

    When --deep-tail is set or the cap is disabled, returns the original list
    (route-translated/staged for the container, defect #3). Otherwise, when the
    list exceeds the cap, writes a HEAD-capped copy into the engagement scans dir
    and returns the path the tool should receive (host path for the host route,
    /engagements path for container), emitting a WARN naming how many labels were
    dropped.
    """
    original = args.wordlist
    if args.deep_tail or args.wordlist_head <= 0:
        return _wordlist_for_route(cfg, original, route)
    try:
        lines = Path(original).read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        # Wordlist lives in-container (default SecLists path is not host-visible);
        # we cannot pre-cap it here — leave it to puredns and note the limitation.
        return _wordlist_for_route(cfg, original, route)
    if len(lines) <= args.wordlist_head:
        return _wordlist_for_route(cfg, original, route)
    capped = wordlist_head(lines, args.wordlist_head)
    name = "brute_wordlist_head.txt"
    host_path, container_path = _paths(cfg, name)
    host_path.parent.mkdir(parents=True, exist_ok=True)
    host_path.write_text("\n".join(capped) + "\n", encoding="utf-8")
    _warn(
        f"wordlist truncated to first {args.wordlist_head} of {len(lines)} labels "
        f"({len(lines) - args.wordlist_head} dropped); pass --deep-tail to brute the full list (CR-19)."
    )
    return str(host_path) if route == "host" else container_path


# --------------------------------------------------------------------------- #
# CR-17 — per-parent wildcard probe + permutation pre-strip.
# --------------------------------------------------------------------------- #


def _random_label() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=12))


def _wildcard_parents(args, cfg, clean_hosts: list[str], route: str) -> set[str]:
    """Probe each discovered parent with random nonexistent labels and return the
    set that behaves as a wildcard SINK (random labels resolve), so the caller can
    strip brute/permutation candidates under them BEFORE DNS spend (CR-17, I-010).

    Uses `dnsx -silent` over the host or container route; parents whose random
    probes all resolve are sinks. Best-effort: any probe failure → treat the
    parent as non-wildcard (do not over-strip).
    """
    candidates = wildcard_parent_candidates(clean_hosts)
    if not candidates:
        return set()
    # Build "<rand>.<parent>" probe lines.
    probe_lines: list[str] = []
    probe_to_parent: dict[str, str] = {}
    for parent in candidates:
        for _ in range(_WILDCARD_PROBE_LABELS):
            name = f"{_random_label()}.{parent}"
            probe_lines.append(name)
            probe_to_parent[name] = parent
    if not probe_lines:
        return set()
    if os.environ.get("VIGIL_KALI_NOOP"):
        # Test/smoke short-circuit: dnsx is a no-op, so report no sinks.
        return set()
    # Run dnsx over an input file in the engagement scans dir so the chosen
    # route (host file path / /engagements container path) can read it.
    host_path, container_path = _paths(cfg, "wildcard_probe_in.txt")
    host_path.write_text("\n".join(probe_lines) + "\n", encoding="utf-8")
    # Route the probe through the SAME audited host-dispatch shim the rest of the
    # pipeline uses (defect #2): the HOST route went via a raw subprocess.run and
    # skipped the audit pipeline, so audit rows diverged by route. Both routes now
    # go through `_exec`/`_host_dispatch` and read the tool's -o output file, so
    # the audit rows are identical regardless of where dnsx runs.
    in_path = str(host_path) if route == "host" else container_path
    out_host, out_container = _paths(cfg, "wildcard_probe_out.txt")
    out_path = str(out_host) if route == "host" else out_container
    cmd = ["dnsx", "-l", in_path, "-silent", "-a", "-o", out_path]
    try:
        _exec(args, cmd, "dns-discovery: wildcard per-parent probe", "dnsx", route=route)
        resolved = set()
        if out_host.is_file():
            resolved = {ln.strip().split()[0] for ln in
                        out_host.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()}
    except (OSError, subprocess.SubprocessError, ValueError):
        return set()
    # A parent is a sink when ALL its random probes resolved.
    by_parent: dict[str, int] = {}
    for name in probe_lines:
        if name in resolved:
            by_parent[probe_to_parent[name]] = by_parent.get(probe_to_parent[name], 0) + 1
    sinks = {p for p in candidates if by_parent.get(p, 0) >= _WILDCARD_PROBE_LABELS}
    if sinks:
        # Record the wildcard environment as a Phase-2 Host/SNI-fuzz surface.
        wc_host, _ = _paths(cfg, "wildcard_parents.txt")
        wc_host.write_text("\n".join(sorted(sinks)) + "\n", encoding="utf-8")
        _warn(
            f"wildcard sinks detected under {len(sinks)} parent(s): {', '.join(sorted(sinks)[:5])}"
            f"{' …' if len(sinks) > 5 else ''} — stripped from brute input and recorded to "
            "scans/dns-discovery/wildcard_parents.txt as a Phase-2 Host/SNI-fuzz surface (CR-17)."
        )
    return sinks


def _under_wildcard(host: str, sinks: set[str]) -> bool:
    h = host.strip().lower().rstrip(".")
    return any(h == s or h.endswith("." + s) for s in sinks)


# --------------------------------------------------------------------------- #
# CR-23 — DNS query-budget WARN (advisory, never hard-blocks the brute).
# --------------------------------------------------------------------------- #


def _budget_warn(args, *, wordlist_lines: int, target_count: int, resolver_count: int) -> None:
    planned = wordlist_lines * max(target_count, 1)
    if args.query_budget > 0 and planned > args.query_budget:
        _warn(
            f"planned brute ≈ {planned} DNS queries ({wordlist_lines} labels × {target_count} targets) "
            f"exceeds the per-engagement budget ({args.query_budget}); proceeding (advisory). "
            "Trim the wordlist (--wordlist-head) or targets, or raise --query-budget (CR-23)."
        )
    try:
        rate = int(args.dns_rate)
    except (TypeError, ValueError):
        rate = 0
    if resolver_count > 0 and rate > 0:
        per_resolver = rate / resolver_count
        if args.per_resolver_qps > 0 and per_resolver > args.per_resolver_qps:
            _warn(
                f"planned per-resolver qps ≈ {per_resolver:.0f} (total {rate} ÷ {resolver_count} resolvers) "
                f"exceeds the advisory ceiling ({args.per_resolver_qps}); lower --dns-rate or use more "
                "resolvers (CR-23). --dns-rate is TOTAL qps across the pool, NOT per-resolver (CR-1)."
            )


# --------------------------------------------------------------------------- #
# CR-16/CR-21 — output-stall watchdog around the in-container brute.
# --------------------------------------------------------------------------- #


def _stall_window(wordlist_lines: int) -> int:
    """Idle window (s) before a frozen brute is STALL-killed, scaled to input size
    so a large warm-up is not falsely killed (CR-21)."""
    return _STALL_BASE_SECONDS + (wordlist_lines // 100_000) * _STALL_PER_100K_LINES


# --------------------------------------------------------------------------- #
# Brute stage (CR-8/9/16/17/19/21/23) for one target set.
# --------------------------------------------------------------------------- #


def _puredns_brute(args, cfg, targets: list[str], *, route: str, brute_r: str,
                   trusted: str, wordlist: str, wordlist_lines: int,
                   produced: list[Path], label: str) -> None:
    """Run a puredns bruteforce pass over *targets*, serialized by the global
    network-heavy lock (CR-9) and budget-WARNed (CR-23). One puredns run per
    target (puredns brutes a single apex/parent at a time)."""
    resolver_count = _resolver_count_for_guard(args, cfg)
    # CR-3 guard — WARN (never raise) when too many distinct resolver IPs in-container.
    if resolver_count is None:
        # --no-default-resolvers with no explicit -r: puredns self-discovers its
        # OWN (huge) resolver set, so the dest-IP fan-out is largest and UNCAPPED
        # on this run. Surface the hazard instead of silently counting 40 (#1).
        _warn(
            "resolver set is operator-managed/uncapped on this run "
            "(--no-default-resolvers with no -r): puredns falls back to its own "
            "self-discovered resolver list, so the destination-IP fan-out is "
            "unbounded by the CR-3 guard. Pass -r <validated-list> or drop "
            "--no-default-resolvers to use the shipped premium-anycast tier (~40 IPs)."
        )
    elif resolver_count:
        runtime_route.warn_excessive_resolver_ips(resolver_count, route=route)
    _budget_warn(args, wordlist_lines=wordlist_lines, target_count=len(targets),
                 resolver_count=resolver_count or 0)
    # CR-21 — scale the stall window to the input size so a large warm-up
    # (puredns preprocesses the whole input before massdns emits) is not killed.
    window_s = _stall_window(wordlist_lines)
    # CR-9 — serialize the whole brute pass across host + container lanes.
    with network_heavy_lock(args.engagement_dir, label=f"puredns brute ({label})"):
        for target in targets:
            safe = target.replace("/", "_")
            brute_host, brute_container = _paths(cfg, f"subs_brute_{safe}.txt")
            out_path = str(brute_host) if route == "host" else brute_container
            cmd = ["puredns", "bruteforce", wordlist, target,
                   "--rate-limit", str(args.dns_rate), "-w", out_path]
            if brute_r:
                cmd.extend(["-r", brute_r])
            if trusted:
                cmd.extend(["--resolvers-trusted", trusted])
            # CR-21 — keep massdns progress visible by default (no -q) so warm-up
            # is legible; only suppress when the operator asks.
            if args.quiet_brute:
                cmd.append("-q")
            # CR-16 — run under the output-stall watchdog (kills a frozen massdns).
            _brute_exec_with_stall(
                args, cmd, f"dns-discovery: puredns bruteforce {target} ({label})",
                "puredns", route=route, out_host=brute_host, window_s=window_s,
            )
            produced.append(brute_host)


# --------------------------------------------------------------------------- #
# Single discovery pass.
# --------------------------------------------------------------------------- #


def _resolve_profile_name(args) -> str:
    """Profile to resolve the merged candidate set with (I-3).

    Auto-selects the fail-fast 'brute-resolve' profile for the big permutation
    pass — only when --brute is active AND the operator left --dnsx-profile at
    its default. An explicit --dnsx-profile is always honored, and the swap is a
    no-op if 'brute-resolve' is somehow absent from DNSX_PROFILES.
    """
    if (
        getattr(args, "brute", False)
        and getattr(args, "dnsx_profile", _DEFAULT_DNSX_PROFILE) == _DEFAULT_DNSX_PROFILE
        and _BRUTE_RESOLVE_PROFILE in DNSX_PROFILES
    ):
        return _BRUTE_RESOLVE_PROFILE
    return args.dnsx_profile


def _resolve_stage(args, cfg, merged_container: str, resolved_container: str, route: str) -> None:
    profile_name = _resolve_profile_name(args)
    profile = DNSX_PROFILES.get(profile_name, DNSX_PROFILES["polite-cdn"])
    if profile_name == _BRUTE_RESOLVE_PROFILE and args.dnsx_profile != _BRUTE_RESOLVE_PROFILE:
        print(
            "dns-discovery: brute pass — resolving the permutation set with the "
            f"fail-fast '{_BRUTE_RESOLVE_PROFILE}' dnsx profile "
            f"(-retry {profile.retry} -timeout {profile.timeout}) instead of "
            f"'{_DEFAULT_DNSX_PROFILE}' so dead names fail fast; override with "
            "--dnsx-profile (I-3).",
            file=sys.stderr,
        )
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
    _exec(args, dnsx_cmd, "dns-discovery: dnsx resolve merged set", "dnsx", route=route)


def _read_hosts(path: Path) -> list[str]:
    if not path.is_file():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]


def _discover_once(args, cfg, apexes: list[str], seed_hosts: set[str],
                   pass_no: int) -> tuple[set[str], list[str], set[str]]:
    """One discover->merge->de-noise->wildcard-strip->resolve pass.

    Returns (resolved_host_set, bruted_targets, resolution_failures). On pass 1 it
    runs passive + CT + the apex brute; later passes re-brute only the productive
    parents found so far (those are passed in via *apexes* by the convergence
    loop). The third element is the I-6 signal: in-scope hosts that ENTERED the
    resolve but produced no A/AAAA (a silent dnsx ``-silent`` drop otherwise).
    """
    produced: list[Path] = []
    dnsx_route = _route_for(args, "dnsx")

    # Pass 1 only: passive + CT (later passes re-resolve the accumulating set).
    if pass_no == 1:
        if not args.no_passive:
            apex_host, apex_container = _paths(cfg, "apexes.txt")
            apex_host.write_text("\n".join(apexes) + "\n", encoding="utf-8")
            route = _route_for(args, "subfinder")
            apex_arg = str(apex_host) if route == "host" else apex_container
            passive_host, passive_container = _paths(cfg, "subs_passive.txt")
            out_arg = str(passive_host) if route == "host" else passive_container
            cmd = ["subfinder", "-dL", apex_arg, "-all", "-t", str(args.subfinder_threads),
                   "-silent", "-o", out_arg]
            # CR-7 — bound per-source wall time so one slow/unkeyed source cannot
            # stall the whole `-all` batch. Idempotent: only add when set/non-zero.
            sf_timeout = str(getattr(args, "subfinder_timeout", "") or "").strip()
            if sf_timeout and sf_timeout != "0":
                cmd.extend(["-timeout", sf_timeout])
            if args.recursive:
                cmd.append("-recursive")
            _exec(args, cmd, "dns-discovery: subfinder passive enum", "subfinder", route=route)
            produced.append(passive_host)

        if not args.no_ct:
            ct_host, ct_container = _paths(cfg, "subs_ct.txt")
            _exec(args, ["sh", "-c", _crt_sh_script(apexes, ct_container)],
                  "dns-discovery: certificate-transparency harvest (crt.sh)", "crt.sh", route="container")
            produced.append(ct_host)

        # OPT-IN axes (CR-6) — only when explicitly enabled; never default-on.
        if args.js_host_mining:
            produced.extend(_js_host_mining(args, cfg, apexes, seed_hosts))
        if args.bbot:
            produced.extend(_bbot_axis(args, cfg, apexes))

    # --- Brute (opt-in) ----------------------------------------------------
    bruted: list[str] = []
    if args.brute and apexes:
        brute_route = _route_for(args, "puredns")
        brute_r, trusted = _resolve_resolver_args(args, cfg, brute_route)
        wordlist = _capped_wordlist(args, cfg, brute_route)
        wl_lines = _wordlist_line_count(args.wordlist, args.wordlist_head, args.deep_tail)
        _puredns_brute(args, cfg, apexes, route=brute_route, brute_r=brute_r,
                       trusted=trusted, wordlist=wordlist, wordlist_lines=wl_lines,
                       produced=produced, label=f"pass{pass_no}")
        bruted = list(apexes)

    # --- Merge + de-noise --------------------------------------------------
    merged_lines: list[str] = list(seed_hosts)
    for path in produced:
        merged_lines.extend(_read_hosts(path))
    clean, dropped = denoise_hosts(merged_lines)
    if not clean:
        return set(), bruted, set()

    # --- CR-17 wildcard pre-strip (only meaningful when bruting/permuting) --
    if args.brute and not args.no_wildcard_strip:
        sinks = _wildcard_parents(args, cfg, clean, dnsx_route)
        if sinks:
            before = len(clean)
            clean = [h for h in clean if not _under_wildcard(h, sinks)]
            print(f"dns-discovery: stripped {before - len(clean)} hosts under "
                  f"{len(sinks)} wildcard parent(s) before resolve (CR-17)", file=sys.stderr)

    merged_host, merged_container = _paths(cfg, "subs_merged.txt")
    merged_host.write_text("\n".join(clean) + "\n", encoding="utf-8")
    merged_arg = str(merged_host) if dnsx_route == "host" else merged_container
    print(f"dns-discovery: pass {pass_no}: {len(clean)} unique hosts after merge+de-noise "
          f"({dropped} dropped as noise)", file=sys.stderr)

    # --- Resolve -----------------------------------------------------------
    resolved_host, resolved_container = _paths(cfg, "resolved_hosts.txt")
    resolved_arg = str(resolved_host) if dnsx_route == "host" else resolved_container
    _resolve_stage(args, cfg, merged_arg, resolved_arg, dnsx_route)
    resolved = set(denoise_hosts(_read_hosts(resolved_host))[0])

    # I-6: dnsx runs `-silent`, so an in-scope host that ENTERED the resolve but
    # produced no A/AAAA (e.g. a CNAME pointing off-network, or a dangling CNAME —
    # a subdomain-takeover lead) is omitted from `-o` with no trace. Diff the
    # resolver INPUT set (`clean`) against the resolved OUTPUT set and surface the
    # gap as an explicit failure signal rather than a silent drop. This is NOT the
    # unbounded-permutation-brute hazard guard above — raw brute guesses never
    # reach `clean` (puredns validates them first), so only observed/validated
    # in-scope names are diffed here.
    failures = set(resolution_failures(clean, resolved))
    if failures:
        sample = ", ".join(sorted(failures)[:5])
        _warn(
            f"pass {pass_no}: {len(failures)} in-scope host(s) entered the resolver but "
            f"produced no A/AAAA (resolution failure, NOT a silent drop): {sample}"
            f"{' …' if len(failures) > 5 else ''}. A dangling/off-network CNAME here is a "
            "subdomain-takeover lead — investigate before treating these as "
            "'does not exist' (I-6)."
        )
    return resolved, bruted, failures


# --------------------------------------------------------------------------- #
# CR-6 opt-in axes (JS host mining, bbot mop-up) — guarded, never default-on.
# --------------------------------------------------------------------------- #


def _js_host_mining(args, cfg, apexes: list[str], seed_hosts: set[str]) -> list[Path]:
    """OPT-IN: mine in-scope hostnames from gau --subs output and re-feed them.

    Runs gau (passive web-archive) over the apexes, extracts hostnames whose
    registrable suffix matches an in-scope apex, and writes them so the merge
    stage re-resolves them. Best-effort; failures are non-fatal.
    """
    out_host, out_container = _paths(cfg, "js_hosts.txt")
    route = "container"  # gau/archive fetch stays in-container (egress-controlled).
    apex_re = "|".join(_ere_escape(a) for a in apexes)
    # gau emits URLs; grep host components, filter to in-scope apexes, dedupe.
    script = (
        "gau --subs " + " ".join(shlex.quote(a) for a in apexes) + " 2>/dev/null "
        "| sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' "
        f"| grep -iE '(^|\\.)({apex_re})$' "
        "| tr 'A-Z' 'a-z' | sort -u > " + shlex.quote(out_container)
    )
    _exec(args, ["sh", "-c", script], "dns-discovery: JS/archive host mining (gau --subs)",
          "gau", route=route)
    if out_host.is_file():
        print(f"dns-discovery: JS/archive host mining harvested "
              f"{len(_read_hosts(out_host))} candidate hosts (CR-6)", file=sys.stderr)
        return [out_host]
    return []


def _bbot_axis(args, cfg, apexes: list[str]) -> list[Path]:
    """OPT-IN: bbot passive subdomain-enum mop-up (CR-6). bbot output is
    unreliable (CR-24: excavate false hostnames), so harvested names are merged
    only after the normal denoise + the convergence resolve pass DNS-validates
    them — we do NOT trust them blindly."""
    out_host, out_container = _paths(cfg, "bbot_hosts.txt")
    route = "container"
    # -y auto-yes, passive flag, JSON output mined for DNS_NAME events.
    script = (
        "bbot -t " + " ".join(shlex.quote(a) for a in apexes) +
        " -p subdomain-enum -rf passive -om json -y 2>/dev/null "
        "| jq -r 'select(.type==\"DNS_NAME\") | .data' 2>/dev/null "
        "| tr 'A-Z' 'a-z' | sort -u > " + shlex.quote(out_container)
    )
    _exec(args, ["sh", "-c", script], "dns-discovery: bbot passive subdomain-enum mop-up",
          "bbot", route=route)
    if out_host.is_file():
        print(f"dns-discovery: bbot harvested {len(_read_hosts(out_host))} candidate hosts "
              "(DNS-validated by the resolve pass before they count; CR-6/CR-24)", file=sys.stderr)
        return [out_host]
    return []


# POSIX ERE metacharacters. `re.escape` targets PYTHON regex and can emit
# backslash sequences that are not portable/safe in POSIX ERE (the dialect
# `grep -E` uses), so escape ONLY the ERE specials explicitly (defect #5). A
# domain apex normally only carries `.`, but escaping the full set keeps the
# generated `grep -iE` pattern correct for any input.
_ERE_METACHARS = frozenset(".^$*+?()[]{}|\\")


def _ere_escape(s: str) -> str:
    """Escape a literal string for safe interpolation into a POSIX ERE pattern."""
    return "".join("\\" + ch if ch in _ERE_METACHARS else ch for ch in s)


# --------------------------------------------------------------------------- #
# Wordlist line counting (for budget + stall scaling) — best-effort.
# --------------------------------------------------------------------------- #


def _wordlist_line_count(path: str, head_cap: int, deep_tail: bool) -> int:
    """Effective brute wordlist size: min(file lines, head cap) unless --deep-tail.
    Falls back to the head cap when the file is not host-visible (lives in-container)."""
    try:
        n = sum(1 for _ in Path(path).open("r", encoding="utf-8", errors="ignore"))
    except OSError:
        # Default SecLists path is in-container only; use the cap as the estimate.
        return head_cap if (head_cap > 0 and not deep_tail) else 0
    if deep_tail or head_cap <= 0:
        return n
    return min(n, head_cap)


# --------------------------------------------------------------------------- #
# CR-6 convergence loop entrypoint.
# --------------------------------------------------------------------------- #


# Defaults for every flag added by this CR wave, so a caller that builds a bare
# args object (older callers / focused tests) still runs with safe defaults and
# the new code never trips on a missing attribute. argparse already supplies
# these on the real CLI path; this only backfills when absent.
_ARG_DEFAULTS = {
    "no_passive": False, "no_ct": False, "recursive": False,
    "subfinder_threads": "20", "subfinder_timeout": "20",
    "brute": False, "wordlist": _DEFAULT_WORDLIST,
    "wordlist_head": _DEFAULT_WORDLIST_HEAD, "deep_tail": False,
    "dns_rate": "1500", "dnsx_profile": _DEFAULT_DNSX_PROFILE, "resolver_profile": "public-tcp",
    "dnsx_extra_args": "", "stage_timeout": 1800, "runtime": "auto",
    "resolvers": "", "resolvers_trusted": "", "no_default_resolvers": False,
    "max_passes": 3, "no_converge": False, "no_parent_recursion": False,
    "parent_min_children": 5, "no_wildcard_strip": False, "quiet_brute": False,
    "js_host_mining": False, "bbot": False,
    "query_budget": _DEFAULT_QUERY_BUDGET, "per_resolver_qps": _DEFAULT_PER_RESOLVER_QPS,
}


def _apply_arg_defaults(args) -> None:
    for name, default in _ARG_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def run(args) -> None:
    _apply_arg_defaults(args)
    cfg = load_config(args.engagement_dir)
    # ``args.engagement_dir`` is the raw CLI flag and is ``None`` on the common
    # active-pointer path (no explicit ``--engagement-dir``). Downstream readers
    # -- ``_host_dispatch`` required-header injection and the ``_puredns_brute``
    # ``network_heavy_lock`` -- consume it directly and crash / silently skip on
    # ``None``. Canonicalize it to the resolved path so every stage, including
    # ``--brute``, sees a real directory.
    args.engagement_dir = cfg.engagement_dir
    out_dir = Path(cfg.engagement_dir) / "scans" / "dns-discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    apexes = [a.strip() for a in args.apexes if a.strip()]
    if not apexes:
        print("dns-discovery: no apexes given.", file=sys.stderr)
        sys.exit(2)

    resolved_all: set[str] = set()
    bruted_apexes: set[str] = set()
    failures_all: set[str] = set()
    zero_streak = 0
    max_passes = 1 if args.no_converge else max(1, int(args.max_passes))

    for pass_no in range(1, max_passes + 1):
        # Pass 1 runs passive/CT/axes + the apex brute; later passes re-brute the
        # productive parents found so far (CR-20) and re-resolve the union (CR-6).
        if pass_no == 1:
            targets = apexes
        else:
            targets = _select_parent_targets(args, resolved_all, bruted_apexes)
            print(f"dns-discovery: productive-parent recursion: re-bruting "
                  f"{len(targets)} parent(s) with >= {args.parent_min_children} children (CR-20)",
                  file=sys.stderr)

        # _discover_once yields (resolved, bruted, resolution_failures). The
        # failure set is read positionally and tolerated-absent so a 2-tuple test
        # double (or any stub of this seam) still drives the convergence loop.
        result = _discover_once(args, cfg, targets, set(resolved_all), pass_no)
        new_resolved, bruted = result[0], result[1]
        failures_all |= result[2] if len(result) > 2 else set()
        bruted_apexes.update(bruted)
        before = len(resolved_all)
        resolved_all |= new_resolved
        net_new = len(resolved_all) - before
        print(f"dns-discovery: pass {pass_no}: +{net_new} net-new resolved "
              f"({len(resolved_all)} total)", file=sys.stderr)

        if args.no_converge:
            break
        # CR-6 — stop after two consecutive passes with zero net-new resolved.
        zero_streak = zero_streak + 1 if net_new == 0 else 0
        if zero_streak >= 2:
            print("dns-discovery: converged (2 consecutive passes added 0 net-new resolved).",
                  file=sys.stderr)
            break
        # A further pass can only add hosts when there is something new to brute:
        # productive-parent recursion (CR-20) requires --brute + recursion enabled
        # and at least one fresh productive parent. Otherwise pass 1's passive/CT/
        # axes already captured everything and re-resolving is a no-op — stop.
        if not _select_parent_targets(args, resolved_all, bruted_apexes):
            break

    # I-6: persist the per-host resolution-FAILURE signal — in-scope hosts that
    # entered the resolver but produced no A/AAAA. A host that resolved in ANY pass
    # is not a failure (a later pass may resolve what an earlier one missed), so
    # subtract the resolved union. Write the canonical artifact BEFORE the
    # zero-resolved early-exit below: a run that resolved nothing because every
    # in-scope host pointed off-network is the single most important case to
    # surface, not bury. Always write (empty when none) so a prior run cannot leave
    # a STALE failure list for follow-on automation to misread.
    failures_all -= resolved_all
    failures_host, _ = _paths(cfg, "resolution_failures.txt")
    if failures_all:
        ordered = sorted(failures_all)
        failures_host.write_text("\n".join(ordered) + "\n", encoding="utf-8")
        sample = ", ".join(ordered[:5]) + (" …" if len(ordered) > 5 else "")
        print(
            f"dns-discovery: {len(failures_all)} in-scope host(s) entered the resolver "
            f"but produced no A/AAAA (resolution failures): {sample}\n"
            f"  -> {failures_host}\n"
            "  NOT silently dropped: a dangling/off-network CNAME here is a "
            "subdomain-takeover lead — investigate before treating them as "
            "'does not exist' (I-6).",
            file=sys.stderr,
        )
    else:
        failures_host.write_text("", encoding="utf-8")

    # Persist the union as the canonical resolved set. Always write the canonical
    # path (empty on a no-result run) so a prior run for a DIFFERENT apex — or an
    # earlier run that resolved hosts — cannot leave STALE entries that follow-on
    # automation (e.g. `vigil assess web-discovery`) would then consume.
    resolved_host, _ = _paths(cfg, "resolved_hosts.txt")
    if resolved_all:
        resolved_host.write_text("\n".join(sorted(resolved_all)) + "\n", encoding="utf-8")
    else:
        resolved_host.write_text("", encoding="utf-8")
        print("dns-discovery: no hosts resolved.", file=sys.stderr)
        sys.exit(0)

    print(f"dns-discovery: done. {len(resolved_all)} resolved hosts -> {resolved_host}\n"
          f"  Next: vigil assess web-discovery {resolved_host}", file=sys.stderr)


def _select_parent_targets(args, resolved_all: set[str], bruted_apexes: set[str]) -> list[str]:
    """CR-20: productive parents to re-brute next pass (>= --parent-min-children),
    excluding parents already bruted. Empty when parent recursion is disabled or
    no brute axis is active (re-bruting needs --brute). Pure — no I/O — so it can
    be called both as the next-pass selector and as the convergence gate."""
    if args.no_parent_recursion or not args.brute:
        return []
    parents = cluster_productive_parents(
        sorted(resolved_all),
        min_children=int(args.parent_min_children),
        bruted_apexes=sorted(bruted_apexes),
    )
    return [p for p in parents if p not in bruted_apexes]
