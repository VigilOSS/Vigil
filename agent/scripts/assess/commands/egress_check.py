"""aith assess egress-check — detect an egress-reputation blackhole early.

The shared NAT egress IP gets progressively blackholed by hardened on-prem
perimeters as scan volume accumulates (§9), silently turning "reachable origins"
into untestable ghosts and wasting agent dispatches. This verb samples N in-scope
hosts PLUS a known-good control, classifies each with the shared
`reachability.classify_probe` verdict (so a bare ``connect=000`` is never a blanket
"blocked" — it must show no TCP connect AND no resolved IP, and a TLS-1.3 reset is
retried with ``--tls-max 1.2``), and — only when the controls still connect but the
in-scope sample is overwhelmingly blackholed — records an **advisory**
``egress_decision`` and emits a blocked-hosts file for
``ingest-endpoints --egress-blocked-hosts``.

Advisory, never a hard gate: it surfaces the block so the operator can stop
dispatching to a burned cluster, but it does not block anything itself.
"""
from __future__ import annotations

import sys
from pathlib import Path

from assess.lib import reachability
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.kali import kali_exec

_DEFAULT_CONTROLS = ("example.com", "cloudflare.com")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "egress-check",
        help="Sample in-scope hosts + a control to detect an egress-reputation blackhole (advisory).",
    )
    p.add_argument("--cluster", default="", help="Logical cluster label stamped on the decision + blocked-hosts file.")
    p.add_argument("--hosts", required=True, help="In-scope hosts: a file path or a comma-separated list.")
    p.add_argument("--control", action="append", default=[], help="Known-good control host(s). Repeatable. Default: example.com,cloudflare.com")
    p.add_argument("--sample", type=int, default=10, help="How many in-scope hosts to sample (default 10).")
    p.add_argument("--block-threshold", dest="block_threshold", type=int, default=80,
                   help="Percent of sampled hosts that must be blackholed (with controls live) to flag the cluster (default 80).")
    p.add_argument("--emit-blocked-hosts", dest="emit_blocked_hosts", default="",
                   help="Write confirmed-blackholed hosts here for `ingest-endpoints --egress-blocked-hosts`.")
    p.add_argument("--no-record", dest="no_record", action="store_true", help="Do not record an egress_decision (print only).")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=180, help="kali_exec --timeout for the probe batch (default 180).")
    p.set_defaults(func=run)


def _load_hosts(spec: str, engagement_dir) -> list[str]:
    # A comma list is hosts, not a path. A single token may be a file: try it
    # as-is, then anchored to the engagement dir (best-effort — a CSV never anchors).
    path = Path(spec)
    if not path.is_file() and "," not in spec:
        try:
            anchored = Path(anchor_engagement_relative(spec, engagement_dir))
            if anchored.is_file():
                path = anchored
        except SystemExit:
            pass
    if path.is_file():
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = spec.split(",")
    out: list[str] = []
    for line in lines:
        h = line.strip()
        if h and not h.startswith("#"):
            out.append(h)
    return out


def _probe_script(hosts: list[str], out_container: str) -> str:
    """sh -c probe loop: curl each host with a -w field line; on a 000 retry once
    with --tls-max 1.2 (the TLS-1.3-appliance recovery from §9). Writes
    ``host http_code time_connect remote_ip`` per line."""
    import shlex
    fmt = "%{http_code} %{time_connect} %{remote_ip}"
    host_list = " ".join(shlex.quote(h) for h in hosts)
    return (
        f"for h in {host_list}; do "
        f"r=$(curl -sS -o /dev/null --max-time 8 -w {shlex.quote(fmt)} \"https://$h/\" 2>/dev/null); "
        "code=$(printf '%s' \"$r\" | awk '{print $1}'); "
        f"if [ \"$code\" = \"000\" ]; then r=$(curl -sS -o /dev/null --max-time 8 --tls-max 1.2 -w {shlex.quote(fmt)} \"https://$h/\" 2>/dev/null); fi; "
        "printf '%s %s\\n' \"$h\" \"$r\"; "
        "done > " + shlex.quote(out_container)
    )


def _parse_probe_line(line: str) -> tuple[str, str, float, str] | None:
    parts = line.split()
    if len(parts) < 2:
        return None
    host = parts[0]
    http_code = parts[1] if len(parts) >= 2 else ""
    try:
        time_connect = float(parts[2]) if len(parts) >= 3 else 0.0
    except ValueError:
        time_connect = 0.0
    remote_ip = parts[3] if len(parts) >= 4 else ""
    return host, http_code, time_connect, remote_ip


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    hosts = _load_hosts(args.hosts, args.engagement_dir)
    if not hosts:
        print("egress-check: no in-scope hosts provided.", file=sys.stderr)
        sys.exit(1)
    sample = hosts[: max(1, int(args.sample))]
    controls = [c.strip() for c in (args.control or list(_DEFAULT_CONTROLS)) if c.strip()]
    all_hosts = controls + sample

    out_host = Path(cfg.engagement_dir) / "scans" / "egress-check" / "probe.txt"
    out_host.parent.mkdir(parents=True, exist_ok=True)
    out_container = f"/engagements/{cfg.engagement_key}/scans/egress-check/probe.txt"

    kali_exec(
        ["sh", "-c", _probe_script(all_hosts, out_container)],
        technique="RECON", intent="egress reputation check (control + in-scope sample)",
        probe_kind="baseline", phase="recon", timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir, tool_name="curl",
    )

    verdicts: dict[str, str] = {}
    if out_host.is_file():
        for line in out_host.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = _parse_probe_line(line.strip())
            if not parsed:
                continue
            host, code, tc, ip = parsed
            verdicts[host] = reachability.classify_probe(http_code=code, time_connect=tc, remote_ip=ip)

    controls_live = controls and all(verdicts.get(c) == reachability.LIVE for c in controls)
    blackholed = [h for h in sample if verdicts.get(h) == reachability.BLACKHOLED]
    # Denominator is the hosts we actually got a verdict for — a host whose probe
    # line was missing/garbled must not dilute the block percentage (which could
    # mask a real blackhole by dropping it below the threshold).
    classified = [h for h in sample if h in verdicts]
    classified_n = len(classified)
    sampled_n = len(sample)
    blocked_pct = round(100 * len(blackholed) / classified_n) if classified_n else 0

    if not controls_live:
        verdict = "control_failure"
    elif blocked_pct >= int(args.block_threshold):
        verdict = "cluster_blackholed"
    else:
        verdict = "reachable"

    # Keep `egress_block_pct=N` in stdout for any consumer that greps for it.
    print(f"cluster={args.cluster or '-'} verdict={verdict} control={'live' if controls_live else 'fail'} "
          f"blackholed={len(blackholed)}/{classified_n} (of {sampled_n} sampled) egress_block_pct={blocked_pct}")

    if verdict == "control_failure":
        print("egress-check: controls did NOT connect — likely a transient/global egress issue, "
              "not a per-cluster block. Not recording a decision; re-run.", file=sys.stderr)
        return

    if verdict == "cluster_blackholed":
        if args.emit_blocked_hosts:
            blocked_path = Path(anchor_engagement_relative(args.emit_blocked_hosts, args.engagement_dir))
            blocked_path.parent.mkdir(parents=True, exist_ok=True)
            blocked_path.write_text("\n".join(blackholed) + "\n", encoding="utf-8")
            print(f"egress-check: wrote {len(blackholed)} blackholed host(s) to {blocked_path} "
                  f"(pipe into `ingest-endpoints --egress-blocked-hosts`).", file=sys.stderr)
        if not args.no_record:
            with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
                client.record_decision({
                    "kind": "egress_decision",
                    "surfaced_to_user": True,
                    "payload": {
                        "cluster": args.cluster or "",
                        "verdict": verdict,
                        "blocked_pct": blocked_pct,
                        "control": "live",
                        "sampled": sampled_n,
                        "blackholed_hosts": blackholed,
                    },
                })
            print("egress-check: recorded an advisory egress_decision. Stop dispatching to this "
                  "cluster until a fresh egress-check returns 'reachable'.", file=sys.stderr)
