"""vigil assess egress-check — detect an egress-reputation blackhole early.

The shared NAT egress IP gets progressively blackholed by hardened on-prem
perimeters as scan volume accumulates (§9), silently turning "reachable origins"
into untestable ghosts and wasting agent dispatches. This verb samples N in-scope
hosts PLUS a known-good control, classifies each with the shared
`reachability.classify_probe` verdict (so a bare ``connect=000`` is never a blanket
"blocked" — it must show no TCP connect AND no resolved IP, and a TLS-1.3 reset is
retried with ``--tls-max 1.2``). It captures a bounded response-body/header sample
so a WAF/edge block cannot masquerade as application reachability. It records every
outcome as an advisory ``egress_decision`` backed by the indexed probe artifact; only a
control-live, overwhelmingly blackholed sample emits a blocked-hosts file for
``ingest endpoints --egress-blocked-hosts``.

Advisory, never a hard gate: it surfaces the block so the operator can stop
dispatching to a burned cluster, but it does not block anything itself.
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path
from typing import NamedTuple

from assess.lib import reachability
from assess.lib.client import AssessmentClient, require_artifact_write_response
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.kali import kali_exec
from assess.lib.kali_output import detect_waf_challenge

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
    """Build a bounded, auditable curl probe loop.

    Each row includes transport fields plus base64-encoded response headers and
    the first 32 KiB of the body. That is enough for the shared WAF detector and
    keeps the resulting evidence artifact line-oriented. A 000 is retried once
    with TLS 1.2 (the TLS-appliance recovery from §9).
    """
    import shlex
    fmt = "%{http_code} %{time_connect} %{remote_ip}"
    host_list = " ".join(shlex.quote(h) for h in hosts)
    return (
        f"for h in {host_list}; do "
        "hdr=$(mktemp); body=$(mktemp); "
        f"r=$(curl -sS --suppress-connect-headers -D \"$hdr\" -o \"$body\" --max-time 8 -w {shlex.quote(fmt)} \"https://$h/\" 2>/dev/null); "
        "code=$(printf '%s' \"$r\" | awk '{print $1}'); "
        "if [ \"$code\" = \"000\" ]; then : >\"$hdr\"; : >\"$body\"; "
        f"r=$(curl -sS --suppress-connect-headers -D \"$hdr\" -o \"$body\" --max-time 8 --tls-max 1.2 -w {shlex.quote(fmt)} \"https://$h/\" 2>/dev/null); fi; "
        "hb=$(base64 <\"$hdr\" | tr -d '\\n'); "
        "bb=$(head -c 32768 \"$body\" | base64 | tr -d '\\n'); "
        "[ -n \"$hb\" ] || hb=-; [ -n \"$bb\" ] || bb=-; "
        "printf '%s %s %s %s\\n' \"$h\" \"$r\" \"$hb\" \"$bb\"; "
        "rm -f \"$hdr\" \"$body\"; "
        "done > " + shlex.quote(out_container)
    )


class _ProbeObservation(NamedTuple):
    host: str
    http_code: str
    time_connect: float
    remote_ip: str
    headers: dict[str, str]
    body: str


def _decode_capture(value: str) -> str:
    if not value or value == "-":
        return ""
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", "replace")
    except (ValueError, UnicodeError):
        return ""


def _parse_response_headers(raw: str, http_code: str) -> dict[str, str]:
    headers: dict[str, str] = {"status_code": http_code}
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            headers = {"status_code": http_code}
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            continue
        headers[name] = f"{headers[name]}\n{value}" if name in headers else value
    return headers


def _parse_probe_line(line: str) -> _ProbeObservation | None:
    parts = line.split(maxsplit=5)
    if len(parts) < 2:
        return None
    host = parts[0]
    http_code = parts[1] if len(parts) >= 2 else ""
    try:
        time_connect = float(parts[2]) if len(parts) >= 3 else 0.0
    except ValueError:
        time_connect = 0.0
    remote_ip = parts[3] if len(parts) >= 4 and parts[3] != "-" else ""
    raw_headers = _decode_capture(parts[4]) if len(parts) >= 5 else ""
    body = _decode_capture(parts[5]) if len(parts) >= 6 else ""
    return _ProbeObservation(
        host=host,
        http_code=http_code,
        time_connect=time_connect,
        remote_ip=remote_ip,
        headers=_parse_response_headers(raw_headers, http_code),
        body=body,
    )


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

    probe_run = kali_exec(
        ["sh", "-c", _probe_script(all_hosts, out_container)],
        technique="RECON", intent="egress reputation check (control + in-scope sample)",
        probe_kind="baseline", phase="recon", timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir, tool_name="curl",
    )

    verdicts: dict[str, str] = {}
    waf_or_edge_observations: dict[str, str] = {}
    if out_host.is_file():
        for line in out_host.read_text(encoding="utf-8", errors="replace").splitlines():
            parsed = _parse_probe_line(line.strip())
            if not parsed:
                continue
            verdicts[parsed.host] = reachability.classify_probe(
                http_code=parsed.http_code,
                time_connect=parsed.time_connect,
                remote_ip=parsed.remote_ip,
            )
            is_waf, waf_reason = detect_waf_challenge(
                parsed.body,
                "",
                parsed.headers,
            )
            if is_waf:
                verdicts[parsed.host] = "waf_challenge"
                waf_or_edge_observations[parsed.host] = waf_reason

    controls_live = bool(controls) and all(
        verdicts.get(c) == reachability.LIVE for c in controls
    )
    blackholed = [h for h in sample if verdicts.get(h) == reachability.BLACKHOLED]
    # The threshold describes the requested sample, so missing/garbled probe rows
    # cannot inflate a sparse observation into a cluster-wide verdict. A partial
    # sample can still meet the threshold when enough hosts are independently
    # classified as blackholed; its missing rows remain visible below.
    classified = [h for h in sample if h in verdicts]
    classified_n = len(classified)
    sampled_n = len(sample)
    blocked_pct = round(100 * len(blackholed) / sampled_n) if sampled_n else 0

    if not controls_live:
        verdict = "control_failure"
        conclusion = "inconclusive"
        reason = "controls_not_live"
    elif blocked_pct >= int(args.block_threshold):
        verdict = "cluster_blackholed"
        conclusion = "observed_blackhole"
        reason = "blocked_threshold_met"
    elif any(host in waf_or_edge_observations for host in sample):
        verdict = "inconclusive"
        conclusion = "inconclusive"
        reason = "waf_or_edge_block_samples"
    elif classified_n < sampled_n:
        verdict = "inconclusive"
        conclusion = "inconclusive"
        reason = "unclassified_samples"
    else:
        verdict = "reachable"
        conclusion = "reachable"
        reason = "complete_sample_below_threshold"

    # Keep `egress_block_pct=N` in stdout for any consumer that greps for it.
    print(f"cluster={args.cluster or '-'} verdict={verdict} control={'live' if controls_live else 'fail'} "
          f"blackholed={len(blackholed)}/{classified_n} (of {sampled_n} sampled) egress_block_pct={blocked_pct}")

    if verdict == "cluster_blackholed":
        if args.emit_blocked_hosts:
            blocked_path = Path(anchor_engagement_relative(args.emit_blocked_hosts, args.engagement_dir))
            blocked_path.parent.mkdir(parents=True, exist_ok=True)
            blocked_path.write_text("\n".join(blackholed) + "\n", encoding="utf-8")
            print(f"egress-check: wrote {len(blackholed)} blackholed host(s) to {blocked_path} "
                  f"(pipe into `ingest-endpoints --egress-blocked-hosts`).", file=sys.stderr)

    if not args.no_record:
        artifact_ref = out_host.relative_to(Path(cfg.engagement_dir)).as_posix()
        command_run_id = getattr(probe_run, "run_id", None)
        if not isinstance(command_run_id, int) or command_run_id < 1:
            command_run_id = None
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            artifact = client.post(
                "artifacts",
                {
                    "path": artifact_ref,
                    "kind": "egress-connectivity-observation",
                    "media_type": "text/plain",
                    "producer_command_run_id": command_run_id,
                },
            )
            artifact = require_artifact_write_response(
                artifact,
                artifact_path=artifact_ref,
                operation="egress-check artifact registration",
            )
            artifact_ref = str(artifact["relative_path"])
            client.record_decision(
                {
                    "kind": "egress_decision",
                    "surfaced_to_user": True,
                    "payload": {
                        "subtype": "connectivity_check",
                        "cluster": args.cluster or "",
                        "verdict": verdict,
                        "conclusion": conclusion,
                        "reason": reason,
                        "blocked_pct": blocked_pct,
                        "control": "live" if controls_live else "fail",
                        "control_observations": {
                            host: verdicts.get(host, "unobserved") for host in controls
                        },
                        "sampled": sampled_n,
                        "classified": classified_n,
                        "sample_observations": {
                            host: verdicts.get(host, "unobserved") for host in sample
                        },
                        "waf_or_edge_observations": waf_or_edge_observations,
                        "blackholed_hosts": blackholed,
                        "artifact_ref": artifact_ref,
                        "provenance": {
                            "source": "vigil assess egress-check",
                            "command_run_id": command_run_id,
                            "artifact_id": int(artifact["id"]),
                        },
                    },
                }
            )

    if verdict == "control_failure":
        recorded = " recorded with its probe artifact" if not args.no_record else " not recorded (--no-record)"
        print(
            "egress-check: controls did NOT connect, so this check is "
            "inconclusive; a failed control cannot establish estate-wide or "
            f"per-host reachability. Observation{recorded}.",
            file=sys.stderr,
        )
        return
    if verdict == "inconclusive":
        recorded = " recorded with its probe artifact" if not args.no_record else " not recorded (--no-record)"
        if reason == "waf_or_edge_block_samples":
            affected = sum(host in waf_or_edge_observations for host in sample)
            print(
                f"egress-check: {affected} of {sampled_n} sampled host(s) "
                "returned a WAF/edge-block response; that does not establish "
                "application reachability or host-wide blocking. "
                f"Observation{recorded}.",
                file=sys.stderr,
            )
        else:
            missing = sampled_n - classified_n
            print(
                f"egress-check: {missing} of {sampled_n} sampled host(s) had no "
                "classified observation, so reachability is inconclusive. "
                f"Observation{recorded}.",
                file=sys.stderr,
            )
        return
    if verdict == "cluster_blackholed" and not args.no_record:
        print(
            "egress-check: recorded an advisory egress_decision with its probe artifact.",
            file=sys.stderr,
        )
