"""vigil assess recon — supervised, resumable recon orchestrator.

Runs the deterministic recon spine as ORDERED, CHECKPOINTED stages so no LLM
holds a long blocking call:

    dns-discovery (subfinder/CT/optional brute → resolve → wildcard-strip)
      → web-discovery (httpx liveness → katana crawl)
      → gau-endpoints (historical-URL mining; default ON, --no-gau to drop)

Each stage writes its canonical artifact (``resolved_hosts.txt`` then
``httpx_live.jsonl``) plus a per-stage ``scans/recon/<stage>.meta.json``
checkpoint. With ``--resume`` a stage is SKIPPED when its checkpoint is
fresh+valid (done, exit 0, matching input fingerprint, artifact present), and
the run restarts from the first incomplete stage — so a killed run re-runs
cleanly with no redo and no orphaned processes (each stage is a single
kali_exec/host_exec that the CLI reaps on its own ``--timeout``). After every
stage the orchestrator rewrites ``scans/recon/recon-status.json`` (read by
``vigil assess recon-status`` and the completeness-assessor specialist).

DNS-heavy / bulk stages route to the HOST with ``enforce=True`` on macOS Docker
Desktop (engagement I-001): a preflight refuses to run if a required host binary
is missing rather than silently degrading to the proxy-wedging container path.
An explicit ``--runtime container`` is always honoured (caller forced isolation).

Run modes:
  * foreground (default): runs the pipeline in-band. Resumable.
  * ``--background``: spawns the foreground orchestrator as a DETACHED host
    process (``start_new_session``), records an ``assessment_jobs`` row, and
    returns a job id immediately so the operator POLLS ``recon-status`` instead
    of blocking. The detached child finalizes its own job row and publishes a
    host-side exit marker (the Phase-0 reconciliation pattern) on exit.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from assess.commands import dns_discovery, gau_endpoints, web_discovery
from assess.lib import runtime_route
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config

# DNS-heavy / bulk tools the pipeline uses that MUST be host-routed on macOS
# Docker Desktop (I-001). The preflight enforces host availability for these.
_ENFORCED_TOOLS = ("subfinder", "dnsx", "httpx")
_BRUTE_TOOL = "puredns"


@dataclass(frozen=True)
class _Stage:
    key: str
    label: str
    artifact: str  # canonical checkpoint artifact, relative to the engagement dir


_DNS_STAGE = _Stage("dns", "dns-discovery", "scans/dns-discovery/resolved_hosts.txt")
_WEB_STAGE = _Stage("web", "web-discovery", "scans/web-discovery/httpx_live.jsonl")
# gau is per-apex + in-container; its sentinel artifact records the apexes mined.
_GAU_STAGE = _Stage("gau", "gau-endpoints", "scans/recon/gau.done")


def _build_stages(args) -> tuple[_Stage, ...]:
    """The active stage list. gau is ON by default (historical-URL enrichment);
    --no-gau drops it (e.g. a brand-new site with no archive history)."""
    stages = [_DNS_STAGE, _WEB_STAGE]
    if not getattr(args, "no_gau", False):
        stages.append(_GAU_STAGE)
    return tuple(stages)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "recon",
        help="Supervised, resumable recon pipeline: dns-discovery -> web-discovery -> "
             "gau-endpoints (checkpointed; --background runs it as a pollable job).",
    )
    p.add_argument("apexes", nargs="+", help="Apex domain(s) to enumerate.")
    p.add_argument("--brute", action="store_true",
                   help="Run the puredns bruteforce pass in dns-discovery (OFF by default).")
    p.add_argument("--runtime", dest="runtime", choices=("auto", "host", "container"), default="auto",
                   help="Where DNS-heavy/bulk stages run. auto = host on macOS Docker Desktop "
                        "(I-001), container elsewhere; container = force isolation (bypasses the "
                        "host-routing enforcement).")
    p.add_argument("--no-crawl", dest="no_crawl", action="store_true",
                   help="Skip the katana crawl in web-discovery.")
    p.add_argument("--no-gau", dest="no_gau", action="store_true",
                   help="Skip the gau historical-URL stage (ON by default). Drop it for a "
                        "brand-new site with no archive/wayback history.")
    p.add_argument("--resume", action="store_true",
                   help="Skip stages whose checkpoint is fresh+valid; restart from the first "
                        "incomplete stage.")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800,
                   help="Per-tool --timeout seconds passed to each stage (default 1800).")
    p.add_argument("--background", action="store_true",
                   help="Spawn the pipeline as a DETACHED host job and return a job id "
                        "immediately; poll with `vigil assess recon-status`.")
    # Internal: the detached child re-invokes itself with these so it runs in-band
    # and finalizes the job row it was given. Not for direct operator use.
    p.add_argument("--foreground", action="store_true", help="(internal) force in-band run.")
    p.add_argument("--job-id", dest="job_id", type=int, default=None, help="(internal) job row to finalize.")
    p.set_defaults(func=run)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _now_epoch() -> int:
    return int(_dt.datetime.now(_dt.timezone.utc).timestamp())


def _recon_dir(cfg) -> Path:
    d = Path(cfg.engagement_dir) / "scans" / "recon"
    d.mkdir(parents=True, exist_ok=True)
    return d


def status_path(cfg) -> Path:
    return _recon_dir(cfg) / "recon-status.json"


def _stage_meta_path(cfg, stage_key: str) -> Path:
    return _recon_dir(cfg) / f"{stage_key}.meta.json"


def _fingerprint(apexes: list[str], args) -> str:
    """Deterministic id for the inputs that affect a stage's output, so a resume
    only reuses a checkpoint produced for the SAME run (generalizes the gau cache
    key idea to the pipeline)."""
    payload = json.dumps(
        {
            "apexes": sorted(a.strip() for a in apexes if a.strip()),
            "brute": bool(args.brute),
            "runtime": str(args.runtime),
            "no_crawl": bool(args.no_crawl),
            "no_gau": bool(getattr(args, "no_gau", False)),
        },
        sort_keys=True,
        ensure_ascii=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _artifact_present(cfg, stage: _Stage) -> bool:
    # Presence, not size: a stage can legitimately complete with an EMPTY artifact
    # (nothing resolved / no historical URLs). Freshness is gated by the meta
    # (done + exit 0 + matching fingerprint); the artifact just has to exist so a
    # clean zero-result stage is not re-run on every --resume.
    return (Path(cfg.engagement_dir) / stage.artifact).is_file()


def _stage_is_fresh(cfg, stage: _Stage, fingerprint: str) -> bool:
    meta = _load_json(_stage_meta_path(cfg, stage.key))
    if not isinstance(meta, dict):
        return False
    if not meta.get("done") or meta.get("exit_code") not in (0, None):
        return False
    if meta.get("fingerprint") != fingerprint:
        return False
    return _artifact_present(cfg, stage)


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json_atomic(path: Path, payload: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def _stage_counts(cfg, stage: _Stage) -> dict:
    """Cheap line-count digest per stage artifact (no parsing of large files)."""
    p = Path(cfg.engagement_dir) / stage.artifact
    if not p.is_file():
        return {}
    if stage.key == "dns":
        return {"resolved_hosts": _count_lines(p)}
    if stage.key == "web":
        return {"live_probes": _count_lines(p)}
    if stage.key == "gau":
        return {"apexes_mined": _count_lines(p)}
    return {}


def _count_lines(p: Path) -> int:
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError:
        return 0


# --------------------------------------------------------------------------- #
# Status digest
# --------------------------------------------------------------------------- #


def _init_status(cfg, apexes, args, job_id, stages) -> dict:
    return {
        "apexes": apexes,
        "job_id": job_id,
        "fingerprint": _fingerprint(apexes, args),
        "overall_state": "running",
        "started_at": _utcnow_iso(),
        "updated_at": _utcnow_iso(),
        "stages": [
            {"key": s.key, "label": s.label, "state": "pending",
             "exit_code": None, "ran_at": None, "artifact": s.artifact, "counts": {}}
            for s in stages
        ],
    }


def _set_stage(status: dict, key: str, **fields) -> None:
    for entry in status["stages"]:
        if entry["key"] == key:
            entry.update(fields)
            break
    status["updated_at"] = _utcnow_iso()


# --------------------------------------------------------------------------- #
# Stage execution (in-process invocation of the existing composed verbs)
# --------------------------------------------------------------------------- #


def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if isinstance(code, int):
        return code
    return 0 if code in (None, "") else 1


def _run_dns(args, cfg) -> int:
    ns = SimpleNamespace(
        apexes=list(args.apexes),
        engagement_dir=args.engagement_dir,
        brute=bool(args.brute),
        runtime=args.runtime,
        stage_timeout=int(args.stage_timeout),
    )
    try:
        dns_discovery.run(ns)
        return 0
    except SystemExit as exc:
        # dns-discovery exits 0 when nothing resolved (a clean, non-error
        # outcome) and 2 when no apexes were given (an error).
        return _exit_code(exc)


def _run_web(args, cfg) -> int:
    resolved = Path(cfg.engagement_dir) / "scans" / "dns-discovery" / "resolved_hosts.txt"
    ns = SimpleNamespace(
        hosts_file=str(resolved),
        engagement_dir=args.engagement_dir,
        runtime=args.runtime,
        no_crawl=bool(args.no_crawl),
        stage_timeout=int(args.stage_timeout),
        db_path="",
    )
    try:
        web_discovery.run(ns)
        return 0
    except SystemExit as exc:
        return _exit_code(exc)


def _run_gau(args, cfg) -> int:
    """Historical-URL enrichment: run gau-endpoints per apex (in-container,
    cache-aware) and write a sentinel listing the apexes mined. gau is
    best-effort enrichment — a per-apex failure (e.g. a brand-new site with no
    archive history) is logged but never fails the stage; the sentinel is always
    written so the checkpoint marks gau done."""
    apexes = [a.strip() for a in args.apexes if a.strip()]
    processed: list[str] = []
    for apex in apexes:
        ns = SimpleNamespace(
            target=apex, source="gau", subs=True, providers="",
            refresh=False, max_cache_age_hours=24.0, db_override=None,
            phase="recon", timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir,
        )
        try:
            gau_endpoints.run(ns)
            processed.append(apex)
        except SystemExit as exc:
            if _exit_code(exc) == 0:
                processed.append(apex)
            else:
                print(f"recon: gau enrichment for {apex} exited {_exit_code(exc)} "
                      "(non-fatal; continuing).", file=sys.stderr)
        except Exception as exc:  # noqa: BLE001 — gau is best-effort; never fail the pipeline on it
            print(f"recon: gau enrichment for {apex} errored ({type(exc).__name__}: {exc}); "
                  "continuing.", file=sys.stderr)
    sentinel = _recon_dir(cfg) / "gau.done"
    sentinel.write_text("".join(f"{a}\n" for a in processed), encoding="utf-8")
    return 0


_STAGE_RUNNERS = {"dns": _run_dns, "web": _run_web, "gau": _run_gau}


# --------------------------------------------------------------------------- #
# Enforcement preflight
# --------------------------------------------------------------------------- #


def _effective_runtime(args) -> str:
    """The concrete runtime recon passes to its stages.

    Unlike the individual verbs' back-compat ``auto``→container default, recon's
    whole purpose is to keep DNS-heavy stages OFF the wedge-prone Docker Desktop
    userspace proxy (I-001), so ``auto`` resolves to **host on Docker Desktop**
    (container on native Linux / remote Docker). Explicit ``host``/``container``
    are honoured as-is (container = caller forced isolation)."""
    req = (getattr(args, "runtime", "auto") or "auto").strip().lower()
    if req in ("host", "container"):
        return req
    return "host" if runtime_route.detect_runtime().is_docker_desktop else "container"


def _enforce_host_routing(args, effective: str) -> None:
    """Fail fast (before any work) when the RESOLVED runtime is ``host`` but a
    required DNS-heavy/bulk host binary is missing — so the recon job refuses to
    silently degrade to the proxy-wedging container path. A container route
    (native Linux, or an explicit ``--runtime container``) is never enforced."""
    if effective != "host":
        return
    tools = list(_ENFORCED_TOOLS)
    if args.brute:
        tools.append(_BRUTE_TOOL)
    for tool in tools:
        try:
            runtime_route.resolve_runtime("host", tool=tool, enforce=True)
        except runtime_route.HostRoutingRequired as exc:
            raise AssessError(str(exc)) from exc


# --------------------------------------------------------------------------- #
# Background (detached host job) launch
# --------------------------------------------------------------------------- #


def _assess_entrypoint() -> Path:
    # recon.py = <root>/agent/scripts/assess/commands/recon.py;
    # the CLI entrypoint is <root>/agent/scripts/assess.py.
    return Path(__file__).resolve().parents[2] / "assess.py"


def _child_argv(args, job_id: int, runtime_value: str) -> list[str]:
    assess_py = _assess_entrypoint()
    if not assess_py.is_file():
        raise AssessError(f"recon --background: assess entrypoint not found at {assess_py}")
    argv = [str(assess_py)]
    if args.engagement_dir:
        argv += ["--engagement-dir", str(args.engagement_dir)]
    argv += ["recon", *list(args.apexes), "--foreground", "--job-id", str(job_id)]
    if args.brute:
        argv.append("--brute")
    if args.no_crawl:
        argv.append("--no-crawl")
    if getattr(args, "no_gau", False):
        argv.append("--no-gau")
    if args.resume:
        argv.append("--resume")
    # Pass the CONCRETE resolved runtime so the detached child does not re-decide.
    argv += ["--runtime", str(runtime_value), "--stage-timeout", str(int(args.stage_timeout))]
    return argv


def _launch_background(args) -> None:
    cfg = load_config(args.engagement_dir)
    effective = _effective_runtime(args)
    _enforce_host_routing(args, effective)  # fail before spawning a doomed detached child
    out_dir = _recon_dir(cfg)
    log_path = out_dir / "recon-job.log"
    audit_meta = {
        "tool": "recon",
        "apexes": list(args.apexes),
        "brute": bool(args.brute),
        "runtime": effective,
        "no_gau": bool(getattr(args, "no_gau", False)),
        "intent": "supervised recon pipeline (dns-discovery -> web-discovery -> gau)",
    }
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        created = client.post("jobs", {"status": "queued", "audit_metadata": audit_meta})
        job_id = int(created["id"])
        # stdout_path drives the Phase-0 exit-marker derivation
        # (<stdout>.with_suffix('.exit')) the sweeper/recon-status reconcile from.
        client.patch(f"jobs/{job_id}", {"stdout_path": str(log_path), "stderr_path": str(log_path)})
        child_argv = _child_argv(args, job_id, effective)
        logf = open(log_path, "ab")  # noqa: SIM115 — handed to the detached child
        try:
            subprocess.Popen(  # noqa: S603 — argv list, no shell
                child_argv,
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=logf,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            logf.close()
        client.patch(f"jobs/{job_id}", {"status": "running", "started_at": _utcnow_iso()})
    print(json.dumps(
        {
            "job_id": job_id,
            "status_file": str(status_path(cfg)),
            "log": str(log_path),
            "poll": f"vigil assess recon-status --job-id {job_id}",
        },
        indent=2,
        ensure_ascii=False,
    ))


def _finalize_job(cfg, job_id: int, exit_code: int, log_path: Path) -> None:
    """Finalize the detached child's own job row AND publish the host-side exit
    marker so the Phase-0 sweep-orphans/job_status reconciliation converges even
    if this PATCH races or fails."""
    marker = log_path.with_suffix(".exit")
    try:
        tmp = marker.with_suffix(".exit.tmp")
        tmp.write_text(str(int(exit_code)), encoding="utf-8")
        tmp.replace(marker)
    except OSError:
        pass
    final = "completed" if exit_code == 0 else "failed"
    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            client.patch(
                f"jobs/{int(job_id)}",
                {"status": final, "exit_code": int(exit_code), "ended_at": _utcnow_iso()},
                accept_409=True,
            )
    except AssessError:
        pass  # marker is the durable fallback


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def _apply_arg_defaults(args) -> None:
    for name, default in {
        "brute": False, "runtime": "auto", "no_crawl": False, "no_gau": False,
        "resume": False, "stage_timeout": 1800, "background": False,
        "foreground": False, "job_id": None,
    }.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def run(args) -> None:
    _apply_arg_defaults(args)
    if args.background and not args.foreground:
        _launch_background(args)
        return

    cfg = load_config(args.engagement_dir)
    effective = _effective_runtime(args)
    _enforce_host_routing(args, effective)
    # Pin the concrete route so each stage routes deterministically (recon's
    # auto→host-on-Docker-Desktop policy, resolved once here, not re-decided
    # per stage against the verbs' container-default auto).
    args.runtime = effective
    apexes = [a.strip() for a in args.apexes if a.strip()]
    if not apexes:
        raise AssessError("recon: no apexes given.")

    fingerprint = _fingerprint(apexes, args)
    stages = _build_stages(args)
    status = _init_status(cfg, apexes, args, args.job_id, stages)
    _write_json_atomic(status_path(cfg), status)

    overall_rc = 0
    for stage in stages:
        if args.resume and _stage_is_fresh(cfg, stage, fingerprint):
            _set_stage(status, stage.key, state="skipped", counts=_stage_counts(cfg, stage))
            _write_json_atomic(status_path(cfg), status)
            print(f"recon: stage {stage.label} skipped (fresh checkpoint).", file=sys.stderr)
            continue

        _set_stage(status, stage.key, state="running", ran_at=_utcnow_iso())
        _write_json_atomic(status_path(cfg), status)
        print(f"recon: stage {stage.label} starting.", file=sys.stderr)

        rc = _STAGE_RUNNERS[stage.key](args, cfg)
        counts = _stage_counts(cfg, stage)
        meta = {
            "done": rc == 0,
            "exit_code": rc,
            "ran_at_epoch": _now_epoch(),
            "fingerprint": fingerprint,
            "artifact": stage.artifact,
            "counts": counts,
        }
        _write_json_atomic(_stage_meta_path(cfg, stage.key), meta)
        _set_stage(status, stage.key, state="done" if rc == 0 else "failed",
                   exit_code=rc, counts=counts)
        _write_json_atomic(status_path(cfg), status)
        print(f"recon: stage {stage.label} {'done' if rc == 0 else f'failed (rc={rc})'} {counts}", file=sys.stderr)
        if rc != 0:
            overall_rc = rc
            # A failed DNS stage leaves no hosts for web-discovery; stop and let
            # the operator inspect recon-status rather than cascade failures.
            break

    status["overall_state"] = "done" if overall_rc == 0 else "failed"
    status["updated_at"] = _utcnow_iso()
    _write_json_atomic(status_path(cfg), status)

    # When invoked as a detached job child, finalize the row + publish the marker.
    if args.job_id is not None:
        log_path = _recon_dir(cfg) / "recon-job.log"
        _finalize_job(cfg, int(args.job_id), overall_rc, log_path)

    print(f"recon: pipeline {status['overall_state']}. "
          f"Review with `vigil assess recon-status`.", file=sys.stderr)
    if overall_rc != 0:
        sys.exit(overall_rc)
