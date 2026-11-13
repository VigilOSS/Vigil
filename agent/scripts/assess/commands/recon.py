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

import contextlib
import datetime as _dt
import hashlib
import json
import os
import signal
import subprocess
import sys
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace

from assess.commands import dns_discovery, gau_endpoints, js_mining, web_discovery
from assess.lib import host_processes, runtime_route, scope
from assess.lib.run_notices import notice_scope
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config

# DNS-heavy / bulk tools the pipeline uses that MUST be host-routed on macOS
# Docker Desktop (I-001). The preflight enforces host availability for these.
_ENFORCED_TOOLS = ("subfinder", "dnsx", "httpx")
_BRUTE_TOOL = ("puredns", "massdns")  # massdns is puredns's required resolver binary


@dataclass(frozen=True)
class _Stage:
    key: str
    label: str
    artifact: str  # canonical checkpoint artifact, relative to the engagement dir


_DNS_STAGE = _Stage("dns", "dns-discovery", "scans/dns-discovery/resolved_hosts.txt")
_WEB_STAGE = _Stage("web", "web-discovery", "scans/web-discovery/httpx_live.jsonl")
# js-mining runs AFTER the web crawl; its sentinel records the mining summary.
_JS_STAGE = _Stage("js", "js-mining", "scans/web-discovery/js-mining/js-mining.done")
# gau is per-apex + in-container; its sentinel artifact records the apexes mined.
_GAU_STAGE = _Stage("gau", "gau-endpoints", "scans/recon/gau.done")


@dataclass(frozen=True)
class _StageOutcome:
    """What a stage runner reports back to the loop.

    ``fatal`` stops the pipeline on a non-zero ``rc`` (dns/web: nothing
    downstream can run without them). A best-effort stage (js-mining, gau) is
    not fatal: its failure is recorded with ``counts`` for the work that DID
    complete and ``errors`` naming what did not, and the next stage still runs.
    ``partial`` marks a stage that completed (``rc`` 0) while some of its rows
    did not land — the backend refused them, or their write outcome is unknown —
    so it reads ``partial`` rather than ``done``.
    """

    rc: int
    counts: dict = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    fatal: bool = True
    partial: bool = False


# Per-stage states. ``done`` / ``skipped`` / ``partial`` stages produced their
# artifact; ``failed`` did not. The pipeline's ``overall_state`` is ``done`` when
# every stage is done or skipped, ``failed`` when a fatal stage failed (the
# pipeline stopped there), and ``partial`` otherwise: it ran to the end but at
# least one stage failed or is partial.
_SETTLED_STAGE_STATES = ("done", "skipped", "partial")


def _overall_state(stages: list[dict], *, fatal_failure: bool) -> str:
    if fatal_failure:
        return "failed"
    if all(stage.get("state") in ("done", "skipped") for stage in stages):
        return "done"
    return "partial"


def _unlanded_rows(summary: object, *, unit: str) -> tuple[dict, list[str]]:
    """Counts and errors for ingest rows a stage's summary says did not land.

    ``summary`` is a verb summary carrying the ingest's ``backend_refused`` and
    ``write_uncertain`` counts (gau-endpoints, js-mining). Each refused or
    uncertain row is named, with the backend's reason, in a WARN line of the
    stage's stderr — the recon job log under ``--background`` — so the error
    says where to read them.
    """
    if not isinstance(summary, dict):
        return {}, []
    counts: dict = {}
    errors: list[str] = []
    refused = int(summary.get("backend_refused") or 0)
    uncertain = int(summary.get("write_uncertain") or 0)
    if refused:
        counts["backend_refused"] = refused
        errors.append(
            f"{unit}: {refused} row(s) the backend refused are not in the work buffer; "
            "each is named with its reason in an 'ingest-endpoints: backend rejected' "
            "WARN line of this run's stderr (the recon job log under --background)"
        )
    if uncertain:
        counts["write_uncertain"] = uncertain
        errors.append(
            f"{unit}: {uncertain} row(s) whose write failed with an unknown outcome may "
            "or may not be in the work buffer; each is named in an 'ingest-endpoints: "
            "write of ... failed with an unknown outcome' WARN line of this run's stderr"
        )
    return counts, errors


def _as_outcome(result) -> _StageOutcome:
    return result if isinstance(result, _StageOutcome) else _StageOutcome(rc=int(result))


class _StderrTail:
    """Tee ``sys.stderr`` while keeping its last few lines.

    A best-effort stage's inner command prints its real error (an HTTP 422, a
    transport failure) to stderr and then exits 1; the tail lets the stage
    record carry that error instead of only the exit code. Everything is still
    written through to the real stream.
    """

    def __init__(self, stream, *, keep: int = 3) -> None:
        self._stream = stream
        self._partial = ""
        self.lines: deque[str] = deque(maxlen=keep)

    def write(self, text: str) -> int:
        self._stream.write(text)
        chunks = (self._partial + text).split("\n")
        self._partial = chunks.pop()
        self.lines.extend(line.strip() for line in chunks if line.strip())
        return len(text)

    def flush(self) -> None:
        self._stream.flush()

    def __getattr__(self, name):
        return getattr(self._stream, name)

    def tail(self) -> str:
        lines = list(self.lines)
        if self._partial.strip():
            lines.append(self._partial.strip())
        return " | ".join(lines[-3:])


def _build_stages(args) -> tuple[_Stage, ...]:
    """The active stage list. gau + js-mining are ON by default; --no-gau drops
    the historical-URL stage (e.g. a brand-new site with no archive history) and
    --no-js-mining drops the JS endpoint/secret mining stage."""
    stages = [_DNS_STAGE, _WEB_STAGE]
    if not getattr(args, "no_js_mining", False):
        stages.append(_JS_STAGE)
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
    p.add_argument("--no-js-mining", dest="no_js_mining", action="store_true",
                   help="Skip the JS endpoint/secret mining stage (ON by default). It mines "
                        "the crawled .js assets for hidden routes + leaked secrets; best-effort.")
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
            "no_js_mining": bool(getattr(args, "no_js_mining", False)),
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
    if stage.key == "js":
        return {"js_mined": _count_lines(p)}
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
        "run_uuid": uuid.uuid4().hex,
        "apexes": apexes,
        "job_id": job_id,
        "fingerprint": _fingerprint(apexes, args),
        "overall_state": "running",
        "started_at": _utcnow_iso(),
        "updated_at": _utcnow_iso(),
        "stages": [
            {"key": s.key, "label": s.label, "state": "pending",
             "exit_code": None, "ran_at": None, "artifact": s.artifact, "counts": {},
             "errors": []}
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


def _apply_scope_filter(cfg, resolved: Path) -> Path:
    """Filter the resolved host set to in-scope hosts BETWEEN the dns and web
    stages, returning the path the web stage should consume.

    Subdomain enumeration + wildcard expansion routinely surface hosts that the
    program carved OUT of scope (e.g. telecom-PTR space, a vendor apex, an
    explicit ``out_of_scope`` entry). denoise_hosts only strips structural noise;
    it does NOT know the engagement's scope. Filtering here, before web-discovery
    probes anything, keeps the bulk httpx/katana passes off out-of-scope hosts —
    the same admission primitive (``host_admitted``: allowlist AND not denylist)
    that ``filter-scope`` uses.

    Degrades gracefully: a missing/malformed scope, or no in-scope allow entries
    (an internal engagement that does not author a host allowlist), returns the
    ORIGINAL resolved file unchanged so the stage never drops every host on a
    scope-read hiccup. Writes the filtered set to ``scans/recon/in_scope_hosts.txt``
    and returns that path only when filtering actually applied."""
    if not resolved.is_file():
        return resolved
    try:
        scope_doc = scope.load_scope(str(cfg.engagement_dir))
    except SystemExit:
        # load_scope/scope_entries raise SystemExit on a missing/malformed scope;
        # in the recon job that must not abort the stage — fall through unfiltered.
        return resolved
    raw_lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    kept, metadata = scope.filter_recon_targets(scope_doc, raw_lines)
    _write_json_atomic(_recon_dir(cfg) / "scope-filter.meta.json", metadata)
    _record_discovered_hosts(cfg, kept)
    dropped = int(metadata["dropped_count"])
    if dropped == 0:
        # Everything already in scope — no need to fork a separate file.
        return resolved
    out = _recon_dir(cfg) / "in_scope_hosts.txt"
    out.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")
    print(f"recon: scope filter kept {len(kept)} / {len(kept) + dropped} resolved hosts "
          f"({dropped} out-of-scope/unscoped dropped before web-discovery).", file=sys.stderr)
    return out


def _record_discovered_hosts(cfg, candidates: list[str]) -> None:
    """Best-effort derived inventory; bookkeeping never aborts recon coverage."""
    try:
        scope.record_discovered_hosts(str(cfg.engagement_dir), candidates)
    except (OSError, ValueError, SystemExit) as exc:
        print(
            f"WARN: could not update scope.json discovered_hosts inventory: {exc}",
            file=sys.stderr,
        )


def _run_web(args, cfg) -> int:
    resolved = Path(cfg.engagement_dir) / "scans" / "dns-discovery" / "resolved_hosts.txt"
    hosts_file = _apply_scope_filter(cfg, resolved)
    ns = SimpleNamespace(
        hosts_file=str(hosts_file),
        engagement_dir=args.engagement_dir,
        runtime=args.runtime,
        no_crawl=bool(args.no_crawl),
        stage_timeout=int(args.stage_timeout),
        db_path="",
        run_uuid=getattr(args, "run_uuid", None),
    )
    try:
        web_discovery.run(ns)
        return 0
    except SystemExit as exc:
        return _exit_code(exc)


def _run_js(args, cfg) -> _StageOutcome:
    """JS endpoint + secret mining over the web-discovery crawl output. Best-effort:
    a failure never stops the pipeline, but it is recorded — an exception, a
    non-zero exit, or a step js-mining itself reports in its summary ``errors``
    (an endpoint ingest the backend refused) marks the stage failed with the
    error. ``undecodable_bodies`` rides into the stage counts. The sentinel is
    always written. Carries the engagement's attribution header + rate cap via
    js_mining's kali_exec body fetch."""
    katana = Path(cfg.engagement_dir) / "scans" / "web-discovery" / "katana.jsonl"
    sentinel = Path(cfg.engagement_dir) / "scans" / "web-discovery" / "js-mining" / "js-mining.done"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    # Endpoint ingest goes to the backend work buffer (js-mining ingests by
    # default); no cases.db path to thread through.
    ns = SimpleNamespace(
        urls_file=str(katana) if katana.is_file() else "",
        target="",
        max_js=js_mining._DEFAULT_MAX_JS,
        httpx_rate_limit="30",
        httpx_threads="20",
        cap_body_bytes=2097152,
        verify=False,
        no_secrets=False,
        stage_timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir,
    )
    mined = 0
    counts: dict = {}
    errors: list[str] = []
    unlanded: list[str] = []
    try:
        summary = js_mining.run(ns)
        if isinstance(summary, dict):
            if "undecodable_bodies" in summary:
                counts["undecodable_bodies"] = int(summary["undecodable_bodies"])
            errors.extend(str(error) for error in summary.get("errors") or [])
            unlanded_counts, unlanded = _unlanded_rows(summary, unit="js-mining")
            counts.update(unlanded_counts)
        endpoints = (Path(cfg.engagement_dir) / "scans" / "web-discovery"
                     / "js-mining" / "js_endpoints.txt")
        if endpoints.is_file():
            mined = sum(1 for line in endpoints.read_text(
                encoding="utf-8", errors="replace").splitlines() if line.strip())
    except SystemExit as exc:
        if _exit_code(exc) != 0:
            errors.append(f"js-mining exited {_exit_code(exc)}")
    except Exception as exc:  # noqa: BLE001 — js-mining is best-effort; never stop the pipeline
        errors.append(f"js-mining errored ({type(exc).__name__}: {exc})")
    sentinel.write_text("".join(f"{i}\n" for i in range(mined)), encoding="utf-8")
    return _StageOutcome(
        rc=1 if errors else 0,
        counts=counts,
        errors=tuple(errors + unlanded),
        fatal=False,
        partial=bool(unlanded),
    )


def _run_gau(args, cfg) -> _StageOutcome:
    """Historical-URL enrichment: run gau-endpoints per apex (in-container,
    cache-aware) and write a sentinel listing the apexes mined. Best-effort: a
    per-apex failure never stops the pipeline, but it marks the stage failed
    with ``apexes_failed`` and an error naming the apex, its exit code and the
    last lines it printed, so an ingest the backend refused is visible on the
    status surface. Rows the backend refused (or whose write outcome is
    unknown) in an apex's ingest leave the stage ``partial`` with a
    ``backend_refused`` / ``write_uncertain`` count and an error naming the apex.
    A brand-new site with no archive history is not a failure (gau exits 0 with
    an empty corpus)."""
    apexes = [a.strip() for a in args.apexes if a.strip()]
    processed: list[str] = []
    errors: list[str] = []
    unlanded: list[str] = []
    unlanded_counts: dict = {}
    first_rc = 0
    for apex in apexes:
        ns = SimpleNamespace(
            target=apex, source="gau", subs=True, providers="",
            refresh=False, max_cache_age_hours=24.0, db_override=None,
            phase="recon", timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir,
        )
        tail = _StderrTail(sys.stderr)
        failure = ""
        rc = 0
        summary = None
        try:
            with contextlib.redirect_stderr(tail):
                summary = gau_endpoints.run(ns)
        except SystemExit as exc:
            rc = _exit_code(exc)
            if rc != 0:
                failure = f"gau-endpoints exited {rc}"
        except Exception as exc:  # noqa: BLE001 — gau is best-effort; never stop the pipeline on it
            rc = 1
            failure = f"gau-endpoints errored ({type(exc).__name__}: {exc})"
        if not failure:
            processed.append(apex)
            apex_counts, apex_unlanded = _unlanded_rows(summary, unit=apex)
            for key, value in apex_counts.items():
                unlanded_counts[key] = unlanded_counts.get(key, 0) + value
            unlanded.extend(apex_unlanded)
            continue
        first_rc = first_rc or rc
        detail = tail.tail()
        errors.append(f"{apex}: {failure}" + (f"; last output: {detail}" if detail else ""))
    sentinel = _recon_dir(cfg) / "gau.done"
    sentinel.write_text("".join(f"{a}\n" for a in processed), encoding="utf-8")
    counts = {"apexes_failed": len(errors)} if errors else {}
    counts.update(unlanded_counts)
    return _StageOutcome(
        rc=first_rc,
        counts=counts,
        errors=tuple(errors + unlanded),
        fatal=False,
        partial=bool(unlanded),
    )


_STAGE_RUNNERS = {"dns": _run_dns, "web": _run_web, "js": _run_js, "gau": _run_gau}


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
        tools.extend(_BRUTE_TOOL)
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
    if getattr(args, "no_js_mining", False):
        argv.append("--no-js-mining")
    if args.resume:
        argv.append("--resume")
    # Pass the CONCRETE resolved runtime so the detached child does not re-decide.
    argv += ["--runtime", str(runtime_value), "--stage-timeout", str(int(args.stage_timeout))]
    return argv


def _job_log_path(cfg, job_id: int) -> Path:
    return _recon_dir(cfg) / f"recon-job-{int(job_id)}.log"


def _launch_background(args) -> None:
    cfg = load_config(args.engagement_dir)
    effective = _effective_runtime(args)
    _enforce_host_routing(args, effective)  # fail before spawning a doomed detached child
    audit_meta = {
        "tool": "recon",
        "apexes": list(args.apexes),
        "brute": bool(args.brute),
        "runtime": effective,
        "no_gau": bool(getattr(args, "no_gau", False)),
        "no_js_mining": bool(getattr(args, "no_js_mining", False)),
        "intent": "supervised recon pipeline (dns-discovery -> web-discovery -> js-mining -> gau)",
    }
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        created = client.post("jobs", {"status": "queued", "audit_metadata": audit_meta})
        job_id = int(created["id"])
        log_path = _job_log_path(cfg, job_id)
        # stdout_path drives the Phase-0 exit-marker derivation
        # (<stdout>.with_suffix('.exit')) the sweeper/recon-status reconcile from.
        client.patch(f"jobs/{job_id}", {"stdout_path": str(log_path), "stderr_path": str(log_path)})
        child_argv = _child_argv(args, job_id, effective)
        logf = open(log_path, "ab")  # noqa: SIM115 — handed to the detached child
        try:
            process = subprocess.Popen(  # noqa: S603 — argv list, no shell
                child_argv,
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=logf,
                start_new_session=True,
                close_fds=True,
            )
        finally:
            logf.close()
        try:
            host_processes.register_process(
                cfg.engagement_dir,
                run_uuid=f"recon-job-{job_id}",
                pid=process.pid,
            )
        except Exception as exc:
            _terminate_background_process(process)
            client.patch(
                f"jobs/{job_id}",
                {"status": "failed", "ended_at": _utcnow_iso()},
                accept_409=True,
            )
            raise AssessError(
                f"recon --background could not register child ownership: {exc}"
            ) from exc
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


def _terminate_background_process(process) -> None:
    """Boundedly reap the newly-created session when ownership registration fails."""
    for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 2)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


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
    finally:
        host_processes.unregister_process(
            cfg.engagement_dir, run_uuid=f"recon-job-{int(job_id)}"
        )


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def _apply_arg_defaults(args) -> None:
    for name, default in {
        "brute": False, "runtime": "auto", "no_crawl": False, "no_gau": False,
        "no_js_mining": False, "resume": False, "stage_timeout": 1800,
        "background": False, "foreground": False, "job_id": None,
    }.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def run(args) -> None:
    _apply_arg_defaults(args)
    if args.background and not args.foreground:
        _launch_background(args)
        return
    # One run scope for the whole pipeline: an advisory every stage's tool runs
    # would print (target concurrency, attribution headers a tool cannot carry)
    # prints once for the job, child processes included.
    with notice_scope():
        _run_pipeline(args)


def _run_pipeline(args) -> None:
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
    args.run_uuid = status["run_uuid"]
    _write_json_atomic(status_path(cfg), status)

    overall_rc = 0
    fatal_failure = False
    for stage in stages:
        if args.resume and _stage_is_fresh(cfg, stage, fingerprint):
            _set_stage(status, stage.key, state="skipped", counts=_stage_counts(cfg, stage))
            _write_json_atomic(status_path(cfg), status)
            print(f"recon: stage {stage.label} skipped (fresh checkpoint).", file=sys.stderr)
            continue

        _set_stage(status, stage.key, state="running", ran_at=_utcnow_iso())
        _write_json_atomic(status_path(cfg), status)
        print(f"recon: stage {stage.label} starting.", file=sys.stderr)

        outcome = _as_outcome(_STAGE_RUNNERS[stage.key](args, cfg))
        rc = outcome.rc
        # A fatal failure produced nothing worth counting; a best-effort stage
        # keeps the counts of the work that did complete beside its errors.
        counts = (
            {**_stage_counts(cfg, stage), **outcome.counts}
            if rc == 0 or not outcome.fatal
            else {}
        )
        errors = list(outcome.errors)
        meta = {
            "run_uuid": status["run_uuid"],
            "done": rc == 0,
            "exit_code": rc,
            "ran_at_epoch": _now_epoch(),
            "fingerprint": fingerprint,
            "artifact": stage.artifact,
            "counts": counts,
            "errors": errors,
        }
        _write_json_atomic(_stage_meta_path(cfg, stage.key), meta)
        if rc != 0:
            state = "failed"
        else:
            state = "partial" if outcome.partial else "done"
        _set_stage(status, stage.key, state=state, exit_code=rc, counts=counts, errors=errors)
        _write_json_atomic(status_path(cfg), status)
        print(f"recon: stage {stage.label} {state if rc == 0 else f'failed (rc={rc})'} {counts}", file=sys.stderr)
        for error in errors:
            print(f"recon: stage {stage.label} error: {error}"
                  + ("" if outcome.fatal else " (best-effort stage; continuing)"),
                  file=sys.stderr)
        if rc != 0:
            overall_rc = overall_rc or rc
            if outcome.fatal:
                # A failed DNS stage leaves no hosts for web-discovery; stop and
                # let the operator inspect recon-status rather than cascade.
                fatal_failure = True
                break

    # The exit code (and so a background job row's status) still reports any
    # failed stage; ``overall_state`` says whether the rest of the pipeline ran.
    status["overall_state"] = _overall_state(status["stages"], fatal_failure=fatal_failure)
    status["updated_at"] = _utcnow_iso()
    _write_json_atomic(status_path(cfg), status)

    # When invoked as a detached job child, finalize the row + publish the marker.
    if args.job_id is not None:
        log_path = _job_log_path(cfg, int(args.job_id))
        _finalize_job(cfg, int(args.job_id), overall_rc, log_path)

    print(f"recon: pipeline {status['overall_state']}. "
          f"Review with `vigil assess recon-status`.", file=sys.stderr)
    if overall_rc != 0:
        sys.exit(overall_rc)
