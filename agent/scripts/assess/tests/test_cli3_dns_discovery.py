"""CLI-3 — dns-discovery regression coverage for two Codex PR#38 findings.

1. Empty-result staleness (finding 2): a no-result run must leave the canonical
   ``resolved_hosts.txt`` empty, never the prior run's stale hosts, so follow-on
   automation (``vigil assess web-discovery``) cannot consume stale data.
2. Host stall-kill scoping (finding 3): the host-route stall watchdog must kill
   ONLY the massdns/puredns processes that descend from THIS dns-discovery
   process — never a host-wide ``pkill -f`` that would also reap a concurrent
   engagement's brute or an unrelated operator job.
"""
from __future__ import annotations

import contextlib
import io
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import dns_discovery as dd
from assess.commands.kali_dnsx import DNSX_PROFILES, resolution_failures
from assess.lib.config import Config


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _run_args(engagement_dir: str, **overrides) -> SimpleNamespace:
    base = dict(dd._ARG_DEFAULTS)
    base.update({
        "apexes": ["example.com"],
        "engagement_dir": engagement_dir,
    })
    base.update(overrides)
    return SimpleNamespace(**base)


def _cfg(eng_dir: Path) -> Config:
    return Config(
        base_url="http://127.0.0.1:18000",
        engagement_dir=str(eng_dir),
        engagement_key="2026-06-15-000000-example",
        agent_root=str(eng_dir / "agent"),
    )


# --------------------------------------------------------------------------- #
# Finding 2 — empty-result run must NOT leave a stale resolved_hosts.txt.
# --------------------------------------------------------------------------- #


def test_empty_result_truncates_stale_resolved_hosts(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    out_dir = eng_dir / "scans" / "dns-discovery"
    out_dir.mkdir(parents=True)
    stale = out_dir / "resolved_hosts.txt"
    # A prior run for a DIFFERENT apex left hosts in the canonical path.
    stale.write_text("stale-a.old.example\nstale-b.old.example\n", encoding="utf-8")

    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    # This run resolves NOTHING (e.g. different apex, or everything was noise).
    monkeypatch.setattr(dd, "_discover_once", lambda *a, **k: (set(), []))

    err = io.StringIO()
    with pytest.raises(SystemExit) as exc, contextlib.redirect_stderr(err):
        dd.run(_run_args(str(eng_dir)))

    assert exc.value.code == 0
    assert "no hosts resolved" in err.getvalue()
    # The canonical artifact is truncated, not left holding the prior run's hosts.
    assert stale.is_file()
    assert stale.read_text(encoding="utf-8") == ""


def test_nonempty_result_writes_union(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    (eng_dir / "scans" / "dns-discovery").mkdir(parents=True)

    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(
        dd, "_discover_once",
        lambda *a, **k: ({"b.example.com", "a.example.com"}, ["example.com"]),
    )
    # Single pass: stop the convergence loop after pass 1 (no new parents).
    monkeypatch.setattr(dd, "_select_parent_targets", lambda *a, **k: [])

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        dd.run(_run_args(str(eng_dir), no_converge=True))

    resolved = eng_dir / "scans" / "dns-discovery" / "resolved_hosts.txt"
    assert resolved.read_text(encoding="utf-8") == "a.example.com\nb.example.com\n"


def test_dns_generation_owns_and_promotes_every_artifact(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    canonical = eng_dir / "scans" / "dns-discovery"
    canonical.mkdir(parents=True)
    (canonical / "subs_ct.txt").write_text("stale.example.com\n", encoding="utf-8")

    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))

    def discover_once(_args, cfg, _targets, _resolved, _pass_no):
        assert cfg.dns_run_uuid == "generation-one"
        for name, content in {
            "apexes.txt": "example.com\n",
            "subs_passive.txt": "api.example.com\n",
            "subs_merged.txt": "api.example.com\n",
            "wildcard_parents.txt": "example.com\n",
        }.items():
            path, container_path = dd._paths(cfg, name)
            assert "/runs/generation-one/" in container_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return {"api.example.com"}, []

    monkeypatch.setattr(dd, "_discover_once", discover_once)
    dd.run(_run_args(str(eng_dir), no_converge=True, run_uuid="generation-one"))

    for name in ("apexes.txt", "subs_passive.txt", "subs_merged.txt", "wildcard_parents.txt"):
        assert (canonical / name).read_text(encoding="utf-8")
    assert (canonical / "resolved_hosts.txt").read_text(encoding="utf-8") == "api.example.com\n"
    # An artifact from the prior accepted generation cannot survive when the
    # new accepted generation did not produce it.
    assert (canonical / "subs_ct.txt").read_text(encoding="utf-8") == ""
    manifest = json.loads((canonical / "generation.json").read_text(encoding="utf-8"))
    assert manifest["run_uuid"] == "generation-one"
    assert manifest["state"] == "accepted"
    assert "resolved_hosts.txt" in manifest["artifacts"]


def test_failed_dns_generation_preserves_last_accepted_canonical_files(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    canonical = eng_dir / "scans" / "dns-discovery"
    canonical.mkdir(parents=True)
    accepted = canonical / "subs_passive.txt"
    accepted.write_text("accepted.example.com\n", encoding="utf-8")

    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))

    def fail_after_writing(_args, cfg, _targets, _resolved, _pass_no):
        path, _ = dd._paths(cfg, "subs_passive.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("partial.example.com\n", encoding="utf-8")
        raise RuntimeError("stage failed")

    monkeypatch.setattr(dd, "_discover_once", fail_after_writing)
    with pytest.raises(RuntimeError, match="stage failed"):
        dd.run(_run_args(str(eng_dir), run_uuid="failed-generation"))

    assert accepted.read_text(encoding="utf-8") == "accepted.example.com\n"
    assert not (canonical / "generation.json").exists()


def test_dns_promotion_replace_failure_rolls_back_entire_canonical_generation(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    canonical = eng_dir / "scans" / "dns-discovery"
    run_dir = canonical / "runs" / "new-run"
    run_dir.mkdir(parents=True)
    for name in ("a.txt", "b.txt"):
        (canonical / name).write_text(f"old-{name}\n", encoding="utf-8")
        (run_dir / name).write_text(f"new-{name}\n", encoding="utf-8")
    old_manifest = {"run_uuid": "old-run", "state": "accepted"}
    (canonical / "generation.json").write_text(
        json.dumps(old_manifest), encoding="utf-8"
    )
    cfg = _cfg(eng_dir)
    cfg.dns_run_uuid = "new-run"

    original_replace = Path.replace
    replacements = 0

    def fail_second_artifact(source: Path, destination: Path):
        nonlocal replacements
        destination = Path(destination)
        if destination.parent == canonical and destination.name in {"a.txt", "b.txt"}:
            replacements += 1
            if replacements == 2:
                raise OSError("injected canonical replace failure")
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", fail_second_artifact)
    with pytest.raises(OSError, match="injected canonical replace failure"):
        dd._promote_generation(
            cfg, state="accepted", resolved_count=1, failure_count=0
        )

    assert (canonical / "a.txt").read_text(encoding="utf-8") == "old-a.txt\n"
    assert (canonical / "b.txt").read_text(encoding="utf-8") == "old-b.txt\n"
    assert json.loads((canonical / "generation.json").read_text()) == old_manifest


def test_concurrent_dns_promotions_publish_one_coherent_generation(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    canonical = eng_dir / "scans" / "dns-discovery"
    canonical.mkdir(parents=True)
    for name in ("a.txt", "b.txt"):
        (canonical / name).write_text(f"old-{name}\n", encoding="utf-8")
    (canonical / "generation.json").write_text(
        json.dumps({"run_uuid": "old-run", "state": "accepted"}), encoding="utf-8"
    )

    configs = {}
    for run_uuid in ("race-a", "race-b"):
        run_dir = canonical / "runs" / run_uuid
        run_dir.mkdir(parents=True)
        for name in ("a.txt", "b.txt"):
            (run_dir / name).write_text(f"{run_uuid}-{name}\n", encoding="utf-8")
        cfg = _cfg(eng_dir)
        cfg.dns_run_uuid = run_uuid
        configs[run_uuid] = cfg

    original_replace = Path.replace
    race_a_replaced_first = threading.Event()
    race_b_committed_manifest = threading.Event()

    def interleave_without_serialization(source: Path, destination: Path):
        destination = Path(destination)
        source_name = source.name
        if source_name.endswith("-race-a") and destination.name == "a.txt":
            result = original_replace(source, destination)
            race_a_replaced_first.set()
            race_b_committed_manifest.wait(timeout=0.5)
            return result
        if source_name.endswith("-race-b") and destination.name == "generation.json":
            result = original_replace(source, destination)
            race_b_committed_manifest.set()
            return result
        return original_replace(source, destination)

    monkeypatch.setattr(Path, "replace", interleave_without_serialization)
    errors: list[BaseException] = []

    def promote(run_uuid: str) -> None:
        try:
            dd._promote_generation(
                configs[run_uuid],
                state="accepted",
                resolved_count=1,
                failure_count=0,
            )
        except BaseException as exc:  # pragma: no cover - assertion reports it
            errors.append(exc)

    first = threading.Thread(target=promote, args=("race-a",))
    first.start()
    assert race_a_replaced_first.wait(timeout=2)
    second = threading.Thread(target=promote, args=("race-b",))
    second.start()
    first.join(timeout=3)
    second.join(timeout=3)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    accepted = json.loads((canonical / "generation.json").read_text())["run_uuid"]
    assert (canonical / "a.txt").read_text() == f"{accepted}-a.txt\n"
    assert (canonical / "b.txt").read_text() == f"{accepted}-b.txt\n"


# --------------------------------------------------------------------------- #
# Finding 3 — host stall-kill is scoped to this process's descendants.
# --------------------------------------------------------------------------- #


def test_host_kill_only_targets_own_descendants(monkeypatch):
    """The host route must kill only massdns/puredns PIDs that descend from this
    process — a sibling engagement's brute (a PID outside the descendant set) is
    left untouched. NO host-wide ``pkill -f`` is issued."""
    monkeypatch.setattr(dd.os, "getpid", lambda: 1000)

    # Process tree: this proc (1000) -> puredns (2000) -> massdns (2001).
    # PID 9999 is an UNRELATED puredns from another engagement/job.
    children = {1000: [2000], 2000: [2001], 2001: []}
    pgrep_name = {"puredns": [2000, 9999], "massdns": [2001]}

    killed: list[int] = []
    pkill_invoked: list[list[str]] = []

    def fake_run(argv, **kwargs):
        if argv[0] == "pgrep" and argv[1] == "-P":
            kids = children.get(int(argv[2]), [])
            return SimpleNamespace(stdout="\n".join(str(p) for p in kids), returncode=0)
        if argv[0] == "pgrep" and argv[1] == "-f":
            pids = pgrep_name.get(argv[2], [])
            return SimpleNamespace(stdout="\n".join(str(p) for p in pids), returncode=0)
        if argv[0] == "kill":
            killed.append(int(argv[2]))
            return SimpleNamespace(stdout="", returncode=0)
        if argv[0] == "pkill":  # the old, dangerous host-wide path
            pkill_invoked.append(list(argv))
            return SimpleNamespace(stdout="", returncode=0)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(dd.subprocess, "run", fake_run)

    dd._kill_brute_processes("host")

    # Own puredns + own massdns killed; the sibling-engagement puredns (9999) is NOT.
    assert sorted(killed) == [2000, 2001]
    assert 9999 not in killed
    # And we never reverted to a host-wide pkill -f.
    assert pkill_invoked == []


def test_host_kill_no_descendants_is_noop(monkeypatch):
    """If pgrep finds no descendants (or is unavailable), kill nothing at all
    rather than falling back to a host-wide sweep."""
    monkeypatch.setattr(dd.os, "getpid", lambda: 1000)

    killed: list[int] = []

    def fake_run(argv, **kwargs):
        if argv[0] == "pgrep" and argv[1] == "-P":
            return SimpleNamespace(stdout="", returncode=1)  # no children
        if argv[0] == "kill":
            killed.append(int(argv[2]))
        if argv[0] == "pkill":
            raise AssertionError("must not fall back to host-wide pkill")
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(dd.subprocess, "run", fake_run)
    dd._kill_brute_processes("host")
    assert killed == []


def test_container_kill_uses_docker_exec_pkill(monkeypatch):
    """Container route is the runtime container (Vigil's own single-tenant box),
    so the scoped docker-exec pkill is retained unchanged."""
    monkeypatch.setattr(
        "assess.lib.client.default_runtime_container", lambda: "vigil"
    )
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(dd.subprocess, "run", fake_run)
    dd._kill_brute_processes("container")

    assert ["docker", "exec", "vigil", "pkill", "-9", "-f", "massdns"] in calls
    assert ["docker", "exec", "vigil", "pkill", "-9", "-f", "puredns"] in calls


# --------------------------------------------------------------------------- #
# I-3 — fail-fast ``brute-resolve`` dnsx profile for the big permutation pass.
#
# Resolving a huge, mostly-dead permutation/brute candidate set under the
# polite-cdn profile (retry=3, timeout=5) pays 3 retries × 5s on every dead
# name. A dedicated low-retry/short-timeout/high-rate ``brute-resolve`` profile
# (retry=1, timeout~2) makes the permutation resolve pass fail fast. It is
# auto-selected when --brute is active AND the operator left --dnsx-profile at
# its default; an explicit --dnsx-profile is always honored.
# --------------------------------------------------------------------------- #


def _flag_value(cmd: list[str], flag: str) -> str:
    idx = cmd.index(flag)
    return cmd[idx + 1]


def test_brute_resolve_profile_is_defined_low_retry_short_timeout_high_rate():
    assert "brute-resolve" in DNSX_PROFILES
    prof = DNSX_PROFILES["brute-resolve"]
    assert prof.retry == 1, "brute-resolve must fail fast: a single retry"
    assert prof.timeout <= 2, "brute-resolve must use a short (~2s) per-query timeout"
    # High rate: at least the bursty-ok ceiling (the documented Docker-safe max).
    assert prof.rate_limit >= DNSX_PROFILES["bursty-ok"].rate_limit


def _capture_resolve_cmd(monkeypatch, **arg_overrides) -> list[str]:
    captured: list[list[str]] = []

    def fake_exec(args, cmd, intent, tool_name, *, route="container"):
        captured.append(list(cmd))
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(dd, "_exec", fake_exec)
    args = _run_args("/tmp/eng", **arg_overrides)
    dd._resolve_stage(args, None, "merged.txt", "resolved.txt", "container")
    assert captured, "expected a dnsx resolve command to be issued"
    return captured[-1]


def test_resolve_stage_uses_brute_resolve_when_bruting_with_default_profile(monkeypatch):
    cmd = _capture_resolve_cmd(monkeypatch, brute=True, dnsx_profile="polite-cdn")
    prof = DNSX_PROFILES["brute-resolve"]
    assert _flag_value(cmd, "-retry") == str(prof.retry) == "1"
    assert _flag_value(cmd, "-timeout") == str(prof.timeout)
    assert _flag_value(cmd, "-rl") == str(prof.rate_limit)


def test_resolve_stage_keeps_polite_cdn_when_not_bruting(monkeypatch):
    cmd = _capture_resolve_cmd(monkeypatch, brute=False, dnsx_profile="polite-cdn")
    # polite-cdn keeps the patient retry budget for the real passive/CT name set.
    assert _flag_value(cmd, "-retry") == str(DNSX_PROFILES["polite-cdn"].retry) == "3"


def test_resolve_stage_respects_explicit_profile_override_even_when_bruting(monkeypatch):
    cmd = _capture_resolve_cmd(monkeypatch, brute=True, dnsx_profile="bursty-ok")
    # Operator explicitly chose bursty-ok: do NOT silently swap to brute-resolve.
    assert _flag_value(cmd, "-retry") == str(DNSX_PROFILES["bursty-ok"].retry) == "2"


# --------------------------------------------------------------------------- #
# I-6 — resolver surfaces a per-host resolution-FAILURE signal (I-006 class).
#
# dnsx resolves with ``-silent``, so an in-scope host that ENTERS the resolver
# but produces no A/AAAA (e.g. a CNAME pointing off-network or a dangling CNAME —
# a subdomain-takeover lead) is omitted from the ``-o`` output with no trace.
# Diffing the resolver INPUT host-set against the resolved OUTPUT host-set must
# surface that gap as an explicit resolution-failure signal (logged + in the
# command result), never a silent drop. This is NOT the unbounded-permutation
# brute hazard guard (a separate code path) — raw brute guesses never reach the
# resolve input; puredns validates them first.
# --------------------------------------------------------------------------- #


def test_resolution_failures_diffs_input_against_resolved():
    """Pure helper: hosts in the resolve INPUT but absent from the resolved OUTPUT
    are returned (sorted, de-duped, case/trailing-dot-insensitive); blanks drop."""
    resolver_input = ["A.example.com", "dangling.example.com", "resolves.example.com", ""]
    resolved_output = ["resolves.example.com", "a.example.com."]  # case + trailing dot
    assert resolution_failures(resolver_input, resolved_output) == ["dangling.example.com"]


def test_resolution_failures_empty_when_all_resolved():
    assert resolution_failures(["a.example.com", "b.example.com"],
                               ["b.example.com", "a.example.com"]) == []


def test_discover_once_surfaces_in_scope_resolution_failure(tmp_path, monkeypatch):
    """An in-scope host that goes INTO the resolve but yields no A/AAAA must come
    back as an explicit resolution failure (3rd return element + a WARN), never
    vanish from the output."""
    eng_dir = tmp_path / "eng"
    (eng_dir / "scans" / "dns-discovery").mkdir(parents=True)
    cfg = _cfg(eng_dir)

    # Two in-scope hosts enter the resolve; only one produces an address.
    seed = {"resolves.example.com", "dangling.example.com"}

    def fake_resolve_stage(args, cfg_, merged_arg, resolved_arg, route):
        # dnsx -silent writes ONLY the host that produced an A record; the
        # dangling-CNAME host is omitted with no trace.
        host, _ = dd._paths(cfg_, "resolved_hosts.txt")
        host.write_text("resolves.example.com\n", encoding="utf-8")

    monkeypatch.setattr(dd, "_resolve_stage", fake_resolve_stage)
    monkeypatch.setattr(dd, "_route_for", lambda args, tool: "container")

    args = _run_args(str(eng_dir), no_passive=True, no_ct=True, brute=False)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        resolved, bruted, failures = dd._discover_once(args, cfg, ["example.com"], set(seed), 1)

    assert resolved == {"resolves.example.com"}
    assert failures == {"dangling.example.com"}
    # Logged, not silently dropped.
    assert "dangling.example.com" in err.getvalue()
    assert "resolution failure" in err.getvalue().lower()


def test_run_writes_resolution_failure_artifact(tmp_path, monkeypatch):
    """``run`` persists the canonical resolution-failure artifact and reports it."""
    eng_dir = tmp_path / "eng"
    (eng_dir / "scans" / "dns-discovery").mkdir(parents=True)
    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(
        dd, "_discover_once",
        lambda *a, **k: ({"a.example.com"}, ["example.com"], {"dangling.example.com"}),
    )
    monkeypatch.setattr(dd, "_select_parent_targets", lambda *a, **k: [])

    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        dd.run(_run_args(str(eng_dir), no_converge=True))

    failures = eng_dir / "scans" / "dns-discovery" / "resolution_failures.txt"
    assert failures.read_text(encoding="utf-8") == "dangling.example.com\n"
    assert "dangling.example.com" in err.getvalue()


def test_resolution_failure_artifact_truncates_stale_and_excludes_resolved(tmp_path, monkeypatch):
    """A host that ALSO resolved (a later-pass win) is not a failure, and a prior
    run's stale failure list is truncated — never left to mislead follow-on work."""
    eng_dir = tmp_path / "eng"
    out = eng_dir / "scans" / "dns-discovery"
    out.mkdir(parents=True)
    (out / "resolution_failures.txt").write_text("old-stale.example.com\n", encoding="utf-8")

    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(
        dd, "_discover_once",
        lambda *a, **k: ({"now.example.com"}, ["example.com"], {"now.example.com"}),
    )
    monkeypatch.setattr(dd, "_select_parent_targets", lambda *a, **k: [])

    with contextlib.redirect_stderr(io.StringIO()):
        dd.run(_run_args(str(eng_dir), no_converge=True))

    assert (out / "resolution_failures.txt").read_text(encoding="utf-8") == ""


def test_resolution_failures_surfaced_even_when_nothing_resolved(tmp_path, monkeypatch):
    """The worst I-6 case — every in-scope host pointed off-network so the resolve
    produced ZERO hosts — must STILL surface the failures, not bury them behind
    the 'no hosts resolved' early-exit."""
    eng_dir = tmp_path / "eng"
    (eng_dir / "scans" / "dns-discovery").mkdir(parents=True)
    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    monkeypatch.setattr(
        dd, "_discover_once",
        lambda *a, **k: (set(), ["example.com"], {"off.example.com", "net.example.com"}),
    )
    monkeypatch.setattr(dd, "_select_parent_targets", lambda *a, **k: [])

    err = io.StringIO()
    with pytest.raises(SystemExit) as exc, contextlib.redirect_stderr(err):
        dd.run(_run_args(str(eng_dir), no_converge=True))

    assert exc.value.code == 0
    failures = eng_dir / "scans" / "dns-discovery" / "resolution_failures.txt"
    assert failures.read_text(encoding="utf-8") == "net.example.com\noff.example.com\n"
    assert "no hosts resolved" in err.getvalue()


def test_brute_engagement_dir_canonicalized_when_flag_is_none(monkeypatch, tmp_path):
    """Regression: ``dns-discovery --brute`` / ``recon --brute`` with no explicit
    ``--engagement-dir`` left ``args.engagement_dir=None``, which crashed the
    puredns brute lock (``network_heavy_lock(None)`` -> ``Path(None)`` TypeError)
    and silently skipped host-route required-header injection. ``run()`` must
    canonicalize it to the resolved cfg dir before any stage consumes it."""
    eng_dir = tmp_path / "eng"
    monkeypatch.setattr(dd, "load_config", lambda _flag: _cfg(eng_dir))
    # Empty apexes -> a clean early ``sys.exit(2)`` right AFTER canonicalization,
    # so the assertion exercises the fix without driving the whole brute pipeline.
    args = _run_args(None, brute=True, apexes=[])
    assert args.engagement_dir is None
    with pytest.raises(SystemExit) as exc:
        dd.run(args)
    assert exc.value.code == 2
    assert args.engagement_dir == str(eng_dir)  # canonicalized in place
