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
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import dns_discovery as dd
from assess.commands.kali_dnsx import DNSX_PROFILES
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
