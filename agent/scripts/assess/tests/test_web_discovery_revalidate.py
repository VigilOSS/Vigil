"""web-discovery stage-2 hardening: I-6 dead-host revalidation pass, I-4 katana
disk-blowup flags, and the scope.rate_limit cap consumption.

These drive the real ``web_discovery.run`` with the execution seams (kali_exec /
host_exec / ingest) stubbed, asserting on the argv the stage built and the
liveness ledger merge — not on a live runtime.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import web_discovery


def _cfg(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://127.0.0.1:18000", engagement_key="eng", engagement_dir=str(tmp_path)
    )


def _scope(tmp_path: Path, **fields) -> None:
    # Most cases actively probe example.com descendants, so the fixture must
    # author the wildcard that actually grants that scope. Bare hosts are exact.
    payload = {"engagement_type": "web", "hosts": ["*.example.com"]}
    payload.update(fields)
    (tmp_path / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def _hosts_file(tmp_path: Path, hosts: list[str]) -> Path:
    p = tmp_path / "hosts.txt"
    p.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    return p


def _args(tmp_path: Path, hosts_file: Path, **over) -> SimpleNamespace:
    ns = SimpleNamespace(hosts_file=str(hosts_file), engagement_dir=str(tmp_path))
    for k, v in over.items():
        setattr(ns, k, v)
    return ns


class _Client:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _install_seams(monkeypatch, tmp_path, *, captured: list[list[str]], live_rows: dict[str, list[str]]):
    """Stub kali_exec to (a) record argv and (b) emulate httpx writing JSONL to
    the -o path. `live_rows` maps a port-list arg → the JSONL lines that pass
    writes for that run, so a test can model 'dead on 80,443, live on 8080'."""
    monkeypatch.setattr(web_discovery, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(web_discovery, "AssessmentClient", lambda *a, **k: _Client())
    monkeypatch.setattr(
        web_discovery, "ingest_httpx_results",
        lambda *a, **k: {"upserted": 0, "by_class": {}},
    )

    container_prefix = "/engagements/eng/"

    def _to_host(path: str) -> Path:
        # The container path is the bind-mounted same inode as the engagement
        # dir; map it back so the fake writes where the real code reads.
        if path.startswith(container_prefix):
            return tmp_path / path[len(container_prefix):]
        return Path(path)

    def fake_kali(cmd, **kwargs):
        captured.append(list(cmd))
        tool = kwargs.get("tool_name")
        if tool == "httpx":
            # Recover the -p and -o args to emulate the httpx JSONL output.
            ports = cmd[cmd.index("-p") + 1] if "-p" in cmd else ""
            out = cmd[cmd.index("-o") + 1] if "-o" in cmd else ""
            rows = live_rows.get(ports, [])
            if out:
                host_out = _to_host(out)
                host_out.parent.mkdir(parents=True, exist_ok=True)
                host_out.write_text("".join(r + "\n" for r in rows), encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(web_discovery, "kali_exec", fake_kali)
    return captured


def test_revalidation_reprobes_dead_hosts_on_nonstandard_ports(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com", "dead.example.com"])
    captured: list[list[str]] = []
    # On 80,443 only `live` answers; on the revalidation ports `dead` answers.
    live_rows = {
        "80,443": ['{"url":"https://live.example.com","input":"live.example.com"}'],
        web_discovery._REVALIDATE_PORTS: [
            '{"url":"https://dead.example.com:8080","input":"dead.example.com"}'
        ],
    }
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=True))

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    # Two httpx passes: the fast default + the revalidation over dead hosts.
    assert len(httpx_runs) == 2
    default_pass, reval_pass = httpx_runs
    assert default_pass[default_pass.index("-p") + 1] == "80,443"
    assert reval_pass[reval_pass.index("-p") + 1] == web_discovery._REVALIDATE_PORTS

    # The revalidation input file contains ONLY the dead-on-default host.
    reval_in = reval_pass[reval_pass.index("-l") + 1]
    assert "/runs/" in reval_in
    canonical_reval = tmp_path / "scans" / "web-discovery" / "revalidate_hosts.txt"
    assert canonical_reval.read_text(encoding="utf-8").split() == ["dead.example.com"]

    # The recovered live row is merged into the primary liveness ledger.
    live_file = tmp_path / "scans" / "web-discovery" / "httpx_live.jsonl"
    merged = live_file.read_text(encoding="utf-8")
    assert "live.example.com" in merged
    assert "dead.example.com:8080" in merged


def test_no_revalidation_when_all_hosts_live(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["a.example.com", "b.example.com"])
    captured: list[list[str]] = []
    live_rows = {
        "80,443": [
            '{"url":"https://a.example.com","input":"a.example.com"}',
            '{"url":"https://b.example.com","input":"b.example.com"}',
        ],
    }
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=True))

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    assert len(httpx_runs) == 1  # nothing dead → no second pass


def test_no_revalidate_ports_flag_skips_second_pass(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com", "dead.example.com"])
    captured: list[list[str]] = []
    live_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=True,
                            no_revalidate_ports=True))

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    assert len(httpx_runs) == 1  # opt-out honoured


def test_katana_carries_omit_response_and_body_flags(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    live_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=False))

    katana_runs = [c for c in captured if c and c[0] == "katana"]
    assert len(katana_runs) == 1
    # I-4: -or (omit response) + -ob (omit body) keep the crawl off disk.
    assert "-or" in katana_runs[0]
    assert "-ob" in katana_runs[0]


def test_katana_injects_scope_no_fire_crawl_exclusions(monkeypatch, tmp_path):
    _scope(tmp_path, off_limits_paths=["/api/send-email", "/account/*"])
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    _install_seams(
        monkeypatch,
        tmp_path,
        captured=captured,
        live_rows={
            "80,443": [
                '{"url":"https://live.example.com","input":"live.example.com"}'
            ]
        },
    )

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=False))

    katana = next(cmd for cmd in captured if cmd[0] == "katana")
    exclusion = katana[katana.index("-cos") + 1]
    assert "send\\-email" in exclusion
    assert "account" in exclusion


def test_rate_cap_clamps_httpx_and_katana(monkeypatch, tmp_path):
    # scope.rate_limit=5 must clamp httpx -rate-limit DOWN from the default 150
    # and set katana -rl/-rlm to the global (per-invocation) ceiling.
    _scope(tmp_path, rate_limit=5)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    live_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=False))

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    rate = httpx_runs[0][httpx_runs[0].index("-rate-limit") + 1]
    assert rate == "5"  # clamped down to the global (per-invocation) cap

    katana_runs = [c for c in captured if c and c[0] == "katana"]
    assert "-rl" in katana_runs[0]
    assert katana_runs[0][katana_runs[0].index("-rl") + 1] == "5"
    assert katana_runs[0][katana_runs[0].index("-rlm") + 1] == "300"  # 5*60


def test_rate_cap_unset_injects_safe_crawl_default(monkeypatch, tmp_path):
    # No program rate_limit configured. The bulk httpx liveness pass keeps its
    # own verb default (150), but the katana CRAWL must NOT ride katana's built-in
    # 150 req/s — it gets the safe crawl default (10 req/s, 600 req/min) so a deep
    # crawl stays polite by capping rate, not depth.
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    live_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    web_discovery.run(_args(tmp_path, hosts_file, runtime="container", no_crawl=False))

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    assert httpx_runs[0][httpx_runs[0].index("-rate-limit") + 1] == "150"
    katana_runs = [c for c in captured if c and c[0] == "katana"]
    assert "-rl" in katana_runs[0]
    assert katana_runs[0][katana_runs[0].index("-rl") + 1] == "10"
    assert katana_runs[0][katana_runs[0].index("-rlm") + 1] == "600"  # 10*60
    # JS-aware + scope-safe + deep crawl defaults are baked in.
    assert "-jsl" in katana_runs[0]
    assert katana_runs[0][katana_runs[0].index("-fs") + 1] == "fqdn"
    assert katana_runs[0][katana_runs[0].index("-d") + 1] == "4"  # fleet-crawl depth default


@pytest.mark.parametrize(
    "requested,cap,expected",
    [
        ("150", None, 150),   # unset cap → verb default unchanged
        ("150", 5.0, 5),      # cap below default → clamp down
        ("3", 50.0, 3),       # cap above default → no-op (ceiling only clamps DOWN)
        ("150", 5.9, 5),      # fractional cap truncates DOWN, never exceeds
        ("150", 0.5, 1),      # sub-1 cap (rejected at create; hand-edit only) → floor to 1, never 0
        ("bad", 10.0, 10),    # non-numeric default → fall back then clamp
    ],
)
def test_clamp_httpx_rate_limit_unit(requested, cap, expected):
    assert web_discovery._clamp_httpx_rate_limit(requested, cap) == expected


def test_resolved_engagement_dir_used_when_flag_is_none(monkeypatch, tmp_path):
    # PR #40 regression: the default CLI path leaves args.engagement_dir=None (run
    # from the engagement dir, or with only $ENGAGEMENT_DIR set); load_config
    # resolves it into cfg.engagement_dir. Post-config reads must use the resolved
    # dir — previously the rate-cap lookup called scope.rate_caps_for_dir(None),
    # which raised TypeError and crashed the whole web-discovery stage before any
    # probe ran. Assert no crash AND the cap is consumed from the resolved
    # scope.json (proving args.engagement_dir was rewritten to the real dir, which
    # is also what carries required_headers into the host route).
    _scope(tmp_path, rate_limit=5)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    live_rows = {"80,443": ['{"url":"https://live.example.com","input":"live.example.com"}']}
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows=live_rows)

    # engagement_dir=None mirrors the normal invocation; must not raise.
    web_discovery.run(
        _args(tmp_path, hosts_file, engagement_dir=None, runtime="container", no_crawl=False)
    )

    httpx_runs = [c for c in captured if c and c[0] == "httpx"]
    assert httpx_runs, "httpx stage never ran (stage crashed on None engagement_dir)"
    assert httpx_runs[0][httpx_runs[0].index("-rate-limit") + 1] == "5"


def test_failed_httpx_run_cannot_ingest_or_replace_prior_canonical_output(
    monkeypatch, tmp_path
):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["fresh.example.com"])
    canonical = tmp_path / "scans" / "web-discovery" / "httpx_live.jsonl"
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_text(
        '{"url":"https://stale.example.com","input":"stale.example.com"}\n',
        encoding="utf-8",
    )
    canonical_input = tmp_path / "scans" / "web-discovery" / "denoised_hosts.txt"
    canonical_input.write_text("prior.example.com\n", encoding="utf-8")
    ingested: list[Path] = []
    monkeypatch.setattr(web_discovery, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(web_discovery, "AssessmentClient", lambda *a, **k: _Client())
    monkeypatch.setattr(
        web_discovery,
        "ingest_httpx_results",
        lambda path, **kwargs: ingested.append(Path(path)) or {"upserted": 0, "by_class": {}},
    )

    def failed_httpx(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        rel = out.removeprefix("/engagements/eng/")
        run_output = tmp_path / rel
        run_output.parent.mkdir(parents=True, exist_ok=True)
        run_output.write_text(
            '{"url":"https://fresh.example.com","input":"fresh.example.com"}\n',
            encoding="utf-8",
        )
        return SimpleNamespace(return_code=7)

    monkeypatch.setattr(web_discovery, "kali_exec", failed_httpx)

    with pytest.raises(SystemExit) as exc:
        web_discovery.run(
            _args(tmp_path, hosts_file, runtime="container", no_crawl=True)
        )

    assert exc.value.code == 7
    assert "stale.example.com" in canonical.read_text(encoding="utf-8")
    assert canonical_input.read_text(encoding="utf-8") == "prior.example.com\n"
    assert ingested == []


def test_empty_denoised_generation_clears_every_stale_canonical(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, [])
    out_dir = tmp_path / "scans" / "web-discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in (
        "denoised_hosts.txt",
        "revalidate_hosts.txt",
        "httpx_live.jsonl",
        "live_urls.txt",
        "katana.jsonl",
    ):
        (out_dir / name).write_text("stale.example.test\n", encoding="utf-8")
    (out_dir / "httpx-health.json").write_text('{"state":"accepted"}', encoding="utf-8")
    (out_dir / "crawl-health.json").write_text('{"state":"accepted"}', encoding="utf-8")
    monkeypatch.setattr(web_discovery, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(
        web_discovery,
        "kali_exec",
        lambda *a, **k: pytest.fail("accepted-empty generation must not execute tools"),
    )

    with pytest.raises(SystemExit) as exc:
        web_discovery.run(
            _args(
                tmp_path,
                hosts_file,
                runtime="container",
                run_uuid="empty-run-1",
            )
        )

    assert exc.value.code == 0
    for name in (
        "denoised_hosts.txt",
        "revalidate_hosts.txt",
        "httpx_live.jsonl",
        "live_urls.txt",
        "katana.jsonl",
    ):
        assert (out_dir / name).read_text(encoding="utf-8") == ""
    assert json.loads((out_dir / "httpx-health.json").read_text())["state"] == "accepted-empty"
    assert json.loads((out_dir / "crawl-health.json").read_text())["state"] == "accepted-empty"


def test_standalone_web_discovery_drops_oos_from_mixed_input(monkeypatch, tmp_path):
    _scope(tmp_path, hosts=["*.example.com"], out_of_scope=["bad.example.com"])
    hosts_file = _hosts_file(
        tmp_path,
        ["good.example.com", "bad.example.com", "evil.test"],
    )
    captured: list[list[str]] = []
    _install_seams(
        monkeypatch,
        tmp_path,
        captured=captured,
        live_rows={
            "80,443": [
                '{"url":"https://good.example.com","input":"good.example.com"}'
            ]
        },
    )

    web_discovery.run(
        _args(tmp_path, hosts_file, runtime="container", no_crawl=True, run_uuid="mixed-1")
    )

    assert (
        tmp_path / "scans" / "web-discovery" / "denoised_hosts.txt"
    ).read_text().split() == ["good.example.com"]
    metadata = json.loads(
        (tmp_path / "scans" / "web-discovery" / "scope-filter.meta.json").read_text()
    )
    assert metadata["input_count"] == 3
    assert metadata["kept_count"] == 1
    assert metadata["dropped_count"] == 2


def test_standalone_web_discovery_drops_descendant_of_exact_apex(monkeypatch, tmp_path):
    _scope(tmp_path, hosts=["example.com"])
    hosts_file = _hosts_file(tmp_path, ["api.example.com"])
    captured: list[list[str]] = []
    _install_seams(monkeypatch, tmp_path, captured=captured, live_rows={})

    with pytest.raises(SystemExit) as exc:
        web_discovery.run(
            _args(
                tmp_path,
                hosts_file,
                runtime="container",
                no_crawl=True,
                run_uuid="exact-apex",
            )
        )

    assert exc.value.code == 0
    assert captured == []
    metadata = json.loads(
        (tmp_path / "scans" / "web-discovery" / "scope-filter.meta.json").read_text()
    )
    assert metadata["kept_count"] == 0
    assert metadata["dropped_count"] == 1


def test_standalone_web_discovery_global_bypass_keeps_mixed_input(monkeypatch, tmp_path):
    _scope(tmp_path, hosts=["example.com"], scope_enforcement="bypass")
    hosts_file = _hosts_file(tmp_path, ["example.com", "evil.test"])
    captured: list[list[str]] = []
    _install_seams(
        monkeypatch,
        tmp_path,
        captured=captured,
        live_rows={
            "80,443": [
                '{"url":"https://example.com","input":"example.com"}',
                '{"url":"https://evil.test","input":"evil.test"}',
            ]
        },
    )

    web_discovery.run(
        _args(tmp_path, hosts_file, runtime="container", no_crawl=True, run_uuid="mixed-2")
    )

    metadata = json.loads(
        (tmp_path / "scans" / "web-discovery" / "scope-filter.meta.json").read_text()
    )
    assert metadata["scope_bypassed"] is True
    assert metadata["kept_count"] == 2
    assert metadata["dropped_count"] == 0


def test_successful_httpx_run_owns_inputs_and_promotes_generation_with_lineage(
    monkeypatch, tmp_path
):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com"])
    captured: list[list[str]] = []
    _install_seams(
        monkeypatch,
        tmp_path,
        captured=captured,
        live_rows={
            "80,443": [
                '{"url":"https://live.example.com","input":"live.example.com"}'
            ]
        },
    )

    web_discovery.run(
        _args(
            tmp_path,
            hosts_file,
            runtime="container",
            no_crawl=True,
            run_uuid="run-httpx-1",
        )
    )

    httpx = next(cmd for cmd in captured if cmd[0] == "httpx")
    input_path = httpx[httpx.index("-l") + 1]
    output = httpx[httpx.index("-o") + 1]
    assert input_path.endswith("/runs/run-httpx-1/denoised_hosts.txt")
    assert "/runs/" in output
    canonical = tmp_path / "scans" / "web-discovery" / "httpx_live.jsonl"
    assert "live.example.com" in canonical.read_text(encoding="utf-8")
    assert (
        tmp_path / "scans" / "web-discovery" / "denoised_hosts.txt"
    ).read_text(encoding="utf-8") == "live.example.com\n"
    lineage = json.loads(
        (tmp_path / "scans" / "web-discovery" / "httpx-health.json").read_text(
            encoding="utf-8"
        )
    )
    assert lineage == {
        "run_uuid": "run-httpx-1",
        "state": "accepted",
        "input_count": 1,
        "live_record_count": 1,
        "revalidation_target_count": 0,
        "recovered_count": 0,
        "exit_code": 0,
    }


def test_failed_revalidation_preserves_prior_complete_canonical(monkeypatch, tmp_path):
    _scope(tmp_path)
    hosts_file = _hosts_file(tmp_path, ["live.example.com", "dead.example.com"])
    canonical = tmp_path / "scans" / "web-discovery" / "httpx_live.jsonl"
    canonical.parent.mkdir(parents=True, exist_ok=True)
    canonical.write_text(
        '{"url":"https://prior.example.com","input":"prior.example.com"}\n',
        encoding="utf-8",
    )
    canonical_revalidation = (
        tmp_path / "scans" / "web-discovery" / "revalidate_hosts.txt"
    )
    canonical_revalidation.write_text("prior.example.com\n", encoding="utf-8")
    monkeypatch.setattr(web_discovery, "load_config", lambda d: _cfg(tmp_path))
    monkeypatch.setattr(web_discovery, "AssessmentClient", lambda *a, **k: _Client())
    monkeypatch.setattr(
        web_discovery,
        "ingest_httpx_results",
        lambda *a, **k: pytest.fail("partial liveness generation must not ingest"),
    )

    def fake_kali(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        path = tmp_path / out.removeprefix("/engagements/eng/")
        path.parent.mkdir(parents=True, exist_ok=True)
        ports = cmd[cmd.index("-p") + 1]
        if ports == "80,443":
            path.write_text(
                '{"url":"https://live.example.com","input":"live.example.com"}\n',
                encoding="utf-8",
            )
            return SimpleNamespace(return_code=0)
        path.write_text(
            '{"url":"https://dead.example.com:8080","input":"dead.example.com"}\n',
            encoding="utf-8",
        )
        return SimpleNamespace(return_code=8)

    monkeypatch.setattr(web_discovery, "kali_exec", fake_kali)

    with pytest.raises(SystemExit) as exc:
        web_discovery.run(
            _args(tmp_path, hosts_file, runtime="container", no_crawl=True)
        )

    assert exc.value.code == 8
    assert "prior.example.com" in canonical.read_text(encoding="utf-8")
    assert canonical_revalidation.read_text(encoding="utf-8") == "prior.example.com\n"


def test_network_heavy_lock_wraps_host_httpx_only(monkeypatch, tmp_path):
    entered: list[str] = []

    @contextmanager
    def fake_lock(engagement_dir, *, label):
        entered.append(label)
        yield True

    monkeypatch.setattr(web_discovery, "network_heavy_lock", fake_lock)
    monkeypatch.setattr(
        web_discovery,
        "_host_dispatch",
        lambda *a, **k: SimpleNamespace(return_code=0),
    )
    monkeypatch.setattr(
        web_discovery,
        "kali_exec",
        lambda *a, **k: SimpleNamespace(return_code=0),
    )
    args = _args(tmp_path, tmp_path / "hosts", tech_detect=False)

    web_discovery._run_httpx_liveness(
        args,
        in_arg="hosts",
        out_arg="out",
        ports="80,443",
        threads=5,
        rate_limit=5,
        route="host",
        timeout=30,
        intent="host",
    )
    web_discovery._run_httpx_liveness(
        args,
        in_arg="hosts",
        out_arg="out",
        ports="80,443",
        threads=5,
        rate_limit=5,
        route="container",
        timeout=30,
        intent="container",
    )

    assert entered == ["httpx host liveness"]
