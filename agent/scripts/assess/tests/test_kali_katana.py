from __future__ import annotations

import argparse
from types import SimpleNamespace

from assess.commands import kali_katana


def test_typed_katana_has_no_automatic_field_scope() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    kali_katana.register(subparsers)

    args = parser.parse_args(
        [
            "katana",
            "--technique",
            "DISCOVERY",
            "--intent",
            "crawl target",
            "--probe-kind",
            "fingerprint",
            "--phase",
            "recon",
            "--timeout",
            "30",
        ]
    )

    assert args.field_scope == ""


def test_typed_katana_keeps_only_explicit_crawl_exclusion(
    monkeypatch, tmp_path
) -> None:
    (tmp_path / "scope.json").write_text(
        '{"hosts":["example.test"],"off_limits_paths":["/notify/*"]}',
        encoding="utf-8",
    )
    captured: list[list[str]] = []
    monkeypatch.setattr(kali_katana, "_resolve_rate_cap", lambda _args: None)
    monkeypatch.setattr(kali_katana, "kali_args_to_kwargs", lambda _args: {})
    monkeypatch.setattr(
        kali_katana,
        "kali_exec",
        lambda cmd, **_kwargs: captured.append(list(cmd)) or SimpleNamespace(),
    )
    monkeypatch.setattr(kali_katana, "emit_result", lambda _result: None)

    args = SimpleNamespace(
        target_url="https://example.test",
        target_list="",
        no_jc=False,
        no_jsl=False,
        depth="5",
        concurrency="5",
        rate_limit="",
        allow_fast_crawl=False,
        field_scope="fqdn",
        known_files="",
        crawl_out_scope="authored-regex",
        headers=None,
        keep_bodies=False,
        include_static=False,
        headless=False,
        output="",
        jsonl=False,
        extra_args="",
        crawl_budget="",
        timeout=1800,
        engagement_dir=str(tmp_path),
    )

    kali_katana.run(args)

    cmd = captured[0]
    value = cmd[cmd.index("-cos") + 1]
    assert value == "authored-regex"
