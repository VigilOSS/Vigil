"""On a program with required attribution headers, every run carries them or never starts.

A run whose requests Vigil cannot attach the headers to is refused before it
starts, with the exact alternative; a caller that knows the run sends no request
to a declared target says so with ``--no-target-requests <reason>``, which the
audit row records. Tools whose header flag reads a FILE (wafw00f) get a headers
file, and a shell SCRIPT FILE runs as an attributed copy beside the original.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from assess.lib import kali
from assess.lib.kali_cli import add_required_kali_flags, kali_args_to_kwargs
from assess.lib.scope import ScopePolicyError

_HANDLE = {"X-HackerOne": "acme-researcher"}


def _engagement(tmp_path: Path, *, required=_HANDLE) -> Path:
    eng = tmp_path / "2026-11-15-acme"
    eng.mkdir()
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "app.example.com",
                "hosts": ["app.example.com"],
                "engagement_type": "web",
                "required_headers": required,
            }
        )
    )
    return eng


def _prepare(cmd: list[str], eng: Path, **kwargs) -> dict:
    report: dict = {}
    kali.prepare_execution_command(
        cmd, tool_name=kwargs.pop("tool_name", cmd[0]), engagement_dir=eng, report=report, **kwargs
    )
    return report


def _header_file(eng: Path, cmd: list[str]) -> Path:
    token = cmd[cmd.index("-H") + 1]
    prefix = f"/engagements/{eng.name}/"
    assert token.startswith(prefix), token
    return eng / token[len(prefix):]


# --------------------------------------------------------------------------- #
# wafw00f takes its headers from a file
# --------------------------------------------------------------------------- #


def test_wafw00f_carries_the_required_header_through_a_headers_file(tmp_path):
    eng = _engagement(tmp_path)
    cmd = ["wafw00f", "https://app.example.com/"]

    report = _prepare(cmd, eng)

    assert report["required_header_status"] == "injected"
    lines = _header_file(eng, cmd).read_text(encoding="utf-8").splitlines()
    assert "X-HackerOne: acme-researcher" in lines
    # The file replaces wafw00f's default header set, so the defaults ride along.
    assert any(line.startswith("User-Agent: ") for line in lines)


def test_wafw00f_on_the_host_route_names_the_host_path(tmp_path):
    eng = _engagement(tmp_path)
    cmd = ["wafw00f", "https://app.example.com/"]

    report: dict = {}
    kali.prepare_execution_command(
        cmd, tool_name="wafw00f", engagement_dir=eng, execution_cwd=eng,
        container_paths=False, report=report,
    )

    path = Path(cmd[cmd.index("-H") + 1])
    assert path.is_absolute() and path.is_relative_to(eng.resolve())
    assert "X-HackerOne: acme-researcher" in path.read_text(encoding="utf-8")


def test_wafw00f_keeps_the_operators_headers_file_and_adds_the_required_header(tmp_path):
    eng = _engagement(tmp_path)
    (eng / "scans").mkdir()
    (eng / "scans" / "headers.txt").write_text("User-Agent: acme-ua\nAccept: */*\n")
    cmd = ["wafw00f", "-H", f"/engagements/{eng.name}/scans/headers.txt", "https://app.example.com/"]

    _prepare(cmd, eng)

    lines = _header_file(eng, cmd).read_text(encoding="utf-8").splitlines()
    assert lines[:2] == ["User-Agent: acme-ua", "Accept: */*"]
    assert "X-HackerOne: acme-researcher" in lines
    assert cmd.count("-H") == 1


def test_wafw00f_refuses_a_header_value_its_file_format_cannot_carry(tmp_path):
    eng = _engagement(tmp_path, required={"X-Bounty": "acme:researcher"})

    with pytest.raises(ScopePolicyError, match="X-Bounty"):
        _prepare(["wafw00f", "https://app.example.com/"], eng)


# --------------------------------------------------------------------------- #
# a shell script file runs as an attributed copy
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "body",
    [
        "#!/bin/sh\ncurl -sS https://app.example.com/a\n",
        '#!/bin/sh\nfor u in https://app.example.com/a; do\n  curl -sS "$u"\ndone\n',
    ],
    ids=["literal", "dynamic"],
)
def test_a_shell_script_file_runs_as_an_attributed_copy(tmp_path, body):
    eng = _engagement(tmp_path)
    original = eng / "scripts" / "probe.sh"
    original.parent.mkdir()
    original.write_text(body)
    cmd = ["sh", f"/engagements/{eng.name}/scripts/probe.sh"]

    report = _prepare(cmd, eng)

    assert report["required_header_status"] == "injected"
    copy = eng / cmd[1][len(f"/engagements/{eng.name}/"):]
    assert copy.parent == original.parent and copy != original
    assert "X-HackerOne: acme-researcher" in copy.read_text(encoding="utf-8")
    assert original.read_text(encoding="utf-8") == body


# --------------------------------------------------------------------------- #
# what cannot be attributed is refused unless declared request-free
# --------------------------------------------------------------------------- #


def test_a_dynamic_script_is_refused_with_the_alternative(tmp_path):
    eng = _engagement(tmp_path)
    (eng / "scripts").mkdir()
    (eng / "scripts" / "probe.py").write_text(
        "import os, requests\nrequests.get(os.environ['TARGET'])\n"
    )

    with pytest.raises(ScopePolicyError) as excinfo:
        _prepare(["python3", "scripts/probe.py"], eng)

    message = str(excinfo.value)
    assert "X-HackerOne" in message
    assert "VIGIL_REQUIRED_HEADERS" in message
    assert "--no-target-requests" in message


def test_a_declared_request_free_run_proceeds_and_records_the_reason(tmp_path):
    eng = _engagement(tmp_path)
    (eng / "scripts").mkdir()
    (eng / "scripts" / "probe.py").write_text(
        "import os, requests\nrequests.get(os.environ['TARGET'])\n"
    )

    report = _prepare(
        ["python3", "scripts/probe.py"], eng,
        no_target_requests="talks only to the local mock at 127.0.0.1",
    )

    assert report["required_header_status"] == "declared_no_target_requests"
    assert report["no_target_requests_reason"] == "talks only to the local mock at 127.0.0.1"


@pytest.mark.parametrize(
    "cmd",
    [["acme-scanner", "--self-test"], ["httprobe"], ["bash", "-c", "cd scripts && python3 login.py"]],
    ids=["unknown-binary", "headerless-http-tool", "c-body-script"],
)
def test_a_run_vigil_cannot_attribute_is_refused_before_it_starts(tmp_path, cmd):
    eng = _engagement(tmp_path)

    with pytest.raises(ScopePolicyError, match="--no-target-requests"):
        _prepare(list(cmd), eng)


def test_a_declaration_cannot_cover_a_run_that_names_a_target(tmp_path):
    eng = _engagement(tmp_path)

    with pytest.raises(ScopePolicyError, match="app.example.com"):
        _prepare(
            ["acme-scanner", "https://app.example.com/"], eng,
            no_target_requests="only reads its local cache",
        )


def test_an_unreadable_script_is_refused_unless_declared(tmp_path):
    eng = _engagement(tmp_path)

    with pytest.raises(ScopePolicyError, match="not readable"):
        _prepare(["bash", "/etc/probe.sh"], eng)
    report = _prepare(["bash", "/etc/probe.sh"], eng, no_target_requests="local helper")
    assert report["required_header_status"] == "declared_no_target_requests"


def test_an_inline_program_without_requests_needs_no_declaration(tmp_path):
    eng = _engagement(tmp_path)

    report = _prepare(["python3", "-c", "import json; print(json.dumps({}))"], eng)

    assert report["required_header_status"] == "not_applicable_no_in_scope_url"


def test_an_inline_program_with_a_literal_target_request_is_refused(tmp_path):
    eng = _engagement(tmp_path)

    with pytest.raises(ScopePolicyError, match="X-HackerOne"):
        _prepare(["node", "-e", "fetch('https://app.example.com/a')"], eng)


def test_every_kali_verb_accepts_the_declaration_and_threads_it(tmp_path):
    parser = argparse.ArgumentParser()
    add_required_kali_flags(parser)
    args = parser.parse_args([
        "--technique", "RECON", "--intent", "local parse", "--probe-kind", "baseline",
        "--phase", "recon", "--timeout", "60", "--no-target-requests", "parses stored bodies",
    ])

    assert kali_args_to_kwargs(args)["no_target_requests"] == "parses stored bodies"
