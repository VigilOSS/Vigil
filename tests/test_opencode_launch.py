"""OpenCode release support and the operator launch every Vigil start shares."""
from __future__ import annotations

import json
import re
import shlex

import pytest

from vigil_cli import opencode_launch


@pytest.mark.parametrize(("version", "support"), [
    ("opencode v2.3.0\n", "supported"), ("2.3.0\n", "supported"), ("v2.3.0", "supported"),
    ("opencode v2.99.0", "supported"),
    ("1.18.10", "unsupported"), ("opencode v2.2.9", "unsupported"), ("opencode v3.0.0", "unsupported"),
    # A pre-release precedes its release.
    ("opencode v2.4.0-beta.1", "unverified"), ("2.3.1-rc.1", "unverified"),
    ("opencode v2.3.0-beta", "unsupported"), ("opencode v3.0.0-rc.1", "unsupported"), ("1.19.0-beta", "unsupported"),
    ("opencode v2.3", "unverified"), ("opencode 2.3.0 (update 2.4.0 available)", "unverified"),
    ("", "unverified"), (None, "unverified"),
])
def test_a_version_reading_stands_against_the_supported_range(version, support):
    assert opencode_launch.version_support(version) == support


@pytest.mark.parametrize("version", ["1.18.10", "opencode v2.2.9", "opencode v3.0.0", "opencode v3.0.0-rc.1"])
def test_a_readable_release_outside_the_range_is_refused(version):
    with pytest.raises(SystemExit, match=re.escape(opencode_launch.SUPPORTED_RANGE)):
        opencode_launch.require_supported(version)


@pytest.mark.parametrize("version", ["opencode v2.3.0", "opencode v2.4.0-beta", None, "",
                                     "opencode 2.3.0 (update 2.4.0 available)"])
def test_a_supported_or_unreadable_version_proceeds(version):
    opencode_launch.require_supported(version)


def test_model_variant_is_saved_and_the_model_rides_the_session_config(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    launch = opencode_launch.plan_operator_launch(
        ["--model", "acme/model-1#max", "--dangerously-skip-permissions"], '{"share": "disabled"}')
    assert launch.arguments == ["--auto"]
    assert launch.config_content is not None
    assert json.loads(launch.config_content) == {
        "share": "disabled", "model": "acme/model-1#max", "agent": {"operator": {"model": "acme/model-1#max"}}}
    assert launch.variant_state == (tmp_path / "opencode/model.json", {"variant": {"acme/model-1": "max"}})


@pytest.mark.parametrize("content", ["[]", '{"agent": []}', '{"agent": {"operator": "acme"}}', "{"])
def test_model_refuses_session_config_it_cannot_extend(content):
    with pytest.raises(SystemExit, match="OPENCODE_CONFIG_CONTENT"):
        opencode_launch.plan_operator_launch(["--model=acme/model-1"], content)


def test_model_keeps_the_operator_agent_settings():
    launch = opencode_launch.plan_operator_launch(
        ["-m=acme/model-1"], '{"agent": {"operator": {"steps": 9}, "recon": {}}}')
    assert launch.arguments == []
    assert launch.config_content is not None
    assert json.loads(launch.config_content) == {
        "model": "acme/model-1", "agent": {"operator": {"steps": 9, "model": "acme/model-1"}, "recon": {}}}


def test_each_launch_flag_is_taken_once():
    """OpenCode rejects a repeated flag ("at most 1 value"), and the start supplies --standalone."""
    launch = opencode_launch.plan_operator_launch(
        ["--auto", "--dangerously-skip-permissions", "--standalone", "--continue"], None)
    assert [opencode_launch.STANDALONE, *launch.arguments] == ["--standalone", "--auto", "--continue"]


# What `opencode --version` does → (client-check status, engagement start, remediation start).
# A start column is True when the start proceeds. A failed probe (non-zero exit,
# timeout) is an unreadable version, as is any output that is not one version line.
_INSTALLED = {
    "2.2.9": (("opencode v2.2.9", "", 0), ("FAIL", False, False)),
    "2.3.0": (("opencode v2.3.0", "", 0), ("OK", True, True)),
    "bare 2.3.0": (("2.3.0", "", 0), ("OK", True, True)),
    "2.99.0": (("opencode v2.99.0", "", 0), ("OK", True, True)),
    "3.0.0": (("opencode v3.0.0", "", 0), ("FAIL", False, False)),
    "1.18.10": (("1.18.10", "", 0), ("FAIL", False, False)),
    "2.x pre-release": (("opencode v2.4.0-beta.1", "", 0), ("UNVERIFIED", True, True)),
    "pre-release of the minimum": (("opencode v2.3.0-beta", "", 0), ("FAIL", False, False)),
    "3.x pre-release": (("opencode v3.0.0-rc.1", "", 0), ("FAIL", False, False)),
    "1.x pre-release": (("1.19.0-beta", "", 0), ("FAIL", False, False)),
    "garbage": (("hello acme", "", 0), ("UNVERIFIED", True, True)),
    "non-zero exit": (("opencode v1.18.10", "boom", 3), ("UNVERIFIED", True, True)),
    "timeout": (None, ("UNVERIFIED", True, True)),
    "stderr warning": (("1.18.10", "warning: acme", 0), ("FAIL", False, False)),
    "version on stderr": (("  ", "1.18.10", 0), ("FAIL", False, False)),
    "missing binary": ("missing", ("MISSING", None, False)),
}


@pytest.mark.parametrize("case", list(_INSTALLED))
def test_every_start_and_client_check_read_the_installed_version_alike(tmp_path, monkeypatch, case):
    from vigil_cli import client_checks, remediation_clients

    behaviour, (status, start, remediation) = _INSTALLED[case]
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin:/bin")
    monkeypatch.setattr(opencode_launch, "PROBE_TIMEOUT_SECONDS", 0.5)
    if behaviour != "missing":
        if behaviour is None:
            version_line = "exec sleep 5"
        else:
            stdout, stderr, code = behaviour
            version_line = (f"printf '%s\\n' {shlex.quote(stdout)}; "
                            + (f"printf '%s\\n' {shlex.quote(stderr)} >&2; " if stderr else "") + f"exit {code}")
        executable = tmp_path / "opencode"
        executable.write_text("#!/bin/sh\n"
                              "if [ \"$1\" = --help ]; then printf '  --prompt  prompt to use\\n'; exit 0; fi\n"
                              f"{version_line}\n")
        executable.chmod(0o755)

    assert client_checks.collect_client_checks("opencode")[0].status == status
    if start is not None:
        def start_proceeds() -> bool:
            try:
                opencode_launch.probe_supported_version(str(tmp_path / "opencode"))
            except SystemExit:
                return False
            return True
        assert start_proceeds() is start
    try:
        remediation_clients._opencode_capabilities()
    except SystemExit:
        assert not remediation
    else:
        assert remediation
