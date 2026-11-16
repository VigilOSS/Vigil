"""The OpenCode major is read the same way by Python starts and the generated launcher."""
from __future__ import annotations

import json
import subprocess

import pytest

from vigil_cli import opencode_launch

VERSIONS = ["1.18.10", "1.19.3", "opencode v2.3.0", "2.3.0", "v2.0.0", "opencode v10.1.0",
            "opencode v1.18.10", "", "not a version", "1.19.3-beta", "opencode v2.3"]


@pytest.mark.parametrize("version", VERSIONS)
def test_launcher_and_python_choose_the_same_major(version):
    script = (f"opencode_major_pattern='{opencode_launch.LAUNCHER_MAJOR_PATTERN}'\n"
              'if [[ "$1" =~ $opencode_major_pattern ]] && (( 10#${BASH_REMATCH[2]} >= 2 )); then echo 2; else echo 1; fi')
    # macOS ships bash 3.2 as /bin/bash; the launcher must read the major there too.
    shell = subprocess.run(["/bin/bash", "-c", script, "probe", version], capture_output=True, text=True, check=True)
    assert int(shell.stdout) == opencode_launch.launch_major(version)


@pytest.mark.parametrize(("version", "release"), [
    ("1.18.10\n", (1, 18, 10)), ("opencode v2.3.0\n", (2, 3, 0)), ("v2.3.0", (2, 3, 0)),
    ("1.19.3-beta", None), ("opencode v2.3", None), ("opencode 2.3.0 (update 2.4.0 available)", None),
])
def test_a_release_is_one_version_line(version, release):
    assert opencode_launch.parse_release(version) == release


@pytest.mark.parametrize(("release", "supported"), [
    ((1, 18, 9), False), ((1, 18, 10), True), ((2, 3, 0), True), ((2, 99, 0), True), ((3, 0, 0), False),
])
def test_supported_range(release, supported):
    assert opencode_launch.is_supported(release) is supported


def test_opencode_1_launch_keeps_its_flags_and_saves_the_variant(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path))
    launch = opencode_launch.plan_operator_launch(
        "1.18.10", ["--model", "acme/model-1#max", "--dangerously-skip-permissions"], '{"share": "disabled"}')
    assert launch.major == 1
    assert opencode_launch.operator_arguments(launch.major) == ["--agent", "operator"]
    assert launch.arguments == ["--model", "acme/model-1", "--dangerously-skip-permissions"]
    assert launch.config_content is None
    assert launch.variant_state == (tmp_path / "opencode/model.json", {"variant": {"acme/model-1": "max"}})


@pytest.mark.parametrize("content", ["[]", '{"agent": []}', '{"agent": {"operator": "acme"}}', "{"])
def test_opencode_2_model_refuses_session_config_it_cannot_extend(content):
    with pytest.raises(SystemExit, match="OPENCODE_CONFIG_CONTENT"):
        opencode_launch.plan_operator_launch("opencode v2.3.0", ["--model=acme/model-1"], content)


def test_opencode_2_model_keeps_the_operator_agent_settings():
    launch = opencode_launch.plan_operator_launch(
        "opencode v2.3.0", ["-m=acme/model-1"], '{"agent": {"operator": {"steps": 9}, "recon": {}}}')
    assert opencode_launch.operator_arguments(launch.major) == ["--standalone"]
    assert launch.arguments == []
    assert launch.config_content is not None
    assert json.loads(launch.config_content) == {
        "model": "acme/model-1", "agent": {"operator": {"steps": 9, "model": "acme/model-1"}, "recon": {}}}


def test_opencode_2_takes_each_launch_flag_once():
    """OpenCode 2 rejects a repeated flag ("at most 1 value"), and the start supplies --standalone."""
    launch = opencode_launch.plan_operator_launch(
        "opencode v2.3.0", ["--auto", "--dangerously-skip-permissions", "--standalone", "--continue"], None)
    assert [*opencode_launch.operator_arguments(launch.major), *launch.arguments] == [
        "--standalone", "--auto", "--continue"]
