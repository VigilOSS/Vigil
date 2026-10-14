"""Native command contracts and release inventory for remediation clients."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("client", ["claude", "opencode", "zcode"])
def test_generated_remediation_command_routes_with_its_native_client(tmp_path, client):
    command = REPO_ROOT / f"agent/.{client}/commands/vigil-remediate.md"
    root = tmp_path / "Acme private workspace"
    invocations = [
        shlex.split(value.replace("<key>", "acme-remediation")
                   .replace("<selected-private-root>", shlex.quote(str(root))))
        for value in re.findall(r"`([^`]+)`", command.read_text())
        if value.startswith("vigil ") and "route --client" in value
    ]
    assert len(invocations) == 1
    root_arguments = ["--root", str(root)] if client == "zcode" else []
    assert invocations[0] == [
        "vigil", *root_arguments, "remediation", "-k", "acme-remediation", "route", "--client", client,
    ]
    executable = tmp_path / "vigil"
    executable.write_text(
        "#!/usr/bin/env python3\nimport json, sys\nprint(json.dumps(sys.argv[1:]))\n",
    )
    executable.chmod(0o755)
    result = subprocess.run(
        [str(executable), *invocations[0][1:], "ACME-12"],
        capture_output=True, text=True, check=True,
    )
    assert json.loads(result.stdout) == [
        *root_arguments, "remediation", "-k", "acme-remediation", "route", "--client", client, "ACME-12",
    ]


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    root = tmp_path_factory.mktemp("remediation-assets")
    source = root / "agent"
    shutil.copytree(
        REPO_ROOT / "agent", source,
        ignore=shutil.ignore_patterns(
            ".claude", ".codex", ".goose", ".opencode", ".zcode",
            "engagements", "references", "skills", "__pycache__", "data",
        ),
    )
    command = source / "commands" / "vigil-remediate.md"
    command.write_text(
        "---\nname: vigil-remediate\ndescription: Acme remediation fixture\n"
        "clients: claude,opencode,zcode\n---\n"
        "<!-- vigil:only claude -->\n```sh\nprintf '%s\\n' 'claude:$ARGUMENTS'\n```\n<!-- vigil:end -->\n"
        "<!-- vigil:only opencode -->\n```sh\nprintf '%s\\n' 'opencode:$ARGUMENTS'\n```\n<!-- vigil:end -->\n"
        "<!-- vigil:only zcode -->\n```sh\nprintf '%s\\n' 'zcode:$ARGUMENTS'\n```\n<!-- vigil:end -->\n",
        encoding="utf-8",
    )
    output = root / "rendered"
    output.mkdir()
    result = subprocess.run(
        ["bash", str(source / "scripts/render-operator-prompts.sh"), "repo", str(output)],
        capture_output=True, text=True,
    )
    return source, output, result


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_native_command_templates_render_client_arguments(rendered, client):
    _, output, result = rendered
    assert result.returncode == 0, result.stderr
    command = output / f".{client}/commands/vigil-remediate.md"
    assert command.is_file()
    _, frontmatter, body = command.read_text().split("---", 2)
    assert yaml.safe_load(frontmatter) == {"description": "Acme remediation fixture"}
    script = body.split("```sh\n", 1)[1].split("```", 1)[0]
    invocation = subprocess.run(
        ["sh", "-c", script.replace("$ARGUMENTS", "ACME-12 https://example.com/ticket/12")],
        capture_output=True, text=True, check=True,
    )
    assert invocation.stdout == f"{client}:ACME-12 https://example.com/ticket/12\n"


def test_zcode_marketplace_resolves_native_plugin_and_command(rendered):
    _, output, result = rendered
    assert result.returncode == 0, result.stderr
    marketplace_path = output / ".zcode/marketplace.json"
    assert marketplace_path.is_file()
    marketplace = json.loads(marketplace_path.read_text())
    entry, = marketplace["plugins"]
    plugin_root = (marketplace_path.parent / entry["source"]).resolve()
    manifest = json.loads((plugin_root / ".zcode-plugin/plugin.json").read_text())
    assert entry["name"] == manifest["name"] == "vigil-remediation"
    assert (plugin_root / "commands/vigil-remediate.md").is_file()


def test_bundle_copies_native_command_assets_and_hashes_inventory(rendered, tmp_path):
    _, output, result = rendered
    assert result.returncode == 0, result.stderr
    spec = importlib.util.spec_from_file_location("vigil_build_assets", REPO_ROOT / "vigil_build.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    bundle = tmp_path / "bundle"
    for name in build._AGENT_DIRS:
        build._copy_tree(output / name, bundle / "agent" / name)
    inventory = build._manifest(bundle, "0.0.0")["files"]
    for path in (
        "agent/.opencode/commands/vigil-remediate.md",
        "agent/.zcode/commands/vigil-remediate.md",
        "agent/.zcode/.zcode-plugin/plugin.json",
        "agent/.zcode/marketplace.json",
    ):
        assert path in inventory
        assert (bundle / path).read_bytes() == (output / path.removeprefix("agent/")).read_bytes()


@pytest.mark.parametrize("relative", [
    ".opencode/commands/vigil-remediate.md",
    ".zcode/commands/vigil-remediate.md",
    ".zcode/.zcode-plugin/plugin.json",
    ".zcode/marketplace.json",
])
def test_render_check_detects_native_asset_drift(rendered, tmp_path, relative):
    source, output, result = rendered
    assert result.returncode == 0, result.stderr
    check_root = tmp_path / "agent"
    shutil.copytree(source, check_root)
    shutil.copytree(output, check_root, dirs_exist_ok=True)
    argv = ["bash", str(check_root / "scripts/render-operator-prompts.sh"), "check", "--type", "red"]
    clean = subprocess.run(argv, capture_output=True, text=True)
    assert clean.returncode == 0, clean.stderr
    asset = check_root / relative
    if asset.suffix == ".json":
        metadata = json.loads(asset.read_text())
        metadata["description"] = "Acme changed local metadata"
        asset.write_text(json.dumps(metadata))
    else:
        asset.write_text(asset.read_text() + "\n```sh\nprintf '%s\\n' changed\n```\n")
    drift = subprocess.run(argv, capture_output=True, text=True)
    assert drift.returncode == 1
