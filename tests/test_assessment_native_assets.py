"""The renderer exposes usable native assessment entrypoints, not copied prose."""
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMANDS = {"vigil-start", "vigil-resume", "vigil-handoff", "vigil-compact",
            "vigil-hunt-deeper", "vigil-fresh-skeptic-verify", "vigil-triage-reply"}


@pytest.fixture(scope="module")
def rendered(tmp_path_factory):
    output = tmp_path_factory.mktemp("native-assets")
    subprocess.run(["bash", str(ROOT / "agent/scripts/render-operator-prompts.sh"),
                    "repo", str(output)], check=True, capture_output=True, text=True)
    return output


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_assessment_native_command_discovery_covers_operator_workflow(rendered, client):
    commands = rendered / f".{client}/assessment/commands"
    assert {path.stem for path in commands.glob("*.md")} == COMMANDS


@pytest.mark.parametrize("client", ["opencode", "zcode"])
def test_assessment_roles_inherit_native_model_and_keep_specialist_boundary(rendered, client):
    roles = rendered / f".{client}/assessment/agents"
    names = {path.stem for path in roles.glob("*.md")}
    assert {"code-architect", "code-vuln-hunter", "code-vuln-verifier"} <= names
    for role in roles.glob("*.md"):
        frontmatter = role.read_text().split("---", 2)[1]
        fields = dict(line.split(":", 1) for line in frontmatter.splitlines() if ":" in line)
        assert fields.get("model", "inherit").strip() == "inherit"
        if client == "zcode":
            assert fields.get("name", "").strip() == role.stem
            assert fields.get("injectAgentsMd", "").strip() == "false"
