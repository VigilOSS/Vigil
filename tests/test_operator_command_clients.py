"""Client capability declarations control executable command discovery."""
from pathlib import Path
import shutil
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_renderer_omits_commands_for_unsupported_clients(tmp_path: Path) -> None:
    source = tmp_path / "agent"
    shutil.copytree(
        REPO_ROOT / "agent", source,
        ignore=shutil.ignore_patterns(
            ".claude", ".codex", ".goose", ".opencode", "engagements",
            "references", "skills", "__pycache__", "data",
        ),
    )
    command = source / "commands" / "vigil-start.md"
    command.write_text(
        "---\nname: vigil-start\ndescription: Synthetic client contract\nclients: claude\n---\nSynthetic body.\n",
        encoding="utf-8",
    )
    output = tmp_path / "rendered"
    output.mkdir()

    result = subprocess.run(
        ["bash", str(source / "scripts" / "render-operator-prompts.sh"), "repo", str(output)],
        capture_output=True, text=True,
    )

    assert result.returncode == 0, result.stderr
    assert (output / ".claude" / "commands" / "vigil-start.md").is_file()
    assert not (output / ".codex" / "skills" / "vigil-start" / "SKILL.md").exists()
    assert (output / ".codex" / "skills" / "vigil-resume" / "SKILL.md").is_file()
