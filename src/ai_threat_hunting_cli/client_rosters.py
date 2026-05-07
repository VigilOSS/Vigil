from __future__ import annotations

from pathlib import Path


def ensure_codex_agents_link(agent_root: Path, codex_dir: Path) -> None:
    """Expose the generated Codex specialist roster inside an engagement cwd."""
    agents_src = agent_root / ".codex" / "agents"
    if not agents_src.is_dir():
        return

    codex_dir.mkdir(parents=True, exist_ok=True)
    agents_dest = codex_dir / "agents"
    if agents_dest.is_symlink():
        try:
            if agents_dest.resolve() == agents_src.resolve():
                return
        except FileNotFoundError:
            pass
        agents_dest.unlink()
    elif agents_dest.exists():
        return

    agents_dest.symlink_to(agents_src.resolve(), target_is_directory=True)


def repair_engagement_codex_agent_links(install_root: Path) -> None:
    """Backfill `.codex/agents` links for existing Codex engagement workdirs."""
    agent_root = install_root / "agent"
    engagements_root = agent_root / "engagements"
    if not engagements_root.is_dir():
        return

    for eng_dir in engagements_root.iterdir():
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        if not ((eng_dir / ".codex").exists() or (eng_dir / "start_codex.sh").exists()):
            continue
        ensure_codex_agents_link(agent_root, eng_dir / ".codex")
