from __future__ import annotations

from pathlib import Path


def _ensure_agents_link(agents_src: Path, client_dir: Path) -> None:
    """Expose a generated specialist roster inside an engagement client dir."""
    if not agents_src.is_dir():
        return

    client_dir.mkdir(parents=True, exist_ok=True)
    agents_dest = client_dir / "agents"
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


def ensure_codex_agents_link(agent_root: Path, codex_dir: Path) -> None:
    """Expose the generated Codex specialist roster inside an engagement cwd."""
    _ensure_agents_link(agent_root / ".codex" / "agents", codex_dir)


def ensure_claude_agents_link(agent_root: Path, claude_dir: Path) -> None:
    """Expose the generated Claude specialist roster inside an engagement cwd."""
    _ensure_agents_link(agent_root / ".claude" / "agents", claude_dir)


def ensure_claude_settings(agent_root: Path, claude_dir: Path) -> None:
    """Copy the generated Claude settings into an engagement cwd when present."""
    settings_src = agent_root / ".claude" / "settings.json"
    if not settings_src.is_file():
        return
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_dest = claude_dir / "settings.json"
    if settings_dest.exists() or settings_dest.is_symlink():
        return
    settings_dest.write_text(settings_src.read_text(encoding="utf-8"), encoding="utf-8")


def repair_engagement_client_rosters(install_root: Path) -> None:
    """Backfill generated client rosters for existing engagement workdirs."""
    agent_root = install_root / "agent"
    engagements_root = agent_root / "engagements"
    if not engagements_root.is_dir():
        return

    for eng_dir in engagements_root.iterdir():
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        if not ((eng_dir / ".codex").exists() or (eng_dir / "start_codex.sh").exists()):
            codex_needed = False
        else:
            codex_needed = True
        claude_needed = (eng_dir / ".claude").exists() or (eng_dir / "start_claude.sh").exists()
        if codex_needed:
            ensure_codex_agents_link(agent_root, eng_dir / ".codex")
        if claude_needed:
            claude_dir = eng_dir / ".claude"
            ensure_claude_settings(agent_root, claude_dir)
            ensure_claude_agents_link(agent_root, claude_dir)


def repair_engagement_codex_agent_links(install_root: Path) -> None:
    """Backfill `.codex/agents` links for existing Codex engagement workdirs."""
    repair_engagement_client_rosters(install_root)
