from __future__ import annotations

from pathlib import Path


def _ensure_agents_link(agents_src: Path, client_dir: Path, *, link_name: str = "agents") -> None:
    """Expose a generated specialist roster inside an engagement client dir.

    ``link_name`` is the directory name the link takes inside ``client_dir``.
    Codex/Claude expose the roster as ``agents``; OpenCode reads ``agent``.
    """
    if not agents_src.is_dir():
        return

    client_dir.mkdir(parents=True, exist_ok=True)
    agents_dest = client_dir / link_name
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


def ensure_opencode_agents_link(agent_root: Path, opencode_dir: Path) -> None:
    """Expose the generated OpenCode specialist roster inside an engagement cwd.

    OpenCode reads project agents from ``.opencode/agent/`` (singular), so the
    link target file name differs from Codex/Claude (which use ``agents``). The
    generated roster lives at ``agent/.opencode/agent``.
    """
    _ensure_agents_link(agent_root / ".opencode" / "agent", opencode_dir, link_name="agent")


def ensure_claude_settings(agent_root: Path, claude_dir: Path) -> None:
    """Copy generated Claude settings into an engagement cwd when present.

    Engagement directories get their own settings.json copy so Claude can load
    hooks from the engagement cwd. Refresh stale copies during repair so hook
    command path fixes reach existing engagements too.
    """
    settings_src = agent_root / ".claude" / "settings.json"
    if not settings_src.is_file():
        return
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_dest = claude_dir / "settings.json"
    settings_text = settings_src.read_text(encoding="utf-8")
    if settings_dest.is_symlink():
        settings_dest.unlink()
    elif settings_dest.exists() and not settings_dest.is_file():
        return
    if settings_dest.exists() and settings_dest.read_text(encoding="utf-8") == settings_text:
        return
    settings_dest.write_text(settings_text, encoding="utf-8")


def ensure_opencode_plugin(agent_root: Path, opencode_dir: Path) -> None:
    """Copy the standard OpenCode plugin into an engagement cwd when present.

    Mirrors ``ensure_claude_settings``: refresh stale copies during repair so a
    fix to the standard scope-check/activity-log plugin reaches existing
    engagements too. Written to both ``plugin`` and ``plugins`` (the binary
    honours either directory name; the singular is predominant).
    """
    plugin_src = agent_root / ".opencode" / "plugin" / "standard-hooks.js"
    if not plugin_src.is_file():
        return
    body = plugin_src.read_text(encoding="utf-8")
    for dirname in ("plugin", "plugins"):
        plugin_dir = opencode_dir / dirname
        plugin_dir.mkdir(parents=True, exist_ok=True)
        dest = plugin_dir / "standard-hooks.js"
        if dest.is_symlink():
            dest.unlink()
        elif dest.exists() and not dest.is_file():
            continue
        if dest.exists() and dest.read_text(encoding="utf-8") == body:
            continue
        dest.write_text(body, encoding="utf-8")


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
        # OpenCode parity: any engagement that got a start_opencode.sh launcher
        # (codex/claude/both installs all emit it) or already has a .opencode dir
        # should carry the standard plugin + roster.
        opencode_needed = (eng_dir / ".opencode").exists() or (eng_dir / "start_opencode.sh").exists()
        if codex_needed:
            ensure_codex_agents_link(agent_root, eng_dir / ".codex")
        if claude_needed:
            claude_dir = eng_dir / ".claude"
            ensure_claude_settings(agent_root, claude_dir)
            ensure_claude_agents_link(agent_root, claude_dir)
        if opencode_needed:
            opencode_dir = eng_dir / ".opencode"
            ensure_opencode_plugin(agent_root, opencode_dir)
            ensure_opencode_agents_link(agent_root, opencode_dir)


def repair_engagement_codex_agent_links(install_root: Path) -> None:
    """Backfill `.codex/agents` links for existing Codex engagement workdirs."""
    repair_engagement_client_rosters(install_root)
