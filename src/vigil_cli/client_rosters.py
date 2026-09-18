from __future__ import annotations

import json
import os
import shlex
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ClientRosterRepairResult:
    """Evidence from reconciling generated client rosters in existing workdirs."""

    scanned_engagement_count: int = 0
    physical_roster_paths: tuple[str, ...] = ()
    refreshed_physical_roster_paths: tuple[str, ...] = ()
    added_file_paths: tuple[str, ...] = ()
    updated_file_paths: tuple[str, ...] = ()
    unchanged_file_paths: tuple[str, ...] = ()
    preserved_extra_paths: tuple[str, ...] = ()

    @property
    def files_added(self) -> int:
        return len(self.added_file_paths)

    @property
    def files_updated(self) -> int:
        return len(self.updated_file_paths)

    @property
    def files_unchanged(self) -> int:
        return len(self.unchanged_file_paths)

    @property
    def extra_files_preserved(self) -> int:
        return len(self.preserved_extra_paths)


@dataclass(frozen=True, slots=True)
class _EngagementClientPlan:
    engagement_dir: Path
    codex_needed: bool
    claude_needed: bool
    opencode_needed: bool
    goose_needed: bool


@dataclass(frozen=True, slots=True)
class _PhysicalRoster:
    engagement_dir: Path
    source: Path
    destination: Path


def unsafe_symlink_destination(
    engagement_dir: Path, destinations: tuple[str, ...]
) -> str | None:
    """Return the first repair destination containing a symlink.

    Client rosters deliberately contain leaf symlinks to generated sources under
    ``agent/``.  Callers therefore pass only paths they own and write through;
    those paths must never contain a symlink, even one that resolves inside the
    engagement, because following it could overwrite unrelated run state.
    """

    for destination in destinations:
        current = engagement_dir
        for part in Path(destination).parts:
            current /= part
            try:
                mode = current.lstat().st_mode
            except FileNotFoundError:
                break
            except (NotADirectoryError, OSError):
                return str(current.relative_to(engagement_dir))
            if stat.S_ISLNK(mode):
                return str(current.relative_to(engagement_dir))
    return None


def _ensure_agents_link(
    agents_src: Path, client_dir: Path, *, link_names: tuple[str, ...] = ("agents",)
) -> None:
    """Expose a generated specialist roster inside an engagement client dir.

    ``link_names`` are the directory name(s) the link takes inside ``client_dir``;
    one symlink per name, all pointing at ``agents_src``. Codex/Claude expose the
    roster as ``agents``; OpenCode is given both ``agent`` and ``agents`` (see
    ``ensure_opencode_agents_link``).
    """
    if not agents_src.is_dir():
        return

    client_dir.mkdir(parents=True, exist_ok=True)
    for link_name in link_names:
        agents_dest = client_dir / link_name
        if agents_dest.is_symlink():
            try:
                if agents_dest.resolve() == agents_src.resolve():
                    continue
            except FileNotFoundError:
                pass
            agents_dest.unlink()
        elif agents_dest.exists():
            continue

        agents_dest.symlink_to(agents_src.resolve(), target_is_directory=True)


def ensure_codex_agents_link(agent_root: Path, codex_dir: Path) -> None:
    """Expose the generated Codex specialist roster inside an engagement cwd."""
    _ensure_agents_link(agent_root / ".codex" / "agents", codex_dir)


def ensure_claude_agents_link(agent_root: Path, claude_dir: Path) -> None:
    """Expose the generated Claude specialist roster inside an engagement cwd."""
    _ensure_agents_link(agent_root / ".claude" / "agents", claude_dir)


def ensure_opencode_agents_link(agent_root: Path, opencode_dir: Path) -> None:
    """Expose the generated OpenCode specialist roster inside an engagement cwd.

    OpenCode globs project agents from BOTH ``.opencode/agent/`` and
    ``.opencode/agents/`` (the 1.17.5 loader scans ``{agent,agents}/**/*.md`` and
    follows symlinks), so — mirroring the dual ``plugin``/``plugins`` write — link
    the roster under both names. Both point at the single generated source roster
    ``agent/.opencode/agent``; the singular name remains the canonical one the
    committed wrappers and the render-check use.
    """
    _ensure_agents_link(
        agent_root / ".opencode" / "agent", opencode_dir, link_names=("agent", "agents")
    )


def _ensure_entry_links(source_dir: Path, dest_dir: Path) -> None:
    """Point an engagement at each generated entry in ``source_dir`` individually.

    The specialist rosters link one whole directory, because nothing else is ever
    written into them.  Operator commands are different: an engagement may carry
    hand-authored commands of its own beside the shipped ones, and a directory
    symlink would either hide them or refuse to install anything at all.  So the
    owning directory stays real and each generated entry becomes its own pointer.

    Two properties follow, both deliberate:

    * A real file the operator wrote **wins** and is never replaced.  Engagement
      directories hold operator-owned content; the generated set yields to it,
      the same way the physical-roster refresh preserves unknown entries.
    * A pointer whose generated source has since been removed is pruned, so a
      renamed or retired command does not keep shipping as a dangling link.

    ADR 0017: engagement files stay bounded pointers, never copies that drift.
    """
    if not source_dir.is_dir():
        return
    if dest_dir.is_symlink():
        # Never write through a symlinked owning directory — following it could
        # land generated content somewhere unrelated to this engagement.
        return
    if dest_dir.exists() and not dest_dir.is_dir():
        return

    dest_dir.mkdir(parents=True, exist_ok=True)
    canonical_names = set()
    for entry in sorted(source_dir.iterdir(), key=lambda child: child.name):
        if entry.name.startswith("."):
            continue
        canonical_names.add(entry.name)
        destination = dest_dir / entry.name
        if destination.is_symlink():
            try:
                if destination.resolve() == entry.resolve():
                    continue
            except (OSError, RuntimeError):
                pass
            destination.unlink()
        elif destination.exists():
            continue
        destination.symlink_to(entry.resolve(), target_is_directory=entry.is_dir())

    source_resolved = source_dir.resolve()
    for destination in sorted(dest_dir.iterdir(), key=lambda child: child.name):
        if destination.name in canonical_names or not destination.is_symlink():
            continue
        try:
            target = destination.readlink()
        except OSError:
            continue
        if target.parent == source_resolved:
            destination.unlink()


def ensure_claude_commands_link(agent_root: Path, claude_dir: Path) -> None:
    """Expose the generated operator slash commands inside an engagement cwd.

    Claude Code reads project slash commands from ``.claude/commands/<name>.md``.
    """
    _ensure_entry_links(agent_root / ".claude" / "commands", claude_dir / "commands")


def ensure_codex_skills_link(agent_root: Path, codex_dir: Path) -> None:
    """Expose the generated operator skills inside an engagement cwd.

    Codex reads project skills from ``.codex/skills/<name>/SKILL.md`` and invokes
    one as ``$<name>``.  Verified against Codex 0.154.0 with
    ``codex debug prompt-input``: a project ``.codex/skills`` tree is discovered,
    a bare ``skills/`` is not, and both a symlinked skill directory and a
    symlinked skills root resolve normally.
    """
    _ensure_entry_links(agent_root / ".codex" / "skills", codex_dir / "skills")


def ensure_codex_config(
    agent_root: Path,
    codex_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    """Copy Codex config with hooks bound to the installed agent root."""
    config_src = agent_root / ".codex" / "config.toml"
    if not config_src.is_file():
        return
    target_root = rendered_agent_root or agent_root
    script_names = ("post-tool-log.sh", "session-end.sh")
    rendered_lines: list[str] = []
    for line in config_src.read_text(encoding="utf-8").splitlines(keepends=True):
        script_name = next((name for name in script_names if name in line), None)
        if script_name is not None and line.lstrip().startswith("command ="):
            command = shlex.join(
                ["bash", str(target_root / "scripts" / "hooks" / script_name)]
            )
            newline = "\n" if line.endswith("\n") else ""
            line = f"command = {json.dumps(command)}{newline}"
        rendered_lines.append(line)
    config_text = "".join(rendered_lines)

    codex_dir.mkdir(parents=True, exist_ok=True)
    config_dest = codex_dir / "config.toml"
    if config_dest.is_symlink():
        config_dest.unlink()
    elif config_dest.exists() and not config_dest.is_file():
        return
    if config_dest.exists() and config_dest.read_text(encoding="utf-8") == config_text:
        return
    config_dest.write_text(config_text, encoding="utf-8")


def ensure_claude_settings(
    agent_root: Path,
    claude_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    """Copy generated Claude settings into an engagement cwd when present.

    Engagement directories get their own settings.json copy so Claude can load
    hooks from the engagement cwd. Refresh stale copies during repair so hook
    command path fixes reach existing engagements too.

    Auto-memory is pinned off here rather than trusted from the template, for
    the same reason hook command paths are rewritten below: this file is the
    engagement's settings contract, and the backend ledger is meant to be the
    engagement's single record of truth. Setting it in the file (not only as a
    launcher env export) means it also holds for a bare `claude` started in the
    engagement directory.
    """
    settings_src = agent_root / ".claude" / "settings.json"
    if not settings_src.is_file():
        return
    claude_dir.mkdir(parents=True, exist_ok=True)
    settings_dest = claude_dir / "settings.json"
    settings = json.loads(settings_src.read_text(encoding="utf-8"))
    settings["autoMemoryEnabled"] = False
    hooks = settings.get("hooks", {})
    post_hooks = hooks.get("PostToolUse")
    if isinstance(post_hooks, list):
        hooks["PostToolUse"] = [
            item
            for item in post_hooks
            if not (isinstance(item, dict) and item.get("matcher") == "Agent")
        ]
    for phase_hooks in hooks.values():
        if not isinstance(phase_hooks, list):
            continue
        for phase_hook in phase_hooks:
            if not isinstance(phase_hook, dict):
                continue
            commands = phase_hook.get("hooks")
            if not isinstance(commands, list):
                continue
            for command in commands:
                if not isinstance(command, dict):
                    continue
                command_text = command.get("command")
                if not isinstance(command_text, str):
                    continue
                for script_name in (
                    "post-tool-log.sh",
                    "pre-compact.sh",
                    "session-end.sh",
                ):
                    if script_name in command_text:
                        target = (
                            rendered_agent_root or agent_root
                        ) / "scripts" / "hooks" / script_name
                        command["command"] = shlex.join(["bash", str(target)])
                        break
    settings_text = json.dumps(settings, indent=2) + "\n"
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
    fix to the standard activity-log plugin reaches existing engagements too.
    Written to both ``plugin`` and ``plugins`` (the binary honours either
    directory name; the singular is predominant).
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


def ensure_goose_recipes_link(agent_root: Path, goose_dir: Path) -> None:
    """Expose the generated Goose specialist recipe roster inside an engagement cwd.

    Goose dispatches a specialist by recipe name (``delegate source <role>``) and
    resolves it from ``GOOSE_RECIPE_PATH`` (set by start_goose.sh to
    ``<engagement>/.goose/recipes``). Link that dir at the single generated source
    roster ``agent/.goose/recipes``. There is NO operator recipe by design (the
    operator prompt is the engagement ``.goosehints``).
    """
    _ensure_agents_link(
        agent_root / ".goose" / "recipes", goose_dir, link_names=("recipes",)
    )


def _goose_hook_command(agent_root: Path, target: Path, *, env_prefix: str = "") -> str:
    """The shell command a Goose hook runs: reshape the payload, then the target script.

    Goose's PreToolUse/PostToolUse payload uses the bare shell tool name ``shell`` (goose
    v1.38.0; ``developer__shell`` in older/doc-form builds) with the command at
    ``tool_input.command``; the shared hook scripts (post-tool-log.sh, bench-guard.sh)
    key on the Claude ``tool_name == "Bash"`` contract.
    ``goose-hook-adapter.sh`` reshapes Goose's payload to that contract and pipes it to
    ``<target>``, propagating the exit code (2 = block). ``env_prefix`` lets the bench
    bake in ``VIGIL_BENCH_OWN_ENGAGEMENT=<key>`` for the guard's cross-attempt isolation.
    """
    adapter = agent_root / "scripts" / "hooks" / "goose-hook-adapter.sh"
    base = f"bash '{adapter}' '{target}'"
    return f"{env_prefix} {base}" if env_prefix else base


def ensure_goose_standard_hooks(
    agent_root: Path,
    eng_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    """Write the standard Goose hooks plugin (activity log) into an engagement.

    Mirrors ``ensure_opencode_plugin``: Goose hooks invoke shell scripts directly, so
    this reuses the SHARED post-tool-log.sh (activity log for the taint audit) on
    PostToolUse, via goose-hook-adapter.sh (payload reshape). Deterministic content →
    idempotent overwrite, refreshed on repair so a hook-path fix reaches existing
    engagements. There is no standard PreToolUse hook: Vigil does not filter its own
    operator's commands (ADR 0019). The bench layers its guard-only PreToolUse hook
    beside this (anticheat._patch_goose_hooks), exactly like the Claude/Codex/OpenCode
    guard layers on the standard hooks.
    """
    hooks_src = agent_root / "scripts" / "hooks"
    command_agent_root = rendered_agent_root or agent_root
    command_hooks_src = command_agent_root / "scripts" / "hooks"
    if not (hooks_src / "goose-hook-adapter.sh").is_file():
        return
    # Goose v1.38.0's tool names are BARE — `shell`, `write`, `edit`, `tree`, `read_image`
    # — NOT `developer__*` (its docs are wrong; verified by a live run). The earlier
    # `developer__.*` matcher matched NOTHING, so post-tool-log.sh never ran on Goose.
    # Goose matches by regex-SEARCH, so listing the bare names also catches the doc-form
    # `developer__shell`/`developer__write` of older builds. The file tools are in the
    # matcher so post-tool-log records file writes, not only shell commands.
    matcher = "shell|write|edit|tree|read_image|text_editor"
    config = {
        "hooks": {
            "PostToolUse": [
                {
                    "matcher": matcher,
                    "hooks": [{
                        "type": "command",
                        "command": _goose_hook_command(
                            command_agent_root, command_hooks_src / "post-tool-log.sh"
                        ),
                        "timeout": 30,
                    }],
                }
            ],
        }
    }
    hooks_dir = eng_dir / ".agents" / "plugins" / "vigil-standard" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "hooks.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def _unsafe_physical_roster(message: str, path: Path) -> RuntimeError:
    return RuntimeError(f"unsafe physical client roster {message}: {path}")


def _walk_tree(root: Path) -> tuple[Path, ...]:
    """Return a deterministic tree walk without following directory symlinks."""
    entries: list[Path] = []
    pending = [root]
    while pending:
        current = pending.pop()
        children = sorted(current.iterdir(), key=lambda child: child.name, reverse=True)
        for child in children:
            entries.append(child)
            mode = child.lstat().st_mode
            if stat.S_ISDIR(mode):
                pending.append(child)
    return tuple(sorted(entries, key=lambda entry: entry.as_posix()))


def _assert_regular_tree(root: Path, *, label: str) -> None:
    mode = root.lstat().st_mode
    if not stat.S_ISDIR(mode):
        raise _unsafe_physical_roster(f"{label} is not a directory", root)
    for entry in _walk_tree(root):
        mode = entry.lstat().st_mode
        if stat.S_ISLNK(mode):
            raise _unsafe_physical_roster(f"{label} contains a symlink", entry)
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise _unsafe_physical_roster(f"{label} contains a non-regular entry", entry)


def _assert_resolves_within(path: Path, root: Path, *, label: str) -> None:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (FileNotFoundError, ValueError) as exc:
        raise _unsafe_physical_roster(f"{label} escapes its owning root", path) from exc


def _strict_physical_destination(roster: _PhysicalRoster) -> bool:
    """Classify one destination, rejecting unsafe parents and stale symlinks."""
    try:
        relative = roster.destination.relative_to(roster.engagement_dir)
    except ValueError as exc:
        raise _unsafe_physical_roster(
            "destination is outside its engagement", roster.destination
        ) from exc

    current = roster.engagement_dir
    for part in relative.parts:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            return False
        except NotADirectoryError as exc:
            raise _unsafe_physical_roster("has a non-directory parent", current) from exc
        if stat.S_ISLNK(mode):
            if current == roster.destination:
                try:
                    if (
                        roster.source.is_dir()
                        and current.resolve(strict=True) == roster.source.resolve(strict=True)
                    ):
                        return False
                except FileNotFoundError:
                    pass
            raise _unsafe_physical_roster("has a symlink collision", current)
        if not stat.S_ISDIR(mode):
            raise _unsafe_physical_roster("has a type collision", current)
    return True


def _preflight_physical_roster(
    roster: _PhysicalRoster, *, agent_root: Path, engagements_root: Path
) -> None:
    _assert_resolves_within(
        roster.engagement_dir, engagements_root, label="engagement directory"
    )
    _assert_resolves_within(roster.source, agent_root, label="generated source")
    _assert_resolves_within(
        roster.destination, roster.engagement_dir, label="destination"
    )
    _assert_regular_tree(roster.source, label="generated source")
    _assert_regular_tree(roster.destination, label="destination")

    for source_entry in _walk_tree(roster.source):
        target = roster.destination / source_entry.relative_to(roster.source)
        try:
            target_mode = target.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISDIR(source_entry.lstat().st_mode):
            if not stat.S_ISDIR(target_mode):
                raise _unsafe_physical_roster(
                    "has a canonical directory type collision", target
                )
        elif not stat.S_ISREG(target_mode):
            raise _unsafe_physical_roster("has a canonical file type collision", target)


def _display_path(path: Path, install_root: Path) -> str:
    try:
        return str(path.relative_to(install_root))
    except ValueError:
        return str(path)


def _atomic_copy(source: Path, destination: Path) -> None:
    descriptor, temp_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.vigil-refresh-",
    )
    os.close(descriptor)
    temporary = Path(temp_name)
    try:
        shutil.copy2(source, temporary, follow_symlinks=False)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _refresh_physical_roster(
    roster: _PhysicalRoster, *, install_root: Path
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    canonical_files: set[Path] = set()
    added: list[str] = []
    updated: list[str] = []
    unchanged: list[str] = []

    for source_entry in _walk_tree(roster.source):
        relative = source_entry.relative_to(roster.source)
        destination = roster.destination / relative
        if source_entry.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            continue
        canonical_files.add(relative)
        if destination.exists() and destination.read_bytes() == source_entry.read_bytes():
            unchanged.append(_display_path(destination, install_root))
            continue
        existed = destination.exists()
        destination.parent.mkdir(parents=True, exist_ok=True)
        _atomic_copy(source_entry, destination)
        (updated if existed else added).append(_display_path(destination, install_root))

    extras = [
        _display_path(entry, install_root)
        for entry in _walk_tree(roster.destination)
        if stat.S_ISREG(entry.lstat().st_mode)
        and entry.relative_to(roster.destination) not in canonical_files
    ]
    return tuple(added), tuple(updated), tuple(unchanged), tuple(extras)


def _client_plan(agent_root: Path, engagement_dir: Path) -> _EngagementClientPlan:
    return _EngagementClientPlan(
        engagement_dir=engagement_dir,
        codex_needed=(engagement_dir / ".codex").exists()
        or (engagement_dir / "start_codex.sh").exists(),
        claude_needed=(engagement_dir / ".claude").exists()
        or (engagement_dir / "start_claude.sh").exists(),
        opencode_needed=(engagement_dir / ".opencode").exists()
        or (engagement_dir / "start_opencode.sh").exists(),
        goose_needed=(engagement_dir / ".goose").exists()
        or (engagement_dir / "start_goose.sh").exists()
        or (engagement_dir / ".goosehints").exists(),
    )


def _rosters_for_plan(agent_root: Path, plan: _EngagementClientPlan) -> tuple[_PhysicalRoster, ...]:
    rosters: list[_PhysicalRoster] = []
    if plan.codex_needed:
        rosters.append(
            _PhysicalRoster(
                plan.engagement_dir,
                agent_root / ".codex" / "agents",
                plan.engagement_dir / ".codex" / "agents",
            )
        )
    if plan.claude_needed:
        rosters.append(
            _PhysicalRoster(
                plan.engagement_dir,
                agent_root / ".claude" / "agents",
                plan.engagement_dir / ".claude" / "agents",
            )
        )
    if plan.opencode_needed:
        for name in ("agent", "agents"):
            rosters.append(
                _PhysicalRoster(
                    plan.engagement_dir,
                    agent_root / ".opencode" / "agent",
                    plan.engagement_dir / ".opencode" / name,
                )
            )
    if plan.goose_needed:
        rosters.append(
            _PhysicalRoster(
                plan.engagement_dir,
                agent_root / ".goose" / "recipes",
                plan.engagement_dir / ".goose" / "recipes",
            )
        )
    return tuple(rosters)


def repair_engagement_client_rosters(
    install_root: Path,
    *,
    refresh_physical_client_rosters: bool = False,
    rendered_install_root: Path | None = None,
) -> ClientRosterRepairResult:
    """Backfill generated client rosters for existing engagement workdirs.

    Physical roster directories are reported but preserved by default because they
    can contain engagement-owned state. The explicit refresh mode preflights every
    candidate before any writes, then atomically adds or refreshes canonical files
    in place without deleting unknown entries.
    """
    agent_root = install_root / "agent"
    rendered_agent_root = (rendered_install_root or install_root) / "agent"
    engagements_root = agent_root / "engagements"
    if not engagements_root.is_dir():
        return ClientRosterRepairResult()

    plans: list[_EngagementClientPlan] = []
    for eng_dir in sorted(engagements_root.iterdir(), key=lambda entry: entry.name):
        if eng_dir.is_symlink():
            if refresh_physical_client_rosters and (eng_dir / "scope.json").is_file():
                raise _unsafe_physical_roster("engagement path is a symlink", eng_dir)
            continue
        if eng_dir.is_dir() and (eng_dir / "scope.json").is_file():
            # The generated roster leaves themselves are external symlinks by
            # design, but none of their owning client directories may be.  This
            # repair also refreshes Claude/OpenCode/Goose support files, so check
            # the hook path's intermediate components as well.
            unsafe_destination = unsafe_symlink_destination(
                eng_dir,
                (
                    ".codex",
                    ".claude",
                    ".opencode",
                    ".goose",
                    ".claude/commands",
                    ".codex/skills",
                    ".agents/plugins/vigil-standard/hooks/hooks.json",
                ),
            )
            if unsafe_destination is not None:
                if refresh_physical_client_rosters:
                    raise _unsafe_physical_roster(
                        "has a symlink collision",
                        eng_dir / unsafe_destination,
                    )
                continue
            plans.append(_client_plan(agent_root, eng_dir))

    all_rosters = tuple(
        roster for plan in plans for roster in _rosters_for_plan(agent_root, plan)
    )
    physical_rosters: list[_PhysicalRoster] = []
    if refresh_physical_client_rosters:
        for roster in all_rosters:
            if roster.source.exists():
                _assert_resolves_within(roster.source, agent_root, label="generated source")
                _assert_regular_tree(roster.source, label="generated source")
            if _strict_physical_destination(roster):
                physical_rosters.append(roster)
        for roster in physical_rosters:
            _preflight_physical_roster(
                roster, agent_root=agent_root, engagements_root=engagements_root
            )
    else:
        physical_rosters = [
            roster
            for roster in all_rosters
            if roster.destination.is_dir() and not roster.destination.is_symlink()
        ]

    for plan in plans:
        eng_dir = plan.engagement_dir
        if plan.codex_needed:
            codex_dir = eng_dir / ".codex"
            ensure_codex_agents_link(agent_root, codex_dir)
            ensure_codex_skills_link(agent_root, codex_dir)
        if plan.claude_needed:
            claude_dir = eng_dir / ".claude"
            ensure_claude_settings(
                agent_root,
                claude_dir,
                rendered_agent_root=rendered_agent_root,
            )
            ensure_claude_agents_link(agent_root, claude_dir)
            ensure_claude_commands_link(agent_root, claude_dir)
        if plan.opencode_needed:
            opencode_dir = eng_dir / ".opencode"
            ensure_opencode_plugin(agent_root, opencode_dir)
            ensure_opencode_agents_link(agent_root, opencode_dir)
        if plan.goose_needed:
            ensure_goose_recipes_link(agent_root, eng_dir / ".goose")
            ensure_goose_standard_hooks(
                agent_root,
                eng_dir,
                rendered_agent_root=rendered_agent_root,
            )

    added: list[str] = []
    updated: list[str] = []
    unchanged: list[str] = []
    extras: list[str] = []
    if refresh_physical_client_rosters:
        for roster in physical_rosters:
            roster_added, roster_updated, roster_unchanged, roster_extras = (
                _refresh_physical_roster(roster, install_root=install_root)
            )
            added.extend(roster_added)
            updated.extend(roster_updated)
            unchanged.extend(roster_unchanged)
            extras.extend(roster_extras)

    physical_paths = tuple(
        sorted(_display_path(roster.destination, install_root) for roster in physical_rosters)
    )
    return ClientRosterRepairResult(
        scanned_engagement_count=len(plans),
        physical_roster_paths=physical_paths,
        refreshed_physical_roster_paths=(
            physical_paths if refresh_physical_client_rosters else ()
        ),
        added_file_paths=tuple(sorted(added)),
        updated_file_paths=tuple(sorted(updated)),
        unchanged_file_paths=tuple(sorted(unchanged)),
        preserved_extra_paths=tuple(sorted(extras)),
    )


def repair_engagement_codex_agent_links(install_root: Path) -> None:
    """Backfill `.codex/agents` links for existing Codex engagement workdirs."""
    repair_engagement_client_rosters(install_root)
