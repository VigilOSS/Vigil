from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from . import docker
from . import config as config_module
from . import term
from .client_rosters import ClientRosterRepairResult, repair_engagement_client_rosters
from .image_freshness import is_excluded_input
from .install_manifest import (
    INSTALL_META_FILENAME,
    MANAGED_PRESERVE_REL_PATHS,
    ROOT_MANAGED_NAMES,
    install_source_content_sha256,
    validate_install_destination,
)
from .install_fs import (
    PinnedDirectory,
    atomic_write_bytes,
    copy_regular_file,
    ensure_directory,
    entry_stat,
    open_child_directory,
    open_pinned_directory,
    remove_entry,
    unsafe_path,
)
from .oob_relay import (
    OOB_ALLOCATION_REGISTRY_FILENAME,
    has_pre_routing_oob_state,
    initialize_relay_route,
)
from .runtime import build_runtime
from .status import write_install_meta

if TYPE_CHECKING:
    from .engagements import ClientEntrypointRepairResult


# Directories/files only a PRIOR Vigil install or run leaves behind. Source-tree
# directory names ("agent", "orchestrator", ".claude", ".codex") are NOT a
# signal: when the install root IS the source checkout they exist before Vigil
# has ever run there, and the FIRST in-place install would report an upgrade.
# OOB relay routing no longer keys off this flag at all — it reads the install's
# own OOB state (`oob_relay.has_pre_routing_oob_state`), because "this root is
# not brand new" never proved that live callbacks were riding the shared
# 53/8443 route. This marker set still has to stay honest for every other
# upgrade-sensitive decision.
PRIOR_INSTALL_MARKERS = (
    INSTALL_META_FILENAME,  # stamped by every install_from_source
    ".runtime-data",  # created by the descriptor-relative installer sync
)

LEGACY_INSTALLER_NAME = "install" ".sh"

_ROOT_OPERATOR_POINTER = """# Vigil Operator Entry Point

The canonical operator instructions live at `agent/AGENTS.md` in this working root.
Read that file in bounded parts, following its Map of This File, and continue until
you have reached the end of the file. Do not treat a tool's partial-read notice as
completion.
"""


@dataclass(frozen=True, slots=True)
class InstallOptions:
    source_root: Path
    install_root: Path
    dry_run: bool = False
    force_image: bool = False
    verify_docker_image: bool = True
    repair_ambiguous_client_permissions_as_skip: bool = False
    refresh_physical_client_rosters: bool = False


@dataclass(frozen=True, slots=True)
class InstallResult:
    install_root: Path
    is_upgrade: bool
    image_built: bool
    client_roster_repair: ClientRosterRepairResult | None = None
    client_entrypoint_repair: ClientEntrypointRepairResult | None = None
    # The checkout whose bytes were actually copied, already resolved through
    # `--source`/env/config. The post-install freshness verdict must compare
    # against THIS root: rediscovering a source afterwards can pick a different
    # checkout on a box that has two, and then report the just-installed root
    # stale against a tree it was never installed from.
    source_root: Path | None = None


def _has_engagement_directories(install_root: Path) -> bool:
    """True when `agent/engagements/` holds at least one real engagement.

    An engagement is a DIRECTORY created by Vigil at engagement time; a pristine
    checkout carries only the tracked `.gitkeep` placeholder file. This is the
    marker that still recognises an install predating `.runtime-data` and the
    install stamp — the case the legacy shared OOB route exists for.
    """
    engagements = install_root / "agent" / "engagements"
    try:
        return any(
            child.is_dir() and not child.name.startswith(".")
            for child in engagements.iterdir()
        )
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return False


def has_prior_install_state(install_root: Path) -> bool:
    """True when a previous Vigil install/run left its own state in this root.

    This is the honest upgrade signal: every marker is Vigil-created, so all are
    absent in a pristine source checkout and at least one is present in any root
    Vigil has installed into or run an engagement from.
    """
    if any((install_root / name).exists() for name in PRIOR_INSTALL_MARKERS):
        return True
    return _has_engagement_directories(install_root)


def _has_preserved_descendant(child_name: str, preserve_rel_paths: set[Path]) -> bool:
    child = Path(child_name)
    return any(path == child or (path.parts and path.parts[0] == child_name) for path in preserve_rel_paths)


def _reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise OSError(f"unsafe symbolic link in install-managed tree: {path}")


def _child_preserve_paths(name: str, paths: set[Path]) -> set[Path]:
    return {
        Path(*path.parts[1:])
        for path in paths
        if path.parts and path.parts[0] == name and len(path.parts) > 1
    }


def _sync_dir_fds(
    source_fd: int,
    destination_fd: int,
    *,
    source_display: Path,
    destination_display: Path,
    preserve_rel_paths: set[Path],
) -> None:
    source_names = set(os.listdir(source_fd))
    for name in os.listdir(destination_fd):
        if _has_preserved_descendant(name, preserve_rel_paths):
            remaining = _child_preserve_paths(name, preserve_rel_paths)
            source_meta = entry_stat(source_fd, name)
            destination_meta = entry_stat(destination_fd, name)
            if (
                remaining
                and source_meta is not None
                and stat.S_ISDIR(source_meta.st_mode)
                and destination_meta is not None
                and stat.S_ISDIR(destination_meta.st_mode)
            ):
                source_child = open_child_directory(
                    source_fd, name, source_display / name
                )
                destination_child = open_child_directory(
                    destination_fd, name, destination_display / name
                )
                try:
                    _sync_dir_fds(
                        source_child,
                        destination_child,
                        source_display=source_display / name,
                        destination_display=destination_display / name,
                        preserve_rel_paths=remaining,
                    )
                finally:
                    os.close(source_child)
                    os.close(destination_child)
            continue
        if name not in source_names and not is_excluded_input(name):
            remove_entry(destination_fd, name, destination_display / name)

    for name in source_names:
        if is_excluded_input(name) or Path(name) in preserve_rel_paths:
            continue
        source_meta = entry_stat(source_fd, name)
        if source_meta is None:
            raise OSError(f"install source changed while copying: {source_display / name}")
        if stat.S_ISLNK(source_meta.st_mode):
            raise unsafe_path(source_display / name)
        destination_path = destination_display / name
        _reject_symlink(destination_path)
        child_preserve = _child_preserve_paths(name, preserve_rel_paths)
        if stat.S_ISDIR(source_meta.st_mode):
            destination_child = ensure_directory(
                destination_fd, name, destination_path
            )
            source_child = open_child_directory(source_fd, name, source_display / name)
            try:
                _sync_dir_fds(
                    source_child,
                    destination_child,
                    source_display=source_display / name,
                    destination_display=destination_path,
                    preserve_rel_paths=child_preserve,
                )
            finally:
                os.close(source_child)
                os.close(destination_child)
        elif stat.S_ISREG(source_meta.st_mode):
            copy_regular_file(
                source_fd,
                name,
                destination_fd,
                name,
                source_display=source_display / name,
                destination_display=destination_path,
            )
        else:
            raise unsafe_path(source_display / name, "non-regular file")


def _prune_missing_source_tree(
    destination_fd: int,
    *,
    destination_display: Path,
    preserve_rel_paths: set[Path],
) -> None:
    """Remove managed descendants absent with their source root, retaining state."""

    for name in os.listdir(destination_fd):
        if _has_preserved_descendant(name, preserve_rel_paths):
            remaining = _child_preserve_paths(name, preserve_rel_paths)
            if not remaining:
                continue
            destination_path = destination_display / name
            metadata = entry_stat(destination_fd, name)
            if metadata is None:
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                raise unsafe_path(destination_path, "non-directory preserved path")
            child_fd = open_child_directory(destination_fd, name, destination_path)
            try:
                _prune_missing_source_tree(
                    child_fd,
                    destination_display=destination_path,
                    preserve_rel_paths=remaining,
                )
            finally:
                os.close(child_fd)
            continue
        if not is_excluded_input(name):
            remove_entry(destination_fd, name, destination_display / name)


def _ensure_directory_chain(root_fd: int, root: Path, parts: tuple[str, ...]) -> None:
    descriptor = os.dup(root_fd)
    try:
        display = root
        for part in parts:
            display /= part
            child = ensure_directory(descriptor, part, display)
            os.close(descriptor)
            descriptor = child
    finally:
        os.close(descriptor)


def _sync_managed_roots(
    source_fd: int,
    destination_fd: int,
    *,
    source_root: Path,
    destination_root: Path,
) -> None:
    for name in ROOT_MANAGED_NAMES:
        source_meta = entry_stat(source_fd, name)
        destination_path = destination_root / name
        if source_meta is None:
            if name in {"agent", "orchestrator"}:
                destination_meta = entry_stat(destination_fd, name)
                if destination_meta is not None:
                    if not stat.S_ISDIR(destination_meta.st_mode):
                        raise unsafe_path(
                            destination_path, "non-directory required path"
                        )
                    destination_child = open_child_directory(
                        destination_fd, name, destination_path
                    )
                    preserve = {
                        Path(*path.parts[1:])
                        for path in MANAGED_PRESERVE_REL_PATHS
                        if path.parts and path.parts[0] == name
                    }
                    try:
                        _prune_missing_source_tree(
                            destination_child,
                            destination_display=destination_path,
                            preserve_rel_paths=preserve,
                        )
                    finally:
                        os.close(destination_child)
                continue
            remove_entry(destination_fd, name, destination_path)
            continue
        if stat.S_ISLNK(source_meta.st_mode):
            raise unsafe_path(source_root / name)
        _reject_symlink(destination_path)
        if stat.S_ISDIR(source_meta.st_mode):
            destination_child = ensure_directory(destination_fd, name, destination_path)
            source_child = open_child_directory(source_fd, name, source_root / name)
            preserve = {
                Path(*path.parts[1:])
                for path in MANAGED_PRESERVE_REL_PATHS
                if path.parts and path.parts[0] == name
            }
            try:
                _sync_dir_fds(
                    source_child,
                    destination_child,
                    source_display=source_root / name,
                    destination_display=destination_path,
                    preserve_rel_paths=preserve,
                )
            finally:
                os.close(source_child)
                os.close(destination_child)
        elif stat.S_ISREG(source_meta.st_mode):
            copy_regular_file(
                source_fd,
                name,
                destination_fd,
                name,
                source_display=source_root / name,
                destination_display=destination_path,
            )
        else:
            raise unsafe_path(source_root / name, "non-regular file")


def _sync_client_entrypoints_fds(
    source_fd: int,
    destination_fd: int,
    *,
    source_root: Path,
    destination_root: Path,
) -> None:
    agent_meta = entry_stat(source_fd, "agent")
    agent_fd = (
        open_child_directory(source_fd, "agent", source_root / "agent")
        if agent_meta is not None and stat.S_ISDIR(agent_meta.st_mode)
        else None
    )
    try:
        agents_meta = entry_stat(agent_fd, "AGENTS.md") if agent_fd is not None else None
        if agents_meta is None:
            remove_entry(destination_fd, "AGENTS.md", destination_root / "AGENTS.md")
        elif stat.S_ISREG(agents_meta.st_mode):
            atomic_write_bytes(
                destination_fd,
                "AGENTS.md",
                _ROOT_OPERATOR_POINTER.encode(),
                mode=0o644,
                display=destination_root / "AGENTS.md",
            )
        else:
            raise unsafe_path(source_root / "agent" / "AGENTS.md")

        claude_meta = entry_stat(agent_fd, "CLAUDE.md") if agent_fd is not None else None
        if claude_meta is None:
            remove_entry(destination_fd, "CLAUDE.md", destination_root / "CLAUDE.md")
        elif stat.S_ISREG(claude_meta.st_mode):
            assert agent_fd is not None
            copy_regular_file(
                agent_fd,
                "CLAUDE.md",
                destination_fd,
                "CLAUDE.md",
                source_display=source_root / "agent" / "CLAUDE.md",
                destination_display=destination_root / "CLAUDE.md",
            )
        else:
            raise unsafe_path(source_root / "agent" / "CLAUDE.md")

        for dirname in (".codex", ".claude"):
            source_meta = entry_stat(agent_fd, dirname) if agent_fd is not None else None
            destination_path = destination_root / dirname
            if source_meta is None:
                remove_entry(destination_fd, dirname, destination_path)
                continue
            if not stat.S_ISDIR(source_meta.st_mode):
                raise unsafe_path(source_root / "agent" / dirname)
            assert agent_fd is not None
            source_child = open_child_directory(
                agent_fd, dirname, source_root / "agent" / dirname
            )
            destination_child = ensure_directory(
                destination_fd, dirname, destination_path
            )
            try:
                _sync_dir_fds(
                    source_child,
                    destination_child,
                    source_display=source_root / "agent" / dirname,
                    destination_display=destination_path,
                    preserve_rel_paths=set(),
                )
            finally:
                os.close(source_child)
                os.close(destination_child)
    finally:
        if agent_fd is not None:
            os.close(agent_fd)


def _sync_install_files(source_root: Path, install_root: Path) -> PinnedDirectory:
    source_pin = open_pinned_directory(source_root)
    assert source_pin is not None
    with source_pin:
        destination_pin = open_pinned_directory(install_root, create=True)
        assert destination_pin is not None
        try:
            same_tree = (
                os.fstat(source_pin.fd).st_dev,
                os.fstat(source_pin.fd).st_ino,
            ) == (
                os.fstat(destination_pin.fd).st_dev,
                os.fstat(destination_pin.fd).st_ino,
            )
            if not same_tree:
                remove_entry(
                    destination_pin.fd,
                    LEGACY_INSTALLER_NAME,
                    install_root / LEGACY_INSTALLER_NAME,
                )
                _sync_managed_roots(
                    source_pin.fd,
                    destination_pin.fd,
                    source_root=source_root,
                    destination_root=install_root,
                )
                _sync_client_entrypoints_fds(
                    source_pin.fd,
                    destination_pin.fd,
                    source_root=source_root,
                    destination_root=install_root,
                )
            _ensure_directory_chain(
                destination_pin.fd, install_root, (".runtime-data", "logs")
            )
            _ensure_directory_chain(
                destination_pin.fd, install_root, (".runtime-data", "pids")
            )
            _ensure_directory_chain(
                destination_pin.fd, install_root, ("agent", "engagements")
            )
            _ensure_directory_chain(
                destination_pin.fd,
                install_root,
                ("orchestrator", "backend", "data"),
            )
            destination_pin.require_attached()
            return destination_pin
        except BaseException:
            destination_pin.close()
            raise


def _configured_oob_slot(caller_config: dict[str, str]) -> str:
    """Resolve the configured OOB relay slot name, honouring the pre-rename key.

    `oob.tenant` is the name this setting shipped under before the OOB "tenant"
    concept was renamed to a relay slot. An install configured then must keep
    allocating the slot the operator named, not silently fall back to the
    install-directory name.
    """
    for value in (
        caller_config.get("oob.slot"),
        caller_config.get("oob.tenant"),
    ):
        if value and value.strip():
            return value.strip()
    return ""


# The "no relay route" notice, in sentences so each audience gets exactly the
# claims that apply to it. Allocation happens inside `install_from_source` and
# ONLY there, so staying silent leaves an operator who configures OOB after
# installing with no idea that a SECOND install is what reserves their slot.
_OOB_NOTICE_FINDING = "[vigil] OOB: no relay route — `oob.domain` is unset."
# Two steps, both named: setting the key alone allocates nothing, and re-running
# `vigil install` alone cannot help while the key is unset. Naming only one of
# them is the no-op loop release follow-up #4 was raised about.
_OOB_NOTICE_REMEDY = (
    "Set the domain, then re-run `vigil install` to reserve this install its "
    "own relay slot:"
)
_OOB_NOTICE_COMMAND = "vigil config set oob.domain <domain>    # or export VIGIL_OOB_DOMAIN"
# Added ONLY for a root whose callbacks are already live on the shared route:
# it answers "will re-running install move them?" for the one population that
# can ask it. On a fresh root it asserted a reassurance about state that root
# does not have, and `vigil doctor`'s `oob.relay-route` row already carries the
# general form.
_OOB_NOTICE_LEGACY_ROUTE_KEPT = (
    "This root keeps the shared legacy route (ports 53/8443) it already runs "
    "OOB on; live callbacks do not move."
)
# Hang continuation lines under the `[vigil] ` marker; the notice's command
# sits two further in so it reads as a thing to copy rather than more prose.
_DIAGNOSTIC_INDENT = " " * len("[vigil] ")


def _diagnostic(text: str) -> str:
    """A `[vigil] ...` stderr line, wrapped for a terminal, untouched by a pipe.

    These lines are machine records (`key=value` fields) as much as operator
    output, so `term.wrap` is deliberately the only treatment applied: piped, it
    returns the record byte-for-byte, one greppable line; on a terminal it hangs
    the overflow under the marker instead of letting an 80-column terminal break
    `permission_overrides=0` across two lines.
    """
    return term.wrap(text, indent=_DIAGNOSTIC_INDENT, stream=sys.stderr)


def _format_oob_route_notice(install_root: Path, *, stream: TextIO) -> str:
    """Render the "no relay route allocated" notice for `stream`.

    On a terminal this is a hung, width-wrapped paragraph plus an indented
    command, because the unwrapped single `print` it replaced let an 80-column
    terminal hard-wrap `vigil install` mid-word. Off a terminal it collapses to
    ONE line — the same notice an LLM reader or a `grep` over a redirected
    install log sees, and fewer bytes than the line it replaced.
    """
    sentences = [_OOB_NOTICE_FINDING]
    if has_pre_routing_oob_state(install_root):
        sentences.append(_OOB_NOTICE_LEGACY_ROUTE_KEPT)
    sentences.append(_OOB_NOTICE_REMEDY)
    paragraph = " ".join(sentences)
    if not term.is_terminal(stream):
        # The command's display padding is alignment, not content: collapse it
        # so a piped reader is never charged for a gutter it cannot see.
        # Gated on `is_terminal`, not `supports_style`: this picks a LAYOUT, and
        # an operator who set NO_COLOR still has a width to wrap to.
        return f"{paragraph} {' '.join(_OOB_NOTICE_COMMAND.split())}"
    return (
        f"{term.wrap(paragraph, indent=_DIAGNOSTIC_INDENT, stream=stream)}\n"
        f"{_DIAGNOSTIC_INDENT}  {_OOB_NOTICE_COMMAND}"
    )


def install_from_source(
    options: InstallOptions,
    *,
    runner: docker.Runner = docker.run_command,
    build_runner: docker.Runner = docker.run_command_streaming,
) -> InstallResult:
    source_path = options.source_root.expanduser()
    install_path = options.install_root.expanduser()

    # Validate the complete managed source and every existing destination path
    # before the first write. Besides making the stamp's manifest available to
    # status, this prevents a pre-created link from redirecting copy or repair
    # work outside the requested working root.
    install_source_content_sha256(source_path)
    validate_install_destination(install_path)
    # Keep the validated path itself instead of resolving it through a link that
    # could be swapped in after preflight. The recursive copier repeats its
    # no-symlink checks while walking.
    source_root = Path(os.path.abspath(source_path))
    install_root = Path(os.path.abspath(install_path))

    # Computed before the descriptor-relative sync creates `.runtime-data`,
    # which would otherwise make every install look like an upgrade to itself.
    is_upgrade = has_prior_install_state(install_root)
    if options.dry_run:
        return InstallResult(
            install_root=install_root,
            is_upgrade=is_upgrade,
            image_built=False,
        )

    # Relative config paths belong to the caller's cwd, not the descriptor-pinned
    # install cwd used by post-sync filesystem phases. Capture one config snapshot
    # and its registry location before entering that scope.
    caller_config_path = config_module.config_path()
    caller_config = config_module.load_config(caller_config_path)
    configured_oob_domain = (
        os.environ.get("VIGIL_OOB_DOMAIN") or caller_config.get("oob.domain") or ""
    )
    configured_oob_slot = _configured_oob_slot(caller_config) or install_root.name
    oob_registry_path = caller_config_path.with_name(
        OOB_ALLOCATION_REGISTRY_FILENAME
    )

    destination_boundary = _sync_install_files(source_root, install_root)
    try:
        destination_boundary.require_attached()
        with destination_boundary.working_directory() as phase_root:
            client_roster_repair = repair_engagement_client_rosters(
                phase_root,
                refresh_physical_client_rosters=options.refresh_physical_client_rosters,
                rendered_install_root=install_root,
            )
            destination_boundary.require_attached()
            if client_roster_repair.physical_roster_paths:
                print(
                    _diagnostic(
                        "[vigil] client-roster repair: "
                        f"scanned={client_roster_repair.scanned_engagement_count} "
                        f"physical={len(client_roster_repair.physical_roster_paths)} "
                        f"refreshed={len(client_roster_repair.refreshed_physical_roster_paths)} "
                        f"files_added={client_roster_repair.files_added} "
                        f"files_updated={client_roster_repair.files_updated} "
                        f"files_unchanged={client_roster_repair.files_unchanged} "
                        f"extras_preserved={client_roster_repair.extra_files_preserved}"
                    ),
                    file=sys.stderr,
                )
                refreshed_paths = set(
                    client_roster_repair.refreshed_physical_roster_paths
                )
                for path in client_roster_repair.physical_roster_paths[:20]:
                    if path in refreshed_paths:
                        print(
                            _diagnostic(f"[vigil] client-roster refreshed path={path}"),
                            file=sys.stderr,
                        )
                    else:
                        print(
                            _diagnostic(
                                "[vigil] warning: preserved physical client roster "
                                f"path={path}; rerun with --refresh-physical-client-rosters "
                                "to add or refresh canonical generated files in place"
                            ),
                            file=sys.stderr,
                        )
                hidden_physical_count = (
                    len(client_roster_repair.physical_roster_paths) - 20
                )
                if hidden_physical_count > 0:
                    print(
                        _diagnostic(
                            "[vigil] warning: client-roster repair has "
                            f"{hidden_physical_count} additional physical paths"
                        ),
                        file=sys.stderr,
                    )

            # Import lazily: engagements consumes the roster helpers above, while the
            # installer owns when existing workdirs are reconciled after their generated
            # sources have been refreshed.
            from .engagements import repair_engagement_client_entrypoints

            destination_boundary.require_attached()
            client_entrypoint_repair = repair_engagement_client_entrypoints(
                phase_root,
                ambiguous_permissions_as_skip=options.repair_ambiguous_client_permissions_as_skip,
                rendered_install_root=install_root,
            )
            destination_boundary.require_attached()
            if client_entrypoint_repair.scanned_count:
                print(
                    _diagnostic(
                        "[vigil] client-entrypoint repair: "
                        f"scanned={client_entrypoint_repair.scanned_count} "
                        f"reconciled={client_entrypoint_repair.reconciled_count} "
                        f"skipped={client_entrypoint_repair.skipped_count} "
                        f"permission_overrides={len(client_entrypoint_repair.permission_overrides)}"
                    ),
                    file=sys.stderr,
                )
                for engagement_key in client_entrypoint_repair.permission_overrides[
                    :20
                ]:
                    print(
                        _diagnostic(
                            "[vigil] warning: client-entrypoint repair applied explicit "
                            "permission_mode=skip override "
                            f"engagement={engagement_key}"
                        ),
                        file=sys.stderr,
                    )
                hidden_override_count = (
                    len(client_entrypoint_repair.permission_overrides) - 20
                )
                if hidden_override_count > 0:
                    print(
                        _diagnostic(
                            "[vigil] warning: client-entrypoint repair applied explicit "
                            f"permission override to {hidden_override_count} additional engagements"
                        ),
                        file=sys.stderr,
                    )
                for skip in client_entrypoint_repair.skipped[:20]:
                    evidence = (
                        f" evidence={','.join(skip.evidence)}" if skip.evidence else ""
                    )
                    print(
                        _diagnostic(
                            "[vigil] warning: client-entrypoint repair skipped "
                            f"engagement={skip.engagement_key} reason={skip.reason}{evidence}"
                        ),
                        file=sys.stderr,
                    )
                hidden_skip_count = client_entrypoint_repair.skipped_count - 20
                if hidden_skip_count > 0:
                    print(
                        _diagnostic(
                            "[vigil] warning: client-entrypoint repair skipped "
                            f"{hidden_skip_count} additional engagements"
                        ),
                        file=sys.stderr,
                    )

            if not configured_oob_domain:
                print(
                    _format_oob_route_notice(phase_root, stream=sys.stderr),
                    file=sys.stderr,
                )
            if configured_oob_domain:
                destination_boundary.require_attached()
                initialize_relay_route(
                    phase_root,
                    slot_name=configured_oob_slot,
                    base_domain=configured_oob_domain,
                    registry_path=oob_registry_path,
                    canonical_install_root=install_root,
                    preserve_install_path=True,
                )
                destination_boundary.require_attached()

            # Stamp in the sync owner so install, update, and up cannot diverge.
            destination_boundary.require_attached()
            write_install_meta(
                phase_root,
                source_root,
                install_fd=destination_boundary.fd,
            )
            destination_boundary.require_attached()

            image_built = False
            if options.verify_docker_image:
                image = "vigil:latest"
                if options.force_image or not docker.image_exists(image, runner=runner):
                    # build_runtime owns the runtime-input label contract.
                    destination_boundary.require_attached()
                    build_runtime(phase_root, runner=build_runner)
                    destination_boundary.require_attached()
                    image_built = True
    finally:
        destination_boundary.close()
    return InstallResult(
        install_root=install_root,
        is_upgrade=is_upgrade,
        image_built=image_built,
        client_roster_repair=client_roster_repair,
        client_entrypoint_repair=client_entrypoint_repair,
        source_root=source_root,
    )
