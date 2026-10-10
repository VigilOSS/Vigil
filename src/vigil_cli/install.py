from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

from . import docker
from . import config as config_module
from . import term
from .client_rosters import ClientRosterRepairResult, repair_engagement_client_rosters
from .install_manifest import (
    INSTALL_META_FILENAME,
    install_source_content_sha256,
)
from .install_fs import (
    open_pinned_directory,
)
from .oob_relay import (
    OOB_ALLOCATION_REGISTRY_FILENAME,
    has_pre_routing_oob_state,
    initialize_relay_route,
)
from .runtime import build_runtime
from .status import write_install_meta
from .workspace import WORKSPACE_FILENAME, initialize_workspace, validate_workspace as validate_install_destination

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
    WORKSPACE_FILENAME,
    INSTALL_META_FILENAME,  # stamped by every install_from_source
    ".runtime-data",  # created by the descriptor-relative installer sync
)



@dataclass(frozen=True, slots=True)
class InstallOptions:
    source_root: Path
    install_root: Path
    dry_run: bool = False
    force_image: bool = False
    verify_docker_image: bool = False
    repair_ambiguous_client_permissions_as_skip: bool = False
    refresh_physical_client_rosters: bool = False


@dataclass(frozen=True, slots=True)
class InstallResult:
    install_root: Path
    is_upgrade: bool
    image_built: bool
    client_roster_repair: ClientRosterRepairResult | None = None
    client_entrypoint_repair: ClientEntrypointRepairResult | None = None
    # The matched application used for this initialization, not a workspace
    # source copy or a subsequently rediscovered checkout.
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


def _report_client_repairs(
    roster: ClientRosterRepairResult | None,
    entrypoints: ClientEntrypointRepairResult | None,
) -> None:
    """Present explicit maintenance results without changing stdout contracts."""
    if roster is not None and roster.physical_roster_paths:
        print(_diagnostic(
            "[vigil] client-roster repair: "
            f"scanned={roster.scanned_engagement_count} physical={len(roster.physical_roster_paths)} "
            f"refreshed={len(roster.refreshed_physical_roster_paths)} files_added={roster.files_added} "
            f"files_updated={roster.files_updated} files_unchanged={roster.files_unchanged} "
            f"extras_preserved={roster.extra_files_preserved}"
        ), file=sys.stderr)
        refreshed = set(roster.refreshed_physical_roster_paths)
        for path in roster.physical_roster_paths[:20]:
            if path in refreshed:
                message = f"[vigil] client-roster refreshed path={path}"
            else:
                message = (
                    f"[vigil] warning: preserved physical client roster path={path}; "
                    "rerun with --refresh-physical-client-rosters to add or refresh canonical generated files in place"
                )
            print(_diagnostic(message), file=sys.stderr)
        if len(roster.physical_roster_paths) > 20:
            print(_diagnostic(f"[vigil] warning: client-roster repair has {len(roster.physical_roster_paths) - 20} additional physical paths"), file=sys.stderr)
    if entrypoints is not None and entrypoints.scanned_count:
        print(_diagnostic(
            "[vigil] client-entrypoint repair: "
            f"scanned={entrypoints.scanned_count} reconciled={entrypoints.reconciled_count} "
            f"skipped={entrypoints.skipped_count} permission_overrides={len(entrypoints.permission_overrides)}"
        ), file=sys.stderr)
        for key in entrypoints.permission_overrides[:20]:
            print(_diagnostic(f"[vigil] warning: client-entrypoint repair applied explicit permission_mode=skip override engagement={key}"), file=sys.stderr)
        if len(entrypoints.permission_overrides) > 20:
            print(_diagnostic(f"[vigil] warning: client-entrypoint repair applied explicit permission override to {len(entrypoints.permission_overrides) - 20} additional engagements"), file=sys.stderr)
        for skip in entrypoints.skipped[:20]:
            evidence = f" evidence={','.join(skip.evidence)}" if skip.evidence else ""
            print(_diagnostic(f"[vigil] warning: client-entrypoint repair skipped engagement={skip.engagement_key} reason={skip.reason}{evidence}"), file=sys.stderr)
        if entrypoints.skipped_count > 20:
            print(_diagnostic(f"[vigil] warning: client-entrypoint repair skipped {entrypoints.skipped_count - 20} additional engagements"), file=sys.stderr)


def install_from_source(
    options: InstallOptions,
    *,
    runner: docker.Runner = docker.run_command,
    build_runner: docker.Runner = docker.run_command_streaming,
) -> InstallResult:
    """Initialize/adopt private data using a matched application; never sync source."""
    from .application import resolve_application_root

    source_root = resolve_application_root(options.source_root, preserve_path=True)
    install_root = Path(os.path.abspath(options.install_root.expanduser()))
    install_source_content_sha256(source_root)
    validate_install_destination(install_root)
    is_upgrade = has_prior_install_state(install_root)
    if options.dry_run:
        return InstallResult(install_root, is_upgrade, False, source_root=source_root)

    if options.refresh_physical_client_rosters or options.repair_ambiguous_client_permissions_as_skip:
        from .client_sessions import active_client_sessions, guard_client_session_upgrade
        for session in active_client_sessions(install_root):
            guard_client_session_upgrade(install_root, Path(session["engagement"]), source_root)

    caller_config_path = config_module.config_path()
    caller_config = config_module.load_config(caller_config_path)
    configured_oob_domain = os.environ.get("VIGIL_OOB_DOMAIN") or caller_config.get("oob.domain") or ""
    configured_oob_slot = _configured_oob_slot(caller_config) or install_root.name
    initialize_workspace(install_root, application_root=source_root)

    # Existing client paths may belong to a running release. Routine adoption
    # leaves them intact; explicit maintenance flags request generated repairs.
    client_roster_repair = None
    client_entrypoint_repair = None
    boundary = open_pinned_directory(install_root)
    assert boundary is not None
    with boundary:
        boundary.require_attached()
        if options.refresh_physical_client_rosters or options.repair_ambiguous_client_permissions_as_skip:
            from .client_sessions import client_session_bootstrap
            from .engagements import repair_engagement_client_entrypoints, repair_engagement_operator_pointers
            previous_application = os.environ.get("VIGIL_APPLICATION_DIR")
            os.environ["VIGIL_APPLICATION_DIR"] = str(source_root)
            try:
                with client_session_bootstrap(install_root, install_root):
                    # Another official start may have completed since preflight.
                    # Hold the same lock through every shared-path rewrite.
                    for session in active_client_sessions(install_root):
                        guard_client_session_upgrade(install_root, Path(session["engagement"]), source_root)
                    with boundary.working_directory() as phase_root:
                        client_roster_repair = repair_engagement_client_rosters(
                            phase_root, refresh_physical_client_rosters=options.refresh_physical_client_rosters,
                            rendered_install_root=install_root,
                        )
                        boundary.require_attached()
                        client_entrypoint_repair = repair_engagement_client_entrypoints(
                            phase_root, ambiguous_permissions_as_skip=options.repair_ambiguous_client_permissions_as_skip,
                            rendered_install_root=install_root,
                        )
                        boundary.require_attached()
                        pointers = repair_engagement_operator_pointers(phase_root, rendered_install_root=install_root)
                        if pointers:
                            print(_diagnostic(f"[vigil] operator pointer repair: {', '.join(pointers)}"), file=sys.stderr)
            finally:
                if previous_application is None:
                    os.environ.pop("VIGIL_APPLICATION_DIR", None)
                else:
                    os.environ["VIGIL_APPLICATION_DIR"] = previous_application
        boundary.require_attached()
        _report_client_repairs(client_roster_repair, client_entrypoint_repair)
        if configured_oob_domain:
            with boundary.working_directory() as phase_root:
                initialize_relay_route(
                    phase_root, slot_name=configured_oob_slot, base_domain=configured_oob_domain,
                    registry_path=caller_config_path.with_name(OOB_ALLOCATION_REGISTRY_FILENAME),
                    canonical_install_root=install_root, preserve_install_path=True,
                )
        else:
            print(_format_oob_route_notice(install_root, stream=sys.stderr), file=sys.stderr)
        boundary.require_attached()
        write_install_meta(install_root, source_root, install_fd=boundary.fd)
        boundary.require_attached()
        # Editable sources may change during setup; canonical workspace
        # provenance describes the application at the completed stamp boundary.
        initialize_workspace(install_root, application_root=source_root)
        boundary.require_attached()
        image_built = False
        if options.verify_docker_image:
            if options.force_image or not docker.image_exists("vigil:latest", runner=runner):
                previous_application = os.environ.get("VIGIL_APPLICATION_DIR")
                os.environ["VIGIL_APPLICATION_DIR"] = str(source_root)
                try:
                    build_runtime(install_root, runner=build_runner, daemon_runner=runner)
                    image_built = True
                finally:
                    if previous_application is None:
                        os.environ.pop("VIGIL_APPLICATION_DIR", None)
                    else:
                        os.environ["VIGIL_APPLICATION_DIR"] = previous_application
        boundary.require_attached()
    return InstallResult(
        install_root, is_upgrade, image_built,
        client_roster_repair=client_roster_repair,
        client_entrypoint_repair=client_entrypoint_repair,
        source_root=source_root,
    )
