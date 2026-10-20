"""Stable native project entries; immutable task contexts remain separate."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shlex
import shutil
import stat
import uuid

from .assessment_clients import CONTEXT_FILE, _json, _write_managed
from .install_fs import open_pinned_directory
from .paths import engagements_root

PROJECT_FILE = ".vigil-client-project.json"
SELECTION_FILE = ".vigil-current-context.json"


def project_directory(engagement: Path, client: str, mode: str) -> Path:
    return engagement / "clients" / client / mode


def prepare_project(snapshot: Path, binding: dict) -> Path:
    """Publish a new-task selection, never retarget an existing task binding."""
    project = project_directory(Path(binding["engagement_dir"]), binding["client"], binding["mode"])
    agent = Path(binding["agent_root"])
    descriptor = {key: binding[key] for key in (
        "client", "mode", "install_root", "engagement_dir", "engagement_key")}
    descriptor.update(schema_version=1, protocol=1, project=str(project),
                      engagements_root=str(engagements_root(Path(binding["install_root"])).resolve()))
    from .engagements import _SPECIALIST_STOP_SIGN
    files = {PROJECT_FILE: _json(descriptor),
        "AGENTS.md": (_SPECIALIST_STOP_SIGN + "\n" + (agent / "native-project-router.md").read_text()).encode(),
        "vigil-project.mjs": (agent / "scripts/native-client/project-binding.mjs").read_bytes(),
        "bootstrap.mjs": (agent / "scripts/native-client/bootstrap.mjs").read_bytes(),
        "bin/vigil": ("#!/bin/sh\nexec " + shlex.quote(shutil.which("node") or binding["tools"]["node"])
            + ' "${0%/*}/../bootstrap.mjs" "$@"\n').encode()}
    for name, data in files.items():
        _write_managed(project / name, data, executable=name == "bin/vigil")
    _write_managed(project / ".vigil-managed-files.json", _json({
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()}))
    if binding["client"] == "zcode":
        _prepare_dispatch_plugin(project, binding)
    selection = _json({"schema_version": 1, "binding_path": str(snapshot / CONTEXT_FILE),
        "binding_sha256": hashlib.sha256((snapshot / CONTEXT_FILE).read_bytes()).hexdigest()})
    pin = open_pinned_directory(project)
    assert pin is not None
    with pin:
        try:
            fd = os.open(SELECTION_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise SystemExit(f"Client project selection collision: {project / SELECTION_FILE}") from exc
        else:
            with os.fdopen(fd, "rb") as document:
                metadata = os.fstat(document.fileno())
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise SystemExit("Client project selection is not a managed regular file")
                # Validate the previous owner before replacing this one mutable file.
                from .client_checks import read_project_context
                try:
                    read_project_context(project)
                except (OSError, ValueError, TypeError, KeyError) as exc:
                    raise SystemExit(f"Cannot replace client project selection; preserve and inspect it: {exc}") from exc
        temporary = ".vigil-selection-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=pin.fd)
        try:
            with os.fdopen(fd, "wb") as document:
                os.fchmod(document.fileno(), 0o600)
                document.write(selection)
                document.flush()
                os.fsync(document.fileno())
            pin.require_attached()
            os.replace(temporary, SELECTION_FILE, src_dir_fd=pin.fd, dst_dir_fd=pin.fd)
            pin.require_attached()
        finally:
            try:
                os.unlink(temporary, dir_fd=pin.fd)
            except FileNotFoundError:
                pass
    return project


def _prepare_dispatch_plugin(project: Path, binding: dict) -> None:
    """Protocol-v1 dispatcher assets are immutable, including their public roster."""
    agent = Path(binding["agent_root"])
    root = Path(binding["install_root"]) / "client-plugins/dispatcher-v1/zcode"
    files = {
        "hooks/dispatch.mjs": (agent / "scripts/native-client/zcode-dispatch.mjs").read_bytes(),
        "hooks/project-binding.mjs": (agent / "scripts/native-client/project-binding.mjs").read_bytes(),
        "hooks/launch.sh": ("#!/bin/sh\nexec " + shlex.quote(shutil.which("node") or binding["tools"]["node"])
            + ' "${ZCODE_PLUGIN_ROOT}/hooks/dispatch.mjs"\n').encode(),
        "vigil-owner.json": _json({"schema_version": 1, "install_root": binding["install_root"],
            "engagements_root": str(engagements_root(Path(binding["install_root"])).resolve())}),
        ".zcode-plugin/plugin.json": _json({"name": "vigil-project-v1", "version": "1.0.0",
            "description": "Vigil web/code task-context dispatcher"}),
        "marketplace.json": _json({"name": "vigil-project-v1", "plugins": [
            {"name": "vigil-project-v1", "source": "./", "version": "1.0.0"}]}),
        "hooks/hooks.json": _json({"hooks": {event: [{**({"matcher": "startup|clear|compact"}
            if event == "SessionStart" else {}), "hooks": [{"type": "process", "command": "/bin/sh",
            "args": ["${ZCODE_PLUGIN_ROOT}/hooks/launch.sh"], "timeoutMs": 5000}]}]
            for event in ("SessionStart", "PostToolUse", "PostToolUseFailure")}}),
    }
    files.update(forwarding_assets(agent, "zcode"))
    for name, data in files.items():
        _write_managed(root / name, data)
    _write_managed(root / ".vigil-managed-files.json", _json({
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()}))
    pin = open_pinned_directory(project)
    assert pin is not None
    with pin:
        try:
            os.symlink(str(root), "plugin", dir_fd=pin.fd)
        except FileExistsError:
            if not (project / "plugin").is_symlink() or (project / "plugin").resolve() != root:
                raise SystemExit(f"Client project plugin collision: {project / 'plugin'}")
        pin.require_attached()


def forwarding_assets(agent: Path, client: str) -> dict[str, bytes]:
    files = {}
    for kind in ("commands", "agents"):
        for path in sorted((agent / f".{client}/assessment" / kind).glob("*.md")):
            name = path.stem
            header = path.read_text().split("---", 2)[1]
            description = next(line for line in header.splitlines() if line.startswith("description:"))
            frontmatter = f"---\nname: {name}\n{description}\n"
            if kind == "agents":
                frontmatter += ("injectAgentsMd: false\n" if client == "zcode" else
                    "mode: primary\n" if name == "operator" else "mode: subagent\n")
            target = f"{kind}/{name}.md"
            files[target] = (frontmatter + "---\n\n"
                "Use the immutable client context and absolute Vigil helper supplied by the native hook "
                "or this specialist's Runtime Identity. Read the matching "
                f"`agent_root/.{client}/assessment/{target}` from that context in full, then follow it. "
                "Resolve agent/... paths against that same agent_root. If the binding is missing, "
                "explain project setup and wait for the user before dependent work.\n\n"
                + ("Arguments: $ARGUMENTS\n" if kind == "commands" else "")).encode()
    return files
