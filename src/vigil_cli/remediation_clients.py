"""Native repository entrypoints; conversation binding remains Claude-owned."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import stat
import subprocess
import sys

from .paths import agent_root

# Locally verified version/help; configuration mappings follow native documentation.
OPENCODE_MINIMUM = (1, 18, 10)
# Released source establishes the launch interface; native GUI E2E remains required.
ZCODE_MINIMUM = (3, 14, 3)


def _opencode_capabilities() -> None:
    try:
        version = subprocess.run(["opencode", "--version"], capture_output=True, text=True, check=True)
        version_text = "\n".join(part for part in (version.stdout, version.stderr) if part)
        match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", version_text)
        if not match or not (OPENCODE_MINIMUM <= tuple(map(int, match.groups())) < (2, 0, 0)):
            raise SystemExit("Remediation requires stable OpenCode 1.18.10 or newer within 1.x")
        help_result = subprocess.run(["opencode", "--help"], capture_output=True, text=True, check=True)
        help_text = "\n".join(part for part in (help_result.stdout, help_result.stderr) if part)
        if not re.search(r"--prompt(?:\s|$)", help_text):
            raise SystemExit("OpenCode lacks the required native --prompt TUI option; upgrade OpenCode")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("OpenCode CLI is required; install a supported stable 1.x release") from exc


def _zcode_application() -> tuple[Path, str]:
    if sys.platform != "darwin":
        raise SystemExit("ZCode desktop remediation launch currently requires macOS")
    for application in (Path("/Applications/ZCode.app"), Path.home() / "Applications/ZCode.app"):
        info = application / "Contents/Info.plist"
        if not info.is_file():
            continue
        try:
            metadata = plistlib.loads(info.read_bytes())
            if not isinstance(metadata, dict):
                raise ValueError("Expected a property list dictionary")
            version = metadata.get("CFBundleShortVersionString")
        except (OSError, plistlib.InvalidFileException, ValueError) as exc:
            raise SystemExit("Cannot read ZCode application metadata; reinstall ZCode") from exc
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version):
            raise SystemExit("ZCode application metadata has no recognizable release version")
        if not (ZCODE_MINIMUM <= tuple(map(int, version.split("."))) < (4, 0, 0)):
            raise SystemExit("This remediation integration candidate requires ZCode 3.14.3 or newer within 3.x; native GUI verification is still required")
        return application, version
    raise SystemExit("Install ZCode.app in /Applications or your Applications folder before starting")


def _command_template(source: Path) -> str:
    try:
        content = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit("Missing generated vigil-remediate command; reinstall Vigil before starting") from exc
    if content.startswith("---\n"):
        sections = content.split("\n---\n", 1)
        if len(sections) != 2:
            raise SystemExit("Invalid generated vigil-remediate command; reinstall Vigil")
        content = sections[1].lstrip("\n")
    if not content.strip():
        raise SystemExit("Empty generated vigil-remediate command; reinstall Vigil")
    return content


def _opencode_configuration(source: Path) -> str:
    try:
        configuration = json.loads(os.environ.get("OPENCODE_CONFIG_CONTENT", "{}"))
    except json.JSONDecodeError as exc:
        raise SystemExit("OPENCODE_CONFIG_CONTENT must contain valid JSON for a Vigil launch") from exc
    if not isinstance(configuration, dict) or not isinstance(configuration.get("command", {}), dict):
        raise SystemExit("OPENCODE_CONFIG_CONTENT must be a JSON object with an object command field")
    commands = configuration.setdefault("command", {})
    if "vigil-remediate" in commands:
        raise SystemExit("OPENCODE_CONFIG_CONTENT already defines vigil-remediate; resolve the command collision before starting")
    commands["vigil-remediate"] = {"template": _command_template(source), "description": "Defensive remediation"}
    return json.dumps(configuration)


def _prepare_zcode_plugin(agent: Path, engagement: Path, repository: Path, project: dict, key: str,
                          *, install_root: Path) -> Path:
    from .application import session_cli_directory
    from .install_fs import atomic_write_bytes, open_pinned_directory

    # This explicit inventory never imports unrelated agents or provider settings.
    source = agent / ".zcode"
    names = (".zcode-plugin/plugin.json", "marketplace.json", "commands/vigil-remediate.md",
             "hooks/hooks.json", "hooks/remediation-context.mjs")
    try:
        files = {name: (source / name).read_bytes() for name in names}
    except OSError as exc:
        raise SystemExit("Missing generated ZCode remediation plugin; reinstall Vigil") from exc
    helper = session_cli_directory(agent.parent)
    context = {"install_root": str(install_root), "engagement_dir": str(engagement), "engagement_key": key,
               "repository": str(repository), "profile": str(project.get("_profile_path") or engagement / "PROJECT.md"),
               "agent_root": str(agent), "helper_path": str(helper) if helper is not None else None}
    files["vigil-context.json"] = (json.dumps(context, indent=2) + "\n").encode()
    # Content identity also separates different profile/context selections.
    digest = hashlib.sha256(str(agent).encode())
    for name, data in sorted(files.items()):
        digest.update(name.encode())
        digest.update(data)
    identity = digest.hexdigest()[:16]
    name = f"vigil-remediation-{identity}"
    try:
        manifest = json.loads(files[".zcode-plugin/plugin.json"])
        marketplace = json.loads(files["marketplace.json"])
        manifest["name"] = name
        marketplace["name"] = name
        marketplace["plugins"] = [{"name": name, "source": "./", "version": manifest.get("version", "0.0.0")}]
    except (ValueError, TypeError) as exc:
        raise SystemExit("Invalid generated ZCode plugin metadata; reinstall Vigil") from exc
    files[".zcode-plugin/plugin.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    files["marketplace.json"] = (json.dumps(marketplace, indent=2) + "\n").encode()
    root = engagement / "remediation/client-context" / identity / "zcode"
    try:
        root_pin = open_pinned_directory(root, create=True)
        assert root_pin is not None
        with root_pin:
            lock_flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            # Concurrent lock creation can transiently report ENOENT.
            # Open an existing lock first; exclusive creation never replaces one.
            for attempt in range(8):
                root_pin.require_attached()
                try:
                    lock = os.open(".prepare.lock", lock_flags, dir_fd=root_pin.fd)
                    break
                except FileNotFoundError:
                    try:
                        lock = os.open(".prepare.lock", lock_flags | os.O_CREAT | os.O_EXCL,
                                       0o600, dir_fd=root_pin.fd)
                        break
                    except (FileExistsError, FileNotFoundError):
                        if attempt == 7:
                            raise
            try:
                if not stat.S_ISREG(os.fstat(lock).st_mode):
                    raise SystemExit(f"ZCode plugin collision: invalid preparation lock in {root}")
                fcntl.flock(lock, fcntl.LOCK_EX)
                root_pin.require_attached()
                for relative, data in files.items():
                    destination = root / relative
                    pinned = open_pinned_directory(destination.parent, create=True)
                    assert pinned is not None
                    with pinned:
                        try:
                            descriptor = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                                 dir_fd=pinned.fd)
                        except FileNotFoundError:
                            atomic_write_bytes(pinned.fd, destination.name, data, mode=0o600, display=destination)
                        else:
                            try:
                                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                                    raise SystemExit(f"ZCode plugin collision: nonregular file {destination}")
                                with os.fdopen(descriptor, "rb", closefd=False) as existing:
                                    if existing.read() != data:
                                        raise SystemExit(f"ZCode plugin collision; preserve and review this file: {destination}")
                            finally:
                                os.close(descriptor)
                        pinned.require_attached()
                root_pin.require_attached()
            finally:
                os.close(lock)
    except OSError as exc:
        raise SystemExit(f"Cannot safely prepare ZCode plugin: {exc}") from exc
    return root


def start_repository_client(args: argparse.Namespace, install_root: Path, engagement: Path, project: dict) -> int:
    from .remediation_sessions import _environment, _start_prompt

    client = args.client
    if getattr(args, "session_id", None):
        raise SystemExit(f"--session-id recovery is supported only for Claude; resume {client} in its native client")
    if project.get("remediation", {}).get("hook_policy", "inherit") == "disabled":
        raise SystemExit(f"{client} cannot guarantee session-scoped hook_policy=disabled; use Claude or explicitly select inherit in PROJECT.md")
    repository = Path(project["repository"]).resolve()
    if not repository.is_dir():
        raise SystemExit("The selected profile requires an existing repository directory")
    agent = agent_root(install_root)
    source = agent / f".{client}/commands/vigil-remediate.md"
    _command_template(source)
    opening = _start_prompt(project, repository, engagement, args.engagement_key, native_binding=False)
    from .application import session_cli_directory

    helpers = session_cli_directory(agent.parent)
    executable = str(helpers / "vigil") if helpers is not None else "vigil"
    prefix = shlex.join([executable, "--root", str(install_root), "remediation", "-k", args.engagement_key])
    opening += ("\n\nThis client has no Vigil native case-conversation binding or exact join adapter. "
                "Retain and resume this conversation in the native client. Do not use Claude session or join "
                f"commands to bind it. Read the remediation role context returned by `{prefix} route --client {client}`; "
                "edit and run verification only inside a prepared, registered case workspace.")
    environment = _environment(engagement, args.engagement_key, install_root)
    environment["VIGIL_CLIENT_NAME"] = client
    checks = project.get("remediation", {}).get("check_commands", [])
    if client == "opencode":
        _opencode_capabilities()
        environment["OPENCODE_CONFIG_CONTENT"] = _opencode_configuration(source)
        argv = ["opencode", "--prompt", opening]
    elif client == "zcode":
        application, version = _zcode_application()
        try:
            subprocess.run(["node", "--version"], capture_output=True, text=True, check=True)
        except (OSError, subprocess.CalledProcessError) as exc:
            raise SystemExit("Node.js is required by the ZCode remediation context hook; install Node and ensure ZCode hooks can find it") from exc
        plugin = _prepare_zcode_plugin(agent, engagement, repository, project, args.engagement_key,
                                       install_root=install_root)
        plugin_name = json.loads((plugin / ".zcode-plugin/plugin.json").read_text())["name"]
        print(f"ZCode {version}: add local marketplace {plugin / 'marketplace.json'}, install and enable "
              f"{plugin_name}, and review its enabled plugin hooks in ZCode. Disable other Vigil remediation "
              "plugins for this repository so only the selected context restores. Select your Z.AI GLM Coding Plan "
              "and model in the client. Create a new task in this repository and paste this opening prompt:\n\n"
              f"{opening}\n\nWorkspace opening must be confirmed in the GUI; no native session identity or "
              "session-end receipt is recorded by this launcher.", flush=True)
        # Send the repository as a macOS open-document request. This works for an
        # already-running app and does not depend on an undocumented Electron flag.
        argv = ["open", "-a", str(application), str(repository)]
    else:
        raise SystemExit(f"Unsupported remediation client: {client}")
    print(f"Starting {client} remediation context\nRepository: {repository}\nProfile: "
          f"{project.get('_profile_path') or engagement / 'PROJECT.md'}\nProfile checks: "
          + (", ".join(check["name"] for check in checks) if checks else "none configured; agree checks before editing")
          + "\nRepository and personal hooks retain their configured policy. Native approvals and selected model remain in effect.",
          flush=True)
    try:
        return subprocess.run(argv, cwd=repository, env=environment).returncode
    except OSError as exc:
        raise SystemExit(f"Cannot launch {client}: {exc}") from exc
