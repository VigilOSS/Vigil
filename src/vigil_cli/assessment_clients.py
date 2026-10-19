"""Native client workspace preparation; GUI opening is not session ownership.

Only official web/code starts write here. Diagnostic readers never call this
module's preparation path. Release-bound workspaces keep modes independent and
do not rewrite an engagement or a client's global configuration.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import uuid

from . import term
from .application import _read_file, application_provenance, session_cli_directory
from .install_fs import open_pinned_directory
from .paths import agent_root, resolve_orchestrator_base_url

CONTEXT_FILE = ".vigil-client-context.json"


def _json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _write_managed(path: Path, data: bytes, *, executable: bool = False) -> None:
    pin = open_pinned_directory(path.parent, create=True)
    assert pin is not None
    mode = 0o755 if executable else 0o600
    with pin:
        def compare_existing() -> bool:
            try:
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pin.fd)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise SystemExit(f"Client workspace collision: {path}") from exc
            try:
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != mode:
                    raise SystemExit(f"Client workspace mode/collision: {path}")
                with os.fdopen(descriptor, "rb") as handle:
                    descriptor = -1
                    existing = handle.read()
                if existing != data:
                    raise SystemExit(f"Client workspace collision; preserve and inspect {path}")
                pin.require_attached()
                return True
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        if compare_existing():
            return
        temporary = f".vigil-create-{uuid.uuid4().hex}"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             mode, dir_fd=pin.fd)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as document:
                descriptor = -1
                document.write(data)
                document.flush()
                os.fsync(document.fileno())
            pin.require_attached()
            try:
                # Publishing a complete file with link is atomic and never
                # replaces a concurrently created operator file/directory.
                os.link(temporary, path.name, src_dir_fd=pin.fd, dst_dir_fd=pin.fd, follow_symlinks=False)
            except FileExistsError:
                if not compare_existing():
                    raise SystemExit(f"Client workspace changed during preparation: {path}")
            pin.require_attached()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.unlink(temporary, dir_fd=pin.fd)


def _source_files(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        raise SystemExit(f"Missing native client assets: {root}; reinstall the matched Vigil release")
    files = {}
    pin = open_pinned_directory(root)
    assert pin is not None
    with pin:
        for source in sorted(root.rglob("*")):
            if source.is_symlink():
                raise SystemExit(f"Native client asset must not be a symlink: {source}")
            if source.is_file():
                name = source.relative_to(root).as_posix()
                files[name] = _read_file(pin.fd, name)
        pin.require_attached()
    return files


def _tools(client: str) -> dict[str, str]:
    tools = {}
    for name in ("uv", "bash", "jq", "node"):
        executable = shutil.which(name)
        if executable is None:
            raise SystemExit(f"{client} context requires {name}; install it before preparing the workspace")
        tools[name] = str(Path(executable).resolve())
    return tools


def prepare_workspace(install_root: Path, engagement: Path, client: str, mode: str,
                      *, native_version: str | None = None) -> tuple[Path, dict]:
    """Prepare immutable native assets; never alter source or global client settings."""
    if client not in {"opencode", "zcode"} or mode not in {"web", "code"}:
        raise SystemExit("Native assessment workspaces support web/code with OpenCode or ZCode only")
    agent = agent_root(install_root)
    assets = _source_files(agent / f".{client}/assessment")
    if not any(name.startswith("commands/") for name in assets) or not any(name.startswith("agents/") for name in assets):
        raise SystemExit("Native assessment commands/roles are unavailable; reinstall the matched release")
    tools = _tools(client)
    provenance = application_provenance(agent.parent)
    release_hash = hashlib.sha256(_json({"application": provenance, "tools": tools,
        "assets": {name: hashlib.sha256(data).hexdigest() for name, data in assets.items()}})).hexdigest()
    binding = {"schema_version": 1, "client": client, "mode": mode,
        "install_root": str(install_root.resolve()), "engagement_dir": str(engagement.resolve()),
        "engagement_key": engagement.name, "agent_root": str(agent.resolve()),
        "application": provenance, "release_id": release_hash, "tools": tools,
        "native_version": native_version,
        "backend_url": resolve_orchestrator_base_url(install_root, engagement)}
    digest = hashlib.sha256(_json(binding)).hexdigest()
    workspace = engagement / "client-context" / digest[:24] / client
    binding["workspace"] = str(workspace.resolve())
    binding["vigil_cli"] = str(workspace.resolve() / "bin/vigil")
    helper_directory = session_cli_directory(agent.parent)
    if helper_directory is None:
        raise SystemExit("Matched Vigil helper is unavailable; reinstall the application before starting")
    # Pinned helpers may themselves invoke uv by name. Supply resolved executable
    # directories explicitly, even when Finder's PATH contains only system paths.
    helper_path = ":".join(dict.fromkeys([*(str(Path(path).parent) for path in tools.values()),
        "/usr/bin", "/bin", "/usr/sbin", "/sbin"]))
    exports = {"PATH": helper_path, "VIGIL_APPLICATION_DIR": str(agent.parent),
        "VIGIL_AGENT_ROOT": str(agent), "VIGIL_INSTALL_DIR": str(install_root.resolve()),
        "ENGAGEMENT_DIR": str(engagement.resolve()), "VIGIL_SESSION_ENGAGEMENT_DIR": str(engagement.resolve()),
        "ENGAGEMENT_KEY": engagement.name, "VIGIL_OPERATOR_MODE": mode,
        "VIGIL_CLIENT_NAME": client, "VIGIL_REQUESTED_CLIENT": client,
        "VIGIL_CLIENT_CONTEXT": str(workspace.resolve() / CONTEXT_FILE),
        "ORCHESTRATOR_BASE_URL": str(binding["backend_url"])}
    helper = "#!/bin/sh\n" + "\n".join(f"export {key}={shlex.quote(value)}" for key, value in exports.items())
    helper += "\nexec " + shlex.quote(str(helper_directory / "vigil")) + ' "$@"\n'
    workspace_files = {"bin/vigil": helper.encode(), CONTEXT_FILE: _json(binding)}
    prompt = agent / ("operator-core-code.md" if mode == "code" else "AGENTS.md")
    from .engagements import _SPECIALIST_STOP_SIGN
    helper_command = shlex.quote(str(binding["vigil_cli"]))
    setup = (
        "## First-task setup\n\n"
        "You are the Vigil operator for this project. Help a newcomer finish setup before starting the selected workflow.\n"
        "This exact folder is the ZCode project; the canonical engagement and audited source remain separate.\n"
        f"1. Run `{helper_command} engagement client-check --client zcode --mode {mode} --json`. Explain failed prerequisites and distinguish installed assets, historical hook observations, and unverified native behavior.\n"
        f"2. If the plugin has not been installed/enabled, ask the user to open Plugin Marketplace → Add → Add plugin marketplace and add `{workspace.resolve() / 'plugin/marketplace.json'}`. Under Personal, review, install and enable the matching Vigil plugin. Native approval belongs to the user.\n"
        "3. Ask the user to select their entitled Z.AI Coding Plan model in ZCode, without sharing credentials. A selected model is not proof of successful authentication.\n"
        "4. After plugin enablement, ask the user to create a NEW task in this same project and use the printed opening prompt or the matching Vigil resume command. An existing task may have captured an earlier hook configuration.\n"
        "5. Verify startup hook delivery and backend hydration separately. If unverified, explain what remains to test; neither opening a project nor finding files proves hooks or compaction work.\n"
        f"For detailed setup and recovery, read `{agent.parent / 'docs/zcode-setup.md'}` explicitly; ZCode does not expand instruction-file imports.\n\n"
    ) if client == "zcode" else ""
    router = (
        _SPECIALIST_STOP_SIGN + "\n"
        f"# Vigil {mode} session\n\n"
        "## Session identity and commands\n\n"
        f"This workspace binds only engagement {json.dumps(engagement.name)} in `{mode}` mode.\n"
        f"Canonical engagement: `{engagement.resolve()}`.\n"
        f"Use `{binding['vigil_cli']}` instead of bare `vigil` in every command.\n"
        f"Client context: `{workspace.resolve() / CONTEXT_FILE}`. Read it for literal artifact paths.\n"
        f"The binding's `mode` is `{mode}`. Interpret VIGIL_OPERATOR_MODE in shared guidance as that bound value, not an assumed GUI environment variable.\n"
        "Environment-variable path notation in shared guidance denotes these literal paths, not ambient GUI variables.\n\n"
        + setup
        + "## Operator workflow and recovery\n\n"
        f"Run `{helper_command} engagement mode` and verify its mode is `{mode}` before reading only `{prompt}` in full.\n"
        f"Read `{engagement.resolve() / 'ENGAGEMENT.md'}` when present. Scope, approvals and backend records remain canonical; the native conversation is not shared durable state.\n"
        f"Before dependent work run `{helper_command} engagement client-check {shlex.quote(engagement.name)} --client {client} --mode {mode} --json`.\n"
        "If setup is incomplete, explain the failed check and the next setup action before dependent work. Instructions do not replace native approvals or executable authorization checks.\n"
        "After any context boundary use the selected workflow's resume hydration before acting; report unavailable backend state rather than inferring it from a summary.\n\n"
        "## Specialist boundaries\n\n"
        "Every specialist assignment must include this context file path, the absolute Vigil helper, canonical engagement/artifact paths, and the normal Runtime Identity.\n"
        "A specialist reads its role and mandatory constraints, never the operator core.\n"
    )
    workspace_files["AGENTS.md"] = router.encode()
    # OpenCode may inherit this bounded router: its canonical stop-sign excludes
    # operator bootstrap for specialists. ZCode roles opt out of AGENTS injection.
    # Both role wrappers require the explicit Runtime Identity context path.
    if client == "opencode":
        for name, data in assets.items():
            workspace_files[f".opencode/{name}"] = data
        plugin = agent / ".opencode/plugin/assessment-hooks.js"
        workspace_files[".opencode/plugins/vigil-assessment.js"] = plugin.read_bytes()
        workspace_files[".opencode/opencode.json"] = _json({"$schema": "https://opencode.ai/config.json",
            "compaction": {"auto": True}, "instructions": [str(workspace.resolve() / "AGENTS.md")]})
    else:
        plugin_root = install_root / "client-plugins" / release_hash[:24] / "zcode"
        plugin_files = {}
        for name, data in assets.items():
            if name == "hooks/hooks.json":
                registration = json.loads(data)
                for groups in registration.get("hooks", {}).values():
                    for group in groups:
                        for executor in group.get("hooks", []):
                            if executor.get("command") == "node":
                                executor["command"] = tools["node"]
                data = _json(registration)
            if name in {".zcode-plugin/plugin.json", "marketplace.json"}:
                manifest = json.loads(data)
                manifest["name"] = f"vigil-assessment-{release_hash[:16]}"
                if name == "marketplace.json":
                    manifest["plugins"] = [{"name": manifest["name"], "source": "./", "version": "1.0.0"}]
                data = _json(manifest)
            _write_managed(plugin_root / name, data)
            plugin_files[name] = hashlib.sha256(data).hexdigest()
        release_file = _json({"release_id": release_hash})
        _write_managed(plugin_root / "vigil-release.json", release_file)
        plugin_files["vigil-release.json"] = hashlib.sha256(release_file).hexdigest()
        _write_managed(plugin_root / ".vigil-managed-files.json", _json(plugin_files))
        # This is a managed pointer to an immutable private plugin, never a write
        # through an operator-provided directory symlink.
        pin = open_pinned_directory(workspace, create=True)
        assert pin is not None
        with pin:
            try:
                os.symlink(str(plugin_root.resolve()), "plugin", dir_fd=pin.fd)
            except FileExistsError:
                if not (workspace / "plugin").is_symlink() or (workspace / "plugin").resolve() != plugin_root.resolve():
                    raise SystemExit(f"Client workspace collision: {workspace / 'plugin'}")
            pin.require_attached()
    for name, data in workspace_files.items():
        _write_managed(workspace / name, data, executable=name == "bin/vigil")
    pin = open_pinned_directory(workspace)
    assert pin is not None
    with pin:
        # Canonical role Load First paths use agent/... from the client cwd.
        # This bounded, known pointer is not a writable managed directory.
        for name, destination in (("agent", agent), ("scope.json", engagement / "scope.json")):
            try:
                os.symlink(str(destination.resolve()), name, dir_fd=pin.fd)
            except FileExistsError:
                if not (workspace / name).is_symlink() or (workspace / name).resolve() != destination.resolve():
                    raise SystemExit(f"Client workspace collision: {workspace / name}")
        pin.require_attached()
    _write_managed(workspace / ".vigil-managed-files.json", _json({
        name: hashlib.sha256(data).hexdigest() for name, data in workspace_files.items()}))
    return workspace, binding


def start_client(install_root: Path, engagement: Path, client: str, mode: str,
                 extra_args: list[str], *, no_autoprompt: bool = False) -> None:
    """Start one selected mode; do not infer GUI native-session ownership."""
    if mode not in {"web", "code"}:
        raise SystemExit("ZCode assessment launch supports web/code only")
    if client == "zcode" and any(argument.startswith("-") for argument in extra_args):
        raise SystemExit("ZCode desktop does not support forwarded CLI flags; select model/approvals in the app")
    forwarded = []
    focus = None
    if client == "opencode":
        from .engagements import client_launch_argv
        tail = iter(client_launch_argv(client, extra_args))
        for argument in tail:
            value = None
            if argument == "--prompt":
                value = next(tail, None)
                if value is None:
                    raise SystemExit("OpenCode --prompt requires a value")
            elif argument.startswith("--prompt="):
                value = argument.split("=", 1)[1]
            else:
                forwarded.append(argument)
            if value is not None:
                if focus is not None:
                    raise SystemExit("Supply one OpenCode operator prompt, not repeated --prompt values")
                focus = value
    application = None
    native_version = None
    executable = None
    if client == "zcode":
        from .remediation_clients import _zcode_application
        application, native_version = _zcode_application()
    else:
        executable = shutil.which("opencode")
        if executable is None:
            raise SystemExit("OpenCode CLI not found on PATH")
        try:
            probe = subprocess.run([executable, "--version"], capture_output=True, text=True,
                                   check=False, timeout=10)
            if probe.returncode == 0:
                native_version = probe.stdout.strip() or probe.stderr.strip()
        except (OSError, subprocess.TimeoutExpired):
            pass  # Diagnostic state remains unverified; no native version invented.
    from .client_sessions import client_session_bootstrap, record_client_session
    with client_session_bootstrap(install_root, engagement):
        workspace, binding = prepare_workspace(install_root, engagement, client, mode, native_version=native_version)
        if client == "opencode":
            record_client_session(install_root, engagement, client, mode)
    from .engagements import set_active_engagement
    try:
        set_active_engagement(install_root, engagement)
    except (SystemExit, OSError):
        pass  # Same best-effort terminal selection as the other official starts.
    opening = "Read this workspace AGENTS.md, verify the selected mode, and perform its startup/resume procedure."
    if client == "zcode":
        helper = shlex.quote(str(binding["vigil_cli"]))
        opening = (
            f"This is a ZCode {mode} assessment. The project folder must be:\n{json.dumps(str(workspace))}\n\n"
            "Run pwd before doing any work. If it is not that folder, stop and ask me to open the correct project in ZCode. "
            "Do not launch another coding client or run engagement start from this task.\n\n"
            f"Read {json.dumps(str(workspace / 'AGENTS.md'))} in full.\n"
            f"Use {helper} for every Vigil command, not bare vigil.\n"
            f"Verify the bound mode with: {helper} engagement mode\n"
            "Then follow the selected workflow's startup/resume procedure."
        )
    if mode == "code":
        from .engagements import SOURCE_TRUST_CONFIRMATION, engagement_source_state
        source = engagement_source_state(engagement)
        opening += (f"\n\nOriginal source: {json.dumps(source['path'])}\n"
            f"Before the first ingest or a refresh, ask:\n{json.dumps(SOURCE_TRUST_CONFIRMATION)}\n"
            "Wait for my confirmation. If sealed source already exists, resume it without duplicate ingestion.")
    if client == "zcode" and extra_args:
        opening += "\n\nOperator focus: " + " ".join(extra_args)
    if client != "zcode" or not term.is_terminal(sys.stdout):
        print(f"workspace: {workspace}\nengagement: {engagement.name}\nclient: {client}\nmode: {mode}", flush=True)
    if client == "zcode":
        if term.is_terminal(sys.stdout):
            print(term.heading("Continue in ZCode", stream=sys.stdout))
            print(term.row("info", "Engagement", engagement.name, stream=sys.stdout))
            print(term.row("info", "Workflow", f"{mode.capitalize()} assessment", stream=sys.stdout))
        print("\n" + term.heading("Project folder", stream=sys.stdout))
        print(term.wrap("In Projects, choose Add project (+) > Open folder. In the macOS folder chooser, "
                        "press Cmd+Shift+G, paste this path, press Return, then Open:", stream=sys.stdout))
        print(f"  {workspace}")
        print(term.wrap("Vigil already created this folder. Use it as the project, not the engagement root or source folder.", stream=sys.stdout))
        print("\n" + term.heading("Plugin setup (first time for this project)", stream=sys.stdout))
        print(term.wrap("1. Open Plugin Marketplace > Add > Add plugin marketplace. In the field "
                        "'GitHub repo, git URL, file, or directory', paste this marketplace file:", stream=sys.stdout))
        print(f"  {workspace / 'plugin/marketplace.json'}")
        plugin_name = json.loads((workspace / "plugin/.zcode-plugin/plugin.json").read_text())["name"]
        print(term.wrap("2. Under Personal, find this plugin. Review its hooks, then install and enable it:", stream=sys.stdout))
        print(f"  {plugin_name}")
        print(term.wrap("3. Select Z.AI Coding Plan and your model in ZCode.", stream=sys.stdout))
        print("\n" + term.wrap("Opening a folder does not verify plugin hooks. Finish setup before asking the agent to work.", stream=sys.stdout))
        if no_autoprompt:
            print("\nStart a new task in this project and follow AGENTS.md.\n", flush=True)
        else:
            print("\n" + term.heading("Paste into a new task", stream=sys.stdout) + "\n")
            print(opening + "\n", flush=True)
        result = subprocess.run(["open", "-a", str(application), str(workspace)], check=False)
        if result.returncode:
            raise SystemExit(f"ZCode workspace opening failed ({result.returncode}); open {workspace} manually")
        from .client_sessions import record_client_launch
        record_client_launch(install_root, engagement, client, mode, event="workspace_opened")
        return
    environment = dict(os.environ)
    environment.update({"VIGIL_CLIENT_CONTEXT": str(workspace / CONTEXT_FILE),
        "OPENCODE_DISABLE_PROJECT_CONFIG": "1", "OPENCODE_CONFIG_DIR": str(workspace / ".opencode"),
        "VIGIL_AGENT_ROOT": binding["agent_root"], "ENGAGEMENT_DIR": binding["engagement_dir"],
        "VIGIL_SESSION_ENGAGEMENT_DIR": binding["engagement_dir"], "VIGIL_OPERATOR_MODE": mode,
        "VIGIL_INSTALL_DIR": binding["install_root"], "VIGIL_CLIENT_NAME": client,
        "VIGIL_REQUESTED_CLIENT": client, "ORCHESTRATOR_BASE_URL": binding["backend_url"]})
    assert executable is not None
    argv = [executable, "--agent", "operator", *forwarded]
    if not no_autoprompt or focus is not None:
        prompt = "" if no_autoprompt else opening
        if focus is not None:
            prompt += ("\n\nOperator focus: " if prompt else "") + focus
        argv.extend(["--prompt", prompt])
    os.chdir(workspace)
    from .client_sessions import record_client_launch
    record_client_launch(install_root, engagement, client, mode)
    os.execve(executable, argv, environment)
