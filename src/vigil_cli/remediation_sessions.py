"""Repository-context remediation conversations using the client's native host."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid
from urllib.parse import unquote, urlsplit

from .remediation_vcs import adapter
from .paths import agent_root as application_agent_root

_TICKET = re.compile(r"[A-Za-z][A-Za-z0-9_]*-\d+")


def register_session_parsers(commands: argparse._SubParsersAction) -> None:
    start = commands.add_parser("start", help="Open repository Claude context for /vigil-remediate")
    start.add_argument("--client", choices=("claude",), default="claude")
    start.add_argument("--session-id", help="Recover and attach an existing Vigil launch without starting another")
    route = commands.add_parser("route", help="Resolve input references and choose remediation role context")
    route.add_argument("references", nargs="+")
    session = commands.add_parser("session", help="Start a full case developer session or bind this conversation")
    session.add_argument("case_id")
    session.add_argument("--bind", action="store_true", help="Bind the existing conversation without launching another")
    session.add_argument("--session-id", help="Native conversation UUID required with --bind")
    session.add_argument("--replace-stopped", action="store_true",
                         help="With --bind, take over a case whose recorded conversation has stopped")
    join = commands.add_parser("join", help="Attach to the exact recorded case developer conversation")
    join.add_argument("case_id")


def normalize_references(references: list[str]) -> list[dict]:
    """Group ticket keys and browse URLs; retrieval still establishes identity."""
    if not references:
        raise ValueError("Supply at least one ticket ID or URL")
    grouped: dict[str, dict] = {}
    for raw in references:
        value = raw.strip()
        if not value or any(ord(char) < 32 for char in value):
            raise ValueError("References must be nonempty ticket IDs or HTTP(S) URLs")
        if _TICKET.fullmatch(value):
            identity = value.upper()
        elif re.fullmatch(r"(?:[A-Za-z0-9][A-Za-z0-9_.:-]*|#\d+)", value):
            identity = value
        else:
            try:
                parsed = urlsplit(value)
            except ValueError as exc:
                raise ValueError(f"Invalid ticket reference: {value}") from exc
            if parsed.scheme not in ("https", "http") or not parsed.hostname:
                raise ValueError(f"Expected a ticket ID or HTTP(S) URL: {value}")
            match = re.fullmatch(r"/browse/([A-Za-z][A-Za-z0-9_]*-\d+)/?", unquote(parsed.path))
            identity = match[1].upper() if match else value
        item = grouped.setdefault(identity, {"identity_hint": identity, "references": [], "resolved": False})
        if value not in item["references"]:
            item["references"].append(value)
    return list(grouped.values())


def route_context(install_root: Path, engagement: Path, project: dict, references: list[str]) -> dict:
    requested = normalize_references(references)
    role = "developer" if len(requested) == 1 else "coordinator"
    pending = engagement / "remediation" / "pending"
    digest = hashlib.sha256(json.dumps(requested, sort_keys=True).encode()).hexdigest()
    path = pending / f"{digest}.json"
    context = {
        "inputs": requested,
        "role": role,
        "instructions": str(application_agent_root(install_root) / f"remediation-{role}.md"),
        "essentials": str(application_agent_root(install_root) / "operator-core-remediation.md"),
        "profile": str(project.get("_profile_path") or engagement / "PROJECT.md"),
        "repository": project["repository"],
        "source_reader": project.get("remediation", {}).get("source_reader", ""),
        "pending_input": str(path),
    }
    _write_json(path, context)
    return context


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _claude_capabilities() -> None:
    try:
        result = subprocess.run(["claude", "--version"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Claude Code is required for remediation sessions") from exc
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", result.stdout)
    if not match or tuple(map(int, match.groups())) < (2, 1, 257):
        raise SystemExit("Remediation command discovery requires Claude Code 2.1.257 or newer")
    try:
        help_result = subprocess.run(["claude", "--help"], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit("Cannot verify Claude's native background session capabilities") from exc
    if not (re.search(r"--bg(?:[\s,]|$)", help_result.stdout)
            and re.search(r"^\s+agents(?:\s|$)", help_result.stdout, re.MULTILINE)
            and re.search(r"^\s+attach(?:\s|$)", help_result.stdout, re.MULTILINE)):
        raise SystemExit("Remediation requires Claude's native background sessions and attach command; upgrade Claude Code")


def _inventory() -> list[dict]:
    try:
        result = subprocess.run(["claude", "agents", "--json", "--all"], capture_output=True, text=True, check=True)
        rows = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise SystemExit("Cannot read Claude's native session inventory; no replacement session was launched") from exc
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SystemExit("Claude returned an invalid native session inventory")
    return rows


def _uuid(value: str | None) -> str:
    try:
        if not isinstance(value, str):
            raise ValueError
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise SystemExit("A valid native conversation UUID is required") from None


def _command_overlay(install_root: Path, engagement: Path) -> Path:
    agent = application_agent_root(install_root)
    release = hashlib.sha256(str(agent.parent).encode()).hexdigest()[:16]
    root = engagement / "remediation" / "client-context" / release
    source = agent / ".claude" / "commands" / "vigil-remediate.md"
    if not source.is_file():
        raise SystemExit("Missing generated vigil-remediate command; reinstall Vigil before starting")
    destination = root / ".claude" / "commands" / source.name
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() and destination.resolve() == source.resolve():
        return root
    if destination.exists() or destination.is_symlink():
        raise SystemExit(f"Command overlay already contains an unrelated file: {destination}")
    try:
        destination.symlink_to(source.resolve())
    except FileExistsError:
        if not destination.is_symlink() or destination.resolve() != source.resolve():
            raise SystemExit(f"Command overlay changed during creation: {destination}") from None
    return root


def _settings(project: dict, engagement: Path | None = None, key: str | None = None,
              install_root: Path | None = None) -> dict:
    settings: dict = {"worktree": {"bgIsolation": "none"}}
    if project.get("remediation", {}).get("hook_policy", "inherit") == "disabled":
        settings["disableAllHooks"] = True
    if engagement is not None and key is not None:
        # Native background hosts retain session settings across process restarts.
        environment = _environment(engagement, key, install_root)
        settings["env"] = {name: environment[name] for name in (
            "ENGAGEMENT_DIR", "VIGIL_SESSION_ENGAGEMENT_DIR", "ENGAGEMENT_KEY", "VIGIL_CLIENT_NAME",
            "VIGIL_APPLICATION_DIR", "VIGIL_AGENT_ROOT", "PATH",
        )}
        if install_root is not None:
            settings["env"]["VIGIL_INSTALL_DIR"] = str(install_root)
    return settings


def _notice(project: dict) -> str:
    if _settings(project).get("disableAllHooks"):
        return ("This profile disables personal, repository, and ordinary plugin Claude hooks and any custom "
                "status line for this session. Organization-managed hooks remain enabled if configured. "
                "Git hooks are unaffected. "
                "Run required checks against case source during verification and before publishing.")
    return "Repository and personal hooks retain their configured policy for this session."


def _start_prompt(project: dict, repository: Path, engagement: Path, key: str) -> str:
    profile = project.get("_profile_path") or engagement / "PROJECT.md"
    return (f"Start a Vigil defensive remediation session for engagement {key}.\n\n"
            f"Repository: {repository}\nProject profile: {profile}\n\n"
            "Read the selected project profile and applicable repository instructions. Raise only "
            "instruction conflicts that need an owner decision. Wait for the owner's "
            "ticket IDs, URLs, or report before beginning investigation. Use /vigil-remediate to route "
            "supplied references and load the appropriate role.\n\n"
            "For one case, retain this conversation as its developer. For several cases, coordinate "
            "separate developer conversations through Vigil.\n\n"
            "Present the diagnosis and proposed fix plan for owner approval before editing.")


def _environment(engagement: Path, key: str, install_root: Path | None = None) -> dict[str, str]:
    from .application import session_cli_directory
    from .paths import resolve_install_root

    root = install_root or resolve_install_root()
    agent = application_agent_root(root)
    environment = dict(os.environ)
    environment.update(ENGAGEMENT_DIR=str(engagement), VIGIL_SESSION_ENGAGEMENT_DIR=str(engagement),
                       ENGAGEMENT_KEY=key, VIGIL_CLIENT_NAME="claude", VIGIL_INSTALL_DIR=str(root),
                       VIGIL_APPLICATION_DIR=str(agent.parent), VIGIL_AGENT_ROOT=str(agent))
    helpers = session_cli_directory(agent.parent)
    if helpers is not None:
        environment["PATH"] = f"{helpers}{os.pathsep}{environment.get('PATH', os.defpath)}"
    environment.pop("VIGIL_OPERATOR_MODE", None)
    # Native background workers are independent full conversations, not nested
    # interactive clients in the invoking conversation.
    environment.pop("CLAUDECODE", None)
    return environment


def _launch_arguments(install_root: Path, engagement: Path, project: dict, session_id: str, key: str) -> list[str]:
    overlay = _command_overlay(install_root, engagement)
    return ["claude", "--session-id", session_id, "--add-dir", str(overlay),
            "--add-dir", str(engagement / "remediation"), "--settings", json.dumps(_settings(project, engagement, key, install_root))]


def _case_directory(engagement: Path, case_id: str) -> Path:
    if not str(case_id).isdigit() or int(case_id) <= 0:
        raise SystemExit("Case ID must be a positive integer")
    return engagement / "remediation" / "cases" / str(case_id)


@contextmanager
def _session_lock(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".session.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _workspace(install_root: Path, project: dict, case: dict, *, allow_branch_drift: bool = False) -> Path:
    supplied = case.get("worktree_path")
    if not supplied:
        raise SystemExit("Prepare and register the case workspace before starting its developer session")
    workspace = Path(supplied).resolve()
    repository = Path(project["repository"]).resolve()
    vcs = adapter(install_root)
    if workspace == repository or not vcs.registered(repository, workspace):
        raise SystemExit("Case workspace is not registered to the selected repository")
    branch = str(case.get("worktree_branch") or "")
    if not branch:
        raise SystemExit("Case workspace has no recorded branch")
    if not vcs.branch_matches(workspace, branch):
        message = f"Case workspace branch differs from the recorded branch {branch}"
        if not allow_branch_drift:
            raise SystemExit(message)
        print(f"Warning: {message}; joining the recorded conversation for diagnosis, not verification.", flush=True)
    return workspace


def _matching_session(binding: dict, rows: list[dict]) -> dict | None:
    matches = [row for row in rows if row.get("sessionId") == binding["session_id"]
               or (binding.get("job_id") and row.get("id") == binding["job_id"])]
    if len(matches) > 1:
        raise SystemExit("Native conversation identity is ambiguous; no session was joined or replaced")
    if not matches:
        return None
    row = matches[0]
    if (row.get("sessionId") and row["sessionId"] != binding["session_id"]
            or Path(row.get("cwd", "")).resolve() != Path(binding["session_cwd"]).resolve()):
        raise SystemExit("Native session identity or repository directory differs from its case binding")
    return row


def _launch_background(command_line: list[str], opening: str, binding: dict,
                       path: Path, repository: Path, environment: dict) -> dict:
    # Record identity before dispatch: an inventory failure must not create a
    # second worker on the next attempt.
    _write_json(path, binding)
    result = subprocess.run([*command_line, "--bg", "--name", f"vigil-{binding['session_id']}", opening],
                            cwd=repository, env=environment, capture_output=True, text=True)
    if result.returncode:
        raise SystemExit(f"Claude session launch failed; binding retained for recovery:\n{result.stderr or result.stdout}")
    for attempt in range(20):
        row = _launched_session(binding, _inventory())
        if row and row.get("id"):
            _record_launched_session(binding, row, path)
            return row
        if attempt < 19:
            time.sleep(0.1)
    raise SystemExit("Claude started but has not reported its conversation identity; binding retained, do not relaunch")


def _launched_session(binding: dict, rows: list[dict]) -> dict | None:
    if binding.get("job_id"):
        return _matching_session(binding, rows)
    # The native background host may assign its own UUID despite --session-id.
    # The unique launch name correlates that host with our pre-dispatch receipt.
    name = f"vigil-{binding.get('launch_id', binding['session_id'])}"
    matches = [row for row in rows if row.get("name") == name
               or row.get("sessionId") == binding["session_id"]]
    if len(matches) > 1:
        raise SystemExit("Native conversation identity is ambiguous; no session was joined or replaced")
    if not matches:
        return None
    row = matches[0]
    _uuid(row.get("sessionId"))
    if not row.get("cwd") or Path(row["cwd"]).resolve() != Path(binding["session_cwd"]).resolve():
        raise SystemExit("Native session repository directory differs from its launch binding")
    return row


def _record_launched_session(binding: dict, row: dict, path: Path) -> None:
    binding.setdefault("launch_id", binding["session_id"])
    binding["session_id"] = _uuid(row.get("sessionId"))
    binding["job_id"] = row["id"]
    _write_json(path, binding)
    # Case binding looks up the launch settings by the actual conversation UUID.
    sessions = path.parent if path.parent.name == "sessions" else path.parent.parent.parent / "sessions"
    _write_json(sessions / f"{binding['session_id']}.json", binding)


def _binding_document(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        binding = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("Cannot read case session binding; refusing a replacement conversation") from exc
    if not isinstance(binding, dict) or not isinstance(binding.get("settings", {}), dict):
        raise SystemExit("Invalid native session binding; refusing a replacement conversation")
    return binding


def _read_binding(path: Path, case_id: str, key: str, workspace: Path, repository: Path) -> dict | None:
    binding = _binding_document(path)
    if binding is None:
        return None
    if (binding.get("case_id") != str(case_id)
            or binding.get("engagement_key") != key
            or binding.get("workspace") != str(workspace)
            or binding.get("session_cwd") != str(repository)):
        raise SystemExit("Case session binding differs from the selected case workspace or repository")
    _uuid(binding.get("session_id"))
    return binding


def run_session_command(args: argparse.Namespace, install_root: Path, engagement: Path,
                        project: dict, *, case_reader=None) -> int:
    command = args.remediation_command
    if command == "route":
        try:
            print(json.dumps(route_context(install_root, engagement, project, args.references), indent=2))
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        return 0
    _claude_capabilities()
    repository = Path(project["repository"]).resolve()
    if not repository.is_dir():
        raise SystemExit("The selected profile requires an existing repository directory")
    key = args.engagement_key
    environment = _environment(engagement, key, install_root)
    notice = _notice(project)
    if command == "session":
        print(notice, flush=True)
    if command == "start":
        if getattr(args, "session_id", None):
            session_id = _uuid(args.session_id)
            path = engagement / "remediation" / "sessions" / f"{session_id}.json"
            with _session_lock(path.parent):
                entry_binding = _binding_document(path)
                if (entry_binding is None or entry_binding.get("engagement_key") != key
                        or entry_binding.get("session_cwd") != str(repository)
                        or session_id not in (entry_binding.get("session_id"), entry_binding.get("launch_id"))):
                    raise SystemExit("Recorded launch differs from the selected engagement or repository")
                entry_row = _launched_session(entry_binding, _inventory())
                if entry_row is None or not entry_row.get("id"):
                    raise SystemExit("Recorded native launch is absent; refusing to create a replacement")
                _record_launched_session(entry_binding, entry_row, path)
                recorded_policy = "disabled" if entry_binding.get("settings", {}).get("disableAllHooks") else "inherit"
                print(_notice({"remediation": {"hook_policy": recorded_policy}}), flush=True)
            return subprocess.run(["claude", "attach", entry_row["id"]], cwd=repository, env=environment).returncode
        session_id = str(uuid.uuid4())
        command_line = _launch_arguments(install_root, engagement, project, session_id, key)
        profile_path = project.get("_profile_path") or engagement / "PROJECT.md"
        print(f"Starting Claude remediation session\nRepository: {repository}\nProfile: {profile_path}", flush=True)
        checks = project.get("remediation", {}).get("check_commands", [])
        print("Profile checks: " + (", ".join(check["name"] for check in checks)
              if checks else "none configured; agree required checks before editing"), flush=True)
        opening = _start_prompt(project, repository, engagement, key)
        entry_binding = {"engagement_key": key, "session_cwd": str(repository),
                         "session_id": session_id, "job_id": None, "settings": _settings(project, engagement, key, install_root)}
        path = engagement / "remediation" / "sessions" / f"{session_id}.json"
        entry_row = _launch_background(command_line, opening, entry_binding, path, repository, environment)
        print("Attaching automatically…", flush=True)
        return subprocess.run(["claude", "attach", entry_row["id"]], cwd=repository, env=environment).returncode
    if case_reader is None:
        raise SystemExit("Case session commands require the authoritative case reader")
    case = case_reader(args.case_id)
    if str(case.get("id")) != str(args.case_id):
        raise SystemExit("Authoritative case identity differs from the requested case")
    workspace = _workspace(install_root, project, case, allow_branch_drift=command == "join")
    directory = _case_directory(engagement, args.case_id)
    path = directory / "session.json"
    with _session_lock(directory):
        binding = _read_binding(path, args.case_id, key, workspace, repository)
        rows = _inventory()
        if command == "join":
            if binding is None:
                raise SystemExit("This case has no recorded developer conversation")
            recorded_policy = "disabled" if binding.get("settings", {}).get("disableAllHooks") else "inherit"
            print(_notice({"remediation": {"hook_policy": recorded_policy}}), flush=True)
            row = _launched_session(binding, rows)
            if row is None:
                raise SystemExit("Recorded native conversation is absent; refusing to create a replacement")
            if row.get("id"):
                _record_launched_session(binding, row, path)
                command_line = ["claude", "attach", row["id"]]
            elif row.get("pid"):
                raise SystemExit("This conversation is already interactive; return to its terminal or background it before joining")
            else:
                raise SystemExit("Use Claude's native session recovery for this stopped interactive conversation")
        elif getattr(args, "bind", False):
            session_id = _uuid(args.session_id)
            launch_path = engagement / "remediation" / "sessions" / f"{session_id}.json"
            launch = _binding_document(launch_path)
            if _settings(project).get("disableAllHooks") and (
                not isinstance(launch, dict) or launch.get("engagement_key") != key
                or launch.get("session_cwd") != str(repository)
                or launch.get("session_id") != session_id
                or not launch.get("settings", {}).get("disableAllHooks")
            ):
                raise SystemExit("This profile disables hooks; enter through vigil remediation start before binding a case")
            proposed = {"case_id": str(args.case_id), "engagement_key": key, "workspace": str(workspace),
                        "session_cwd": str(repository), "session_id": session_id, "job_id": None,
                        "settings": launch.get("settings") if launch else {},
                        "workspace_branch": case["worktree_branch"]}
            if binding and binding["session_id"] != session_id:
                previous = _launched_session(binding, rows)
                stopped = previous is None or previous.get("state") == "stopped"
                if not getattr(args, "replace_stopped", False):
                    if stopped:
                        raise SystemExit("Case belongs to a developer conversation that has stopped; "
                                         "rerun with --replace-stopped to bind this one instead")
                    raise SystemExit("Case already belongs to another developer conversation; use join")
                if not stopped:
                    raise SystemExit("The recorded developer conversation is still running; use join")
                proposed["replaced_session_id"] = binding["session_id"]
            row = _matching_session(proposed, rows)
            if row is None:
                raise SystemExit("The supplied conversation is not in Claude's native repository session inventory")
            proposed["job_id"] = row.get("id")
            _write_json(path, proposed)
            print(json.dumps(proposed, indent=2))
            return 0
        else:
            if binding:
                row = _launched_session(binding, rows)
                if row:
                    if row.get("id"):
                        _record_launched_session(binding, row, path)
                    print(json.dumps(binding, indent=2))
                    return 0
                raise SystemExit("Case already has a recorded conversation; recover it instead of launching a duplicate")
            handoff = directory / "handoff.md"
            if not handoff.is_file():
                raise SystemExit("Render the authoritative case handoff before launching its developer")
            session_id = str(uuid.uuid4())
            binding = {"case_id": str(args.case_id), "engagement_key": key, "workspace": str(workspace),
                       "session_cwd": str(repository), "session_id": session_id, "job_id": None,
                       "settings": _settings(project, engagement, key, install_root), "workspace_branch": case["worktree_branch"]}
            command_line = _launch_arguments(install_root, engagement, project, session_id, key)
            profile_path = project.get("_profile_path") or engagement / "PROJECT.md"
            opening = (f"Case: {args.case_id}. Code workspace: {workspace}. Handoff: {handoff}. "
                       f"Profile: {profile_path}. Developer instructions: "
                       f"{application_agent_root(install_root) / 'remediation-developer.md'}. Essentials: "
                       f"{application_agent_root(install_root) / 'operator-core-remediation.md'}. {notice}\n"
                       "Read the handoff, profile, and repository instructions. Validate the report and "
                       "present your proposed fix before editing. Keep all case code edits in its registered "
                       "workspace; this repository directory supplies native MCPs, skills, and settings.")
            _launch_background(command_line, opening, binding, path, repository, environment)
            print(json.dumps(binding, indent=2))
            return 0
    return subprocess.run(command_line, cwd=repository, env=environment).returncode
