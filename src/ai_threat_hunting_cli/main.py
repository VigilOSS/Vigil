from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import webbrowser
from dataclasses import asdict
from pathlib import Path

from .engagements import (
    CreateEngagementOptions,
    create_engagement,
    current_engagement_path,
    list_engagements,
    print_shell_cd_init,
    resolve_engagement_path,
    start_engagement,
)
from .install import InstallOptions, install_from_source
from .mitmproxy import MitmproxyOptions, start_proxy, stop_proxy
from .orchestrator import OrchestratorOptions, orchestrator_status, start_orchestrator, stop_orchestrator
from .paths import resolve_install_root, resolve_source_root
from .runtime import RuntimeOptions, build_runtime, runtime_status, start_runtime, stop_runtime


def main(argv: list[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    command_idx = _top_level_command_index(raw_argv)
    if command_idx is not None and raw_argv[command_idx] == "assess":
        _exec_assess_passthrough(raw_argv, command_idx)
        return
    parser = argparse.ArgumentParser(prog="aith", description="AI Threat Hunting operator CLI")
    parser.add_argument("--root", help="Install root (default: $AI_THREAT_HUNTING_INSTALL_DIR or ~/security-research)")
    parser.add_argument("--source", help="Source checkout root for install/upgrade")
    sub = parser.add_subparsers(dest="command", required=True)

    install_p = sub.add_parser("install")
    install_p.add_argument("install_dir", nargs="?")
    install_p.add_argument("--dry-run", action="store_true")
    install_p.add_argument("--force-image", action="store_true")
    install_p.add_argument("--skip-image-check", action="store_true")

    sub.add_parser("doctor")

    engagement_p = sub.add_parser("engagement")
    engagement_sub = engagement_p.add_subparsers(dest="engagement_command", required=True)
    engagement_sub.add_parser("list").add_argument("--json", action="store_true")
    create_p = engagement_sub.add_parser("create")
    create_p.add_argument("target_or_name", nargs="?")
    create_p.add_argument("--type", choices=["web", "code", "both"], default=None)
    create_p.add_argument("--name")
    create_p.add_argument("--target")
    create_p.add_argument("--hosts")
    create_p.add_argument("--auth-mode", choices=["none", "manual", "auth_json", "proxy_capture"], default=None)
    create_p.add_argument("--exploit-policy", choices=["pause", "full_send", "selected"], default=None)
    create_p.add_argument("--repo", action="append", default=[])
    create_p.add_argument("--skip-permissions", action="store_true")
    create_p.add_argument("--no-prompt", action="store_true")
    path_p = engagement_sub.add_parser("path")
    path_p.add_argument("key", nargs="?")
    path_p.add_argument("--select", action="store_true")
    path_p.add_argument("--latest", action="store_true")
    cd_p = engagement_sub.add_parser("cd-init")
    cd_p.add_argument("shell", choices=["zsh", "bash"], default="zsh", nargs="?")
    start_p = engagement_sub.add_parser("start")
    start_p.add_argument("key", nargs="?")
    start_p.add_argument("--select", action="store_true")
    start_p.add_argument("--latest", action="store_true")
    start_p.add_argument("--client", choices=["codex", "claude"], required=True)
    start_p.add_argument("client_args", nargs=argparse.REMAINDER)

    orch_p = sub.add_parser("orchestrator")
    orch_sub = orch_p.add_subparsers(dest="orchestrator_command", required=True)
    orch_start = orch_sub.add_parser("start")
    orch_start.add_argument("--build", action="store_true")
    orch_start.add_argument("--foreground", action="store_true")
    orch_sub.add_parser("stop")
    orch_sub.add_parser("restart")
    orch_sub.add_parser("status")
    orch_logs = orch_sub.add_parser("logs")
    orch_logs.add_argument("--follow", action="store_true")
    orch_logs.add_argument("--lines", default="80")
    orch_sub.add_parser("open")

    runtime_p = sub.add_parser("runtime")
    runtime_sub = runtime_p.add_subparsers(dest="runtime_command", required=True)
    runtime_build = runtime_sub.add_parser("build")
    runtime_build.add_argument("variant", choices=["full", "lightweight"], nargs="?", default="full")
    runtime_build.add_argument("--dev", action="store_true")
    runtime_start = runtime_sub.add_parser("start")
    runtime_start.add_argument("--recreate", action="store_true")
    runtime_sub.add_parser("stop")
    runtime_sub.add_parser("restart")
    runtime_sub.add_parser("status")
    runtime_logs = runtime_sub.add_parser("logs")
    runtime_logs.add_argument("--follow", action="store_true")
    runtime_sub.add_parser("shell")
    runtime_sub.add_parser("mcp-server")

    mitm_p = sub.add_parser("mitmproxy")
    mitm_sub = mitm_p.add_subparsers(dest="mitmproxy_command", required=True)
    mitm_start = mitm_sub.add_parser("start")
    mitm_start.add_argument("engagement", nargs="?")
    mitm_start.add_argument("--port", type=int, default=8080)
    mitm_sub.add_parser("stop")
    mitm_sub.add_parser("status")
    mitm_logs = mitm_sub.add_parser("logs")
    mitm_logs.add_argument("--follow", action="store_true")
    mitm_sub.add_parser("cert")

    mcp_p = sub.add_parser("mcp")
    mcp_sub = mcp_p.add_subparsers(dest="mcp_command", required=True)
    mcp_install = mcp_sub.add_parser("install")
    mcp_install.add_argument("client", choices=["codex", "claude", "both"])

    assess_p = sub.add_parser("assess", add_help=False)
    assess_p.add_argument("assess_args", nargs=argparse.REMAINDER)

    args = parser.parse_args(raw_argv)
    install_root = resolve_install_root(getattr(args, "install_dir", None) or args.root)

    if args.command == "install":
        source_root = resolve_source_root(args.source, install_root=install_root)
        path = install_from_source(
            InstallOptions(
                source_root=source_root,
                install_root=install_root,
                dry_run=args.dry_run,
                force_image=args.force_image,
                verify_docker_image=not args.skip_image_check,
            )
        )
        print(path)
    elif args.command == "doctor":
        _doctor()
    elif args.command == "engagement":
        _engagement(args, install_root)
    elif args.command == "orchestrator":
        _orchestrator(args, install_root)
    elif args.command == "runtime":
        _runtime(args, install_root)
    elif args.command == "mitmproxy":
        _mitmproxy(args, install_root)
    elif args.command == "mcp":
        _mcp(args)
    elif args.command == "assess":
        assess = install_root / "agent" / "scripts" / "assess.py"
        os.execv(str(assess), [str(assess), *args.assess_args])


def _top_level_command_index(raw_argv: list[str]) -> int | None:
    i = 0
    while i < len(raw_argv):
        token = raw_argv[i]
        if token in {"--root", "--source"}:
            i += 2
            continue
        if token.startswith("--root=") or token.startswith("--source="):
            i += 1
            continue
        return i
    return None


def _exec_assess_passthrough(raw_argv: list[str], idx: int) -> None:
    root_value: str | None = None
    source_value: str | None = None
    i = 0
    while i < idx:
        if raw_argv[i] == "--root" and i + 1 < idx:
            root_value = raw_argv[i + 1]
            i += 2
            continue
        if raw_argv[i] == "--source" and i + 1 < idx:
            source_value = raw_argv[i + 1]
            i += 2
            continue
        if raw_argv[i].startswith("--root="):
            root_value = raw_argv[i].split("=", 1)[1]
            i += 1
            continue
        if raw_argv[i].startswith("--source="):
            source_value = raw_argv[i].split("=", 1)[1]
            i += 1
            continue
        i += 1
    install_root = resolve_install_root(root_value)
    assess = install_root / "agent" / "scripts" / "assess.py"
    if not assess.exists():
        source_root = resolve_source_root(source_value, install_root=install_root)
        assess = source_root / "agent" / "scripts" / "assess.py"
    os.execv(str(assess), [str(assess), *raw_argv[idx + 1 :]])


def _engagement(args: argparse.Namespace, install_root: Path) -> None:
    command = args.engagement_command
    if command == "list":
        rows = list_engagements(install_root)
        if args.json:
            print(json.dumps([asdict(row) | {"path": str(row.path)} for row in rows], indent=2))
        else:
            for row in rows:
                print(f"{row.key}\t{row.status}\t{row.current_phase}\t{row.target}\t{row.path}")
    elif command == "create":
        engagement_type = args.type
        positional = args.target_or_name
        if engagement_type is None:
            if not args.no_prompt and sys.stdin.isatty() and not positional and not args.hosts and not args.repo:
                engagement_type = _prompt_choice("Engagement type", "web", ["web", "code", "both"])
            else:
                engagement_type = "web" if (args.hosts or (positional and "." in positional)) else "code"
        target = args.target
        name = args.name
        if positional:
            if engagement_type == "code" and not name:
                name = positional
            elif not target:
                target = positional
        hosts = [item.strip() for item in (args.hosts or "").split(",") if item.strip()]
        if not args.no_prompt and sys.stdin.isatty():
            if engagement_type in {"web", "both"} and not target and not hosts:
                target = input("Target URL or host: ").strip()
            if engagement_type in {"code", "both"} and not name:
                name = input("Engagement name: ").strip()
            if engagement_type in {"web", "both"} and args.auth_mode is None:
                args.auth_mode = _prompt_choice("Auth mode", "none", ["none", "auth_json", "manual", "proxy_capture"])
            if args.exploit_policy is None:
                args.exploit_policy = _prompt_choice("Exploit policy", "pause", ["pause", "full_send", "selected"])
        auth_mode = args.auth_mode or "none"
        exploit_policy = args.exploit_policy or "pause"
        created = create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type=engagement_type,
                target=target,
                name=name,
                hosts=hosts,
                auth_mode=auth_mode,
                exploit_policy=exploit_policy,
                repos=args.repo,
                skip_permissions=args.skip_permissions,
            )
        )
        print(created.path)
    elif command == "path":
        print(resolve_engagement_path(install_root, args.key, select=args.select, latest=args.latest))
    elif command == "cd-init":
        print(print_shell_cd_init(args.shell), end="")
    elif command == "start":
        path = resolve_engagement_path(install_root, args.key, select=args.select, latest=args.latest)
        start_engagement(install_root, path, args.client, args.client_args)


def _orchestrator(args: argparse.Namespace, install_root: Path) -> None:
    if args.orchestrator_command == "start":
        start_orchestrator(OrchestratorOptions(install_root=install_root, build=args.build, foreground=args.foreground))
    elif args.orchestrator_command == "stop":
        stop_orchestrator(install_root)
    elif args.orchestrator_command == "restart":
        stop_orchestrator(install_root)
        start_orchestrator(OrchestratorOptions(install_root=install_root))
    elif args.orchestrator_command == "status":
        print(orchestrator_status(install_root))
    elif args.orchestrator_command == "logs":
        log_file = install_root / ".runtime-data" / "logs" / "orchestrator.log"
        argv = ["tail", "-n", str(args.lines)]
        if args.follow:
            argv.append("-f")
        argv.append(str(log_file))
        subprocess.run(argv, check=False)
    elif args.orchestrator_command == "open":
        webbrowser.open("http://127.0.0.1:18000")


def _runtime(args: argparse.Namespace, install_root: Path) -> None:
    if args.runtime_command == "build":
        build_runtime(install_root, variant=args.variant, dev=args.dev)
    elif args.runtime_command == "start":
        start_runtime(RuntimeOptions(install_root=install_root, recreate=args.recreate))
    elif args.runtime_command == "stop":
        stop_runtime()
    elif args.runtime_command == "restart":
        stop_runtime()
        start_runtime(RuntimeOptions(install_root=install_root, recreate=True))
    elif args.runtime_command == "status":
        print(runtime_status())
    elif args.runtime_command == "logs":
        argv = ["docker", "logs"]
        if args.follow:
            argv.append("-f")
        argv.append("security-research")
        subprocess.run(argv, check=False)
    elif args.runtime_command == "shell":
        os.execvp("docker", ["docker", "exec", "-it", "security-research", "bash"])
    elif args.runtime_command == "mcp-server":
        os.execvp("docker", ["docker", "exec", "-i", "security-research", "mcp-server"])


def _mitmproxy(args: argparse.Namespace, install_root: Path) -> None:
    if args.mitmproxy_command == "start":
        engagement = (
            Path(args.engagement).expanduser()
            if args.engagement
            else current_engagement_path() or resolve_engagement_path(install_root, latest=True)
        )
        start_proxy(MitmproxyOptions(install_root=install_root, engagement_dir=engagement, port=args.port))
    elif args.mitmproxy_command == "stop":
        stop_proxy()
    elif args.mitmproxy_command == "status":
        subprocess.run(["docker", "ps", "--filter", "name=security-research-proxy"], check=False)
    elif args.mitmproxy_command == "logs":
        argv = ["docker", "logs"]
        if args.follow:
            argv.append("-f")
        argv.append("security-research-proxy")
        subprocess.run(argv, check=False)
    elif args.mitmproxy_command == "cert":
        print("docker cp security-research-proxy:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem")
        print("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem")


def _mcp(args: argparse.Namespace) -> None:
    if args.client in {"claude", "both"}:
        _replace_mcp_server(
            "claude",
            ["claude", "mcp", "remove", "-s", "user", "kali"],
            ["claude", "mcp", "add", "-s", "user", "kali", "--", "docker", "exec", "-i", "security-research", "mcp-server"],
        )
    if args.client in {"codex", "both"}:
        _replace_mcp_server(
            "codex",
            ["codex", "mcp", "remove", "kali"],
            ["codex", "mcp", "add", "kali", "--", "docker", "exec", "-i", "security-research", "mcp-server"],
        )


def _replace_mcp_server(client: str, remove_argv: list[str], add_argv: list[str]) -> None:
    try:
        subprocess.run(remove_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        result = subprocess.run(add_argv, check=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"{client} CLI not found on PATH") from exc
    if result.returncode != 0:
        raise SystemExit(f"Failed to install Kali MCP server for {client}")
    print(f"installed {client} MCP server: kali")


def _doctor() -> None:
    checks = [
        ("uv", ["uv", "--version"]),
        ("docker", ["docker", "--version"]),
        ("npm", ["npm", "--version"]),
        ("codex", ["codex", "--version"]),
        ("claude", ["claude", "--version"]),
        ("fzf", ["fzf", "--version"]),
    ]
    for name, argv in checks:
        result = subprocess.run(argv, text=True, capture_output=True, check=False)
        status = "OK" if result.returncode == 0 else "MISSING"
        print(f"{status}\t{name}")


def _prompt_choice(label: str, default: str, choices: list[str]) -> str:
    print(label, file=sys.stderr)
    for idx, choice in enumerate(choices, start=1):
        suffix = " [default]" if choice == default else ""
        print(f"  {idx}. {choice}{suffix}", file=sys.stderr)
    raw = input("> ").strip()
    if not raw:
        return default
    if raw.isdigit() and 1 <= int(raw) <= len(choices):
        return choices[int(raw) - 1]
    if raw in choices:
        return raw
    raise SystemExit(f"Invalid {label.lower()}: {raw}")


if __name__ == "__main__":
    main()
