from __future__ import annotations

import argparse
import ipaddress
import json
import os
import shlex
import subprocess
import sys
import tarfile
import webbrowser
from dataclasses import asdict
from pathlib import Path

from . import auth as auth_module
from . import backup as backup_module
from . import blue as blue_module
from . import config as config_module
from .docker import run_command as docker_run_command
from .engagements import (
    CreateEngagementOptions,
    create_engagement,
    current_engagement_path,
    export_pdf,
    list_engagements,
    print_shell_cd_init,
    resolve_engagement_path,
    start_engagement,
)
from .install import InstallOptions, InstallResult, install_from_source
from .mitmproxy import (
    MitmproxyOptions,
    build_image as build_proxy_image,
    proxy_status_payload,
    read_proxy_routes,
    request_proxy_reload,
    start_proxy,
    stop_proxy,
)
from .oob import (
    DEFAULT_FRP_HOST,
    DEFAULT_FRP_PORT,
    DEFAULT_OOB_DOMAIN,
    OOB_ROOT,
    OobOptions,
    callback_urls,
    list_oob_clients,
    match_interactions_to_nonces,
    mint_nonce,
    oob_status,
    parse_interactsh_log,
    read_client_log,
    sanitize_name,
    start_oob,
    start_oob_client,
    stop_oob,
    stop_oob_client,
    test_oob,
)
from .orchestrator import (
    OrchestratorOptions,
    build_frontend,
    orchestrator_status,
    orchestrator_status_payload,
    start_orchestrator,
    stop_orchestrator,
)
from .paths import resolve_install_root, resolve_source_root
from .runtime import RuntimeOptions, aith_runtime_resources, build_runtime, runtime_status, start_runtime, stop_runtime
from .status import collect_doctor_checks, collect_status, print_doctor, print_status
from .up import UpOptions, run_up


def _print_post_install(result: InstallResult) -> None:
    root = result.install_root
    print()
    if result.is_upgrade:
        print("Upgrade complete. Services using the previous install should be restarted:")
        print(f"  - Kali runtime:   aith runtime restart")
        print(f"  - Orchestrator:   aith orchestrator restart")
        if result.image_built:
            print(f"  - Docker image was rebuilt — running containers use the old image until restarted")
        else:
            print(f"  - Docker image:   run  aith runtime build  if agent scripts or Dockerfile changed")
    else:
        print("Install complete. Next steps:")
        print(f"  1. Configure tokens and API keys in {root / '.env'}")
        print(f"  2. Optional OOB: aith config set oob.frp_token <token>")
        print(f"  3. aith up                      # build/start runtime, orchestrator, and OOB")
        print(f"  4. aith engagement create <target>  # create your first engagement")
        print(f"  5. aith assess kali --help      # discover target-facing CLI verbs")
    print()


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

    install_p = sub.add_parser("install", help="Install or update the working root from source")
    install_p.add_argument("install_dir", nargs="?")
    install_p.add_argument("--dry-run", action="store_true")
    install_p.add_argument("--force-image", action="store_true")
    install_p.add_argument("--skip-image-check", action="store_true")
    update_p = sub.add_parser("update", help="Alias for install")
    update_p.add_argument("install_dir", nargs="?")
    update_p.add_argument("--dry-run", action="store_true")
    update_p.add_argument("--force-image", action="store_true")
    update_p.add_argument("--skip-image-check", action="store_true")

    sub.add_parser("doctor")
    status_p = sub.add_parser("status")
    status_p.add_argument("--json", action="store_true")
    up_p = sub.add_parser("up", help="Build stale images and start the local runtime stack")
    # Legacy shims — the proxy now serves every active engagement, so the
    # selector is a no-op. Kept for back-compat with operator scripts that
    # still pass them.
    up_p.add_argument("--engagement", help=argparse.SUPPRESS)
    up_p.add_argument("--select", action="store_true", help=argparse.SUPPRESS)
    up_p.add_argument("--no-build", action="store_true")
    up_p.add_argument("--runtime-restart-timeout", type=int, default=10)
    up_p.add_argument("--yes-restart-runtime", action="store_true")
    up_p.add_argument("--no-restart-runtime", action="store_true")
    logs_p = sub.add_parser("logs")
    logs_p.add_argument("target", choices=["orchestrator", "runtime", "mitmproxy", "oob", "all"])
    logs_p.add_argument("--follow", action="store_true")
    logs_p.add_argument("--lines", default="80")

    config_p = sub.add_parser("config")
    config_sub = config_p.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("path")
    config_sub.add_parser("list")
    config_get = config_sub.add_parser("get")
    config_get.add_argument("key")
    config_set = config_sub.add_parser("set")
    config_set.add_argument("key")
    config_set.add_argument("value")
    config_unset = config_sub.add_parser("unset")
    config_unset.add_argument("key")
    config_sub.add_parser("edit")

    engagement_p = sub.add_parser("engagement")
    engagement_sub = engagement_p.add_subparsers(dest="engagement_command", required=True)
    engagement_sub.add_parser("list").add_argument("--json", action="store_true")
    create_p = engagement_sub.add_parser("create")
    create_p.add_argument("target_or_name", nargs="?")
    create_p.add_argument("--type", choices=["web", "code", "both", "android"], default=None)
    create_p.add_argument("--name")
    create_p.add_argument("--target")
    create_p.add_argument("--hosts")
    create_p.add_argument("--repo", action="append", default=[])
    create_p.add_argument("--apk", action="append", default=[], help="Android APK/AAB/XAPK artifact path")
    create_p.add_argument("--package-name", help="Android package name, for example com.example.app")
    create_p.add_argument("--dynamic-mode", choices=["static_only", "device", "emulator"], default="static_only")
    create_p.add_argument("--skip-permissions", action="store_true")
    create_p.add_argument("--no-prompt", action="store_true")
    path_p = engagement_sub.add_parser("path")
    path_p.add_argument("key", nargs="?")
    path_p.add_argument("--select", action="store_true")
    cd_p = engagement_sub.add_parser("cd-init")
    cd_p.add_argument("shell", choices=["zsh", "bash"], default="zsh", nargs="?")
    start_p = engagement_sub.add_parser("start")
    start_p.add_argument("key", nargs="?")
    start_p.add_argument("--select", action="store_true")
    start_p.add_argument("--client", choices=["codex", "claude"], required=True)
    start_p.add_argument("client_args", nargs="*")
    open_p = engagement_sub.add_parser("open")
    open_p.add_argument("key", nargs="?")
    open_p.add_argument("--select", action="store_true")
    archive_p = engagement_sub.add_parser("archive")
    archive_p.add_argument("key", nargs="?")
    archive_p.add_argument("--select", action="store_true")
    export_p = engagement_sub.add_parser("export")
    export_p.add_argument("key", nargs="?")
    export_p.add_argument("--select", action="store_true")
    export_p.add_argument("--output")
    export_pdf_p = engagement_sub.add_parser("export-pdf", help="Export report.md as a PDF using pandoc + Chrome headless")
    export_pdf_p.add_argument("key", nargs="?")
    export_pdf_p.add_argument("--select", action="store_true")
    export_pdf_p.add_argument("--output", help="Output PDF path (default: <engagement>/report.pdf)")
    migrate_p = engagement_sub.add_parser(
        "migrate-scope",
        help=(
            "One-shot migration: set code_phase=ingest on legacy "
            "engagement_type=both engagements created before dual-track "
            "phase tracking landed. Idempotent."
        ),
    )
    migrate_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what would change without writing scope.json.",
    )
    migrate_p.add_argument(
        "--json",
        action="store_true",
        help="Emit migrated entries as JSON.",
    )

    blue_module.register_blue_parser(sub)

    orch_p = sub.add_parser("orchestrator")
    orch_sub = orch_p.add_subparsers(dest="orchestrator_command", required=True)
    orch_start = orch_sub.add_parser("start")
    orch_start.add_argument("--build", action="store_true")
    orch_start.add_argument("--foreground", action="store_true")
    orch_sub.add_parser("stop")
    orch_sub.add_parser("restart")
    orch_status_p = orch_sub.add_parser("status")
    orch_status_p.add_argument("--json", action="store_true")
    orch_sub.add_parser("open")
    orch_build = orch_sub.add_parser(
        "build",
        help="Build the install-side frontend dist (recovery for direct-uvicorn launches that bypass aith up).",
    )
    orch_build.add_argument("--force", action="store_true", help="Rebuild even if dist looks up-to-date.")

    runtime_p = sub.add_parser("runtime")
    runtime_sub = runtime_p.add_subparsers(dest="runtime_command", required=True)
    runtime_build = runtime_sub.add_parser("build")
    runtime_build.add_argument("variant", choices=["full", "lightweight"], nargs="?", default="full")
    runtime_build.add_argument("--dev", action="store_true")
    runtime_start = runtime_sub.add_parser("start")
    runtime_start.add_argument("--recreate", action="store_true")
    runtime_start.add_argument(
        "--allow-oversubscribe",
        action="store_true",
        help="Start even when the configured memory tier exceeds a safe fraction of the "
             "shared Docker VM (bypasses the oversubscription refusal).",
    )
    runtime_sub.add_parser("stop")
    runtime_sub.add_parser("restart")
    runtime_sub.add_parser("status")
    runtime_sub.add_parser("shell")
    runtime_shell_exec = runtime_sub.add_parser("shell-exec", help="Run a non-interactive shell command inside the Kali runtime")
    runtime_shell_exec.add_argument("shell_command", nargs=argparse.REMAINDER, metavar="COMMAND")
    runtime_resources_p = runtime_sub.add_parser("resources", help="Print configured runtime resource tier and live cgroup state")
    runtime_resources_p.add_argument("--json", action="store_true")

    mitm_p = sub.add_parser(
        "mitmproxy",
        help="Manage the engagement-wide intercepting proxy (Docker container security-research-proxy on :8080).",
    )
    mitm_sub = mitm_p.add_subparsers(dest="mitmproxy_command", required=True)
    mitm_start = mitm_sub.add_parser(
        "start",
        help="Start (or restart) the proxy container; builds the image first if missing.",
    )
    # Positional kept as a deprecated shim — one or two release cycles of grace
    # so existing operator habits don't error out.
    mitm_start.add_argument("engagement", nargs="?", help=argparse.SUPPRESS)
    mitm_start.add_argument("--select", action="store_true", help=argparse.SUPPRESS)
    mitm_start.add_argument("--port", type=int, default=8080, help="Host port to bind (default 8080).")
    mitm_start.add_argument(
        "--build",
        action="store_true",
        help="Force-rebuild the proxy image before starting (use after Dockerfile or addon changes).",
    )
    mitm_sub.add_parser("stop", help="Stop and remove the proxy container.")
    mitm_status = mitm_sub.add_parser(
        "status",
        help="Show container state, port reachability, cert volume, loaded routes, and last log lines on crash.",
    )
    mitm_status.add_argument("--json", action="store_true")
    mitm_sub.add_parser(
        "cert",
        help="Print docker-cp + keychain-trust commands for the proxy's CA certificate.",
    )
    mitm_build = mitm_sub.add_parser(
        "build",
        help="Build the proxy Docker image without starting a container.",
    )
    mitm_build.add_argument("--force", action="store_true", help="Rebuild with --no-cache even if the tag exists.")
    mitm_sub.add_parser("reload", help="Force the proxy to refresh its engagement registry.")
    mitm_routes = mitm_sub.add_parser("routes", help="Print the proxy's loaded engagement→scope mapping.")
    mitm_routes.add_argument("--json", action="store_true")

    # `aith mcp` retired in the typed-CLI cutover. Keep the parser so calls fail with a clear message
    # instead of argparse's generic "unknown command" error; downstream handler prints the deprecation note.
    mcp_p = sub.add_parser("mcp", help="(removed) Kali MCP support retired; use `aith assess kali ...`")
    mcp_p.add_argument("mcp_args", nargs=argparse.REMAINDER)

    auth_p = sub.add_parser("auth")
    auth_sub = auth_p.add_subparsers(dest="auth_command", required=True)
    for auth_name in ("status", "show", "edit", "clear"):
        auth_cmd = auth_sub.add_parser(auth_name)
        auth_cmd.add_argument("engagement", nargs="?")
        auth_cmd.add_argument("--select", action="store_true")
    auth_import = auth_sub.add_parser("import")
    auth_import.add_argument("engagement", nargs="?")
    auth_import.add_argument("--source")
    auth_import.add_argument("--select", action="store_true")

    backup_p = sub.add_parser("backup")
    backup_sub = backup_p.add_subparsers(dest="backup_command", required=True)
    backup_sub.add_parser("create")
    backup_sub.add_parser("list")
    backup_show = backup_sub.add_parser("show")
    backup_show.add_argument("backup", nargs="?")
    backup_restore = backup_sub.add_parser("restore")
    backup_restore.add_argument("backup")
    backup_restore.add_argument("--force", action="store_true")

    oob_p = sub.add_parser("oob")
    oob_sub = oob_p.add_subparsers(dest="oob_command", required=True)
    oob_sub.add_parser("start")
    oob_sub.add_parser("stop")
    oob_sub.add_parser("restart")
    oob_status_p = oob_sub.add_parser("status")
    oob_status_p.add_argument("--json", action="store_true")
    oob_sub.add_parser("test")
    oob_mint = oob_sub.add_parser(
        "mint",
        help="Mint a unique OAST nonce callback URL and record a probe to the backend.",
    )
    oob_mint.add_argument("--engagement")
    oob_mint.add_argument("--select", action="store_true")
    oob_mint.add_argument("--target-url", default="", help="URL/endpoint the payload targets (for correlation context).")
    oob_mint.add_argument("--param", default="", help="Injected parameter/slot name.")
    oob_mint.add_argument("--technique", default="", help="e.g. ssrf, blind-xss, cmdi, xxe.")
    oob_mint.add_argument("--probe-kind", default="", help="Free-form probe classifier.")
    oob_mint.add_argument("--request-hash", default="", help="Hash of the request that carries the payload.")
    oob_mint.add_argument("--notes", default="")
    oob_mint.add_argument("--json", action="store_true", help="Emit the minted probe + URLs as JSON.")
    oob_poll = oob_sub.add_parser(
        "poll",
        help="Parse the interactsh-client log and correlate callbacks to recorded probes.",
    )
    oob_poll.add_argument("--engagement")
    oob_poll.add_argument("--select", action="store_true")
    oob_poll.add_argument(
        "--client",
        required=True,
        help="OOB client name whose interaction log to read (see `aith oob client list`).",
    )
    oob_poll.add_argument("--lines", type=int, default=2000, help="Tail this many log lines (default 2000).")
    oob_poll.add_argument("--json", action="store_true", help="Emit matched/unmatched correlation result as JSON.")
    oob_client = oob_sub.add_parser("client")
    oob_client_sub = oob_client.add_subparsers(dest="oob_client_command", required=True)
    oob_client_start = oob_client_sub.add_parser("start")
    oob_client_start.add_argument("name")
    oob_client_start.add_argument("--engagement")
    oob_client_start.add_argument("--select", action="store_true")
    oob_client_start.add_argument("--agent")
    oob_client_logs = oob_client_sub.add_parser("logs")
    oob_client_logs.add_argument("name")
    oob_client_logs.add_argument("--follow", action="store_true")
    oob_client_logs.add_argument("--lines", default="80")
    oob_client_stop = oob_client_sub.add_parser("stop")
    oob_client_stop.add_argument("name")
    oob_client_sub.add_parser("list")

    assess_p = sub.add_parser("assess", add_help=False)
    assess_p.add_argument("assess_args", nargs=argparse.REMAINDER)

    args = parser.parse_args(raw_argv)
    install_root = resolve_install_root(getattr(args, "install_dir", None) or args.root)

    if args.command in {"install", "update"}:
        source_root = resolve_source_root(args.source, install_root=install_root)
        result = install_from_source(
            InstallOptions(
                source_root=source_root,
                install_root=install_root,
                dry_run=args.dry_run,
                force_image=args.force_image,
                verify_docker_image=not args.skip_image_check,
            )
        )
        if not args.dry_run:
            config_module.set_config_value("install.root", str(result.install_root))
        print(result.install_root)
        if not args.dry_run:
            _print_post_install(result)
    elif args.command == "doctor":
        print_doctor(collect_doctor_checks(install_root, runner=docker_run_command))
    elif args.command == "status":
        print_status(collect_status(install_root, runner=docker_run_command), json_output=args.json)
    elif args.command == "up":
        if args.yes_restart_runtime and args.no_restart_runtime:
            raise SystemExit("Specify only one of --yes-restart-runtime or --no-restart-runtime.")
        if args.engagement or args.select:
            print(
                "[aith] `aith up --engagement/--select` is a no-op now; the proxy serves every active engagement.",
                file=sys.stderr,
            )
        run_up(
            UpOptions(
                install_root=install_root,
                no_build=args.no_build,
                runtime_restart_timeout=args.runtime_restart_timeout,
                yes_restart_runtime=args.yes_restart_runtime,
                no_restart_runtime=args.no_restart_runtime,
            ),
            runner=docker_run_command,
        )
    elif args.command == "logs":
        _logs(args, install_root)
    elif args.command == "config":
        _config(args)
    elif args.command == "engagement":
        _engagement(args, install_root)
    elif args.command == "blue":
        blue_module.run_blue(args, install_root)
    elif args.command == "orchestrator":
        _orchestrator(args, install_root)
    elif args.command == "runtime":
        _runtime(args, install_root)
    elif args.command == "mitmproxy":
        _mitmproxy(args, install_root)
    elif args.command == "mcp":
        _mcp(args)
    elif args.command == "auth":
        _auth(args, install_root)
    elif args.command == "backup":
        _backup(args, install_root)
    elif args.command == "oob":
        _oob(args, install_root)
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


def _config(args: argparse.Namespace) -> None:
    if args.config_command == "path":
        print(config_module.config_path())
    elif args.config_command == "list":
        print(json.dumps(config_module.load_config(), indent=2))
    elif args.config_command == "get":
        value = config_module.get_config_value(args.key)
        if value is None:
            raise SystemExit(f"Config key not set: {args.key}")
        print(value)
    elif args.config_command == "set":
        config_module.set_config_value(args.key, args.value)
        print(f"{args.key}={args.value}")
    elif args.config_command == "unset":
        config_module.unset_config_value(args.key)
    elif args.config_command == "edit":
        config_module.edit_config()


def _logs(args: argparse.Namespace, install_root: Path) -> None:
    if args.target == "all":
        if args.follow:
            raise SystemExit("`aith logs all --follow` is not supported; follow one target at a time.")
        for target in ("orchestrator", "runtime", "mitmproxy", "oob"):
            print(f"==> {target} <==")
            _logs(argparse.Namespace(target=target, follow=False, lines=args.lines), install_root)
        return
    if args.target == "orchestrator":
        log_file = install_root / ".runtime-data" / "logs" / "orchestrator.log"
        argv = ["tail", "-n", str(args.lines)]
        if args.follow:
            argv.append("-f")
        argv.append(str(log_file))
        subprocess.run(argv, check=False)
    elif args.target == "runtime":
        _docker_logs("security-research", args.lines, args.follow)
    elif args.target == "mitmproxy":
        _docker_logs("security-research-proxy", args.lines, args.follow)
    elif args.target == "oob":
        tail_flag = "-f" if args.follow else ""
        command = f"tail -n {shlex.quote(str(args.lines))} {tail_flag} {OOB_ROOT}/*.log {OOB_ROOT}/clients/*.log 2>/dev/null || true"
        subprocess.run(["docker", "exec", "security-research", "sh", "-lc", command], check=False)


def _docker_logs(container_name: str, lines: str, follow: bool) -> None:
    argv = ["docker", "logs", "--tail", str(lines)]
    if follow:
        argv.append("-f")
    argv.append(container_name)
    subprocess.run(argv, check=False)


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
            if not args.no_prompt and sys.stdin.isatty() and not positional and not args.hosts and not args.repo and not args.apk:
                engagement_type = _prompt_choice("Engagement type", "web", ["web", "code", "both", "android"])
            else:
                engagement_type = (
                    "android"
                    if (args.apk or (positional and _looks_like_android_artifact(positional)))
                    else "web" if (args.hosts or (positional and _looks_like_web_target(positional)))
                    else "code"
                )
        target = args.target
        name = args.name
        artifacts = list(args.apk or [])
        android_package = args.package_name
        if positional:
            if engagement_type == "android" and _looks_like_android_artifact(positional):
                if positional not in artifacts:
                    artifacts.insert(0, positional)
                if not name:
                    name = Path(positional).name
            elif engagement_type == "android":
                android_package = android_package or positional
                if not name:
                    name = positional
            elif engagement_type == "code" and not name:
                name = positional
            elif not target:
                target = positional
        hosts = [item.strip() for item in (args.hosts or "").split(",") if item.strip()]
        if not args.no_prompt and sys.stdin.isatty():
            if engagement_type in {"web", "both"} and not target and not hosts:
                target = input("Target URL or host: ").strip()
            if engagement_type in {"code", "both"} and not name:
                name = input("Engagement name: ").strip()
            if engagement_type == "android" and not name and not args.package_name and not artifacts:
                name = input("Engagement name: ").strip()
        created = create_engagement(
            CreateEngagementOptions(
                install_root=install_root,
                engagement_type=engagement_type,
                target=target,
                name=name,
                hosts=hosts,
                repos=args.repo,
                artifacts=artifacts,
                android_package=android_package,
                dynamic_mode=args.dynamic_mode,
                skip_permissions=args.skip_permissions,
            )
        )
        print(created.path)
    elif command == "path":
        print(_resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select))
    elif command == "cd-init":
        print(print_shell_cd_init(args.shell), end="")
    elif command == "start":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        client_args = args.client_args[1:] if args.client_args[:1] == ["--"] else args.client_args
        start_engagement(install_root, path, args.client, client_args)
    elif command == "open":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        webbrowser.open(path.as_uri())
    elif command == "archive":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        scope_path = path / "scope.json"
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
        scope["status"] = "archived"
        scope_path.write_text(json.dumps(scope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(path)
    elif command == "export":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        output = Path(args.output).expanduser() if args.output else install_root / ".runtime-data" / "exports" / f"{path.name}.tar.gz"
        output.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output, "w:gz") as tar:
            tar.add(path, arcname=path.name)
        print(output)
    elif command == "export-pdf":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        output = Path(args.output).expanduser() if args.output else None
        print(export_pdf(path, output))
    elif command == "migrate-scope":
        from .engagements import migrate_legacy_both_engagements

        migrated = migrate_legacy_both_engagements(install_root, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(migrated, indent=2))
        else:
            prefix = "[dry-run] would migrate" if args.dry_run else "migrated"
            if not migrated:
                print(
                    "No legacy `engagement_type=both` engagements need migration."
                    + ("" if not args.dry_run else " (dry-run)")
                )
            else:
                for entry in migrated:
                    print(f"[aith] {prefix}: {entry['key']} code_phase -> {entry['to']}")


def _looks_like_web_target(value: str) -> bool:
    if "://" in value:
        return True
    host = value.split("/", 1)[0].split(":", 1)[0]
    if host in {"localhost"}:
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return "." in host


def _looks_like_android_artifact(value: str) -> bool:
    return Path(value).suffix.lower() in {".apk", ".aab", ".xapk", ".apks"}


def _orchestrator(args: argparse.Namespace, install_root: Path) -> None:
    if args.orchestrator_command == "start":
        start_orchestrator(OrchestratorOptions(install_root=install_root, build=args.build, foreground=args.foreground))
    elif args.orchestrator_command == "stop":
        stop_orchestrator(install_root)
    elif args.orchestrator_command == "restart":
        stop_orchestrator(install_root)
        start_orchestrator(OrchestratorOptions(install_root=install_root))
    elif args.orchestrator_command == "status":
        if args.json:
            print(json.dumps(orchestrator_status_payload(install_root), indent=2))
        else:
            print(orchestrator_status(install_root))
    elif args.orchestrator_command == "open":
        webbrowser.open("http://127.0.0.1:18000")
    elif args.orchestrator_command == "build":
        build_frontend(install_root, force=args.force)


def _runtime(args: argparse.Namespace, install_root: Path) -> None:
    if args.runtime_command == "build":
        build_runtime(install_root, variant=args.variant, dev=args.dev)
    elif args.runtime_command == "start":
        start_runtime(
            RuntimeOptions(
                install_root=install_root,
                recreate=args.recreate,
                allow_oversubscribe=getattr(args, "allow_oversubscribe", False),
            )
        )
    elif args.runtime_command == "stop":
        stop_runtime()
    elif args.runtime_command == "restart":
        stop_runtime()
        start_runtime(RuntimeOptions(install_root=install_root, recreate=True))
    elif args.runtime_command == "status":
        print(runtime_status())
    elif args.runtime_command == "shell":
        os.execvp("docker", ["docker", "exec", "-it", "security-research", "bash"])
    elif args.runtime_command == "shell-exec":
        _runtime_shell_exec(args.shell_command)
    elif args.runtime_command == "resources":
        aith_runtime_resources(json_output=args.json)


def _runtime_shell_exec(command_parts: list[str]) -> None:
    if command_parts[:1] == ["--"]:
        command_parts = command_parts[1:]
    if not command_parts:
        raise SystemExit("Specify a command string for `aith runtime shell-exec`.")
    command = command_parts[0] if len(command_parts) == 1 else " ".join(shlex.quote(part) for part in command_parts)
    if not command.strip():
        raise SystemExit("Specify a non-empty command string for `aith runtime shell-exec`.")
    try:
        result = subprocess.run(["docker", "exec", "security-research", "sh", "-lc", command], check=False)
    except FileNotFoundError as exc:
        raise SystemExit("docker CLI not found on PATH") from exc
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _mitmproxy(args: argparse.Namespace, install_root: Path) -> None:
    engagements_root = install_root / "agent" / "engagements"
    if args.mitmproxy_command == "start":
        if args.engagement or args.select:
            # The engagement positional / --select is a legacy shim. The proxy
            # now serves every active engagement at once, so we silently ignore
            # the value after printing one line so the operator knows.
            print(
                "[aith] mitmproxy now serves all active engagements; ignoring engagement selector.",
                file=sys.stderr,
            )
        engagements_root.mkdir(parents=True, exist_ok=True)
        start_proxy(
            MitmproxyOptions(
                install_root=install_root,
                engagements_root=engagements_root,
                port=args.port,
            ),
            force_rebuild=args.build,
        )
    elif args.mitmproxy_command == "stop":
        stop_proxy()
    elif args.mitmproxy_command == "build":
        build_proxy_image(install_root, force=args.force)
    elif args.mitmproxy_command == "status":
        payload = proxy_status_payload(install_root, engagements_root)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            _print_mitmproxy_status(payload)
    elif args.mitmproxy_command == "cert":
        print("docker cp security-research-proxy:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem")
        print("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem")
    elif args.mitmproxy_command == "reload":
        request_proxy_reload(engagements_root)
        print(f"[aith] mitmproxy reload requested ({engagements_root})")
    elif args.mitmproxy_command == "routes":
        snapshot = read_proxy_routes(engagements_root)
        if snapshot is None:
            raise SystemExit(
                f"No routes cache at {engagements_root}/.mitmproxy-routes.json — "
                "is the proxy running and has it loaded its registry yet?"
            )
        if args.json:
            print(json.dumps(snapshot, indent=2))
            return
        print(f"generated_at: {snapshot.get('generated_at', '-')}")
        for entry in snapshot.get("engagements", []):
            patterns = ", ".join(entry.get("scope_patterns", []) or ["(no scope hosts)"])
            print(
                f"  {entry.get('key', '-'):30s}  priority={entry.get('scope_priority', 0):>3}  "
                f"updated={entry.get('updated_at', '-'):>20}  scope=[{patterns}]"
            )


def _print_mitmproxy_status(payload: dict) -> None:
    state = payload.get("state", "?")
    print(
        f"mitmproxy\t{state}\tcontainer={payload.get('container', '-')}"
        f"\tport={payload.get('port', '-')}\tport_reachable={payload.get('port_reachable')}"
    )
    pid_or_id = payload.get("container_id") or "-"
    print(
        f"image\t{payload.get('image', '-')}\tpresent={payload.get('image_present')}"
        f"\tcontainer_id={pid_or_id}"
    )
    print(
        f"cert\tvolume={payload.get('cert_volume', '-')}"
        f"\tpresent={payload.get('cert_volume_present')}"
    )
    print(
        f"upstream\t{payload.get('upstream_url', '-')}"
        f"\tengagements_root={payload.get('engagements_root', '-')}"
    )
    routes_loaded = payload.get("routes_loaded") or 0
    print(
        f"routes\tloaded={routes_loaded}"
        f"\tgenerated_at={payload.get('routes_generated_at') or '-'}"
    )
    if payload.get("exit_code") is not None and not payload.get("running"):
        print(
            f"last_exit\tcode={payload['exit_code']}"
            f"\tstarted_at={payload.get('started_at') or '-'}"
            f"\tfinished_at={payload.get('finished_at') or '-'}"
        )
    log_tail = payload.get("log_tail")
    if log_tail:
        print("recent_logs:")
        for line in log_tail.splitlines()[-12:]:
            print(f"  {line}")


def _mcp(args: argparse.Namespace) -> None:
    """Stub: Kali MCP support was removed in the typed-CLI cutover."""
    print(
        "aith mcp install/status/uninstall/remove/repair were removed in the typed-CLI cutover.",
        file=sys.stderr,
    )
    print(
        "Use `aith assess kali ...` for target-facing tool execution and `aith runtime status` "
        "or `aith runtime resources` for runtime visibility.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _auth(args: argparse.Namespace, install_root: Path) -> None:
    engagement = _resolve_command_engagement(install_root, args)
    if args.auth_command == "status":
        print(auth_module.status_line(engagement))
    elif args.auth_command == "show":
        print(json.dumps(auth_module.read_auth(engagement), indent=2, sort_keys=True))
    elif args.auth_command == "edit":
        auth_module.edit_auth(engagement)
    elif args.auth_command == "clear":
        auth_module.clear_auth(engagement)
        print(engagement / "auth.json")
    elif args.auth_command == "import":
        auth_module.import_auth(engagement, args.source)
        print(engagement / "auth.json")


def _backup(args: argparse.Namespace, install_root: Path) -> None:
    if args.backup_command == "create":
        print(backup_module.create_backup(install_root))
    elif args.backup_command == "list":
        for item in backup_module.list_backups(install_root):
            print(f"{item.path.name}\t{item.modified_at}\t{item.size}\t{item.path}")
    elif args.backup_command == "show":
        if args.backup:
            path = backup_module.resolve_backup(install_root, args.backup)
            stat = path.stat()
            print(json.dumps({"path": str(path), "size": stat.st_size}, indent=2))
        else:
            latest = backup_module.latest_backup(install_root)
            if latest is None:
                raise SystemExit("No backups found")
            print(json.dumps(asdict(latest) | {"path": str(latest.path)}, indent=2))
    elif args.backup_command == "restore":
        if orchestrator_status(install_root) == "running" and not args.force:
            raise SystemExit("Stop the orchestrator before restoring a backup, or pass --force.")
        backup = backup_module.resolve_backup(install_root, args.backup)
        print(backup_module.restore_backup(install_root, backup))


def _oob(args: argparse.Namespace, install_root: Path) -> None:
    options = _oob_options(install_root)
    if args.oob_command == "start":
        start_oob(options, runner=docker_run_command)
    elif args.oob_command == "stop":
        stop_oob(runner=docker_run_command)
    elif args.oob_command == "restart":
        stop_oob(runner=docker_run_command)
        start_oob(options, runner=docker_run_command)
    elif args.oob_command == "status":
        payload = oob_status(oob_domain=options.oob_domain, runner=docker_run_command)
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(
                f"{payload['state']}\tserver={payload['server']}\tfrpc={payload['frpc']}"
                f"\tclients={len(payload['clients'])}\tdomain={payload['domain']}"
            )
    elif args.oob_command == "test":
        test_oob(options, runner=docker_run_command)
    elif args.oob_command == "mint":
        _oob_mint(args, install_root, options)
    elif args.oob_command == "poll":
        _oob_poll(args, install_root, options)
    elif args.oob_command == "client":
        _oob_client(args, install_root, options)


def _tmux_has_oob_client(name: str) -> bool:
    result = docker_run_command(["docker", "exec", "security-research", "sh", "-lc", f"tmux has-session -t oob-client-{shlex.quote(name)} 2>/dev/null"])
    return result.returncode == 0


def _oob_client(args: argparse.Namespace, install_root: Path, options: OobOptions) -> None:
    if args.oob_client_command == "start":
        if args.engagement and args.select:
            raise SystemExit("Specify either --engagement or --select, not both")
        engagement_key = None
        if args.engagement:
            engagement_key = resolve_engagement_path(install_root, args.engagement).name
        elif args.select:
            engagement_key = resolve_engagement_path(install_root, select=True).name
        elif current := current_engagement_path():
            engagement_key = current.name
        start_oob_client(options, args.name, engagement=engagement_key, agent=args.agent, runner=docker_run_command)
    elif args.oob_client_command == "logs":
        client = sanitize_name(args.name)
        tail_flag = "-f" if args.follow else ""
        command = f"tail -n {shlex.quote(str(args.lines))} {tail_flag} {OOB_ROOT}/clients/{shlex.quote(client)}.log 2>/dev/null || true"
        subprocess.run(["docker", "exec", "security-research", "sh", "-lc", command], check=False)
    elif args.oob_client_command == "stop":
        stop_oob_client(args.name, runner=docker_run_command)
    elif args.oob_client_command == "list":
        clients = list_oob_clients(runner=docker_run_command)
        if not clients:
            print("No OOB clients configured.", file=sys.stderr)
        for client in clients:
            alive = _tmux_has_oob_client(client)
            status = "running" if alive else "dead"
            print(f"{client}\t{status}")


# Test seam: deterministic nonce minting. Tests monkeypatch this to a
# fixed token_factory; production leaves it None so `mint_nonce` draws from
# `secrets`. Kept at module scope so `aith oob mint` stays seedable without
# threading a factory argument through argparse.
_oob_nonce_token_factory = None


def _build_assessment_client(install_root: Path, engagement_key: str):
    """Construct an AssessmentClient (used as a context manager) for the
    given engagement, reusing the same orchestrator base-url resolution as
    the rest of the CLI and the assess library shipped under agent/scripts.

    The import is deferred and path-bridged exactly like
    ``engagements._init_cases_db`` so the installable ``src`` package keeps a
    single source of truth for the HTTP client without a hard dependency on
    the agent tree at import time.
    """
    from .paths import add_assess_import_path, resolve_orchestrator_base_url

    eng_dir = resolve_engagement_path(install_root, engagement_key)
    base_url = resolve_orchestrator_base_url(install_root, eng_dir)
    add_assess_import_path(install_root)
    try:
        from assess.lib.client import AssessmentClient  # type: ignore[import-not-found]
    except ImportError as exc:  # pragma: no cover - defensive
        raise SystemExit(
            "Cannot import the assessment HTTP client (assess.lib.client). "
            "Run from a source checkout or a completed `aith install`."
        ) from exc
    return AssessmentClient(base_url, engagement_key)


def _oob_mint(args: argparse.Namespace, install_root: Path, options: OobOptions) -> None:
    engagement_path = _resolve_command_engagement(install_root, args)
    engagement_key = engagement_path.name
    nonce = mint_nonce(prefix=sanitize_name(engagement_key), token_factory=_oob_nonce_token_factory)
    urls = callback_urls(nonce, options.oob_domain)
    with _build_assessment_client(install_root, engagement_key) as client:
        record = client.post(
            "oob-probes",
            {
                "nonce": nonce,
                "target_url": args.target_url,
                "param": args.param,
                "technique": args.technique,
                "probe_kind": args.probe_kind,
                "request_hash": args.request_hash,
                "oob_domain": options.oob_domain,
                "notes": args.notes,
            },
        )
    if args.json:
        print(json.dumps({"nonce": nonce, "urls": urls, "probe": record}, indent=2))
        return
    print(f"nonce\t{nonce}")
    print(f"http\t{urls['http']}")
    print(f"dns\t{urls['dns']}")
    print(f"probe\tid={record.get('id')}\tstatus={record.get('status')}\ttechnique={record.get('technique') or '-'}")


def _oob_poll(args: argparse.Namespace, install_root: Path, options: OobOptions) -> None:
    engagement_path = _resolve_command_engagement(install_root, args)
    engagement_key = engagement_path.name
    log_text = read_client_log(args.client, runner=docker_run_command, lines=args.lines)
    interactions = parse_interactsh_log(log_text)
    with _build_assessment_client(install_root, engagement_key) as client:
        probes = client.get("oob-probes")
        nonces = [str(p.get("nonce", "")) for p in probes if p.get("nonce")]
        matched_interactions, unmatched_interactions = match_interactions_to_nonces(interactions, nonces)
        matched_pairs: list[dict] = []
        for interaction in matched_interactions:
            result = client.post(
                "oob-probes/interactions",
                {
                    "nonce": interaction.nonce,
                    "protocol": interaction.protocol,
                    "remote_address": interaction.remote_address,
                    "query_type": interaction.query_type,
                    "raw_request": interaction.raw_line,
                    "observed_at": interaction.observed_at,
                },
            )
            matched_pairs.append({"interaction": interaction, "result": result})

    if args.json:
        payload = {
            "client": sanitize_name(args.client),
            "parsed": len(interactions),
            "matched": [
                {
                    "nonce": pair["interaction"].nonce,
                    "protocol": pair["interaction"].protocol,
                    "remote_address": pair["interaction"].remote_address,
                    "observed_at": pair["interaction"].observed_at,
                    "duplicate": bool(pair["result"].get("duplicate")),
                    "probe": pair["result"].get("probe"),
                }
                for pair in matched_pairs
            ],
            "unmatched": [
                {
                    "protocol": item.protocol,
                    "full_host": item.full_host,
                    "remote_address": item.remote_address,
                    "observed_at": item.observed_at,
                }
                for item in unmatched_interactions
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    print(f"parsed\t{len(interactions)} interaction(s) from client {sanitize_name(args.client)}")
    print(f"matched\t{len(matched_pairs)}\tunmatched\t{len(unmatched_interactions)}")
    if matched_pairs:
        print("matched probe<->callback pairs:")
        for pair in matched_pairs:
            interaction = pair["interaction"]
            probe = pair["result"].get("probe") or {}
            dup = " (duplicate)" if pair["result"].get("duplicate") else ""
            print(
                f"  {interaction.nonce}\t{interaction.protocol}\tfrom={interaction.remote_address or '-'}"
                f"\ttechnique={probe.get('technique') or '-'}\ttarget={probe.get('target_url') or '-'}{dup}"
            )
    if unmatched_interactions:
        print("unmatched interactions:")
        for item in unmatched_interactions:
            print(f"  {item.full_host}\t{item.protocol}\tfrom={item.remote_address or '-'}")


def _oob_options(install_root: Path) -> OobOptions:
    token = os.environ.get("AI_THREAT_HUNTING_FRP_TOKEN") or config_module.get_config_value("oob.frp_token") or ""
    host = os.environ.get("AI_THREAT_HUNTING_FRP_HOST") or config_module.get_config_value("oob.frp_host", DEFAULT_FRP_HOST) or DEFAULT_FRP_HOST
    port = int(os.environ.get("AI_THREAT_HUNTING_FRP_PORT") or config_module.get_config_value("oob.frp_port", str(DEFAULT_FRP_PORT)) or DEFAULT_FRP_PORT)
    domain = os.environ.get("AI_THREAT_HUNTING_OOB_DOMAIN") or config_module.get_config_value("oob.domain", DEFAULT_OOB_DOMAIN) or DEFAULT_OOB_DOMAIN
    return OobOptions(install_root=install_root, frp_host=host, frp_port=port, frp_token=token, oob_domain=domain)


def _resolve_command_engagement(install_root: Path, args: argparse.Namespace) -> Path:
    key = getattr(args, "engagement", None)
    return _resolve_current_or_selected_engagement(install_root, key=key, select=getattr(args, "select", False))


def _resolve_current_or_selected_engagement(install_root: Path, *, key: str | None = None, select: bool = False) -> Path:
    if key:
        return resolve_engagement_path(install_root, key)
    if select:
        return resolve_engagement_path(install_root, select=True)
    if current := current_engagement_path():
        return current
    raise SystemExit("Specify an engagement key or --select, or run from inside an engagement")


def _resolve_engagement_reference(install_root: Path, value: str) -> Path:
    try:
        return resolve_engagement_path(install_root, value)
    except SystemExit as exc:
        candidate = Path(value).expanduser()
        if candidate.exists() or candidate.is_absolute() or "/" in value:
            return candidate
        raise exc


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
