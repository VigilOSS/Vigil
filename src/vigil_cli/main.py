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
from . import bench as bench_module
from . import blue as blue_module
from . import config as config_module
from . import email as email_module
from .docker import run_command as docker_run_command
from .engagements import (
    PROGRAM_HEADER_PRESETS,
    CreateEngagementOptions,
    add_out_of_scope,
    clear_active_engagement,
    create_engagement,
    current_engagement_path,
    export_pdf,
    list_engagements,
    plan_engagement,
    print_shell_cd_init,
    remove_out_of_scope,
    resolve_current_engagement,
    resolve_engagement_path,
    resolve_out_of_scope,
    resolve_rate_limit,
    resolve_required_headers,
    set_active_engagement,
    set_engagement_header,
    start_engagement,
    unset_engagement_header,
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
    OOB_ROOT,
    OobOptions,
    callback_urls,
    clean_oob_clients,
    client_payload_host,
    list_oob_clients,
    list_running_oob_clients,
    match_interactions_to_nonces,
    mint_nonce,
    oob_options as _oob_options,
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
from .paths import default_runtime_container, resolve_install_root, resolve_source_root
from .quickstart import QuickstartOptions, run_quickstart
from .runtime import RuntimeOptions, vigil_runtime_resources, build_runtime, runtime_image_build_state, runtime_status, start_runtime, stop_runtime
from .status import collect_doctor_checks, collect_status, print_doctor, print_status, write_install_meta
from .up import UpOptions, run_up


def _print_post_install(result: InstallResult) -> None:
    root = result.install_root
    print()
    if result.is_upgrade:
        print("Upgrade complete. Services using the previous install should be restarted:")
        print("  - Kali runtime:   vigil runtime restart")
        print("  - Orchestrator:   vigil orchestrator restart")
        if result.image_built:
            print("  - Docker image was rebuilt — running containers use the old image until restarted")
        else:
            state = runtime_image_build_state(root)
            if state == "stale":
                print("  - Docker image:   OUT OF DATE (baked runtime input changed) — run  vigil runtime build")
            elif state == "missing":
                print("  - Docker image:   not built yet — run  vigil runtime build")
            elif state == "current":
                print("  - Docker image:   up to date — a restart is enough (no rebuild needed)")
            else:
                print("  - Docker image:   run  vigil runtime build  only if the runtime Dockerfile or "
                      "docker/callback_* changed (most code is host-side; restart is enough)")
    else:
        print("Install complete. Next steps:")
        print(f"  1. Configure tokens and API keys in {root / '.env'}")
        print("  2. Optional OOB: vigil config set oob.frp_token <token>")
        print("  3. vigil up                      # build/start runtime, orchestrator, and OOB")
        print("  4. vigil engagement create <target>  # create your first engagement")
        print("  5. vigil assess kali --help      # discover target-facing CLI verbs")
    print()
    print(
        "Two-layer model: `vigil install`/`update` upgraded the WORKING ROOT "
        "(code/prompts/skills/scripts). `uv tool upgrade vigil` upgrades only the CLI "
        "binary. `vigil status` warns when the working root falls behind its source."
    )
    print()


def main(argv: list[str] | None = None) -> None:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    command_idx = _top_level_command_index(raw_argv)
    if command_idx is not None and raw_argv[command_idx] == "assess":
        _exec_assess_passthrough(raw_argv, command_idx)
        return
    parser = argparse.ArgumentParser(prog="vigil", description="Vigil operator CLI")
    parser.add_argument("--root", help="Install root (default: $VIGIL_INSTALL_DIR or ~/vigil)")
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

    quickstart_p = sub.add_parser(
        "quickstart",
        help="Onboarding wizard: probe host prerequisites/recon tools and print the setup checklist",
        description=(
            "macOS-first onboarding wizard. Reports the bootstrap prerequisites "
            "(uv/git/docker/go/npm), detects missing host-side recon tools, and "
            "prints the ordered next-command checklist for the resolved install "
            "root. It only mutates the host when --install-host-tools is passed "
            "(and never under --dry-run); without it the host-tool installs are "
            "planned/printed, not run."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    quickstart_p.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; use flags/defaults only (implied when stdin is not a TTY)",
    )
    quickstart_p.add_argument(
        "--yes",
        dest="assume_yes",
        action="store_true",
        help="Assume yes to prompts (e.g. run the host-tool installs without confirmation)",
    )
    quickstart_p.add_argument(
        "--install-host-tools",
        action="store_true",
        help="Actually run the host-tool install commands (default: plan/print only)",
    )
    quickstart_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan everything, execute nothing (overrides --install-host-tools)",
    )
    quickstart_p.add_argument("--target", help="First engagement target URL/host for the checklist")
    quickstart_p.add_argument("--hosts", help="In-scope hosts (comma-separated) for the checklist")
    quickstart_p.add_argument("--json", action="store_true", help="Emit the readiness report as JSON")

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

    use_p = sub.add_parser(
        "use",
        help="Set the active engagement (persisted; honoured by `vigil` verbs and `vigil assess`).",
    )
    use_p.add_argument("key", nargs="?", help="Engagement key to activate")
    use_p.add_argument("--select", action="store_true", help="Pick the engagement interactively")
    use_p.add_argument("--clear", action="store_true", help="Unset the active-engagement pointer")

    engagement_p = sub.add_parser("engagement")
    engagement_sub = engagement_p.add_subparsers(dest="engagement_command", required=True)
    engagement_sub.add_parser("list").add_argument("--json", action="store_true")
    create_p = engagement_sub.add_parser(
        "create",
        help="Create a new engagement workspace",
        description=(
            "Create an engagement workspace under <install-root>/agent/engagements/.\n"
            "When --type is omitted it is inferred from the inputs (URL/host → web,\n"
            "--repo → code, both kinds of evidence → both, APK/--package-name → android)\n"
            "and the inferred type is echoed so it can be overridden. On a terminal,\n"
            "missing required fields are asked for interactively; pass --no-prompt to\n"
            "fail instead of asking."
        ),
        epilog=(
            "Examples:\n"
            "  vigil engagement create https://app.example.com --hosts app.example.com\n"
            "  vigil engagement create --type code my-project --repo ~/src/my-project\n"
            "  vigil engagement create https://app.example.com --repo ~/src/my-project --name my-project\n"
            "  vigil engagement create --type android ./app.apk\n"
            "  vigil engagement create https://app.example.com --dry-run\n"
            "\n"
            "Blue (defensive) engagements are created via `vigil blue engage`.\n"
            "Exploit policy always starts as `pause` and auth always starts unset;\n"
            "both are configured after creation (orchestrator UI / `vigil auth`)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    create_p.add_argument(
        "target_or_name",
        nargs="?",
        help="Target URL/host (web), engagement name (code), or APK path/package (android)",
    )
    create_p.add_argument(
        "--type",
        choices=["web", "code", "both", "android"],
        default=None,
        help="Engagement type; inferred from the other inputs when omitted",
    )
    create_p.add_argument("--name", help="Engagement name (required for code/both)")
    create_p.add_argument("--target", help="Primary target URL or host (web/both)")
    create_p.add_argument("--hosts", help="Comma-separated in-scope hosts")
    create_p.add_argument(
        "--host",
        action="append",
        default=[],
        help="In-scope host; repeatable, merged with --hosts and --hosts-file",
    )
    create_p.add_argument(
        "--hosts-file",
        help="File of in-scope hosts, one per line (blank lines and # comments ignored)",
    )
    create_p.add_argument(
        "--repo",
        action="append",
        default=[],
        help="Source repository path or URL (code/both); repeatable",
    )
    create_p.add_argument("--apk", action="append", default=[], help="Android APK/AAB/XAPK artifact path")
    create_p.add_argument("--package-name", help="Android package name, for example com.example.app")
    create_p.add_argument(
        "--dynamic-mode",
        choices=["static_only", "device", "emulator"],
        default="static_only",
        help="Android dynamic-analysis mode (default: static_only)",
    )
    create_p.add_argument(
        "--skip-permissions",
        action="store_true",
        help="Generate launchers that skip client permission prompts",
    )
    create_p.add_argument(
        "--program",
        choices=sorted(PROGRAM_HEADER_PRESETS),
        default=None,
        help="Bug-bounty program preset; sets the program's mandated attribution "
             "header (requires --researcher). web/both/android only.",
    )
    create_p.add_argument(
        "--researcher",
        default=None,
        help="Researcher handle sent as the --program attribution header value",
    )
    create_p.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="Required request header injected into every in-scope HTTP probe; "
             "repeatable. e.g. --header \"X-Bug-Bounty: vigiloss\"",
    )
    create_p.add_argument(
        "--out-of-scope",
        action="append",
        default=[],
        metavar="HOST|*.WILDCARD|CIDR",
        help="Out-of-scope carve-out excluded even when an in-scope wildcard "
             "would match it; repeatable. web/both/android only.",
    )
    create_p.add_argument(
        "--rate-limit",
        dest="rate_limit",
        type=float,
        default=None,
        metavar="REQ_PER_SEC",
        help="Per-invocation / global request-rate ceiling (req/s) for the recon "
             "pipeline's bulk web stages (httpx liveness, katana crawl, js-mining "
             "body-fetch). httpx -rate-limit / katana -rl are single GLOBAL token "
             "buckets, so this caps each stage's AGGREGATE rate over the whole "
             "in-scope host set probed in one invocation and bounds per-host only "
             "as a side effect (a cap of 5 over 100 hosts is ~0.05 req/s/host). "
             "Does NOT cover the recon-specialist's nuclei/ffuf/nmap/whatweb/nikto "
             "probes or gau body-fetches. Must be >= 1 (sub-1 is rejected — the "
             "tools take an integer req/s); a value >= 1 is accepted but truncates "
             "DOWN at use (5.9 -> 5), and a cap above a stage's verb default is a "
             "no-op (the ceiling only clamps DOWN). Unset = today's behavior (per-tool "
             "defaults, agent discretion, no hard gate). web/both/android only. "
             "e.g. --rate-limit 5",
    )
    create_p.add_argument(
        "--no-prompt",
        action="store_true",
        help="Never prompt interactively; fail when required fields are missing",
    )
    create_p.add_argument(
        "--json",
        action="store_true",
        help="Emit created-engagement metadata as JSON on stdout instead of the bare path",
    )
    create_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and show what would be created without writing anything",
    )
    set_header_p = engagement_sub.add_parser(
        "set-header", help="Add/replace a required attribution header on an engagement"
    )
    set_header_p.add_argument("key")
    set_header_p.add_argument("header", metavar="NAME: VALUE")
    unset_header_p = engagement_sub.add_parser(
        "unset-header", help="Remove a required attribution header from an engagement"
    )
    unset_header_p.add_argument("key")
    unset_header_p.add_argument("name")
    add_oos_p = engagement_sub.add_parser(
        "add-oos", help="Add out-of-scope carve-out(s) to an engagement"
    )
    add_oos_p.add_argument("key")
    add_oos_p.add_argument("entries", nargs="+", metavar="HOST|*.WILDCARD|CIDR")
    remove_oos_p = engagement_sub.add_parser(
        "remove-oos", help="Remove an out-of-scope carve-out from an engagement"
    )
    remove_oos_p.add_argument("key")
    remove_oos_p.add_argument("entry")
    path_p = engagement_sub.add_parser("path")
    path_p.add_argument("key", nargs="?")
    path_p.add_argument("--select", action="store_true")
    eng_use_p = engagement_sub.add_parser(
        "use", help="Alias for `vigil use`: set the active-engagement pointer."
    )
    eng_use_p.add_argument("key", nargs="?")
    eng_use_p.add_argument("--select", action="store_true")
    eng_use_p.add_argument("--clear", action="store_true")
    engagement_sub.add_parser(
        "current",
        help="Print the resolved active engagement and which tier won (flag/cwd/pointer/env).",
    )
    cd_p = engagement_sub.add_parser("cd-init")
    cd_p.add_argument("shell", choices=["zsh", "bash"], default="zsh", nargs="?")
    start_p = engagement_sub.add_parser("start")
    start_p.add_argument("key", nargs="?")
    start_p.add_argument("--select", action="store_true")
    start_p.add_argument("--client", choices=["codex", "claude", "opencode", "goose"], required=True)
    start_p.add_argument("--thinking", choices=["off", "high", "max"], default=None,
                         help="DeepSeek thinking level for --client opencode: off=disabled, "
                              "high=on, max=maximum (default: client default — thinking on). "
                              "Ignored for claude/codex.")
    start_p.add_argument("client_args", nargs="*")
    open_p = engagement_sub.add_parser("open")
    open_p.add_argument("key", nargs="?")
    open_p.add_argument("--select", action="store_true")
    archive_p = engagement_sub.add_parser("archive")
    archive_p.add_argument("key", nargs="?")
    archive_p.add_argument("--select", action="store_true")
    export_p = engagement_sub.add_parser(
        "export",
        help=(
            "Export an engagement. Default packs the engagement dir as a "
            "tar.gz; --format markdown-tree writes a diffable per-finding tree "
            "(one dir per finding: draft.md / debate.md / report.md) sourced "
            "from the backend. For a single consolidated findings.md report doc "
            "instead, use `vigil assess export-findings`."
        ),
    )
    export_p.add_argument("key", nargs="?")
    export_p.add_argument("--select", action="store_true")
    export_p.add_argument(
        "--format",
        dest="export_format",
        choices=["tar.gz", "markdown-tree"],
        default="tar.gz",
        help=(
            "Export format (default: tar.gz archive). markdown-tree = diffable "
            "per-finding tree (vs `vigil assess export-findings` = single "
            "findings.md report doc)."
        ),
    )
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
    bench_module.register_bench_parser(sub)

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
        help="Build the install-side frontend dist (recovery for direct-uvicorn launches that bypass vigil up).",
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
        help="Manage the engagement-wide intercepting proxy (Docker container vigil-proxy on :8080).",
    )
    mitm_sub = mitm_p.add_subparsers(dest="mitmproxy_command", required=True)
    mitm_start = mitm_sub.add_parser(
        "start",
        help=(
            "Start (or restart) the shared proxy container for all active "
            "engagements; builds the image first if missing."
        ),
    )
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

    # `vigil mcp` retired in the typed-CLI cutover. Keep the parser so calls fail with a clear message
    # instead of argparse's generic "unknown command" error; downstream handler prints the deprecation note.
    email_p = sub.add_parser(
        "email",
        help="Read recent messages from a local Mail.app mailbox (e.g. fetch a verification code)",
        description=(
            "Read recent messages addressed to a test mailbox via local Mail.app automation "
            "(same mechanism as email-utility; no SMTP/IMAP/API, no stored "
            "credentials). The mailbox must be a configured Mail.app account on this host. "
            "Primary use: retrieving short-lived email-verification codes sent to a test "
            "mailbox during authenticated security testing."
        ),
    )
    email_p.add_argument(
        "mailbox",
        help="recipient mailbox address to read (e.g. researcher@example.com)",
    )
    email_p.add_argument(
        "--from",
        dest="from_filter",
        default=None,
        help="only messages FROM this address or domain (e.g. security@acme-bank.example or @acme-bank.example)",
    )
    email_p.add_argument(
        "--within",
        type=int,
        default=3,
        help="only messages received in the last N minutes (default: 3)",
    )
    email_p.add_argument(
        "--match",
        default=None,
        help=(
            "regex to extract a token from each message body; the first capture group "
            "(or whole match) is printed. Implies extraction."
        ),
    )
    email_p.add_argument(
        "--extract",
        action="store_true",
        help=(
            "extract a verification token even without --match, using the default "
            f"6-8 digit code pattern ({email_module.DEFAULT_CODE_PATTERN})"
        ),
    )
    email_p.add_argument(
        "--limit",
        type=int,
        default=200,
        help="maximum Mail.app messages to scan (default: 200)",
    )
    email_p.add_argument(
        "--timeout-seconds",
        type=float,
        default=30.0,
        help="timeout for the Mail.app read (default: 30)",
    )
    email_p.add_argument(
        "--json",
        action="store_true",
        help="emit results as JSON for programmatic parsing",
    )

    mcp_p = sub.add_parser("mcp", help="(removed) Kali MCP support retired; use `vigil assess kali ...`")
    mcp_p.add_argument("mcp_args", nargs=argparse.REMAINDER)

    auth_p = sub.add_parser("auth")
    auth_sub = auth_p.add_subparsers(dest="auth_command", required=True)
    for auth_name in ("status", "show", "edit", "clear", "export"):
        auth_cmd = auth_sub.add_parser(auth_name)
        auth_cmd.add_argument("engagement", nargs="?")
        auth_cmd.add_argument("--select", action="store_true")
        auth_cmd.add_argument(
            "--identity", help="Named identity (default: the active identity)"
        )
        if auth_name == "clear":
            auth_cmd.add_argument(
                "--all", action="store_true",
                help="Clear ALL identities (default: only the active identity)",
            )
        if auth_name == "status":
            auth_cmd.add_argument(
                "--probe",
                action="store_true",
                help=(
                    "Actively verify session liveness with a lightweight authed GET "
                    "(requires --probe-url). Without it, `stale` reflects only the "
                    "expiry timestamp — presence of cookies is NOT proof of liveness. "
                    "Without a material.liveness signature the probe stays 'unknown'."
                ),
            )
            auth_cmd.add_argument(
                "--probe-url",
                dest="probe_url",
                help=(
                    "URL to GET as the active identity for the --probe liveness check "
                    "(e.g. an authed landing page). The response (status line + headers "
                    "incl. Location + body) is matched case-sensitively against "
                    "material.liveness = {expect_status, authed_marker, dead_marker}; "
                    "redirects are NOT followed."
                ),
            )
        if auth_name == "export":
            auth_cmd.add_argument(
                "--host",
                help=(
                    "Target host to scope captured per-host session cookies to "
                    "(e.g. portal.acme-agency.example). Required on a multi-host engagement "
                    "to get the right session — without it this only renders "
                    "the legacy flat cookie view, which can be empty even when "
                    "a proxy-captured session exists for that host."
                ),
            )
            auth_cmd.add_argument(
                "--method",
                help=(
                    "HTTP method the exported args will be used with. Pass a "
                    "state-changing verb (POST/PUT/PATCH/DELETE) to also emit the "
                    "identity's opt-in CSRF double-submit header, matching what "
                    "`vigil assess kali --identity` injects. Safe methods omit it."
                ),
            )
    auth_import = auth_sub.add_parser(
        "import",
        help="Import identity material (cookies/headers/tokens) from a JSON file or stdin.",
        description=(
            "Import credential material into the engagement's centralized store from a "
            "JSON file (or '-'/stdin).\n\n"
            "The JSON MAY also include a `material.liveness` block —\n"
            '  {"expect_status": 200, "authed_marker": "...", "dead_marker": "sessionExpired"}\n'
            "(every key optional) — which is stored via the backend's extra-keys "
            "passthrough and is what makes `vigil auth status --probe` and "
            "`vigil auth keepalive` return a real live/dead verdict instead of "
            "'unknown'. Matching is case-sensitive substring against the probe "
            "response (status line + headers incl. Location + body)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    auth_import.add_argument("engagement", nargs="?")
    auth_import.add_argument("--source")
    auth_import.add_argument("--select", action="store_true")
    auth_import.add_argument(
        "--identity", default="default", help="Identity to import into (default: default)"
    )
    auth_activate = auth_sub.add_parser("set-active")
    auth_activate.add_argument("engagement", nargs="?")
    auth_activate.add_argument("--select", action="store_true")
    auth_activate.add_argument("--identity", required=True, help="Identity to activate")

    auth_keepalive = auth_sub.add_parser(
        "keepalive",
        help=(
            "Keep long-lived (enterprise SSO / reverse-proxy) sessions live during "
            "long engagements; name the anchor cookie(s) with --anchor-cookie."
        ),
        description=(
            "Fire ONE read-only authed GET per identity every --interval seconds to "
            "reset the enterprise IDLE timeout, teeing a LIVE/DEAD + userId verdict to "
            "a log. Each cycle re-resolves the freshest full-anchor capture per "
            "distinct login (skipping captured logouts), so re-logins are auto-"
            "followed; --identity overrides that. The live probe — routed through "
            "`vigil assess kali exec` for correct egress + audit + identity injection "
            "— is the AUTHORITATIVE liveness oracle (cookie age is never trusted "
            "alone).\n\n"
            "ANCHOR COOKIES ARE ENGAGEMENT-SPECIFIC and REQUIRED: Vigil bakes in NO "
            "target-specific cookie names. Declare this engagement's session-anchor "
            "cookie name(s) with --anchor-cookie (repeatable) — their value identifies "
            "a distinct login (for freshest-per-login dedup) and a Set-Cookie: "
            "<anchor>=deleted marks a server logout to skip.\n\n"
            "HARD CEILINGS: this defeats the IDLE timeout ONLY. It does NOT extend the "
            "absolute/max-session lifetime, and it cannot survive a same-user browser "
            "re-login (which emits Set-Cookie: <anchor>=deleted and kills the prior "
            "session). For multi-hour runs you still need a fresh browser login "
            "periodically.\n\n"
            "Use --detach to run it as a background daemon (double-fork; PID file "
            "under <engagement>/pids/) that outlives the launching shell."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    auth_keepalive.add_argument("engagement", nargs="?")
    auth_keepalive.add_argument("--select", action="store_true")
    auth_keepalive.add_argument(
        "--identity",
        action="append",
        help=(
            "Identity to keep alive (repeatable). Omit to auto-resolve the freshest "
            "--caps captures per session anchor each cycle."
        ),
    )
    auth_keepalive.add_argument(
        "--anchor-cookie",
        dest="anchor_cookie",
        action="append",
        metavar="NAME",
        help=(
            "REQUIRED (repeatable). Name(s) of THIS engagement's session-anchor "
            "cookie(s) — the cookie whose value identifies a distinct login and that "
            "the server sets to `deleted` on logout. Engagement-specific: Vigil "
            "assumes no default. Example: --anchor-cookie SESSIONID --anchor-cookie "
            "AUTHTOKEN."
        ),
    )
    auth_keepalive.add_argument(
        "--probe-url",
        dest="probe_url",
        help=(
            "REQUIRED. Authed URL to GET each cycle (an endpoint that returns logged-"
            "in content). Matched against material.liveness when present, else the "
            "default HTTP-200/no-sessionExpired check."
        ),
    )
    auth_keepalive.add_argument(
        "--interval",
        type=int,
        default=285,
        help="Seconds between cycles; keep below the target's idle window (default: 285).",
    )
    auth_keepalive.add_argument(
        "--iters",
        type=int,
        default=120,
        help="Number of cycles to run (default: 120, i.e. ~9.5h at 285s).",
    )
    auth_keepalive.add_argument(
        "--caps",
        type=int,
        default=4,
        help="Freshest captures to probe per cycle when auto-resolving (default: 4).",
    )
    auth_keepalive.add_argument(
        "--log",
        dest="log",
        help="Log path (default: <engagement>/tools/keepalive.log).",
    )
    auth_keepalive.add_argument(
        "--detach",
        action="store_true",
        help=(
            "Fork into a background daemon (double-fork), write a PID file under "
            "<engagement>/pids/, redirect output to the log, and print the PID."
        ),
    )

    backup_p = sub.add_parser("backup")
    backup_sub = backup_p.add_subparsers(dest="backup_command", required=True)
    backup_sub.add_parser("create")
    backup_sub.add_parser("list")
    backup_show = backup_sub.add_parser("show")
    backup_show.add_argument("backup", nargs="?")
    backup_restore = backup_sub.add_parser("restore")
    backup_restore.add_argument("backup")
    backup_restore.add_argument("--force", action="store_true")

    oob_p = sub.add_parser(
        "oob",
        help="Out-of-band (OAST) callback infra for blind vulns (SSRF, blind XSS, cmdi, XXE).",
        description=(
            "Manage the out-of-band application security testing (OAST) callback "
            "infrastructure and correlate blind-vuln callbacks to the requests that "
            "triggered them.\n\n"
            "Workflow (mint -> poll -> correlate):\n"
            "  1. Bring up the shared server + tunnel once per host:  vigil oob start\n"
            "  2. Start a per-agent listener:                         vigil oob client start <name> --engagement <key>\n"
            "  3. Mint a unique callback URL and record the probe:    vigil oob mint --client <name> --technique ssrf ...\n"
            "  4. Fire the payload carrying that URL at the target (via your normal request tooling).\n"
            "  5. Read the listener log and correlate hits to probes: vigil oob poll --client <name>\n\n"
            "`start/stop/restart/status/test` operate the shared server; `client` "
            "manages per-agent listeners; `mint`/`poll` are the per-probe correlate loop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    oob_sub = oob_p.add_subparsers(dest="oob_command", required=True)
    oob_sub.add_parser(
        "start",
        help="Start the shared OOB server + frp tunnel (idempotent; one per host).",
    )
    oob_sub.add_parser(
        "stop",
        help="Stop the shared OOB server sessions.",
    )
    oob_sub.add_parser(
        "restart",
        help="Stop then start the shared OOB server (e.g. to pick up config changes).",
    )
    oob_status_p = oob_sub.add_parser(
        "status",
        help="Report OOB server + client health and the effective callback domain.",
    )
    oob_status_p.add_argument("--json", action="store_true")
    oob_sub.add_parser(
        "test",
        help="Fire a self-test callback to confirm the OOB server is reachable end-to-end.",
    )
    oob_clean_p = oob_sub.add_parser(
        "clean",
        help="Remove OOB client logs/metadata for non-running clients older than N days.",
        description=(
            "Manual retention cleanup. Deletes the log, metadata, and session files for OOB "
            "clients that are NOT currently running AND whose every artifact is older than "
            "--days days. Running clients, and any client touched within the window, are never "
            "removed. Use --dry-run to preview what would go.\n\n"
            "  vigil oob clean                 # remove non-running clients idle > 5 days\n"
            "  vigil oob clean --days 14        # keep the last two weeks\n"
            "  vigil oob clean --dry-run        # preview only, delete nothing"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    oob_clean_p.add_argument(
        "--days", type=int, default=5,
        help="Age threshold in days (default 5); non-running clients idle longer than this are removed.",
    )
    oob_clean_p.add_argument("--dry-run", action="store_true", help="List what would be removed without deleting.")
    oob_clean_p.add_argument("--json", action="store_true", help="Emit the cleanup summary as JSON.")
    oob_mint = oob_sub.add_parser(
        "mint",
        help="Mint a unique OAST nonce callback URL and record a probe to the backend.",
    )
    oob_mint.add_argument("--engagement")
    oob_mint.add_argument("--select", action="store_true")
    oob_mint.add_argument(
        "--client",
        default=None,
        help="Running OOB client whose interactsh id the nonce binds under so `poll` can see the hit "
        "(see `vigil oob client list`). Optional when exactly one client is running; required to disambiguate.",
    )
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
        help="OOB client name whose interaction log to read (see `vigil oob client list`).",
    )
    oob_poll.add_argument("--lines", type=int, default=2000, help="Tail this many log lines (default 2000).")
    oob_poll.add_argument("--json", action="store_true", help="Emit matched/unmatched correlation result as JSON.")
    oob_client = oob_sub.add_parser(
        "client",
        help="Manage per-agent interactsh listeners that receive OOB callbacks.",
        description=(
            "Manage the named per-agent interactsh listeners. Each listener owns a "
            "correlation id that `vigil oob mint --client <name>` binds nonces under "
            "so `vigil oob poll --client <name>` can see and correlate the callbacks."
        ),
    )
    oob_client_sub = oob_client.add_subparsers(dest="oob_client_command", required=True)
    oob_client_start = oob_client_sub.add_parser(
        "start",
        help="Start a named interactsh listener (registers its callback host).",
    )
    oob_client_start.add_argument("name")
    oob_client_start.add_argument("--engagement")
    oob_client_start.add_argument("--select", action="store_true")
    oob_client_start.add_argument("--agent")
    oob_client_logs = oob_client_sub.add_parser(
        "logs",
        help="Tail a listener's raw interaction log (use --follow to stream).",
    )
    oob_client_logs.add_argument("name")
    oob_client_logs.add_argument("--follow", action="store_true")
    oob_client_logs.add_argument("--lines", default="80")
    oob_client_stop = oob_client_sub.add_parser(
        "stop",
        help="Stop a named interactsh listener.",
    )
    oob_client_stop.add_argument("name")
    oob_client_sub.add_parser(
        "list",
        help="List configured listeners and whether each is running.",
    )

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
            # Stamp the source commit synced into the working root so `vigil
            # status` can later warn when the install lags its source (I-5).
            write_install_meta(result.install_root, source_root)
        print(result.install_root)
        if not args.dry_run:
            _print_post_install(result)
    elif args.command == "doctor":
        print_doctor(collect_doctor_checks(install_root, runner=docker_run_command))
    elif args.command == "status":
        print_status(collect_status(install_root, runner=docker_run_command), json_output=args.json)
    elif args.command == "quickstart":
        exit_code = run_quickstart(
            QuickstartOptions(
                install_root=install_root,
                non_interactive=args.non_interactive,
                assume_yes=args.assume_yes,
                install_host_tools=args.install_host_tools,
                dry_run=args.dry_run,
                json_output=args.json,
                target=args.target,
                hosts=args.hosts,
            )
        )
        if exit_code:
            raise SystemExit(exit_code)
    elif args.command == "up":
        if args.yes_restart_runtime and args.no_restart_runtime:
            raise SystemExit("Specify only one of --yes-restart-runtime or --no-restart-runtime.")
        if args.engagement or args.select:
            print(
                "[vigil] `vigil up --engagement/--select` is a no-op now; the proxy serves every active engagement.",
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
    elif args.command == "use":
        _use(args, install_root)
    elif args.command == "engagement":
        _engagement(args, install_root)
    elif args.command == "blue":
        blue_module.run_blue(args, install_root)
    elif args.command == "bench":
        bench_module.run_bench(args, install_root)
    elif args.command == "orchestrator":
        _orchestrator(args, install_root)
    elif args.command == "runtime":
        _runtime(args, install_root)
    elif args.command == "mitmproxy":
        _mitmproxy(args, install_root)
    elif args.command == "email":
        _email(args)
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


def _use(args: argparse.Namespace, install_root: Path) -> None:
    """Set (or clear) the persisted active-engagement pointer.

    Writes both ~/.config/vigil/config.json:active_engagement_dir and the
    <engagements_root>/.active mirror. Ranked BELOW cwd walk-up in the resolver,
    so it is a durable default, never an override of where you actually are.
    """
    if getattr(args, "clear", False):
        clear_active_engagement(install_root)
        print("[vigil] active-engagement pointer cleared.", file=sys.stderr)
        return
    key = getattr(args, "key", None)
    select = getattr(args, "select", False)
    if not key and not select:
        raise SystemExit("Specify an engagement key, --select, or --clear.")
    path = resolve_engagement_path(install_root, key=key, select=select)
    resolved = set_active_engagement(install_root, path)
    print(f"[vigil] active engagement: {resolved.name}", file=sys.stderr)
    print(resolved)


def _engagement_current(install_root: Path) -> None:
    """Print the resolved active engagement and which tier won.

    Authoritative answer to "which engagement is active right now" — ends the
    guesswork and surfaces a stale $ENGAGEMENT_DIR mismatch.
    """
    env_dir = os.environ.get("ENGAGEMENT_DIR")
    pointer = config_module.get_config_value("active_engagement_dir")
    result = resolve_current_engagement()
    if result is None:
        print("No active engagement resolved.", file=sys.stderr)
        print(f"  cwd walk-up: (no scope.json ancestor of {Path.cwd()})", file=sys.stderr)
        print(f"  active pointer: {pointer or '(unset)'}", file=sys.stderr)
        print(f"  $ENGAGEMENT_DIR: {env_dir or '(unset)'}", file=sys.stderr)
        raise SystemExit(
            "Set one with `vigil use <key>`, run from inside an engagement, or pass --engagement-dir."
        )
    path, tier = result
    tier_label = {
        "cwd": "cwd walk-up",
        "pointer": "active pointer",
        "env": "$ENGAGEMENT_DIR",
    }.get(tier, tier)
    print(f"[vigil] active engagement: {path.name}  (resolved from {tier_label})", file=sys.stderr)
    print(path)


def _logs(args: argparse.Namespace, install_root: Path) -> None:
    if args.target == "all":
        if args.follow:
            raise SystemExit("`vigil logs all --follow` is not supported; follow one target at a time.")
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
        _docker_logs(default_runtime_container(), args.lines, args.follow)
    elif args.target == "mitmproxy":
        _docker_logs("vigil-proxy", args.lines, args.follow)
    elif args.target == "oob":
        tail_flag = "-f" if args.follow else ""
        command = f"tail -n {shlex.quote(str(args.lines))} {tail_flag} {OOB_ROOT}/*.log {OOB_ROOT}/clients/*.log 2>/dev/null || true"
        subprocess.run(["docker", "exec", default_runtime_container(), "sh", "-lc", command], check=False)


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
        _engagement_create(args, install_root)
    elif command == "set-header":
        headers = set_engagement_header(install_root, args.key, args.header)
        print(f"[vigil] {args.key} required_headers: {json.dumps(headers)}", file=sys.stderr)
    elif command == "unset-header":
        headers = unset_engagement_header(install_root, args.key, args.name)
        print(f"[vigil] {args.key} required_headers: {json.dumps(headers)}", file=sys.stderr)
    elif command == "add-oos":
        entries = add_out_of_scope(install_root, args.key, args.entries)
        print(f"[vigil] {args.key} out_of_scope: {json.dumps(entries)}", file=sys.stderr)
    elif command == "remove-oos":
        entries = remove_out_of_scope(install_root, args.key, args.entry)
        print(f"[vigil] {args.key} out_of_scope: {json.dumps(entries)}", file=sys.stderr)
    elif command == "path":
        print(_resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select))
    elif command == "use":
        _use(args, install_root)
    elif command == "current":
        _engagement_current(install_root)
    elif command == "cd-init":
        print(print_shell_cd_init(args.shell), end="")
    elif command == "start":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        client_args = args.client_args[1:] if args.client_args[:1] == ["--"] else args.client_args
        if args.client == "opencode":
            from .engagements import write_opencode_reasoning_config
            write_opencode_reasoning_config(path, args.thinking)
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
        if getattr(args, "export_format", "tar.gz") == "markdown-tree":
            from .engagements import export_engagement_tree

            output = (
                Path(args.output).expanduser()
                if args.output
                else install_root / ".runtime-data" / "exports" / f"{path.name}-findings"
            )
            with _build_assessment_client(install_root, path.name) as client:
                result = export_engagement_tree(client, output, fmt="markdown-tree")
            print(f"[vigil] exported {result.finding_count} finding(s) to {result.output_root}", file=sys.stderr)
            print(result.output_root)
        else:
            output = Path(args.output).expanduser() if args.output else install_root / ".runtime-data" / "exports" / f"{path.name}.tar.gz"
            output.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(output, "w:gz") as tar:
                tar.add(path, arcname=path.name)
            print(output)
    elif command == "export-pdf":
        path = _resolve_current_or_selected_engagement(install_root, key=args.key, select=args.select)
        pdf_output = Path(args.output).expanduser() if args.output else None
        print(export_pdf(path, pdf_output))
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
                    print(f"[vigil] {prefix}: {entry['key']} code_phase -> {entry['to']}")


def _engagement_create(args: argparse.Namespace, install_root: Path) -> None:
    interactive = not args.no_prompt and sys.stdin.isatty()
    positional = args.target_or_name
    target = args.target
    name = args.name
    hosts = _collect_hosts(args)
    artifacts = list(args.apk or [])
    android_package = args.package_name

    asked = False
    engagement_type = args.type
    if engagement_type is None:
        engagement_type = _infer_engagement_type(
            positional,
            target=target,
            hosts=hosts,
            repos=args.repo,
            apks=args.apk,
            package_name=android_package,
        )
        if engagement_type is not None:
            print(f"[vigil] inferred type: {engagement_type} (pass --type to override)", file=sys.stderr)
        elif interactive:
            engagement_type = _prompt_choice("Engagement type", "web", ["web", "code", "both", "android"])
            asked = True
        else:
            described = repr(positional) if positional else "the provided flags"
            raise SystemExit(
                f"cannot infer engagement type from {described}; pass --type web|code|both|android "
                "(blue engagements: vigil blue engage)"
            )

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

    if interactive:
        if engagement_type in {"web", "both"} and not target and not hosts:
            target = _ask_required("Target URL or host")
            asked = True
        if engagement_type in {"code", "both"} and not name:
            name = _ask_required("Engagement name")
            asked = True
        if engagement_type == "android" and not name and not android_package and not artifacts:
            name = _ask_required("Engagement name")
            asked = True
        # Required attribution header + out-of-scope carve-outs apply to HTTP
        # (web/both) engagements. A program-mandated header is security-relevant
        # and easy to forget, so the interactive wizard always offers it unless
        # the operator already passed the flag (or --no-prompt / a non-TTY).
        # android (APK) engagements are excluded — pass --program/--header
        # explicitly for those. Mutating `args` here lets the normal
        # resolve_required_headers/resolve_out_of_scope path pick them up.
        if engagement_type in {"web", "both"}:
            if not args.program and not args.header:
                header_choice = _prompt_choice(
                    "Required attribution header (some programs, e.g. BugCrowd, mandate one on all traffic)",
                    "none",
                    [*PROGRAM_HEADER_PRESETS, "custom", "none"],
                )
                if header_choice in PROGRAM_HEADER_PRESETS:
                    args.program = header_choice
                    args.researcher = _ask_required(
                        f"Researcher handle (sent as {PROGRAM_HEADER_PRESETS[header_choice]}: <handle>)"
                    )
                    asked = True
                elif header_choice == "custom":
                    args.header.append(_ask_required('Header (e.g. "X-Bug-Bounty: vigiloss")'))
                    asked = True
            if not args.out_of_scope:
                oos_raw = _ask_optional(
                    "Out-of-scope carve-outs (space-separated host / *.wildcard, blank for none)"
                )
                if oos_raw:
                    args.out_of_scope.extend(oos_raw.split())
                    asked = True
    required_headers = resolve_required_headers(args.program, args.researcher, args.header)
    out_of_scope = resolve_out_of_scope(args.out_of_scope)
    rate_limit = resolve_rate_limit(args.rate_limit)

    # Dry runs skip the summary + confirmation: nothing will be created either
    # way, and the dry-run path prints its own plan summary.
    if interactive and asked and not args.dry_run:
        _print_create_summary(
            engagement_type,
            target=target,
            name=name,
            hosts=hosts,
            repos=args.repo,
            artifacts=artifacts,
            android_package=android_package,
            required_headers=required_headers,
            out_of_scope=out_of_scope,
            rate_limit=rate_limit,
        )
        if not _confirm("Create engagement? [Y/n]"):
            raise SystemExit("aborted: engagement not created")

    options = CreateEngagementOptions(
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
        required_headers=required_headers,
        out_of_scope=out_of_scope,
        rate_limit=rate_limit,
    )

    if args.dry_run:
        # Validation and derivation only — no directory, snapshot, or
        # backend contact. stdout stays empty in text mode so scripted
        # `eng=$(vigil engagement create ...)` callers can never mistake a
        # dry run for a created engagement.
        plan = plan_engagement(options)
        if args.json:
            payload = {
                "dry_run": True,
                "engagement_type": plan.engagement_type,
                "label": plan.label,
                "scope": plan.scope,
                "manifest": plan.manifest,
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print("[vigil] dry-run: no engagement created", file=sys.stderr)
            scope_hosts = plan.scope.get("hosts")
            _print_create_summary(
                plan.engagement_type,
                target=str(plan.manifest.get("target") or ""),
                name=plan.report_name,
                hosts=[str(host) for host in scope_hosts] if isinstance(scope_hosts, list) else [],
                repos=[repo["path"] for repo in plan.repos],
                artifacts=artifacts,
                android_package=android_package,
                required_headers=required_headers,
                out_of_scope=out_of_scope,
                rate_limit=rate_limit,
            )
        return

    created = create_engagement(options)
    if args.json:
        scope = json.loads((created.path / "scope.json").read_text(encoding="utf-8"))
        payload = {
            "key": created.key,
            "path": str(created.path),
            "engagement_type": str(scope.get("engagement_type") or ""),
            "scope": scope,
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(created.path)


def _collect_hosts(args: argparse.Namespace) -> list[str]:
    """Merge --hosts (csv), repeatable --host, and --hosts-file, deduped in order."""
    hosts = [item.strip() for item in (args.hosts or "").split(",") if item.strip()]
    # --host also splits on commas: before it existed, `--host a,b` reached
    # --hosts via argparse prefix abbreviation, so keep that spelling working.
    for entry in args.host or []:
        hosts.extend(item.strip() for item in entry.split(",") if item.strip())
    if args.hosts_file:
        path = Path(args.hosts_file).expanduser()
        if not path.is_file():
            raise SystemExit(f"--hosts-file: file not found: {path}")
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"--hosts-file: cannot read {path}: {exc}") from exc
        for line in content.splitlines():
            entry = line.strip()
            if entry and not entry.startswith("#"):
                hosts.append(entry)
    return list(dict.fromkeys(hosts))


def _infer_engagement_type(
    positional: str | None,
    *,
    target: str | None,
    hosts: list[str],
    repos: list[str],
    apks: list[str],
    package_name: str | None,
) -> str | None:
    """Infer the engagement type from corroborating evidence, or None.

    Returns None when the inputs are ambiguous (e.g. a bare name with no
    repo/host/APK evidence) — the caller then asks interactively or fails
    with a clear message instead of silently defaulting, which used to
    misclassify bare names as code engagements.
    """
    android_evidence = bool(apks) or bool(package_name) or bool(positional and _looks_like_android_artifact(positional))
    if android_evidence:
        return "android"
    web_evidence = bool(target) or bool(hosts) or bool(positional and _looks_like_web_target(positional))
    code_evidence = bool(repos)
    if web_evidence and code_evidence:
        return "both"
    if web_evidence:
        return "web"
    if code_evidence:
        return "code"
    return None


def _read_line() -> str:
    try:
        return input()
    except EOFError as exc:
        raise SystemExit("stdin closed during interactive prompt; pass the missing flags or --no-prompt") from exc


def _ask_required(label: str, *, attempts: int = 3) -> str:
    """Prompt on stderr for a required value, re-asking on empty input.

    Prompts never touch stdout so `eng=$(vigil engagement create ...)` works
    even when the wizard engages.
    """
    for _ in range(attempts):
        print(f"{label}: ", end="", file=sys.stderr, flush=True)
        value = _read_line().strip()
        if value:
            return value
        print("A value is required.", file=sys.stderr)
    raise SystemExit(f"{label} is required")


def _ask_optional(label: str) -> str:
    """Prompt on stderr for an optional value; empty input returns "".

    Like `_ask_required` but never re-asks and never raises — a blank answer is
    a valid "skip". Prompts stay on stderr so command substitution still works.
    """
    print(f"{label}: ", end="", file=sys.stderr, flush=True)
    return _read_line().strip()


def _confirm(prompt: str) -> bool:
    print(f"{prompt} ", end="", file=sys.stderr, flush=True)
    return _read_line().strip().lower() in {"", "y", "yes"}


def _print_create_summary(
    engagement_type: str,
    *,
    target: str | None,
    name: str | None,
    hosts: list[str],
    repos: list[str],
    artifacts: list[str],
    android_package: str | None,
    required_headers: dict[str, str] | None = None,
    out_of_scope: list[str] | None = None,
    rate_limit: float | None = None,
) -> None:
    print("[vigil] engagement summary:", file=sys.stderr)
    print(f"[vigil]   type:      {engagement_type}", file=sys.stderr)
    if target:
        print(f"[vigil]   target:    {target}", file=sys.stderr)
    if name:
        print(f"[vigil]   name:      {name}", file=sys.stderr)
    if hosts:
        print(f"[vigil]   hosts:     {', '.join(hosts)}", file=sys.stderr)
    if repos:
        print(f"[vigil]   repos:     {', '.join(repos)}", file=sys.stderr)
    if artifacts:
        print(f"[vigil]   artifacts: {', '.join(artifacts)}", file=sys.stderr)
    if android_package:
        print(f"[vigil]   package:   {android_package}", file=sys.stderr)
    if required_headers:
        rendered = ", ".join(f"{k}: {v}" for k, v in required_headers.items())
        print(f"[vigil]   headers:   {rendered}", file=sys.stderr)
    if out_of_scope:
        print(f"[vigil]   out-of-scope: {', '.join(out_of_scope)}", file=sys.stderr)
    if rate_limit is not None:
        print(
            f"[vigil]   rate-limit: {rate_limit:g} req/s "
            "(global per-invocation; bounds per-host as a side effect)",
            file=sys.stderr,
        )


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
        os.execvp("docker", ["docker", "exec", "-it", default_runtime_container(), "bash"])
    elif args.runtime_command == "shell-exec":
        _runtime_shell_exec(args.shell_command)
    elif args.runtime_command == "resources":
        vigil_runtime_resources(json_output=args.json)


def _runtime_shell_exec(command_parts: list[str]) -> None:
    if command_parts[:1] == ["--"]:
        command_parts = command_parts[1:]
    if not command_parts:
        raise SystemExit("Specify a command string for `vigil runtime shell-exec`.")
    command = command_parts[0] if len(command_parts) == 1 else " ".join(shlex.quote(part) for part in command_parts)
    if not command.strip():
        raise SystemExit("Specify a non-empty command string for `vigil runtime shell-exec`.")
    try:
        result = subprocess.run(["docker", "exec", default_runtime_container(), "sh", "-lc", command], check=False)
    except FileNotFoundError as exc:
        raise SystemExit("docker CLI not found on PATH") from exc
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def _mitmproxy(args: argparse.Namespace, install_root: Path) -> None:
    engagements_root = install_root / "agent" / "engagements"
    if args.mitmproxy_command == "start":
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
        print("docker cp vigil-proxy:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem")
        print("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem")
    elif args.mitmproxy_command == "reload":
        request_proxy_reload(engagements_root)
        print(f"[vigil] mitmproxy reload requested ({engagements_root})")
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


def _email(args: argparse.Namespace) -> None:
    """Read recent Mail.app messages for a mailbox and optionally extract a code."""
    if args.within <= 0:
        raise SystemExit("--within must be a positive number of minutes")
    if args.limit <= 0:
        raise SystemExit("--limit must be a positive integer")
    if args.timeout_seconds <= 0:
        raise SystemExit("--timeout-seconds must be > 0")

    cutoff = email_module.cutoff_for_window(args.within)
    try:
        messages = email_module.read_messages(
            since=cutoff,
            limit=args.limit,
            timeout_seconds=args.timeout_seconds,
        )
        matched = email_module.filter_messages(
            messages,
            mailbox_address=args.mailbox,
            from_filter=args.from_filter,
            since=cutoff,
        )
        # Extract when a regex is given, when --extract is set, or always in
        # JSON mode (the automation wants a candidate `extracted` field).
        do_extract = bool(args.match) or args.extract or args.json
        pattern = args.match or email_module.DEFAULT_CODE_PATTERN
        extracted_by_id = {}
        if do_extract:
            for index, message in enumerate(matched):
                extracted_by_id[index] = email_module.extract_token(
                    message.body, pattern=pattern
                )
    except email_module.EmailReadError as exc:
        raise SystemExit(f"error: {exc}") from exc

    if args.json:
        payload = {
            "mailbox": args.mailbox,
            "from": args.from_filter,
            "within_minutes": args.within,
            "cutoff": cutoff.isoformat(),
            "count": len(matched),
            "messages": [
                email_module.message_to_dict(message, extracted=extracted_by_id.get(index))
                for index, message in enumerate(matched)
            ],
        }
        print(json.dumps(payload, indent=2))
        return

    if not matched:
        print(
            f"no messages to {args.mailbox} in the last {args.within} minute(s)",
            file=sys.stderr,
        )
        raise SystemExit(1)

    for index, message in enumerate(matched):
        timestamp = message.received_at.isoformat()
        extracted = extracted_by_id.get(index) if do_extract else None
        line = f"{timestamp}\t{message.sender}\t{message.subject}"
        if do_extract:
            line += f"\t{extracted if extracted is not None else '-'}"
        print(line)


def _mcp(args: argparse.Namespace) -> None:
    """Stub: Kali MCP support was removed in the typed-CLI cutover."""
    print(
        "vigil mcp install/status/uninstall/remove/repair were removed in the typed-CLI cutover.",
        file=sys.stderr,
    )
    print(
        "Use `vigil assess kali ...` for target-facing tool execution and `vigil runtime status` "
        "or `vigil runtime resources` for runtime visibility.",
        file=sys.stderr,
    )
    raise SystemExit(2)


def _auth(args: argparse.Namespace, install_root: Path) -> None:
    engagement = _resolve_command_engagement(install_root, args)
    identity = getattr(args, "identity", None)
    if args.auth_command == "status":
        print(auth_module.status_line(engagement))
        if getattr(args, "probe", False):
            probe_url = getattr(args, "probe_url", None)
            if not probe_url:
                raise SystemExit("--probe requires --probe-url <url>")
            result = auth_module.probe_liveness(engagement, probe_url, identity)
            detail = f"reason={result.get('reason')}"
            if result.get("http_status") is not None:
                detail += f"\thttp_status={result['http_status']}"
            if result.get("error"):
                detail += f"\terror={result['error']}"
            # WS4 opt-in persistence: when a SPECIFIC identity is probed, persist
            # the classified verdict (live->available, dead->dead, unknown leaves
            # state untouched — never a false verdict). The active-identity probe
            # (no --identity) stays read-only.
            if identity:
                persisted = auth_module.persist_liveness(
                    engagement, identity, result["liveness"]
                )
                detail += f"\tpersisted={bool(persisted)}"
            print(f"liveness={result['liveness']}\t{detail}")
    elif args.auth_command == "show":
        print(json.dumps(auth_module.read_auth(engagement), indent=2, sort_keys=True))
    elif args.auth_command == "export":
        print(auth_module.export_curl_args(
            engagement, identity, host=getattr(args, "host", None), method=getattr(args, "method", None)
        ))
    elif args.auth_command == "edit":
        auth_module.edit_auth(engagement, identity)
    elif args.auth_command == "clear":
        clear_all = bool(getattr(args, "all", False))
        auth_module.clear_auth(engagement, identity, all_identities=clear_all)
        if clear_all:
            print(f"cleared ALL credentials for {engagement.name}")
        else:
            scope = f" (identity={identity})" if identity else " (active identity)"
            print(f"cleared credentials for {engagement.name}{scope}")
    elif args.auth_command == "set-active":
        assert identity is not None  # argparse marks --identity required here
        auth_module.set_active(engagement, identity)
        print(f"active identity for {engagement.name}: {identity}")
    elif args.auth_command == "import":
        auth_module.import_auth(engagement, args.source, identity or auth_module.DEFAULT_IDENTITY)
        print(f"imported credentials into {engagement.name} (identity={identity or auth_module.DEFAULT_IDENTITY})")
    elif args.auth_command == "keepalive":
        # ``--identity`` is action="append" here, so ``args.identity`` is a list
        # (or None) — the per-login anchor auto-resolution kicks in when it's empty.
        auth_module.keepalive(
            engagement,
            identities=getattr(args, "identity", None),
            anchor_cookies=getattr(args, "anchor_cookie", None),
            interval=args.interval,
            iters=args.iters,
            caps=args.caps,
            probe_url=getattr(args, "probe_url", None),
            log_path=getattr(args, "log", None),
            detach=bool(getattr(args, "detach", False)),
        )


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


def _print_oob_status(payload: dict[str, object], *, as_json: bool) -> None:
    """Render `vigil oob status` and make a non-ok health loud + machine-detectable.

    Liveness used to print green even when every client was failing to register;
    now a ``degraded``/``down`` health prints its issues to stderr and exits
    non-zero so scripts/agents that gate on OOB readiness catch the outage
    instead of proceeding into blind tests with no working callback path.
    """
    health = str(payload.get("health", ""))
    running_raw = payload.get("running")
    running: list[object] = running_raw if isinstance(running_raw, list) else []
    ch_raw = payload.get("client_health")
    client_health: list[object] = ch_raw if isinstance(ch_raw, list) else []
    registered = sum(1 for c in client_health if isinstance(c, dict) and c.get("registered"))
    if as_json:
        print(json.dumps(payload, indent=2))
    else:
        clients = payload.get("clients")
        client_count = len(clients) if isinstance(clients, list) else 0
        resolves = payload.get("domain_resolves")
        resolves_str = "n/a" if resolves is None else str(bool(resolves)).lower()
        print(
            f"{payload.get('state')}\thealth={health}\tserver={payload.get('server')}\tfrpc={payload.get('frpc')}"
            f"\tclients={client_count}\trunning={len(running)}\tregistered={registered}/{len(running)}"
            f"\tdomain_resolves={resolves_str}\tdomain={payload.get('domain')}"
        )
    issues = payload.get("issues") or []
    if isinstance(issues, list):
        for issue in issues:
            print(f"  ! {issue}", file=sys.stderr)
    if health in {"degraded", "down"}:
        raise SystemExit(1)


def _print_oob_clean(payload: dict[str, object], *, as_json: bool) -> None:
    """Render `vigil oob clean`: a one-line summary plus the pruned client names."""
    if as_json:
        print(json.dumps(payload, indent=2))
        return
    clients_raw = payload.get("clients")
    clients = clients_raw if isinstance(clients_raw, list) else []
    files_raw = payload.get("files")
    files = files_raw if isinstance(files_raw, list) else []
    days = payload.get("max_age_days")
    dry = bool(payload.get("dry_run"))
    if not clients:
        print(f"oob clean\tnothing to remove — no non-running clients older than {days}d")
        return
    verb = "would remove" if dry else "removed"
    suffix = " [dry-run]" if dry else ""
    print(f"oob clean\t{verb} {len(clients)} client(s), {len(files)} file(s) older than {days}d{suffix}")
    for name in clients:
        print(f"  - {name}")


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
        _print_oob_status(payload, as_json=args.json)
    elif args.oob_command == "test":
        test_oob(options, runner=docker_run_command)
    elif args.oob_command == "clean":
        payload = clean_oob_clients(max_age_days=args.days, dry_run=args.dry_run, runner=docker_run_command)
        _print_oob_clean(payload, as_json=args.json)
    elif args.oob_command == "mint":
        _oob_mint(args, install_root, options)
    elif args.oob_command == "poll":
        _oob_poll(args, install_root, options)
    elif args.oob_command == "client":
        _oob_client(args, install_root, options)


def _tmux_has_oob_client(name: str) -> bool:
    result = docker_run_command(["docker", "exec", default_runtime_container(), "sh", "-lc", f"tmux has-session -t oob-client-{shlex.quote(name)} 2>/dev/null"])
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
        subprocess.run(["docker", "exec", default_runtime_container(), "sh", "-lc", command], check=False)
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
# `secrets`. Kept at module scope so `vigil oob mint` stays seedable without
# threading a factory argument through argparse.
_oob_nonce_token_factory = None


def _build_assessment_client(install_root: Path, engagement_key: str):
    """Construct an AssessmentClient (used as a context manager) for the
    given engagement, reusing the same orchestrator base-url resolution as
    the rest of the CLI and the assess library shipped under agent/scripts.

    The import is deferred and path-bridged (via ``paths.add_assess_import_path``)
    so the installable ``src`` package keeps a single source of truth for the
    HTTP client without a hard dependency on the agent tree at import time.
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
            "Run from a source checkout or a completed `vigil install`."
        ) from exc
    return AssessmentClient(base_url, engagement_key)


def _resolve_mint_client(args: argparse.Namespace, options: OobOptions) -> tuple[str, str]:
    """Pick the running OOB client to bind a minted nonce under, and resolve its
    interactsh payload host.

    A minted callback only reaches ``vigil oob poll`` when its host carries a
    running client's correlation id, so mint must bind the nonce under one.
    Auto-selects the sole running client; with several, requires ``--client``;
    with none (or one that has not registered yet) it fails with guidance rather
    than emitting an un-pollable bare URL. Returns ``(client_name, payload_host)``.
    """
    running = list_running_oob_clients(runner=docker_run_command)
    if args.client:
        name = sanitize_name(args.client)
        if name not in running:
            raise SystemExit(
                f"OOB client {name!r} is not running, so a minted nonce could not be correlated.\n"
                f"Running clients: {', '.join(running) if running else '(none)'}\n"
                f"Start it:  vigil oob client start {name} --engagement {options_engagement_hint()}"
            )
    elif not running:
        raise SystemExit(
            "No OOB client is running. `vigil oob mint` binds the nonce under a client's interactsh id "
            "so `vigil oob poll` can see the callback (a bare nonce only shows in the raw server log).\n"
            "Start one:  vigil oob client start <name> --engagement <key> --agent <agent>\n"
            "Then check: vigil oob status --json"
        )
    elif len(running) > 1:
        raise SystemExit(
            f"Multiple OOB clients are running ({', '.join(running)}). "
            "Pass --client <name> to choose which one's interactsh id the nonce binds under."
        )
    else:
        name = running[0]
    payload_host = client_payload_host(name, runner=docker_run_command, oob_domain=options.oob_domain)
    if not payload_host:
        raise SystemExit(
            f"OOB client {name!r} is running but has not registered an interactsh payload yet, "
            "so the nonce cannot be bound to it.\n"
            f"Wait for the '<id>.{options.oob_domain}' line, then retry:\n"
            f"  vigil oob client logs {name}"
        )
    return name, payload_host


def options_engagement_hint() -> str:
    """Best-effort current engagement key for error hints (never raises)."""
    current = current_engagement_path()
    return current.name if current else "<key>"


def _oob_mint(args: argparse.Namespace, install_root: Path, options: OobOptions) -> None:
    engagement_path = _resolve_command_engagement(install_root, args)
    engagement_key = engagement_path.name
    client_name, payload_host = _resolve_mint_client(args, options)
    nonce = mint_nonce(prefix=sanitize_name(engagement_key), token_factory=_oob_nonce_token_factory)
    urls = callback_urls(nonce, payload_host)
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
        print(json.dumps(
            {"nonce": nonce, "client": client_name, "payload_host": payload_host, "urls": urls, "probe": record},
            indent=2,
        ))
        return
    print(f"nonce\t{nonce}")
    print(f"client\t{client_name}\t({payload_host})")
    print(f"http\t{urls['http']}")
    print(f"dns\t{urls['dns']}")
    print(f"probe\tid={record.get('id')}\tstatus={record.get('status')}\ttechnique={record.get('technique') or '-'}")
    print(f"note\tfire the EXACT host above; it embeds client '{client_name}', so `vigil oob poll --client {client_name}` correlates the hit")


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


def _prompt_choice(label: str, default: str, choices: list[str], *, attempts: int = 3) -> str:
    for _ in range(attempts):
        print(label, file=sys.stderr)
        for idx, choice in enumerate(choices, start=1):
            suffix = " [default]" if choice == default else ""
            print(f"  {idx}. {choice}{suffix}", file=sys.stderr)
        print("> ", end="", file=sys.stderr, flush=True)
        raw = _read_line().strip()
        if not raw:
            return default
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            return choices[int(raw) - 1]
        if raw in choices:
            return raw
        print(f"Invalid {label.lower()}: {raw}", file=sys.stderr)
    raise SystemExit(f"Invalid {label.lower()}: no valid selection after {attempts} attempts")


if __name__ == "__main__":
    main()
