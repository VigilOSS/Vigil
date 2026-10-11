"""``vigil blue`` — incident-response CLI surface.

Thin wrapper group over the existing ``vigil assess`` verbs plus the
``engagement create``/``engagement list`` flow. The blue surface gives
operators a vocabulary that matches the IR lifecycle (intake → triage →
investigate → verify → respond → report) while every durable write still
lands through the existing red-team backend (assessment_findings,
assessment_dispatches, activity_entries, assessment_artifacts).

Operator prompt / lifecycle reference: ``agent/operator-core-blue.md`` (canonical
blue operator core) and the blue section of the repo ``README.md``.

Critical CLI-verb drift handled here:

* ``vigil assess log-entry`` does NOT exist — the real verb is ``vigil assess log``.
* ``vigil assess finding verify --status`` accepts CLI vocab
  ``{confirmed | downgraded | false_positive | disputed}`` while blue
  specialists speak ``{verified | false_positive | downgraded | escalated}``.
  ``vigil blue verify`` translates blue → CLI for the storage row and
  separately stamps the blue word into ``details.disposition`` so the
  report-writer sees the blue vocabulary verbatim.
* ``vigil assess finding link --intel <id>`` attaches one or more intel
  rows to a finding's ``details.related_intel_ids[]`` (merges with the
  existing list, dedupe-preserve-order). ``vigil blue`` does not wrap
  this directly; specialists call ``vigil assess finding link`` from the
  ioc-enrichment skill.
"""
from __future__ import annotations

import argparse
import email
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .engagements import (
    CreateEngagementOptions,
    create_engagement,
    current_engagement_path,
    list_engagements,
    resolve_engagement_path,
    start_engagement,
    write_opencode_reasoning_config,
)
from .preflight import _preflight_engagement_start
from .paths import agent_root as application_agent_root, tenant_references_root

# Platform → tenant-file suffix. Google Workspace tenant references use the
# descriptive ``workspace`` suffix, while the CLI keeps the familiar ``gws``
# platform spelling. Other platforms map 1:1 today.
PLATFORM_TO_TENANT_SUFFIX: dict[str, str] = {
    "gws": "workspace",
    "m365": "m365",
    "aws": "aws",
    "okta": "okta",
    "edr": "edr",
    "network": "network",
    "generic": "generic",
}

# Blue → CLI disposition. The CLI/storage layer uses red-team vocab; we
# translate at the wrapper level so blue specialists keep their vocabulary
# (and the report-writer reads it verbatim from details.disposition).
BLUE_TO_CLI_DISPOSITION: dict[str, str] = {
    "verified": "confirmed",
    "false_positive": "false_positive",
    "downgraded": "downgraded",
    "escalated": "disputed",
}

CONTAINMENT_BLAST_RADII: frozenset[str] = frozenset(
    {"single-user", "multi-user", "multi-tenant", "cross-platform"}
)

KEBAB_SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")


# ---------------------------------------------------------------------------
# Argument parser registration
# ---------------------------------------------------------------------------


def register_blue_parser(sub: argparse._SubParsersAction) -> None:
    """Register the ``vigil blue`` subcommand group on the top-level parser."""
    blue_p = sub.add_parser(
        "blue",
        help="Incident-response engagement flow (alert intake, triage, contain)",
        description=(
            "Incident-response (blue-team) engagement surface. Lifecycle: "
            "intake -> triage -> investigate -> verify -> respond -> report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "lifecycle: intake -> triage -> investigate -> verify -> respond -> report\n"
            "\n"
            "HUMAN verbs (you, the operator, run these directly):\n"
            "  engage         create a blue engagement (interactive picker if no --customer/--platform)\n"
            "  customers      list customers with tenant references available\n"
            "  tenant init    scaffold a new <customer>-<platform> tenant reference\n"
            "  list           list blue engagements\n"
            "  show           show a blue engagement's status\n"
            "\n"
            "OPERATOR verbs (the LLM operator runs these inside the session):\n"
            "  alert record   record the pasted alert body into scope.json + artifact index\n"
            "  Specialist dispatch: use `vigil assess agent start ... "
            "--prompt-context-json <file> --emit-prompt`; blue tenant refs are "
            "validated and injected from scope.json.\n"
            "  tier           record the current tier on a finding\n"
            "  verify         verify a finding (blue vocab -> CLI storage)\n"
            "  propose-contain  record a containment proposal (operator-approved before execute)\n"
            "  contain        record an approved, already-executed containment action\n"
            "  report         dispatch report-writer to render the incident report\n"
            "  closeout       dispatch report-writer to render a customer-facing closeout\n"
            "\n"
            "Typical human start:\n"
            "  vigil blue engage                                   # interactive picker\n"
            "  vigil blue engage --customer <c> --platform gws --severity high --start codex\n"
        ),
    )
    blue_sub = blue_p.add_subparsers(dest="blue_command", required=True)

    engage_p = blue_sub.add_parser("engage", help="(human) Create a new blue (incident) engagement")
    engage_p.add_argument(
        "--customer",
        required=False,
        default=None,
        help="Customer kebab-case slug, e.g. 'acme' (omit for interactive picker)",
    )
    engage_p.add_argument(
        "--platform",
        required=False,
        default=None,
        help="Comma-separated platforms: gws,m365,aws,okta,edr,network,generic (omit for interactive picker)",
    )
    engage_p.add_argument("--severity", default=None, help="Alert severity hint (low|medium|high|critical|info)")
    engage_p.add_argument("--source", default="operator_chat", help="Alert source (default: operator_chat)")
    engage_p.add_argument("--skip-permissions", action="store_true")
    engage_p.add_argument(
        "--skip-preflight",
        action="store_true",
        help="With --start, launch the client without the preflight checks (client "
             "binary, provider key, orchestrator, runtime container, install freshness).",
    )
    engage_p.add_argument(
        "--start",
        choices=("codex", "claude", "opencode", "goose", "kimi"),
        default=None,
        help=(
            "After creating the engagement, immediately launch the operator session "
            "(replaces this process). CAVEAT: this execs an interactive client, so do "
            "NOT combine it with command substitution — eng=$(vigil blue engage ... --start codex) "
            "would feed the captured path to the client. Scripts capturing the path must omit --start."
        ),
    )

    customers_p = blue_sub.add_parser("customers", help="(human) List customers with tenant references available for blue engagements")
    customers_p.add_argument("--platform", default=None, help="Filter to a platform: gws,m365,aws,okta,edr,network,generic")
    customers_p.add_argument("--json", action="store_true")

    alert_p = blue_sub.add_parser("alert", help="(operator) Manage alert intake on a blue engagement")
    alert_sub = alert_p.add_subparsers(dest="alert_command", required=True)
    alert_record_p = alert_sub.add_parser("record", help="(operator) Record a pasted alert body from a file into scope.json + artifact index")
    alert_record_p.add_argument(
        "--body-file",
        required=True,
        help="Path containing the raw alert text from the operator chat, or '-' to read from stdin (heredoc/pipe)",
    )
    alert_record_p.add_argument("-k", "--engagement-key", default=None)
    alert_record_p.add_argument("--select", action="store_true")
    alert_record_p.add_argument("--external-id", default=None)
    alert_record_p.add_argument("--severity", default=None)
    alert_record_p.add_argument("--source", default=None, help="Alert source override (default: operator_chat)")
    alert_record_p.add_argument("--replace", action="store_true", help="Replace existing alert metadata while preserving prior raw alert files")

    list_p = blue_sub.add_parser("list", help="(human) List blue engagements")
    list_p.add_argument("--customer", default=None)
    list_p.add_argument("--status", default=None)
    list_p.add_argument("--phase", default=None)
    list_p.add_argument("--json", action="store_true")

    show_p = blue_sub.add_parser("show", help="(human) Show blue engagement status")
    show_p.add_argument("engagement_key", nargs="?")
    show_p.add_argument("--select", action="store_true")

    tier_p = blue_sub.add_parser("tier", help="(operator) Record current tier on a finding's details_json")
    tier_p.add_argument("finding_slug")
    tier_p.add_argument("--tier", choices=("L1", "L2", "L3", "L4"), required=True)
    tier_p.add_argument("--notes", default=None)
    tier_p.add_argument("-k", "--engagement-key", default=None)
    tier_p.add_argument("--select", action="store_true")

    verify_p = blue_sub.add_parser("verify", help="(operator) Verify a finding (blue vocab → CLI storage)")
    verify_p.add_argument("finding_slug")
    verify_p.add_argument(
        "--disposition",
        choices=tuple(sorted(BLUE_TO_CLI_DISPOSITION.keys())),
        required=True,
    )
    verify_p.add_argument("--reason", required=True)
    verify_p.add_argument("--evidence-refs", default=None, help="Comma-separated evidence ids")
    verify_p.add_argument(
        "--proof-receipt-id",
        dest="proof_receipt_ids",
        action="append",
        type=int,
        help="Proof-receipt id produced by the independent verifier (repeatable)",
    )
    verify_p.add_argument(
        "--counter-check-file",
        help="Completed structured false-positive counter-check JSON",
    )
    verify_p.add_argument("--new-severity", default=None)
    verify_p.add_argument("--force", action="store_true", help="Bypass the incident-verifier dispatch gate")
    verify_p.add_argument("-k", "--engagement-key", default=None)
    verify_p.add_argument("--select", action="store_true")

    propose_p = blue_sub.add_parser("propose-contain", help="(operator) Record a containment proposal (operator-approved before execute)")
    propose_p.add_argument("finding_slug")
    propose_p.add_argument("--action", required=True, help="Containment verb (revoke_session, reset_cred, disable_account, isolate_host, block_ioc, ...)")
    propose_p.add_argument("--target", required=True, help="Target id (user email, host id, IOC value, ...)")
    propose_p.add_argument("--platform", choices=tuple(sorted(PLATFORM_TO_TENANT_SUFFIX)), required=True)
    propose_p.add_argument("--rollback", required=True, help="Rollback / undo description")
    propose_p.add_argument(
        "--blast-radius",
        choices=tuple(sorted(CONTAINMENT_BLAST_RADII)),
        required=True,
    )
    propose_p.add_argument("--note", default=None)
    propose_p.add_argument("-k", "--engagement-key", default=None)
    propose_p.add_argument("--select", action="store_true")

    contain_p = blue_sub.add_parser(
        "contain",
        help="(operator) Record an approved containment action that was already executed and log the action",
    )
    contain_p.add_argument("finding_slug")
    contain_p.add_argument(
        "--proposal",
        required=True,
        help=(
            "dispatch-decisions row id (decision_id) printed by `vigil blue "
            "propose-contain`. Must already be approved via `vigil assess "
            "approve-proposal <decision-id>`; contain refuses unresolved rows."
        ),
    )
    contain_p.add_argument("--proof-artifact", default=None)
    contain_p.add_argument(
        "--command-run-id",
        type=int,
        default=None,
        help="assessment_command_runs id from the audited host-exec execution; required if --proof-artifact is omitted",
    )
    contain_p.add_argument("--action", default=None, help="(audit) Containment verb echoed into activity_entries metadata")
    contain_p.add_argument("--target", default=None, help="(audit) Containment target echoed into activity_entries metadata")
    contain_p.add_argument("-k", "--engagement-key", default=None)
    contain_p.add_argument("--select", action="store_true")

    report_p = blue_sub.add_parser("report", help="(operator) Dispatch report-writer to render the blue incident report")
    report_p.add_argument("-k", "--engagement-key", default=None)
    report_p.add_argument("--select", action="store_true")
    report_p.add_argument("--template", default=None)

    closeout_p = blue_sub.add_parser("closeout", help="(operator) Dispatch report-writer to render a customer-facing closeout summary")
    closeout_p.add_argument("-k", "--engagement-key", default=None)
    closeout_p.add_argument("--select", action="store_true")
    closeout_p.add_argument("--agent-id", default=None)

    tenant_p = blue_sub.add_parser("tenant", help="(human) Manage tenant reference scaffolds")
    tenant_sub = tenant_p.add_subparsers(dest="tenant_command", required=True)
    tenant_init_p = tenant_sub.add_parser("init", help="(human) Copy a tenant template to a new <customer>-<platform>.md ref")
    tenant_init_p.add_argument("--customer", required=True)
    tenant_init_p.add_argument("--platform", required=True)
    tenant_init_p.add_argument("--force", action="store_true")


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


def run_blue(args: argparse.Namespace, install_root: Path) -> None:
    command = args.blue_command
    if command == "engage":
        _cmd_engage(args, install_root)
    elif command == "customers":
        _cmd_customers(args, install_root)
    elif command == "alert":
        if args.alert_command == "record":
            _cmd_alert_record(args, install_root)
        else:
            raise SystemExit(f"unknown alert subcommand: {args.alert_command}")
    elif command == "list":
        _cmd_list(args, install_root)
    elif command == "show":
        _cmd_show(args, install_root)
    elif command == "tier":
        _cmd_tier(args, install_root)
    elif command == "verify":
        _cmd_verify(args, install_root)
    elif command == "propose-contain":
        _cmd_propose_contain(args, install_root)
    elif command == "contain":
        _cmd_contain(args, install_root)
    elif command == "report":
        _cmd_report(args, install_root)
    elif command == "closeout":
        _cmd_closeout(args, install_root)
    elif command == "tenant":
        if args.tenant_command == "init":
            _cmd_tenant_init(args, install_root)
        else:
            raise SystemExit(f"unknown tenant subcommand: {args.tenant_command}")
    else:
        raise SystemExit(f"unknown blue command: {command}")


# ---------------------------------------------------------------------------
# engage
# ---------------------------------------------------------------------------


def _pick_option(items: list[str], title: str) -> str:
    """Interactive single-select over ``items`` (fzf, else numbered stderr menu).

    Modeled on ``engagements._select_engagement``: prefer ``fzf`` when present,
    otherwise print a numbered menu to stderr and read a 1-based index from
    ``input``. Kept local to blue.py — the row shapes differ from
    ``EngagementRow`` and a shared refactor buys nothing.
    """
    if not items:
        raise SystemExit(f"{title}: no options available")
    if shutil.which("fzf"):
        result = subprocess.run(
            ["fzf", "--prompt", f"{title}> "],
            input="\n".join(items),
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            choice = result.stdout.strip().splitlines()[0]
            if choice in items:
                return choice
    print(f"{title}:", file=sys.stderr)
    for idx, item in enumerate(items, start=1):
        print(f"{idx}. {item}", file=sys.stderr)
    choice = input("> ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(items)):
        raise SystemExit("Invalid selection")
    return items[int(choice) - 1]


def _run_engage_picker(args: argparse.Namespace, install_root: Path) -> None:
    """Fill in missing ``--customer``/``--platform``/``--severity`` on ``args``.

    Non-TTY: raise a ``SystemExit`` listing the available customer/platform
    combinations (or pointing at ``vigil blue tenant init`` when none exist).
    TTY: run an interactive picker.
    """
    rows = _discover_blue_customers(install_root)

    if not sys.stdin.isatty():
        lines = [
            "vigil blue engage: --customer and --platform are required when stdin is not a TTY.",
        ]
        if rows:
            lines.append("Available customer/platform combinations:")
            for row in rows:
                lines.append(f"  {row['customer']}: {','.join(row['platforms'])}")
            example = rows[0]
            lines.append("")
            lines.append(
                f"Example: vigil blue engage --customer {example['customer']} "
                f"--platform {example['platforms'][0]}"
            )
        else:
            lines.append("No tenant references found. Scaffold one first:")
            lines.append("  vigil blue tenant init --customer <slug> --platform <platform>")
        raise SystemExit("\n".join(lines))

    if not rows:
        raise SystemExit(
            "No tenant references found. Scaffold one first:\n"
            "  vigil blue tenant init --customer <slug> --platform <platform>"
        )

    customer = (args.customer or "").strip()
    if not customer:
        customer = _pick_option([str(row["customer"]) for row in rows], "Select customer")
    args.customer = customer

    if not (args.platform or "").strip():
        matching = [r for r in rows if r["customer"] == customer]
        raw_platforms = matching[0]["platforms"] if matching else None
        platforms = (
            list(raw_platforms)
            if isinstance(raw_platforms, list)
            else sorted(PLATFORM_TO_TENANT_SUFFIX)
        )
        if len(platforms) == 1:
            platform = platforms[0]
            print(f"[vigil blue] platform: {platform} (only option)", file=sys.stderr)
        else:
            platform = _pick_option(platforms, "Select platform")
        args.platform = platform

    if not args.severity:
        allowed = ("low", "medium", "high", "critical", "info")
        prompt = "severity (low|medium|high|critical|info, blank = none) > "
        for attempt in range(2):
            raw = input(prompt).strip()
            if not raw:
                break  # blank = no severity hint
            if raw in allowed:
                args.severity = raw
                break
            if attempt == 1:
                raise SystemExit(
                    f"invalid severity {raw!r}; expected one of {', '.join(allowed)} or blank"
                )


def _cmd_engage(args: argparse.Namespace, install_root: Path) -> None:
    if not args.customer or not args.platform:
        _run_engage_picker(args, install_root)

    customer = (args.customer or "").strip()
    if not customer:
        raise SystemExit("--customer is required")
    if not KEBAB_SLUG_RE.match(customer):
        raise SystemExit(
            f"--customer must be lowercase kebab-case (got {customer!r}). "
            "Example: --customer acme"
        )

    raw_platforms = [piece.strip() for piece in (args.platform or "").split(",") if piece.strip()]
    if not raw_platforms:
        raise SystemExit("--platform must list at least one platform (comma-separated)")
    bad = [p for p in raw_platforms if p not in PLATFORM_TO_TENANT_SUFFIX]
    if bad:
        raise SystemExit(
            f"unsupported platform(s): {bad}. "
            f"Supported: {sorted(PLATFORM_TO_TENANT_SUFFIX.keys())}"
        )

    tenant_dir = tenant_references_root(install_root)
    resolved_paths: list[str] = []
    missing: list[tuple[str, list[Path]]] = []
    for platform in raw_platforms:
        suffix = PLATFORM_TO_TENANT_SUFFIX[platform]
        candidate = tenant_dir / f"{customer}-{suffix}.md"
        alt_candidate = tenant_dir / f"{customer}-{platform}.md" if suffix != platform else None
        if candidate.is_file():
            resolved_paths.append(str(candidate))
        else:
            choices = [candidate]
            if alt_candidate is not None and alt_candidate.is_file():
                resolved_paths.append(str(alt_candidate))
                continue
            if alt_candidate is not None:
                choices.append(alt_candidate)
            missing.append((platform, choices))

    if missing:
        lines = [
            "Missing tenant reference file(s) for blue engagement:",
        ]
        for platform, paths in missing:
            paths_str = " or ".join(str(p) for p in paths)
            lines.append(f"  - platform={platform}: expected {paths_str}")
        lines.append("")
        lines.append("Known customers/platforms: vigil blue customers")
        for platform, _paths in missing:
            lines.append(
                f"Recover by: vigil blue tenant init --customer {customer} --platform {platform}"
            )
        raise SystemExit("\n".join(lines))

    options = CreateEngagementOptions(
        install_root=install_root,
        engagement_type="blue",
        customer=customer,
        platforms=raw_platforms,
        tenant_reference_paths=resolved_paths,
        alert_source=args.source,
        severity_hint=args.severity,
        skip_permissions=getattr(args, "skip_permissions", False),
    )
    created = create_engagement(options)

    if getattr(args, "start", None):
        # Chain straight into the operator session. stdout stays the bare path
        # (the eng=$(vigil blue engage …) contract), then launch hints go to
        # stderr — everything is printed and flushed BEFORE start_engagement,
        # which does os.chdir + os.execv and never returns.
        #
        # create_engagement already printed the key and start command on stderr,
        # so a preflight refusal below leaves the operator able to retry with
        # `vigil engagement start`. The preflight runs BEFORE the stdout path
        # line so a refusal never leaves a bare path behind for `eng=$(…)` to
        # capture as success.
        if not getattr(args, "skip_preflight", False):
            _preflight_engagement_start(install_root, created.path, args.start)
        print(created.path)
        sys.stdout.flush()
        print(f"[vigil blue] launching operator session ({args.start})…", file=sys.stderr)
        print("  Paste the alert into the operator chat; the operator records intake", file=sys.stderr)
        print(
            "  (vigil blue alert record), then dispatches triage with "
            "`vigil assess agent start ... --prompt-context-json <file> --emit-prompt`.",
            file=sys.stderr,
        )
        sys.stderr.flush()
        if args.start == "opencode":
            # Mirror main.py: ensure the opencode permission block exists. A
            # blank level leaves provider options untouched.
            write_opencode_reasoning_config(created.path, "")
        # MUST be the final statement — os.chdir + os.execv, never returns.
        start_engagement(install_root, created.path, args.start, [])
        return

    print(created.path)
    print("next:", file=sys.stderr)
    print("  After starting, paste the alert into the operator chat; the operator records intake", file=sys.stderr)
    print(
        "  (vigil blue alert record), then dispatches triage with "
        "`vigil assess agent start ... --prompt-context-json <file> --emit-prompt`.",
        file=sys.stderr,
    )
    print(f"  Shortcut next time: vigil blue engage --customer {customer} --platform {','.join(raw_platforms)} --start codex", file=sys.stderr)


# ---------------------------------------------------------------------------
# customers
# ---------------------------------------------------------------------------


def _cmd_customers(args: argparse.Namespace, install_root: Path) -> None:
    requested_platform = (args.platform or "").strip()
    if requested_platform and requested_platform not in PLATFORM_TO_TENANT_SUFFIX:
        raise SystemExit(
            f"--platform must be one of {sorted(PLATFORM_TO_TENANT_SUFFIX.keys())} "
            f"(got {requested_platform!r})"
        )

    rows = _discover_blue_customers(install_root)
    if requested_platform:
        rows = [
            row
            for row in rows
            if requested_platform in row["platforms"]
        ]
        rows = [
            {
                "customer": row["customer"],
                "platforms": [requested_platform],
                "tenant_reference_paths": [
                    row["tenant_reference_paths"][row["platforms"].index(requested_platform)]
                ],
            }
            for row in rows
        ]

    if args.json:
        print(json.dumps(rows, indent=2))
        return

    if not rows:
        print("(no blue customers found)", file=sys.stderr)
        return

    print("customer\tplatforms\ttenant_reference_paths")
    for row in rows:
        print(
            f"{row['customer']}\t{','.join(row['platforms'])}\t"
            f"{','.join(row['tenant_reference_paths'])}"
        )


def _discover_blue_customers(install_root: Path) -> list[dict[str, str | list[str]]]:
    tenant_dir = tenant_references_root(install_root)
    if not tenant_dir.is_dir():
        return []

    suffix_to_platform = {suffix: platform for platform, suffix in PLATFORM_TO_TENANT_SUFFIX.items()}
    grouped: dict[str, dict[str, str]] = {}
    for path in sorted(tenant_dir.glob("*.md")):
        if path.name.startswith("_template-"):
            continue
        stem = path.stem
        for suffix, platform in sorted(suffix_to_platform.items(), key=lambda item: len(item[0]), reverse=True):
            marker = f"-{suffix}"
            if not stem.endswith(marker):
                continue
            customer = stem[: -len(marker)]
            if not customer:
                continue
            grouped.setdefault(customer, {})[platform] = str(path)
            break

    rows: list[dict[str, str | list[str]]] = []
    for customer in sorted(grouped):
        platforms = sorted(grouped[customer])
        rows.append(
            {
                "customer": customer,
                "platforms": platforms,
                "tenant_reference_paths": [grouped[customer][platform] for platform in platforms],
            }
        )
    return rows


# ---------------------------------------------------------------------------
# alert record
# ---------------------------------------------------------------------------


def _cmd_alert_record(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    scope_path = eng_dir / "scope.json"
    scope = _read_scope(scope_path, require_blue=True)
    alert_md = dict(scope.get("alert_metadata") or {})
    if (alert_md.get("raw_body") or alert_md.get("parsed")) and not getattr(args, "replace", False):
        raise SystemExit(
            "alert intake already recorded for this engagement. "
            "Create a new engagement for a separate alert, or pass --replace to correct the intake record."
        )

    if args.body_file == "-":
        if sys.stdin.isatty():
            print(
                "[vigil blue] reading alert body from stdin; finish with Ctrl-D",
                file=sys.stderr,
            )
        body = sys.stdin.read()
        if not body.strip():
            raise SystemExit(
                "alert record: stdin body was empty (heredoc/pipe the alert, or pass --body-file <path>)"
            )
    else:
        body_file = Path(args.body_file)
        if not body_file.is_file():
            raise SystemExit(f"alert record: --body-file not found: {body_file}")
        body = body_file.read_text(encoding="utf-8")
        if not body.strip():
            raise SystemExit(f"alert record: --body-file was empty: {body_file}")

    parsed = _parse_alert_body(body)
    now_iso = _utc_now_iso()

    alerts_dir = eng_dir / "ir" / "alerts"
    alerts_dir.mkdir(parents=True, exist_ok=True)
    ts_label = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = (args.external_id or f"alert-{ts_label}") + ".txt"
    # Defensive: filenames from --external-id may carry slashes / colons.
    fname = re.sub(r"[^A-Za-z0-9_.\-]+", "_", fname)
    raw_path = _unique_path(alerts_dir / fname)
    raw_path.write_text(body, encoding="utf-8")

    # Register the alert as an artifact for FTS + chain-of-custody. Failures
    # here are non-fatal (backend may be offline during local-only runs) but
    # we surface a clear warning so the operator can retry.
    register_rc = _run_assess(
        install_root,
        eng_dir,
        ["artifact", "register", str(raw_path), "--kind", "alert_intake"],
        check=False,
    )
    if register_rc != 0:
        print(
            f"WARN vigil blue alert record: artifact register failed (rc={register_rc}); "
            f"alert body persisted at {raw_path} but is not in the artifact index yet. "
            f"Retry with: vigil assess artifact register {raw_path} --kind alert_intake",
            file=sys.stderr,
        )

    log_title = "alert intake"
    log_result = "alert recorded"
    log_rc = _run_assess(
        install_root,
        eng_dir,
        # `vigil assess log` signature: <agent> <title> <action> <result>
        ["log", "operator", log_title, "alert_intake", log_result, "--actor-kind", "operator"],
        check=False,
    )
    if log_rc != 0:
        print(
            f"WARN vigil blue alert record: activity log entry failed (rc={log_rc}). "
            "the raw alert file was written and scope.json will still be updated; rerun "
            "`vigil assess log operator 'alert intake' alert_intake '<msg>' --actor-kind operator` manually if you want the audit row.",
            file=sys.stderr,
        )

    alert_md["source"] = args.source or alert_md.get("source") or "operator_chat"
    if args.external_id:
        alert_md["external_id"] = args.external_id
    alert_md["received_at"] = now_iso
    if args.severity:
        alert_md["severity_hint"] = args.severity
    alert_md["raw_body"] = body
    alert_md["raw_path"] = str(raw_path)
    alert_md["parsed"] = parsed
    scope["alert_metadata"] = alert_md
    _write_json_atomic(scope_path, scope)

    print(str(raw_path))
    print(
        "\nnext: vigil assess agent start --role alert-triage-specialist --tier L1 "
        "--skills alert-triage --rate-budget '<authored tenant query budget>' "
        "--prompt-context-json dispatch-context.json --emit-prompt",
        file=sys.stderr,
    )


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for index in range(2, 1000):
        candidate = path.with_name(f"{stem}-{index}{suffix}")
        if not candidate.exists():
            return candidate
    raise SystemExit(f"could not allocate unique alert path near {path}")


def _parse_alert_body(body: str) -> dict | None:
    stripped = body.lstrip()
    # JSON sniff.
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (dict, list)):
                return {"format": "json", "payload": parsed}
        except json.JSONDecodeError:
            pass
    # EML sniff: header-block followed by blank line.
    head = "\n".join(stripped.splitlines()[:30])
    if re.search(r"^(From|To|Subject):", head, flags=re.MULTILINE):
        try:
            msg = email.message_from_string(body)
            headers = {k: msg.get(k) for k in ("From", "To", "Cc", "Subject", "Date", "Message-ID") if msg.get(k)}
            text_parts: list[str] = []
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        payload = part.get_payload(decode=False)
                        if isinstance(payload, str):
                            text_parts.append(payload)
            else:
                payload = msg.get_payload(decode=False)
                if isinstance(payload, str):
                    text_parts.append(payload)
            return {
                "format": "eml",
                "headers": headers,
                "body_text": "\n".join(text_parts)[:8000],
            }
        except Exception:  # noqa: BLE001 - best-effort parse
            pass
    return None


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------


def _cmd_list(args: argparse.Namespace, install_root: Path) -> None:
    rows = list_engagements(install_root)
    filtered: list[dict] = []
    for row in rows:
        scope = _read_scope(row.path / "scope.json", require_blue=False)
        if scope.get("engagement_type") != "blue":
            continue
        if args.customer and scope.get("customer") != args.customer:
            continue
        if args.status and row.status != args.status:
            continue
        if args.phase and row.current_phase != args.phase:
            continue
        filtered.append(
            asdict(row) | {
                "path": str(row.path),
                "customer": scope.get("customer"),
                "platforms": scope.get("platforms"),
            }
        )
    if args.json:
        print(json.dumps(filtered, indent=2))
        return
    if not filtered:
        print("(no blue engagements matched)", file=sys.stderr)
        return
    for entry in filtered:
        platforms = ",".join(entry.get("platforms") or []) or "-"
        print(
            f"{entry['key']}\t{entry['status']}\t{entry['current_phase']}\t"
            f"{entry.get('customer') or '-'}\t{platforms}\t{entry['path']}"
        )


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


def _cmd_show(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    scope = _read_scope(eng_dir / "scope.json", require_blue=True)

    print(f"# Blue engagement: {eng_dir.name}")
    print(f"customer: {scope.get('customer') or '-'}")
    print(f"platforms: {','.join(scope.get('platforms') or []) or '-'}")
    print(f"current_phase: {scope.get('current_phase') or '-'}")
    print(f"status: {scope.get('status') or '-'}")
    print()
    alert_md = scope.get("alert_metadata") or {}
    print("## Alert metadata")
    print(f"  external_id: {alert_md.get('external_id') or '-'}")
    print(f"  severity_hint: {alert_md.get('severity_hint') or '-'}")
    print(f"  source: {alert_md.get('source') or '-'}")
    print(f"  received_at: {alert_md.get('received_at') or '-'}")
    parsed = alert_md.get("parsed") or {}
    if isinstance(parsed, dict) and parsed:
        kind = parsed.get("format") or "unknown"
        print(f"  parsed: format={kind}")
        if kind == "eml":
            headers = parsed.get("headers") or {}
            for key in ("From", "To", "Subject"):
                if headers.get(key):
                    print(f"    {key}: {headers[key]}")
    print()
    print("## Findings")
    _run_assess(install_root, eng_dir, ["finding", "list"], check=False)
    print()
    print("## Resume brief (tenant scope)")
    _run_assess(install_root, eng_dir, ["resume-brief"], check=False)


# ---------------------------------------------------------------------------
# tier
# ---------------------------------------------------------------------------


def _cmd_tier(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    _read_scope(eng_dir / "scope.json", require_blue=True)
    details: dict[str, object] = {"tier": args.tier}
    if args.notes:
        details["tier_notes"] = args.notes
    rc = _run_assess(
        install_root,
        eng_dir,
        [
            "finding",
            "update",
            args.finding_slug,
            "--details-inline",
            json.dumps(details),
            "--reason",
            f"blue tier annotation: {args.tier}",
        ],
        check=False,
    )
    if rc != 0:
        raise SystemExit(rc)


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def _cmd_verify(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    _read_scope(eng_dir / "scope.json", require_blue=True)
    blue_disp = args.disposition
    cli_disp = BLUE_TO_CLI_DISPOSITION[blue_disp]

    if not args.force and not _has_verifier_dispatch_for(install_root, eng_dir, args.finding_slug):
        raise SystemExit(
            f"vigil blue verify: no incident-verifier dispatch found that references "
            f"finding {args.finding_slug!r}. Dispatch the verifier first via: "
            f"vigil assess agent start --role incident-verifier --tier L3 "
            f"--skills alert-fp-verification --task 'verify {args.finding_slug}' "
            f"--rate-budget '<authored tenant query budget>' "
            f"--prompt-context-json dispatch-context.json --emit-prompt, or rerun "
            "with --force to record an operator-approved bypass."
        )

    evidence_refs: list[str] = []
    if args.evidence_refs:
        evidence_refs = [piece.strip() for piece in args.evidence_refs.split(",") if piece.strip()]

    proof_receipt_ids = args.proof_receipt_ids or []

    if blue_disp == "false_positive":
        if not args.counter_check_file:
            raise SystemExit(
                "verify --disposition false_positive requires --counter-check-file "
                "with a completed structured counter-check (finding verify contract)"
            )
        details = {
            "disposition": blue_disp,  # preserve blue vocab verbatim for report-writer
            "evidence_refs": evidence_refs,
        }
        assess_args = [
            "finding",
            "verify",
            args.finding_slug,
            "--status",
            cli_disp,
            "--reason",
            args.reason,
            "--counter-check-file",
            args.counter_check_file,
            "--details-inline",
            json.dumps(details),
        ]
    else:
        details = {
            "disposition": blue_disp,  # blue vocab verbatim
            "evidence_refs": evidence_refs,
        }
        assess_args = [
            "finding",
            "verify",
            args.finding_slug,
            "--status",
            cli_disp,
            "--reason",
            args.reason,
            "--details-inline",
            json.dumps(details),
        ]
        if blue_disp in {"verified", "downgraded"} and not proof_receipt_ids:
            raise SystemExit(
                f"verify --disposition {blue_disp} requires at least one "
                "--proof-receipt-id (finding verify contract)"
            )
        for receipt_id in proof_receipt_ids:
            assess_args.extend(["--proof-receipt-id", str(receipt_id)])
        if blue_disp == "downgraded":
            if not args.new_severity:
                raise SystemExit("verify --disposition downgraded requires --new-severity")
            assess_args.extend(["--new-severity", args.new_severity])

    rc = _run_assess(install_root, eng_dir, assess_args, check=False)
    if rc != 0:
        raise SystemExit(rc)


def _has_verifier_dispatch_for(install_root: Path, eng_dir: Path, finding_slug: str) -> bool:
    # Cheap heuristic: list incident-verifier dispatches and grep for the
    # finding slug in their task / finding_slugs field. Best-effort — if the
    # backend is unreachable we return True so the verify call still attempts
    # (the user's warning is only suppressed in that case).
    try:
        result = subprocess.run(
            _build_assess_argv(install_root, eng_dir, ["agent", "list", "--filter-role", "incident-verifier", "--limit", "50"]),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return True  # fail-open; the warning is advisory anyway
    if result.returncode != 0:
        return True
    haystack = result.stdout or ""
    return finding_slug in haystack


def _fetch_containment_decision(
    install_root: Path, eng_dir: Path, decision_id: int
) -> dict | None:
    """Return the dispatch-decisions row for ``decision_id`` (kind=containment_proposal).

    Pages through dispatch-decision fetches via the assess CLI's raw `fetch`
    command. Falls back to None on error so callers can produce a clean
    operator-facing error.
    """
    page_size = 1000
    offset = 0
    while True:
        endpoint = (
            "dispatch-decisions?kind=containment_proposal"
            f"&limit={page_size}&offset={offset}"
        )
        try:
            result = subprocess.run(
                _build_assess_argv(install_root, eng_dir, ["fetch", endpoint]),
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if result.returncode != 0:
            return None
        try:
            rows = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None
        if not isinstance(rows, list):
            return None
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                row_id = int(row.get("id") or -1)
            except (ValueError, TypeError):
                continue
            if row_id == int(decision_id):
                return row
        if len(rows) < page_size:
            return None
        offset += page_size


def _fetch_command_run(install_root: Path, eng_dir: Path, command_run_id: int) -> dict | None:
    """Return the command-run row for ``command_run_id`` in this engagement."""
    try:
        result = subprocess.run(
            _build_assess_argv(
                install_root,
                eng_dir,
                ["fetch", f"command-runs/{int(command_run_id)}"],
            ),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        row = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return row if isinstance(row, dict) else None


def _fetch_containment_finding(install_root: Path, eng_dir: Path, slug: str) -> dict | None:
    try:
        result = subprocess.run(
            _build_assess_argv(install_root, eng_dir, ["finding", "get", slug]),
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        row = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    return row if isinstance(row, dict) and row.get("slug") == slug else None


def _require_containment_command_run(
    command_row: dict, command_run_id: int, *, finding_id: int, proposal_id: int,
    action: str, target: str,
) -> None:
    failures: list[str] = []
    route = str(command_row.get("route") or "").strip()
    if route != "host_exec":
        failures.append(f"route={route!r}; expected 'host_exec'")
    phase = str(command_row.get("phase") or "").strip().lower()
    if phase != "respond":
        failures.append(f"phase={phase!r}; expected 'respond'")
    technique = str(command_row.get("technique") or "").strip().upper()
    if technique != "CONTAINMENT":
        failures.append(f"technique={technique!r}; expected 'CONTAINMENT'")
    if command_row.get("success") is not True:
        failures.append(f"success={command_row.get('success')!r}; expected true")
    if command_row.get("finding_id") != finding_id:
        failures.append(f"finding_id={command_row.get('finding_id')!r}; expected {finding_id}")
    intent_tokens = str(command_row.get("intent") or "").split()
    if f"proposal={proposal_id}" not in intent_tokens:
        failures.append(f"intent does not identify proposal={proposal_id}")
    if f"action={action}" not in intent_tokens:
        failures.append(f"intent does not identify action={action}")
    argv = command_row.get("argv")
    if not isinstance(argv, list) or target not in argv:
        failures.append(f"argv does not contain target {target!r} as an argument")
    if failures:
        raise SystemExit(
            f"vigil blue contain: command run id {command_run_id} is not valid containment proof: "
            + "; ".join(failures)
            + ". Execute the approved action through "
            "`vigil assess host-exec --require-audit --phase respond --technique CONTAINMENT ...` "
            "and pass that run id."
        )


# ---------------------------------------------------------------------------
# propose-contain
# ---------------------------------------------------------------------------


def _cmd_propose_contain(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    _read_scope(eng_dir / "scope.json", require_blue=True)
    if args.blast_radius not in CONTAINMENT_BLAST_RADII:
        raise SystemExit(f"--blast-radius must be one of {sorted(CONTAINMENT_BLAST_RADII)}")

    payload = {
        "action": args.action,
        "target": args.target,
        "platform": args.platform,
        "rollback": args.rollback,
        "blast_radius": args.blast_radius,
    }
    if args.note:
        payload["note"] = args.note
    if args.finding_slug:
        payload["finding_slug"] = args.finding_slug

    # Authoritative approval ledger row in assessment_dispatch_decisions.
    #    `vigil blue contain` refuses to execute until this row's `resolved` flag
    #    is 1 (set via `vigil assess approve-proposal <decision-id>`). The row's
    #    integer id (printed below) is what the operator passes to
    #    `vigil blue contain --proposal <id> --command-run-id <run-id>`.
    decision_payload = dict(payload)
    decision_payload["finding_slug"] = args.finding_slug
    decision_argv = [
        "agent",
        "decision",
        "--kind",
        "containment_proposal",
        "--payload-json",
        json.dumps(decision_payload),
    ]
    try:
        decision_result = subprocess.run(
            _build_assess_argv(install_root, eng_dir, decision_argv),
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"assess entry not found: {exc}") from exc
    if decision_result.returncode != 0:
        sys.stderr.write(decision_result.stderr or "")
        raise SystemExit(decision_result.returncode)

    decision_row: dict[str, object] = {}
    try:
        decision_row = json.loads(decision_result.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        sys.stderr.write(
            "WARN vigil blue propose-contain: could not parse decision row JSON from "
            "`vigil assess agent decision` output. Operator must locate the decision id via "
            "`vigil assess agent list` (kind=containment_proposal) before `vigil blue contain`.\n"
        )

    decision_id = decision_row.get("id")
    print(json.dumps(
        {
            "decision_id": decision_id,
            "approval_hint": (
                f"vigil assess approve-proposal {decision_id} --approved-by <operator>"
                if decision_id is not None
                else None
            ),
        },
        ensure_ascii=False,
    ))


# ---------------------------------------------------------------------------
# contain
# ---------------------------------------------------------------------------


def _cmd_contain(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    _read_scope(eng_dir / "scope.json", require_blue=True)

    # Approval gate: refuse unless the decision row referenced by --proposal
    # is resolved (`resolved=1`). Approval lands via
    # `vigil assess approve-proposal <decision-id>`.
    proposal_action: str | None = None
    proposal_target: str | None = None
    proposal_platform: str | None = None

    decision_id_raw = str(args.proposal).strip()
    try:
        decision_id_int = int(decision_id_raw)
    except ValueError:
        decision_id_int = None

    if decision_id_int is None:
        raise SystemExit(
            f"vigil blue contain --proposal must be a decision-id integer (got {decision_id_raw!r}). "
            f"`vigil blue propose-contain` prints the decision_id; approve via "
            f"`vigil assess approve-proposal <decision-id> --approved-by <operator>`."
        )

    decision_row = _fetch_containment_decision(install_root, eng_dir, decision_id_int)
    if decision_row is None:
        raise SystemExit(
            f"vigil blue contain: containment proposal decision id {decision_id_int} not found in "
            f"dispatch-decisions. Re-run `vigil blue propose-contain ...` to generate one."
        )
    if not decision_row.get("resolved"):
        raise SystemExit(
            f"vigil blue contain: proposal {decision_id_int} not approved — run: "
            f"vigil assess approve-proposal {decision_id_int} --approved-by <operator>"
        )
    payload = decision_row.get("payload") if isinstance(decision_row, dict) else None
    if isinstance(payload, dict):
        proposal_finding = payload.get("finding_slug") if isinstance(payload.get("finding_slug"), str) else None
        if proposal_finding and proposal_finding != args.finding_slug:
            raise SystemExit(
                f"vigil blue contain: proposal {decision_id_int} belongs to finding "
                f"{proposal_finding!r}, not {args.finding_slug!r}."
            )
        proposal_action = payload.get("action") if isinstance(payload.get("action"), str) else None
        proposal_target = payload.get("target") if isinstance(payload.get("target"), str) else None
        proposal_platform = (
            payload.get("platform") if isinstance(payload.get("platform"), str) else None
        )

    if args.action and args.action != proposal_action:
        raise SystemExit("vigil blue contain: action differs from the approved action")
    if args.target and args.target != proposal_target:
        raise SystemExit("vigil blue contain: target differs from the approved target")
    action = proposal_action or "contain"
    target = proposal_target or "-"

    command_run_id = getattr(args, "command_run_id", None)
    if not args.proof_artifact and command_run_id is None:
        raise SystemExit(
            "vigil blue contain requires --proof-artifact or --command-run-id. "
            "Execute the approved action through `vigil assess host-exec --require-audit ...` "
            "and pass the command run id, or register the captured stdout/screenshot as proof."
        )
    if command_run_id is not None:
        command_row = _fetch_command_run(install_root, eng_dir, int(command_run_id))
        if command_row is None:
            raise SystemExit(
                f"vigil blue contain: command run id {command_run_id} not found in this engagement. "
                "Pass the id printed by `vigil assess host-exec --require-audit ...` or use --proof-artifact."
            )
        finding_row = _fetch_containment_finding(install_root, eng_dir, args.finding_slug)
        if finding_row is None or not isinstance(finding_row.get("id"), int):
            raise SystemExit(f"vigil blue contain: finding {args.finding_slug!r} could not be resolved for command proof")
        _require_containment_command_run(
            command_row, int(command_run_id), finding_id=finding_row["id"],
            proposal_id=decision_id_int, action=action, target=target,
        )

    if args.proof_artifact:
        proof_path = Path(args.proof_artifact)
        # Relative --proof-artifact should resolve against the engagement
        # directory first (operators frequently run `vigil blue contain -k <key>`
        # from outside the eng_dir). Fall back to CWD with a stderr warning
        # so the operator notices when their relative path didn't match
        # eng_dir layout.
        if not proof_path.is_absolute():
            eng_relative = eng_dir / proof_path
            if eng_relative.exists():
                proof_path = eng_relative
            else:
                cwd_relative = Path.cwd() / proof_path
                if cwd_relative.exists():
                    proof_path = cwd_relative
                    print(
                        f"[vigil blue] proof-artifact resolved against CWD, not eng_dir: {proof_path}",
                        file=sys.stderr,
                    )
        if not proof_path.is_file():
            raise SystemExit(f"--proof-artifact not found: {proof_path}")
        rc = _run_assess(
            install_root,
            eng_dir,
            [
                "artifact",
                "register",
                str(proof_path),
                "--kind",
                "containment_proof",
                "--finding",
                args.finding_slug,
            ],
            check=False,
        )
        if rc != 0:
            print(
                f"WARN vigil blue contain: artifact register failed (rc={rc}); proof artifact "
                f"{proof_path} not in artifact index yet.",
                file=sys.stderr,
            )
            if command_run_id is None:
                raise SystemExit(rc)

    metadata = {
        "containment_action": action,
        "target": target,
        "platform": proposal_platform,
        "proposal_id": args.proposal,
        "finding_slug": args.finding_slug,
        "command_run_id": getattr(args, "command_run_id", None),
    }
    log_result = (
        f"recorded approved containment action (action={action}, target={target}, "
        f"proposal={args.proposal}, command_run_id={getattr(args, 'command_run_id', None) or '-'})"
    )
    rc = _run_assess(
        install_root,
        eng_dir,
        [
            "log",
            "operator",
            f"contain {args.finding_slug}",
            "contain",
            log_result,
            "--actor-kind",
            "operator",
            "--metadata-inline",
            json.dumps(metadata),
        ],
        check=False,
    )
    if rc != 0:
        raise SystemExit(rc)

    # Bump finding workflow status. `contained` is now a registered enum value
    # in WORKFLOW_STATUSES (alongside `eradicated` and `recovered` — see
    # orchestrator/backend/app/services/state_manager.py).
    update_rc = _run_assess(
        install_root,
        eng_dir,
        [
            "finding",
            "update",
            args.finding_slug,
            "--status",
            "contained",
            "--details-inline",
            json.dumps(
                {
                    "containment_status": "contained",
                    "containment_action": action,
                    "containment_command_run_id": getattr(args, "command_run_id", None),
                }
            ),
            "--reason",
            f"blue contain executed via proposal {args.proposal}",
        ],
        check=False,
    )
    if update_rc != 0:
        raise SystemExit(update_rc)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


def _cmd_report(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    scope = _read_scope(eng_dir / "scope.json", require_blue=True)
    # Pre-flight: emit the gathered report-findings table so the operator sees
    # the input set before report-writer is dispatched.
    preflight_rc = _run_assess(install_root, eng_dir, ["finding", "report", "--mode", "final"], check=False)
    if preflight_rc != 0:
        raise SystemExit(preflight_rc)
    template_hint = (
        f" Use template variant: {args.template}." if args.template else ""
    )
    task = (
        "Render blue incident report from durable backend state. Load template "
        "at agent/skills/report-generation/templates/blue.md. Pull findings, "
        "timeline, artifacts, containment actions per the template's BACKEND "
        "QUERIES section. Apply agent/rules/triage.md §21 (Writing "
        f"discipline). Phase=report.{template_hint}"
    )
    # See C1 — auto-generate agent-id so the backend validator accepts the
    # dispatch without operator-supplied --agent-id, and so the operator can
    # reference the id later (handoff, done, render-handoff).
    agent_id = getattr(args, "agent_id", None) or f"report-writer-{uuid.uuid4().hex[:8]}"
    print(f"[vigil blue] dispatched with agent-id={agent_id}", file=sys.stderr)
    rc = _run_assess(
        install_root,
        eng_dir,
        [
            "agent",
            "start",
            "--role",
            "report-writer",
            "--skills",
            "report-generation",
            "--task",
            task,
            "--dispatch-mode",
            "deep-manual",
            "--agent-id",
            agent_id,
            "--no-target-traffic",
            "--emit-prompt",
            "--prompt-context-json",
            json.dumps(_blue_report_prompt_context(scope, eng_dir, "incident report")),
        ],
        check=False,
    )
    if rc != 0:
        raise SystemExit(rc)


# ---------------------------------------------------------------------------
# closeout
# ---------------------------------------------------------------------------


def _cmd_closeout(args: argparse.Namespace, install_root: Path) -> None:
    eng_dir = _resolve_blue_engagement(install_root, args)
    scope = _read_scope(eng_dir / "scope.json", require_blue=True)
    preflight_rc = _run_assess(install_root, eng_dir, ["finding", "report", "--mode", "final"], check=False)
    if preflight_rc != 0:
        raise SystemExit(preflight_rc)
    task = (
        "Render customer-facing blue closeout summary to closeout.md from durable "
        "backend state. This artifact is required even for false positive, benign, "
        "no-impact, or inconclusive outcomes. Include customer, alert source and "
        "external id, disposition, short closure description, evidence reviewed, "
        "reasoning for benign/no-incident or unresolved status, actions taken, "
        "recommended follow-up, and UTC timestamps. Register closeout.md as "
        "kind=ir_closeout with `vigil assess artifact register closeout.md "
        "--kind ir_closeout --agent-id <report-writer-agent-id>` when the draft is ready. "
        "Use active blue-team language and avoid red-team report vocabulary."
    )
    agent_id = getattr(args, "agent_id", None) or f"closeout-writer-{uuid.uuid4().hex[:8]}"
    print(f"[vigil blue] dispatched with agent-id={agent_id}", file=sys.stderr)
    rc = _run_assess(
        install_root,
        eng_dir,
        [
            "agent",
            "start",
            "--role",
            "report-writer",
            "--skills",
            "report-generation",
            "--task",
            task,
            "--dispatch-mode",
            "deep-manual",
            "--agent-id",
            agent_id,
            "--no-target-traffic",
            "--emit-prompt",
            "--prompt-context-json",
            json.dumps(_blue_report_prompt_context(scope, eng_dir, "incident closeout")),
        ],
        check=False,
    )
    if rc != 0:
        raise SystemExit(rc)


def _blue_report_prompt_context(
    scope: dict, engagement_dir: Path, artifact_kind: str
) -> dict[str, str]:
    """Build the complete offline report-writer context from owned state."""
    return {
        "authorized_phase": "report",
        "target": (
            f"blue engagement {engagement_dir.name}; customer="
            f"{scope.get('customer') or 'unknown'}"
        ),
        "hunt_scope": f"not applicable — render the {artifact_kind}",
        "mindset_lens": "not applicable — report composition",
        "depth_expectation": "complete every template section from durable state",
        "oob": "not needed — no target traffic",
        "auth_context": "backend read-only reporting",
        "credential_id": "none",
        "prior_state": "final finding projection, activity, artifacts, and handoffs",
        "coverage": "all report-ready durable backend records",
        "cleanup": "none expected — offline report composition",
        "human_reach_decision": "none — no target traffic",
        "role_specific_additions": f"render and register the {artifact_kind}",
    }


# ---------------------------------------------------------------------------
# tenant init
# ---------------------------------------------------------------------------


def _cmd_tenant_init(args: argparse.Namespace, install_root: Path) -> None:
    customer = (args.customer or "").strip()
    platform = (args.platform or "").strip()
    if not KEBAB_SLUG_RE.match(customer):
        raise SystemExit(f"--customer must be lowercase kebab-case (got {customer!r})")
    if platform not in PLATFORM_TO_TENANT_SUFFIX:
        raise SystemExit(
            f"--platform must be one of {sorted(PLATFORM_TO_TENANT_SUFFIX.keys())} (got {platform!r})"
        )
    tenant_dir = tenant_references_root(install_root)
    template = application_agent_root(install_root) / "references" / "tenants" / f"_template-{platform}.md"
    suffix = PLATFORM_TO_TENANT_SUFFIX[platform]
    dest = tenant_dir / f"{customer}-{suffix}.md"
    if dest.resolve().is_relative_to(application_agent_root(install_root).resolve()):
        raise SystemExit(f"Tenant references must be private workspace data, not application assets: {dest}")
    if not template.is_file():
        raise SystemExit(
            f"Tenant template not found at {template}. "
            "Restore the matching agent/references/tenants/_template-<platform>.md "
            "file before retrying."
        )
    if dest.exists() and not args.force:
        raise SystemExit(f"Tenant ref already exists at {dest}. Pass --force to overwrite.")
    tenant_dir.mkdir(parents=True, exist_ok=True)
    dest.write_text(template.read_text(encoding="utf-8"), encoding="utf-8")
    # Show both input + output so operators can see how the alias map
    # (e.g. ``gws → workspace``) was applied to the on-disk filename — this
    # is the same mapping `vigil blue engage` uses to find the tenant ref.
    print(f"template: {template}", file=sys.stderr)
    print(f"alias: --platform {platform} → suffix {suffix}", file=sys.stderr)
    print(str(dest))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_blue_engagement(install_root: Path, args: argparse.Namespace) -> Path:
    key = getattr(args, "engagement_key", None)
    if key:
        return resolve_engagement_path(install_root, key)
    if getattr(args, "select", False):
        return resolve_engagement_path(install_root, select=True)
    if current := current_engagement_path():
        return current
    raise SystemExit(
        "Specify an engagement key with -k/--engagement-key, pass --select, or run from inside an engagement"
    )


def _read_scope(scope_path: Path, *, require_blue: bool) -> dict:
    if not scope_path.is_file():
        raise SystemExit(f"scope.json not found at {scope_path}")
    try:
        payload = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"failed to read {scope_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"scope.json at {scope_path} is not a JSON object")
    if require_blue and payload.get("engagement_type") != "blue":
        raise SystemExit(
            f"{scope_path} has engagement_type={payload.get('engagement_type')!r}; "
            "this command only works on blue engagements."
        )
    return payload


def _write_json_atomic(path: Path, payload: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_assess_argv(install_root: Path, eng_dir: Path, assess_args: list[str]) -> list[str]:
    assess = application_agent_root(install_root) / "scripts" / "assess.py"
    return [str(assess), "--engagement-dir", str(eng_dir), *assess_args]


def _run_assess(install_root: Path, eng_dir: Path, assess_args: list[str], *, check: bool = True) -> int:
    """Invoke ``vigil assess ...`` via the assess.py entry script.

    Resolves the same application assets as main.py's assess pass-through.
    We use ``subprocess.run`` instead of ``os.execv`` because the blue wrapper
    composes multiple assess calls per blue verb — execv would replace this
    process and clobber the chain.
    """
    argv = _build_assess_argv(install_root, eng_dir, assess_args)
    try:
        result = subprocess.run(argv, check=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"assess entry not found at {argv[0]}: {exc}") from exc
    if check and result.returncode != 0:
        raise SystemExit(result.returncode)
    return result.returncode
