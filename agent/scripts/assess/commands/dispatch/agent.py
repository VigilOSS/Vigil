"""Backend agent lifecycle verbs.

Internal action names register / update-status / abort-duplicate / list / get /
record-decision / record-handoff — backend-table writes via the orchestrator
API (assessment_dispatches + assessment_dispatch_handoffs +
assessment_dispatch_decisions). These are dbless: they take no cases.db path.
The operator-facing surface routes here through ``vigil assess agent``.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import (
    default_dispatch_mode_for_role,
    validate_specialist_dispatch_contract,
)

from assess.commands.dispatch._shared import (
    _utcnow_iso,
    _split_csv,
    _load_json_arg,
)


# Actions that don't need a cases.db (work-buffer SQLite). When the first
# positional arg matches one of these names, we treat it as the action and
# leave db_path empty rather than forcing the operator to pass a useless path.
# These hit the orchestrator backend (not the work buffer). The operator-facing
# CLI maps them to ``vigil assess agent start|done|list|get|handoff|decision|...``.
_DBLESS_ACTIONS = (
    "render-handoff",
    "register",
    "update-status",
    "abort-duplicate",
    "list",
    "get",
    "record-decision",
    "record-handoff",
)

_HANDOFF_PATCHABLE_FIELDS = frozenset(
    {
        "summary",
        "phase",
        "confidence",
        "finding_slugs",
        "coverage_gaps",
        "next_steps",
        "runtime_issues",
        "working_artifacts",
        "open_questions",
        "recommended_next_agent",
        "handoff_status",
        "closed_dispatch_status",
        "extras",
    }
)


def _client_for(args) -> tuple[AssessmentClient, Any]:
    cfg = load_config(getattr(args, "engagement_dir", None))
    return AssessmentClient(cfg.base_url, cfg.engagement_key), cfg


def _build_register_payload(args) -> dict:
    payload: dict[str, Any] = {}
    if getattr(args, "from_json", None):
        loaded = _load_json_arg(args.from_json)
        if not isinstance(loaded, dict):
            print("agent start --from-json: file must contain a JSON object", file=sys.stderr)
            sys.exit(1)
        payload.update(loaded)
    # CLI flags override / supplement the JSON payload.
    cli_fields = {
        "agent_id": getattr(args, "agent_id", None),
        "agent_role": getattr(args, "agent_role", None),
        "task": getattr(args, "task", None),
        "application_unit_id": getattr(args, "application_unit_id", None),
        "requested_model": getattr(args, "dispatch_model", None),
        "requested_reasoning": getattr(args, "reasoning", None),
        "dispatch_mode": getattr(args, "dispatch_mode_arg", None),
        "skills": getattr(args, "skills", None),
        "tier": getattr(args, "tier", None),
        "vuln_classes": getattr(args, "vuln_classes", None),
        "identity": getattr(args, "dispatch_identity", None),
    }
    for k, v in cli_fields.items():
        if v is not None:
            payload[k] = v
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        payload["finding_slugs"] = finding_slugs
    if "agent_role" not in payload and payload.get("role"):
        payload["agent_role"] = payload.pop("role")
    elif "role" in payload and "agent_role" in payload:
        payload.pop("role", None)
    if not payload.get("agent_id"):
        print("agent start: --agent-id is required (or include 'agent_id' in --from-json)", file=sys.stderr)
        sys.exit(1)
    if not payload.get("agent_role"):
        print("agent start: --agent-role is required (or include 'agent_role' in --from-json)", file=sys.stderr)
        sys.exit(1)
    if not payload.get("dispatch_mode"):
        _defaulted_mode = default_dispatch_mode_for_role(payload.get("agent_role"))
        payload["dispatch_mode"] = _defaulted_mode
        print(
            f"WARN agent start: dispatch_mode not set; defaulting to "
            f"'{_defaulted_mode}' for role '{payload.get('agent_role')}'. "
            "Pass --dispatch-mode explicitly to override.",
            file=sys.stderr,
        )
    errors, warnings = validate_specialist_dispatch_contract(payload)
    for warning in warnings:
        print(f"WARN agent start: {warning}", file=sys.stderr)
    if errors:
        for error in errors:
            print(f"agent start: {error}", file=sys.stderr)
        sys.exit(1)
    skills_value = payload.get("skills")
    if isinstance(skills_value, list):
        payload["skills"] = ",".join(str(skill).strip() for skill in skills_value)
    return payload


def _register_dispatch(args) -> None:
    payload = _build_register_payload(args)
    client, _ = _client_for(args)
    try:
        if getattr(args, "check_overlap", False) and not getattr(args, "allow_duplicate", False):
            _warn_on_overlapping_dispatch(client, payload)
        row = client.record_dispatch(payload)
    finally:
        client.close()
    print(json.dumps({
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "status": row.get("status"),
    }, ensure_ascii=False))


def _warn_on_overlapping_dispatch(client: AssessmentClient, payload: dict[str, Any]) -> None:
    """Emit an advisory warning for exact structured overlap.

    This intentionally does not block. Parallel dispatches often share a role,
    host, or prose objective for legitimate reasons; only concrete overlap on
    refs or an exact copied task gets surfaced.
    """
    role = str(payload.get("agent_role") or "")
    if not role:
        return
    try:
        rows = client.list_dispatches(role=role, status="in-progress", limit=1000)
    except AssessError as exc:
        print(f"WARN agent start: duplicate-overlap check skipped: {exc}", file=sys.stderr)
        return
    current_agent_id = str(payload.get("agent_id") or "")
    overlaps: list[tuple[dict[str, Any], str]] = []
    for row in rows:
        if str(row.get("agent_id") or "") == current_agent_id:
            continue
        reason = _dispatch_overlap_reason(payload, row)
        if reason:
            overlaps.append((row, reason))
    if not overlaps:
        return
    print(
        "WARN agent start: active dispatch rows appear to overlap this dispatch. "
        "Registration will continue; use --allow-duplicate to suppress this advisory "
        "when the overlap is intentional.",
        file=sys.stderr,
    )
    for row, reason in overlaps[:5]:
        print(
            f"  - {row.get('agent_id', '?')} ({row.get('agent_role', '?')}): {reason}",
            file=sys.stderr,
        )


def _dispatch_overlap_reason(payload: dict[str, Any], row: dict[str, Any]) -> str:
    finding_overlap = _set_overlap(payload.get("finding_slugs"), row.get("finding_slugs"))
    if finding_overlap:
        return "same finding_slugs: " + ",".join(sorted(finding_overlap))
    task = _norm_text(payload.get("task"))
    if task and task == _norm_text(row.get("task")):
        return "exact same task text"
    return ""


def _norm_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _set_overlap(left: Any, right: Any) -> set[str]:
    return _string_set(left) & _string_set(right)


def _string_set(value: Any) -> set[str]:
    if value is None:
        return set()
    if isinstance(value, str):
        items = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        items = value
    else:
        return set()
    return {str(item).strip() for item in items if str(item).strip()}


def _dispatch_ids(args, extra: list[str]) -> list[str]:
    """Collect one-or-more agent ids from the variadic ``extra`` positional,
    falling back to ``--agent-id`` when no positional id was given. Batch:
    every id in ``extra`` is processed with the same shared flags."""
    ids = [str(x).strip() for x in (extra or []) if str(x).strip()]
    if not ids:
        fallback = (getattr(args, "agent_id", "") or "").strip()
        if fallback:
            ids = [fallback]
    return ids


def _update_dispatch_status(args, extra: list[str]) -> None:
    ids = _dispatch_ids(args, extra)
    if not ids:
        print("Usage: vigil assess agent done <agent-id> [<agent-id> ...] --status ...", file=sys.stderr)
        sys.exit(1)
    patch: dict[str, Any] = {}
    if getattr(args, "dispatch_status", None):
        patch["status"] = args.dispatch_status
        if args.dispatch_status in ("completed", "failed", "aborted", "blocked"):
            patch["completed_at"] = getattr(args, "completed_at", None) or _utcnow_iso()
    elif getattr(args, "completed_at", None):
        patch["completed_at"] = args.completed_at
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        patch["finding_slugs"] = finding_slugs
    if not patch:
        print(
            "agent done: pass at least one of --status, --completed-at, --finding-slugs",
            file=sys.stderr,
        )
        sys.exit(1)
    client, _ = _client_for(args)
    rows: list[dict[str, Any]] = []
    failed = 0
    try:
        for agent_id in ids:
            try:
                rows.append(client.update_dispatch(agent_id, patch))
            except Exception as exc:  # noqa: BLE001 - one bad id must not drop the rest
                failed += 1
                print(f"agent done: {agent_id} failed: {exc}", file=sys.stderr)
    finally:
        client.close()
    if len(ids) == 1 and rows:
        print(json.dumps(rows[0], ensure_ascii=False))
    else:
        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
        print(f"[agent done] updated {len(rows)} dispatch(es); {failed} failed.", file=sys.stderr)
    if failed:
        sys.exit(1)


def _abort_duplicate_dispatch(args, extra: list[str]) -> None:
    agent_id = (extra[0].strip() if extra else (getattr(args, "agent_id", "") or ""))
    replacement = (getattr(args, "replacement_agent_id", "") or "").strip()
    reason = (getattr(args, "reason", "") or "").strip()
    if not agent_id or not replacement or not reason:
        print(
            "Usage: vigil assess agent abort-duplicate <agent-id> "
            "--replacement-agent-id <agent-id> --reason TEXT",
            file=sys.stderr,
        )
        sys.exit(1)
    if agent_id == replacement:
        print(
            "abort-duplicate: --replacement-agent-id must point at the dispatch to keep, "
            "not the duplicate being aborted.",
            file=sys.stderr,
        )
        sys.exit(1)
    client, _ = _client_for(args)
    now = _utcnow_iso()
    try:
        replacement_row = client.get_dispatch(replacement)
        if replacement_row is None:
            print(
                f"abort-duplicate: replacement dispatch '{replacement}' was not found; "
                "register the canonical replacement before aborting the duplicate.",
                file=sys.stderr,
            )
            sys.exit(2)
        row = client.update_dispatch(agent_id, {"status": "aborted", "completed_at": now})
        decision = client.record_decision(
            {
                "kind": "dispatch_duplicate",
                "payload": {
                    "aborted_agent_id": agent_id,
                    "replacement_agent_id": replacement,
                    "reason": reason,
                },
                "surfaced_to_user": False,
            }
        )
    finally:
        client.close()
    print(json.dumps({"dispatch": row, "decision": decision}, ensure_ascii=False))


def _list_dispatches(args) -> None:
    filters: dict[str, Any] = {}
    role = getattr(args, "filter_role", None)
    if role:
        filters["role"] = role
    status_value = getattr(args, "dispatch_status", None)
    if status_value:
        filters["status"] = status_value
    since = getattr(args, "filter_since", None)
    if since:
        filters["since"] = since
    task_q = getattr(args, "task_q", None)
    if task_q:
        filters["task_q"] = task_q
    limit = getattr(args, "dispatch_limit", None)
    if limit:
        filters["limit"] = int(limit)
    client, _ = _client_for(args)
    try:
        rows = client.list_dispatches(**filters)
    finally:
        client.close()
    for row in rows:
        print(json.dumps(row, ensure_ascii=False))


def _get_dispatch(args, extra: list[str]) -> None:
    ids = _dispatch_ids(args, extra)
    if not ids:
        print("Usage: vigil assess agent get <agent-id> [<agent-id> ...]", file=sys.stderr)
        sys.exit(1)
    client, _ = _client_for(args)
    missing = 0
    try:
        for agent_id in ids:
            row = client.get_dispatch(agent_id)
            if row is None:
                missing += 1
                print(f"agent get: agent_id '{agent_id}' not found", file=sys.stderr)
                continue
            print(json.dumps(row, ensure_ascii=False))
    finally:
        client.close()
    if missing:
        sys.exit(2)


def _record_decision(args) -> None:
    kind = getattr(args, "decision_kind", None)
    if not kind:
        print("agent decision: --kind is required", file=sys.stderr)
        sys.exit(1)
    payload_json = getattr(args, "payload_json", None)
    if payload_json:
        loaded = _load_json_arg(payload_json)
        if not isinstance(loaded, dict):
            print("agent decision --payload-json: must produce a JSON object", file=sys.stderr)
            sys.exit(1)
        payload = dict(loaded)
    else:
        # Build payload from friendly flags. The fields we collect depend on
        # the kind, but we do not enforce strict per-kind shape — the backend
        # accepts any dict. Operators can always fall back to --payload-json.
        payload = {}
        host = getattr(args, "decision_host", None)
        vendor = getattr(args, "decision_vendor", None)
        choice = getattr(args, "decision_choice", None)
        note = getattr(args, "decision_note", None)
        reason = getattr(args, "reason", None)
        phase = getattr(args, "decision_phase", None)
        if host:
            payload["host"] = host
        if vendor:
            payload["vendor"] = vendor
        if choice:
            payload["choice"] = choice
        if note:
            payload["note"] = note
        if reason:
            payload["reason"] = reason
        if phase:
            payload["phase"] = phase
        if not payload:
            print(
                "agent decision: pass --payload-json or at least one of "
                "--host/--vendor/--choice/--note/--reason/--phase",
                file=sys.stderr,
            )
            sys.exit(1)
    body = {
        "kind": kind,
        "payload": payload,
        "surfaced_to_user": bool(getattr(args, "surfaced_to_user", False)),
    }
    client, _ = _client_for(args)
    try:
        row = client.record_decision(body)
    finally:
        client.close()
    print(json.dumps(row, ensure_ascii=False))


def _build_handoff_payload(args) -> dict:
    if getattr(args, "from_json", None):
        loaded = _load_json_arg(args.from_json)
        if not isinstance(loaded, dict):
            print("agent handoff --from-json: file must contain a JSON object", file=sys.stderr)
            sys.exit(1)
        # When --from-json is given we honour it as the authoritative shape,
        # but explicit identity flags are integrity checks. A mismatch usually
        # means the handoff is about to be written under a label that the
        # operator cannot retrieve by the actual spawned agent id.
        for key, val in (
            ("agent_id", getattr(args, "agent_id", None)),
            ("agent_role", getattr(args, "agent_role", None)),
            ("summary", getattr(args, "hf_summary", None)),
        ):
            if not val:
                continue
            existing = loaded.get(key)
            if existing and str(existing) != str(val):
                print(
                    f"agent handoff: --from-json {key}={existing!r} does not match "
                    f"explicit --{key.replace('_', '-')} {val!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            loaded[key] = val
        return loaded

    payload: dict[str, Any] = {}
    agent_id = getattr(args, "agent_id", None)
    agent_role = getattr(args, "agent_role", None)
    summary = getattr(args, "hf_summary", None)
    if not agent_id:
        print(
            "agent handoff: --agent-id is required "
            "(or pass --from-json with an agent_id)",
            file=sys.stderr,
        )
        sys.exit(1)
    payload["agent_id"] = agent_id
    if agent_role:
        payload["agent_role"] = agent_role
    if summary:
        payload["summary"] = summary
    if getattr(args, "hf_confidence", None):
        payload["confidence"] = args.hf_confidence
    finding_slugs = _split_csv(getattr(args, "finding_slugs", None))
    if finding_slugs:
        payload["finding_slugs"] = finding_slugs
    next_steps_raw = getattr(args, "hf_next_steps", None) or []
    if next_steps_raw:
        payload["next_steps"] = [{"action": item} for item in next_steps_raw]
    coverage_raw = getattr(args, "hf_coverage_gaps", None) or []
    if coverage_raw:
        coverage_rows = []
        for item in coverage_raw:
            area, _, reason = item.partition(":")
            coverage_rows.append({"area": area.strip(), "reason": reason.strip()})
        payload["coverage_gaps"] = coverage_rows
    runtime_raw = getattr(args, "hf_runtime_issues", None) or []
    if runtime_raw:
        runtime_rows = []
        for item in runtime_raw:
            kind_part, _, detail = item.partition(":")
            runtime_rows.append({
                "kind": kind_part.strip(),
                "detail": detail.strip(),
                "severity": "info",
            })
        payload["runtime_issues"] = runtime_rows
    artifacts_raw = getattr(args, "hf_working_artifacts", None) or []
    if artifacts_raw:
        payload["working_artifacts"] = [{"path": p} for p in artifacts_raw]
    open_qs = getattr(args, "hf_open_questions", None) or []
    if open_qs:
        payload["open_questions"] = list(open_qs)
    if getattr(args, "hf_recommended_next_agent", None):
        payload["recommended_next_agent"] = args.hf_recommended_next_agent
    if getattr(args, "hf_handoff_status", None):
        payload["handoff_status"] = args.hf_handoff_status
    if getattr(args, "hf_closed_dispatch_status", None):
        payload["closed_dispatch_status"] = args.hf_closed_dispatch_status
    extras_json = getattr(args, "hf_extras_json", None)
    if extras_json:
        loaded = _load_json_arg(extras_json)
        if not isinstance(loaded, dict):
            print("agent handoff --extras-json: must produce a JSON object", file=sys.stderr)
            sys.exit(1)
        payload["extras"] = loaded
    return payload


def _record_handoff(args) -> None:
    # If both --from-json and flag-based content are given, honour --from-json
    # but warn so the operator notices they're mixing modes (the JSON wins).
    has_flag_based = any(
        getattr(args, name, None)
        for name in (
            "hf_summary",
            "hf_confidence",
            "hf_next_steps",
            "hf_coverage_gaps",
            "hf_runtime_issues",
            "hf_working_artifacts",
            "hf_open_questions",
            "hf_recommended_next_agent",
            "hf_handoff_status",
            "hf_closed_dispatch_status",
            "hf_extras_json",
        )
    )
    if getattr(args, "from_json", None) and has_flag_based:
        print(
            "agent handoff: --from-json is set and flag-based content was also "
            "supplied; flag-based fields are ignored except as fallback for "
            "agent_id / agent_role / summary.",
            file=sys.stderr,
        )
    payload = _build_handoff_payload(args)
    client, _ = _client_for(args)
    try:
        agent_id = str(payload.get("agent_id") or "")
        if payload.get("agent_role") and payload.get("summary"):
            # Full checkpoints are idempotent: POST on the first write and
            # transparently PATCH on a duplicate agent_id.
            row = client.record_handoff(payload, upsert=True)
        else:
            # Lifecycle promotion is a true partial update. Requiring the
            # caller to re-send the summary risks replacing the specialist's
            # authored record just to change handoff_status.
            existing = client.get_handoff(agent_id)
            if existing is None:
                print(
                    "agent handoff: --agent-role and --summary are required when "
                    f"creating new handoff {agent_id!r}",
                    file=sys.stderr,
                )
                sys.exit(1)
            patch = {
                key: value
                for key, value in payload.items()
                if key in _HANDOFF_PATCHABLE_FIELDS
            }
            if not patch:
                print(
                    "agent handoff: supply at least one handoff field to update",
                    file=sys.stderr,
                )
                sys.exit(1)
            row = client.update_handoff(agent_id, patch)
    finally:
        client.close()
    print(json.dumps({
        "id": row.get("id"),
        "agent_id": row.get("agent_id"),
    }, ensure_ascii=False))
