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
import uuid
from typing import Any

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import (
    MIXED_ASSESSMENT_ROLES,
    default_dispatch_mode_for_role,
    validate_specialist_dispatch_contract,
)

from assess.commands.dispatch._shared import (
    _utcnow_iso,
    _split_csv,
    _load_json_arg,
)


# Backend dispatch actions. The operator-facing CLI maps these to
# ``vigil assess agent start|done|list|get|handoff|decision|...``; no local
# database path is part of that public contract.
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
# The backend rejects a longer summary with an HTTP 422, which a specialist
# only sees after authoring the whole checkpoint and sending it. Mirroring the
# bound here fails the write before the request while the text is still in the
# author's editor. Characters, not bytes — Pydantic counts characters on a str.
# KEEP IN SYNC with ``HandoffCreate.summary`` (authoritative) and
# ``HandoffUpdate.summary`` in ``orchestrator/backend/app/api/assessment.py``.
_HANDOFF_SUMMARY_MAX_CHARS = 2000

_OVERLAP_PAGE_SIZE = 1000
_OVERLAP_MAX_PAGES = 1000
_OVERLAP_DISPLAY_LIMIT = 5


def _client_for(args) -> tuple[AssessmentClient, Any]:
    cfg = load_config(getattr(args, "engagement_dir", None))
    return AssessmentClient(cfg.base_url, cfg.engagement_key), cfg


def _build_register_payload(args) -> dict:
    payload: dict[str, Any] = {}
    json_has_budget = False
    if getattr(args, "from_json", None):
        loaded = _load_json_arg(args.from_json)
        if not isinstance(loaded, dict):
            print("agent start --from-json: file must contain a JSON object", file=sys.stderr)
            sys.exit(1)
        payload.update(loaded)
        json_has_budget = "rate_budget" in payload or "no_target_traffic" in payload
    # CLI flags override / supplement the JSON payload.
    cli_fields = {
        "agent_id": getattr(args, "agent_id", None),
        "agent_role": getattr(args, "agent_role", None),
        "task": getattr(args, "task", None),
        "application_unit_id": getattr(args, "application_unit_id", None),
        "requested_model": getattr(args, "dispatch_model", None),
        "requested_reasoning": getattr(args, "reasoning", None),
        "dispatch_mode": getattr(args, "dispatch_mode_arg", None),
        "assessment_mode": getattr(args, "assessment_mode", None),
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
    json_rate_budget = payload.pop("rate_budget", None)
    json_no_target_traffic = payload.pop("no_target_traffic", None)
    json_prompt_context = payload.pop("prompt_context", None)
    if json_prompt_context is not None:
        if getattr(args, "prompt_context_json", None):
            print(
                "agent start: prompt context must come from either --from-json or "
                "--prompt-context-json, not both",
                file=sys.stderr,
            )
            sys.exit(1)
        args.prompt_context = json_prompt_context
    if not payload.get("agent_role"):
        print("agent start: --agent-role is required (or include 'agent_role' in --from-json)", file=sys.stderr)
        sys.exit(1)
    if not payload.get("agent_id"):
        if getattr(args, "action", None) == "start":
            role_slug = (
                str(payload["agent_role"])
                .replace("_", "-")
                .replace(" ", "-")
            )
            payload["agent_id"] = f"{role_slug}-{uuid.uuid4().hex[:8]}"
            args.agent_id = payload["agent_id"]
        else:
            print(
                "agent start: --agent-id is required (or include 'agent_id' in --from-json)",
                file=sys.stderr,
            )
            sys.exit(1)
    has_traffic_contract = (
        hasattr(args, "rate_budget")
        or hasattr(args, "no_target_traffic")
        or json_has_budget
    )
    if has_traffic_contract:
        cli_rate_budget = str(getattr(args, "rate_budget", None) or "").strip()
        cli_no_target_traffic = bool(getattr(args, "no_target_traffic", False))
        if json_has_budget and (cli_rate_budget or cli_no_target_traffic):
            print(
                "agent start: traffic budget must come from either --from-json or "
                "CLI flags, not both",
                file=sys.stderr,
            )
            sys.exit(1)
        if json_has_budget:
            if json_rate_budget is not None and not isinstance(json_rate_budget, str):
                print("agent start --from-json: rate_budget must be a string", file=sys.stderr)
                sys.exit(1)
            if json_no_target_traffic is not None and not isinstance(
                json_no_target_traffic, bool
            ):
                print(
                    "agent start --from-json: no_target_traffic must be true or false",
                    file=sys.stderr,
                )
                sys.exit(1)
            rate_budget = str(json_rate_budget or "").strip()
            no_target_traffic = json_no_target_traffic is True
        else:
            rate_budget = cli_rate_budget
            no_target_traffic = cli_no_target_traffic
        if bool(rate_budget) == no_target_traffic:
            print(
                "agent start: pass exactly one of --rate-budget or "
                "--no-target-traffic; Vigil does not infer a traffic budget",
                file=sys.stderr,
            )
            sys.exit(1)
        args.rate_budget = rate_budget or None
        args.no_target_traffic = no_target_traffic
    if not payload.get("dispatch_mode"):
        _defaulted_mode = default_dispatch_mode_for_role(payload.get("agent_role"))
        payload["dispatch_mode"] = _defaulted_mode
        print(
            f"WARN agent start: dispatch_mode not set; defaulting to "
            f"'{_defaulted_mode}' for role '{payload.get('agent_role')}'. "
            "Pass --dispatch-mode explicitly to override.",
            file=sys.stderr,
        )
    if payload.get("agent_role") in MIXED_ASSESSMENT_ROLES and not payload.get("assessment_mode"):
        print(
            f"agent start: {payload.get('agent_role')} requires --assessment-mode code|web",
            file=sys.stderr,
        )
        sys.exit(1)
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
        if not getattr(args, "allow_duplicate", False):
            _warn_on_overlapping_dispatch(client, payload)
        row = client.record_dispatch(payload)
    finally:
        client.close()
    # `dispatch_id`, not a bare `id`: this row lives in assessment_dispatches while
    # `agent handoff` returns an assessment_dispatch_handoffs row. Two unrelated
    # sequences printed under the same key sent a verifier at the wrong lifecycle
    # record. `agent_id` remains the addressable key for every other verb.
    print(json.dumps({
        "dispatch_id": row.get("id"),
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
    overlap_count = 0
    scanned_count = 0
    ranked_overlaps: list[tuple[dict[str, Any], str]] = []
    complete = True
    try:
        for status in ("in-progress", "completed"):
            offset = 0
            prior_page_signature: tuple[tuple[Any, Any, Any], ...] | None = None
            for _page_number in range(_OVERLAP_MAX_PAGES):
                page = client.list_dispatches(
                    role=role,
                    status=status,
                    limit=_OVERLAP_PAGE_SIZE,
                    offset=offset,
                )
                page_signature = tuple(
                    (
                        row.get("id"),
                        row.get("agent_id"),
                        row.get("completed_at") or row.get("dispatched_at"),
                    )
                    for row in page
                    if isinstance(row, dict)
                )
                if page_signature and page_signature == prior_page_signature:
                    complete = False
                    break
                prior_page_signature = page_signature
                for row in page:
                    if not isinstance(row, dict):
                        continue
                    scanned_count += 1
                    if str(row.get("agent_id") or "") == str(
                        payload.get("agent_id") or ""
                    ):
                        continue
                    reason = _dispatch_overlap_reason(payload, row)
                    if not reason:
                        continue
                    overlap_count += 1
                    ranked_overlaps.append((row, reason))
                    _rank_overlaps(ranked_overlaps, payload)
                    del ranked_overlaps[_OVERLAP_DISPLAY_LIMIT:]
                if len(page) < _OVERLAP_PAGE_SIZE:
                    break
                offset += len(page)
            else:
                complete = False
    except AssessError as exc:
        print(f"WARN agent start: duplicate-overlap check skipped: {exc}", file=sys.stderr)
        return
    if not overlap_count:
        if not complete:
            print(
                "WARN agent start: duplicate-overlap history scan incomplete: "
                f"{scanned_count} dispatch rows inspected and no overlap found in "
                "the inspected rows, but backend history was not exhausted.",
                file=sys.stderr,
            )
        return

    print(
        "WARN agent start: dispatch rows appear to overlap this dispatch. "
        "Registration will continue; use --allow-duplicate to suppress this advisory "
        "when the overlap is intentional.",
        file=sys.stderr,
    )
    for row, reason in ranked_overlaps:
        print(
            f"  - {row.get('agent_id', '?')} ({row.get('agent_role', '?')}, "
            f"{row.get('status', '?')}): {reason}",
            file=sys.stderr,
        )
    shown = len(ranked_overlaps)
    if complete:
        count_text = f"{shown} of {overlap_count} overlapping dispatches shown"
    else:
        count_text = (
            f"{shown} of at least {overlap_count} overlapping dispatches shown "
            "(history scan bounded before the backend exhausted)"
        )
    print(f"  {count_text}", file=sys.stderr)


def _rank_overlaps(
    overlaps: list[tuple[dict[str, Any], str]], payload: dict[str, Any]
) -> None:
    """Rank in-place while retaining deterministic tie-breaks."""
    overlaps.sort(key=lambda item: str(item[0].get("agent_id") or ""))
    overlaps.sort(
        key=lambda item: str(
            item[0].get("completed_at")
            or item[0].get("dispatched_at")
            or ""
        ),
        reverse=True,
    )
    overlaps.sort(
        key=lambda item: (
            len(_set_overlap(payload.get("finding_slugs"), item[0].get("finding_slugs"))),
            len(_string_set(item[0].get("finding_slugs"))),
            _norm_text(payload.get("task")) == _norm_text(item[0].get("task")),
        ),
        reverse=True,
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
    source = getattr(args, "from_json", None)
    if not source:
        print("agent handoff: --from-json is required", file=sys.stderr)
        sys.exit(1)
    loaded = _load_json_arg(source)
    if not isinstance(loaded, dict):
        print("agent handoff --from-json: file must contain a JSON object", file=sys.stderr)
        sys.exit(1)
    if not str(loaded.get("agent_id") or "").strip():
        print("agent handoff --from-json: agent_id is required", file=sys.stderr)
        sys.exit(1)
    # Every create payload and every partial-update patch passes through here,
    # so one check covers both writes. The summary is never trimmed or split:
    # that would ship text the specialist did not author.
    summary = loaded.get("summary")
    if isinstance(summary, str) and len(summary) > _HANDOFF_SUMMARY_MAX_CHARS:
        print(
            f"agent handoff --from-json: summary is {len(summary)} characters, over "
            f"the {_HANDOFF_SUMMARY_MAX_CHARS}-character backend cap. Shorten it and "
            "move the detail into the structured fields that carry it: "
            "coverage_gaps, next_steps, runtime_issues.",
            file=sys.stderr,
        )
        sys.exit(1)
    return loaded


def _record_handoff(args) -> None:
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
                    "agent handoff --from-json: agent_role and summary are required "
                    f"keys when creating new handoff {agent_id!r}",
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
    # `handoff_id` names the namespace (assessment_dispatch_handoffs) so it cannot
    # be confused with the `dispatch_id` that `agent start` prints — see the note there.
    print(json.dumps({
        "handoff_id": row.get("id"),
        "agent_id": row.get("agent_id"),
    }, ensure_ascii=False))
