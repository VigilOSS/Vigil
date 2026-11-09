"""Backend agent lifecycle verbs.

Internal action names register / update-status / abort-duplicate / list / get /
record-decision / record-handoff — backend-table writes via the orchestrator
API (assessment_dispatches + assessment_dispatch_handoffs +
assessment_dispatch_decisions). These are dbless: they take no cases.db path.
The operator-facing surface routes here through ``vigil assess agent``.
"""
from __future__ import annotations

import difflib
import json
import sys
import uuid
from typing import Any

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.code_record_input import fail
from assess.lib.config import load_config
from assess.lib.contract_registry import HANDOFF_SUMMARY_MAX_CHARS as _HANDOFF_SUMMARY_MAX_CHARS
from assess.lib.contracts import (
    MIXED_ASSESSMENT_ROLES,
    default_dispatch_mode_for_role,
    validate_specialist_dispatch_contract,
)

from assess.commands.dispatch._shared import (
    ARTIFACT_PRESENT,
    _utcnow_iso,
    _split_csv,
    _load_json_arg,
    resolve_engagement_artifact_path,
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
        # Mirrors backend HandoffUpdate: the caller's read-version guard. Without
        # it in this tuple an authored guard was dropped and the write proceeded
        # unguarded, which is the opposite of what the author asked for.
        "expected_handoff_version",
    }
)
# `agent_role` is immutable once the row exists and `agent_id` is URL-bound, so
# both are create-only; everything else round-trips through either write.
_HANDOFF_PAYLOAD_FIELDS = frozenset({"agent_id", "agent_role"}) | _HANDOFF_PATCHABLE_FIELDS
# Keys a specialist plausibly copies back out of `agent get` / a prior row. The
# backend owns every one of them, so name the owner instead of the bare key.
_HANDOFF_BACKEND_OWNED_HINTS = {
    "handoff_version": (
        "handoff_version (backend-managed; pass expected_handoff_version to guard "
        "the write against a concurrent one)"
    ),
    "last_checkpoint_at": "last_checkpoint_at (backend-managed write timestamp)",
    "created_at": "created_at (backend-managed)",
    "id": "id (backend-managed; --agent-id addresses the row)",
    "engagement_id": "engagement_id (resolved from the engagement, never sent)",
}
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
            fail("agent start --from-json", "file must contain a JSON object")
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
        if not isinstance(json_prompt_context, dict):
            fail("agent start --from-json", "prompt_context must be a JSON object")
        # Shallow-merge rather than refuse: shared wave boilerplate (target,
        # prior_state, coverage, cleanup, oob) is authored once in --from-json
        # and overridden per lane by --prompt-context-json, under the same
        # "CLI flags override / supplement the JSON payload" rule as above.
        # `_validate_prompt_context` then runs on the merged dict unchanged.
        merged = dict(json_prompt_context)
        if getattr(args, "prompt_context_json", None):
            overlay = _load_json_arg(args.prompt_context_json)
            if not isinstance(overlay, dict):
                fail("agent start", "--prompt-context-json must provide a JSON object")
            merged.update(overlay)
        args.prompt_context = merged
    if not payload.get("agent_role"):
        fail("agent start", "--agent-role is required (or include 'agent_role' in --from-json)")
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
            fail("agent start", "--agent-id is required (or include 'agent_id' in --from-json)")
    has_traffic_contract = (
        hasattr(args, "rate_budget")
        or hasattr(args, "no_target_traffic")
        or json_has_budget
    )
    if has_traffic_contract:
        cli_rate_budget = str(getattr(args, "rate_budget", None) or "").strip()
        cli_no_target_traffic = bool(getattr(args, "no_target_traffic", False))
        if json_has_budget and (cli_rate_budget or cli_no_target_traffic):
            fail(
                "agent start",
                "traffic budget must come from either --from-json or "
                "CLI flags, not both",
            )
        if json_has_budget:
            if json_rate_budget is not None and not isinstance(json_rate_budget, str):
                fail("agent start --from-json", "rate_budget must be a string")
            if json_no_target_traffic is not None and not isinstance(
                json_no_target_traffic, bool
            ):
                fail("agent start --from-json", "no_target_traffic must be true or false")
            rate_budget = str(json_rate_budget or "").strip()
            no_target_traffic = json_no_target_traffic is True
        else:
            rate_budget = cli_rate_budget
            no_target_traffic = cli_no_target_traffic
        if bool(rate_budget) == no_target_traffic:
            fail(
                "agent start",
                "pass exactly one of --rate-budget or "
                "--no-target-traffic; Vigil does not infer a traffic budget",
            )
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
        fail("agent start", f"{payload.get('agent_role')} requires --assessment-mode code|web")
    from assess.commands.agent import _CODE_SOURCE_IDENTITY_ROLES
    if payload.get("agent_role") in _CODE_SOURCE_IDENTITY_ROLES:
        if payload.get("assessment_mode") not in (None, 'code'):
            fail("agent start", 'code-only roles require assessment_mode=code')
        payload['assessment_mode'] = 'code'
    non_canonical = _non_canonical_vuln_classes(payload.get("vuln_classes"))
    if non_canonical:
        fail(
            "agent start",
            "--vuln-classes must name canonical vuln classes: "
            + "; ".join(non_canonical)
            + ". List them with `vigil assess list-skills --json` or read "
            "agent/references/runtime-guides/vuln-taxonomy.md.",
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


def _non_canonical_vuln_classes(value: Any) -> list[str]:
    """Every supplied class token the taxonomy does not know, with its neighbour.

    ``vuln_classes`` is the dispatch's own declaration and the depth ledger never
    trusts it for coverage, but it is read by humans and by every class-keyed
    view, so a token no reader can resolve is a typo worth catching at the
    keyboard instead of storing. The vocabulary stays in its canonical owner
    (``assess.lib.vuln_taxonomy``); nothing is re-listed here, and the stored
    text is the operator's own — only its tokens are checked.
    """
    if not value:
        return []
    from assess.lib.vuln_taxonomy import (
        VULN_CLASSES,
        is_valid_class,
        parse_vuln_class_field,
    )

    problems: list[str] = []
    for token in parse_vuln_class_field(value):
        if is_valid_class(token):
            continue
        nearest = difflib.get_close_matches(token, sorted(VULN_CLASSES), n=1, cutoff=0.6)
        problems.append(
            f"{token!r} is not a canonical class"
            + (f" (nearest: {nearest[0]})" if nearest else "")
        )
    return problems


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
    if not patch and not finding_slugs:
        fail("agent done", "pass at least one of --status, --completed-at, --finding-slugs")
    client, _ = _client_for(args)
    rows: list[dict[str, Any]] = []
    failed = 0
    try:
        for agent_id in ids:
            try:
                row_patch = dict(patch)
                if finding_slugs:
                    # The contract says --finding-slugs is "appended additively to
                    # the row, not replaced", and the backend PATCH replaces the
                    # column wholesale. Union here, where both lists are known, so
                    # an operator who adds one produced slug does not delete the
                    # input scope `agent start --finding-slugs` recorded.
                    row_patch["finding_slugs"] = _union_dispatch_finding_slugs(
                        client, agent_id, finding_slugs
                    )
                rows.append(client.update_dispatch(agent_id, row_patch))
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


def _union_dispatch_finding_slugs(
    client: AssessmentClient, agent_id: str, added: list[str]
) -> list[str]:
    """Stable union of the dispatch row's current slugs with the supplied ones.

    Same rule as ``handoff_renderer``: both lists are independently useful audit
    surfaces, so neither silently loses the other's entries. A failed read must
    stop the dependent PATCH: sending only the added list would replace scope
    whose contents this invocation never learned.
    """
    from assess.commands.dispatch.handoff_renderer import _normalise_finding_slugs

    row = client.get_dispatch(agent_id)
    existing = _normalise_finding_slugs((row or {}).get("finding_slugs"))
    return list(dict.fromkeys(existing + added))


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
        fail(
            "abort-duplicate",
            "--replacement-agent-id must point at the dispatch to keep, "
            "not the duplicate being aborted.",
        )
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
        fail("agent decision", "--kind is required")
    payload: dict[str, Any] = {}
    payload_json = getattr(args, "payload_json", None)
    if payload_json:
        loaded = _load_json_arg(payload_json)
        if not isinstance(loaded, dict):
            fail("agent decision --payload-json", "must produce a JSON object")
        payload.update(loaded)
    # CLI flags override / supplement the JSON payload — the same rule `agent
    # start --from-json` and `host-exec --from-json` already apply. The flags
    # used to be read only when --payload-json was absent, so
    # `--payload-json '{"choice":"in_scope"}' --host acme.example` recorded a
    # scope decision with no host at exit 0 and no warning, while
    # --surfaced-to-user applied on both paths.
    #
    # The fields collected depend on the kind, but no strict per-kind shape is
    # enforced here — the backend accepts any dict, and kind-aware models
    # validate the kinds that gate behaviour.
    flag_fields = (
        ("host", getattr(args, "decision_host", None)),
        ("vendor", getattr(args, "decision_vendor", None)),
        ("choice", getattr(args, "decision_choice", None)),
        ("note", getattr(args, "decision_note", None)),
        ("reason", getattr(args, "reason", None)),
        ("phase", getattr(args, "decision_phase", None)),
    )
    for key, value in flag_fields:
        if value:
            payload[key] = value
    if not payload:
        fail(
            "agent decision",
            "pass --payload-json or at least one of "
            "--host/--vendor/--choice/--note/--reason/--phase",
        )
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
        fail("agent handoff", "--from-json is required")
    loaded = _load_json_arg(source)
    if not isinstance(loaded, dict):
        fail("agent handoff --from-json", "file must contain a JSON object")
    if not str(loaded.get("agent_id") or "").strip():
        fail(
            "agent handoff --from-json",
            "agent_id is required in the payload and must "
            "equal --agent-id; the match is what stops a sibling lane's handoff file "
            "from being re-sent, so the key cannot be filled in from the flag",
        )
    expected = getattr(args, "agent_id", None)
    if loaded["agent_id"] != expected:
        fail(
            "agent handoff",
            f"payload agent_id {loaded['agent_id']!r} does not match --agent-id {expected!r}; "
            "write your own handoff file rather than re-sending another dispatch's",
        )
    # Every create payload and every partial-update patch passes through here,
    # so one check covers both writes. The create model is extra="forbid", so a
    # misspelled key 422s there; the patch path used to filter it out silently
    # and print a success receipt. Reject by name on both, mirroring the
    # prompt-context rejection in `agent start`.
    unknown = sorted(set(loaded) - _HANDOFF_PAYLOAD_FIELDS)
    if unknown:
        fail(
            "agent handoff --from-json",
            "unknown handoff keys: "
            + ", ".join(_HANDOFF_BACKEND_OWNED_HINTS.get(key, key) for key in unknown)
            + ". Read `vigil assess contract agent handoff` or "
            "agent/references/runtime-guides/handoff-schema.md for the field set.",
        )
    expected_version = loaded.get("expected_handoff_version")
    if expected_version is not None and (
        type(expected_version) is not int or expected_version < 1
    ):
        fail(
            "agent handoff --from-json",
            "expected_handoff_version must be the integer "
            "handoff_version you read (>= 1); it guards this write against a "
            "concurrent one and is never a string",
        )
    # Every create payload and every partial-update patch passes through here,
    # so one check covers both writes. The summary is never trimmed or split:
    # that would ship text the specialist did not author.
    summary = loaded.get("summary")
    if isinstance(summary, str) and len(summary) > _HANDOFF_SUMMARY_MAX_CHARS:
        fail(
            "agent handoff --from-json",
            f"summary is {len(summary)} characters, over "
            f"the {_HANDOFF_SUMMARY_MAX_CHARS}-character persistence limit. Input is unchanged; shorten the summary and "
            "retain evidence in working_artifacts. Use these structured fields for their meanings: "
            "coverage_gaps, next_steps, runtime_issues.",
        )
    return loaded


def _record_handoff(args) -> None:
    payload = _build_handoff_payload(args)
    client, cfg = _client_for(args)
    try:
        agent_id = str(payload.get("agent_id") or "")
        guarded = payload.get("expected_handoff_version") is not None
        if not guarded and payload.get("agent_role") and payload.get("summary"):
            # Full checkpoints are idempotent: POST on the first write and
            # transparently PATCH on a duplicate agent_id.
            row = client.record_handoff(payload, upsert=True)
        else:
            # Lifecycle promotion is a true partial update. Requiring the
            # caller to re-send the summary risks replacing the specialist's
            # authored record just to change handoff_status.
            existing = client.get_handoff(agent_id)
            if existing is None:
                if guarded:
                    fail(
                        "agent handoff --from-json",
                        "expected_handoff_version guards an "
                        f"existing handoff row and {agent_id!r} has none yet; write the "
                        "first handoff without the guard",
                    )
                fail(
                    "agent handoff --from-json",
                    "agent_role and summary are required "
                    f"keys when creating new handoff {agent_id!r}",
                )
            patch = {
                key: value
                for key, value in payload.items()
                if key in _HANDOFF_PATCHABLE_FIELDS
            }
            if not patch:
                fail("agent handoff", "supply at least one handoff field to update")
            row = client.update_handoff(agent_id, patch)
    finally:
        client.close()
    artifact_states = _handoff_artifact_states(cfg.engagement_dir, row, payload)
    # `handoff_id` names the namespace (assessment_dispatch_handoffs) so it cannot
    # be confused with the `dispatch_id` that `agent start` prints — see the note there.
    print(json.dumps({
        "handoff_id": row.get("id"),
        "agent_id": row.get("agent_id"),
        "handoff_version": row.get("handoff_version"),
        "last_checkpoint_at": row.get("last_checkpoint_at"),
        "summary_characters": len(row.get("summary") or payload.get("summary") or ""),
        # The claim meets the filesystem here or nowhere: the backend already
        # computes this while registering each path and throws it away, and the
        # renderer only reports it to whoever reads the handoff LATER.
        "working_artifacts": [
            {"path": path, "state": state} for path, state in artifact_states
        ],
    }, ensure_ascii=False))
    _report_handoff_artifact_states(
        artifact_states,
        handoff_status=str(row.get("handoff_status") or payload.get("handoff_status") or ""),
        handoff_version=row.get("handoff_version"),
    )


def _handoff_artifact_states(
    engagement_dir: str, row: dict, payload: dict
) -> list[tuple[str, str]]:
    """Stat every artifact the stored handoff now claims, in recorded order.

    Prefer the row the backend returned: a lifecycle promotion patch carries no
    ``working_artifacts`` of its own, yet the row it promotes to ``ready`` still
    asserts every artifact an earlier checkpoint recorded.
    """
    claimed = row.get("working_artifacts")
    if not isinstance(claimed, list):
        claimed = payload.get("working_artifacts")
    if not isinstance(claimed, list):
        return []
    states: list[tuple[str, str]] = []
    for entry in claimed:
        if not isinstance(entry, dict):
            continue
        raw_path = str(entry.get("path") or "").strip()
        if not raw_path:
            continue
        _resolved, state = resolve_engagement_artifact_path(engagement_dir, raw_path)
        states.append((raw_path, state))
    return states


def _report_handoff_artifact_states(
    artifact_states: list[tuple[str, str]],
    *,
    handoff_status: str,
    handoff_version: object,
) -> None:
    """Warn per unverifiable artifact; refuse a `ready` handoff that claims one.

    ``checkpointed`` and ``blocked`` legitimately name an artifact whose write
    was aborted, so those stay warnings. ``ready`` asserts a finished result, so
    a file it did not write is the fabrication case and the command exits
    non-zero — AFTER the write, because discarding the specialist's authored
    summary over a path typo would destroy the durable state the handoff exists
    to hold.
    """
    unverifiable = [(path, state) for path, state in artifact_states if state != ARTIFACT_PRESENT]
    if not unverifiable:
        return
    for path, state in unverifiable:
        print(
            f"WARN agent handoff: working artifact {path!r} is {state}; no artifact row "
            "exists for it and `agent render-handoff` will show the next dispatch the "
            "same state. Write the file, or drop the entry from working_artifacts.",
            file=sys.stderr,
        )
    if handoff_status != "ready":
        return
    fail(
        "agent handoff",
        f"REFUSED to confirm this ready handoff: it claims "
        f"{len(unverifiable)} working artifact(s) that are not present in the "
        "engagement ("
        + ", ".join(f"{path} [{state}]" for path, state in unverifiable)
        + f"). The handoff row WAS persisted (handoff_version={handoff_version}) — this "
        "non-zero exit reports an unsubstantiated artifact claim, not a failed write. "
        "Write the files or remove the entries, then re-run the same command; a ready "
        "handoff asserting a file it never wrote is a fabricated result.",
    )
