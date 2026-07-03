"""Helpers for metadata-rich surface candidate records."""
from __future__ import annotations

import json
import re

from assess.lib.classify import classify_type


def json_text(value) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True)


def text_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "; ".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def int_value(value) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def slug_signal(value: str) -> str:
    slug = re.sub(r"[^a-z0-9_:-]+", "_", value.lower()).strip("_")
    return slug or "candidate"


def signal_tokens(record: dict) -> list[str]:
    raw = record.get("signals")
    if raw is None or raw == []:
        raw = record.get("selection_reasons")
    if isinstance(raw, dict):
        values = list(raw.keys())
    elif isinstance(raw, list):
        values = raw
    elif isinstance(raw, str):
        values = [part.strip() for part in raw.split(",")]
    else:
        values = []
    return [slug_signal(str(value)) for value in values if str(value).strip()]


def signal_has(signals: set[str], *needles: str) -> bool:
    return any(needle in signal for signal in signals for needle in needles)


def surface_refs(record: dict) -> list[int]:
    """Extract candidate ``surface_refs`` as a list of backend surface ids.

    A candidate record may name the backend surfaces its request variant
    belongs to so ingest can auto-create the surface↔request-variant links.
    Non-integer / non-positive entries are dropped defensively rather than
    failing the whole record.
    """
    raw = record.get("surface_refs")
    if isinstance(raw, (int, str)):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    refs: list[int] = []
    for value in raw:
        ref = int_value(value)
        if ref is not None and ref > 0 and ref not in refs:
            refs.append(ref)
    return refs


def selected_by(record: dict, signals: list[str]) -> str | None:
    selected = record.get("selected_by") or record.get("selected_signal")
    if selected:
        return str(selected)
    if signals:
        return signals[0]
    return None


def priority_reason(record: dict) -> str | None:
    reason = (
        record.get("priority_reason")
        or record.get("triage_rationale")
        or record.get("rationale")
        or record.get("selection_reasons")
    )
    return text_value(reason)


def cluster_key(record: dict, selected: str | None) -> str | None:
    cluster = record.get("cluster_key") or record.get("bucket")
    if cluster:
        return str(cluster)
    if selected:
        slug = slug_signal(selected)
        return slug if slug.startswith("gf:") else f"gf:{slug}"
    return None


def candidate_type(record: dict, method: str, url_path: str, signals: list[str]) -> str:
    explicit = str(record.get("type") or "").strip()
    if explicit and explicit != "unknown":
        return explicit

    signal_set = set(signals)
    path = url_path.lower()
    if signal_set & {"debug", "debug_config", "admin_debug", "config", "backup_config"} or signal_has(
        signal_set, "debug", "config", "secret", "admin"
    ) or any(
        token in path for token in ("/admin", "/debug", "/console", "/config", "/.env")
    ):
        return "debug_config"
    if signal_set & {"feed", "event_feed", "events", "stream"} or signal_has(
        signal_set, "event", "feed", "stream"
    ) or any(
        token in path for token in ("/feed", "/event-feed", "/org-event-feed", "/events", "/notifications", "/stream")
    ):
        return "event_feed"
    if signal_set & {"portal", "portal_session"} or signal_has(signal_set, "portal") or "/s/" in path or "portalsession" in path:
        return "portal_session"
    if signal_set & {"auth", "login", "sso", "session"} or signal_has(signal_set, "auth", "login", "session") or any(
        token in path for token in ("/login", "/logout", "/auth", "/sso", "/oauth", "/session", "/token")
    ):
        return "auth_entry"
    if signal_set & {"workflow", "registration", "onboarding"} or signal_has(
        signal_set, "workflow", "drupal", "form", "object_reference", "filter"
    ) or any(
        token in path for token in ("/register", "/enroll", "/submit", "/apply", "/reset", "/recover", "/workflow", "/online-form", "/media/oembed")
    ):
        return "workflow"

    detected = classify_type(method, url_path, "", "")
    if detected == "api" or signal_has(signal_set, "api"):
        return "api_route"
    return detected


def candidate_metadata(record: dict, case_type: str, signals: list[str]) -> dict[str, object]:
    selected = selected_by(record, signals)
    metadata: dict[str, object] = {
        "priority_score": int_value(record.get("priority_score", record.get("score"))),
        "priority_reason": priority_reason(record),
        "cluster_key": cluster_key(record, selected),
        "signals": signals,
        "selected_by": selected,
        "triage_rationale": text_value(
            record.get("triage_rationale") or record.get("rationale") or record.get("selection_reasons")
        ),
        "live_status": text_value(record.get("live_status") or record.get("status")),
        "type": case_type,
    }
    return {key: value for key, value in metadata.items() if value not in (None, "", [])}
