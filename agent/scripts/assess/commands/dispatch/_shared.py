"""Shared helpers for the dispatch package (CLI arg parsing, time, JSON).

Small pure utilities used by both the work-buffer (``work_items``) and the
backend lifecycle (``agent``) submodules. Kept here so neither submodule has
to import the other just to reach a CSV splitter or an ISO timestamp.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [token.strip() for token in value.split(",") if token.strip()]


def _looks_like_json_path(text: str) -> bool:
    """True when the value can only have been meant as a path, never inline JSON.

    A `.json` suffix is only ambiguous for a bare JSON string literal, which
    would start with a quote rather than an object/array opener; guarding on the
    opener keeps inline payloads out of the path branch.
    """
    if text.startswith("@") or text.startswith("/"):
        return True
    return text.endswith(".json") and not text.startswith(("{", "["))


def _load_json_arg(value: str | None) -> Any:
    """Read a `--*-json` flag: inline JSON, a path to a JSON file, or ``-`` (stdin).

    A value that is unambiguously a path reports a missing file AS a missing
    file. Retrying it as inline JSON reported "invalid JSON" for a mistyped
    filename, which lands on a specialist at the end of its dispatch — exactly
    where a misread error produces an unwritten handoff.
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    if text == "-":
        try:
            return json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            print(f"ERROR: invalid JSON on stdin: {exc}", file=sys.stderr)
            sys.exit(1)
    if _looks_like_json_path(text):
        candidate = text[1:] if text.startswith("@") else text
        try:
            with open(candidate, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except FileNotFoundError:
            print(f"ERROR: no such JSON file: {candidate}", file=sys.stderr)
            sys.exit(1)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"ERROR: failed to read JSON from {candidate}: {exc}", file=sys.stderr)
            sys.exit(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        print(
            f"ERROR: invalid JSON: {exc}. A file argument must be absolute, start "
            "with '@', or end with '.json'; '-' reads the payload from stdin.",
            file=sys.stderr,
        )
        sys.exit(1)


# The three states a declared working-artifact path can be in. `present` is
# EXISTENCE, matching the backend artifact index: a directory of captures is
# present even though it has no body to hash.
ARTIFACT_PRESENT = "present"
ARTIFACT_MISSING = "missing"
ARTIFACT_OUT_OF_ENGAGEMENT = "out-of-engagement"


def resolve_engagement_artifact_path(
    engagement_dir: str | os.PathLike[str], raw_path: str
) -> tuple[Path | None, str]:
    """Resolve one ``working_artifacts[].path`` and report its on-disk state.

    One rule for both the handoff WRITE receipt and ``render-handoff``, mirroring
    the backend artifact index (``_normalize_relative_path``): a non-file URL or
    a path that resolves outside the engagement root is not engagement-local, so
    the backend refuses to register it and no artifact row can exist for it.
    Reporting such a path as ``present`` because it happens to exist on the
    operator's disk is the one answer that is never true of the engagement.
    """
    text = str(raw_path or "").strip()
    root = Path(engagement_dir).expanduser().resolve()
    if not text:
        return None, ARTIFACT_OUT_OF_ENGAGEMENT
    if "://" in text and urlparse(text).scheme != "file":
        return None, ARTIFACT_OUT_OF_ENGAGEMENT
    raw = Path(text)
    candidate = raw.expanduser() if raw.is_absolute() else root / raw
    try:
        resolved = candidate.resolve()
        inside = True
        try:
            resolved.relative_to(root)
        except ValueError:
            inside = False
        if not inside:
            return None, ARTIFACT_OUT_OF_ENGAGEMENT
        present = resolved.exists()
    except OSError:
        # The handoff write has already landed by the time this runs, so a path
        # the filesystem refuses to answer for must report a state rather than
        # replace the receipt with a traceback. It is not usable by the next
        # dispatch either way.
        return None, ARTIFACT_MISSING
    return resolved, (ARTIFACT_PRESENT if present else ARTIFACT_MISSING)


#: Roles whose completeness contract runs through a queue lease. Only
#: ``code-vuln-hunter`` fetches and completes a queue item (see
#: ``agent/shared-constraints-code.md`` §11), so only its dispatches can be
#: non-covering for want of one.
LEASE_BEARING_ROLES = frozenset({"code-vuln-hunter"})


def lane_coverage_basis(context: object) -> str:
    """What a dispatch's file coverage is anchored to, as one rendered phrase.

    ``code-record analysis`` and ``code-dispatch done`` both require the fetched
    ``queue_item_id``/``lease_token`` pair, so a lane handed neither
    ``queue_item_ids`` nor a ``lane_file`` cannot write a receipt for anything it
    reads. One resolver for the dispatch-time advisory and ``render-handoff`` so
    the operator is told the same thing before and after the lane runs; the empty
    string means "no lease basis at all".
    """
    if not isinstance(context, dict):
        return ""
    parts: list[str] = []
    queue_ids = context.get("queue_item_ids")
    if isinstance(queue_ids, (list, tuple)) and queue_ids:
        parts.append(
            "queue items " + ", ".join(str(item) for item in queue_ids)
        )
    lane_file = str(context.get("lane_file") or "").strip()
    if lane_file and lane_file.lower() not in {"none", "not applicable", "not supplied"}:
        parts.append(f"lane_file {lane_file}")
    return "; ".join(parts)


def _safe_int_arg(value: str, name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        print(f"ERROR: {name} must be an integer (got '{value}')", file=sys.stderr)
        sys.exit(1)


def _validate_id_list(id_list) -> list[int]:
    """Parse and validate IDs given as a comma-separated string OR a list of tokens.

    Accepts either ``"1,2,3"``, ``["1", "2", "3"]``, or mixed forms like
    ``["1,2", "3"]``. Pure-comma strings (``","``) and empty inputs raise so a
    typo doesn't silently turn into a no-op UPDATE.
    """
    if isinstance(id_list, (list, tuple)):
        tokens: list[str] = []
        for entry in id_list:
            tokens.extend(str(entry).split(","))
    else:
        tokens = str(id_list).split(",")
    cleaned = [token.strip() for token in tokens if token.strip()]
    if not cleaned:
        print(
            "ERROR: id_list must contain at least one numeric ID (got empty/comma-only input)",
            file=sys.stderr,
        )
        sys.exit(1)
    ids: list[int] = []
    for token in cleaned:
        if not token.isdigit():
            print(
                f"ERROR: id_list must contain only numeric IDs (got '{token}')",
                file=sys.stderr,
            )
            sys.exit(1)
        ids.append(int(token))
    return ids
