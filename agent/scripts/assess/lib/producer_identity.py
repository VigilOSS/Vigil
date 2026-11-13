"""The report-writer dispatch a report or submission registration is attributed to.

Report and submission QC (ADR 0045) refuse a reviewer that registered the bytes
it reviews, so every registration of ``report.md`` or a submission workspace
names the dispatch that wrote it. A specialist's shell carries no per-dispatch
identity: no dispatch launch path exports one (native clients spawn subagents
in the operator's environment, and ``$AGENT_NAME`` / ``$VIGIL_AGENT_NAME`` are
only read, never set, by Vigil). So when ``--agent-id`` is omitted the backend's
in-progress report-writer dispatches decide: the one in scope is the writer,
several are refused as ambiguous, and none means the operator is rendering.
``--agent-id`` always wins.

The inference reads dispatch state, not the caller, so it cannot tell the
operator from the writer: a render the operator runs while exactly one
report-writer dispatch is in scope is credited to that writer. The operator
renders before dispatching the writer or after closing it.
"""
from __future__ import annotations

import sys
from typing import Any
from urllib.parse import urlencode

from assess.lib.client import AssessError, require_recorded_dispatch

REPORT_WRITER_ROLE = "report-writer"
# The dispatch list's page ceiling (`MAX_ASSESSMENT_LIST_LIMIT`). A full page
# cannot say there is only one writer, so it is refused rather than guessed from.
_DISPATCH_PAGE_LIMIT = 5000


def resolve_report_writer(
    client: Any,
    agent_id: str | None,
    *,
    operation: str,
    finding_slug: str | None = None,
    unattributed_note: str = "",
) -> str | None:
    """The dispatch to record as producer, or None for the operator's render.

    *finding_slug* scopes a submission: writers whose ``finding_slugs`` name it,
    else writers that name no finding (a writer scoped to another finding is
    writing that one). *unattributed_note* is printed when no writer is in
    progress, after the line saying the render is the operator's.
    """
    explicit = (agent_id or "").strip()
    if explicit:
        require_recorded_dispatch(client, explicit, operation=operation)
        return explicit
    rows = client.get("dispatches?" + urlencode({
        "role": REPORT_WRITER_ROLE, "status": "in_progress", "limit": _DISPATCH_PAGE_LIMIT,
    }))
    if not isinstance(rows, list):
        raise AssessError(
            f"{operation}: the in-progress report-writer dispatch list is not a list; "
            "pass --agent-id <your dispatch agent_id> from your packet's Runtime Identity"
        )
    if len(rows) >= _DISPATCH_PAGE_LIMIT:
        raise AssessError(
            f"{operation}: {len(rows)} in-progress report-writer dispatches fill one page, "
            "so the writer cannot be told apart; pass --agent-id <your dispatch agent_id> "
            "from your packet's Runtime Identity"
        )
    scope = f" for {finding_slug}" if finding_slug else ""
    pool = [row for row in rows if isinstance(row, dict)]
    if finding_slug:
        named = [row for row in pool if finding_slug in (row.get("finding_slugs") or [])]
        pool = named or [row for row in pool if not row.get("finding_slugs")]
    ids = sorted({str(row["agent_id"]) for row in pool if row.get("agent_id")})
    if len(ids) == 1:
        print(
            f"{operation}: attributed to {ids[0]}, the one in-progress report-writer "
            f"dispatch{scope}; pass --agent-id to name another dispatch",
            file=sys.stderr,
        )
        return ids[0]
    if ids:
        raise AssessError(
            f"{operation}: {len(ids)} in-progress report-writer dispatches{scope} could "
            f"have written this ({', '.join(ids)}), so it cannot be attributed; pass "
            "--agent-id <your dispatch agent_id> from your packet's Runtime Identity"
        )
    print(
        f"{operation}: no in-progress report-writer dispatch{scope}, so this is "
        "recorded as the operator's registration (no producer dispatch)"
        + (f". {unattributed_note}" if unattributed_note else ""),
        file=sys.stderr,
    )
    return None
