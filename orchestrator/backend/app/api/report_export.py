from __future__ import annotations

import datetime as dt
import importlib.metadata
import json
import os
import uuid
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from ..services import artifact_index
from ..services import state_manager
from ..services.engagements import get_engagement_view_or_404

router = APIRouter(prefix="/engagements/{engagement_key}/assessment", tags=["assessment"])

# The sentinel string the single-file report template ships with, anchored to
# the closing </script> tag of the data node so we replace ONLY the data node
# and never the identical string baked into the bundled JS (which references it
# as a constant for its own dev-fallback detection). See
# orchestrator/report/index.html and orchestrator/report/src/App.tsx.
_SENTINEL = '"__VIGIL_REPORT_DATA__"'
_INJECT_TARGET = _SENTINEL + "</script>"

_TEMPLATE_MISSING_HELP = (
    "Report template not built. Run `cd orchestrator/report && npm ci && npm run build` "
    "(or `vigil orchestrator build`) to produce dist/template.html, then retry."
)


def _vigil_version() -> str:
    try:
        return importlib.metadata.version("vigil-orchestrator-backend")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class ReportExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["draft", "final"] = Field(default="draft")


def _assemble_report_payload(engagement, mode: str) -> dict[str, Any]:
    """Build the injected report payload from existing projections only.

    No new SQL — calls assessment_summary, list_report_finding_groups,
    list_attack_chains, and report_readiness, exactly mirroring the
    orchestrator/report/src/types.ts ReportData contract.
    """
    summary = state_manager.assessment_summary(engagement.id)
    finding_groups = state_manager.list_report_finding_groups(engagement.id, mode=mode)
    attack_chains = state_manager.list_attack_chains(engagement.id)
    readiness = state_manager.report_readiness(engagement.id)
    return {
        "generated_at": _utc_now().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "vigil_version": _vigil_version(),
        "mode": mode,
        "engagement": {
            "key": engagement.key,
            "target": engagement.target,
            "status": engagement.status,
            "current_phase": engagement.current_phase,
            "engagement_type": engagement.engagement_type,
            "customer": engagement.customer,
            "scope_hosts": list(engagement.scope_hosts or []),
            "created_at": engagement.created_at,
        },
        "summary": summary,
        "finding_groups": finding_groups,
        "attack_chains": attack_chains,
        "report_readiness": readiness,
    }


def _encode_payload_for_script(payload: dict[str, Any]) -> str:
    """JSON-encode the payload safely for embedding inside a <script> node.

    Finding titles/notes/summaries and attack-chain narratives are
    attacker-influenced (they describe what a target app does, including raw
    payloads), so the encoded JSON must not be able to alter the surrounding
    HTML markup. The contents of *any* ``<script>`` element \u2014 including
    ``type="application/json"`` \u2014 are tokenized in the HTML "script data" state,
    where a bare ``</`` is not the only breakout: ``<!--`` followed by
    ``<script`` enters the script-data-double-escaped state, in which the data
    node's own ``</script>`` no longer closes it and the rest of the document is
    swallowed as script text. Escaping only ``</`` therefore does not protect
    the node.

    - ``ensure_ascii=False`` keeps the file compact/readable.
    - Every ``<`` and ``>`` is rewritten to its ``\\u003c`` / ``\\u003e`` JSON
      escape. ``JSON.parse(textContent)`` decodes these back losslessly, but no
      ``<!--`` / ``<script`` / ``</script`` byte sequence can survive in the
      markup, so the data node cannot influence HTML tokenization at all.
    - U+2028 / U+2029 are escaped because, although valid in JSON strings, they
      are line terminators in ECMAScript and would corrupt the inline script.
    """
    json_text = json.dumps(payload, ensure_ascii=False)
    json_text = json_text.replace("<", "\\u003c").replace(">", "\\u003e")
    json_text = json_text.replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    return json_text


def _render_report_html(payload: dict[str, Any]) -> str:
    template_path = settings_report_template_path()
    if not template_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"detail": _TEMPLATE_MISSING_HELP, "fix": "vigil orchestrator build"},
        )
    template = template_path.read_text(encoding="utf-8")
    if _INJECT_TARGET not in template:
        # A built template that lost its data node — treat like a missing build
        # rather than silently shipping an un-injectable report.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "detail": (
                    "Report template is present but missing its data-injection node. "
                    + _TEMPLATE_MISSING_HELP
                ),
                "fix": "vigil orchestrator build",
            },
        )
    encoded = _encode_payload_for_script(payload)
    # Replace exactly once, anchored on the closing tag so only the data node
    # (not the JS constant) is rewritten.
    return template.replace(_INJECT_TARGET, encoded + "</script>", 1)


def settings_report_template_path() -> Path:
    # Indirection so tests (and a future env override) can point at a temp
    # template by overriding settings.report_template_path the way conftest
    # overrides frontend_dist_dir.
    from ..config import settings

    return Path(settings.report_template_path)


@router.post("/report-export")
def export_report(engagement_key: str, request: ReportExportRequest) -> dict[str, Any]:
    engagement = get_engagement_view_or_404(engagement_key)
    mode = request.mode

    if mode == "final":
        readiness = state_manager.report_readiness(engagement.id)
        if not readiness["ready"]:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=readiness)

    payload = _assemble_report_payload(engagement, mode)
    html = _render_report_html(payload)

    root = Path(engagement.engagement_root).resolve()
    reports_dir = root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    # The second-precision stamp keeps the filename human-sortable, but two
    # exports for the same engagement+mode within the same UTC second (two UI
    # sessions, an API retry) would otherwise resolve to the same path — the
    # second write overwrites the first, and register_artifact upserts the same
    # relative_path, so an earlier response's artifact_id/download would later
    # serve different report contents. A short uuid4 suffix makes each export a
    # distinct, collision-proof artifact.
    stamp = _utc_now().strftime("%Y%m%dT%H%M%SZ")
    unique = uuid.uuid4().hex[:8]
    filename = f"vigil-report-{mode}-{stamp}-{unique}.html"
    out_path = reports_dir / filename
    out_path.write_text(html, encoding="utf-8")
    size_bytes = out_path.stat().st_size

    record = artifact_index.register_artifact(
        engagement.id,
        path=str(out_path),
        kind="report",
        media_type="text/html",
        producer_agent_role="orchestrator-ui",
    )

    return {
        "artifact_id": int(record["id"]),
        "relative_path": str(record["relative_path"]),
        "mode": mode,
        "size_bytes": size_bytes,
    }


@router.get("/report-export/{artifact_id}/download")
def download_report(engagement_key: str, artifact_id: int) -> FileResponse:
    engagement = get_engagement_view_or_404(engagement_key)
    record = artifact_index.get_artifact(engagement.id, artifact_id)
    # The artifact must belong to this engagement (enforced by get_artifact's
    # engagement_id scoping) AND be a report we generated — never serve an
    # arbitrary indexed file through this route.
    if record.get("kind") != "report":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report artifact not found")
    root = Path(engagement.engagement_root).resolve()
    file_path = (root / str(record["relative_path"])).resolve()
    # Defense in depth: confirm the resolved path is still inside the
    # engagement root and exists on disk.
    if not file_path.is_file() or os.path.commonpath([str(root), str(file_path)]) != str(root):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report file not found")
    return FileResponse(
        path=file_path,
        media_type="text/html",
        filename=file_path.name,
        content_disposition_type="attachment",
    )
