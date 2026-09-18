from __future__ import annotations

import datetime as dt
import importlib.metadata
import json
import os
import uuid
from collections import Counter
from collections.abc import Mapping
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


# ── The delivered payload's field allow-lists ─────────────────────────────
#
# The exported HTML is the one Vigil artifact whose reader is the CLIENT rather
# than the operator, so what travels in its data node is a disclosure decision.
# The projections below all return whole SQL rows: `SELECT *` on
# assessment_findings carried `notes`, `provenance`, the raw `details` object
# and the `submission_*` columns into every delivered report, none of which the
# template renders, and all of which a reader sees with View Source.
#
# This is NOT the masking ADR 0019 forbids, and the distinction is the whole
# design: a field is copied verbatim or dropped outright — nothing is masked,
# truncated, or reduced to a shape. And the narrowing lives HERE, at the
# delivery boundary, never inside the projections: `list_report_finding_groups`
# also backs `GET report-findings` and `vigil assess finding report --json`,
# which the operator and the report-writer specialist read, and those must keep
# every column.
#
# Each tuple is one half of a contract whose other half is
# orchestrator/report/src/types.ts, and a tuple carries a field only if a
# component actually reads it (FullReport, FindingsTab, StatisticsTab,
# FindingParts, lib/findingMarkdown, lib/format) — a field can be read without
# being typed, and declared without being read.
#
# Both directions are pinned. `npm run build`'s `tsc --noEmit` catches a
# component reading a field types.ts does not declare; the other direction — a
# field this module stops sending, which renders blank in a client's report and
# raises no error anywhere — is pinned by tests/test_report_export.py, which
# parses these four interfaces out of types.ts and asserts set-equality against
# the tuples below. So adding a field to the template means adding it in both
# places, and removing one from either side fails the build or the suite.

# ReportSummary, pass-through half: keys copied verbatim out of
# assessment_summary(), which additionally returns whole surface rows, recent
# probe evidence refs, open coverage URLs and an egress rollup. These three
# describe the engagement — how much attack surface was left open, how many
# credentials it held, how many chains it proved — and the Statistics tab renders
# all three as stat cards.
_SUMMARY_FIELDS = (
    "attack_chain_count",
    "open_surface_count",
    "credential_count",
)

# ReportSummary, derived half: the finding rollups, computed from THIS report's
# own findings rather than copied from assessment_summary.
#
# assessment_summary is not mode-filtered. Its status rollups are unfiltered
# ``GROUP BY``s over every row of assessment_findings, and its count/severity
# rollups admit everything that is not merged or false-positive — including
# findings no report projection will show, because a report admits only
# ``confirmed``/``downgraded`` (and, for a final export, a reportable workflow
# status). Copying them handed a client a headline count and a severity donut
# describing more findings than their report contained, and a Workflow chart
# carrying internal triage state down to a literal `false positive` row.
#
# That is the same disclosure argument this module already accepted when it
# stopped shipping ``report_readiness`` in a final export. Deriving them is not
# masking either: no value is reduced or reshaped, the question is simply asked
# of the delivered findings instead of the whole triage queue. The operator's own
# ``GET /assessment/summary`` is untouched and still counts everything.
#
# Draft and final do NOT differ here, deliberately. A draft's summary describing
# a body it disagrees with is the same defect wearing a different mode, and the
# operator reading a draft already has the unfiltered rollups one endpoint away —
# plus ``report_readiness``, which a draft still ships, to name what is being
# held back and why.
_DERIVED_SUMMARY_FIELDS = (
    "finding_count",
    "finding_severities",
    "finding_workflow_statuses",
    "finding_verification_statuses",
)

# ReportFinding. The trailing root-cause keys exist on siblings only — they are
# written onto the record by links.py:_root_cause_link_metadata, whose other
# three keys the template has no use for: the group structure already names the
# root (`root_cause_slug`) and already carries the siblings in the order the
# backend sorted them into (`sibling_order`), and `root_cause_link_id` is a row
# id. Because they are the payload's only conditionally-present fields, a fixture
# holding one standalone finding covers neither of the two that survive — see
# tests/test_report_export.py, which exports a real group.
_FINDING_FIELDS = (
    "report_id",
    "slug",
    "title",
    "severity",
    "workflow_status",
    "verification_status",
    "canonical_location",
    "auth_context",
    "evidence_type",
    "source_name",
    "summary",
    "impact",
    "evidence_detail",
    "remediation",
    "steps_to_reproduce",
    "repro_runs",
    "cwe_id",
    "owasp_category",
    "cvss_score",
    "cvss_vector",
    "entry_point",
    "sink",
    "poc_code",
    "poc_request",
    "poc_response",
    "references",
    "root_cause_effect",
    "root_cause_note",
)

# ReportAttackChain. Drops the chain's own `evidence_ref` and `provenance_json`,
# and `created_at` with them: the chain header renders when the path was last
# established, never when its row was first inserted.
_CHAIN_FIELDS = (
    "chain_key",
    "title",
    "status",
    "severity",
    "narrative",
    "updated_at",
)

# ReportAttackChainLink. `entity_id` is deliberately absent: the report resolves
# a step through `entity_ref`, which report_readiness requires on every step
# link of a finalizable engagement, and the payload carries no finding row ids
# for an `entity_id` to resolve against.
_CHAIN_LINK_FIELDS = ("chain_key", "relation", "entity_kind", "entity_ref", "notes")

# ReportReadiness, minus the `coverage` rollup that no component reads.
_READINESS_FIELDS = ("ready", "blocker_count", "blockers", "advisory_count", "advisories")


def _project(record: Mapping[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Copy the allow-listed keys of ``record`` verbatim, dropping every other."""
    return {field: record[field] for field in fields if field in record}


def _report_finding_groups(engagement_id: int, mode: str) -> dict[str, Any]:
    groups = state_manager.list_report_finding_groups(engagement_id, mode=mode)
    return {
        "mode": groups["mode"],
        "groups": [
            {
                "root": _project(group["root"], _FINDING_FIELDS),
                "siblings": [_project(item, _FINDING_FIELDS) for item in group["siblings"]],
                "sibling_count": group["sibling_count"],
                "residual_path_count": group["residual_path_count"],
                "highest_severity": group["highest_severity"],
            }
            for group in groups["groups"]
        ],
        "standalone": [_project(item, _FINDING_FIELDS) for item in groups["standalone"]],
        "group_count": groups["group_count"],
        "standalone_count": groups["standalone_count"],
        "finding_count": groups["finding_count"],
    }


def _summary_finding_rollups(groups: Mapping[str, Any]) -> dict[str, Any]:
    """Roll the delivered findings up into the numbers the Statistics tab shows.

    Counted over the projected payload itself — every root, every sibling, every
    standalone — so the headline count, the severity donut and the two breakdown
    charts describe exactly the findings the reader can scroll to. See
    ``_DERIVED_SUMMARY_FIELDS`` for why they are not copied from
    ``assessment_summary``. Keys are sorted to mirror that projection's own
    ``ORDER BY``; absent values are not counted rather than being given an
    invented default.
    """
    records = [
        *(
            record
            for group in groups["groups"]
            for record in (group["root"], *group["siblings"])
        ),
        *groups["standalone"],
    ]
    rollups: dict[str, Counter[str]] = {
        field: Counter() for field in ("severity", "workflow_status", "verification_status")
    }
    for record in records:
        for field, counter in rollups.items():
            value = record.get(field)
            if isinstance(value, str) and value:
                counter[value] += 1
    return {
        "finding_count": len(records),
        "finding_severities": dict(sorted(rollups["severity"].items())),
        "finding_workflow_statuses": dict(sorted(rollups["workflow_status"].items())),
        "finding_verification_statuses": dict(
            sorted(rollups["verification_status"].items())
        ),
    }


def _report_attack_chain_links(engagement_id: int) -> list[dict[str, Any]]:
    """Chain links in the order they were recorded, which is their step order.

    ``list_attack_chain_links`` orders newest-first for the operator SPA's
    activity views. The schema carries no step-order column, so insertion order
    (``id`` ascending) is the only ordering the recorded path has — re-sort it
    here rather than shipping a row id the renderer has no other use for.
    """
    links = sorted(state_manager.list_attack_chain_links(engagement_id), key=lambda link: link["id"])
    return [_project(link, _CHAIN_LINK_FIELDS) for link in links]


def _assemble_report_payload(engagement, mode: str) -> dict[str, Any]:
    """Build the injected report payload from existing projections only.

    No new SQL — calls assessment_summary, list_report_finding_groups,
    list_attack_chains, list_attack_chain_links, and report_readiness, then
    narrows each to the fields the orchestrator/report/src/types.ts ReportData
    contract declares (see the allow-lists above). The summary's finding rollups
    are the one thing not copied from a projection: they are recounted from this
    report's own findings, so its headline numbers and its body agree.
    """
    finding_groups = _report_finding_groups(engagement.id, mode)
    payload = {
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
        "summary": {
            **_project(state_manager.assessment_summary(engagement.id), _SUMMARY_FIELDS),
            **_summary_finding_rollups(finding_groups),
        },
        "finding_groups": finding_groups,
        "attack_chains": [
            _project(chain, _CHAIN_FIELDS)
            for chain in state_manager.list_attack_chains(engagement.id)
        ],
        "attack_chain_links": _report_attack_chain_links(engagement.id),
    }
    if mode == "draft":
        # Draft only, mirroring the Statistics tab's ReadinessNotice. A `final`
        # export cannot be produced while blockers stand, so the reader of one
        # is shown nothing here — while its ADVISORIES are not empty by
        # construction and quote internal QA doubt about the engagement's own
        # evidence. The reader of a draft is the operator, who acts on them.
        payload["report_readiness"] = _project(
            state_manager.report_readiness(engagement.id), _READINESS_FIELDS
        )
    return payload


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
