"""vigil assess export-findings — generate the single findings.md report doc from backend state.

This produces ONE consolidated report document (one ``## [slug] title`` section
per finding, severity-sorted, with root-cause grouping inline). For a
git-diff-able per-finding tree (draft/debate/report.md per finding) use instead:
``vigil engagement export --format markdown-tree``.

The per-finding markdown block is produced by the shared renderer in
``assess.lib.finding_render`` (also used by the markdown-tree export) so the two
exporters never drift.
"""
from __future__ import annotations

import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.finding_render import render_finding
from assess.lib.scope import load_scope

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "findings",
        help=(
            "Generate the single findings.md report doc from backend state "
            "(one section per finding). For a diffable per-finding tree use "
            "`vigil engagement export --format markdown-tree`."
        ),
    )
    p.set_defaults(func=run)


def _render_finding(f: dict) -> str:
    """Render one finding's findings.md section via the shared renderer.

    export-findings includes the inline root-cause grouping bullets that the
    markdown-tree draft omits, and re-joins the (newline-stripped) blocks itself
    in ``run`` — hence ``include_root_cause_group=True`` and no trailing newline.
    """
    return render_finding(f, include_root_cause_group=True)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    scope = load_scope(cfg.engagement_dir)
    engagement_name = scope.get("engagement_name") or scope.get("name") or cfg.engagement_key

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        findings = client.get("findings")
        groups = client.get("finding-groups")

    if not isinstance(findings, list):
        print("export-findings: unexpected response from backend", file=sys.stderr)
        sys.exit(1)
    if not isinstance(groups, list):
        groups = []

    finding_by_slug = {str(finding.get("slug", "")): finding for finding in findings if finding.get("slug")}
    for group in groups:
        if not isinstance(group, dict):
            continue
        root = group.get("root")
        if isinstance(root, dict):
            root_slug = str(root.get("slug", ""))
            if root_slug in finding_by_slug:
                finding_by_slug[root_slug]["root_cause_role"] = "root"
                finding_by_slug[root_slug]["sibling_count"] = group.get("sibling_count", 0)
        for sibling in group.get("siblings", []):
            if not isinstance(sibling, dict):
                continue
            sibling_slug = str(sibling.get("slug", ""))
            if sibling_slug in finding_by_slug:
                finding_by_slug[sibling_slug].update(
                    {
                        "root_cause_role": "sibling",
                        "root_cause_slug": sibling.get("root_cause_slug", ""),
                        "root_cause_effect": sibling.get("root_cause_effect", "eliminates_finding"),
                        "root_cause_note": sibling.get("root_cause_note", ""),
                        "sibling_order": sibling.get("sibling_order"),
                    }
                )

    findings.sort(key=lambda f: (
        _SEVERITY_ORDER.get((f.get("severity") or "medium").lower(), 99),
        f.get("slug", ""),
    ))

    header_lines = [
        f"# Findings — {engagement_name}",
        "",
        f"- **Finding Count**: {len(findings)}",
        "",
    ]

    body_blocks = [_render_finding(f) for f in findings]
    # Separate sections with a blank line so consecutive ``##`` headings are not
    # glued onto the previous section's last line (which collapses two findings
    # into one in most Markdown renderers). The leading "\n" guarantees a blank
    # line between the header block and the first finding too.
    body = "\n\n".join(body_blocks)
    content = "\n".join(header_lines) + ("\n" + body + "\n" if body else "")

    out_path = Path(cfg.engagement_dir) / "findings.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"Exported {len(findings)} findings to {out_path}")
