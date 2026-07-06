"""vigil assess export-submission — per-finding, platform-shaped submission writeup.

Renders ONE finding into a submission-ready ``submission.md`` (+ a machine-readable
``submission-context.json``) under ``$ENGAGEMENT_DIR/submissions/<slug>/``, shaped
for a bug-bounty platform (Bugcrowd / HackerOne) or a direct company disclosure.

This is the submission-first replacement for the retired red/code ``report.md``
path (docs/plans/submission-first-reporting-2026-07.md). Two modes:

  * ``--draft`` (the normal report-writer entrypoint) always writes, inserting
    ``[NEEDS: <field>]`` markers wherever a proof-critical field is missing.
  * final (default) applies the strict gate: it refuses to write and exits
    non-zero unless title, severity + CVSS vector, the platform taxonomy
    (Bugcrowd VRT / HackerOne weakness), an attacker-impact statement, and at
    least one concrete proof are all present.

Field selection and PoC formatting reuse ``assess.lib.finding_render`` so a
submission never drifts from ``export-findings`` / the markdown-tree export. The
rendered structure mirrors the platform templates under
``agent/skills/report-generation/templates/{bugcrowd,hackerone,direct}.md`` (this
command references them by path; it does not read their bytes).

Command evidence is sourced ONLY from explicit ``finding-links``
(``target_kind="command_run"``) — never a fuzzy command search (plan decision 4).
The generated ``submission.md`` is registered as a finding-linked artifact
(``kind="submission"``); the finding's ``submission_status`` is never written
(omitting the field preserves it).

The generator is FAITHFUL: it never rewrites the finding's content — a
target-application UUID, a filename, or a path reaches the report-writer
verbatim, because silently mangling them (a blanket UUID scrub redacting the very
identifier a PoC proves, a greedy ``cases.db`` regex clipping a real filename)
confuses the editor more than it protects. Instead it FLAGS internal identifiers
— this finding's slug, engagement / finding / agent UUIDs, absolute engagement
paths, and cases.db references — as non-destructive ``hygiene_warnings`` (in the
context JSON and on stderr), so the report-writer and the blind-triage gate strip
them deliberately before an EXTERNAL submission.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
# ``_fence_for`` and ``header_lines`` are the same PoC-formatting primitives the
# shared finding renderer uses (finding_render.py ~:205/:225); reusing them keeps
# submission PoC blocks byte-identical to export-findings rather than reimplementing.
from assess.lib.finding_render import _fence_for, detail_value, details_object, header_lines, string_list

_PLATFORMS = ("bugcrowd", "hackerone", "direct")
_PLATFORM_LABEL = {"bugcrowd": "Bugcrowd", "hackerone": "HackerOne", "direct": "Direct disclosure"}

# UUID shape — used only to confirm a collected internal id is genuinely a UUID
# before we FLAG (never rewrite) its presence. A target-application UUID in PoC
# proof (e.g. an IDOR/BOLA on a UUID-keyed resource) is never touched.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
# Detects a reference to the internal cases.db work database (presence only).
_CASES_DB_RE = re.compile(r"cases\.db")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "export-submission",
        help=(
            "Render one finding into a platform-shaped, submission-ready "
            "submission.md (+ context JSON). --draft always writes with "
            "[NEEDS: ...] markers; final mode gates on proof completeness."
        ),
    )
    p.add_argument("slug", help="Finding slug to render (e.g. VA-047)")
    p.add_argument(
        "--platform",
        required=True,
        choices=_PLATFORMS,
        help="Submission target: bugcrowd (VRT) | hackerone (weakness) | direct (company-facing)",
    )
    p.add_argument(
        "--draft",
        action="store_true",
        help="Always write; mark missing proof-critical fields with [NEEDS: ...] instead of gating.",
    )
    p.add_argument(
        "--output",
        dest="output_dir",
        default="",
        help="Override the output directory (default: $ENGAGEMENT_DIR/submissions/<slug>/).",
    )
    p.add_argument("--overwrite", action="store_true", help="Overwrite an existing submission.md.")
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit a machine-readable summary to stdout.")
    p.add_argument(
        "--vrt-category",
        dest="vrt_category",
        default="",
        help="Bugcrowd VRT category (else read from finding details.vrt_category).",
    )
    p.add_argument(
        "--weakness",
        dest="weakness",
        default="",
        help="HackerOne weakness (else read from finding details.weakness).",
    )
    p.set_defaults(func=run)


def _nonempty(value: object) -> str:
    return str(value or "").strip()


def _needs(value: object, field: str) -> str:
    """Return ``value`` or, when empty, the ``[NEEDS: field]`` draft marker.

    Final mode never reaches the renderer with an empty proof-critical field
    (the strict gate raises first), so the marker only ever surfaces in drafts.
    """
    text = _nonempty(value)
    return text or f"[NEEDS: {field}]"


def _poc_pair_present(finding: dict) -> bool:
    request = detail_value(finding, "poc_request")
    response = detail_value(finding, "poc_response")
    return bool(isinstance(request, dict) and request and isinstance(response, dict) and response)


def _evaluate(finding: dict, platform: str, vrt_category: str, weakness: str) -> dict:
    """Resolve the submission's proof-critical fields and the strict-gate misses.

    ``missing`` is the ordered list of proof-critical fields absent for this
    ``platform``; it drives both the final-mode gate (any entry => refuse) and
    the ``[NEEDS: ...]`` draft markers.
    """
    title = _nonempty(finding.get("title"))
    severity = _nonempty(finding.get("severity"))
    cvss_vector = _nonempty(detail_value(finding, "cvss_vector", ""))
    cvss_score = finding.get("cvss_score")
    if cvss_score is None:
        cvss_score = detail_value(finding, "cvss_score", None)
    # Attacker-impact statement: finding `impact` (top-level or details), else
    # `summary` — matching the templates' "Populated from: impact / summary".
    impact = _nonempty(detail_value(finding, "impact", "")) or _nonempty(finding.get("summary"))

    poc_pair = _poc_pair_present(finding)
    poc_code = _nonempty(detail_value(finding, "poc_code", ""))
    evidence_ref = _nonempty(detail_value(finding, "evidence_ref", ""))
    has_proof = poc_pair or bool(poc_code) or bool(evidence_ref)

    vrt = _nonempty(vrt_category) or _nonempty(detail_value(finding, "vrt_category", ""))
    weak = _nonempty(weakness) or _nonempty(detail_value(finding, "weakness", ""))

    missing: list[str] = []
    if not title:
        missing.append("title")
    if not severity:
        missing.append("severity")
    if not cvss_vector:
        missing.append("CVSS vector")
    if platform == "bugcrowd" and not vrt:
        missing.append("VRT category")
    elif platform == "hackerone" and not weak:
        missing.append("weakness")
    if not impact:
        missing.append("attacker-impact statement")
    if not has_proof:
        missing.append("proof (poc_request+poc_response, poc_code, or evidence_ref)")

    return {
        "title": title,
        "severity": severity,
        "cvss_vector": cvss_vector,
        "cvss_score": cvss_score,
        "impact": impact,
        "vrt": vrt,
        "weakness": weak,
        "poc_pair": poc_pair,
        "poc_code": poc_code,
        "evidence_ref": evidence_ref,
        "has_proof": has_proof,
        "missing": missing,
    }


def _command_evidence(client, slug: str) -> list[dict]:
    """Command-run evidence for ``slug`` from EXPLICIT finding-links only.

    Sources command runs strictly from ``finding-links`` rows whose
    ``target_kind == "command_run"`` for this finding, then fetches each linked
    run for its command string. There is deliberately NO fuzzy
    ``command-runs?q=`` search here (plan decision 4): the report-writer agent
    runs the targeted ``list-command-runs`` search itself and links the exact
    reproducing run; this command only renders what was explicitly linked.
    """
    try:
        links = client.get("finding-links")
    except AssessError as exc:
        print(f"WARN export-submission: could not load finding-links: {exc}", file=sys.stderr)
        return []
    if not isinstance(links, list):
        return []

    run_ids: list[int] = []
    seen: set[int] = set()
    for link in links:
        if not isinstance(link, dict):
            continue
        if _nonempty(link.get("finding_slug")) != slug:
            continue
        if _nonempty(link.get("target_kind")) != "command_run":
            continue
        target_id = link.get("target_id")
        run_id: int | None = None
        if isinstance(target_id, bool):
            continue
        if isinstance(target_id, int):
            run_id = target_id
        elif isinstance(target_id, str) and target_id.isdigit():
            run_id = int(target_id)
        if run_id is None or run_id in seen:
            continue
        seen.add(run_id)
        run_ids.append(run_id)

    evidence: list[dict] = []
    for run_id in run_ids:
        try:
            row = client.get(f"command-runs/{run_id}")
        except AssessError as exc:
            print(f"WARN export-submission: command-run {run_id} unavailable: {exc}", file=sys.stderr)
            continue
        if isinstance(row, dict) and _nonempty(row.get("command")):
            evidence.append(row)
    return evidence


def _poc_lines(finding: dict) -> list[str]:
    """Render poc_code / poc_request / poc_response, reusing finding_render's fencing."""
    lines: list[str] = []
    poc_code = _nonempty(detail_value(finding, "poc_code", ""))
    if poc_code:
        fence = _fence_for(poc_code)
        lines += ["**PoC Code:**", f"{fence}\n{poc_code}\n{fence}", ""]

    poc_request = detail_value(finding, "poc_request")
    if isinstance(poc_request, dict) and poc_request:
        req_headers = header_lines(poc_request.get("headers"))
        req_body = str(poc_request.get("body") or "")
        request_line = f"{poc_request.get('method', '')} {poc_request.get('url', '')}".strip()
        fence = _fence_for(request_line, "\n".join(req_headers), req_body)
        block = [f"{fence}\n{request_line}"]
        block += req_headers
        if poc_request.get("body"):
            block.append(f"\n{poc_request['body']}")
        block.append(fence)
        lines += ["**PoC Request:**", "\n".join(block), ""]

    poc_response = detail_value(finding, "poc_response")
    if isinstance(poc_response, dict) and poc_response:
        resp_headers = header_lines(poc_response.get("headers"))
        resp_body = str(poc_response.get("body_excerpt") or "")
        status_line = f"HTTP {poc_response.get('status', '')}".strip()
        fence = _fence_for(status_line, "\n".join(resp_headers), resp_body)
        block = [f"{fence}\n{status_line}"]
        block += resp_headers
        if poc_response.get("body_excerpt"):
            block.append(f"\n{poc_response['body_excerpt']}")
        block.append(fence)
        lines += ["**PoC Response:**", "\n".join(block), ""]
    return lines


def _command_evidence_lines(command_evidence: list[dict]) -> list[str]:
    lines: list[str] = []
    for row in command_evidence:
        command = _nonempty(row.get("command"))
        if not command:
            continue
        intent = _nonempty(row.get("intent"))
        rc = row.get("return_code")
        rc_str = "" if rc is None else f" (rc={rc})"
        header = f"**Reproducing command{rc_str}:**" + (f" {intent}" if intent else "")
        fence = _fence_for(command)
        lines += [header, f"{fence}\n{command}\n{fence}", ""]
    return lines


def _section(title: str, body: list[str]) -> list[str]:
    return [f"## {title}", "", *body, ""]


def _render_markdown(finding: dict, resolved: dict, platform: str, command_evidence: list[dict]) -> str:
    # The slug identifies the draft via its directory + context JSON; it is kept OUT
    # of the body (bugbounty-submission-format.md "No internal identifiers") so the
    # outward-facing copy needs no slug edit.
    title = _needs(resolved["title"], "title")
    heading = f"# {title}"

    lines: list[str] = [heading, ""]

    # Metadata block ---------------------------------------------------------
    lines.append(f"- **Platform**: {_PLATFORM_LABEL[platform]}")
    severity = resolved["severity"]
    lines.append(f"- **Severity**: {severity.upper() if severity else '[NEEDS: severity]'}")
    cvss = _needs(resolved["cvss_vector"], "CVSS vector")
    if resolved["cvss_vector"] and resolved["cvss_score"] is not None:
        cvss = f"{cvss} ({resolved['cvss_score']})"
    lines.append(f"- **CVSS**: {cvss}")
    if platform == "bugcrowd":
        lines.append(f"- **VRT Category**: {_needs(resolved['vrt'], 'VRT category')}")
    elif platform == "hackerone":
        lines.append(f"- **Weakness**: {_needs(resolved['weakness'], 'weakness')}")

    cwe = _nonempty(detail_value(finding, "cwe_id", ""))
    if cwe:
        lines.append(f"- **CWE**: {cwe}")
    owasp = _nonempty(detail_value(finding, "owasp_category", ""))
    if owasp:
        lines.append(f"- **OWASP**: {owasp}")
    location = _nonempty(finding.get("canonical_location"))
    if location:
        method = _nonempty(details_object(finding).get("request_method"))
        lines.append(f"- **Location**: {f'{method} {location}' if method else location}")
    auth_context = _nonempty(finding.get("auth_context"))
    if auth_context:
        lines.append(f"- **Auth Context**: {auth_context}")
    lines.append("")

    # Summary ----------------------------------------------------------------
    summary = _nonempty(finding.get("summary"))
    if summary:
        lines += _section("Summary", [summary])

    # Steps to Reproduce -----------------------------------------------------
    steps = string_list(detail_value(finding, "steps_to_reproduce", []))
    if steps:
        lines += _section(
            "Steps to Reproduce",
            [f"{i}. {step}" for i, step in enumerate(steps, 1)],
        )

    # Evidence (proof) -------------------------------------------------------
    evidence_body: list[str] = []
    evidence_body += _poc_lines(finding)
    if resolved["evidence_ref"]:
        evidence_body += [f"- **Evidence reference**: {resolved['evidence_ref']}", ""]
    evidence_body += _command_evidence_lines(command_evidence)
    if not resolved["has_proof"]:
        evidence_body.append(
            "[NEEDS: proof — a reproducing request/response, PoC code, or evidence reference]"
        )
    lines += _section("Evidence", evidence_body)

    # Attack Scenario (optional) --------------------------------------------
    attack_scenario = _nonempty(detail_value(finding, "attack_scenario", ""))
    if attack_scenario:
        lines += _section("Attack Scenario", [attack_scenario])

    # Impact -----------------------------------------------------------------
    lines += _section("Impact", [_needs(resolved["impact"], "attacker-impact statement")])

    # Remediation ------------------------------------------------------------
    remediation = _nonempty(finding.get("remediation")) or _nonempty(detail_value(finding, "remediation", ""))
    if remediation:
        lines += _section("Remediation", [remediation])

    # References -------------------------------------------------------------
    references = string_list(detail_value(finding, "references", []))
    if references:
        lines += _section("References", [f"- {ref}" for ref in references])

    text = "\n".join(lines).rstrip()
    return text + "\n"


def _internal_ids(finding: dict, command_evidence: list[dict]) -> list[str]:
    """UUID-shaped internal identifiers to FLAG (never rewrite) in the output.

    Only ids the backend assigns to its own records — this finding, its
    engagement, and the agents/rows behind the linked command runs. Never the
    target-application identifiers, so PoC proof is never mistaken for internal
    state. Integer ids (e.g. a command-run row's ``id``) collected here are
    harmless: ``_hygiene_warnings`` flags a value only when it is a full UUID.
    """
    ids: list[str] = []
    for key in ("id", "engagement_id", "merged_into_finding_id"):
        ids.append(_nonempty(finding.get(key)))
    for row in command_evidence:
        for key in ("producer_agent_id", "agent_id", "engagement_id", "finding_id"):
            ids.append(_nonempty(row.get(key)))
    seen: set[str] = set()
    unique: list[str] = []
    for value in ids:
        if value and value not in seen:
            seen.add(value)
            unique.append(value)
    return unique


def _hygiene_warnings(text: str, slug: str, internal_ids: list[str], engagement_dir: str) -> list[str]:
    """Non-destructively FLAG internal identifiers that leaked into the output.

    Returns advisory strings; it NEVER mutates ``text``. The finding's content
    reaches the report-writer verbatim — a target-app UUID, filename, or path must
    survive — and these warnings let the report-writer (and the blind-triage gate)
    decide what to strip before an EXTERNAL submission. Draft submissions are
    internal working artifacts, so leaving the identifiers in place is correct;
    only the outward-facing copy the operator pastes must be clean.
    """
    warnings: list[str] = []
    slug = _nonempty(slug)
    if slug and slug in text:
        warnings.append(
            f"finding slug '{slug}' appears in the body (heading) — remove before external submission"
        )
    eng = _nonempty(engagement_dir).rstrip("/")
    if eng and eng in text:
        warnings.append(
            f"absolute engagement path '{eng}' appears — make paths relative before external submission"
        )
    for value in internal_ids:
        if value and _UUID_RE.fullmatch(value) and value in text:
            warnings.append(
                f"internal identifier '{value}' appears — remove before external submission"
            )
    if _CASES_DB_RE.search(text):
        warnings.append(
            "reference to the internal cases.db work database appears — remove before external submission"
        )
    return warnings


def _engagement_relative(path: Path, engagement_dir: str) -> str | None:
    """Engagement-relative form of ``path``, or None if it lies outside the tree."""
    try:
        rel = os.path.relpath(str(path), str(engagement_dir))
    except ValueError:
        return None
    if rel.startswith(".."):
        return None
    return rel


def _build_context(
    slug: str,
    platform: str,
    draft: bool,
    resolved: dict,
    command_evidence: list[dict],
    submission_rel: str,
    hygiene_warnings: list[str],
) -> dict:
    return {
        "slug": slug,
        "platform": platform,
        "mode": "draft" if draft else "final",
        "submission_path": submission_rel,
        "missing": resolved["missing"],
        "proof": {
            "poc_request_and_response": resolved["poc_pair"],
            "poc_code": bool(resolved["poc_code"]),
            "evidence_ref": bool(resolved["evidence_ref"]),
            "has_proof": resolved["has_proof"],
        },
        "taxonomy": {"vrt_category": resolved["vrt"], "weakness": resolved["weakness"]},
        "command_evidence": [
            {
                "command": _nonempty(row.get("command")),
                "intent": _nonempty(row.get("intent")),
                "return_code": row.get("return_code"),
            }
            for row in command_evidence
        ],
        # Advisory only — the report-writer strips these before external submission.
        "hygiene_warnings": hygiene_warnings,
    }


def run(args) -> None:
    slug = args.slug
    platform = args.platform
    draft = bool(args.draft)

    cfg = load_config(args.engagement_dir)
    engagement_dir = cfg.engagement_dir

    if args.output_dir:
        out_dir = Path(args.output_dir)
        if not out_dir.is_absolute():
            out_dir = Path(engagement_dir) / out_dir
    else:
        out_dir = Path(engagement_dir) / "submissions" / slug
    submission_md = out_dir / "submission.md"
    context_json = out_dir / "submission-context.json"

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        finding = client.get(f"findings/{slug}")
        if not isinstance(finding, dict):
            raise AssessError(f"export-submission: unexpected response fetching finding {slug!r}")

        command_evidence = _command_evidence(client, slug)
        internal_ids = _internal_ids(finding, command_evidence)
        resolved = _evaluate(finding, platform, args.vrt_category, args.weakness)

        # Final mode: refuse to write an incomplete submission (plan decision 3).
        # Raised BEFORE any file write or artifact POST — a gated finding leaves
        # no partial artifacts behind.
        if not draft and resolved["missing"]:
            raise AssessError(
                f"export-submission: cannot render a FINAL {platform} submission for "
                f"{slug!r} — missing proof-critical fields: {', '.join(resolved['missing'])}. "
                "Complete the finding or re-run with --draft to write a work-in-progress "
                "with [NEEDS: ...] markers."
            )

        # Overwrite guard — checked before writing so a stale submission is never
        # silently replaced.
        if submission_md.exists() and not args.overwrite:
            raise AssessError(
                f"export-submission: {_engagement_relative(submission_md, engagement_dir) or submission_md} "
                "already exists; pass --overwrite to replace it."
            )

        submission_rel = _engagement_relative(submission_md, engagement_dir)

        # FAITHFUL render — no content rewriting. Internal identifiers are flagged
        # (not stripped) so the report-writer removes them deliberately.
        markdown = _render_markdown(finding, resolved, platform, command_evidence)
        hygiene_warnings = _hygiene_warnings(markdown, slug, internal_ids, engagement_dir)
        context = _build_context(
            slug, platform, draft, resolved, command_evidence, submission_rel or str(submission_md), hygiene_warnings
        )
        context_text = json.dumps(context, indent=2, ensure_ascii=False)

        out_dir.mkdir(parents=True, exist_ok=True)
        submission_md.write_text(markdown, encoding="utf-8")
        context_json.write_text(context_text + "\n", encoding="utf-8")

        # Register the submission as a finding-linked artifact. NEVER include
        # submission_status: create lands 'none', and omitting the field on any
        # later upsert preserves whatever the operator set by hand.
        artifact_registered = False
        if submission_rel is not None:
            try:
                client.post(
                    "artifacts",
                    {
                        "path": submission_rel,
                        "kind": "submission",
                        "media_type": "text/markdown",
                        "sensitive": False,
                        "producer_agent_id": None,
                        "producer_agent_role": None,
                        "producer_command_run_id": None,
                        "related_finding_slug": slug,
                    },
                )
                artifact_registered = True
            except AssessError as exc:
                print(f"WARN export-submission: artifact registration failed: {exc}", file=sys.stderr)
        else:
            print(
                "WARN export-submission: output is outside the engagement dir; "
                "skipping artifact registration.",
                file=sys.stderr,
            )

    # Internal-identifier hygiene is advisory, never fatal: it is the report-writer's
    # job to strip these before the operator submits externally.
    for warning in hygiene_warnings:
        print(f"WARN export-submission: {warning}", file=sys.stderr)

    display_path = submission_rel or str(submission_md)
    if args.as_json:
        summary = {
            "slug": slug,
            "platform": platform,
            "mode": "draft" if draft else "final",
            "path": display_path,
            "missing": resolved["missing"],
            "has_proof": resolved["has_proof"],
            "command_evidence": len(command_evidence),
            "artifact_registered": artifact_registered,
            "hygiene_warnings": hygiene_warnings,
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    else:
        mode = "draft" if draft else "final"
        print(f"Wrote {mode} {platform} submission for {slug} to {display_path}")
        if resolved["missing"]:
            print("  NEEDS: " + ", ".join(resolved["missing"]))
