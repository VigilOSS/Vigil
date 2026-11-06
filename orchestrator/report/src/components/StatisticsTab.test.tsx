import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { StatisticsTab } from "./StatisticsTab";
import { devData } from "../devData";
import type { ReportData, ReportFinding, ReportReadinessItem } from "../types";

// Draft readiness. `report_readiness` ships on a DRAFT export only, and the
// backend stamps every item it returns with the gating class that produced it:
// `block` refuses a final export, `advisory` never does. The panel groups the
// two, but the ITEM — kind plus detail — is what gets copied into a handoff or
// a ticket, and it arrives at its next reader with the grouping long gone.
// Two near-homonym kinds gate oppositely: `missing_cited_markdown_artifact`
// never blocks while `finding_evidence_missing_artifact` always does.

function draft(items: { blockers: ReportReadinessItem[]; advisories: ReportReadinessItem[] }): string {
  const data: ReportData = {
    ...devData,
    mode: "draft",
    report_readiness: {
      ready: items.blockers.length === 0,
      blocker_count: items.blockers.length,
      blockers: items.blockers,
      advisory_count: items.advisories.length,
      advisories: items.advisories,
    },
  };
  return renderToStaticMarkup(<StatisticsTab data={data} />);
}

test("each readiness row carries the gating class the backend stamped on it", () => {
  const html = draft({
    blockers: [
      {
        kind: "finding_evidence_missing_artifact",
        severity: "block",
        detail: "VA-003 evidence_ref is indexed but the index last saw nothing at that path.",
      },
    ],
    advisories: [
      {
        kind: "missing_cited_markdown_artifact",
        severity: "advisory",
        detail: "notes/scope.md cites an artifact that is absent.",
      },
    ],
  });

  // Both rows render, and each one says for itself whether it gates.
  assert.match(html, /finding_evidence_missing_artifact<\/span><span class="rpt-gating">blocking<\/span>/);
  assert.match(html, /missing_cited_markdown_artifact<\/span><span class="rpt-gating">advisory<\/span>/);
  assert.ok(html.includes("notes/scope.md cites an artifact that is absent."), html);
});

test("an unstamped row still renders, without inventing a gating class for it", () => {
  const html = draft({
    blockers: [{ kind: "unreviewed_findings", detail: "VA-006 is still unreviewed." }],
    advisories: [],
  });

  assert.ok(html.includes("VA-006 is still unreviewed."), html);
  assert.doesNotMatch(html, /rpt-gating/);
});

test("a final export renders no readiness at all", () => {
  // Its blockers are empty by construction (the export is refused while any
  // stand) and its advisories quote internal QA doubt about the engagement's
  // own evidence, which is not the client's to read.
  const html = renderToStaticMarkup(<StatisticsTab data={{ ...devData, mode: "final" }} />);
  assert.doesNotMatch(html, /Draft readiness/);
});

test("the verification breakdown says how many of its verdicts are operator-attested", () => {
  // The bar states a DISTRIBUTION — "confirmed: 4" — and a reader takes every
  // one of them for a proven finding. Counted from this report's own body, the
  // same population the backend derives the rollups from, so the note and the
  // bar cannot disagree.
  const html = renderToStaticMarkup(<StatisticsTab data={devData} />);
  assert.match(html, /1 of these verdicts was recorded on the operator&#x27;s attestation rather than a proof receipt/);
});

test("a report with no attested verdict carries no note about them", () => {
  const groups = devData.finding_groups;
  const strip = (finding: ReportFinding): ReportFinding => ({ ...finding, operator_authority: null });
  const data: ReportData = {
    ...devData,
    finding_groups: {
      ...groups,
      groups: groups.groups.map((group) => ({
        ...group,
        root: strip(group.root),
        siblings: group.siblings.map(strip),
      })),
      standalone: groups.standalone.map(strip),
    },
  };
  const html = renderToStaticMarkup(<StatisticsTab data={data} />);
  assert.doesNotMatch(html, /operator&#x27;s attestation/);
});
