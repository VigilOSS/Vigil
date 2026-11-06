import assert from "node:assert/strict";
import { test } from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { FullReport } from "./FullReport";
import { FindingDetail } from "./FindingsTab";
import { devData } from "../devData";
import type { ReportData, ReportFinding } from "../types";

// ADR 0043's visibility obligation, pinned at the two surfaces that deliver a
// finding to the client. `OperatorAuthorityTag` and
// `OperatorAuthorityAttestation` are tested on their own in
// FindingParts.test.tsx; what these pin is that both views actually MOUNT them.
// A verdict recorded on the operator's attestation rather than a proof receipt
// carries the same `verification_status` word as a dispatch-verified one, so a
// view that forgot to render the stamp would look completely correct and would
// be shipping a waiver to the recipient as proof.
//
// devData carries exactly one attested finding (VA-005) for this reason.

/** The one attested finding in the fixture, as each view receives it. */
function attestedFinding(data: ReportData): ReportFinding {
  const found = data.finding_groups.standalone.find((finding) => finding.slug === "VA-005");
  assert.ok(found, "devData no longer carries the attested fixture finding VA-005");
  return found;
}

const views: Array<[string, (data: ReportData) => string]> = [
  ["full report document", (data) => renderToStaticMarkup(<FullReport data={data} />)],
  [
    "findings table detail",
    (data) => renderToStaticMarkup(<FindingDetail finding={attestedFinding(data)} draft />),
  ],
];

for (const [name, render] of views) {
  test(`the ${name} marks an operator-attested verdict beside its status`, () => {
    const html = render(devData);
    assert.match(html, /Operator attested · intel tech-component 17/);
    assert.match(html, /rather than a proof receipt/);
    assert.ok(
      html.includes("The edge proxy configuration (intel tech-component 17) strips the Server header"),
      `${name} dropped the operator's verbatim reason`,
    );
  });

  test(`the ${name} says nothing of the kind when every verdict is receipt-backed`, () => {
    const strip = (finding: ReportFinding): ReportFinding => ({
      ...finding,
      operator_authority: null,
    });
    const groups = devData.finding_groups;
    const html = render({
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
    });
    assert.doesNotMatch(html, /Operator attested/);
    assert.doesNotMatch(html, /rather than a proof receipt/);
  });
}
