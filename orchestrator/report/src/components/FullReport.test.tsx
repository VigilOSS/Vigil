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

// Each chain shows the severity its author stated and, labelled separately, the
// chain-derived value: the stated severity when every step is a finding this
// report delivers verified (`chain_proven`, derived by the backend), otherwise
// none. The legs keep their own severities.

test("a proven chain shows its chain-derived severity beside the stated one", () => {
  const html = renderToStaticMarkup(<FullReport data={devData} />);
  const proven = html.slice(
    html.indexOf("Unauthenticated admin takeover</h3>"),
    html.indexOf("Session theft via reflected XSS</h3>"),
  );
  assert.match(proven, /Stated: <\/span><span class="rpt-sev-badge rpt-sev-critical">critical<\/span>/);
  assert.match(proven, /Chain-derived: critical/);
});

test("an unproven chain keeps its stated severity and derives none", () => {
  const html = renderToStaticMarkup(<FullReport data={devData} />);
  const unproven = html.slice(html.indexOf("Session theft via reflected XSS</h3>"));
  assert.match(unproven, /Stated: <\/span><span class="rpt-sev-badge rpt-sev-high">high<\/span>/);
  assert.match(unproven, /Chain-derived: not proven by this report&#x27;s verified findings/);
  assert.doesNotMatch(unproven, /Chain-derived: high/);
});

test("a chain's severity never replaces the severity of a finding on its path", () => {
  // VA-004 is a medium leg of the high session-theft chain.
  const html = renderToStaticMarkup(<FullReport data={devData} />);
  const leg = html.slice(html.indexOf('id="finding-va-004"'));
  assert.match(leg, /rpt-sev-badge rpt-sev-medium">medium</);
});
