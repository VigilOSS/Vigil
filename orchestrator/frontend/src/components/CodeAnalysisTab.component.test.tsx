// @vitest-environment jsdom

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import type { CodeAnalysisResult } from "../lib/api";
import { CodeAnalysisTab } from "./CodeAnalysisTab";

function result(
  id: number,
  receiptBindingStatus: string,
): CodeAnalysisResult {
  return {
    id,
    queue_item_id: id,
    file_id: 1,
    file_path: "src/parser.py",
    agent_name: "code-vuln-hunter",
    receipt_kind: "file",
    receipt_binding_status: receiptBindingStatus,
    callable_refs: [],
    reviewed_spans: [],
    function_name: "",
    hypothesis: "",
    evidence: "",
    disposition: "skipped",
    confidence: "low",
    finding_slug: "",
    cwe_id: "",
    slot_type: "",
    notes: "fixture intentionally skipped",
    audit_metadata: {},
    created_at: "2026-09-12T12:00:00Z",
  };
}

afterEach(cleanup);

describe("CodeAnalysisTab receipt identity", () => {
  it("distinguishes a current skipped receipt from legacy unbound history", () => {
    render(
      <CodeAnalysisTab
        persistedPhase="hunt"
        loadError={null}
        repos={[]}
        modules={[]}
        queueStats={null}
        coverage={null}
        readiness={null}
        results={[
          result(1, "skipped_unbound"),
          result(2, "legacy_unbound"),
          result(3, "legacy_ambiguous"),
          result(4, "legacy_missing"),
          result(5, "source_span"),
        ]}
      />,
    );

    expect(screen.getByText("file receipt (skipped/no source anchors)")).toBeTruthy();
    expect(screen.getAllByText("file receipt (historical unbound identity)")).toHaveLength(3);
    expect(screen.getByText("file receipt (no source anchors)")).toBeTruthy();
  });
});
