import { describe, expect, it } from "vitest";

import {
  BLOCKER_LABELS,
  blockerCount,
  blockerLabel,
  directReadReason,
  familyLabel,
  parseQualityWarning,
  requirementLabel,
} from "./codeLabels";
import { CODE_VIEWS } from "./useCodeRoute";

describe("code label map", () => {
  it("gives every known blocker a plain label that is not its raw code", () => {
    for (const [code, entry] of Object.entries(BLOCKER_LABELS)) {
      expect(entry.label.trim()).not.toBe("");
      expect(entry.label).not.toContain(code);
      if (entry.view && entry.view !== "findings") expect(CODE_VIEWS).toContain(entry.view);
    }
  });

  it("falls back to readable text for a code it does not know", () => {
    expect(blockerLabel("future_gate_code").label).toBe("Future gate code");
  });

  it("reads the leading count only for counted blockers", () => {
    expect(blockerCount("analysis_queue_active", "Repository has 1,234 active or errored analysis queue item(s).")).toBe(1234);
    expect(blockerCount("structural_index_stale", "Structural index is not bound to snapshot 2.")).toBeNull();
  });

  it("names requirement levels", () => {
    expect(requirementLabel(false)).toBe("Required");
    expect(requirementLabel(true)).toBe("Can be skipped with a recorded reason");
  });

  it("explains why a file needs a direct read", () => {
    expect(directReadReason("degraded", false)).toBe("Partly parsed");
    expect(directReadReason("unsupported", false)).toBe("Not parsed");
    expect(directReadReason("complete", true)).toBe("Too large to fully index");
    expect(directReadReason("degraded", true)).toBe("Partly parsed, too large to fully index");
  });

  it("formats vulnerability families", () => {
    expect(familyLabel("algorithmic-dos")).toBe("Algorithmic DoS");
    expect(familyLabel("ssrf")).toBe("SSRF");
    expect(familyLabel("web-app-injection")).toBe("Web app injection");
    expect(familyLabel("ai-ml-security")).toBe("AI/ML security");
  });

  it("structures known quality warnings and keeps unknown ones verbatim", () => {
    expect(parseQualityWarning("Critical file src/a.js: family 'deserialization' effort 45 < 70")).toEqual({
      kind: "effort",
      text: "Critical file src/a.js: family 'deserialization' effort 45 < 70",
      risk: "critical",
      file: "src/a.js",
      family: "deserialization",
      effort: 45,
      threshold: 70,
    });
    expect(parseQualityWarning("High file src/b.js: missing slot_types").kind).toBe("missing_slots");
    expect(parseQualityWarning("Repository 4 structural coverage debt: 3 unreviewed admitted file(s)").kind).toBe("direct_read");
    expect(parseQualityWarning("src/c.js: something new")).toEqual({ kind: "other", text: "src/c.js: something new" });
  });
});
