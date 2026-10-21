import { describe, expect, it } from "vitest";

import type { ActivityEntity, ActivityItem } from "../../lib/activityApi";
import { appendOlder, buildFeed, codeFileHref, dispatchSpanText, dispatchStatusEntry, entityHref, mergeNewer, type FeedEntry } from "./activityModel";

const NOW = Date.parse("2026-10-20T15:00:00Z");

let nextId = 1;
function item(at: string, overrides: Partial<ActivityItem> = {}): ActivityItem {
  const id = nextId++;
  return {
    id: `audit:${id}`,
    source: "audit",
    source_id: id,
    cursor: `c${id}`,
    occurred_at: at,
    actor: { name: "code-vuln-hunter", kind: "agent" },
    category: "code",
    kind: "code-record analysis",
    summary: `Reviewed code file #${id}: clean`,
    entities: [],
    dispatch: null,
    detail: {},
    ...overrides,
  };
}

function lane(agentId: string, kind: string, at: string, overrides: Partial<ActivityItem> = {}): ActivityItem {
  return item(at, {
    kind,
    category: kind === "agent handoff" ? "decisions" : "lifecycle",
    summary: `${kind} ${agentId}`,
    dispatch: { agent_id: agentId, role: "code-vuln-hunter", run_id: null },
    ...overrides,
  });
}

function shape(entries: FeedEntry[]): string[] {
  return entries.map((entry) =>
    entry.type === "row" ? `row:${entry.item.id}`
      : entry.type === "dispatch" ? `dispatch:${entry.agentId}`
        : `burst:${entry.entries.length}`,
  );
}

describe("buildFeed day groups", () => {
  it("groups newest-first rows by UTC day with Today and Yesterday labels", () => {
    const today = item("2026-10-20T00:30:00Z", { category: "notes", kind: "Scoped Acme", summary: "Scoped Acme" });
    const yesterday = item("2026-10-19T23:59:59.500Z", { category: "notes", kind: "Mapped Acme", summary: "Mapped Acme" });
    const older = item("2026-10-13T08:00:00Z", { category: "notes", kind: "Kickoff", summary: "Kickoff" });

    const days = buildFeed([today, yesterday, older], NOW);

    expect(days.map((day) => day.label)).toEqual(["Today", "Yesterday", "Tue 2026-10-13"]);
    expect(days.map((day) => day.day)).toEqual(["2026-10-20", "2026-10-19", "2026-10-13"]);
    expect(days.map((day) => day.count)).toEqual([1, 1, 1]);
  });
});

describe("buildFeed dispatch cards", () => {
  it("collapses one dispatch's rows into a card at its newest row", () => {
    const decision = item("2026-10-20T14:15:17.435Z", { category: "decisions", kind: "agent decision", summary: "Decision: dispatch closed from handoff" });
    const done = lane("cvh-lane065", "agent done", "2026-10-20T14:15:17.432Z", {
      detail: { result: "failed" },
      entities: [{ type: "finding", key: "CH-041", label: "CH-041" }],
    });
    const handoff = lane("cvh-lane065", "agent handoff", "2026-10-20T14:15:17.427Z", { detail: { result: "No final handoff" } });
    const unrelated = item("2026-10-20T14:14:00Z");
    const start = lane("cvh-lane065", "agent start", "2026-10-20T14:11:12Z");

    const [day] = buildFeed([decision, done, handoff, unrelated, start], NOW);

    expect(shape(day.entries)).toEqual([`row:${decision.id}`, "dispatch:cvh-lane065", `row:${unrelated.id}`]);
    const card = day.entries[1];
    if (card.type !== "dispatch") throw new Error("expected a dispatch card");
    expect(card.items.map((member) => member.id)).toEqual([done.id, handoff.id, start.id]);
    expect(card.status).toBe("failed");
    expect(card.startLoaded).toBe(true);
    expect(card.durationMs).toBe(Date.parse(done.occurred_at) - Date.parse(start.occurred_at));
    expect(card.findings.map((entity) => entity.key)).toEqual(["CH-041"]);
    expect(card.handoff?.id).toBe(handoff.id);
    expect(day.count).toBe(5);
  });

  it("reads a dispatch's status from the done report's stored status, never from words in free text", () => {
    const card = (rows: ActivityItem[]) => {
      const entry = buildFeed(rows, NOW)[0].entries.find((candidate) => candidate.type === "dispatch");
      if (!entry || entry.type !== "dispatch") throw new Error("expected a dispatch card");
      return entry;
    };
    const lifecycle = (agentId: string, result: string) => [
      lane(agentId, "agent done", "2026-10-20T14:20:00Z", { detail: { result } }),
      lane(agentId, "agent start", "2026-10-20T14:10:00Z"),
    ];
    for (const stored of ["completed", "failed", "aborted", "blocked"]) {
      expect(card(lifecycle(`lane-${stored}`, stored)).status).toBe(stored);
    }
    // A free-text result is a finished report with no stored status: "0 failures" is not a failure.
    const prose = card(lifecycle("lane-prose", "0 failures, 3 checks passed"));
    expect(prose.status).toBe("finished");
    expect(dispatchStatusEntry(prose.status)).toMatchObject({ label: "Finished", tone: "info" });
    expect(dispatchStatusEntry("failed")).toMatchObject({ label: "Failed", tone: "danger" });
    expect(card([lane("lane-run", "agent decision", "2026-10-20T14:12:00Z"), lane("lane-run", "agent start", "2026-10-20T14:10:00Z")]).status).toBe("in-progress");
    expect(dispatchStatusEntry("in-progress").label).toBe("In progress");
    expect(card([lane("lane-off", "agent handoff", "2026-10-20T14:12:00Z"), lane("lane-off", "agent start", "2026-10-20T14:10:00Z")]).status).toBe("handed-off");
  });

  it("leaves a lone dispatch row as a row", () => {
    const start = lane("cvh-lane066", "agent start", "2026-10-20T14:13:12Z");
    expect(shape(buildFeed([start], NOW)[0].entries)).toEqual([`row:${start.id}`]);
  });
});

describe("buildFeed bursts", () => {
  it("folds three or more same-kind rows by one actor that arrive close together", () => {
    const reviews = [0, 1, 2, 3].map((minute) => item(`2026-10-20T14:0${9 - minute}:00Z`));
    const note = item("2026-10-20T14:04:00Z", { category: "notes", kind: "Lane note", summary: "Lane note" });

    const [day] = buildFeed([...reviews, note], NOW);

    expect(shape(day.entries)).toEqual(["burst:4", `row:${note.id}`]);
    const burst = day.entries[0];
    if (burst.type !== "burst") throw new Error("expected a burst");
    expect(burst.label).toBe("4 code file reviews");
    expect(burst.actorName).toBe("code-vuln-hunter");
    expect(burst.at).toBe(reviews[0].occurred_at);
    expect(burst.oldestAt).toBe(reviews[3].occurred_at);
  });

  it("keeps pairs, notes, and rows separated by a long gap unfolded", () => {
    const pair = [item("2026-10-20T14:09:00Z"), item("2026-10-20T14:08:00Z")];
    const notes = [0, 1, 2].map((minute) => item(`2026-10-20T13:5${minute}:00Z`, { category: "notes", kind: "Note", summary: "Same note" }));
    const later = item("2026-10-20T12:00:00Z");
    const later2 = item("2026-10-20T11:59:00Z");

    const [day] = buildFeed([...pair, ...notes.reverse(), later, later2], NOW);

    expect(day.entries.every((entry) => entry.type === "row")).toBe(true);
    expect(day.entries).toHaveLength(7);
  });

  it("folds interleaved repeats inside one cluster and repeated dispatch cards by role", () => {
    const rows: ActivityItem[] = [];
    for (let index = 0; index < 3; index += 1) {
      const second = 50 - index * 10;
      rows.push(item(`2026-10-20T14:15:${second}.900Z`, { category: "decisions", kind: "agent decision", summary: "Decision: dispatch closed from handoff", actor: { name: "vigil-assess", kind: "system" } }));
      rows.push(lane(`lane-${index}`, "agent done", `2026-10-20T14:15:${second}.500Z`, { detail: { result: "failed" } }));
      rows.push(lane(`lane-${index}`, "agent start", `2026-10-20T14:13:${second}.000Z`));
    }
    rows.sort((a, b) => Date.parse(b.occurred_at) - Date.parse(a.occurred_at));

    const [day] = buildFeed(rows, NOW);

    expect(shape(day.entries)).toEqual(["burst:3", "burst:3"]);
    const [decisions, dispatches] = day.entries;
    if (decisions.type !== "burst" || dispatches.type !== "burst") throw new Error("expected bursts");
    expect(decisions.label).toBe("3 × Decision: dispatch closed from handoff");
    expect(dispatches.label).toBe("3 code-vuln-hunter dispatches · 3 failed");
  });
});

describe("page merging", () => {
  it("prepends newer rows and keeps loaded older pages without duplicates", () => {
    const first = [item("2026-10-20T14:00:00Z"), item("2026-10-20T13:00:00Z")];
    const older = [item("2026-10-20T12:00:00Z")];
    const loaded = appendOlder(first, [first[1], ...older]);
    expect(loaded.map((row) => row.id)).toEqual([first[0].id, first[1].id, older[0].id]);

    const fresh = item("2026-10-20T14:30:00Z");
    const merged = mergeNewer(loaded, [fresh, first[0]]);
    expect(merged.map((row) => row.id)).toEqual([fresh.id, first[0].id, first[1].id, older[0].id]);
  });
});

describe("entityHref", () => {
  const href = (entity: Partial<ActivityEntity> & Pick<ActivityEntity, "type" | "key">) =>
    entityHref("acme key", { label: entity.key, ...entity });

  it("opens the exact record each entity's ref names", () => {
    expect(href({ type: "finding", key: "VA-001", ref: { finding_slug: "VA-001" } }))
      .toBe("#/engagements/acme%20key?tab=findings&finding=VA-001");
    expect(href({ type: "run", key: "12", ref: { run_id: 12 } })).toBe("#/engagements/acme%20key?tab=runs&run=12");
    expect(href({ type: "http_variant", key: "7", ref: { request_variant_id: 7 } }))
      .toBe("#/engagements/acme%20key?tab=http&request=7");
    expect(href({ type: "surface", key: "https://app.example.com/login", ref: { surface_id: 41 } }))
      .toBe("#/engagements/acme%20key?tab=surfaces&surface=41");
    expect(href({ type: "intel", key: "note:Login flow", ref: { intel_type: "note", intel_id: 5 } }))
      .toBe("#/engagements/acme%20key?tab=intel&intel_type=note&intel_id=5");
    expect(href({ type: "chain", key: "acme-chain", ref: { chain_key: "acme-chain", finding_slug: "CH-002" } }))
      .toBe("#/engagements/acme%20key?tab=findings&finding=CH-002");
    expect(href({ type: "file", key: "RESUME.md", ref: { file_name: "RESUME.md" } }))
      .toBe("#/engagements/acme%20key?tab=artifacts&file=RESUME.md");
    expect(href({
      type: "code_file",
      key: "4101",
      ref: { code_file_id: 4101, repo_id: 7, file_path: "src/app.ts", result_id: 902 },
    })).toBe(codeFileHref("acme key", { code_file_id: 4101, repo_id: 7, file_path: "src/app.ts", result_id: 902 }));
    expect(href({ type: "oob_probe", key: "208", ref: { probe_id: 208 } })).toBe("#/engagements/acme%20key?tab=oast&probe=208");
  });

  it("opens a reviewed code file's result record, or its repository's results when no result is named", () => {
    expect(href({ type: "code_file", key: "4101", ref: { code_file_id: 4101, repo_id: 7, file_path: "src/app.ts", result_id: 902 } }))
      .toBe("#/engagements/acme%20key?tab=code&view=results&repo=7&q=src%2Fapp.ts&result=902");
    expect(href({ type: "code_file", key: "4101", ref: { code_file_id: 4101, repo_id: 7, file_path: "src/app.ts", result_id: null } }))
      .toBe("#/engagements/acme%20key?tab=code&view=results&repo=7&q=src%2Fapp.ts");
  });

  it("does not link an entity whose record cannot be opened", () => {
    const reason = "Only engagement root documents open in Files; this registered file has no viewer.";
    expect(href({ type: "file", key: "scans/acme.txt", ref: null, unlinked_reason: reason })).toBeNull();
    expect(href({ type: "intel", key: "note:gone", ref: null, unlinked_reason: "No note record with this name is recorded." })).toBeNull();
    expect(href({ type: "mystery", key: "1", ref: { id: 1 } })).toBeNull();
    expect(href({ type: "oob_probe", key: "0", ref: { probe_id: 0 } })).toBeNull();
  });

  it("keeps exact key links for feeds that predate entity refs", () => {
    expect(href({ type: "finding", key: "VA-001" })).toBe("#/engagements/acme%20key?tab=findings&finding=VA-001");
    expect(href({ type: "run", key: "12" })).toBe("#/engagements/acme%20key?tab=runs&run=12");
    expect(href({ type: "run", key: "not-a-number" })).toBeNull();
    expect(href({ type: "surface", key: "https://app.example.com/login" })).toBeNull();
  });
});

describe("burst identity", () => {
  it("keeps a burst's identity when a newer repeat joins it", () => {
    const reviews = [0, 1, 2].map((minute) => item(`2026-10-20T14:0${8 - minute}:00Z`));
    const [before] = buildFeed(reviews, NOW);
    const newer = item("2026-10-20T14:09:00Z");
    const [after] = buildFeed([newer, ...reviews], NOW);
    const [burstBefore] = before.entries;
    const [burstAfter] = after.entries;
    if (burstBefore.type !== "burst" || burstAfter.type !== "burst") throw new Error("expected bursts");
    expect(burstAfter.entries).toHaveLength(4);
    expect(burstAfter.id).toBe(burstBefore.id);
  });
});

describe("dispatch span", () => {
  it("never claims a zero-length lower bound when the dispatch start is not loaded", () => {
    const done = lane("acme-lane", "agent done", "2026-10-20T14:15:17.432Z", { detail: { result: "completed" } });
    const handoff = lane("acme-lane", "agent handoff", "2026-10-20T14:15:17.427Z");
    const [day] = buildFeed([done, handoff], NOW);
    const card = day.entries[0];
    if (card.type !== "dispatch") throw new Error("expected a dispatch card");
    expect(dispatchSpanText(card)).toBe("start not loaded");
    expect(dispatchSpanText({ ...card, startLoaded: true })).toBe("under 1s");
    expect(dispatchSpanText({ ...card, durationMs: 240_000 })).toBe("≥ 4m 0s");
  });
});
