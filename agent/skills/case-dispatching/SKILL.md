---
name: case-dispatching
description: Guide operator through the transient work-buffer coordination loop for security testing
origin: AI Threat Hunting
---

# Case Dispatching

Guides consumption of the transient local work buffer in `cases.db` for batching worker tasks. The orchestrator backend remains canonical for findings, coverage, services, request variants, and chains, and the work buffer should mirror canonical backend identities rather than inventing its own request identity.

This skill is coordination-only. Use it to inspect the work buffer, route batches, mark completion or errors, and requeue canonical work items. Do not use host-side shell commands from this skill to probe, crawl, fuzz, or exploit targets directly. All target-facing execution must happen through the attached Kali MCP tools.

## When to Activate

- Phase 3 (Consume & Test) after surface-collector has populated the work buffer
- When pending work items exist in the work buffer
- When a producer has added new work items

## The Consumption Loop

**Routing rule: Fetch work items and route per the type-to-agent table below. Each agent is specialized — vulnerability-analyst lacks the DOM/JS parsing context that source-analyzer has, and source-analyzer lacks the request-crafting methodology that vulnerability-analyst has, so mixing types produces shallow analysis.**

**Dispatch mode switches on work-buffer volume.** Type-based fetch orders within a type by id, which is fine for small buffers but blind to signal quality. At 2000+ pending items, switch to priority-first fetch so specialists see high-signal clusters first.

Each iteration (set `DB="$DIR/cases.db"`):
```
1. Reset stale: aith assess dispatch "$DB" reset-stale 10
2. Check stats: aith assess dispatch "$DB" stats    # read total pending
3a. Pending < 2000 → type-based dispatch (vulnerability-analyst and source-analyzer can run IN PARALLEL):

    vulnerability-analyst: api, api-spec, form, upload, graphql, websocket
    source-analyzer: page, javascript, stylesheet, data

    aith assess dispatch "$DB" fetch <type> 10 <agent_name>

3b. Pending >= 2000 → priority-first dispatch:

    # Populate priority/cluster once (idempotent):
    aith assess classify-work "$DB"

    # Optional: review clusters, defer low-signal ones before dispatch:
    aith assess list-clusters "$DB"
    aith assess dispatch "$DB" defer-cluster <cluster_key> --reason "..."

    # Fetch across types by priority. `fetch-by-priority` is route-aware: it
    # only claims rows whose type maps to a real specialist route and rejects
    # free-form agent names so stray labels can't mix work types.
    #   auto                      — claim the top N routable rows globally and
    #                               stamp each with its canonical owner.
    #   vulnerability-analyst[-N] — claim only api/api-spec/form/upload/graphql/
    #                               websocket rows (N is an optional instance label).
    #   source-analyzer[-N]       — claim only page/javascript/stylesheet/data rows.
    aith assess dispatch "$DB" fetch-by-priority 10 auto
    aith assess dispatch "$DB" fetch-by-priority 10 vulnerability-analyst
    aith assess dispatch "$DB" fetch-by-priority 10 source-analyzer-2

4. On subagent return:
   - Done: aith assess dispatch "$DB" done "id1,id2,..."
   - New endpoints: feed them back through `aith assess ingest-endpoints "$DB" <source>` or `aith assess ingest-spec "$DB" <spec-file>` so backend state is created first, then rerun `classify-work` so the new rows enter the priority queue with scores
   - Findings: write structured finding state with `aith assess record-finding`
   - Errors: aith assess dispatch "$DB" error "id1,id2,..."
5. pending=0 and producers stopped → report completion
6. Otherwise → loop back to step 1
```

### Priority-mode scoring reference

`classify-work` populates four fields on each work item from the URL structure (see
`agent/scripts/assess/commands/classify_work.py` for the exact weight table):

- `cluster_key` — `gf:<bucket>` when a parameter or path pattern matches a gf bucket; otherwise
  `path:/<first-two-url-segments>` as the fallback when nothing matches.
- `priority_score` — integer 0-50. Weights (highest first): rce (50), ssrf (45), sqli/lfi (40),
  idor (35), debug_logic (30), ssti/redirect (25), xss (20), interestingparams (15).
  Cluster_key and priority_score track the single highest-weight match; when two buckets tie,
  earlier declaration order wins deterministically.
- `priority_reason` — e.g. `"gf:ssrf+gf:idor"` listing every matched bucket, so the operator sees
  why an item scored high without running gf manually.
- `terminal_reason` — set on hopeless items (`inert_type` for image/video/font/archive); these
  are excluded from `fetch-by-priority`.

Each gf bucket has a reference at `agent/references/gf-patterns/<bucket>.md` — consult it when
you're unsure why a cluster scored the way it did.

## Type → Agent Routing

| Type | Agent | Type | Agent |
|------|-------|------|-------|
| api | vulnerability-analyst | page | source-analyzer |
| api-spec | vulnerability-analyst | page | source-analyzer |
| form | vulnerability-analyst | javascript | source-analyzer |
| upload | vulnerability-analyst | stylesheet | source-analyzer |
| graphql | vulnerability-analyst | data | source-analyzer |
| websocket | vulnerability-analyst | unknown | operator (manual) |
| image/video/font/archive | skipped | | |

## Batch Strategy

- Up to 10 same-type work items per cycle, dispatch immediately
- Priority: api-spec > api > form > graphql > page > javascript > others

## Progress Display (after EVERY batch)

```
Phases: [x] Recon (pass 1)  [x] Recon (gate ✓)  [x] Collect  [>] Consume & Test  [ ] Exploit  [ ] Report
[work-buffer] 120/495 done (24%) | api: 15/21 | page: 98/464 | js: 7/10 | findings: 5
```
```bash
sqlite3 "$DB" ".timeout 5000" "
  SELECT type, SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) as done,
    SUM(CASE WHEN status!='skipped' THEN 1 ELSE 0 END) as total
  FROM work_items GROUP BY type ORDER BY total DESC;"
```

## Key Rules

- Use `aith assess dispatch "$DB" <action>` for all work-buffer operations — reading cases.db directly bypasses the backend sync layer and can produce stale or inconsistent state
- Treat this skill as host-side coordination only. All real target testing stays in Kali MCP.
- Record findings in backend state immediately via `aith assess record-finding`
- Re-ingest new endpoints through backend-first producers; let the work buffer mirror the resulting canonical ids
- Use reset-stale at start of each iteration
- **DO NOT STOP EARLY** — loop until pending=0 for all consumable types
- On subagent error: mark work items `error`, log, CONTINUE (don't halt loop)
- Stop on any of:
  - pending=0 everywhere (normal completion)
  - the upstream work-buffer producer (surface-collector, ingestion, nuclei sweep) is itself stuck or failing — looping against an empty or broken producer burns dispatch budget on no real work. Escalate the producer issue first, then resume.

## Dispatcher Quick Reference

```bash
DB="$DIR/cases.db"
aith assess dispatch "$DB" stats
aith assess dispatch "$DB" fetch <type> <limit> <agent_name>
aith assess dispatch "$DB" done "id1,id2,id3"
aith assess dispatch "$DB" error "id1,id2,id3"
aith assess dispatch "$DB" reset-stale <minutes>
echo '{"url":"...","method":"GET","type":"api","auth_context":"anonymous"}' | aith assess dispatch "$DB" requeue
echo '{"url":"https://target.example/api/search","method":"GET","type":"api","auth_context":"anonymous","request_variant_id":42,"coverage_item_id":77,"queue_key":"variant:42:api"}' | aith assess dispatch "$DB" requeue
```
