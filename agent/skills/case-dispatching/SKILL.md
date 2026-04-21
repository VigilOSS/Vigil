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

**Routing rule: Fetch work items by type separately and route per the table below. Each agent type is specialized — mixing types produces shallow analysis because vulnerability-analyst lacks the DOM/JS parsing context that source-analyzer has, and source-analyzer lacks the request-crafting methodology that vulnerability-analyst has.**

Each iteration (set `DB="$DIR/cases.db"`):
```
1. Reset stale: ./scripts/assess.py dispatch "$DB" reset-stale 10
2. Check stats: ./scripts/assess.py dispatch "$DB" stats
3. Fetch and route by type (vulnerability-analyst and source-analyzer can run IN PARALLEL):

   vulnerability-analyst: api, api-spec, form, upload, graphql, websocket
   source-analyzer: page, javascript, stylesheet, data

   ./scripts/assess.py dispatch "$DB" fetch <type> 10 <agent_name>

4. On subagent return:
   - Done: ./scripts/assess.py dispatch "$DB" done "id1,id2,..."
   - New endpoints: feed them back through `assess.py ingest-endpoints "$DB" <source>` or `assess.py ingest-spec "$DB" <spec-file>` so backend state is created first
   - Findings: write structured finding state with `assess.py record-finding`
   - Errors: ./scripts/assess.py dispatch "$DB" error "id1,id2,..."
5. pending=0 and producers stopped → report completion
6. Otherwise → loop back to step 1
```

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

- Use `./scripts/assess.py dispatch "$DB" <action>` for all work-buffer operations — reading cases.db directly bypasses the backend sync layer and can produce stale or inconsistent state
- Treat this skill as host-side coordination only. All real target testing stays in Kali MCP.
- Record findings in backend state immediately via `assess.py record-finding`
- Re-ingest new endpoints through backend-first producers; let the work buffer mirror the resulting canonical ids
- Use reset-stale at start of each iteration
- **DO NOT STOP EARLY** — loop until pending=0 for all consumable types
- On subagent error: mark work items `error`, log, CONTINUE (don't halt loop)
- Stop on any of:
  - pending=0 everywhere (normal completion)
  - user /stop
  - a critical-severity finding surfaces that warrants an immediate Phase-5 pivot — the exploit path takes priority over draining the remaining queue; resume the loop after the pivot settles
  - the upstream work-buffer producer (surface-collector, ingestion, nuclei sweep) is itself stuck or failing — looping against an empty or broken producer burns dispatch budget on no real work. Escalate the producer issue first, then resume.

## Dispatcher Quick Reference

```bash
DB="$DIR/cases.db"
./scripts/assess.py dispatch "$DB" stats
./scripts/assess.py dispatch "$DB" fetch <type> <limit> <agent_name>
./scripts/assess.py dispatch "$DB" done "id1,id2,id3"
./scripts/assess.py dispatch "$DB" error "id1,id2,id3"
./scripts/assess.py dispatch "$DB" reset-stale <minutes>
echo '{"url":"...","method":"GET","type":"api","auth_context":"anonymous"}' | ./scripts/assess.py dispatch "$DB" requeue
echo '{"url":"https://target.example/api/search","method":"GET","type":"api","auth_context":"anonymous","request_variant_id":42,"coverage_item_id":77,"queue_key":"variant:42:api"}' | ./scripts/assess.py dispatch "$DB" requeue
```
