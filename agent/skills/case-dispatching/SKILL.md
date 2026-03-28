---
name: case-dispatching
description: Guide operator through the transient work-buffer consumption loop for security testing
origin: RedteamOpencode
---

# Case Dispatching

Guides consumption of the transient local work buffer in `cases.db` for batching worker tasks. The orchestrator backend remains canonical for findings, coverage, services, request variants, and chains, and the work buffer should mirror canonical backend identities rather than inventing its own request identity.

## When to Activate

- After `./scripts/init_engagement.sh ...` when `cases.db` is created
- When pending work items exist in the work buffer
- When a producer has added new work items

## The Consumption Loop

**CRITICAL: Fetch work items by type SEPARATELY. Route per table below. NEVER mix types.
NEVER send page/js/css/data to vulnerability-analyst. NEVER send api/form/upload to source-analyzer.**

Each iteration:
```
1. Reset stale: ./scripts/dispatcher.sh $DB reset-stale 10
2. Check stats: ./scripts/dispatcher.sh $DB stats
3. Fetch and route by type (vulnerability-analyst and source-analyzer can run IN PARALLEL):

   vulnerability-analyst: api, api-spec, form, upload, graphql, websocket
   source-analyzer: page, javascript, stylesheet, data

   ./scripts/dispatcher.sh $DB fetch <type> 10 <agent_name>

4. On subagent return:
   - Done: ./scripts/dispatcher.sh $DB done "id1,id2,..."
   - New endpoints: feed them back through `recon_ingest.sh` or `spec_ingest.sh` so backend state is created first
   - Findings: write structured finding state first with `record_finding.sh`, then keep findings.md synchronized
   - Errors: ./scripts/dispatcher.sh $DB error "id1,id2,..."
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
Phases: [x] Recon  [x] Collect  [>] Consume & Test  [ ] Exploit  [ ] Report
[work-buffer] 120/495 done (24%) | api: 15/21 | page: 98/464 | js: 7/10 | findings: 5
```
```bash
sqlite3 "$DB" ".timeout 5000" "
  SELECT type, SUM(CASE WHEN status='done' THEN 1 ELSE 0 END) as done,
    SUM(CASE WHEN status!='skipped' THEN 1 ELSE 0 END) as total
  FROM work_items GROUP BY type ORDER BY total DESC;"
```

## Key Rules

- ALWAYS use `./scripts/dispatcher.sh` for work-buffer ops (never read cases.db directly)
- Record findings in backend state immediately and keep findings.md synchronized
- Re-ingest new endpoints through backend-first producers; let the work buffer mirror the resulting canonical ids
- Use reset-stale at start of each iteration
- **DO NOT STOP EARLY** — loop until pending=0 for all consumable types
- On subagent error: mark cases `error`, log, CONTINUE (don't halt loop)
- Only stop on: pending=0 everywhere, or user /stop

## Dispatcher Quick Reference

```bash
DB="<engagement_dir>/cases.db"
./scripts/dispatcher.sh "$DB" stats
./scripts/dispatcher.sh "$DB" fetch <type> <limit> <agent_name>
./scripts/dispatcher.sh "$DB" done "id1,id2,id3"
./scripts/dispatcher.sh "$DB" error "id1,id2,id3"
./scripts/dispatcher.sh "$DB" reset-stale <minutes>
echo '{"url":"...","method":"GET","type":"api","auth_context":"anonymous"}' | ./scripts/dispatcher.sh "$DB" requeue
```
