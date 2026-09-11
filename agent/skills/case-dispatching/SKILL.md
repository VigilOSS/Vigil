---
name: case-dispatching
description: Guide operator through the transient work-buffer coordination loop for security testing
origin: Vigil
---

# Case Dispatching

Guides consumption of the backend work buffer (`assessment_work_items`) for batching worker tasks. The orchestrator backend is canonical for the work buffer itself — not only for findings, coverage, services, request variants, and chains: ingest verbs derive each work-item row server-side from the posted request-observation in the same transaction (ADR 0013), so there is no separate local queue to keep in sync or drift from canonical backend identities.

This skill is coordination-only. Use it to inspect the work buffer, route batches, mark completion or errors, and requeue canonical work items. Do not use host-side shell commands from this skill to probe, crawl, fuzz, or exploit targets directly. All target-facing execution must happen through `vigil assess kali ...` subcommands so the audit pipeline stays truthful.

## When to Activate

- Phase 4 (Consume & Test) after surface-collector has populated the work buffer
- When pending work items exist in the work buffer
- When a producer has added new work items

## The Consumption Loop

**Routing rule: Fetch work items and route per the type-to-agent table below. Each agent is specialized — vulnerability-analyst lacks the DOM/JS parsing context that source-analyzer has, and source-analyzer lacks the request-crafting methodology that vulnerability-analyst has, so mixing types produces shallow analysis.**

**Dispatch mode switches on work-buffer volume.** Type-based fetch orders within a type by id, which is fine for small buffers but blind to signal quality. At 2000+ pending items, switch to priority-first fetch so specialists see high-signal clusters first.

Each iteration:
```
1. Reset stale: vigil assess work-buffer reset-stale 10
2. Check stats: vigil assess work-buffer stats    # read total pending
3a. Pending < 2000 → type-based dispatch (vulnerability-analyst and source-analyzer can run IN PARALLEL):

    vulnerability-analyst: api, api-spec, form, upload, graphql, websocket
    source-analyzer: page, javascript, stylesheet, data

    vigil assess work-buffer fetch <type> 10 <agent_name>

3b. Pending >= 2000 → priority-first dispatch:

    # Classification ran inline at ingestion, so priority_score / cluster_key
    # are already populated. Re-run `work-buffer reclassify` only if you
    # intentionally changed _BUCKETS in classify_buckets.py and want to
    # re-apply the new weights to already-ingested rows.

    # Review clusters and defer low-signal ones before dispatch:
    vigil assess work-buffer clusters
    vigil assess work-buffer defer-cluster <cluster_key> --reason "..."

    # Fetch across types by priority. `fetch-by-priority` is route-aware: it
    # only claims rows whose type maps to a real specialist route and rejects
    # free-form agent names so stray labels can't mix work types.
    #   auto                      — claim the top N routable rows globally and
    #                               stamp each with its canonical owner.
    #   vulnerability-analyst[-N] — claim only API/auth/workflow/debug/portal/
    #                               event rows (N is an optional instance label).
    #   source-analyzer[-N]       — claim only page/javascript/stylesheet/data rows.
    vigil assess work-buffer fetch-by-priority 10 auto
    vigil assess work-buffer fetch-by-priority 10 vulnerability-analyst
    vigil assess work-buffer fetch-by-priority 10 source-analyzer-2

4. On subagent return:
   - Done: vigil assess work-buffer done 101 102 103
   - New endpoints: feed them back through `vigil assess ingest endpoints <source>` or `vigil assess ingest spec <spec-file>` — those paths run inline classification so the new rows enter the priority queue with scores immediately
   - Findings: write structured finding state with `vigil assess finding record`
   - Errors: vigil assess work-buffer error 101 102 103
5. pending=0 and producers stopped → report completion
6. Otherwise → loop back to step 1
```

### Priority-mode scoring reference

Classification runs inline during `db_insert_work_item()` and populates four fields on
each work item from the URL structure (see `agent/scripts/assess/lib/classify_buckets.py`
for the authoritative weight table):

- `cluster_key` — `gf:<bucket>` when a parameter or path pattern matches a gf bucket; otherwise
  `path:/<first-two-url-segments>` as the fallback when nothing matches.
- `priority_score` — integer 0-50 for automatic gf buckets; curated candidate-record
  ingest may carry higher operator scores. Weights (highest first): rce (50), ssrf (40), sqli/lfi (40),
  img_traversal (35), trust_surface (35), idor (35), upload_fields (30), debug_logic (30),
  redirect/ssti/cors (25), xss (20), interestingparams (15), interestingext (10).
  Cluster_key and priority_score track the single highest-weight match; when two buckets tie,
  earlier declaration order wins deterministically.
- `priority_reason` — e.g. `"gf:ssrf+gf:idor"` listing every matched bucket, so the operator sees
  why an item scored high without running gf manually.
- `terminal_reason` — set on hopeless items (`inert_type` for image/video/font/archive/sourcemap/manifest);
  these are excluded from `fetch-by-priority`.

Each gf bucket has a reference at `agent/references/gf-patterns/<bucket>.md` — consult it when
you're unsure why a cluster scored the way it did.

## Type → Agent Routing

The inert/skipped type list is owned by
`agent/scripts/assess/lib/classify_buckets.py:INERT_TYPES`; this table mirrors
that set so an operator reading the skill gets the same answer as the
inline classifier. If the table goes stale, fix the drift in this file
because the code is the source of truth.

| Type        | Agent                  |
|-------------|------------------------|
| api         | vulnerability-analyst  |
| api-spec    | vulnerability-analyst  |
| form        | vulnerability-analyst  |
| upload      | vulnerability-analyst  |
| graphql     | vulnerability-analyst  |
| websocket   | vulnerability-analyst  |
| auth_entry  | vulnerability-analyst  |
| workflow    | vulnerability-analyst  |
| api_route   | vulnerability-analyst  |
| event_feed  | vulnerability-analyst  |
| debug_config | vulnerability-analyst |
| portal_session | vulnerability-analyst |
| page        | source-analyzer        |
| javascript  | source-analyzer        |
| stylesheet  | source-analyzer        |
| data        | source-analyzer        |
| unknown     | operator (manual)      |
| image / video / font / archive / sourcemap / manifest | skipped at insert (status='skipped', terminal_reason='inert_type') |

## Signal → Skill Trigger Table

Before dispatching a batch, scan the work items for these signals. When a signal matches,
the named skill MUST be included in the dispatch context (`--skills` on `agent start`)
in addition to the specialist's default skill. This prevents new skills from going unused.

| Signal in Work Item / Intel | Required Skill | Agent |
|-----------------------------|----------------|-------|
| Search endpoint + ES tech fingerprint (hits/took/_source in responses, `X-Elastic-Product` header) | `elasticsearch-injection` | vulnerability-analyst |
| BFF/proxy architecture detected (Express middleware, API gateway, `X-Forwarded-User` header in responses) | `bff-parameter-override` | vulnerability-analyst |
| PUT/PATCH endpoint where body contains `_id`, `id`, `objectId` that mirrors route param | `split-brain-idor` | vulnerability-analyst |
| SAML SP endpoint (`/saml/acs`, `/saml/metadata`, SAML login redirect) | `saml-sso-testing` | vulnerability-analyst |
| Object reference IDs in URL params or path segments | `idor-testing` | vulnerability-analyst |
| Login/register/reset/MFA/OAuth endpoint | `auth-bypass` | vulnerability-analyst |
| GraphQL endpoint (`/graphql`, introspection response) | `graphql-testing` | vulnerability-analyst |
| File upload endpoint (multipart form, file parameter) | `file-upload-testing` | vulnerability-analyst |
| URL/callback/webhook parameter (server-side fetch surface) | `ssrf-testing` | vulnerability-analyst |
| Redirect parameter (`next`, `return_to`, `url`, `redirect_uri`) | `open-redirect-testing` | vulnerability-analyst |
| MongoDB/CouchDB tech fingerprint (ObjectId format, Mongoose errors) | `nosql-injection` | vulnerability-analyst |
| XML input accepted (SOAP, SVG upload, RSS, SAML) | `xxe-testing` | vulnerability-analyst |

**Operator obligation**: When fetching work items, scan the URL patterns and intel for these
signals. If a signal matches, name the skill in the dispatch prompt. The specialist loads what
the operator names — if the operator omits it, the specialist won't know the skill exists.

## Batch Strategy

- Up to 10 same-type work items per cycle, dispatch immediately
- Priority: api-spec > api > form > graphql > page > javascript > others

## Progress Display (after EVERY batch)

```
Phases: [x] Recon (pass 1)  [x] Recon (gate ✓)  [x] Collect  [>] Consume & Test  [ ] Exploit  [ ] Report
[work-buffer] 120/495 done (24%) | api: 15/21 | page: 98/464 | js: 7/10 | findings: 5
```
```bash
vigil assess work-buffer stats
```
`stats` (default `--by status`) prints a `status|type|count` row per (status, type) pair —
the per-type done/total breakdown the progress line above summarizes.

## Out-of-Scope Triage (operator-only, before the dispatching pass)

Before dispatching specialists against the surface-candidate list, walk the top of the queue and mark any candidates that are out of scope per the engagement's `scope.json` as `not_applicable` with a one-line rationale. Each out-of-scope dispatch costs a full specialist context window; the operator can kill those candidates in two seconds.

Examples that recur in real engagements:

- Subdomains explicitly excluded in the program brief (named in `scope.json` `exclusions` or scope-policy text)
- `*.dev` / `*.staging` / `*.sandbox` subdomains when the brief is production-only
- Third-party-hosted assets (CDN edges, marketing platforms, support portals, Helpdesk widgets) that surfaced because the in-scope domain links to them
- Azure SCM / Kudu / `*.scm.azurewebsites.net` and other deployment-platform endpoints when the in-scope target is the application surface, not the deployment platform
- Salesforce-managed vendor SaaS hosts when the brief covers the customer's app, not the vendor platform

```bash
vigil assess resolve surface <id> --status not_applicable \
  --rationale "Out of scope per program brief: <quote the relevant exclusion>"
```

Triage these BEFORE the dispatching pass, not during. A specialist that opens an out-of-scope candidate runs the full skill methodology before realising the scope error, then writes a handoff explaining why it stopped — the operator could have prevented all of that with one `resolve surface` call. This is queue hygiene under `agent/shared-constraints.md` §1: remove non-admitted work before selecting a dispatch objective.

## Linking Surfaces to Work-Buffer Clusters

When a recorded surface (`vigil assess record-surface`) corresponds to a cluster of work-buffer items already ingested with a durable `request_variant_id`, link them on the backend so the surface's coverage trail points at the exact requests that back it:

```bash
vigil assess work-buffer link-surface --cluster <cluster_key> --surface-id <id> \
  --relation primary-endpoint --link-evidence-ref "<artifact path>"
```

Selection is by `--cluster` (the work buffer's `cluster_key`) or `--queue-key`; a work item that never successfully posted to the backend (no `request_variant_id`) is skipped with a warning rather than failing the whole run.

## Key Rules

- Use `vigil assess work-buffer <action>` for all work-buffer operations — calling the backend API directly bypasses the classification/priority logic these verbs apply and can produce stale or inconsistent state
- Treat this skill as host-side coordination only. All real target testing stays in `vigil assess kali ...`.
- Record findings in backend state immediately via `vigil assess finding record`
- Re-ingest new endpoints through backend-first producers; let the work buffer mirror the resulting canonical ids
- Use reset-stale at start of each iteration
- **Loop until pending=0 for all consumable types** — stopping early leaves tested surfaces unrecorded and forces a re-dispatch to pick up the tail
- On subagent error: mark work items `error`, log, CONTINUE — halting the loop on a single error abandons the remaining batch
- Stop on any of:
  - pending=0 everywhere (normal completion)
  - the upstream work-buffer producer (surface-collector, ingestion, nuclei sweep) is itself stuck or failing — looping against an empty or broken producer burns dispatch budget on no real work. Escalate the producer issue first, then resume.

## Dispatcher Quick Reference

```bash
vigil assess work-buffer stats
vigil assess work-buffer fetch <type> <limit> <agent_name>
vigil assess work-buffer done 101 102 103
vigil assess work-buffer error 101 102 103
vigil assess work-buffer reset-stale <minutes>
echo '{"url":"...","method":"GET","type":"api","auth_context":"anonymous"}' | vigil assess work-buffer requeue
echo '{"url":"https://target.example/api/search","method":"GET","type":"api","auth_context":"anonymous","request_variant_id":42,"coverage_item_id":77,"queue_key":"variant:42:api"}' | vigil assess work-buffer requeue
```
