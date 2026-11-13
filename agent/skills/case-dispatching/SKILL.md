---
name: case-dispatching
description: Guide operator through the transient work-buffer coordination loop for security testing
origin: Vigil
---

# Case Dispatching

Coordination for consuming the backend work buffer (`assessment_work_items`). Ingest verbs derive
each work item from the posted request observation in the same transaction (ADR 0013), so the
backend is canonical and there is no local queue to keep in sync. This skill inspects, routes,
completes and requeues work items. All target-facing execution stays in `vigil assess kali ...`.
Use `vigil assess work-buffer <action>` rather than the backend API, because the verbs apply the
classification and priority logic.

Load it in Phase 4 once surface-collector has populated the buffer, and again whenever a producer
adds work.

## The Consumption Loop

`agent/phases/phase-4-consume-test.md` steps b-g own the loop: reset stale, read stats, fetch by
type (pending < 2000) or by priority (pending ≥ 2000), dispatch with the raw fetched rows, mark
`done` only after the subagent wrote durable findings, probe runs and coverage, and repeat until
pending is 0 for every consumable type. This skill adds the routing tables, the signal → skill
triggers and the queue-hygiene steps below.

### Priority-mode scoring reference

Classification runs inline at ingestion and stamps each row from its URL structure;
`agent/scripts/assess/lib/classify_buckets.py` holds the authoritative bucket weights and
`agent/references/gf-patterns/<bucket>.md` explains each bucket.

- `cluster_key` — `gf:<bucket>` for the highest-weight matching gf bucket (ties go to declaration
  order); otherwise `path:/<first-two-url-segments>`.
- `priority_score` — that bucket's weight (curated candidate ingest may carry higher operator
  scores).
- `priority_reason` — every matched bucket (`"gf:ssrf+gf:idor"`), so the operator sees why a row
  scored high.
- `terminal_reason` — set on hopeless rows (`inert_type`), which `fetch-by-priority` excludes.

Review clusters with `vigil assess work-buffer clusters` and drop low-signal ones with
`vigil assess work-buffer defer-cluster <cluster_key> --reason "…"` before dispatch.
`fetch-by-priority <n> auto|vulnerability-analyst[-N]|source-analyzer[-N]` is route-aware: it
claims only rows whose type maps to that specialist. Re-run `work-buffer reclassify` only after
intentionally changing the bucket table.

## Type → Agent Routing

The inert type set is `INERT_TYPES` in `agent/scripts/assess/lib/classify_buckets.py`.

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
| image / video / font / archive / manifest | skipped at insert (status='skipped', terminal_reason='inert_type') |

## Signal → Skill Trigger Table

Before dispatching a batch, scan the work items and intel for these signals. When one matches,
name the skill in the dispatch context (`--skills` on `agent start`) alongside the specialist's
default skill. The signals point at likely classes; they do not limit what the specialist tests.

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
| LLM/agent endpoint (`gf:llm_api` cluster, `/v1/chat/completions`, `/embeddings`, `/inference`, or a `messages`/`system_prompt`/`max_tokens`/`tool_choice` parameter — a bare `?prompt=` is an OIDC parameter, not an LLM one) | `llm-api-testing` | vulnerability-analyst |

Naming the skill puts it in the specialist's first load; specialists can still find others with
`vigil assess list-skills`, but a named skill is the one the lane is built around.

## Batch strategy and progress

Send up to 10 same-type items per cycle and dispatch at once, in the priority order api-spec > api
> form > graphql > page > javascript > others. After every batch, run `vigil assess work-buffer
stats` (one `status|type|count` row per pair) and show a progress line:

```
Phases: [x] Recon  [x] Collect  [>] Consume & Test  [ ] Exploit  [ ] Report
[work-buffer] 120/495 done (24%) | api: 15/21 | page: 98/464 | js: 7/10 | findings: 5
```

When a subagent errors, mark its items `error`, log it and carry on; halting abandons the rest of
the batch. If the producer itself (surface-collector, ingestion, a nuclei sweep) is stuck or
failing, stop looping and escalate the producer issue, because looping over a broken producer burns
dispatch budget on nothing.

## Out-of-Scope Triage (operator-only, before the dispatching pass)

Before the dispatching pass, walk the top of the queue and resolve the candidates `scope.json` puts
out of scope. Each one would cost a specialist a full context window before it noticed. Common
cases are:

- subdomains the brief excludes
- `*.dev` / `*.staging` / `*.sandbox` hosts on a production-only brief
- third-party assets the in-scope domain links to (CDN edges, marketing platforms, helpdesk
  widgets)
- deployment-platform endpoints such as Azure SCM/Kudu (`*.scm.azurewebsites.net`)
- vendor-managed SaaS hosts when the brief covers only the customer's app

```bash
vigil assess resolve surface <id> --status not_applicable \
  --rationale "Out of scope per program brief: <quote the relevant exclusion>"
```

This is queue hygiene under `agent/shared-constraints.md` §1: remove non-admitted work before you
pick a dispatch objective.

## Linking Surfaces to Work-Buffer Clusters

When a recorded surface (`vigil assess record-surface`) corresponds to a cluster of work-buffer items already ingested with a durable `request_variant_id`, link them on the backend so the surface's coverage trail points at the exact requests that back it:

```bash
vigil assess work-buffer link-surface --cluster <cluster_key> --surface-id <id> \
  --relation primary-endpoint --link-evidence-ref "<artifact path>"
```

Selection is by `--cluster` (the work buffer's `cluster_key`) or `--queue-key`; a work item that never successfully posted to the backend (no `request_variant_id`) is skipped with a warning rather than failing the whole run.

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
