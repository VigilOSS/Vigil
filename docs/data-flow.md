# Vigil data flow — how assessment state is ingested, stored, and consumed

> **Purpose.** A human-reviewable map of Vigil's web-assessment data pipeline: what each ingestion
> tool captures, which backend model/table it feeds, how that state is consumed downstream (coverage,
> depth gate, resume-brief, phase gates, work-buffer), how the pieces depend on each other, and which
> checks actually *block* vs merely *advise*. It also answers a recurring design question — **why
> coverage-items stay coarse** — and documents the current state of **header ingestion**.
>
> **Audience.** Anyone reviewing or extending the ingestion/coverage machinery. Anchors are
> `file:line` (backend paths under `orchestrator/backend/app/`, CLI under `agent/scripts/assess/`).
> Verified 2026-07-05, updated 2026-07-08 for the work-buffer fold. Companion: `CODE-MAP.md`
> (ownership/registration), `docs/adr/0001-coverage-as-harness-not-gate.md` (the gating philosophy
> this doc reflects) as calibrated by `docs/adr/0012-coverage-grain-selective-load-bearing-depth.md`
> (the decisive-unit class-gate), and `docs/adr/0013-work-buffer-folded-into-backend-ledger.md` (the
> single-store work-buffer decision this doc now assumes throughout).

---

## 0. The one-paragraph mental model

Recon/discovery tools produce **URLs and requests**. Those are POSTed into the **durable backend
ledger** as **request-observations**. The backend folds each admitted observation into a deduped
**request-variant**, auto-generates a coarse **coverage-item** to-do list (one item per *input class*
× *implied vuln-class*), and — in the same transaction — derives a **work-item** row
(`assessment_work_items`, priority-scored and gf-classified) for the triage/dispatch queue (ADR 0013;
there is no separate local queue). Specialists then run **probes** against those inputs and record
**findings**. Downstream, an **app-unit scorer** + **depth ledger** decide whether each app-unit was
tested deeply enough; a small set of **hard gates** in `transition_phase.py` are the *only* things that
actually block phase progress. Everything else — the resume-brief, the coverage rollups, the per-host
audit — is advisory orientation. This "gate at the family level — and, for decisive/high-confidence
units, at the class level — keep everything else finer advisory" split is a deliberate architecture
decision (ADR 0001, calibrated by ADR 0012 for the decisive-unit exception).

---

## 1. One store, one job

| Store | What it is | Written by | Read by |
|---|---|---|---|
| **Backend ledger** (SQLite via FastAPI) | Durable canonical state: targets/services/request-variants/observations, coverage-items, probes, surfaces, findings, chains, intel, host-liveness, command-runs, **and the work-buffer queue** (`assessment_work_items`) — engagement-scoped via a real `engagement_id` FK, priority-scored + gf-classified *at insert*. | Ingest verbs (via `/request-observations[/bulk]`, which carries a `work_item` derivation block the backend persists server-side in the same transaction — ADR 0013) + `ingest arjun`/out-of-scope-skip rows via `/work-items/bulk` directly + the record/resolve CLI verbs + the machine auto-emit path. | Everything downstream: coverage, depth gate, resume-brief, phase gates, report readiness, frontend, **and** work-buffer triage (`work-buffer clusters`, `fetch-by-priority`) → specialist dispatch routing. |

Before ADR 0013, the work-item row lived in a separate per-engagement SQLite file (`cases.db`) written
by a second, decoupled step after the observation POST, so its backend FKs
(`request_variant_id`/`service_id`/`coverage_item_id`) could transiently lag the observation that
produced them. The backend now derives the work-item row in the **same transaction** as the
observation/coverage-item write, so that lag window no longer exists. `dns-discovery` still leaves data
on disk with no exporter — that is orthogonal to the work-buffer fold.

### Operator API/CLI contract pointers

This is an ownership map, not a second schema. Use `vigil assess contract <verb>` for the executable
CLI contract and the named request model/service for payload and persistence truth.

| Operator action | CLI owner | API/model owner | Storage/service owner |
|---|---|---|---|
| Dispatch start, validation-only dry run, and identity attribution | `agent/scripts/assess/commands/agent.py`; `lib/instruction_identity.py` | `api/assessment.py:DispatchCreate` | `services/state_manager/dispatches.py`; `assessment_dispatches` |
| Finding create/update/verify and author repair | `commands/record_finding.py`, `update_finding.py`, `verify_finding.py`, `repair_finding_author.py` | `api/assessment.py` finding request models | `services/state_manager/findings.py`; `assessment_findings` and audit events |
| Intel record, create/update outcome, filtering, and point reads | `commands/record_intel.py`, `list_intel.py`, `get_intel.py` | `api/intel_schemas.py`; `api/intel.py` | `services/intel.py`; `intel_*` tables and search index |
| Artifact register, targeted refresh, search, and finding unlink | `commands/artifact.py` | `api/artifact_index.py` | `services/artifact_index.py`; `assessment_artifacts` (proof receipts remain independent and immutable) |
| Resume orientation and count/truncation truth | `commands/resume_brief.py` | `api/assessment.py` resume route | `services/assessment_memory.py` projections over canonical backend tables |
| Code repository ingestion | `commands/code_ingest.py` | `api/code_analysis.py` | `services/code_analysis.py`; `code_repos`/`code_files` (legacy `scope.json` repo keys are read-only compatibility input) |

---

## 2. Ingestion — tool → backend model → table

| Tool / verb | Backend endpoint | Model | Table(s) | **Headers?** |
|---|---|---|---|---|
| `ingest endpoints` (bulk crawler/gau/katana/gf — highest volume) | `/request-observations/bulk` + `/coverage-items/bulk` | `RequestObservationIngestRequest`, `CoverageItemBulkRecordRequest` | request-variants/observations/coverage-items + gf class-typed coverage-items | **populated** — header names captured from the ingested rows where present (`ingest_endpoints.py:667`); left `{}` (with a one-line why-not comment) only when a given row genuinely carries no header data |
| `ingest candidates` (curated JSONL) | `/request-observations/bulk` + `/surface-request-variant-links` | same + `SurfaceRequestVariantLinkRequest` | same + `surface_request_variant_links` | **populated** *if the JSONL supplies `headers`* (`_coerce_header_params`) — no automated producer feeds it |
| `ingest spec` (OpenAPI import) | `/request-observations/bulk` | same | same | **populated** from `in: header` params (`ingest_spec.py:469-518`) |
| `ingest httpx` (host liveness) | `/host-liveness` | `HostLivenessUpsertRequest` | `assessment_host_liveness` | n/a (host-level, no request) |
| **mitmproxy** `proxy_addon.py` (derived observation) | `/request-observations` | `RequestObservationIngestRequest` | request-variants/observations/coverage-items + `assessment_work_items` (derived server-side, ADR 0013 — the addon no longer opens a local SQLite connection) | **populated** into `header_schema` from the `dict(req.headers)` the proxy already holds (`:1013`); full headers also still dumped into an opaque `raw_payload` blob |
| mitmproxy (full-flow capture) | `/http-flows` | `HttpFlowIngestRequest` | `assessment_http_flows` | **full headers** — but **opt-in** (off by default) and orthogonal to coverage |
| `dns-discovery` | — | — | local files only | n/a |
| `web-discovery` | `/host-liveness` + delegates to `ingest endpoints` | — | host-liveness + (delegated) | **populated** (inherits `ingest endpoints`'s capture; katana run `-or -ob`) |
| `gau endpoints` / `gau js-endpoints` | delegate to `ingest endpoints` | — | (delegated) | **populated** (inherits `ingest endpoints`'s capture) |
| `ingest arjun` | `/work-items/bulk` (direct — no observation POST) | `WorkItemBulkIngestRequest` | `assessment_work_items` | header-discovery is **dead code** (`arjun_enrich.py` hardcodes `[]`; arjun's `--headers` = auth headers, not discovery) |
| `record-surface` / `resolve surface` / `work-buffer link-surface` | `/surfaces`, `/surface-request-variant-links` | `SurfaceRecordRequest` etc. | `assessment_surfaces`, links | n/a |
| `record-probe` (folds the former `record-attempt`) | `/probe-runs` | `ProbeRunRecordRequest` | `assessment_probe_runs` | only the free-text `input_slot="header:Name"` convention |
| `resolve coverage-item` | `PATCH /coverage-items/{id}` | `CoverageItemUpdateRequest` | `assessment_coverage_items` | n/a |
| `finding record` / `intel record` / `record-chain` / `block-technique` / kali `command-runs` | resp. endpoints | resp. models | outcome tables | n/a (outcome writes) |

**Header takeaway:** capture now spans OpenAPI-spec import, hand-authored candidate JSONL, the bulk
endpoint-ingest path, and the live proxy — the two previously-dropping, highest-volume paths now populate
`header_schema` from data they already hold. Per-header-NAME coverage-items are still not emitted by any
path. See §6.

---

## 3. The core chain: observation → request-variant → coverage-item

All observation ingest routes through `coverage.py:_ingest_request_observation` (`:830`). Per item:

1. **`_upsert_target`** → `assessment_targets` (by identity).
2. **`_upsert_service`** → `assessment_services` (by endpoint+protocol). `coverage_status` is
   sticky-forward: a fresh `pending` never regresses an already `covered/partial/blocked` service.
3. **`_upsert_request_variant`** → `assessment_request_variants`. The dedup point. Its natural key is a
   hash over `{query, path, cookie, **headers**}` + body schema + method/path/auth_context/content-type.
   **`header_schema` is part of that hash** — so a header-schema change forks a variant into a new row.
   Headers land in `header_schema_json` (`db.py:850`).
4. **`_insert_request_observation`** → `assessment_request_observations` (one row per capture; not
   deduped; carries the opaque `raw_payload`).
5. **Coverage-item auto-generation** (`_auto_request_coverage_candidates`, `coverage.py:607-626`): emits
   **one candidate per coarse input class present** — `endpoint` (always), `query`/`body`/`path`
   (if that schema is non-empty), `cookie`, **`header` iff `header_schema` non-empty** — plus a
   `service` candidate. Each is upserted into `assessment_coverage_items`, natural key
   `UNIQUE(engagement_id, request_variant_id, service_id, auth_context, input_slot, attack_family)`
   (`db.py:912`).

Separately, the **gf-bucket bridge** (`ingest_endpoints.py:_gf_coverage_item_payloads`) re-runs the
classifier per ingested URL and POSTs one **class-typed** coverage-item per matched gf bucket
(`attack_family = GF_BUCKET_TO_CLASS[bucket]`, `input_slot` hardcoded `"endpoint"`) — this is how the
local classifier's signal becomes durable state the depth gate can read.

---

## 4. Consumption — who reads the state

| Consumer | Reads | Produces | Blocks? |
|---|---|---|---|
| **App-unit scorer** (`app_units.py:584`) | request-variants/observations/surfaces, tech intel, coverage-items (`attack_family` only) | `assessment_application_units`: `deep_required`, `depth_tier`, structure/risk/suppressor scores | **Advisory** (WARN-first) |
| **Depth ledger** (`depth_ledger.py:112`) | app-units, request-variants (incl. `header_schema_json`), coverage-items + probes (**`attack_family` only, never `input_slot`**), dispatches, findings | per-unit `expected`/`covered`/`missing_block`/`touched`/`signal_classes_uncovered` | **Advisory itself** — but `signal_classes_uncovered` is now selectively load-bearing for decisive units via `terminal_depth_block` below (ADR 0012) |
| **`terminal_depth_block`** (`depth_ledger.py:918`) | scorer + ledger; `confidence`, `decisive_surface`, `depth_satisfied`, `touched`, `signal_classes_uncovered` (restricted to `BLOCK_HIGH` classes) | two grains of blocking unit, `block_grain="family"` (the historical untouched/unsatisfied case) and `block_grain="class"` (ADR 0012) | feeds the **one** hard gate (in `transition_phase.py`), split into two `severity="block"` blocker `kind`s — `depth_unsatisfied_units` (family) and `depth_uncovered_classes` (class); a decisive/high-confidence unit with a non-empty `BLOCK_HIGH`-class `signal_classes_uncovered` now BLOCKS via the class grain **regardless of `touched`/family `depth_satisfied`** (ADR 0012) |
| **Coverage rollup** (`coverage.py:2810`) | coverage-items × host-liveness | `coverage_by_reachability` (reachable/blackholed/…) | Advisory |
| **Per-host C40 audit** (`coverage.py:2104`) | services/surfaces/intel/findings (never command-runs) | 5 objectives per host (waf/inventory/fuzz/fingerprint/osint) | **WARN-only** |
| **Resume brief** (`assessment_memory.py:580`) | ~everything | 12-section operating picture incl. **`## Per-Input Coverage`** grid | **Never blocks** (display) |
| **Phase readiness** (`phase_readiness.py:306`) | coverage_readiness + per_host + depth_ledger + report_readiness + intel | assembled per-phase payload | Assembly only |
| **`check-phase-readiness`** (CLI) | the above | text/JSON + exit code | **Mixed** (see §5) |
| **Work-buffer triage** (`classify_buckets.py`, `dispatch/work_items.py`) | backend `assessment_work_items` | priority/cluster/terminal-reason; claimed dispatch batches | Advisory routing |
| **`transition_phase.py`** (CLI) | scope, findings, dispatches, report-readiness, `terminal-block` | writes `scope.json[current_phase]` | **The only hard, process-exiting gates** |
| **Report readiness** (`report_readiness.py:51`) | findings, coverage, links, artifacts, chains, handoffs | `{ready, blockers[], advisories[]}` (~18 blocker kinds) | **Blocks** report finalize + `report` transition |

### The per-input grid (where WS2 lives)
`assessment_memory._per_input_coverage_section` (`:463-577`) groups the most recent 400
`assessment_probe_runs` by `(target_host, target_path, attack_family, input_slot, auth_context)`,
marks a cell covering if any probe is `tested|signal`, and surfaces `observed_http_status` as the wall
code. **This is the only consumer that reads the per-input-NAME `slot:name` grain — and it is purely
advisory (resume orientation), never a gate.**

### Dedicated-dispatch satisfaction (structured assignment, evidence-owned coverage)

A deep unit has a separate **dedicated specialist dispatch** obligation in addition to its class
coverage. `vigil assess agent start --application-unit-id <id>` records the optional concrete unit
identity on `assessment_dispatches`; the backend validates that the unit belongs to the same
engagement and does not infer or admit host scope. `vuln_classes` remains optional intent metadata.

`depth_ledger._dedicated_dispatch_satisfied` (`depth_ledger.py:~842`) resolves this: a dispatch
QUALIFIES only when its `status='completed'`, its `application_unit_id` names the unit, AND it carries
**work evidence** — ≥1 covering probe (`result_status ∈ {tested, signal}`) or a recorded
finding mapped to the unit. A bare `status='completed'` with only a self-attested handoff summary does
**not** qualify. Class coverage is independent and evidence-owned: only recorded probe/coverage-item
`attack_family` values clear `missing_block`; dispatch `vuln_classes`, `skills`, and free-text `task`
are never read as coverage. `depth_satisfied` therefore requires both no evidence-backed
`missing_block` families and a qualifying dedicated dispatch.

---

## 5. What actually blocks (vs advises)

Almost everything is advisory/WARN-first. The **only** hard, process-exiting gates live in
`transition_phase.py`, escapable via `--force` (an optional `--reason` is retained in the recorded
override decision):

- **`missing_variant_pass`** — every confirmed critical/high finding needs a completed
  `variant-rotation` VA dispatch naming it. Gates `verify → exploit`.
- **`missing_chain_construction`** — ≥2 confirmed high/critical findings require a completed EX
  dispatch. Gates `exploit → report/complete`.
- **`missing_blind_triage`** — every Medium+ active finding needs an accept-verdict triage decision.
  Gates `report/complete`.
- **`terminal_depth_block`** — the one hard block from the depth harness, split into two blocker `kind`s
  from the same call (`_depth_backstop_blockers`), both `severity="block"`, both cleared by the same
  `depth_deferral`/`--force` valves (with an optional recorded `--reason`):
  - `depth_unsatisfied_units` (`block_grain="family"`, the historical block) — fires when an app-unit is
    high-confidence-or-decisive **and** unsatisfied **and** untouched **and** undeferred.
  - `depth_uncovered_classes` (`block_grain="class"`, ADR 0012) — fires when a high-confidence-or-decisive
    app-unit's `signal_classes_uncovered`, restricted to `BLOCK_HIGH` classes, is non-empty and undeferred
    — **independent of `touched`/family `depth_satisfied`**, so it can block a unit that otherwise looks
    family-satisfied or merely touched (the single-class blind spot). Every non-decisive/non-high-confidence
    unit is unaffected and keeps the unconditional touched→WARN downgrade.
- **Report readiness** (separate) blocks report export finalize (409) and the `report` transition.

`check-phase-readiness`'s `--strict`/`--strict-deep` are a *different* command's exit codes and do
**not** drive the `transition_phase` gates. `signal_classes_uncovered` (the per-class refinement) now
renders in the **default** `check-phase-readiness` text (`_render_depth_ledger`), not only `--json` —
and, for decisive/high-confidence units, it is no longer purely advisory: an uncovered `BLOCK_HIGH`
class feeds the one hard gate above (ADR 0012). It stays advisory-only for every other unit.

**Preview, not a cold block (fixed by ADR 0012).** `_DEPTH_PHASES` (`check_phase_readiness.py:104`) now
includes `report` alongside `consume`/`verify`, so `check-phase-readiness --phase report` renders the
depth ledger — and specifically the would-block set — as a **preview** before the actual transition,
with the `depth_deferral` escape named inline. This closes the previous gap, where `terminal_depth_block`
(firing at `report`/`complete`) could not be previewed from the readiness surface at all and surfaced
only at the live `transition-phase report/complete` call. See
`docs/adr/0012-coverage-grain-selective-load-bearing-depth.md` for the root-cause framing (the fix is a
*continuous, legible* deferred-terminal obligation, not a reworded "advisory" label).

---

## 6. Header ingestion — current state and the gap

**Populated (real per-header data in `header_schema_json`):** all four request-observation ingest paths
now capture it — `ingest spec` (OpenAPI `in: header`), `ingest candidates` (only if the JSONL supplies
`headers` — no automated producer does), **and, per ADR 0012, `ingest endpoints`** (`:667`, header names
from the ingested rows where present — the highest-volume path, plus everything delegating to it:
`web-discovery`, `gau-*`) **and the mitmproxy derived observation** (`proxy_addon.py:1013`, populated
from the `dict(req.headers)` the proxy already holds).

**Still coarse at the coverage-item/gate layer (deliberately — see §7 / ADR 0012):** `header_schema`
itself is a per-header-NAME dict (needed for the depth ledger's CORS/proxy token-presence checks below),
but nothing downstream widens on it. The coverage generator still emits one coarse `header` candidate
per variant (never `header:X-Forwarded-Host`), and the coverage-item natural key (`db.py:912`) is
untouched. Per-name header evidence stays on `assessment_probe_runs.input_slot` — the advisory probe
grid — exactly like every other input class.

**Captured but still unqueryable for coverage:** the proxy also still dumps full headers into
`raw_payload` (opaque, per-capture, unqueryable) and, *opt-in only*, into `assessment_http_flows`
(structured, but not read by coverage/depth machinery — it's a HAR/audit surface). Populating
`header_schema` from the same in-hand headers is a separate, narrower write than either of those.

**The machinery on the far side is now fed, not starved.** The coverage generator's
`header → header-review` candidate (gated on headers being present) and the depth ledger's
`header_schema_json` presence trigger for the CORS (`client-side`) and proxy/CDN (`protocol`) families
now fire across the full ingest breadth, not only the spec/candidate slice. Both families are
`BLOCK_WARN` (§4/§5), so this widens *advisory* coverage completeness — it does **not**, by itself,
create a new hard block; a header-driven family only enters the hard block-set the same indirect way any
family would, if the unit is otherwise decisive/high-confidence and its `signal_classes_uncovered`
includes a `BLOCK_HIGH` class (ADR 0012) — which header presence alone never contributes, since neither
header-driven family is `BLOCK_HIGH`.

**Full per-header-NAME first-class inputs would still require** (remains carved out as its own,
sign-off-gated wave — see `ws3-feed-the-grid.md §6`; step 1 below is now done):
1. ~~Populate `header_schema` in `ingest_endpoints.py:667` + `proxy_addon.py:1013`~~ — **done** (above).
2. Emit per-header-NAME coverage candidates (`header:X-Forwarded-Host`) instead of one coarse `header`.
3. Widen the coverage-item natural key (`db.py:912`) to accept the `slot:name` form — **which reverses
   the coarse-coverage-item invariant** (§7), so it still needs explicit sign-off.

The standing attack-header checklist (`X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`,
`X-Http-Method-Override`, `X-Forwarded-For`, …) is unaffected by any of this: those are
*injected-at-test-time* inputs the operator/specialist chooses to probe, recorded via
`record-probe --input-slot header:Name` into the advisory per-input grid, the same as any other input.

---

## 7. Why coverage-items stay coarse (the design question)

There are **two grains on purpose**:

- **Coverage-items = the coarse, machine-generated to-do list** that drives the *gate*. One item per
  input *class* (`endpoint|query|body|path|cookie|header|service`) × implied vuln-class. The gate asks
  "was this vuln-*class* exercised on this app-unit?" — and keys entirely on `attack_family`, **never**
  `input_slot` (`depth_ledger.py` doesn't even select `input_slot`).
- **Probes = the fine, per-input evidence layer.** `assessment_probe_runs.input_slot` carries the
  free-text `slot:name` convention (`header:X-Forwarded-Host`), is part of the probe dedup key, and is
  surfaced by the advisory per-input grid. **This is where per-name granularity already lives.**

This split is deliberate, and it follows the project's central architecture decision
(`docs/adr/0001-coverage-as-harness-not-gate.md`): an earlier *strict* per-item gate was rejected as
**gameable and skippable** — free-text/self-labeled "covered" claims on many tiny items. The chosen
design gates only on durable, structured signal at the *family* level (one hard block), and pushes all
finer detail into an advisory harness. Making coverage-items per-header-name would:

- **Explode the write/index layer** — the key is already 6-dimensional; adding header-name multiplies
  rows by (header names) × (header-relevant families, several of which have no gf-bucket) × auth_context,
  and muddies the service-level `covered/partial/pending` rollup the consumption gates rely on staying
  simple. (The flat `pending: N` is already "permanently scary" — `coverage.py:2813`.)
- **Miss the headers that matter** — the highest-value test headers (`X-Forwarded-Host`,
  `X-Original-URL`, `X-Rewrite-URL`, `X-Http-Method-Override`) are usually **injected during testing**,
  not present in what was recon'd. A generator keyed to *observed* header names would systematically
  miss exactly the attacker-introduced surface — which is why the depth ledger already treats
  `header_schema` as a coarse *"does this look CORS/proxy-ish"* trigger, not an enumeration.
- **Reintroduce the gameable-claim problem** ADR 0001 rejected — dozens of tiny self-attested
  coverage-items an LLM marks "tested," or a huge always-red backlog.

**Net:** coverage-items are coarse because (1) nothing writes a fine value there, (2) nothing on the
read side looks past `attack_family`, (3) ADR 0001 rejects fine-grained self-attested gating, and
(4) the one place operators legitimately need "did we test header X" already gets it from the advisory
per-input grid — without touching the gate. Reversing this *for headers specifically* is a legitimate,
scoped, sign-off-gated change (§6), not a bug.

**ADR 0012 addendum.** The gate described in §4/§5 is now selectively load-bearing at the *class* level
for decisive/high-confidence units — but this reads `signal_classes_uncovered`, a signal already derived
from the same durable, non-self-attested state this section defends (a real `request_variant` + a
whitelisted `result_status`), never from a widened coverage-item. Coverage-item coarseness (this
section) and gate selectivity (§4/§5) are independent choices — ADR 0012 changes only the second.

---

## 8. The dependency graph

```
recon/discovery tools  ──►  classify_from_fields (inline, client-side, unchanged;
   (ingest endpoints/          same _BUCKETS taxonomy as before) ──► folded into the
    candidates/spec)           observation's `work_item` derivation block
        │
        ▼
   backend: request_observation
        │
        ├─► assessment_work_items  (derived SERVER-SIDE, SAME transaction — ADR 0013,
        │        │                  no dual write)
        │        ├─ work-buffer clusters / fetch-by-priority
        │        │     ──► specialist dispatch (advisory)
        │        └─ work-buffer reclassify (idempotent re-classify)
        │
        ├─► request_variant  (query/body/path/cookie/HEADER schema_json;
        │        │            header_schema is PART of the dedup hash; now
        │        │            populated by ingest endpoints + proxy_addon too)
        │        ├─► _auto_request_coverage_candidates  (COARSE: 1 item per
        │        │       input CLASS × implied vuln-class)
        │        └─► header_schema_json ──► depth_ledger._header_has_token
        │               (CORS / proxy-CDN PRESENCE trigger; both BLOCK_WARN
        │                families — advisory only, never the hard gate alone)
        │
        └─► gf-bucket bridge ──► class-typed coverage_items (attack_family=class,
                                  input_slot ALWAYS "endpoint")

   ingest arjun / out-of-scope-skip rows ──► POST directly to /work-items/bulk (no
   observation — these reuse an already-in-scope URL or record a skip) ──► assessment_work_items
                                   │
                                   ▼
                 assessment_coverage_items  (key: eng×variant×service×auth_context×input_slot×family)
                                   │
                ┌──────────────────┼───────────────────────────┐
                ▼                  ▼                            ▼
        app_units.gf_density   coverage_rollup            per_host_coverage (C40)
                │              (reachability, advisory)    (outcome objectives, WARN-only)
                ▼
        score_application_units ──► assessment_application_units (deep_required, depth_tier)
                │
                ▼
        depth_ledger  ◄──── assessment_probe_runs (attack_family, result_status ∈ {tested,signal})
         (covered keyed          │
          on attack_family,      └─ probe_runs.input_slot = "slot:name" (header:X-Forwarded-Host)
          PLUS class for               ──► READ ONLY by assessment_memory._per_input_coverage_section
          decisive units —              (resume-brief grid — advisory, never a gate)
          ADR 0012)
                ▲
                │  structured dispatch satisfaction (never free-text `task`, S7)
        assessment_dispatches (application_unit_id; vuln_classes is metadata only)
          ◄── `agent start --application-unit-id`
                │
                └─► depth_ledger._dedicated_dispatch_satisfied: status=completed AND unit id matches
                     AND ≥1 covering probe or finding exists under the unit
                     (bare completed/handoff alone never counts)
                     class coverage remains probe/coverage-item evidence only
                │
                ▼
        terminal_depth_block ──► transition_phase.py  ═══►  THE ONE HARD DEPTH GATE (report/complete)
          two blocker kinds, same call: depth_unsatisfied_units (family — untouched, historical) OR
          depth_uncovered_classes (class — BLOCK_HIGH class still uncovered, fires even if "touched" /
          family-satisfied; ADR 0012, decisive units only)
                                                              escape: depth_deferral / --force [--reason ...]

phase_readiness() assembles coverage_readiness + per_host + depth_ledger + report_readiness + intel
        │                                                              │
        ▼                                                              ▼
   check-phase-readiness (mixed advisory/blocking, --strict/-deep;   report_readiness ═══► blocks report
     depth-ledger + would-block preview now render for --phase
     report too, not only consume|verify — ADR 0012)
        └── INDEPENDENT of ──►  transition_phase hard gates (missing_variant_pass,
                                missing_chain_construction, missing_blind_triage, terminal_depth_block)

resume-brief ── reads ~everything ──► operator's bounded operating picture (NEVER blocks)
```

---

## 9. Quick reference — "if I change X, who cares?"

- **Add a field to an ingested observation** → `RequestObservationIngestRequest` (model) +
  `_ingest_request_observation` (chain) + possibly the request-variant dedup hash (if identity-bearing).
- **Change what's "covered"** → you're touching the gate; it keys on `attack_family` in `depth_ledger.py`,
  PLUS class (`signal_classes_uncovered`, restricted to `BLOCK_HIGH` families) for decisive/high-confidence
  units only (ADR 0012). Per-input/per-name changes still belong on `assessment_probe_runs`, which stays
  gate-neutral by design.
- **Make headers first-class (fully, per-name)** → §6's remaining 2 steps (step 1, capture, is done);
  reverses §7's coverage-item invariant; sign-off required.
- **Add a hard gate** → `transition_phase.py` (nowhere else actually blocks except report finalize).
- **Surface something to the operator without gating** → the resume-brief (`assessment_memory.py`) or
  the advisory harness (`signal_classes_uncovered`), not a coverage-item or a gate.
