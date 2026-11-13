# Phase 4 — Consume & Test

**Read-on-phase-entry.** Read this doc when you enter Phase 4 and again on a method re-anchor: this phase's cadence drifts toward breadth on long runs, and the Depth Doctrine is the countervailing cue. It carries the doctrine and lane fan-out, the Phased mindset flow, the Lens Vocabulary, the mid-phase cadence, the work-buffer loop (a–h) and cross-surface synthesis (i).

For the commands below, set:

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
```

4. **CONSUME & TEST** → operator-orchestrated. Load `agent/skills/case-dispatching/SKILL.md`.

   ### Depth Doctrine — Per-Domain VA Fan-Out

   **Depth is the doctrine; breadth-bias is the failure mode.** The pull toward covering everything and resolving each surface to a status favors quick checks, which means fewer vuln classes per surface, premature closure and missed bugs. A single surface is often a whole application (an authenticated portal, an API root, an admin console) that warrants its own campaign: crawl, content discovery, a parameter sweep, an IDOR sweep across its object references, JS/secret extraction, and one or more dedicated lanes. Concentrate the fan-out instead of spreading it.

   - **Focus 1-2 targets at a time; a surface can be a target.** Name the focused surface in each dispatch objective. For a DEEP lane on one concrete app unit, pass its id to `agent start --application-unit-id <id>` so the depth ledger credits it; omit the field for multi-unit work. When a hot lead emerges, converge disjoint-host lanes on it, then re-widen once it is resolved.
   - **Fan VA lanes at depth, not a swarm.** Partition the focused target into lanes keyed on **(surface group × mindset lens)** — e.g. the API surface group under `idor-bac.md`, upload/form surfaces under `injection-surface.md`, auth/session surfaces under `business-logic.md` — one `vulnerability-analyst` per lane, each running a real campaign at `item-iterating`/`hypothesis-driven` depth. Which vuln classes a lane finds signal in is the specialist's own hypothesis, labelled afterwards with `--vuln-classes` for the audit trail.
   - **Phased mindset flow** sets which mindset each lane loads, by pass:

     | Pass | `hunt_scope` / `dispatch_mode` | Mindset | Carried by |
     |---|---|---|---|
     | 1 — WIDE | `wide` / `hypothesis-driven` | Baseline (`adversarial-mindset.md` + `mindsets/developer.md`), no family lens — sweeps broadly and records per-family **signal**, confirms/kills nothing | `vulnerability-analyst`, `source-analyzer` |
     | 2 — DEEP | `deep` / `item-iterating` | One family lens (`idor-bac.md` / `injection-surface.md` / `business-logic.md`, closest fit) + matching vuln-class skill, per signal cell the wide pass flagged | `vulnerability-analyst`, `fuzzer` |
     | 3 — EXPLOIT | `deep` / `deep-manual` | `chain-impact.md`, cross-lane chain synthesis over the confirmed set | `exploit-developer` |

     Roles not in the table sit outside this rotation; code-track roles follow the code session's own flow. `vulnerability-analyst` also carries `agent/rules/mindsets/verification-skeptic.md` as standing context on every pass, separate from the lens rotation.
   - **Exploit-developer fan-out for high-value targets.** On a rich target, fan `exploit-developer` (deep-manual, `--assessment-mode web`, `chain-impact.md`) across the same lanes with full surface and intel context and an open objective ("find and prove P1/P2 impact on this surface"). After several under-directed lanes, read their handoffs together for A→B primitives (auth bypass + IDOR, reset poisoning + takeover, info leak + SSRF), and only then dispatch chain-directed follow-ups.
   - **Lane count = the smaller of surface breadth and runtime capacity.** A thin surface gets one lane, a broad app-like target 3-4; a dedicated Heavy/Comfortable runtime supports 4-6 concurrent specialists, a Standard tier about 2-3 ("Runtime sizing tiers" in `agent/references/runtime-guides/dispatch-resource-policy.md`).
   - **The "very little attack surface" exception.** Breadth across many surfaces at once is right only when the target genuinely has very little attack surface after a thorough pass: a handful of routes, no object references, no privileged features, no auth boundary, no useful source intel. Rotate to breadth only when the focused target is genuinely dry (`agent/rules/hunting.md` "Depth over breadth; rotate only when genuinely dry").
   - **Dead vs unfinished.** Before any phase exit, re-audit surfaces resolved `covered`/`deferred`/`not_applicable`: re-open the unfinished ones (closed on a timer, one quick pass, or one status-code check) and fan a lane at them; only varied probes across several classes make a surface dead. Step h cannot make this distinction.
   - **Cross-lane politeness = disjoint hosts.** Give lanes disjoint hosts wherever possible and keep at most one active target-facing tool per host across all lanes: concurrent in-container probes against one host thrash the resolver and produce false negatives. Combine it with the per-target rate calibration and named-identity disjointness (`agent/references/runtime-guides/auth-recovery.md` "Named identities and cross-identity depth"). This is a cue, not a CLI gate.
   - **Bookend the fan-out** with the operator core's "Mandatory Phase-Exit Passes": the variant/sibling pass per confirmed finding, and chain construction across targets once each target's fan-out completes.

   ### Lens Vocabulary — Finer-Grained Failure-Family Lenses

   **One mindset lens per dispatch, cycled across batches.** A lens names a family of developer assumptions that fail together, never a menu and never a bug: naming the bug caps depth at your guess, naming the lens lets the specialist generalize across every surface the family touches. The dispatch's `mindset lens` is the packet path under `agent/rules/mindsets/` plus the one-line reason it fits the observed signal (e.g. `idor-bac.md — numeric object references with two named identities available`). It fills the role's own `## Dispatch Mindset` slot, which governs where it competes with the role's baseline mindset.

   A finer-grained lens is a parenthetical qualifier on its backing packet path, e.g.
   `mindset lens: agent/rules/mindsets/developer.md (Caching) — stale invalidation on the CDN edge cache key`
   (`business-logic.md` is the closer parent for the state-machine rows: Race conditions, Mass assignment).

   | Lens | What fails together |
   |---|---|
   | Caching | stale invalidation, shared-key leakage, cache-key injection |
   | Data handling / over-trust | caller-supplied values accepted without re-validation, over-broad deserialization |
   | Race conditions | TOCTOU, non-atomic credit/inventory, session-merge |
   | Mass assignment | unfiltered bind, hidden field promotion |
   | Upload / file handling | extension bypass, path traversal on store, content-type trust |
   | Client-side trust | server echoes client-controlled values, DOM sink injection |

   **Lens rotation:** re-run a winning lens on new surfaces, since the same developer pattern recurs; dispatch a fresh lens on an already-worked surface, since a surface clean under caching assumptions may still fail under race or upload assumptions.

   ### Mid-Phase Cadence

   - **Run `check-phase-readiness` every few batches**, not only at the end: it is an advisory, EV-ranked view of under-covered surfaces and thin depth that steers the next batch while gaps are still cheap to fill.
   - **A readiness command that times out is a tooling failure, not a verdict.** Retry once with narrower flags (one `--phase`, one host or app unit), record an operator checkpoint, and surface the failure. Do not loop on it, and do not `--force` past a gate you could not read.
   - **Read `vigil assess coverage` between batches** (the per-host ledger, a projection, not a gate). A host is covered only by a recorded verdict (a finding or an evidence-backed negative), never by a completed dispatch; `uncovered` real-app hosts still need a lane, and `needs_browser_reprobe` hosts need a browser pass because curl undercounts routes behind a WAF.

   ### Steps

   a. **Template coverage audit** (once, before the work-buffer loop) — dispatch `recon-specialist` with `agent/skills/nuclei-scanning/SKILL.md` "Coverage Audit Mode". It runs templates only against the hosts and template sets the Phase 1-2 reactive sweeps missed, under that skill's substrate-sweep scoping (severity, directory-scoped templates, a bounded origin subset at host scale, OOB ready first). Decide the timing: run it to completion before VA lanes touch those hosts, or fold each host subset into the VA lane that owns it, never concurrently with a lane on the same host. The dispatch carries the ENGAGEMENT.md rate cap through `--rate-budget`; the skill's `-rate-limit 150 -c 25` is a ceiling, never a reason to exceed that cap. Critical/high hits become work-buffer priority entries or findings after manual validation; medium hits become intel; gf buckets are leads, never findings.
   b. Reset stale work items: `vigil assess work-buffer reset-stale 10`
   c. Check stats: `vigil assess work-buffer stats`
   d. Fetch and route by pending volume:
      - **Pending < 2000 → type-based dispatch**, independent types in parallel: `api`, `api-spec`, `form`, `upload`, `graphql`, `websocket`, `auth_entry`, `workflow`, `api_route`, `event_feed`, `debug_config`, `portal_session` → vulnerability-analyst (matching vuln-class skill via `vigil assess list-skills`); `page`, `javascript`, `stylesheet`, `data` → source-analyzer (`source-analysis` skill, `agent start --assessment-mode web`). Fetch with `vigil assess work-buffer fetch <type> 10 <agent-name>`.
      - **Pending ≥ 2000 → priority-first dispatch**, since type-based fetch orders by id: `vigil assess work-buffer fetch-by-priority 10 auto` claims the highest-signal routable rows and stamps each with its owner; `fetch-by-priority 10 vulnerability-analyst` (or `source-analyzer`, or an `-N` instance label) claims only that route. Between batches, `vigil assess work-buffer clusters` shows which clusters to `defer-cluster` (bucket weights: `agent/scripts/assess/lib/classify_buckets.py`; what `cluster_key`/`priority_score`/`priority_reason`/`terminal_reason` mean: `agent/skills/case-dispatching/SKILL.md` "Priority-mode scoring reference").
      Pass the raw fetched JSON rows into the dispatch context: their `request_variant_id`, `service_id` and `coverage_item_id` are what specialists need for durable probe and coverage writes. Blind-testing lanes start, mint and poll their own OOB listener (`vigil oob status --json` first); if `$DIR/.listener_url` exists, include the tunnel address for agents that need a callback target.
   e. On return: `vigil assess work-buffer done 101 102 103`, only after the subagent wrote durable state for its findings, significant probe runs and coverage. Every pending coverage item the surface accrued must leave `pending`/`queued`/`deferred` — one per implied vuln class, not just the cluster winner's (a `gf:ssrf` surface whose params also imply `sqli` carries both). `check-phase-readiness --phase consume`/`verify` reports the residual as `signal_classes_uncovered` (a sibling class covering the family does not satisfy a distinct class); the resume-brief's Per-Input Coverage grid shows which input was probed for which class as which identity. On a decisive-surface or high-confidence `deep_required` unit an unresolved BLOCK_HIGH class holds the unit at the report/complete edge (`agent/rules/hunting-operator.md` "A URL can be a whole application"; deep-test it or record a `depth_deferral`), so drain it now. If the agent skipped durable recording, send it back rather than duplicating the state yourself. Record surfaces with `vigil assess record-surface`; re-ingest new endpoints with `vigil assess ingest endpoints <source>`.
   f. When vulnerability-analyst signals FUZZER_NEEDED for a parameter or directory, dispatch fuzzer with `agent/skills/parameter-fuzzing/SKILL.md` or `agent/skills/directory-fuzzing/SKILL.md` and a bounded objective (target URL, parameter name, max payloads).
   g. Repeat b-f until pending=0 for all consumable types. A drained queue ends the breadth pass, not the phase: give every `deep_required` app unit and every lane that returned signal a `hunt_scope: deep` lane (`check-phase-readiness --by-app-unit` names the units).
   h. Before leaving: `vigil assess check-phase-readiness --phase consume`. It relays the surface-level coverage gate, the scope-entry consumption gate, the depth ledger and the intel advisory. Resolve each remaining surface as `covered`, `deferred` or `not_applicable`; high-risk surfaces (`account_recovery`, `dynamic_render`, `object_reference`, `privileged_write`) resolve only as `covered` or `not_applicable`, because a deferred high-risk surface disappears from the report. Before the hunt winds down, re-run collection (a fresh `vigil assess recon` / `surface-collector` pass over the apexes): handler paths that surfaced after the first crawl are otherwise never tested.
   i. **System-level synthesis (cross-surface).** Some findings exist only between surfaces: an auth boundary one host enforces and a sibling does not, or a capability chain across findings (info disclosure + open redirect, SSRF + token leak, IDOR + impersonation). Build seams as in code Phase 2D — **structural** (findings/surfaces sharing an auth context, host or trust boundary) and **capability** (pair findings by primitive, bucketed by capability so it stays O(capabilities²)) — and scale the dispatch to the seam count: one `vulnerability-analyst` in `hypothesis-driven` mode for small scope, or a `vigil assess agent start-swarm` fan-out (one worker per 1-3 seams) for large multi-host scope, then a reduce pass for multi-hop chains.
