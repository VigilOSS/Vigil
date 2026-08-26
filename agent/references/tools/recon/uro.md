---
description: Structural URL dedup stage inside the gau pipelines — collapses near-duplicate URLs (same path, different param VALUES; cache-busted asset variants) to one representative. Wired as a shared helper, not a standalone verb
skill: gau-triage
---

# uro (structural URL dedup)

**Purpose:** Collapse a large URL corpus to its structurally-distinct members. uro removes near-duplicates that differ only in *values* — `?id=1`/`?id=2`/`?id=3`, cache-busted bundles (`app.js?v=1` vs `app.js?v=2`), incremental path segments, fingerprinted asset names — keeping one representative per structure. That shrinks the set the downstream body-fetch / ingest works on without dropping a distinct surface.

**Where it lives:** `/usr/local/bin/uro` in `runtime-full` (`pip install uro` — see `agent/docker/runtime-full/Dockerfile`).

## How it is wired (not a standalone verb)

uro is **not** a `vigil assess kali` verb — it is a non-target dedup stage wired into the gau pipelines as a single shared helper, `assess.lib.gau_pipeline.run_uro_dedup` (the single source for the gau pipeline). All three gau pipelines dedupe identically through it:

| Pipeline | Where uro runs |
|---|---|
| `gau secrets` | between the inert-extension filter and the httpx body-fetch (the body-fetch needs the trimmed list — a uro failure aborts the run). |
| `gau endpoints` | between the gau corpus and `ingest endpoints` (WARN + fall back to the raw corpus on a uro failure — the classifier dedupes by template again downstream). |
| `gau js-endpoints` | on the `.js` target list before the JS-only body-fetch (collapses cache-busted bundle variants; WARN + fall back on failure). |

`run_uro_dedup` runs `uro -i <in> -o <out>` inside the runtime container via `kali_exec` (so the stage is audited as `tool_bin=uro`) and returns the deduped line count. The pure argv builder is `build_uro_command`.

## Ordering rule — uro BEFORE gf, never after

When combining with `gf` (parameter-pattern classification): **filter static assets → `uro` (structural dedup) → `gf` (classify)**. Do NOT `uro` the output of a `gf` bucket — a bucket can be all variants of one parameterized URL (different `id=` values), and uro would flatten them to a single entry, losing the per-value coverage signal that matters for IDOR. See `agent/references/tools/recon/gf.md` ("gf before uro — ordering rule").

## Why structural, not lexical

A plain `sort -u` (which the gau pipelines also do) removes only byte-identical duplicates; it keeps `?id=1` and `?id=2` as two URLs. uro is structural — it understands that those are one route with a varying value — so it is the dedup that actually shrinks a historical-URL corpus to its testable surface. Run it as the stage above; do not hand-roll a uro invocation through `kali exec`.
