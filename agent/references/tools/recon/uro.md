---
description: Structural URL dedup stage inside the gau pipelines — collapses near-duplicate URLs (same path, different param VALUES; cache-busted asset variants) to one representative. Wired as a shared helper, not a standalone verb
skill: gau-triage
---

# uro (structural URL dedup)

uro collapses URLs that differ only in values (`?id=1`/`?id=2`, `app.js?v=1`/`app.js?v=2`,
incremental path segments, fingerprinted asset names) to one representative per structure;
`sort -u` removes only byte-identical lines. It is not a `vigil assess kali` verb: the three gau
pipelines dedupe through one shared helper, `assess.lib.gau_pipeline.run_uro_dedup`, which runs
`uro -i <in> -o <out>` in the runtime through `kali_exec` (audited as `tool_bin=uro`; argv builder
`build_uro_command`). Use the pipelines rather than a hand-rolled `kali exec` uro call.

| Pipeline | Where uro runs | On uro failure |
|---|---|---|
| `gau secrets` | between the inert-extension filter and the httpx body-fetch | the run aborts (the body-fetch needs the trimmed list) |
| `gau endpoints` | between the gau corpus and `ingest endpoints` | WARN, fall back to the raw corpus (the classifier dedupes by template downstream) |
| `gau js-endpoints` | on the `.js` target list before the JS-only body-fetch | WARN, fall back |

uro runs before gf, never over a gf bucket: `gf.md` "gf before uro — ordering rule".
