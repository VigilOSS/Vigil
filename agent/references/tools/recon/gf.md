---
description: gf URL parameter-pattern classifier — the bucket source-of-truth is the inline `assess.lib.classify_buckets` classifier applied at ingest; `vigil assess kali gf` for ad-hoc triage of an un-ingested corpus, the installed pattern library, the gf-before-uro ordering rule
skill: gau-triage
---

# gf (grep-friendly)

The gf bucket patterns are compiled into `assess.lib.classify_buckets._BUCKETS` and applied
inline at ingest. That classifier is the source of truth and runs on every ingested URL, so
anything entering the work buffer is already bucketed. `vigil assess kali gf` complements it for a
corpus on disk you have not ingested (a raw gau/wayback dump) or to cross-check one bucket against
the upstream library; usage and its maintenance-verb status (no audit flags, no target traffic):
`vigil assess contract kali gf`.

**Installed library.** The runtime stages the 1ndianl33t/Gf-Patterns set in `/root/.gf/` (pins in
`agent/docker/runtime-full/Dockerfile`, licences in `THIRD_PARTY_NOTICES.md`); `$GF_DIR` overrides
the location. `vigil assess kali gf --list` prints the authoritative set. Signal per bucket:
`ssrf`, `redirect`, `idor`, `lfi`, `rce`, `debug_logic` and `takeovers` (with DNS) are high;
`xss` (noisy on search endpoints), `sqli`, `interestingparams`, `interestingEXT` and
`img-traversal` medium; `interestingsubs` low. A pattern that returns zero hits on a large corpus
and is missing from `--list` means `/root/.gf/` was not seeded. A new pattern file is read on the
next invocation.

Hits are leads for downstream validation, never verdicts. sqlmap's bulk-file mode has no typed
flag, so it rides in `--extra-args`; `--sql-technique` is sqlmap's own `--technique`, and a long
list is split so each call fits the 600-second ceiling:

```bash
vigil assess kali sqlmap \
  --extra-args="-m /engagements/$ENGAGEMENT_KEY/scans/gf_sqli.txt" \
  --sql-technique BEU --batch \
  --technique SQLI --intent "gf-classified SQLi candidate sweep" \
  --probe-kind payload --phase consume-test --timeout 600
```

## gf before uro — ordering rule

Filter static assets first, then `uro` for structural dedup, then `gf` to classify; that keeps one
representative per attack class. Do not run `uro` over a gf bucket: a bucket can hold only variants
of one parameterized URL, and uro would flatten the different `id=` values that matter for IDOR
into one entry.
