---
name: nuclei-scanning
description: Template-based vulnerability scanning with nuclei for CVEs, misconfigs, and exposures
origin: Vigil
---

# Nuclei Scanning

## When to Activate

- New live URLs landed in Phase 1-2 (reactive sweep), the Phase 4a coverage audit, or a scoped
  Phase-4 substrate sweep.
- Known CVEs may match discovered software versions.

Audit flags: `--technique CVE-VALIDATION` for CVE runs, `DISCOVERY` for tech/fingerprint templates,
`INFO-DISCLOSURE` for exposure templates, `OTHER` for mixed sweeps.

**Appendices.** `agent/references/recon/nuclei-sweep-recipes.md` — load when you build a
reactive delta, run the 4a gap audit, or loop a substrate sweep (the shell recipes).
`agent/references/tools/recon/nuclei.md` — flags, WAF-resilience options, "OOB Callbacks",
template management. `vigil assess list-references --skill nuclei-scanning` lists both.

## Reactive Sweep Mode

Reactive sweeps run in-phase on each URL delta so template hits become intel and finding
candidates **before** Phase 4 specialists dispatch; specialists then inherit the signal instead of
rediscovering it. Trigger one whenever live URLs land: the recon job reports new hosts in
`vigil assess recon-status`; recon-specialist, source-analyzer or surface-collector returns or
ingests URLs; subdomain enumeration or wildcard expansion adds live hosts.

**The delta** is live URLs not yet in a prior reactive run's input list, filtered through
`vigil assess scope filter -`. That filter is the scope boundary: it matches wildcards correctly
and drops hosts pulled in from passive sources, which would otherwise break the authorization
envelope even if the finding were accurate.

**Standard invocation** (reactive and gap audit use the same template set and severity, so
coverage is comparable):

```bash
vigil assess kali nuclei \
  -l /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.txt \
  -t http/cves/,http/misconfiguration/,http/exposures/,http/default-logins/,http/technologies/,http/exposed-panels/ \
  -severity medium,high,critical -as -stream -jsonl \
  -rate-limit 150 -c 25 -bs 25 --extra-args="-stats -si 30" \
  -o /engagements/$ENGAGEMENT_KEY/scans/nuclei_reactive_$RID.jsonl \
  --technique CVE-VALIDATION --intent "reactive nuclei sweep on URL delta" \
  --probe-kind fingerprint --phase recon --timeout 600
```

- Leave `http/fuzzing/` and payload-heavy directories to Phase 4 targeted work: higher FP rate,
  WAF-tripping volume, and their hits need specialist context to triage.
- 150 rps is a ceiling; lower `-rate-limit` and `-c` to the dispatch's `--rate-budget` or the
  WAF-tier row when tighter.
- The wrapper injects `-exclude-tags dos,fuzz,intrusive,brute-force` unless you pass your own
  `-exclude-tags`/`-etags`, which replaces it verbatim.
- Run each sweep as a blocking `vigil assess kali nuclei … --timeout N` call with N at or under
  600; size the URL list to fit ("Bound the host dimension" below), and a sweep that still cannot fit is an
  operator `kali job` you name in `next_steps`. `agent/shared-constraints.md` §2 owns the
  synchronous-execution and process-cleanup rules.

**Output lock.** The wrapper locks on the `-o` path: runs with distinct `-o` files run in
parallel; two runs on the same file serialize (the second blocks). A dead holder's lock recovers
on the next run; remove `$ENGAGEMENT_DIR/scans/.<output>.lock` by hand only when the PID is dead.

**Zero results.** Empty output with stderr lacking `Templates loaded for current scan: N` is a
loader failure (the wrapper WARNs; not a clean negative). With that line present it is a real
no-match, except in the **known fingerprint-suppression cases** where `-as` (wappalyzer-driven
selection) selects nothing: Salesforce
Experience Cloud / Lightning (generic edge chrome — use explicit
`-t http/technologies/salesforce*,http/cves/CVE-*-salesforce-*` or the vendor-platform-enum
payloads), Akamai-fronted hosts, Cloudflare with aggressive bot rules, and WAF-fronted enterprise
edges generally. Re-run those with explicit `-t` directories; `vigil assess command-run get <id>`
stderr is the source of truth for whether templates executed.

**Ingestion.** Hits are candidates, not findings; manual revalidation catches template false
positives (SSRF probes on patched endpoints, version-string collisions).

- Critical/high: re-run the template's PoC via `vigil assess kali exec` or the matching typed
  verb; record with `vigil assess finding record <your-role> <finding.json> --agent-id <your-agent_id>`
  only if the re-test reproduces.
- Medium: `vigil assess intel record note` with template id and URL; these usually seed Phase 4.
- Tech fingerprints: `vigil assess intel record tech-component`; CVE matches `intel record cve`.
- **`http/takeovers/` hits are a signature, not a verdict.** Claimability depends on the
  provider's re-binding controls (CloudFront cert gate, Azure reserved labels, owned parent zones,
  S3 region pinning / taken global names). Route every hit through
  `agent/skills/cloud-exposure/SKILL.md` (`agent/references/subdomain-takeover.md`) before
  recording; one engagement had 7 perfect-signature CloudFront candidates, none claimable.
- Record false positives you identify; they inform later template selection.

## Coverage Audit Mode (Phase 4a)

An audit, not a second broad sweep: compute in-scope live URLs minus every prior reactive/gap
input list. Empty gap → log the coverage summary (`vigil assess log recon-specialist …`) and
advance; the logged absence of a run is coverage evidence for the report. Non-empty → run the
standard invocation on the gap list only (`--phase consume-test`). Gaps usually come from late
ingestion, such as an endpoint a VA discovered mid-Phase-4. Triage as above.

## Phase-4 substrate sweep scoping

A full template set × every in-scope host is not politely completable and collides with VA lanes.
Scope every dimension:

- **Severity** `high,critical` (the reactive and gap passes keep medium because their scope is
  already small).
- **Directories, not tags.** One curated tag selection resolved to 1,515 templates × 155 hosts ≈
  561k requests. Use cheap discovery directories (the standard set plus `http/takeovers/`).
- **Bound the host dimension.** `-as` and dedup never cap host count. Above ~25-50 live hosts,
  sweep a subset of dedicated/origin/non-CDN hosts (asnmap→cero origin IPs; Cloud-fronted vs
  Origin rows in `agent/references/recon/rate-calibration.md`), sized as templates × hosts ≈
  requests. At host scale, OSINT version→CVE matching (`intel record cve` via osint-analyst) plus
  targeted VA validation often gives most of the CVE value for a fraction of the traffic.
- **One pass per directory**, each with its own `--timeout` and `-o`.
- **No collision with VA lanes**: either run the bounded sweep to completion before any VA lane
  touches those hosts, or hand the per-subset call to the VA lane that owns them. Never run a
  concurrent operator sweep across hosts a VA lane is testing.

## Prerequisites and lead quality

- Runtime images ship the binary, not templates: the first run in a fresh runtime pays the
  `nuclei -update-templates` download; run it as its own call first so the sweep fits the
  `--timeout` ceiling (`agent/shared-constraints.md` §2).
- Blind/OOB templates: confirm `vigil oob status --json` reports `health=ok` (it folds in the
  server, frpc, relay-route and domain checks), then pass `--oob-mode vigil` (`nuclei.md` "OOB Callbacks"). Without OOB,
  keep `--oob-mode none` and defer blind classes rather than recording a clean OOB template as a
  true negative.
- gf bucket tags are high-false-positive leads, never verdicts.
- Authenticated surfaces need an authenticated pass when credentials are in scope; an unauth sweep
  is not full coverage there.
