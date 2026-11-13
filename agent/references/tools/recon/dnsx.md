---
description: dnsx bulk resolution — NXDOMAIN/CPU-spike trap (lean bulk pass, then enrich survivors), tight-RAM GOMAXPROCS=1 nice -n 10 form, GeoDNS multi-region resolver pass, DNSSEC/AXFR probe-once-and-skip
skill: subdomain-enumeration
---

# dnsx

Run as `vigil assess kali dnsx`. The wrapper's Docker-safe defaults, profile gating and the
`--allow-bulk-json` rule are in `vigil assess contract kali dnsx`; `vigil assess kali dnsx --help`
prints what each `--dnsx-profile` sets and which flags are guarded (they must be typed, never
passed through `--extra-args`). Keep the `public-tcp` resolver profile unless there is a reason to
use UDP: UDP-heavy dnsx runs have crashed Docker Desktop laptop runtimes.

## NXDOMAIN / CPU-spike trap

`-resp -json` emits a JSON record for every NXDOMAIN, not only for names that resolve. On a
110k-entry candidate list with the usual 95-99% miss rate that is 100k+ serialisations per pass,
enough to saturate container CPU and force several pacing reductions. Resolve the bulk list lean
(no `-resp`/`-json`, as in the manual stages' "Phase 3"), then enrich only the survivors:

```bash
vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt \
  -resp -json --allow-bulk-json -a -cname -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/dnsx_enriched.jsonl \
  --technique RECON --intent "enrich resolved survivors with A+CNAME JSON" \
  --probe-kind fingerprint --phase recon --timeout 600
```

The wrapper cannot count a container-path list host-side, so the enrichment pass needs
`--allow-bulk-json` even on a short survivor list.

On a tight-RAM runtime (`VIGIL_RUNTIME_MEMORY_GB=2`), bound goroutine CPU with
`env GOMAXPROCS=1 nice -n 10 dnsx ... -rl 100 -t 20 -retry 3 -timeout 5` under
`vigil assess kali exec`. That raw form skips the typed wrapper's rate guard, so keep it at the
polite-cdn values.

## GeoDNS multi-region resolver pass

A GeoDNS/GSLB target answers by resolver vantage, so one vantage under-reports the surface.
Re-resolve the apex and a sample of hosts against resolvers in 2-3 geographies, diff the answer
sets, record each region's A/CNAME set as separate surface, and feed the geo-specific IPs to the
Phase 3 cert grab. This complements `openssl-sans.md` §4, which varies time from one vantage and
catches rotation but not geo-varying records.

- **dnsx:** dnsx has no EDNS Client-Subnet flag, so run the typed verb once per region-pinned
  resolver file (`-r /engagements/$ENGAGEMENT_KEY/wordlists/resolvers_eu.txt -a -cname -resp`)
  and diff the outputs.
- **dig ECS:** `dig +subnet=<client-cidr> A <apex> @1.1.1.1` spoofs the client region through one
  resolver. Reach for it when region-pinned resolvers are unavailable; it adds no destination IPs.

Keep the distinct resolver-IP count small so the pass stays under the Docker Desktop
per-destination-IP ceiling (`agent/references/runtime-guides/docker-desktop-network-hazards.md`).

## DNSSEC / AXFR — probe once, then skip

Both answers are almost always "no". Probe each zone once, record the verdict as an explicit skip
in the recon facts, and never retry.

- **DNSSEC:** get the NS with `-ns -resp`, then one `dig +dnssec DNSKEY <apex> @<ns>` (dnsx has no
  DNSSEC flag). Zone-walking applies only when RRSIG/NSEC are present and the zone is NSEC, not
  NSEC3 (hashed); a walk enumerates the whole zone, so it is an explicit operator opt-in.
  Otherwise log `DNSSEC absent / NSEC3 — skip walk`.
- **AXFR:** one attempt per NS (`dnsx -axfr` through `--extra-args`, or `dig AXFR @<ns> <apex>`).
  A refusal or timeout is terminal: log `AXFR refused — skip`. A successful transfer is rare and
  high-value; dump the zone.
