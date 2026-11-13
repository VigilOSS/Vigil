---
description: wafw00f WAF identification, run first per live host — the WAF-tier table mapping each result to its rate-calibration row, the batch CSV invocation, per-host (never averaged) tiers, and its untagged-traffic gap on required-header programs
skill: web-recon
---

# wafw00f

Run as `vigil assess kali wafw00f` (`--help` for the typed flags: positional target or `-i <file>`,
`-a`, `-p`, `-r`, `-o`). It is the first step of the web-recon order because the tier it finds picks
the rate for every later tool; picking a profile before it means tripping the WAF early, losing the
engagement to rate limits or losing port data to host-timeout retries. The recon-specialist's
pre-output self-check requires a recorded WAF tier for every live in-scope host.

```bash
vigil assess kali wafw00f -i /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -a \
  -o /engagements/$ENGAGEMENT_KEY/scans/wafw00f_results.csv \
  --technique RECON --intent "WAF tier sweep across in-scope live hosts" \
  --probe-kind fingerprint --phase recon --timeout 600
```

`-o` writes CSV only (wafw00f has no JSON output); parse the CSV or stdout. Rate each host from its
own row and never average across a batch: CDN-fronted and bare-origin hosts in one scope need
different profiles. Re-run wafw00f for each host that enters scope later (TLS SAN, subdomain
enumeration); it may sit behind a different tier than the apex.

A WAF measurement row cites the run that measured its hosts. The sweep records the hosts its list
file holds as its target (`vigil assess command-run get <id>` → `target_host`); a host it does not name
(a list over the target limit, a file outside the engagement) needs its own single-target run,
`vigil assess kali wafw00f https://<host> ...`, and the row for that host cites that run.

**Required headers.** wafw00f's own `-H` reads a headers file rather than an inline value, so the
wrapper cannot inject a program attribution header: it warns and the traffic goes untagged. On a
program that mandates one, carry the header another way before running it.

## WAF-tier rate adjustment table

The wafw00f result picks the row of `agent/references/recon/rate-calibration.md`, which holds the
rate for every later tool. A mismatch costs either coverage (host timeouts) or the rest of the
engagement (WAF lockout).

| wafw00f result | rate-calibration row |
|---|---|
| A WAF of any tier, including a generic rule set | WAF-protected |
| A CDN or edge platform with no WAF | Cloud-fronted |
| No WAF or CDN | Origin / single-server, or Vendor SaaS when httpx shows a vendor host pattern |
| Any result on a `.gov`, `.mil`, finance or healthcare target | High-friction policy / regulated |
| A dedicated lab the ROE clears for aggressive rates | Lab / CTF |

On a cautious-tier target the same row governs a triggered nikto run (`nikto.md`
"Pause and rate control").
