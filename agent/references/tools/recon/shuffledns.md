---
description: shuffledns fallback brute (no typed verb) — when to use it instead of puredns, the required -mode and -massdns flags, no qps flag (only -t concurrency), and recording the load choice in --intent
skill: subdomain-enumeration
---

# shuffledns

A leaner massdns wrapper than puredns, with weaker wildcard handling: its single-pass check
misreads CDN-issued wildcards as live hosts that puredns's multi-pass test catches. Default to
puredns; reach for shuffledns when

- puredns fails at startup (check with
  `vigil assess kali exec --technique HEALTH --intent "puredns startup preflight" --probe-kind fingerprint --phase recon --timeout 30 -- puredns -h`);
- the wordlist is small (<5k entries) and puredns's wildcard-batch pre-pass is overkill; or
- the container is tight on RAM (`VIGIL_RUNTIME_MEMORY_GB=2`) and puredns's dedup map is the limit.

There is no typed verb, so it runs under `vigil assess kali exec` and the dnsx/puredns rate
guards do not apply. shuffledns has no qps flag: its one load knob is `-t` (concurrent massdns
lookups, default 10000), so set it deliberately and write the choice and the
`agent/references/recon/rate-calibration.md` row it stands in for into `--intent`; the audit row
keeps the intent verbatim for coverage review. `-mode bruteforce` (or `resolve`) is required, and
`-massdns /usr/bin/massdns` names the binary.

```bash
vigil assess kali exec --technique RECON \
  --intent "shuffledns fallback brute, small wordlist, -t <n> for the polite-CDN-fronted-target row" \
  --probe-kind fingerprint --phase recon --timeout 600 -- \
  shuffledns -mode bruteforce -d target.example \
  -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt \
  -r /engagements/$ENGAGEMENT_KEY/wordlists/premium-anycast.txt \
  -t <concurrency> -massdns /usr/bin/massdns \
  -o /engagements/$ENGAGEMENT_KEY/scans/shuffledns_brute.txt
```

The resolver path is the staged copy described in `puredns.md` ("Resolver paths").
