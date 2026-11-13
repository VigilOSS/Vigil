---
description: bbot passive mop-up (Phase 0) — full subdomain-enum preset is an operator kali job, a focused module set fits one call; v2.6.0 output is unreliable, so harvest DNS_NAME events from output.json and DNS-validate them
skill: subdomain-enumeration
---

# bbot

Multi-module passive recon, run as `vigil assess kali bbot` (gating, the 600 s ceiling and the
focused synchronous example: `vigil assess contract kali bbot`). It is a mop-up that adds the
occasional name the keyed-passive + CT + brute pipeline missed; it never replaces that pipeline,
and `vigil assess dns-discovery --bbot` runs it as a validated axis.

**Full preset is an operator job.** `-p subdomain-enum -rf passive` runs 15-30 minutes. A
specialist runs a few modules (`-m crt -m certspotter -m hackertarget -rf passive`) and names the
full sweep in `next_steps`; the operator runs it as a job
(`agent/references/runtime-guides/kali-cli.md` "Long-running probes"):

```bash
vigil assess kali job start --technique OSINT \
  --intent "Phase 0 deep passive enum (bbot subdomain-enum preset)" \
  --probe-kind fingerprint --phase recon --timeout 2400 \
  -- bbot -t target.example -p subdomain-enum -rf passive -om json \
     -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs
```

## Output reliability — harvest JSON, never the final txt

bbot v2.6.0's `dnsresolve` module crash-loops mid-run and truncates the final `*.txt` outputs to
about 250 B, and the `excavate` module emits mangled, false hostnames. The typed verb injects
`-om json` (unless `--extra-args` carries an `-om`) and writes `output.json` into the output dir,
which defaults to `/engagements/$ENGAGEMENT_KEY/scans/bbot_<ts>` when no `-o` is given.

1. Take only `DNS_NAME` events:
   `jq -r 'select(.type=="DNS_NAME") | .data' <outdir>/output.json | sort -u`.
2. DNS-validate every name through the host resolver path (host-exec or the dnsx host route,
   not the container resolver) and keep only names that resolve, before merging them into the
   candidate set.
