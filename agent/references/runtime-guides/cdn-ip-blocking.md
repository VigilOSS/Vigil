---
description: CDN/edge IP-reputation block detection with vigil assess egress-check (403 + reference codes, TCP reset, 000-status as candidate signals), the four mitigation options (program allowlist / residential proxy / browser-based tool / accept-gap), give-up-vs-escalate rule, and the vigil assess ingest endpoints --egress-blocked-hosts deferral
---

# CDN / Edge IP-Reputation Blocking — Detection and Mitigation

This guide covers the case where the runtime's own egress IP is on a CDN or WAF reputation list
(datacenter and shared-runtime IPs collect hits over time). Recon then collapses into hard 403s
and 000-status timeouts on every host, and each specialist wastes a dispatch rediscovering it. The
operator's Egress reputation checkpoint (`agent/phases/phase-1-recon.md`) catches it once. When a
single probe is denied but the host otherwise answers, read
`agent/references/runtime-guides/cdn-edge-behavior.md` instead.

## Detection

Run `vigil assess egress-check --hosts <hosts> --control example.com --emit-blocked-hosts <file>`.
It samples in-scope hosts and known-good controls and classifies each with the shared
reachability verdict. It retries a TLS-1.3 reset with `--tls-max 1.2`, keeps bounded headers and
body bytes so an edge block can't pass as reachable, and records each outcome as an advisory
`egress_decision`. A bare `connect=000` counts as blocked only when there was neither a TCP
connect nor a resolved IP. Only a control-live, mostly transport-blackholed sample yields
`cluster_blackholed` and the blocked-hosts file. The Overview egress banner and `/summary`
`egress_status` read only the latest `egress-check` result.

These are the candidate shapes behind a block. Each is a lead, not a verdict, until the retained
response evidence and an independent control or route agree:

1. **Hard 403 with a CDN reference code** on a path that should be 200/3xx (`/`, `/robots.txt`, a
   public asset). A header carries a support-correlation id (`x-reference-id`,
   `x-akamai-edgescape`, `x-amzn-cf-id`, `x-edge-request-id`, …), and the 403 is the same across
   paths. A per-path authorization 403 would vary by path.
2. **TCP reset or refusal on connect** (geo or ASN policy): curl exits 7 or reports `000` almost
   at once on every host behind the same edge.
3. **Consistent `000` on a host other tools show is up**, which also covers TLS handshake aborts
   and possible JA3/JA4 fingerprint blocks. `000` alone means only that no HTTP answer was seen.

If the verdict is blackholed, re-sample after five minutes, because a transient rate-limit
window often clears. Surface the four options below only when the second sample agrees. Pass the
emitted file to later ingestion so URLs to those hosts defer with
`cluster_key=deferred:egress-blocked` instead of filling the work buffer:

```bash
vigil assess ingest endpoints --egress-blocked-hosts "$DIR/scans/egress_blocked_hosts.txt" \
  katana < "$DIR/scans/katana.txt"
```

Record the operator's choice with its evidence-backed percentage:
`vigil assess agent decision --kind egress_decision --choice <option> --payload-json
'{"blocked_pct": N, ...}' --note "<rationale>"`.

## Mitigation options

1. **Program allowlist** (`allowlist-requested`). Try this first for any authorized program. It is
   the only option with a clean signal: no proxy artifact and no fingerprint drift. Capture the
   egress IP with `vigil assess kali exec --technique HEALTH --intent "capture runtime egress IP"
   --probe-kind fingerprint --phase recon --timeout 30 -- curl -s https://api.ipify.org`, send it
   to the program contact with the scope, wait for confirmation, and record `{"egress_ip",
   "program_contact"}` on the decision. Audit rows look the same either way, so the decision row
   and the activity log carry the outcome.
2. **Residential proxy or clean-IP VPS** (`residential-proxy`). Use this when the program can't
   allowlist, or when the engagement explicitly authorizes a clean egress. Set `HTTPS_PROXY` /
   `HTTP_PROXY` for the runtime, confirm the egress IP changed, and record `{"provider",
   "egress_range"}`. Exploitation through a proxy needs explicit operator and program approval,
   because the proxy's logs sit outside the audit pipeline. Keep concurrency and rate capped on the
   runtime side to stay under residential-IP abuse thresholds.
3. **Browser-based tool in the runtime** (`browser-based-tool`). Use this when the evidence is
   JA3/JA4 or TLS-fingerprint shaped (reset mid-handshake, 403 only for curl-class fingerprints). A
   real browser fingerprint gets past the block without changing the IP. For crawling, use
   `vigil assess kali katana -headless …`. Headless Chromium is itself fingerprinted by
   Akamai/Cloudflare bot-manager tiers, so a defended login needs a headed stealth browser
   (`agent/skills/browser-automation/SKILL.md`). Raw-socket tools such as nmap can't go through a
   browser, so for those use option 1 or 2. In the audit history, the TLS fingerprint of record is
   the browser's, not curl's.
4. **Accept and document the gap** (`accept-gap`). Use this when 1–3 fail. Record the decision with
   `--surfaced-to-user`, write the gap as a `vigil assess intel record note` so the report-writer
   puts it in Methodology/Coverage, and mark the affected scope entries `status=deferred` in
   `scope.json` so the coverage gate treats them as terminal. Every 403 stays recorded as a 403.

## When to give up vs when to escalate

Try allowlisting first. Then pick by symptom: a fingerprint-shaped block goes to the browser path
(cheap), and an IP-reputation-shaped block (403 on every fingerprint, vendor reference code) goes
to a different egress. Accept the gap when the timeline allows nothing more. Once one mitigation
attempt produces no signal, stop rather than stacking proxy hops: a documented coverage gap is
worth more in the report than a noisy, unaudited bypass.
