# CDN / Edge IP-Reputation Blocking — Detection and Mitigation

When the runtime container's egress IP is on a CDN edge's reputation list,
target-facing recon collapses into uninformative 403s and 000-status timeouts.
This guide documents the detection signals, the egress reputation curl script,
the four mitigation options exposed at the operator's Egress reputation
checkpoint, and the give-up-vs-escalate decision.

## Why this matters

Datacenter, cloud-VPS, and shared-runtime IPs accumulate reputation hits over
time — open proxies, scraping farms, and prior abuse all leave fingerprints
that CDN edges (and several enterprise WAFs) recognize. Once the runtime IP
sits on the reputation list, the edge serves a hard 403 (often with a vendor
reference code header) or drops the TCP connection on geoblock-style policies.
Specialists hitting that wall produce no signal and burn a full context
window per dispatch. The Egress reputation checkpoint catches the failure
once and routes the operator to a fix instead of letting every Phase 3
specialist rediscover it.

## Detection signals

The egress block presents in three shapes; any single shape across the
representative live-host set is enough to dispatch the checkpoint.

### 1. Hard 403 with a CDN reference code

The edge serves an HTTP 403 with a vendor reference identifier in a response
header — typically a UUID or hex blob — meant for support-side correlation.
The body may carry a generic "Access Denied" page. Pattern:

- Response is 403 against an endpoint that should plausibly return 200/3xx
  (the apex `/`, a public asset, a `/robots.txt`).
- A response header carries a reference code. Major CDN edges use
  `x-reference-id`, `x-akamai-edgescape`, `x-amzn-cf-id`, `x-edge-request-id`,
  or vendor-specific equivalents — different vendors, same shape.
- The 403 is consistent across the representative set (not a per-endpoint
  authorization 403, which would vary by path).

### 2. TCP reset / connection refused on connect

The edge implements geoblocking or a connection-time policy (commonly a
country-of-origin or ASN block). The TCP handshake does not complete; curl
returns exit code 7 (CURLE_COULDNT_CONNECT) or status 000 with a connection
error. Pattern:

- `curl -m 10` returns immediately (well under the timeout).
- The HTTP code captured is `000` because no HTTP exchange happened.
- The pattern is consistent on every representative host the egress IP
  reaches the same edge through.

### 3. Consistent 000-status from curl on a known-up host

A host other tools confirm is up returns `000` from curl with no HTTP body.
This usually overlaps with shape #2 but also covers TLS handshake aborts
(JA3/JA4 fingerprint blocks where the edge resets the connection mid-TLS).

## Egress reputation script

Run this against the live-host list before Phase 3 dispatch. It samples up
to 10 representative hosts, counts 403/000 responses, and emits the block
percentage. Default-conservative: do not increase the sample size or remove
the 10s per-host timeout. The script is intentionally lightweight to avoid
adding load on hosts that are already 403'ing.

```bash
REPRS=$(head -10 "$DIR/scans/live_hosts.txt")
blocked=0; total=0
for h in $REPRS; do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -m 10 "https://$h/" || echo 000)
  [ "$code" = "403" ] || [ "$code" = "000" ] && blocked=$((blocked+1))
  total=$((total+1))
done
pct=$((blocked * 100 / total))
echo "egress_block_pct=$pct"
[ "$pct" -gt 50 ] && echo "WARN: egress reputation blocked on >50% of sampled hosts"
```

When the script reports `egress_block_pct > 50`, the operator surfaces the
numbered checkpoint with the four mitigation options below. Record the
chosen option in `$DIR/agent-registry.json` with
`{kind: "egress_decision", blocked_pct: N, choice: "..."}`.

If a subset of hosts in the representative set returned 100% 403, write
those host strings to `$DIR/scans/egress_blocked_hosts.txt` and pass the
file to subsequent ingestion runs:

```bash
aith assess ingest-endpoints \
  --egress-blocked-hosts "$DIR/scans/egress_blocked_hosts.txt" \
  "$DB" katana < "$DIR/scans/katana.txt"
```

URLs to those hosts defer with `cluster_key=deferred:egress-blocked` instead
of polluting the work buffer; specialists do not rediscover the block per-URL.

## Mitigation options

The four options the checkpoint exposes — each with when-to-choose, setup
shape, and audit-pipeline considerations.

### 1. Request IP allowlisting from the target program

**When to choose.** First-line option for any authorized VDP / bug-bounty
program. The program owner can add the runtime egress IP to the WAF
allowlist, which is the standard answer for legitimate testing and the only
option that produces a clean signal (no JA3 mismatch, no proxy artifact, no
TLS fingerprint drift).

**How to set up.** Capture the runtime egress IP via
`aith assess kali exec -- curl -s https://api.ipify.org`. Email or message
the program contact with the IP and the engagement scope. Wait for
confirmation before retesting. Record the request in
`agent-registry.json` so a later operator can reproduce it.

**Audit-pipeline considerations.** The audit row reflects the runtime egress
IP only — the audit pipeline does not see the program's allowlist, so the
audit story is the same whether the allowlist is in place or not. The
operator records the allowlisting outcome in `agent-registry.json` and the
activity log; downstream specialists see clean responses again and treat
them as the truth.

### 2. Route through a residential proxy or clean-IP VPS

**When to choose.** When the program owner cannot allowlist the IP (large
program, slow turnaround) or when the engagement explicitly authorizes
testing through a clean-reputation egress. Residential proxies present a
consumer-grade IP that most CDN reputation lists treat as benign; a
clean-IP VPS works when the target's reputation feed is conservative.

**How to set up.** Configure the proxy in `aith assess kali exec` via the
runtime's standard `HTTPS_PROXY` / `HTTP_PROXY` env vars. Verify the egress
IP shifted before re-running the egress reputation script. Document the
proxy provider, the egress IP range, and the engagement-side authorization
in `agent-registry.json`. Do not route exploitation traffic through a
proxy without explicit operator and program approval — proxy logs are
out-of-pipeline and complicate the audit trail.

**Audit-pipeline considerations.** The audit row records `aith assess kali`
invocations regardless of proxy state, but the proxy provider's logs are
outside the audit pipeline. Treat the proxy as a privileged egress; record
the proxy config and the egress-IP-of-record in `agent-registry.json`.
Rate-limit through the proxy is the proxy provider's concern; cap concurrency
and request rate on the runtime side anyway to stay under the residential-IP
abuse threshold.

### 3. Use a browser-based tool inside the runtime

**When to choose.** When the edge implements a JA3/JA4 TLS fingerprint
block (the runtime's curl/httpx fingerprint is on a vendor blacklist of
known scanners). A browser inside the runtime (Playwright, headless
Chromium, real Firefox) presents a legitimate browser TLS fingerprint and
defeats the JA3 block without changing the egress IP.

**How to set up.** The runtime image carries Playwright and a headless
Chromium binary. Drive it via `aith assess kali exec -- python3 -m
playwright_runner` (or the Katana wrapper, which forwards traffic through
a Chromium TLS stack). Verify by re-running the egress reputation script
through the Katana / browser path.

**Audit-pipeline considerations.** Browser-driven traffic still flows
through `aith assess kali` so the audit row records the invocation. The
TLS fingerprint of record is the browser's, not the runtime's curl —
specialists reading the audit history should not assume a curl-style
fingerprint. Some recon tools (nmap, raw-socket fingerprinters) cannot be
proxied through a browser; in that case fall back to option 1 or 2.

### 4. Accept the limited coverage and document the gap

**When to choose.** When the program does not allowlist, no clean egress
is available, and the JA3 block is layered behind WAF policy that the
browser path also fails. The engagement records the egress block as a
Phase-3 blocker and ships the report with the documented gap; this is a
real failure mode for some heavily-CDN-fronted programs.

**How to set up.** Record `{kind: "egress_decision", blocked_pct: N,
choice: "accept-gap"}` in `agent-registry.json` and write the gap into
`agent/skills/report-generation` Phase-3 coverage notes via
`aith assess record-intel note` so the report-writer surfaces it. Mark
affected scope entries `status=deferred` in `scope.json` so the scope
coverage gate accepts them as terminal.

**Audit-pipeline considerations.** The audit row reflects what actually
ran — every 403 is recorded as a 403, not as a synthetic skip. The
report-writer reads `aith assess fetch summary` and the
`vendor_saas_pending_decision` / `egress_block_status` projections (both
exposed under `/summary`) and includes the documented gap in the
Methodology / Coverage section.

## When to give up vs when to escalate

The operator's escalation rule, in priority order:

1. **First pass: option 1 (allowlist).** Always try the program contact
   first. The cost is one message and a wait; the upside is a clean
   audit trail.
2. **Second pass: option 3 (browser).** When the symptom shape is JA3 /
   TLS-fingerprint-shaped (TLS reset mid-handshake, 403 only on curl-class
   fingerprints), a browser inside the runtime sidesteps the block
   without changing the egress IP. Cheap to try.
3. **Third pass: option 2 (proxy).** When the symptom is IP-reputation
   shaped (403 on every TLS fingerprint, hard 403 with a vendor reference
   code), the only fix is a different egress IP. Proxy or clean-IP VPS
   resolves it; document the operator-side authorization.
4. **Last resort: option 4 (accept).** When 1–3 all fail and the
   engagement timeline does not allow further escalation. Document the
   gap and ship.

Step away from a path that produces no signal after one mitigation attempt
fails; do not stack five proxy hops to push through a hardened block. The
report value of a documented coverage gap exceeds the value of a noisy,
unaudited bypass attempt.

## Cross-references

- `agent/operator-core.md` "Phase 1 — Egress reputation checkpoint"
  sub-bullet — the user-facing numbered choice.
- `agent/skills/web-recon/SKILL.md` "Egress reputation check" step — the
  recon-side trigger that runs the script after wafw00f.
- `agent/skills/subdomain-enumeration/SKILL.md` "Tooling preflight" cross-link
  — DNS resolution success-rate parallels egress reputation; if every host
  resolves but no host responds, run the reputation script.
- `agent/scripts/assess/commands/ingest_endpoints.py` `--egress-blocked-hosts`
  flag — the deferral path that turns the per-host block list into
  `cluster_key=deferred:egress-blocked` work-buffer rows.
