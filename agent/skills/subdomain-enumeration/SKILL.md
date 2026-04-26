---
name: subdomain-enumeration
description: Subdomain discovery via subfinder, DNS brute-force, and passive sources
origin: AI Threat Hunting
---

# Subdomain Enumeration

> **`aith assess kali` audit flags:** use `--technique RECON` when actively probing in-scope DNS infrastructure (DNS brute-force, wildcard tests, zone transfers). Switch to `OSINT` for passive external-source lookups (certificate transparency logs, public archives, OSINT APIs).

## When to Activate

- Beginning of engagement when the `hosts` array in scope.json includes `*.domain` entries (e.g., `*.target.example`)
- Need to discover additional attack surface beyond the primary domain
- **Phase 1a (first-class) when scope.json `hosts` contains `*.domain` entries** — dispatched BEFORE the parallel recon+source pass so live subdomains land in the endpoint inventory before downstream steps depend on them.
- After finding references to subdomains in JS/HTML source code

## Tools

- `subfinder` — passive subdomain enumeration (40+ sources, API keys recommended)
- `puredns` — active DNS brute-force with accurate wildcard filtering
- `dnsx` — fast bulk DNS resolution and filtering
- `httpx` — HTTP probing for live host confirmation, tech fingerprint, status codes
- `ffuf` — vhost fuzzing when DNS brute-force is insufficient
- `curl` / `nmap` — manual verification

## Methodology

### 1. Passive Enumeration with subfinder

subfinder queries 40+ passive sources (crt.sh, VirusTotal, Shodan, SecurityTrails, etc.)
without sending traffic to the target.

```bash
# Basic enumeration
subfinder -d target.example -silent

# With all sources (API keys are passed via docker --env-file from the
# install-root .env when `aith runtime start` launched the container;
# subfinder reads them straight from the process environment, no per-
# engagement file is mounted)
subfinder -d target.example -all -silent -o /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt

# Multiple domains
subfinder -dL /engagements/$ENGAGEMENT_KEY/scans/domains.txt -silent -o /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt

# JSON output for detailed source info
subfinder -d target.example -all -json -o /engagements/$ENGAGEMENT_KEY/scans/subdomains.json

# Resolve IPs while enumerating
subfinder -d target.example -all -silent -nW -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_raw.txt
```

**API keys** enhance results significantly. Set them in the install-root `.env`
(not the engagement directory) so `aith runtime start` passes them via
`docker --env-file` into the runtime container — subfinder reads them from
the process environment on every `aith assess kali subfinder` execution:
```
SUBFINDER_VIRUSTOTAL_API_KEY=...
SUBFINDER_SECURITYTRAILS_API_KEY=...
SUBFINDER_SHODAN_API_KEY=...
```
Restart the Kali runtime (`aith runtime restart`)
after editing `.env` so the new values reach the container.

### 1b. Active DNS Brute-Force with puredns

Active brute-force with wildcard filtering (catches subdomains passive sources miss):

```bash
# Brute-force with wildcard detection
puredns bruteforce /seclists/Discovery/DNS/subdomains-top1million-5000.txt target.example \
  -r /engagements/$ENGAGEMENT_KEY/scans/resolvers.txt -w /engagements/$ENGAGEMENT_KEY/scans/subdomains_brute.txt

# Resolve a list of known subdomains (validate passive results)
puredns resolve /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt \
  -r /engagements/$ENGAGEMENT_KEY/scans/resolvers.txt -w /engagements/$ENGAGEMENT_KEY/scans/subdomains_resolved.txt
```

### 1c. Bulk DNS Resolution with dnsx

Fast resolution and record-type enumeration:

```bash
# Resolve subdomains and get A records
cat /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt | dnsx -silent -a -resp -o /engagements/$ENGAGEMENT_KEY/scans/dns_resolved.txt

# Get CNAME records (useful for subdomain takeover detection)
cat /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt | dnsx -silent -cname -resp -o /engagements/$ENGAGEMENT_KEY/scans/dns_cnames.txt
```

### 2. DNS Brute-Force with ffuf

Active brute-force for subdomains not found by passive sources:

```bash
# First, baseline — get response size for non-existent subdomain
curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent-xyz.target.example" http://TARGET_IP

# Brute-force with vhost fuzzing
ffuf -u http://TARGET_IP -H "Host: FUZZ.target.example" \
  -w /seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <baseline_size> -t 50 \
  -o /engagements/$ENGAGEMENT_KEY/scans/vhost_fuzz.json -of json

# Larger wordlist if initial results are sparse
ffuf -u http://TARGET_IP -H "Host: FUZZ.target.example" \
  -w /seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -fs <baseline_size> -t 50 \
  -o /engagements/$ENGAGEMENT_KEY/scans/vhost_fuzz_20k.json -of json
```

### 3. Filter, Verify & Fingerprint Subdomains

Three-stage filter: DNS resolution → HTTP probe → fingerprint. Only subdomains that
pass ALL stages enter the engagement pipeline.

```bash
# Stage 1: HTTP probing with httpx (replaces manual curl loop — faster and richer)
cat /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt | httpx -silent -status-code -title -tech-detect \
  -server -content-length -follow-redirects -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_live.txt

# httpx outputs: URL STATUS_CODE [TITLE] [SERVER] [TECH]
# Filter for responsive hosts only (httpx drops non-responsive by default)

# Stage 2: Web port check — try HTTP (80), HTTPS (443), then common alt ports (8080, 8443)
> "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
while IFS= read -r sub; do
  live=""
  for proto_port in "http://$sub" "https://$sub" "http://$sub:8080" "https://$sub:8443"; do
    code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 -k "$proto_port" 2>/dev/null)
    if [ "$code" != "000" ] && [ -n "$code" ]; then
      echo "$sub $proto_port $code" >> "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
      live="yes"
      break
    fi
  done
  [ -z "$live" ] && echo "  [SKIP] $sub — no open web port (80/443/8080/8443)"
done < "$ENGAGEMENT_DIR/scans/subdomains_resolved.txt"
echo "Live web: $(wc -l < $ENGAGEMENT_DIR/scans/subdomains_live.txt)"

# Stage 3: Fingerprint live subdomains for prioritization
echo "subdomain|url|status|server|title|size|notes" > "$ENGAGEMENT_DIR/scans/subdomains_fingerprint.csv"
TMPDIR_FINGERPRINT=$(mktemp -d)
trap 'rm -rf "$TMPDIR_FINGERPRINT"' EXIT
while IFS=' ' read -r sub url code; do
  resp=$(curl -s -o "$TMPDIR_FINGERPRINT/sub_resp.html" -w "%{size_download}" \
    -D "$TMPDIR_FINGERPRINT/sub_headers.txt" --connect-timeout 5 -k "$url" 2>/dev/null)
  size="$resp"
  server=$(grep -i "^server:" "$TMPDIR_FINGERPRINT/sub_headers.txt" 2>/dev/null | head -1 | cut -d: -f2- | tr -d '\r')
  title=$(grep -oE '<title>[^<]+</title>' "$TMPDIR_FINGERPRINT/sub_resp.html" 2>/dev/null | head -1 | sed 's/<[^>]*>//g')
  notes=""
  grep -qi "debug\|x-debug\|x-powered-by\|x-aspnet" "$TMPDIR_FINGERPRINT/sub_headers.txt" 2>/dev/null && notes="${notes}debug_headers "
  grep -qi "error\|exception\|traceback\|stack.trace" "$TMPDIR_FINGERPRINT/sub_resp.html" 2>/dev/null && notes="${notes}verbose_errors "
  [ "$code" = "401" ] || [ "$code" = "403" ] && notes="${notes}auth_protected "
  echo "$sub|$url|$code|$server|$title|$size|$notes" >> "$ENGAGEMENT_DIR/scans/subdomains_fingerprint.csv"
  echo "  $sub → $code ($server) [$title] ${notes}"
done < "$ENGAGEMENT_DIR/scans/subdomains_live.txt"
```

**Filter summary**: Only subdomains in `subdomains_fingerprint.csv` should enter engagements.
Subdomains that fail DNS or have no web port are logged and skipped — do NOT create
engagements for them.

Fingerprint signals for prioritization:
- **debug_headers**: likely dev/test environment → HIGH priority
- **verbose_errors**: misconfigured → HIGH priority
- **auth_protected**: admin panel or internal tool → test for bypass
- **Small response size**: minimal app or API → less hardened
- **Non-standard server**: unusual tech, potentially unpatched

Translate those signals into explicit hypotheses:
- auth-protected admin panels may expose reusable identity or trust-boundary mistakes
- unusual infrastructure may indicate separate ownership, weaker controls, or stale deployments
- verbose errors plus unusual headers often justify staged validation before heavier exploitation

### 4. Recursive Enumeration

If new subdomains are found, enumerate their subdomains too:

```bash
# Feed discovered subdomains back for deeper enumeration
subfinder -dL /engagements/$ENGAGEMENT_KEY/scans/subdomains.txt -all -silent \
  -o /engagements/$ENGAGEMENT_KEY/scans/subdomains_recursive.txt
```

### 5. Feed Results into Pipeline

Import discovered subdomains into canonical backend state for coverage tracking. The local queue
can still be used as a transient batching buffer for follow-up testing:

```bash
# Only import verified live web entries. subdomains_live.txt is: "<subdomain> <url> <status>"
awk '{print $1}' "$ENGAGEMENT_DIR/scans/subdomains_live.txt" | sort -u | while IFS= read -r sub; do
  echo "GET https://$sub"
done | \
  aith assess ingest-endpoints "$ENGAGEMENT_DIR/cases.db" subdomain-enum
```

After ingestion, the operator triggers a reactive nuclei sweep against the newly-live subdomains — see `agent/skills/nuclei-scanning/SKILL.md` "Reactive Sweep Mode".

## What to Record

- **Total subdomains found** (passive + active)
- **Live subdomains** with HTTP status codes
- **Interesting subdomains**: staging, dev, admin, api, internal, test, beta
- **Services** running on non-standard ports
- **Source** of each subdomain (subfinder source, brute-force, JS reference)
- Any subdomain pointing to **different infrastructure** (cloud, CDN, third-party)
- The hypothesis each interesting subdomain suggests: auth bypass, stale deployment, separate trust zone, or chain opportunity

## Extended Resources

- `agent/references/tools/recon/puredns.md` — active DNS brute-force with wildcard filtering
- `agent/references/tools/recon/dnsx.md` — bulk DNS resolution and record enumeration
- `agent/references/tools/recon/httpx.md` — HTTP probing and live host confirmation
