---
description: Command recipes for the web-recon per-host chain (wafw00f, egress sample, nmap + SAN extraction, httpx, header/OPTIONS diff, whatweb, ffuf L1, conditional nikto, TLS grab, vendor-template header capture, JS list)
skill: web-recon
---

# Web recon — command recipes

Load when you run a step of `agent/skills/web-recon/SKILL.md` and need the exact
`vigil assess kali` invocation. `<row ...>` placeholders come from the
`agent/references/recon/rate-calibration.md` row the WAF step picked: `<row nmap flags>` is the
row's nmap profile plus the `--max-retries` / `--host-timeout` its nmap bullet sets, and
`<row dir-fuzz rate>` is its dir-fuzz column. The Lab / CTF row has no rate cap, so there drop
`-rate` and pass `-t 40`. Each is a blocking call with `--timeout 600` or less
(`agent/shared-constraints.md` §2); a host list or wordlist too large for one call splits across
calls. Host-side shell reads the same files at `$DIR/scans/` (`agent/shared-constraints.md` §11).

## Step 0 — WAF detection

```bash
vigil assess kali wafw00f https://TARGET \
  --technique RECON --intent "WAF tier identification, drives rate-limit choice for later tools" \
  --probe-kind fingerprint --phase recon --timeout 300
vigil assess kali wafw00f -i /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt \
  --technique RECON --intent "WAF tier sweep across in-scope live hosts" \
  --probe-kind fingerprint --phase recon --timeout 600
```

## Step 0b — manual egress sample (fallback only)

Use only when the operator's `vigil assess egress-check` verdict is missing. `000` (no HTTP
answer) is excluded from the percentage because its cause is unknown; a 403 percentage is a
candidate signal, never proof of a blackhole. The Overview egress banner reads only
`egress-check` results, so this sample does not appear there.

```bash
vigil assess kali exec --technique RECON --intent "egress reputation sample (CDN-IP-block detection)" \
  --probe-kind fingerprint --phase recon --timeout 300 -- bash -c '
REPRS=$(head -10 /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt); blocked=0; total=0
for h in $REPRS; do
  code=$(curl -sS -o /dev/null -w "%{http_code}" -m 10 "https://$h/")   # prints 000 on failure; no || fallback
  case "$code" in 000) ;; 403) blocked=$((blocked+1)); total=$((total+1)) ;; *) total=$((total+1)) ;; esac
  sleep 1
done
[ "$total" -eq 0 ] && { echo "egress check skipped: no live hosts to sample"; exit 0; }
pct=$((blocked * 100 / total)); echo "egress_block_pct=$pct (blocked=$blocked alive=$total)"
[ "$pct" -gt 50 ] && echo "WARN: egress reputation blocked on >50% of alive sampled hosts"'
```

## Step 1 — nmap + SAN extraction

```bash
vigil assess kali nmap-scan --target www.example.com \
  --ports top-1000 --scripts safe --extra-args "<row nmap flags>" \
  -oA /engagements/$ENGAGEMENT_KEY/scans/nmap_top1000 \
  --technique RECON --intent "initial nmap pass at the rate-calibration row profile" \
  --probe-kind fingerprint --phase recon --timeout 600
grep -oE 'DNS:[^ ,]+' "$DIR/scans/nmap_top1000.nmap" | sed 's/DNS://' | sort -u \
  > "$DIR/scans/nmap_san_hosts.txt"
```

Multi-host: `-iL <hosts.txt>` with the same profile (port-data assertion:
`agent/skills/port-scanning/SKILL.md`).

## Step 2 — httpx fingerprint and route diff

```bash
vigil assess kali httpx -l /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt \
  -tech-detect -title -tls-grab -status-code -web-server -cl -follow-redirects \
  -o /engagements/$ENGAGEMENT_KEY/scans/httpx_fingerprint.jsonl \
  --technique RECON --intent "httpx tech + tls-grab fingerprint" --probe-kind fingerprint --phase recon --timeout 600
vigil assess kali exec --technique RECON --intent "header diff across routes" \
  --probe-kind fingerprint --phase recon --timeout 60 -- curl -sI -L https://TARGET
vigil assess kali exec --technique RECON --intent "OPTIONS for DAV / methods detection" \
  --probe-kind fingerprint --phase recon --timeout 60 -- curl -sI -X OPTIONS https://TARGET
```

## Step 3 — whatweb

```bash
vigil assess kali whatweb https://TARGET -a 3 \
  --technique RECON --intent "whatweb deep technology fingerprint" \
  --probe-kind fingerprint --phase recon --timeout 300
```

## Step 5 — ffuf L1

```bash
vigil assess kali ffuf -u https://TARGET/FUZZ \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-small-directories.txt \
  -rate <row dir-fuzz rate> -ac \
  --extra-args "-e .php,.html,.js,.txt,.bak,.old,.conf,.xml,.json,.yml,.env,.log,.sql,.zip" \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_dirs.json -of json \
  --technique RECON --intent "L1 directory fuzz with tech-extension variants" \
  --probe-kind fingerprint --phase recon --timeout 600
```

## Step 6 — conditional nikto

```bash
vigil assess kali nikto --host www.example.com -ssl -Tuning x60 -Pause 2 -maxtime 300 \
  -Format json -output /engagements/$ENGAGEMENT_KEY/scans/nikto_www.json \
  --technique INFO-DISCLOSURE --intent "nikto on legacy IIS/7.5 fingerprint" \
  --probe-kind payload --phase recon --timeout 600
```

## Step 8 — TLS grab

```bash
vigil assess kali exec --technique RECON --intent "TLS cert SAN/CN/issuer extraction" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null \
    | openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"'
```

## Step 8b — vendor-template header capture

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "vendor-template CSP/CORS re-baseline header capture" \
  --probe-kind fingerprint --phase recon --timeout 30 -- \
  curl -sSI -o /engagements/$ENGAGEMENT_KEY/scans/headers_TARGET.txt 'https://TARGET/'
```

Then run the greps in `agent/references/payloads/csp-default-grep.md` against the file.

## Step 10 — JS list for source-analyzer

```bash
vigil assess kali exec --technique RECON --intent "JS extraction for source-analyzer handoff" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -sL https://TARGET | grep -oE "src=\"[^\"]*\\.js\"" | sed "s/src=\"//;s/\"//"'
```
