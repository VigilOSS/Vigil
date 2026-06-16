---
name: parameter-fuzzing
description: Discover hidden parameters, test values, and identify input handling anomalies
origin: Vigil
---

# Parameter Fuzzing

## When to Activate

- Endpoint needs parameter testing or hidden/debug parameter discovery
- IDOR, access control, or logic bug testing via parameter manipulation
- API accepts unknown parameters

## Tools

`ffuf` (primary), `curl` (verification), `arjun` (dedicated param discovery), `ParamSpider` (mine params from web archives)

## Methodology

### 1. Establish Baseline
```bash
curl -s -o /dev/null -w "Code: %{http_code}, Size: %{size_download}" https://TARGET/endpoint
```
Record baseline response size for `-fs` filter.

### 2. GET Parameter Discovery
```bash
ffuf -u "https://TARGET/endpoint?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs BASELINE_SIZE
# Or with auto-calibration: -ac
```

### 3. POST Parameter Discovery
```bash
# URL-encoded
ffuf -u "https://TARGET/endpoint" -X POST -d "FUZZ=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs BASELINE_SIZE
# JSON
ffuf -u "https://TARGET/endpoint" -X POST -d '{"FUZZ":"test"}' \
  -H "Content-Type: application/json" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs BASELINE_SIZE
```

### 4. Value Fuzzing

Generate the value wordlist from the parameter's observed value instead of hand-rolling ranges and
toggle lists. `vigil assess classify-payload` types the value and emits intent-keyed variants
(neighbor / boundary / escalation / format / empty) you can pipe straight into ffuf:

```bash
# Build a type-aware value wordlist from a captured value, then fuzz with it
vigil assess classify-payload 1042 --mutations --json \
  | jq -r '.intents | to_entries[].value[]' | sort -u > /tmp/values.txt
ffuf -u "https://TARGET/endpoint?id=FUZZ" -w /tmp/values.txt -fs BASELINE_SIZE   # IDOR / boundary / escalation in one sweep

ffuf -u "https://TARGET/endpoint?param=FUZZ" -w /usr/share/seclists/Fuzzing/special-chars.txt -fs BASELINE_SIZE
```
`classify-payload` replaces the ad-hoc loops: a `sequential_id` already yields the IDOR neighbours
(`<seq 1 1000>` equivalents around the real value), the `0/-1/overflow` boundaries, and the
`admin`/`root`/`1` escalation values; a `boolean` yields the `true/false/1/0` toggles; an `email`
yields `admin@`/`root@` escalation. Classify each discovered parameter's value and fuzz with its
variant set rather than a generic list.

### 5. Header Fuzzing
```bash
ffuf -u "https://TARGET/endpoint" -H "FUZZ: test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs BASELINE_SIZE
# Common bypass headers:
for header in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "X-Original-URL: /admin" \
  "X-Debug: true" "X-Debug-Mode: 1" "X-Forwarded-Host: localhost"; do
  curl -s -o /dev/null -w "%{http_code} %{size_download}" -H "$header" "https://TARGET/endpoint"
done
```

### 6. Cookie Fuzzing
```bash
ffuf -u "https://TARGET/endpoint" -b "FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs BASELINE_SIZE
```

### 7. Multi-Parameter / Clusterbomb
```bash
ffuf -u "https://TARGET/endpoint?W1=W2" -w params.txt:W1 -w values.txt:W2 \
  -mode clusterbomb -fs BASELINE_SIZE
```

### 8. Arjun (typed verb + work-buffer enrichment)

Prefer Arjun through the audited verb so the run is recorded AND its findings flow back into the work buffer (where the classifier re-routes the now-parameterized endpoint). Passive-first, then escalate.

```bash
# (a) GATE the target list from the buffer (live + dynamic + template-deduped + param-poor).
#     On an engagement with no liveness ledger, add --include-unknown.
vigil assess arjun-select "$DB" -o "$DIR/scans/arjun/targets.txt" --param-poor-only --max-per-host 5

# (b) BOUNDED first pass — a focused -w list + --stable --rate-limit keep the run gentle; Arjun's
#     default list expands to ~100+ chunks/host, enough to overload a rate-sensitive or production
#     target. Auth via --headers. Keep the batch small (--max-per-host above) so one endpoint that
#     returns an unexpected status can't abort the whole -i list (an Arjun 2.2.7 quirk).
vigil assess kali arjun -i /engagements/$ENGAGEMENT_KEY/scans/arjun/targets.txt -m GET \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt --stable --rate-limit 10 \
  --headers $'Authorization: Bearer TOKEN' \
  --technique PARAM-DISCOVERY --intent "bounded hidden-param discovery" \
  --probe-kind fingerprint --phase consume-test --timeout 1800

# (c) ESCALATE for depth on one high-value endpoint: drop -w (full ~25k list) and/or add --passive.
#     --passive folds wayback/otx param names into the wordlist and then scans actively, so it adds
#     coverage and request volume; keep --stable --rate-limit set and give it a single -u target.
vigil assess kali arjun -u "https://TARGET/high-value" --passive --stable --rate-limit 10 \
  --technique PARAM-DISCOVERY --intent "deep archive-augmented hidden-param discovery" \
  --probe-kind fingerprint --phase consume-test --timeout 1800

# (d) FOLD findings back in — discovered params re-route the endpoint (file=->gf:lfi, url=->gf:ssrf,
#     id=->gf:sqli/idor) and stamp a triage_rationale that names `kali sqlmap` for DB-class params:
vigil assess ingest-arjun "$DB" /engagements/$ENGAGEMENT_KEY/scans/arjun/<target>/<hash>.json
```

Use raw `arjun -u …` only for a one-off manual check; the verb path is what feeds Phase 3. Full reference: `references/tools/recon/arjun.md`.

### 9. ParamSpider (Historical Parameter Mining)
```bash
# Mine parameters from web archives for the target domain
paramspider -d TARGET_DOMAIN -o /engagements/$ENGAGEMENT_KEY/scans/paramspider_output.txt

# Feed discovered parameterized URLs into ffuf or manual testing
cat /engagements/$ENGAGEMENT_KEY/scans/paramspider_output.txt | \
  grep "?" | sort -u > /engagements/$ENGAGEMENT_KEY/scans/params_to_test.txt
```
ParamSpider pulls historically-known parameters from Wayback Machine and other archives.
Use it to discover parameters that active fuzzing would miss.

### 10. Triage and Verification

A single `-fs BASELINE_SIZE` filter catches only size deltas and assumes you picked the right
baseline. To find every parameter/value that altered the response — including status flips, title
changes, and word/line shifts a size filter misses — rank the ffuf result population with
`vigil assess anomaly-score`. ffuf's JSON `results` carry `status`, `length`, `words`, `lines`,
`url`, which the oracle reads directly (rename only the hyphenated `content-type`):

```bash
ffuf -u "https://TARGET/endpoint?FUZZ=test" -w params.txt \
  -o /tmp/ffuf_params.json -of json    # discovery sweep, no -fs needed
jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
  /tmp/ffuf_params.json > /tmp/ffuf_pop.json
vigil assess anomaly-score /tmp/ffuf_pop.json --top 10
#   #1  score=4.17  status=200  len=2210  url=...?debug=test   ← the param that changed behaviour
#       ^ length_bucket=...  ^ words_bucket=...                 the inert params clustered at the baseline
```

The high-scoring records are the parameters/values worth investigating (their response diverged
from the inert cluster); the flat low-scoring tail is noise. Then confirm the specific hit by hand:

```bash
curl -sv "https://TARGET/endpoint?discovered_param=test" 2>&1
diff <(curl -s "https://TARGET/endpoint") <(curl -s "https://TARGET/endpoint?param=value")
```

## Extended Resources

- `agent/references/tools/fuzzing/ffuf.md` — ffuf flags, filter/matcher options, wordlist selection
