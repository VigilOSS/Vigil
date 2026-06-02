# gf (grep-friendly)

**Purpose:** Classify URLs by vulnerability-parameter patterns using pre-baked JSON pattern
files. Bug-bounty staple for triaging large historical URL corpora (gau, waybackurls, katana).

**In this repo**: the gf bucket patterns are compiled into `assess.lib.classify_buckets._BUCKETS` and applied inline at ingest — operators do not need to run `gf` directly. The runtime image still ships `gf` plus the upstream pattern library for ad-hoc one-off triage, invokable via `vigil assess kali exec --technique RECON --intent "<why>" --probe-kind fingerprint --phase recon --timeout <seconds> -- gf ...`.

## Install layout

`gf` is a Go tool installed from `github.com/tomnomnom/gf`. The runtime image preloads it
plus community patterns from `github.com/1ndianl33t/Gf-Patterns` into `/root/.gf/`.

Pattern discovery order (first match wins):
1. `$GF_DIR` (if set)
2. `~/.gf/` (default — where the image stages patterns)

Add a pattern by dropping a JSON file into `/root/.gf/`. Schema is minimal:

```json
{
  "flags": "-HnriE",
  "pattern": "(?i)(api[_-]?key|secret|token)="
}
```

Or a list form:

```json
{
  "flags": "-Hnri",
  "patterns": ["\\?url=", "\\?dest=", "\\?redirect="]
}
```

## Usage

```bash
# From stdin
cat urls.txt | gf ssrf

# From a file argument
gf ssrf urls.txt

# List installed patterns
gf -list

# Bucket by multiple patterns
for p in ssrf redirect idor sqli lfi; do
  gf "$p" < urls.txt > "bucket_${p}.txt"
done
```

## Installed patterns (1ndianl33t/Gf-Patterns)

| Pattern | Matches (examples) | Signal level |
|---|---|---|
| `xss` | `?q=`, `?search=`, `?query=`, `?input=`, `?message=` | Medium — noisy on search endpoints |
| `ssrf` | `?url=`, `?uri=`, `?dest=`, `?redirect=`, `?proxy=`, `?host=` | High |
| `redirect` | `?next=`, `?return=`, `?redirect_to=`, `?continue=`, `?rurl=` | High |
| `idor` | `?id=`, `?user_id=`, `?account=`, `?order=`, `?uid=` | High |
| `sqli` | `?id=`, `?page=`, `?category=`, `?sort=`, `?cid=` | Medium |
| `lfi` | `?file=`, `?path=`, `?template=`, `?include=`, `?doc=` | High |
| `rce` | `?cmd=`, `?exec=`, `?run=`, `?execute=` | High |
| `debug_logic` | `?debug=`, `?test=`, `?admin=`, `?verbose=`, `?log=` | High |
| `interestingparams` | Catch-all for unusual param names (token, key, auth, jwt, session, etc.) | Medium |
| `interestingsubs` | Interesting subdomain patterns | Low |
| `interestingEXT` | Interesting file extensions (bak, swp, sql, config) | Medium |
| `img-traversal` | Image-parameter path traversal | Medium |
| `takeovers` | Subdomain-takeover candidates | High (when combined with DNS) |

Run `gf -list` inside the runtime to see the authoritative installed set — the upstream repo
occasionally adds patterns.

## Pipeline patterns

`gf` is a host-side URL classifier — it reads a corpus file and writes matched URLs to stdout. Run it on the host without `vigil assess kali`; feed its output into a file, then pass the file to `vigil assess kali` verbs for the target-facing steps.

```bash
# Classify the corpus into per-bucket files (host-side, no target traffic)
for p in ssrf redirect idor sqli lfi; do
  gf "$p" < /engagements/$ENGAGEMENT_KEY/scans/gau_example.txt \
    > /engagements/$ENGAGEMENT_KEY/scans/gf_${p}.txt
done

# Feed classified URLs into target-facing tools via vigil assess kali
vigil assess kali httpx \
  -l /engagements/$ENGAGEMENT_KEY/scans/gf_ssrf.txt \
  -silent -mc 200 \
  -o /engagements/$ENGAGEMENT_KEY/scans/gf_ssrf_live.jsonl \
  --technique SSRF --intent "confirm live SSRF-candidate URLs from gf classification" \
  --probe-kind fingerprint --phase consume-test --timeout 600

vigil assess kali sqlmap \
  -m /engagements/$ENGAGEMENT_KEY/scans/gf_sqli.txt \
  --technique=BEU --batch \
  --technique SQLI --intent "gf-classified SQLi candidate sweep" \
  --probe-kind payload --phase consume-test --timeout 1800

# Combine multiple patterns into one priority set (host-side)
for p in ssrf redirect idor sqli lfi; do gf "$p" < urls.txt; done | sort -u \
  > /engagements/$ENGAGEMENT_KEY/scans/gf_priority.txt

# Count per pattern
for p in xss ssrf redirect idor sqli lfi debug_logic; do
  printf "%-15s %d\n" "$p" "$(gf "$p" < urls.txt 2>/dev/null | wc -l)"
done
```

## gf before uro — ordering rule

When using `uro` (smart structural dedup) alongside `gf`:

1. **First** filter static assets (grep) → **then** `uro` for structural dedup → **then** `gf`
   for classification. This preserves one representative per attack class.
2. Do **not** `uro` the output of `gf` per-bucket unless you have a specific reason — the
   bucket may only contain variants of one parameterized URL, and uro will flatten them into
   a single entry, losing coverage signals (e.g. different `id=` values that could be
   IDOR-relevant).

## Gotchas

- `gf` loads patterns at startup. A fresh pattern file in `~/.gf/` is only picked up on the
  next invocation.
- Case-sensitivity depends on the pattern's `flags` field. Most 1ndianl33t patterns use
  `-i` for case-insensitive matching.
- `gf` is not a scanner — it only classifies. Hits need downstream validation via `httpx`,
  `sqlmap`, manual probing, etc.
- When a pattern returns zero hits on a large corpus, check `gf -list` — if the pattern is
  missing, the image's `~/.gf/` was not seeded correctly.
