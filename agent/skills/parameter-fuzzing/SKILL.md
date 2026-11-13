---
name: parameter-fuzzing
description: Discover hidden parameters and fuzz parameter values for injection, access control, and logic flaws
origin: Vigil
---

# Parameter Fuzzing

## When to Activate

- An endpoint needs hidden or debug parameter discovery, or parameter manipulation for IDOR,
  access control or logic testing; an API accepts unknown parameters.

All target traffic goes through `vigil assess kali …` (`agent/shared-constraints.md` §2): the
typed `kali ffuf` verb (POST data, cookies and clusterbomb mode via `--extra-args`, which is
shlex-split, so quote JSON inside it), `kali arjun`, and `arjun-sweep`. Flags and wordlists:
`agent/references/tools/fuzzing/ffuf.md`, `agent/references/tools/recon/arjun.md`. Parameter-name
list: `/usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt`.
Container paths are `/engagements/$ENGAGEMENT_KEY/...`; host-side files use `$DIR/...`.

## 1. Name discovery

- **Buffer-wide:** `vigil assess arjun-sweep --param-poor-only --max-per-host 5 --technique
  PARAM-DISCOVERY --intent "hidden-param discovery" --probe-kind fingerprint --phase consume-test
  --timeout 600` gates the work-buffer list, scans each method under its own `-m` (POST/JSON/XML
  bodies are not scanned as GET) and ingests the results, so a discovered `file=`/`url=`/`id=`
  re-routes the endpoint to its class. Add `--include-unknown` only when no liveness ledger exists;
  a timed-out or failed arm is a hole to re-run, not a negative.
- **One high-value endpoint:** `vigil assess kali arjun -u <url> --passive --stable --rate-limit
  10 …` folds archive parameter names in (more coverage and more requests), then
  `vigil assess ingest arjun <output.json>`.
- **Manual ffuf** for GET (`?FUZZ=test`), form and JSON bodies (`--extra-args "-X POST -d
  '{\"FUZZ\":\"test\"}'" -H 'Content-Type: application/json'`, `-H` being a typed flag),
  headers (`-H "FUZZ: test"`) and cookies, with `-ac` or a measured baseline filter.
- **Historical:** `vigil assess gau endpoints <domain>`, then `vigil assess work-buffer clusters
  --host <domain>` (read-only). Claim only the unit the operator assigned with `work-buffer
  fetch-by-unit --unit-id <id> --agent <your-role>`; `fetch-by-priority` can claim another host.
- Proxy-trusted headers (`X-Forwarded-For`, `X-Original-URL`, `X-Forwarded-Host`, debug flags) are
  their own sweep (`agent/rules/hunting.md` §10, `agent/skills/host-header-injection/SKILL.md`).

## 2. Value fuzzing

Type the observed value and fuzz with its variants rather than a generic list:

```bash
vigil assess classify-payload 1042 --mutations --json \
  | jq -r '.intents | to_entries[].value[]' | sort -u > "$DIR/scans/values.txt"
vigil assess kali ffuf -u "https://TARGET/endpoint?id=FUZZ" \
  -w /engagements/$ENGAGEMENT_KEY/scans/values.txt -ac \
  -o /engagements/$ENGAGEMENT_KEY/scans/ffuf_values.json -of json \
  --technique IDOR --intent "typed value sweep on id" \
  --probe-kind payload --phase consume-test --timeout 600
```

A `sequential_id` yields IDOR neighbours, `0`/`-1`/overflow boundaries and escalation values; a
`boolean` yields toggles; an `email` yields `admin@`/`root@` variants. Special characters:
`/usr/share/wordlists/SecLists/Fuzzing/special-chars.txt`.

## 3. Triage

A size filter catches only size deltas from the baseline you picked. Rank the whole population
instead (ffuf JSON results carry `status`, `length`, `words`, `lines`, `url`; rename
`content-type`):

```bash
jq '[.results[] | {url, status, length, words, lines, content_type: .["content-type"]}]' \
  "$DIR/scans/ffuf_values.json" > "$DIR/scans/ffuf_pop.json"
vigil assess anomaly-score "$DIR/scans/ffuf_pop.json" --top 10
```

High scorers diverged from the inert cluster (status flips, title, word or line shifts); confirm
each with a single `vigil assess kali exec … -- curl -s -i` replay against the baseline.
