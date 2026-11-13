---
name: surface-collection
description: URL collection pipeline and intelligent triage methodology for Phase 2 work-buffer population
origin: Vigil
---

# Surface Collection

> **`vigil assess kali` audit flags:** use `--technique DISCOVERY`. Katana, gau and wayback
> collection plus triage expand the inventory without sending attack payloads.

This skill is the Phase 2 pipeline that turns Phase 1 output and crawl/archive results into a
prioritized, attack-signal-enriched work buffer for Phase 4. The surface-collector role prompt
owns the triage categories, the output sections and the closing verbs. This skill owns the
commands and the order to run them in. Tag every ingestion source correctly (`recon`, `katana`,
`gau`, `source-analysis`, `spec`), because coverage tracking uses source provenance.

## Pipeline

```bash
DIR="${ENGAGEMENT_DIR:?set by the engagement launcher}"
```

### Step 1: Ingest Phase 1 Endpoints

```bash
cat "$DIR/scans/endpoints.txt" | vigil assess ingest endpoints recon
cat "$DIR/scans/source-endpoints.txt" | vigil assess ingest endpoints source-analysis   # if source-analyzer wrote one
```

### Step 2: Live Crawl via Katana

Crawl depth, headless escalation, rate, exclusions and version-specific `--extra-args` are in
`agent/references/tools/recon/katana.md`. Run one crawl per in-scope web host in `scope.json`.

```bash
vigil assess kali katana \
  -u https://target.example -d 3 -c 10 -rl 20 \
  -o /engagements/$ENGAGEMENT_KEY/scans/katana_output.txt \
  --technique DISCOVERY --intent "live crawl of target.example" \
  --probe-kind fingerprint --phase collect --timeout 600
cat "$DIR/scans/katana_output.txt" | vigil assess ingest endpoints katana
```

- **Auth-aware.** When `vigil auth status` shows a usable credential with `use_for_requests: true`,
  re-crawl with `--identity <name>` (it injects that identity's session and stamps the run's
  `auth_context` without a raw token in the audit argv); for material outside the credential store
  use the typed `-H 'Cookie: ...'` / `-H 'Authorization: Bearer ...'`, repeated per header. Write
  the re-crawl to its own output file. `ingest endpoints` stamps `auth_context` from the
  engagement's active credential state, not from the crawl that produced the file, so diff the
  authenticated output against the anonymous one: endpoints that appear only with auth are
  high-priority IDOR and privilege-escalation targets.
- **Browser-semantic.** Add `-headless` (use `-c 5 -rl 10`) and load
  `agent/skills/browser-semantic-analysis/SKILL.md` when its triggers apply. Keep API-only and
  high-volume work on the normal path, which is more accurate for it.
- **TLS.** If the installed Katana can't skip invalid TLS, spot-check with an audited `curl -k`
  and carry on with the other sources rather than assuming Katana crawled it.
- **Curated candidates.** If triage produced metadata-rich candidate JSONL (score, signals,
  rationale, bucket, live status), ingest it with `vigil assess ingest candidates
  surface-collector-curated "$DIR/scans/surface-collector/candidate_records.jsonl"`. Flattening it
  to URLs throws away the priority metadata.

### Step 3: Historical URL Enrichment via gau

Run once per in-scope domain:

```bash
vigil assess gau endpoints TARGET_DOMAIN --subs --providers wayback,otx,commoncrawl,urlscan
```

When `waymore` is installed (it is not in the runtime image; `agent/skills/osint-recon/SKILL.md`
Tools) and gau's Wayback coverage looks thin, run it through `vigil assess kali exec -- waymore ...`
and fold its output into the same dedup and ingest pass.

This runs `kali gau`, or reuses a cached corpus for the exact target and flag set (by default
`--max-cache-age-hours 24`; `--refresh` forces a new run). It ingests the URLs with inline
classification and prints a JSON summary that includes `cache_reused`. Archives find what Katana
can't: deprecated routes, old API versions, test and admin paths that were public once. Two
follow-ons share the same corpus:

- `vigil assess gau js-endpoints TARGET_DOMAIN --fetch-if-missing` extracts routes that exist only
  in minified JS bundles and ingests them as `source='js-extract'`.
- `vigil assess gau secrets TARGET_DOMAIN` captures bodies and runs a trufflehog scan, with
  `--no-verification` by default and `--verify` to enable verification.

Use `vigil assess ingest endpoints` directly only for non-gau sources (Katana, specs, mitmproxy
captures).

### Step 4: OpenAPI/Swagger Spec Ingestion

`vigil assess ingest spec "$DIR/scans/openapi.json"` creates `api-spec` work items with their
parameter schemas and generates coverage candidates.

### Step 5: Volume and Dedup Check

`vigil assess work-buffer stats`. Ingestion dedups by parameter structure, so the same endpoint
with different values is one item. If one source contributed a disproportionate count, check
whether dedup is working. There is no per-host URL cap; volume is controlled at ingest:

- `image`, `video`, `font`, `archive` and `manifest` rows are stamped `skipped`. Source maps are
  not inert: they classify as `gf:interestingext` and stay queued.
- Every row gets a `cluster_key` and `priority_score` at insert time. Review clusters with
  `vigil assess work-buffer clusters` and defer low-signal ones explicitly with `vigil assess
  work-buffer defer-cluster <key> --reason "…"`, so nothing is silently truncated.
- Out-of-scope URLs are skipped at insert. A CDN-IP-blocked host
  (`agent/references/runtime-guides/cdn-ip-blocking.md`) is deferred by passing
  `--egress-blocked-hosts <file>` to `ingest endpoints`, and its URLs land under
  `cluster_key=deferred:egress-blocked`. Admin, internal or config paths that gau finds on a
  blocked host still tell you about the environment, so save them as `vigil assess intel record
  note` for the report.
- A host that appears after initial ingestion (an enumeration delta or an OSINT discovery) gets
  its own gau pass. Don't assume the first collection was exhaustive.

### Step 6: Intelligent Triage

Triage is classification, so it sends no target-facing probes. Read rows without claiming them:

```bash
vigil assess work-buffer peek api 50    # also: page, unknown, …
```

`peek` leaves rows pending. Claiming with `fetch` for triage and then releasing with `reset-stale`
returns every processing row in the engagement to pending, sibling lanes' claims included.

For corpora over about 500 URLs, or when response-body secret scanning is in scope, ask the
operator for a follow-up surface-collector dispatch with `agent/skills/gau-triage/SKILL.md`.
It adds `gf` classification, httpx body capture and trufflehog on top of this corpus.

**Auth-gate redirects are leads.** A 301/302/307/308 to a login page, SSO entry or policy wall is
a bypass-test lead, not a "gated" closure (`agent/rules/hunting.md` §12(e)). Record it, and the
auth-bypass sweep (`agent/skills/auth-bypass/SKILL.md` "Attack the Gate Itself") picks it up:

```bash
vigil assess record-surface auth_entry "https://TARGET/protected" surface-collector \
  --rationale "auth-bypass lead: 302 -> /login; route exists and is enforced" --status discovered
```

### Step 6.5: URL-shape body-field harvest (SSRF candidates)

Path-pattern triage misses URL and host fields inside admin or settings POST/PUT bodies, which are
SSRF candidates wherever they appear. `peek` is per type, so loop it across the body-bearing types:

```bash
for t in api api-spec form upload graphql websocket auth_entry workflow api_route event_feed debug_config portal_session; do
  vigil assess work-buffer peek "$t" 500
done | jq -s -r 'add // [] | .[] | select(.method=="POST" or .method=="PUT")
           | "\(.url)\t\(.body_params // empty)"' \
  | grep -iE '\b(url|uri|host|hostname|endpoint|callback|webhook|notify|postback|target|destination|return|redirect|next|continue|origin|fetch|import|source|metadata|discovery)\b\s*[:=]'
```

Record each hit:

```bash
vigil assess record-surface privileged_write "<endpoint>" surface-collector-url-shape \
  --rationale "SSRF candidate: POST/PUT body field <field> accepts a URL — server-side fetch on save / connection-test (SaaS connector pattern)" \
  --status discovered
```

Then recommend in `next_steps` a `vulnerability-analyst` dispatch with `--skills ssrf-testing` on
the highest-yield candidates: admin and settings pages, integration lists, connection-test
handlers. The testing recipe is `agent/skills/ssrf-testing/SKILL.md` "SaaS integration connectors".

### Step 6.6: Hidden-parameter discovery via Arjun (collect→consume bridge)

Arjun finds parameters an endpoint accepts but never advertised. Start with a bounded first pass
over param-poor dynamic endpoints:

```bash
vigil assess arjun-sweep --param-poor-only --max-per-host 5 \
  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt \
  --technique PARAM-DISCOVERY --intent "bounded hidden-param discovery over gated buffer" \
  --probe-kind fingerprint --phase collect --timeout 600
```

`arjun-sweep` gates the buffer (live, dynamic, template-deduped, param-poor). Add
`--include-unknown` only when there is no liveness ledger. It scans each method list under its own
`-m`, so POST/JSON/XML bodies aren't scanned as GET, and ingests the results with
`selected_by=arjun` and a `triage_rationale`. A failed or timed-out arm is a hole to re-run, not a
negative. For depth on one high-value endpoint, use `kali arjun -u … --passive`
(`agent/references/tools/recon/arjun.md`).

On a compiled SPA over an allowlisting JSON:API or strong-params layer, mine the bundles first.
The routes and field names are in the shipped JavaScript, and a wordlist can't find parameters the
server's allowlist refuses by design, so run Arjun and deep Katana against the mined manifest as
confirmation. On a server-rendered estate the order flips, and Arjun is the discovery step.

### Step 7: Record and report

Record high-signal discoveries with `vigil assess record-surface <type> <target> <source>
--rationale "<why>" --status discovered`. Record decisive triage evidence (for example an API key
with a real value in a URL parameter) with `vigil assess finding record surface-collector
<finding-json-file> --agent-id <your-agent_id>`. Finish with `vigil assess work-buffer stats` and
a ranked priority manifest of clusters, each with its triage signals, dispatch order and suggested
vuln-class skill.

## Extended Resources

- `agent/references/tools/recon/katana.md`, `gau.md`, `httpx.md`: tool doctrine
- `agent/references/runtime-guides/browser-semantic-evidence.md`: browser evidence contract
