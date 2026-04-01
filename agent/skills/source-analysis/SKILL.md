---
name: source-analysis
description: Frontend source code analysis for hidden routes, API endpoints, and secrets
origin: AI Threat Hunting
---

# Source Code Analysis

## When to Activate

- After recon identifies target's web pages and JS/CSS files
- SPA framework detected (React, Vue, Angular)
- Directory fuzzing sparse — source analysis reveals paths fuzzing misses
- GraphQL/REST API schema discovery needed

## Tools

- `LinkFinder` — automated endpoint extraction from JavaScript files
- `SecretFinder` — scan JS files for API keys, tokens, and secrets
- `curl`, `grep`/`sed`/`awk`, `jq` — manual extraction and verification

## Division of Labor

| Task | Agent |
|------|-------|
| Fetch pages, fingerprint, fuzz dirs | recon-specialist |
| Analyze HTML/JS/CSS for hidden content | source-analyzer |
| Fuzz discovered params | fuzzer |
| Test endpoints for vulns | vulnerability-analyst |

## Methodology

Do not stop at inventory. Convert routes, config fragments, and client logic into hypotheses
about backend behavior, trust boundaries, auth assumptions, and reachable follow-on attack paths.

### 1. Identify Source Files
List `<script src>`, `<link stylesheet href>`, inline `<script>` blocks, source map refs.

### 2. HTML Analysis
Extract: href/src/action values, hidden fields, data-url/data-api attributes,
HTML comments, meta tags (canonical, CSRF, API base), inline config (`window.__CONFIG__`).

### 3. JavaScript Analysis
```bash
curl -sL <js-url> | grep -oE '["'"'"'](/[a-zA-Z0-9_/\-\.]+)["'"'"']' | sort -u
```

#### Automated JS Endpoint Extraction

```bash
# LinkFinder — extract endpoints from JS (far more thorough than manual grep on minified code)
python3 linkfinder.py -i https://TARGET/static/js/app.js -o cli

# Batch all JS files discovered in step 1
for js_url in $(cat /engagement/scans/js_files.txt); do
  python3 linkfinder.py -i "$js_url" -o cli
done | sort -u > /engagement/scans/js_endpoints.txt

# SecretFinder — scan for API keys, tokens, credentials in JS
python3 SecretFinder.py -i https://TARGET/static/js/app.js -o cli

# Batch scan
for js_url in $(cat /engagement/scans/js_files.txt); do
  python3 SecretFinder.py -i "$js_url" -o cli
done | sort -u > /engagement/scans/js_secrets.txt
```

Use LinkFinder and SecretFinder as the primary extraction pass. Fall back to manual grep
for edge cases they miss (inline scripts, dynamically loaded chunks, non-standard patterns).

- API calls: fetch(), axios, XHR, $.ajax patterns
- SPA routes: React `path="/..."`, Vue `{ path: }`, Angular `{ path: }`
- Secrets: api_key, token, secret, password assignments; AWS `AKIA[A-Z0-9]{16}`; JWT `eyJ...`
- Webpack: chunk manifest, chunk URLs, `window.__INITIAL_STATE__`
- Infer more than strings: auth role checks, feature flags, internal-only branches, tenant IDs,
  object naming patterns, callback routes, proxy base paths, and debugging toggles.

### 4. CSS Analysis
Extract `url()` refs, `@import` paths, source map refs.

### 5. API Schema Discovery
Probe: /swagger.json, /openapi.json, /api-docs, /graphql (introspection), /application.wadl

If an OpenAPI / Swagger spec is accessible, ingest it into the canonical backend assessment state.
The local queue can still be populated as a transient batching aid, but the operator contract is
the backend ledger:

```bash
curl -sL "https://TARGET/openapi.json" -o /engagement/scans/openapi.json
./scripts/spec_ingest.sh "$ENGAGEMENT_DIR/cases.db" "$ENGAGEMENT_DIR/scans/openapi.json"
./scripts/dispatcher.sh "$ENGAGEMENT_DIR/cases.db" stats
```

This creates durable request/service coverage candidates and, when the local buffer is in use,
`api-spec` work items that should be routed to `vulnerability-analyst`.

### 6. Source Map Analysis
Fetch .map → extract `sources` array → reconstruct original source for analysis.

### 7. Hypothesis Promotion

- Hidden admin or support routes: verify whether they sit behind a weaker trust boundary than the main app.
- Role checks in frontend only: test for direct API access before assuming server-side enforcement exists.
- Config and environment leakage: stage proof from low-noise disclosure toward decisive impact.
- Multiple API bases or internal hostnames: look for chainable pivots into different services or auth realms.

## Priority Order

1. Secrets and tokens (immediate high-value)
2. API endpoints not found by fuzzing
3. Frontend routes revealing app structure
4. Hidden form fields and debug endpoints
5. Source maps and debug artifacts
