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
- `trufflehog` — scan saved JS/source-map artifacts through `aith assess kali exec --` (host-side installs
  aren't required; the runtime image ships trufflehog)
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

Write the grep pattern to a temp file to avoid shell-quoting issues, then run via `aith assess kali exec`:

```bash
# Host-side: write the extraction script to a file inside the engagement dir
cat > "$ENGAGEMENT_DIR/scans/js_grep.sh" << 'SCRIPT'
#!/bin/sh
curl -sL "$1" | grep -oE '["\x27](/[a-zA-Z0-9_/\-\.]+)["\x27]' | sort -u
SCRIPT
chmod +x "$ENGAGEMENT_DIR/scans/js_grep.sh"

# Run via audit-wrapped exec
aith assess kali exec --technique DISCOVERY \
  --intent "manual JS endpoint grep for inline route strings" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c \
  '/engagements/$ENGAGEMENT_KEY/scans/js_grep.sh <js-url>'
```

#### Automated JS Endpoint Extraction

```bash
# LinkFinder — extract endpoints from JS (far more thorough than manual grep on minified code)
aith assess kali exec --technique DISCOVERY \
  --intent "LinkFinder endpoint extraction from app.js" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  python3 linkfinder.py -i https://TARGET/static/js/app.js -o cli

# Batch all JS files discovered in step 1
aith assess kali exec --technique DISCOVERY \
  --intent "LinkFinder batch endpoint extraction from all JS files" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
for js_url in $(cat /engagements/$ENGAGEMENT_KEY/scans/js_files.txt); do
  python3 linkfinder.py -i "$js_url" -o cli
done | sort -u > /engagements/$ENGAGEMENT_KEY/scans/js_endpoints.txt
'

# SecretFinder — scan for API keys, tokens, credentials in JS
aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "SecretFinder secret scan on app.js" \
  --probe-kind fingerprint --phase recon --timeout 300 -- \
  python3 SecretFinder.py -i https://TARGET/static/js/app.js -o cli

# Batch scan
aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "SecretFinder batch secret scan across all JS files" \
  --probe-kind fingerprint --phase recon --timeout 600 -- bash -c '
for js_url in $(cat /engagements/$ENGAGEMENT_KEY/scans/js_files.txt); do
  python3 SecretFinder.py -i "$js_url" -o cli
done | sort -u > /engagements/$ENGAGEMENT_KEY/scans/js_secrets.txt
'
```

Use LinkFinder and SecretFinder as the primary extraction pass. Fall back to manual grep
for edge cases they miss (inline scripts, dynamically loaded chunks, non-standard patterns).
When scanning saved artifacts for secrets, invoke `trufflehog filesystem` via
`aith assess kali exec --technique INFO-DISCLOSURE --intent "secret scan on saved JS/source-map artifacts" --probe-kind fingerprint --phase recon --timeout 600 -- trufflehog filesystem ...`
against `/engagements/$ENGAGEMENT_KEY/...` paths so the runtime-owned install is used consistently
and the run lands in the audit pipeline.

For code-analysis engagements, remember that `aith assess code-ingest` skips generated/minified
build output by default while writing a skipped-artifacts manifest under
`tools/analysis-state/skipped-artifacts/`. If a browser-visible minified bundle is security-relevant,
prefer the source equivalent or source map for deep review; if neither exists, ask the operator to
rerun `code-ingest` with a targeted `--include-path` / `--include-minified` include so the bundle is
explicitly queued rather than silently absent from backend `code/files`.

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
aith assess kali exec --technique DISCOVERY \
  --intent "fetch OpenAPI spec for spec ingestion" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  curl -sL "https://TARGET/openapi.json" -o /engagements/$ENGAGEMENT_KEY/scans/openapi.json
# Host-side: ingest the downloaded spec into the backend work buffer
aith assess ingest-spec "$ENGAGEMENT_DIR/cases.db" "$ENGAGEMENT_DIR/scans/openapi.json"
aith assess work-buffer "$ENGAGEMENT_DIR/cases.db" stats
```

This creates durable request/service coverage candidates and, when the local buffer is in use,
`api-spec` work items that should be routed to `vulnerability-analyst`.

### 6. Source Map Analysis
Fetch .map → extract `sources` array → reconstruct original source for analysis.

### 6a. APP_VERSION / BUILD_HASH / Sentry-release Extraction

When a vendor product has been fingerprinted from the recon pass, source-maps and minified
bundles routinely inline build-time constants that pin the deployed version to a specific
patch level. Extracting these constants is a precondition for accurate CVE matching —
osint-analyst's exact-version triangulation cross-checks them against package-registry
sister-version dates and vendor changelogs. A version inferred from feature flags alone
is too loose for CVE work.

Grep patterns to run against fetched bundles, source-maps, and inline scripts:

```bash
# Constants commonly inlined by webpack DefinePlugin / Vite define / build scripts
grep -EHn 'APP_VERSION|__APP_VERSION__|BUILD_HASH|__BUILD_HASH__|__GIT_SHA__|__BUILD_VERSION__' \
  /engagements/$ENGAGEMENT_KEY/downloads/*.js \
  /engagements/$ENGAGEMENT_KEY/downloads/*.js.map

# Sentry release-tag — pinned to git tag or short SHA in production builds
grep -EHn 'Sentry\.init\([^)]*release:|process\.env\.SENTRY_RELEASE|SENTRY_RELEASE' \
  /engagements/$ENGAGEMENT_KEY/downloads/*.js \
  /engagements/$ENGAGEMENT_KEY/downloads/*.js.map

# package.json fragments are sometimes inlined at the bottom of bundles
grep -EHn '"version"\s*:\s*"[0-9]+\.[0-9]+\.[0-9]+' /engagements/$ENGAGEMENT_KEY/downloads/*.js
```

When a value is found, hand it to osint-analyst as part of the `#### Intelligence` output
so the triangulation step in `agent/skills/osint-recon/SKILL.md` (Exact-version
triangulation) can cross-reference package-registry sister-version dates and confirm the
exact patch level. Per-vendor mapping examples live in
`agent/references/payloads/version-fingerprint-probes.md`.

### 6b. Vendor-product CSP / CORS re-baseline + deep-enum handoff

When the source-map fingerprint or the `sources[]` paths inside the .map files (or the
package-name strings in `chunk-vendors.<hash>.js`) match a vendor product — e.g.,
`@salesforce/lightning-design-system`, `@servicenow/sn-*`, Drupal core modules under
`core/misc/drupal*.js`, or Pexip's `pexrtc.js` — fire two follow-on probes before
returning. The fingerprint match is the trigger for both probes; without it, neither
fires from a generic SPA bundle.

#### Vendor-product CSP / CORS re-baseline

Re-pull the page's response headers and grep for the vendor's installer-template
placeholder literals. Vendor products ship with permissive CSPs and operators are
expected to harden them; a placeholder surviving into production confirms the operator
did not run the vendor's hardening checklist.

```bash
aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "vendor-product CSP/CORS re-baseline header capture" \
  --probe-kind fingerprint --phase recon --timeout 30 -- \
  curl -sSI 'https://TARGET/' \
  > /engagements/$ENGAGEMENT_KEY/scans/headers_TARGET.txt

aith assess kali exec --technique INFO-DISCLOSURE \
  --intent "vendor-product placeholder + unsafe-inline/eval grep" \
  --probe-kind payload --phase recon --timeout 60 -- bash -c '
  grep -inE "example\.(com|org|net|test)|domain-here\.tld|your-domain\.tld|placeholder|REPLACE_ME|TODO|FIXME|localhost|127\.0\.0\.1|::1" \
    /engagements/$ENGAGEMENT_KEY/scans/headers_TARGET.txt
  grep -iE "script-src[^;]*unsafe-inline[^;]*unsafe-eval|script-src[^;]*unsafe-eval[^;]*unsafe-inline" \
    /engagements/$ENGAGEMENT_KEY/scans/headers_TARGET.txt
'
```

Match against `Content-Security-Policy`, `Access-Control-Allow-Origin`, `Feature-Policy`,
`Permissions-Policy`, and `X-Frame-Options`. Full per-vendor default snippets (Salesforce
Communities, ServiceNow, Drupal, Pexip, Cisco appliance) and the sweep helper live in
`agent/references/payloads/csp-default-grep.md`. When one placeholder fires, retrieve the
vendor's published "production hardening checklist" and verify whether the deployment
fails three or more items — the lesson is "the operator skipped the hardening pass," not
the specific directive.

#### Vendor-platform deep-enumeration handoff

When the fingerprint matches a vendor multi-tenant platform AND any anonymous read
primitive surfaces from the source analysis (a route the bundle calls without
`Authorization`, a hardcoded admin path, an exposed `getRecordWithFields` endpoint), the
**same dispatch** must run the matching deep-enum playbook from
`agent/skills/vendor-platform-enum/SKILL.md`. The four playbooks (Salesforce Aura,
ServiceNow GlideRecord, Drupal JSON:API, Pexip admin API) each chain namespace
enumeration, tenant-singleton reads, chain-walks, and IDOR boundedness tests; stopping at
the first leak misses the full anonymous-readable namespace that the vendor template
exposed.

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

## Supply Chain Checks

- [ ] Identify internal/private package names from exposed manifests or JS source maps
- [ ] Check if private package names exist on public registries (npm, PyPI, RubyGems)
- [ ] Look for typosquatting candidates: common misspellings of popular packages in dependency lists
- [ ] Check for scoped vs unscoped npm packages — `@company/pkg` vs `company-pkg`
- [ ] Check for lockfile manipulation: does the app use lockfiles for reproducible builds?
- [ ] Verify that `package-lock.json` registry URLs point to expected registries (not attacker-controlled)
- [ ] Check for mixed registries in lockfiles (public + private pointing to wrong source)
- [ ] Verify CDN-loaded scripts/styles have `integrity` attributes (SRI)
- [ ] Check if `<script>` tags loading from third-party domains use SRI hashes
- [ ] Test if missing SRI allows content injection via compromised CDN

## Output Contract

The skill produces these structured sections in the source-analyzer's return payload.
Backend writes (`record-finding`, `record-intel`, `record-surface`,
`ingest-endpoints`, `aith assess agent handoff`) are the durable record; this contract names what
each markdown section should hold so downstream specialists can parse the output
consistently.

| Section | Holds |
|---|---|
| `#### Summary` | One-paragraph headline: bundles analyzed, route count extracted, secret-scan hits, vendor-platform fingerprint hits, app-version pinned. |
| `#### Findings` | Decisive findings the source pass already proved (e.g., a live API key with non-empty value, a secret string verified against a third-party endpoint). Each must also be recorded via `aith assess record-finding`. |
| `#### Surface Candidates` | Requestable endpoints, API bases, hidden routes, GraphQL endpoints, admin paths extracted from JS / source maps / inline config — each surfaced via `aith assess record-surface` and ingested via `aith assess ingest-endpoints "$DIR/cases.db" source-analysis`. |
| `#### Secrets` | Secret-scan hits (API keys, JWT samples, AWS access-key prefixes, internal hostnames, tokens) with confidence and matched pattern. Confirmed-live secrets escalate to `#### Findings`; unverified hits stay here as leads. |
| `#### Backend Hypotheses` | Inferred backend shape from frontend evidence — auth role checks, feature flags, internal-only branches, tenant IDs, callback routes, proxy base paths, debugging toggles. Drives the next-step list for vulnerability-analyst dispatch. |
| `#### Intelligence` | Tech components from bundle fingerprinting, vendor-product fingerprints (Salesforce / ServiceNow / Drupal / Pexip), APP_VERSION / BUILD_HASH / Sentry-release constants for osint-analyst triangulation, vendor-template CSP / CORS placeholder hits — each row landed via `aith assess record-intel <type>`. |
| `#### Coverage Gaps` | Bundles too minified to analyze, files behind auth, source-maps not present, vendor-platform deep-enum trigger fired but the matching playbook could not run. The operator reads this section to decide whether to re-dispatch. |

## Extended Resources

- `agent/references/payloads/info-disclosure-probes.md` — standard probe endpoints, metadata paths, and environment file paths
- `agent/references/tools/exploitation/dalfox.md` — for JS-discovered parameterized URLs that may be XSS candidates
