# Vendor Exact-version Fingerprint Probes

When osint-analyst needs an exact patch level for CVE matching, version-only
inferred ranges are insufficient — a backported security patch keeps a
nominally-old major running while sister-package fingerprints reveal the
precise patch level. This file carries the curl + jq probes plus per-vendor
mapping examples that `agent/skills/osint-recon/SKILL.md` references from its
"Exact-version triangulation" section.

All HTTP probes wrap in `vigil assess kali exec` so the run lands in the
audit pipeline. Place every audit flag (`--technique`, `--intent`,
`--probe-kind`, `--phase`, `--timeout`) BEFORE the trailing `-- bash -c
'...'` — flags after the heredoc are passed to bash itself and silently
dropped by vigil. Use neutral hostnames (`example.test`) in examples.

## 1. Source-map Bundle Constants

Source-maps and minified bundles routinely inline `APP_VERSION`, `BUILD_HASH`,
`__GIT_SHA__`, and Sentry release tags. The grep recipes live in
`agent/skills/source-analysis/SKILL.md` § "APP_VERSION / BUILD_HASH /
Sentry-release extraction"; this file picks up where source-analyzer hands
off the discovered constants to osint-analyst.

A typical handoff payload:

```
APP_VERSION = "2.7.4"
BUILD_HASH = "a1b2c3d4"
SENTRY_RELEASE = "frontend@2.7.4-rc3"
```

These three values feed the cross-checks below.

## 2. npm Registry Probe

Vendors that ship JS libraries from a monorepo publish sister packages on the
same release day. Querying the registry's `time` field per version is the
most reliable cross-check.

```bash
vigil assess kali exec --technique OSINT --intent "npm registry probe for <pkg>@<version>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://registry.npmjs.org/<pkg>/<version>" \
    | jq "{name, version, dist_tags: ._npmUser, dependencies, time: ._npmVersion}"
'

# All-version timeline including publish dates per version
vigil assess kali exec --technique OSINT --intent "npm publish timeline for <pkg>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://registry.npmjs.org/<pkg>" | jq ".time"
'
```

Cross-check: if `<pkg>@<version>` and `<sister-pkg>@<sister-version>` were
published on the same day, the deployed app almost certainly bundles both at
those exact versions — a stronger signal than feature-flag inference.

## 3. PyPI Registry Probe

```bash
vigil assess kali exec --technique OSINT --intent "PyPI registry probe for <pkg>==<version>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://pypi.org/pypi/<pkg>/<version>/json" \
    | jq "{name: .info.name, version: .info.version, requires_dist: .info.requires_dist, urls: [.urls[] | {filename, upload_time}]}"
'

# All-version metadata
vigil assess kali exec --technique OSINT --intent "PyPI publish timeline for <pkg>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://pypi.org/pypi/<pkg>/json" \
    | jq "[.releases | to_entries[] | {version: .key, upload_time: (.value[0].upload_time // \"unknown\")}]"
'
```

`upload_time` per release file is the source of truth for the publish date.

## 4. Maven Central Probe

```bash
vigil assess kali exec --technique OSINT \
  --intent "Maven Central probe for <group>:<artifact>:<version>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://search.maven.org/solrsearch/select?q=g:<group>+AND+a:<artifact>+AND+v:<version>&wt=json&rows=20" \
    | jq ".response.docs[] | {g, a, v, timestamp, ec}"
'

# All known versions for an artifact
vigil assess kali exec --technique OSINT \
  --intent "Maven Central version timeline for <group>:<artifact>" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s "https://search.maven.org/solrsearch/select?q=g:<group>+AND+a:<artifact>&wt=json&core=gav&rows=200" \
    | jq "[.response.docs[] | {v, timestamp}] | sort_by(.timestamp)"
'
```

The `timestamp` field is a Unix-millis epoch — convert with
`date -u -r $((TS / 1000))` to compare against vendor changelog dates.

## 5. Sentry Release-tag Recipes

Sentry release tags are pinned to a build's git tag or short SHA in
production. After source-analyzer extracts the literal `release: "..."` value,
cross-reference it against the vendor's public tag list:

```bash
# When the release tag matches a git ref in a public mirror
vigil assess kali exec --technique OSINT --intent "Resolve Sentry release tag to git SHA" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/<vendor-mirror>/<repo>/git/refs/tags/<release-tag>" \
    | jq "{ref, sha: .object.sha, url: .object.url}"
'

# Resolve a short SHA inside a public repo
vigil assess kali exec --technique OSINT --intent "Resolve Sentry release short SHA" \
  --probe-kind fingerprint --phase recon --timeout 60 -- bash -c '
  curl -s -H "Authorization: Bearer $GITHUB_TOKEN" \
    "https://api.github.com/repos/<vendor-mirror>/<repo>/commits/<short-sha>" \
    | jq "{sha, commit: .commit.message, date: .commit.author.date}"
'
```

A confirmed git SHA fixes the deployed code at a specific commit, which is
strictly more precise than any version string.

## 6. Per-vendor Mapping Examples

The triangulation pattern is the same regardless of vendor. The examples
below are illustrative; in every case the source-map APP_VERSION is the
primary signal, sister-package publish dates are the secondary cross-check,
and the vendor changelog plus Sentry release tag are the tertiary
disambiguators.

### Pexip-style video conferencing platform

```
Step 1 — Source-map APP_VERSION extraction (handed off from source-analyzer):
    APP_VERSION = "32.5.1"
    BUILD_HASH  = "df88e7a"

Step 2 — npm sister-package probe for the bundled SDK:
    curl -s https://registry.npmjs.org/<vendor-sdk>/32.5.1
    -> time field: 2025-07-14T11:22:00Z

Step 3 — Vendor public release notes for v32.5.1:
    -> "Released 2025-07-14. Includes patches for CVE-2025-XXXXX..."

Step 4 — Vendor security bulletin cross-check:
    -> "v32.5.1 patches CVE-2025-XXXXX; v32.5.0 is unaffected by CVE-2025-YYYYY"

Triangulated conclusion: deployed version is exactly 32.5.1, patched against
CVE-2025-XXXXX, vulnerable to no published advisory in the 32.5.x branch.
```

### Salesforce-style multi-tenant SaaS

Salesforce's exact orgs run a vendor-controlled release train; the deployed
release is fingerprinted from the Aura framework's bundle hash plus the
release-name string in the page chrome.

```
Step 1 — Source-map APP_VERSION:
    APP_VERSION = "260.18"  (Spring '26 patch 18)

Step 2 — Vendor release calendar:
    -> "Spring '26 patch 18 deployed 2026-03-21 to Pod NA113"

Step 3 — Vendor security advisory cross-check for Spring '26 line:
    -> "Patches 1 through 17: vulnerable to CVE-2026-XXXXX"
    -> "Patch 18 ships the fix"

Conclusion: deployed pod is on patch 18 → CVE-2026-XXXXX no longer applies.
```

### ServiceNow-style platform

```
Step 1 — Source-map BUILD_HASH:
    __GIT_SHA__ = "tokyo-glide-q3-2025-patch4"

Step 2 — Vendor changelog cross-check:
    -> "Tokyo Glide Q3 2025 Patch 4 deployed 2025-10-08"

Step 3 — npm sister-package probe for vendor SDK:
    -> "<vendor-sdk>@7.4.4 published 2025-10-08T16:00:00Z"

Conclusion: instance is on Tokyo Glide Q3 2025 Patch 4.
```

### Drupal-style CMS

```
Step 1 — Bundle inline:
    Drupal.version = "10.2.6"

Step 2 — packagist (composer) sister-package probe:
    curl -s https://repo.packagist.org/p2/drupal/core.json
    -> "10.2.6 published 2025-04-02"

Step 3 — Vendor security advisory:
    -> "10.2.5 vulnerable to SA-CORE-2025-XXX"
    -> "10.2.6 ships the patch"

Conclusion: deployed Drupal core is exactly 10.2.6 → SA-CORE-2025-XXX
patched.
```

## 7. Triangulation Output Format

Hand back to the operator (and on to exploit-developer for validation):

```
Vendor product: <vendor>/<product>
Source-map APP_VERSION: <value>
Source-map BUILD_HASH:  <value>
Sentry release tag:     <value> (-> git SHA <sha>)
Sister-package signals:
  - npm <pkg>@<v> published <date>
  - pypi <pkg>==<v> published <date>
Vendor changelog cross-check: <release-name> matches publish-date
Confirmed exact version: <version>
CVEs in scope after patch-line check:
  - CVE-XXXX-YYYYY (applicable)
  - CVE-XXXX-ZZZZZ (NOT applicable, patched in <version>)
```

This payload feeds `vigil assess record-intel cve <json>` (one call per
applicable CVE) and a follow-up exploit-developer dispatch for live
validation before any CVE becomes a durable finding.

## Cross-references

- `agent/skills/osint-recon/SKILL.md` — methodology section "Exact-version triangulation"
- `agent/skills/source-analysis/SKILL.md` — APP_VERSION / BUILD_HASH / Sentry-release extraction grep recipes
- `agent/references/tools/recon/github-osint.md` — GitHub API for resolving Sentry tags to git SHAs
