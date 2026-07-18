---
description: Secret scanner (filesystem mode, 800+ detectors, v3 positional-path syntax, `--no-verification` default)
skill: source-analysis
---

# TruffleHog

**Purpose:** Scan files, directories, git repositories, and live services for secrets,
tokens, API keys, and credentials. v3 ships 800+ detectors and can optionally verify
discovered secrets by making live API calls.

**In this repo**: primary secret scanner for stored HTTP response bodies. The `vigil assess gau secrets` wrapper composes gau → uro → httpx body capture → trufflehog filesystem mode in one verb (default `--no-verification`; pass `--verify` to enable verification). For ad-hoc scans against existing artifacts, invoke via `vigil assess kali exec --technique INFO-DISCLOSURE --intent "<why>" --probe-kind fingerprint --phase <phase> --timeout <seconds> -- trufflehog ...` with the standard audit-flag set; never from host-side bash against in-scope artifacts.

## CLI syntax (v3)

Scan paths can be passed positionally (preferred for single-path scans) or via
`--directory=PATH` (repeatable, v3 also supports it). The `--path` flag from older
pipelines does not exist in v3.

```bash
# Filesystem (directory tree or single file) — positional
trufflehog filesystem /path/to/scan --json

# Multiple paths — positional
trufflehog filesystem /path/one /path/two --json

# Equivalent via --directory (useful when scripting from config)
trufflehog filesystem --directory=/path/one --directory=/path/two --json

# Git repository on disk
trufflehog git file:///path/to/repo --json

# GitHub repository (makes API calls)
trufflehog github --repo https://github.com/org/repo --json
```

## Key flags

| Flag | Effect |
|---|---|
| `--json` (`-j`) | Structured NDJSON output (one finding per line) |
| `--no-update` | Skip version-check network call — faster, offline-safe |
| `--no-verification` | Do **not** attempt to verify detected secrets against third-party APIs. **Default in `gau secrets`.** |
| `--results=RESULTS` | Comma-separated filter: `verified,unverified,unknown,filtered_unverified`. Use `--results=verified` to report only confirmed-live secrets (triggers external HTTP). Default: `verified,unverified,unknown`. |
| `--include-detectors=<list>` | Comma-separated detector names/IDs or `all` |
| `--exclude-detectors=<list>` | Skip noisy detectors (takes precedence over include) |
| `--concurrency=N` | Worker count (default 4) |
| `--filter-unverified` | Output only first unverified result per chunk per detector |
| `--filter-entropy=N` | Shannon-entropy filter for unverified results (start with 3.0) |
| `--archive-max-depth=N` | Recursion into zips/tarballs |
| `--fail` | Exit with code 183 when results are found (useful in CI) |

## Verification — watch the traffic

Live verification (enabled by default, or explicitly via `--results=verified`) makes
**external HTTP requests**. TruffleHog submits discovered tokens to AWS STS, GitHub API,
Slack, Stripe, and hundreds of other services to check validity. That traffic:

- Leaves the Kali runtime and hits third-party infrastructure
- Is out-of-scope for most authorized engagements
- Can get tokens blacklisted or rate-limited upstream
- May log IP/token pairs on the vendor side

**Default posture in this repo**: `--no-verification`. Opt into `--results=verified` only
when the engagement's `exploit_policy` and scope explicitly cover external validation
traffic, and record the decision via `vigil assess log operator "trufflehog verification opt-in" "<command>" "<scope/policy justification>"` (activity_entries).

## Output shape (JSON mode)

Each line is one finding:

| Key | Meaning |
|---|---|
| `DetectorName` | e.g. `"AWS"`, `"Stripe"`, `"GitHub"`, `"JWT"` |
| `DetectorType` | Numeric enum (less useful than `DetectorName`) |
| `Verified` | Boolean — `true` only when `--no-verification` is **not** set and the check succeeded |
| `VerificationError` | Present when verification attempted but failed (non-2xx or network error) |
| `Raw` | Raw secret string as matched |
| `RawV2` | Second capture group if the detector uses one |
| `Redacted` | Partially masked version (safe for logs) |
| `SourceMetadata.Data.Filesystem.file` | File where the secret was found |
| `SourceMetadata.Data.Filesystem.line` | Line number |
| `ExtraData` | Detector-specific context (e.g. IAM ARN for AWS) |

## jq one-liners

```bash
# Count findings by detector
jq -r '.DetectorName' results.json | sort | uniq -c | sort -rn

# All verified hits
jq 'select(.Verified==true)' results.json

# Compact review row
jq -r '"\(.DetectorName)\t\(.SourceMetadata.Data.Filesystem.file)\t\(.Raw[0:120])"' results.json

# Group by file
jq -r '.SourceMetadata.Data.Filesystem.file' results.json | sort | uniq -c | sort -rn
```

## Detector coverage (selected)

Cloud: AWS (IAM, STS, S3, SSM), GCP (service accounts, API keys, OAuth), Azure (AD, Storage, DevOps).
SaaS: Stripe, Twilio, SendGrid, Mailgun, Slack, Discord, Okta, PagerDuty.
Source control: GitHub (PAT, OAuth, app), GitLab, Bitbucket.
Backends: MongoDB Atlas, Firebase, Supabase, PostgreSQL URIs, MySQL URIs, Redis URIs.
Crypto: JWT, PGP private keys, SSH private keys, PKCS, certificates.
Full list: `trufflehog --help` or upstream detector index.

## Why TruffleHog over regex/grep

- Context-aware detectors reduce false positives from string-shaped noise
- Optional live validation (when in scope) eliminates stale-credential FPs
- Handles base64, hex, and gzip-encoded secrets where raw grep misses
- Structured JSON makes downstream triage scriptable with `jq`

## Gotchas

- Verification is enabled by default. Always explicitly pass `--no-verification` in batch
  pipelines unless external traffic is authorized.
- `--no-update` avoids a blocking HTTPS call to GitHub releases on every run — always set
  it in engagement pipelines.
- Large response-body corpora (GB-scale) benefit from `--concurrency=16` on fat runtimes;
  default (`4`) is fine for typical stored-response sets.
- `--only-verified` does **not** exist in v3 filesystem mode. Use `--results=verified`.
- `Raw` contains the actual secret. Do **not** upload raw results to untrusted sinks; keep
  them in `$DIR/scans/gau-pipeline/<target>/<cache_key>/` (where `gau secrets` writes
  `trufflehog.json` namespaced per target + gau-flag-set).
