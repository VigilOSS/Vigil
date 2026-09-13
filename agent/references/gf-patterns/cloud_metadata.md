---
name: gf-patterns:cloud_metadata
description: Cloud instance-metadata (IMDS) SSRF probe signatures — AWS/Azure link-local address, GCP metadata host, IMDS paths, and obfuscated address forms
origin: local overlay (no upstream gf equivalent)
bucket: cloud_metadata
skill: ssrf-testing
weight: 40
---

# gf: cloud_metadata

## What this bucket classifies

URLs that embed a cloud instance-metadata-service (IMDS) target — the literal that an
SSRF-to-IMDS payload uses to pivot from a vulnerable fetcher to the instance credential
endpoint (Capital-One-class breach). The signal is not a parameter NAME (any `url=`-style
param is the `ssrf` bucket's job); it is the metadata ENDPOINT itself appearing in a query
value, host, or path — typically a proof URL captured in archived/historical data or sitting
in a request parameter. It maps to the canonical `ssrf` class.

## Load this reference when

- A captured URL contains the AWS/Azure link-local IMDS address `169.254.169.254`, the GCP
  metadata host `metadata.google.internal`, or an IMDS path (`/latest/meta-data`,
  `/computeMetadata`, `/metadata/instance`)
- A URL carries an obfuscated form of the link-local address — decimal `2852039166` or
  hex `0xA9FEA9FE` — which evades naive `169.254.169.254` string filters
- Operator is reviewing an SSRF surface (`ssrf` co-fired) and needs to confirm whether a
  metadata-endpoint pivot has already been proven in the corpus

## Parameter keys that match

None. `cloud_metadata` is a regex-only bucket with an **empty key set** — it never matches on
a parameter name. A bare URL-fetch parameter such as `?url=` or `?uri=` is the `ssrf` bucket's
signal; `cloud_metadata` fires only when the IMDS target literal is present (see below).

## Path patterns that match

None as literal path fragments. `cloud_metadata` carries an **empty path-fragment tuple**; its
only signal is the alternation in `_REGEX_BUCKET_RULES["cloud_metadata"]`:

```
169\.254\.169\.254          # AWS / Azure link-local IMDS address
metadata\.google\.internal  # GCP metadata server hostname
/latest/meta-data           # AWS IMDS path
/computeMetadata            # GCP IMDS path
/metadata/instance          # Azure IMDS path
0x[aA]9[fF][eE][aA]9[fF][eE] # obfuscated hex form of 169.254.169.254 (0xA9FEA9FE)
\b2852039166\b              # obfuscated decimal form of 169.254.169.254
```

These regexes are applied **twice**: `bucket_matches` runs them against the `url_path` (so the
path-form IMDS literals `/latest/meta-data`, `/computeMetadata`, `/metadata/instance` fire on
the path alone), and because the address most often sits in a **query value or host** rather
than the path, `cloud_metadata` is also listed in `_FULL_URL_REGEX_BUCKETS` so `classify_row`
re-runs the same rules against the **full `url`** (authority + query string) and appends the
bucket, deduped against a path-side hit.

Regex guard notes: unlike literal fragments, regex rules are **not** boundary-wrapped by the
matcher — each pattern supplies its own anchoring (`\b` word boundaries on the numeric forms,
explicit `\.` on the dotted address and host). Matching is effectively case-insensitive because
the haystack is lowercased before search and the hex pattern itself spells both cases
(`0x[aA]9[fF][eE][aA]9[fF][eE]`). The full-URL pass is **boost-only**: when `url` is absent (the
default-kwarg test convention) the supplementary pass is skipped entirely, so any no-context
call stays byte-identical and the bucket can only RAISE a score or add a reason-chain entry,
never reorder an existing chain.

## Weight and priority interpretation

- Baseline priority score: 40
- Tied with `ssrf` (40); `cloud_metadata` is declared AFTER `ssrf` in `_BUCKETS`, so a co-fire
  on a shared weight-40 SSRF surface keeps the existing `ssrf` cluster by the
  first-at-max-weight tie-break, with `cloud_metadata` additively recorded in the reason chain
- Terminal reasons that suppress this bucket: `inert_type` (image/video/font/archive are
  skipped at ingest before classification runs)

## Example URLs that match

- `https://target.example/image-proxy?src=http://169.254.169.254/latest/meta-data/iam/security-credentials/` — AWS IMDS credential probe in a fetch param
- `https://target.example/api/fetch?url=http://metadata.google.internal/computeMetadata/v1/` — GCP metadata server pivot
- `https://target.example/proxy?uri=http://169.254.169.254/metadata/instance?api-version=2021-02-01` — Azure IMDS pivot
- `https://target.example/render?target=http://0xA9FEA9FE/latest/meta-data/` — hex-obfuscated link-local address evading naive `169.254.169.254` filters
- `https://target.example/load?u=http://2852039166/latest/meta-data/` — decimal-obfuscated link-local address

## What it does NOT classify

- A bare URL-fetch parameter (`?url=`, `?uri=`, `?next=`) with no IMDS literal — that is the
  `ssrf` bucket; `cloud_metadata` only adds signal once the metadata target itself appears
- A legitimate `169.254.0.0/16` link-local reference that is NOT the IMDS address — only the
  exact `169.254.169.254` (and its decimal/hex encodings) match; neighbouring link-local
  addresses do not
- Internal/RFC-1918 SSRF targets (`127.0.0.1`, `10.x`, `192.168.x`, `localhost`) — those are
  general SSRF surfaces routed through `ssrf`, not the cloud-metadata bucket

## Attack classes

- **IMDSv1 credential theft:** an SSRF that reaches `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` on an IMDSv1 instance returns temporary IAM keys with the instance role's permissions (the Capital One pattern)
- **GCP service-account token exfiltration:** `GET http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` (with the `Metadata-Flavor: Google` header) returns an OAuth token
- **Azure managed-identity token theft:** `GET http://169.254.169.254/metadata/instance` and the `/oauth2/token` identity endpoint expose managed-identity credentials
- **WAF/filter bypass via address obfuscation:** decimal (`2852039166`) and hex (`0xA9FEA9FE`) encodings of the link-local address defeat string-equality blocklists while still resolving to the IMDS endpoint

## Corpus grounding

This is proactive generic coverage for engagements where an archived or proof URL embeds an IMDS
pivot. The full-URL matcher is required because the metadata marker usually lives in a query value
or authority rather than the request path. See ADR 0008, `DRIFT.md`, and the focused classifier
regressions for the accepted rationale.

## Sources

- [AWS — Instance Metadata Service (IMDS) and IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html) — `169.254.169.254` / `/latest/meta-data`, IMDSv2 hardening
- [GCP — Storing and retrieving instance metadata](https://cloud.google.com/compute/docs/metadata/overview) — `metadata.google.internal` / `/computeMetadata/v1`
- [Azure — Instance Metadata Service](https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service) — `169.254.169.254/metadata/instance`
- [Capital One 2019 SSRF-to-IMDS breach](https://www.capitalone.com/digital/facts2019/) — the canonical real-world cloud-metadata SSRF incident this bucket models
- [PayloadsAllTheThings SSRF — Cloud metadata](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Server%20Side%20Request%20Forgery#cloud-instances) — payload library including obfuscated address forms

## Related

- `agent/references/gf-patterns/ssrf.md` — the parent SSRF bucket; `cloud_metadata` is the IMDS-specific reinforcement that co-fires on a proven metadata pivot
- `agent/references/gf-patterns/object-storage.md` — sibling full-URL regex bucket (`_FULL_URL_REGEX_BUCKETS`) matching cloud-storage host markers
- `agent/skills/ssrf-testing/SKILL.md` — the follow-up test skill once an SSRF/metadata surface is identified
- `agent/references/payloads/ssrf-payloads.md` — payload library, including IMDS and obfuscated-address payloads
