---
name: cloud-exposure
description: Exposed cloud storage triage — S3/GCS/Azure buckets, severity escalation, swarm-dispatch over corpus
origin: Vigil
vuln_class: info-disclosure
---

# Cloud Exposure Investigation

## Reality Check

A public bucket is not automatically critical. Severity rides on **what is in the bucket** and **what infrastructure points at it**, not on the existence of the bucket. A public bucket of CSS sprites used as a CDN is informational; a public bucket of `.env` files, source repos, or backup tarballs is critical. This skill is about working through the blast radius systematically rather than recording an estimated severity from the listing alone.

## When to Activate

- A bucket listing is publicly accessible (S3 `?list-type=2`, GCS XML listing, Azure `?comp=list`).
- A domain or subdomain CNAMEs to a bucket endpoint and the bucket is browseable.
- Recon discovered references to bucket names in HTML / JS source / DNS history that resolve to live buckets.
- A subdomain takeover candidate sits on bucket infrastructure (dangling CNAME → a bucket that returns `NoSuchBucket`) — treat this as a *screening* signal to work claimability through Step 2, not as a finding on its own (see `agent/references/subdomain-takeover.md`).
- During code analysis, hard-coded bucket names point to buckets you can reach unauthenticated.

## Tools

All through `vigil assess kali exec` (`--technique OSINT` for discovery, `INFO-DISCLOSURE` for
listing and sampling):

- `cloud_enum -k <keyword>` **discovers** bucket/blob/host names across AWS, Azure and GCP from a
  brand/product keyword (mutates it against a built-in fuzz list; beats hand-guessing names).
- `s3scanner -bucket <name>` (or `-bucket-file`) reports existence, region and per-grant ACL
  (READ/WRITE/READ_ACP/WRITE_ACP) without credentials; `bucket_not_found` is a takeover
  screening signal, not a verdict (`agent/references/subdomain-takeover.md`).
- `aws s3 ls|cp s3://<bucket> --no-sign-request` — the runtime holds no AWS credentials, so a
  signed call fails with `NoCredentials`; signed calls run host-side via
  `vigil assess host-exec --tool aws` (`agent/skills/aws-iam-privesc/SKILL.md`).
- GCS and Azure have no CLI in the image: list anonymously over HTTPS with curl
  (`https://storage.googleapis.com/<bucket>?prefix=`,
  `https://<account>.blob.core.windows.net/<container>?restype=container&comp=list`).
- `trufflehog filesystem <dir>` over the downloaded sample (a local copy, no target traffic).
- Corpus-scale source review is proposed to the operator as a swarm in `next_steps` (Step 4).

---

## Investigation Procedure

Do these steps in order. Skipping ahead (e.g. recording severity from the listing alone) is exactly the failure mode this skill prevents. Step 0 is the discovery pass; start there only when you have a keyword but no concrete bucket — when recon already handed you a specific bucket name, begin at Step 1.

### Step 0 — Enumerate candidate buckets you don't have a name for yet

When recon gives you a company / product / brand keyword but no concrete bucket, enumerate the namespace before sampling — hand-guessing single names misses the bulk of the surface, and a single keyword routinely expands to dozens of live storage endpoints across the three clouds. `cloud_enum` mutates the keyword against its built-in fuzz list and probes AWS S3, Azure blob/host/container, and GCP buckets in one pass:

```bash
vigil assess kali exec --technique OSINT --intent "multi-cloud bucket enumeration for <keyword>" \
  --probe-kind fingerprint --phase recon --timeout 600 -- \
  cloud_enum -k <keyword> -k <keyword>.com -k <product-name> \
    -l /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/cloud_enum.log
```

Route each result by its state: an OPEN S3 bucket goes into Step 1 (sample) and Step 2 (consumer mapping); a bucket cloud_enum reports as **absent / not-found** is a *takeover screening* candidate — run it through the s3scanner + claimability check in Step 2, never record it as a takeover on the not-found result alone (`agent/references/subdomain-takeover.md`).

### Step 1 — Sample, don't slurp

Download a representative sample first. Pulling the entire corpus when the bucket holds 100k+ objects burns disk + dispatch time for analysis you cannot use yet.

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "list and sample bucket <name>" --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2&max-keys=200" > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-listing.xml'
```

Pull 10–30 objects across the directory shape variety the listing reveals: pick one from each top-level prefix, plus any object whose key name suggests sensitive content (`.env`, `backup`, `dump`, `credentials`, `config`, `.git`, `.pem`, `.key`).

### Step 2 — Identify what runs from this bucket

A bucket sitting in isolation is less interesting than a bucket that backs a known application. Map the bucket to its consumer:

- **DNS**: `vigil assess kali exec … -- dig +short <consumer-host>` (and the bucket host) — does any in-scope host CNAME to this bucket?
- **JS source references**: `grep -r "<bucket-name>" "$ENGAGEMENT_DIR/scans/"` — which scraped JS or HTML references this bucket?
- **Cloudfront/CDN distribution**: `curl -sI https://<bucket>.s3.amazonaws.com/` looking for `x-amz-bucket-region` and any CDN headers.
- **Subdomain takeover SCREENING signal (not a verdict)**: a scope subdomain CNAME'ing to a bucket that returns `NoSuchBucket` is the *screening* signal that the name is unserved — it proves the bucket is absent, **not** that *you* can re-bind the name, so it is necessary but not sufficient to record a takeover. S3 names are one global namespace pinned to a region; confirm the name is genuinely claimable (the right region, and not already taken in the global namespace) and **prove it with a benign own-account claim** before recording anything, because a signature-only takeover is the #1 false-positive class for this bug type (it gets closed Not-Reproducible). `agent/references/subdomain-takeover.md` is the single source of truth for the per-provider claimability rules and the own-account-claim proof — defer to it rather than recording on the `NoSuchBucket` result alone.

Use `s3scanner` to turn the bucket name into a deterministic existence + permission + region report before mapping it — it checks the bucket creds-free and is the screening input for the takeover path, so you are reading a tool's verdict rather than inferring from a curl status:

```bash
# Scan one bucket (or -bucket-file <list> from Step 0) for existence, region, and
# the per-grant ACL (READ / WRITE / READ_ACP / WRITE_ACP). `bucket_not_found` is a
# takeover SCREENING signal, not a verdict — feed it to the claimability check.
vigil assess kali exec --technique INFO-DISCLOSURE --intent "s3scanner permission + existence scan of <bucket>" \
  --probe-kind fingerprint --phase recon --timeout 120 -- \
  bash -c 's3scanner -bucket <bucket> -json > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-s3scanner.json'
```

A `bucket_not_found` for a name a scope subdomain still CNAMEs to is the takeover screening signal from the bullet above: run the claimability check and own-account claim before recording anything.

Record the bucket-to-consumer mapping as intel before dispatching downstream specialists. This is what turns "a public bucket" into "the static-asset backing for the customer admin portal at admin.example.com."

### Step 3 — Classify the content

Bucket content falls into one of four classes; the dispatch shape changes with each:

| Class | Typical contents | Dispatch shape (severity: the ladder below) |
|---|---|---|
| Public static assets | CSS, images, marketing copy | record once, move on |
| Logs / metrics dumps | request logs, telemetry exports, billing rollups | content review with `agent/skills/info-disclosure-testing/SKILL.md` |
| Source code / repos | `.git/` directories, build artifacts, tarballs | **propose a `code-vuln-hunter` swarm** to the operator (Step 4) |
| Credentials / secrets | `.env`, `*.key`, `*.pem`, IAM access keys, DB dumps | The operator's Credential Auto-Use step confirms the key is live, then a `vulnerability-analyst` lane tests what it grants |

The classification comes from the actual sample, not the bucket name. A bucket called `internal-prod-secrets` may turn out to hold only product imagery; a bucket called `marketing-assets` may turn out to hold an archived source tarball.

When the credentials/secrets sample is an AWS access key, session token, or role-assumable ARN,
the `vulnerability-analyst` lane loads `agent/skills/aws-iam-privesc/SKILL.md` before testing the key live —
that skill's methodology (the 14-vector privesc matrix, cross-account role assumption, IMDS
exploitation) is what turns "the key authenticates" into a proved blast radius, rather than a
single `get-caller-identity` call.

### Step 4 — Hand large source corpora to the operator as a swarm

When Step 3 lands the corpus in the "Source code / repos" class and the listing shows 100+ source
files, one `code-vuln-hunter` over the whole corpus runs out of context, so the corpus needs a
swarm. Swarm registration and dispatch belong to the operator (`agent/references/runtime-guides/dispatch-template.md`
"Swarm dispatch"): a specialist that starts workers itself competes with the operator's lanes for the
client's subagent cap and leaves dispatch rows nobody accounts for. Build the items file, then
propose the swarm in the handoff:

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "enumerate bucket source files" --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2" \
    | python3 -c "import sys,re; [print(m.group(1)) for m in re.finditer(r\"<Key>([^<]+)</Key>\", sys.stdin.read()) if m.group(1).endswith((\".js\",\".py\",\".rb\",\".go\",\".ts\",\".env\",\".yml\",\".yaml\"))]" \
    > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-sources.txt'
```

The `next_steps` entry names `recommended_agent: code-vuln-hunter`, the items-file path, the file
count with a suggested worker count and batch size, the `code-vulnerability-analysis` skill, the
per-worker task (download each file in the batch from `<bucket>`, scan for hardcoded credentials,
API keys, internal hostnames, and exploitable patterns), and the bucket request budget the workers
need. Put the same items-file path in `working_artifacts`.

### Step 5 — Offline secret scan over the downloaded sample

Alongside the Step 4 handoff, run TruffleHog over the downloaded sample inside the runtime. Different signal from the per-file LLM scan — TruffleHog catches known-format secrets (AWS access keys, Slack tokens, JWT, Stripe keys, GitHub tokens) deterministically. `--no-verification` keeps the scan from calling third-party providers; liveness is the operator's Credential Auto-Use step:

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "trufflehog filesystem scan of bucket sample" --probe-kind fingerprint --phase recon --timeout 600 -- \
  bash -c 'trufflehog filesystem /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>/ --json --no-verification \
    > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-trufflehog.jsonl'
```

Every credential-shaped hit goes to Credential Auto-Use (operator validation, then a `vulnerability-analyst` lane); severity moves only as the ladder's evidence is proven.

---

## Severity Escalation Ladder

| Evidence proven | Severity |
|---|---|
| Public bucket exists; content is static assets | INFO |
| Public bucket holds logs / metrics with no secrets | LOW |
| Public bucket holds internal documentation, schemas, or build configs | MEDIUM |
| Public bucket holds source code (any language); no secrets in sample yet | MEDIUM (HIGH if the source is the in-scope application backend) |
| Public bucket holds credentials / API keys / DB dumps / `.env` files | HIGH |
| Verified live credentials (operator replay against the live provider) | CRITICAL |
| Verified live credentials AND target-proven access to a real account or resource via a `vulnerability-analyst` lane | CRITICAL with confirmed impact |

CRITICAL requires a `vulnerability-analyst` lane proving the keys work against the live provider. A liveness check (including a TruffleHog `verified=true` result from a verifying scan) is necessary but not sufficient: it confirms the credential is live, not that it grants useful access.

---

## What to Record

- `intel record note` with the bucket name, region, listing-URL, consumer mapping from Step 2, and a one-line content classification from Step 3.
- `vigil assess finding record <your-role> <file>` for LOW–MEDIUM disclosures this lane proves (public logs, schemas, internal docs).
- `finding record code-vuln-hunter` for HIGH source-disclosure (the swarm workers record these per-batch).
- `finding record vulnerability-analyst` for CRITICAL credential exposures **after** target-proven replay.
- `intel record cve` if the exposed source matches a known vulnerable version.

Cleanup obligation: any object downloaded to the runtime container or the host should land in `/engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>/` so the engagement directory captures the evidence with the audit row. Do not delete the listing after recording — it is the durable proof of exposure shape at the time of the finding.

---

## Extended Resources

- `agent/skills/info-disclosure-testing/SKILL.md` — adjacent skill for verbose-error / endpoint-disclosure work
- `agent/skills/source-analysis/SKILL.md` — for any source files the swarm workers want to manually trace before recording
- `agent/skills/case-dispatching/SKILL.md` — operator-side coordination of the swarm + consolidating dispatches
- `agent/references/runtime-guides/dispatch-template.md` "Swarm dispatch" — the operator's `start-swarm` procedure the Step 4 proposal feeds
- `agent/references/subdomain-takeover.md` — subdomain-takeover claimability: why a `NoSuchBucket` / dangling-CNAME signature is necessary-but-not-sufficient, the per-provider claimability rules (region pinning, global-namespace already-taken, cert gates, reserved labels, owned parent zones), and the benign own-account claim that proves or kills a candidate before you record it
