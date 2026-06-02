---
name: cloud-exposure
description: Exposed cloud storage triage — S3/GCS/Azure buckets, severity escalation, swarm-dispatch over corpus
origin: Vigil
---

# Cloud Exposure Investigation

## Reality Check

A public bucket is not automatically critical. Severity rides on **what is in the bucket** and **what infrastructure points at it**, not on the existence of the bucket. A public bucket of CSS sprites used as a CDN is informational; a public bucket of `.env` files, source repos, or backup tarballs is critical. This skill is about working through the blast radius systematically rather than recording an estimated severity from the listing alone.

## When to Activate

- A bucket listing is publicly accessible (S3 `?list-type=2`, GCS XML listing, Azure `?comp=list`).
- A domain or subdomain CNAMEs to a bucket endpoint and the bucket is browseable.
- Recon discovered references to bucket names in HTML / JS source / DNS history that resolve to live buckets.
- A subdomain takeover candidate sits on bucket infrastructure (dangling CNAME → unclaimed bucket).
- During code analysis, hard-coded bucket names point to buckets you can reach unauthenticated.

## Tools

- `vigil assess kali exec -- curl ...` for the bucket listing and sample object pulls (use `--technique INFO-DISCLOSURE --probe-kind fingerprint --phase recon --timeout 60`)
- `vigil assess kali exec -- aws s3 ls s3://<bucket> --no-sign-request` and `aws s3 cp` for AWS listings (or `gsutil ls` / `az storage blob list` for GCS/Azure)
- `vigil assess kali exec -- trufflehog filesystem <dir>` for offline secret scanning over a downloaded sample (host-side tool, not target-facing)
- `vigil assess agent start-swarm` for fanning corpus-scale source review out to many parallel `code-vuln-hunter` workers — see "Swarm Dispatch" below

---

## Investigation Procedure

Do these five steps in order. Skipping ahead (e.g. recording severity from the listing alone) is exactly the failure mode this skill prevents.

### Step 1 — Sample, don't slurp

Download a representative sample first. Pulling the entire corpus when the bucket holds 100k+ objects burns disk + dispatch time for analysis you cannot use yet.

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "list and sample bucket <name>" --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2&max-keys=200" > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-listing.xml'
```

Pull 10–30 objects across the directory shape variety the listing reveals: pick one from each top-level prefix, plus any object whose key name suggests sensitive content (`.env`, `backup`, `dump`, `credentials`, `config`, `.git`, `.pem`, `.key`).

### Step 2 — Identify what runs from this bucket

A bucket sitting in isolation is less interesting than a bucket that backs a known application. Map the bucket to its consumer:

- **DNS**: `dig +short <bucket>.s3.amazonaws.com` and `dig +short <consumer-host>` — does any in-scope host CNAME to this bucket?
- **JS source references**: `grep -r "<bucket-name>" agent/engagements/$ENGAGEMENT_KEY/scans/` — which scraped JS or HTML references this bucket?
- **Cloudfront/CDN distribution**: `curl -sI https://<bucket>.s3.amazonaws.com/` looking for `x-amz-bucket-region` and any CDN headers.
- **Subdomain takeover signal**: if a scope subdomain CNAMEs to a bucket that returns `NoSuchBucket`, the bucket is unclaimed and is a takeover finding.

Record the bucket-to-consumer mapping as intel before dispatching downstream specialists. This is what turns "a public bucket" into "the static-asset backing for the customer admin portal at admin.example.com."

### Step 3 — Classify the content

Bucket content falls into one of four classes; the dispatch shape changes with each:

| Class | Typical contents | Dispatch shape |
|---|---|---|
| Public static assets | CSS, images, marketing copy | LOW; record once, move on |
| Logs / metrics dumps | request logs, telemetry exports, billing rollups | MEDIUM-HIGH; dispatch `info-disclosure-testing` specialist for content review |
| Source code / repos | `.git/` directories, build artifacts, tarballs | HIGH; **dispatch `code-vuln-hunter` swarm** (Step 4) |
| Credentials / secrets | `.env`, `*.key`, `*.pem`, IAM access keys, DB dumps | CRITICAL; dispatch `exploit-developer` to test the keys live |

The classification comes from the actual sample, not the bucket name. A bucket called `internal-prod-secrets` may turn out to hold only product imagery; a bucket called `marketing-assets` may turn out to hold an archived source tarball.

### Step 4 — Swarm dispatch for large source corpora

When Step 3 lands the corpus in the "Source code / repos" class and the listing shows 100+ source files, **do not** dispatch one `code-vuln-hunter` at full reasoning over the whole corpus — that runs out of context. Use the swarm helper:

```bash
# Build the items file
vigil assess kali exec --technique INFO-DISCLOSURE --intent "enumerate bucket source files" --probe-kind fingerprint --phase recon --timeout 60 -- \
  bash -c 'curl -s "https://<bucket>.s3.amazonaws.com/?list-type=2" \
    | python3 -c "import sys,re; [print(m.group(1)) for m in re.finditer(r\"<Key>([^<]+)</Key>\", sys.stdin.read()) if m.group(1).endswith((\".js\",\".py\",\".rb\",\".go\",\".ts\",\".env\",\".yml\",\".yaml\"))]" \
    > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-sources.txt'

# Fan out to N parallel low-reasoning workers
vigil assess agent start-swarm \
    --role code-vuln-hunter \
    --workers 10 --batch-size 50 \
    --items-file /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-sources.txt \
    --skills code-vulnerability-analysis \
    --model gpt-5.5 --reasoning low \
    --task "download each file in this batch from <bucket>, scan for hardcoded credentials, API keys, internal hostnames, exploitable patterns; record findings as code-vuln-hunter prefix"
```

The helper does NOT spawn specialists — it writes N dispatch rows and prints the agent_id table. Operator dispatches the N workers manually via `@code-vuln-hunter` (Claude Code) or `spawn_agent` (Codex). Each worker reads its slice from `vigil assess agent get <agent_id>`. Detail: `agent/operator-core.md` Swarm Dispatch.

### Step 5 — Offline secret scan over the downloaded sample

In parallel with Step 4, run TruffleHog over the downloaded sample on the host. Different signal from the per-file LLM scan — TruffleHog catches known-format secrets (AWS access keys, Slack tokens, JWT, Stripe keys, GitHub tokens) deterministically:

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "trufflehog filesystem scan of bucket sample" --probe-kind fingerprint --phase recon --timeout 600 -- \
  trufflehog filesystem /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>/ --json --no-verification \
    > /engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>-trufflehog.jsonl
```

Verified hits (TruffleHog confirms the secret is live against its provider) escalate severity to CRITICAL immediately and trigger an `exploit-developer` dispatch.

---

## Severity Escalation Ladder

| Evidence proven | Severity |
|---|---|
| Public bucket exists; content is static assets | INFO |
| Public bucket holds logs / metrics with no secrets | LOW |
| Public bucket holds internal documentation, schemas, or build configs | MEDIUM |
| Public bucket holds source code (any language); no secrets in sample yet | MEDIUM (HIGH if the source is the in-scope application backend) |
| Public bucket holds credentials / API keys / DB dumps / `.env` files | HIGH |
| Verified live credentials (TruffleHog verification or successful replay against the live provider) | CRITICAL |
| Verified live credentials AND target-proven access to a real account or resource via `exploit-developer` | CRITICAL with confirmed impact |

CRITICAL requires exploit-developer proving the keys work against the live provider. The TruffleHog `verified=true` flag is necessary but not sufficient — the `verified` API check only confirms the credential format is live, not that it grants useful access.

---

## What to Record

- `record-intel note` with the bucket name, region, listing-URL, consumer mapping from Step 2, and a one-line content classification from Step 3.
- `record-finding info-disclosure-testing` for LOW–MEDIUM disclosures (public logs, schemas, internal docs).
- `record-finding code-vuln-hunter` for HIGH source-disclosure (the swarm workers record these per-batch).
- `record-finding exploit-developer` for CRITICAL credential exposures **after** target-proven replay.
- `record-intel cve` if the exposed source matches a known vulnerable version.

Cleanup obligation: any object downloaded to the runtime container or the host should land in `/engagements/$ENGAGEMENT_KEY/scans/cloud-exposure/<bucket>/` so the engagement directory captures the evidence with the audit row. Do not delete the listing after recording — it is the durable proof of exposure shape at the time of the finding.

---

## Extended Resources

- `agent/skills/info-disclosure-testing/SKILL.md` — adjacent skill for verbose-error / endpoint-disclosure work
- `agent/skills/source-analysis/SKILL.md` — for any source files the swarm workers want to manually trace before recording
- `agent/skills/case-dispatching/SKILL.md` — operator-side coordination of the swarm + consolidating dispatches
- `agent/operator-core.md` Swarm Dispatch section — the `start-swarm` helper this skill depends on
