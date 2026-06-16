---
name: gf-patterns:object-storage
description: Cloud and Domino object-storage path patterns (S3, GCS, blob, Lotus .nsf file objects)
origin: local overlay (no upstream gf equivalent)
bucket: object-storage
weight: 25
---

# gf: object-storage

## What this bucket classifies

Cloud object-storage endpoints (S3, GCS, Azure Blob) and Domino/Lotus Notes file-object
paths (`$FILE`, `files.nsf`, `docscat`, `didc`) where an attacker can exploit public-bucket
listing, SSRF via presigned URL generation, path-traversal to listing, or unauthenticated
object download.

## Load this reference when

- The corpus contains `/s3/`, `/gcs/`, `/blob/`, `/bucket/` paths or Lotus/Domino `.nsf` document routes
- Param keys `bucket`, `blob`, or `prefix` appear in query strings
- Operator is checking for misconfigured cloud storage access or legacy Domino document exposure

## Parameter keys that match

`bucket, blob, prefix`

`key` and `object` were considered but rejected: they are too generic (HTTP caching, GraphQL
object fields) and would generate substantial cross-bucket false positives.

## Path patterns that match

Cloud storage endpoints:
`/s3/`, `/gcs/`, `/blob/`, `/bucket/`

Domino/Lotus Notes file-object discriminators:
`$file`, `.nsf`, `files.nsf`, `docscat`, `didc`

Note: bare `/files/` and `/storage/` are deliberately excluded. The cms-gov corpus has
thousands of `/files/*.pdf` (public content delivery), and `/storage/` appears as a
front-end asset prefix on many frameworks. Only cloud-specific discriminators and the
Domino-specific token set are allowed to avoid flooding the queue with benign CDN paths.
See override #2 in `classify_buckets.py`.

## Weight and priority interpretation

- Baseline priority score: 25
- Below specific vulnerability buckets (ssrf=40, auth=40, graphql=45) — param signal
  from those buckets dominates when they co-fire
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Cloud storage:

- `https://target.example/s3/bucket/objects?prefix=reports/` — S3-proxy with listing prefix
- `https://target.example/api/files?bucket=user-uploads&blob=avatar.jpg` — GCS blob reference
- `https://target.example/storage/blob/container/file.dat` — Azure Blob path

Domino/Lotus Notes:

- `https://target.example/api.nsf/$file/report.pdf` — Domino file attachment
- `https://target.example/names.nsf/files.nsf/document` — Lotus files database
- `https://target.example/portals/docscat/item?id=123` — Document catalog object
- `https://target.example/didc/record/fetch` — DIDC document record

## What it does NOT classify

- `/files/document.pdf` (bare static file delivery) — excluded by design; cms-gov has
  thousands of these at priority 0 and they should remain low
- `/storage/app.js` (front-end asset) — excluded; framework asset path, not cloud storage
- S3 presigned URL parameters (`X-Amz-Signature`, `AWSAccessKeyId`) in query strings —
  those belong to `interestingparams` or a dedicated cloud-auth bucket

## Attack classes

- **Public bucket listing:** `GET /s3/bucket/?prefix=` or `HEAD /bucket/` returns object
  inventory when ACLs are not scoped
- **SSRF via presigned URL generation:** endpoint at `/s3/sign?key=user-data/...` generates
  signed URLs; SSRF if the `key` path traverses to another principal's prefix
- **Unauthenticated Domino file access:** `$FILE` attachments in `.nsf` databases are
  sometimes exposed without authentication when the database ACL is `Default: Reader`
- **Bucket CORS misconfiguration:** cloud-storage origins with permissive CORS allow
  cross-origin JavaScript to exfiltrate object contents

## Corpus grounding

18 actionable `object-storage` templates (84 rows) in the first deep cms-gov sweep;
3 more (6 rows) in the second sweep; 655 actionable `object_storage` templates (655 rows)
in the third targeted sweep, dominated by Domino/Lotus `.nsf`, `$FILE`, `docscat`, and
document-library paths. The Domino-specific discriminators (`$file`, `.nsf`, `files.nsf`,
`docscat`, `didc`) were added specifically to capture this corpus signal.
See `docs/plans/classify-surface-rd-2026-06-15.md` §4b and the long-tail sections.

## Sources

- [AWS S3 — Bucket policies and ACLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html)
- [HackTricks — Cloud storage](https://book.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-s3-enumeration)
- [HCL Domino/Lotus Notes Security](https://help.hcltechsw.com/domino/14.0.0/admin/conf_databaseaccess_c.html)

## Related

- `agent/references/gf-patterns/ssrf.md` — SSRF via presigned URL generation or storage-proxy fetch
- `agent/references/gf-patterns/idor.md` — object-reference keys that may co-fire with storage paths
- `agent/references/gf-patterns/trust_surface.md` — broader trust-delegation bucket (upload/download flows)
