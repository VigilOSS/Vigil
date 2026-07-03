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
- Bucket-listing params (`list-type`, `marker`, `delimiter`, `continuation-token`)
  appear, or the URL host is `*.s3.amazonaws.com`, `*.blob.core.windows.net`, or
  `storage.googleapis.com`
- Operator is checking for misconfigured cloud storage access or legacy Domino document exposure

## Parameter keys that match

`bucket, blob, prefix, list-type, marker, delimiter, continuation-token`

`bucket`, `blob`, and `prefix` are the original keys. `list-type`, `marker`,
`delimiter`, and `continuation-token` were added (classify-context-and-surface
2026-06, Part 3 §C.14): these are the S3/GCS/Azure bucket-LISTING query
parameters (`list-type=2` selects the S3 ListObjectsV2 API; `marker` /
`continuation-token` page a listing; `delimiter` / `prefix` scope it). Their
presence on a request is a strong open-bucket object-enumeration signal.

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

## Host markers (full-URL regex, classify-context-and-surface 2026-06, Part 3 §C.14)

Cloud-storage object URLs carry the bucket in the URL AUTHORITY, not the path, so
these markers are matched by `_REGEX_BUCKET_RULES["object-storage"]` against the
FULL `url` (authority + query). `object-storage` is one of the
`_FULL_URL_REGEX_BUCKETS` (alongside `cloud_metadata`):

- `.s3.amazonaws.com` — AWS S3 virtual-hosted / path-style bucket host
- `blob.core.windows.net` — Azure Blob Storage host
- `storage.googleapis.com` — Google Cloud Storage host

`classify_row` lowercases the full `url` and runs these patterns against it,
appending `gf:object-storage` (deduped against any url_path-side hit). They fire
even when the url_path carries no `/s3/`/`/blob/` fragment, so a direct
`https://acme-uploads.s3.amazonaws.com/?list-type=2` enumeration URL still
clusters as `gf:object-storage`. The full-`url` pass is **boost-only**: when the
classifier is called without a `url` (the default-kwarg test convention), the
host-marker pass is skipped and path/param matching is unchanged.

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

Bucket-host + listing (full-URL host markers, no path fragment required):

- `https://acme-uploads.s3.amazonaws.com/?list-type=2&prefix=backups/` — S3 ListObjectsV2 enumeration (host marker `.s3.amazonaws.com` + `list-type`/`prefix` keys)
- `https://acme.blob.core.windows.net/container?marker=...&restype=container&comp=list` — Azure Blob container listing (host marker fires; `marker` key reinforces)
- `https://storage.googleapis.com/acme-bucket/?prefix=&delimiter=/` — GCS object listing (host marker + `prefix`/`delimiter` keys)

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

- **Public bucket listing / object enumeration:** `GET /s3/bucket/?prefix=`,
  `?list-type=2`, or `HEAD /bucket/` returns object inventory when ACLs are not
  scoped; `marker`/`continuation-token` then page the full inventory, and the
  cloud host markers above expose the listing endpoint directly
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
See `docs/plans/research/classify-surface-2026-06/README.md` §4b (object-storage long-tail validation).

## Sources

- [AWS S3 — Bucket policies and ACLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html)
- [HackTricks — Cloud storage](https://book.hacktricks.xyz/pentesting-cloud/aws-security/aws-services/aws-s3-enumeration)
- [HCL Domino/Lotus Notes Security](https://help.hcltechsw.com/domino/14.0.0/admin/conf_databaseaccess_c.html)

## Related

- `agent/references/gf-patterns/ssrf.md` — SSRF via presigned URL generation or storage-proxy fetch
- `agent/references/gf-patterns/idor.md` — object-reference keys that may co-fire with storage paths
- `agent/references/gf-patterns/trust_surface.md` — broader trust-delegation bucket (upload/download flows)
