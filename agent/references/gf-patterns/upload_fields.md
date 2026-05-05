# GF Bucket: upload_fields

## Purpose

Multipart and file-transfer fields should cluster as upload work even when the route name is generic, such as `/api/users/avatar` with a `file` part. This prevents generic `lfi` or `idor` keys from hiding upload parser and storage issues.

## Classifier Signal

- Weight: `30` baseline, with cluster preference on `type=upload` when only generic overlap buckets won
- Parameter keys: `file`, `filename`, `upload`, `attachment`, `avatar`, `image`, `photo`, `document`, `media`
- Path fragments: none

## Review Notes

Check extension allowlists, content sniffing, filename/path handling, overwrite behavior, stored XSS, image parser exposure, object ownership, and whether uploaded content is served from a privileged origin.
