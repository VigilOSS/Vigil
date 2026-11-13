---
name: file-upload-testing
description: Test file upload functionality for unrestricted upload, bypass, and code execution
origin: Vigil
vuln_class: file-upload
---

# File Upload Vulnerability Testing

## When to Activate

- Any multipart upload (avatars, documents, attachments, imports) or server-side file processing
  (image resize, PDF conversion, archive extraction).

Audit technique by outcome: `--technique RCE` for executable uploads, `LFI` when the filename
traverses, `XSS` for SVG/HTML rendered in a browser, `SSRF` when processing fetches a URL. Uploads
go through `vigil assess kali exec … --probe-kind payload --phase consume-test --timeout 60 -- curl
-F …`; add `--destructive` for anything that writes executable content. Extension, case,
alternate-extension, trailing-character, ADS, `.htaccess`/`.user.ini`, Content-Type, magic-byte,
polyglot/EXIF (PHP) payloads, SVG XSS and zip slip:
`agent/references/payloads/upload-payloads.md` (prepare files host-side).

## Map the mechanism first

Where files are stored (same origin, CDN, S3), whether they are served back by URL, whether the
filename survives, what processing runs, and whether the bridge is CSRF-gated.

**CSRF-gated bridges.** Enterprise upload endpoints return 403/"Invalid token" with valid cookies
until the CSRF token arrives in the expected channel; bypass work against that 403 hits the wrong
layer. Salesforce Aura/Chatter (`aura.token` in the POST envelope), ServiceNow
(`/api/now/attachment/file` with `X-UserToken`), Confluence/Jira (`atl_token`), SharePoint
(`X-RequestDigest`, reusable until the form-digest timeout, 30 minutes by default), Rails
(`<meta name="csrf-token">` → `X-CSRF-Token`). GET the page that renders the upload UI, extract the
token (meta tag, hidden input, `XSRF-TOKEN` cookie, or a response header), and replay in the same
channel the server checks (header vs form field vs query); mixing channels is the usual failure.
Post-CSRF validation is often weak because the developer treated CSRF as the boundary. If a
browser-rendered nonce cannot be reproduced, capture the whole flow through mitmproxy with a live
session and replay that known-good request with the bypass variations.

## Attack surface

- **Executable upload:** extension/Content-Type/magic-byte bypasses until a served file executes.
  Use a benign marker (`echo` of a nonce, `id`) under a randomised name, never a persistent
  interactive webshell, and record the path for cleanup.
- **Filename traversal** (`../`, `..%2f`, `....//`): writes outside the upload directory.
  Overwriting existing files (`index.php`, `config.php`, cron) destroys target state: prove the
  traversal with a new uniquely named file and stop there unless the operator approves more
  (`agent/shared-constraints.md` §1).
- **Content-driven:** SVG/HTML → stored XSS (`agent/skills/xss-testing/SKILL.md`); SVG, DOCX,
  XLSX inner XML → XXE (`agent/skills/xxe-testing/SKILL.md`); PDF JavaScript; zip slip; image and
  media processors → ImageMagick/FFmpeg argument and protocol tricks
  (`agent/references/payloads/command-injection-payloads.md` "By wrapper tool").
- **Resource limits:** decompression bombs, pixel floods and bulk uploads are denial of service;
  check declared limits with one bounded probe and only with operator approval.

## What to Record

Upload endpoint and filename parameter, the bypass that worked, the stored URL and whether it
executes or renders, the attacker outcome (`agent/rules/hunting.md` §2: command output, script
execution in another user's or an admin's view, a write outside the upload directory), and the
artefacts left for cleanup. Severity: `agent/references/finding-fp-and-severity-gate.md`; format:
`agent/references/runtime-guides/web-finding-recording.md`.
