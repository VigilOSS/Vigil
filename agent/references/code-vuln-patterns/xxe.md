---
description: External entity fetches, SSRF/file-read pivots, parser configuration regressions
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS, Java, Go
---

# XXE — External Entity Fetches, File Read Pivots, and Parser Configuration Regressions

> Target: XML parsing paths where external entities, DTD processing, or expansion behavior can
> read files, perform SSRF, or trigger resource exhaustion despite “secure parser” assumptions.

---

## What You're Hunting

### 1. Secure-by-Wrapper, Insecure-by-Callsite

The project has a safe parser helper, but a later refactor bypasses it.

- Direct parser construction in one code path
- Safe defaults overwritten for validation/debug modes
- Streaming parser configured differently than DOM parser — in Java, `XMLInputFactory`
  (StAX) sits beside `DocumentBuilderFactory` and `SAXParserFactory` and is hardened
  through its own properties, so a project that secured the DOM path often left it open

### 2. Indirect XML Reachability

The input is not obviously “XML” at the entry point.

- Uploaded SVG/DOCX/XLSX
- SAML assertions
- SOAP envelopes
- Configuration/import formats with embedded XML

### 3. SSRF and File-Read Pivots

The dangerous behavior is often the resolver, not the document body.

- Metadata/internal host fetches
- Local file disclosure
- Parameter entities or external DTDs fetched during validation

### 4. Expansion Limits and Mixed Parser Modes

- Entity resolution disabled, but external DTD fetch still allowed
- Expansion limits present in one parser mode but not another
- Validation mode re-enables dangerous features

---

## Audit Questions

- Which exact parser configuration is used on untrusted XML in every call path?
- Do any upload/import/document features reach XML under the hood?
- Can validation, schema loading, or resolver hooks trigger outbound fetches?
- Are both external entities and expansion DoS guarded?
