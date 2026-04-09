---
name: web-recon
description: Enumerate web technologies, headers, endpoints, and metadata from a target
origin: AI Threat Hunting
---

# Web Reconnaissance

## When to Activate

- Beginning of engagement, new domain/subdomain, need tech stack before deeper testing

## Tools

- `httpx` — fast HTTP probing, tech detection, status codes, titles (primary for bulk host verification)
- `whatweb` — deep web technology fingerprinting
- `wafw00f` — WAF identification (identify before attempting bypass)
- `curl`, `openssl`, `grep`/`sed`/`jq` — manual inspection and verification

## Methodology

Treat each fingerprint as a hypothesis, not a trophy. Infer proxy layers, framework choices,
auth boundaries, and likely privileged workflows from small signals, then hand those
hypotheses to the next skill or phase for validation.

### 1. HTTP Header Analysis
```bash
curl -sI -L https://TARGET
curl -sI https://TARGET | grep -iE "^(server|x-powered-by|x-aspnet|x-frame|content-security|strict-transport|set-cookie|www-authenticate)"
curl -sI -X OPTIONS https://TARGET
```
Note: compare headers across unauthenticated, error, and alternate routes. Differences often
expose reverse proxies, app servers, framework routing, and auth enforcement boundaries.

### 2. Technology Fingerprinting
```bash
whatweb -a 3 https://TARGET
curl -sL https://TARGET | grep -iE "generator|powered.by|built.with"
curl -sL https://TARGET | grep -i '<meta' | head -20
```

```bash
# httpx bulk probing — confirms live hosts and captures tech stack in one pass
echo "https://TARGET" | httpx -silent -status-code -title -tech-detect -server -content-length

# WAF detection — identify the WAF before attempting bypass payloads
wafw00f https://TARGET
```

### 3. CMS Detection
```bash
# WordPress
curl -s https://TARGET/wp-login.php -o /dev/null -w "%{http_code}"
curl -s https://TARGET/wp-json/wp/v2/users
# Joomla
curl -s https://TARGET/administrator/ -o /dev/null -w "%{http_code}"
# Drupal
curl -s https://TARGET/CHANGELOG.txt | head -5
# Generic
curl -s https://TARGET/readme.html -o /dev/null -w "%{http_code}"
```

### 4. SSL/TLS Analysis
```bash
echo | openssl s_client -connect TARGET:443 -servername TARGET 2>/dev/null | openssl x509 -noout -text | grep -E "Subject:|Issuer:|Not Before|Not After|DNS:"
for proto in tls1 tls1_1 tls1_2 tls1_3; do
  echo | openssl s_client -connect TARGET:443 -$proto 2>/dev/null | grep -q "Protocol" && echo "$proto: supported"
done
```

### 5. Well-Known Files
```bash
curl -s https://TARGET/robots.txt
curl -s https://TARGET/sitemap.xml | head -50
curl -s https://TARGET/.well-known/security.txt
for path in crossdomain.xml clientaccesspolicy.xml humans.txt .well-known/openid-configuration; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" != "404" ] && echo "$path -> $code"
done
```

### 6. JS File Extraction (surface-level — deep analysis is source-analyzer's job)
```bash
curl -sL https://TARGET | grep -oE 'src="[^"]*\.js"' | sed 's/src="//;s/"//'
# Quick grep for API paths and secrets in each JS file
```

Only queue endpoints that are directly requestable and evidenced by a real response or real
HTML/form/link extraction. Directory stems, SPA routes, and guessed names should stay as follow-up
notes or surface candidates, not queue inputs.

### 7. HTML Source (surface-level — deep analysis is source-analyzer's job)
```bash
curl -sL https://TARGET | grep -oE '<!--.*?-->'                           # Comments
curl -sL https://TARGET | grep -oiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}'  # Emails
curl -sL https://TARGET | grep -i 'type="hidden"'                         # Hidden fields
curl -sL https://TARGET | grep -oE 'href="[^"]*"' | sed 's/href="//;s/"//' | sort -u  # Links
```

### 8. API Surface Discovery

```bash
# OpenAPI/Swagger spec
for path in /swagger.json /openapi.json /api-docs /swagger/v1/swagger.json /v2/api-docs /v3/api-docs; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://TARGET$path")
  [ "$code" != "404" ] && echo "$path -> $code"
done

# GraphQL endpoint
for path in /graphql /gql /api/graphql /graphql/console; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "https://TARGET$path" -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  [ "$code" != "404" ] && echo "$path -> $code"
done
```

### 9. Recon-to-Hypothesis Conversion

- Reverse-proxy plus framework leakage: test for route normalization, cache confusion, and trust-boundary mistakes.
- Auth-protected admin or internal-looking routes: treat them as realistic escalation paths, not dead ends.
- Error traces, version strings, or verbose debug hints: validate in stages before attempting full exploitation.
- Reused cookie scope, shared API prefixes, or odd host routing: look for cross-app chains and auth-context drift.

## What to Record

- Live targets with status codes, titles, and server headers
- Technology stack (framework, CMS, server, WAF, CDN)
- Authentication mechanism identified
- API specs discovered (OpenAPI, GraphQL)
- Admin/management endpoints found
- TLS certificate details (SANs, CN, issuer)
- JavaScript files queued for source-analyzer
- Surface candidates for operator ingestion

## Extended Resources

- `agent/references/tools/recon/nmap.md` — port/service discovery, enumeration flags, output parsing
- `agent/references/tools/recon/whatweb.md` — web technology fingerprinting depth levels
- `agent/references/tools/recon/httpx.md` — HTTP probing, tech detection, live host confirmation
- `agent/references/tools/recon/wafw00f.md` — WAF identification and fingerprinting
- `agent/references/tools/recon/curl.md` — HTTP request crafting and manual inspection
- `agent/references/payloads/info-disclosure-probes.md` — standard endpoint checklist (/metrics, /.env, /actuator, cloud metadata)
