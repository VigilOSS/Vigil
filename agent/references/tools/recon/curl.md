---
description: HTTP request crafting and testing
---

# curl

**Purpose:** HTTP request crafting and testing
For live target requests during an engagement, execute `curl` via `vigil assess kali exec --technique <enum> --intent "<why>" --probe-kind <kind> --phase <phase> --timeout <seconds> -- curl ...` with the standard audit-flag set.

## GET Requests

**Basic GET:** `curl -v https://target/`
**Headers only (HEAD):** `curl -I https://target/`
**Silent with status code:** `curl -s -o /dev/null -w "%{http_code}" https://target/`
**Follow redirects:** `curl -L https://target/`
**TLS skip (self-signed certs):** `curl -k https://target/`

## POST / PUT / DELETE

**POST form data:** `curl -d "param=value" https://target/api`
**JSON POST:** `curl -H "Content-Type: application/json" -d '{"key":"value"}' https://target/api`
**Data from file:** `curl -H "Content-Type: application/json" -d @payload.json https://target/api`
**PUT:** `curl -X PUT -H "Content-Type: application/json" -d '{"key":"value"}' https://target/api`
**PATCH:** `curl -X PATCH -d '{"field":"new"}' -H "Content-Type: application/json" https://target/api`
**DELETE:** `curl -X DELETE https://target/api/resource/1`

## File Upload

**Multipart form upload:** `curl -F "file=@shell.php" -F "name=test" https://target/upload`
**With content type override:** `curl -F "file=@shell.php;type=image/png" https://target/upload`

## Auth & Headers

**Cookie:** `curl -b "session=abc123" https://target/`
**Cookie jar (save):** `curl -c cookies.txt https://target/login -d "user=admin&pass=test"`
**Cookie jar (send):** `curl -b cookies.txt https://target/dashboard`
**Custom header:** `curl -H "Authorization: Bearer token" https://target/api`
**Multiple headers:** `curl -H "Cookie: x=1" -H "X-Custom: value" https://target/`
**Basic auth:** `curl -u user:pass https://target/admin`

## Output & Debugging

**Save response:** `-o output.html`
**Verbose (see headers):** `-v`
**Response headers to stdout:** `-D -`
**Write-out template:** `-w "code: %{http_code} size: %{size_download} time: %{time_total}\n"`
**Proxy through Burp:** `-x http://127.0.0.1:8080`
**Timeout:** `--connect-timeout 5 --max-time 30`
**HTTP/2:** `--http2`
**URL encode data:** `--data-urlencode "q=hello world"`

## Browser-Like Curl Baseline

If `curl_chrome116` exists in the runtime, use it as a narrow baseline when a
CDN/Bot-Manager or TLS-client-fingerprint difference is suspected:

```bash
vigil assess kali exec \
  --technique RECON --intent "browser-like curl baseline for edge/TLS ambiguity" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  curl_chrome116 -sS -D - https://target.example/
```

This is still HTTP request evidence. It can help distinguish scanner-client
blocks from app behavior, but it does not execute JavaScript, maintain DOM
state, or prove browser-enforced security behavior, and it cannot *solve* an
interactive bot-manager challenge — it can only replay a session that already
cleared one. Load `agent/skills/browser-semantic-analysis/SKILL.md` when runtime
browser semantics are required. To establish that session in the first place
(headed stealth login on a bot-defended site), use
`agent/skills/browser-automation/SKILL.md`, then feed the cookie jar here:
`curl_chrome116 -b cookies.txt ...`.
