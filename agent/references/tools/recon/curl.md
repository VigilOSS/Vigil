---
description: curl against targets through kali exec (attribution header auto-injected) and the curl_chrome116 browser-like TLS/HTTP2 fingerprint baseline for CDN/Bot-Manager ambiguity, including replaying a cookie jar from a headed login
skill: web-recon
---

# curl

Target-facing curl runs as
`vigil assess kali exec --technique <enum> --intent "<why>" --probe-kind <kind> --phase <phase> --timeout <seconds> -- curl ...`.
curl is attribution-header injectable, so a program's mandated header is appended to the recorded
argv automatically.

## Browser-like curl baseline

The runtime ships `curl_chrome116` (curl-impersonate: Chrome's TLS JA3/JA4 and HTTP/2 fingerprint,
full curl flag compatibility). Use it as a narrow baseline when a CDN/Bot-Manager block or a
TLS-client-fingerprint difference is suspected, to separate scanner-client blocks from application
behaviour:

```bash
vigil assess kali exec \
  --technique RECON --intent "browser-like curl baseline for edge/TLS ambiguity" \
  --probe-kind fingerprint --phase recon --timeout 60 -- \
  curl_chrome116 -sS -D - https://target.example/
```

It is still HTTP request evidence: it runs no JavaScript, keeps no DOM state, proves no
browser-enforced behaviour, and cannot solve an interactive bot-manager challenge, only replay a
session that already cleared one. Establish that session with a headed stealth login
(`agent/skills/browser-automation/SKILL.md`), then replay its cookie jar with
`curl_chrome116 -b cookies.txt ...`. When runtime browser semantics are the question, load
`agent/skills/browser-semantic-analysis/SKILL.md`.
