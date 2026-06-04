---
name: gf-patterns:interestingparams
description: Credential and session-token parameter patterns that signal secret-handling surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: interestingparams
weight: 15
---

# gf: interestingparams

## What this bucket classifies

Parameters whose names indicate authentication material is being passed in the URL or body —
API keys, tokens, session ids, and raw passwords. These surfaces are primarily interesting
for secret disclosure in logs, Referer leaks, and history-based credential theft.

## Load this reference when

- The corpus has `?api_key=`, `?token=`, `?auth=`, `?session=`, or `?password=` keys
- Historical URLs from gau returned any query string containing a bearer-like value (the key
  name triggers this bucket; trufflehog covers the value-side secret detection)
- Operator wants to check whether OAuth state/nonce tokens are floating unprotected

## Parameter keys that match

`api_key, apikey, token, auth, session, secret, password, passwd, pwd`

## Path patterns that match

None — interestingparams is keyed entirely off parameter names.

## Weight and priority interpretation

- Baseline priority score: 15 (lowest weight because URL-borne secrets are frequently test/expired values)
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/api/call?api_key=AKIA...` — AWS key in URL
- `https://target.example/login?password=admin` — credentials in query (Referer leak risk)
- `https://target.example/webhook?token=ghp_...` — GitHub PAT in webhook URL
- `https://target.example/reset?secret=e3b0c4...` — password-reset secret
- `https://target.example/oauth/exchange?auth=bearer-xyz&session=sess-abc` — combined auth surface

## What it does NOT classify

- Non-URL-borne secrets (headers-only, JSON body-only tokens) — those live in trufflehog's body-scan output, not gf
- Public-key fingerprints or non-sensitive "token" UI identifiers — still fire but de-prioritize after human triage
- Cookie-based session material — covered by session-handling review, not gf pattern matching

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) — complementary value-side secret detector

## Related

- `agent/references/tools/recon/trufflehog.md` — value-side secret scanning (pairs with this key-side bucket)
- `agent/skills/gau-triage/SKILL.md` — the pipeline that runs both the gf key-match and trufflehog passes
- `agent/references/gf-patterns/debug_logic.md` — adjacent bucket (debug paths often carry token params)
