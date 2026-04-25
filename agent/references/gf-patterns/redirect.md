---
name: gf-patterns:redirect
description: Return-URL parameter patterns that signal open-redirect and OAuth redirect surfaces
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
---

# gf: redirect

## What this bucket classifies

Parameters that carry a return/forward target. These surfaces are candidates for open
redirect, OAuth redirect_uri poisoning (when followed by token theft), and same-site
phishing chains.

## Load this reference when

- Login and OAuth flows are in scope and the corpus shows `redirect_uri=`, `next=`, `return=` keys
- Operator is hunting account-takeover chains where an open redirect could leak a token
- Multiple login surfaces exist (SSO + local) — redirect bucket surfaces cross-flow candidates

## Parameter keys that match

`redirect, return, returnto, return_to, next, redir, forward, continue, url, rurl, u, target,
dest, destination, redirect_uri, go`

## Path patterns that match

None — redirect is keyed entirely off parameter names.

## Weight and priority interpretation

- Baseline priority score: 25
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

- `https://target.example/login?next=https://evil.example` — classic open redirect
- `https://target.example/oauth/authorize?redirect_uri=https://attacker.example/callback&client_id=...` — OAuth redirect poisoning
- `https://target.example/signin?return=//evil.example` — protocol-relative bypass candidate
- `https://target.example/logout?continue=https://attacker.example` — post-logout open redirect
- `https://target.example/track?u=https%3A%2F%2Fevil.example` — encoded redirect handle

## What it does NOT classify

- Server-side fetching of the URL (that is `ssrf`) — a user-visible redirect vs server fetch
  is the key split, and both buckets can fire on the same URL
- Internal-only navigation tokens that are never compared against a host allow-list — those
  are less interesting unless combined with session loss

## Sources

- [1ndianl33t/Gf-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — canonical community pattern set
- [tomnomnom/gf](https://github.com/tomnomnom/gf) — tool
- [PayloadsAllTheThings Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect)

## Related

- `agent/skills/oauth-oidc-testing/SKILL.md` — OAuth flow testing when the redirect_uri is the vector
- `agent/references/payloads/open-redirect-payloads.md` — parsing-confusion and unicode bypass payloads
- `agent/references/gf-patterns/ssrf.md` — adjacent bucket (both fire on `url=` / `next=`)
