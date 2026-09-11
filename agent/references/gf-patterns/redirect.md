---
name: gf-patterns:redirect
description: Return-URL parameter patterns that signal open-redirect and OAuth redirect surfaces
origin: 1ndianl33t/Gf-Patterns@f686f06ae647726578920084c894100d702496cc (+ local overlay)
bucket: redirect
skill: open-redirect-testing
weight: 25
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
dest, destination, redirect_uri, go, goto, rt, to, domain, site`

### Upstream gf param additions (2026-06)

The single-token keys `goto`, `rt`, `to`, `domain`, `site` were folded in from the upstream
gf pattern sets, which carry classic open-redirect params our set lacked.

The compound `*_url`/`*_uri`/`*_to` open-redirect family (`return_url`, `redirect_url`,
`callback_url`, `next_url`, …) is handled on TWO layers (Fix 4, landed — see `DRIFT.md` → "Fix 4"):

1. **Curated whole keys (precision).** The common compound names are listed as whole keys above,
   in both `snake_case` and `concatenated` (camelCase-lowercased) forms, so a bare `?return_url=`
   clusters `gf:redirect` STRONGLY — *not* `gf:ssrf`. (The inner `url` token alone is an ssrf@40
   key and would mis-route the row to SSRF; matching the whole name avoids that.) This mirrors how
   the `idor` bucket enumerates its `*_id` family rather than tokenizing.
2. **Tiered inner-token rescue (recall).** For novel compound names not curated here,
   `classify_row` splits the key on `_`/`-`/camelCase and matches the inner tokens at a capped
   weight (`WEAK_TOKEN_CAP`), so an unrecognized `?someRedirectThing=` is still triaged instead of
   scoring 0. A weak match never overrides a strong cluster; on a strongly-matched row it is
   recorded as a `secondary_bucket` for cross-routing.

FP guard: `to`, `domain`, and `site` are mildly generic and can appear on benign navigation
params. This is acceptable because bucket weight only orders triage — it never gates inclusion
or skips a row — so a marginal match changes ordering, never suppression. No path fragments were
added, so generic content paths are unaffected.

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
- [PayloadsAllTheThings Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Open%20Redirect)

## Related

- `agent/skills/oauth-oidc-testing/SKILL.md` — OAuth flow testing when the redirect_uri is the vector
- `agent/references/payloads/open-redirect-payloads.md` — parsing-confusion and unicode bypass payloads
- `agent/references/gf-patterns/ssrf.md` — adjacent bucket (both fire on `url=` / `next=`)
