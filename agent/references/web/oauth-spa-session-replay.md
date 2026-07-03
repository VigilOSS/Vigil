---
description: Replaying a live SPA session for authenticated API testing without being chained to a short-lived captured token — the silent-PKCE self-mint pattern (authorize?prompt=none&code_challenge=… → follow the single Akamai akredirect bounce → auth-silent/?code=… → token endpoint) to mint a fresh access_token on demand from live SPA session cookies; cross-issuer trust domains (www realm issuer != api gateway issuer) and the X-CSRF-Token / channel-header envelope that gateways require BEFORE evaluating the bearer; the liveness-gate-first rule; and the dead-end traps (api v5 web-token / AuthProofGenerator / WAS-LTPA). Worked example: bank.acme.example member realm → bank.acme.example. Paired with oauth-oidc-testing.
skill: oauth-oidc-testing
---

# OAuth / OIDC SPA Session Replay — silent-PKCE self-mint + cross-issuer envelopes

When you hold a **captured live SPA session** (cookies from a proxied browser login) and need to
make **authenticated API calls** for surface mapping / BOLA / authz testing, the naive approach —
replay the captured `access_token` from the credential store — fails within minutes: SPA access tokens are
**short-lived** (here ~599s / 3–10 min) and a human page-refresh does **not** rotate them. You burn
the engagement re-capturing, and worse, you record "unreachable" verdicts that were really just a
**dead token** (see the liveness rule below).

The robust fix is to **reproduce the SPA's own silent OAuth flow** and **self-mint a fresh token on
demand** from the still-valid session cookies (the ForgeRock/IdP SSO cookies typically live much
longer — ~11h on Acme Bank — than the opaque access_token). This **decouples** your testing from token
TTL: mint right before each batch.

Worked example throughout: **`bank.acme.example` member realm → `bank.acme.example` gateway** (2026-06-19).
The mechanics (silent PKCE, the cross-issuer split, the CSRF-envelope requirement) generalize to
any IdP-backed SPA fronting a separate API gateway.

## A. Silent-PKCE self-mint (mint a fresh access_token from live cookies)

The SPA keeps itself logged in by silently re-running the authorization-code+PKCE flow with
`prompt=none` against the IdP, using its still-valid SSO cookies — no user interaction, no password.
Reproduce exactly that.

**Step 1 — silent authorize (`prompt=none`), with the session cookie jar:**

```bash
# PKCE: code_verifier (43+ chars) and S256 challenge
V=$(head -c32 /dev/urandom | base64 | tr -d "=+/" | cut -c1-43)
C=$(printf "%s" "$V" | openssl dgst -binary -sha256 | openssl base64 -A | tr "+/" "-_" | tr -d "=")
NONCE=$(head -c8 /dev/urandom | base64 | tr -d "=+/" | cut -c1-12)

# client_id + scope come from the SPA's own JS bundle (e.g. cip_main.js)
AURL="https://bank.acme.example/access-management/oauth2/member/authorize\
?client_id=c144bdef-0894-4049-9598-7f960c5123f3\
&redirect_uri=https%3A%2F%bank.acme.example%2Futils%2Foauth%2Fauth-silent%2F\
&response_type=code&code_challenge=$C&code_challenge_method=S256\
&nonce=$NONCE&scope=Acme Bank.inf.presentation.page-templates%20openid\
&prompt=none&response_mode=query"

# *** FOLLOW the single Akamai akredirect interstitial bounce (-L) ***  -> lands on auth-silent/?code=<CODE>
FURL=$(curl_chrome116 -sSL --max-redirs 5 --max-time 25 -b "$JAR" -c "$JAR" -o /dev/null -w "%{url_effective}" "$AURL")
CODE=$(printf "%s" "$FURL" | sed -nE "s/.*[?&]code=([^&]+).*/\1/p")
```

> **The akredirect bounce is the #1 thing that fooled prior agents.** The silent `authorize`
> returns a `302` to an Akamai edge **`akredirect`** URL that *looks like* a bounce back to
> `/Logon` (i.e. "session expired"). It is **not** a session failure — it is a transient edge gate.
> **Follow it once** (`curl -L`) and you land on `…/utils/oauth/auth-silent/?code=<CODE>`. Reading
> it as a login redirect is a false "session dead" negative. If `CODE` is genuinely empty after
> following, *then* the ForgeRock SSO session has lapsed (or an `_abck` Akamai bot hard-challenge
> fired) — re-capture and retry immediately.

**Step 2 — exchange the code at the IdP token endpoint (PKCE `code_verifier`):**

```bash
TOK=$(curl_chrome116 -sS --max-time 25 -b "$JAR" -c "$JAR" \
  -X POST "https://bank.acme.example/access-management/oauth2/member/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=https://bank.acme.example/utils/oauth/auth-silent/" \
  --data-urlencode "client_id=c144bdef-0894-4049-9598-7f960c5123f3" \
  --data-urlencode "code_verifier=$V" \
  | sed -nE 's/.*"access_token" *: *"([^"]+)".*/\1/p')
# -> 200 {access_token, scope:"openid Acme Bank.inf.presentation.page-templates", token_type:Bearer, expires_in:599}
```

**Step 3 — present it on the API** with the full envelope (see §C for the CSRF header):

```bash
curl_chrome116 -sS -b "$JAR" \
  -H "Authorization: Bearer $TOK" \
  -H "X-CSRF-Token: $MGS" \            # MGS = MemberGlobalSession cookie value (read from the jar)
  -H "Accept: application/json" \
  "https://bank.acme.example/v1/presentation/page-templates/v2/enterprise/core-customer-guid/party/id/$GUID"
```

**Where the inputs come from.** `client_id`, `scope`, and the `redirect_uri` are read from the
SPA's own JS bundle (grep the bundle for `authorize`, `code_challenge`, the client GUID — on Acme Bank,
`cip_main.js` carried `client_id=c144bdef-…` and `scope=Acme Bank.inf.presentation.page-templates
openid`). The cookie jar is the proxied-browser session. `curl_chrome116` (curl-impersonate) is used
so the TLS/JA3 fingerprint survives Akamai Bot Manager.

## B. Liveness-gate-first rule (don't record verdicts against a dead session)

**When the session came from the credential store, gate with the built-in probe first** —
`vigil assess auth-status --probe --identity <name> --probe-url <authed-url>` — rather than
hand-rolling this check. It's the same own-object-read idea below, generalized: it never follows
redirects, persists the verdict against that named identity (`live`/`dead`/`unknown`, never a false
positive on a transport error), and clears a `stale` mark on `live`. The self-minted-token pattern
in this section applies when the identity was never captured into the store at all (a freshly
self-minted access_token from live SPA cookies, §A above) or when no `material.liveness` signature
has been declared yet for that identity — declare one (`vigil auth import`/`edit`) so future probes
go through the CLI instead of a one-off script.

Before trusting **any** authenticated result — and *especially* before recording an "unreachable" /
"not-exposed" verdict — **prove the session is live** with an own-object read that you know returns
`200`:

```bash
LIVE=$(curl_chrome116 -sS -o /dev/null -w "%{http_code}" -b "$JAR" \
  -H "Authorization: Bearer $TOK" -H "X-CSRF-Token: $MGS" -H "Accept: application/json" \
  "https://bank.acme.example/v1/presentation/page-templates/v2/enterprise/core-customer-guid/party/id/$GUID")
[ "$LIVE" = 200 ] || { echo "SESSION DEAD — re-mint; discard any 'unreachable' results"; exit 1; }
```

A dead-session `401`/`403` is **not** evidence that a path is unreachable. Four prior agents recorded
"unreachable" verdicts on `bank.acme.example` that were entirely a **dead captured token**; re-running
with a freshly self-minted token (§A) and gating on this control made the verdicts sound. The full
gate-then-differential implementation is `tools/exploit-state/sensitive-endpoint-replay.sh`. The
reachability-classification side of this (what `27368` vs `2736803` means once the session is live)
is in `agent/references/recon/cdn-edge-and-bff-reachability.md`.

## C. Cross-issuer trust domains + the X-CSRF / channel-header envelope

Two gateway gotchas that make a perfectly valid token return errors:

**1. Cross-issuer — co-located hosts are not one trust domain.** The www member realm issuer
(`https://bank.acme.example/access-management/oauth2/member`) is a **different OAuth issuer** from the
`bank.acme.example` gateway, whose own OIDC discovery declares `issuer: https://bank.acme.example:8443`
(non-standard `:8443`). A token minted on www is **not** honored by the api gateway's *own* v5
web-token flow. **Read `/.well-known/openid-configuration` on each host and compare `issuer` /
`authorization_endpoint`** before assuming a token crosses. (The happy accident here: the api
*page-templates BFF* accepts the www access_token directly once the envelope is complete — but its
*native* v5 flow does not. Don't generalize "the token worked on one path" to "the issuers trust
each other.")

**2. The envelope runs BEFORE token evaluation.** `bank.acme.example` rejects at a request-**validation**
layer that fires *before* the bearer is looked at. Proof: no-token, a valid access_token, a captured
OpenAM bearer, and a fresh privileged token **all** returned byte-identical
`401 www-authenticate: Bearer error="Invalid request"` + `{"error":"invalid_request",
"error_description":"Validation error"}`. The token was irrelevant until the envelope passed. The
missing element was **`X-CSRF-Token: <MemberGlobalSession cookie value>`**, and the **header name is
exact** — only `X-CSRF-Token` cleared it; `X-XSRF-TOKEN`, `csrf-token`, `X-Acme Bank-CSRF`,
`X-Requested-With` all still failed. With it present, the BFF accepted the ordinary www token.

> **Operational read.** If *every* token (including a known-good one) yields the **same**
> `invalid_request`/validation error, the token is not the problem — you are missing an **envelope
> element** (a CSRF header sourced from a cookie, a channel/device header, a cookie the gateway
> cross-checks). **Diff the SPA's own working request against yours, header-by-header**, and source
> the missing header from the cookie jar (here: `X-CSRF-Token` = the `MemberGlobalSession` cookie
> value).

## D. Dead-end traps (don't burn time here)

- **The api `v5/web/token` + `AuthProofGenerator` + WAS-LTPA flow is a red herring.** The SPA's JS
  *does* reference a separate `https://bank.acme.example/auth/oauth/v5/web/token` flow gated by a
  WebSphere `LtpaToken2` cookie via `/inet/ent_ltpa_exchange/v3/AuthProofGenerator`. A proxy capture
  of the *ForgeRock* session does **not** carry a live WAS/LTPA session, so `AuthProofGenerator`
  returns `302 -> /Logon` and this path dead-ends for headless replay. It is also **unnecessary** —
  the silent-PKCE self-mint (§A) + the X-CSRF envelope (§C) reaches the same BFF data. Four agents
  burned on the v5 path before this was confirmed a dead end.
- **Scope is part of the token, not just the path.** The self-minted token is
  `page-templates`-scoped. Raw `/v2/enterprise/core-customer-individual-name/...` (outside the BFF
  prefix) returns `401` "outside scope" — you need a differently-scoped token, not a different
  envelope. Request the scope you need in the `authorize` call if the client is allowed it.
- **Shared/fragile session.** If the cookie jar is a shared operator session, re-read the
  `access_token` + CSRF-source cookie before every batch and re-baseline your own-object read first
  (the session can be invalidated out from under you).

## Generalization checklist (any IdP-backed SPA → separate API gateway)

1. Grep the SPA JS for `authorize`, `code_challenge`, `prompt=none`, the `client_id`, `scope`, and
   the `redirect_uri` (often an `auth-silent`/`silent-renew` path).
2. Reproduce the silent `authorize` with the session cookie jar and **`prompt=none`**; **follow any
   single edge interstitial** (`akredirect`-style) with `-L` before concluding the session is dead.
3. Exchange the code with the PKCE `code_verifier` at the token endpoint → fresh access_token.
4. **Read `/.well-known/openid-configuration` per host**; if `issuer` differs, the token may not
   cross — find the right mint or the right envelope.
5. If a known-good token still yields a uniform `invalid_request`/validation error, **add the
   envelope element** the SPA sends (CSRF header from a cookie, channel/device header).
6. **Gate on a live own-object 200** before recording any authed verdict; re-mint per batch to
   defeat token TTL.

## Cross-references

- `agent/skills/browser-automation/SKILL.md` — the **upstream** step: how to drive a headed stealth
  Playwright browser past a bot-defended login and dump `context.cookies()` into the cookie jar (`$JAR`)
  this reference consumes. This file is what you do *after* you hold those cookies.
- `agent/references/recon/cdn-edge-and-bff-reachability.md` — the consumer side: once the session is
  live, how to read `27368` (no origin map / not exposed) vs `2736803` (edge authz deny / exists) vs
  the BFF-capture trap, and the leaked-`serverIP`-is-CDN-edge caveat.
- `agent/references/gf-patterns/oauth-oidc.md` — OIDC discovery keys; the per-host `issuer` check.
- `agent/references/payloads/jwt-payloads.md` — once you hold a minted id_token, the alg/key-confusion
  attacks (HS256 issuers like the api gateway are in scope for key-confusion).
- `agent/skills/oauth-oidc-testing/SKILL.md` — the parent skill; this reference is its session-replay
  detail (silent self-mint + cross-issuer envelopes) beyond the redirect_uri/PKCE-tamper checklist.
- `agent/references/gf-patterns/redirect.md` — `redirect_uri` allow-list bypass at the URL level
  (the silent flow's `redirect_uri` is a high-value target for that class).
