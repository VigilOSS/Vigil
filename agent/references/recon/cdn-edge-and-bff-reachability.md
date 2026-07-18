---
description: Reading CDN/edge error-envelope semantics to decide whether a path is architecturally NOT exposed vs auth/scope-denied vs session-dead — Akamai errorCode 27368 (no origin map), 2736803 (edge access-control deny), 498 MISSING_MAIN_HEADER (missing signed mobile header), the akredirect interstitial bounce; the BFF-capture trap (browser-proxied URLs that are server-side-only) and the "test with a confirmed-LIVE token before declaring unreachable" rule; the cross-issuer trust-domain + X-CSRF-Token envelope gotcha; and the "origin IPs in error envelopes are usually the CDN edge, not true origin" caveat. Worked example: Akamai-fronted bank.acme.example. DISTINCT from cdn-edge-behavior.md (edge defending against your probe) and cdn-ip-blocking.md (our egress IP on a reputation list).
skill: web-recon
---

# CDN / Edge Error-Envelope Semantics + BFF Reachability

This reference is about **deciding what a CDN/edge error actually means** — specifically,
whether a path is **architecturally not exposed to the internet** (no origin behind it),
**reached the edge but denied by an access-control rule**, or **reached the origin and was
answered by the app**. Getting this wrong produces the two most expensive false verdicts on a
CDN-fronted API: declaring a path "unreachable" when your *session* was simply dead, or chasing
a "data" endpoint that only ever existed as a **server-side BFF call** and is not routable from
the internet at all.

It is **distinct** from two neighbouring files — read the right one:

- `agent/references/runtime-guides/cdn-edge-behavior.md` — the **target edge defending itself
  against your probe** (per-request WAF deny vs rate-block vs Bot-Manager UA block). Read that
  when a *specific malicious-looking probe* is denied but the host is otherwise live.
- `agent/references/runtime-guides/cdn-ip-blocking.md` — **our own egress IP** is on a CDN
  reputation list and *all* recon collapses to 403. Read that when every host goes dark.
- **This file** — the path is *clean* (no payload, no reputation issue) and you need to read the
  **error envelope** to decide: not-exposed vs edge-authz-deny vs origin-answer vs dead-session.

Worked example throughout: **Akamai-fronted `bank.acme.example`** (Acme Bank banking API gateway,
2026-06-19). Vendor specifics (the numeric `errorCode`s, the `akredirect` bounce, `MISSING_MAIN_HEADER`)
are **Akamai/Acme Bank traits**; the *method* — never trust a single status, classify the envelope, and
gate on a known-live control — generalizes to any CDN.

## Why this matters

A `500`/`403`/`401` on a CDN-fronted API path is **not** a verdict by itself. The same status can
mean four completely different things, and three of the four are commonly misread:

1. **The edge has no origin mapping for that path** — the path is architecturally NOT exposed.
   This is the strongest possible "out of scope / not attackable" signal, but it *looks* like a
   generic server error.
2. **The edge reached an access-control rule and denied you** — the path *is* exposed; you have
   the wrong token/scope. This is a real, attackable signal (find the right scope).
3. **The origin answered** — a genuine application verdict (200/206/401/403 from the app).
4. **Your session is dead** — every authed path returns 401/403 and you wrongly conclude the
   *paths* are unreachable. This is the trap that burned four prior agents on `bank.acme.example`.

The disambiguator is the **error envelope** (the JSON/headers the edge returns) plus a
**liveness control** (a path you *know* returns 200 for your identity).

## A. Akamai edge error-code semantics (the worked example)

Akamai-origin error envelopes carry a numeric `errorCode` (and a `diagnosticData` block with
`clientIP`/`serverIP`/`serverVIP`/`requestID`). The `errorCode` is the load-bearing field — the
HTTP status alone is ambiguous.

| Signal | Status / shape | What it MEANS | Attackability |
|---|---|---|---|
| **`errorCode 27368`** | `HTTP 500`, ~420-byte `text/html` `{"code":"500","errorCode":"27368",...}`, `Server: AkamaiGHost`, `x-cache: TCP_MEM_HIT` (edge-**cached**) | **The edge has no origin map for this path** — the request never reaches an origin. Architectural NOT-exposed. The 500 (not 404) is because all unknown paths fall through to one edge error handler. | **Not attackable** — there is no origin behind it. The strongest not-exposed verdict. |
| **`errorCode 2736803`** | `HTTP 403`, Acme Bank-origin JSON error envelope | **Edge access-control / authz deny** — the request reached an edge ACL or WAF rule. The path *is* mapped; you were denied (wrong scope/token/identity). | **Attackable surface** — the path exists. Hunt for the right scope/token; this is signal, not a dead end. |
| **`errorCode 498` / `MISSING_MAIN_HEADER`** | `HTTP 498` (Acme Bank-custom), required value in a base64 `x-Acme Bank-em` response header; `secondaryCode: MISSING_MAIN_HEADER` | **Origin gateway rejecting requests that lack a required signed device/channel "main header"** that only the native mobile app sends. (Observed on `mapi`/`mapi-a`/`mobileapps`.) | **Gated, not absent** — reachable only by reproducing the signed header (reverse from the mobile app / capture native traffic). External recon dead-end; mobile-track lead. The base64 `x-Acme Bank-em` is itself a minor info-disclosure (leaks `serverIP`/`serverVIP`/`requestID` + the gate name). |
| **`akredirect` interstitial** | A `302` to an Akamai edge **`akredirect`** URL that bounces once, then lands on your real target (`...?code=<CODE>`) | **A transient Akamai edge gate, NOT a login/session failure.** It looks like a self-redirect or a bounce back to `/Logon`, which is exactly why agents misread a *working* silent-auth flow as "session expired". | **Follow it once** (`curl -L`, `--max-redirs 5`). After the single bounce the flow proceeds normally. Treating it as a failure is a false negative. |

**The decisive proof that `27368` is architectural, not a session/WAF artifact.** A token that
returns **`200` on one path** (e.g. the live `party/id/{own-guid}` BFF control) and **`27368` on
another path in the same batch** proves the `27368` is about the *path having no origin map*, not
about your token, your session, or a WAF rule. Always run this differential before recording a
not-exposed verdict: same identity, same envelope, one known-good path + the path under test.

**Contrast across sibling hosts (don't assume uniform behavior).** On the same engagement,
`bank.acme.example` returned `500`/`27368` for unknown paths, `bank.acme.example` returned plain `404`,
and `bank.acme.example` returned `498`. The error grammar is **per-host config**, not a property of
"Acme Bank" — re-baseline each host.

## B. The BFF-capture trap (and the confirmed-live-token rule)

**The trap.** A browser/proxy capture (mitmproxy, Burp) shows the SPA calling a URL like
`/v2/payments-platform/funds-transfer` or `/enterprise/aml/kyc/sanctions/...`. It is tempting to
replay that URL directly and, when it returns `500`/`27368`, conclude "exposed but broken" — or
worse, to treat it as a reachable money-movement endpoint. **Many such URLs are server-side-only
BFF calls**: the *presentation BFF* (here `bank.acme.example/v1/presentation/page-templates/...`) makes
them origin-side, on the member's behalf, and they are **never routable from the public internet**.
The browser only ever saw the *BFF wrapper response*, not a direct call to the inner path.

On `bank.acme.example` the verdict matrix came out as:

- **`aml/kyc/sanctions`, `funds-transfer`, `billpay`, `member-eligibility`, `join/prefill`,
  `member-authentication/credentials`, `userinfo`** → `500`/`27368`, **identical bare vs.
  full-live-envelope**, in BOTH the direct `/enterprise/...` form AND the
  `/v1/presentation/page-templates/...`-wrapped form → **genuinely NOT externally routable.**
- **`spousal-access/parties`, `member-home/banking`** → `401` bare / `403`+`2736803` full →
  edge access-control deny (wrong-scope token, reached a rule, not the origin).
- **Only 3 guid-keyed page-templates BFF object endpoints reach member data**
  (`party/id/{guid}`, `marketing-analytics/digital-profile/{guid}`,
  `core-customer-individual-name/individuals/{guid}/name`) — and **object-level authz is ENFORCED
  on all three** (guid-swap BOLA negative).

**The rule that makes the verdict sound — test with a confirmed-LIVE token first.** Before you
record *any* "unreachable" / "not exposed" conclusion against an authed API:

1. **Gate on liveness.** Hit a path you *know* returns 200 for your identity (an own-object
   read). If that control is not 200, your session is dead — **STOP**, re-capture/re-mint, and
   discard every "unreachable" result you just collected. A dead-session 401/403 is **not**
   evidence of unreachability. (Prior `bank.acme.example` agents recorded "unreachable" verdicts that
   were entirely a dead captured token — see §C for the fix that decouples from token TTL.)
   When the identity lives in the credential store, run this gate with the built-in probe —
   `vigil assess auth status --probe --identity <name> --probe-url <authed-url>` — instead of a
   one-off own-object curl: it never follows redirects and persists a real `live`/`dead`/`unknown`
   verdict against that identity (declare `material.liveness` once via `vigil auth import`/`edit`
   if it isn't set yet), so every subsequent dispatch reads the same ground truth rather than
   re-deriving it.
2. **Run the differential.** For each path under test, compare **bare (no-auth)** vs **full
   live-envelope** responses, in *both* the direct and the BFF-wrapped form. If bare and
   full-live are byte-identical `27368`, the path is not routed (auth is irrelevant — there's no
   origin). If full-live advances the error (e.g. `401`→`403`/`2736803`), you reached a rule and
   the path exists.
3. **Only then** write the verdict, citing the live control status in the same batch.

A ready-made implementation of this exact gate-then-differential pattern lives at
`tools/exploit-state/sensitive-endpoint-replay.sh` in the Acme Bank engagement (mints a fresh token,
asserts the party-oracle own-guid is 200, then prints the bare-vs-full status differential for
every sensitive path) — use it as the template for any "is this BFF path actually reachable"
question.

## C. Cross-issuer trust domains + the X-CSRF envelope gotcha

A single brand often runs **multiple OAuth issuers that do not trust each other's tokens**, and a
gateway may demand a **non-bearer envelope element before it even evaluates the bearer token**.
Both bit the Acme Bank engagement and both are easy to miss.

- **Cross-issuer:** the www member realm issuer
  (`https://bank.acme.example/access-management/oauth2/member`) is a **different OAuth issuer** from the
  `bank.acme.example` gateway, whose OIDC discovery declares `issuer: https://bank.acme.example:8443`
  (note the non-standard `:8443`). A token minted on www is **not** accepted by the api gateway's
  *own* v5 web-token flow. Always read `/.well-known/openid-configuration` on **each** host and
  compare the `issuer`/`authorization_endpoint` — co-located hostnames do **not** imply a shared
  trust domain.
- **The X-CSRF envelope element runs BEFORE token evaluation.** `bank.acme.example` rejects at a
  request-**validation** layer that fires before the bearer token is looked at: no-token, a valid
  access_token, and a fresh privileged token all returned **byte-identical**
  `401 www-authenticate: Bearer error="Invalid request"` + `{"error":"invalid_request",
  "error_description":"Validation error"}` until the envelope was completed. The missing element
  was **`X-CSRF-Token: <MemberGlobalSession cookie value>`**. Header-name matters: only
  `X-CSRF-Token` cleared the check (`X-XSRF-TOKEN`, `csrf-token`, `X-Acme Bank-CSRF`, `X-Requested-With`
  all still failed). With that header present, the page-templates BFF endpoints accepted the
  **ordinary www `access_token`** directly — the elaborate "api v5 web-token / AuthProofGenerator /
  WAS-LTPA" flow turned out to be a **dead-end red herring** and was unnecessary.

**Operational read.** If *every* token (including a known-good one) yields the **same**
validation/`invalid_request` error, the token is not the problem — you are missing an **envelope
element** (a CSRF header, a channel header, a cookie the gateway cross-checks). Diff the SPA's own
working request against yours header-by-header before concluding "auth is broken." See
`agent/references/web/oauth-spa-session-replay.md` for the silent-PKCE self-mint that produces a
fresh token to test the envelope with, and the cross-issuer handling.

## D. Honest caveat — "origin IPs" in error envelopes are usually the CDN edge

Akamai (and most CDNs) include a `diagnosticData` block leaking `serverIP` / `serverVIP` /
`clientIP` / `requestID`. It is **tempting to treat `serverIP` as the true origin** and attempt a
direct-to-origin bypass (Host-header / SNI to that IP to skip the edge). **Resist it.** On
`bank.acme.example` the leaked `serverIP 23.3.12.227` / `serverVIP 23.49.186.129` reverse-resolved to
`a23-3-12-227.deploy.akamaitechnologies.com` — i.e. they are **Akamai edge nodes, not the
backend origin**. A direct-to-origin attempt against them just hits another edge node; the
true origin is not disclosed. Before spending effort on an origin-bypass from an error envelope:

- **rDNS / ASN-check the leaked IP.** If it resolves into the CDN's own space
  (`*.akamaitechnologies.com`, Cloudflare/Fastly/CloudFront ranges, the CDN's ASN), it is an edge
  node — origin bypass is a dead end (this killed the Acme Bank `RE-002` origin-bypass lead).
- Treat the leak as **minor info-disclosure** (internal IPs + the gating mechanism name +
  request-tracing IDs) — worth recording as a low-severity finding, **not** as an origin-bypass
  primitive, unless rDNS/ASN actually places the IP outside the CDN.

## Quick procedure (drop-in)

1. **Baseline the host's error grammar.** Hit `/` and a junk path unauthenticated; capture the
   status, `Server`, `x-cache`, and any `errorCode`/`x-Acme Bank-em`/`diagnosticData`. Each sibling host
   may differ — re-baseline per host.
2. **Classify the envelope** (§A): `27368`-class (no origin map / not exposed) vs
   `2736803`-class (edge authz deny / exists) vs `498`-class (missing signed header / mobile-gated)
   vs an `akredirect` bounce (follow it once).
3. **Establish a liveness control** (§B-rule): an own-object read that you can make return 200.
4. **Run the bare-vs-full differential** for every path under test, in both direct and BFF-wrapped
   forms; identical-`27368` = not routable, advancing-error = reachable rule.
5. **Complete the envelope** (§C) if every token yields the same `invalid_request` validation
   error — add the CSRF/channel header the SPA sends; check issuer-per-host for cross-issuer trust.
6. **rDNS/ASN any leaked `serverIP`** (§D) before any origin-bypass effort.

## Cross-references

- `agent/references/web/oauth-spa-session-replay.md` — the **silent-PKCE self-mint** that produces
  a fresh, confirmed-live token for the §B liveness gate, plus the cross-issuer / X-CSRF envelope
  handling in depth. (Paired with `oauth-oidc-testing`.)
- `agent/references/runtime-guides/cdn-edge-behavior.md` — the **distinct** concern: the edge
  defending against a *malicious-looking probe* (WAF deny vs rate-block vs Bot-Manager UA block).
- `agent/references/runtime-guides/cdn-ip-blocking.md` — the **distinct** concern: our own egress
  IP on a CDN reputation list (global 403 collapse).
- `agent/references/payloads/info-disclosure-probes.md` and
  `agent/skills/info-disclosure-testing/SKILL.md` — the leaked `serverIP`/`requestID`/gate-name in
  the error envelope is a low-severity info-disclosure to record (§D).
- `agent/references/payloads/bff-override-params.md` / `agent/skills/bff-parameter-override/SKILL.md`
  — once a BFF path is confirmed *reachable* (not §B-trap), the internal-parameter override surface.
- `agent/references/gf-patterns/oauth-oidc.md` — OIDC discovery keys; read `issuer` per host for
  the §C cross-issuer check.
- `agent/skills/web-recon/SKILL.md` — wafw00f→edge-tier mapping; this file is the
  error-envelope-reading detail behind the "is it even exposed" recon step.
