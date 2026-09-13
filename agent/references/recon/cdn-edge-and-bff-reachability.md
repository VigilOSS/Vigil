---
description: Classifying CDN and API-gateway error envelopes without confusing an unmapped path, an authorization denial, an origin response, or an expired session; includes BFF reachability, cross-issuer, envelope-header, and leaked-edge-IP checks using a fictional target.
skill: web-recon
---

# CDN / Edge Error Envelopes and BFF Reachability

Use this reference when a clean request to a CDN-fronted API returns an ambiguous
`401`, `403`, `404`, `498`, or `500`. A status code alone cannot tell you whether the
path is absent, mapped but denied, answered by the origin, or tested with a dead
session. The reliable method is a controlled response differential.

This is distinct from:

- `agent/references/runtime-guides/cdn-edge-behavior.md`, which covers a WAF or bot
  control reacting to the probe itself; and
- `agent/references/runtime-guides/cdn-ip-blocking.md`, which covers the operator's
  egress IP being reputation-blocked across otherwise unrelated paths.

All names and response shapes below are synthetic. Learn the target's real grammar
from its own traffic; do not assume these example labels are vendor constants.

## The four verdicts

1. **No route to an origin.** The edge handles the request with a stable, often
   cached error. Authentication changes nothing because the path has no backend.
2. **Mapped but denied.** Supplying the correct request envelope changes the
   response, but an edge or gateway authorization rule still rejects the identity.
3. **Origin answered.** Origin-specific headers, body shape, latency, or a known
   application response proves the request crossed the edge.
4. **Session dead.** A previously working own-object control fails in the same
   batch. No path-level conclusion from that batch is trustworthy.

## Build a response fingerprint

Record more than the status:

- body bytes or a stable body digest;
- `Server`, cache, request-ID, gateway, and redirect headers;
- content type and length;
- redirect chain;
- timing; and
- any structured error code or secondary reason.

A fictional gateway might expose these distinguishable shapes:

| Shape | Interpretation | Next action |
|---|---|---|
| Cached `500` with `errorCode: EDGE_NO_ROUTE`, identical with and without auth | No public origin mapping | Record not externally routable with the live-control evidence |
| `401` becomes `403` with `errorCode: POLICY_DENY` after adding the live envelope | A mapped policy boundary exists | Test the correct identity, scope, and object |
| `498` with `secondaryCode: DEVICE_HEADER_REQUIRED` | Origin or gateway expects a signed channel header | Route to the mobile/client-analysis track |
| One edge interstitial redirect, then the expected callback | Edge challenge, not necessarily session expiry | Follow a bounded redirect chain once and inspect the final URL |

These labels are examples only. The evidence is the differential, not the spelling.

## Live-control-first procedure

Before classifying an authenticated path, prove the identity is live against a
known own-object endpoint:

```bash
vigil assess auth status \
  --probe \
  --identity user_a \
  --probe-url https://api.acme-bank.example/v1/me
```

If the control is not live, stop and refresh the identity. A dead-session `401` or
`403` says nothing about whether another path is routed.

With a live control in the same batch, compare each candidate using:

1. no authentication;
2. the complete known-working cookies, bearer, CSRF value, and required channel
   headers; and
3. where applicable, both the browser-visible BFF URL and the suspected inner URL.

Persist the raw responses. If the unauthenticated and complete-envelope requests
are byte-identical edge errors while the live control remains `200`, the strongest
supported verdict is “not publicly routed.” If the envelope advances the response,
the path is mapped and the changed layer is useful attack-surface evidence.

## The BFF capture trap

A browser response can contain data fetched server-side by a backend-for-frontend.
An inner path visible in JSON, source maps, or logs is not proof that the browser
called that path directly. For a synthetic example, the browser may request:

```text
https://api.acme-bank.example/v1/view/account-summary
```

while the BFF internally calls:

```text
/internal/ledger/accounts/{account_id}
```

Test both forms with the same live identity. A stable edge “no route” response on
the inner form means the path is not externally reachable; it does not prove the
inner service is broken or exposed. Keep captured URL provenance—browser request,
response-embedded string, JavaScript constant, or server-side trace—so these
categories are not collapsed.

## Cross-issuer and request-envelope checks

Sibling hosts can use different OAuth issuers. Read
`/.well-known/openid-configuration` for each trust domain and compare `issuer`,
`authorization_endpoint`, audience, and supported scopes. A token working on
`app.acme-bank.example` is not evidence that `api.acme-bank.example` accepts it.

Some gateways validate a CSRF cookie/header pair, device proof, or channel header
before evaluating the bearer token. If no token, a known-good token, and a
different token all produce the same validation error, diff the SPA's working
request header-by-header. Complete the request envelope before declaring an
authentication failure.

## Leaked “origin” addresses

CDN diagnostics often include `serverIP`, `serverVIP`, or similarly named fields.
Do not call these origin IPs without proof. Check reverse DNS, ASN ownership, TLS,
and response equivalence. If the address belongs to the CDN, it is another edge
node, not an origin-bypass primitive. Preserve the diagnostic disclosure as
evidence, but rate impact from what it actually enables.

## Completion checklist

- The own-object liveness control succeeded in the same batch.
- Bare and complete-envelope responses were retained and compared.
- Direct and BFF-wrapped forms were kept distinct.
- Issuer and audience assumptions were checked per host.
- Uniform validation errors triggered an envelope diff.
- Leaked addresses were attributed by rDNS/ASN/TLS before origin claims.
- The final verdict names the observed layer and its evidence, not only a status.

## Cross-references

- `agent/references/web/oauth-spa-session-replay.md`
- `agent/references/runtime-guides/cdn-edge-behavior.md`
- `agent/references/runtime-guides/cdn-ip-blocking.md`
- `agent/references/payloads/bff-override-params.md`
- `agent/skills/info-disclosure-testing/SKILL.md`
