---
name: gf-patterns:webhook
description: Inbound/outbound webhook registration and delivery endpoint patterns
origin: local overlay (no upstream gf equivalent)
bucket: webhook
skill: ssrf-testing
weight: 30
---

# gf: webhook

## What this bucket classifies

Webhook registration and delivery endpoints where an attacker can supply a
server-controlled delivery URL (SSRF via webhook), intercept inbound payloads (HMAC
bypass), or enumerate registered destinations.

## Load this reference when

- The corpus contains `/webhook`, `/webhooks`, `/hook`, `/hooks`, or `/notify` paths
- Param keys `endpoint` or `target` appear in the registration query string or body
- Operator is assessing integrations where third-party events are delivered to caller-supplied URLs

## Parameter keys that match

`endpoint, target`

`url` is deliberately excluded — `ssrf` at weight 40 already wins on `?url=` and a webhook
registration with `?url=` will correctly cluster as `gf:ssrf` (the higher-weight bucket).
The `endpoint` and `target` keys provide webhook-specific additional signal for paths that
use those names instead.

## Path patterns that match

`/webhook`, `/webhooks`, `/hook`, `/hooks`, `/notify`

`/callback` is OMITTED — it is owned by `trust_surface` (weight 35). `/event` and `/events`
are OMITTED because they are content-navigation-prone: `/events/2024/conf` is a conference
listing, not a webhook. The real webhook-with-target case is captured by the `endpoint`/`target`
param keys, while the unambiguous `/webhook(s)` and `/hook(s)` routes fire path-only.
See the implementation note in `classify_buckets.py`.

## Weight and priority interpretation

- Baseline priority score: 30
- Lower than `ssrf` (40) because a webhook path alone does not confirm an attacker-supplied URL
  is being fetched server-side; specialist dispatch at 30 is correct before confirming SSRF
- When `url=` is also present, `ssrf` (40) wins the cluster; `gf:webhook` still appears in
  the `priority_reason` chain as a secondary reason
- Terminal reasons that suppress this bucket: `inert_type`

## Example URLs that match

Path-fragment matches:

- `https://target.example/webhook` — single webhook registration endpoint
- `https://target.example/webhooks/register` — REST webhook management
- `https://target.example/hook/create` — abbreviated hook path
- `https://target.example/hooks` — webhook listing endpoint (IDOR surface for enumerating others')
- `https://target.example/notify` — notification delivery endpoint

Param-key matches (co-fire with path):

- `https://target.example/webhook/create?endpoint=https://attacker.example/capture` — SSRF candidate
- `https://target.example/hooks/new?target=https://internal.corp:8500/v1/catalog` — internal delivery target

## What it does NOT classify

- `/callback` — owned by `trust_surface`
- `/events` or `/event` — content-navigation paths; see design rationale above
- Webhook signing secret params (`secret`, `token`) — those fall to `interestingparams`
- Inbound webhook payloads from third parties (GitHub push events, Stripe payment events) —
  inbound delivery is the opposite direction; classify by the receiving endpoint type

## Attack classes

- **SSRF via webhook URL:** attacker supplies `endpoint=http://169.254.169.254/...` or
  `endpoint=http://internal-redis:6379`; server fetches/delivers to the attacker-controlled URL
- **HMAC secret bypass:** webhook delivery signatures (X-Hub-Signature, Stripe-Signature) can
  be bypassed when the server verifies with a weak or empty shared secret
- **IDOR on webhook list:** `/webhooks` or `/hooks` endpoints sometimes return all registered
  webhooks regardless of ownership; swap `?owner=user_id` or paginate without auth
- **Replay attack:** webhook payloads without timestamp validation (`X-Timestamp`) can be
  replayed indefinitely to trigger the registered action

## Corpus grounding

Webhook registration and delivery routes recurred across independent reviews but remained a
secondary signal, supporting the conservative P3 classification. See
`docs/research/classify-surface/README.md` for the public evidence summary.

## Sources

- [PayloadsAllTheThings — SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a/Server%20Side%20Request%20Forgery)
- [OWASP — Webhook security](https://cheatsheetseries.owasp.org/cheatsheets/Webhook_Delivery_Security_Cheat_Sheet.html)

## Related

- `agent/references/gf-patterns/ssrf.md` — primary SSRF bucket; wins over webhook when `url=` is present
- `agent/references/gf-patterns/trust_surface.md` — broader trust-delegation surface that owns `/callback`
- `agent/references/gf-patterns/idor.md` — webhook list endpoints as BOLA surfaces
