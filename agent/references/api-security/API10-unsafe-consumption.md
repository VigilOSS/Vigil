---
description: Unsafe consumption of third-party APIs (fetchers that follow redirects, unsigned inbound webhooks, trusted IdP or partner data, fail-open integrations)
skill: ssrf-testing
---

# API10:2023 — Unsafe Consumption of APIs

The target trusts what another API sends it. Where each case is worked:

- **Outbound fetchers** that take a user-configurable integration, webhook or callback URL, and
  whether the backend follows a 302 from an external host to an internal one:
  `agent/skills/ssrf-testing/SKILL.md` ("SaaS integration connectors").
- **Inbound webhooks** (`/webhooks/stripe`-style receivers): no or invalid signature, replay of a
  captured delivery, and an edited body (event type, amount, user ID) accepted; signature checks are
  in `agent/skills/business-logic-testing/SKILL.md` ("Webhook integrity").
- **Identity-provider tokens:** issuer and `aud` not validated, a token from one provider accepted
  where another is expected: `agent/skills/oauth-oidc-testing/SKILL.md`.
- **Partner data:** partner-supplied fields stored or rendered without encoding (stored XSS or
  injection reached through the integration), or trusted for access-control, price or inventory
  decisions.
- **Failure handling:** the integration unavailable or timing out fails open (business-logic
  "Degraded mode"), or its error responses leak internal state.
- **Source-side:** outbound calls over plain HTTP or with TLS verification disabled, and hardcoded
  third-party credentials: `agent/skills/source-analysis/SKILL.md`.
