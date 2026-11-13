---
description: API-specific SSRF sinks (webhooks, HTML-to-PDF renderers, URL import, image proxy and unfurl, OAuth redirect_uri)
skill: ssrf-testing
---

# API7:2023 — Server Side Request Forgery

Workflow, OOB mechanics and oracles: `agent/skills/ssrf-testing/SKILL.md`. URL schemes,
parser tricks, DNS rebinding, redirect chains and cloud metadata paths:
`agent/references/payloads/ssrf-payloads.md`.

## API sinks

- **Webhook registration:** an internal URL or metadata endpoint as the webhook `url`; note whether
  the delivery response comes back to the user (full SSRF) or only its status (blind).
- **HTML-to-PDF / HTML render:** user HTML reaches a server-side renderer, so every subresource is a
  fetch: `<img src>`, `<iframe src>` (a metadata credentials path renders into the PDF), `<link>`,
  `<script>`, and CSS `url()` in a `style` block.
- **URL import / fetch:** "import from URL", file-from-URL upload, `avatar_url` / image URL fields,
  RSS/feed parsers.
- **Image proxy and previews:** `/proxy?url=`, link unfurl, OpenGraph/metadata fetchers.
- **OAuth `redirect_uri`:** an internal URL where the server fetches or validates it during
  authorization.
