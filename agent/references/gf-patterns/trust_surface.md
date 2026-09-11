---
name: gf-patterns:trust_surface
description: Sensitive lifecycle paths (`/upload`, `/webhook`, `/oauth`, `/reset`)
origin: local overlay (no upstream 1ndianl33t/Gf-Patterns pattern at the audited revision)
bucket: trust_surface
weight: 35
---

# GF Bucket: trust_surface

## Purpose

Sensitive lifecycle routes deserve attention even when they have no obvious vulnerable parameter name. Uploads, imports, exports, callbacks, password reset, OAuth, downloads, previews, and render/convert flows often trust attacker-controlled tokens, filenames, URLs, MIME types, or object references.

## Classifier Signal

- Weight: `35`
- Parameter keys: none; this is intentionally path-driven
- Path fragments: `/upload`, `/import`, `/export`, `/webhook`, `/callback`, `/reset`, `/recover`, `/invite`, `/share`, `/oauth`, `/authorize`, `/token`, `/connect`, `/download`, `/preview`, `/render`, `/convert`

## Review Notes

This bucket is Python-only, not a direct upstream GF pattern. Keep it because adversarial review repeatedly finds bugs at trust boundaries that do not advertise themselves through parameter names.
