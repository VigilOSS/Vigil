---
name: gf-patterns:llm_api
description: LLM and agent API route and request-key patterns that signal prompt injection, system-prompt disclosure, tool-calling SSRF, and unbounded token spend
origin: local overlay (no upstream gf equivalent)
bucket: llm_api
skill: llm-api-testing
weight: 40
---

# gf: llm_api

## What this bucket classifies

HTTP endpoints that hand attacker-influenced text to a language model and act on what comes back:
chat/completion routes, embedding/RAG ingestion, self-hosted inference endpoints, and any route
carrying the LLM request vocabulary (`system_prompt`, `messages`, `max_tokens`, `tool_choice`, …).

The class this routes to is `prompt-injection` (family `ai-ml`). The taxonomy has declared that
family since it was written; until this bucket existed, **no gf-bucket mapped to it**, so the
web/URL track could never route a row there at all.

## Load this reference when

- The corpus contains `/v1/chat/completions`, `/embeddings`, or `/inference` routes
- A parameter named `system_prompt`, `messages`, `max_tokens`, or `tool_choice` appears
- You are deciding whether a chat-shaped surface is worth a dispatch and to which specialist

## Parameter keys that match

`user_prompt, userprompt, system_prompt, systemprompt, prompt_template, prompttemplate,
system_message, systemmessage, messages, max_tokens, maxtokens, top_p, topp, embedding, embeddings,
tool_choice, toolchoice, function_call, functioncall`

Both `snake_case` and concatenated (camelCase-lowercased by `collect_keys`) spellings are listed,
mirroring the curated compound families on `rce` / `ssrf` / `redirect`.

The bare token `prompt` is **not** a key — see "What it does NOT classify".

## Path patterns that match

`/completions`, `/embeddings`, `/inference`

`fragment_in_path` anchors at `[/?#=&.]` or end-of-string, so `/completions` already covers
`/v1/chat/completions` and `/openai/deployments/<name>/chat/completions` — a separate
`/chat/completions` fragment would be a redundant sibling, not extra recall.

## Weight and priority interpretation

- Baseline priority score: 40 — the tier of `auth` / `deserialization` / `sqli`. An LLM endpoint is a
  first-class application surface (prompt injection, tool-calling SSRF, system-prompt disclosure,
  unbounded token spend), and it must outrank the `api-versioning` (25) and `api` (20) family-level
  hints.
- **Declared LAST in the weight-40 run** (after `xxe`). At equal weight the first-declared bucket
  wins `cluster_key`, so this position guarantees the addition cannot re-cluster any pre-existing
  weight-40 row — the additive rule of ADR 0008. Pinned by
  `agent/scripts/assess/tests/test_classify_llm_api.py`.
- Terminal reasons that suppress this bucket: `inert_type`.

## Example URLs that match

- `https://target.example/v1/chat/completions` — chat-completion endpoint
- `https://target.example/openai/deployments/gpt-4o/chat/completions` — Azure OpenAI deployment route
- `https://target.example/api/inference` — self-hosted model server
- `https://target.example/api/assistant?system_prompt=…` — system-prompt request key
- `https://target.example/support/ask` with body `{"messages":[…],"max_tokens":4096}` — the request
  KEYS are what catch an Anthropic/OpenAI-shaped proxy, at whatever path it is mounted

## What it does NOT classify

Signals deliberately kept out, because each would flood the bucket with ordinary REST surface:

- **`model`** — every product filter, device catalogue and CMS carries a `?model=` parameter. A
  bucket firing on it would swallow half the corpus.
- **`system`** — `?system=linux` on a downloads or config route.
- **`temperature`** — IoT, thermostat, weather and lab-equipment APIs own this word.
- **`tools` / `functions`** — generic collection nouns, and `func`/`function` are already `rce`
  members at weight 50, so a bare `functions` key would mis-cluster the row as `gf:rce`. The
  compound `tool_choice` / `function_call` keys ARE carried: they name the tool-calling surface
  unambiguously.
- **The bare `prompt` key.** OIDC Core §3.1.2.1 *defines* `prompt`, with the values `none` /
  `login` / `consent` / `select_account`, and Azure AD, Auth0, Okta, Keycloak and Google all emit
  it. At weight 40 it re-clustered the highest-value auth surface in a web engagement as an LLM
  endpoint: `/oauth2/authorize?client_id=…&prompt=login` became `gf:llm_api`, accruing an
  unclosable `prompt-injection` coverage item on every SSO entry point and turning the gap
  recommendation into `llm-api-testing` where `auth-bypass` / `saml-sso-testing` belongs.
  `/login?prompt=select_account` survived only because `auth` is declared first at the same weight
  — a tie-break, not a design. It was dropped rather than guarded by an
  `_suppress_auth_on_sso_route`-style predicate, because such a predicate must enumerate IdP
  authorize routes and companion vocabulary, and every gap in that enumeration silently recreates
  the defect on the surface that can least afford it. The compounds carry the recall and are
  unambiguous: no IdP claims `user_prompt` / `system_prompt` / `prompt_template`.
- **A bare `/messages`, `/chat` or `/generate` path fragment** — an inbox, a support-chat widget and
  a report exporter respectively.
- **The version-qualified `/v1/messages` and `/v1/responses`**, for the same reason. REST APIs are
  conventionally versioned, so `/api/v1/messages` IS the inbox route and `/api/v1/responses` IS the
  survey-response route; qualifying a generic collection noun with `/v<n>/` buys no discrimination,
  it only moves the flood behind a prefix. Those routes now land where their evidence points —
  `gf:idor`, via the path object-ref predicate on `/api/v1/messages/1024`.
- **Provider host markers** (`api.openai.com`, `api.anthropic.com`) as a `_FULL_URL_REGEX_BUCKETS`
  rule — considered and skipped. A target's own URLs rarely carry the provider host, and the
  provider's API is out of scope by definition; the mechanism would be speculative rather than
  corpus-grounded. See `DRIFT.md`.

## Attack classes

- **Indirect prompt injection** — instructions planted in content the model *retrieves* (an uploaded
  document, a profile field, a support ticket, a fetched page) that execute on a different user's
  request. This is the variant with a real victim, and the one most often left untested.
- **System-prompt / context disclosure** — extraction of the server-side policy prompt, of retrieved
  documents, or of another tenant's context bleeding into the window.
- **Tool-calling SSRF and agent actions** — a fetch/browse/webhook tool invoked with
  attacker-chosen arguments, proved with an OOB callback. An agent that renders a markdown image
  from attacker text is an exfiltration channel.
- **Conversation-scope IDOR** — `conversation_id` / `thread_id` / `assistant_id` swapped across
  accounts; chat-shaped URLs are still object references.
- **Unbounded token spend** — a client-supplied `max_tokens`, a caller-selectable `model`, or an
  unauthenticated proxy to a paid provider key: direct financial loss, and usually the cheapest real
  bug on this surface.

## Corpus grounding

Measured before this bucket existed: `/v1/chat/completions` reached only `25 gf:api-versioning`
(from the generic `/v<n>/` regex, i.e. it was indistinguishable from any other versioned route),
and `?system_prompt=` scored **0**, landing in the `path:/api/assistant` fallback. The code track
already recognised the surface —
`code_analysis.ROLE_CONTEXT_VULN_CLASSES` maps the `llm`/`prompt`/`rag`/`mcp`/`embedding` role
keywords to `ai-ml-security` — so the web track was the only one blind to it.

## Sources

- [OWASP Top 10 for LLM Applications — LLM01 Prompt Injection](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP API Security Top 10:2023 — API4 Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)
- [NIST AI 100-2 — Adversarial Machine Learning: Taxonomy and Terminology](https://csrc.nist.gov/pubs/ai/100/2/e2023/final)

## Related

- `agent/skills/llm-api-testing/SKILL.md` — the procedure this bucket dispatches.
- `agent/references/gf-patterns/ssrf.md` — a tool-calling fetch lands here; prove it with OOB.
- `agent/references/gf-patterns/idor.md` — conversation/thread scope is object-level authorization.
- `agent/references/gf-patterns/api-versioning.md` — co-fires on `/v1/...` as a generic version hint.
