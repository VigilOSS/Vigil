---
name: llm-api-testing
description: LLM and agent API security testing over HTTP — prompt injection, system-prompt disclosure, tool-calling SSRF, cross-tenant conversation access, unbounded token spend
origin: Vigil
vuln_class: prompt-injection, ai-ml-security
---

# LLM / Agent API Testing

> **`vigil assess kali` audit flags:** use `--technique RECON --probe-kind fingerprint` to map the
> endpoint shape and provider dialect; `--technique PROMPT-INJECTION` for injection and
> system-prompt-extraction payloads; and the sink's OWN class when an injected instruction reaches a
> downstream sink — `SSRF` for a tool/retrieval fetch, `IDOR` for cross-tenant conversation reads,
> `INFO-DISCLOSURE` for leaked context.

## When to Activate

- A route matching the `llm_api` gf-bucket surfaces in the work buffer (`/v1/chat/completions`,
  `/embeddings`, `/inference`, or a `messages` / `system_prompt` / `max_tokens` / `tool_choice`
  parameter). A bare `?prompt=` is NOT one of them — OIDC Core §3.1.2.1 defines `prompt`, so on an
  authorize route it is an SSO parameter, not an LLM one; judge it by the rest of the request.
- A response streams `text/event-stream` chunks whose payload is model output, or carries
  provider-shaped fields (`choices[].delta`, `content[].type`, `usage.prompt_tokens`).
- The application exposes a chat widget, a "summarize / draft / explain" action, an agentic
  workflow that calls tools, or a RAG search over documents the tester can write into.
- Source or JS analysis reveals a provider SDK (`openai`, `@anthropic-ai/sdk`, `langchain`,
  `llamaindex`) or a server-side proxy to a provider host.

## The distinction that decides severity

An LLM saying something embarrassing is **not a finding**. A finding needs a *security boundary
crossed*: another tenant's data read, a request made from the server, a privileged tool invoked, a
secret returned, or a bill run up without limit. Establish which boundary the model sits behind
before writing anything up — that is the same prove-or-kill discipline
`agent/rules/hunting.md` §2 demands of every class, and it is what separates a real report from
"I made the chatbot swear".

## Tools

- `vigil assess kali exec -- curl ...` — all target-facing requests go through the wrapper.
- `vigil oob mint` / `vigil oob poll` — the only reliable proof for tool-calling / retrieval SSRF:
  mint a nonce-tagged host (`vigil assess kali exec` is not needed for the mint itself), place the
  EXACT host it prints inside the prompt or the retrieved document, then poll for the callback. Defer
  to `agent/skills/ssrf-testing/SKILL.md` for the full mint→fire→poll loop and for classifying what
  the callback proves.
- Burp Repeater / `curl` for hand-shaped bodies; the request body IS the attack surface here, so
  work at the JSON level rather than through the app's own UI.

## Methodology

### 1. Fingerprint the endpoint

- [ ] Identify the dialect: OpenAI-compatible (`messages[]`, `model`, `max_tokens`), Anthropic
      (`system` top-level, `content[]` blocks), or bespoke (`{"prompt": "..."}`).
- [ ] Send a malformed body and read the error — provider SDK errors leak the upstream model name,
      the proxy's own system prompt length, and sometimes the provider API base URL.
- [ ] Note whether `model` is attacker-selectable. A caller-chosen model is a cost lever and often
      an authorization gap (a cheap tier's key reaching an expensive model).
- [ ] Record whether the response is streamed; streaming responses frequently bypass the output
      filter the non-streaming path applies.

### 2. System-prompt and context disclosure

- [ ] Ask directly, then indirectly (translate, summarize, base64, "repeat the text above").
- [ ] Look for the system prompt echoed in error paths, in `usage` accounting, or in a debug field.
- [ ] Check whether a client-supplied `system` / `system_prompt` parameter is ACCEPTED — a
      server-side guardrail the client can overwrite is not a guardrail.
- [ ] Probe for retrieved-context bleed: ask for "the documents you were given" and check whether
      any belongs to another tenant.

### 3. Prompt injection — direct and indirect

- [ ] Direct: instructions in the user turn that override the system policy.
- [ ] **Indirect (the one that matters):** plant instructions in content the model will *retrieve* —
      an uploaded document, a profile field, a web page the agent fetches, a support-ticket body —
      and confirm they execute on a DIFFERENT user's request. Indirect injection is the variant with
      a real victim and the one most often left untested.
- [ ] Confirm the boundary crossed, not merely that the model complied.

### 4. Tool calling and agent actions

- [ ] Enumerate the tools: ask the model to list them, or read `tools` / `tool_choice` off the
      request schema.
- [ ] For each tool, ask what it would take to invoke it with attacker-chosen arguments. A fetch /
      browse / webhook tool is SSRF; a database or search tool is injection; an email or payment
      tool is business logic.
- [ ] Prove a tool-driven fetch with an OOB callback — an agent that renders a markdown image from
      attacker text is an exfiltration channel, not a rendering bug.
- [ ] Check whether tool results are re-fed to the model unescaped (the second injection hop).

### 5. Conversation and tenancy boundaries

- [ ] Swap `conversation_id` / `thread_id` / `assistant_id` across sessions and accounts — this is
      IDOR with a chat-shaped URL; defer to `agent/skills/idor-testing/SKILL.md` for the
      two-account protocol and the evidence standard.
- [ ] Check whether embeddings / vector search is scoped per tenant, or filtered only in the
      application layer after an unscoped retrieval.

### 6. Resource and cost abuse

- [ ] Is `max_tokens` clamped server-side, or accepted from the client?
- [ ] Is there a per-account rate or token budget? Defer to
      `agent/skills/rate-limit-bypass/SKILL.md` for the bypass matrix.
- [ ] Can an unauthenticated caller reach the endpoint at all? An unauthenticated proxy to a paid
      provider key is a direct financial-loss finding, and the cheapest real bug on this surface.

## False-positive gate

Before recording, confirm all of:

- The behaviour is **reproducible** across sessions, not a single sampled generation. Re-run the
  exact request at least three times and record the hit rate; a non-deterministic model makes
  one-shot evidence worthless.
- A **security boundary** was crossed (another tenant's data, a server-side request, a privileged
  action, a secret, or uncapped spend) — not merely undesirable text.
- The content the model emitted is **not attacker-supplied text echoed back**; an LLM repeating what
  you just pasted proves nothing.
- The endpoint is **in scope** — a proxied provider host (`api.openai.com`, `api.anthropic.com`) is
  the provider's asset, never the target's. Test what the target's own server does with your input;
  never attack the upstream provider.

## Recording

Record against `prompt-injection` for injection and system-prompt disclosure. When the injection's
IMPACT lands in another class, record the class of the outcome — a tool-calling fetch is `ssrf`, a
cross-tenant conversation read is `idor`, leaked context is `info-disclosure` — and cite the
injection as the entry point in the attacker-outcome statement.

## Related

- `agent/references/gf-patterns/llm_api.md` — the bucket's keys, fragments, and routing.
- `agent/skills/ssrf-testing/SKILL.md` — the OOB loop that proves a tool/retrieval fetch.
- `agent/skills/idor-testing/SKILL.md` — the two-account protocol for conversation-scope tests.
- `agent/skills/rate-limit-bypass/SKILL.md` — budget and quota bypass for the token-spend angle.
- `agent/skills/ai-ml-on-device-security/SKILL.md` — the MOBILE / on-device counterpart (model
  extraction from a shipped app). Different surface: that skill reads a bundled model, this one
  tests a served API.
