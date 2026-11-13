---
name: ai-ml-on-device-security
description: Security testing for on-device AI/ML features including model extraction, inference data leakage, AI feature manipulation, prompt injection in mobile LLMs, and federated learning risks
origin: Vigil
vuln_class: ai-ml-security, prompt-injection
---

# On-Device AI/ML Security Testing

## When to Activate

- The app bundles or downloads Core ML, TFLite, ONNX or PyTorch Mobile models; uses ML Kit,
  Vision or Natural Language frameworks; integrates an on-device LLM (Apple's Foundation Models
  framework / Writing Tools, Gemini Nano via AICore) or a third-party LLM SDK; or participates in
  federated learning / on-device personalization.

## Scope Gate

Authorized builds, models and APIs on owned devices. Extraction and adversarial testing cover the
app's own bundled or downloaded models, not platform system models, unless platform research is
authorized. Proprietary weights never leave the engagement lab.

Model locations, inference hook targets, filter-trust techniques, federated-learning signals,
finding criteria and evidence standards: `agent/references/mobile/ai-ml-on-device-security.md`;
load it once a model
or LLM integration is found. Prompt-injection technique for LLM features is
`agent/skills/llm-api-testing/SKILL.md`; code patterns are
`agent/references/code-vuln-patterns/ai-ml-security.md`.

## Checks

1. **Inventory:** model files in the bundle and the app container (`.mlmodelc`/`.mlmodel`/
   `.mlpackage`, `.tflite`, `.onnx`, `.pt`/`.ptl`), runtime downloads, and LLM API references
   in strings and decompiled code (`SystemLanguageModel`, `LanguageModelSession`, `GenerativeModel`,
   AICore, `openai`/`anthropic`/`gemini`/`llama` SDKs). Record path, format, size, encryption and
   purpose.
2. **Integrity of downloaded models** (checksum/signature absent) is the security-relevant
   extraction result; an extractable model is usually by-design or an IP concern, reportable only
   when it carries secrets, enables a filter/integrity bypass, or the program scopes model theft
   (`agent/references/finding-fp-and-severity-gate.md`).
3. **Inference leakage:** hook inference APIs, exercise the AI features, then look for cached
   inputs/outputs (images, text, audio, embeddings), inference data logged at INFO/DEBUG, inference
   data in crash-report metadata (provoke the crash on your own lab device only), and results sent
   to analytics with user-identifiable metadata.
4. **Client-side filter trust:** for on-device moderation, try standard evasions (homoglyphs,
   zero-width characters, language mixing) and hook the filter to force a pass; what matters is
   whether the server trusts the client's verdict. Adversarial image perturbation (white-box after
   extraction, black-box otherwise) applies to classification gates.
5. **Mobile LLM features:** map injection surfaces (chat, search, imported documents, clipboard and
   shared content), then test cross-feature injection, tool calls that trigger app actions (send,
   purchase, contacts), and context persisting across sessions; capture the full prompt context
   with hooks or the proxy.
6. **Federated learning:** participation (`MLUpdateTask`, Federated Compute, On-Device
   Personalization), update traffic and its TLS validation, training samples or gradients cached
   beyond the round.

Map findings to MASVS-RESILIENCE and the OWASP ML/LLM Top 10 with reproducible evidence. Format:
`agent/references/runtime-guides/web-finding-recording.md`.
