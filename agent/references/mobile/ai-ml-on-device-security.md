---
description: "On-device AI/ML: Core ML/TFLite/ONNX model locations and identification signals, inference hook targets, leakage sinks, client-side filter trust, mobile LLM and federated-learning signals, finding criteria and evidence standards"
skill: ai-ml-on-device-security
---

# AI/ML On-Device Security Testing Reference

Locations, API names and signals for each check in `agent/skills/ai-ml-on-device-security/SKILL.md`,
with the finding criteria and evidence standard per area. Inspection scripts (coremltools,
`tf.lite.Interpreter`, `onnx.load`) and Frida hooks are written on demand against the targets
named here.

## On-Device Model Extraction

**iOS bundle locations:** `Payload/<App>.app/*.mlmodelc`, `…/Models/`, `…/Resources/`, and
`…/Frameworks/*.framework/*.mlmodelc`; also `.mlmodel` / `.mlpackage`. Runtime downloads land in
the data container, `/var/mobile/Containers/Data/Application/<UUID>/` (jailbroken device), alongside
any `.tflite` / `.onnx`. A compiled `.mlmodelc` is a directory: `model.espresso.net`
(architecture), `model.espresso.shape`, `model.espresso.weights`, `metadata.json`,
`coremldata.bin`; `metadata.json` and the spec's `userDefined` metadata carry author, project and
training-source strings.

**Apple Intelligence / Foundation Models:** system-level, not app-bundled. Usage signals in the
binary: `SystemLanguageModel`, `LanguageModelSession`, `WritingTools` / `WritingToolsUI`,
`IntelligenceKit`, `IntelligenceUI`, `_TtC…Intelligence`. System model assets
(`/System/Library/AssetsV2/com_apple_MobileAsset_TrialLanguageModelForSiri/`) are encrypted and
signed; extraction is platform research and out of scope without that authorization.

**Android locations:** `assets/*.tflite`, `assets/models/`, `res/raw/`, also `.lite`, `.onnx`,
`.pt` / `.ptl`; runtime downloads under `/data/data/<pkg>/` (including generic `.bin`). TFLite
metadata (via `tflite_support` `MetadataDisplayer`) can pack associated files such as label maps.

**Gemini Nano / ML Kit GenAI:** `GenerativeModel`, `GenerativeAiInferenceClient`, `genai`,
`aicore` in decompiled code or dex strings; on device the AICore service
(`dumpsys activity services | grep -i aicore`, `pm list packages | grep aicore`).

### What Constitutes a Finding

An extractable model is usually by-design or an IP concern (the skill's "Integrity of downloaded
models" check). It is reportable
when:
- a runtime-downloaded model is stored or loaded without integrity verification (checksum or
  signature absent), so a network or local attacker can substitute it;
- extracted metadata or associated files carry secrets, internal endpoints or credentials;
- the extracted model enables a filter or integrity bypass (white-box adversarial input against a
  gate the server trusts);
- the program explicitly scopes model theft, in which case weights that load into a standard
  framework and replicate the app's feature are the result.

### Evidence Standard

Model file path, size, format and metadata; the input/output specification; for a replication
claim, a successful inference outside the app on a test input.

## Model Input/Output Data Leakage

**Hook targets.** iOS: `MLModel -predictionFromFeatures:error:` (input features and returned
prediction), `VNImageRequestHandler -performRequests:error:` (Vision), `NLModel
-predictedLabelForString:` (Natural Language). Android: `org.tensorflow.lite.Interpreter.run(Object,
Object)`, ML Kit `com.google.mlkit.vision.text.TextRecognizer.process(InputImage)` and
`com.google.mlkit.vision.face.FaceDetector.process(InputImage)`.

**Sinks to check after exercising the feature:** files created after the feature ran (`find -newer`
against a pre-use reference file in the app container), SQLite tables named for ML, model, predict,
inference, cache or feature; logcat lines carrying inputs, prompts, labels, confidence scores or
embeddings; crash-reporter stores `/data/data/<pkg>/files/crashlytics/` and `…/files/sentry/` after
a crash provoked mid-inference (malformed or oversized input, own lab device only), and on iOS
Settings > Privacy & Security > Analytics & Improvements > Analytics Data; analytics requests
carrying results with user-identifiable metadata. Where the app claims on-device processing,
outbound connections to inference endpoints during feature use contradict the claim and show
server-side processing of the input.

### What Constitutes a Finding

- Inference inputs (photos, text, voice transcripts) cached unencrypted after the feature completes.
- Outputs (labels, scores, generated text) in system logs at INFO or lower.
- Crash reports carrying the user's AI-feature input in metadata or custom keys.
- Inference results sent to analytics with user-identifiable metadata.

### Evidence Standard

The hook output capturing the inference input/output, then the same data in storage, logs or a
crash report, with timestamps linking feature use to persistence.

## AI Feature Manipulation

On-device moderation (text toxicity, image NSFW), smart compose, classification gates. Find the
filter class by enumerating loaded classes for `moderate`, `filter`, `safety`, `toxicity`, then hook
its verdict method to a forced pass and follow the content downstream. The finding is a server that
trusts the client's verdict, which reduces the safety gate to a client-side check. Text evasions:
Cyrillic homoglyphs (`hаte` with U+0430), zero-width characters (U+200B, ZWJ/ZWNJ) between
characters, leetspeak, mixed-script and language mixing, semantic rephrasing. Image gates:
white-box perturbation (FGSM-style) once the model is extracted, black-box otherwise. Smart compose:
capture the suggestion API through the proxy, then inject context via clipboard or message history
and check whether safety filtering is timing-dependent under rapid input.

### What Constitutes a Finding

- A concrete evasion payload gets policy-violating content posted.
- A forced-pass hook on the moderation function lets content through downstream pipelines.
- An adversarial perturbation misclassifies above the app's acceptance threshold.
- Smart compose or autocomplete suggests harmful, private or policy-violating text under manipulation.

### Evidence Standard

The adversarial input, the filter's original decision where observable, the technique, the
resulting behaviour (content posted, image accepted, suggestion generated), and confidence scores
before and after perturbation.

## Prompt Injection in Mobile AI

Payload technique is `agent/skills/llm-api-testing/SKILL.md`. Mobile-specific integration signals:
iOS `SystemLanguageModel`, `LanguageModelSession`, `WritingToolsUI`, `IntelligenceUI`; Android
`GenerativeModel`, `ChatSession`, `GenerativeAiInferenceClient`; third-party SDK strings `openai`,
`anthropic`, `gemini`, `llama`, `mistral`, `ollama`, `ChatCompletion`. Mobile injection surfaces:
chat and search fields, imported documents (metadata, comments, hidden text), pasteboard content
pulled into the prompt, and shared-sheet content. Capture the full prompt context at the HTTP
client: iOS `NSURLSession -dataTaskWithRequest:completionHandler:` (`HTTPBody`), Android
`okhttp3.internal.connection.RealCall.execute` (body via `okio.Buffer`), filtering for
`generativelanguage`, `chat/completions` and provider hosts; or read it in the proxy.

### What Constitutes a Finding

- Chat input makes the model reveal its system prompt or internal instructions.
- Text in a processed document causes unintended actions (exfiltration through a summary,
  unauthorized API calls).
- Injection through one feature (document import) changes behaviour in another (chat): shared
  context without isolation.
- Crafted input makes the model call app functions (send messages, read contacts, purchase).

### Evidence Standard

The injected prompt, the response showing success, the resulting behaviour, and the full
request/response from the proxy or hooks; for indirect injection, the document content carrying the
payload and the altered output.

## Federated Learning Testing

**Participation signals.** iOS: `MLUpdateTask`, `MLUpdateContext`, `MLUpdateProgressHandlers`
(Core ML on-device update), `federated`, `localTraining`. Android: `FederatedCompute`,
`OnDevicePersonalization`, `federated`, `localTraining`; on device
`dumpsys activity services | grep -i federated` and the `federatedcompute` package. Traffic: model
and update URLs containing `model`, `federated`, `update`, `gradient`, `checkpoint`. Local
artifacts: `*.ckpt`, `*.checkpoint`, `*gradient*`, `*training*`, `*update*`, `*federated*` under the
app's data directory, and files modified during the training window.

### What Constitutes a Finding

- Gradients or model updates sent without TLS or with weak certificate validation.
- Training samples cached unencrypted and persisting beyond the training round.
- Model update payloads not integrity-checked, so a network attacker can inject an update.
- Gradient content or update metadata revealing which data categories the user interacted with.

### Evidence Standard

The update upload/download traffic, the local artifacts created during training, and, where
gradients are observable, what user data they let you infer.

## Source Anchors

- OWASP MASVS-RESILIENCE: https://mas.owasp.org/MASVS/08-MASVS-RESILIENCE/
- OWASP Machine Learning Security Top 10: https://owasp.org/www-project-machine-learning-security-top-10/
- MITRE ATLAS: https://atlas.mitre.org/
- Android On-Device Personalization: https://developer.android.com/design-for-safety/privacy-sandbox/on-device-personalization
- Android Federated Compute: https://developer.android.com/design-for-safety/privacy-sandbox/protected-computation
