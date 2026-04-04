# A08:2025 — Software or Data Integrity Failures

## Insecure Deserialization — Java
- [ ] Look for `ObjectInputStream` usage indicators: `Content-Type: application/x-java-serialized-object`
- [ ] Check for Java serialization magic bytes in cookies/parameters: `rO0AB` (base64) or `ac ed 00 05` (hex)
- [ ] Test with ysoserial payloads against known gadget chains (Commons Collections, Spring, etc.)
- [ ] Check for Java deserialization in RMI, JMX, JMS endpoints
- [ ] Test ViewState deserialization in JSF applications

## Insecure Deserialization — PHP
- [ ] Look for `serialize()`/`unserialize()` patterns in parameters, cookies, session data
- [ ] Test with PHP object injection payloads: `O:8:"stdClass":0:{}`
- [ ] Check for POP chains (Property-Oriented Programming) in framework classes
- [ ] Test `phar://` deserialization via file operations if file upload exists

## Insecure Deserialization — Python
- [ ] Check for `pickle.loads()` on user input — extremely dangerous
- [ ] Test Python pickle payloads: `cos\nsystem\n(S'id'\ntR.`
- [ ] Check for `yaml.load()` without `SafeLoader` (PyYAML RCE)
- [ ] Test `jsonpickle`, `shelve`, and other serialization libraries in use

## Insecure Deserialization — Node.js
- [ ] Check for `node-serialize` usage — known RCE via `_$$ND_FUNC$$_` marker
- [ ] Test `serialize-javascript` with function injection
- [ ] Check for prototype pollution via `JSON.parse()` with user-controlled `__proto__`

## Insecure Deserialization — .NET
- [ ] Check for `BinaryFormatter`, `SoapFormatter`, `ObjectStateFormatter` usage
- [ ] Look for `__VIEWSTATE` without MAC validation
- [ ] Test `TypeNameHandling` in JSON.NET (Newtonsoft) — RCE via `$type` field
- [ ] Check for `DataContractSerializer` with known type confusion

## CI/CD Pipeline Exposure
- [ ] Check for exposed `.github/workflows/` YAML files with secrets or deploy keys
- [ ] Test for exposed Jenkinsfile with hardcoded credentials
- [ ] Check for `.gitlab-ci.yml` revealing internal infrastructure
- [ ] Look for exposed build artifacts: `/build/`, `/dist/`, `/artifacts/`
- [ ] Check for GitHub Actions artifact download URLs accessible without auth

## Unsigned Updates & Plugins
- [ ] Check if software update mechanism verifies digital signatures
- [ ] Test for plugin/extension installation without integrity checking
- [ ] Verify package sources use HTTPS and signature verification
- [ ] Check for auto-update URLs modifiable via DNS hijacking or MITM

## Dependency & Subresource Integrity
- [ ] Verify CDN-loaded scripts/styles have `integrity` attributes (SRI)
- [ ] Check if `<script>` tags loading from third-party domains use SRI hashes
- [ ] Test if missing SRI allows content injection via compromised CDN

## S3 / Storage Integrity
- [ ] Test S3 bucket write permissions: `curl -X PUT https://BUCKET.s3.amazonaws.com/test.txt -d "test"`
- [ ] Check for public-write S3 policies allowing file replacement
- [ ] Verify signed URLs cannot be extended or manipulated for unauthorized writes

## Webhook Signature Bypass
- [ ] Test webhook endpoints without signature verification
- [ ] Test with empty/invalid `X-Hub-Signature` or equivalent header
- [ ] Check if webhook signature uses HMAC-MD5 or other weak algorithm
- [ ] Verify replay protection — can old webhook payloads be replayed?

## Framework-Specific Checks
- [ ] **Django**: Check for `pickle` in cache backend or session serializer
- [ ] **Rails**: Check `Marshal.load` usage, test `cookies_serializer` config (should be `:json`)
- [ ] **Express**: Check for `cookie-session` with unsigned cookies
- [ ] **Spring**: Check for `DefaultSerializer` in session persistence, test RememberMe tokens
- [ ] **Laravel**: Check encrypted cookie handling, `APP_KEY` rotation issues

---
> Cross-reference skills: `deserialization-testing`
