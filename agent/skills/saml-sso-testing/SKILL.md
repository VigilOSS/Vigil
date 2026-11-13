---
name: saml-sso-testing
description: SAML SSO security testing — assertion forgery, signature bypass, RelayState redirect, and SP/IdP trust boundary attacks
origin: Vigil
vuln_class: saml
---

# SAML SSO Testing

## When to Activate

- SP endpoints such as `/saml/acs`, `/saml/metadata`, `/saml2/acs`, `/auth/saml/callback`, a
  login redirect carrying `SAMLRequest`, or SAML namespaces in metadata.
- Source analysis shows a SAML library (passport-saml, node-saml, ruby-saml, python3-saml,
  spring-security-saml, SimpleSAMLphp, OneLogin).

`--technique SAML`. Build and sign variants locally (xmlstarlet/xmllint, a SAML toolkit when
installed); every request to the target goes through `vigil assess kali exec … --intent …
--phase consume-test --timeout <N>`. Templates for every attack below are in
`agent/references/payloads/saml-attack-payloads.md` (unsigned assertion, XSW1/2/3/4/7, NameID,
attribute and condition manipulation, XXE in the response and in fetched metadata,
library-specific payloads; RelayState values come from
`agent/references/payloads/open-redirect-payloads.md` and blind XXE from
`agent/references/payloads/xxe-payloads.md`); load it before constructing a forged response.

## Where SAML fails, in order of yield

1. **Signature only checked if present.** Test first: capture a SAMLResponse, decode, delete
   `<ds:Signature>`, optionally change NameID/attributes, re-encode, submit to the ACS. Metadata
   with `WantAssertionsSigned` absent or `false` is the decisive tell.
2. **Signature wrapping (XSW).** The signature validates its subtree, but if the SP's XPath picks
   the first NameID match (the forged one), authentication is bypassed. Success is
   library-specific, so try every placement (the reference's 1/2/3/4/7 plus the standard 5/6/8).
3. **Certificate acceptance:** a self-signed cert, the cert stripped and an attacker key used, an
   expired cert, or any cert during a rollover window (two certs in metadata).
4. **NameID / attribute / condition manipulation:** comment injection
   (`admin<!-- -->@acme.example` parsed differently by XML and string handling), encoding and
   domain confusion, role attributes that drive authorization, extended validity, removed or
   wrong audience (cross-SP), replay with `InResponseTo` removed.
5. **RelayState:** client-controlled post-auth redirect; when the redirect carries a token in the
   URL, an external RelayState leaks it via Referer.
6. **XXE** in the SAMLResponse or in metadata the SP fetches from a URL you control
   (`agent/skills/xxe-testing/SKILL.md`; OOB via `agent/references/offensive-tactics/frp-tunneling.md`).

Library tells: passport-saml CVE-2022-39299 (verified the first assertion, used the second) and
comment injection; node-saml unsigned acceptance history; ruby-saml CVE-2024-45409 (wrapping);
older python3-saml/py-saml2 relaxed signature requirements; spring-security-saml namespace
confusion; SimpleSAMLphp comment injection and metadata XXE.

## Proof and severity

Show the forged assertion, the session it produced, and an authenticated request as the
impersonated user. Severity follows `agent/references/finding-fp-and-severity-gate.md`: what the
impersonated identity can reach, not the technique name.

## Kill Signals

- Removing the signature yields "Invalid signature"/"Signature required".
- The SP pins the IdP certificate and rejects all others.
- Every wrapping placement fails signature validation.
- RelayState is validated against internal paths.

## Escalate When

- An unsigned or wrapped assertion authenticates → change NameID to a privileged user and
  demonstrate the access.
- RelayState accepts external URLs → look for tokens in the redirect.
- A self-signed certificate is accepted → forge any identity.

## What to Record

ACS URL, the manipulation that succeeded, whether the SP requires/validates signatures, the forged
assertion and resulting session. Format: `agent/references/runtime-guides/web-finding-recording.md`.
