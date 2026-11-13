---
name: masvs-privacy-testing
description: OWASP MASVS-PRIVACY testing for identifier auditing, tracking transparency (ATT/Privacy Sandbox), data deletion verification, privacy label validation, and analytics SDK data collection auditing
origin: Vigil
---

# MASVS Privacy Testing

## When to Activate

- Device identifiers (IDFA, IDFV, GAID, IMEI, MAC, ANDROID_ID) may be collected or sent without
  consent; ATT or Privacy Sandbox compliance needs checking; account deletion must be verified;
  a Privacy Label / Data Safety declaration needs comparing with observed behaviour.

## Scope Gate

Only apps, accounts, devices, APIs and analytics endpoints under written authorization, with
synthetic accounts and data. Never capture real users' traffic or production analytics data.
Coordinate server-side deletion tests with the app owner.

Hook targets, traffic signals (identifier patterns, ATT tracking parameters, privacy-label category
keys), deletion residue locations and per-platform API lists:
`agent/references/mobile/masvs-privacy-testing.md`; load it before hooking. Lab and
proxy setup: `agent/skills/mobile-lab-setup/SKILL.md`.

## Checks

1. **Identifiers:** hook identifier APIs and flag outbound identifier patterns. Each access needs
   a consent gate or a legitimate purpose; an identifier sent to a third-party domain without the
   user's knowledge is the candidate.
2. **Tracking transparency (iOS ATT):** fresh install, deny (or never trigger) the prompt, capture
   a full session. Look for IDFA/IDFV to tracking domains before `.authorized`; **probabilistic
   fingerprints** (four or more device signals in one payload) to attribution/analytics domains;
   hidden zero-size or 1x1 WebViews used as a fingerprinting surface; raw device signals sent to
   first-party domains for server-side joining.
3. **Privacy Sandbox (Android):** GAID still used alongside Topics/Attribution Reporting; PII or
   precise identifiers in attribution registration URIs; ad SDKs still in the main process rather
   than the SDK Runtime.
4. **Deletion:** snapshot local storage, Keychain/Keystore and caches; delete the account; re-scan
   for residue and orphaned entries; search a backup (for Android, `adb backup` only works on
   debuggable or targetSdk ≤ 30 apps); then the impactful checks — **server access with a cached
   token after deletion**, and **re-registration with the same email resurrecting old data**.
5. **Declared vs observed:** build a matrix of declared data types against observed traffic and
   storage; an observed-but-undeclared type is a candidate.
6. **Analytics, crash and ad SDK over-collection** is owned by
   `agent/skills/sdk-supply-chain-security/SKILL.md` ("Data exfiltration"); run it there.

## Reportability and evidence

Label mismatches and telemetry over-collection are often compliance issues rather than security
findings, and many programs exclude them: report when the data is sensitive, leaves the user's
control without consent, or a deletion leaves data reachable
(`agent/references/finding-fp-and-severity-gate.md`). Capture the hook output with backtrace,
the request carrying the data, the destination's owner, the consent state at that moment, the
declaration text, and the MASVS-PRIVACY control. Format:
`agent/references/runtime-guides/web-finding-recording.md`.
