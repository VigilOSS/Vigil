# Reporting Rules

These rules keep reports human-first, evidence-backed, and severity-disciplined.

## 1. No speculative language

Do not write "could potentially", "may allow", or similar hedge language. State what the attacker can do, or do not report it yet.

Banned phrases:

- `could potentially`
- `may allow`
- `might be possible`
- `could lead to`
- `could be chained with ...`

Preferred pattern:

- `An attacker can [exact action] by [exact method].`

## 2. Proof is mandatory

Show exact impact, not just status codes or tool noise. The report should make the failure obvious to a reviewer.

## 3. Severity follows proven impact

Do not let recon hints, CVEs, or intuition inflate severity beyond what the evidence proves.

If you use CVSS, make it match the proved attack path, not the imagined best case for the attacker.

## 4. Verify the data is actually non-public

Before calling something exposure or disclosure, confirm the same information is not already intentionally public.

## 5. Use distinct identities when ownership matters

For cross-user access issues, show attacker context and victim context clearly enough that the unauthorized boundary crossing is undeniable.

## 6. Lead with attacker outcome

Sentence one should explain what the attacker gains, not what category label the bug belongs to.

## 7. Keep it concise and human-readable

A strong report should be fast to scan without losing exact technical proof.

## 8. Title quality matters

Prefer: `[Bug Class] in [exact endpoint or feature] allows [attacker role] to [impact] [scope]`

Avoid vague titles like:

- `IDOR vulnerability found`
- `Security issue in API`
- `XSS in user input`

## 9. Use durable finding state as the source

Do not invent details that are not present in recorded findings, synchronized artifacts, or confirmed evidence references.
