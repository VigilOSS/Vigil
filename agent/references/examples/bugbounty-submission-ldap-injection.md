---
description: "Example: LDAP injection bug bounty submission with working POC"
skill: report-generation
category: Disclosure & Reporting Formats
---

**Title:** Unvalidated rotation target lets vault editors hijack any AD account

**VRT:** Broken Access Control (BAC) > Privilege Escalation

**Severity:** HIGH

**CVSS:** CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1)

**Run:** `python3 poc-ldap-injection.py`
**Pass if:** every `[CONFIRMED]` line prints

---

### Summary

An attacker with edit access to a shared credential record takes over any Active Directory account just by typing its name into the `login` field. The AD rotation plugin builds its search filter from that field with no check that the account matches what the record is scoped to manage: `f'(&(objectClass=user)(sAMAccountName={name}))'`. Because the field is also interpolated without escaping, the same point is separately injectable — but the takeover above used no metacharacters at all. The attached POC calls the installed rotation function and captures the filters it constructs for both cases.

**Exploit flow**
1. A contractor with edit access to a shared AD rotation credential record sets the `login` field to an account name they don't own.
2. The scheduled rotation job resolves that name with no ownership or scope check.
3. The rotation job changes that account's password and writes the new value into the vault record.
4. The attacker reads the new password from the vault record and logs in with that account's full privileges.

### Steps to Reproduce

1. [attacker] Run the offline POC against the installed package:
```
python3 poc-ldap-injection.py
```
**Expect:** the PLAIN_HIJACK case resolves the administrator's DN and changes their password with no metacharacters. The two injection cases separately show unescaped metacharacters reaching the filter. Full output in Evidence.

For end-to-end reproduction on a live AD environment:

2. [attacker] Create a credential record with the AD rotation plugin, a valid AD host, and valid bind credentials.
3. [attacker] Set the login field to `DOMAIN\administrator` — a plain, valid account name with no LDAP syntax in it.
4. [server] Run the scheduled rotation.
**Expect:** the administrator's password changes and the new value is stored in the vault record, with no metacharacter ever sent.

### Evidence

```
--- PLAIN_HIJACK: no metacharacters, no injection -- just a name you don't own ---
  Login field value:  DOMAIN\administrator
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=administrator))     <-- ordinary, well-formed filter
  [CONFIRMED] Resolves to admin DN; modify_password changes admin password    <-- ATO, zero LDAP syntax used

--- WILDCARD_ENUM: the same field is also injectable -- enumerate ALL users ---
  Login field value:  DOMAIN\*
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=*))       <-- rotate() output
  [CONFIRMED] Returns every user object in the domain instead of one

--- BLIND_BOOLEAN: boolean-based blind extraction of email prefix ---
  Login field value:  DOMAIN\administrator)(mail=admin@*
  CAPTURED filter:    (&(objectClass=user)(sAMAccountName=administrator)(mail=admin@*))
  [CONFIRMED] Binary oracle: result count reveals if email starts with admin@
```

All filters captured from the installed `rotate()` function. PLAIN_HIJACK proves the takeover needs no injection: the plugin never checks the resolved account against what the record is scoped to manage. `escape_filter_chars()` from `ldap3` is already used elsewhere in the same codebase but wasn't applied here. That closes WILDCARD_ENUM and BLIND_BOOLEAN, but does nothing for PLAIN_HIJACK: `administrator` has no character in it to escape.

### Impact

Full Active Directory account takeover: an editor with access to one credential record retargets its rotation at any account and reads the resulting password. The wildcard and blind-boolean primitives add enumeration and extraction at the same point, closed by escaping alone — not what enables the takeover.

### Remediation

Constrain rotation to the account the credential record was created for. Store the intended target's identifier at record creation, immutable to later edits, and reject a rotation whose resolved account differs from it. Separately, apply `escape_filter_chars()` at the interpolation site to close the wildcard and blind-boolean primitives, which remain exploitable even after the target is pinned:
```python
from ldap3.utils.conv import escape_filter_chars
request = f'(&(objectClass=user)(sAMAccountName={escape_filter_chars(name)}))'
```
