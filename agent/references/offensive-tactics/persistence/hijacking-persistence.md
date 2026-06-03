---
description: DLL proxying, COM hijacking, .lnk modification
---

# Hijacking-Based Persistence

## DLL Hijacking / Proxying
- Find DLL search order gaps with Process Monitor (NAME NOT FOUND)
- Place malicious DLL in application directory before system directories
- Compile a purpose-built DLL that performs the authorized proof action and logs execution evidence
- DLL proxying: forward legitimate exports to original DLL while running payload

## COM Hijacking (T1546.015)
- Target: `HKCU\Software\Classes\CLSID\{CLSID}\InprocServer32` — redirect a COM CLSID to a malicious DLL
- Find hijackable CLSIDs: Process Monitor → filter for `RegOpenKey` + `NAME NOT FOUND` on CLSID paths
- When a legitimate application loads the COM object, your DLL executes instead
- Common targets: `MMC20.Application`, `ShellBrowserWindow`, scheduled task COM handlers

## mscfile UAC Bypass (T1548.002)
- Hijack: `HKCU\Software\Classes\mscfile\shell\open\command` → `powershell.exe`
- eventvwr.exe auto-elevates and reads mscfile handler from HKCU (user-writable)
- Result: powershell runs as high integrity without UAC prompt

## Shortcut (.lnk) Modification
```powershell
# Modify existing shortcut to run payload + original program
powershell.exe -c "invoke-item original.exe; invoke-item c:\payload.exe"
```
- Change shortcut icon back to original; set Run: Minimized to hide window

## File Extension Hijacking
- Hijack .txt handler: `HKCR\txtfile\shell\open\command`
- Change from `notepad.exe %1` to `c:\tools\shell.cmd %1`
- shell.cmd launches reverse shell AND opens file normally with notepad

## Trust Provider Hijacking
- Modify trust provider DLLs in registry to load malicious code during signature verification
