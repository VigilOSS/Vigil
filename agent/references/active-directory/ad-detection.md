# Active Directory Attack Detection

Quick reference for detecting common AD attacks via Windows event logs.

## Pass-the-Ticket (T1550.003)

### Key Events
- **4768** — TGT requested (Kerberos Authentication Service)
- **4769** — Service ticket requested (Kerberos Ticket Granting Service)
- **4771** — Kerberos pre-authentication failed

### Detection Logic
- TGS request (4769) without prior TGT request (4768) from same IP = pre-existing/forged ticket
- RC4 encryption type (0x17) in AES-enforced environment = ticket manipulation
- Same user authenticating from multiple IPs in short window = ticket reuse

Splunk:
```
index=windows EventCode=4769 Ticket_Encryption_Type=0x17 | stats dc(IpAddress) as ip_count, values(IpAddress) as ips by TargetUserName | where ip_count > 1
```

## Pass-the-Hash (T1550.002)

### Detection Logic
- NTLM authentication (not Kerberos) to sensitive hosts
- Event ID 4624 with LogonType=3 and AuthenticationPackageName=NTLM from unexpected source
- High volume of NTLM auth from single source across multiple targets

## Golden Ticket (T1558.001)

### Detection Logic  
- TGT with abnormally long lifetime (default max is 10 hours)
- TGT encryption using RC4 when AES is enforced
- Event ID 4768 with unusual account SID or non-existent username
- TGS requests without matching TGT request on the DC

## Kerberoasting (T1558.003)
See `kerberos-attacks.md` § Detection & Defense

## DCSync (T1003.006)
See `ad-persistence.md` § DCSync Detection
