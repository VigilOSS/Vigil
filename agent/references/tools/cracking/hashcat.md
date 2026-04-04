# hashcat

**Purpose:** GPU-accelerated password hash cracking
Run hashcat through the Kali MCP command-execution tool.

## Hash Mode Quick Reference

| Mode | Hash Type | Example Hash Prefix |
|------|-----------|-------------------|
| 0 | MD5 | `5d41402abc4b2a76b9719d911017c592` |
| 100 | SHA1 | `aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d` |
| 1400 | SHA256 | `e3b0c44298fc1c149afb...` |
| 1800 | SHA-512 crypt (Linux) | `$6$rounds=...` |
| 1000 | NTLM | `a87f3a337d73085c45f9416be4a8035e` |
| 3200 | bcrypt | `$2b$12$...` |
| 5600 | NetNTLMv2 | `user::domain:challenge:...` |
| 13100 | Kerberos TGS-REP (Kerberoast) | `$krb5tgs$23$*...` |
| 18200 | Kerberos AS-REP (ASREPRoast) | `$krb5asrep$23$...` |
| 22000 | WPA-PBKDF2-PMKID+EAPOL | `WPA*...` |
| 16500 | JWT (HMAC-SHA) | `eyJ...` |
| 1731 | MSSQL (2012+) | `0x0200...` |
| 300 | MySQL 4.1+ | `*6C8989366EAF6...` |

## Attack Modes

**Dictionary (mode 0):** `hashcat -m MODE -a 0 hashes.txt wordlist.txt`
**Dictionary + rules:** `hashcat -m MODE -a 0 hashes.txt wordlist.txt -r rules/best64.rule`
**Brute-force (mode 3):** `hashcat -m MODE -a 3 hashes.txt ?a?a?a?a?a?a`
**Combination (mode 1):** `hashcat -m MODE -a 1 hashes.txt wordlist1.txt wordlist2.txt`
**Hybrid dict+mask (mode 6):** `hashcat -m MODE -a 6 hashes.txt wordlist.txt ?d?d?d`
**Hybrid mask+dict (mode 7):** `hashcat -m MODE -a 7 hashes.txt ?d?d?d wordlist.txt`

## Mask Charsets

`?l` = a-z, `?u` = A-Z, `?d` = 0-9, `?s` = special, `?a` = all printable, `?b` = 0x00-0xff

## Essential Flags

**Show cracked:** `hashcat -m MODE hashes.txt --show`
**Force CPU (no GPU):** `--force` (needed in VMs without GPU passthrough)
**Optimized kernels:** `-O` (faster, limits password length to 32)
**Session management:** `--session=engagement1` / `--restore --session=engagement1`
**Potfile isolation:** `--potfile-path=./engagement.pot`
**Output to file:** `-o cracked.txt --outfile-format=3` (format: hash:plain)
**Threads/workload:** `-w 3` (1=low, 2=default, 3=high, 4=nightmare)
**Status:** press `s` during run

## Common Wordlists (Kali)

```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/seclists/Passwords/Leaked-Databases/
```

## Common Rules

```
rules/best64.rule          # fast, good coverage
rules/rockyou-30000.rule   # thorough
rules/d3ad0ne.rule         # aggressive
rules/toggles5.rule        # case toggling
```
