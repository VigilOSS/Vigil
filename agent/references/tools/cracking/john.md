# john (John the Ripper)

**Purpose:** Offline password hash cracking with format auto-detection and conversion utilities
Run john via `aith assess kali exec -- john ...` with the standard audit-flag set.

## Basic Usage

**Auto-detect hash:** `john hashes.txt`
**With wordlist:** `john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`
**Specific format:** `john --format=raw-md5 hashes.txt`
**Show cracked:** `john --show hashes.txt`
**Rules (mangling):** `john --wordlist=wordlist.txt --rules=best64 hashes.txt`
**Incremental (brute-force):** `john --incremental hashes.txt`
**Parallelism:** `john --fork=4 hashes.txt`
**List formats:** `john --list=formats`
**Find format by keyword:** `john --list=formats | grep -i ntlm`

## *2john Converters (Critical for Engagements)

Convert encrypted files to john-crackable format:

| Converter | Source File | Usage |
|-----------|------------|-------|
| `ssh2john` | SSH private key | `ssh2john id_rsa > ssh_hash.txt` |
| `zip2john` | Encrypted ZIP | `zip2john protected.zip > zip_hash.txt` |
| `rar2john` | Encrypted RAR | `rar2john protected.rar > rar_hash.txt` |
| `keepass2john` | KeePass database | `keepass2john database.kdbx > kp_hash.txt` |
| `office2john` | Office docs (xlsx/docx) | `office2john secret.xlsx > office_hash.txt` |
| `pdf2john` | Encrypted PDF | `pdf2john protected.pdf > pdf_hash.txt` |
| `gpg2john` | GPG private key | `gpg2john key.gpg > gpg_hash.txt` |
| `bitlocker2john` | BitLocker volume | `bitlocker2john image.raw > bl_hash.txt` |
| `wpapcap2john` | WPA handshake | `wpapcap2john capture.cap > wpa_hash.txt` |
| `krb2john` | Kerberos tickets | `krb2john ticket.kirbi > krb_hash.txt` |

## Common Format Names

`raw-md5`, `raw-sha256`, `raw-sha512`, `bcrypt`, `sha512crypt`, `nt`, `netntlmv2`,
`krb5tgs`, `krb5asrep`, `mssql12`, `mysql-sha1`, `zip`, `rar`, `ssh`, `keepass`,
`office`, `PDF`, `wpapsk`

## Pot File Management

**Custom pot file:** `john --pot=./engagement.pot hashes.txt`
**Query specific pot:** `john --show --pot=./engagement.pot hashes.txt`

## When to Use john vs hashcat

- **john**: auto-detection, `*2john` converters for file-based hashes, CPU cracking, exotic formats
- **hashcat**: GPU acceleration, faster for standard hash types, better rule engine, mask attacks
