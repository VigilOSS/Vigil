---
description: Subtle mode/parameter misuse, timing leaks, non-obvious randomness issues
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Cryptographic Misuse — Subtle Implementation Patterns

CWE-327, CWE-208, CWE-330, CWE-295, CWE-916. The algorithm is right; the mode, parameters,
comparison, randomness source, or composition is not.

## What You're Hunting (LLM-Advantage Patterns)

### 1. Correct algorithm, wrong mode or parameters

- **CBC padding oracle.** A distinguishable failure from `EVP_DecryptFinal_ex` (error message, status
  code, timing) versus a later MAC or parse failure lets an attacker decrypt byte by byte. The fix is
  AEAD, or encrypt-then-MAC verified before decrypting.
- **RSA PKCS#1 v1.5** (`RSA_PKCS1_PADDING`) for encryption is Bleichenbacher-exposed; SAST checks the
  algorithm, not the padding constant. Use `RSA_PKCS1_OAEP_PADDING`. OpenSSL 3.2+ applies implicit
  rejection on v1.5 decryption, which narrows the decrypt-side oracle; check the linked version.
- **GCM nonce reuse** under one key reveals the GHASH authentication key (allowing forgeries) and the
  XOR of the two plaintexts; it does not reveal the AES key. Random 96-bit nonces stay within NIST's
  limit only up to about 2^32 messages per key, and counter nonces must never repeat, including across
  restarts and replicas.
- **Fixed IVs:** `Buffer.alloc(16, 0)` to `createCipheriv('aes-256-cbc', ...)` makes encryption
  deterministic.

### 2. Comparison timing

`memcmp`/`strcmp`/`==` on MACs, tokens, or password hashes short-circuit on the first differing byte,
and an early length check leaks length. Use `CRYPTO_memcmp()` or `timingsafe_bcmp()` in C,
`hmac.compare_digest()` in Python, and `crypto.timingSafeEqual()` (equal-length buffers) in Node.

### 3. Predictable randomness through indirection

`srand(time(NULL) ^ getpid())` at startup in one module and `rand()` for session ids in another;
SAST may flag the seed but not trace it to the security use. Python `random` and JavaScript
`Math.random()` used for tokens, reset codes, or OAuth `state` are the same bug. Trace every
security-relevant random value (ids, tokens, nonces, IVs, keys) back to its generator.

### 4. TLS validation gaps

- `SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL)` verifies the chain but not the name; hostname
  checking needs `SSL_set1_host` (or `X509_check_host`).
- Custom wildcard matching must match exactly one leftmost label (`*.example.com` matches
  `a.example.com`, not `a.b.example.com`), reject partial-label wildcards, and reject wildcards
  directly under a public suffix (`*.com`).

### 5. Key derivation

PBKDF2 iteration counts set far from the call, in a header or in config, and overridable from a file
or environment variable (an attacker who can set config lowers the work factor); counts far below
current guidance (OWASP recommends 600,000 for PBKDF2-HMAC-SHA256); a NULL or empty salt; a username
as the salt. A fast hash (`hashlib.sha256(password)`) for password storage instead of bcrypt, scrypt,
or Argon2.

### 6. Missing or misordered authentication

Encryption with no MAC lets an attacker flip ciphertext bits (in CBC, flipping bit n of block k-1 flips
bit n of plaintext block k). A MAC over the plaintext sent beside the ciphertext (encrypt-and-MAC), or
MAC-then-encrypt as in TLS 1.2 and earlier CBC suites without the encrypt-then-MAC extension (RFC
7366), forces decryption before verification and reopens padding oracles. Encrypt, then MAC the
ciphertext, or use an AEAD.

## C/C++ Specifics

- OpenSSL: `SSL_VERIFY_NONE`; `X509_verify_cert` or `SSL_get_verify_result` unchecked, or checked only
  after data was sent; no `SSL_set_tlsext_host_name`, so SNI is missing and a multi-tenant server may
  present another tenant's certificate.
- libsodium: a reused `crypto_secretbox` nonce breaks confidentiality; `crypto_box_seal` is anonymous
  and authenticates no sender; `crypto_pwhash` with `OPSLIMIT_INTERACTIVE` for long-term offline
  storage where `OPSLIMIT_SENSITIVE` fits.

## Python Specifics

pyca `cryptography` hazmat `Cipher(algorithms.AES(key), modes.CBC(iv))` is unauthenticated where
`Fernet` or `AESGCM` would be; PyCryptodome `unpad()` raises `ValueError` on bad padding, and
propagating that distinctly to the caller is the padding oracle.

## JavaScript Specifics

Web Crypto `AES-CBC` where `AES-GCM` is available; one key's raw material imported for both `HMAC` and
`AES` (derive per-purpose keys with HKDF).

## Real CVE Examples

- **CVE-2022-29217 (PyJWT).** A blocklist refused `ssh-rsa` public keys as HMAC secrets but not
  `ssh-ed25519` or `ecdsa-sha2-*`, so an application accepting `get_default_algorithms()` let an
  attacker sign HS256 with the published verification key. The token chose the algorithm; the guard
  named one instance instead of the invariant. Fixed in 2.4.0.
- **CVE-2018-0737 (OpenSSL RSA key generation).** A non-constant-time GCD helper inside otherwise
  correct prime generation leaked prime bits to a local cache-timing attacker.
