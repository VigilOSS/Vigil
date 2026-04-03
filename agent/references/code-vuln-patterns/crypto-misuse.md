# Cryptographic Misuse — Subtle Implementation Patterns

> Target: Crypto bugs that survive SAST because the algorithm choice is correct — the misuse
> is in parameters, modes, comparison methods, randomness sources, or protocol composition.
> These require understanding cryptographic semantics, not just algorithm names.

---

## What SAST Already Catches (Skip These)

- MD5 or SHA1 used for password hashing
- ECB mode block cipher usage
- Hardcoded encryption keys or API secrets in source code
- DES or RC4 usage (deprecated algorithms)
- SSL/TLS version < 1.2 explicitly configured

---

## What You're Hunting (LLM-Advantage Patterns)

### 1. Correct Algorithm, Wrong Mode or Parameters

The algorithm is approved (AES-256, RSA-2048, etc.) but the mode or parameters
introduce vulnerability.

#### AES-CBC Without HMAC (Padding Oracle)
```c
EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &final_len);
if (ret <= 0) {
    send_error(conn, "Decryption failed");  // PADDING ORACLE
    // Attacker learns whether padding was correct by observing error vs success
}
```

The fix is authenticated encryption (AES-GCM or AES-CBC + HMAC verified BEFORE
decryption). But many codebases use CBC without authentication because AES-CBC is
"standard" and "NIST-approved."

#### RSA Without OAEP (Bleichenbacher Attack)
```c
RSA_public_encrypt(len, plaintext, ciphertext, rsa, RSA_PKCS1_PADDING);
// RSA_PKCS1_PADDING (v1.5) is vulnerable to Bleichenbacher's chosen-ciphertext attack
// Should use RSA_PKCS1_OAEP_PADDING
```

SAST tools check for the algorithm (RSA) but not the padding mode constant.

#### GCM With Nonce Reuse
```c
unsigned char nonce[12];
RAND_bytes(nonce, sizeof(nonce));  // correct for first message
// But if this function is called for each message in a stream,
// and RAND_bytes produces a collision (birthday bound at ~2^48 for 96-bit nonce),
// or if the nonce is derived from a counter that wraps...
```

Nonce reuse with GCM allows key recovery. The code looks correct because it uses
a random nonce — but random nonces have a birthday bound problem for long-lived keys.
Counter-based nonces are safer but only if the counter never repeats (even across
restarts).

### 2. Comparison Timing Leaks

#### memcmp for HMAC Verification
```c
unsigned char expected_mac[32], received_mac[32];
HMAC(EVP_sha256(), key, key_len, data, data_len, expected_mac, NULL);
if (memcmp(expected_mac, received_mac, 32) != 0) {
    return AUTH_FAILED;
}
```

`memcmp` short-circuits on the first differing byte. An attacker who can measure
response timing (even over a network, with statistical analysis) can determine the
HMAC byte-by-byte. The fix: `CRYPTO_memcmp()` or `timingsafe_bcmp()`.

#### Early-Exit Token Comparison
```c
int verify_token(const char *provided, const char *expected) {
    if (strlen(provided) != strlen(expected)) return 0;  // length leak!
    return strcmp(provided, expected) == 0;  // timing leak on content!
}
```

Even the length comparison leaks information. Constant-time comparison must be
used for all secret-derived values.

### 3. Predictable Randomness Through Indirection

The PRNG is seeded from time or PID, but the connection to security use is indirect.

```c
// Module A: initialization (at startup)
void init_session_manager() {
    srand(time(NULL) ^ getpid());  // seeded from predictable values
}

// Module B: session ID generation (seems to use "random")
void create_session(session_t *sess) {
    sess->id = rand();  // looks random but is predictable
}

// Module C: security check (trusts session ID is unpredictable)
int validate_session(uint32_t session_id) {
    session_t *s = find_session(session_id);
    return s != NULL;
}
```

SAST may flag `srand(time(NULL))` but may not trace the taint through to where
`rand()` is used for security-sensitive purposes, especially when the seed and
use are in different modules.

**In wget**: Cookie generation, temporary file name generation.
**In cURL**: Random values for boundary strings in multipart uploads.

### 4. TLS Certificate Validation Gaps

#### Validates CA Chain But Not Hostname
```c
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
// Verifies the certificate is signed by a trusted CA
// But does NOT verify the hostname matches the certificate's CN/SAN
// Missing: SSL_set_hostflags + SSL_set1_host (or X509_check_host)
```

#### Validates Hostname But Accepts Wildcards Too Broadly
```c
// Custom hostname matching:
int match_hostname(const char *pattern, const char *hostname) {
    if (pattern[0] == '*') {
        // Accepts *.com matching evil.example — should only match one level
        return strcmp(pattern + 1, strrchr(hostname, '.') - strlen(pattern) + 2) == 0;
    }
    return strcmp(pattern, hostname) == 0;
}
```

Wildcard matching must: (a) only match one label level (*.example.com matches
a.example.com but not a.b.example.com), (b) not match partial labels (*ample.com
should not match example.com in strict implementations), (c) not be accepted in
TLDs (*.com must be rejected).

#### Certificate Pinning Bypass via Intermediate CA
Certificate pinning checks the leaf certificate but not intermediate CAs. An attacker
with a rogue intermediate CA (compromised CA, government CA) can issue a valid chain
with a different leaf cert that passes chain validation but not pinning — unless the
pinning also covers the intermediates.

### 5. Key Derivation Weaknesses

#### Insufficient Iterations
```c
PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len,
                    1000,  // iterations: 1000 was fine in 2005, not in 2026
                    EVP_sha256(), key_len, key);
```

The iteration count may be in a config file or constant defined in a header far from
the PBKDF2 call. If the config can be overridden (env var, file), an attacker who
can influence config can reduce iterations.

#### Missing Salt
```c
PKCS5_PBKDF2_HMAC(password, strlen(password), NULL, 0, ...);
// No salt: enables precomputation (rainbow tables for derived keys)
```

#### Salt Derived From Non-Random Source
```c
char salt[16];
snprintf(salt, sizeof(salt), "%s", username);  // username as salt
// Same password for same username always produces same key
// Also: salt length may be shorter than username, truncated
```

### 6. Encryption Without Authentication (Or Wrong Order)

#### Encrypt Then Nothing
```c
AES_cbc_encrypt(plaintext, ciphertext, len, &aes_key, iv, AES_ENCRYPT);
send(sock, ciphertext, len, 0);
// No MAC/HMAC/signature: attacker can flip ciphertext bits
// In CBC mode, flipping bit N of block K-1 flips bit N of block K plaintext
```

#### Authenticate Then Encrypt (Wrong Order)
```c
HMAC(EVP_sha256(), mac_key, mac_key_len, plaintext, len, mac, NULL);
AES_cbc_encrypt(plaintext, ciphertext, len, &enc_key, iv, AES_ENCRYPT);
send(sock, mac, 32, 0);
send(sock, ciphertext, len, 0);
// MAC covers plaintext, not ciphertext — SSL 3.0 / TLS < 1.2 pattern
// Vulnerable to padding oracle attacks because decryption happens before
// MAC verification (must decrypt to verify MAC)
```

The correct order: encrypt THEN authenticate the ciphertext. Or use AEAD (AES-GCM).

---

## C/C++ Specific Patterns

### OpenSSL API Misuse
- `SSL_CTX_set_verify` without `SSL_VERIFY_PEER`: disables certificate verification
- `X509_verify_cert` called but return value not checked
- `SSL_get_verify_result` called but only after data has been sent (too late)
- `BIO_new_ssl_connect` without `SSL_set_tlsext_host_name`: SNI not sent, may get
  wrong certificate from multi-tenant servers

### libsodium Misuse
libsodium is designed to be misuse-resistant, but:
- `crypto_secretbox` with a reused nonce breaks confidentiality
- `crypto_box_seal` is anonymous — cannot verify sender identity
- Key derivation with `crypto_pwhash` using `OPSLIMIT_INTERACTIVE` for offline storage
  (should use `OPSLIMIT_SENSITIVE`)

### Custom Crypto Implementations
Any hand-rolled AES, RSA, HMAC, or PRNG implementation in a C project is almost
certainly vulnerable. Look for bit manipulation that implements cipher rounds,
modular exponentiation that's not constant-time, or XOR-based "encryption."

---

## Python Specific Patterns

### cryptography Library Misuse
```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
# Using hazmat (low-level) API without authentication
# Should use Fernet (high-level, authenticated) instead
```

### PyCryptodome Padding Issues
```python
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
# Padding errors propagated to caller → padding oracle
```

### hashlib Without Salt for Password Hashing
```python
password_hash = hashlib.sha256(password.encode()).hexdigest()
# No salt, no iterations, fast hash — vulnerable to rainbow tables and GPU cracking
# Even with salt: sha256 is too fast for password hashing
# Should use bcrypt, scrypt, or argon2
```

---

## JavaScript Specific Patterns

### Web Crypto API Misuse
```javascript
const key = await crypto.subtle.importKey('raw', keyData, 'AES-CBC', false, ['encrypt']);
const encrypted = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, key, plaintext);
// AES-CBC without authentication — same issue as C version
// Web Crypto supports AES-GCM; no reason to use CBC
```

### subtle.importKey With Wrong Algorithm
```javascript
// Key imported for signing, used for encryption (or vice versa)
const key = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
// Later, same keyData imported for AES — using same key for different purposes
```

Using the same key material for different purposes (encryption vs authentication)
can break security assumptions. Keys should be derived separately for each purpose.

### crypto.createCipheriv With Fixed IV
```javascript
const iv = Buffer.alloc(16, 0);  // all zeros — fixed IV!
const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
// Same key + same IV = same ciphertext for same plaintext (deterministic)
// Enables frequency analysis and known-plaintext attacks
```

---

## Detection Questions

1. **"Is this encryption authenticated — and in the right order?"**
   For every encryption operation, check: is there an HMAC/MAC/signature? Does it
   cover the ciphertext (not plaintext)? Is it verified BEFORE decryption?

2. **"How is the comparison of secret values performed?"**
   Every `memcmp`, `strcmp`, `==`, or `equals` on HMAC values, tokens, passwords,
   or session IDs should be constant-time. Search for comparison of security-sensitive
   values.

3. **"Where does the randomness come from, and what seeds it?"**
   Trace every random value used for security (session IDs, tokens, nonces, IVs,
   keys) back to its PRNG. What seeds that PRNG? Is it `time()`, `getpid()`, or
   `RAND_bytes()`?

4. **"Is the TLS certificate validation complete?"**
   Five things must be verified: CA chain, expiration, revocation (optional),
   hostname match, and key usage. Missing any one creates a gap.

5. **"Is the iteration count / work factor sufficient AND immutable?"**
   For password hashing and key derivation, check the iteration count. Then check
   whether it can be overridden by config, environment variable, or header value.

---

## Real CVE Examples

### CVE-2020-8169 (cURL — credential leak via DNS over HTTPS)
cURL's DoH (DNS over HTTPS) implementation sent DNS queries with credentials
included in certain configurations. The TLS connection to the DoH server was
properly encrypted, but the URL construction for the DoH query included
authentication credentials from the original URL. The crypto implementation was
correct (TLS worked fine), but the security boundary was wrong — credentials
intended for the target server were sent to the DNS resolver. This is a
cryptographic misuse pattern: correct encryption to the wrong party.

### CVE-2016-0777 (OpenSSH — roaming buffer leak)
The OpenSSH client's roaming feature (for resuming interrupted connections) included
a buffer that could leak private key material to a malicious server. The key was
properly encrypted for storage and properly protected in memory during normal
operations, but the roaming buffer captured raw memory contents including key
material. The crypto was correct; the memory management around it violated the
security assumptions.

### CVE-2019-5443 (cURL — non-constant-time NTLM response comparison)
The NTLM authentication handler in cURL compared challenge-response values using
standard memory comparison (`memcmp`). While NTLM itself is a deprecated protocol,
the timing side-channel in the comparison allowed network-adjacent attackers to
accelerate brute-force attacks against the NTLM response. The authentication
algorithm was implemented correctly; only the comparison method was wrong.
