---
description: Canonicalization bypass, archive extraction writes, symlink and separator confusion
skill: code-vulnerability-analysis, code-variant-analysis
languages: C/C++, Python, JS
---

# Path Traversal — Canonicalization, Archive Writes, and Indirect Filesystem Reachability

Attacker-controlled path components that survive normalization, join logic, archive extraction, or
storage indirection and reach sensitive reads or writes.

## What You're Hunting

### 1. Canonicalization Order Bugs

Validation happens before decode, cleanup, or separator folding.

- Validate raw path, then URL-decode
- Strip `..` before collapsing repeated separators
- Enforce prefix before resolving symlinks

### 2. Mixed Trust Components

One component is allowlisted, another is attacker-controlled, and the final composed path escapes.

- Trusted storage root + attacker filename
- Template directory + attacker locale/theme/plugin name
- Cache key used later as a filesystem path

### 3. Archive and Bulk Extraction Writes

The code validates the destination directory once but not each archive entry.

- Tar/zip entry names with `../`
- Absolute paths
- Symlink entries that pivot later writes outside the extraction root

**Check the extraction library and the call shape first:**
- Python `zipfile.extract()`/`extractall()` sanitize `..` and absolute member names (since 2.7.4 and
  3.3.1). Manual extraction — `zf.open(name)` or `zf.read(name)` written to
  `os.path.join(dest, name)` — has no such protection and is the vulnerable shape.
- Python `tarfile.extractall()` trusts member names, links, and modes unless a `filter=` is passed.
  The parameter exists from 3.12 and was backported to 3.8.17, 3.9.17, 3.10.12, and 3.11.4; the
  default stays fully trusting through 3.13 (3.12-3.13 warn) and becomes `'data'` in 3.14. The
  `'data'` filter itself had bypasses (CVE-2025-4517 and related), fixed in 3.12.11 and 3.13.4, so
  check the patch level when the code relies on it.
- Go `archive/zip`/`archive/tar` and Java `ZipInputStream`/`ZipFile` do no filtering; the caller must
  validate each entry. Go 1.20 added `filepath.IsLocal` for that check and Go 1.24 `os.Root` for
  confined file access.

### 4. Indirect Traversal

The attacker does not control the final path directly; they control a lookup key, alias, or identifier
that maps to a path later in the chain.

- User-controlled profile image ID -> storage path lookup
- Plugin/theme name -> disk path resolution
- Import/export job name -> temp file path reuse
- A server-supplied filename trusted for the local write: CVE-2016-4971, wget following an HTTP-to-FTP
  redirect saved under the FTP server's filename (`.bash_profile`), because the redirect moved the
  trust boundary the filename check assumed

---

## Audit Questions

- Where does attacker input become a filename, relative path, archive entry, or storage key?
- Is confinement checked after all decoding, normalization, and symlink resolution?
- Are reads and writes both protected, or only one direction?
- Can a “safe” upload path later become an unsafe execution/include/load path?
