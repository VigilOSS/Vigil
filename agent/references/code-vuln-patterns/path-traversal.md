# Path Traversal — Canonicalization, Archive Writes, and Indirect Filesystem Reachability

> Target: Filesystem access bugs where attacker-controlled path components survive normalization,
> join logic, archive extraction, or storage indirection and reach sensitive reads/writes.

---

## Baseline Patterns

- Direct `../../etc/passwd` concatenated onto a base directory
- Zip Slip extraction with no path canonicalization
- `os.path.join(base, user_input)` with no post-join confinement check

---

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

### 4. Indirect Traversal

The attacker does not control the final path directly; they control a lookup key, alias, or identifier
that maps to a path later in the chain.

- User-controlled profile image ID -> storage path lookup
- Plugin/theme name -> disk path resolution
- Import/export job name -> temp file path reuse

---

## Audit Questions

- Where does attacker input become a filename, relative path, archive entry, or storage key?
- Is confinement checked after all decoding, normalization, and symlink resolution?
- Are reads and writes both protected, or only one direction?
- Can a “safe” upload path later become an unsafe execution/include/load path?
