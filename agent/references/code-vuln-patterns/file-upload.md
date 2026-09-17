---
description: Validation/storage drift, archive smuggling, upload-to-parser and upload-to-execution chains
skill: code-vulnerability-analysis, code-variant-analysis
languages: Python, JS, Java, Go
---

# File Upload — Validation/Storage Drift and Upload-to-Execution Chains

> Target: Upload paths where filename, content, archive contents, or downstream processing let
> attacker files escape validation or pivot into parsing, traversal, SSRF, or code execution.

---

## What You're Hunting

### 1. Validation vs Storage Drift

The file is validated under one name or type and later stored/served under another.

- Temporary filename validated, original filename used later
- Extension checked before Unicode normalization or case-folding
- Recompressed or transformed files inheriting unsafe metadata

### 2. Archive and Container Uploads

The dangerous content is inside a “safe” wrapper.

- Zip/tar extraction with traversal
- Office/SVG/document formats carrying active content
- Nested image/document parsers that fetch external resources

### 3. Upload-to-Parser / Upload-to-Execution Pivots

- Uploaded file later parsed as XML/HTML/template/script
- Image processing pipeline invoking external tools
- “Import” feature loading attacker-controlled structured data into privileged code paths

### 4. Cross-Tenant and Cross-User Exposure

The bug is not code execution but the ability to overwrite, replace, or expose another user’s file.

- Predictable object keys
- Shared bucket/key namespaces
- Reuse of attacker-controlled filenames in public URLs

---

## Audit Questions

- Is the final stored artifact the same thing that was validated?
- Can archive, SVG, document, or media parsing reach traversal, XXE, or SSRF sinks?
- Is upload storage isolated from executable/template/include paths?
- Can one user overwrite or read another user’s uploaded object?
