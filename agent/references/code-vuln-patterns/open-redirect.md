# Open Redirect — Redirect Validation Gaps and OAuth Theft Chains

> Target: Redirect flows where attacker-controlled destinations survive relative/absolute URL
> checks, host allowlists, or route helper abstractions and can pivot into phishing or token theft.

---

## Baseline Patterns

- `return redirect(request.args["next"])`
- Host allowlist that accepts any string containing the trusted domain
- Relative-path-only check that misses protocol-relative URLs

---

## What You're Hunting

### 1. Host Validation by String Prefix/Suffix

- `startsWith("https://trusted.example")`
- `endsWith(".trusted.example")` with missing dot-boundary handling
- Naive substring checks that accept attacker-controlled hostnames

### 2. Relative vs Absolute URL Confusion

- `//attacker.test/path`
- Backslash normalization differences
- Encoded schemes or separators decoded after validation

### 3. OAuth and Auth Flow Redirect Chains

The redirect is not just a phishing nuisance if it sits in:

- `redirect_uri` validation
- login handoff / SSO callback flows
- post-password-reset or email-verification redirects

### 4. Framework Helper Abstraction Leaks

“Safe” route helpers often become unsafe when they accept mixed local/remote inputs.

- Route helper accepts route name or absolute URL
- Redirect wrapper unwraps nested `next` parameters later
- Middleware validates one redirect parameter while downstream code uses another

---

## Audit Questions

- Does validation happen on the final destination after decoding and normalization?
- Are protocol-relative, backslash, and encoded-separator forms rejected?
- Can a redirect chain leak OAuth codes, reset tokens, or session handoff secrets?
- Do multiple layers disagree on what counts as “local”?
