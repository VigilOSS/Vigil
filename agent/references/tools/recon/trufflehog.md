---
description: TruffleHog in Vigil — gau secrets composition with --no-verification default, ad-hoc filesystem scans via kali exec, v3 syntax traps, verification-traffic policy and how to log an opt-in, output keys and the Raw-over-Redacted rule
skill: source-analysis
---

# TruffleHog

Primary secret scanner for stored HTTP response bodies. `vigil assess gau secrets` composes gau →
uro → httpx body capture → `trufflehog filesystem`, with `--no-verification` by default and
`--verify` to enable verification; it writes `trufflehog.json` under
`$DIR/scans/gau-pipeline/<target>/<cache_key>/`, namespaced per target and gau flag set. For an
ad-hoc scan of existing artifacts, run it in the runtime:

```bash
vigil assess kali exec --technique INFO-DISCLOSURE --intent "trufflehog over captured bodies" \
  --probe-kind fingerprint --phase collect --timeout 600 -- \
  trufflehog filesystem /engagements/$ENGAGEMENT_KEY/scans/bodies --json --no-update --no-verification
```

**v3 syntax traps.** Paths are positional (or repeatable `--directory=PATH`); `--path` does not
exist. `--only-verified` does not exist in filesystem mode; use `--results=verified`. Pass
`--no-update` in engagement pipelines to skip the blocking release check. On GB-scale corpora on a
large runtime, `--concurrency=16` helps (default 4).

**Verification sends secrets to third parties.** Verification is on unless `--no-verification` is
passed, and `--results=verified` also triggers it. It submits each token to AWS STS, GitHub,
Slack, Stripe and hundreds of other services: traffic that leaves the runtime, is out of scope
for most engagements, can get tokens revoked or rate-limited, and leaves IP/token pairs in vendor
logs. Opt in only when the engagement's `exploit_policy` and scope cover external validation, and
record the decision:
`vigil assess log operator "trufflehog verification opt-in" "<command>" "<scope/policy justification>"`.

**Output keys** (one JSON finding per line): `DetectorName`, `Verified` (true only when
verification ran and succeeded), `VerificationError`, `Raw` / `RawV2`, `Redacted`,
`SourceMetadata.Data.Filesystem.file` and `.line`, `ExtraData` (detector context, e.g. the IAM
ARN). Use `Raw` in Vigil records; `Redacted` is a partial tool rendering.
