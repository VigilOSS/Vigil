# GF Pattern Drift Decisions

This file records the static bucket-review decisions behind `agent/scripts/assess/lib/classify_buckets.py`. Upstream GF pattern repositories are effectively stable; the Python classifier intentionally narrows URL triage to buckets that can route work-buffer items, so this rationale is maintained by review rather than a sync script.

## Current Intentional Python-Only Buckets

- `trust_surface` — path-only trust-boundary routes that upstream GF does not model directly. Keep this bucket because uploads, OAuth callbacks, reset flows, webhooks, imports, exports, downloads, previews, and render/convert flows are high-value even without parameter-key signal.

## Upstream-Only Categories To Reassess Before Adding

- Secret or content-body categories (`aws_keys`, `base64`, `firebase`, `json_sec`, `strings`, `s3_buckets`) usually belong to body/artifact scanning skills such as `gau-triage`, not URL priority bucketing.
- Source-code categories (`go_functions`, `php_curl`, `php_errors`, `php_serialized`, `php_sinks`, `php_sources`) belong to source/code analysis rather than live URL dispatch.
- Infrastructure categories (`http_auth`, `interestingsubs`, `ip`, `servers`, `takeovers`, `urls`) may become separate recon or surface-collection signals, but should not be copied into `_BUCKETS` unless they produce a clear `work_items` dispatch cluster.
- `debug_pages`, `fw`, `meg_headers`, and `sec` need human review against existing `debug_logic`, `interestingparams`, and tool-output handling before becoming new buckets.

When adding a bucket, update `_BUCKETS`, add or update the matching `gf-patterns/*.md` reference, record the accept/skip rationale here when relevant, and add a focused classifier/dispatch regression test.
