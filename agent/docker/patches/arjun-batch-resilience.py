#!/usr/bin/env python3
"""Patch Arjun 2.2.7 so one bad endpoint can't abort an entire ``-i`` batch.

Arjun's per-URL loop in ``__main__.main()`` is wrapped in a ``try`` that catches
only ``KeyboardInterrupt``, so any *other* exception raised while scanning one
endpoint propagates out and ends the whole run. Two real failure modes hit this
on production / rate-limited targets:

  1. A target that returns 400/413/418/429/503 takes the "unhealthy target"
     branch, which prints ``request.status_code`` — but ``request`` is a dict, so
     it raises ``AttributeError: 'dict' object has no attribute 'status_code'``.
     A single rate-limited (429) endpoint therefore kills a gated ``-i`` batch.
  2. Any other per-URL error (the requester returns an error string, a parse
     failure, a transient network error) propagates the same way.

This patch makes both survivable:
  (a) fixes the ``request.status_code`` typo to ``response_1.status_code`` so a
      rate-limited endpoint no longer raises; and
  (b) wraps the per-URL ``initialize()`` call in ``try/except`` so any remaining
      per-endpoint error is logged and skipped instead of ending the run.

Idempotent — re-running on an already-patched file is a no-op. Pinned to
``arjun==2.2.7`` via the exact source anchors below; if Arjun is bumped, the
anchors will not match and this exits non-zero so the image build surfaces it
(an unpatched-but-present Arjun must never ship silently).
"""
from __future__ import annotations

import sys

# --- Anchor 1: the unhealthy-target typo (request is a dict, not a response). --
TYPO_OLD = (
    "print('%s Target returned HTTP %i, this may cause problems.' "
    "% (bad, request.status_code))"
)
TYPO_NEW = (
    "print('%s Target returned HTTP %i, this may cause problems.' "
    "% (bad, response_1.status_code))"
)

# --- Anchor 2: the per-URL call in main()'s loop (12-space indent in source). --
LOOP_OLD = (
    "            these_params = initialize(request, wordlist, single_url=is_single)\n"
    "            count += 1\n"
)
LOOP_NEW = (
    "            try:\n"
    "                these_params = initialize(request, wordlist, single_url=is_single)\n"
    "            except Exception as _vigil_exc:\n"
    "                print('%s Skipped %s due to error: %s' % (bad, url, _vigil_exc))\n"
    "                count += 1\n"
    "                continue\n"
    "            count += 1\n"
)


def patch(path: str) -> int:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            src = fh.read()
    except FileNotFoundError:
        # No arjun at this path (e.g. a PRELOADED_TOOLS base installed it
        # elsewhere). Nothing to do — let the build proceed.
        print(f"arjun patch: no file at {path}; skipping", file=sys.stderr)
        return 0

    original = src
    typo_done = TYPO_NEW in src
    loop_done = "_vigil_exc" in src

    if not typo_done and TYPO_OLD in src:
        src = src.replace(TYPO_OLD, TYPO_NEW, 1)
        typo_done = True
    if not loop_done and LOOP_OLD in src:
        src = src.replace(LOOP_OLD, LOOP_NEW, 1)
        loop_done = True

    if not (typo_done and loop_done):
        print(
            f"arjun patch: ERROR anchors not found in {path} "
            f"(typo_ok={typo_done} loop_ok={loop_done}) — Arjun version likely "
            "changed; re-verify the patch before shipping.",
            file=sys.stderr,
        )
        return 1

    if src == original:
        print(f"arjun patch: already applied to {path}")
        return 0

    compile(src, path, "exec")  # fail loudly if the edit broke syntax
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(src)
    print(f"arjun patch: applied batch-resilience + status_code fix to {path}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "usage: arjun-batch-resilience.py <path-to-arjun/__main__.py>",
            file=sys.stderr,
        )
        sys.exit(2)
    sys.exit(patch(sys.argv[1]))
