"""Fold a status or label word to the canonical spelling it names.

Mirrors the backend's ``folded_vocabulary`` (``app/api/assessment.py``): case
and the separators ``-``, ``_`` and space are ignored, so ``Blocked``,
``pending-runtime-proof`` and ``in_progress`` each name exactly one canonical
word. A word outside the vocabulary is returned unchanged, so argparse
``choices`` or the schema still refuses it by its own spelling.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable


def vocabulary_key(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value.casefold())


def word_folder(words: Iterable[str]) -> Callable[[str], str]:
    """An argparse ``type`` (or plain function) folding a word into ``words``."""
    by_key = {vocabulary_key(word): word for word in words}

    def fold(value: str) -> str:
        if not isinstance(value, str):
            return value
        return by_key.get(vocabulary_key(value), value)

    return fold
