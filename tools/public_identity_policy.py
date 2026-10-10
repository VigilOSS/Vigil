"""Load private audit fingerprints without publishing them in the repository."""
import hashlib
import json
import os
from pathlib import Path
import re


def load_private_identity_digests(repo_root: Path) -> frozenset[str]:
    data = os.environ.get("VIGIL_PRIVATE_IDENTITY_DIGESTS")
    local = repo_root / ".git" / "vigil-private-identity-digests.json"
    if not data and local.is_file():
        data = local.read_text(encoding="utf-8")
    if not data:
        if os.environ.get("VIGIL_REQUIRE_PRIVATE_IDENTITY_POLICY", "").lower() == "true":
            raise ValueError("private identity policy is required for maintainer CI")
        return frozenset()
    try:
        values = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid private identity policy JSON") from exc
    if not isinstance(values, list) or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in values
    ):
        raise ValueError("invalid private identity policy digests")
    if not values and os.environ.get("VIGIL_REQUIRE_PRIVATE_IDENTITY_POLICY", "").lower() == "true":
        raise ValueError("private identity policy is required and must be nonempty")
    return frozenset(values)


def identity_token_digests(text: str) -> frozenset[str]:
    lowered = text.lower()
    words = re.findall(r"[a-z0-9]+", lowered)
    tokens = words + re.findall(r"[a-z0-9]+(?:[._-][a-z0-9]+)+", lowered)
    tokens += re.findall(r"[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}", lowered)
    for size in range(2, 5):
        for start in range(len(words) - size + 1):
            phrase = words[start:start + size]
            tokens.extend((" ".join(phrase), "".join(phrase)))
    return frozenset(hashlib.sha256(token.encode()).hexdigest() for token in set(tokens))
