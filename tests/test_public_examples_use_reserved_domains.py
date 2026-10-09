from __future__ import annotations

import os
from pathlib import Path
import hashlib
import re


REPO_ROOT = Path(__file__).resolve().parents[1]
_BANNED_PLACEHOLDERS = (
    "target.example",
    "attacker.example",
    "evil.example",
    "trusted.example",
    "acme.example",
    "acme.example",
    "legitimate.example",
)
_BANNED_IDENTITY_TOKEN_DIGESTS = {
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
    "eaececc3bfbba9c2def506f0596898fd0dd2605722e2665d489930b143a82e4e",
}
def _public_text_files() -> list[Path]:
    files: list[Path] = []
    for directory, names, filenames in os.walk(REPO_ROOT):
        names[:] = [
            name
            for name in names
            if name
            not in {
                ".git",
                ".jj",
                ".mypy_cache",
                ".pytest_cache",
                ".ruff_cache",
                ".venv",
                "__pycache__",
                "build",
                "dist",
                "node_modules",
            }
        ]
        for filename in filenames:
            path = Path(directory) / filename
            if path != Path(__file__):
                files.append(path)
    return files


def test_public_examples_do_not_use_registered_placeholder_domains() -> None:
    violations: list[str] = []
    for path in _public_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        lowered = text.lower()
        for domain in _BANNED_PLACEHOLDERS:
            if domain in lowered:
                violations.append(f"{path.relative_to(REPO_ROOT)}: {domain}")

    assert not violations, "use reserved .example domains:\n" + "\n".join(violations)


def test_public_tree_has_no_private_identity_fragments() -> None:
    violations: list[str] = []
    for path in _public_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        token_digests = {
            hashlib.sha256(token.encode()).hexdigest()
            for token in re.findall(r"[a-z0-9]+", text.lower())
        }
        if token_digests & _BANNED_IDENTITY_TOKEN_DIGESTS:
            violations.append(f"{path.relative_to(REPO_ROOT)}: private identity token")

    assert not violations, "remove private identity fragments:\n" + "\n".join(violations)
