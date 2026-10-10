from __future__ import annotations

import os
from pathlib import Path
import hashlib
import sys

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
_BANNED_PLACEHOLDERS = (
    "target.com",
    "attacker.com",
    "evil.com",
    "trusted.com",
    "contoso.com",
    "bigcorp.com",
    "legit.com",
)
sys.path.insert(0, str(REPO_ROOT / "tools"))
from public_identity_policy import identity_token_digests, load_private_identity_digests  # noqa: E402

_BANNED_IDENTITY_TOKEN_DIGESTS = load_private_identity_digests(REPO_ROOT)


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
    if not _BANNED_IDENTITY_TOKEN_DIGESTS:
        pytest.skip("private identity policy is available in maintainer audits and trusted CI")
    violations: list[str] = []
    for path in [*_public_text_files(), Path(__file__)]:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        token_digests = identity_token_digests(text)
        if token_digests & _BANNED_IDENTITY_TOKEN_DIGESTS:
            violations.append(f"{path.relative_to(REPO_ROOT)}: private identity token")

    assert not violations, "remove private identity fragments:\n" + "\n".join(violations)


def test_identity_guard_scans_its_own_source(monkeypatch, tmp_path: Path) -> None:
    import sys
    import pytest

    sentinel = "syntheticprivatemarker"
    source = tmp_path / "source_guard.py"
    source.write_text(sentinel, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "__file__", str(source))
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "_BANNED_IDENTITY_TOKEN_DIGESTS", {
        hashlib.sha256(sentinel.encode()).hexdigest(),
    })

    with pytest.raises(AssertionError, match="private identity token"):
        test_public_tree_has_no_private_identity_fragments()


def test_identity_guard_rejects_compound_private_markers(monkeypatch, tmp_path: Path) -> None:
    import sys
    import pytest

    sentinel = "synthetic-private-marker"
    source = tmp_path / "example.py"
    source.write_text(sentinel, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "__file__", str(source))
    monkeypatch.setattr(sys.modules[__name__], "_public_text_files", lambda: [source])
    monkeypatch.setattr(sys.modules[__name__], "_BANNED_IDENTITY_TOKEN_DIGESTS", {
        hashlib.sha256(sentinel.encode()).hexdigest(),
    })

    with pytest.raises(AssertionError, match="private identity token"):
        test_public_tree_has_no_private_identity_fragments()


def test_identity_guard_rejects_spaced_private_markers(monkeypatch, tmp_path: Path) -> None:
    import sys
    import pytest

    source = tmp_path / "example.py"
    source.write_text("synthetic private", encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "__file__", str(source))
    monkeypatch.setattr(sys.modules[__name__], "_public_text_files", lambda: [source])
    monkeypatch.setattr(sys.modules[__name__], "_BANNED_IDENTITY_TOKEN_DIGESTS", {
        hashlib.sha256(b"syntheticprivate").hexdigest(),
    })

    with pytest.raises(AssertionError, match="private identity token"):
        test_public_tree_has_no_private_identity_fragments()


def test_public_tree_does_not_embed_private_audit_fingerprints() -> None:
    if not _BANNED_IDENTITY_TOKEN_DIGESTS:
        pytest.skip("private identity policy is available in maintainer audits and trusted CI")
    for path in [*_public_text_files(), Path(__file__)]:
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        assert not any(digest in text for digest in _BANNED_IDENTITY_TOKEN_DIGESTS), (
            f"{path.relative_to(REPO_ROOT)}: private audit fingerprint belongs outside the public tree"
        )


@pytest.mark.parametrize("text", ["Synthetic Private Audit", "synthetic@example.test"])
def test_identity_guard_matches_full_private_identifiers(monkeypatch, tmp_path: Path, text: str) -> None:
    source = tmp_path / "example.py"
    source.write_text(text, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "REPO_ROOT", tmp_path)
    monkeypatch.setattr(sys.modules[__name__], "__file__", str(source))
    monkeypatch.setattr(sys.modules[__name__], "_public_text_files", lambda: [source])
    monkeypatch.setattr(sys.modules[__name__], "_BANNED_IDENTITY_TOKEN_DIGESTS", {
        hashlib.sha256(text.lower().encode()).hexdigest(),
    })

    with pytest.raises(AssertionError, match="private identity token"):
        test_public_tree_has_no_private_identity_fragments()
