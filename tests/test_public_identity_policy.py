from pathlib import Path
import hashlib
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from public_identity_policy import load_private_identity_digests  # noqa: E402


def test_environment_policy_overrides_private_local_policy(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    local = hashlib.sha256(b"local synthetic marker").hexdigest()
    supplied = hashlib.sha256(b"environment synthetic marker").hexdigest()
    (tmp_path / ".git" / "vigil-private-identity-digests.json").write_text(json.dumps([local]))
    monkeypatch.setenv("VIGIL_PRIVATE_IDENTITY_DIGESTS", json.dumps([supplied]))

    assert load_private_identity_digests(tmp_path) == frozenset({supplied})


def test_invalid_private_policy_fails_closed(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VIGIL_PRIVATE_IDENTITY_DIGESTS", '["invalid digest"]')

    with pytest.raises(ValueError, match="private identity policy"):
        load_private_identity_digests(tmp_path)


def test_maintainer_policy_cannot_be_silently_omitted(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("VIGIL_PRIVATE_IDENTITY_DIGESTS", raising=False)
    monkeypatch.setenv("VIGIL_REQUIRE_PRIVATE_IDENTITY_POLICY", "true")

    with pytest.raises(ValueError, match="private identity policy is required"):
        load_private_identity_digests(tmp_path)


def test_empty_maintainer_policy_cannot_disable_audit(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("VIGIL_PRIVATE_IDENTITY_DIGESTS", "[]")
    monkeypatch.setenv("VIGIL_REQUIRE_PRIVATE_IDENTITY_POLICY", "true")

    with pytest.raises(ValueError, match="private identity policy is required"):
        load_private_identity_digests(tmp_path)
