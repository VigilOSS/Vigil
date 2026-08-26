from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from harnesses.code_workflow import recipe


_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXPECTED_IMPLEMENTATION_PATHS = (
    "tests/eval/schemas/code-workflow-result-v1.schema.json",
)


def test_recipe_bundle_is_sorted_content_bound_and_complete() -> None:
    bundle = recipe.build_recipe_bundle(_REPO_ROOT)
    files = bundle["files"]
    paths = [row["path"] for row in files]

    assert bundle["schema"] == recipe.RECIPE_BUNDLE_SCHEMA
    assert paths == sorted(set(paths))
    assert set(recipe._IMPLEMENTATION_PATHS).issubset(paths)
    for row in files:
        source = (_REPO_ROOT / row["path"]).read_bytes()
        assert row == {
            "path": row["path"],
            "bytes": len(source),
            "sha256": hashlib.sha256(source).hexdigest(),
        }
    assert bundle["bundle_sha256"] == recipe._canonical_sha256(
        {"schema": bundle["schema"], "files": files}
    )


def test_recipe_inventory_covers_the_exact_executable_contract() -> None:
    assert recipe._IMPLEMENTATION_PATHS == _EXPECTED_IMPLEMENTATION_PATHS


def test_recipe_reader_rejects_escaping_and_symlink_paths(tmp_path: Path) -> None:
    regular = tmp_path / "regular.md"
    regular.write_text("bounded", encoding="utf-8")
    linked = tmp_path / "linked.md"
    linked.symlink_to(regular)

    with pytest.raises(recipe.RecipeIdentityError, match="unsafe recipe path"):
        recipe._read_bounded(tmp_path, "../regular.md")
    with pytest.raises(recipe.RecipeIdentityError, match="must be regular"):
        recipe._read_bounded(tmp_path, "linked.md")
