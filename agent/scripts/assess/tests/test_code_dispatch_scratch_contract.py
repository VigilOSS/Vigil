"""The scratch contract names the helper field; executable leases namespace files."""
from __future__ import annotations

from assess.commands import code_dispatch
from assess.lib import contracts


def _dispatch_contract() -> contracts.CommandContract:
    contract = contracts.get_contract("code-dispatch")
    assert contract is not None
    return contract


def test_scratch_dir_is_a_declared_helper_supplied_field() -> None:
    defaults = dict(_dispatch_contract().helper_defaults)

    assert "scratch_dir" in defaults
    assert "tools/analysis-state/code-dispatch-scratch" in defaults["scratch_dir"]


def test_lease_scratch_paths_keep_attempt_files_distinct(tmp_path) -> None:
    paths = []
    for item_id, token in [(41, "acme-first"), (41, "acme-reclaimed"), (42, "acme-second")]:
        relative = code_dispatch._prepare_dispatch_scratch_dir(
            tmp_path, queue_item_id=item_id, lease_token=token,
        )
        destination = tmp_path / relative / f"{item_id}-handoff.json"
        destination.write_text(token, encoding="utf-8")
        paths.append(destination)
    assert len(set(paths)) == 3
    assert [path.read_text(encoding="utf-8") for path in paths] == [
        "acme-first", "acme-reclaimed", "acme-second",
    ]
    assert all(path.resolve().is_relative_to(tmp_path.resolve()) for path in paths)
