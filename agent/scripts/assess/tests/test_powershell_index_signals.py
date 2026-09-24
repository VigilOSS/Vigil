"""PowerShell module edges for agent navigation across script trees."""

from assess.lib.treesitter_index import index_file


def test_powershell_dot_sourced_module_has_a_navigation_target() -> None:
    indexed = index_file("scripts/deploy.ps1", "powershell", b". ./lib/helpers.psm1\n")

    assert indexed["analysis_status"] == "complete"
    assert indexed["import_targets"] == [
        {"raw": "./lib/helpers.psm1", "resolved": "./lib/helpers.psm1"}
    ]
