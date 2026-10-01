"""CLI import-cache tests must not retire the backend's loaded dependencies."""
import sys

from app import main
from app.services import remediation


_DEPENDENCIES = {
    "assess.lib.remediation_vcs": remediation._vcs,
    "assess.lib.remediation_project": sys.modules[remediation.load_engagement_project.__module__],
}


def test_cli_module_cache_eviction_can_run_in_isolation():
    for name in list(sys.modules):
        if name == "assess" or name.startswith("assess."):
            sys.modules.pop(name, None)
    assert all(name not in sys.modules for name in _DEPENDENCIES)


def test_following_backend_test_retains_dependency_identity_and_readiness():
    for name, dependency in _DEPENDENCIES.items():
        assert sys.modules.get(name) is dependency
    snapshot = main._backend_runtime_snapshot()
    assert snapshot["restart_required"] is False, snapshot["changed_inputs"]
