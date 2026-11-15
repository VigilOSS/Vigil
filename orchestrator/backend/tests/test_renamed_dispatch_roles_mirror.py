"""The CLI's renamed-role map matches the backend's, spelling for spelling.

`agent start` and `agent continue` register a retired role spelling as its
current role, and the backend treats a handoff naming the current role as the
role a dispatch stored under the retired spelling. A spelling one side maps and
the other does not would register a role whose handoff the backend refuses, or
accept a handoff the CLI would never have registered.
"""
from __future__ import annotations


def test_cli_renamed_dispatch_roles_mirror_the_backend() -> None:
    from assess.lib.contract_registry import RENAMED_DISPATCH_ROLES as CLI_RENAMED
    from app.services.state_manager.dispatches import RENAMED_DISPATCH_ROLES

    assert dict(CLI_RENAMED) == dict(RENAMED_DISPATCH_ROLES)
