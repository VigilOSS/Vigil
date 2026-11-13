"""An action view shows every note, mistake and default that applies to it.

`vigil assess contract <command> <action>` narrows a multi-action contract to
one action. An entry that names no action is shared; one that names actions
shows under them. An entry about one action that names others only in passing
(`An empty fetch ...` pointing at `adopt-lease`) states its actions with
`Scoped`, so it is not hidden from the action it is about.
"""
from __future__ import annotations

from assess.lib import contract_registry, contracts


def _note(contract_name: str, fragment: str) -> str:
    (note,) = [n for n in contracts.get_contract(contract_name).notes if fragment in n]
    return note


def test_a_note_about_an_action_shows_in_that_action_view() -> None:
    for command, action, fragment in (
        ("code-dispatch", "fetch", "An empty fetch says WHICH"),
        ("code-dispatch", "fetch", "carries `applicable_vuln_classes`"),
        ("code-dispatch", "done", "candidate receipts decide the close"),
        ("code-dispatch", "adopt-lease", "Adoption is an audited"),
        ("code-dispatch", "requeue-triggers", "Trigger requeue takes exactly"),
        ("artifact", "register", "Bulk accounting is exact"),
    ):
        note = _note(command, fragment)
        assert note in contracts.get_contract(f"{command} {action}").notes, (command, action)


def test_a_scoped_entry_names_only_actions_its_contract_has() -> None:
    checked = 0
    for contract in [*contracts.all_command_contracts(), *contracts.kali_verb_contracts()]:
        actions = {variant.name for variant in contract.variants}
        entries = [
            *contract.notes,
            *(wrong for wrong, _fix in contract.common_mistakes),
            *(key for key, _value in contract.helper_defaults),
        ]
        for entry in entries:
            if isinstance(entry, contract_registry.Scoped):
                checked += 1
                assert entry.actions and set(entry.actions) <= actions, (contract.name, entry[:60])
    assert checked, "no Scoped entry found; the scan no longer sees the registry"
