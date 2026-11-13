"""`contract kali job start` names only flags `kali job start` accepts.

The job verb shares the kali audit flags, but it is its own parser: it has no
`--force`, `--extra-args` or `--agent-id`, and a contract that inherited the
synchronous verbs' notes sent the operator to flags argparse refuses.
"""
from __future__ import annotations

import argparse
import re

from assess.commands import kali_job
from assess.lib import contracts


def _start_options() -> set[str]:
    parser = argparse.ArgumentParser()
    kali_job.register(parser.add_subparsers())
    job = parser._subparsers._group_actions[0].choices["job"]
    start = job._subparsers._group_actions[0].choices["start"]
    return {option for action in start._actions for option in action.option_strings}


def test_every_flag_the_job_start_contract_names_is_a_job_start_option() -> None:
    contract = contracts.get_contract("kali job start")
    text = "\n".join((*contract.author_supplied_fields, *contract.notes))
    named = set(re.findall(r"(?<![\w-])(--[a-z][a-z-]*)", text))

    assert named, "the scan found no flags; the contract shape changed"
    assert named <= _start_options(), sorted(named - _start_options())
