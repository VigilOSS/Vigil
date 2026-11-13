"""Contracts never teach a blocking target-facing call longer than the ceiling.

A dispatched agent's blocking call has to end before the agent-harness ceiling
kills the agent (exit 144 / SIGUSR1) and orphans the probe, so every blocking
`--timeout` a contract shows is at most 600 seconds. Work that cannot fit is an
operator-owned `kali job`, whose `--timeout` budgets a detached job and is the
one place a larger value belongs.
"""
from __future__ import annotations

import re
from collections.abc import Iterator

import pytest

from assess.lib import contracts
from assess.lib.contract_registry import KALI_VERBS

_BLOCKING_TIMEOUT_CEILING_S = 600

# `--timeout N` or `--timeout=N` as a whole flag (not --stage-timeout /
# --dalfox-timeout / --page-timeout), and nmap's `--host-timeout Ns`.
_TIMEOUT = re.compile(r"(?<![\w-])--timeout[ =](?P<seconds>\d+)(?P<plus>\+?)")
_HOST_TIMEOUT = re.compile(r"(?<![\w-])--host-timeout[ =](?P<seconds>\d+)s\b")


def _contract_texts() -> Iterator[tuple[str, str]]:
    names = set(contracts.contract_names()) | {f"kali {verb}" for verb in KALI_VERBS}
    for name in sorted(names):
        contract = contracts.get_contract(name)
        assert contract is not None, name
        views = [contract, *(contracts.get_contract(f"{name} {v.name}") for v in contract.variants)]
        for view in views:
            assert view is not None, name
            texts = [
                *view.preferred_invocations,
                *view.author_supplied_fields,
                *view.notes,
                *(f"{key}: {value}" for key, value in view.helper_defaults),
                *(f"{mistake}: {fix}" for mistake, fix in view.common_mistakes),
                *(str(example.get("command", "")) for example in view.examples),
            ]
            for text in texts:
                yield view.name, text


def _blocking_timeouts_over_ceiling(text: str) -> list[str]:
    over: list[str] = []
    for match in _TIMEOUT.finditer(text):
        # `kali job start ... --timeout N` budgets an operator-owned detached job.
        if "job start" in text[: match.start()]:
            continue
        if int(match.group("seconds")) > _BLOCKING_TIMEOUT_CEILING_S or match.group("plus"):
            over.append(match.group(0))
    for match in _HOST_TIMEOUT.finditer(text):
        if int(match.group("seconds")) > _BLOCKING_TIMEOUT_CEILING_S:
            over.append(match.group(0))
    return over


def test_no_contract_shows_a_blocking_timeout_above_the_ceiling() -> None:
    offenders = [
        f"{name}: {hit} in {text[:160]!r}"
        for name, text in _contract_texts()
        for hit in _blocking_timeouts_over_ceiling(text)
    ]
    assert offenders == []


@pytest.mark.parametrize(
    ("text", "flagged"),
    [
        ("vigil assess kali exec ... --timeout 1800 -- nmap", ["--timeout 1800"]),
        ("run synchronously with --timeout 1800+", ["--timeout 1800+"]),
        ("vigil assess kali nmap-scan ... --timeout 600", []),
        ("vigil assess kali job start ... --timeout 21600 -- nuclei", []),
        ("--stage-timeout 1800 --dalfox-timeout 900", []),
        ("nmap --host-timeout 1800s", ["--host-timeout 1800s"]),
    ],
)
def test_ceiling_scan_flags_only_blocking_timeouts(text: str, flagged: list[str]) -> None:
    assert _blocking_timeouts_over_ceiling(text) == flagged
