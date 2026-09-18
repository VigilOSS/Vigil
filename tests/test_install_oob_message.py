"""`vigil install`'s "no relay route" notice: what it claims, and to whom.

Two separate contracts are pinned here.

**Audience.** The legacy-route sentence ("a root already running OOB on the
shared 53/8443 route keeps it") answers a question only an operator with LIVE
callbacks can have. Printing it on a brand-new root asserted a reassurance
about state that root does not have, and duplicated the `oob.relay-route` row
`vigil doctor` already prints. It is now gated on the same predicate the router
itself branches on, ``oob_relay.has_pre_routing_oob_state``.

**Dual readers.** The notice is stderr, which both an operator and an LLM
(`vigil assess`, the `agent/` operator prompts) read. On a terminal it may wrap
and indent; through a pipe it must stay ONE grep-able record, carry no escape
byte, and cost no more bytes than the unstyled line it replaced. The same
pipe-side contract is pinned for the `client-roster`/`client-entrypoint` repair
records, which share this file's ``_diagnostic`` rendering but stay machine
records either way.
"""
from __future__ import annotations

import io
from pathlib import Path

import pytest

from vigil_cli import install as install_module
from vigil_cli.oob_relay import OOB_STATE_RELATIVE_PATH

ESC = "\x1b"

# The exact line `vigil install` printed before this refinement. It is the byte
# budget, not a target: the replacement must never cost a piped reader more.
PRE_REFINEMENT_NOTICE = (
    "[vigil] no OOB route allocated: `oob.domain` is not set. "
    "Set it (`vigil config set oob.domain <domain>` or "
    "VIGIL_OOB_DOMAIN) and re-run `vigil install` to reserve this "
    "install its own relay slot. A root already running OOB on the "
    "shared legacy route (ports 53/8443) keeps that route instead, "
    "so its live callbacks are not moved."
)

LEGACY_ROUTE_MARKER = "53/8443"


class FakeStream(io.StringIO):
    def __init__(self, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


@pytest.fixture(autouse=True)
def _styled_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "80")


def _seed_live_oob_state(install_root: Path) -> None:
    """Leave behind what `vigil oob start` leaves behind, and nothing else.

    A rendered ``frpc.toml`` is the discriminator ``has_pre_routing_oob_state``
    reads: routing records (``relay-routing.json`` and friends) are bookkeeping
    and deliberately do not count.
    """
    state_dir = install_root / OOB_STATE_RELATIVE_PATH
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "frpc.toml").write_text("[common]\n", encoding="utf-8")


def _piped(install_root: Path) -> str:
    return install_module._format_oob_route_notice(install_root, stream=FakeStream(tty=False))


def _on_a_tty(install_root: Path) -> str:
    return install_module._format_oob_route_notice(install_root, stream=FakeStream(tty=True))


def test_fresh_root_states_the_finding_and_both_remedy_steps(tmp_path: Path) -> None:
    """Release follow-up #4: a remedy must not be a no-op loop. Here it is
    genuinely two-step, so both steps are named."""
    notice = _piped(tmp_path)
    assert "`oob.domain` is unset" in notice
    assert "vigil config set oob.domain <domain>" in notice
    assert "VIGIL_OOB_DOMAIN" in notice
    assert "vigil install" in notice


def test_fresh_root_does_not_claim_anything_about_the_legacy_route(tmp_path: Path) -> None:
    """The brand-new-root case: no live callbacks exist, so the reassurance
    about not moving them answers a question this operator cannot have."""
    assert LEGACY_ROUTE_MARKER not in _piped(tmp_path)
    assert LEGACY_ROUTE_MARKER not in _on_a_tty(tmp_path)


def test_root_already_running_oob_is_told_its_route_is_kept(tmp_path: Path) -> None:
    _seed_live_oob_state(tmp_path)
    notice = _piped(tmp_path)
    assert LEGACY_ROUTE_MARKER in notice
    assert "callbacks" in notice
    # The finding and the remedy do not change; only the reassurance is added.
    assert "`oob.domain` is unset" in notice
    assert "vigil config set oob.domain <domain>" in notice


def test_routing_records_alone_do_not_count_as_live_oob(tmp_path: Path) -> None:
    """Mirrors ``has_pre_routing_oob_state``'s own rule: an interrupted pin
    leaves a lock file with nothing ever routed through it."""
    state_dir = tmp_path / OOB_STATE_RELATIVE_PATH
    state_dir.mkdir(parents=True)
    (state_dir / "relay-routing.json.lock").write_text("", encoding="utf-8")
    assert LEGACY_ROUTE_MARKER not in _piped(tmp_path)


@pytest.mark.parametrize("live_oob", [False, True])
def test_piped_notice_is_one_record_with_no_escape_bytes(tmp_path: Path, live_oob: bool) -> None:
    if live_oob:
        _seed_live_oob_state(tmp_path)
    notice = _piped(tmp_path)
    assert "\n" not in notice, notice
    assert ESC not in notice
    assert notice.startswith("[vigil] ")


@pytest.mark.parametrize("live_oob", [False, True])
def test_piped_notice_is_not_longer_than_the_line_it_replaced(
    tmp_path: Path, live_oob: bool
) -> None:
    if live_oob:
        _seed_live_oob_state(tmp_path)
    notice = _piped(tmp_path)
    assert len(notice.encode()) <= len(PRE_REFINEMENT_NOTICE.encode()), notice


def test_piped_notice_ignores_terminal_width(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A narrow terminal must not reshape what a pipe receives — the consumer of
    a redirected log has no columns at all."""
    monkeypatch.setenv("COLUMNS", "40")
    narrow = _piped(tmp_path)
    monkeypatch.setenv("COLUMNS", "200")
    assert narrow == _piped(tmp_path)


def test_tty_notice_wraps_within_an_80_column_terminal(tmp_path: Path) -> None:
    """The reported defect: an unwrapped ``print`` let the terminal hard-wrap
    mid-word (``vigil insta\\nll``)."""
    notice = _on_a_tty(tmp_path)
    assert "\n" in notice
    assert all(len(line) <= 80 for line in notice.splitlines()), notice


def test_tty_notice_keeps_the_command_copy_pasteable(tmp_path: Path) -> None:
    notice = _on_a_tty(tmp_path)
    assert any(
        line.strip().startswith("vigil config set oob.domain <domain>")
        for line in notice.splitlines()
    ), notice


def test_install_prints_the_notice_to_stderr_when_no_domain_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """End-to-end: the notice still rides the real install path, on stderr."""
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.delenv("VIGIL_OOB_DOMAIN", raising=False)
    source_root = tmp_path / "source"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "agent" / "README").write_text("managed", encoding="utf-8")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=tmp_path / "install",
            verify_docker_image=False,
        )
    )

    captured = capsys.readouterr()
    assert "`oob.domain` is unset" in captured.err
    assert "`oob.domain` is unset" not in captured.out


def test_install_is_silent_about_the_route_when_a_domain_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from vigil_cli.install import InstallOptions, install_from_source

    monkeypatch.setenv("VIGIL_CONFIG", str(tmp_path / "config.json"))
    monkeypatch.setenv("VIGIL_OOB_DOMAIN", "oob.example.test")
    source_root = tmp_path / "source"
    (source_root / "agent").mkdir(parents=True)
    (source_root / "agent" / "README").write_text("managed", encoding="utf-8")

    install_from_source(
        InstallOptions(
            source_root=source_root,
            install_root=tmp_path / "install",
            verify_docker_image=False,
        )
    )

    assert "oob.domain" not in capsys.readouterr().err


def test_repair_records_are_byte_identical_through_a_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The `client-entrypoint repair:` / `client-roster repair:` lines are machine
    records and stay machine records: `_diagnostic` may only hang them under the
    `[vigil] ` marker for a terminal, never reshape what a pipe receives."""
    monkeypatch.setattr("sys.stderr", FakeStream(tty=False))
    record = (
        "[vigil] client-entrypoint repair: scanned=3 reconciled=3 skipped=0 "
        "permission_overrides=0"
    )
    assert install_module._diagnostic(record) == record


def test_repair_records_hang_under_the_marker_on_a_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("sys.stderr", FakeStream(tty=True))
    record = (
        "[vigil] client-entrypoint repair: scanned=3 reconciled=3 skipped=0 "
        "permission_overrides=0"
    )
    rendered = install_module._diagnostic(record)
    lines = rendered.splitlines()
    assert len(lines) > 1, "an 88-column record must not be left to the terminal to break"
    assert all(len(line) <= 80 for line in lines), rendered
    assert lines[1].startswith(" " * len("[vigil] "))
    assert "permission_overrides=0" in rendered, "a field must never be split"
