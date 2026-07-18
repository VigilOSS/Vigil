"""Wave-0: ``kali arjun`` pre-creates the ``-oJ`` parent directory BEFORE the run.

Arjun writes its ``-oJ`` output during the run but does not create parent
directories itself, so a first run against a novel target (whose
``scans/arjun/<token>/<digest>/`` dir does not exist yet) crashed at export and
lost the whole run. The engagement tree is bind-mounted into the kali container,
so a host-side mkdir makes the path exist in-container too.
"""
from __future__ import annotations

from types import SimpleNamespace

from assess.commands import kali_arjun


def test_arjun_identity_injects_auth_into_headers():
    """`kali arjun --identity <name>` folds the named identity's session/bearer
    into arjun's ``--headers`` via the shared kali flag-spec — so an operator
    never hand-pastes a raw bearer token onto the command line (where it would
    leak into argv and the audit log). Locks arjun's membership in
    ``_REQUIRED_HEADER_FLAG_SPECS`` and the generic identity-injection path;
    would fail if either regressed.
    """
    from assess.lib.kali import _apply_identity_material
    from assess.lib.kali_output import _REQUIRED_HEADER_FLAG_SPECS

    # The flag-spec that tells the injector arjun takes headers via ``--headers``.
    assert "arjun" in _REQUIRED_HEADER_FLAG_SPECS

    # Bearer-token identity -> Authorization header folded into --headers.
    cmd = ["arjun", "-u", "https://target.example/api/item", "-m", "GET",
           "-oJ", "scans/arjun/x.json"]
    assert _apply_identity_material(cmd, "arjun", {"token": "SECRET-BEARER"}) is True
    assert "--headers" in cmd
    assert "Authorization: Bearer SECRET-BEARER" in cmd

    # Cookie-session identity -> Cookie header folded into --headers.
    cmd2 = ["arjun", "-u", "https://t.example/x", "-m", "GET"]
    assert _apply_identity_material(cmd2, "arjun", {"cookies": {"session": "abc"}}) is True
    assert "--headers" in cmd2
    assert "Cookie: session=abc" in cmd2


def test_precreate_json_parent_creates_dir_before_run(monkeypatch, tmp_path):
    json_path = "scans/arjun/nca-memo/deadbeef1234.json"
    host = tmp_path / json_path
    monkeypatch.setattr(kali_arjun, "_host_json_path", lambda args, path: str(host))
    args = SimpleNamespace(engagement_dir=str(tmp_path))

    assert not host.parent.exists()
    kali_arjun._precreate_json_parent(args, json_path)
    assert host.parent.is_dir()


def test_precreate_json_parent_is_best_effort_when_unresolvable(monkeypatch, tmp_path):
    # No resolvable host path (no engagement context) -> silent no-op, never raises.
    monkeypatch.setattr(kali_arjun, "_host_json_path", lambda args, path: None)
    kali_arjun._precreate_json_parent(SimpleNamespace(engagement_dir=None), "scans/arjun/x/y.json")
