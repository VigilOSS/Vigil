"""The eval-capture provenance filter mirrors the backend's refusal set.

`state_manager/findings.py` owns which provenance keys the service stamps and
refuses from a caller (`_SERVICE_STAMPED_PROVENANCE_REMEDIES`). `eval_capture`
drops exactly those keys when it turns a live finding into a fixture, because a
fixture that kept one replays as a 400 rather than as the finding it was
captured from -- the capture is the only place that can strip them, since the
replay has no way to tell a captured stamp from an authored one.

The two trees package separately, so the CLI holds a copy rather than importing
the backend. This pins the copy. It is a drift detector, not a restatement:
neither side's membership is written here, so adding a sixth service-stamped key
to the backend fails this test until the capture filter learns about it.
"""


def test_eval_capture_drops_exactly_the_provenance_keys_the_service_stamps() -> None:
    from app.services.state_manager.findings import (
        _SERVICE_STAMPED_PROVENANCE_REMEDIES,
    )
    from assess.commands.eval_capture import _SERVICE_STAMPED_PROVENANCE_KEYS

    assert set(_SERVICE_STAMPED_PROVENANCE_KEYS) == set(
        _SERVICE_STAMPED_PROVENANCE_REMEDIES
    )
