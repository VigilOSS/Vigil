from __future__ import annotations

import pytest

from app.services.state_manager.cvss import CvssVectorError, base_score


VECTOR = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        (VECTOR, 9.2),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N", 9.9),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
        ("CVSS:4.0/SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:P/AC:H/AV:N", 9.2),
    ],
)
def test_cvss40_base_score(vector, expected):
    assert base_score(vector) == expected


@pytest.mark.parametrize(
    "vector",
    [
        VECTOR.removesuffix("/SA:N"),
        VECTOR + "/AV:N",
        VECTOR.replace("AT:P", "AT:X"),
        VECTOR.replace("UI:N", "UI:R"),
        VECTOR.replace("SC:N", "SC:S"),
        VECTOR.replace("CVSS:4.0", "CVSS:4.1"),
        VECTOR + "/E:U",
        VECTOR + "/MAV:L",
        VECTOR + "/",
    ],
)
def test_cvss40_rejects_incomplete_invalid_and_non_base_vectors(vector):
    with pytest.raises(CvssVectorError):
        base_score(vector)
