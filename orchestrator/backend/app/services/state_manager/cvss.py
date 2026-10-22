"""Deterministic CVSS v3.1 and v4.0 base scores for finding integrity gates."""
from __future__ import annotations

import math

from cvss import CVSS4
from cvss.exceptions import CVSS4Error


class CvssVectorError(ValueError):
    """Raised when a vector is not a complete supported base vector."""


_VALUES = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
_PR_VALUES = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_REQUIRED = frozenset({"AV", "AC", "PR", "UI", "S", "C", "I", "A"})
_REQUIRED_V4 = frozenset({"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"})


def _parse(vector: str) -> dict[str, str]:
    parts = str(vector or "").strip().split("/")
    if not parts or parts[0] != "CVSS:3.1":
        raise CvssVectorError("vector must begin with CVSS:3.1")
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        if ":" not in part:
            raise CvssVectorError(f"invalid metric: {part}")
        name, value = part.split(":", 1)
        if name in metrics:
            raise CvssVectorError(f"duplicate metric: {name}")
        metrics[name] = value
    if set(metrics) != _REQUIRED:
        raise CvssVectorError("vector must contain every base metric exactly once")
    if metrics["S"] not in {"U", "C"}:
        raise CvssVectorError("invalid S metric")
    for name, values in _VALUES.items():
        if metrics[name] not in values:
            raise CvssVectorError(f"invalid {name} metric")
    if metrics["PR"] not in _PR_VALUES[metrics["S"]]:
        raise CvssVectorError("invalid PR metric")
    return metrics


def _round_up(value: float) -> float:
    return math.ceil((value * 10.0) - 1e-10) / 10.0


def base_score(vector: str) -> float:
    """Return a base score using the version declared in the vector itself.

    Findings store base scores only. In particular, CVSS4's calculator also
    accepts threat/environmental metrics that affect its score; reject those
    here rather than presenting an adjusted score as a base score.
    """
    vector = str(vector or "").strip()
    version, *fields = vector.split("/")
    if version == "CVSS:4.0":
        if {field.partition(":")[0] for field in fields} != _REQUIRED_V4:
            raise CvssVectorError("vector must contain every v4.0 base metric and no other metrics")
        try:
            return float(CVSS4(vector).scores()[0])
        except CVSS4Error as exc:
            raise CvssVectorError(str(exc)) from exc
    if version != "CVSS:3.1":
        raise CvssVectorError("vector must begin with CVSS:3.1 or CVSS:4.0")
    metrics = _parse(vector)
    impact_subscore = 1.0 - (
        (1.0 - _VALUES["C"][metrics["C"]])
        * (1.0 - _VALUES["I"][metrics["I"]])
        * (1.0 - _VALUES["A"][metrics["A"]])
    )
    scope = metrics["S"]
    if scope == "U":
        impact = 6.42 * impact_subscore
    else:
        impact = (
            7.52 * (impact_subscore - 0.029)
            - 3.25 * ((impact_subscore - 0.02) ** 15)
        )
    if impact <= 0:
        return 0.0
    exploitability = (
        8.22
        * _VALUES["AV"][metrics["AV"]]
        * _VALUES["AC"][metrics["AC"]]
        * _PR_VALUES[scope][metrics["PR"]]
        * _VALUES["UI"][metrics["UI"]]
    )
    raw = impact + exploitability
    if scope == "C":
        raw *= 1.08
    return _round_up(min(raw, 10.0))
