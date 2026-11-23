"""CVSS v3.1 base scores (FIRST CVSS v3.1 specification §7). Scores are computed, never model-generated."""

from __future__ import annotations

import math

_WEIGHTS: dict[str, dict[str, float]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_PRIVILEGES = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
_ORDER = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
PREFIX = "CVSS:3.1/"


def parse(vector: str) -> dict[str, str]:
    if not vector.startswith(PREFIX):
        raise ValueError(f"not a CVSS 3.1 vector: {vector!r}")
    metrics: dict[str, str] = {}
    for part in vector[len(PREFIX) :].split("/"):
        name, sep, value = part.partition(":")
        if not sep or name in metrics:
            raise ValueError(f"malformed or repeated metric {part!r}")
        metrics[name] = value
    if tuple(metrics) != _ORDER:
        raise ValueError(f"expected base metrics {'/'.join(_ORDER)} in order")
    if metrics["S"] not in _PRIVILEGES or metrics["PR"] not in _PRIVILEGES["U"]:
        raise ValueError("invalid scope or privileges value")
    for name, table in _WEIGHTS.items():
        if metrics[name] not in table:
            raise ValueError(f"invalid {name} value {metrics[name]!r}")
    return metrics


def roundup(value: float) -> float:
    """The specification's Roundup, which avoids floating-point surprises (Appendix A)."""
    scaled = round(value * 100_000)
    if scaled % 10_000 == 0:
        return scaled / 100_000.0
    return (math.floor(scaled / 10_000) + 1) / 10.0


def base_score(vector: str) -> float:
    m = parse(vector)
    w = {name: _WEIGHTS[name][m[name]] for name in _WEIGHTS}
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    changed = m["S"] == "C"
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * _PRIVILEGES[m["S"]][m["PR"]] * w["UI"]
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return roundup(min(total, 10.0))


def severity(score: float) -> str:
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
