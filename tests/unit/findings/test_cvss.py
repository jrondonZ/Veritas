import pytest

from veritas.findings.cvss import base_score, roundup, severity

# Well-known CVSS 3.1 base scores (FIRST calculator).
VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize(("vector", "score"), VECTORS)
def test_base_scores(vector, score):
    assert base_score(vector) == score


@pytest.mark.parametrize(
    "vector",
    [
        "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_invalid_vectors_are_rejected(vector):
    with pytest.raises(ValueError, match=r"CVSS|metric|expected|invalid"):
        base_score(vector)


def test_roundup_absorbs_float_error_but_rounds_real_fractions_up():
    assert roundup(4.000002) == 4.0  # floating-point noise, not a real fraction
    assert roundup(4.02) == 4.1
    assert roundup(4.0) == 4.0


@pytest.mark.parametrize(
    ("score", "label"), [(0.0, "none"), (3.1, "low"), (6.5, "medium"), (7.0, "high"), (9.8, "critical")]
)
def test_severity(score, label):
    assert severity(score) == label
