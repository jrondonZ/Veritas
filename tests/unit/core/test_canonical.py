import math

import pytest

from veritas.core.canonical import CanonicalizationError, canonical_json, digest


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        # ECMAScript Number::toString cases from RFC 8785 appendix B
        (0.0, "0"),
        (-0.0, "0"),
        (1e21, "1e+21"),
        (1e-7, "1e-7"),
        (1e-6, "0.000001"),
        (123456789012345680000.0, "123456789012345680000"),
        (9007199254740991.0, "9007199254740991"),
        (5e-324, "5e-324"),
        (1.7976931348623157e308, "1.7976931348623157e+308"),
        (333333333.3333333, "333333333.3333333"),
        (-1.5, "-1.5"),
        (100.0, "100"),
        (0.1, "0.1"),
    ],
)
def test_number_formatting(value, expected):
    assert canonical_json(value) == expected


def test_object_keys_sorted_by_utf16_code_units():
    # U+1F600 (surrogate pair D83D DE00) sorts before U+FB33 in UTF-16, after it in code points.
    assert canonical_json({"דּ": 1, "\U0001f600": 2}) == '{"\U0001f600":2,"דּ":1}'


def test_string_escaping_is_minimal():
    assert canonical_json('a"b\\c\n\u0001é€') == '"a\\"b\\\\c\\n\\u0001é€"'


def test_nested_structure_has_no_whitespace():
    assert canonical_json({"b": [1, True, None], "a": {"y": "z"}}) == '{"a":{"y":"z"},"b":[1,true,null]}'


@pytest.mark.parametrize("bad", [math.nan, math.inf, 2**53 + 1, {1: "x"}, object()])
def test_rejects_non_canonicalizable_values(bad):
    with pytest.raises(CanonicalizationError):
        canonical_json(bad)


def test_digest_is_key_order_independent():
    assert digest({"a": 1, "b": 2}) == digest({"b": 2, "a": 1})
    assert digest({"a": 1}).startswith("sha256:")
