"""The mechanical behavior spec against the lexfmt ground truth, the spec gate's filters, and winnowing."""

import json

import pytest

from veritas.analyze.gate import Gate, clean_view, spec_digest
from veritas.analyze.ground import compare
from veritas.analyze.similarity import fingerprints, overlap, tokens
from veritas.analyze.spec import build_spec
from veritas.documents import load_yaml


@pytest.fixture(scope="module")
def truth(lexfmt):
    return load_yaml(lexfmt / "expected-facts.yaml")


@pytest.fixture(scope="module")
def spec(lexfmt_model):
    return build_spec([lexfmt_model])


@pytest.fixture(scope="module")
def gate(lexfmt_model, lexfmt):
    return Gate([lexfmt_model], [(lexfmt / "dist" / "lexfmt.js").read_text(encoding="utf-8")])


def test_the_mechanical_spec_matches_the_ground_truth(spec, truth):
    result = compare(spec["claims"], truth)
    assert result.precision == 1.0, [c["fact"] for c in result.unmatched]
    assert result.recall == 1.0, result.missed
    assert (result.forbidden, result.missing_limitations) == ([], [])
    assert result.passes()


def test_every_observed_claim_cites_the_engine_record(spec):
    observed = [c for c in spec["claims"] if c["kind"] == "observed"]
    assert observed
    assert all(c["evidence"] == ["E-0123456789ab"] for c in observed)
    assert [i["id"] for i in spec["interfaces"]] == ["IF-api", "IF-format", "IF-errors"]
    assert spec["excluded"] == [{"file": "dist/lexfmt.js", "function": "checkLicense", "reason": "license-like name"}]


def test_the_gate_passes_the_mechanical_spec_and_the_clean_view_carries_nothing_dirty(spec, gate, lexfmt_model):
    result = gate.run(spec["claims"])
    assert (len(result.passed), result.blocked) == (len(spec["claims"]), [])
    clean = clean_view(
        spec, result.passed, [{"id": "v1", "sample": "s.lex", "sha256": "sha256:x", "expect": {}}], "readLex"
    )
    text = json.dumps(clean)
    assert "E-0123456789ab" not in text
    assert not any(name in text for name in ("checkLicense", "decodeSection", "crc32", "HEADER_SIZE", "crcTable"))
    assert spec_digest(clean) == spec_digest(json.loads(text))  # canonical: key order and whitespace don't matter


@pytest.mark.parametrize(
    ("text", "flt"),
    [
        ("`readLex` hands each payload to `decodeSection`.", "identifiers"),
        ("`readLex` checks a table named crcTable.", "identifiers"),
        ("`readLex` fails with the message 'not a .lex file'.", "assets"),
        ("The bundle carries the key AKIAABCDEFGHIJKLMNOP.", "secrets"),
        ("The license key in section 0x7F is checked with a weighted sum.", "excluded"),
        ("for (let i = 0; i < end; i++) crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);", "similarity"),
    ],
)
def test_each_filter_blocks_what_it_should(gate, text, flt):
    claim = {"id": "C-9999", "kind": "observed", "text": text, "fact": {"kind": "note"}, "evidence": []}
    result = gate.run([claim])
    assert flt in {b["filter"] for b in result.blocked}, result.blocked
    if flt == "excluded":  # withheld, and replaced by a limitation saying so
        assert [c["kind"] for c in result.passed] == ["limitation"]
    else:
        assert result.passed == []


def test_ground_truth_comparison_catches_wrong_forbidden_and_missing_claims(truth):
    claims = [
        {"kind": "observed", "text": "`readLex` reads a u8 at offset 3.", "fact": {"kind": "read", "offset": 3}},
        {"kind": "observed", "text": "Header flag bit 0x04 marks compressed files.", "fact": {"kind": "note"}},
    ]
    result = compare(claims, truth)
    assert (result.precision, result.matched) == (0.0, 0)
    assert result.forbidden == ["a meaning for header flag bit 0x04"]
    assert result.missing_limitations == truth["limitations"]
    assert not result.passes()


def test_winnowing_sees_through_renaming():
    original = "function crc(data, end) { let c = 0; for (let i = 0; i < end; i++) c = table[(c ^ data[i]) & 255]; }"
    renamed = "function sum(input, stop) { let s = 0; for (let k = 0; k < stop; k++) s = lut[(s ^ input[k]) & 255]; }"
    reference = fingerprints(tokens(original, normalize=True), 5)
    assert overlap(renamed, reference, normalize=True) == 1.0
    assert overlap(renamed, fingerprints(tokens(original), 5)) < 0.5  # raw tokens differ
    assert overlap("short", reference) == 0.0
