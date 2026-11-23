"""Analysis charters, and the JavaScript engine run locally against the lexfmt subject."""

import shutil

import pytest
import yaml

from veritas.analyze.charter import check_charter
from veritas.core.canonical import sha256_hex

SUBJECT = "dist/lexfmt.js"
VENDORED_ACORN = "76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b"


def copy_lab(lexfmt, tmp_path, **changes):
    for item in ("dist", "samples", "conformance.json", "README.md"):
        source = lexfmt / item
        (shutil.copytree if source.is_dir() else shutil.copyfile)(source, tmp_path / item)
    doc = yaml.safe_load((lexfmt / "veritas.charter.yaml").read_text(encoding="utf-8"))
    for key, value in changes.items():
        node = doc
        *parents, last = key.split("__")
        for part in parents:
            node = node[part]
        node[last] = value
    path = tmp_path / "veritas.charter.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return path


def test_the_lab_charter_pins_everything_it_references(lexfmt):
    report = check_charter(lexfmt / "veritas.charter.yaml")
    assert report.ok, report.errors
    assert (report.call, len(report.vectors)) == ("readLex", 12)
    assert {k.split(":")[0] for k in report.files} == {"reference", "subject", "conformance", "sample"}
    assert report.digest.startswith("sha256:")


def test_a_changed_subject_or_sample_changes_the_verdict(lexfmt, tmp_path):
    first = check_charter(copy_lab(lexfmt, tmp_path))
    sample = tmp_path / "samples" / "minimal.lex"
    sample.write_bytes(sample.read_bytes() + b"\x00")
    assert check_charter(tmp_path / "veritas.charter.yaml").digest != first.digest
    (tmp_path / SUBJECT).write_text("export const x = 1;\n", encoding="utf-8")
    report = check_charter(tmp_path / "veritas.charter.yaml")
    assert any("does not match its pinned sha256" in e for e in report.errors), report.errors


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"constraints__execute_subject": True}, "constraints.execute_subject"),
        ({"constraints__network": "target-scope"}, "constraints.network"),
        ({"basis": "curiosity"}, "basis"),
        ({"purpose": "because"}, "purpose"),
        ({"conformance": None, "deliverables": ["behavior-spec", "implementation"]}, "needs conformance vectors"),
    ],
)
def test_charter_rules(lexfmt, tmp_path, changes, fragment):
    report = check_charter(copy_lab(lexfmt, tmp_path, **changes))
    assert not report.ok
    assert any(fragment in e for e in report.errors), report.errors


def test_the_vendored_parser_is_unchanged(repo_root):
    vendored = repo_root / "plugins" / "js-engine" / "vendor" / "acorn.mjs"
    assert sha256_hex(vendored.read_bytes()) == VENDORED_ACORN


def test_engine_facts_for_the_subject(lexfmt_model):
    facts = lexfmt_model.facts
    assert [e["name"] for e in facts["exports"]] == ["SectionType", "HeaderFlags", "LexError", "readLex", "writeLex"]
    assert facts["excluded"] == [{"function": "checkLicense", "reason": "license-like name"}]
    owners = {x.get("function") for kind in ("strings", "calls", "throws", "numbers", "functions") for x in facts[kind]}
    assert "checkLicense" not in owners  # nothing inside excluded logic becomes a fact
    assert "checkLicense" not in {f["name"] for f in facts["functions"]}
    reads = {(r["width"], str(r["at"])) for r in facts["reads"] if r["function"] == "readLex"}
    assert {(2, "{'absolute': 4}"), (4, "{'absolute': 8}"), (4, "{'from_end': 4}")} <= reads
    assert lexfmt_model.reachable("readLex") == ["readLex", "crc32", "decodeSection", "decodeText"]
    assert lexfmt_model.excluded_reached("readLex") == {"checkLicense"}


def test_engine_refuses_paths_outside_its_inputs_and_changed_content(run_engine, lexfmt, subject_sha):
    outside, changed = run_engine(
        lexfmt, [{"path": "../README.md", "sha256": subject_sha}, {"path": SUBJECT, "sha256": "0" * 64}]
    )
    assert "refused input path" in outside["error"]
    assert changed["error"] == "content does not match the pinned sha256"
