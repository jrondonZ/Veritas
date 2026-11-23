"""Static security rules: the vuln-notes app's own source against its code ground truth, and one case per rule."""

import json

import pytest

from veritas.analyze.ground import compare_code
from veritas.analyze.program import FileModel
from veritas.analyze.sarif import render_code_sarif
from veritas.analyze.security import RULES, code_findings, summary
from veritas.core.canonical import sha256_hex
from veritas.documents import load_yaml
from veritas.findings.lint import lint_claims

APP = ("server.mjs", "db.mjs", "openapi.mjs", "start.mjs", "reset.mjs")


def models(run_engine, folder, names, prefix=""):
    files = [{"path": name, "sha256": sha256_hex((folder / name).read_bytes())} for name in names]
    results = run_engine(folder, files)
    assert all("error" not in r for r in results), [r.get("error") for r in results]
    return [FileModel(f"{prefix}{r['path']}", r["sha256"], f"E-{n:012x}", r) for n, r in enumerate(results, 1)]


@pytest.fixture(scope="module")
def vuln_notes(run_engine, repo_root):
    return models(run_engine, repo_root / "labs" / "vuln-notes" / "app", APP, prefix="app/")


def test_the_lab_source_yields_exactly_the_expected_candidates(vuln_notes, repo_root):
    found = code_findings(vuln_notes)
    truth = load_yaml(repo_root / "labs" / "vuln-notes" / "expected-code-findings.yaml")
    result = compare_code(found, truth, files={m.path for m in vuln_notes})  # the source; the recording has its own
    assert (result.precision, result.recall) == (1.0, 1.0), (result.unexpected, result.missed)
    assert result.look_alikes == []
    assert [f["id"] for f in found] == [f"S-{n:04d}" for n in range(1, 9)]


def test_each_candidate_names_the_assess_check_that_proves_it_live(vuln_notes, repo_root):
    """The bridge: what the code shows (Analyze) is what the running lab proves (Assess), item by item."""
    code_truth = load_yaml(repo_root / "labs" / "vuln-notes" / "expected-code-findings.yaml")
    live_truth = load_yaml(repo_root / "labs" / "vuln-notes" / "expected-findings.yaml")
    live = {item["id"]: item["match"]["check"] for item in live_truth["planted"] if "match" in item}
    by_function = {f["function"]: f for f in code_findings(vuln_notes)}
    for item in (i for i in code_truth["expected"] if i["file"].startswith("app/")):
        assert by_function[item["function"]]["confirms_with"] == live[item["id"]], item["id"]


def test_candidates_are_typed_claims_that_cite_evidence(vuln_notes):
    found = code_findings(vuln_notes)
    claims = [c for f in found for c in f["claims"]]
    evidence = {m.evidence for m in vuln_notes}
    assert lint_claims("code", claims, evidence.__contains__) == []
    assert {c["kind"] for c in claims} == {"observed", "limitation", "guidance"}
    assert all(f["status"] == "candidate" for f in found)


def test_a_clean_library_has_no_candidates(lexfmt_model):
    assert code_findings([lexfmt_model]) == []


@pytest.fixture(scope="module")
def sample(run_engine, repo_root):
    return models(run_engine, repo_root / "tests" / "unit" / "analyze" / "fixtures" / "rules", ["sample.mjs"])


def test_one_case_per_rule_and_the_safe_variants_stay_quiet(sample):
    found = code_findings(sample)
    rules = sorted(f["rule"] for f in found)
    assert rules == sorted(
        [
            "dynamic-code", "shell-command", "path-from-input", "redirect-from-input", "dom-html", "weak-hash",
            "weak-random", "tls-unverified", "hardcoded-secret", "open-external", "electron-node-integration",
            "electron-context-isolation",
        ]
    )  # fmt: skip
    functions = {f["function"] for f in found}
    assert "shuffle" not in functions  # Math.random outside a security value
    lines = {(f["rule"], f["line"]) for f in found}
    assert len(lines) == len(found)  # one finding per site


def test_secret_values_never_appear_in_a_finding(sample):
    (secret,) = [f for f in code_findings(sample) if f["rule"] == "hardcoded-secret"]
    text = json.dumps(secret)
    assert "AKIAABCDEFGHIJKLMNOP" not in text
    assert "aws-access-key" in secret["claims"][0]["text"]


def test_sarif_puts_each_candidate_at_its_file_and_line(vuln_notes):
    found = code_findings(vuln_notes)
    sarif = render_code_sarif(found, "r-0001")
    (run,) = sarif["runs"]
    assert sarif["version"] == "2.1.0"
    assert len(run["results"]) == len(found)
    first = run["results"][0]
    location = first["locations"][0]["physicalLocation"]
    assert (location["artifactLocation"]["uri"], location["region"]["startLine"]) == (
        found[0]["file"],
        found[0]["line"],
    )
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {f["rule"] for f in found}
    assert all("CWE-" in " ".join(r["properties"]["tags"]) for r in run["tool"]["driver"]["rules"])


def test_the_summary_names_what_static_rules_do_not_cover(vuln_notes):
    info = summary(code_findings(vuln_notes))
    assert info["candidates"] == 8
    assert info["rules"] == len(RULES)
    assert any("authorization" in item for item in info["not_covered"])
