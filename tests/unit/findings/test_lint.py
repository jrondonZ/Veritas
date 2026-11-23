import copy

import pytest

from veritas.findings.lint import drop_unsupported, lint_document, lint_finding

E1, E2 = "E-0123456789ab", "E-ba9876543210"
KNOWN = {E1, E2}.__contains__


def finding(**changes):
    base = {
        "id": "F-0001",
        "status": "confirmed",
        "cvss": {"version": "3.1", "score": 6.5},
        "claims": [
            {"id": "C-0001", "kind": "observed", "text": "alice read bob's note", "evidence": [E1], "based_on": []},
            {"id": "C-0002", "kind": "observed", "text": "bob read his own note", "evidence": [E2], "based_on": []},
            {
                "id": "C-0003",
                "kind": "inferred",
                "text": "any user can read any note",
                "based_on": ["C-0001", "C-0002"],
            },
            {"id": "C-0004", "kind": "unknown", "text": "writes were not tested"},
            {"id": "C-0005", "kind": "guidance", "text": "scope the lookup by owner"},
        ],
    }
    base.update(changes)
    return base


def with_claim(index, **changes):
    f = finding()
    f["claims"] = copy.deepcopy(f["claims"])
    f["claims"][index].update(changes)
    return f


def rules(f):
    return [p.rule for p in lint_finding(f, KNOWN)]


def test_a_well_formed_finding_passes():
    assert lint_finding(finding(), KNOWN) == []
    assert lint_finding({"id": "F-0002", "status": "blocked", "claims": []}, KNOWN) == []


CASCADE = "reference.claim"  # C-0003 rests on C-0001 and C-0002, so a broken basis flags it too


@pytest.mark.parametrize(
    ("f", "expected"),
    [
        (with_claim(0, kind="opinion"), ["claim.kind", CASCADE]),
        (with_claim(0, id="claim-1"), ["claim.id", CASCADE]),
        (with_claim(1, id="C-0001"), ["claim.id", CASCADE]),
        (with_claim(3, text="   "), ["claim.text"]),
        (with_claim(3, text="x" * 2001), ["claim.text"]),
        (with_claim(0, evidence=["E-ffffffffffff"]), ["reference.evidence", CASCADE]),
        (with_claim(0, evidence=["../etc/passwd"]), ["reference.evidence", CASCADE]),
        (with_claim(0, evidence=[]), ["observed.evidence", CASCADE]),
        (with_claim(1, based_on=["C-0001"]), ["observed.basis", CASCADE]),
        (with_claim(2, based_on=[]), ["inferred.basis"]),
        (with_claim(2, based_on=["C-0009"]), ["reference.claim"]),
        (with_claim(2, based_on=["C-0004"]), ["reference.claim"]),  # a later claim cannot support an earlier one
        (with_claim(4, based_on=["C-0003"]), []),  # guidance may cite reasoning
    ],
)
def test_claim_rules(f, expected):
    assert rules(f) == expected


def test_an_inference_cannot_rest_on_an_unknown():
    f = finding()
    f["claims"] = [f["claims"][3], {"id": "C-0006", "kind": "inferred", "text": "so...", "based_on": ["C-0004"]}]
    assert "inferred.basis" in rules(f)


def test_finding_rules():
    no_observed = finding(
        claims=[c for c in finding()["claims"] if c["kind"] != "observed" and c["kind"] != "inferred"]
    )
    assert rules(no_observed) == ["finding.observed"]
    assert rules(finding(claims=finding()["claims"][:4])) == ["finding.guidance"]
    assert rules(finding(cvss=None)) == ["finding.cvss"]
    assert rules(finding(status="rejected")) == ["finding.cvss"]


def test_claim_ids_are_unique_across_a_document():
    problems = lint_document({"findings": [finding(), finding(id="F-0002")]}, KNOWN)
    assert {(p.finding, p.rule) for p in problems} == {("F-0002", "claim.id"), ("F-0002", CASCADE)}


def test_drop_unsupported_removes_flagged_claims_and_what_rests_on_them():
    document = {"findings": [with_claim(0, evidence=["E-ffffffffffff"])]}
    problems = lint_document(document, KNOWN)
    assert drop_unsupported(document, problems) == 2
    assert [c["id"] for c in document["findings"][0]["claims"]] == ["C-0002", "C-0004", "C-0005"]
