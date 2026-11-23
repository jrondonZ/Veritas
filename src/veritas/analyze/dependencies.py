"""Bundled dependencies matched against the operator's imported advisories (CWE-1395).

The inventory comes from Electron archives: each bundled package's manifest, by name and
version. The advisories come from `veritas advisories import`, offline. A match is a
candidate: the bundled version falls in a range the advisory lists as affected. Whether the
app reaches the vulnerable code isn't checked, and each finding says so.

Each matched advisory is added to the run as evidence, so the finding's claims cite both
what the archive declares and what the advisory states.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..core.canonical import canonical_bytes, sha256_hex
from ..findings.cvss import base_score, severity
from ..imports.osv import MEDIA_TYPE, Advisories, affected, describe, first_fixed
from .security import PRODUCER, RULES

RULE = "vulnerable-dependency"
ECOSYSTEM = "npm"  # Electron archives bundle npm packages
Evidence = Callable[[bytes, str, str], str]  # (data, media type, source) -> evidence ID


def _plural(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _finding(subject: dict[str, Any], dep: dict[str, Any], record: dict[str, Any], cited: str) -> dict[str, Any]:
    rule = RULES[RULE]
    name, version = dep["name"], dep["version"]
    path = f"{subject['path']}!/{dep['path']}" if dep.get("path") else subject["path"]
    vector = record.get("cvss") or rule.cvss
    score = base_score(vector)
    known = ", ".join([record["id"], *record.get("aliases", [])[:3]])
    rated = f" The advisory rates it {record['label'].lower()}." if record.get("label") else ""
    stated = f": {record['summary'].rstrip('.')}." if record.get("summary") else "."
    fixed = first_fixed(version, record)
    target = f"{fixed} or later" if fixed else "a version the advisory doesn't list as affected"
    claims = [
        {"kind": "observed", "text": f"{subject['path']} bundles {name} {version} ({path}).",
         "evidence": [subject["facts"]]},
        {"kind": "observed", "text": f"Advisory {known} lists {name} {describe(record)} as affected{stated}{rated}",
         "evidence": [cited]},
        {"kind": "inferred", "text": f"The bundled {name} {version} is in a range the advisory lists as affected.",
         "evidence": []},
        {"kind": "limitation", "text": "Matched by package name and version against advisories imported offline. "
         "Whether the app reaches the vulnerable code isn't checked." + (
             "" if record.get("cvss") else " The advisory has no CVSS 3 vector, so the score is this rule's default."),
         "evidence": []},
        {"kind": "guidance", "text": f"Update {name} to {target}, rebuild the archive, and analyze it again.",
         "evidence": []},
    ]  # fmt: skip
    return {
        "id": "",
        "rule": RULE,
        "title": rule.title,
        "status": "candidate",
        "cwe": sorted({*rule.cwe, *record.get("cwe", [])}),
        "if_confirmed": {"severity": severity(score), "cvss": {"vector": vector, "score": score}},
        "file": path,
        "line": 0,
        "function": f"{name}@{version}",
        "confirms_with": None,
        "fingerprint": sha256_hex(f"{RULE}|{path}|{record['id']}".encode())[:16],
        "advisory": {"id": record["id"], "aliases": record.get("aliases", []), "source": record["source"]},
        "claims": [{**c, "id": "", "based_on": [], "producer": PRODUCER} for c in claims],
    }


def dependency_candidates(
    subjects: list[dict[str, Any]], advisories: Advisories | None, add_evidence: Evidence
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """(findings, limitations, a summary for the analysis document) for the dependencies the subjects bundle."""
    bundled = [(s, d) for s in subjects for d in s.get("dependencies") or [] if d.get("name") and s.get("facts")]
    if not bundled:
        return [], [], {"bundled": 0}
    if advisories is None:
        note = (f"{_plural(len(bundled), 'bundled dependency was', 'bundled dependencies were')} not checked for "
                "known vulnerabilities, because no advisories are imported (`veritas advisories import`)")  # fmt: skip
        return [], [note], {"bundled": len(bundled), "checked": False}
    findings: list[dict[str, Any]] = []
    cited: dict[tuple[str, str], str] = {}
    unknown: list[str] = []
    unversioned = 0
    for subject, dep in bundled:
        if not dep.get("version"):
            unversioned += 1
            continue
        for record in advisories.for_package(ECOSYSTEM, dep["name"]):
            if record.get("withdrawn"):
                continue
            hit = affected(dep["version"], record)
            if hit is None:
                unknown.append(f"{dep['name']} {dep['version']} ({record['id']})")
            if not hit:
                continue
            key = (record["id"], dep["name"])
            if key not in cited:
                data = canonical_bytes({"v": 1, "kind": "advisory", "ecosystem": ECOSYSTEM, "package": dep["name"],
                                        "record": record})  # fmt: skip
                cited[key] = add_evidence(data, MEDIA_TYPE, f"advisory:{record['source'][:16]}")
            findings.append(_finding(subject, dep, record, cited[key]))
    notes = []
    if unversioned:
        notes.append(f"{_plural(unversioned, 'bundled dependency has', 'bundled dependencies have')} no version, "
                     "so it couldn't be checked against advisories")  # fmt: skip
    if unknown:
        notes.append(f"{_plural(len(unknown), 'advisory range', 'advisory ranges')} couldn't be compared with a bundled "
                     f"version: {', '.join(unknown[:5])}")  # fmt: skip
    sources = sorted({r["source"] for r in (f["advisory"] for f in findings)})
    return findings, notes, {"bundled": len(bundled), "checked": True, "matched": len(findings), "sources": sources}
