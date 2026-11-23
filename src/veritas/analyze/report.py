"""The Analyze report for people: subjects, the behavior spec by interface, limitations, and the gate."""

from __future__ import annotations

from typing import Any

KIND = {"observed": "Observed", "inferred": "Inferred", "unknown": "Unknown", "limitation": "Limitation"}


def _text(text: object) -> str:
    """Claim text may one day come from a model that read subject data, so it is never rendered as markup."""
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def _cell(text: object) -> str:
    """Names that come from a subject (files inside an archive, functions) can't break a table or a code span."""
    return _text(text).replace("`", "'").replace("|", "\\|")


def _dependencies(subjects: list[dict[str, Any]], matching: dict[str, Any], limit: int = 40) -> list[str]:
    rows = [(s["path"], d) for s in subjects for d in s.get("dependencies") or []]
    if not rows:
        return []
    if matching.get("checked"):
        checked = (f"They were matched against the advisories you imported: {matching.get('matched', 0)} match(es), "
                   "listed above as `vulnerable-dependency` candidates.")  # fmt: skip
    else:
        checked = "No advisories are imported, so they weren't checked for known vulnerabilities."
    out = ["", "## Bundled dependencies (inventory, operator only)", "",
           f"{len(rows)} packages, also listed in `sbom.cdx.json` (CycloneDX). {checked}", "",
           "| Package | Version | In |", "|---|---|---|"]  # fmt: skip
    out += [f"| {_cell(d['name'])} | {_cell(d.get('version') or '?')} | `{_cell(path)}` |" for path, d in rows[:limit]]
    if len(rows) > limit:
        out.append(f"| … {len(rows) - limit} more in `sbom.cdx.json` | | |")
    return out


def _code(candidates: list[dict[str, Any]], code: dict[str, Any]) -> list[str]:
    out = ["", "## Security findings (candidates, operator only)", ""]
    if candidates:
        out += [
            "Each one was found by reading the subjects (code, archives, and recordings), without sending any traffic, "
            "and is not yet confirmed. Where a live check exists, Assess proves or refutes it on a running target.",
            "",
            "| ID | If confirmed | Finding | Where | Confirm live with |",
            "|---|---|---|---|---|",
        ]
        for f in candidates:
            at = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            where = f"`{_cell(at)}`" + (f" in `{_cell(f['function'])}`" if f["function"] else "")
            live = f"`{f['confirms_with']}`" if f["confirms_with"] else "review"
            out.append(f"| {f['id']} | {f['if_confirmed']['severity'].upper()} | {_text(f['title'])} · "
                       f"{', '.join(f['cwe'])} | {where} | {live} |")  # fmt: skip
    else:
        out.append(f"No candidates from the {code.get('rules', 0)} static rules.")
    out += ["", "Static rules don't cover these; Assess tests them on a running target:", ""]
    out += [f"- {item}" for item in code.get("not_covered", [])]
    return out


def render_analysis(
    document: dict[str, Any],
    draft: dict[str, Any],
    clean: dict[str, Any],
    candidates: list[dict[str, Any]] | None = None,
) -> str:
    charter, spec = document["charter"], document["spec"]
    out = [
        f"# Veritas analysis: {charter['name']} ({document['run']})",
        "",
        "| | |",
        "|---|---|",
        f"| Outcome | {document['outcome']} |",
        f"| Basis | {charter['basis']} (recorded, not verified by Veritas) |",
        f"| Purpose | {_text(charter['purpose'])} |",
        f"| Charter digest | `{charter['digest']}` |",
        f"| Started | {document['started']} ({document['duration_s']} s) |",
        "",
        "## Subjects",
        "",
        "| Subject | Type | SHA-256 | Facts |",
        "|---|---|---|---|",
    ]
    for s in document["subjects"]:
        facts = ", ".join(f"{k} {v}" for k, v in (s.get("counts") or {}).items()) or _text(s.get("error", "no engine"))
        out.append(f"| `{s['path']}` | {s['type']} | `{s['sha256'][:16]}…` | {facts} |")
    out += ["", "## Behavior spec", ""]
    out.append(
        f"Spec digest `{clean['digest']}`. {spec['gate']['passed']} claims passed the spec gate and "
        f"{spec['gate']['blocked']} were blocked. Nothing crosses into a clean-room context until a person approves "
        f"this digest with `veritas spec approve {document['run']}`."
    )
    for interface in clean["interfaces"]:
        out += ["", f"### {interface['id']} · {interface['title']}", ""]
        out += [f"- **{KIND.get(c['kind'], c['kind'])}** {_text(c['text'])} ({c['id']})" for c in interface["claims"]]
    if document.get("code") is not None:
        out += _code(candidates or [], document["code"])
    out += _dependencies(document["subjects"], document.get("dependencies") or {})
    if document["limitations"]:
        out += ["", "## Limitations", ""] + [f"- {_text(text)}" for text in document["limitations"]]
    if draft.get("excluded"):
        out += ["", "## Excluded by policy (operator only)", ""]
        out += [f"- `{e['file']}`: one function excluded ({e['reason']})" for e in draft["excluded"]]
    blocked = draft.get("gate", {}).get("blocked") or []
    if blocked:
        out += ["", "## Blocked at the gate (operator only)", "", "| Claim | Filter | Reason |", "|---|---|---|"]
        out += [f"| {b['claim']} | {b['filter']} | {_text(b['reason'])} |" for b in blocked]
    out += [
        "",
        "## Next",
        "",
        f"1. Review the claims above, then approve the spec: `veritas spec approve {document['run']}`.",
        f"2. Verify an implementation against it: `veritas cleanroom verify {document['run']} --impl <dir>`.",
        "",
    ]
    return "\n".join(out)
